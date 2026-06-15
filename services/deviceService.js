/**
 * services/deviceService.js
 * Full device registry: trusted_devices table + in-memory TTL cache (no Redis).
 *
 * Trust score factors (0-100):
 *   +40/25/10/0 — trust_level (high/medium/low/untrusted)
 *   +20         — same IP as last seen
 *   +15         — registered > 30 days ago
 *   +8          — registered 7-30 days ago
 *   +10         — no VPN
 *   +15         — same geo-country as last seen
 *   -20         — inactive > 90 days
 */
const getDB = require("../config/db");

// In-memory trust cache: key → { score, expiry }
const _cache = new Map();
const CACHE_TTL_MS = Number(process.env.DEVICE_TRUST_CACHE_TTL || 300) * 1000;

function dbQ() {
    const pool = getDB();
    if (!pool) throw new Error("Database not ready");
    return pool.promise();
}

function cacheGet(key) {
    const entry = _cache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiry) { _cache.delete(key); return null; }
    return entry.score;
}
function cacheSet(key, score) {
    _cache.set(key, { score, expiry: Date.now() + CACHE_TTL_MS });
}
function cacheDel(key) { _cache.delete(key); }

class DeviceService {

    // ── REGISTRATION ──────────────────────────────────────────────────────────

    async registerDevice(userId, fingerprint, context) {
        const existing = await this.getDevice(userId, fingerprint);
        if (existing) {
            await this._updateLastSeen(userId, fingerprint, context);
            return existing;
        }

        const deviceName = this._parseDeviceName(context.userAgent || "");
        try {
            await dbQ().query(
                `INSERT INTO trusted_devices
                 (user_id, device_fingerprint, device_name, trust_level,
                  last_seen_ip, last_seen_country, verification_method)
                 VALUES (?,?,?,'low',?,?,'totp_verified')`,
                [userId, fingerprint, deviceName, context.ip, context.geoCountry ?? "UNKNOWN"]
            );
        } catch (e) {
            if (e.code !== "ER_DUP_ENTRY") throw e; // tolerate race condition
        }
        cacheDel(`device:${userId}:${fingerprint}`);
        return this.getDevice(userId, fingerprint);
    }

    // ── TRUST SCORE ───────────────────────────────────────────────────────────

    async getTrustScore(userId, fingerprint, context) {
        if (!fingerprint) return 0;

        const cacheKey = `device:${userId}:${fingerprint}`;
        const cached   = cacheGet(cacheKey);
        if (cached !== null) return cached;

        let device = await this.getDevice(userId, fingerprint);
        if (!device) {
            await this.registerDevice(userId, fingerprint, context);
            device = await this.getDevice(userId, fingerprint);
        }
        if (!device) { cacheSet(cacheKey, 10); return 10; }

        const score = this._calculateScore(device, context);
        cacheSet(cacheKey, score);
        return score;
    }

    _calculateScore(device, context) {
        let score = 0;
        const levelMap = { high: 40, medium: 25, low: 10, untrusted: 0 };
        score += levelMap[device.trust_level] ?? 0;

        if (device.last_seen_ip === context.ip)              score += 20;

        const daysSinceReg  = (Date.now() - new Date(device.registered_at)) / 86_400_000;
        if      (daysSinceReg > 30) score += 15;
        else if (daysSinceReg > 7)  score += 8;

        if (!context.isVPN)                                   score += 10;
        if (device.last_seen_country === context.geoCountry)  score += 15;

        const daysSinceSeen = (Date.now() - new Date(device.last_seen_at)) / 86_400_000;
        if (daysSinceSeen > 90)                               score -= 20;

        return Math.max(0, Math.min(100, score));
    }

    // ── IMPOSSIBLE TRAVEL DETECTION ───────────────────────────────────────────

    async checkImpossibleTravel(userId, currentCountry, currentTime) {
        if (currentCountry === "UNKNOWN") return false;
        const windowHr = Number(process.env.IMPOSSIBLE_TRAVEL_WINDOW_HR || 2);
        try {
            const [rows] = await dbQ().query(
                `SELECT geo_country, created_at FROM access_contexts
                 WHERE user_id = ?
                   AND created_at > DATE_SUB(NOW(), INTERVAL ? HOUR)
                 ORDER BY created_at DESC LIMIT 10`,
                [userId, windowHr]
            );
            for (const row of rows) {
                if (row.geo_country !== currentCountry && row.geo_country !== "UNKNOWN") {
                    const minsApart = (currentTime - new Date(row.created_at)) / 60_000;
                    if (minsApart < windowHr * 60) return true;
                }
            }
        } catch { /* non-fatal — access_contexts may not exist yet */ }
        return false;
    }

    // ── UPDATE LAST SEEN ──────────────────────────────────────────────────────

    async updateLastSeen(userId, fingerprint, context) {
        return this._updateLastSeen(userId, fingerprint, context);
    }

    async _updateLastSeen(userId, fingerprint, context) {
        try {
            await dbQ().query(
                `UPDATE trusted_devices
                 SET last_seen_at=NOW(), last_seen_ip=?, last_seen_country=?
                 WHERE user_id=? AND device_fingerprint=?`,
                [context.ip, context.geoCountry ?? "UNKNOWN", userId, fingerprint]
            );
            // Do NOT bust the cache here — the cached score is still valid.
            // The cache expires naturally after DEVICE_TRUST_CACHE_TTL seconds.
        } catch { /* non-fatal */ }
    }

    // ── TRUST LEVEL MANAGEMENT ────────────────────────────────────────────────

    async upgradeTrustLevel(userId, fingerprint, newLevel) {
        const validLevels = ["low", "medium", "high"];
        if (!validLevels.includes(newLevel)) throw new Error("Invalid trust level");
        await dbQ().query(
            `UPDATE trusted_devices
             SET trust_level=?, verification_method='admin_approved'
             WHERE user_id=? AND device_fingerprint=?`,
            [newLevel, userId, fingerprint]
        );
        cacheDel(`device:${userId}:${fingerprint}`);
    }

    async revokeDevice(userId, fingerprint) {
        await dbQ().query(
            `UPDATE trusted_devices
             SET is_active=FALSE, trust_level='untrusted'
             WHERE user_id=? AND device_fingerprint=?`,
            [userId, fingerprint]
        );
        cacheDel(`device:${userId}:${fingerprint}`);
    }

    async requiresStepUp(userId, fingerprint, context) {
        const device = await this.getDevice(userId, fingerprint);
        if (!device || device.trust_level === "untrusted") return true;
        if (device.trust_level === "low")                   return true;
        if (device.last_seen_country !== context.geoCountry) return true;
        return false;
    }

    // ── HELPERS ───────────────────────────────────────────────────────────────

    async getDevice(userId, fingerprint) {
        try {
            const [rows] = await dbQ().query(
                `SELECT * FROM trusted_devices
                 WHERE user_id=? AND device_fingerprint=? AND is_active=TRUE`,
                [userId, fingerprint]
            );
            return rows[0] ?? null;
        } catch { return null; }
    }

    _parseDeviceName(ua = "") {
        if (!ua)                    return "Unknown device";
        if (ua.includes("Mobile")) return "Mobile browser";
        if (ua.includes("Chrome")) return "Chrome desktop";
        if (ua.includes("Firefox")) return "Firefox desktop";
        if (ua.includes("Safari")) return "Safari desktop";
        return "Unknown browser";
    }
}

module.exports = new DeviceService();
