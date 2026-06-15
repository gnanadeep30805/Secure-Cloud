/**
 * services/riskEngine.js
 * Enhanced risk-based scoring with 7 behavioural factors + contextFlag adjustments.
 * Persists every score to risk_scores table for forensic analysis.
 * No Redis — in-memory TTL cache.
 */
const getDB = require("../config/db");

// ── In-memory cache: "risk:<userId>:<ip>" → { score, expiry } ─────────────
const _cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function _cacheGet(key) {
    const e = _cache.get(key);
    if (!e) return null;
    if (Date.now() > e.expiry) { _cache.delete(key); return null; }
    return e.score;
}
function _cacheSet(key, score) {
    _cache.set(key, { score, expiry: Date.now() + CACHE_TTL_MS });
}

// Prune stale entries every 5 min
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of _cache) { if (now > v.expiry) _cache.delete(k); }
}, 5 * 60 * 1000).unref();

class RiskEngine {

    /**
     * Main entry — called by both RBA middleware and PEP middleware.
     * @param {string|number} userId
     * @param {object}        context      from contextBuilder
     * @param {string[]}      contextFlags from contextBuilder.getContextConstraints()
     * @returns {Promise<number>} 0-100
     */
    async calculate(userId, context, contextFlags = []) {
        // Base score (cached per user+IP to avoid double-compute in RBA→PEP)
        const baseScore = await this._getBaseScore(userId, context);

        // PEP-specific adjustments from context flags (additive, not cached)
        let adjusted = baseScore;
        if (contextFlags.includes("STALE_SESSION")) adjusted += 15;
        if (contextFlags.includes("UNKNOWN_GEO"))   adjusted += 10;

        return Math.min(adjusted, 100);
    }

    /**
     * Map score → action for RBA middleware.
     */
    determineAction(score) {
        if (score <= 40) return "allow";
        if (score <= 60) return "step_up_totp";
        if (score <= 80) return "step_up_email_otp";
        return "block";
    }

    // ── INTERNAL: cached base score with factor evaluation ────────────────

    async _getBaseScore(userId, context) {
        const cacheKey = `risk:${userId}:${context.ip}`;
        const cached = _cacheGet(cacheKey);
        if (cached !== null) return cached;

        const factors = await this.evaluateFactors(userId, context);
        const score   = this._sumFactors(factors);

        // Persist snapshot to risk_scores table (non-blocking)
        this._persistScore(userId, score, factors, context);

        _cacheSet(cacheKey, score);
        return score;
    }

    // ── FACTOR EVALUATION (7 factors, parallel) ──────────────────────────

    async evaluateFactors(userId, context) {
        const [
            isNewDevice,
            isNewGeo,
            isUnusualHour,
            recentFailures,
            isNewUserAgent,
        ] = await Promise.all([
            this._checkNewDevice(userId, context.deviceFingerprint),
            this._checkNewGeo(userId, context.geoCountry),
            this._checkUnusualHour(userId, context.currentHour),
            this._getRecentFailures(userId),
            this._checkNewUserAgent(userId, context.userAgent),
        ]);

        return {
            new_device:      isNewDevice      ? 30 : 0,
            new_geo:         isNewGeo          ? 25 : 0,
            unusual_hour:    isUnusualHour     ? 15 : 0,
            failed_attempts: Math.min(recentFailures * 5, 20),
            vpn_detected:    context.isVPN     ? 10 : 0,
            new_user_agent:  isNewUserAgent    ? 10 : 0,
        };
    }

    _sumFactors(factors) {
        const total = Object.values(factors).reduce((a, b) => a + b, 0);
        return Math.min(total, 100);
    }

    // ── INDIVIDUAL FACTOR CHECKS ─────────────────────────────────────────

    async _checkNewDevice(userId, fingerprint) {
        if (!fingerprint) return true;
        const db = getDB();
        if (!db) return false;
        try {
            const [rows] = await db.promise().query(
                `SELECT id FROM trusted_devices
                 WHERE user_id=? AND device_fingerprint=? AND is_active=TRUE LIMIT 1`,
                [userId, fingerprint]
            );
            return rows.length === 0;
        } catch { return false; }
    }

    async _checkNewGeo(userId, country) {
        if (!country || country === "UNKNOWN") return false;
        const db = getDB();
        if (!db) return false;
        try {
            const [rows] = await db.promise().query(
                `SELECT DISTINCT geo_country FROM access_contexts
                 WHERE user_id=? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)`,
                [userId]
            );
            if (rows.length === 0) return false; // no history → not suspicious
            return !rows.map(r => r.geo_country).includes(country);
        } catch { return false; }
    }

    async _checkUnusualHour(userId, currentHour) {
        const db = getDB();
        if (!db) return false;
        try {
            const [rows] = await db.promise().query(
                `SELECT current_hour FROM access_contexts
                 WHERE user_id=? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
                 ORDER BY created_at DESC LIMIT 100`,
                [userId]
            );
            if (rows.length < 10) return false; // not enough history
            const hours   = rows.map(r => r.current_hour);
            const avgHour = hours.reduce((a, b) => a + b, 0) / hours.length;
            return Math.abs(currentHour - avgHour) > 6;
        } catch { return false; }
    }

    async _getRecentFailures(userId) {
        const db = getDB();
        if (!db) return 0;
        try {
            const [rows] = await db.promise().query(
                `SELECT COUNT(*) AS cnt FROM user_activities
                 WHERE user_id = ? AND action LIKE '%_denied'
                   AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)`,
                [String(userId)]
            );
            return rows[0]?.cnt ?? 0;
        } catch { return 0; }
    }

    async _checkNewUserAgent(userId, userAgent) {
        if (!userAgent || userAgent === "UNKNOWN") return false;
        const db = getDB();
        if (!db) return false;
        try {
            const [rows] = await db.promise().query(
                `SELECT id FROM access_contexts WHERE user_id=? AND user_agent=? LIMIT 1`,
                [userId, userAgent]
            );
            return rows.length === 0;
        } catch { return false; }
    }

    // ── PERSIST ──────────────────────────────────────────────────────────

    async _persistScore(userId, score, factors, context) {
        const db = getDB();
        if (!db) return;
        try {
            const action = this.determineAction(score);
            await db.promise().query(
                `INSERT INTO risk_scores
                 (user_id, score, factors, action_taken, ip_address, geo_country)
                 VALUES (?,?,?,?,?,?)`,
                [userId, score, JSON.stringify(factors), action,
                 context.ip, context.geoCountry ?? "UNKNOWN"]
            );
        } catch (e) {
            console.warn("[RiskEngine] persist failed:", e.message);
        }
    }
}

module.exports = new RiskEngine();
