/**
 * services/anomalyDetector.js
 * Rule-based anomaly detection listening on the security event bus.
 *
 * Adapted from spec:
 *   - No Redis → in-memory Map counters with TTL
 *   - DB via getDB().promise() (no direct require('../config/db'))
 *   - lockAccount: graceful skip if status column absent
 *   - revokeAllSessions: graceful no-op (no sessions table)
 */
const eventBus     = require("./eventBus");
const auditService = require("./auditService");
const notifier     = require("./notifier");
const getDB        = require("../config/db");

// ── In-memory rate counters (replaces Redis) ──────────────────────────────────
// key → { count: number, expiry: timestamp }
const _counters = new Map();

function _incr(key, ttlMs) {
    const now   = Date.now();
    const entry = _counters.get(key);
    if (!entry || now > entry.expiry) {
        _counters.set(key, { count: 1, expiry: now + ttlMs });
        return 1;
    }
    entry.count += 1;
    return entry.count;
}

// Prune stale counter entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of _counters) { if (now > v.expiry) _counters.delete(k); }
}, 5 * 60 * 1000);

// ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector {
    constructor() {
        this.rules = [
            { type: "BRUTE_FORCE_LOGIN",   check: this._checkBruteForce.bind(this) },
            { type: "TOTP_FLOOD",          check: this._checkTOTPFlood.bind(this) },
            { type: "BULK_DOWNLOAD",       check: this._checkBulkDownload.bind(this) },
            { type: "NEW_GEO_LOGIN",       check: this._checkNewGeo.bind(this) },
            { type: "OFF_HOURS_SENSITIVE", check: this._checkOffHoursSensitive.bind(this) },
            { type: "CONCURRENT_SESSION",  check: this._checkConcurrentSession.bind(this) },
        ];
    }

    /** Wire all event bus listeners — call once at startup */
    start() {
        eventBus.on("auth.failure",   (e) => this._analyze("auth.failure",   e));
        eventBus.on("totp.failure",   (e) => this._analyze("totp.failure",   e));
        eventBus.on("file.download",  (e) => this._analyze("file.download",  e));
        eventBus.on("auth.success",   (e) => this._analyze("auth.success",   e));
        eventBus.on("access.denied",  (e) => this._analyze("access.denied",  e));
        eventBus.on("external.probe", (e) => this._analyze("external.probe", e));
        eventBus.on("rate.limit",     (e) => this._analyze("rate.limit",     e));
        console.log("[AnomalyDetector] Listening on event bus ✅");
    }

    async _analyze(eventType, event) {
        for (const rule of this.rules) {
            try {
                const detection = await rule.check(eventType, event);
                if (detection) await this._respond(detection, event);
            } catch (e) {
                console.warn(`[AnomalyDetector] Rule ${rule.type} error:`, e.message);
            }
        }
    }

    // ── RULE 1: Brute force login (>5 failures in 10 min) ──────────────────
    async _checkBruteForce(eventType, event) {
        if (eventType !== "auth.failure") return null;
        const count = _incr(`bf:login:${event.ip}`, 10 * 60 * 1000);
        if (count >= 5)
            return { type: "BRUTE_FORCE_LOGIN", severity: "high",
                     detail: { ip: event.ip, count, userId: event.userId } };
        return null;
    }

    // ── RULE 2: TOTP flood (>3 failures in 5 min) ──────────────────────────
    async _checkTOTPFlood(eventType, event) {
        if (eventType !== "totp.failure") return null;
        const count = _incr(`bf:totp:${event.userId}`, 5 * 60 * 1000);
        if (count >= 3)
            return { type: "TOTP_FLOOD", severity: "critical",
                     detail: { userId: event.userId, count } };
        return null;
    }

    // ── RULE 3: Bulk download (>15 files in 1 hour) ────────────────────────
    async _checkBulkDownload(eventType, event) {
        if (eventType !== "file.download") return null;
        const count = _incr(`bulk:dl:${event.userId}`, 60 * 60 * 1000);
        if (count >= 15)
            return { type: "BULK_DOWNLOAD", severity: "high",
                     detail: { userId: event.userId, count } };
        return null;
    }

    // ── RULE 4: Login from new country ─────────────────────────────────────
    async _checkNewGeo(eventType, event) {
        if (eventType !== "auth.success" || !event.userId) return null;
        const db = getDB();
        if (!db) return null;
        try {
            const [rows] = await db.promise().query(
                `SELECT geo_country FROM access_contexts
                 WHERE user_id=? AND created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)
                 GROUP BY geo_country ORDER BY MAX(created_at) DESC LIMIT 5`,
                [event.userId]
            );
            const knownCountries = rows.map((r) => r.geo_country);
            if (knownCountries.length > 0 &&
                !knownCountries.includes(event.geoCountry) &&
                event.geoCountry !== "UNKNOWN") {
                return { type: "NEW_GEO_LOGIN", severity: "medium",
                         detail: { userId: event.userId, country: event.geoCountry, knownCountries } };
            }
        } catch { /* access_contexts may not have enough data yet */ }
        return null;
    }

    // ── RULE 5: Sensitive action outside hours (before 6am or after 11pm) ──
    async _checkOffHoursSensitive(eventType, event) {
        if (!["file.upload", "file.download"].includes(eventType)) return null;
        const hour = new Date().getHours();
        if (hour < 6 || hour >= 23)
            return { type: "OFF_HOURS_SENSITIVE", severity: "low",
                     detail: { userId: event.userId, hour, action: eventType } };
        return null;
    }

    // ── RULE 6: Concurrent sessions from different IPs ─────────────────────
    async _checkConcurrentSession(eventType, event) {
        if (eventType !== "auth.success") return null;
        const db = getDB();
        if (!db) return null;
        try {
            const [rows] = await db.promise().query(
                `SELECT DISTINCT ip_address FROM access_contexts
                 WHERE user_id=? AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)`,
                [event.userId]
            );
            const otherIps = rows
                .map((r) => r.ip_address)
                .filter((ip) => ip && ip !== event.ip);
            if (otherIps.length > 0)
                return { type: "CONCURRENT_SESSION", severity: "high",
                         detail: { userId: event.userId, currentIp: event.ip, otherIps } };
        } catch { /* non-fatal */ }
        return null;
    }

    // ── AUTOMATED RESPONSE ENGINE ───────────────────────────────────────────
    async _respond(detection, event) {
        const db = getDB();

        // Persist security event to DB
        if (db) {
            try {
                await db.promise().query(
                    `INSERT INTO security_events
                     (user_id, event_type, severity, source_ip, geo_country, detail, auto_action)
                     VALUES (?,?,?,?,?,?,?)`,
                    [
                        event.userId  ?? null,
                        detection.type,
                        detection.severity,
                        event.ip      ?? null,
                        event.geoCountry ?? null,
                        JSON.stringify(detection.detail),
                        this._getAutoAction(detection.severity),
                    ]
                );
            } catch (e) {
                console.warn("[AnomalyDetector] security_events insert failed:", e.message);
            }
        }

        // Write to tamper-evident audit log
        await auditService.log({
            userId:  event.userId,
            action:  `anomaly.${detection.type.toLowerCase()}`,
            outcome: "blocked",
            reason:  detection.type,
            ip:      event.ip,
        });

        console.warn(`[AnomalyDetector] ${detection.severity.toUpperCase()} — ${detection.type}`, detection.detail);

        // Execute severity-based automated response
        switch (detection.severity) {
            case "critical":
                await this._lockAccount(event.userId, db);
                await notifier.alertAdmin(detection, event);
                break;
            case "high":
                await notifier.alertAdmin(detection, event);
                break;
            case "medium":
                await notifier.alertAdmin(detection, event);
                break;
            case "low":
                // Logged only — already done above
                break;
        }
    }

    _getAutoAction(severity) {
        return {
            critical: "account_locked + admin_alerted",
            high:     "admin_alerted",
            medium:   "admin_alerted",
            low:      "logged",
        }[severity] ?? "logged";
    }

    /** Soft-lock a user account. No-op if status column doesn't exist yet. */
    async _lockAccount(userId, db) {
        if (!userId || !db) return;
        try {
            await db.promise().query(
                "UPDATE users SET status='locked', locked_at=NOW() WHERE id=?",
                [userId]
            );
            console.warn(`[AnomalyDetector] Account ${userId} locked`);
        } catch (e) {
            // Column may not exist — non-fatal
            console.warn("[AnomalyDetector] lockAccount skipped:", e.message);
        }
    }
}

module.exports = new AnomalyDetector();
