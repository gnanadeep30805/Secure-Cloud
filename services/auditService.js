/**
 * services/auditService.js
 * Tamper-evident, HMAC-SHA512 chained audit log.
 * Each row signs itself + the hash of the previous row (blockchain-style).
 * Adapted: uses getDB().promise() (no Redis, no direct db import).
 */
const crypto = require("crypto");
const getDB  = require("../config/db");

// LOG_HMAC_KEY must be 64+ chars and never change after first log row is written.
const LOG_HMAC_KEY = process.env.LOG_HMAC_KEY
    || "insecure-dev-key-replace-in-prod-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

class AuditService {

    /** Write one tamper-evident log entry. Never throws — always best-effort. */
    async log(data) {
        try {
            const db = getDB();
            if (!db) return;
            const pool = db.promise();

            const eventId     = crypto.randomUUID();
            const prevLogHash = await this._getLastHash(pool);

            const entry = {
                event_id:           eventId,
                user_id:            data.userId            ?? null,
                action:             String(data.action),
                resource_type:      data.resourceType      ?? null,
                resource_id:        data.resourceId != null ? String(data.resourceId) : null,
                outcome:            data.outcome,
                reason:             data.reason ? String(data.reason).slice(0, 200) : null,
                risk_score:         data.riskScore         ?? null,
                device_trust_score: data.deviceTrustScore  ?? null,
                ip_address:         data.ip                ?? null,
                geo_location:       data.geoLocation       ?? null,
                is_vpn:             data.isVPN             ? 1 : 0,
                user_agent:         data.userAgent ? String(data.userAgent).slice(0, 500) : null,
                session_age_min:    data.sessionAgeMin     ?? null,
                context_flags:      JSON.stringify(data.contextFlags ?? []),
                duration_ms:        data.durationMs        ?? null,
                prev_log_hash:      prevLogHash,
            };

            const logHash = this._signEntry(entry);

            await pool.query(
                `INSERT INTO audit_logs
                 (event_id, user_id, action, resource_type, resource_id,
                  outcome, reason, risk_score, device_trust_score, ip_address,
                  geo_location, is_vpn, user_agent, session_age_min, context_flags,
                  duration_ms, log_hash, prev_log_hash)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
                [
                    entry.event_id,   entry.user_id,       entry.action,
                    entry.resource_type, entry.resource_id, entry.outcome,
                    entry.reason,     entry.risk_score,    entry.device_trust_score,
                    entry.ip_address, entry.geo_location,  entry.is_vpn,
                    entry.user_agent, entry.session_age_min, entry.context_flags,
                    entry.duration_ms, logHash,            prevLogHash,
                ]
            );
            return eventId;
        } catch (err) {
            // Never let audit failure crash the request
            console.error("[AuditService] Log write failed:", err.message);
        }
    }

    /** HMAC-SHA512 sign a log entry using key fields */
    _signEntry(entry) {
        const payload = JSON.stringify({
            event_id:      entry.event_id,
            user_id:       entry.user_id,
            action:        entry.action,
            outcome:       entry.outcome,
            ip_address:    entry.ip_address,
            prev_log_hash: entry.prev_log_hash,
        });
        return crypto
            .createHmac("sha512", LOG_HMAC_KEY)
            .update(payload)
            .digest("hex");
    }

    /** Fetch the hash of the most recent row — the chain's last link */
    async _getLastHash(pool) {
        try {
            const [rows] = await pool.query(
                "SELECT log_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
            );
            return rows[0]?.log_hash ?? "GENESIS";
        } catch {
            return "GENESIS"; // table may not exist yet on first boot
        }
    }

    /**
     * Nightly chain verification — detect any tampering.
     * Returns { checked, violations, broken[] }
     */
    async verifyChain(limit = 1000) {
        const db = getDB();
        if (!db) return { checked: 0, violations: 0, broken: [] };
        try {
            const [rows] = await db.promise().query(
                "SELECT * FROM audit_logs ORDER BY id ASC LIMIT ?", [limit]
            );
            let prevHash = "GENESIS";
            const broken = [];
            for (const row of rows) {
                const expected = this._signEntry({
                    event_id:      row.event_id,
                    user_id:       row.user_id,
                    action:        row.action,
                    outcome:       row.outcome,
                    ip_address:    row.ip_address,
                    prev_log_hash: row.prev_log_hash,
                });
                try {
                    if (!crypto.timingSafeEqual(
                        Buffer.from(expected,     "hex"),
                        Buffer.from(row.log_hash, "hex")
                    )) broken.push({ id: row.id, event_id: row.event_id, reason: "HMAC_MISMATCH" });
                } catch {
                    broken.push({ id: row.id, event_id: row.event_id, reason: "HASH_INVALID" });
                }
                if (row.prev_log_hash !== prevHash)
                    broken.push({ id: row.id, event_id: row.event_id, reason: "CHAIN_BROKEN" });
                prevHash = row.log_hash;
            }
            return { checked: rows.length, violations: broken.length, broken };
        } catch (e) {
            return { checked: 0, violations: 0, error: e.message };
        }
    }
}

module.exports = new AuditService();
