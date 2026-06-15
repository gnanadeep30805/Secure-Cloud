/**
 * middleware/threatGuard.js
 * Perimeter security: rate limiting, IP blocklist, suspicious payload detection.
 *
 * Adapted from spec:
 *   - express-rate-limit with built-in memory store (no Redis)
 *   - DB via getDB().promise() 
 *   - logViolation uses ON DUPLICATE KEY UPDATE
 */
const rateLimit        = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");
const eventBus         = require("../services/eventBus");
const getDB            = require("../config/db");

// ── Rate limiters (memory store — no Redis needed) ────────────────────────────

/** Auth login: 10 attempts per 15 minutes per IP */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max:      10,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: (req) => ipKeyGenerator(req),
    handler: async (req, res) => {
        eventBus.rateLimitHit({ ip: req.ip, endpoint: "/login", ts: Date.now() });
        await _logViolation(req.ip, "/login");
        res.status(429).json({ error: "Too many login attempts — try again in 15 minutes", code: "RATE_LIMITED" });
    },
});

/** TOTP verification: 5 attempts per 5 minutes per user+IP */
const totpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max:      5,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: (req) => `${ipKeyGenerator(req)}:${req.user?.id ?? "anon"}`,
    handler: (req, res) => {
        eventBus.rateLimitHit({ ip: req.ip, endpoint: "/totp", userId: req.user?.id });
        res.status(429).json({ error: "Too many TOTP attempts — try again in 5 minutes", code: "TOTP_RATE_LIMITED" });
    },
});

/** File uploads: 30 per hour per user */
const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max:      30,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: (req) => String(req.user?.id ?? ipKeyGenerator(req)),
    handler: (req, res) => {
        res.status(429).json({ error: "Upload limit reached — try again in 1 hour", code: "UPLOAD_RATE_LIMITED" });
    },
});

/** File downloads: 50 per hour per user */
const downloadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max:      50,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: (req) => String(req.user?.id ?? ipKeyGenerator(req)),
    handler: (req, res) => {
        eventBus.rateLimitHit({ ip: req.ip, endpoint: "/download", userId: req.user?.id });
        res.status(429).json({ error: "Download limit reached — try again in 1 hour", code: "DOWNLOAD_RATE_LIMITED" });
    },
});

// ── IP blocklist check ────────────────────────────────────────────────────────

const checkBlocklist = async (req, res, next) => {
    const db = getDB();
    if (!db) return next();
    try {
        const [rows] = await db.promise().query(
            `SELECT 1 FROM rate_limit_violations
             WHERE ip_address=? AND is_blocked=TRUE
               AND (blocked_until IS NULL OR blocked_until > NOW())
             LIMIT 1`,
            [req.ip]
        );
        if (rows.length > 0) {
            eventBus.externalProbe({ ip: req.ip, type: "BLOCKED_IP_ACCESS", ts: Date.now() });
            return res.status(403).json({ error: "Access denied", code: "IP_BLOCKED" });
        }
    } catch { /* non-fatal — fail open if DB unavailable */ }
    next();
};

// ── Suspicious payload detector ───────────────────────────────────────────────

const _SUSPICIOUS = [
    /<script/i,           // XSS
    /union\s+select/i,    // SQL injection
    /\.\.\//,             // path traversal
    /eval\s*\(/i,         // code injection
    /base64_decode/i,     // encoded payloads
];

const detectSuspiciousPayload = (req, res, next) => {
    const body = JSON.stringify(req.body ?? {});
    const url  = req.originalUrl;

    for (const pattern of _SUSPICIOUS) {
        if (pattern.test(url) || pattern.test(body)) {
            eventBus.externalProbe({
                ip:      req.ip,
                type:    "SUSPICIOUS_PAYLOAD",
                pattern: pattern.toString(),
                url,
            });
            return res.status(400).json({ error: "Invalid request", code: "SUSPICIOUS_PAYLOAD" });
        }
    }
    next();
};

// ── Internal helper ───────────────────────────────────────────────────────────

async function _logViolation(ip, endpoint) {
    const db = getDB();
    if (!db) return;
    try {
        await db.promise().query(
            `INSERT INTO rate_limit_violations (ip_address, endpoint, hit_count, last_seen)
             VALUES (?,?,1,NOW())
             ON DUPLICATE KEY UPDATE hit_count=hit_count+1, last_seen=NOW()`,
            [ip, endpoint]
        );
    } catch { /* non-fatal */ }
}

module.exports = {
    loginLimiter,
    totpLimiter,
    uploadLimiter,
    downloadLimiter,
    checkBlocklist,
    detectSuspiciousPayload,
};
