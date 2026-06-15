/**
 * services/contextBuilder.js
 * Builds the full request context for PEP + Policy Engine.
 * Uses geoip-lite for geolocation. No Redis required.
 */
const crypto = require("crypto");
let geoip;
try { geoip = require("geoip-lite"); } catch { geoip = null; }

const getDB = require("../config/db");

const VPN_RANGES = (process.env.VPN_IP_RANGES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

class ContextBuilder {
    async build(req) {
        const ip  = this.extractIP(req);
        const geo = geoip ? (geoip.lookup(ip) ?? {}) : {};
        const now = new Date();

        return {
            requestId:       crypto.randomUUID(),
            // Network
            ip,
            geoCountry:      geo.country  ?? "UNKNOWN",
            geoCity:         geo.city     ?? "UNKNOWN",
            geoTimezone:     geo.timezone ?? "UNKNOWN",
            isVPN:           this.isVPN(ip, req),
            // Device
            deviceFingerprint: req.headers["x-device-fingerprint"] ?? null,
            userAgent:         req.headers["user-agent"] ?? "UNKNOWN",
            // Time
            currentHour:     now.getHours(),
            currentDay:      now.getDay(),
            isWeekend:       [0, 6].includes(now.getDay()),
            isBusinessHours: now.getHours() >= 9 && now.getHours() <= 18,
            timestamp:       now.toISOString(),
            // Session
            sessionAge:    req.user?.iat ? Date.now() - req.user.iat * 1000 : 0,
            sessionAgeMin: req.user?.iat
                ? Math.floor((Date.now() - req.user.iat * 1000) / 60000)
                : 0,
        };
    }

    extractIP(req) {
        return (
            req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
            req.headers["x-real-ip"] ||
            req.connection?.remoteAddress ||
            req.ip ||
            "0.0.0.0"
        );
    }

    isVPN(ip, req) {
        // Check configured VPN ranges
        if (VPN_RANGES.some((r) => ip.startsWith(r))) return true;
        // Fallback: presence of proxy headers
        return !!(req.headers["via"] || req.headers["x-proxy-id"]);
    }

    /** Returns true for loopback and RFC-1918 private addresses */
    _isPrivateIP(ip) {
        if (!ip || ip === "0.0.0.0") return true;
        if (ip === "127.0.0.1" || ip === "::1" || ip.startsWith("127.")) return true;
        if (ip.startsWith("10."))   return true;
        if (ip.startsWith("192.168.")) return true;
        // 172.16.0.0 – 172.31.255.255
        const m = ip.match(/^172\.(\d+)\./);
        if (m && parseInt(m[1], 10) >= 16 && parseInt(m[1], 10) <= 31) return true;
        if (ip.startsWith("::ffff:")) return this._isPrivateIP(ip.replace("::ffff:", ""));
        return false;
    }

    /** Returns an array of context constraint flags for the PEP */
    getContextConstraints(context) {
        const flags = [];

        if (context.isVPN) {
            flags.push({ type: "VPN_DETECTED", severity: "medium", action: "reduce_trust",    detail: "Request originates from VPN/proxy" });
        }
        if (!context.isBusinessHours) {
            flags.push({ type: "OFF_HOURS",    severity: "low",    action: "require_step_up", detail: `Request at hour ${context.currentHour} outside 09:00-18:00` });
        }
        if (context.sessionAgeMin > Number(process.env.SESSION_MAX_AGE_MIN || 30)) {
            flags.push({ type: "STALE_SESSION", severity: "medium", action: "require_reauth", detail: `Session ${context.sessionAgeMin} min old` });
        }
        // Only flag unknown geo for non-private IPs — local/dev traffic can't be geolocated
        if (context.geoCountry === "UNKNOWN" && !this._isPrivateIP(context.ip)) {
            flags.push({ type: "UNKNOWN_GEO",  severity: "medium", action: "reduce_trust",   detail: "Cannot resolve geolocation for this IP" });
        }

        return flags;
    }

    /** Persist a snapshot of this context to access_contexts for audit/anomaly */
    async persist(userId, context, deviceTrustScore) {
        const db = getDB();
        if (!db) return;
        try {
            await db.promise().query(
                `INSERT INTO access_contexts
                 (user_id, request_id, ip_address, geo_country, geo_city,
                  is_vpn, device_fingerprint, device_trust_score,
                  session_age_ms, current_hour, current_day, user_agent)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
                [
                    userId, context.requestId, context.ip,
                    context.geoCountry, context.geoCity,
                    context.isVPN ? 1 : 0,
                    context.deviceFingerprint, deviceTrustScore,
                    context.sessionAge, context.currentHour,
                    context.currentDay, context.userAgent.slice(0, 500),
                ]
            );
        } catch (e) {
            // Non-fatal — audit persists best-effort
            console.warn("[ContextBuilder] persist failed:", e.message);
        }
    }
}

module.exports = new ContextBuilder();
