/**
 * services/abacService.js
 * Attribute-Based Access Control — fine-grained policy evaluation.
 * Evaluates subject attributes, resource attributes, and environment conditions.
 * No Redis — in-memory TTL cache.
 */
const getDB = require("../config/db");

// ── In-memory cache ─────────────────────────────────────────────
const _cache = new Map();
function _get(k) { const e = _cache.get(k); if (!e) return undefined; if (Date.now() > e.exp) { _cache.delete(k); return undefined; } return e.val; }
function _set(k, v, ttl = 5 * 60 * 1000) { _cache.set(k, { val: v, exp: Date.now() + ttl }); }
function _del(k) { _cache.delete(k); }
setInterval(() => { const n = Date.now(); for (const [k, v] of _cache) { if (n > v.exp) _cache.delete(k); } }, 5 * 60 * 1000).unref();

class ABACService {

    /**
     * Main evaluation — check all applicable ABAC policies.
     * Deny-first: any matching deny policy wins immediately.
     */
    async evaluate(subject, resource, action, environment) {
        const policies = await this.getApplicablePolicies(
            resource.type ?? "file", action
        );

        let finalDecision = "NO_ABAC_POLICY"; // default — defer to RBAC

        for (const policy of policies) {
            const match = this._matchesPolicy(policy, subject, resource, environment);
            if (!match) continue;

            if (policy.effect === "deny") {
                return { permit: false, reason: `ABAC_DENY:${policy.name}`, policy: policy.name };
            }
            if (policy.effect === "permit") {
                finalDecision = "PERMIT";
            }
        }

        return {
            permit: finalDecision === "PERMIT" || finalDecision === "NO_ABAC_POLICY",
            reason: finalDecision,
            policy: null,
        };
    }

    // ── POLICY MATCHING ─────────────────────────────────────────

    _matchesPolicy(policy, subject, resource, environment) {
        const subCond = typeof policy.subject_conditions === "string"
            ? JSON.parse(policy.subject_conditions) : (policy.subject_conditions ?? {});
        const resCond = typeof policy.resource_conditions === "string"
            ? JSON.parse(policy.resource_conditions) : (policy.resource_conditions ?? {});
        const envCond = typeof policy.env_conditions === "string"
            ? JSON.parse(policy.env_conditions || "{}") : (policy.env_conditions ?? {});

        return (
            this._matchConditions(subCond, subject) &&
            this._matchConditions(resCond, resource) &&
            this._matchEnvConditions(envCond, environment)
        );
    }

    _matchConditions(conditions, attributes) {
        for (const [key, expected] of Object.entries(conditions)) {
            const actual = attributes[key];
            if (actual === undefined) return false;
            if (Array.isArray(expected)) {
                if (!expected.includes(actual)) return false;
            } else {
                if (actual !== expected) return false;
            }
        }
        return true;
    }

    _matchEnvConditions(conditions, environment) {
        if (!conditions || Object.keys(conditions).length === 0) return true;
        for (const [key, expected] of Object.entries(conditions)) {
            switch (key) {
                case "business_hours":
                    if (expected && !environment.isBusinessHours) return false;
                    if (!expected && environment.isBusinessHours) return false;
                    break;
                case "allow_vpn":
                    if (!expected && environment.isVPN) return false;
                    break;
                case "allowed_countries":
                    if (Array.isArray(expected) && !expected.includes(environment.geoCountry)) return false;
                    break;
                case "max_risk_score":
                    if (environment.riskScore > expected) return false;
                    break;
                default:
                    if (environment[key] !== expected) return false;
            }
        }
        return true;
    }

    // ── DEPT-LEVEL OWNERSHIP CHECK (secret files) ───────────────

    async checkDeptAccess(userId, fileId) {
        const db = getDB();
        if (!db) return false;
        try {
            const [rows] = await db.promise().query(
                `SELECT fa.owner_dept, fa.allowed_depts, ua.department
                 FROM   file_attributes fa
                 JOIN   user_attributes ua ON ua.user_id = ?
                 WHERE  fa.file_id = ?`,
                [userId, fileId]
            );
            if (rows.length === 0) return true; // no attributes → allow
            const { owner_dept, allowed_depts, department } = rows[0];
            if (allowed_depts) {
                const list = typeof allowed_depts === "string" ? JSON.parse(allowed_depts) : allowed_depts;
                return list.includes(department);
            }
            return department === owner_dept;
        } catch { return true; }
    }

    // ── FILE EXPIRY CHECK ───────────────────────────────────────

    async isFileAccessible(fileId) {
        const db = getDB();
        if (!db) return true;
        try {
            const [rows] = await db.promise().query(
                "SELECT expires_at FROM file_attributes WHERE file_id=?", [fileId]
            );
            if (rows.length === 0 || !rows[0].expires_at) return true;
            return new Date() < new Date(rows[0].expires_at);
        } catch { return true; }
    }

    // ── LOAD SUBJECT ATTRIBUTES ─────────────────────────────────

    async getSubjectAttributes(userId) {
        const cacheKey = `abac:sub:${userId}`;
        const cached = _get(cacheKey);
        if (cached !== undefined) return cached;

        const db = getDB();
        if (!db) return { department: "general", clearance_level: "internal", account_type: "internal" };

        try {
            const [rows] = await db.promise().query(
                `SELECT ua.department, ua.clearance_level,
                        ua.job_title, ua.location, ua.account_type
                 FROM   user_attributes ua
                 WHERE  ua.user_id = ?`,
                [userId]
            );
            const attrs = rows[0] ?? {
                department: "general", clearance_level: "internal", account_type: "internal",
            };
            _set(cacheKey, attrs);
            return attrs;
        } catch {
            return { department: "general", clearance_level: "internal", account_type: "internal" };
        }
    }

    // ── LOAD RESOURCE ATTRIBUTES ────────────────────────────────

    async getResourceAttributes(fileId) {
        if (!fileId) return { sensitivity: "internal", shareable: true };

        const cacheKey = `abac:res:${fileId}`;
        const cached = _get(cacheKey);
        if (cached !== undefined) return cached;

        const db = getDB();
        if (!db) return { sensitivity: "internal", shareable: true };

        try {
            const [rows] = await db.promise().query(
                "SELECT * FROM file_attributes WHERE file_id=?", [fileId]
            );
            const attrs = rows[0] ?? { sensitivity: "internal", shareable: true };
            _set(cacheKey, attrs, 2 * 60 * 1000);
            return attrs;
        } catch {
            return { sensitivity: "internal", shareable: true };
        }
    }

    // ── FETCH APPLICABLE POLICIES ───────────────────────────────

    async getApplicablePolicies(resourceType, action) {
        const cacheKey = `abac:pol:${resourceType}:${action}`;
        const cached = _get(cacheKey);
        if (cached !== undefined) return cached;

        const db = getDB();
        if (!db) return [];

        try {
            const [rows] = await db.promise().query(
                `SELECT * FROM abac_policies
                 WHERE resource_type=? AND action=? AND is_active=TRUE
                 ORDER BY priority ASC`,
                [resourceType, action]
            );
            _set(cacheKey, rows);
            return rows;
        } catch { return []; }
    }

    // ── CACHE BUST ──────────────────────────────────────────────

    bustCaches(userId, fileId) {
        if (userId) _del(`abac:sub:${userId}`);
        if (fileId) _del(`abac:res:${fileId}`);
        // Clear all policy caches
        for (const k of _cache.keys()) {
            if (k.startsWith("abac:pol:")) _cache.delete(k);
        }
    }
}

module.exports = new ABACService();
