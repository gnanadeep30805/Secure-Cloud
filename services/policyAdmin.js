/**
 * services/policyAdmin.js
 * Manages policies: DB persistence + in-memory TTL cache (no Redis required).
 */
const getDB = require("../config/db");

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
let _cache = null;
let _cacheExpiry = 0;

function dbP() {
    const pool = getDB();
    if (!pool) throw new Error("Database not ready");
    return pool.promise();
}

function invalidateCache() {
    _cache = null;
    _cacheExpiry = 0;
}

class PolicyAdminService {
    async getPolicies() {
        if (_cache && Date.now() < _cacheExpiry) return _cache;

        const [rows] = await dbP().query(
            "SELECT * FROM policies WHERE is_active = TRUE ORDER BY priority ASC"
        );
        _cache = rows;
        _cacheExpiry = Date.now() + CACHE_TTL_MS;
        return rows;
    }

    async getApplicable(resourceType, action) {
        const all = await this.getPolicies();
        return all.filter(
            (p) => p.resource_type === resourceType && p.action === action
        );
    }

    async createPolicy(data, adminId) {
        const [result] = await dbP().query(
            `INSERT INTO policies
             (name, resource_type, action, required_role, min_trust_score,
              max_risk_score, require_mfa, ip_whitelist, time_allow, abac_conditions, priority)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
            [
                data.name, data.resource_type, data.action,
                data.required_role, data.min_trust_score ?? 0,
                data.max_risk_score ?? 100, data.require_mfa ?? true,
                JSON.stringify(data.ip_whitelist ?? null),
                JSON.stringify(data.time_allow ?? null),
                JSON.stringify(data.abac_conditions ?? null),
                data.priority ?? 10,
            ]
        );
        invalidateCache();
        return result.insertId;
    }

    async updatePolicy(policyId, data) {
        await dbP().query(
            `UPDATE policies
             SET name=?, required_role=?, min_trust_score=?, max_risk_score=?,
                 require_mfa=?, ip_whitelist=?, time_allow=?, abac_conditions=?,
                 priority=?, version = version + 1
             WHERE id=?`,
            [
                data.name, data.required_role, data.min_trust_score,
                data.max_risk_score, data.require_mfa,
                JSON.stringify(data.ip_whitelist),
                JSON.stringify(data.time_allow),
                JSON.stringify(data.abac_conditions),
                data.priority, policyId,
            ]
        );
        invalidateCache();
    }

    async deactivatePolicy(policyId) {
        await dbP().query(
            "UPDATE policies SET is_active = FALSE WHERE id = ?",
            [policyId]
        );
        invalidateCache();
    }
}

module.exports = new PolicyAdminService();
