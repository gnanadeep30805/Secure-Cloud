/**
 * services/rbacService.js
 * Role-Based Access Control — coarse-grained permission checks.
 * Uses role_permissions table + role hierarchy.
 * No Redis — in-memory TTL cache.
 */
const getDB = require("../config/db");

// ── In-memory cache ─────────────────────────────────────────────
const _cache = new Map();
const CACHE_TTL = 10 * 60 * 1000; // 10 min

function _get(key) {
    const e = _cache.get(key);
    if (!e) return undefined;
    if (Date.now() > e.exp) { _cache.delete(key); return undefined; }
    return e.val;
}
function _set(key, val, ttl = CACHE_TTL) {
    _cache.set(key, { val, exp: Date.now() + ttl });
}
function _del(key) { _cache.delete(key); }

setInterval(() => {
    const now = Date.now();
    for (const [k, v] of _cache) { if (now > v.exp) _cache.delete(k); }
}, 5 * 60 * 1000).unref();

// ── Role hierarchy ──────────────────────────────────────────────
const ROLE_HIERARCHY = {
    admin:  ["admin", "editor", "viewer", "guest"],
    editor: ["editor", "viewer", "guest"],
    viewer: ["viewer", "guest"],
    guest:  ["guest"],
};

// Map existing DB roles (user/admin) → RBAC roles
const DB_ROLE_MAP = {
    admin: "admin",
    user:  "editor",   // default DB 'user' role maps to 'editor'
};

class RBACService {

    /**
     * Check if a specific role has permission for resource+action.
     */
    async isPermitted(role, resourceType, action) {
        const cacheKey = `rbac:${role}:${resourceType}:${action}`;
        const cached = _get(cacheKey);
        if (cached !== undefined) return cached;

        const db = getDB();
        if (!db) return false;

        try {
            const [rows] = await db.promise().query(
                `SELECT is_allowed FROM role_permissions
                 WHERE role=? AND resource_type=? AND action=?`,
                [role, resourceType, action]
            );
            const allowed = rows[0]?.is_allowed === 1;
            _set(cacheKey, allowed);
            return allowed;
        } catch { return false; }
    }

    /**
     * Role hierarchy — check all inherited roles.
     */
    getRoleHierarchy(role) {
        return ROLE_HIERARCHY[role] ?? ["guest"];
    }

    /**
     * Check if userRole (or any inherited role) has permission.
     */
    async hasPermission(userRole, resourceType, action) {
        const roles = this.getRoleHierarchy(userRole);
        for (const role of roles) {
            const permitted = await this.isPermitted(role, resourceType, action);
            if (permitted) return true;
        }
        return false;
    }

    /**
     * Get the user's highest active role from user_roles table.
     * Falls back to mapping from users.role column.
     */
    async getUserRole(userId) {
        const cacheKey = `user:role:${userId}`;
        const cached = _get(cacheKey);
        if (cached !== undefined) return cached;

        const db = getDB();
        if (!db) return "guest";

        try {
            // Check user_roles table first (explicit assignment)
            const [assigned] = await db.promise().query(
                `SELECT role FROM user_roles
                 WHERE user_id=?
                   AND (expires_at IS NULL OR expires_at > NOW())
                 ORDER BY FIELD(role,'admin','editor','viewer','guest') ASC
                 LIMIT 1`,
                [userId]
            );
            if (assigned.length > 0) {
                _set(cacheKey, assigned[0].role, 5 * 60 * 1000);
                return assigned[0].role;
            }

            // Fallback: map from users.role column
            const [user] = await db.promise().query(
                "SELECT role FROM users WHERE id=?", [userId]
            );
            const dbRole = user[0]?.role ?? "user";
            const mapped = DB_ROLE_MAP[dbRole] ?? "editor";
            _set(cacheKey, mapped, 5 * 60 * 1000);
            return mapped;
        } catch { return "guest"; }
    }

    /**
     * Assign a role to a user.
     */
    async assignRole(userId, role, assignedBy, expiresAt = null) {
        const db = getDB();
        if (!db) throw new Error("DB not ready");
        await db.promise().query(
            `INSERT INTO user_roles (user_id, role, assigned_by, expires_at)
             VALUES (?,?,?,?)
             ON DUPLICATE KEY UPDATE assigned_by=?, expires_at=?`,
            [userId, role, assignedBy, expiresAt, assignedBy, expiresAt]
        );
        _del(`user:role:${userId}`);
    }

    /**
     * Get all permissions for a role (for admin/frontend display).
     */
    async getRolePermissions(role) {
        const db = getDB();
        if (!db) return [];
        const [rows] = await db.promise().query(
            "SELECT * FROM role_permissions WHERE role=?", [role]
        );
        return rows;
    }
}

module.exports = new RBACService();
