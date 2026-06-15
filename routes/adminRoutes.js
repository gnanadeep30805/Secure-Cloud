/**
 * routes/adminRoutes.js
 * Admin API endpoints for managing roles, user attributes, file sensitivity, and ABAC policies.
 * All routes require: authMiddleware → PEP(admin, admin_panel)
 */
const express        = require("express");
const router         = express.Router();
const authMiddleware = require("../middleware/authMiddleware");
const pep            = require("../middleware/pepMiddleware");
const rbacService    = require("../services/rbacService");
const abacService    = require("../services/abacService");
const getDB          = require("../config/db");

// Admin gate: JWT+lock check → PEP(admin, system)
const adminGate = [authMiddleware, pep("admin", "system")];

// ── ROLE MANAGEMENT ─────────────────────────────────────────────

// Assign role to user
router.post("/users/:userId/role", ...adminGate, async (req, res) => {
    try {
        const { role, expiresAt } = req.body;
        if (!["admin", "editor", "viewer", "guest"].includes(role)) {
            return res.status(400).json({ error: "Invalid role" });
        }
        await rbacService.assignRole(
            parseInt(req.params.userId), role, req.user.id, expiresAt ?? null
        );
        res.json({ message: `Role '${role}' assigned to user ${req.params.userId}` });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get all role permissions
router.get("/permissions", ...adminGate, async (req, res) => {
    try {
        const db = getDB();
        const [rows] = await db.promise().query(
            "SELECT * FROM role_permissions ORDER BY role, resource_type, action"
        );
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get a specific user's effective role
router.get("/users/:userId/role", ...adminGate, async (req, res) => {
    try {
        const role = await rbacService.getUserRole(parseInt(req.params.userId));
        res.json({ userId: parseInt(req.params.userId), role });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── USER ATTRIBUTES (ABAC) ──────────────────────────────────────

// Update user attributes (department, clearance, account type)
router.put("/users/:userId/attributes", ...adminGate, async (req, res) => {
    try {
        const { department, clearance_level, account_type, job_title, location } = req.body;
        const db = getDB();
        await db.promise().query(
            `INSERT INTO user_attributes (user_id, department, clearance_level, account_type, job_title, location)
             VALUES (?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE
               department=VALUES(department), clearance_level=VALUES(clearance_level),
               account_type=VALUES(account_type), job_title=VALUES(job_title), location=VALUES(location)`,
            [parseInt(req.params.userId),
             department ?? "general", clearance_level ?? "internal",
             account_type ?? "internal", job_title ?? null, location ?? null]
        );
        abacService.bustCaches(parseInt(req.params.userId), null);
        res.json({ message: "User attributes updated" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get user attributes
router.get("/users/:userId/attributes", ...adminGate, async (req, res) => {
    try {
        const attrs = await abacService.getSubjectAttributes(parseInt(req.params.userId));
        res.json(attrs);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── FILE ATTRIBUTES (sensitivity) ───────────────────────────────

// Update file sensitivity
router.put("/files/:fileId/sensitivity", ...adminGate, async (req, res) => {
    try {
        const { sensitivity, allowed_depts, expires_at } = req.body;
        const db = getDB();
        await db.promise().query(
            `INSERT INTO file_attributes (file_id, sensitivity, allowed_depts, expires_at)
             VALUES (?,?,?,?)
             ON DUPLICATE KEY UPDATE
               sensitivity=VALUES(sensitivity), allowed_depts=VALUES(allowed_depts), expires_at=VALUES(expires_at)`,
            [parseInt(req.params.fileId),
             sensitivity ?? "internal",
             allowed_depts ? JSON.stringify(allowed_depts) : null,
             expires_at ?? null]
        );
        abacService.bustCaches(null, parseInt(req.params.fileId));
        res.json({ message: "File sensitivity updated" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── ABAC POLICIES ───────────────────────────────────────────────

// Create ABAC policy
router.post("/policies/abac", ...adminGate, async (req, res) => {
    try {
        const { name, resource_type, action, subject_conditions,
                resource_conditions, env_conditions, effect, priority } = req.body;
        const db = getDB();
        const [result] = await db.promise().query(
            `INSERT INTO abac_policies
             (name, resource_type, action, subject_conditions,
              resource_conditions, env_conditions, effect, priority)
             VALUES (?,?,?,?,?,?,?,?)`,
            [name, resource_type, action,
             JSON.stringify(subject_conditions ?? {}),
             JSON.stringify(resource_conditions ?? {}),
             JSON.stringify(env_conditions ?? {}),
             effect ?? "permit", priority ?? 10]
        );
        abacService.bustCaches(null, null);
        res.json({ id: result.insertId, message: "ABAC policy created" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// List active ABAC policies
router.get("/policies/abac", ...adminGate, async (req, res) => {
    try {
        const db = getDB();
        const [rows] = await db.promise().query(
            "SELECT * FROM abac_policies WHERE is_active=TRUE ORDER BY priority ASC"
        );
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

module.exports = router;
