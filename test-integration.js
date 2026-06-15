/**
 * Full-stack integration test — exercises every security layer including RBAC and ABAC.
 * Requires server NOT to be running (shares DB connection).
 */
require("dotenv").config();
const getDB = require("./config/db");

getDB.onReady(async () => {
    const pool = getDB().promise();
    let passed = 0;
    let failed = 0;
    let testUserId = null;

    function ok(name)      { passed++; console.log(`  ✅ ${name}`); }
    function fail(name, e) { failed++; console.error(`  ❌ ${name}: ${e}`); }

    console.log("\n══════════════════════════════════════════════════");
    console.log("  FULL INTEGRATION TEST (WITH RBAC+ABAC)");
    console.log("══════════════════════════════════════════════════\n");

    // ── SETUP: create a test user for FK constraints ────────────────
    try {
        const bcrypt = require("bcrypt");
        const hash = await bcrypt.hash("TestPass123!", 10);
        await pool.query(
            "INSERT INTO users (username, email, password, mfaSecret, role) VALUES (?,?,?,?,?)",
            ["_test_user_", "_test@integration.local", hash, "JBSWY3DPEHPK3PXP", "user"]
        );
        const [rows] = await pool.query("SELECT id FROM users WHERE email='_test@integration.local'");
        testUserId = rows[0].id;
        ok(`Test user created (id=${testUserId})`);
    } catch (e) {
        const [rows] = await pool.query("SELECT id FROM users WHERE email='_test@integration.local'");
        if (rows.length > 0) { testUserId = rows[0].id; ok(`Test user exists (id=${testUserId})`); }
        else { fail("setup", e.message); process.exit(1); }
    }

    // ── 1. DATABASE TABLES (18) ─────────────────────────────────────
    console.log("\n── 1. Database Tables ──");
    const expectedTables = [
        "users", "files", "email_verifications", "user_activities",
        "policies", "trusted_devices", "access_contexts",
        "audit_logs", "security_events", "rate_limit_violations",
        "risk_scores", "step_up_challenges",
        "roles", "role_permissions", "user_attributes",
        "file_attributes", "abac_policies", "user_roles"
    ];
    for (const t of expectedTables) {
        try { await pool.query(`SELECT 1 FROM ${t} LIMIT 0`); ok(`'${t}'`); }
        catch (e) { fail(`'${t}'`, e.message); }
    }

    // ── 2. RBAC SERVICE ──────────────────────────────────────────────
    console.log("\n── 2. RBAC Service ──");
    const rbacService = require("./services/rbacService");
    try {
        const adminUp = await rbacService.hasPermission("admin", "file", "upload");
        const guestUp = await rbacService.hasPermission("guest", "file", "upload");
        const editorUp = await rbacService.hasPermission("editor", "file", "upload");
        
        if (adminUp && !guestUp && editorUp) ok("hasPermission() handles hierarchy and permissions");
        else fail("hasPermission()", `admin=${adminUp}, guest=${guestUp}, editor=${editorUp}`);

        // Assign role test
        await rbacService.assignRole(testUserId, "editor", null);
        const uRole = await rbacService.getUserRole(testUserId);
        if (uRole === "editor") ok("assignRole() and getUserRole()");
        else fail("assignRole()", `got ${uRole} instead of editor`);

    } catch (e) { fail("rbacService", e.message); }

    // ── 3. ABAC SERVICE ──────────────────────────────────────────────
    console.log("\n── 3. ABAC Service ──");
    const abacService = require("./services/abacService");
    try {
        // Mock DB entries
        await pool.query(
            "INSERT IGNORE INTO user_attributes (user_id, clearance_level, department) VALUES (?, 'internal', 'engineering') ON DUPLICATE KEY UPDATE clearance_level='internal', department='engineering'",
            [testUserId]
        );
        const attrs = await abacService.getSubjectAttributes(testUserId);
        if (attrs.clearance_level === "internal") ok("getSubjectAttributes() works");
        else fail("getSubjectAttributes()", attrs.clearance_level);

        // evaluate rule (external user trying to download internal)
        const evalRes = await abacService.evaluate(
            { account_type: "external" },
            { type: "file", sensitivity: "internal" },
            "download",
            {}
        );
        // Should deny because external cannot download internal/confidential/secret
        if (evalRes.permit === false && evalRes.policy === "external_users_public_only") ok("evaluate() denies correctly based on policy");
        else fail("evaluate()", JSON.stringify(evalRes));

        const evalRes2 = await abacService.evaluate(
            { account_type: "internal", clearance_level: "internal" },
            { type: "file", sensitivity: "internal" },
            "download",
            {}
        );
        if (evalRes2.permit === true) ok("evaluate() permits correctly based on policy");
        else fail("evaluate()", JSON.stringify(evalRes2));

    } catch (e) { fail("abacService", e.message); }

    // ── 4. ACCESS CONTROLLER ────────────────────────────────────────
    console.log("\n── 4. Access Controller (RBAC->ABAC->PE) ──");
    const accessController = require("./services/accessController");
    try {
        const mockCtx = {
            ip: "127.0.0.1", geoCountry: "UNKNOWN",
            isBusinessHours: true, isVPN: false,
            mfaVerified: true,
        };
        
        const decision1 = await accessController.check({
            userId: testUserId, userRole: "editor", fileId: null,
            resourceType: "file", action: "upload", context: mockCtx,
            riskScore: 0, deviceTrustScore: 100
        });
        // editor can upload file
        if (decision1.permit) ok("Access Controller permits valid request");
        else fail("Access Controller", decision1.reason);

        const decision2 = await accessController.check({
            userId: testUserId, userRole: "guest", fileId: null,
            resourceType: "file", action: "upload", context: mockCtx,
            riskScore: 0, deviceTrustScore: 100
        });
        // guest cannot upload file (RBAC Deny)
        if (!decision2.permit && decision2.layer === "RBAC") ok("Access Controller denies correctly at RBAC layer");
        else fail("Access Controller", JSON.stringify(decision2));

    } catch (e) { fail("accessController", e.message); }

    // ── 5. EVENT BUS AND ANOMALY DETECTOR ───────────────────────────
    console.log("\n── 5. Anomaly Detector (start + listen) ──");
    try {
        const ad = require("./services/anomalyDetector");
        ad.start(); // wire listeners
        const eventBus = require("./services/eventBus");
        const events = ["auth.failure","totp.failure","auth.success","file.download","access.denied","rate.limit"];
        for (const e of events) {
            if (eventBus.listenerCount(e) >= 1) ok(`'${e}' → ${eventBus.listenerCount(e)} listener(s)`);
            else fail(e, "no listeners");
        }
    } catch (e) { fail("anomalyDetector", e.message); }

    // ── CLEANUP ─────────────────────────────────────────────────────
    try {
        await pool.query("DELETE FROM user_roles WHERE user_id=?", [testUserId]);
        await pool.query("DELETE FROM user_attributes WHERE user_id=?", [testUserId]);
        await pool.query("DELETE FROM step_up_challenges WHERE user_id=?", [testUserId]);
        await pool.query("DELETE FROM risk_scores WHERE user_id=?", [testUserId]);
        await pool.query("DELETE FROM audit_logs WHERE user_id=?", [testUserId]);
        await pool.query("DELETE FROM access_contexts WHERE user_id=?", [testUserId]);
        await pool.query("DELETE FROM trusted_devices WHERE user_id=?", [testUserId]);
        await pool.query("DELETE FROM users WHERE id=?", [testUserId]);
    } catch {}

    // ── SUMMARY ─────────────────────────────────────────────────────
    console.log("\n══════════════════════════════════════════════════");
    if (failed === 0) {
        console.log(`  ✅ ALL ${passed} TESTS PASSED`);
    } else {
        console.log(`  RESULTS: ${passed} passed, ${failed} failed`);
    }
    console.log("══════════════════════════════════════════════════\n");

    process.exit(failed > 0 ? 1 : 0);
});
