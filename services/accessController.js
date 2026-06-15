/**
 * services/accessController.js
 * Unified access decision — orchestrates RBAC → ABAC → Policy Engine.
 * Called by PEP middleware for every protected request.
 */
const rbacService  = require("./rbacService");
const abacService  = require("./abacService");
const policyEngine = require("./policyEngine");
const auditService = require("./auditService");

class AccessController {

    /**
     * Full 3-layer access check: RBAC → ABAC → Policy Engine.
     */
    async check({ userId, userRole, fileId, resourceType, action, context, riskScore, deviceTrustScore }) {
        const startTime = Date.now();

        // ── STEP 1: RBAC — coarse-grained role permission ────────
        const rbacAllowed = await rbacService.hasPermission(userRole, resourceType, action);

        if (!rbacAllowed) {
            auditService.log({
                userId, action: `rbac_${action}`, resourceType, resourceId: fileId,
                outcome: "denied", reason: `RBAC_DENIED:role=${userRole}`,
                riskScore, deviceTrustScore, durationMs: Date.now() - startTime,
            });
            return { permit: false, reason: "RBAC_DENIED", layer: "RBAC" };
        }

        // ── STEP 2: ABAC — fine-grained attribute checks ─────────
        const subjectAttrs  = await abacService.getSubjectAttributes(userId);
        const resourceAttrs = await abacService.getResourceAttributes(fileId);

        // File expiry check
        if (fileId) {
            const accessible = await abacService.isFileAccessible(fileId);
            if (!accessible) {
                return { permit: false, reason: "FILE_ACCESS_EXPIRED", layer: "ABAC" };
            }
        }

        // Dept-level access for secret files
        if (resourceAttrs.sensitivity === "secret" && fileId) {
            const deptAllowed = await abacService.checkDeptAccess(userId, fileId);
            if (!deptAllowed) {
                auditService.log({
                    userId, action: `abac_${action}`, resourceType, resourceId: fileId,
                    outcome: "denied", reason: "ABAC_DEPT_MISMATCH",
                    riskScore, deviceTrustScore, durationMs: Date.now() - startTime,
                });
                return { permit: false, reason: "ABAC_DEPT_MISMATCH", layer: "ABAC" };
            }
        }

        // Determine business hours for env conditions
        const h = context.currentHour ?? new Date().getHours();
        const d = context.currentDay ?? new Date().getDay();
        const isBusinessHours = h >= 9 && h < 18 && d >= 1 && d <= 5;

        const environment = {
            isBusinessHours,
            isVPN:       context.isVPN ?? false,
            geoCountry:  context.geoCountry ?? "UNKNOWN",
            riskScore:   riskScore ?? 0,
        };

        const abacResult = await abacService.evaluate(
            subjectAttrs, resourceAttrs, action, environment
        );

        if (!abacResult.permit) {
            auditService.log({
                userId, action: `abac_${action}`, resourceType, resourceId: fileId,
                outcome: "denied", reason: abacResult.reason,
                riskScore, deviceTrustScore, durationMs: Date.now() - startTime,
            });
            return { permit: false, reason: abacResult.reason, layer: "ABAC" };
        }

        // ── STEP 3: Policy Engine — ZTA final gate ───────────────
        const subject = {
            userId,
            roles: rbacService.getRoleHierarchy(userRole),
            mfaVerified:     context.mfaVerified ?? true,
            deviceTrustScore: deviceTrustScore ?? 0,
            riskScore:       riskScore ?? 0,
            contextFlags:    context.contextFlags ?? [],
            ...subjectAttrs,
        };
        const resource = {
            type:   resourceType,
            fileId: fileId,
            ...resourceAttrs,
        };

        const peResult = await policyEngine.evaluate(subject, resource, action, context);
        const durationMs = Date.now() - startTime;

        return {
            permit:        peResult.permit,
            reason:        peResult.reason,
            layer:         peResult.permit ? "PERMITTED" : "PE",
            durationMs,
            subjectAttrs,
            resourceAttrs,
        };
    }
}

module.exports = new AccessController();
