/**
 * middleware/pepMiddleware.js  — Policy Enforcement Point
 *
 * Full pipeline per request:
 *   contextBuilder.build()
 *   → getContextConstraints()  [VPN / off-hours / stale-session / unknown-geo flags]
 *   → deviceService.getTrustScore()
 *   → impossibleTravel check   [hard-deny]
 *   → riskEngine.calculate()
 *   → rbacService.getUserRole() [map user to RBAC role]
 *   → accessController.check() [RBAC → ABAC → Policy Engine]
 *   → contextBuilder.persist() [audit snapshot]
 *   → deviceService.updateLastSeen()
 *   → auditService.log + logActivity [dual-write audit]
 *   → DENY 403 | PERMIT next()
 */
const accessController = require("../services/accessController");
const rbacService      = require("../services/rbacService");
const riskEngine       = require("../services/riskEngine");
const deviceService    = require("../services/deviceService");
const contextBuilder   = require("../services/contextBuilder");
const auditService     = require("../services/auditService");
const eventBus         = require("../services/eventBus");
const { logActivity }  = require("../utils/activity");

const pep = (action, resourceType = "file") => {
    return async (req, res, next) => {
        try {
            const userId      = req.user?.id;
            const fingerprint = req.headers["x-device-fingerprint"] ?? null;

            if (!userId) {
                return res.status(401).json({ error: "Unauthorized", code: "ZTA_NO_USER" });
            }

            // 1. Build full request context (IP, geo, time, session, device fp)
            const context = await contextBuilder.build(req);

            // 2. Derive context constraint flags
            const constraints  = contextBuilder.getContextConstraints(context);
            const contextFlags = constraints.map((c) => c.type);

            // 3. Device trust score (0-100) — register unknown device as low-trust
            const deviceTrustScore = await deviceService.getTrustScore(
                userId, fingerprint, context
            );

            // 4. Impossible travel — hard deny, no policy override
            const impossibleTravel = await deviceService.checkImpossibleTravel(
                userId, context.geoCountry, new Date()
            );
            if (impossibleTravel) {
                logActivity(userId, "zta_impossible_travel_denied", JSON.stringify({ ip: context.ip, country: context.geoCountry }));
                return res.status(403).json({
                    error: "Access denied — impossible travel detected",
                    code:  "IMPOSSIBLE_TRAVEL",
                });
            }

            // 5. Stale session — soft flag (raises risk, not hard-block)

            // 6. Risk score — reuses RBA's cached base score + contextFlag adjustments
            const riskScore = await riskEngine.calculate(userId, context, contextFlags);

            // 7. Get user's RBAC role (from user_roles table or users.role fallback)
            const userRole = await rbacService.getUserRole(userId);

            // 8. Build enriched context for access controller
            const enrichedContext = {
                ...context,
                contextFlags,
                mfaVerified:    req.user.mfaVerified === true,
                isBusinessHours: (() => {
                    const h = context.currentHour ?? new Date().getHours();
                    const d = context.currentDay ?? new Date().getDay();
                    return h >= 9 && h < 18 && d >= 1 && d <= 5;
                })(),
            };

            // 9. Full RBAC → ABAC → Policy Engine evaluation
            const fileId = req.params?.id ?? req.params?.fileId ?? req.body?.fileId ?? null;
            const decision = await accessController.check({
                userId,
                userRole,
                fileId,
                resourceType,
                action,
                context:          enrichedContext,
                riskScore,
                deviceTrustScore,
            });

            // 10. Persist context snapshot for audit / anomaly analysis
            await contextBuilder.persist(userId, context, deviceTrustScore);

            // 11. Update device last-seen timestamp
            if (fingerprint) {
                await deviceService.updateLastSeen(userId, fingerprint, context);
            }

            // 12. Audit log (dual-write): audit_logs (tamper-evident) + user_activities (feed)
            const outcome = decision.permit ? "permitted" : "denied";
            auditService.log({
                userId,
                action:           `zta_${action}`,
                resourceType,
                resourceId:       fileId,
                outcome,
                reason:           decision.reason,
                riskScore,
                deviceTrustScore,
                ip:               context.ip,
                geoLocation:      `${context.geoCity}, ${context.geoCountry}`,
                isVPN:            context.isVPN,
                userAgent:        context.userAgent,
                sessionAgeMin:    context.sessionAgeMin,
                contextFlags,
            });
            logActivity(
                userId,
                `zta_${action}_${outcome}`,
                JSON.stringify({
                    reason: decision.reason, layer: decision.layer,
                    riskScore, deviceTrustScore, userRole,
                    ip: context.ip, geo: `${context.geoCity}, ${context.geoCountry}`,
                    isVPN: context.isVPN, contextFlags,
                })
            );

            // 13. Enforce — emit event on deny
            if (!decision.permit) {
                eventBus.accessDenied({
                    userId, ip: context.ip, geoCountry: context.geoCountry,
                    action, reason: decision.reason, layer: decision.layer,
                });
                return res.status(403).json({
                    error:  "Access denied",
                    reason: decision.reason,
                    layer:  decision.layer,
                    code:   "ACCESS_DENIED",
                });
            }

            // 14. Attach full ZTA context for downstream handlers
            req.ztaContext = {
                userId, userRole, decision,
                subjectAttrs:   decision.subjectAttrs,
                resourceAttrs:  decision.resourceAttrs,
                riskScore, deviceTrustScore, contextFlags, context,
            };
            next();

        } catch (err) {
            console.error("[PEP] Error:", err.message);
            return res.status(403).json({
                error: "Access evaluation failed",
                code:  "ZTA_PEP_ERROR",
            });
        }
    };
};

module.exports = pep;
