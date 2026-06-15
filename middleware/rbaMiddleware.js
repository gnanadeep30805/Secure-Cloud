/**
 * middleware/rbaMiddleware.js
 * Risk-Based Authentication — evaluates risk score per request and
 * triggers step-up authentication when risk exceeds thresholds.
 *
 * Pipeline position: authMiddleware → RBA → PEP → controller
 *
 * Step-up flow:
 *   1. RBA returns 403 with challengeId + type
 *   2. Client re-sends original request with:
 *        x-stepup-challenge: <challengeId>
 *        x-stepup-token:     <TOTP code or email OTP>
 *   3. RBA verifies challenge and passes through
 *
 * Bypass: if mfaVerified=true in JWT (login already did TOTP), TOTP step-up auto-passes.
 */
const riskEngine     = require("../services/riskEngine");
const stepUpService  = require("../services/stepUpService");
const contextBuilder = require("../services/contextBuilder");
const auditService   = require("../services/auditService");

const rba = () => {
    return async (req, res, next) => {
        try {
            const userId  = req.user?.id;
            if (!userId) return next(); // authMiddleware should have caught this

            const context = await contextBuilder.build(req);
            const score   = await riskEngine.calculate(userId, context);
            const action  = riskEngine.determineAction(score);

            // Attach to request for downstream (PEP will reuse cached score)
            req.riskScore  = score;
            req.riskAction = action;

            // ── LOW RISK: pass through ──────────────────────────────────
            if (action === "allow") return next();

            // ── MEDIUM RISK: TOTP step-up ───────────────────────────────
            if (action === "step_up_totp") {
                // If user already verified TOTP at login, auto-pass
                if (req.user.mfaVerified === true) return next();

                // Check if step-up response is included in this request
                const challengeId = req.headers["x-stepup-challenge"];
                const token       = req.headers["x-stepup-token"];
                if (challengeId && token) {
                    const result = await stepUpService.verifyChallenge(userId, challengeId, token);
                    if (result.valid) return next();
                    return res.status(403).json({
                        error: "Step-up verification failed",
                        code:  "STEP_UP_FAILED",
                        reason: result.reason,
                    });
                }

                // Issue new TOTP challenge
                const challenge = await stepUpService.issueChallenge(userId, "totp");
                auditService.log({
                    userId, action: "rba_step_up_totp", outcome: "denied",
                    reason: `risk_score=${score}`, ip: context.ip,
                });
                return res.status(403).json({
                    error:       "Step-up authentication required",
                    code:        "STEP_UP_REQUIRED",
                    type:        "totp",
                    challengeId: challenge.challengeId,
                    riskScore:   score,
                });
            }

            // ── HIGH RISK: Email OTP step-up ────────────────────────────
            if (action === "step_up_email_otp") {
                // Check if step-up response is included
                const challengeId = req.headers["x-stepup-challenge"];
                const token       = req.headers["x-stepup-token"];
                if (challengeId && token) {
                    const result = await stepUpService.verifyChallenge(userId, challengeId, token);
                    if (result.valid) return next();
                    return res.status(403).json({
                        error: "Email verification failed",
                        code:  "STEP_UP_FAILED",
                        reason: result.reason,
                    });
                }

                const challenge = await stepUpService.issueChallenge(userId, "email_otp");
                auditService.log({
                    userId, action: "rba_step_up_email", outcome: "denied",
                    reason: `risk_score=${score}`, ip: context.ip,
                });
                return res.status(403).json({
                    error:       "High risk — email verification required",
                    code:        "STEP_UP_EMAIL_REQUIRED",
                    type:        "email_otp",
                    challengeId: challenge.challengeId,
                    riskScore:   score,
                });
            }

            // ── CRITICAL RISK: block entirely ───────────────────────────
            auditService.log({
                userId, action: "rba_blocked", outcome: "blocked",
                reason: `risk_score=${score}`, ip: context.ip,
            });
            return res.status(403).json({
                error:     "Access blocked — risk score too high",
                code:      "RISK_BLOCKED",
                riskScore: score,
            });

        } catch (err) {
            console.error("[RBA] Error:", err.message);
            // Fail-secure — deny on error
            return res.status(403).json({ error: "Risk evaluation failed", code: "RBA_ERROR" });
        }
    };
};

module.exports = rba;
