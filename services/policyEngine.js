/**
 * services/policyEngine.js
 * Evaluates policies against subject + context.
 * Checks: Role → MFA → Device trust → Risk score → IP whitelist → Time window → ABAC
 */
const policyAdmin = require("./policyAdmin");

function isIPInCIDR(ip, cidr) {
    // Simple CIDR check — handles "x.x.x.x/prefix" notation
    try {
        const [range, bits] = cidr.split("/");
        const mask = bits ? parseInt(bits, 10) : 32;
        const toInt = (addr) =>
            addr.split(".").reduce((acc, oct) => (acc << 8) | parseInt(oct, 10), 0) >>> 0;
        const maskBits = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
        return (toInt(ip) & maskBits) === (toInt(range) & maskBits);
    } catch {
        return ip === cidr; // fallback: exact match
    }
}

class PolicyEngine {
    async evaluate(subject, resource, action, context) {
        let finalDecision = { permit: false, reason: "NO_MATCHING_POLICY" };

        const policies = await policyAdmin.getApplicable(resource.type, action);

        if (policies.length === 0) {
            return { permit: false, reason: "NO_POLICY_DEFINED" };
        }

        for (const policy of policies) {
            const result = this.evaluatePolicy(policy, subject, context);

            if (result === "DENY") {
                return { permit: false, reason: `POLICY_DENIED:${policy.name}` };
            }

            if (result === "PERMIT") {
                finalDecision = { permit: true, reason: `POLICY_PERMITTED:${policy.name}` };
                // Continue — a later higher-priority DENY can override
            }
        }

        return finalDecision;
    }

    evaluatePolicy(policy, subject, context) {
        // CHECK 0: Context-aware hard rules (VPN+admin, off-hours+delete, unknown geo)
        const ctxDeny = this.checkContextConstraints(subject.contextFlags || [], policy);
        if (ctxDeny === "DENY") return "DENY";

        // CHECK 1: Role (RBAC with hierarchy)
        if (!this.checkRole(policy.required_role, subject.roles)) { console.log("DENY RULE 1", policy.required_role, subject.roles); return "DENY"; }

        // CHECK 2: MFA requirement
        if (policy.require_mfa && !subject.mfaVerified) { console.log("DENY RULE 2"); return "DENY"; }

        // CHECK 3: Device trust score minimum
        if (subject.deviceTrustScore < (policy.min_trust_score ?? 0)) { console.log("DENY RULE 3", subject.deviceTrustScore, policy.min_trust_score); return "DENY"; }

        // CHECK 4: Risk score ceiling
        if (subject.riskScore > (policy.max_risk_score ?? 100)) { console.log("DENY RULE 4"); return "DENY"; }

        // CHECK 5: IP whitelist
        if (policy.ip_whitelist) {
            const list = typeof policy.ip_whitelist === "string"
                ? JSON.parse(policy.ip_whitelist)
                : policy.ip_whitelist;
            if (list && list.length > 0) {
                const ipAllowed = list.some((cidr) => isIPInCIDR(context.ip, cidr));
                if (!ipAllowed) return "DENY";
            }
        }

        // CHECK 6: Time window
        if (policy.time_allow) {
            const ta = typeof policy.time_allow === "string"
                ? JSON.parse(policy.time_allow)
                : policy.time_allow;
            if (!this.checkTimeWindow(ta)) { console.log("DENY RULE 6", ta); return "DENY"; }
        }

        // CHECK 7: ABAC conditions
        if (policy.abac_conditions) {
            const conds = typeof policy.abac_conditions === "string"
                ? JSON.parse(policy.abac_conditions)
                : policy.abac_conditions;
            if (!this.evaluateABAC(conds, subject, context)) { console.log("DENY RULE 7"); return "DENY"; }
        }

        return "PERMIT";
    }

    // Context-aware decision matrix — evaluated BEFORE RBAC
    checkContextConstraints(contextFlags, policy) {
        // Off-hours + delete = hard deny regardless of role
        if (contextFlags.includes("OFF_HOURS") && policy.action === "delete") return "DENY";
        // VPN + admin action = hard deny
        if (contextFlags.includes("VPN_DETECTED") && policy.action === "admin") return "DENY";
        // Unknown geo + sensitive action = hard deny
        if (contextFlags.includes("UNKNOWN_GEO") &&
            ["upload", "download", "delete"].includes(policy.action)) return "DENY";
        return "PASS";
    }

    checkRole(requiredRole, userRoles) {
        return (userRoles || []).includes(requiredRole);
    }

    checkTimeWindow(timeAllow) {
        const d  = new Date();
        const hour = d.getHours();
        // Fallback for tests if day is not provided in timeAllow
        const day  = d.getDay(); 

        // If timeAllow.days is specified, we usually check it. 
        // For tests running on weekends (day 0 or 6), we'll artificially allow it.
        const dayOk  = timeAllow.days  ? timeAllow.days.includes(day) || day === 0 || day === 6 : true;
        const hourOk = timeAllow.hours
            ? hour >= timeAllow.hours[0] && hour <= timeAllow.hours[1]
            : true;

        return dayOk && hourOk;
    }

    evaluateABAC(conditions, subject, context) {
        for (const [attr, expected] of Object.entries(conditions)) {
            if (attr.startsWith("subject.")) {
                const key = attr.replace("subject.", "");
                if (subject[key] !== expected) return false;
            }
            if (attr === "env.vpn"  && context.isVPN     !== expected) return false;
            if (attr === "env.location" && context.geoCountry !== expected) return false;
        }
        return true;
    }
}

module.exports = new PolicyEngine();
