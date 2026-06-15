/**
 * services/notifier.js
 * Admin alerting for security events.
 * Uses SMTP if configured; falls back to console.log (EMAIL_DEV_LOG=true).
 */
const nodemailer = require("nodemailer");

class Notifier {
    _getTransport() {
        if (!process.env.SMTP_HOST || !process.env.SMTP_USER) return null;
        return nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT || "587", 10),
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });
    }

    async alertAdmin(detection, event) {
        const subject = `[SecureCloud] ${detection.severity.toUpperCase()} — ${detection.type}`;
        const body = [
            "Security event detected:",
            "",
            `Type:     ${detection.type}`,
            `Severity: ${detection.severity}`,
            `User ID:  ${event.userId ?? "unknown"}`,
            `IP:       ${event.ip    ?? "unknown"}`,
            `Country:  ${event.geoCountry ?? "unknown"}`,
            `Time:     ${new Date().toISOString()}`,
            `Detail:   ${JSON.stringify(detection.detail, null, 2)}`,
        ].join("\n");

        const transport = this._getTransport();
        if (transport && process.env.ADMIN_EMAIL) {
            try {
                await transport.sendMail({
                    from:    process.env.SMTP_FROM || process.env.SMTP_USER,
                    to:      process.env.ADMIN_EMAIL,
                    subject,
                    text:    body,
                });
                console.log(`[Notifier] Admin alerted via SMTP: ${detection.type}`);
            } catch (e) {
                console.warn("[Notifier] SMTP failed, falling back to console:", e.message);
                console.warn(`\n${"=".repeat(60)}\n${subject}\n${body}\n${"=".repeat(60)}\n`);
            }
        } else {
            // Dev mode — print to console
            console.warn(`\n${"=".repeat(60)}\n${subject}\n${body}\n${"=".repeat(60)}\n`);
        }
    }
}

module.exports = new Notifier();
