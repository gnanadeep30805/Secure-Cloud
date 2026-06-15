/**
 * services/stepUpService.js
 * Issues and verifies step-up authentication challenges (TOTP or email OTP).
 * Used by RBA middleware when risk score requires additional verification.
 * No Redis — DB-backed challenges with expiry.
 */
const crypto    = require("crypto");
const bcrypt    = require("bcrypt");
const speakeasy = require("speakeasy");
const getDB     = require("../config/db");

class StepUpService {

    /**
     * Issue a step-up challenge.
     * @param {number} userId
     * @param {'totp'|'email_otp'} type
     * @returns {{ challengeId, type, expiresAt }}
     */
    async issueChallenge(userId, type = "totp") {
        const db = getDB();
        if (!db) throw new Error("Database not ready");

        const challengeId = crypto.randomUUID();
        const expiresAt   = new Date(Date.now() + 5 * 60 * 1000); // 5 min

        if (type === "email_otp") {
            const otp     = String(Math.floor(100000 + Math.random() * 900000));
            const otpHash = await bcrypt.hash(otp, 10);

            await db.promise().query(
                `INSERT INTO step_up_challenges
                 (user_id, challenge_id, type, otp_hash, expires_at)
                 VALUES (?,?,?,?,?)`,
                [userId, challengeId, "email_otp", otpHash, expiresAt]
            );

            // Send OTP — console fallback when SMTP not configured
            await this._sendOTP(userId, otp);
        } else {
            // TOTP — user uses their authenticator app, no OTP to store
            await db.promise().query(
                `INSERT INTO step_up_challenges
                 (user_id, challenge_id, type, expires_at)
                 VALUES (?,?,?,?)`,
                [userId, challengeId, "totp", expiresAt]
            );
        }

        return { challengeId, type, expiresAt };
    }

    /**
     * Verify a step-up challenge response.
     * @param {number} userId
     * @param {string} challengeId
     * @param {string} userInput — TOTP code or email OTP
     * @returns {{ valid: boolean, reason: string }}
     */
    async verifyChallenge(userId, challengeId, userInput) {
        const db = getDB();
        if (!db) return { valid: false, reason: "DB_NOT_READY" };

        const [rows] = await db.promise().query(
            `SELECT * FROM step_up_challenges
             WHERE challenge_id=? AND user_id=?
               AND completed=FALSE AND expires_at > NOW()`,
            [challengeId, userId]
        );

        if (rows.length === 0) {
            return { valid: false, reason: "CHALLENGE_INVALID_OR_EXPIRED" };
        }

        const challenge = rows[0];
        let valid = false;

        if (challenge.type === "totp") {
            // Query user's MFA secret (column is mfaSecret in this project)
            const [userRows] = await db.promise().query(
                "SELECT mfaSecret FROM users WHERE id=?", [userId]
            );
            if (userRows[0]?.mfaSecret) {
                valid = speakeasy.totp.verify({
                    secret:   userRows[0].mfaSecret,
                    encoding: "base32",
                    token:    userInput,
                    window:   1,
                });
            }
        } else {
            // Email OTP — compare hash
            valid = await bcrypt.compare(String(userInput), challenge.otp_hash);
        }

        if (valid) {
            await db.promise().query(
                "UPDATE step_up_challenges SET completed=TRUE WHERE challenge_id=?",
                [challengeId]
            );
        }

        return { valid, reason: valid ? "OK" : "WRONG_CODE" };
    }

    /**
     * Send OTP to user's email — falls back to console when SMTP not configured.
     */
    async _sendOTP(userId, otp) {
        const db = getDB();
        if (!db) return;

        const [userRows] = await db.promise().query(
            "SELECT email FROM users WHERE id=?", [userId]
        );
        const email = userRows[0]?.email;
        if (!email) return;

        // If SMTP is configured, send email
        if (process.env.SMTP_HOST && process.env.SMTP_USER) {
            try {
                const nodemailer  = require("nodemailer");
                const transporter = nodemailer.createTransport({
                    host: process.env.SMTP_HOST,
                    port: parseInt(process.env.SMTP_PORT || "587", 10),
                    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
                });
                await transporter.sendMail({
                    from:    process.env.SMTP_FROM || process.env.SMTP_USER,
                    to:      email,
                    subject: "SecureCloud — Step-up verification code",
                    text:    `Your one-time verification code is: ${otp}\n\nExpires in 5 minutes.`,
                });
                console.log(`[StepUp] Email OTP sent to ${email}`);
                return;
            } catch (e) {
                console.warn("[StepUp] SMTP failed, falling back to console:", e.message);
            }
        }

        // Dev fallback — print to console (same pattern as EMAIL_DEV_LOG)
        console.log(`\n${"=".repeat(50)}`);
        console.log(`[StepUp] EMAIL OTP for user ${userId} (${email}): ${otp}`);
        console.log(`${"=".repeat(50)}\n`);
    }
}

module.exports = new StepUpService();
