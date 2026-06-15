const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { verifyTotp } = require("../utils/totp");
const eventBus    = require("../services/eventBus");
const auditService = require("../services/auditService");

//SIGNUP
exports.signup = async (req, res) => {
    try {
        let { username, email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
        }
        if (!username || String(username).trim() === "") {
            username = String(email).split("@")[0] || "user";
        }

        User.findByEmail(email, async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message || "Database error" });
            }

            if (results && results.length > 0) {
                return res.status(400).json({ error: "User already exists" });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const secret = speakeasy.generateSecret({ name: `SecureCloud:${username}@${email}`, length: 20 });

            User.create(
                username,
                email,
                hashedPassword,
                secret.base32,
                async (err) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }

                    try {
                        const qrCode = await QRCode.toDataURL(secret.otpauth_url);
                        return res.status(201).json({
                            message: "User registered successfully",
                            qrCodeUrl: `/qr/${encodeURIComponent(email)}`,
                            qrImageDataUrl: qrCode
                        });
                    } catch (innerErr) {
                        console.error("QRCode generation error:", innerErr);
                        return res.status(500).json({ error: innerErr.message || "QR code generation error" });
                    }
                }
            );
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/** Info only — reset uses Google Authenticator (same secret as login), not email. */
exports.forgotPassword = (req, res) => {
    res.json({
        message:
            "Use the reset form with your email, new password, and the current 6-digit code from Google Authenticator.",
    });
};

exports.resetPassword = async (req, res) => {
    try {
        const { email, token, newPassword } = req.body || {};
        if (!email || !token || !newPassword) {
            return res.status(400).json({
                error: "Email, token (Authenticator code), and newPassword are required",
            });
        }
        if (String(newPassword).length < 8) {
            return res.status(400).json({ error: "Password must be at least 8 characters" });
        }

        User.findByEmail(email, async (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!results || results.length === 0) {
                return res.status(400).json({ error: "Invalid email or authenticator code" });
            }
            const user = results[0];
            if (!user.mfaSecret || !verifyTotp(user.mfaSecret, token)) {
                return res.status(400).json({ error: "Invalid authenticator code" });
            }

            const hashed = await bcrypt.hash(newPassword, 10);
            User.updatePasswordByEmail(email, hashed, (e3) => {
                if (e3) return res.status(500).json({ error: e3.message });
                return res.json({ message: "Password updated. You can sign in now." });
            });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

//LOGIN
exports.login = async (req, res) => {
    try {
        const { email, password, token } = req.body;

        if (!email || !password || !token) {
            return res.status(400).json({ msg: "Email, password & OTP required" });
        }

        User.findByEmail(email, async (err, results) => {
            if (err) return res.status(500).json({ error: err.message });

            if (results.length === 0) {
                return res.status(400).json({ msg: "User not found" });
            }

            const user = results[0];

            // Block locked accounts (set by anomaly detector on critical events)
            if (user.status === "locked") {
                auditService.log({ userId: user.id, action: "login", outcome: "denied",
                    reason: "account_locked", ip: req.ip, userAgent: req.headers["user-agent"] });
                return res.status(403).json({ msg: "Account locked due to suspicious activity. Contact admin." });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                eventBus.authFailure({ ip: req.ip, userId: user.id, reason: "BAD_PASSWORD" });
                auditService.log({ userId: user.id, action: "login", outcome: "failure",
                    reason: "invalid_password", ip: req.ip, userAgent: req.headers["user-agent"] });
                return res.status(400).json({ msg: "Invalid password (use your account password, not the OTP)" });
            }

            const verified = verifyTotp(user.mfaSecret, token);

            if (!verified) {
                eventBus.totpFailure({ ip: req.ip, userId: user.id });
                auditService.log({ userId: user.id, action: "login_totp", outcome: "failure",
                    reason: "invalid_totp", ip: req.ip, userAgent: req.headers["user-agent"] });
                return res.status(400).json({ msg: "Invalid OTP (use the 6-digit code from Google Authenticator)" });
            }

            const ip = req.ip || req.connection.remoteAddress || "unknown_ip";
            const ua = req.headers['user-agent'] || "unknown_ua";
            const sessionHash = require("crypto").createHash("sha256").update(ip + ua).digest("hex");

            const jwtToken = jwt.sign(
                { id: user.id, role: user.role || "user", shash: sessionHash, mfaVerified: true },
                process.env.JWT_SECRET,
                { expiresIn: "24h" }
            );

            // Emit success event to anomaly detector (new geo, concurrent session checks)
            const ctxIp = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.ip || "0.0.0.0";
            let geoCountry = "UNKNOWN";
            try {
                const geoip = require("geoip-lite");
                geoCountry = geoip.lookup(ctxIp)?.country ?? "UNKNOWN";
            } catch { /* geoip optional */ }
            eventBus.authSuccess({ ip: ctxIp, userId: user.id, geoCountry });
            auditService.log({ userId: user.id, action: "login", outcome: "success",
                ip: ctxIp, userAgent: req.headers["user-agent"],
                geoLocation: geoCountry });

            return res.status(200).json({
                message: "Login successful",
                token: jwtToken
            });
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};