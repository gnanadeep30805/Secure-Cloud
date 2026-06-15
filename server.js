const express = require("express");
const path    = require("path");
const dotenv  = require("dotenv");
const cors    = require("cors");
const helmet  = require("helmet");
const speakeasy = require("speakeasy");
const QRCode  = require("qrcode");
const User    = require("./models/User");

dotenv.config();

// Pre-load or generate 4096-bit Server RSA Key Pair (Blocks sync on first boot)
const { loadOrGenerateServerKeys } = require("./utils/rsaKeys");
loadOrGenerateServerKeys();

const app = express();

// Middleware — body parsers first; JSON errors must be handled before routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text());

app.use((err, req, res, next) => {
    const msg = err && err.message ? String(err.message) : "";
    const isJsonBodyError =
        err &&
        (err.type === "entity.parse.failed" ||
            err instanceof SyntaxError ||
            (msg.includes("JSON") && (msg.includes("position") || msg.includes("Bad escaped"))));
    if (isJsonBodyError) {
        return res.status(400).json({
            error:
                "Invalid JSON body. Windows paths in JSON must use / or double backslashes (\\\\). For decrypt, use Body → form-data → key file (File), not raw JSON.",
            detail: msg
        });
    }
    next(err);
});

const threatGuard      = require("./middleware/threatGuard");
const anomalyDetector  = require("./services/anomalyDetector");

// Security headers
app.use(helmet({ contentSecurityPolicy: false }));

// Perimeter protection — runs before all routes
app.use(threatGuard.checkBlocklist);
app.use(threatGuard.detectSuspiciousPayload);

app.use(cors());

// DB Connection (HTTP server starts inside onReady after migrations)
const getDB = require("./config/db");

// Request logging middleware
app.use((req, res, next) => {
    console.log(`[LOG] ${req.method} ${req.path}`);
    next();
});

// Routes
const authRoutes = require("./routes/authRoutes");
const fileRoutes = require("./routes/fileRoutes");
const adminRoutes = require("./routes/adminRoutes");

// Routes — auth gets rate limiter, files get upload/download limiters in the router
app.use("/api/auth",  threatGuard.loginLimiter, authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/admin", adminRoutes);

app.get("/api/health", (req, res) => {
    res.json({ ok: true, service: "Secure Cloud API", ui: "/" });
});

const publicDir = path.join(__dirname, "frontend/public");

app.get("/", (req, res) => {
    res.sendFile(path.join(publicDir, "index.html"));
});

app.use(express.static(publicDir));

// QR Code route
app.get("/qr/:email", async (req, res) => {
    try {
        const email = decodeURIComponent(req.params.email);
        User.findByEmail(email, async (err, results) => {
            if (err) {
                return res.status(500).send('Database error');
            }
            if (!results || results.length === 0) {
                return res.status(404).send('User not found');
            }
            const user = results[0];
            const secret = {
                base32: user.mfaSecret,
                otpauth_url: `otpauth://totp/SecureCloud:${user.username}@${email}?secret=${user.mfaSecret}&issuer=SecureCloud`
            };
            const qrCodeDataURL = await QRCode.toDataURL(secret.otpauth_url);
            const base64Data = qrCodeDataURL.split(',')[1];
            const imgBuffer = Buffer.from(base64Data, 'base64');
            res.setHeader('Content-Type', 'image/png');
            res.send(imgBuffer);
        });
    } catch (err) {
        console.error('QR code generation error:', err);
        res.status(500).send('Error generating QR code');
    }
});

// Global error handler (always returns JSON; respects HTTP errors e.g. 400 from parsers)
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    if (res.headersSent) return next(err);
    const status =
        typeof err?.status === "number"
            ? err.status
            : typeof err?.statusCode === "number"
              ? err.statusCode
              : 500;
    res.status(status).json({ error: err?.message || "Internal server error" });
});

// Server starts only after MySQL pool + serial migrations (avoids Unknown column user_id races)
const PORT = process.env.PORT || 5000;
getDB.onReady(() => {
    // Start anomaly detector after DB is ready
    anomalyDetector.start();

    app.listen(PORT, () => {
        console.log("");
        console.log("======== Secure Cloud (this process) ========");
        console.log("Project:", __dirname);
        console.log(`Listening: http://127.0.0.1:${PORT}/`);
        console.log(`Health:    http://127.0.0.1:${PORT}/api/health`);
        console.log("If the browser shows old text, stop OTHER Node apps using this port.");
        console.log("==============================================");
        console.log("");
    });
});