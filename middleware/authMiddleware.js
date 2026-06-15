const jwt   = require("jsonwebtoken");
const getDB = require("../config/db");

module.exports = async (req, res, next) => {
    const authHeader = req.header("Authorization");

    if (!authHeader) {
        return res.status(401).json({ msg: "No token, authorization denied" });
    }

    //Bearer <token>
    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ msg: "Token format invalid" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const uid =
            decoded.id !== undefined && decoded.id !== null
                ? decoded.id
                : decoded.userId !== undefined && decoded.userId !== null
                  ? decoded.userId
                  : decoded.sub;
        if (uid === undefined || uid === null) {
            return res.status(401).json({ msg: "Token missing user id" });
        }

        // Zero-trust session validation
        const ip = req.ip || req.connection.remoteAddress || "unknown_ip";
        const ua = req.headers['user-agent'] || "unknown_ua";
        const currentSessionHash = require("crypto").createHash("sha256").update(ip + ua).digest("hex");

        if (decoded.shash && decoded.shash !== currentSessionHash) {
            return res.status(401).json({ msg: "Token access restricted: device or session details changed" });
        }

        // Check if account has been locked (by anomaly detector or admin)
        const db = getDB();
        if (db) {
            try {
                const [rows] = await db.promise().query(
                    "SELECT status FROM users WHERE id = ? LIMIT 1", [uid]
                );
                if (rows[0]?.status === "locked") {
                    return res.status(403).json({ msg: "Account locked due to suspicious activity. Contact admin." });
                }
            } catch { /* non-fatal — if column doesn't exist, skip check */ }
        }

        req.user = { ...decoded, id: uid };

        next();
    } catch (err) {
        console.error("JWT ERROR:", err.message);
        return res.status(401).json({ msg: "Token is not valid" });
    }
};