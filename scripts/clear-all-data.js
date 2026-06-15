/**
 * Wipes app-stored identity and file data:
 * - user_activities, email_verifications, files, users (MySQL)
 * - all files under uploads/ (encrypted blobs)
 *
 * Does NOT change .env. Old JWTs stay valid until they expire unless you change JWT_SECRET.
 *
 * Usage: node scripts/clear-all-data.js
 *    or: npm run clear-data
 */

require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
const mysql = require("mysql2");
const fs = require("fs");
const path = require("path");

const uploadsDir = path.join(__dirname, "..", "uploads");

function query(conn, sql) {
    return new Promise((resolve, reject) => {
        conn.query(sql, (err, res) => (err ? reject(err) : resolve(res)));
    });
}

async function main() {
    const conn = mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT || 3306,
    });

    await new Promise((resolve, reject) => {
        conn.connect((err) => (err ? reject(err) : resolve()));
    });

    console.log("Clearing MySQL tables (order: activities → verifications → files → users)...");

    await query(conn, "DELETE FROM user_activities");
    await query(conn, "DELETE FROM email_verifications");
    await query(conn, "DELETE FROM files");
    await query(conn, "DELETE FROM users");

    await query(conn, "ALTER TABLE user_activities AUTO_INCREMENT = 1");
    await query(conn, "ALTER TABLE email_verifications AUTO_INCREMENT = 1");
    await query(conn, "ALTER TABLE files AUTO_INCREMENT = 1");
    await query(conn, "ALTER TABLE users AUTO_INCREMENT = 1");

    conn.end();

    if (fs.existsSync(uploadsDir)) {
        let removed = 0;
        for (const name of fs.readdirSync(uploadsDir)) {
            if (name === ".gitkeep") continue;
            const full = path.join(uploadsDir, name);
            try {
                fs.unlinkSync(full);
                removed += 1;
            } catch (e) {
                console.warn("Could not remove:", full, e.message);
            }
        }
        console.log(`Removed ${removed} file(s) from uploads/`);
    }

    console.log("");
    console.log("Done. All accounts, MFA secrets, file rows, email codes, and upload blobs are gone.");
    console.log("Sign up again. Clear site data in your browser (or use a private window) for a clean UI.");
    console.log("To invalidate old login tokens immediately, change JWT_SECRET in .env and restart the server.");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
