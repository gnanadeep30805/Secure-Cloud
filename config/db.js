const mysql = require("mysql2");
require("dotenv").config();

let db;
const readyCallbacks = [];
let dbMigrationsDone = false;

function getDB() {
    return db;
}

/** Call after pool is up and all CREATE + migrations finished (avoids user_id race). */
getDB.onReady = function onReady(fn) {
    if (typeof fn !== "function") return;
    if (dbMigrationsDone) setImmediate(fn);
    else readyCallbacks.push(fn);
};

function signalDbReady() {
    if (dbMigrationsDone) return;
    dbMigrationsDone = true;
    readyCallbacks.splice(0).forEach((fn) => {
        try {
            fn();
        } catch (e) {
            console.error("onReady callback error:", e);
        }
    });
}

// 🔹 Step 1: Temporary connection (NO database selected)
const tempConnection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});

tempConnection.connect((err) => {
    if (err) {
        console.error("❌ MySQL temp connection failed:", err);
        process.exit(1);
    }

    console.log("✅ MySQL temp connected");

    // 🔹 Step 2: Create DB if not exists
    const dbName = process.env.DB_NAME;

    tempConnection.query(
        `CREATE DATABASE IF NOT EXISTS \`${dbName}\``,
        (err) => {
            if (err) {
                console.error("❌ Database creation failed:", err);
                process.exit(1);
            }

            console.log(`✅ Database "${dbName}" ready`);

            tempConnection.end();

            // 🔹 Step 3: Create Pool
            createPool();
        }
    );
});

// 🔹 Step 4: Create connection pool WITH database
function createPool() {
    db = mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });

    // 🔹 Step 5: Test connection
    db.getConnection((err, connection) => {
        if (err) {
            console.error("❌ MySQL pool connection failed:", err);
            process.exit(1);
        }

        console.log("✅ MySQL pool connected");

        connection.release();

        // 🔹 Step 6: Initialize tables (serial — no API traffic until migrations finish)
        initializeTables();
    });
}

// 🔹 Step 7: Create required tables (one chain — migrations always run before server listens)
function initializeTables() {
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            mfaSecret VARCHAR(255),
            role ENUM('user', 'admin') DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `;

    const createFilesTable = `
        CREATE TABLE IF NOT EXISTS files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(255),
            file_path TEXT,
            original_name TEXT,
            encrypted_key TEXT,
            hmac TEXT,
            iv TEXT,
            algorithm VARCHAR(50),
            is_compressed BOOLEAN DEFAULT FALSE,
            storage_mode ENUM('plain','encrypted') DEFAULT 'encrypted',
            signed_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `;

    const createEmailVerifications = `
        CREATE TABLE IF NOT EXISTS email_verifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(64) NOT NULL,
            purpose VARCHAR(64) NOT NULL,
            file_id INT NULL,
            code_hash VARCHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            consumed_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user_purpose (user_id, purpose),
            INDEX idx_expires (expires_at)
        )
    `;

    const createActivities = `
        CREATE TABLE IF NOT EXISTS user_activities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(64) NOT NULL,
            action VARCHAR(64) NOT NULL,
            detail TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user_time (user_id, created_at)
        )
    `;

    db.query(createUsersTable, (err) => {
        if (err) console.error("❌ Error creating users table:", err);
        else console.log("✅ Users table ready");

        db.query(createFilesTable, (err2) => {
            if (err2) console.error("❌ Error creating files table:", err2);
            else console.log("✅ Files table ready");

            migrateFilesTableSchema(db, (mErr) => {
                if (mErr) {
                    console.error("❌ files table schema migration:", mErr.message);
                } else {
                    console.log("✅ files columns aligned with app (user_id, …)");
                }

                db.query(createEmailVerifications, (err3) => {
                    if (err3) {
                        console.error("❌ Error creating email_verifications:", err3);
                    } else {
                        console.log("✅ email_verifications ready");
                    }

                    migrateEmailVerificationsSchema(db, (evErr) => {
                        if (evErr) {
                            console.error(
                                "❌ email_verifications migration:",
                                evErr.message
                            );
                        } else {
                            console.log("✅ email_verifications columns OK");
                        }

                        db.query(createActivities, (err4) => {
                            if (err4) {
                                console.error("❌ Error creating user_activities:", err4);
                            } else {
                                console.log("✅ user_activities ready");
                            }

                            migrateUserActivitiesSchema(db, (uaErr) => {
                                if (uaErr) {
                                    console.error(
                                        "❌ user_activities migration:",
                                        uaErr.message
                                    );
                                } else {
                                    console.log("✅ user_activities columns OK");
                                }

                                // ── Policies table ──────────────────────────
                                const createPolicies = `
                                    CREATE TABLE IF NOT EXISTS policies (
                                        id              INT AUTO_INCREMENT PRIMARY KEY,
                                        name            VARCHAR(100) NOT NULL,
                                        resource_type   ENUM('file','folder','system') NOT NULL,
                                        action          ENUM('upload','download','preview','delete','admin') NOT NULL,
                                        required_role   ENUM('admin','editor','viewer','guest') NOT NULL,
                                        min_trust_score INT DEFAULT 0,
                                        max_risk_score  INT DEFAULT 100,
                                        require_mfa     BOOLEAN DEFAULT TRUE,
                                        ip_whitelist    JSON,
                                        time_allow      JSON,
                                        abac_conditions JSON,
                                        priority        INT DEFAULT 10,
                                        is_active       BOOLEAN DEFAULT TRUE,
                                        version         INT DEFAULT 1,
                                        created_at      DATETIME DEFAULT NOW(),
                                        updated_at      DATETIME DEFAULT NOW() ON UPDATE NOW()
                                    )
                                `;

                                db.query(createPolicies, (pErr) => {
                                    if (pErr) {
                                        console.error("❌ Error creating policies table:", pErr);
                                    } else {
                                        console.log("✅ policies table ready");
                                    }

                                    seedDefaultPolicies(db, () => {
                                        const createTrustedDevices = `
                                            CREATE TABLE IF NOT EXISTS trusted_devices (
                                                id                  INT AUTO_INCREMENT PRIMARY KEY,
                                                user_id             INT NOT NULL,
                                                device_fingerprint  VARCHAR(128) NOT NULL,
                                                device_name         VARCHAR(200),
                                                trust_level         ENUM('high','medium','low','untrusted') DEFAULT 'low',
                                                registered_at       DATETIME DEFAULT NOW(),
                                                last_seen_at        DATETIME DEFAULT NOW(),
                                                last_seen_ip        VARCHAR(45),
                                                last_seen_country   VARCHAR(10),
                                                verification_method ENUM('email_verified','totp_verified','admin_approved'),
                                                is_active           BOOLEAN DEFAULT TRUE,
                                                UNIQUE KEY uq_user_device (user_id, device_fingerprint),
                                                FOREIGN KEY (user_id) REFERENCES users(id)
                                            )
                                        `;

                                        const createAccessContexts = `
                                            CREATE TABLE IF NOT EXISTS access_contexts (
                                                id                 INT AUTO_INCREMENT PRIMARY KEY,
                                                user_id            INT NOT NULL,
                                                request_id         VARCHAR(36) NOT NULL,
                                                ip_address         VARCHAR(45),
                                                geo_country        VARCHAR(10),
                                                geo_city           VARCHAR(100),
                                                is_vpn             BOOLEAN DEFAULT FALSE,
                                                device_fingerprint VARCHAR(128),
                                                device_trust_score INT,
                                                session_age_ms     BIGINT,
                                                current_hour       TINYINT,
                                                current_day        TINYINT,
                                                user_agent         TEXT,
                                                created_at         DATETIME DEFAULT NOW(),
                                                FOREIGN KEY (user_id) REFERENCES users(id)
                                            )
                                        `;

                                        db.query(createTrustedDevices, (tdErr) => {
                                            if (tdErr) console.error("❌ trusted_devices:", tdErr.message);
                                            else console.log("✅ trusted_devices table ready");

                                            db.query(createAccessContexts, (acErr) => {
                                                if (acErr) console.error("❌ access_contexts:", acErr.message);
                                                else console.log("✅ access_contexts table ready");

                                                // ── Audit + security monitoring tables ─────────
                                                const createAuditLogs = `
                                                    CREATE TABLE IF NOT EXISTS audit_logs (
                                                        id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
                                                        event_id           VARCHAR(36)  NOT NULL UNIQUE,
                                                        user_id            INT          NULL,
                                                        action             VARCHAR(80)  NOT NULL,
                                                        resource_type      VARCHAR(40)  NULL,
                                                        resource_id        VARCHAR(36)  NULL,
                                                        outcome            ENUM('permitted','denied','success','failure','blocked') NOT NULL,
                                                        reason             VARCHAR(200) NULL,
                                                        risk_score         INT          NULL,
                                                        device_trust_score INT          NULL,
                                                        ip_address         VARCHAR(45)  NULL,
                                                        geo_location       VARCHAR(100) NULL,
                                                        is_vpn             BOOLEAN      DEFAULT FALSE,
                                                        user_agent         TEXT         NULL,
                                                        session_age_min    INT          NULL,
                                                        context_flags      JSON         NULL,
                                                        duration_ms        INT          NULL,
                                                        log_hash           VARCHAR(128) NOT NULL,
                                                        prev_log_hash      VARCHAR(128) NOT NULL DEFAULT 'GENESIS',
                                                        created_at         DATETIME     DEFAULT NOW(),
                                                        INDEX idx_al_user    (user_id),
                                                        INDEX idx_al_action  (action),
                                                        INDEX idx_al_created (created_at),
                                                        INDEX idx_al_outcome (outcome)
                                                    )
                                                `;

                                                const createSecurityEvents = `
                                                    CREATE TABLE IF NOT EXISTS security_events (
                                                        id               INT AUTO_INCREMENT PRIMARY KEY,
                                                        user_id          INT          NULL,
                                                        event_type       VARCHAR(80)  NOT NULL,
                                                        severity         ENUM('low','medium','high','critical') NOT NULL,
                                                        source_ip        VARCHAR(45)  NULL,
                                                        geo_country      VARCHAR(10)  NULL,
                                                        detail           JSON         NULL,
                                                        auto_action      VARCHAR(80)  NULL,
                                                        resolved         BOOLEAN      DEFAULT FALSE,
                                                        resolved_by      INT          NULL,
                                                        resolved_at      DATETIME     NULL,
                                                        created_at       DATETIME     DEFAULT NOW(),
                                                        INDEX idx_se_user     (user_id),
                                                        INDEX idx_se_severity (severity),
                                                        INDEX idx_se_resolved (resolved)
                                                    )
                                                `;

                                                const createRateLimitViolations = `
                                                    CREATE TABLE IF NOT EXISTS rate_limit_violations (
                                                        id            INT AUTO_INCREMENT PRIMARY KEY,
                                                        ip_address    VARCHAR(45)  NOT NULL,
                                                        endpoint      VARCHAR(100) NOT NULL,
                                                        hit_count     INT DEFAULT 1,
                                                        first_seen    DATETIME DEFAULT NOW(),
                                                        last_seen     DATETIME DEFAULT NOW(),
                                                        is_blocked    BOOLEAN DEFAULT FALSE,
                                                        blocked_until DATETIME NULL,
                                                        UNIQUE KEY uq_ip_ep (ip_address, endpoint),
                                                        INDEX idx_rl_ip (ip_address)
                                                    )
                                                `;

                                                db.query(createAuditLogs, (alErr) => {
                                                    if (alErr) console.error("❌ audit_logs:", alErr.message);
                                                    else console.log("✅ audit_logs table ready");

                                                    db.query(createSecurityEvents, (seErr) => {
                                                        if (seErr) console.error("❌ security_events:", seErr.message);
                                                        else console.log("✅ security_events table ready");

                                                        db.query(createRateLimitViolations, (rlErr) => {
                                                            if (rlErr) console.error("❌ rate_limit_violations:", rlErr.message);
                                                            else console.log("✅ rate_limit_violations table ready");

                                                            // ── Risk-based auth tables ──────────
                                                            const createRiskScores = `
                                                                CREATE TABLE IF NOT EXISTS risk_scores (
                                                                    id           INT AUTO_INCREMENT PRIMARY KEY,
                                                                    user_id      INT NOT NULL,
                                                                    score        INT NOT NULL,
                                                                    factors      JSON NOT NULL,
                                                                    action_taken VARCHAR(80) NOT NULL,
                                                                    ip_address   VARCHAR(45),
                                                                    geo_country  VARCHAR(10),
                                                                    created_at   DATETIME DEFAULT NOW(),
                                                                    INDEX idx_rs_user    (user_id),
                                                                    INDEX idx_rs_created (created_at)
                                                                )
                                                            `;

                                                            const createStepUpChallenges = `
                                                                CREATE TABLE IF NOT EXISTS step_up_challenges (
                                                                    id           INT AUTO_INCREMENT PRIMARY KEY,
                                                                    user_id      INT NOT NULL,
                                                                    challenge_id VARCHAR(36) NOT NULL UNIQUE,
                                                                    type         ENUM('totp','email_otp') NOT NULL,
                                                                    otp_hash     VARCHAR(128) NULL,
                                                                    issued_at    DATETIME DEFAULT NOW(),
                                                                    expires_at   DATETIME NOT NULL,
                                                                    completed    BOOLEAN DEFAULT FALSE,
                                                                    FOREIGN KEY (user_id) REFERENCES users(id)
                                                                )
                                                            `;

                                                            db.query(createRiskScores, (rsErr) => {
                                                                if (rsErr) console.error("❌ risk_scores:", rsErr.message);
                                                                else console.log("✅ risk_scores table ready");

                                                                db.query(createStepUpChallenges, (suErr) => {
                                                                    if (suErr) console.error("❌ step_up_challenges:", suErr.message);
                                                                    else console.log("✅ step_up_challenges table ready");

                                                                    migrateRBACandABAC(db, () => {
                                                                        migrateUsersForSecurity(db, () => {
                                                                            console.log("✅ Database migrations finished");
                                                                            signalDbReady();
                                                                        });
                                                                    });
                                                                });
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
}

/** Insert default policies only if the table is empty */
function seedDefaultPolicies(dbConn, callback) {
    dbConn.query("SELECT COUNT(*) AS cnt FROM policies", (err, rows) => {
        if (err || (rows && rows[0] && rows[0].cnt > 0)) {
            // Already seeded or table error — skip
            if (rows && rows[0] && rows[0].cnt > 0) {
                console.log("✅ policies already seeded (" + rows[0].cnt + " rows)");
            }
            return callback();
        }

        const seed = `
            INSERT INTO policies
              (name, resource_type, action, required_role, min_trust_score, max_risk_score, require_mfa, time_allow, priority)
            VALUES
              ('upload_file',   'file',   'upload',   'editor', 50, 60,  TRUE, '{"days":[1,2,3,4,5],"hours":[0,23]}', 10),
              ('download_file', 'file',   'download', 'viewer', 40, 60,  TRUE, NULL, 10),
              ('preview_file',  'file',   'preview',  'viewer', 30, 70,  TRUE, NULL, 20),
              ('delete_file',   'file',   'delete',   'editor', 70, 40,  TRUE, '{"days":[1,2,3,4,5],"hours":[9,18]}', 5),
              ('admin_action',  'system', 'admin',    'admin',  0, 100, TRUE, NULL, 1)
        `;

        dbConn.query(seed, (sErr) => {
            if (sErr) {
                console.error("❌ Error seeding policies:", sErr.message);
            } else {
                console.log("✅ Default policies seeded (5 rows)");
            }
            callback();
        });
    });
}


/** Add security columns (status, locked_at) to users table if missing */
function migrateUsersForSecurity(dbConn, callback) {
    dbConn.query("DESCRIBE users", (err, rows) => {
        if (err) { return callback(); } // non-fatal
        const cols = columnSet(rows);
        const alters = [];
        if (!cols.has("status"))     alters.push("ADD COLUMN status ENUM('active','locked') DEFAULT 'active'");
        if (!cols.has("locked_at"))  alters.push("ADD COLUMN locked_at DATETIME NULL");
        if (alters.length === 0) { console.log("✅ users security columns OK"); return callback(); }
        dbConn.query(`ALTER TABLE users ${alters.join(", ")}`, (aErr) => {
            if (aErr) console.error("❌ users security migration:", aErr.message);
            else console.log("✅ users security columns added");
            callback();
        });
    });
}

function columnSet(rows) {
    return new Set((rows || []).map((r) => r.Field));
}

/** Case-insensitive: MySQL may report userId vs user_id differently per OS. */
function hasColumnCI(rows, name) {
    const want = String(name).toLowerCase();
    return (rows || []).some((r) => String(r.Field).toLowerCase() === want);
}

function findColumnCI(rows, name) {
    const want = String(name).toLowerCase();
    const row = (rows || []).find((r) => String(r.Field).toLowerCase() === want);
    return row ? row.Field : null;
}

function addColumnIfMissing(dbConn, table, colName, ddl, cb) {
    dbConn.query(`SHOW COLUMNS FROM \`${table}\``, (e1, rows) => {
        if (e1) return cb(e1);
        if (hasColumnCI(rows, colName)) return cb(null);
        dbConn.query(
            `ALTER TABLE \`${table}\` ADD COLUMN \`${colName}\` ${ddl}`,
            cb
        );
    });
}

function migrateEmailVerificationsSchema(dbConn, callback) {
    if (!dbConn) return callback(null);
    const tasks = [
        ["user_id", "VARCHAR(64) NULL"],
        ["purpose", "VARCHAR(64) NULL"],
        ["file_id", "INT NULL"],
        ["code_hash", "VARCHAR(64) NULL"],
        ["expires_at", "DATETIME NULL"],
        ["consumed_at", "DATETIME NULL"],
    ];
    let i = 0;
    function next(err) {
        if (err) return callback(err);
        if (i >= tasks.length) return callback(null);
        const [col, ddl] = tasks[i];
        i += 1;
        addColumnIfMissing(dbConn, "email_verifications", col, ddl, next);
    }
    next(null);
}

function migrateUserActivitiesSchema(dbConn, callback) {
    if (!dbConn) return callback(null);
    const tasks = [
        ["user_id", "VARCHAR(64) NULL"],
        ["action", "VARCHAR(64) NULL"],
        ["detail", "TEXT NULL"],
    ];
    let i = 0;
    function next(err) {
        if (err) return callback(err);
        if (i >= tasks.length) return callback(null);
        const [col, ddl] = tasks[i];
        i += 1;
        addColumnIfMissing(dbConn, "user_activities", col, ddl, next);
    }
    next(null);
}

function runSerial(dbConn, queries, cb) {
    let i = 0;
    function next(err) {
        if (err) return cb(err);
        if (i >= queries.length) return cb(null);
        const q = queries[i];
        i += 1;
        dbConn.query(q, next);
    }
    next(null);
}

/**
 * Older init used userId / fileName. App expects user_id, file_path, original_name, hmac, iv, algorithm.
 * CREATE TABLE IF NOT EXISTS does not alter existing tables — migrate in place.
 */
function migrateFilesTableSchema(dbConn, callback) {
    if (!dbConn) return callback(null);
    dbConn.query("SHOW COLUMNS FROM files", (err, rows) => {
        if (err) {
            if (String(err.code) === "ER_NO_SUCH_TABLE") return callback(null);
            return callback(err);
        }
        const renames = [];
        const oldUserCol = findOldUserIdColumn(rows);
        if (oldUserCol && !hasColumnCI(rows, "user_id")) {
            renames.push(
                `ALTER TABLE files CHANGE COLUMN \`${oldUserCol}\` user_id VARCHAR(255) NULL`
            );
        }
        const oldFileName = findColumnCI(rows, "filename");
        if (
            oldFileName &&
            !hasColumnCI(rows, "original_name")
        ) {
            renames.push(
                `ALTER TABLE files CHANGE COLUMN \`${oldFileName}\` original_name TEXT NULL`
            );
        }
        runSerial(dbConn, renames, (e1) => {
            if (e1) return callback(e1);
            dbConn.query("SHOW COLUMNS FROM files", (e2, rows2) => {
                if (e2) return callback(e2);
                const adds = [];
                if (!hasColumnCI(rows2, "user_id")) {
                    adds.push(
                        "ALTER TABLE files ADD COLUMN user_id VARCHAR(255) NULL"
                    );
                }
                if (!hasColumnCI(rows2, "file_path")) {
                    adds.push("ALTER TABLE files ADD COLUMN file_path TEXT NULL");
                }
                if (!hasColumnCI(rows2, "original_name")) {
                    adds.push(
                        "ALTER TABLE files ADD COLUMN original_name TEXT NULL"
                    );
                }
                if (!hasColumnCI(rows2, "encrypted_key")) {
                    adds.push(
                        "ALTER TABLE files ADD COLUMN encrypted_key TEXT NULL"
                    );
                }
                if (!hasColumnCI(rows2, "hmac")) {
                    adds.push("ALTER TABLE files ADD COLUMN hmac TEXT NULL");
                }
                if (!hasColumnCI(rows2, "iv")) {
                    adds.push("ALTER TABLE files ADD COLUMN iv TEXT NULL");
                }
                if (!hasColumnCI(rows2, "algorithm")) {
                    adds.push(
                        "ALTER TABLE files ADD COLUMN algorithm VARCHAR(50) NULL"
                    );
                }
                if (!hasColumnCI(rows2, "is_compressed")) {
                    adds.push(
                        "ALTER TABLE files ADD COLUMN is_compressed BOOLEAN DEFAULT FALSE"
                    );
                }
                if (!hasColumnCI(rows2, "storage_mode")) {
                    adds.push(
                        "ALTER TABLE files ADD COLUMN storage_mode ENUM('plain','encrypted') DEFAULT 'encrypted'"
                    );
                }
                if (!hasColumnCI(rows2, "signed_hash")) {
                    adds.push(
                        "ALTER TABLE files ADD COLUMN signed_hash TEXT NULL"
                    );
                }
                runSerial(dbConn, adds, callback);
            });
        });
    });
}

/** userId (camel) only — not user_id. */
function findOldUserIdColumn(rows) {
    if (hasColumnCI(rows, "user_id")) return null;
    for (const r of rows || []) {
        const f = String(r.Field);
        if (f.toLowerCase() === "userid" || f === "userId") return f;
    }
    return null;
}

/** ── RBAC & ABAC Migration and Seeder ────────────────────────────────── */
function migrateRBACandABAC(dbConn, callback) {
    const ddl = [
        `CREATE TABLE IF NOT EXISTS roles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name ENUM('admin','editor','viewer','guest') NOT NULL UNIQUE,
            description VARCHAR(200),
            created_at DATETIME DEFAULT NOW()
         )`,
        `CREATE TABLE IF NOT EXISTS role_permissions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            role ENUM('admin','editor','viewer','guest') NOT NULL,
            resource_type ENUM('file','folder','system','report','admin_panel') NOT NULL,
            action ENUM('upload','download','preview','delete','share',
                        'admin','view_logs','manage_users','manage_policies') NOT NULL,
            is_allowed BOOLEAN NOT NULL DEFAULT FALSE,
            UNIQUE KEY uq_role_res_action (role, resource_type, action)
         )`,
        `CREATE TABLE IF NOT EXISTS user_attributes (
            user_id INT PRIMARY KEY,
            department VARCHAR(80) DEFAULT 'general',
            clearance_level ENUM('public','internal','confidential','secret') DEFAULT 'internal',
            job_title VARCHAR(100) NULL,
            location VARCHAR(80) NULL,
            account_type ENUM('internal','contractor','external') DEFAULT 'internal',
            updated_at DATETIME DEFAULT NOW() ON UPDATE NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id)
         )`,
        `CREATE TABLE IF NOT EXISTS file_attributes (
            file_id INT PRIMARY KEY,
            sensitivity ENUM('public','internal','confidential','secret') DEFAULT 'internal',
            owner_dept VARCHAR(80) NULL,
            allowed_depts JSON NULL,
            requires_clearance ENUM('public','internal','confidential','secret') DEFAULT 'internal',
            shareable BOOLEAN DEFAULT TRUE,
            expires_at DATETIME NULL,
            created_at DATETIME DEFAULT NOW(),
            FOREIGN KEY (file_id) REFERENCES files(id)
         )`,
        `CREATE TABLE IF NOT EXISTS abac_policies (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            resource_type VARCHAR(40) NOT NULL,
            action VARCHAR(40) NOT NULL,
            subject_conditions JSON NOT NULL,
            resource_conditions JSON NOT NULL,
            env_conditions JSON,
            effect ENUM('permit','deny') NOT NULL DEFAULT 'permit',
            priority INT DEFAULT 10,
            is_active BOOLEAN DEFAULT TRUE,
            created_at DATETIME DEFAULT NOW()
         )`,
        `CREATE TABLE IF NOT EXISTS user_roles (
            user_id INT NOT NULL,
            role ENUM('admin','editor','viewer','guest') NOT NULL,
            assigned_by INT NULL,
            assigned_at DATETIME DEFAULT NOW(),
            expires_at DATETIME NULL,
            PRIMARY KEY (user_id, role),
            FOREIGN KEY (user_id) REFERENCES users(id)
         )`
    ];

    runSerial(dbConn, ddl, (err) => {
        if (err) {
            console.error("❌ Error migrating RBAC/ABAC tables:", err);
            return callback();
        }
        console.log("✅ RBAC and ABAC tables ready");

        // Seed Default Roles & Permissions
        dbConn.query("SELECT COUNT(*) AS cnt FROM role_permissions", (rpErr, rows) => {
            if (!rpErr && rows[0] && rows[0].cnt === 0) {
                const seedRP = `
                    INSERT IGNORE INTO role_permissions (role, resource_type, action, is_allowed) VALUES
                    ('admin',  'file',        'upload',        TRUE),
                    ('admin',  'file',        'download',      TRUE),
                    ('admin',  'file',        'preview',       TRUE),
                    ('admin',  'file',        'delete',        TRUE),
                    ('admin',  'file',        'share',         TRUE),
                    ('admin',  'system',      'admin',         TRUE),
                    ('admin',  'admin_panel', 'manage_users',  TRUE),
                    ('admin',  'admin_panel', 'manage_policies',TRUE),
                    ('admin',  'report',      'view_logs',     TRUE),
                    ('editor', 'file',        'upload',        TRUE),
                    ('editor', 'file',        'download',      TRUE),
                    ('editor', 'file',        'preview',       TRUE),
                    ('editor', 'file',        'delete',        TRUE),
                    ('editor', 'file',        'share',         TRUE),
                    ('editor', 'system',      'admin',         FALSE),
                    ('editor', 'report',      'view_logs',     FALSE),
                    ('viewer', 'file',        'upload',        FALSE),
                    ('viewer', 'file',        'download',      TRUE),
                    ('viewer', 'file',        'preview',       TRUE),
                    ('viewer', 'file',        'delete',        FALSE),
                    ('viewer', 'file',        'share',         FALSE),
                    ('guest',  'file',        'upload',        FALSE),
                    ('guest',  'file',        'download',      FALSE),
                    ('guest',  'file',        'preview',       TRUE),
                    ('guest',  'file',        'delete',        FALSE)
                `;
                dbConn.query(seedRP, () => console.log("✅ RBAC default role permissions seeded"));
            }

            // Seed Default ABAC Policies
            dbConn.query("SELECT COUNT(*) AS cnt FROM abac_policies", (apErr, pRows) => {
                if (!apErr && pRows[0] && pRows[0].cnt === 0) {
                    const seedAP = `
                        INSERT IGNORE INTO abac_policies
                        (name, resource_type, action, subject_conditions, resource_conditions, env_conditions, effect, priority)
                        VALUES
                        ('confidential_requires_clearance', 'file', 'download', '{"clearance_level":["confidential","secret"]}', '{"sensitivity":"confidential"}', NULL, 'permit', 5),
                        ('secret_files_own_dept_only', 'file', 'download', '{}', '{"sensitivity":"secret"}', NULL, 'deny', 1),
                        ('contractors_no_secret', 'file', 'download', '{"account_type":"contractor"}', '{"sensitivity":["confidential","secret"]}', NULL, 'deny', 2),
                        ('delete_only_business_hours', 'file', 'delete', '{}', '{}', '{"business_hours":true}', 'permit', 10),
                        ('no_download_via_vpn_for_secret', 'file', 'download', '{}', '{"sensitivity":"secret"}', '{"allow_vpn":false}', 'deny', 3),
                        ('external_users_public_only', 'file', 'download', '{"account_type":"external"}', '{"sensitivity":["internal","confidential","secret"]}', NULL, 'deny', 2)
                    `;
                    dbConn.query(seedAP, () => {
                        console.log("✅ ABAC default policies seeded");
                        callback();
                    });
                } else {
                    callback();
                }
            });
        });
    });
}

module.exports = getDB;