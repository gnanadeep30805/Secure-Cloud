const db = require('./config/db');

async function promoteToAdmin() {
    try {
        console.log("Promoting user ID 1 to admin...");
        // Promote user 1 to admin explicitly, or you can change the ID
        await db.pool.query("INSERT IGNORE INTO user_roles (user_id, role) VALUES (1, 'admin') ON DUPLICATE KEY UPDATE role='admin'");
        
        console.log("Success! User 1 is now an admin.");
        process.exit(0);
    } catch (e) {
        console.error("Failed to promote:", e.message);
        process.exit(1);
    }
}

promoteToAdmin();
