const mysql = require('mysql2/promise');
require('dotenv').config();

async function makeAdmin() {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: process.env.DB_PORT
        });

        // Get the first user
        const [users] = await connection.query("SELECT id, email FROM users ORDER BY id ASC LIMIT 1");
        
        if (users.length === 0) {
            console.log("There are no users in the database yet! Please sign up on the frontend first.");
            process.exit(0);
        }

        const firstUserId = users[0].id;
        console.log(`Found first user: ${users[0].email} (ID: ${firstUserId}). Promoting to Admin...`);

        // Insert into user_roles
        await connection.query(
            "INSERT INTO user_roles (user_id, role) VALUES (?, 'admin') ON DUPLICATE KEY UPDATE role='admin'",
            [firstUserId]
        );
        
        console.log(`Successfully assigned 'admin' role to user ID ${firstUserId}!`);
        await connection.end();
        process.exit(0);
    } catch (error) {
        console.error("Failed:", error);
        process.exit(1);
    }
}

makeAdmin();
