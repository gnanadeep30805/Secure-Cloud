const initDB = (db) => {
    const query = `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        email VARCHAR(150) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        mfaSecret VARCHAR(255),
        isMFAEnabled BOOLEAN DEFAULT FALSE,
        role ENUM('user', 'admin') DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    `;

    db.query(query, (err) => {
        if (err) {
            console.error("Table creation error:", err);
        } else {
            console.log("Users table ready ✅");
        }
    });

    const createFilesTable = `
    CREATE TABLE IF NOT EXISTS files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userId INT,
        fileName VARCHAR(255),
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `;

    db.query(createFilesTable, (err) => {
        if (err) console.error("Files table error:", err);
        else console.log("Files table ready ✅");
    });
};

module.exports = initDB;