const getDB = require("../config/db");

const User = {
    create: (username, email, password, mfaSecret, callback) => {
        const db = getDB();

        const query = `
            INSERT INTO users (username, email, password, mfaSecret)
            VALUES (?, ?, ?, ?)
        `;
        db.query(query, [username, email, password, mfaSecret], callback);
    },

    findByEmail: (email, callback) => {
        const db = getDB();

        const query = `SELECT * FROM users WHERE email = ?`;
        db.query(query, [email], callback);
    },

    findById: (id, callback) => {
        const db = getDB();
        db.query(`SELECT * FROM users WHERE id = ?`, [id], callback);
    },

    updatePasswordByEmail: (email, hashedPassword, callback) => {
        const db = getDB();
        db.query(`UPDATE users SET password = ? WHERE email = ?`, [hashedPassword, email], callback);
    },
};

module.exports = User;
