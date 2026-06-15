const getDB = require("../config/db");

function logActivity(userId, action, detail, callback) {
    const db = getDB();
    if (!db) {
        if (callback) callback();
        return;
    }
    db.query(
        `INSERT INTO user_activities (user_id, action, detail) VALUES (?, ?, ?)`,
        [String(userId), action, detail ? String(detail).slice(0, 2000) : null],
        () => {
            if (callback) callback();
        }
    );
}

module.exports = { logActivity };
