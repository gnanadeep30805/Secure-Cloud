/**
 * services/columnEncryption.js
 * AES-256-GCM column-level encryption for sensitive DB fields.
 * Encrypts before INSERT, decrypts after SELECT.
 * Usage: colEnc.encrypt(plaintext) → base64 string for DB storage
 *        colEnc.decrypt(stored)    → original plaintext
 */
const crypto = require("crypto");

const ALG = "aes-256-gcm";

// DB_COLUMN_ENC_KEY must be 64 hex chars (32 bytes). Falls back to a dev key.
function _getKey() {
    const hex = process.env.DB_COLUMN_ENC_KEY;
    if (hex && hex.length >= 64) return Buffer.from(hex.slice(0, 64), "hex");
    // Dev fallback — NOT safe for production
    return Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "hex");
}

class ColumnEncryption {
    constructor() {
        this._key = _getKey();
    }

    /**
     * Encrypt a plaintext string → base64 packed: iv(12) + authTag(16) + ciphertext
     */
    encrypt(plaintext) {
        const iv     = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(ALG, this._key, iv);
        const enc    = Buffer.concat([
            cipher.update(String(plaintext), "utf8"),
            cipher.final(),
        ]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, enc]).toString("base64");
    }

    /**
     * Decrypt a base64 packed value → original plaintext
     */
    decrypt(stored) {
        const buf  = Buffer.from(stored, "base64");
        const iv   = buf.subarray(0, 12);
        const tag  = buf.subarray(12, 28);
        const ctxt = buf.subarray(28);

        const decipher = crypto.createDecipheriv(ALG, this._key, iv);
        decipher.setAuthTag(tag);

        try {
            return Buffer.concat([
                decipher.update(ctxt),
                decipher.final(),
            ]).toString("utf8");
        } catch {
            throw new Error("Column decryption failed — data may be tampered");
        }
    }
}

module.exports = new ColumnEncryption();
