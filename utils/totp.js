const speakeasy = require("speakeasy");

/**
 * Verify a 6-digit Google Authenticator code against a base32 TOTP secret.
 */
function verifyTotp(secretBase32, token) {
    if (!secretBase32 || token === undefined || token === null) return false;
    const clean = String(token).replace(/\s/g, "");
    if (!/^\d{6}$/.test(clean)) return false;
    return speakeasy.totp.verify({
        secret: secretBase32,
        encoding: "base32",
        token: clean,
        window: 5,
    });
}

module.exports = { verifyTotp };
