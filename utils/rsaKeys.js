const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const KEYS_DIR = path.join(__dirname, "../config/keys");
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, "server_private.pem");
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, "server_public.pem");

let serverKeys = null;

function generateKeysSync() {
    console.log("Generating 4096-bit Server RSA Key Pair (this may take a moment)...");
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 4096,
        publicKeyEncoding: {
            type: "spki",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
        },
    });

    if (!fs.existsSync(KEYS_DIR)) {
        fs.mkdirSync(KEYS_DIR, { recursive: true });
    }

    fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
    fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });

    console.log("Server RSA keys generated and saved to config/keys/");
    return { publicKey, privateKey };
}

function loadOrGenerateServerKeys() {
    if (serverKeys) return serverKeys;

    if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
        const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
        const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
        serverKeys = { publicKey, privateKey };
    } else {
        serverKeys = generateKeysSync();
    }
    return serverKeys;
}

exports.loadOrGenerateServerKeys = loadOrGenerateServerKeys;
exports.getServerKeys = () => loadOrGenerateServerKeys();
