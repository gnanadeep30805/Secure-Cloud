const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");

const isServerless = process.env.VERCEL === "1" || process.env.VERCEL_ENV;
const KEYS_DIR = isServerless
    ? path.join(os.tmpdir(), "secure-cloud-keys")
    : path.join(__dirname, "../config/keys");
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, "server_private.pem");
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, "server_public.pem");
const BUNDLED_PRIVATE = path.join(__dirname, "../config/keys/server_private.pem");
const BUNDLED_PUBLIC = path.join(__dirname, "../config/keys/server_public.pem");

let serverKeys = null;

function keysFromEnv() {
    const privateKey = process.env.SERVER_PRIVATE_KEY;
    const publicKey = process.env.SERVER_PUBLIC_KEY;
    if (!privateKey || !publicKey) return null;
    return {
        privateKey: privateKey.replace(/\\n/g, "\n"),
        publicKey: publicKey.replace(/\\n/g, "\n"),
    };
}

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

    console.log("Server RSA keys generated and saved to", KEYS_DIR);
    return { publicKey, privateKey };
}

function loadFromDisk(privatePath, publicPath) {
    if (!fs.existsSync(privatePath) || !fs.existsSync(publicPath)) return null;
    return {
        privateKey: fs.readFileSync(privatePath, "utf8"),
        publicKey: fs.readFileSync(publicPath, "utf8"),
    };
}

function loadOrGenerateServerKeys() {
    if (serverKeys) return serverKeys;

    serverKeys =
        keysFromEnv() ||
        loadFromDisk(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH) ||
        loadFromDisk(BUNDLED_PRIVATE, BUNDLED_PUBLIC) ||
        generateKeysSync();

    return serverKeys;
}

exports.loadOrGenerateServerKeys = loadOrGenerateServerKeys;
exports.getServerKeys = () => loadOrGenerateServerKeys();
