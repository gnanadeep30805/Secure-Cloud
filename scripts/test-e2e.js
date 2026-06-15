require("dotenv").config();
const http = require("http");
const FormData = require("form-data");
const fs = require("fs");
const path = require("path");
const speakeasy = require("speakeasy");
const getDB = require("../config/db");

const API_BASE = "http://localhost:5001";
const EMAIL = "test" + Date.now() + "@example.com";
const PASSWORD = "Password123!";

function randStr() { return Math.random().toString(36).slice(2); }

function request(method, pathStr, body, headers = {}) {
    return new Promise((resolve, reject) => {
        let isFormData = body instanceof FormData;
        const u = new URL(API_BASE + pathStr);
        const req = http.request({
            hostname: u.hostname,
            port: u.port,
            path: u.pathname + u.search,
            method,
            headers: {
                ...(isFormData ? body.getHeaders() : body ? {"Content-Type": "application/json"} : {}),
                ...headers
            }
        }, (res) => {
            let data = [];
            res.on("data", c => data.push(c));
            res.on("end", () => {
                const buf = Buffer.concat(data);
                // Return buffer instead of string for download-final
                resolve({ status: res.statusCode, body: buf, headers: res.headers });
            });
        });
        req.on("error", reject);
        if (isFormData) {
            body.pipe(req);
        } else if (body) {
            req.write(JSON.stringify(body));
            req.end();
        } else {
            req.end();
        }
    });
}

function parseJSON(bodyStr) {
    try { return JSON.parse(bodyStr.toString()); } catch(e) { return {}; }
}

async function runTest() {
    console.log("=== API E2E TEST ===");

    // Wait for DB completely ready
    await new Promise(r => getDB.onReady(r));
    const db = getDB();

    console.log("[1] Signing up", EMAIL);
    let res = await request("POST", "/api/auth/signup", { email: EMAIL, password: PASSWORD });
    if (res.status !== 201) throw new Error("Signup failed " + res.body);

    console.log("[2] Reading user's MFA secret from DB manually");
    const getSecret = () => new Promise(r => db.query('SELECT mfaSecret FROM users WHERE email=?', [EMAIL], (err, rows) => r(rows[0].mfaSecret)));
    const secret = await getSecret();
    console.log("    Secret is", secret);

    const getTotp = () => speakeasy.totp({ secret, encoding: 'base32' });

    console.log("[3] Logging in");
    res = await request("POST", "/api/auth/login", { email: EMAIL, password: PASSWORD, token: getTotp() });
    if (res.status !== 200) throw new Error("Login failed " + res.body);
    const token = parseJSON(res.body).token;
    console.log("    JWT obtained.");

    const authHeaders = { Authorization: `Bearer ${token}` };

    console.log("[4] Creating dummy file for upload");
    const testFile = path.join(__dirname, "test-file.txt");
    const fileData = "Hello, world! This is a test file for chunk secure streaming over AES-GCM.\n".repeat(5000);
    fs.writeFileSync(testFile, fileData);

    console.log("[5] Uploading file");
    const form = new FormData();
    form.append("totp", getTotp());
    form.append("file", fs.createReadStream(testFile));
    res = await request("POST", "/api/files/upload", form, authHeaders);
    const upData = parseJSON(res.body);
    if (res.status !== 201) throw new Error("Upload failed " + res.body);
    const fileId = upData.fileId;
    console.log("    Upload Success! File ID =", fileId);

    console.log("[6] Verifying Download Step 1 (Integrity Check)");
    res = await request("POST", `/api/files/${fileId}/verify-download-1`, { token: getTotp() }, authHeaders);
    const s1Data = parseJSON(res.body);
    if (!s1Data.integrityMatch) throw new Error("Integrity match failed " + res.body);
    console.log("    Integrity matched! previewToken obtained.");

    console.log("[7] Verifying Download Step 2 (Download token)");
    res = await request("POST", `/api/files/${fileId}/verify-download-2`, { token: getTotp() }, authHeaders);
    const s2Data = parseJSON(res.body);
    console.log("    downloadToken obtained.");

    console.log("[8] Downloading final file");
    res = await request("GET", `/api/files/download-final?token=${encodeURIComponent(s2Data.downloadToken)}`, null, authHeaders);
    if (res.status !== 200) throw new Error("Download failed " + res.body);
    
    // File downloaded from GCM stream!
    const downloadedData = res.body.toString();
    console.log("    Downloaded bytes:", res.body.length);

    if (downloadedData === fileData) {
        console.log("✅ MATCH! Uploaded and downloaded data are identical.");
    } else {
        console.error("❌ MISMATCH!");
        console.log("Expected len:", fileData.length, "Got len:", downloadedData.length);
    }
    
    fs.unlinkSync(testFile);
    console.log("Done.");
    process.exit(0);
}

runTest().catch(e => {
    console.error("Test Error:", e);
    process.exit(1);
});
