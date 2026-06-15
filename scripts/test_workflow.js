const http = require("http");
const crypto = require("crypto");
const speakeasy = require("speakeasy");
const fs = require("fs");
const path = require("path");

function request(method, pathUrl, headers = {}, body = null) {
    return new Promise((resolve, reject) => {
        const req = http.request(
            {
                hostname: "127.0.0.1",
                port: 5000,
                path: pathUrl,
                method,
                headers,
            },
            (res) => {
                const chunks = [];
                res.on("data", (d) => chunks.push(d));
                res.on("end", () => {
                    const buffer = Buffer.concat(chunks);
                    resolve({ status: res.statusCode, headers: res.headers, body: buffer });
                });
            }
        );
        req.on("error", reject);
        if (body) {
            req.write(body);
        }
        req.end();
    });
}

function parseJson(buf) {
    try {
        return JSON.parse(buf.toString());
    } catch {
        return null;
    }
}

async function run() {
    console.log("--- End-to-End Test ---");
    const email = `test_${Date.now()}@test.com`;
    const password = "password123";

    console.log("1. Signup");
    const signupReq = JSON.stringify({ email, password });
    let res = await request("POST", "/api/auth/signup", { "Content-Type": "application/json" }, signupReq);
    const signupData = parseJson(res.body);
    console.log("Signup status:", res.status);
    if (res.status !== 201) throw new Error("Signup failed: " + res.body.toString());

    // We need the DB user to get the mfaSecret to perform 2FA login.
    // Or we can just read from the DB here because it's a test.
    const mysql = require("mysql2/promise");
    require("dotenv").config();
    const conn = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT
    });
    const [rows] = await conn.query("SELECT mfaSecret FROM users WHERE email=?", [email]);
    const mfaSecret = rows[0].mfaSecret;

    console.log("2. Login");
    const token = speakeasy.totp({ secret: mfaSecret, encoding: "base32" });
    const loginReq = JSON.stringify({ email, password, token });
    res = await request("POST", "/api/auth/login", { "Content-Type": "application/json" }, loginReq);
    const loginData = parseJson(res.body);
    console.log("Login status:", res.status);
    if (res.status !== 200) throw new Error("Login failed: " + res.body.toString());
    const jwtAuth = loginData.token;

    console.log("3. Upload File (Stream & Chunk encryption)");
    // Manually construct multipart form data
    const boundary = "------WebKitFormBoundaryXYZ";
    const uploadToken = speakeasy.totp({ secret: mfaSecret, encoding: "base32" });
    let formBody = "";
    
    // totp MUST come first
    formBody += `--${boundary}\r\n`;
    formBody += `Content-Disposition: form-data; name="totp"\r\n\r\n`;
    formBody += `${uploadToken}\r\n`;
    
    formBody += `--${boundary}\r\n`;
    formBody += `Content-Disposition: form-data; name="file"; filename="hello.txt"\r\n`;
    formBody += `Content-Type: text/plain\r\n\r\n`;
    formBody += `Hello streaming AES-256-GCM zero trust chunking world! This is a test file.\r\n`;
    formBody += `--${boundary}--\r\n`;

    res = await request("POST", "/api/files/upload", {
        "Authorization": `Bearer ${jwtAuth}`,
        "Content-Type": `multipart/form-data; boundary=${boundary}`
    }, Buffer.from(formBody));
    
    const uploadData = parseJson(res.body);
    console.log("Upload status:", res.status, uploadData);
    if (res.status !== 201) throw new Error("Upload failed");
    const fileId = uploadData.fileId;

    console.log("4. Download Step 1 (Verify Auth Tags & Create Preview Token)");
    const step1Token = speakeasy.totp({ secret: mfaSecret, encoding: "base32" });
    res = await request("POST", `/api/files/${fileId}/verify-download-1`, {
        "Authorization": `Bearer ${jwtAuth}`,
        "Content-Type": "application/json"
    }, JSON.stringify({ token: step1Token }));
    const step1Data = parseJson(res.body);
    console.log("Step 1 status:", res.status, step1Data);
    if (res.status !== 200 || !step1Data.integrityMatch) throw new Error("Step 1 Integrity check failed");

    console.log("5. Download Step 2 (Get Download Token)");
    const step2Token = speakeasy.totp({ secret: mfaSecret, encoding: "base32" });
    res = await request("POST", `/api/files/${fileId}/verify-download-2`, {
        "Authorization": `Bearer ${jwtAuth}`,
        "Content-Type": "application/json"
    }, JSON.stringify({ token: step2Token }));
    const step2Data = parseJson(res.body);
    console.log("Step 2 status:", res.status, step2Data);
    if (res.status !== 200) throw new Error("Step 2 failed");
    const dlToken = step2Data.downloadToken;

    console.log("6. Final Download (Stream Decryption)");
    res = await request("GET", `/api/files/download-final?token=${dlToken}`, {
        "Authorization": `Bearer ${jwtAuth}`
    });
    console.log("Download Final status:", res.status);
    console.log("Downloaded Decrypted Content:", res.body.toString());

    if (res.body.toString().includes("Hello streaming AES")) {
        console.log("SUCCESS! All steps passed.");
    } else {
        console.log("FAILED to decode content properly.");
    }
    await conn.end();
}

run().catch(console.error);
