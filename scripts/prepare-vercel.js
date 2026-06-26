/**
 * Copies frontend assets into public/ for Vercel CDN static serving.
 * Vercel ignores express.static(); files must live under public/**.
 */
const fs = require("fs");
const path = require("path");

const src = path.join(__dirname, "../frontend/public");
const dest = path.join(__dirname, "../public");

fs.rmSync(dest, { recursive: true, force: true });
fs.cpSync(src, dest, { recursive: true });
console.log("Copied frontend/public -> public/ for Vercel");
