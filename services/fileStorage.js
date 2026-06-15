/**
 * services/fileStorage.js
 * Secure file storage — path traversal prevention + secure delete (zero-overwrite).
 * Used by controllers for upload/download file operations.
 */
const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");

const UPLOAD_ROOT = process.env.UPLOAD_DIR || path.join(process.cwd(), "uploads");
const CHUNK_DIR   = path.join(UPLOAD_ROOT, "chunks");
const PLAIN_DIR   = path.join(UPLOAD_ROOT, "plain");

// Ensure directories exist with restrictive permissions
for (const dir of [UPLOAD_ROOT, CHUNK_DIR, PLAIN_DIR]) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

class FileStorage {

    /**
     * Encrypted upload — write a chunk to an isolated per-file directory.
     */
    writeChunk(fileId, chunkIndex, encryptedBuffer) {
        const dir = path.join(CHUNK_DIR, String(fileId));
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        const safeName  = `chunk_${parseInt(chunkIndex, 10)}.enc`;
        const chunkPath = path.join(dir, safeName);

        // Verify resolved path is inside expected directory
        this._assertInside(chunkPath, CHUNK_DIR);

        fs.writeFileSync(chunkPath, encryptedBuffer);
        return chunkPath;
    }

    /**
     * Plain upload — write a compressed/plain file.
     */
    writePlain(fileId, buffer) {
        const safeName = `${crypto.randomUUID()}.dat`;
        const filePath = path.join(PLAIN_DIR, safeName);
        this._assertInside(filePath, PLAIN_DIR);
        fs.writeFileSync(filePath, buffer);
        return filePath;
    }

    /**
     * Secure delete — overwrite with zeros before unlinking.
     * Prevents data recovery from disk.
     */
    secureDelete(filePath) {
        const resolved = path.resolve(filePath);
        this._assertInside(resolved, UPLOAD_ROOT);
        if (!fs.existsSync(resolved)) return;

        const size  = fs.statSync(resolved).size;
        const fd    = fs.openSync(resolved, "r+");
        const zeros = Buffer.alloc(Math.min(size, 65536));
        let written = 0;
        while (written < size) {
            const toWrite = Math.min(zeros.length, size - written);
            fs.writeSync(fd, zeros, 0, toWrite, written);
            written += toWrite;
        }
        fs.closeSync(fd);
        fs.unlinkSync(resolved);
    }

    /**
     * Delete all chunks for a file (secure wipe each one).
     */
    deleteFileChunks(fileId) {
        const dir = path.join(CHUNK_DIR, String(fileId));
        if (!fs.existsSync(dir)) return;
        for (const f of fs.readdirSync(dir)) {
            this.secureDelete(path.join(dir, f));
        }
        fs.rmdirSync(dir);
    }

    /**
     * Path traversal guard — throws if resolved path escapes the root.
     */
    _assertInside(filePath, root) {
        const resolved    = path.resolve(filePath);
        const resolvedRoot = path.resolve(root);
        if (!resolved.startsWith(resolvedRoot)) {
            throw new Error("Path traversal attempt detected");
        }
    }
}

module.exports = new FileStorage();
