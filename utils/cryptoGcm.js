const crypto = require("crypto");
const { Transform } = require("stream");

// 1MB max chunk size. Any data > 1MB gets split.
const CHUNK_SIZE = 1024 * 1024;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = 4; // To store ChunkLength (UInt32BE)

class ChunkEncryptor extends Transform {
    constructor(aesKey) {
        super();
        this.aesKey = aesKey;
        this.buffer = Buffer.alloc(0);
    }

    _transform(chunk, encoding, callback) {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this.processBuffer();
        callback();
    }

    _flush(callback) {
        if (this.buffer.length > 0) {
            this.processBuffer(true);
        }
        callback();
    }

    processBuffer(flush = false) {
        while (this.buffer.length >= CHUNK_SIZE || (flush && this.buffer.length > 0)) {
            const sizeToEmit = Math.min(this.buffer.length, CHUNK_SIZE);
            const plaintext = this.buffer.slice(0, sizeToEmit);
            this.buffer = this.buffer.slice(sizeToEmit);

            const iv = crypto.randomBytes(IV_LEN);
            const cipher = crypto.createCipheriv("aes-256-gcm", this.aesKey, iv);
            let ciphertext = cipher.update(plaintext);
            let final = cipher.final();
            ciphertext = Buffer.concat([ciphertext, final]);
            const authTag = cipher.getAuthTag();

            const header = Buffer.alloc(HEADER_LEN);
            header.writeUInt32BE(ciphertext.length, 0);

            // Emit: [4B len][12B IV][16B Tag][Ciphertext]
            this.push(Buffer.concat([header, iv, authTag, ciphertext]));
        }
    }
}

class ChunkDecryptor extends Transform {
    constructor(aesKey) {
        super();
        this.aesKey = aesKey;
        this.buffer = Buffer.alloc(0);
        this.currentChunkLen = null;
    }

    _transform(chunk, encoding, callback) {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        try {
            this.processBuffer();
            callback();
        } catch (err) {
            callback(err);
        }
    }

    processBuffer() {
        while (true) {
            if (this.currentChunkLen === null) {
                // Must read 4 + 12 + 16 = 32 bytes minimum to know the chunk size
                const MIN_HEADER = HEADER_LEN + IV_LEN + TAG_LEN;
                if (this.buffer.length < MIN_HEADER) {
                    break; // Wait for more data
                }
                const ciphertextLen = this.buffer.readUInt32BE(0);
                this.currentChunkLen = MIN_HEADER + ciphertextLen;
            }

            if (this.buffer.length >= this.currentChunkLen) {
                const chunkData = this.buffer.slice(0, this.currentChunkLen);
                this.buffer = this.buffer.slice(this.currentChunkLen);

                let offset = HEADER_LEN;
                const iv = chunkData.slice(offset, offset + IV_LEN);
                offset += IV_LEN;
                const authTag = chunkData.slice(offset, offset + TAG_LEN);
                offset += TAG_LEN;
                const ciphertext = chunkData.slice(offset);

                const decipher = crypto.createDecipheriv("aes-256-gcm", this.aesKey, iv);
                decipher.setAuthTag(authTag);

                try {
                    let plaintext = decipher.update(ciphertext);
                    let finalArgs = decipher.final();
                    plaintext = Buffer.concat([plaintext, finalArgs]);
                    this.push(plaintext);
                } catch (err) {
                    // Auth tag mismatch throws error here
                    throw new Error("Integrity check failed! Chunk tampered.");
                }

                this.currentChunkLen = null; // Ready for next chunk
            } else {
                break; // Wait for more data
            }
        }
    }
}

module.exports = {
    ChunkEncryptor,
    ChunkDecryptor
};
