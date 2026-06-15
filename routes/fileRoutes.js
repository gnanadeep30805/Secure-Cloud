const express        = require("express");
const router         = express.Router();
const ctrl           = require("../controllers/secureFileController");
const authMiddleware = require("../middleware/authMiddleware");
const rba            = require("../middleware/rbaMiddleware");
const pep            = require("../middleware/pepMiddleware");
const { uploadLimiter, downloadLimiter } = require("../middleware/threatGuard");

// Pipeline: rateLimiter → auth(JWT+lock) → RBA(risk+step-up) → PEP(ZTA policy) → controller

// ── list / activity (read-only, viewer-level — no RBA, low sensitivity) ──────
router.get("/list",     authMiddleware, pep("preview", "file"), ctrl.listMyFiles);
router.get("/activity", authMiddleware, pep("preview", "file"), ctrl.listActivity);

// ── file detail (viewer-level — no RBA) ──────────────────────────────────────
router.get("/:id/detail", authMiddleware, pep("preview", "file"), ctrl.getFileDetail);

// ── upload (rate-limited + RBA + PEP) ────────────────────────────────────────
router.post("/upload/plain",     uploadLimiter, authMiddleware, rba(), pep("upload", "file"), ctrl.uploadPlain);
router.post("/upload/encrypted", uploadLimiter, authMiddleware, rba(), pep("upload", "file"), ctrl.uploadEncrypted);

// ── download verify steps (rate-limited + RBA + PEP) ─────────────────────────
router.post("/:id/verify-download-1/plain",     downloadLimiter, authMiddleware, rba(), pep("download", "file"), ctrl.verifyDownloadStep1Plain);
router.post("/:id/verify-download-2/plain",     downloadLimiter, authMiddleware, rba(), pep("download", "file"), ctrl.verifyDownloadStep2Plain);
router.post("/:id/verify-download-1/encrypted", downloadLimiter, authMiddleware, rba(), pep("download", "file"), ctrl.verifyDownloadStep1Encrypted);
router.post("/:id/verify-download-2/encrypted", downloadLimiter, authMiddleware, rba(), pep("download", "file"), ctrl.verifyDownloadStep2Encrypted);

// ── token-gated streaming ────────────────────────────────────────────────────
// Scoped JWT tokens validated inside the controller — no PEP/RBA needed
router.get("/preview",        ctrl.sendPreview);
router.get("/download-final", ctrl.sendDownloadFinal);

module.exports = router;
