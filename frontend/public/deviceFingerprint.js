/**
 * deviceFingerprint.js
 * Browser-side device fingerprint generator.
 * Sends fingerprint as x-device-fingerprint header on every API request.
 * Uses canvas + audio context for stable cross-session identification.
 */

async function generateFingerprint() {
  const components = [
    navigator.userAgent,
    navigator.language,
    (navigator.languages || []).join(","),
    `${screen.width}x${screen.height}x${screen.colorDepth}`,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    String(navigator.hardwareConcurrency || 0),
    String(navigator.deviceMemory || 0),
    navigator.platform || "",
    _canvasFingerprint(),
    await _audioFingerprint(),
  ];

  const raw     = components.join("|||");
  const encoded = new TextEncoder().encode(raw);
  const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function _canvasFingerprint() {
  try {
    const canvas = document.createElement("canvas");
    const ctx    = canvas.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillText("SecureCloud-fp-2025", 2, 2);
    return canvas.toDataURL();
  } catch {
    return "canvas_blocked";
  }
}

async function _audioFingerprint() {
  try {
    const ctx  = new OfflineAudioContext(1, 44100, 44100);
    const osc  = ctx.createOscillator();
    const comp = ctx.createDynamicsCompressor();
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    const buf = await ctx.startRendering();
    return String(buf.getChannelData(0)[0]);
  } catch {
    return "audio_blocked";
  }
}

// Cache the fingerprint for the lifetime of this page load
let _cachedFp = null;
async function getFingerprint() {
  if (!_cachedFp) _cachedFp = await generateFingerprint();
  return _cachedFp;
}

// Export for app.js to use when building fetch options
window.__getDeviceFingerprint = getFingerprint;
