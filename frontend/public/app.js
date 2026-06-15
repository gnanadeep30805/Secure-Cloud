/* global crypto */
(function () {
  const API = "";

  const state = {
    token: localStorage.getItem("token") || "",
    page: "login",
    files: [],
    activities: [],
    authError: "",
    authMessage: "",
    signupUsername: "",
    signupEmail: "",
    signupPassword: "",
    loginEmail: "",
    loginPassword: "",
    loginOtp: "",
    resetEmail: "",
    resetTotp: "",
    resetPassword: "",
    signupQrDataUrl: "",
    // upload
    uploadMode: "encrypted",
    uploadFile: null,
    uploadHash: "",
    uploadTotp: "",
    uploadMsg: "",
    uploadErr: "",
    // files / download
    selectedFileId: null,
    selectedFileMode: "encrypted",
    fileDetail: null,
    dlStage1Code: "",
    dlStage2Code: "",
    dlMsg: "",
    dlErr: "",
    dlPreviewToken: "",
    dlDownloadToken: "",
    dlIntegrity: null,
    dlOriginalName: "",
    // step-up RBA
    stepUpActive: false,
    stepUpChallengeId: "",
    stepUpType: "",
    stepUpToken: "",
    stepUpErr: "",
    stepUpMsg: "",
    // admin panel
    adminPolicies: [],
    adminPerms: [],
    adminUsers: [], // mock for UI
    adminErr: "",
    adminMsg: "",
  };

  const $ = (id) => document.getElementById(id);

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  function authHeaders() {
    return state.token ? { Authorization: `Bearer ${state.token}` } : {};
  }

  async function api(path, opts = {}) {
    const headers = { ...opts.headers };
    if (opts.json) headers["Content-Type"] = "application/json";
    if (state.token && !opts.skipAuth) headers.Authorization = `Bearer ${state.token}`;
    // Attach device fingerprint on every request (best-effort)
    try {
      if (window.__getDeviceFingerprint) {
        headers["x-device-fingerprint"] = await window.__getDeviceFingerprint();
      }
    } catch { /* non-fatal */ }
    const res = await fetch(`${API}${path}`, {
      ...opts,
      headers,
      body: opts.json ? JSON.stringify(opts.json) : opts.body,
    });
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (!res.ok) {
      if (res.status === 403 && data.code === "STEP_UP_REQUIRED" && data.challengeId) {
        state.stepUpActive = true;
        state.stepUpChallengeId = data.challengeId;
        state.stepUpType = data.type || "totp";
        state.stepUpErr = "";
        state.stepUpMsg = "Unusual activity detected. Please verify your identity.";
        render();
        throw new Error("STEP_UP_REQUIRED"); // Halt promise chain
      }
      if (res.status === 403 && data.layer) {
        throw new Error(`[${data.layer} Block] ${data.reason || data.error || "Access Denied by Zero-Trust"}`);
      }
      throw new Error(data.error || data.msg || data.message || `HTTP ${res.status}`);
    }
    return data;
  }

  async function sha512HexOfFile(file) {
    const buf = await file.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-512", buf);
    return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function loadDashboardData() {
    try { const f = await api("/api/files/list"); state.files = Array.isArray(f) ? f : []; } catch { state.files = []; }
    try { const a = await api("/api/files/activity"); state.activities = Array.isArray(a) ? a : []; } catch { state.activities = []; }
  }

  async function openFileDetail(id, mode) {
    state.selectedFileId = id;
    state.selectedFileMode = mode || "encrypted";
    state.fileDetail = null;
    state.dlStage1Code = "";
    state.dlStage2Code = "";
    state.dlMsg = "";
    state.dlErr = "";
    state.dlPreviewToken = "";
    state.dlDownloadToken = "";
    state.dlIntegrity = null;
    render();
    try { state.fileDetail = await api(`/api/files/${id}/detail`); } catch (e) { state.dlErr = e.message; }
    render();
  }

  function setPage(p) {
    state.page = p;
    state.authError = "";
    state.uploadErr = "";
    state.dlErr = "";
    render();
    if (state.token && (p === "dashboard" || p === "files")) loadDashboardData().then(render);
  }

  function logout() {
    localStorage.removeItem("token");
    state.token = "";
    state.page = "login";
    render();
  }

  /* ── AUTH ── */
  async function submitSignup(e) {
    e.preventDefault(); state.authError = "";
    try {
      const data = await api("/api/auth/signup", {
        method: "POST",
        json: { username: state.signupUsername.trim() || undefined, email: state.signupEmail.trim(), password: state.signupPassword },
        skipAuth: true,
      });
      state.signupQrDataUrl = data.qrImageDataUrl || "";
      state.loginEmail = state.signupEmail.trim();
      state.signupPassword = "";
      state.page = "signupQr";
    } catch (err) { state.authError = err.message; }
    render();
  }

  function finishSignupQr() {
    state.page = "login";
    state.signupQrDataUrl = "";
    state.authMessage = "Sign in with your email, password, and a code from Google Authenticator.";
    render();
  }

  async function submitLogin(e) {
    e.preventDefault(); state.authError = "";
    try {
      const data = await api("/api/auth/login", {
        method: "POST",
        json: { email: state.loginEmail.trim(), password: state.loginPassword, token: state.loginOtp.trim().replace(/\s/g, "") },
        skipAuth: true,
      });
      state.token = data.token;
      localStorage.setItem("token", data.token);
      state.page = "dashboard";
      await loadDashboardData();
    } catch (err) { state.authError = err.message; }
    render();
  }

  async function submitReset(e) {
    e.preventDefault(); state.authError = "";
    try {
      await api("/api/auth/reset-password", {
        method: "POST",
        json: { email: state.resetEmail.trim(), token: state.resetTotp.trim().replace(/\s/g, ""), newPassword: state.resetPassword },
        skipAuth: true,
      });
      state.loginEmail = state.resetEmail.trim();
      state.loginPassword = "";
      state.loginOtp = "";
      state.resetTotp = "";
      state.resetPassword = "";
      state.authMessage = "";
      state.page = "resetDone";
    } catch (err) { state.authError = err.message; }
    render();
  }

  function finishResetDone() {
    state.page = "login";
    state.authMessage = "Sign in with your email, new password, and a 6-digit code from Google Authenticator.";
    render();
  }

  /* ── UPLOAD ── */
  async function onUploadFilePick(e) {
    const f = e.target.files && e.target.files[0];
    state.uploadFile = f || null;
    state.uploadHash = "";
    state.uploadErr = "";
    if (f) {
      try { state.uploadHash = await sha512HexOfFile(f); } catch (err) { state.uploadErr = err.message; }
    }
    render();
  }

  async function submitUpload(e) {
    e.preventDefault();
    state.uploadErr = "";
    state.uploadMsg = "";
    if (!state.uploadFile) { state.uploadErr = "Select a file first."; render(); return; }
    if (!state.uploadTotp.trim()) { state.uploadErr = "Enter the 6-digit Authenticator code."; render(); return; }
    const endpoint = state.uploadMode === "plain" ? "/api/files/upload/plain" : "/api/files/upload/encrypted";
    const fd = new FormData();
    fd.append("totp", state.uploadTotp.trim().replace(/\s/g, ""));
    fd.append("file", state.uploadFile);
    try {
      const uploadHeaders = { ...authHeaders() };
      try {
        if (window.__getDeviceFingerprint) {
          uploadHeaders["x-device-fingerprint"] = await window.__getDeviceFingerprint();
        }
      } catch { /* non-fatal */ }
      const res = await fetch(`${API}${endpoint}`, { method: "POST", headers: uploadHeaders, body: fd });
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = {}; }
      if (!res.ok) throw new Error(data.error || data.msg || text);
      const fid = data.fileId;
      state.uploadMsg = `Uploaded. File ID #${fid}.`;
      state.uploadFile = null;
      state.uploadHash = "";
      state.uploadTotp = "";
      await loadDashboardData();
      window.alert(`Upload successful\n\n${data.originalName}\nStored as file #${fid}.`);
      state.page = "files";
      state.selectedFileId = null;
      state.fileDetail = null;
    } catch (err) { state.uploadErr = err.message; }
    render();
  }

  /* ── DOWNLOAD helpers ── */
  function dlStep1Url() {
    const mode = state.selectedFileMode === "plain" ? "plain" : "encrypted";
    return `/api/files/${state.selectedFileId}/verify-download-1/${mode}`;
  }
  function dlStep2Url() {
    const mode = state.selectedFileMode === "plain" ? "plain" : "encrypted";
    return `/api/files/${state.selectedFileId}/verify-download-2/${mode}`;
  }

  async function verifyDl1() {
    state.dlMsg = ""; state.dlErr = ""; state.dlIntegrity = null; state.dlPreviewToken = "";
    try {
      const data = await api(dlStep1Url(), { method: "POST", json: { token: state.dlStage1Code.trim().replace(/\s/g, "") } });
      state.dlIntegrity = data.integrityMatch === true;
      if (!state.dlIntegrity) {
        state.dlErr = data.error || "Integrity check failed.";
        render(); return;
      }
      state.dlPreviewToken = data.previewToken;
      state.dlOriginalName = data.originalName || "file";
      state.dlMsg = "Integrity verified. Preview loaded. Enter a fresh code for Step 2 to download.";
    } catch (e) { state.dlErr = e.message; }
    render();
  }

  async function verifyDl2() {
    state.dlMsg = ""; state.dlErr = ""; state.dlDownloadToken = "";
    try {
      const data = await api(dlStep2Url(), { method: "POST", json: { token: state.dlStage2Code.trim().replace(/\s/g, "") } });
      state.dlDownloadToken = data.downloadToken;
      state.dlOriginalName = data.originalName || state.dlOriginalName;
      state.dlMsg = "Download authorized.";
    } catch (e) { state.dlErr = e.message; }
    render();
  }

  function finalDownloadUrl() {
    if (!state.dlDownloadToken) return "";
    return `${window.location.origin}/api/files/download-final?token=${encodeURIComponent(state.dlDownloadToken)}`;
  }

  function previewUrl() {
    if (!state.dlPreviewToken) return "";
    return `${window.location.origin}/api/files/preview?token=${encodeURIComponent(state.dlPreviewToken)}`;
  }

  /* ── RENDER AUTH ── */
  function renderAuth() {
    const root = $("root");

    if (state.page === "signupQr") {
      const qrSrc = state.signupQrDataUrl || "";
      const safeQr = qrSrc.replace(/"/g, "&quot;");
      const fallback = `${window.location.origin}/qr/${encodeURIComponent(state.loginEmail || "")}`;
      const qrBlock = qrSrc
        ? `<img src="${safeQr}" width="220" height="220" alt="Scan in Google Authenticator" class="signup-qr-img" />`
        : `<p class="error">QR missing. <a href="${esc(fallback)}" target="_blank">Open QR image</a></p>`;
      root.innerHTML = `<div class="auth-wrap"><div class="auth-card signup-qr-card">
        <h1>Set up Google Authenticator</h1>
        <p class="hint signup-qr-steps">Open <strong>Google Authenticator</strong> → tap <strong>+</strong> → <strong>Scan a QR code</strong> → point at the code below. Then tap <strong>Next</strong>.</p>
        <div class="signup-qr-wrap">${qrBlock}</div>
        <button type="button" class="btn btn-primary" id="signup-qr-next">Next — go to login</button>
      </div></div>`;
      $("signup-qr-next").onclick = finishSignupQr;
      return;
    }

    if (state.page === "resetDone") {
      root.innerHTML = `<div class="auth-wrap"><div class="auth-card signup-qr-card">
        <h1>Password updated</h1>
        <p class="hint signup-qr-steps">Your password was changed. Google Authenticator stays the same — use the same 6-digit code.</p>
        <div class="signup-qr-wrap reset-done-badge" aria-hidden="true">✓</div>
        <button type="button" class="btn btn-primary" id="reset-done-next">Next — go to login</button>
      </div></div>`;
      $("reset-done-next").onclick = finishResetDone;
      return;
    }

    if (state.page === "forgot") {
      root.innerHTML = `<div class="auth-wrap"><div class="auth-card">
        <h1>Reset password</h1>
        <p class="hint">Use your <strong>Google Authenticator</strong> code (same as login).</p>
        <form id="reset-form">
          <div class="field"><label>Email</label><input type="email" required id="reset-email" value="${esc(state.resetEmail)}" /></div>
          <div class="field"><label>Authenticator code (6 digits)</label><input type="text" required id="reset-totp" autocomplete="one-time-code" /></div>
          <div class="field"><label>New password</label><input type="password" id="reset-pass" required minlength="8" /></div>
          <button type="submit" class="btn btn-primary">Update password</button>
        </form>
        <p class="hint"><a id="back-login">Back to login</a></p>
        ${state.authError ? `<p class="error">${esc(state.authError)}</p>` : ""}
      </div></div>`;
      $("reset-form").onsubmit = submitReset;
      $("reset-email").oninput = (e) => (state.resetEmail = e.target.value);
      $("reset-totp").oninput = (e) => (state.resetTotp = e.target.value);
      $("reset-pass").oninput = (e) => (state.resetPassword = e.target.value);
      $("back-login").onclick = () => { state.page = "login"; render(); };
      return;
    }

    const isSignup = state.page === "signup";
    root.innerHTML = `<div class="auth-wrap"><div class="auth-card">
      <h1>${isSignup ? "Create account" : "Sign in"}</h1>
      <form id="auth-form">
        ${isSignup ? `<div class="field"><label>Username (optional)</label><input type="text" id="su-user" placeholder="defaults from email" /></div>` : ""}
        <div class="field"><label>Email</label><input type="email" required id="auth-email" value="${isSignup ? esc(state.signupEmail) : esc(state.loginEmail)}" /></div>
        <div class="field"><label>Password</label><input type="password" required id="auth-pass" /></div>
        ${!isSignup ? `<div class="field"><label>Authenticator code (6 digits)</label><input type="text" required id="auth-otp" placeholder="Google Authenticator" autocomplete="one-time-code" /></div>` : ""}
        <button type="submit" class="btn btn-primary">${isSignup ? "Sign up" : "Log in"}</button>
      </form>
      <p class="hint">${isSignup ? `<a id="to-login">Already have an account?</a>` : `<a id="to-signup">Create account</a> · <a id="to-forgot">Forgot password?</a>`}</p>
      ${state.authError ? `<p class="error">${esc(state.authError)}</p>` : ""}
      ${state.authMessage ? `<p class="success">${esc(state.authMessage)}</p>` : ""}
    </div></div>`;

    $("auth-form").onsubmit = isSignup ? submitSignup : submitLogin;
    if (isSignup) {
      $("su-user").oninput = (e) => (state.signupUsername = e.target.value);
      $("auth-email").oninput = (e) => (state.signupEmail = e.target.value);
      $("auth-pass").oninput = (e) => (state.signupPassword = e.target.value);
    } else {
      $("auth-email").oninput = (e) => (state.loginEmail = e.target.value);
      $("auth-pass").oninput = (e) => (state.loginPassword = e.target.value);
      $("auth-otp").oninput = (e) => (state.loginOtp = e.target.value);
    }
    if ($("to-login")) $("to-login").onclick = () => { state.signupQrDataUrl = ""; state.page = "login"; render(); };
    if ($("to-signup")) $("to-signup").onclick = () => { state.page = "signup"; render(); };
    if ($("to-forgot")) $("to-forgot").onclick = () => { state.signupQrDataUrl = ""; state.page = "forgot"; state.resetEmail = state.loginEmail.trim(); state.resetTotp = ""; state.resetPassword = ""; render(); };
  }

  /* ── RENDER APP ── */
  function renderApp() {
    const navBtn = (id, label) => `<button type="button" data-nav="${id}" class="${state.page === id ? "active" : ""}">${label}</button>`;
    const root = $("root");
    root.innerHTML = `<div class="layout">
      <nav class="nav">
        <span class="brand">Secure Cloud</span>
        ${navBtn("dashboard", "Dashboard")}
        ${navBtn("upload", "Upload")}
        ${navBtn("files", "Files")}
        ${navBtn("admin", "Admin Panel")}
        <button type="button" id="nav-out">Logout</button>
      </nav>
      <main class="page" id="main-page"></main>
      
      <!-- Step-Up RBA Modal -->
      ${state.stepUpActive ? `
        <div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:999;">
          <div class="card" style="width:300px;">
            <h3>Security Verification</h3>
            <p class="hint">${esc(state.stepUpMsg)}</p>
            <div class="field">
              <label>${state.stepUpType === 'email_otp' ? 'Email OTP' : 'Authenticator Code'}</label>
              <input type="text" id="su-token" autocomplete="one-time-code" placeholder="123456" />
            </div>
            <button class="btn btn-primary" id="su-submit">Verify</button>
            <button class="btn btn-secondary" id="su-cancel" style="margin-top:0.5rem;">Cancel</button>
            ${state.stepUpErr ? `<p class="error">${esc(state.stepUpErr)}</p>` : ""}
          </div>
        </div>
      ` : ""}
    </div>`;

    root.querySelectorAll("[data-nav]").forEach((btn) => { btn.onclick = () => setPage(btn.getAttribute("data-nav")); });
    $("nav-out").onclick = logout;

    if (state.stepUpActive) {
      if ($("su-token")) $("su-token").oninput = (e) => (state.stepUpToken = e.target.value);
      if ($("su-cancel")) $("su-cancel").onclick = () => { state.stepUpActive = false; render(); };
      if ($("su-submit")) $("su-submit").onclick = async () => {
        try {
          // Send verification
          await api("/api/auth/step-up", {
            method: "POST",
            json: { challengeId: state.stepUpChallengeId, token: state.stepUpToken }
          });
          state.stepUpActive = false;
          state.stepUpToken = "";
          alert("Verification successful. Please try your action again.");
          render();
        } catch (e) {
          state.stepUpErr = e.message;
          render();
        }
      };
    }

    const main = $("main-page");

    /* ── Dashboard ── */
    if (state.page === "dashboard") {
      main.innerHTML = `<h2>Dashboard</h2>
        <div class="card">
          <p><strong>${state.files.length}</strong> file(s) stored.</p>
          <p class="hint">Upload or manage files using the menu above.</p>
        </div>
        <div class="card">
          <h3 style="margin-top:0;font-size:1rem;">Recent activity</h3>
          ${state.activities.length === 0
          ? `<p class="hint">No activity yet.</p>`
          : state.activities.map((a) => `<div class="activity-item"><strong>${esc(a.action)}</strong>${a.detail ? " — " + esc(a.detail) : ""}<br/><span>${esc(a.created_at)}</span></div>`).join("")}
        </div>`;
    }

    /* ── Upload ── */
    if (state.page === "upload") {
      const isPlain = state.uploadMode === "plain";
      main.innerHTML = `<h2>Secure Upload</h2>
        <div class="card">
          <div class="step"><strong>1.</strong> Choose storage mode</div>
          <div class="mode-toggle" style="display:flex;gap:1rem;margin:0.75rem 0 1.25rem;">
            <label class="mode-btn ${isPlain ? "mode-active" : ""}">
              <input type="radio" name="upmode" value="plain" ${isPlain ? "checked" : ""} id="mode-plain" style="display:none"/>
              <span>🔓 Option 1 — No Encryption</span>
              <small>Your files will be stored in plain text on the server. However, this method uses Hash verification for ensuring data
              integrity and file authenticity but privacy is compromised, and 2FA verification.</small>
            </label>
            <label class="mode-btn ${!isPlain ? "mode-active" : ""}">
              <input type="radio" name="upmode" value="encrypted" ${!isPlain ? "checked" : ""} id="mode-enc" style="display:none"/>
              <span>🔐 Option 2 — Encrypted</span>
              <small>Your files will be encrypted into ciphertext on your device before being uploaded to the server. This is more secure. 
              This method used encryption for data confidentiality and 2FA verification.</small>
            </label>
          </div>

          <div class="step"><strong>2.</strong> Select file</div>
          <input type="file" id="up-file" style="margin-bottom:0.75rem;" />
          ${state.uploadHash ? `<p class="mono hint">SHA-512: ${esc(state.uploadHash)}</p>` : ""}

          <div class="step"><strong>3.</strong> Authenticator code</div>
          <div class="field" style="margin-top:0.75rem;">
            <label>6-digit Authenticator code</label>
            <input type="text" id="up-code" placeholder="123456" autocomplete="one-time-code" value="${esc(state.uploadTotp)}" />
          </div>

          <form id="up-form">
            <button type="submit" class="btn btn-primary" ${!state.uploadFile ? "disabled" : ""}>Upload</button>
          </form>
          ${state.uploadMsg ? `<p class="success">${esc(state.uploadMsg)}</p>` : ""}
          ${state.uploadErr ? `<p class="error">${esc(state.uploadErr)}</p>` : ""}
        </div>`;

      $("mode-plain").onchange = () => { state.uploadMode = "plain"; state.uploadHash = ""; state.uploadFile = null; render(); };
      $("mode-enc").onchange = () => { state.uploadMode = "encrypted"; state.uploadHash = ""; state.uploadFile = null; render(); };
      $("up-file").onchange = onUploadFilePick;
      $("up-code").oninput = (e) => (state.uploadTotp = e.target.value);
      $("up-form").onsubmit = submitUpload;
    }

    /* ── Files ── */
    if (state.page === "files") {
      const fileList = state.files.length === 0
        ? `<p class="hint">No files yet. Upload from the Upload page.</p>`
        : state.files.map((f) => {
          const fid = f.id != null ? f.id : "";
          const label = (f.original_name || f.originalName || "(unnamed)").trim() || "(unnamed)";
          const mode = f.storage_mode || "encrypted";
          const badge = mode === "plain"
            ? `<span class="badge badge-plain">No Encryption</span>`
            : `<span class="badge badge-enc">Encrypted</span>`;
          const when = f.created_at || f.createdAt || "";
          return `<div class="file-row" data-fid="${esc(fid)}" data-mode="${esc(mode)}">
              <span>${esc(label)} ${badge} <span class="hint">#${esc(fid)}</span></span>
              <span class="hint">${esc(when)}</span>
            </div>`;
        }).join("");

      const mode = state.selectedFileMode;
      const isPlain = mode === "plain";

      const detailHtml = state.selectedFileId == null ? "" : `<div class="card" style="margin-top:1rem;">
        <h3 style="margin-top:0;">File #${esc(state.selectedFileId)}
          <span class="badge ${isPlain ? "badge-plain" : "badge-enc"}" style="font-size:0.75rem;margin-left:0.5rem;">${isPlain ? "No Encryption" : "Encrypted"}</span>
        </h3>
        ${state.dlErr && !state.fileDetail ? `<p class="error">${esc(state.dlErr)}</p>` : ""}
        ${!state.fileDetail ? `<p class="hint">Loading…</p>` : `
          <p><strong>Name:</strong> ${esc(state.fileDetail.originalName)}</p>

          <h4 style="margin-top:1.5rem;">Download</h4>

          ${isPlain ? `
            <div class="step"><strong>A.</strong> Integrity check</div>
            <div class="field"><label>6-digit Authenticator code</label><input type="text" id="dl1c" autocomplete="one-time-code" placeholder="123456"/></div>
            <button type="button" class="btn btn-secondary" id="btn-dl1-go">Verify integrity &amp; unlock preview</button>
          ` : `
            <div class="step"><strong>A.</strong> Integrity check</div>
            <div class="field"><label>6-digit Authenticator code</label><input type="text" id="dl1c" autocomplete="one-time-code" placeholder="123456"/></div>
            <button type="button" class="btn btn-secondary" id="btn-dl1-go">Verify integrity &amp; unlock preview</button>
          `}

          ${state.dlPreviewToken ? `
            <p class="success">✓ Integrity verified. Preview:</p>
            <iframe class="preview-frame" title="preview" src="${esc(previewUrl())}"></iframe>
          ` : ""}

          ${state.dlPreviewToken ? `
            <div class="step" style="margin-top:1.5rem;"><strong>B.</strong> Authorize download</div>
            <p class="hint">Wait for the next code in your Authenticator app.</p>
            <div class="field"><label>6-digit Authenticator code</label><input type="text" id="dl2c" autocomplete="one-time-code" placeholder="123456"/></div>
            <button type="button" class="btn btn-secondary" id="btn-dl2-go">Authorize download</button>
          ` : ""}

          ${state.dlDownloadToken ? `
            <p class="success">✓ Download authorized.</p>
            <a class="btn btn-primary" style="display:inline-block;text-decoration:none;margin-top:0.5rem;" href="${esc(finalDownloadUrl())}" download="${esc(state.dlOriginalName)}">⬇ Download ${esc(state.dlOriginalName)}</a>
          ` : ""}

          ${state.dlMsg ? `<p class="success">${esc(state.dlMsg)}</p>` : ""}
          ${state.dlErr ? `<p class="error">${esc(state.dlErr)}</p>` : ""}
        `}
      </div>`;

      main.innerHTML = `<h2>Your Files</h2>
        <div class="card">${fileList}</div>
        ${detailHtml}`;

      main.querySelectorAll(".file-row").forEach((row) => {
        row.onclick = () => openFileDetail(Number(row.getAttribute("data-fid")), row.getAttribute("data-mode"));
      });
      if ($("dl1c")) $("dl1c").oninput = (e) => (state.dlStage1Code = e.target.value);
      if ($("btn-dl1-go")) $("btn-dl1-go").onclick = verifyDl1;
      if ($("dl2c")) $("dl2c").oninput = (e) => (state.dlStage2Code = e.target.value);
      if ($("btn-dl2-go")) $("btn-dl2-go").onclick = verifyDl2;
    }

    /* ── Admin Panel ── */
    if (state.page === "admin") {
      main.innerHTML = `<h2>Admin Panel</h2>
        <div class="card">
          <p class="hint">Administrative controls for Zero-Trust Policies and Roles.</p>
          <div style="margin-top:1rem;">
            <button class="btn btn-secondary" id="admin-load-btn">Load Admin Data</button>
          </div>
          ${state.adminErr ? `<p class="error">${esc(state.adminErr)}</p>` : ""}
          ${state.adminMsg ? `<p class="success">${esc(state.adminMsg)}</p>` : ""}
        </div>
        
        ${state.adminPolicies.length > 0 ? `
          <div class="card" style="margin-top:1rem;">
            <h3>Active ABAC Policies</h3>
            ${state.adminPolicies.map(p => `
              <div style="border-bottom:1px solid #333; padding-bottom:1rem; margin-bottom:1rem;">
                <strong>${esc(p.name)}</strong> (Priority: ${p.priority})<br/>
                <span class="hint">Action: ${esc(p.action)} | Resource: ${esc(p.resource_type)} | Effect: <span style="color:${p.effect === 'deny' ? 'red' : 'lime'}">${esc(p.effect)}</span></span><br/>
                <pre style="background:#111;padding:0.5rem;font-size:0.8rem;border-radius:4px;overflow-x:auto;">
Subj: ${esc(p.subject_conditions)}
Res:  ${esc(p.resource_conditions)}
Env:  ${esc(p.env_conditions)}</pre>
              </div>
            `).join("")}
          </div>
        ` : ""}
        
        <div class="card" style="margin-top:1rem;">
          <h3>Assign Role manually</h3>
          <div class="field"><label>User ID</label><input type="number" id="adm-uid" placeholder="1"/></div>
          <div class="field">
            <label>Role</label>
            <select id="adm-role" style="width:100%;padding:0.75rem;background:#222;color:#fff;border:1px solid #444;border-radius:6px;">
              <option value="admin">Admin</option>
              <option value="editor">Editor</option>
              <option value="viewer">Viewer</option>
              <option value="guest">Guest</option>
            </select>
          </div>
          <button class="btn btn-primary" id="adm-role-btn" style="margin-top:1rem;">Assign Role</button>
        </div>
      `;

      if ($("admin-load-btn")) {
        $("admin-load-btn").onclick = async () => {
          state.adminErr = ""; state.adminMsg = ""; render();
          try {
            const pols = await api("/api/admin/policies/abac");
            state.adminPolicies = Array.isArray(pols) ? pols : [];
            state.adminMsg = "Policies loaded.";
          } catch (e) { state.adminErr = e.message; }
          render();
        };
      }

      if ($("adm-role-btn")) {
        $("adm-role-btn").onclick = async () => {
          state.adminErr = ""; state.adminMsg = "";
          const uid = $("adm-uid").value;
          const role = $("adm-role").value;
          if (!uid) return;
          try {
            await api(`/api/admin/users/${uid}/role`, { method: "POST", json: { role } });
            state.adminMsg = `Assigned ${role} to user ${uid}`;
          } catch (e) { state.adminErr = e.message; }
          render();
        };
      }
    }
  }

  function render() {
    if (!state.token) renderAuth();
    else renderApp();
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (state.token) { state.page = "dashboard"; loadDashboardData().then(render); }
    else render();
  });
})();
