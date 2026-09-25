/**
 * ui.js — All DOM rendering functions.
 *
 * This module contains ONLY display logic.
 * It never makes API calls or mutates AppState.
 */

// ---------------------------------------------------------------------------
// Progress indicator
// ---------------------------------------------------------------------------

function updateProgress(currentPhase) {
  document.querySelectorAll(".phase-step").forEach((el) => {
    const phase = parseInt(el.dataset.phase);
    el.classList.remove("active", "done");
    if (phase === currentPhase) el.classList.add("active");
    else if (phase < currentPhase) el.classList.add("done");
  });
}

// ---------------------------------------------------------------------------
// Section visibility
// ---------------------------------------------------------------------------

function showSection(id) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.add("visible");
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function hideSection(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove("visible");
}

function resetSections() {
  ["section-protect", "section-packet", "section-transmit", "section-verify", "section-recover"].forEach(hideSection);
}

// ---------------------------------------------------------------------------
// Loading / error states
// ---------------------------------------------------------------------------

function showLoading(buttonEl, text = "Processing…") {
  buttonEl.disabled = true;
  buttonEl.dataset.originalText = buttonEl.textContent;
  buttonEl.innerHTML = `<span class="btn-spinner"></span>${text}`;
}

function hideLoading(buttonEl) {
  buttonEl.disabled = false;
  buttonEl.textContent = buttonEl.dataset.originalText || "Submit";
}

function showError(containerId, message) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `<div class="alert alert-error"><span class="alert-icon">&#9888;</span>${escapeHtml(message)}</div>`;
  el.style.display = "block";
}

function clearError(containerId) {
  const el = document.getElementById(containerId);
  if (el) { el.innerHTML = ""; el.style.display = "none"; }
}

// ---------------------------------------------------------------------------
// Protection steps animation
// ---------------------------------------------------------------------------

function renderProtectionSteps(steps, mode) {
  const container = document.getElementById("protect-steps");
  if (!container) return;
  container.innerHTML = "";

  const modeLabel = mode === "AH"
    ? '<span class="badge badge-ah">AH</span> Authentication Header — HMAC-SHA256'
    : '<span class="badge badge-esp">ESP</span> Encapsulating Security Payload — AES-256-GCM';

  container.innerHTML = `<div class="mode-header">${modeLabel}</div><div class="steps-flow" id="steps-flow"></div>`;
  const flow = document.getElementById("steps-flow");

  steps.forEach((step, i) => {
    const div = document.createElement("div");
    div.className = "step-card";
    div.style.animationDelay = `${i * 0.18}s`;
    div.innerHTML = `
      <div class="step-number">${step.step}</div>
      <div class="step-body">
        <div class="step-title">${escapeHtml(step.title)}</div>
        <div class="step-desc">${escapeHtml(step.description)}</div>
        ${step.value ? `<div class="step-value mono">${escapeHtml(step.value)}</div>` : ""}
      </div>
    `;
    flow.appendChild(div);

    if (i < steps.length - 1) {
      const arrow = document.createElement("div");
      arrow.className = "step-arrow";
      arrow.innerHTML = "&#8595;";
      flow.appendChild(arrow);
    }
  });
}

// ---------------------------------------------------------------------------
// Protected packet card
// ---------------------------------------------------------------------------

function renderProtectedPacket(sender, receiver, protectedPacket) {
  const container = document.getElementById("packet-card");
  if (!container) return;

  const mode = protectedPacket.mode;
  const isModeAH = mode === "AH";

  let fieldsHtml = `
    <div class="packet-row"><span class="packet-label">Sender</span><span class="packet-value">${escapeHtml(sender)}</span></div>
    <div class="packet-row"><span class="packet-label">Receiver</span><span class="packet-value">${escapeHtml(receiver)}</span></div>
    <div class="packet-row"><span class="packet-label">Mode</span><span class="packet-value"><span class="badge badge-${mode.toLowerCase()}">${mode}</span></span></div>
  `;

  if (isModeAH) {
    fieldsHtml += `
      <div class="packet-row"><span class="packet-label">Payload</span><span class="packet-value">${escapeHtml(protectedPacket.payload)}</span></div>
      <div class="packet-row"><span class="packet-label">Auth Tag</span><span class="packet-value mono truncate">${escapeHtml(protectedPacket.authentication_tag)}</span><button class="copy-btn" onclick="copyToClipboard('${escapeHtml(protectedPacket.authentication_tag)}')">Copy</button></div>
    `;
  } else {
    fieldsHtml += `
      <div class="packet-row"><span class="packet-label">Ciphertext</span><span class="packet-value mono truncate">${escapeHtml(protectedPacket.ciphertext)}</span><button class="copy-btn" onclick="copyToClipboard('${escapeHtml(protectedPacket.ciphertext)}')">Copy</button></div>
      <div class="packet-row"><span class="packet-label">Nonce</span><span class="packet-value mono">${escapeHtml(protectedPacket.nonce)}</span></div>
      <div class="packet-row"><span class="packet-label">Auth Tag</span><span class="packet-value mono truncate">${escapeHtml(protectedPacket.authentication_tag)}</span><button class="copy-btn" onclick="copyToClipboard('${escapeHtml(protectedPacket.authentication_tag)}')">Copy</button></div>
    `;
  }

  const headerClass = isModeAH ? "ah-header" : "esp-header";
  container.innerHTML = `
    <div class="packet-card">
      <div class="packet-header ${headerClass}">
        <span class="packet-icon">${isModeAH ? "&#128274;" : "&#128272;"}</span>
        ${mode} PROTECTED PACKET
      </div>
      <div class="packet-fields">${fieldsHtml}</div>
    </div>
    ${isModeAH
      ? `<div class="info-note"><strong>Note:</strong> AH does not encrypt the message. The payload remains readable. Only authentication and integrity are protected.</div>`
      : `<div class="info-note"><strong>Note:</strong> ESP encrypts the message. The original text is hidden inside the ciphertext. Confidentiality is protected.</div>`}
  `;
}

// ---------------------------------------------------------------------------
// Network transmission animation
// ---------------------------------------------------------------------------

function renderTransmission(sender, receiver, modified) {
  const container = document.getElementById("transmission-viz");
  if (!container) return;

  container.innerHTML = `
    <div class="net-path">
      <div class="net-node sender-node">
        <div class="node-icon">&#128100;</div>
        <div class="node-label">${escapeHtml(sender)}</div>
        <div class="node-role">Sender</div>
      </div>
      <div class="net-line">
        <div class="packet-dot ${modified ? "packet-dot-modified" : "packet-dot-ok"}" id="packet-dot"></div>
        <div class="net-label">Protected Packet</div>
        ${modified ? `<div class="attacker-node">
          <div class="attacker-icon">&#128373;</div>
          <div class="attacker-label">Attacker</div>
          <div class="attacker-action">Packet Modified</div>
        </div>` : ""}
      </div>
      <div class="net-node receiver-node">
        <div class="node-icon">&#128100;</div>
        <div class="node-label">${escapeHtml(receiver)}</div>
        <div class="node-role">Receiver</div>
      </div>
    </div>
  `;

  // Trigger the travel animation
  setTimeout(() => {
    const dot = document.getElementById("packet-dot");
    if (dot) dot.classList.add("traveling");
  }, 100);
}

// ---------------------------------------------------------------------------
// Modification diff view
// ---------------------------------------------------------------------------

function renderModification(detail) {
  const container = document.getElementById("modification-diff");
  if (!container || !detail) { if (container) container.innerHTML = ""; return; }

  container.innerHTML = `
    <div class="diff-card">
      <div class="diff-header">
        <span class="diff-icon">&#9888;</span>
        Packet Modified — Field: <strong>${escapeHtml(detail.field)}</strong>
      </div>
      <div class="diff-body">
        <div class="diff-row diff-before">
          <span class="diff-marker">&#8722;</span>
          <span class="diff-label">Before:</span>
          <span class="mono">${escapeHtml(String(detail.before))}</span>
        </div>
        <div class="diff-row diff-after">
          <span class="diff-marker">+</span>
          <span class="diff-label">After:</span>
          <span class="mono">${escapeHtml(String(detail.after))}</span>
        </div>
      </div>
      <div class="diff-explanation">${escapeHtml(detail.explanation)}</div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

function renderVerification(result) {
  const container = document.getElementById("verify-cards");
  if (!container) return;

  const checks = [
    { label: "Authentication", key: "authentication" },
    { label: "Integrity", key: "integrity" },
    { label: "Confidentiality", key: "confidentiality" },
  ];

  const cardsHtml = checks.map(({ label, key }) => {
    const check = result[key];
    const isValid = check.status === "VALID" || check.status === "PROTECTED";
    const isNA = check.status === "NOT_APPLICABLE";
    const statusClass = isNA ? "status-na" : (isValid ? "status-valid" : "status-invalid");
    const icon = isNA ? "&#9135;" : (isValid ? "&#10003;" : "&#10007;");
    return `
      <div class="verify-card ${statusClass}">
        <div class="verify-icon">${icon}</div>
        <div class="verify-label">${label}</div>
        <div class="verify-status">${check.status}</div>
        ${check.detail ? `<div class="verify-detail">${escapeHtml(check.detail)}</div>` : ""}
      </div>
    `;
  }).join("");

  const accepted = result.packet_status === "ACCEPTED";
  const overallClass = accepted ? "overall-accepted" : "overall-rejected";
  const overallIcon = accepted ? "&#10003;" : "&#10007;";

  container.innerHTML = `
    <div class="verify-grid">${cardsHtml}</div>
    <div class="overall-status ${overallClass}">
      <span class="overall-icon">${overallIcon}</span>
      <div>
        <div class="overall-label">Packet ${result.packet_status}</div>
        ${result.reason ? `<div class="overall-reason">${escapeHtml(result.reason)}</div>` : ""}
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Recovery result
// ---------------------------------------------------------------------------

function renderRecovery(response, securityMode) {
  const container = document.getElementById("recovery-content");
  if (!container) return;

  const accepted = response.packet_status === "ACCEPTED";
  const message = response.recovered_message;

  // Recovery steps
  const stepsHtml = (response.recovery_steps || []).map((s, i) => `
    <div class="recovery-step" style="animation-delay:${i * 0.15}s">
      <div class="step-number">${s.step}</div>
      <div class="step-body">
        <div class="step-title">${escapeHtml(s.title)}</div>
        <div class="step-desc">${escapeHtml(s.description)}</div>
        ${s.value ? `<div class="step-value mono">"${escapeHtml(s.value)}"</div>` : ""}
      </div>
    </div>
    ${i < (response.recovery_steps.length - 1) ? '<div class="step-arrow">&#8595;</div>' : ""}
  `).join("");

  if (accepted && message) {
    container.innerHTML = `
      <div class="steps-flow">${stepsHtml}</div>
      <div class="recovered-message-card">
        <div class="recovered-label">Recovered Message</div>
        <div class="recovered-text">"${escapeHtml(message)}"</div>
      </div>
    `;
  } else {
    container.innerHTML = `
      <div class="steps-flow">${stepsHtml}</div>
      <div class="recovery-blocked">
        <div class="blocked-icon">&#128274;</div>
        <div class="blocked-title">Message Recovery Blocked</div>
        <div class="blocked-desc">
          The packet failed verification and was rejected.
          ${securityMode === "ESP" ? "Decryption is not attempted for packets that fail authentication." : "The packet data could not be authenticated."}
        </div>
      </div>
    `;
  }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {
    // Fallback for environments where clipboard API is unavailable
    const el = document.createElement("textarea");
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
  });
  // Brief visual feedback
  const tooltip = document.createElement("div");
  tooltip.className = "copy-tooltip";
  tooltip.textContent = "Copied!";
  document.body.appendChild(tooltip);
  setTimeout(() => document.body.removeChild(tooltip), 1200);
}

function setModeExplanation(mode) {
  const ahEl = document.getElementById("explain-ah");
  const espEl = document.getElementById("explain-esp");
  if (!ahEl || !espEl) return;
  ahEl.classList.toggle("explain-active", mode === "AH");
  espEl.classList.toggle("explain-active", mode === "ESP");
}
