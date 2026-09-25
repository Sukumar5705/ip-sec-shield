/**
 * api.js — All HTTP communication with the FastAPI backend.
 *
 * Functions:
 *   protectPacket(sender, receiver, message, securityMode)
 *   modifyPacket(packetId, modificationType, protectedPacket, newData)
 *   verifyPacket(packetId, securityMode, sender, receiver, originalMessage, protectedPacket)
 *   recoverMessage(packetId, securityMode, sender, receiver, originalMessage, protectedPacket)
 *   checkHealth()
 *
 * Never put raw fetch() calls in UI code — always use these functions.
 */

const BASE_URL = "";   // Same origin — FastAPI serves both API and frontend

/**
 * Core fetch wrapper with JSON body and error handling.
 */
async function apiPost(path, body) {
  const response = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const data = await response.json().catch(() => ({
    detail: "Server returned a non-JSON response.",
  }));

  if (!response.ok) {
    const message =
      data?.detail ||
      data?.message ||
      `HTTP ${response.status}: ${response.statusText}`;
    throw new Error(message);
  }

  return data;
}

async function apiGet(path) {
  const response = await fetch(`${BASE_URL}${path}`);
  const data = await response.json().catch(() => ({
    detail: "Non-JSON response.",
  }));
  if (!response.ok) throw new Error(data?.detail || "Request failed.");
  return data;
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/**
 * Protect a packet using AH or ESP.
 */
async function protectPacket(sender, receiver, message, securityMode) {
  return apiPost("/api/ipsec/protect", {
    sender,
    receiver,
    message,
    security_mode: securityMode,
  });
}

/**
 * Simulate an attacker modifying the packet.
 * modificationType: "DATA" | "AUTH_TAG" | "HEADER"
 */
async function modifyPacket(packetId, modificationType, protectedPacket, newData = null) {
  return apiPost("/api/ipsec/modify", {
    packet_id: packetId,
    modification_type: modificationType,
    protected_packet: protectedPacket,
    new_data: newData,
  });
}

/**
 * Ask the backend to verify authentication and integrity.
 */
async function verifyPacket(packetId, securityMode, sender, receiver, originalMessage, protectedPacket) {
  return apiPost("/api/ipsec/verify", {
    packet_id: packetId,
    security_mode: securityMode,
    sender,
    receiver,
    original_message: originalMessage,
    protected_packet: protectedPacket,
    modified: false,
  });
}

/**
 * Ask the backend to verify and recover the original message.
 */
async function recoverMessage(packetId, securityMode, sender, receiver, originalMessage, protectedPacket) {
  return apiPost("/api/ipsec/recover", {
    packet_id: packetId,
    security_mode: securityMode,
    sender,
    receiver,
    original_message: originalMessage,
    protected_packet: protectedPacket,
  });
}

/**
 * Check backend health.
 */
async function checkHealth() {
  return apiGet("/api/health");
}
