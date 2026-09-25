/**
 * state.js — Application state management.
 *
 * A single plain object holds all simulation state.
 * Mutate only through the provided setter functions.
 * Never access window.* or localStorage — keep state in memory.
 */

const AppState = {
  // Phase tracking (1 = Configure, 2 = Protect, 3 = Transmit, 4 = Verify, 5 = Recover)
  currentPhase: 1,

  // --- Configure (Phase 1) ---
  sender: "Alice",
  receiver: "Bob",
  message: "Hello Bob, this is a secure message.",
  securityMode: "ESP",    // "AH" | "ESP"

  // --- Protect (Phase 2) ---
  protectResponse: null,          // Full /protect response
  protectedPacket: null,          // The protected_packet sub-object

  // --- Transmit / Attack (Phase 3) ---
  packetInFlight: null,           // The packet travelling the network
  wasModified: false,
  modificationDetail: null,       // { field, before, after, explanation }
  modifyResponse: null,

  // --- Verify (Phase 4) ---
  verificationResult: null,

  // --- Recover (Phase 5) ---
  recoverResponse: null,
  recoveredMessage: null,
};

// ---------------------------------------------------------------------------
// Setters — keep mutation explicit
// ---------------------------------------------------------------------------

function setPhase(phase) {
  AppState.currentPhase = phase;
}

function setConfig(sender, receiver, message, securityMode) {
  AppState.sender = sender;
  AppState.receiver = receiver;
  AppState.message = message;
  AppState.securityMode = securityMode;
}

function setProtectResult(response) {
  AppState.protectResponse = response;
  AppState.protectedPacket = response.protected_packet;
  AppState.packetInFlight = response.protected_packet;
  AppState.wasModified = false;
  AppState.modificationDetail = null;
  AppState.modifyResponse = null;
  AppState.verificationResult = null;
  AppState.recoverResponse = null;
  AppState.recoveredMessage = null;
}

function setModifyResult(response) {
  AppState.modifyResponse = response;
  AppState.packetInFlight = response.protected_packet;
  AppState.wasModified = true;
  AppState.modificationDetail = response.modification_detail;
}

function setNoModification() {
  AppState.packetInFlight = AppState.protectedPacket;
  AppState.wasModified = false;
  AppState.modificationDetail = null;
}

function setVerificationResult(result) {
  AppState.verificationResult = result;
}

function setRecoverResult(response) {
  AppState.recoverResponse = response;
  AppState.recoveredMessage = response.recovered_message;
}

function resetSimulation() {
  AppState.currentPhase = 1;
  AppState.protectResponse = null;
  AppState.protectedPacket = null;
  AppState.packetInFlight = null;
  AppState.wasModified = false;
  AppState.modificationDetail = null;
  AppState.modifyResponse = null;
  AppState.verificationResult = null;
  AppState.recoverResponse = null;
  AppState.recoveredMessage = null;
}
