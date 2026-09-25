"""
verification_service.py — Unified packet verification and message recovery.

Provides a single entry point that dispatches to AH or ESP verification
and handles recovery for ESP.  Route handlers should call these functions
rather than calling ah_service / esp_service directly.
"""

from app.services import ah_service, esp_service


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_packet(
    security_mode: str,
    sender: str,
    receiver: str,
    original_message: str,
    protected_packet: dict,
) -> dict:
    """
    Verify a (possibly modified) packet.

    For AH: re-derives canonical data and checks HMAC.
    For ESP: attempts AES-GCM decryption (tag check implicit).

    Returns a verification result dict suitable for the VerificationResult schema.
    """
    if security_mode == "AH":
        # For AH the sender/receiver from the packet itself are used for
        # canonical data because those are what the attacker may have changed.
        packet_sender = protected_packet.get("sender", sender)
        packet_receiver = protected_packet.get("receiver", receiver)
        packet_payload = protected_packet.get("payload", original_message)
        return ah_service.verify_ah(packet_sender, packet_receiver, protected_packet)

    else:  # ESP
        # The compact ESP representation normally contains only the protected
        # payload fields.  The attack simulator adds sender/receiver metadata
        # when a conceptual header is altered; reject that unexpected metadata
        # instead of treating a header attack as a purely visual change.
        if "sender" in protected_packet or "receiver" in protected_packet:
            return {
                "authentication": {
                    "status": "INVALID",
                    "detail": "Received ESP header metadata does not match the protected packet representation.",
                },
                "integrity": {
                    "status": "INVALID",
                    "detail": "Conceptual packet header was modified in transit.",
                },
                "confidentiality": {"status": "PROTECTED", "detail": "Message remains encrypted with AES-256-GCM."},
                "packet_status": "REJECTED",
                "reason": "Verification failed: protected packet header metadata was modified.",
            }
        return esp_service.verify_esp(protected_packet)


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

def recover_message(
    security_mode: str,
    sender: str,
    receiver: str,
    original_message: str,
    protected_packet: dict,
) -> dict:
    """
    Verify and (for ESP) decrypt the packet to recover the original message.

    Returns a dict with:
      - packet_status      : ACCEPTED | REJECTED
      - recovered_message  : str | None
      - verification       : verification result dict
      - recovery_steps     : ordered list of steps for the UI
    """
    # Step 1: always verify first
    verification = verify_packet(
        security_mode, sender, receiver, original_message, protected_packet
    )
    accepted = verification["packet_status"] == "ACCEPTED"

    # Step 2: attempt recovery
    if security_mode == "AH":
        recovery_steps, recovered_message = _recover_ah(accepted, protected_packet)
    else:
        recovery_steps, recovered_message = _recover_esp(accepted, protected_packet)

    return {
        "packet_status": "ACCEPTED" if accepted else "REJECTED",
        "recovered_message": recovered_message,
        "verification": verification,
        "recovery_steps": recovery_steps,
    }


# ---------------------------------------------------------------------------
# Mode-specific recovery helpers
# ---------------------------------------------------------------------------

def _recover_ah(accepted: bool, protected_packet: dict) -> tuple[list, str | None]:
    """AH recovery: no decryption needed — payload is already readable."""
    if accepted:
        message = protected_packet.get("payload", "")
        steps = [
            {"step": 1, "title": "Verification Passed", "description": "HMAC-SHA256 tag is valid."},
            {"step": 2, "title": "Message Recovery", "description": "AH does not encrypt. The payload is already readable."},
            {"step": 3, "title": "Recovered Message", "description": f'"{message}"', "value": message},
        ]
        return steps, message
    else:
        steps = [
            {"step": 1, "title": "Verification Failed", "description": "HMAC-SHA256 tag did not match. Packet rejected."},
            {"step": 2, "title": "Recovery Blocked", "description": "The packet was rejected. No message is returned."},
        ]
        return steps, None


def _recover_esp(accepted: bool, protected_packet: dict) -> tuple[list, str | None]:
    """ESP recovery: AES-GCM decrypt only if verification passed."""
    if accepted:
        success, message = esp_service.recover_esp_message(protected_packet)
        if success:
            steps = [
                {"step": 1, "title": "Verification Passed", "description": "GCM authentication tag is valid."},
                {"step": 2, "title": "AES-GCM Decryption", "description": "Using the shared ESP key and the nonce to decrypt the ciphertext."},
                {"step": 3, "title": "Recovered Message", "description": f'"{message}"', "value": message},
            ]
            return steps, message
        else:
            # Shouldn't happen if verify_esp passed, but handle defensively
            steps = [
                {"step": 1, "title": "Verification Passed", "description": "GCM authentication tag is valid."},
                {"step": 2, "title": "Decryption Failed", "description": "Unexpected decryption error."},
            ]
            return steps, None
    else:
        steps = [
            {"step": 1, "title": "Verification Failed", "description": "GCM authentication tag invalid. Packet rejected."},
            {"step": 2, "title": "Decryption Blocked", "description": "The packet was rejected. Decryption is not attempted for invalid packets."},
        ]
        return steps, None
