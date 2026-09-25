"""
esp_service.py — Encapsulating Security Payload (ESP) simulation service.

Demonstrates:
  - Confidentiality  (message is encrypted — ciphertext is not readable)
  - Integrity        (GCM authentication tag covers ciphertext)
  - Authentication   (only the holder of the shared ESP key can produce
                      a valid authenticated ciphertext)

Algorithm: AES-256-GCM (authenticated encryption with associated data).

EDUCATIONAL NOTE:
  Real IPsec ESP (RFC 4303) has a specific wire format with SPI, Sequence
  Number, Padding, Next Header, and ICV fields.  This simulator captures
  the essential concepts (encryption + authenticated integrity) without
  reproducing the complete wire format.
"""

from cryptography.exceptions import InvalidTag

from ..utils.crypto import (
    ESP_KEY,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    truncate_hex,
)


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def protect_with_esp(message: str) -> dict:
    """
    Apply simulated ESP protection to a packet.

    Returns a dict containing:
      - ciphertext          : AES-GCM ciphertext (hex)
      - nonce               : 96-bit GCM nonce (hex)
      - authentication_tag  : 128-bit GCM authentication tag (hex)
      - protection_steps    : ordered list of step descriptions for the UI
    """
    plaintext = message.encode("utf-8")
    ciphertext_hex, nonce_hex, auth_tag_hex = aes_gcm_encrypt(ESP_KEY, plaintext)

    protection_steps = [
        {
            "step": 1,
            "title": "Original Message",
            "description": f'The plaintext message "{message}" is ready for encryption.',
            "value": message,
        },
        {
            "step": 2,
            "title": "Generate Nonce",
            "description": (
                "A cryptographically random 96-bit nonce is generated. "
                "Each encryption uses a unique nonce so that encrypting the same "
                "message twice produces different ciphertext."
            ),
            "value": truncate_hex(nonce_hex),
        },
        {
            "step": 3,
            "title": "AES-256-GCM Encryption",
            "description": (
                "The message is encrypted using AES-256 in Galois/Counter Mode. "
                "GCM produces ciphertext AND an authentication tag in one operation. "
                "The original message is no longer readable from the ciphertext alone."
            ),
            "value": truncate_hex(ciphertext_hex),
        },
        {
            "step": 4,
            "title": "Authentication Tag",
            "description": (
                "GCM produces a 128-bit authentication tag that covers the ciphertext. "
                "Any modification to the ciphertext or the tag will cause decryption to fail."
            ),
            "value": truncate_hex(auth_tag_hex),
        },
        {
            "step": 5,
            "title": "ESP Protected Packet",
            "description": (
                "The ciphertext, nonce, and authentication tag are bundled into the "
                "simulated ESP payload. The original message is hidden inside the ciphertext."
            ),
            "value": f"Ciphertext: {truncate_hex(ciphertext_hex)} | Nonce: {truncate_hex(nonce_hex)} | Tag: {truncate_hex(auth_tag_hex)}",
        },
    ]

    return {
        "mode": "ESP",
        "ciphertext": ciphertext_hex,
        "nonce": nonce_hex,
        "authentication_tag": auth_tag_hex,
        "protection_steps": protection_steps,
    }


def verify_esp(protected_packet: dict) -> dict:
    """
    Verify an ESP-protected packet WITHOUT decrypting the message.

    AES-GCM decryption inherently verifies the authentication tag.
    We attempt decryption; if the tag is invalid we reject the packet.

    Returns a verification result dict.
    """
    try:
        _attempt_esp_decrypt(protected_packet)
        return {
            "authentication": {"status": "VALID", "detail": "GCM authentication tag is intact."},
            "integrity": {"status": "VALID", "detail": "Ciphertext has not been altered."},
            "confidentiality": {"status": "PROTECTED", "detail": "Message is encrypted with AES-256-GCM."},
            "packet_status": "ACCEPTED",
            "reason": None,
        }
    except (InvalidTag, ValueError, KeyError) as exc:
        return {
            "authentication": {
                "status": "INVALID",
                "detail": "GCM authentication tag verification failed.",
            },
            "integrity": {
                "status": "INVALID",
                "detail": "Ciphertext or authentication tag has been altered.",
            },
            "confidentiality": {"status": "PROTECTED", "detail": "Message is encrypted with AES-256-GCM."},
            "packet_status": "REJECTED",
            "reason": (
                "Verification failed: the GCM authentication tag does not match. "
                "The packet was rejected without decrypting the payload."
            ),
        }


def recover_esp_message(protected_packet: dict) -> tuple[bool, str | None]:
    """
    Attempt to decrypt and recover the original ESP message.

    Returns:
        (success: bool, message: str | None)

    Decryption only proceeds if GCM authentication succeeds.
    If the tag is invalid, (False, None) is returned.
    """
    try:
        plaintext = _attempt_esp_decrypt(protected_packet)
        return True, plaintext.decode("utf-8")
    except (InvalidTag, ValueError, KeyError):
        return False, None


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _attempt_esp_decrypt(protected_packet: dict) -> bytes:
    """Internal: decrypt using AES-GCM. Raises InvalidTag on failure."""
    ciphertext_hex = protected_packet["ciphertext"]
    nonce_hex = protected_packet["nonce"]
    auth_tag_hex = protected_packet["authentication_tag"]
    return aes_gcm_decrypt(ESP_KEY, ciphertext_hex, nonce_hex, auth_tag_hex)
