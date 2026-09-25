"""
attack_service.py — Simulated packet tampering / attack service.

This module simulates what an attacker could do to an in-transit packet.
This is a CONTROLLED EDUCATIONAL simulation — no real packets are modified.

Supported modification types:
  DATA       — alter the readable payload (AH) or replace ciphertext bytes (ESP)
  AUTH_TAG   — corrupt the authentication/integrity tag
  HEADER     — change sender / receiver metadata
"""

import secrets
from copy import deepcopy


def tamper_packet(
    security_mode: str,
    modification_type: str,
    protected_packet: dict,
    new_data: str | None = None,
) -> tuple[dict, dict]:
    """
    Return (modified_packet, modification_detail).

    modification_detail contains before/after values for the UI diff view.
    """
    packet = deepcopy(protected_packet)
    detail: dict = {}

    if modification_type == "DATA":
        detail = _modify_data(security_mode, packet, new_data)

    elif modification_type == "AUTH_TAG":
        detail = _modify_auth_tag(packet)

    elif modification_type == "HEADER":
        detail = _modify_header(packet)

    return packet, detail


# ---------------------------------------------------------------------------
# Modification helpers
# ---------------------------------------------------------------------------

def _modify_data(mode: str, packet: dict, new_data: str | None) -> dict:
    """Alter the payload field (AH) or flip bits in ciphertext (ESP)."""
    if mode == "AH":
        original = packet.get("payload", "")
        replacement = new_data if new_data else _flip_words(original)
        packet["payload"] = replacement
        return {
            "field": "payload",
            "before": original,
            "after": replacement,
            "explanation": (
                "The attacker changed the readable payload. "
                "Because AH's authentication tag still covers the original data, "
                "the receiver's HMAC check will fail."
            ),
        }
    else:  # ESP
        original_ct = packet.get("ciphertext", "")
        corrupted_ct = _corrupt_hex(original_ct)
        packet["ciphertext"] = corrupted_ct
        return {
            "field": "ciphertext",
            "before": original_ct[:32] + "…",
            "after": corrupted_ct[:32] + "…",
            "explanation": (
                "The attacker flipped bits in the encrypted ciphertext. "
                "AES-GCM's authentication tag covers the ciphertext, "
                "so this modification will be detected during decryption."
            ),
        }


def _modify_auth_tag(packet: dict) -> dict:
    """Replace the authentication tag with a random value."""
    original_tag = packet.get("authentication_tag", "")
    fake_tag = secrets.token_hex(len(original_tag) // 2)
    packet["authentication_tag"] = fake_tag
    return {
        "field": "authentication_tag",
        "before": original_tag[:32] + "…",
        "after": fake_tag[:32] + "…",
        "explanation": (
            "The attacker replaced the authentication tag with a random value. "
            "The receiver's verification will compute the correct tag and find "
            "it does not match this fake one."
        ),
    }


def _modify_header(packet: dict) -> dict:
    """Change sender/receiver metadata if present in the packet."""
    original_sender = packet.get("sender", "Alice")
    original_receiver = packet.get("receiver", "Bob")
    packet["sender"] = "Eve"
    packet["receiver"] = "Mallory"
    return {
        "field": "header",
        "before": f"sender={original_sender}, receiver={original_receiver}",
        "after": "sender=Eve, receiver=Mallory",
        "explanation": (
            "The attacker changed the sender and receiver fields. "
            "For AH, the authentication tag covers these fields and "
            "the verification will fail. For ESP, metadata is checked separately."
        ),
    }


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _flip_words(text: str) -> str:
    """A simple content replacement for demo purposes."""
    replacements = {
        "Bob": "Eve",
        "Alice": "Mallory",
        "Hello": "Hacked",
        "secure": "unsafe",
        "message": "payload",
    }
    result = text
    for original, replacement in replacements.items():
        result = result.replace(original, replacement)
    # If nothing changed, just append "[TAMPERED]"
    if result == text:
        result = text + " [TAMPERED]"
    return result


def _corrupt_hex(hex_string: str) -> str:
    """Flip a few bits in a hex string to simulate ciphertext corruption."""
    if len(hex_string) < 4:
        return secrets.token_hex(len(hex_string) // 2)
    data = bytearray.fromhex(hex_string)
    # Flip a byte near the start of the ciphertext
    data[0] ^= 0xFF
    if len(data) > 4:
        data[4] ^= 0xAA
    return data.hex()
