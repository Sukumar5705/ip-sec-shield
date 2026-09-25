"""
crypto.py — Cryptographic utility functions for the IPsec simulator.

Provides:
  - HMAC-SHA256 for AH authentication/integrity simulation
  - AES-256-GCM for ESP authenticated encryption simulation
  - Secure random nonce/key generation
  - Safe constant-time comparison

IMPORTANT: This is an educational simulation only.
"""

import hmac
import hashlib
import secrets
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------
# 32-byte (256-bit) keys generated once at module load time.
# They are never sent to the frontend.
# In production you would load these from a KMS or secrets manager.
AH_KEY: bytes = secrets.token_bytes(32)
ESP_KEY: bytes = secrets.token_bytes(32)


# ---------------------------------------------------------------------------
# HMAC-SHA256 helpers  (AH simulation)
# ---------------------------------------------------------------------------

def compute_hmac(key: bytes, data: bytes) -> str:
    """Return a hex-encoded HMAC-SHA256 tag over *data* using *key*."""
    mac = hmac.new(key, data, hashlib.sha256)
    return mac.hexdigest()


def verify_hmac(key: bytes, data: bytes, expected_tag: str) -> bool:
    """Constant-time comparison of HMAC tag to resist timing attacks."""
    actual = compute_hmac(key, data)
    return hmac.compare_digest(actual, expected_tag)


# ---------------------------------------------------------------------------
# AES-256-GCM helpers  (ESP simulation)
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[str, str, str]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns:
        (ciphertext_hex, nonce_hex, auth_tag_hex)

    Note: AESGCM from the cryptography library appends the 16-byte GCM tag
    to the ciphertext.  We split it out for display purposes so the UI can
    show nonce, ciphertext and auth tag as separate fields.
    """
    nonce = secrets.token_bytes(12)          # 96-bit nonce as recommended for GCM
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # GCM tag is always the last 16 bytes
    ciphertext = ciphertext_with_tag[:-16]
    auth_tag = ciphertext_with_tag[-16:]

    return (
        ciphertext.hex(),
        nonce.hex(),
        auth_tag.hex(),
    )


def aes_gcm_decrypt(key: bytes, ciphertext_hex: str, nonce_hex: str, auth_tag_hex: str) -> bytes:
    """
    Decrypt an AES-256-GCM ciphertext.

    Raises cryptography.exceptions.InvalidTag if authentication fails.
    """
    ciphertext = bytes.fromhex(ciphertext_hex)
    nonce = bytes.fromhex(nonce_hex)
    auth_tag = bytes.fromhex(auth_tag_hex)

    aesgcm = AESGCM(key)
    # Re-combine ciphertext + tag as cryptography expects
    ciphertext_with_tag = ciphertext + auth_tag
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def generate_packet_id() -> str:
    """Return a short unique packet identifier."""
    return "pkt_" + secrets.token_hex(6)


def truncate_hex(value: str, chars: int = 16) -> str:
    """Return first *chars* characters of a hex string followed by '…'."""
    if len(value) <= chars:
        return value
    return value[:chars] + "…"
