"""
ah_service.py — Authentication Header (AH) simulation service.

Demonstrates:
  - Authentication   (message came from expected sender)
  - Integrity        (message was not altered in transit)
  - NO confidentiality (payload remains readable)

Algorithm: HMAC-SHA256 over a canonical packet representation.

EDUCATIONAL NOTE:
  This is a simplified academic simulation.  Real IPsec AH (RFC 4302)
  covers a carefully defined set of immutable IP header fields plus the
  entire upper-layer payload.  Here we cover sender, receiver, and message
  to keep the demonstration clear and code-readable.
"""

import json
from ..utils.crypto import AH_KEY, compute_hmac, verify_hmac, truncate_hex


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_canonical_data(sender: str, receiver: str, message: str) -> bytes:
    """
    Produce a deterministic byte representation of the packet fields
    that AH is supposed to protect.

    Using JSON with sorted keys guarantees the same byte sequence every
    time the same inputs are provided.
    """
    canonical = json.dumps(
        {"sender": sender, "receiver": receiver, "message": message},
        sort_keys=True,
        ensure_ascii=False,
    )
    return canonical.encode("utf-8")


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def protect_with_ah(sender: str, receiver: str, message: str) -> dict:
    """
    Apply simulated AH protection to a packet.

    Returns a dict containing:
      - payload        : the original readable message (AH does NOT encrypt)
      - authentication_tag : HMAC-SHA256 hex tag
      - protection_steps   : ordered list of step descriptions for the UI
    """
    canonical_data = _build_canonical_data(sender, receiver, message)
    auth_tag = compute_hmac(AH_KEY, canonical_data)

    protection_steps = [
        {
            "step": 1,
            "title": "Original Message",
            "description": f'The plaintext message "{message}" is prepared for protection.',
            "value": message,
        },
        {
            "step": 2,
            "title": "Build Canonical Packet Data",
            "description": (
                "A deterministic representation of sender, receiver, and message "
                "is created. This is the data that HMAC will cover."
            ),
            "value": canonical_data.decode("utf-8"),
        },
        {
            "step": 3,
            "title": "HMAC-SHA256 Computation",
            "description": (
                "HMAC-SHA256 is applied to the canonical data using a shared secret "
                "known only to the sender and receiver. "
                "This produces an authentication/integrity tag."
            ),
            "value": truncate_hex(auth_tag),
        },
        {
            "step": 4,
            "title": "AH Protected Packet",
            "description": (
                "The original message is kept readable (AH provides no confidentiality). "
                "The authentication tag is attached so the receiver can verify the packet."
            ),
            "value": f"Payload: {message} | Auth Tag: {truncate_hex(auth_tag)}",
        },
    ]

    return {
        "mode": "AH",
        "payload": message,
        "authentication_tag": auth_tag,
        "protection_steps": protection_steps,
    }


def verify_ah(sender: str, receiver: str, protected_packet: dict) -> dict:
    """
    Verify an AH-protected packet.

    The receiver independently re-derives the canonical data from the
    (potentially modified) packet fields and re-computes the HMAC.
    If the result does not match the attached tag the packet is rejected.

    Returns a verification result dict.
    """
    payload = protected_packet.get("payload", "")
    received_tag = protected_packet.get("authentication_tag", "")

    # Re-build canonical data using fields from the received packet.
    # If any field was altered the canonical data will differ and
    # the HMAC will not match.
    canonical_data = _build_canonical_data(sender, receiver, payload)
    tag_valid = verify_hmac(AH_KEY, canonical_data, received_tag)

    if tag_valid:
        return {
            "authentication": {"status": "VALID", "detail": "HMAC-SHA256 tag matches."},
            "integrity": {"status": "VALID", "detail": "Packet data has not been altered."},
            "confidentiality": {"status": "NOT_APPLICABLE", "detail": "AH does not provide confidentiality."},
            "packet_status": "ACCEPTED",
            "reason": None,
        }
    else:
        return {
            "authentication": {
                "status": "INVALID",
                "detail": "Computed HMAC does not match the received tag.",
            },
            "integrity": {
                "status": "INVALID",
                "detail": "Packet data appears to have been modified in transit.",
            },
            "confidentiality": {"status": "NOT_APPLICABLE", "detail": "AH does not provide confidentiality."},
            "packet_status": "REJECTED",
            "reason": (
                "Verification failed: the received packet no longer produces "
                "the expected HMAC-SHA256 tag. The packet was rejected."
            ),
        }
