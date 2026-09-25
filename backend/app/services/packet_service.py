"""
packet_service.py — Packet lifecycle management.

Coordinates between AH / ESP services to produce protection responses
and builds the structured objects returned by the /protect endpoint.
"""

from ..utils.crypto import generate_packet_id
from ..models.schemas import ProtectRequest
from . import ah_service, esp_service


def build_protect_response(req: ProtectRequest) -> dict:
    """
    Protect a packet using the requested security mode and return
    all data needed by the frontend to visualize the process.
    """
    packet_id = generate_packet_id()

    if req.security_mode == "AH":
        result = ah_service.protect_with_ah(req.sender, req.receiver, req.message)
    else:
        result = esp_service.protect_with_esp(req.message)

    protection_steps = result.pop("protection_steps")

    return {
        "packet_id": packet_id,
        "sender": req.sender,
        "receiver": req.receiver,
        "security_mode": req.security_mode,
        "original_message": req.message,
        "protected_packet": result,
        "status": "PROTECTED",
        "protection_steps": protection_steps,
    }
