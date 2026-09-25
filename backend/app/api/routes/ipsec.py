"""
ipsec.py — IPsec simulation API routes.

Endpoints:
  GET  /api/health          — liveness check
  POST /api/ipsec/protect   — apply AH or ESP protection to a packet
  POST /api/ipsec/modify    — simulate attacker tampering
  POST /api/ipsec/verify    — receiver verification
  POST /api/ipsec/recover   — message recovery (ESP decrypt after verification)

Route handlers are intentionally thin — all business logic lives in services/.
"""

from fastapi import APIRouter, HTTPException, status

from ...models.schemas import (
    ProtectRequest,
    ModifyRequest,
    VerifyRequest,
    RecoverRequest,
    HealthResponse,
)
from ...services import packet_service, attack_service, verification_service

router = APIRouter()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check():
    """Return service liveness status."""
    return HealthResponse()


# ---------------------------------------------------------------------------
# Protect
# ---------------------------------------------------------------------------

@router.post("/ipsec/protect", tags=["IPsec"])
def protect_packet(req: ProtectRequest):
    """
    Apply AH or ESP protection to the supplied packet data.

    Returns the protected packet representation and step-by-step
    explanation of the protection process.
    """
    try:
        return packet_service.build_protect_response(req)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Protection failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Modify (attack simulation)
# ---------------------------------------------------------------------------

@router.post("/ipsec/modify", tags=["IPsec"])
def modify_packet(req: ModifyRequest):
    """
    Simulate an attacker modifying a protected packet in transit.

    Returns the modified packet and a before/after diff for the UI.
    """
    if not req.protected_packet:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="protected_packet is required.",
        )

    try:
        modified_packet, modification_detail = attack_service.tamper_packet(
            security_mode=req.protected_packet.get("mode", "AH"),
            modification_type=req.modification_type,
            protected_packet=req.protected_packet,
            new_data=req.new_data,
        )
        return {
            "packet_id": req.packet_id,
            "modification_type": req.modification_type,
            "modification_detail": modification_detail,
            "protected_packet": modified_packet,
            "modified": True,
            "status": "MODIFIED",
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Modification failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

@router.post("/ipsec/verify", tags=["IPsec"])
def verify_packet(req: VerifyRequest):
    """
    Verify authentication and integrity of a (possibly modified) packet.

    Does NOT decrypt — use /recover for that.
    """
    try:
        result = verification_service.verify_packet(
            security_mode=req.security_mode,
            sender=req.sender,
            receiver=req.receiver,
            original_message=req.original_message,
            protected_packet=req.protected_packet,
        )
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification error: {exc}",
        )


# ---------------------------------------------------------------------------
# Recover
# ---------------------------------------------------------------------------

@router.post("/ipsec/recover", tags=["IPsec"])
def recover_message(req: RecoverRequest):
    """
    Verify the packet and (for ESP) decrypt to recover the original message.

    The message is only returned when verification passes.
    A modified/invalid packet is rejected without revealing the message.
    """
    try:
        result = verification_service.recover_message(
            security_mode=req.security_mode,
            sender=req.sender,
            receiver=req.receiver,
            original_message=req.original_message,
            protected_packet=req.protected_packet,
        )
        result["packet_id"] = req.packet_id
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recovery error: {exc}",
        )
