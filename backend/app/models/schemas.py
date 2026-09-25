"""
schemas.py — Pydantic request/response models for the IPsec simulator API.

All models are strict about field types to give clear validation errors.
Secret keys are never included in any response model.
"""

from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared enums / literals
# ---------------------------------------------------------------------------

SecurityMode = Literal["AH", "ESP"]
ModificationType = Literal["DATA", "AUTH_TAG", "HEADER"]
PacketStatus = Literal["PROTECTED", "MODIFIED", "ACCEPTED", "REJECTED"]
CheckStatus = Literal["VALID", "INVALID", "PROTECTED", "NOT_APPLICABLE"]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ProtectRequest(BaseModel):
    sender: str = Field(..., min_length=1, max_length=64, examples=["Alice"])
    receiver: str = Field(..., min_length=1, max_length=64, examples=["Bob"])
    message: str = Field(..., min_length=1, max_length=2048, examples=["Hello Bob"])
    security_mode: SecurityMode = Field(..., examples=["ESP"])


class ModifyRequest(BaseModel):
    """Simulate an attacker modifying the protected packet."""
    packet_id: str
    modification_type: ModificationType
    # For DATA modifications the user can supply a new plaintext payload.
    # For AUTH_TAG / HEADER the backend generates a plausible fake value.
    new_data: Optional[str] = Field(None, max_length=2048)
    # Full protected packet forwarded from the protect response
    protected_packet: dict


class VerifyRequest(BaseModel):
    """Ask the backend to verify a (possibly modified) packet."""
    packet_id: str
    security_mode: SecurityMode
    sender: str
    receiver: str
    original_message: str          # needed so AH can re-derive canonical data
    protected_packet: dict
    modified: bool = False


class RecoverRequest(BaseModel):
    """Ask the backend to recover the original message (ESP only)."""
    packet_id: str
    security_mode: SecurityMode
    sender: str
    receiver: str
    original_message: str
    protected_packet: dict
    modified: bool = False


# ---------------------------------------------------------------------------
# Inner response structures
# ---------------------------------------------------------------------------

class AHProtectedPacket(BaseModel):
    mode: Literal["AH"] = "AH"
    payload: str                    # readable original message
    authentication_tag: str         # HMAC-SHA256 hex


class ESPProtectedPacket(BaseModel):
    mode: Literal["ESP"] = "ESP"
    ciphertext: str                 # AES-GCM ciphertext hex
    nonce: str                      # 96-bit nonce hex
    authentication_tag: str         # GCM auth tag hex


class VerificationDetail(BaseModel):
    status: CheckStatus
    detail: Optional[str] = None


class VerificationResult(BaseModel):
    authentication: VerificationDetail
    integrity: VerificationDetail
    confidentiality: VerificationDetail
    packet_status: Literal["ACCEPTED", "REJECTED"]
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Top-level response models
# ---------------------------------------------------------------------------

class ProtectResponse(BaseModel):
    packet_id: str
    sender: str
    receiver: str
    security_mode: SecurityMode
    original_message: str
    protected_packet: AHProtectedPacket | ESPProtectedPacket
    status: Literal["PROTECTED"] = "PROTECTED"
    # Educational step-by-step description of what happened
    protection_steps: list[dict]


class ModifyResponse(BaseModel):
    packet_id: str
    sender: str
    receiver: str
    security_mode: SecurityMode
    original_message: str
    protected_packet: dict          # possibly modified packet
    modification_type: ModificationType
    modification_detail: dict       # before/after values for the UI
    modified: bool = True
    status: Literal["MODIFIED"] = "MODIFIED"


class RecoverResponse(BaseModel):
    packet_id: str
    packet_status: Literal["ACCEPTED", "REJECTED"]
    recovered_message: Optional[str] = None
    verification: VerificationResult
    recovery_steps: list[dict]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str = "IPsec Security Simulator"
