"""
test_verification.py — Unit tests for the verification and recovery service.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from app.services.ah_service import protect_with_ah
from app.services.esp_service import protect_with_esp
from app.services.attack_service import tamper_packet
from app.services.verification_service import verify_packet, recover_message


SENDER = "Alice"
RECEIVER = "Bob"
MESSAGE = "Hello Bob, this is a test."


# ---------------------------------------------------------------------------
# AH verification
# ---------------------------------------------------------------------------

def test_verify_ah_valid():
    packet = protect_with_ah(SENDER, RECEIVER, MESSAGE)
    result = verify_packet("AH", SENDER, RECEIVER, MESSAGE, packet)
    assert result["packet_status"] == "ACCEPTED"


def test_verify_ah_tampered():
    packet = protect_with_ah(SENDER, RECEIVER, MESSAGE)
    tampered, _ = tamper_packet("AH", "DATA", packet, new_data="Hello Eve")
    result = verify_packet("AH", SENDER, RECEIVER, MESSAGE, tampered)
    assert result["packet_status"] == "REJECTED"


# ---------------------------------------------------------------------------
# ESP verification
# ---------------------------------------------------------------------------

def test_verify_esp_valid():
    packet = protect_with_esp(MESSAGE)
    result = verify_packet("ESP", SENDER, RECEIVER, MESSAGE, packet)
    assert result["packet_status"] == "ACCEPTED"


def test_verify_esp_tampered():
    packet = protect_with_esp(MESSAGE)
    tampered, _ = tamper_packet("ESP", "AUTH_TAG", packet)
    result = verify_packet("ESP", SENDER, RECEIVER, MESSAGE, tampered)
    assert result["packet_status"] == "REJECTED"


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

def test_recover_ah_valid():
    packet = protect_with_ah(SENDER, RECEIVER, MESSAGE)
    result = recover_message("AH", SENDER, RECEIVER, MESSAGE, packet)
    assert result["packet_status"] == "ACCEPTED"
    assert result["recovered_message"] == MESSAGE


def test_recover_ah_tampered():
    packet = protect_with_ah(SENDER, RECEIVER, MESSAGE)
    tampered, _ = tamper_packet("AH", "DATA", packet, new_data="Hello Eve")
    result = recover_message("AH", SENDER, RECEIVER, MESSAGE, tampered)
    assert result["packet_status"] == "REJECTED"
    assert result["recovered_message"] is None


def test_recover_esp_valid():
    packet = protect_with_esp(MESSAGE)
    result = recover_message("ESP", SENDER, RECEIVER, MESSAGE, packet)
    assert result["packet_status"] == "ACCEPTED"
    assert result["recovered_message"] == MESSAGE


def test_recover_esp_tampered():
    packet = protect_with_esp(MESSAGE)
    tampered, _ = tamper_packet("ESP", "DATA", packet)
    result = recover_message("ESP", SENDER, RECEIVER, MESSAGE, tampered)
    assert result["packet_status"] == "REJECTED"
    assert result["recovered_message"] is None
