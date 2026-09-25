"""
test_attack.py — Unit tests for the attack (packet tampering) service.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from app.services.attack_service import tamper_packet
from app.services.ah_service import protect_with_ah
from app.services.esp_service import protect_with_esp


SENDER = "Alice"
RECEIVER = "Bob"
MESSAGE = "Hello Bob"


@pytest.fixture
def ah_packet():
    return protect_with_ah(SENDER, RECEIVER, MESSAGE)


@pytest.fixture
def esp_packet():
    return protect_with_esp(MESSAGE)


# ---------------------------------------------------------------------------
# AH attack tests
# ---------------------------------------------------------------------------

def test_ah_data_modification_changes_payload(ah_packet):
    """DATA modification must change the AH payload field."""
    modified, detail = tamper_packet("AH", "DATA", ah_packet, new_data="Hello Eve")
    assert modified["payload"] == "Hello Eve"
    assert detail["field"] == "payload"
    assert detail["before"] != detail["after"]


def test_ah_tag_modification_changes_auth_tag(ah_packet):
    """AUTH_TAG modification must replace the authentication_tag."""
    original_tag = ah_packet["authentication_tag"]
    modified, detail = tamper_packet("AH", "AUTH_TAG", ah_packet)
    assert modified["authentication_tag"] != original_tag
    assert detail["field"] == "authentication_tag"


def test_ah_header_modification_changes_metadata(ah_packet):
    """HEADER modification must change sender/receiver fields."""
    modified, detail = tamper_packet("AH", "HEADER", ah_packet)
    assert modified.get("sender") == "Eve" or detail["field"] == "header"
    assert "Eve" in detail["after"]


# ---------------------------------------------------------------------------
# ESP attack tests
# ---------------------------------------------------------------------------

def test_esp_data_modification_corrupts_ciphertext(esp_packet):
    """DATA modification must corrupt the ESP ciphertext."""
    original_ct = esp_packet["ciphertext"]
    modified, detail = tamper_packet("ESP", "DATA", esp_packet)
    assert modified["ciphertext"] != original_ct
    assert detail["field"] == "ciphertext"


def test_esp_tag_modification_changes_auth_tag(esp_packet):
    """AUTH_TAG modification must replace the GCM authentication tag."""
    original_tag = esp_packet["authentication_tag"]
    modified, detail = tamper_packet("ESP", "AUTH_TAG", esp_packet)
    assert modified["authentication_tag"] != original_tag
