"""
test_ah.py — Unit tests for the AH (Authentication Header) service.

Tests:
  - Correct message produces a VALID verification result
  - Modified message causes INVALID verification
  - Modified authentication tag causes INVALID verification
"""

import pytest
from app.services.ah_service import protect_with_ah, verify_ah


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SENDER = "Alice"
RECEIVER = "Bob"
MESSAGE = "Hello Bob, this is a secure message."


@pytest.fixture
def protected():
    """Return an AH-protected packet."""
    result = protect_with_ah(SENDER, RECEIVER, MESSAGE)
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_ah_protect_returns_readable_payload(protected):
    """AH must NOT encrypt — payload should be the original message."""
    assert protected["payload"] == MESSAGE


def test_ah_protect_produces_authentication_tag(protected):
    """AH protection must produce a non-empty authentication tag."""
    assert len(protected["authentication_tag"]) > 0


def test_ah_correct_message_verifies_valid(protected):
    """An unmodified AH packet must pass verification."""
    result = verify_ah(SENDER, RECEIVER, protected)
    assert result["packet_status"] == "ACCEPTED"
    assert result["authentication"]["status"] == "VALID"
    assert result["integrity"]["status"] == "VALID"


def test_ah_modified_message_verifies_invalid(protected):
    """Changing the payload must cause verification to fail."""
    protected["payload"] = "Hello Eve"
    result = verify_ah(SENDER, RECEIVER, protected)
    assert result["packet_status"] == "REJECTED"
    assert result["authentication"]["status"] == "INVALID"
    assert result["integrity"]["status"] == "INVALID"


def test_ah_modified_tag_verifies_invalid(protected):
    """Replacing the authentication tag must cause verification to fail."""
    protected["authentication_tag"] = "a" * 64   # 32-byte fake HMAC
    result = verify_ah(SENDER, RECEIVER, protected)
    assert result["packet_status"] == "REJECTED"
    assert result["authentication"]["status"] == "INVALID"


def test_ah_protection_steps_present(protected):
    """Protection steps should be provided for the frontend UI."""
    # protect_with_ah returns protection_steps before packet_service pops them
    # Here we call protect_with_ah directly which includes the steps
    result = protect_with_ah(SENDER, RECEIVER, MESSAGE)
    assert "protection_steps" in result
    assert len(result["protection_steps"]) >= 3
