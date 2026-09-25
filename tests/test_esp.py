"""
test_esp.py — Unit tests for the ESP (Encapsulating Security Payload) service.

Tests:
  - Correct packet verifies as VALID and message is recovered
  - Modified ciphertext causes INVALID verification
  - Modified authentication tag causes INVALID verification
  - Invalid packet does not return a recovered message
"""

import pytest
from app.services.esp_service import protect_with_esp, verify_esp, recover_esp_message


MESSAGE = "Hello Bob, this is a confidential message."


@pytest.fixture
def protected():
    result = protect_with_esp(MESSAGE)
    return result


def test_esp_protect_hides_plaintext(protected):
    """ESP ciphertext must not equal the original message."""
    assert protected["ciphertext"] != MESSAGE
    assert protected["ciphertext"] != MESSAGE.encode().hex()


def test_esp_protect_has_all_fields(protected):
    """Protected ESP packet must have ciphertext, nonce, and authentication_tag."""
    assert "ciphertext" in protected
    assert "nonce" in protected
    assert "authentication_tag" in protected


def test_esp_correct_packet_verifies_valid(protected):
    """An unmodified ESP packet must pass verification."""
    result = verify_esp(protected)
    assert result["packet_status"] == "ACCEPTED"
    assert result["authentication"]["status"] == "VALID"
    assert result["integrity"]["status"] == "VALID"
    assert result["confidentiality"]["status"] == "PROTECTED"


def test_esp_correct_packet_message_recovered(protected):
    """Message recovery must return the original message for a valid packet."""
    success, message = recover_esp_message(protected)
    assert success is True
    assert message == MESSAGE


def test_esp_modified_ciphertext_verifies_invalid(protected):
    """Flipping ciphertext bits must cause verification to fail."""
    ct = bytearray.fromhex(protected["ciphertext"])
    ct[0] ^= 0xFF
    protected["ciphertext"] = ct.hex()
    result = verify_esp(protected)
    assert result["packet_status"] == "REJECTED"
    assert result["authentication"]["status"] == "INVALID"


def test_esp_modified_auth_tag_verifies_invalid(protected):
    """Replacing the GCM tag must cause verification to fail."""
    protected["authentication_tag"] = "00" * 16   # 16 zero bytes
    result = verify_esp(protected)
    assert result["packet_status"] == "REJECTED"


def test_esp_invalid_packet_no_message_recovery(protected):
    """A modified ESP packet must not yield a recovered message."""
    protected["ciphertext"] = "deadbeef" * 4
    success, message = recover_esp_message(protected)
    assert success is False
    assert message is None


def test_esp_wrong_nonce_verifies_invalid(protected):
    """Using a different nonce must cause decryption / verification to fail."""
    import secrets
    protected["nonce"] = secrets.token_hex(12)
    result = verify_esp(protected)
    assert result["packet_status"] == "REJECTED"
