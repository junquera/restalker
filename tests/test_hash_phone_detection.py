#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test phone vs hash detection with GLiNER2.

These tests verify that phone numbers embedded in cryptographic hashes
are correctly filtered out, preventing false positives.
"""

from restalker import Phone, reStalker


class TestPhoneVsHashDetection:
    """Test suite for phone number detection in various contexts."""

    def test_phone_in_hex_hash_not_detected(self):
        """Phone-like pattern inside a hex hash should NOT be detected."""
        # This hex string contains what looks like a phone number
        # but is actually part of a cryptographic hash
        text = "56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Expected no phones in hex hash, but found: {[p.value for p in phones]}"
        )

    def test_phone_in_sha256_hash_not_detected(self):
        """Phone-like pattern in SHA256 hash should NOT be detected."""
        # Real SHA256 hash that might contain phone-like patterns
        text = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Expected no phones in SHA256 hash, but found: {[p.value for p in phones]}"
        )

    def test_phone_in_md5_hash_not_detected(self):
        """Phone-like pattern in MD5 hash should NOT be detected."""
        # MD5 hash
        text = "5d41402abc4b2a76b9719d911017c592"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Expected no phones in MD5 hash, but found: {[p.value for p in phones]}"
        )

    def test_real_phone_in_text_detected(self):
        """Real phone number in normal text should be detected."""
        text = "Contact me at +1-555-123-4567 for more information."

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) > 0, "Expected to detect phone number in normal text"
        # Check if phone was detected (with or without formatting)
        normalized_values = [
            p.value.replace("-", "").replace(" ", "").replace("+", "") for p in phones
        ]
        assert any(
            "+1-555-123-4567" in p.value or "15551234567" in normalized_values
            for p in phones
        ), f"Expected phone not found in: {[p.value for p in phones]}"

    def test_phone_with_spaces_detected(self):
        """Phone number with spaces in normal text should be detected."""
        text = "Call me: +44 20 7946 0958"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) > 0, "Expected to detect phone number with spaces"

    def test_multiple_phones_with_hash(self):
        """Multiple phones in text with hash should only detect real phones."""
        text = """
        Contact: +1-555-123-4567
        Hash: 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518
        Support: +44 20 7946 0958
        """

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        # Should detect the 2 real phones but not the hash
        assert len(phones) >= 2, (
            f"Expected at least 2 phones, found: {len(phones)}"
        )

        # Verify no phone values contain mostly hex characters
        for phone in phones:
            # Remove common phone formatting characters
            clean_phone = (
                phone.value
                .replace("-", "").replace(" ", "").replace("+", "")
                .replace("(", "").replace(")", "")
            )
            hex_chars = sum(1 for c in clean_phone if c in "ABCDEFabcdef")
            # Real phones should have minimal hex letters
            assert hex_chars < len(clean_phone) * 0.5, (
                f"Phone '{phone.value}' looks like hex code"
            )

    def test_bitcoin_address_not_detected_as_phone(self):
        """Bitcoin address should not be detected as phone."""
        # Bitcoin addresses can contain numbers that look like phones
        text = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Bitcoin address should not be detected as phone, but found: {[p.value for p in phones]}"
        )

    def test_ethereum_address_not_detected_as_phone(self):
        """Ethereum address should not be detected as phone."""
        text = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Ethereum address should not be detected as phone, but found: {[p.value for p in phones]}"
        )

    def test_phone_at_start_of_hash_not_detected(self):
        """Phone-like pattern at the start of a hex string should NOT be detected."""
        text = "4567890ABCDEF1234567890ABCDEF1234567890ABCDEF12"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Expected no phones at start of hex string, but found: {[p.value for p in phones]}"
        )

    def test_phone_at_end_of_hash_not_detected(self):
        """Phone-like pattern at the end of a hex string should NOT be detected."""
        text = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Expected no phones at end of hex string, but found: {[p.value for p in phones]}"
        )


class TestPhoneContextValidation:
    """Test suite for phone context validation."""

    def test_phone_surrounded_by_letters_not_detected(self):
        """Phone-like number surrounded by letters should NOT be detected."""
        text = "abc1234567890xyz"

        stalker = reStalker(use_gliner=False, phone=True)
        results = list(stalker.parse(text))
        phones = [r for r in results if isinstance(r, Phone)]

        assert len(phones) == 0, (
            f"Expected no phones when surrounded by letters, but found: {[p.value for p in phones]}"
        )

    def test_phone_with_valid_separators_detected(self):
        """Phone with valid separators (space, dash, parens) should be detected."""
        test_cases = [
            "+1 (555) 123-4567",
            "+1-555-123-4567",
            "+1 555 123 4567",
            "(555) 123-4567",
        ]

        stalker = reStalker(use_gliner=False, phone=True)

        for phone_text in test_cases:
            text = f"Call me at {phone_text} today."
            results = list(stalker.parse(text))
            phones = [r for r in results if isinstance(r, Phone)]

            assert len(phones) > 0, (
                f"Expected to detect phone '{phone_text}', but found none"
            )
