import pytest

from restalker.restalker import Card_Number, reStalker


def test_bin_extraction():
    s = reStalker(bin_number=True, credit_card=False, ccn_number=False)
    text = "My BIN is 123456 and another is 87654321. Not a BIN: 12345 or 123456789."
    results = list(s.parse(text))
    bins = [r.value for r in results if r.value.startswith("BIN/IIN=")]
    assert "BIN/IIN=123456" in bins
    assert "BIN/IIN=87654321" in bins
    assert all(len(b.split('=')[1]) in (6,8) for b in bins)
    assert "BIN/IIN=12345" not in bins
    assert "BIN/IIN=123456789" not in bins

def test_ccn_extraction():
    s = reStalker(ccn_number=True, credit_card=False, bin_number=False)
    text = "Valid: 123456789012, 1234567890123456789. Invalid: 1234567, 12345678901234567890."
    results = list(s.parse(text))
    ccns = [r.value for r in results if r.value.startswith("CCN=")]
    assert "CCN=123456789012" in ccns
    assert "CCN=1234567890123456789" in ccns
    assert all(8 <= len(c.split('=')[1]) <= 19 for c in ccns)
    assert "CCN=1234567" not in ccns
    assert "CCN=12345678901234567890" not in ccns

def test_credit_card_and_ccn_no_duplicate():
    # 16-digit Visa, should be detected as credit card, not as generic CCN
    visa = "4111111111111111"
    s = reStalker(credit_card=True, ccn_number=True)
    results = list(s.parse(visa))
    ccns = [r.value for r in results if r.value.startswith("CCN=")]
    cards = [r.value for r in results if r.value.startswith("Companies=")]
    assert len(cards) == 1
    assert len(ccns) == 0  # No duplicate generic CCN for a real card

def test_credit_card_luhn():
    # Should only yield if Luhn valid
    valid = "4111111111111111"  # Visa test
    invalid = "4111111111111121"
    s = reStalker(credit_card=True)
    results_valid = list(s.parse(valid))
    results_invalid = list(s.parse(invalid))
    assert any(isinstance(r, Card_Number) for r in results_valid)
    assert not any(isinstance(r, Card_Number) for r in results_invalid)

if __name__ == "__main__":
    pytest.main([__file__])
