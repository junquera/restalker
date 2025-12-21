#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Quick test to validate the improved phone regex patterns
"""

from restalker import reStalker, Phone

# Test cases with various phone number formats
test_cases = """
International formats:
+1-234-567-8901
+44 20 7123 4567
+34 666 777 888
+86 138 0013 8000
+1 (555) 123-4567

US/Canada formats:
(555) 123-4567
555-123-4567
555.123.4567
555 123 4567
1-800-123-4567
(800) 555-1234

European formats:
+34 91 123 45 67
+33 1 42 86 82 00
+49 30 12345678
020 7123 4567
91 123 45 67

Mobile formats:
+34 666 777 888
+1 (555) 867-5309
555-867-5309

Extensions:
555-123-4567 ext 123
(555) 123-4567 x456

Contact: +1-555-867-5309
Call me at (555) 123-4567
Phone: +44 20 7123 4567
Tel: 555.123.4567
"""

if __name__ == "__main__":
    stalker = reStalker(phone=True)
    results = list(stalker.parse(test_cases))
    
    phones = [r for r in results if isinstance(r, Phone)]
    
    print(f"\n{'='*60}")
    print(f"Phone Number Detection Test")
    print(f"{'='*60}\n")
    
    print(f"Total phone numbers found: {len(phones)}\n")
    
    valid_count = 0
    invalid_count = 0
    
    for i, phone in enumerate(phones, 1):
        is_valid = Phone.isvalid(phone.value)
        status = "✓ VALID" if is_valid else "✗ INVALID"
        
        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1
        
        print(f"{i:2d}. {status:12s} | {phone.value}")
    
    print(f"\n{'='*60}")
    print(f"Summary: {valid_count} valid, {invalid_count} invalid")
    print(f"{'='*60}\n")
    
    # Test specific formats
    print("\nTesting specific validation rules:")
    
    test_validation = [
        ("+1-555-123-4567", True, "International with dashes"),
        ("555-123-4567", True, "Standard US format"),
        ("(555) 123-4567", True, "Format with parentheses"),
        ("+34 666 777 888", True, "European mobile"),
        ("123", False, "Too short (only 3 digits)"),
        ("12345678901234567890", False, "Too long (20 digits)"),
        ("2023-12-21", False, "Date format (should be rejected)"),
        ("1999-01-01", False, "Date format (should be rejected)"),
        ("abc-def-ghij", False, "No digits"),
    ]
    
    for phone_str, expected, description in test_validation:
        result = Phone.isvalid(phone_str)
        status = "✓" if result == expected else "✗"
        print(f"{status} {description:35s} | {phone_str:20s} | Valid: {result} (expected: {expected})")
