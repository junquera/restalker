#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extended test for phone detection in different contexts"""

from restalker import reStalker, Phone

test_cases = [
    # Case 1: Hash alone
    ("56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518", 
     "Hash alone", 0),
    
    # Case 2: Hash with spaces around
    ("Hash: 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518 verified",
     "Hash with spaces", 0),
    
    # Case 3: Hash with line breaks
    ("Hash:\n56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518\nNext line",
     "Hash with line breaks", 0),
    
    # Case 4: Multiple hashes
    ("H1: 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518 H2: ABC123DEF456",
     "Multiple hashes", 0),
    
    # Case 5: Real phone should be detected
    ("The phone is 542179 please call",
     "Real isolated phone", 1),
    
    # Case 6: Hash in a larger text
    ("The file hash is 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518 and the phone is 123456789",
     "Hash with real phone", 1),
]

stalker = reStalker(phone=True)
all_passed = True

for i, (text, description, expected_phones) in enumerate(test_cases, 1):
    print(f"\n{'='*70}")
    print(f"Test {i}: {description}")
    print(f"Text: {text[:80]}{'...' if len(text) > 80 else ''}")
    
    results = list(stalker.parse(text))
    phones = [r for r in results if isinstance(r, Phone)]
    
    print(f"Expected phones: {expected_phones}")
    print(f"Detected phones: {len(phones)}")
    if phones:
        for phone in phones:
            print(f"  - {phone.value}")
    
    if len(phones) == expected_phones:
        print("✓ PASSED")
    else:
        print(f"✗ FAILED: Expected {expected_phones}, got {len(phones)}")
        all_passed = False

print(f"\n{'='*70}")
if all_passed:
    print("✓✓✓ ALL TESTS PASSED")
else:
    print("✗✗✗ SOME TESTS FAILED")
