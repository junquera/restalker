#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Final comprehensive test for hash cases"""

from restalker import reStalker, Phone

print("="*70)
print("FINAL HASH TEST - Testing phone detection in hex contexts")
print("="*70)

test_cases = [
    # User's exact case
    ("56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518",
     "User's exact hash", 0),
    
    # Hash with 542179 specifically
    ("ABC542179DEF",
     "Short hex with 542179", 0),
    
    # Real phone 542179 isolated
    ("Call me at 542179",
     "Real isolated 542179", 1),  
    
    # Hash in normal text
    ("The hash value is 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518 for verification",
     "Hash in sentence", 0),
    
    # Multiple hashes
    ("Hash1: 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518 Hash2: ABC123DEF456789",
     "Multiple hashes", 0),
    
    # Hash with real phone nearby
    ("Hash: 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518 Phone: 555-1234",
     "Hash with nearby phone", 1),
    
    # MD5 hashes (32 chars)
    ("5d41402abc4b2a76b9719d911017c554",
     "MD5 hash", 0),
    
    # SHA256 hashes (64 chars)  
    ("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
     "SHA256 hash", 0),
    
    # Bitcoin address-like
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
     "Bitcoin-like address", 0),
    
    # Mixed case
    ("Test 123ABC456DEF phone should not be detected but 555-1234 should",
     "Mixed alphanumeric and real phone", 1),
]

stalker = reStalker(phone=True)
all_passed = True
failed_cases = []

for i, (text, description, expected) in enumerate(test_cases, 1):
    results = list(stalker.parse(text))
    phones = [r for r in results if isinstance(r, Phone)]
    
    passed = len(phones) == expected
    status = "✓" if passed else "✗"
    
    print(f"\n{status} Test {i:2d}: {description}")
    print(f"  Text: {text[:70]}{'...' if len(text) > 70 else ''}")
    print(f"  Expected: {expected} | Detected: {len(phones)}")
    
    if phones:
        print(f"  Phones: {[p.value for p in phones]}")
    
    if not passed:
        all_passed = False
        failed_cases.append((i, description, expected, len(phones)))

print("\n" + "="*70)
if all_passed:
    print("✓✓✓ ALL TESTS PASSED ✓✓✓")
    print("\nPhone detection correctly handles:")
    print("  - Numbers inside hashes (hex context)")
    print("  - Numbers inside alphanumeric codes")
    print("  - Real isolated phone numbers")
else:
    print("✗✗✗ SOME TESTS FAILED ✗✗✗")
    print("\nFailed tests:")
    for case_num, desc, exp, got in failed_cases:
        print(f"  {case_num}. {desc}: expected {exp}, got {got}")

print("="*70)
