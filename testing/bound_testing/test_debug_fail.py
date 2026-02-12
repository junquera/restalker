#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Debug the failing case"""

from restalker import reStalker, Phone

text = "Test 123ABC456DEF phone should not be detected but 555-1234 should"
print(f"Text: {text}")

stalker = reStalker(phone=True)
results = list(stalker.parse(text))
phones = [r for r in results if isinstance(r, Phone)]

print(f"\nPhones detected: {len(phones)}")
for i, phone in enumerate(phones, 1):
    print(f"{i}. {phone.value}")
    pos = text.find(phone.value)
    if pos != -1:
        print(f"   Position: {pos}")
        # Get context
        context_start = max(0, pos - 10)
        context_end = min(len(text), pos + len(phone.value) + 10)
        before = text[context_start:pos]
        after = text[pos + len(phone.value):context_end]
        print(f"   Before (10 chars): '{before}'")
        print(f"   After (10 chars): '{after}'")
        
        # Check hex ratio
        combined = before + after
        if combined:
            hex_chars = sum(1 for c in combined if c in '0123456789ABCDEFabcdef')
            hex_ratio = hex_chars / len(combined)
            print(f"   Hex ratio: {hex_ratio:.2%} ({hex_chars}/{len(combined)})")
            
print("\nExpected: Only '555-1234' should be detected")
print(f"Status: {'PASS' if len(phones) == 1 and '555-1234' in [p.value for p in phones] else 'FAIL'}")
