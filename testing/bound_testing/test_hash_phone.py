#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test for phone detection inside hashes"""

from restalker import reStalker, Phone

# Test case: phone number inside a hash
text = "56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518"
print(f"Text: {text}")
print(f"Text length: {len(text)}")

stalker = reStalker(phone=True)
results = list(stalker.parse(text))
phones = [r for r in results if isinstance(r, Phone)]

print(f"\nPhones detected: {[p.value for p in phones]}")
print(f"Number of phones: {len(phones)}")

if len(phones) == 0:
    print("✓ CORRECT: No phone detected inside the hash")
else:
    print(f"✗ ERROR: Phones were detected: {phones}")
    for phone in phones:
        print(f"  - {phone.value}")
        # Find position in text
        pos = text.find(phone.value)
        if pos != -1:
            print(f"    Position: {pos}")
            if pos > 0:
                print(f"    Char before: '{text[pos-1]}'")
            if pos + len(phone.value) < len(text):
                print(f"    Char after: '{text[pos + len(phone.value)]}'")
