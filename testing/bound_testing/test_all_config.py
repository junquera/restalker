#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test with all=True configuration"""

from restalker import reStalker, Phone

text = "56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518"
print(f"Text: {text}")

# Test with all=True (includes GLiNER)
print("\n" + "="*70)
print("Testing with all=True")
stalker_all = reStalker(all=True)
results_all = list(stalker_all.parse(text))
phones_all = [r for r in results_all if isinstance(r, Phone)]

print(f"Phones detected: {len(phones_all)}")
if phones_all:
    for phone in phones_all:
        print(f"  - {phone.value}")
else:
    print("  (none)")

# Test with only phone=True
print("\n" + "="*70)
print("Testing with phone=True only")
stalker_phone = reStalker(phone=True)
results_phone = list(stalker_phone.parse(text))
phones_phone = [r for r in results_phone if isinstance(r, Phone)]

print(f"Phones detected: {len(phones_phone)}")
if phones_phone:
    for phone in phones_phone:
        print(f"  - {phone.value}")
else:
    print("  (none)")

# Test in a longer context
print("\n" + "="*70)
print("Testing in longer text context")
long_text = """
This is a log file with several entries.
Hash value: 56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518
Phone: 555-1234
Another hash: ABC123DEF456789
"""

stalker_long = reStalker(all=True)
results_long = list(stalker_long.parse(long_text))
phones_long = [r for r in results_long if isinstance(r, Phone)]

print(f"Phones detected: {len(phones_long)}")
for phone in phones_long:
    print(f"  - {phone.value}")
