#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test chunk boundary issue"""

from restalker import reStalker, Phone

# Create a very long text with the hash at specific positions
base_text = "A" * 10000  # Padding to force chunking

# Test 1: Hash at different positions relative to chunk boundaries
positions = [1000, 5000, 10000, 10200, 10240, 15000, 20000]

hash_text = "56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE518"

stalker = reStalker(phone=True)

for pos in positions:
    text = "A" * pos + hash_text + "B" * 100
    results = list(stalker.parse(text))
    phones = [r for r in results if isinstance(r, Phone)]
    
    status = "✓" if len(phones) == 0 else "✗"
    print(f"{status} Position {pos:5d}: {len(phones)} phones detected", end="")
    if phones:
        print(f" -> {[p.value for p in phones]}")
    else:
        print()

# Test 2: Hash exactly at chunk boundary (10240)
print("\n" + "="*70)
print("Specific test: hash at chunk boundary")
text_boundary = "X" * 10240 + hash_text + "Y" * 100
results_boundary = list(stalker.parse(text_boundary))
phones_boundary = [r for r in results_boundary if isinstance(r, Phone)]

print(f"Text length: {len(text_boundary)}")
print(f"Hash position: 10240")
print(f"Phones detected: {len(phones_boundary)}")
if phones_boundary:
    for phone in phones_boundary:
        print(f"  - {phone.value}")
