#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test específico para el ejemplo que mencionaste"""

from restalker import reStalker, Phone, MD5

# Tu ejemplo exacto
text1 = "sdjkasj640721423askdjask"
print(f"Texto 1: {text1}")
stalker = reStalker(phone=True, all=True)
results = list(stalker.parse(text1))
phones = [r for r in results if isinstance(r, Phone)]
md5s = [r for r in results if isinstance(r, MD5)]

print(f"Teléfonos detectados: {[p.value for p in phones]}")
print(f"MD5s detectados: {[m.value for m in md5s]}")

if len(phones) == 0:
    print("✓ CORRECTO: No se detectó el 640721423 dentro del hash")
else:
    print(f"✗ ERROR: Se detectaron teléfonos: {phones}")

print("\n" + "="*60 + "\n")

# Ahora el número aislado
text2 = "El hash es abc123def pero el teléfono es 640721423 aislado"
print(f"Texto 2: {text2}")
results2 = list(stalker.parse(text2))
phones2 = [r for r in results2 if isinstance(r, Phone)]
print(f"Teléfonos detectados: {[p.value for p in phones2]}")

if len(phones2) > 0:
    print("✓ CORRECTO: Se detectó el teléfono aislado")
else:
    print("✗ ERROR: No se detectó el teléfono aislado")
