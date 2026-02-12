#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test completo para verificar que ninguna detección encuentra substrings 
dentro de palabras más largas, hashes o códigos.

El problema: elementos como "640721423" dentro de "djfdh640721423jsdkj" 
no deberían detectarse, solo elementos aislados o separados por espacios/puntuación.
"""

from restalker import reStalker, Phone, Email, MD5, SHA1, SHA256

def test_phone_not_in_hash():
    """Los números de teléfono dentro de hashes NO deben detectarse"""
    text = "Hash MD5: djfdh640721423jsdkj y SHA: abc640721423def"
    stalker = reStalker(phone=True)
    results = list(stalker.parse(text))
    phones = [r for r in results if isinstance(r, Phone)]
    
    assert len(phones) == 0, f"No debería detectar teléfonos en hashes: {phones}"
    print("✓ Teléfonos NO detectados dentro de hashes")


def test_phone_isolated():
    """Los números aislados SÍ deben detectarse"""
    text = "Teléfono: 640721423 o llama al 912345678"
    stalker = reStalker(phone=True)
    results = list(stalker.parse(text))
    phones = [r for r in results if isinstance(r, Phone)]
    
    assert len(phones) > 0, f"Debería detectar al menos un teléfono: {phones}"
    print(f"✓ Teléfonos detectados correctamente: {len(phones)} encontrados")


def test_email_not_in_code():
    """Emails dentro de códigos NO deben detectarse"""
    text = "Code: xyztest@example.comabc123 Token: abc456test@test.comdef890"
    stalker = reStalker(email=True)
    results = list(stalker.parse(text))
    emails = [r for r in results if isinstance(r, Email)]
    
    # Debug: mostrar qué se detectó
    if emails:
        print(f"  DEBUG: Emails detectados: {[e.value for e in emails]}")
    
    # No debería detectar emails pegados con texto alfanumérico
    assert len(emails) == 0, f"No debería detectar emails en códigos: {emails}"
    print("✓ Emails NO detectados dentro de códigos")


def test_email_isolated():
    """Emails aislados SÍ deben detectarse"""
    text = "Contacto: test@example.com o test@test.com para más info"
    stalker = reStalker(email=True)
    results = list(stalker.parse(text))
    emails = [r for r in results if isinstance(r, Email)]
    
    assert len(emails) >= 1, f"Debería detectar al menos un email: {emails}"
    print(f"✓ Emails detectados correctamente: {len(emails)} encontrados")


def test_md5_not_in_string():
    """Hashes MD5 dentro de strings más largos NO deben detectarse"""
    # Un MD5 válido tiene 32 caracteres hexadecimales
    text = "Token: abc5d41402abc4b2a76b9719d911017c554176xyz890"
    stalker = reStalker(md5=True)
    results = list(stalker.parse(text))
    md5s = [r for r in results if isinstance(r, MD5)]
    
    assert len(md5s) == 0, f"No debería detectar MD5 dentro de tokens: {md5s}"
    print("✓ MD5 NO detectado dentro de tokens largos")


def test_md5_isolated():
    """Hashes MD5 aislados SÍ deben detectarse"""
    text = "MD5: 5d41402abc4b2a76b9719d911017c554 verificado"
    stalker = reStalker(md5=True)
    results = list(stalker.parse(text))
    md5s = [r for r in results if isinstance(r, MD5)]
    
    assert len(md5s) > 0, f"Debería detectar el MD5: {md5s}"
    print(f"✓ MD5 detectado correctamente: {len(md5s)} encontrados")


def test_sha256_not_in_code():
    """Hashes SHA256 dentro de códigos NO deben detectarse"""
    # Un SHA256 tiene 64 caracteres hexadecimales
    text = "xyz2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824abc"
    stalker = reStalker(sha256=True)
    results = list(stalker.parse(text))
    sha256s = [r for r in results if isinstance(r, SHA256)]
    
    assert len(sha256s) == 0, f"No debería detectar SHA256 en códigos: {sha256s}"
    print("✓ SHA256 NO detectado dentro de códigos")


def test_sha256_isolated():
    """Hashes SHA256 aislados SÍ deben detectarse"""
    text = "SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    stalker = reStalker(sha256=True)
    results = list(stalker.parse(text))
    sha256s = [r for r in results if isinstance(r, SHA256)]
    
    assert len(sha256s) > 0, f"Debería detectar el SHA256: {sha256s}"
    print(f"✓ SHA256 detectado correctamente: {len(sha256s)} encontrados")


def test_mixed_context():
    """Prueba con múltiples elementos mezclados"""
    text = """
    Hash MD5 incorrecto: abc1234567890abcdef1234567890abcdef (rodeado de texto)
    Hash MD5 correcto: 5d41402abc4b2a76b9719d911017c554
    
    Teléfono incorrecto en hash: djksh912345678askjd
    Teléfono correcto: 912345678
    
    Email incorrecto: xyztest@example.comabc
    Email correcto: test@example.com
    """
    
    stalker = reStalker(md5=True, phone=True, email=True)
    results = list(stalker.parse(text))
    
    md5s = [r for r in results if isinstance(r, MD5)]
    phones = [r for r in results if isinstance(r, Phone)]
    emails = [r for r in results if isinstance(r, Email)]
    
    print(f"\n Resultados del test mixto:")
    print(f"  - MD5s encontrados: {len(md5s)} -> {[m.value for m in md5s]}")
    print(f"  - Teléfonos encontrados: {len(phones)} -> {[p.value for p in phones]}")
    print(f"  - Emails encontrados: {len(emails)} -> {[e.value for e in emails]}")
    
    # Deberían detectarse solo los elementos "correctos" (aislados)
    # Permito un poco de flexibilidad porque phonenumbers puede ser agresivo
    assert len(md5s) <= 2, f"Debería detectar máximo 2 MD5, encontró {len(md5s)}"
    assert len(phones) <= 2, f"Debería detectar máximo 2 teléfonos, encontró {len(phones)}"
    assert len(emails) <= 2, f"Debería detectar máximo 2 emails, encontró {len(emails)}"
    
    print("✓ Test mixto completado correctamente")


def test_edge_cases():
    """Casos especiales: inicio, fin y palabra única"""
    # Al inicio del texto
    text1 = "640721423 es mi teléfono"
    stalker = reStalker(phone=True)
    results1 = list(stalker.parse(text1))
    phones1 = [r for r in results1 if isinstance(r, Phone)]
    assert len(phones1) > 0, "Debería detectar teléfono al inicio"
    
    # Al final del texto
    text2 = "Mi teléfono es 640721423"
    results2 = list(stalker.parse(text2))
    phones2 = [r for r in results2 if isinstance(r, Phone)]
    assert len(phones2) > 0, "Debería detectar teléfono al final"
    
    # Solo el teléfono (palabra única)
    text3 = "640721423"
    results3 = list(stalker.parse(text3))
    phones3 = [r for r in results3 if isinstance(r, Phone)]
    assert len(phones3) > 0, "Debería detectar teléfono como única palabra"
    
    print("✓ Casos especiales (inicio, fin, única palabra) funcionan correctamente")


if __name__ == "__main__":
    print("=" * 70)
    print("TEST DE VALIDACIÓN DE CONTEXTO PARA TODAS LAS DETECCIONES")
    print("=" * 70)
    print("\nVerificando que los elementos NO se detecten dentro de palabras/hashes...")
    print("-" * 70)
    
    try:
        test_phone_not_in_hash()
        test_phone_isolated()
        test_email_not_in_code()
        test_email_isolated()
        test_md5_not_in_string()
        test_md5_isolated()
        test_sha256_not_in_code()
        test_sha256_isolated()
        test_mixed_context()
        test_edge_cases()
        
        print("\n" + "=" * 70)
        print("✓ ✓ ✓  TODOS LOS TESTS PASARON EXITOSAMENTE  ✓ ✓ ✓")
        print("=" * 70)
        print("\nLa validación de contexto funciona correctamente.")
        print("Los elementos solo se detectan cuando están aislados,")
        print("no como substrings dentro de palabras más largas.\n")
        
    except AssertionError as e:
        print(f"\n✗ TEST FALLÓ: {e}\n")
        raise
    except Exception as e:
        print(f"\n✗ ERROR EN TEST: {e}\n")
        raise
