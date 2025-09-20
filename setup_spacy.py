#!/usr/bin/env python3
"""
Script para preparar el entorno para restalker con spaCy.
Este script instala los modelos necesarios de spaCy.
"""

import sys
import subprocess
import spacy

def install_spacy_models():
    print("Instalando modelos de spaCy...")
    
    # Intentar instalar el modelo español
    try:
        subprocess.check_call([
            sys.executable, "-m", "spacy", "download", "es_core_news_md"
        ])
        print("Modelo español instalado correctamente.")
    except subprocess.CalledProcessError:
        print("No se pudo instalar el modelo español. Intentando con el modelo inglés...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "spacy", "download", "en_core_web_md"
            ])
            print("Modelo inglés instalado correctamente.")
        except subprocess.CalledProcessError:
            print("No se pudo instalar el modelo inglés medio. Instalando modelo pequeño...")
            subprocess.check_call([
                sys.executable, "-m", "spacy", "download", "en_core_web_sm"
            ])
            print("Modelo inglés pequeño instalado correctamente.")

def check_spacy_models():
    """Verifica qué modelos de spaCy están disponibles"""
    print("Verificando modelos de spaCy disponibles...")
    
    models_to_check = ["es_core_news_md", "en_core_web_md", "en_core_web_sm"]
    available_models = []
    
    for model_name in models_to_check:
        try:
            spacy.load(model_name)
            available_models.append(model_name)
            print(f"✓ El modelo '{model_name}' está instalado y disponible.")
        except OSError:
            print(f"✗ El modelo '{model_name}' no está instalado.")
    
    return available_models

if __name__ == "__main__":
    print("=== Preparación del entorno para restalker con spaCy ===")
    
    # Verificar modelos disponibles
    available_models = check_spacy_models()
    
    # Si no hay ningún modelo instalado, instalarlos
    if not available_models:
        print("No se encontraron modelos de spaCy instalados.")
        install_spacy_models()
        check_spacy_models()
    else:
        print("Al menos un modelo de spaCy ya está instalado. No es necesario instalar más modelos.")
    
    print("\n=== Preparación completada ===")
    print("Ya puede ejecutar los tests con:")
    print("  python test.py [archivo_texto]")
    print("  python test_textan.py")