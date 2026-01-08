import sys
from restalker.textan import TextAnalysis

# Test para la clase TextAnalysis con spaCy
print("\n--- Test de TextAnalysis con spaCy ---")
test_text = """
La inteligencia artificial (IA) es la simulación de procesos de inteligencia humana por parte de máquinas,
especialmente sistemas informáticos. Estos procesos incluyen el aprendizaje (la adquisición de información
y reglas para el uso de la información), el razonamiento (usando las reglas para llegar a conclusiones aproximadas o definitivas)
y la autocorrección. Las aplicaciones particulares de la IA incluyen sistemas expertos, reconocimiento de voz
y visión artificial.

El aprendizaje automático es una rama de la inteligencia artificial que permite que las aplicaciones
se vuelvan más precisas en la predicción de resultados sin ser explícitamente programadas.
"""

# Crear instancia de TextAnalysis con el texto de prueba
ta = TextAnalysis(test_text)

# Extraer frases clave
print("Frases clave extraídas:")
keyphrases = ta.extract_top_keyphrases(5)
for i, phrase in enumerate(keyphrases, 1):
    print(f"{i}. {phrase}")

# Comprobar si ciertas palabras clave están presentes
keywords_to_check = ["inteligencia", "artificial", "aprendizaje", "sistemas", "palabra_inexistente"]
print("\nVerificación de palabras clave:")
for keyword in keywords_to_check:
    presence = ta.is_keyword_present(keyword)
    print(f"'{keyword}': {'Presente' if presence > 0 else 'No presente'} (valor: {presence})")

print("\nTest completado.")