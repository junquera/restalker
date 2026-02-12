from restalker.textan import TextAnalysis

# Test for TextAnalysis class with NLP AI (now running gliner)
print("\n--- TextAnalysis Test with NLP AI ---")
test_text = """
La inteligencia artificial (IA) es la simulación de procesos de inteligencia humana por parte de máquinas,
especialmente sistemas informáticos. Estos procesos incluyen el aprendizaje (la adquisición de información
y reglas para el uso de la información), el razonamiento (usando las reglas para llegar a conclusiones aproximadas o definitivas)
y la autocorrección. Las aplicaciones particulares de la IA incluyen sistemas expertos, reconocimiento de voz
y visión artificial.

El aprendizaje automático es una rama de la inteligencia artificial que permite que las aplicaciones
se vuelvan más precisas en la predicción de resultados sin ser explícitamente programadas.
"""

# Create TextAnalysis instance with test text
ta = TextAnalysis(test_text)

# Extract key phrases
print("Extracted key phrases:")
keyphrases = ta.extract_top_keyphrases(5)
for i, phrase in enumerate(keyphrases, 1):
    print(f"{i}. {phrase}")

# Check if certain keywords are present
keywords_to_check = ["inteligencia", "artificial", "aprendizaje", "sistemas", "nonexistent_word"]
print("\nKeyword verification:")
for keyword in keywords_to_check:
    presence = ta.is_keyword_present(keyword)
    print(f"'{keyword}': {'Present' if presence > 0 else 'Not present'} (value: {presence})")

print("\nTest completed.")