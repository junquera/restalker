import sys 
sys.modules['tensorflow'] = None

from gliner import GLiNER

model = GLiNER.from_pretrained('nvidia/gliner-PII')

entity_labels = ['PERSON', 'ORGANIZATION', "LOC", "GPE", "FAC", "LOCATION", "USERNAME", 'PASSWORD']

text = ""

with open('../fixtures/dummy_text.txt', 'r', encoding='utf-8') as file:
    text = file.read()
    file.close()
    
results = model.predict_entities(text, entity_labels)

for result in results:
    print(result)