from gliner2 import GLiNER2

model = GLiNER2.from_pretrained('fastino/gliner2-large-v1')

entity_labels = ['PERSON', 'ORGANIZATION', "LOC", "GPE", "FAC", "LOCATION", "USERNAME", 'PASSWORD']

text = ""

with open('../fixtures/dummy_text.txt', 'r', encoding='utf-8') as file:
    text = file.read()
    file.close()

results = model.extract_entities(text, entity_labels)

for result in results:
    print(result)
