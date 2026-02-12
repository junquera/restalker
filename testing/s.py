import json
text = None
with open('./phones.txt', 'r', encoding='utf-8') as file:
    text = file.read()
    file.close()
    
text = text.split('\n')

for i in range(len(text)):
    text[i] = text[i].strip()

with open('./expected_phones.json', 'w+', encoding='utf-8') as file:
    json.dump(text, file, ensure_ascii=False)
    file.close()