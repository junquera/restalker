from restalker import restalker

stalker = restalker.reStalker(use_ner=True, all=True)

text = ""

with open('../fixtures/phones.txt', 'r', encoding='utf-8') as file:
    text = file.read()
    file.close()

res = stalker.parse(text)

for r in res:
    print(r)
