from restalker import restalker

stalker = restalker.reStalker(all=True)

text = ""

with open('./testing/dummy_text.txt', 'r', encoding='utf-8') as file:
    text = file.read()
    file.close()
    
res = stalker.parse(text)

for r in res:
    print(r)