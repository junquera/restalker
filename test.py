import restalker

s = restalker.reStalker(all=True)

parse = s.parse('jaja')

for p in parse:
    print(p)
    print(type(p))