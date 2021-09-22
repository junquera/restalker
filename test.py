import stalker

s = stalker.Stalker(all=True)

parse = s.parse('jaja')

for p in parse:
    print(p)
    print(type(p))