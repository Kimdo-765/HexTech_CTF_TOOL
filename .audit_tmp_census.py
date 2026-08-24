import json, collections, sys
p = sys.argv[1]
kinds=collections.Counter(); tools=collections.Counter(); rolekind=collections.Counter()
for l in open(p):
    d=json.loads(l)
    kinds[d.get('kind')]+=1
    rolekind[(d.get('role'),d.get('kind'))]+=1
    if 'tool' in (d.get('kind') or ''):
        tools[(d.get('kind'), d.get('name') or d.get('tool') or d.get('title'))]+=1
print('KINDS', kinds.most_common())
print()
print('TOOLS', tools.most_common(25))
print()
for k,v in rolekind.most_common(40): print(v, k)
