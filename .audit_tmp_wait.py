import json, sys
p = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 6
c = 0
for l in open(p):
    d = json.loads(l)
    if d.get('kind') == 'wait':
        print(json.dumps(d, ensure_ascii=False)[:1500])
        print('---')
        c += 1
        if c >= n:
            break
