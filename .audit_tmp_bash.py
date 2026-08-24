import json, sys, collections
p = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else 'list'
evs = [json.loads(l) for l in open(p)]
if mode == 'waitdetail':
    c = collections.Counter()
    dur = collections.Counter()
    for d in evs:
        if d.get('kind') == 'tool_completed' and (d.get('tool') or '').lower() == 'wait':
            c[(d.get('detail') or '')[:80]] += 1
            dur[round((d.get('duration_ms') or 0)/1000)] += 1
    print('DETAILS:', c.most_common(10))
    print('DUR HIST:', sorted(dur.items()))
    sys.exit()
if mode == 'bashinput':
    n = 0
    for d in evs:
        if d.get('kind') == 'tool_started' and d.get('tool') == 'Bash':
            inp = d.get('input')
            s = json.dumps(inp, ensure_ascii=False)
            print(d['ts'][11:19], s[:230].replace('\\n', ' ⏎ '))
            n += 1
    print('n=', n)
    sys.exit()
# default: interleaved timeline of started tools + waits
for d in evs:
    k = d.get('kind')
    if k in ('tool_started', 'wait', 'artifact', 'message'):
        s = ''
        if k in ('tool_started', 'artifact'):
            s = json.dumps(d.get('input'), ensure_ascii=False)[:150]
        elif k == 'message':
            s = (d.get('summary') or '')[:150]
        print(d['ts'][11:19], (d.get('role') or '')[:5], k, (d.get('tool') or ''), s.replace('\n', ' '))
