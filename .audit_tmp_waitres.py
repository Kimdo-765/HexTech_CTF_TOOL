import json, sys
p = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 6
skip = int(sys.argv[3]) if len(sys.argv) > 3 else 0
c = 0
for l in open(p):
    d = json.loads(l)
    if d.get('kind') == 'tool_completed' and (d.get('tool') or '').lower() == 'wait':
        c += 1
        if c <= skip:
            continue
        print('ts=', d['ts'], 'dur_ms=', d.get('duration_ms'), 'call_id=', d.get('call_id'))
        print('input=', json.dumps(d.get('input'), ensure_ascii=False)[:600])
        print('detail=', (d.get('detail') or '')[:900].replace('\n', ' | '))
        print('---')
        if c >= skip + n:
            break
