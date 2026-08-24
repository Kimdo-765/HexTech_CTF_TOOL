import json, sys, collections, datetime as dt
p = sys.argv[1]
evs = [json.loads(l) for l in open(p)]
def T(s): return dt.datetime.fromisoformat(s)
t0 = T(evs[0]['ts']); t1 = T(evs[-1]['ts'])
span = (t1 - t0).total_seconds()
print('span_s=%.0f (%.2f h)  first=%s last=%s' % (span, span/3600, evs[0]['ts'], evs[-1]['ts']))

byname = collections.defaultdict(list)
for d in evs:
    if d.get('kind') == 'tool_completed' and d.get('duration_ms') is not None:
        byname[(d.get('tool') or '?')].append(d['duration_ms']/1000.0)
print()
print('%-12s %5s %10s %8s %8s %8s %8s' % ('tool','n','sum_s','mean','p50','p90','max'))
for k, v in sorted(byname.items(), key=lambda kv: -sum(kv[1])):
    v2 = sorted(v); n = len(v2)
    print('%-12s %5d %10.1f %8.1f %8.1f %8.1f %8.1f' % (
        k, n, sum(v2), sum(v2)/n, v2[n//2], v2[min(n-1,int(n*0.9))], v2[-1]))
tot = sum(sum(v) for v in byname.values())
print('total tool wall_s=%.0f  (%.0f%% of span)' % (tot, 100*tot/span))

# main-role only
mains = [d for d in evs if d.get('role') == 'main']
print()
print('main events: %d, first %s last %s' % (len(mains), mains[0]['ts'], mains[-1]['ts']))
ms = (T(mains[-1]['ts']) - T(mains[0]['ts'])).totalseconds() if False else (T(mains[-1]['ts'])-T(mains[0]['ts'])).total_seconds()
ntool = sum(1 for d in mains if d.get('kind')=='tool_completed')
print('main span %.2f h; tool_completed=%d -> %.1f tools/hour' % (ms/3600, ntool, ntool/(ms/3600)))

# gaps between consecutive main events
gaps = []
prev = None
for d in mains:
    t = T(d['ts'])
    if prev is not None:
        gaps.append(((t-prev).total_seconds(), d.get('kind'), d.get('tool'), d['ts']))
    prev = t
gaps.sort(key=lambda g: -g[0])
print()
print('TOP 15 gaps between consecutive main events:')
for g in gaps[:15]:
    print('  %8.1fs  before %s/%s at %s' % g)
