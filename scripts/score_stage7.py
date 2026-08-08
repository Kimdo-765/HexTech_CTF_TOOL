#!/usr/bin/env python3
"""Score the stage-7 replay against hand-labelled ground truth.

NO ACCURACY NUMBER IS PRINTED, on purpose. 31 of the 42 replayable jobs are
positives, so "always success" scores 74% and looks good. Only a stratified
table says anything, and even then only where BOTH classes exist — which after
correcting the labels is `pwn` (8 positive / 8 negative) and `web` (3/3).
`rev` (13/1) and `crypto` (6/0) cannot measure discrimination at all, and are
printed with that stated rather than folded into a total.

Two verdicts are scored, and they answer different questions:

  prejudge  would the gate have BLOCKED this run before the sandbox started?
            Right answer: block the jobs that captured nothing, let the rest
            through. A block on a job that went on to capture is the expensive
            error — it costs a real solve.
  postjudge did the run succeed? Compared against the label directly.

Ground truth is `wip/ground_truth.json` — hand-labelled by three independent
raters (41/42 unanimous), NOT `meta.status`, which is wrong on 3 of the 42.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

POSITIVE = {"true_capture", "false_negative"}     # the job really did capture
NEGATIVE = {"true_negative", "false_success"}     # it really did not


def load(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def blocked(prejudge: dict | None) -> bool | None:
    """Would the runner have refused to spawn? None when unmeasured."""
    if not isinstance(prejudge, dict) or prejudge.get("error"):
        return None
    from modules._judge import prejudge_blocks_ship

    return prejudge_blocks_ship(prejudge)


def said_success(postjudge: dict | None) -> bool | None:
    if not isinstance(postjudge, dict) or postjudge.get("error"):
        return None
    v = str(postjudge.get("verdict") or "").lower()
    if not v or v == "unknown":
        return None
    return v == "success"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--truth", default="/home/yadohyun/hextech-handoff/wip/ground_truth.json")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    truth = {r["id"]: r for r in json.loads(Path(args.truth).read_text(encoding="utf-8"))}
    rows = load(Path(args.results))

    scored = []
    for r in rows:
        jid = r.get("job_id")
        t = truth.get(jid)
        if not t:
            continue
        label = t["label"]
        scored.append({
            "id": jid,
            "module": t["module"],
            "meta_status": t["status"],
            "label": label,
            "really_captured": label in POSITIVE,
            "prejudge_blocked": blocked(r.get("prejudge")),
            "prejudge_severity": (r.get("prejudge") or {}).get("severity"),
            "postjudge_verdict": (r.get("postjudge_verdict") or {}).get("verdict"),
            "postjudge_success": said_success(r.get("postjudge_verdict")),
            "gaps": r.get("gaps") or [],
            "prejudge_error": (r.get("prejudge") or {}).get("error"),
            "postjudge_error": (r.get("postjudge_verdict") or {}).get("error"),
        })

    missing = sorted(set(truth) - {s["id"] for s in scored})
    print(f"replayed and scored: {len(scored)} / {len(truth)} labelled"
          + (f"   (not replayed: {missing})" if missing else ""))
    print()

    # ---- prejudge: a block on a job that captured is the expensive error ----
    print("== prejudge — would it have blocked the run before the sandbox? ==")
    print("   (a block on a job that DID capture costs a real solve)")
    cells = collections.Counter()
    for s in scored:
        b = s["prejudge_blocked"]
        key = "unmeasured" if b is None else ("blocked" if b else "allowed")
        cells[(s["module"], s["really_captured"], key)] += 1
    _table(cells, scored, ("blocked", "allowed", "unmeasured"))

    costly = [s for s in scored if s["prejudge_blocked"] and s["really_captured"]]
    print(f"\n   BLOCKED a job that really captured: {len(costly)}")
    for s in costly:
        print(f"     {s['module']:<7} {s['id'][:12]}  severity={s['prejudge_severity']}")
    caught = [s for s in scored if s["prejudge_blocked"] and not s["really_captured"]]
    print(f"   BLOCKED a job that captured nothing: {len(caught)}")
    for s in caught:
        print(f"     {s['module']:<7} {s['id'][:12]}  severity={s['prejudge_severity']}")

    # ---- postjudge: did it agree with what really happened? ----
    print("\n== postjudge — did it call the run a success? ==")
    cells2 = collections.Counter()
    for s in scored:
        v = s["postjudge_success"]
        key = "unmeasured" if v is None else ("success" if v else "not-success")
        cells2[(s["module"], s["really_captured"], key)] += 1
    _table(cells2, scored, ("success", "not-success", "unmeasured"))

    fp = [s for s in scored if s["postjudge_success"] and not s["really_captured"]]
    fn = [s for s in scored if s["postjudge_success"] is False and s["really_captured"]]
    print(f"\n   said SUCCESS on a job that captured nothing: {len(fp)}")
    for s in fp:
        print(f"     {s['module']:<7} {s['id'][:12]}  label={s['label']}")
    print(f"   said NOT-success on a job that really captured: {len(fn)}")
    for s in fn:
        print(f"     {s['module']:<7} {s['id'][:12]}  verdict={s['postjudge_verdict']}"
              + ("  [multi-attempt: hint history missing]"
                 if any("prior_hints" in g for g in s["gaps"]) else ""))

    errs = [s for s in scored if s["prejudge_error"] or s["postjudge_error"]]
    if errs:
        print(f"\n   stages that errored (excluded from every cell above): {len(errs)}")
        for s in errs[:10]:
            print(f"     {s['id'][:12]}  pre={str(s['prejudge_error'])[:60]}"
                  f"  post={str(s['postjudge_error'])[:60]}")

    if args.out:
        Path(args.out).write_text(json.dumps(scored, ensure_ascii=False, indent=1),
                                  encoding="utf-8")
        print(f"\nper-job scoring written to {args.out}")
    return 0


def _table(cells, scored, keys):
    mods = sorted({s["module"] for s in scored})
    width = max(12, max(len(k) for k in keys) + 2)
    head = f"   {'module':<9}{'truth':<11}" + "".join(f"{k:>{width}}" for k in keys)
    print(head)
    for m in mods:
        pos = sum(1 for s in scored if s["module"] == m and s["really_captured"])
        neg = sum(1 for s in scored if s["module"] == m and not s["really_captured"])
        for really, name in ((True, "captured"), (False, "no capture")):
            n = pos if really else neg
            if not n:
                continue
            print(f"   {m:<9}{name:<11}"
                  + "".join(f"{cells.get((m, really, k), 0):>{width}}" for k in keys))
        if pos < 3 or neg < 3:
            print(f"   {'':<9}{'':<11}   ^ {m}: {pos} positive / {neg} negative — "
                  "one class too small to measure discrimination")


if __name__ == "__main__":
    raise SystemExit(main())
