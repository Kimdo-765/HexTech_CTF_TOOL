#!/usr/bin/env python3
"""Run the out-of-band shadow sweep against LIVE recordings, on a scratch copy.

Stage 6 built two halves and only one of them has ever met real data. The
recording half now has: two live jobs ran with `judge_mode=shadow` and left
per-cycle inputs with artifact fingerprints. The evaluating half —
`judge_shadow.evaluate()` — has 207 unit checks and zero live exercise, because
stage 7's 42-job replay could not use it: those jobs predate fingerprints, so
`_require_unchanged` would refuse every one of them, and stage 7 therefore went
through a separate entry point (`judge_replay.py`) that judges artifacts rather
than reproducing a gate. This script closes that gap on the only corpus where
`evaluate()` can run as designed.

**Why a scratch copy rather than the real job dir.** The designed sweep writes
verdicts next to the inputs, in the job's own `judge_shadow.jsonl`, and that is
within the stage-6 contract (`run.log` and `meta` are the frozen surfaces, not
the shadow ledger). But `_judge.prejudge_script` / `postjudge_run` also call
`record_usage_by_model(job_id=…, role="judge", stage=…)`, and that row carries
no shadow marker. Writing it into a finished shadow-mode job — a job whose
defining property is that the gate never called the judge — leaves a ledger in
which an out-of-band sweep is indistinguishable from an in-run gate call.
Anyone later asking "what did the judge cost during this run" gets a number
that was never spent during the run.

What this run is measuring is the MECHANISM (do the fingerprints match on
frozen artifacts, does the cycle pair up, does the session-identity guard
refrain from firing spuriously, does the summary land in the shadow file and
not in `run.log`), not accuracy — stage 7's stratified table owns accuracy, and
n=2 could not support a quantitative claim anyway. Every one of those checks
gives the same answer in a copy. So the copy costs nothing that matters and
keeps two finished jobs pristine.

The one honest deviation: the judge prompt embeds the job path, so the prompt
differs from the one enforce would have built by that string. Same deviation
stage 7 accepted, recorded here rather than glossed.

`--dry-run` injects a runner double and makes no model call at all: it proves
the pairing/ordering/session logic without spending a judge turn. Run it first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# BEFORE importing modules. `usage_ledger` and `_common` resolve the jobs root
# at import time, and the first version of the stage-7 harness learned this the
# expensive way: `record_usage` wrote into the REAL job tree of a job it was
# only supposed to read.
_SCRATCH_ROOT = os.environ.get("SHADOW_EVAL_ROOT", "/data/shadoweval")
os.environ["DATA_DIR"] = _SCRATCH_ROOT
os.environ["JOBS_DIR"] = str(Path(_SCRATCH_ROOT) / "jobs")

from modules import judge_shadow  # noqa: E402

_HASH_BELOW = 1 << 20


def tree_digest(root: Path) -> str:
    """Integrity manifest for `root`, path-ordered.

    Same function as the stage-7 harness. Size+mtime for everything, content
    hash for files under 1 MiB — mtime alone misses a rewrite that preserves
    both, and hashing a 300 MB decomp dump to prove we did not touch it is not
    worth the minutes.
    """
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            h.update(b"L" + str(p.relative_to(root)).encode())
            continue
        if not p.is_file():
            continue
        rel = str(p.relative_to(root)).encode()
        try:
            st = p.stat()
        except Exception:
            h.update(b"?" + rel)
            continue
        h.update(rel + str(st.st_size).encode() + str(st.st_mtime_ns).encode())
        if st.st_size < _HASH_BELOW:
            try:
                h.update(hashlib.sha256(p.read_bytes()).digest())
            except Exception:
                h.update(b"<unreadable>")
    return h.hexdigest()


def _double(stage: str, inputs: dict) -> dict:
    """A runner that answers without a model, for --dry-run.

    Shapes match what the real stages return closely enough for the gate
    predicates (`prejudge_blocks_ship`, `postjudge_would_retry`) to be exercised
    — the point of the dry run is the cycle plumbing around the runner, not the
    verdict content.
    """
    if stage == "prejudge":
        return {"ok": True, "severity": "low", "summary": "(dry-run double)"}
    if stage == "supervise":
        return {"action": "wait", "summary": "(dry-run double)"}
    return {"next_action": "continue", "summary": "(dry-run double)"}


def _pin_judge(job_copy: Path, provider: str) -> None:
    """Route the judge onto one backend in the COPY's meta.

    Both live jobs already stamp `agent_role_providers={"judge": "claude"}` at
    create time, so this is normally a no-op — kept so a future recording made
    under a different route can still be swept onto one backend.
    """
    mp = job_copy / "meta.json"
    try:
        meta = json.loads(mp.read_text(encoding="utf-8"))
    except Exception:
        meta = {}
    roles = dict(meta.get("agent_role_providers") or {})
    roles["judge"] = provider
    meta["agent_role_providers"] = roles
    mp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")


def _shadow_jobs(jobs_root: Path) -> list[str]:
    return sorted(p.parent.name for p in jobs_root.glob("*/judge_shadow.jsonl"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jobs", nargs="*", help="job ids; default = every job with a shadow ledger")
    ap.add_argument("--src-root", default="/data/jobs")
    ap.add_argument("--judge-provider", default="", help="pin the judge role in the copy")
    ap.add_argument("--dry-run", action="store_true", help="inject a double; no model call")
    args = ap.parse_args()

    src_root = Path(args.src_root)
    ids = args.jobs or _shadow_jobs(src_root)
    if not ids:
        print("no job carries a shadow ledger", file=sys.stderr)
        return 2

    scratch_jobs = Path(_SCRATCH_ROOT) / "jobs"
    scratch_jobs.mkdir(parents=True, exist_ok=True)

    before = {j: tree_digest(src_root / j) for j in ids}
    # Every check that can fail appends here, and the exit code is derived from
    # it. Printing "run.log 불변: False" and then exiting 0 made this harness
    # unusable as the R5 mechanical gate it was written to be: a green exit
    # reads as "the contract held" to anything that consumes exit codes, which
    # is exactly the false-green this project keeps being bitten by.
    failures: list[str] = []

    for job_id in ids:
        src = src_root / job_id
        dst = scratch_jobs / job_id
        if dst.exists():
            shutil.rmtree(dst)
        # `symlinks=True` and an lstat-skipping ignore: a device node in a job
        # tree once hung a sync copytree hard enough to freeze uvicorn's loop.
        shutil.copytree(src, dst, symlinks=True,
                        ignore=lambda d, names: [
                            n for n in names
                            if not (Path(d, n).is_symlink()
                                    or Path(d, n).is_file()
                                    or Path(d, n).is_dir())])
        if args.judge_provider:
            _pin_judge(dst, args.judge_provider)

        pend = judge_shadow.pending_inputs(job_id)
        log_before = (dst / "run.log").read_bytes() if (dst / "run.log").exists() else b""

        print(f"\n=== {job_id} — pending {len(pend)}: "
              f"{[r.get('stage') for r in pend]}")

        n = judge_shadow.evaluate(job_id, dst,
                                  runner=_double if args.dry_run else None)

        log_after = (dst / "run.log").read_bytes() if (dst / "run.log").exists() else b""
        log_same = log_before == log_after
        print(f"  evaluated: {n}")
        print(f"  §8.1 run.log 불변: {log_same}")
        if not log_same:
            failures.append(f"{job_id}: evaluation wrote to run.log (§8.1 violated)")

        # Completeness is "every input was ANSWERED", not "every input was
        # evaluated". A refusal is a designed outcome — `6685e3e65add` cycle 1
        # legitimately refuses because attempt 2 overwrote the artifacts the
        # fingerprint pinned — so failing on `n != len(pend)` would paint a
        # correct run red. Asked of `pending_inputs`, the module's own
        # predicate, rather than restated here: an input with no verdict row
        # is still pending, and that is the thing that must never survive.
        remaining = judge_shadow.pending_inputs(job_id)
        if remaining:
            failures.append(
                f"{job_id}: {len(remaining)} input(s) left with no verdict row "
                f"({[r.get('stage') for r in remaining]})")

        for rec in judge_shadow.read_shadow(job_id):
            if rec.get("kind") != "verdict":
                continue
            v = rec.get("verdict") or {}
            why = v.get("unevaluable")
            head = f"  [{rec.get('stage')}]"
            if why:
                print(f"{head} UNEVALUABLE — {why}")
            else:
                keys = {k: v[k] for k in
                        ("ok", "severity", "next_action", "action", "verdict",
                         "flag_likelihood", "error_kind")
                        if k in v}
                print(f"{head} {keys}")
                for f in ("summary", "reason", "hint"):
                    if v.get(f):
                        print(f"        {f}: {str(v[f])[:300]}")
            if rec.get("opened_session") is not None:
                print(f"        opened_session: {bool(rec.get('opened_session'))}")

        print(f"  rollup: {json.dumps(judge_shadow.summary(job_id), ensure_ascii=False)}")

    print("\n=== 원본 불변 검증 ===")
    for job_id in ids:
        after = tree_digest(src_root / job_id)
        same = after == before[job_id]
        print(f"  {job_id}  diff_zero={same}")
        if not same:
            failures.append(f"{job_id}: the SOURCE job tree changed — a read-only "
                            "sweep mutated the job it was measuring")

    print()
    if failures:
        print(f"=== FAIL ({len(failures)}) ===")
        for f in failures:
            print(f"  {f}")
        return 1
    print("=== OK — 계약 전부 성립 ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
