#!/usr/bin/env python3
"""Stage 7 — replay the judge over completed jobs and score it.

The review gate is "shadow 전후 status/meta.flags/run.log 불변 — 리플레이 전후
diff 0". This does not achieve that by being careful: the judge is handed
`Read`, `Bash`, `Glob` and `Grep` with `permission_mode="bypassPermissions"`
over its cwd, so a replay pointed at `/data/jobs/<id>` could write there. Every
job is therefore COPIED to a scratch root first and judged there, and the
originals are hashed before and after so the claim is measured rather than
asserted.

The cost of that safety is one known deviation: both prompt templates
interpolate `cwd`, so the replayed prompt names the copy's path. It is one path
string, the artifacts are byte-identical, and it is recorded per run rather
than left for a reviewer to discover.

  --dry-run   reconstruct every job's inputs and write them out, calling NO
              model. Run this first: it proves the reconstruction before 80+
              judge calls are spent on it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# BEFORE importing anything that reads it. `_common.JOBS_DIR` is computed at
# import time from DATA_DIR, and the usage ledger resolves it per call — so
# pointing DATA_DIR at the scratch root is what keeps every job-id-keyed side
# effect out of the real corpus.
#
# This is not hypothetical. The first real replay ran the judge on a COPY and
# still mutated the original: `record_usage` is keyed by job_id, job_id
# defaults to the job dir's name, and the ledger landed in
# /data/jobs/<id>/usage.jsonl. The judge never wrote anything; our own
# accounting did. The diff-0 check caught it, which is the whole reason it
# hashes rather than trusts.
_SCRATCH_ROOT = os.environ.get("REPLAY7_ROOT", "/data/replay7root")
os.environ["DATA_DIR"] = _SCRATCH_ROOT
os.environ["JOBS_DIR"] = str(Path(_SCRATCH_ROOT) / "jobs")

from modules import judge_replay  # noqa: E402


# Content-hash the small files; for the rest, size+mtime. A job dir runs to 2 GB
# (decomp trees, extracted binaries) and content-hashing 5.5 GB twice buys
# nothing here: any write the judge could make changes a size or an mtime, and
# the artifacts that actually decide a verdict are all far under this.
_HASH_BELOW = 1 << 20


def tree_digest(root: Path) -> str:
    """Integrity manifest for `root`, path-ordered."""
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


def _pin_judge(job_copy: Path, provider: str) -> None:
    """Route the judge onto one backend for this replay, in the COPY's meta.

    Without this the replay inherits each job's own `agent_provider` — and the
    corpus is mixed: 25 claude, 10 grok, 6 gpt. A stratified table built over
    that measures three different judges at once, which is not the question
    stage 7 asks. (It also hides that the gpt route is dead on this account:
    `gpt-5.6` is rejected outright with "not supported when using Codex with a
    ChatGPT account", so all six of those jobs came back transport_error.)

    Uses `agent_role_providers` — the per-role override stage 1 added — rather
    than rewriting `agent_provider`, so the replay routes the judge exactly the
    way production would and leaves the job's own backend alone.
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


def replayable(jobs_root: Path) -> list[Path]:
    out = []
    for d in sorted(jobs_root.iterdir()):
        if d.is_dir() and any(d.glob("*.stdout")):
            out.append(d)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs-root", default="/data/jobs")
    ap.add_argument("--scratch", default=str(Path(_SCRATCH_ROOT) / "jobs"))
    ap.add_argument("--out", default=str(Path(_SCRATCH_ROOT) / "results.jsonl"))
    ap.add_argument("--only", default="", help="comma-separated job ids")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--judge-provider", default="",
                    help="force the judge onto one backend (claude|gpt|grok)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    jobs_root = Path(args.jobs_root)
    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)

    picked = replayable(jobs_root)
    if args.only:
        want = {s.strip() for s in args.only.split(",") if s.strip()}
        picked = [p for p in picked if p.name in want]
    if args.limit:
        picked = picked[: args.limit]

    skipped = [d.name for d in sorted(jobs_root.iterdir())
               if d.is_dir() and not any(d.glob("*.stdout"))]

    before = {d.name: tree_digest(d) for d in picked}
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    t0 = time.time()

    with out_path.open("w", encoding="utf-8") as fh:
        for i, src in enumerate(picked, 1):
            rec: dict = {"job_id": src.name}
            if args.dry_run:
                inp = judge_replay.replay_inputs(src)
                rec.update(inp or {"unreplayable": True})
                rec["dry_run"] = True
            else:
                dst = scratch / src.name
                if dst.exists():
                    shutil.rmtree(dst, ignore_errors=True)
                try:
                    shutil.copytree(src, dst, symlinks=True,
                                    ignore_dangling_symlinks=True)
                except Exception as exc:
                    rec["copy_error"] = f"{type(exc).__name__}: {exc}"
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    fh.flush()
                    continue
                if args.judge_provider:
                    _pin_judge(dst, args.judge_provider)
                    rec["judge_provider_forced"] = args.judge_provider
                res = judge_replay.replay_job(dst)
                rec.update(res or {"unreplayable": True})
                rec["judged_cwd"] = str(dst)
                rec["cwd_deviation"] = (
                    "prompt names the scratch copy, not /data/jobs/<id>")
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            written += 1
            print(f"[{i}/{len(picked)}] {src.name} "
                  f"{'(dry)' if args.dry_run else ''} "
                  f"{time.time() - t0:.0f}s", flush=True)

    after = {d.name: tree_digest(d) for d in picked}
    changed = [k for k in before if before[k] != after.get(k)]

    summary = {
        "scratch_root": _SCRATCH_ROOT,
        "judge_provider_forced": args.judge_provider or None,
        "replayed": written,
        "skipped_unreplayable": skipped,
        "originals_changed": changed,
        "diff_zero": not changed,
        "dry_run": bool(args.dry_run),
        "elapsed_s": round(time.time() - t0, 1),
        "out": str(out_path),
    }
    (out_path.parent / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0 if summary["diff_zero"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
