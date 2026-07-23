#!/usr/bin/env python3
"""Forensic collector entrypoint.

Invoked by the worker via:
    docker run --rm -v <hostjob>:/job hextech_ctf_tool-forensic <image_path> \
        [--type auto|raw|qcow2|vmdk|memory|log] [--os auto|linux|windows] \
        [--bulk-extractor]

Outputs (written into /job):
    artifacts/                 — extracted files, paths preserved
    summary.json               — structured finding list
    volatility/<plugin>.json   — present for memory dumps
    log_findings.json          — credentials / SQLi / XSS / etc. mined
                                 from every text artifact
    collect.log                — stdout/stderr trace

Type 'log' is a fast path: skip disk/memory analysis and mine the upload
directly. Single .log/.txt are read as-is; .gz/.zip/.tar/.tar.gz/.tgz are
extracted into artifacts/logs/ first.
"""
import argparse
import gzip
import json
import shlex
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

# Prefix-anchored flag shapes (mirrors the orchestrator's FLAG_RE prefixes) —
# kept high-signal so a raw binary sweep doesn't flood the summary with noise.
_RAW_FLAG_ERE = r'(FLAG|flag|Flag|CTF|ctf|DH|dreamhack|HTB|htb|KEY|key)\{[ -~]{1,200}\}'


def _scan_raw_image(image: Path, log_fn, timeout: int = 240) -> list[str]:
    """Deterministic strings|grep flag sweep of the RAW image itself.

    A flag that lives in the dump but is NOT surfaced by a curated extractor
    (a specific Volatility plugin, a sleuthkit-recovered artifact) would
    otherwise be silently missed. Hard-bounded via shell `timeout`; returns
    CANDIDATES only (the agent/operator curates — this never auto-captures).
    """
    if shutil.which("strings") is None:
        # `strings` (binutils) must be in the image — otherwise the pipe's tail
        # (head) exits 0 and this looks IDENTICAL to a genuine no-match. Fail LOUD.
        log_fn("[raw-scan] SKIP — `strings` not found (add binutils to forensic/Dockerfile + rebuild)")
        return []
    cmd = ["bash", "-c",
           f"timeout {timeout} strings -a -n 6 {shlex.quote(str(image))} "
           f"| grep -aoE {shlex.quote(_RAW_FLAG_ERE)} | sort -u | head -300"]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        hits = [ln for ln in cp.stdout.splitlines() if ln.strip()]
    except Exception as e:
        log_fn(f"[raw-scan] failed (non-fatal): {e!r}")
        hits = []
    log_fn(f"[raw-scan] {len(hits)} flag-shaped candidate(s) in the raw image")
    return hits

from disk import process_disk
from log_miner import scan_logs
from memory import process_memory


_LOG_TEXT_SUFFIXES = (".log", ".txt", ".out", ".csv", ".json", ".jsonl", ".tsv")
_LOG_ARCHIVE_SUFFIXES = (".gz", ".tar", ".zip", ".tgz")


def detect_kind(image: Path) -> str:
    """Return one of: qcow2, vmdk, vhd, vhdx, e01, raw_disk, memory, log."""
    try:
        out = subprocess.run(["file", "-b", str(image)], capture_output=True, text=True, timeout=60).stdout.lower()
    except Exception:
        out = ""
    suffix = image.suffix.lower()
    if "qcow" in out:
        return "qcow2"
    if "vmware" in out or "vmdk" in out:
        return "vmdk"
    if "vhd" in out and "x" in out:
        return "vhdx"
    if "vhd" in out or suffix in (".vhd",):
        return "vhd"
    if "expert witness" in out or "ewf" in out or suffix in (".e01", ".ex01"):
        return "e01"
    if suffix in (".vhdx",):
        return "vhdx"
    # Plain log files — recognise by extension or `file` magic before
    # falling through to mmls/memory. .gz/.tar/.zip are NOT auto-classed
    # as logs (could equally be disk images zipped up); the user must
    # pick type=log explicitly for archives.
    if suffix in _LOG_TEXT_SUFFIXES:
        return "log"
    if "ascii text" in out or "utf-8 unicode text" in out or "log file" in out:
        return "log"
    # Try mmls — if succeeds, it's a disk image with a partition table
    try:
        rc = subprocess.run(
            ["mmls", str(image)], capture_output=True, text=True, timeout=120
        ).returncode
    except Exception:
        rc = 1
    if rc == 0:
        return "raw_disk"
    return "memory"


def _process_log(image: Path, out: Path, log_fn) -> dict:
    """Stage the upload under artifacts/logs/ so log_miner can scan it.

    Single text files are copied verbatim. Archive uploads are extracted
    in place. Anything else (e.g. an unrecognised binary) is still copied
    so the mining pass at least sees it.
    """
    logs_dir = out / "artifacts" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    name_low = image.name.lower()
    suffix = image.suffix.lower()

    if name_low.endswith(".tar.gz") or name_low.endswith(".tgz"):
        with tarfile.open(image, "r:gz") as tf:
            tf.extractall(logs_dir)
        log_fn(f"untarred {image.name} → artifacts/logs/")
    elif suffix == ".tar":
        with tarfile.open(image, "r:") as tf:
            tf.extractall(logs_dir)
        log_fn(f"untarred {image.name} → artifacts/logs/")
    elif suffix == ".zip":
        with zipfile.ZipFile(image, "r") as zf:
            zf.extractall(logs_dir)
        log_fn(f"unzipped {image.name} → artifacts/logs/")
    elif suffix == ".gz":
        # Plain gzip of a single file — strip .gz to get original name
        target = logs_dir / Path(image.stem).name
        with gzip.open(image, "rb") as fin, target.open("wb") as fout:
            shutil.copyfileobj(fin, fout)
        log_fn(f"gunzipped {image.name} → artifacts/logs/{target.name}")
    else:
        target = logs_dir / image.name
        shutil.copy(image, target)
        log_fn(f"staged {image.name} → artifacts/logs/{target.name}")

    staged = sum(1 for p in logs_dir.rglob("*") if p.is_file())
    return {
        "input": str(image),
        "staged_dir": str(logs_dir.relative_to(out)),
        "staged_files": staged,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("image", help="Path to image inside container (typically /job/image.bin)")
    p.add_argument("--type", default="auto",
                   choices=["auto", "raw", "qcow2", "vmdk", "vhd", "vhdx", "e01", "memory", "log"])
    p.add_argument("--os", dest="target_os", default="auto",
                   choices=["auto", "linux", "windows"])
    p.add_argument("--bulk-extractor", action="store_true",
                   help="Run bulk_extractor for unstructured carving (slow)")
    p.add_argument("--out", default="/job", help="Output dir (default /job)")
    args = p.parse_args()

    image = Path(args.image).resolve()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    log = (out / "collect.log").open("w")
    def L(msg):
        print(msg, file=sys.stderr); log.write(msg + "\n"); log.flush()

    if not image.is_file():
        L(f"image not found: {image}")
        return 2

    kind = args.type
    if kind == "auto":
        kind = detect_kind(image)
    L(f"detected kind: {kind}")

    summary = {"image": str(image), "kind": kind, "target_os": args.target_os}

    try:
        if kind == "log":
            log_summary = _process_log(image, out, log_fn=L)
            summary["log"] = log_summary
        elif kind == "memory":
            mem_summary = process_memory(image, out, args.target_os, log_fn=L)
            summary["memory"] = mem_summary
        else:
            disk_summary = process_disk(
                image, kind, out, args.target_os,
                bulk_extractor=args.bulk_extractor, log_fn=L,
            )
            summary["disk"] = disk_summary
    except Exception as e:
        import traceback
        L(f"ERROR: {e}\n{traceback.format_exc()}")
        summary["error"] = str(e)
        (out / "summary.json").write_text(json.dumps(summary, indent=2))
        return 1

    # Deterministic flag sweep of the RAW image itself — catches a flag that
    # lives in the dump but wasn't surfaced by a curated extractor. Skip
    # kind=='log' (already text-mined above). Non-fatal. The agent is told to
    # read summary.json first, so these candidates + the raw image name reach it.
    summary["raw_image"] = image.name
    if kind != "log":
        try:
            raw_hits = _scan_raw_image(image, log_fn=L)
            if raw_hits:
                summary["raw_flag_candidates"] = raw_hits
        except Exception as e:
            L(f"raw-scan failed (non-fatal): {e!r}")

    # Mine extracted text artifacts (logs, bash_history, browser history,
    # volatility plugin output) for credentials, web-attack signatures
    # (SQLi/XSS/LFI/RCE), auth events, and flag-shaped strings. Failures
    # are non-fatal — the rest of the report is still useful.
    # When kind=='log' the user explicitly handed us logs, so mine every
    # text file regardless of name (force=True).
    try:
        roots = [out / "artifacts", out / "volatility"]
        log_findings = scan_logs(
            [r for r in roots if r.exists()],
            out / "log_findings.json",
            log_fn=L,
            force=(kind == "log"),
        )
        summary["log_findings"] = {
            "scanned_files": log_findings.get("scanned_files", 0),
            "counts": log_findings.get("counts", {}),
        }
    except Exception as e:
        import traceback
        L(f"log_miner failed (non-fatal): {e}\n{traceback.format_exc()}")
        summary["log_findings"] = {"error": str(e)}

    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    L("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
