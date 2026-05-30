#!/usr/bin/env python3
"""Misc/stego analyzer. Runs a curated tool sweep on the input file
and writes findings.json + an extracted/ directory.

Invoked by the worker:
    docker run --rm -v <hostjob>:/job hextech_ctf_tool-misc <input_path> [--passphrase ...]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

FLAG_RE = re.compile(
    r"(?i)(?:FLAG|CTF|HTB|picoCTF|DH|KCTF|XCTF|BSidesCP|HACKTHEBOX)\{[^\s}]{1,200}\}"
)
LIBERAL_FLAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,16}\{[!-~]{2,200}\}")


def run(cmd: list[str], input_bytes: bytes | None = None, timeout: int = 120) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(
            cmd, input=input_bytes, capture_output=True, timeout=timeout
        )
        return cp.returncode, cp.stdout.decode("utf-8", errors="replace"), cp.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)


def head(text: str, n: int = 200) -> str:
    lines = text.splitlines()
    return "\n".join(lines[:n])


def collect_filetype(path: Path) -> dict:
    rc, out, _ = run(["file", "--mime", str(path)])
    rc2, out2, _ = run(["file", "-b", str(path)])
    mime = out.split(":", 1)[-1].strip() if rc == 0 else None
    desc = out2.strip() if rc2 == 0 else None
    return {"mime": mime, "description": desc}


def collect_exif(path: Path) -> dict:
    rc, out, err = run(["exiftool", "-j", "-G", str(path)])
    if rc == 0 and out.strip().startswith("["):
        try:
            return {"json": json.loads(out)}
        except json.JSONDecodeError:
            pass
    return {"raw": head(out + err, 80)}


def collect_strings(path: Path) -> dict:
    rc, out, _ = run(["strings", "-a", "-n", "6", str(path)], timeout=120)
    if rc != 0:
        return {"error": "strings failed"}
    candidates = sorted(set(FLAG_RE.findall(out)))
    liberal = sorted(set(LIBERAL_FLAG_RE.findall(out)) - set(candidates))
    return {
        "flag_candidates": candidates,
        "liberal_candidates": liberal[:50],
        "total_strings_lines": len(out.splitlines()),
    }


def collect_pngcheck(path: Path) -> dict:
    rc, out, err = run(["pngcheck", "-v", str(path)])
    return {"rc": rc, "output": head(out + err, 80)}


def collect_zsteg(path: Path) -> dict:
    rc, out, err = run(["zsteg", "-a", str(path)], timeout=180)
    return {"rc": rc, "output": head(out + err, 200)}


def collect_steghide(path: Path, passphrase: str | None, work_dir: Path) -> dict:
    info_rc, info_out, info_err = run(["steghide", "info", "-q", str(path)])
    result: dict[str, Any] = {"info": head(info_out + info_err, 40)}
    # Try empty passphrase first, then user-provided
    candidates = ["", passphrase] if passphrase else [""]
    for pp in candidates:
        if pp is None:
            continue
        out_path = work_dir / f"steghide_extract_{('empty' if pp=='' else 'user')}.bin"
        rc, out, err = run(
            ["steghide", "extract", "-sf", str(path), "-xf", str(out_path), "-p", pp, "-f"],
            timeout=60,
        )
        if rc == 0 and out_path.exists() and out_path.stat().st_size > 0:
            result["extracted"] = str(out_path.relative_to(work_dir.parent))
            result["passphrase"] = "(empty)" if pp == "" else "(user-provided)"
            return result
        else:
            result.setdefault("attempts", []).append(
                {"pp": "(empty)" if pp == "" else "(user-provided)", "rc": rc, "stderr_tail": err[-200:]}
            )
    return result


def collect_binwalk(path: Path, work_dir: Path) -> dict:
    rc_sig, out_sig, _ = run(["binwalk", str(path)], timeout=180)
    extract_dir = work_dir / "binwalk_extracted"
    extract_dir.mkdir(exist_ok=True)
    rc_ex, out_ex, err_ex = run(
        ["binwalk", "--matryoshka", "-e", "--directory", str(extract_dir), str(path)],
        timeout=300,
    )
    files = []
    for p in extract_dir.rglob("*"):
        if p.is_file():
            try:
                files.append({
                    "path": str(p.relative_to(work_dir.parent)),
                    "size": p.stat().st_size,
                })
            except Exception:
                pass
    return {
        "signatures": head(out_sig, 80),
        "extract_rc": rc_ex,
        "extracted_count": len(files),
        "extracted": files[:200],
    }


def collect_pdf(path: Path) -> dict:
    rc1, out1, _ = run(["pdfinfo", str(path)])
    rc2, out2, _ = run(["pdftotext", "-q", "-layout", str(path), "-"], timeout=60)
    text_candidates = sorted(set(FLAG_RE.findall(out2 or "")))
    return {
        "pdfinfo": head(out1, 30) if rc1 == 0 else None,
        "text_excerpt": head(out2 or "", 60),
        "flag_candidates_in_text": text_candidates,
    }


def collect_archive_listing(path: Path) -> dict:
    rc, out, err = run(["7z", "l", "-slt", str(path)], timeout=60)
    return {"rc": rc, "listing": head(out + err, 80)}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("input", help="Path inside container, typically /job/<filename>")
    p.add_argument("--passphrase", default=None, help="Optional steghide passphrase")
    p.add_argument("--out", default="/job", help="Output dir (default /job)")
    args = p.parse_args()

    in_path = Path(args.input).resolve()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    extracted = out / "extracted"
    extracted.mkdir(exist_ok=True)

    log_path = out / "analyze.log"
    log = log_path.open("w")
    def L(s):
        print(s, file=sys.stderr); log.write(s + "\n"); log.flush()

    if not in_path.is_file():
        L(f"input not found: {in_path}")
        return 2

    findings: dict[str, Any] = {"input": str(in_path), "size": in_path.stat().st_size}
    L(f"=== file ===")
    findings["filetype"] = collect_filetype(in_path)
    L(json.dumps(findings["filetype"]))

    L("=== exiftool ===")
    findings["exif"] = collect_exif(in_path)

    L("=== strings ===")
    findings["strings"] = collect_strings(in_path)
    L(f"flag candidates: {findings['strings'].get('flag_candidates')}")

    desc = (findings["filetype"].get("description") or "").lower()
    mime = (findings["filetype"].get("mime") or "").lower()
    is_png = "png" in desc or "image/png" in mime
    is_bmp = "bitmap" in desc or "bmp" in mime
    is_jpg = "jpeg" in desc or "image/jpeg" in mime
    is_wav = "wave" in desc or "audio/wav" in mime
    is_pdf = "pdf" in desc or "application/pdf" in mime
    is_archive = any(k in desc for k in ["zip archive", "7-zip archive", "rar archive", "gzip"])

    if is_png:
        L("=== pngcheck ===")
        findings["pngcheck"] = collect_pngcheck(in_path)
    if is_png or is_bmp:
        L("=== zsteg ===")
        findings["zsteg"] = collect_zsteg(in_path)
    if is_jpg or is_wav or is_bmp:
        L("=== steghide ===")
        findings["steghide"] = collect_steghide(in_path, args.passphrase, extracted)
    if is_pdf:
        L("=== pdf ===")
        findings["pdf"] = collect_pdf(in_path)
    if is_archive:
        L("=== archive ===")
        findings["archive"] = collect_archive_listing(in_path)

    L("=== binwalk ===")
    findings["binwalk"] = collect_binwalk(in_path, extracted)

    # Recursive flag search in extracted contents
    embedded_flag_hits = []
    for p in extracted.rglob("*"):
        if not p.is_file() or p.stat().st_size == 0:
            continue
        try:
            data = p.read_bytes()[: 5 * 1024 * 1024]
        except Exception:
            continue
        text = data.decode("utf-8", errors="replace")
        for m in FLAG_RE.findall(text):
            embedded_flag_hits.append({"file": str(p.relative_to(out)), "flag": m})
    findings["embedded_flag_hits"] = embedded_flag_hits[:50]

    (out / "findings.json").write_text(json.dumps(findings, indent=2, default=str))
    L("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
