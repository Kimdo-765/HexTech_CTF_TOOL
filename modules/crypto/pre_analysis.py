"""Deterministic (no-LLM) crypto pre-analysis.

The crypto module was derived from the pwn pipeline and, until now, its only
pre-flight was a free-text LLM recon subagent. This front-loads the reliable
SCUTWORK the way pwn's libc_profile/decompile front-loads binary facts:

  * inventory the source/ciphertext files,
  * extract named integer parameters (n, e, c, p, q, d, phi, …) from .py/.txt,
  * detect the cipher family from imports/keywords,
  * run a CHEAP automated first pass on any RSA modulus (small-prime trial
    division, Fermat close-prime factoring, factordb lookup, structural
    signals for small-e / Wiener / common-modulus).

Two properties that make this worth its own module:

  1. It is PURE CODE — no model turn — so it can never trip the policy
     classifier that deterministically AUP-blocks some benign crypto chals
     (see memory crypto_aup_bytecaesar_falsepos). Even when the LLM pre-recon
     refuses, the agent still starts with these facts.
  2. On a factorable modulus it effectively hands the agent the solve
     (p, q recovered → RSA is done), instead of asking it to re-derive.

Everything is best-effort and bounded: no unbounded loops, short network
timeouts, and every stage is wrapped so a failure degrades to "less
pre-analysis", never a crash or a hang of the job.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

# Only files worth scanning for parameters / cipher hints. Keep small so a
# huge bundled corpus (wordlists, images) doesn't blow the budget.
_TEXT_SUFFIXES = {".py", ".txt", ".sage", ".json", ".md", ".out", ".enc"}
_MAX_FILE_BYTES = 256 * 1024
_MAX_FILES = 60

# name = <int>  (decimal or 0x-hex), tolerant of underscores in digits.
# Accept a SINGLE digit so a small public exponent (e = 3 / 5 / 17) — the
# most security-relevant RSA param — is captured; noise from small values
# bound to must-be-huge names is filtered below (see _BIG_ONLY).
_ASSIGN_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]{0,20})\s*=\s*"
    r"(?P<val>0[xX][0-9a-fA-F_]+|\d[\d_]*)",
)
# Long hex blob (>= 32 hex chars) — typical ciphertext dump.
_HEXBLOB_RE = re.compile(r"\b(?P<hex>[0-9a-fA-F]{32,})\b")

# Parameter names we care about, normalised to lowercase.
_RSA_NAMES = {"n", "modulus", "e", "c", "ct", "ciphertext", "p", "q",
              "d", "phi", "dp", "dq", "flag_enc", "enc"}
# Names that are ALWAYS large integers in real RSA — a sub-64-bit capture for
# one of these is a loop/index var, not a parameter, so drop it. (e and c are
# deliberately NOT here: a small e or a small unwrapped c are both signals.)
_BIG_ONLY = {"p", "q", "d", "phi", "dp", "dq"}

_CIPHER_SIGNS = [
    ("RSA", ("rsa", "getprime", "pow(", "inverse(", "d = ", "e = 65537",
             "n = ", "phi", "pkcs1")),
    ("ECC/ECDSA", ("ecdsa", "secp256", "elliptic", "point(", "curve",
                   "nist", "brainpool", "signature", "nonce")),
    ("AES", ("aes", "cbc", "ecb", "ctr", "gcm", "cipher.new", "unpad",
             "pkcs7")),
    ("ChaCha/Salsa", ("chacha", "salsa20", "poly1305")),
    ("DH/ElGamal", ("diffie", "elgamal", "generator", "g = ", "g**",
                    "discrete log", "dlog")),
    ("Hash", ("md5", "sha1", "sha256", "hashlib", "length extension",
              "merkle")),
    ("PRNG", ("random.getrandbits", "mersenne", "mt19937", "getstate",
              "lcg", "seed(", "randint")),
    ("XOR/stream", ("xor", "^ key", "otp", "one-time pad", "keystream")),
]


def _iter_int(raw: str) -> int | None:
    raw = raw.replace("_", "")
    try:
        return int(raw, 16) if raw[:2].lower() == "0x" else int(raw)
    except (ValueError, IndexError):
        return None


def _small_factor(n: int, bound: int = 100_000) -> int | None:
    """Trial-divide by primes up to `bound`. Cheap; catches multi-prime /
    smooth moduli and 'n has a tiny factor' mistakes."""
    if n % 2 == 0:
        return 2
    f = 3
    while f <= bound and f * f <= n:
        if n % f == 0:
            return f
        f += 2
    return None


def _fermat(n: int, max_iter: int = 200_000) -> tuple[int, int] | None:
    """Fermat factorisation — recovers p, q when they are close (the classic
    'primes generated too near each other' RSA bug). Bounded iterations."""
    if n <= 1 or n % 2 == 0:
        return None
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        if b2 >= 0:
            b = math.isqrt(b2)
            if b * b == b2:
                p, q = a - b, a + b
                if 1 < p < n and p * q == n:
                    return (p, q)
        a += 1
    return None


def _factordb(n: int, log_fn) -> list[int] | None:
    """Look n up on factordb.com (fully-factored → returns the factors).
    Best-effort outbound call; short timeout; silent on any failure."""
    try:
        import requests  # noqa: PLC0415
        r = requests.get(
            "http://factordb.com/api", params={"query": str(n)}, timeout=6
        )
        data = r.json()
        if str(data.get("status")) == "FF":  # Fully Factored
            factors: list[int] = []
            for base, exp in data.get("factors", []):
                factors.extend([int(base)] * int(exp))
            if len(factors) >= 2:
                return factors
    except Exception as e:  # network off / rate-limited / json shape drift
        log_fn(f"[crypto-preanalysis] factordb skipped: {type(e).__name__}")
    return None


def _analyse_rsa(params: dict[str, int], log_fn) -> list[str]:
    """Structural + cheap-computational checks on extracted RSA params."""
    out: list[str] = []
    n = params.get("n") or params.get("modulus")
    e = params.get("e")
    if n is None:
        return out
    bits = n.bit_length()
    out.append(f"- modulus n: {bits} bits")
    if e is not None:
        out.append(f"- public exponent e = {e}")
        if e <= 7:
            out.append(f"  → SIGNAL: small e ({e}) — try cube/e-th root "
                       "or Håstad broadcast if you have >= e ciphertexts.")

    # 1) small factor / multi-prime.
    sf = _small_factor(n)
    if sf is not None:
        out.append(f"- ★ n has a SMALL factor {sf} (n is NOT a hard "
                   "semiprime) — divide it out; likely trivially factorable.")
        return out

    # 2) Fermat (close primes).
    fer = _fermat(n)
    if fer is not None:
        p, q = fer
        out.append(f"- ★ FERMAT FACTORED n (close primes): p={p}\n"
                   f"    q={q}\n  → RSA is broken; compute d = e^-1 mod "
                   "(p-1)(q-1) and decrypt.")
        return out

    # 3) factordb.
    fdb = _factordb(n, log_fn)
    if fdb is not None:
        shown = ", ".join(str(x) for x in fdb[:4])
        out.append(f"- ★ factordb has n FULLY FACTORED: [{shown}"
                   f"{' …' if len(fdb) > 4 else ''}] → reconstruct d and "
                   "decrypt.")
        return out

    # 4) Wiener signal (only a hint — needs d small; can't cheaply test).
    if e is not None and e > (n >> 3):
        out.append("- SIGNAL: e is large relative to n — candidate for "
                   "Wiener's attack (small private exponent d).")
    out.append("- n did not fall to small-prime / Fermat / factordb; if "
               "it's a hard semiprime, look for a leaked bit / partial key "
               "(Coppersmith) or a protocol reuse (common modulus).")
    return out


def run_crypto_pre_analysis(src_root: str | None, log_fn) -> str:
    """Return a compact markdown breadcrumb of deterministic findings, or ""
    when there is nothing worth injecting. Never raises."""
    if not src_root:
        return ""
    try:
        root = Path(src_root)
        if not root.is_dir():
            return ""
        files = [
            p for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix.lower() in _TEXT_SUFFIXES
        ][:_MAX_FILES]
        if not files:
            return ""

        blob_parts: list[str] = []
        params: dict[str, int] = {}
        multi_n: list[int] = []
        hexblobs: set[str] = set()
        for p in files:
            try:
                if p.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = p.read_text(errors="replace")
            except Exception:
                continue
            blob_parts.append(text.lower())
            for m in _ASSIGN_RE.finditer(text):
                name = m.group("name").lower()
                val = _iter_int(m.group("val"))
                if val is None:
                    continue
                if name in _BIG_ONLY and val.bit_length() < 64:
                    continue  # a small value here is a loop var, not a param
                if name in _RSA_NAMES:
                    # Keep the FIRST binding per name, but collect every 'n'
                    # so we can flag a common-modulus setup.
                    if name in ("n", "modulus"):
                        multi_n.append(val)
                    params.setdefault(name, val)
            for hm in _HEXBLOB_RE.finditer(text):
                hexblobs.add(hm.group("hex"))

        haystack = "\n".join(blob_parts)
        families = [name for name, signs in _CIPHER_SIGNS
                    if any(s in haystack for s in signs)]

        sections: list[str] = []
        sections.append("FILES: " + ", ".join(p.name for p in files[:12])
                        + (" …" if len(files) > 12 else ""))
        if families:
            sections.append("CIPHER FAMILY (keyword/import scan): "
                            + ", ".join(families))
        if params:
            shown = {k: (f"{v.bit_length()}-bit int" if v.bit_length() > 64
                         else v) for k, v in params.items()}
            sections.append("EXTRACTED PARAMS: "
                            + ", ".join(f"{k}={shown[k]}" for k in shown))
        if len(set(multi_n)) >= 2:
            sections.append("★ MULTIPLE DISTINCT MODULI n found — check for "
                            "common-modulus / shared-factor (GCD) attack "
                            "across them.")
        if hexblobs:
            longest = max(hexblobs, key=len)
            sections.append(f"CIPHERTEXT?: longest hex blob = {len(longest)} "
                            f"hex chars ({len(longest)//2} bytes), starts "
                            f"{longest[:24]}…")

        rsa_lines = _analyse_rsa(params, log_fn)
        if rsa_lines:
            sections.append("RSA AUTO-CHECK:\n" + "\n".join(rsa_lines))

        # Nothing but a bare file list is not worth injecting.
        if len(sections) <= 1:
            return ""

        body = "\n".join(sections)
        log_fn("[crypto-preanalysis] emitted "
               f"{len(params)} params, families={families or 'none'}, "
               f"rsa_checks={'yes' if rsa_lines else 'no'}")
        return body
    except Exception as e:
        log_fn(f"[crypto-preanalysis] failed: {type(e).__name__}: {e}")
        return ""
