#!/usr/bin/env python3
"""The tcache `key` check is a glibc 2.29 mainline feature, not 2.35.

Run: python3 scripts/test_tcache_key_version.py

The change landed on master for 2.29 and was officially backported to the
release/2.28 branch (glibc commit bcdaad21d4635931d1bd3b54a7894276925d081d;
Sourceware libc-stable message ``[2.28 COMMITTED] malloc: tcache double free
check``). Everything here once said 2.35: the gate in `worker/chal_libc_fix.py`
that produces `libc_profile.json`, the `HEAP_FIX_HINTS` entry injected on a
heap retry, the scaffold helper's own docstring, the judge's failure-code
table, and the pwn version table. The value is load-bearing in both
directions — the prompt tells the agent whether to zero the key, and the
profile tells `scaffold.tcache_poison.key_bypass_needed()` the same thing — so
a wrong threshold made the two agree on the wrong answer for every target
between 2.29 and 2.34. Ubuntu 20.04 ships 2.31 and is squarely inside that
window: the agent was told no bypass was needed and the double-free aborted on
the remote with `free(): double free detected in tcache 2`.

This pins the fact in one place and checks every file that repeats it, because
the previous fix landed in one file and left five behind.
"""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

checks = 0
fails = 0


def chk(label: str, cond: bool, got: object = "") -> None:
    global checks, fails
    checks += 1
    if cond:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got=%r" % (label, got))


def section(name: str) -> None:
    print("\n--- %s %s" % (name, "-" * max(0, 56 - len(name))))


# ---------------------------------------------------------------- the gate
section("the profile generator covers 2.29 plus the 2.28 backport")

spec = importlib.util.spec_from_file_location(
    "_clf_under_test", ROOT / "worker" / "chal_libc_fix.py")
clf = importlib.util.module_from_spec(spec)
sys.modules["_clf_under_test"] = clf
spec.loader.exec_module(clf)

# (version, expected tcache_key). 2.28 is deliberately conservative: version
# detection returns only major.minor, so it cannot distinguish the initial
# release from an official stable build carrying the backport.
MATRIX = [
    ((2, 27), False), ((2, 28), True), ((2, 29), True),
    ((2, 30), True), ((2, 31), True),
    ((2, 32), True), ((2, 34), True), ((2, 35), True), ((2, 39), True),
]
for ver, expect in MATRIX:
    got = bool(clf._derive_features(list(ver)).get("tcache_key"))
    chk("glibc %d.%d -> tcache_key=%s" % (ver[0], ver[1], expect),
        got == expect, got)

# Vendor builds invalidate a major.minor-only boundary: Ubuntu's
# 2.27-3ubuntu1.6 carries the check even though pristine upstream 2.27 does
# not.  `emit_profile()` already has the exact libc path, so a positive marker
# in that file must override the fallback version gate.
MARKER = b"free(): double free detected in tcache 2"
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    patched_227 = td / "libc-2.27-patched.so"
    patched_227.write_bytes(b"ELF fixture\0" + MARKER + b"\0tail")
    pristine_227 = td / "libc-2.27-pristine.so"
    pristine_227.write_bytes(b"ELF fixture without the diagnostic")
    markerless_228 = td / "libc-2.28-markerless.so"
    markerless_228.write_bytes(b"ELF fixture with diagnostic text removed")

    got = clf._derive_features([2, 27], patched_227)
    chk("REGRESSION: a patched 2.27 libc marker overrides the version gate",
        got["tcache_key"] is True, got)
    chk("...and the patched 2.27 profile recommends the +0x08 bypass",
        "key bypass" in " ".join(got["recommended_techniques"]).lower(), got)

    got = clf._derive_features([2, 27], pristine_227)
    chk("a markerless 2.27 fixture retains the version fallback result",
        got["tcache_key"] is False, got)

    got = clf._derive_features([2, 28], markerless_228)
    chk("markerless/reworded 2.28 remains conservatively true by fallback",
        got["tcache_key"] is True, got)

    got = clf._derive_features([2, 28], td / "unreadable-or-missing-libc.so")
    chk("an unreadable 2.28 libc also falls back conservatively",
        got["tcache_key"] is True, got)

    # Pin the production call path, not only the helper: emit_profile must pass
    # its existing libc argument into content-aware feature derivation.
    clf._extract_symbols = lambda _path: {}
    clf._extract_one_gadget = lambda _path: []
    clf._how2heap_techniques = lambda _version: {"available": False}
    clf._binary_arch = lambda _path: "fixture"
    profile_path = clf.emit_profile(
        td, patched_227, td / "ld-fixture", td / "binary-fixture", "2.27")
    profile = json.loads(profile_path.read_text()) if profile_path else {}
    chk("emit_profile uses exact-libc marker evidence for vendor 2.27",
        profile.get("tcache_key") is True, profile)

# The specific target the old gate got wrong, and the consequence that made it
# matter: the recommendation list is what the agent reads.
rec = " ".join(clf._derive_features([2, 31]).get("recommended_techniques") or [])
chk("REGRESSION: 2.31 (Ubuntu 20.04) recommends the key bypass — the old "
    ">= (2, 35) gate silently omitted it",
    "key bypass" in rec.lower(), rec)
chk("...and 2.28 is conservatively covered because the stable backport cannot "
    "be distinguished from the initial release",
    "key bypass" in " ".join(
        clf._derive_features([2, 28]).get("recommended_techniques") or []).lower())

# The flag must stay ADVISORY. `blacklisted_techniques` is consumed by
# `scaffold.assert_techniques_match()`, which raises SystemExit(2) on a match —
# so if flipping this gate ever started blacklisting something, a chain that
# runs today on a 2.29-2.34 target would begin dying locally instead. It does
# not: the only two blacklist entries are gated on hooks_alive and
# str_finish_patched. Pin that, because "purely additive" is the property that
# makes the runtime change safe.
for ver in ((2, 28), (2, 31), (2, 34)):
    bl = clf._derive_features(list(ver)).get("blacklisted_techniques") or []
    chk("glibc %d.%d: tcache_key adds nothing to blacklisted_techniques"
        % ver, not any("tcache" in b.lower() or "key" in b.lower() for b in bl), bl)

# The key is a member of each freed tcache_entry, not of
# tcache_perthread_struct. Confusing those two layouts sends a UAF write to an
# unrelated allocator-metadata address and is worse than omitting the hint.
for ver in ((2, 28), (2, 31), (2, 34)):
    rec = " ".join(clf._derive_features(list(ver)).get("recommended_techniques") or [])
    chk("glibc %d.%d: recommendation names the freed tcache_entry +0x08 key"
        % ver,
        "freed tcache_entry key" in rec and "+0x08" in rec, rec)
    chk("glibc %d.%d: recommendation never invents a perthread-struct key"
        % ver, "tcache_perthread_struct" not in rec, rec)

common = (ROOT / "modules/_common.py").read_text(errors="replace")
chk("unaligned-target hint does not call tcache_perthread_struct+8*slot a key",
    "tcache_perthread_struct + 8 * slot" not in common)
chk("unaligned-target hint says the real +0x08 entry key is not aligned",
    "tcache_entry `key` is at user-data offset +0x08" in common
    and "NOT itself a valid aligned allocation target" in common)

# --------------------------------------------- the worked example must agree
section("the profile example in the prompt matches the generator")

# modules/_prompts.py shows an agent a full libc_profile.json for glibc 2.31 as
# the answer to "what does the cached profile look like". It carried
# `"tcache_key": false` — the wrong side of this very boundary — and a
# preferred_fsop_chain the generator has never emitted for 2.31. A worked
# example that disagrees with the code is a second source of truth, so compare
# them field by field rather than fixing the one field that prompted this.
_pp = (ROOT / "modules/_prompts.py").read_text(errors="replace")
_i = _pp.index('"version_tuple": [2, 31]')
_example = _pp[_i - 200:_i + 900]
_truth = clf._derive_features([2, 31])
for field in ("safe_linking", "tcache_key", "hooks_alive",
              "io_str_jumps_finish_patched", "preferred_fsop_chain"):
    val = _truth[field]
    literal = ('"%s"' % val) if isinstance(val, str) else ("true" if val else "false")
    chk("example's %s == what _derive_features emits for 2.31 (%s)"
        % (field, literal),
        ('"%s": %s' % (field, literal)) in _example,
        [ln.strip() for ln in _example.splitlines() if field in ln])

# ------------------------------------------------------- no file says 2.35
section("no file still calls it a 2.35 feature")

# Every file that mentions the key field in a version context. Listed rather
# than globbed so that a NEW file repeating the claim is a deliberate add here,
# not something a glob quietly starts or stops covering.
SOURCES = (
    "modules/_common.py",
    "modules/_judge.py",
    "modules/pwn/prompts.py",
    "modules/_prompts.py",
    "worker/chal_libc_fix.py",
    "scaffold/tcache_poison.py",
    "scaffold/heap_menu.py",
)
import re

# A first attempt matched any line mentioning both 2.35 and the key, and
# promptly failed on the two lines that exist to DENY the claim ("2.29, not
# 2.35", "2.35-2.36 No new heap check ... the 2.29 key bypass"). Enumerating
# denial phrasings is a losing game, so invert the rule instead:
#
#   a line may mention 2.35 near the key ONLY if it also says 2.29.
#
# Every correct sentence about this boundary names the real version; every
# wrong one named 2.35 alone. That holds no matter how the sentence is worded.
NEAR = re.compile(r"2\.35[^\n]{0,80}\b(?:key|tcache_key)\b"
                  r"|\b(?:key|tcache_key)\b[^\n]{0,80}2\.35", re.I)
for rel in SOURCES:
    p = ROOT / rel
    if not p.is_file():
        chk("%s exists" % rel, False, "missing")
        continue
    hits = [ln.strip()[:100] for ln in p.read_text(errors="replace").splitlines()
            if NEAR.search(ln) and "2.29" not in ln]
    chk("%s never dates the key field to 2.35 without naming 2.29" % rel,
        not hits, hits)

# The version-keyed catalog must preserve mainline history and tell 2.27 users
# that the actual libc profile wins when a vendor backport is present.
lt = (ROOT / "modules/pwn/libc_targets.py").read_text(errors="replace")
chk("libc_targets.py records the 2.28 stable backport",
    '"2.28"' in lt and "official" in lt and "stable branch backported" in lt)
chk("libc_targets.py still records 2.29 as the first mainline release",
    "First mainline release with the check" in lt)
chk("libc_targets.py does not call every 2.27 build keyless",
    "Ubuntu 2.27-3ubuntu1.6" in lt and "libc_profile.json" in lt)

pt = (ROOT / "modules/pwn/prompts.py").read_text(errors="replace")
chk("the prompt's 2.27 row delegates vendor backports to the content profile",
    "Ubuntu 2.27-3ubuntu1.6" in pt and "actual libc" in pt
    and "libc_profile.json" in pt)

# ------------------------------------------- the helper name agents are told
section("the scaffold symbol the prompts name actually exists")

tp = (ROOT / "scaffold/tcache_poison.py").read_text(errors="replace")
chk("scaffold defines key_bypass_needed", "def key_bypass_needed(" in tp)
chk("scaffold does NOT define needs_key_bypass",
    "def needs_key_bypass(" not in tp)

NAMERS = SOURCES + ("README.md", "scaffold/README.md")
stale = [rel for rel in NAMERS
         if (ROOT / rel).is_file()
         and "needs_key_bypass" in (ROOT / rel).read_text(errors="replace")]
chk("no file tells the agent to call `needs_key_bypass`", not stale, stale)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
