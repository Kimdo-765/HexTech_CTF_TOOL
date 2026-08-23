#!/usr/bin/env python3
"""The tcache `key` check is a glibc 2.29 feature, not 2.35.

Run: python3 scripts/test_tcache_key_version.py

`modules/pwn/libc_targets.py` has said "tcache_key check added 2.29" since it
was written. Everything else said 2.35: the gate in `worker/chal_libc_fix.py`
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
import sys
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
section("the profile generator gates at 2.29")

spec = importlib.util.spec_from_file_location(
    "_clf_under_test", ROOT / "worker" / "chal_libc_fix.py")
clf = importlib.util.module_from_spec(spec)
sys.modules["_clf_under_test"] = clf
spec.loader.exec_module(clf)

# (version, expected tcache_key). The boundary is what regresses, so both
# sides of it are named explicitly rather than generated.
MATRIX = [
    ((2, 27), False), ((2, 28), False),
    ((2, 29), True), ((2, 30), True), ((2, 31), True),
    ((2, 32), True), ((2, 34), True), ((2, 35), True), ((2, 39), True),
]
for ver, expect in MATRIX:
    got = bool(clf._derive_features(list(ver)).get("tcache_key"))
    chk("glibc %d.%d -> tcache_key=%s" % (ver[0], ver[1], expect),
        got == expect, got)

# The specific target the old gate got wrong, and the consequence that made it
# matter: the recommendation list is what the agent reads.
rec = " ".join(clf._derive_features([2, 31]).get("recommended_techniques") or [])
chk("REGRESSION: 2.31 (Ubuntu 20.04) recommends the key bypass — the old "
    ">= (2, 35) gate silently omitted it",
    "key bypass" in rec.lower(), rec)
chk("...and 2.28 still does NOT (the check does not exist there)",
    "key bypass" not in " ".join(
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

# The one file that was right all along must stay right — it is the citation
# the corrected texts point at.
lt = (ROOT / "modules/pwn/libc_targets.py").read_text(errors="replace")
chk("libc_targets.py still records 'tcache_key check added 2.29'",
    "tcache_key check added 2.29" in lt)

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
