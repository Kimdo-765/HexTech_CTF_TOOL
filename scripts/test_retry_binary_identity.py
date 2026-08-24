#!/usr/bin/env python3
"""A retry is the SAME challenge, so its subject must not drift.

Run: python3 scripts/test_retry_binary_identity.py

`_resubmit` used to name the retried challenge after `iterdir()`'s first
regular file. Directory order is not the challenge. On the real corpus that
disagreed with the identity the original upload chose in 4 of 12 rev retries
(4 of 7 among multi-file jobs), and the name goes straight into
`meta["filename"]` and on to the analyzer:

    3a948819a443   parent said `main`                retried as `README.md`
    d342333ffed3   parent said `CVE-2015-2291.exe`   retried as `output.pdf.enc`
    4c96e913b6e6   inherited that drift              retried as `output.pdf.enc`
    c918d057a4fc   parent said `client_old`          retried as `server`

The fixtures below reproduce each of those bin/ directories by name and size.

Two separate things are checked, because fixing only one leaves the bug:

  * `_carry_binary_name` prefers the name the previous job carried
  * the fallback picker is genuinely deterministic

The second is not free. Job f94c35eb16a2 stages `client` and `client_old` at
exactly 19208 bytes each, and both pickers sorted on size alone -- a stable
sort, so an exact tie left the winner to rglob, i.e. the filesystem. A picker
that two code paths must agree on cannot be decided by directory order.

Sliced from source: importing api.routes.retry drags in fastapi.
"""
from __future__ import annotations

import ast
import pathlib
import sys
import tempfile
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]

checks = 0
fails = 0


def chk(label, cond, got=None):
    global checks, fails
    checks += 1
    if cond:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got=%r" % (label, got))


def section(name):
    print("\n--- %s %s" % (name, "-" * max(0, 56 - len(name))))


def _slice(path: pathlib.Path, names: set[str], ns: dict) -> dict:
    tree = ast.parse(path.read_text())
    nodes = [n for n in tree.body
             if (isinstance(n, ast.FunctionDef) and n.name in names)
             or (isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") in names for t in n.targets))]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<s>", "exec"), ns)
    return ns


# The real shared picker, exec'd rather than stubbed, so this exercises the
# code all three ingest paths now depend on.
picker_ns = _slice(ROOT / "modules/_common.py",
                   {"pick_challenge_binary", "_by_size_then_name",
                    "_CHAL_ARCHIVE_EXTS"},
                   {"Path": pathlib.Path})

common_stub = types.ModuleType("modules._common")
common_stub.pick_challenge_binary = picker_ns["pick_challenge_binary"]
mod_pkg = types.ModuleType("modules")
mod_pkg.__path__ = []
sys.modules.setdefault("modules", mod_pkg)
sys.modules["modules._common"] = common_stub

# _carry_binary_name walks the retry chain via read_job_meta; feed it a fake
# corpus so the chain logic is exercised rather than stubbed away.
FAKE_METAS: dict = {}
carry_ns = _slice(ROOT / "api/routes/retry.py", {"_carry_binary_name"},
                  {"Path": pathlib.Path,
                   "read_job_meta": lambda jid: FAKE_METAS[str(jid)]})
carry = carry_ns["_carry_binary_name"]

ELF = b"\x7fELF" + b"\0" * 60
PE = b"MZ" + b"\0" * 62


def make(files: dict[str, tuple[int, bytes]]) -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp())
    for name, (size, magic) in files.items():
        body = magic + b"\0" * max(0, size - len(magic))
        (d / name).write_bytes(body[:size] if size else magic)
    return d


TXT = b"#\n"

# the four real bin/ directories, by name and size
CASES = {
    "3a948819a443": (
        {"Dockerfile": (227, TXT), "README.md": (300, TXT),
         "main": (76969952, ELF), "sample.png": (224, TXT)},
        "main", "README.md"),
    "d342333ffed3": (
        {"CVE-2015-2291.exe": (2859008, PE), "kmdf1.sys": (16152, PE),
         "output.pdf.enc": (132616, TXT)},
        "CVE-2015-2291.exe", "output.pdf.enc"),
    "c918d057a4fc": (
        {"client": (19208, ELF), "client_diff": (832, TXT),
         "client_old": (19208, ELF), "server": (12744, ELF)},
        "client_old", "server"),
}

section("a retry keeps the identity its parent recorded")
for job, (files, parent_name, drifted_to) in CASES.items():
    d = make(files)
    FAKE_METAS.clear()
    FAKE_METAS["root"] = {"id": "root", "filename": parent_name, "retry_of": None}
    got = carry(d, {"id": job, "filename": parent_name, "retry_of": "root"})
    chk("%s keeps %r" % (job, parent_name), got == parent_name, got)
    chk("%s does NOT drift to %r" % (job, drifted_to), got != drifted_to, got)

section("a chain already polluted upstream is repaired, not perpetuated")
# 4c96e913b6e6 is the case the previous version of this file claimed to cover
# and did not: its comment said "four real bin directories" while CASES held
# three. It inherited `output.pdf.enc` from d342333ffed3, which had itself
# drifted from the root's CVE-2015-2291.exe. Trusting the immediate parent
# keeps promoting a ciphertext as the challenge forever.
pdf_bundle = {"CVE-2015-2291.exe": (2859008, PE), "kmdf1.sys": (16152, PE),
              "output.pdf.enc": (132616, TXT)}
d = make(pdf_bundle)
FAKE_METAS.clear()
FAKE_METAS["5d4ba07beba7"] = {"id": "5d4ba07beba7",
                              "filename": "CVE-2015-2291.exe", "retry_of": None}
FAKE_METAS["d342333ffed3"] = {"id": "d342333ffed3",
                              "filename": "output.pdf.enc",
                              "retry_of": "5d4ba07beba7"}
polluted_parent = FAKE_METAS["d342333ffed3"]
got = carry(d, polluted_parent)
chk("4c96e913b6e6 does NOT inherit the polluted 'output.pdf.enc'",
    got != "output.pdf.enc", got)
chk("...it recovers the root identity 'CVE-2015-2291.exe'",
    got == "CVE-2015-2291.exe", got)
# and the immediate-parent rule still applies when there is no usable root
FAKE_METAS.clear()
FAKE_METAS["gone"] = {"id": "gone", "filename": "not-staged.bin",
                      "retry_of": None}
got2 = carry(d, {"id": "child", "filename": "kmdf1.sys", "retry_of": "gone"})
chk("a root whose file is not staged falls through to the parent's name",
    got2 == "kmdf1.sys", got2)
# a cycle in retry_of must not hang
FAKE_METAS.clear()
FAKE_METAS["a"] = {"id": "a", "filename": "kmdf1.sys", "retry_of": "b"}
FAKE_METAS["b"] = {"id": "b", "filename": "kmdf1.sys", "retry_of": "a"}
chk("a cycle in retry_of terminates",
    carry(d, FAKE_METAS["a"]) in ("kmdf1.sys", "CVE-2015-2291.exe"),
    "did not hang")

section("which mechanism is doing the work, per case")
# Non-vacuity, stated precisely rather than hand-waved. The old rule read
# `iterdir()` order, which is the filesystem's and cannot be reproduced here,
# so asserting against a stand-in ordering proves nothing. What CAN be pinned
# is whether the preserved name and the picker agree — and where they disagree
# the preservation clause is the only thing holding identity.
for job, (files, parent_name, drifted_to) in CASES.items():
    d = make(files)
    blind = carry(d, {})                      # picker only, no parent name
    kept = carry(d, {"filename": parent_name})
    chk("%s: neither route returns the drifted %r" % (job, drifted_to),
        blind != drifted_to and kept != drifted_to, (blind, kept))
    if blind != parent_name:
        chk("%s: picker alone would say %r, so preservation is load-bearing"
            % (job, blind), kept == parent_name, (blind, kept))
    else:
        chk("%s: picker independently agrees on %r" % (job, parent_name),
            kept == blind, (blind, kept))

section("the fallback picker is deterministic on ties")
tie = {"client": (19208, ELF), "client_old": (19208, ELF),
       "server": (12744, ELF)}
picks = {carry(make(tie), {}) for _ in range(8)}
chk("an exact size tie resolves to ONE name across runs", len(picks) == 1, picks)
chk("...and it is the name-ordered winner", picks == {"client"}, picks)

section("fallback order: previous name, then ELF/PE, then non-archive")
d = make({"main": (5000, ELF), "notes.txt": (900000, TXT)})
chk("a huge text file does not beat a real ELF",
    carry(d, {}) == "main", carry(d, {}))
chk("a previous name that is NOT staged falls through to the picker",
    carry(d, {"filename": "vanished.bin"}) == "main",
    carry(d, {"filename": "vanished.bin"}))
d2 = make({"blob.dex": (900, TXT), "small.txt": (10, TXT)})
chk("with no ELF/PE, the largest non-archive wins",
    carry(d2, {}) == "blob.dex", carry(d2, {}))
d3 = make({})
chk("an empty bin dir yields None", carry(d3, {}) is None, carry(d3, {}))
chk("an empty bin dir with a recorded name still yields None",
    carry(d3, {"filename": "gone"}) is None)

section("all three ingest paths share ONE picker")
# The defect this replaces: hybrid kept private copies whose docstrings said
# "Match scalar rev ingest", and they stopped matching the moment the scalar
# side gained a tie-break. On f94c35eb16a2 (client and client_old both exactly
# 19208 bytes) the two then chose different binaries.
#
# The canonical picker lives in modules/_common.py rather than beside the
# upload route because the worker container does not mount `api/` -- a
# `from api.routes...` inside modules/** dies at RQ load.
import re as _re
common_src = (ROOT / "modules/_common.py").read_text()
rev_src = (ROOT / "api/routes/rev_module.py").read_text()
hyb_src = (ROOT / "modules/hybrid/worker.py").read_text()
retry_src2 = (ROOT / "api/routes/retry.py").read_text()

chk("the canonical picker is defined in modules/_common.py",
    "def pick_challenge_binary(" in common_src)
for name, src in (("rev_module", rev_src), ("hybrid worker", hyb_src),
                  ("retry", retry_src2)):
    chk("%s calls the shared picker" % name,
        "pick_challenge_binary" in src)
    chk("%s no longer sorts candidates itself" % name,
        "candidates.sort(" not in src, name)
# Parse rather than grep: the sentence "a `from api.routes...` inside
# modules/** dies at RQ load" appears in a COMMENT explaining this very rule,
# and a substring search flagged it as a violation.
def _imports_api(src: str) -> list[str]:
    bad = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("api"):
            bad.append("%s@%d" % (node.module, node.lineno))
        elif isinstance(node, ast.Import):
            bad += ["%s@%d" % (a.name, node.lineno) for a in node.names
                    if a.name.startswith("api")]
    return bad


for name, src in (("modules/_common.py", common_src),
                  ("modules/hybrid/worker.py", hyb_src)):
    chk("%s imports nothing from api/" % name, _imports_api(src) == [],
        _imports_api(src))

# the real tie, run through the one picker: same answer every time
tie_bundle = {"client": (19208, ELF), "client_diff": (832, TXT),
              "client_old": (19208, ELF), "server": (12744, ELF)}
pick = picker_ns["pick_challenge_binary"]
answers = {pick(make(tie_bundle)).name for _ in range(6)}
chk("the shared picker gives one answer on the real 19208-byte tie",
    len(answers) == 1, answers)
ties: list = []
pick(make(tie_bundle), ties=ties)
chk("...and it reports that the choice was arbitrary",
    sorted(ties) == ["client", "client_old"], ties)
chk("a bundle with no tie reports none",
    (lambda t: (pick(make({"a": (10, ELF), "b": (20, ELF)}), ties=t), t == [])[1])([]))
# and the retry path is NOT decided by that tie: it preserves the root name
FAKE_METAS.clear()
FAKE_METAS["f94c35eb16a2"] = {"id": "f94c35eb16a2", "filename": "client_old",
                              "retry_of": None}
chk("a retry of the tied bundle keeps the root's client_old, tie or not",
    carry(make(tie_bundle),
          {"id": "c918d057a4fc", "filename": "server",
           "retry_of": "f94c35eb16a2"}) == "client_old")

section("the caller no longer names the challenge after directory order")
retry_src = (ROOT / "api/routes/retry.py").read_text()
chk("the iterdir-first assignment is gone",
    "binary_name = binary_name or f.name" not in retry_src)
chk("_resubmit routes through the shared helper",
    "_carry_binary_name(new_bin, prev_meta)" in retry_src)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
