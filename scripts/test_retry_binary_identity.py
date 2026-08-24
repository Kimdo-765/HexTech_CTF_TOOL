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


# The real picker, exec'd rather than stubbed, so this exercises the shared
# code both paths depend on.
picker_ns = _slice(ROOT / "api/routes/rev_module.py",
                   {"_first_binary_in", "_largest_non_archive", "_ARCHIVE_EXTS"},
                   {"Path": pathlib.Path, "Optional": object})

stub = types.ModuleType("api.routes.rev_module")
stub._first_binary_in = picker_ns["_first_binary_in"]
stub._largest_non_archive = picker_ns["_largest_non_archive"]
api_pkg = types.ModuleType("api")
api_pkg.__path__ = []
routes_pkg = types.ModuleType("api.routes")
routes_pkg.__path__ = []
sys.modules.setdefault("api", api_pkg)
sys.modules.setdefault("api.routes", routes_pkg)
sys.modules["api.routes.rev_module"] = stub

carry_ns = _slice(ROOT / "api/routes/retry.py", {"_carry_binary_name"},
                  {"Path": pathlib.Path})
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
    got = carry(d, {"filename": parent_name})
    chk("%s keeps %r" % (job, parent_name), got == parent_name, got)
    chk("%s does NOT drift to %r" % (job, drifted_to), got != drifted_to, got)

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

section("the caller no longer names the challenge after directory order")
retry_src = (ROOT / "api/routes/retry.py").read_text()
chk("the iterdir-first assignment is gone",
    "binary_name = binary_name or f.name" not in retry_src)
chk("_resubmit routes through the shared helper",
    "_carry_binary_name(new_bin, prev_meta)" in retry_src)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
