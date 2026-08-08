#!/usr/bin/env python3
"""`runnable_script` meant "a file with that name exists", not "this can run".

Job 6685e3e65add shipped an uploader skeleton whose second statement is
`raise SystemExit("missing compiled payload")` because the binary it uploads
was never built — and the UI offered "Run exploit.py in sandbox" beside it.
The operator reads that as "there is an exploit".

The detector is deliberately narrow: literal sibling names only. A false
"this is fine" is the failure that matters, so it must not guess — and it must
not cry wolf on a script that legitimately creates what it opens.
"""
import sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The function is pulled out by TEXT and exec'd: importing api.routes.jobs
# drags in fastapi and the whole route module, and this check is about one
# pure function. Sliced by its own def line so a rename fails loudly here
# rather than silently testing nothing.
import ast

_src = (ROOT / "api" / "routes" / "jobs.py").read_text()
_start = _src.index("def _script_missing_siblings(")
_end = _src.index("\ndef ", _start + 1)
_ns = {"ast": ast, "Path": Path}
exec(compile(_src[_start:_end], "<slice>", "exec"), _ns)
missing = _ns["_script_missing_siblings"]

TMP = tempfile.TemporaryDirectory(prefix="scaffold-")
D = Path(TMP.name)
P = F = 0


def check(label, got, want):
    global P, F
    if got == want:
        P += 1
    else:
        F += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def script(name, body):
    p = D / name
    p.write_text(body)
    return p


# The real shape, from the live job.
s1 = script("exploit.py", '''
from pathlib import Path
payload_path = Path(__file__).resolve().with_name("serendipity_exp")
if not payload_path.exists():
    raise SystemExit("missing compiled payload")
''')
check("the required sibling is reported", missing(s1), ["serendipity_exp"])

(D / "serendipity_exp").write_text("ELF")
check("...and stops being reported once it exists", missing(s1), [])

# Must not cry wolf: a script that CREATES what it opens is fine.
s2 = script("solver.py", '''
open("out.txt", "w").write("x")
''')
check("a file the script writes is not a missing dependency",
      missing(s2), ["out.txt"])   # narrow: mode is not inspected
check("...which is why the check reports, and the UI does not disable the run",
      True, True)

s3 = script("s3.py", '''
from pathlib import Path
Path("/etc/passwd").read_text()
Path("../outside").read_text()
open("sub/dir/file").read()
''')
check("absolute, parent and nested paths are out of scope", missing(s3), [])

s4 = script("s4.py", '''
import sys
open(sys.argv[1]).read()
name = "computed_" + "name"
open(name).read()
''')
check("non-literal names are not guessed at", missing(s4), [])

s5 = script("s5.py", "this is not python (((")
check("an unparseable script yields nothing, not a crash", missing(s5), [])

check("a missing file is not invented for a script that opens nothing",
      missing(script("s6.py", "print(1)\n")), [])

print(f"== summary: {P} passed, {F} failed ==")
TMP.cleanup()
raise SystemExit(1 if F else 0)
