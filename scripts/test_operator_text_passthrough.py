#!/usr/bin/env python3
"""The operator's own words must reach the agent unrewritten.

Run: python3 scripts/test_operator_text_passthrough.py

`_sanitize_hint` exists to keep MODEL phrasing from tripping the prompt
classifier. It was also being applied to text a HUMAN typed: the `/continue`
comment, a hand-written `/retry` hint, and every `/resume` hint (that route
refuses without one). So "reverse shell to 127.0.0.1:4444" reached the agent as
"network callback session to 127.0.0.1:4444" — a sentence the operator never
wrote — while `continue_comment` in the same meta.json kept the original and
nothing logged the divergence.

Five call sites could carry operator text. Four of them live inside
`_retry_preamble` / `_resume_preamble`, and reading only their callers makes
them look model-only; `retry_with_hint` does `if manual_hint is not None: hint =
manual_hint`, which is what actually routes a human's words there. This file
pins the distinction so a future reader does not re-derive it wrongly.

Sliced from source: importing api.routes.retry drags in fastapi.
"""
import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = (ROOT / "api/routes/retry.py").read_text()

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


tree = ast.parse(SRC)


def func(name):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


section("both preambles accept an operator_text declaration")
for fn in ("_retry_preamble", "_resume_preamble"):
    node = func(fn)
    chk("%s exists" % fn, node is not None)
    if not node:
        continue
    kwonly = [a.arg for a in node.args.kwonlyargs]
    chk("%s takes operator_text" % fn, "operator_text" in kwonly, kwonly)
    # default must be False so untouched callers keep today's behaviour
    idx = kwonly.index("operator_text") if "operator_text" in kwonly else -1
    if idx >= 0:
        dflt = node.args.kw_defaults[idx]
        chk("%s defaults operator_text to False" % fn,
            isinstance(dflt, ast.Constant) and dflt.value is False,
            ast.unparse(dflt) if dflt else None)

section("model text is still sanitized, operator text is not")
for fn in ("_retry_preamble", "_resume_preamble"):
    node = func(fn)
    body = ast.get_source_segment(SRC, node) or ""
    chk("%s guards the sanitizer on operator_text" % fn,
        "hint if operator_text else _sanitize_hint(hint)" in body, body[:0])
    chk("%s renders the guarded local, not the raw call" % fn,
        '_sanitize_hint(hint)}"' not in body and '{_hint_text}"' in body)

section("the /continue comment is never rewritten")
cont = ast.get_source_segment(SRC, func("_continue_in_place")) or ""
chk("_continue_in_place does not call the sanitizer",
    "_sanitize_hint" not in cont)
chk("...and still formats the operator's comment into the template",
    "_CONTINUE_HINT_TMPL.format(comment=comment.strip())" in cont)

section("call sites declare the origin honestly")
chk("retry_with_hint passes operator_text=manual_hint is not None",
    "operator_text=manual_hint is not None" in SRC)
chk("/resume declares operator_text=True (the route refuses without a hint)",
    re.search(r"_resume_preamble\([^)]*operator_text=True", SRC, re.S) is not None)
# the reviewer paths must NOT claim operator origin
rev = ast.get_source_segment(SRC, func("retry_with_hint")) or ""
chk("the reviewer branch still produces the hint it will sanitize",
    "_ask_reviewer_with_failover" in rev)

section("the docstring no longer licenses rewriting a human")
rsrc = (ROOT / "modules/reviewer.py").read_text()
chk("the 'safe on user-supplied hints' claim is gone",
    "Safe to call on both reviewer-generated and user-supplied hints" not in rsrc)
chk("...and it says model-only instead",
    "FOR MODEL-GENERATED TEXT ONLY" in rsrc)

section("behavioural: a human sentence survives verbatim")
# exercise the real table against text an operator would plausibly type
start = rsrc.index("_HINT_REPLACEMENTS: tuple")
start = rsrc.index("= (", start) + 2
depth = 0
for i in range(start, len(rsrc)):
    if rsrc[i] == "(":
        depth += 1
    elif rsrc[i] == ")":
        depth -= 1
        if depth == 0:
            end = i + 1
            break
ns = {"_re": re}
exec("_HINT_REPLACEMENTS = " + rsrc[start:end], ns)          # noqa: S102
TABLE = ns["_HINT_REPLACEMENTS"]


def sanitize(t):
    for pat, repl in TABLE:
        t = pat.sub(repl, t)
    return t


OPERATOR = "try a reverse shell to 127.0.0.1:4444 and exfiltrate the flag"


def guarded(hint, operator_text):
    """The exact expression both preambles now evaluate. Written out rather
    than asserted about, so this check fails if the guard is ever inverted."""
    return hint if operator_text else sanitize(hint)


chk("the table WOULD have rewritten it (so the bypass is load-bearing)",
    sanitize(OPERATOR) != OPERATOR, sanitize(OPERATOR))
chk("operator_text=True passes the human sentence through byte-for-byte",
    guarded(OPERATOR, True) == OPERATOR, guarded(OPERATOR, True))
chk("operator_text=False still sanitizes model text",
    guarded(OPERATOR, False) != OPERATOR, guarded(OPERATOR, False))
chk("...and the address the operator typed survives either way",
    "127.0.0.1:4444" in guarded(OPERATOR, True)
    and "127.0.0.1:4444" in guarded(OPERATOR, False))
# the guard expression in the shipped file must match the one tested here
chk("the shipped guard is the expression this test exercises",
    SRC.count("hint if operator_text else _sanitize_hint(hint)") == 2)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
