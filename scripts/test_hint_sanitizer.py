#!/usr/bin/env python3
"""Regression tests for the reviewer hint sanitizer.

Run: python3 scripts/test_hint_sanitizer.py

The sanitizer rewrites reviewer output before it reaches the next agent. That
makes it the one place where a bad regex does not merely garble text — it can
INVERT a finding. The rule that prompted this file replaced
`\\b\\S+ is firewalled\\b` with a phrase beginning "the target is …", so it ate
the subject and turned "REFUTED: outbound DNS is firewalled" into an assertion
that the collector is reachable. The reviewer's whole value is its REFUTED
list; a sanitizer that inverts refutations is worse than no sanitizer.

These load the real _HINT_REPLACEMENTS out of modules/reviewer.py by source, so
FastAPI is not needed and the table under test is the shipped one.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = (ROOT / "modules/reviewer.py").read_text()

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


# --- load the real table ----------------------------------------------------
# Execute only the _HINT_REPLACEMENTS assignment, with `_re` bound to `re`.
# The ASSIGNMENT, not the first mention — the name appears in a docstring
# 2000 lines earlier and slicing from there yields unbalanced source.
start = SRC.index("_HINT_REPLACEMENTS: tuple")
depth = 0
start = SRC.index("= (", start) + 2
for i in range(start, len(SRC)):
    if SRC[i] == "(":
        depth += 1
    elif SRC[i] == ")":
        depth -= 1
        if depth == 0:
            end = i + 1
            break
ns: dict = {"_re": re}
exec("_HINT_REPLACEMENTS = " + SRC[start:end], ns)          # noqa: S102 - the table is source we ship
TABLE = ns["_HINT_REPLACEMENTS"]
chk("loaded the shipped replacement table", len(TABLE) > 5, len(TABLE))


def sanitize(text):
    for pat, repl in TABLE:
        text = pat.sub(repl, text)
    return text


# --- the subject of a refutation must survive -------------------------------
SUBJECTS = [
    ("REFUTED: outbound DNS is firewalled (no resolution observed)", "outbound DNS"),
    ("REFUTED: egress to port 443 is firewalled", "port 443"),
    ("the container is firewalled", "container"),
    ("webhook.site is firewalled", "webhook.site"),
    ("the bot is firewalled from the internet", "bot"),
]
for text, subject in SUBJECTS:
    out = sanitize(text)
    chk("subject %r survives sanitization" % subject, subject.lower() in out.lower(), out)

# The specific inversion: a refutation must not come out asserting reachability
# ABOUT SOMETHING ELSE. The subject staying put is what prevents that.
out = sanitize("REFUTED: outbound DNS is firewalled (no resolution observed)")
chk("a refutation is not turned into a claim about 'the target'",
    not out.startswith("REFUTED: outbound the target"), out)
chk("...and the parenthetical evidence is untouched",
    "(no resolution observed)" in out, out)

# --- no rule may double an article or leave a dangling fragment --------------
for text, _ in SUBJECTS:
    out = sanitize(text)
    chk("no doubled article in %r" % text[:34],
        not re.search(r"\bthe the\b|\ba a\b", out, re.I), out)

# --- the sanitizer must never empty a hint ----------------------------------
# Every replacement substitutes a non-empty string, so a non-empty hint stays
# non-empty. If that ever changes, an "empty hint" would read as "the reviewer
# had nothing to say" when in fact the sanitizer ate it.
for text, _ in SUBJECTS:
    chk("non-empty in, non-empty out: %r" % text[:34], bool(sanitize(text).strip()))

# --- the rules it is actually there for still fire ---------------------------
FIRES = [
    ("we should exfiltrate the flag", "exfiltrate"),
    ("bypass the firewall using a callback", "bypass the firewall"),
]
for text, gone in FIRES:
    out = sanitize(text)
    chk("%r is still rewritten" % gone, gone.lower() not in out.lower(), out)

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
