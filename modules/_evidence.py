"""What ends a run: a budget that only NEVER-BEFORE-SEEN evidence replenishes.

The operator's model is a closed finite knowledge space, and the rule they
shipped in 0a98e93 is "a run ends when nothing is new, not when a counter runs
out".  Transferring that rule from prejudge issues to a reviewer loop is the
whole problem, and the naive transfer does not work:
`" | ".join(sorted(issues))[:600]` compared by exact equality is viable only
because prejudge issues are machine-generated and byte-stable.  A reviewer plan
is free-form prose from a temperature-bearing model.  It never repeats exactly,
so exact-signature dedup on it reports "new" every single time while the
reviewer circles — an instrument that cannot fail, which is not an instrument.

THE INVERSION.  Four independent designs for this were built and all four were
killed by the same attack: they normalised free text against a closed list of
scrub patterns, and real artifacts carry volatility no denylist anticipates —
a rotating instance port, a session nonce, a run-dependent counter in an
exception message, a shifted traceback line.  Any one of those buys an
iteration forever.

So this module enumerates SIGNAL, not noise.  Every field of an evidence point
is drawn from a domain the code itself declares finite, and anything that is
not — an exception class, a prejudge issue string, a flag-candidate set — goes
through a bounded interner that hands out the first K distinct values and maps
everything after to a single absorbing OTHER.  |E| is therefore finite BY
CONSTRUCTION, independent of what the inputs do, and it is printable
(``alphabet_size()``).  An unscrubbed nonce cannot buy an iteration because it
is not a field.

TERMINATION.  A refund requires a never-before-seen, non-saturated point of a
finite set, so refunds are bounded by |E| and iterations by ``B * (|E| + 1)``.
This holds whether or not evidence ever repeats — which is the property the
four killed designs lacked, all of which ran forever on a drifting reviewer.

WHAT THIS DOES NOT DO.  It does not detect drift.  A reviewer wandering out of
the challenge's space produces genuinely new evidence every round and is
formally indistinguishable from exploration without a relevance model, which
does not exist here.  Drift is now merely FINITE.  That is the honest
degradation and it is the strongest available.

Stdlib only, and imports nothing from ``modules._common`` or ``api.*``: the
worker container has no ``api/`` mount, and an ``api.*`` import inside
``modules/**`` dies at RQ load time.  Pure functions throughout, so the whole
surface is unit-testable with synthetic dicts and no job tree.
"""
from __future__ import annotations

import hashlib
import re

# The absorbing value.  A field that has seen more than its K distinct values
# collapses here and STAYS here, which is what makes the alphabet finite.
OTHER = "OTHER"

# Budgets.  Both are spent on a repeat and restored in full by novelty.
#
# HONESTY: B is tuned on nothing.  It was chosen to give a lineage roughly the
# depth its measured behaviour suggests (real lineages realise 2-3 distinct
# evidence points, so B=3 lets a run outlive its repeats without outliving its
# ideas) and then checked against replayed lineages, not derived from them.
# K_FLAG=3 is tuned on ONE lineage.  Re-derive both from live enforce jobs
# once the ledger has been recording for a while; the log line and the
# WHY_STOPPED block exist so that is possible without a code change.
B = 3
B1 = 2

# Interner capacities.  Small on purpose: a slot that never saturates is an
# unbounded field wearing a bound's clothes.
#
# MEASURED ON THE FIRST THREE LIVE JOBS, and it changes which number matters.
# Reading the ledgers back (8 observations across 3 pwn jobs), the count of
# distinct evidence points equalled the `pj` interner's slot count EXACTLY in
# every job — 3/3, 3/3, 2/2 — while `exc` and `flag` allocated ZERO slots.
#
# So in practice this instrument was a prejudge-issue-set novelty detector and
# the other eight fields contributed nothing. That makes K_PJ, not B, the
# operative ceiling on those runs: after 4 distinct issue sets the channel
# saturates permanently, every later point reads as a repeat, and the budget
# can never be refunded again. One job had already spent 3 of the 4.
#
# NOT changed on that evidence. Three jobs of one module is not a basis for
# retuning, and raising K_PJ would trade the finiteness bound for depth
# without knowing the exchange rate. What IS shipped is the measurement:
# channel_report() below runs on every job and renders into WHY_STOPPED, so
# the next revision of these numbers comes from many jobs rather than three.
K_EXC = 6
K_PJ = 4
K_FLAG = 3

# Mirrors of modules._judge's domains.  Copied rather than imported because
# _judge pulls the SDK and this module must stay importable anywhere, including
# a bare unit test.  scripts/test_evidence_budget.py asserts the copies are
# equal to the originals, so drift is a named failure rather than a silent one.
VALID_VERDICTS = frozenset({
    "success", "partial", "hung", "parse_error",
    "network_error", "crash", "timeout", "unknown",
})
VALID_HEAP_FAILURE_CODES = frozenset({
    "heap.libc_version_mismatch",
    "heap.unaligned_libc_base",
    "heap.safe_linking_missing",
    "heap.safe_linking_misapplied",
    "heap.hook_on_modern_libc",
    "heap.str_finish_patched",
    "heap.vtable_write_order_violated",
    "heap.tcache_key_not_bypassed",
    "heap.aslr_unstable",
    "heap.unaligned_tcache_target",
    "heap.whitespace_in_address",
    "heap.interactive_in_sandbox",
    "heap.unbounded_recv",
})

# The four values modules/_common.py's flag gate can take.  Mirrored for the
# same reason and asserted the same way.
GATE_REASONS = frozenset({
    "judge_success", "marker_capture", "weak_flag_evidence",
    "no_capture_evidence",
})


class Interner:
    """First K distinct values get a slot; everything after saturates.

    The slot NAMES are positional (``s0``, ``s1``, ...) rather than the values
    themselves, so nothing volatile is retained and the ledger is safe to
    render into WHY_STOPPED on a public repo.
    """

    __slots__ = ("k", "slots")

    def __init__(self, k: int, slots: dict | None = None):
        self.k = int(k)
        self.slots = dict(slots or {})

    def id(self, value) -> str:
        """"" for absent, ``sN`` for a known value, OTHER once saturated."""
        if not value:
            return ""
        key = str(value)
        if key in self.slots:
            return self.slots[key]
        if len(self.slots) < self.k:
            self.slots[key] = f"s{len(self.slots)}"
            return self.slots[key]
        return OTHER

    def to_state(self) -> dict:
        return dict(self.slots)


# The exception CLASS, never the message.  Solvers routinely report their own
# attempt count in the exception text ("no flag after N valid sessions/M
# attempts"), and that counter increments every run; keeping the message would
# hand a circling loop an unlimited supply of "new" evidence.  Same reason the
# traceback's line numbers are excluded — they shift whenever the agent edits
# anything above them.
_EXC_LINE_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_.]*\.)?([A-Z][A-Za-z0-9_]*(?:Error|Exception|"
    r"Exit|Interrupt|Warning))\b",
    re.MULTILINE,
)


def last_exception_class(stderr) -> str:
    """The class name of the LAST exception in a traceback, or ""."""
    if not stderr:
        return ""
    matches = _EXC_LINE_RE.findall(str(stderr)[-4000:])
    return matches[-1] if matches else ""


def prejudge_key(prejudge) -> str:
    """A stable key for a prejudge block's issue set.

    Interned rather than compared directly: modules/_judge.py embeds a verbatim
    report.md snippet in its issues, so the text is paraphrasable even though
    the underlying objection is not.
    """
    if not isinstance(prejudge, dict):
        return ""
    issues = [str(i).strip() for i in (prejudge.get("issues") or [])]
    issues = [i for i in issues if i]
    if not issues:
        return ""
    joined = " | ".join(sorted(issues))[:600]
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:16]


def flag_candidate_key(flags) -> str:
    """A digest of the SET of flag-shaped candidates seen so far.

    Order-insensitive and content-hashed, so the ledger never stores a
    candidate string — this file's output is rendered into WHY_STOPPED, and
    WHY_STOPPED is carried into the next job.  Flag curation is the operator's
    and nothing here filters or drops a candidate; this only asks "is the set
    the same one as last time?".
    """
    items = sorted({str(f) for f in (flags or []) if str(f).strip()})
    if not items:
        return ""
    joined = "\x00".join(items)
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:16]


def new_ledger() -> dict:
    """The per-job ledger.  Plain JSON so it round-trips through summary."""
    return {
        "seen": [],
        "budget": B,
        "delivered": [],
        "plan_budget": B1,
        "interners": {"exc": {}, "pj": {}, "flag": {}},
        "log": [],
    }


def _interners(ledger: dict) -> dict:
    state = ledger.setdefault("interners", {"exc": {}, "pj": {}, "flag": {}})
    return {
        "exc": Interner(K_EXC, state.get("exc")),
        "pj": Interner(K_PJ, state.get("pj")),
        "flag": Interner(K_FLAG, state.get("flag")),
    }


def _save_interners(ledger: dict, interners: dict) -> None:
    ledger["interners"] = {
        name: obj.to_state() for name, obj in interners.items()
    }


def evidence_point(
    last_sandbox,
    *,
    ran: bool,
    verdict,
    gate_reason,
    flags,
    interners: dict,
) -> list:
    """One observation of the world, as a list of finite-domain fields.

    A list rather than a tuple because this round-trips through `summary` as
    JSON; `points_equal` does the comparison so callers never depend on the
    container type.
    """
    sandbox = last_sandbox if isinstance(last_sandbox, dict) else {}
    exit_code = sandbox.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        exit_code = None
    elif not (0 <= exit_code <= 255):
        exit_code = None
    judge = sandbox.get("judge")
    judge = judge if isinstance(judge, dict) else {}
    failure_code = judge.get("failure_code")
    return [
        bool(ran),
        exit_code,
        [
            bool(sandbox.get("timeout")),
            bool(sandbox.get("container_disappeared")),
            bool(sandbox.get("killed_by_supervise")),
        ],
        verdict if verdict in VALID_VERDICTS else None,
        failure_code if failure_code in VALID_HEAP_FAILURE_CODES else None,
        gate_reason if gate_reason in GATE_REASONS else None,
        interners["exc"].id(last_exception_class(sandbox.get("stderr"))),
        interners["pj"].id(prejudge_key(sandbox.get("prejudge"))),
        interners["flag"].id(flag_candidate_key(flags)),
    ]


def _canon(point) -> str:
    """A comparison key that survives the JSON round-trip (tuple -> list)."""
    return repr(_freeze(point))


def _freeze(value):
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def is_saturated(point) -> bool:
    """True once ANY field has collapsed into the absorbing value.

    A saturated point is never novel.  Without this the interner is decorative:
    a field with unbounded distinct values would emit OTHER forever, and OTHER
    paired with any other varying field would keep minting fresh points.
    """
    return any(f == OTHER for f in _freeze(point) if isinstance(f, str))


def observe(ledger: dict, point) -> dict:
    """Charge the budget, or refund it in full for genuinely new evidence.

    Novelty is NEVER-BEFORE-SEEN, not changed-since-last.  An A,B,A,B
    oscillation between two dead branches would refund forever under the
    weaker reading; under this one it refunds twice and then charges to zero.
    """
    key = _canon(point)
    seen = ledger.setdefault("seen", [])
    saturated = is_saturated(point)
    novel = (key not in seen) and not saturated
    if novel:
        seen.append(key)
        ledger["budget"] = B
    else:
        ledger["budget"] = int(ledger.get("budget", B)) - 1
    ledger.setdefault("log", []).append({
        "novel": novel,
        "saturated": saturated,
        "budget": ledger["budget"],
        "distinct": len(seen),
    })
    return {
        "novel": novel,
        "saturated": saturated,
        "budget": ledger["budget"],
        "progress": ledger["budget"] > 0,
    }


def evidence_progress(ledger) -> bool:
    """Is there budget left?  An absent ledger reads as progress (fail-open).

    Fail-open is deliberate and narrow: this predicate REPLACES a hard
    one-per-job cap, so a missing ledger must not be more restrictive than the
    thing it replaced was.  Termination is still guaranteed — the ledger is
    created by the same code that reads it, and the only way to be here without
    one is to have never observed anything.
    """
    if not isinstance(ledger, dict):
        return True
    return int(ledger.get("budget", B)) > 0


# --------------------------------------------------------------------- plans

_ANCHOR_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_./-]{3,}")


def extract_anchors(text, vocabulary=None) -> frozenset:
    """Identifier-shaped tokens in a hint, optionally kept to a vocabulary.

    The vocabulary is what makes this a GROUNDED anchor set rather than a bag
    of words: a token that appears nowhere in the evidence the reviewer was
    given is the model's own invention, and two hints that share only invented
    tokens have not proposed the same thing.
    """
    if not text:
        return frozenset()
    tokens = {t.lower() for t in _ANCHOR_RE.findall(str(text)[:4000])}
    if vocabulary is None:
        return frozenset(tokens)
    vocab = {str(v).lower() for v in vocabulary}
    return frozenset(tokens & vocab)


def plan_key(hint, hint_cls: str, vocabulary=None) -> list:
    """[class, sorted grounded anchors] — the plan's identity, not its wording."""
    return [str(hint_cls or ""), sorted(extract_anchors(hint, vocabulary))]


def observe_plan(ledger: dict, key) -> dict:
    """Charge when a plan names nothing the run has not already been told.

    P1 CARRIES NO TERMINATION GUARANTEE and is not asked to.  Measured against
    realistic reviewer rounds, an anchor-subset test reported NOVEL on 19 of 19
    and fired only on the healthy case where a reviewer legitimately narrows a
    previous plan — i.e. its only demonstrated behaviour was a false stop.
    Making it a budget rather than a per-hint gate keeps the operator's "stop
    when the plan overlaps what was already tried" clause honest while costing
    one narrowing hint a charge instead of the whole run.  Termination rests
    entirely on observe().
    """
    cls, anchors = (key + ["", []])[:2] if isinstance(key, list) else ("", [])
    anchor_set = frozenset(anchors or [])
    delivered = ledger.setdefault("delivered", [])
    covered = False
    if anchor_set:
        for prev in delivered:
            prev_cls, prev_anchors = (list(prev) + ["", []])[:2]
            if prev_cls == cls and anchor_set <= frozenset(prev_anchors or []):
                covered = True
                break
    if covered:
        ledger["plan_budget"] = int(ledger.get("plan_budget", B1)) - 1
    else:
        delivered.append([cls, sorted(anchor_set)])
        ledger["plan_budget"] = B1
    return {
        "covered": covered,
        "plan_budget": ledger["plan_budget"],
        "progress": ledger["plan_budget"] > 0,
    }


def plan_progress(ledger) -> bool:
    if not isinstance(ledger, dict):
        return True
    return int(ledger.get("plan_budget", B1)) > 0


# ------------------------------------------------------------------ reporting

def alphabet_size() -> int:
    """|E| as DECLARED — the bound the termination proof rests on.

    2 (ran) x 257 (exit_code incl. None) x 8 (run flags) x 9 (verdict incl.
    None) x 14 (failure_code incl. None) x 5 (gate_reason incl. None)
    x (K+2) per interned slot (its K values, plus absent, plus OTHER).

    READ THIS AS A FINITENESS CLAIM, NOT AS A DESCRIPTION OF THE INSTRUMENT.
    It counts what the domains ALLOW, and measurement says most of them never
    move:

      * `failure_code` draws from _VALID_HEAP_FAILURE_CODES, i.e. pwn-heap
        only — one module of the five that run this loop. It has never been
        populated in the corpus, and it multiplies this number by 14.
      * `run_flags` (timeout / container_disappeared / killed_by_supervise)
        was all-False in every corpus job measured, and multiplies by 8.
      * On the first three live jobs, ONLY the `pj` channel moved at all.

    So this number is ~10^2 larger than anything an actual run explores.
    Quoting it as the instrument's resolution would be false; the honest
    statement is that the alphabet is finite and therefore the budget must
    run out. Use channel_report() for what a given run actually used.
    """
    return (
        2 * 257 * 8
        * (len(VALID_VERDICTS) + 1)
        * (len(VALID_HEAP_FAILURE_CODES) + 1)
        * (len(GATE_REASONS) + 1)
        * (K_EXC + 2) * (K_PJ + 2) * (K_FLAG + 2)
    )


def max_iterations() -> int:
    """The bound the termination argument actually gives: B * (|E| + 1).

    Astronomically larger than any real run, and that is fine — the claim is
    FINITENESS, not tightness.  What bounds a real run is that its evidence
    collapses to 2-3 distinct points, so the budget drains after a handful of
    repeats.  Do not quote this number as a practical limit.
    """
    return B * (alphabet_size() + 1)


def channel_report(ledger) -> dict:
    """Which interned channels this run actually used, and how close to full.

    Exists because the first three live jobs answered a question the design
    could not: the count of distinct evidence points equalled the `pj` slot
    count exactly in all three, while `exc` and `flag` allocated none. If that
    holds broadly, the operative bound is K_PJ rather than B, and the six
    non-interned fields are carrying nothing.

    Only the INTERNED channels can be reported from stored state — the other
    six leave no per-channel trace in the ledger, so their movement is
    inferred, not read. Said here rather than implied: a caller must not
    report "only pj moved" as measured for those six.
    """
    out = {}
    if not isinstance(ledger, dict):
        return out
    state = ledger.get("interners") or {}
    for name, cap in (("exc", K_EXC), ("pj", K_PJ), ("flag", K_FLAG)):
        used = len((state.get(name) or {}))
        out[name] = {"used": used, "capacity": cap, "saturated": used >= cap}
    return out


def render_stop_block(ledger) -> list:
    """Markdown lines for WHY_STOPPED — an observation table, no candidates."""
    if not isinstance(ledger, dict):
        return []
    log = ledger.get("log") or []
    if not log:
        return []
    out = [
        "## Evidence budget (why the loop had, or had not, run out of road)",
        "",
        "Each scored iteration: genuinely new evidence restores the budget in "
        "full, a repeat spends one. SCOPE — the budget is consulted where the "
        "judge votes to STOP: with it positive the run may continue past that "
        "vote, and with it at zero the run ends there. A judge that keeps "
        "voting continue is not bounded by this table, so a zero here does "
        "not by itself mean the run was about to end.",
        "",
        "| iter | new evidence? | saturated | budget left | distinct states |",
        "|---|---|---|---|---|",
    ]
    for i, row in enumerate(log, 1):
        out.append(
            f"| {i} | {'yes' if row.get('novel') else 'no'} | "
            f"{'yes' if row.get('saturated') else 'no'} | "
            f"{row.get('budget')} | {row.get('distinct')} |"
        )
    out.append("")

    # WHICH CHANNEL DID THE WORK. On the first three live jobs the distinct-
    # state count equalled the `pj` slot count exactly, and the other two
    # interned channels allocated nothing — so the practical ceiling was
    # K_PJ, not the budget. Rendered on every job so that observation either
    # generalises or is refuted by data rather than by argument.
    chans = channel_report(ledger)
    if chans:
        out += [
            "Interned channels used by this run (a channel that fills "
            "SATURATES permanently, after which no later state can be new):",
            "",
            "| channel | slots used | capacity | saturated |",
            "|---|---|---|---|",
        ]
        _label = {"exc": "exception class", "pj": "prejudge issues",
                  "flag": "flag-candidate set"}
        for name in ("exc", "pj", "flag"):
            c = chans.get(name) or {}
            out.append("| %s | %s | %s | %s |"
                       % (_label.get(name, name), c.get("used"),
                          c.get("capacity"),
                          "YES" if c.get("saturated") else "no"))
        out += [
            "",
            "The six non-interned fields (ran, exit_code, run flags, verdict, "
            "heap failure_code, gate reason) leave no per-channel trace, so "
            "this table does not speak for them.",
            "",
        ]

    plan_budget = ledger.get("plan_budget")
    if plan_budget is not None:
        out += [
            f"Plan budget remaining: {plan_budget} of {B1} "
            f"(spent when a retry plan names nothing the run had not already "
            f"been told).",
            "",
        ]
    return out
