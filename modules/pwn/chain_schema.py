"""Chain JSON schema + validator (Phase 8 ship gate).

The exploit author writes `./chain.json` alongside `./exploit.py`.
It is a structured statement of the chain main intends to run:
which primitives are enumerated, which are empirically verified,
and what each step does + how it can be verified.

prejudge calls `validate_chain` to catch the failure mode observed
on jobs 4a6bd25a0d1d and 7ad50a878e91: main writes a chain whose
final RCE step depends on a primitive that empirical probing
revealed to be blocked, but the script ships anyway and burns
a sandbox + judge cycle confirming what was already known.

Schema (lenient — every field has a sane fallback so validation
catches *real* errors, not formatting nits):

  {
    "schema_version": 1,
    "chain_name": "<one-line label>",
    "rce_target": "<final goal — e.g. '__free_hook = system'>",
    "primitives": [
      {
        "id": "P1",
        "name": "<short name, e.g. 'canary leak via filled buf'>",
        "verified": true | false,
        "verify_method": "<how you empirically confirmed (or would)>",
        "reason_failed": "<only when verified=false — why probing said no>"
      },
      ...
    ],
    "steps": [
      {
        "n": 1,
        "action": "<what this step does>",
        "uses_primitives": ["P1", "P2"],
        "prereq": "none" | "step 0" | "step 2",
        "verify": "<empirical check: 'leak & 0xfff == 0', 'sbrk top > 0x100000000', etc>"
      },
      ...
    ]
  }

Failure classes the validator emits (severity-tagged):

  CRITICAL  — chain logically can't fire as written (e.g. a step
              uses an unverified primitive); ship-blocking.
  HIGH      — chain is structurally broken (dangling prereq,
              undefined primitive ref); ship-blocking.
  MED       — missing recommended field (verify, rce_target);
              advisory, not ship-blocking on its own.

Caller decides escalation policy. The default in
`_judge.prejudge_script` treats any CRITICAL as severity=high +
ok=False; HIGH joins the existing issues list at the LLM's chosen
severity; MED becomes informational issues.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
CHAIN_FILENAME = "chain.json"

# A prereq like "step 2" or "steps 1+3" should still parse; we just
# need to recover the integer step indices referenced. Be liberal.
_STEP_REF_RE = re.compile(r"\bstep\s*(\d+)\b|\b(\d+)\b", re.IGNORECASE)

# rce_target self-admission patterns. When main writes the chain
# but admits in rce_target itself that no working chain was found,
# treat that as critical — the chain is by main's own statement a
# partial/leak-only deliverable that does not warrant a sandbox
# cycle. Observed on jobs 59ab9dfe2d2a / de15654c8f39 (rce_target:
# "intended __free_hook = system overwrite, but no arbitrary-write
# primitive is reachable…").
# A primitive carries verified=false for two very different reasons:
#   (a) TESTED-AND-FAILED — local probing said NO (known-broken). Ship-blocking.
#   (b) UNTESTABLE-LOCALLY — the worker physically cannot test it (env limit:
#       no vsyscall page, CET/SHSTK enforced by the WSL2 host kernel, no
#       matching-kernel VM, no /dev/kvm). The REMOTE is then the ONLY test.
# Blocking (b) dead-ends a chain that's only verifiable on the target AND
# penalizes the agent's honesty in marking it unverified (had it lied
# verified=true, the run would have proceeded). So (b) downgrades to a `med`
# probe-allowed finding, not a `critical` ship-block. Detected from the
# primitive's reason_failed / verify_method text. (Job bc2138675967, 2026-05-28:
# vsyscall primitive marked "Untestable on worker ... confirmed by sandbox" got
# CHAIN-INVALID-blocked, wasting the only available test — the remote.)
_UNTESTABLE_LOCALLY_RE = re.compile(
    r"untestable"
    r"|cannot (?:be )?(?:test|verif)\w*\s+local|can.?t (?:be )?(?:test|verif)\w*\s+local"
    r"|not (?:testable|verifiable) local"
    r"|vsyscall\s*=?\s*none|no vsyscall|vsyscall (?:unmapped|not (?:present|mapped))"
    r"|wsl2|host kernel|worker kernel|no /dev/kvm"
    r"|(?:will (?:be|only)|to be|can only be) (?:confirmed|verified|tested)"
    r"[\w\s]{0,20}?(?:by|on|via|against)\s+(?:the )?(?:sandbox|remote|deploy|target)"
    r"|only (?:testable|verifiable|confirmable)\s+(?:on|against|at)\s+"
    r"(?:the )?(?:remote|deploy|target|sandbox)"
    r"|remote(?:[- ]only| is the only)",
    re.IGNORECASE,
)


_RCE_TARGET_NEGATIVE = re.compile(
    r"\b(?:"
    r"no\s+(?:working|viable|known)\s+(?:chain|path|exploit)|"
    r"no\s+(?:arbitrary[- ]write|leak|rce|hook|write)\s+primitive|"
    r"no\s+(?:arb|arbitrary)[- ]?write|"
    r"not\s+(?:reachable|achievable|available|achieved|reached|yet)|"
    # Job 96cd1092b992: rce_target was
    # "__free_hook = system (not achieved — info leak missing)"
    # The "not achieved" portion is caught above; this clause covers
    # the parenthetical "info leak missing" / "X missing" tail that
    # main agents seem to favor.
    r"(?:leak|primitive|chain|target|prereq)\s+missing|"
    r"missing\s+(?:leak|primitive|chain|prereq)|"
    r"structurally\s+(?:blocked|impossible|unreachable|dead)|"
    r"give[- ]up|"
    r"partial[- ]only|"
    r"chain\s+(?:blocked|halted|terminated|dead)|"
    # Hedged admissions seen on 96cd1092b992 in non-rce_target fields
    # but legal here too: "could not discover", "appears genuinely
    # hard", "best-effort intended path".
    r"could\s+not\s+(?:discover|reproduce|achieve)|"
    r"genuinely\s+hard|"
    r"best[- ]effort|"
    # Job 7f903a8e152b: rce_target = "PARTIAL — libc leak only; ..."
    # The "leak only" phrase is the actual admission; "PARTIAL" as a
    # standalone word at the start is also a clear signal.
    r"does\s+not\s+achieve|"
    r"(?:libc\s+leak|leak)\s+only\b"
    r")\b",
    re.IGNORECASE,
)

# Job 7f903a8e152b's rce_target started with "PARTIAL — ". We treat
# a bare "PARTIAL" only when followed by an em-dash / colon / "only"
# / ellipsis at the very START of rce_target — that disambiguates
# self-classification ("PARTIAL — leak only") from legitimate uses
# like "partial RELRO bypass via GOT overwrite". The narrower lookahead
# avoids false-positives on benign mitigation descriptions.
_RCE_TARGET_PARTIAL_PREFIX = re.compile(
    r"^\s*partial\s*[—–\-:]\s*\w|"     # PARTIAL — / PARTIAL : / PARTIAL - x
    r"^\s*partial\s+(?:only|chain|deliverable|result)\b",
    re.IGNORECASE,
)


def _parse_step_refs(prereq: str) -> set[int]:
    """Extract integer step indices from a prereq string."""
    refs: set[int] = set()
    for m in _STEP_REF_RE.finditer(prereq or ""):
        s = m.group(1) or m.group(2)
        if s:
            try:
                refs.add(int(s))
            except ValueError:
                pass
    return refs


def validate_chain(data: Any) -> list[tuple[str, str]]:
    """Validate a parsed chain dict. Returns [(severity, message), ...].

    Severities: 'critical', 'high', 'med'. Empty result = chain is
    structurally sound (does not imply chain is sufficient; main
    can still ship a self-consistent but doomed chain — that case
    is handled by self-defeat regex elsewhere).
    """
    issues: list[tuple[str, str]] = []

    if not isinstance(data, dict):
        issues.append(("high", "chain.json root is not a JSON object"))
        return issues

    if data.get("schema_version") != SCHEMA_VERSION:
        issues.append((
            "med",
            f"schema_version missing or != {SCHEMA_VERSION} "
            f"(got {data.get('schema_version')!r})",
        ))

    primitives = data.get("primitives")
    if not isinstance(primitives, list) or not primitives:
        issues.append((
            "high",
            "primitives must be a non-empty list — every chain has "
            "at least one enumerated primitive",
        ))
        primitives = []

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        issues.append((
            "high",
            "steps must be a non-empty list — chain has no steps",
        ))
        steps = []

    # --- primitives table integrity ---
    p_by_id: dict[str, dict] = {}
    seen_ids: set[str] = set()
    for i, p in enumerate(primitives):
        if not isinstance(p, dict):
            issues.append(("high", f"primitives[{i}] is not an object"))
            continue
        pid = p.get("id")
        if not pid or not isinstance(pid, str):
            issues.append((
                "high",
                f"primitives[{i}] missing or non-string `id`",
            ))
            continue
        if pid in seen_ids:
            issues.append(("high", f"duplicate primitive id {pid!r}"))
        seen_ids.add(pid)
        p_by_id[pid] = p
        if "verified" not in p:
            issues.append((
                "med",
                f"primitive {pid!r} missing `verified` (true/false) — "
                f"can't tell if main probed it or assumed it",
            ))
        if not (p.get("verify_method") or "").strip():
            issues.append((
                "med",
                f"primitive {pid!r} missing `verify_method` — name "
                f"how empirical confirmation is done",
            ))
        if p.get("verified") is False and not (
            p.get("reason_failed") or ""
        ).strip():
            issues.append((
                "med",
                f"primitive {pid!r} verified=false but no "
                f"`reason_failed` recorded",
            ))

    # --- step DAG + primitive references ---
    seen_n: set[int] = set()
    for i, s in enumerate(steps):
        if not isinstance(s, dict):
            issues.append(("high", f"steps[{i}] is not an object"))
            continue
        n = s.get("n")
        if not isinstance(n, int):
            issues.append((
                "high",
                f"steps[{i}] missing integer `n` (step number)",
            ))
            continue
        if n in seen_n:
            issues.append(("high", f"duplicate step n={n}"))
        # prereq DAG: every referenced step must already appear above
        prereq = s.get("prereq", "")
        if prereq and prereq != "none":
            refs = _parse_step_refs(prereq)
            for r in refs:
                if r >= n:
                    issues.append((
                        "high",
                        f"step {n}: prereq references step {r} "
                        f"which is not earlier (chain DAG broken)",
                    ))
                elif r not in seen_n:
                    issues.append((
                        "high",
                        f"step {n}: prereq references step {r} which "
                        f"is not defined above",
                    ))
        # uses_primitives must reference defined IDs
        ups = s.get("uses_primitives") or []
        if not isinstance(ups, list):
            issues.append((
                "high",
                f"step {n}: uses_primitives must be a list",
            ))
            ups = []
        for pid in ups:
            if pid not in p_by_id:
                issues.append((
                    "high",
                    f"step {n}: uses_primitives ref {pid!r} not "
                    f"defined in primitives table",
                ))
                continue
            # step uses a primitive marked verified=false. Distinguish
            # TESTED-AND-FAILED (ship-block) from UNTESTABLE-LOCALLY (env
            # limit — the remote is the only test → allow as a probe).
            if p_by_id[pid].get("verified") is False:
                _prim = p_by_id[pid]
                _why = (
                    f"{_prim.get('reason_failed') or ''} "
                    f"{_prim.get('verify_method') or ''}"
                )
                if _UNTESTABLE_LOCALLY_RE.search(_why):
                    issues.append((
                        "med",
                        f"step {n} uses primitive {pid!r} with "
                        f"verified=false for an UNTESTABLE-LOCALLY reason "
                        f"(worker env limit — no vsyscall/CET/kernel match; "
                        f"the remote is the only test). Allowing the run as "
                        f"a remote probe rather than ship-blocking.",
                    ))
                else:
                    issues.append((
                        "critical",
                        f"step {n} uses primitive {pid!r} but "
                        f"primitive.verified=false — chain depends on "
                        f"an empirically-blocked primitive; cannot fire "
                        f"as written",
                    ))
        # every step needs an empirical verify
        if not (s.get("verify") or "").strip():
            issues.append((
                "med",
                f"step {n}: missing `verify` field — no way to tell "
                f"if the step's effect actually landed",
            ))
        if not (s.get("action") or "").strip():
            issues.append((
                "high",
                f"step {n}: missing/empty `action` field",
            ))
        seen_n.add(n)

    # --- final RCE target ---
    rce = (data.get("rce_target") or "").strip()
    if not rce:
        issues.append((
            "med",
            "rce_target missing — name the end-of-chain goal "
            "(e.g. '__free_hook = system' or 'vtable hijack → "
            "one_gadget')",
        ))
    elif _RCE_TARGET_NEGATIVE.search(rce):
        issues.append((
            "critical",
            f"rce_target is a self-admission of no working chain: "
            f"{rce[:160]!r} — chain.json itself declares the "
            f"deliverable is partial/leak-only with no RCE; "
            f"sandbox would only confirm what main already concluded. "
            f"Ship blocked.",
        ))
    elif _RCE_TARGET_PARTIAL_PREFIX.match(rce):
        # Bare "PARTIAL ..." prefix — main classifying the chain as
        # incomplete in the field whose purpose is to name the
        # end-of-chain RCE goal. Same ship-block rationale as above
        # but caught separately so the operator sees the distinct
        # pattern (and so we don't grow the main regex with a clause
        # that would false-positive on benign uses of "partial").
        issues.append((
            "critical",
            f"rce_target starts with 'PARTIAL' — chain.json is "
            f"self-classifying as leak-only deliverable: {rce[:160]!r}. "
            f"Sandbox would only confirm what main already concluded. "
            f"Ship blocked.",
        ))

    # --- bulk verified=false check ---
    # When main writes a chain but every primitive is verified=false,
    # the chain is a documentation artifact, not an exploit. Useful
    # for the operator to read, but not worth a sandbox cycle.
    verified_flags = [
        p.get("verified") for p in primitives
        if isinstance(p, dict) and "verified" in p
    ]
    if verified_flags and all(v is False for v in verified_flags):
        issues.append((
            "critical",
            f"all {len(verified_flags)} primitives have verified=false "
            f"— chain.json is itself a self-admission of unsolvability; "
            f"sandbox cannot capture a flag from an entirely "
            f"unverified primitive set. Ship blocked.",
        ))

    return issues


def load_chain(work_dir: Path) -> tuple[dict | None, list[tuple[str, str]]]:
    """Load + validate ./chain.json from a job work dir.

    Returns (parsed_or_None, issues). When the file is absent the
    parsed value is None and a single 'med' advisory is returned —
    chain.json is recommended but not yet mandatory.
    """
    p = work_dir / CHAIN_FILENAME
    if not p.is_file():
        return None, [(
            "med",
            f"./{CHAIN_FILENAME} missing — main did not write a "
            f"structured chain. Without it, prereq/verify gaps are "
            f"not auto-detected (only self-defeat regex + LLM "
            f"prejudge catch them).",
        )]
    try:
        data = json.loads(p.read_text(errors="ignore"))
    except (OSError, json.JSONDecodeError) as e:
        return None, [(
            "high",
            f"./{CHAIN_FILENAME} unreadable / invalid JSON: {e}",
        )]
    return data, validate_chain(data)
