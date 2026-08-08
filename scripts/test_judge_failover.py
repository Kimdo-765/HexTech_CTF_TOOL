#!/usr/bin/env python3
"""Cross-provider judge failover — the destination the AUP ladder never had.

The failure this cures is documented in this repo and is not hypothetical: a
server-side classifier blocks the call over the challenge's own content, and
re-running the same request on the same vendor blocks again. A fresh session
does not cure it. The other vendor's classifier is a different classifier.

So the retry has to be narrow, and the narrowness is the thing worth testing:
only a policy block retries, only once, never resuming across the boundary,
and the job pins to whichever provider answered.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="judge-failover-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
PRESETS = DATA / "model_presets.json"
PRESETS.write_text(json.dumps({"version": 2, "providers": {}}))
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))
os.environ.update(
    DATA_DIR=str(DATA),
    SETTINGS_PATH=str(SETTINGS),
    MODEL_PRESETS_PATH=str(PRESETS),
    JOBS_DIR=str(DATA / "jobs"),
)
for _k in ("AGENT_PROVIDER", "CLAUDE_MODEL", "GROK_MODEL", "GPT_MODEL"):
    os.environ.pop(_k, None)


def _missing(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is None
    except (ImportError, ValueError):
        return True


STUBBED = [n for n in ("claude_agent_sdk",) if _missing(n)]
if _missing("claude_agent_sdk"):
    _sdk = types.ModuleType("claude_agent_sdk")
    for _n in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage",
               "SystemMessage", "TextBlock"):
        setattr(_sdk, _n, type(_n, (), {}))

    async def _query(*a, **k):  # pragma: no cover
        if False:
            yield None

    _sdk.query = _query
    _sdk.create_sdk_mcp_server = lambda *a, **k: None
    _sdk.tool = lambda *a, **k: (lambda fn: fn)
    _sdk.AgentDefinition = type("AgentDefinition", (), {"__init__": lambda s, **k: None})
    _sdk.HookMatcher = type("HookMatcher", (), {"__init__": lambda s, **k: None})
    _sdk.ClaudeSDKClient = type("ClaudeSDKClient", (), {})
    _sdk.UserMessage = type("UserMessage", (), {})
    _sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk

import modules._judge as J  # noqa: E402
import modules.agent_provider as AP  # noqa: E402
from modules import usage_ledger as UL  # noqa: E402

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def make_job(job_id: str, **meta) -> Path:
    d = DATA / "jobs" / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({"id": job_id, **meta}))
    J._forget_sid(job_id)
    return d


# Both providers are "authed" unless a case says otherwise.
_orig_auth = AP.has_provider_auth
AP.has_provider_auth = lambda p=None: True

# Record what each simulated turn was asked to do.
CALLS: list[dict] = []


def scripted(outcomes: dict):
    """Replace `_run_judge_turn` with a per-provider script."""

    async def _fake(user_prompt, *, cwd, resume_sid, model=None, provider_override=None):
        provider = provider_override or "claude"
        CALLS.append({"provider": provider, "resume_sid": resume_sid, "model": model})
        spec = dict(outcomes.get(provider) or {})
        return J.JudgeTurnResult(
            text=spec.get("text", ""),
            session_id=spec.get("sid"),
            provider=provider,
            model=spec.get("model", f"{provider}-model"),
            error_kind=spec.get("error_kind"),
            error_detail=spec.get("error_detail", ""),
            tokens=spec.get("tokens") or {},
        )

    J._run_judge_turn = _fake


_orig_turn = J._run_judge_turn

# ---------------------------------------------------------------------------
# 1. Session ids are provider-scoped. A handle into one vendor's store means
#    nothing to another, and handing it over looks like it should work.
# ---------------------------------------------------------------------------
make_job("sid1", agent_provider="claude")
J._remember_sid("sid1", "claude-session", "claude")
check("recall for the issuing provider", J._recall_sid("sid1", "claude"), "claude-session")
check("recall for a DIFFERENT provider is refused", J._recall_sid("sid1", "gpt"), None)
check("the pinned provider is recorded", J._pinned_provider("sid1"), "claude")

J._remember_sid("sid1", None, "gpt")
check("a provider change drops the stale id", J._recall_sid("sid1", "gpt"), None)
check("...and re-pins the job", J._pinned_provider("sid1"), "gpt")
check("the old provider no longer recalls it", J._recall_sid("sid1", "claude"), None)

# ---------------------------------------------------------------------------
# 2. Only a policy block fails over.
# ---------------------------------------------------------------------------
for kind in ("timeout", "auth", "transport_error", "agent_error", None):
    CALLS.clear()
    jid = f"only-{kind}"
    make_job(jid, agent_provider="claude")
    scripted({"claude": {"error_kind": kind, "text": "" if kind else "{}", "sid": "c1"}})
    out = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="prejudge", resume=False)
    check(f"{kind or 'success'}: exactly one turn, no failover", len(CALLS), 1)
    check(f"{kind or 'success'}: no failover diagnosis", out.failover_diagnosis, None)

# ---------------------------------------------------------------------------
# 3. A policy block retries ONCE on the other provider, with a FRESH session.
# ---------------------------------------------------------------------------
CALLS.clear()
jid = "fo-ok"
make_job(jid, agent_provider="claude")
J._remember_sid(jid, "claude-session", "claude")
scripted({
    "claude": {"error_kind": "policy_refusal", "error_detail": "violates our usage policy"},
    "gpt": {"text": '{"ok": true}', "sid": "g1", "tokens": {"input_tokens": 10}},
})
out = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="prejudge", resume=True)
check("two turns: the block, then the retry", len(CALLS), 2)
check("the first ran on the job's provider", CALLS[0]["provider"], "claude")
check("...resuming its own session", CALLS[0]["resume_sid"], "claude-session")
check("the retry ran on the other provider", CALLS[1]["provider"], "gpt")
check("the retry NEVER resumes across the boundary", CALLS[1]["resume_sid"], None)
check("the retry lets the target pick its own model", CALLS[1]["model"], None)
check("the answer is the retry's", out.text, '{"ok": true}')
check("...with no error", out.error_kind, None)
check("the failover origin is recorded", out.failover_from, "claude")
check("a provider-specific block is diagnosed as such", out.failover_diagnosis, "provider_specific")

# The job is now PINNED: later stages must not go back.
check("the job is pinned to the answering provider", J._pinned_provider(jid), "gpt")
CALLS.clear()
scripted({"gpt": {"text": '{"action": "continue"}', "sid": "g2"}})
J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="supervise", resume=True)
check("the next stage stays on the pinned provider", CALLS[0]["provider"], "gpt")
check("...and resumes the pinned provider's session", CALLS[0]["resume_sid"], "g1")

# ---------------------------------------------------------------------------
# 4. Both providers blocked: the content is the problem, not the vendor.
# ---------------------------------------------------------------------------
CALLS.clear()
jid = "fo-both"
make_job(jid, agent_provider="claude")
scripted({
    "claude": {"error_kind": "policy_refusal", "error_detail": "blocked A"},
    "gpt": {"error_kind": "policy_refusal", "error_detail": "blocked B"},
})
out = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="postjudge", resume=False)
check("both were tried", len(CALLS), 2)
check("the ORIGINAL result is returned", out.provider, "claude")
check("...still a policy_refusal", out.error_kind, "policy_refusal")
check("diagnosed as content, not vendor", out.failover_diagnosis, "content_or_prompt")
# turn 0031 D1: when BOTH blocked we return the original result, so reading
# its `provider` reported a failover to the place it came from. The target
# that was actually tried has to be recorded explicitly.
check("the TARGET that was tried is recorded", out.failover_to, "gpt")
check("the detail names both attempts", "blocked A" in out.error_detail and "blocked B" in out.error_detail, True)
# Pinning records who ANSWERED. When nobody did, there is nothing to pin: the
# next stage re-resolves normally and gets its own failover attempt, because a
# block is per-call and supervise's prompt is not prejudge's.
check("a doubly-blocked job is pinned to nobody", J._pinned_provider(jid), None)
CALLS.clear()
scripted({
    "claude": {"error_kind": "policy_refusal", "error_detail": "blocked A"},
    "gpt": {"text": '{"action": "continue"}', "sid": "g5"},
})
nxt = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="supervise", resume=True)
check("so the next stage still gets its own retry", len(CALLS), 2)
check("...and can succeed where the last one did not", nxt.error_kind, None)
check("...which finally pins the job", J._pinned_provider(jid), "gpt")

# A retry that fails for an unrelated reason proves nothing either way.
CALLS.clear()
jid = "fo-incon"
make_job(jid, agent_provider="claude")
scripted({
    "claude": {"error_kind": "policy_refusal", "error_detail": "blocked"},
    "gpt": {"error_kind": "timeout", "error_detail": "timed out"},
})
out = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="prejudge", resume=False)
check("a retry that timed out is inconclusive", out.failover_diagnosis, "inconclusive")
check("the original block is still what callers see", out.error_kind, "policy_refusal")

# ---------------------------------------------------------------------------
# 5. No target configured: say so instead of pretending it was tried.
# ---------------------------------------------------------------------------
AP.has_provider_auth = lambda p=None: p == "claude"
CALLS.clear()
jid = "fo-noauth"
make_job(jid, agent_provider="claude")
scripted({"claude": {"error_kind": "policy_refusal", "error_detail": "blocked"}})
out = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="prejudge", resume=False)
check("with no authed target, only one turn runs", len(CALLS), 1)
check("the result says why there was no retry", "no failover target" in out.error_detail, True)
check("and it is not diagnosed", out.failover_diagnosis, None)
AP.has_provider_auth = lambda p=None: True

check("claude fails over to gpt", J._failover_target("claude"), "gpt")
check("gpt fails over to claude", J._failover_target("gpt"), "claude")

# turn 0029 D4: the Grok exclusion has to hold on the SOURCE side too.
# Iterating the target set and skipping `current` looks symmetric but is not —
# a Grok job is not IN that set, so nothing was skipped and Grok failed over
# to Claude, leaving the role boundary it is supposed to stay behind.
#
# The assertion this replaces was written as `!= "gpt"` under a label that
# claimed to check for None. It checked something else and would have passed
# on any wrong answer but one.
check("grok never fails over at all (whole-job in v1)", J._failover_target("grok"), None)
check("an unknown provider has no target", J._failover_target("gemini"), None)
check("an empty provider has no target", J._failover_target(""), None)
check("grok is never a TARGET either", "grok" in AP.ROLE_TARGET_PROVIDERS, False)

# ---------------------------------------------------------------------------
# 5b. turn 0044 D4 — the exception boundary belongs at the ATTEMPT.
#     Catching further out meant supervise/postjudge propagated with zero
#     ledger rows, and in a failover an exception from the ALTERNATE was
#     attributed to the primary's provider while the primary's own refusal row
#     was lost with it.
# ---------------------------------------------------------------------------
def raising(outcomes: dict):
    """Provider -> either a spec dict or an exception to raise."""

    async def _fake(user_prompt, *, cwd, resume_sid, model=None, provider_override=None):
        provider = provider_override or "claude"
        CALLS.append({"provider": provider, "resume_sid": resume_sid, "model": model})
        spec = outcomes.get(provider)
        if isinstance(spec, BaseException):
            raise spec
        spec = dict(spec or {})
        return J.JudgeTurnResult(
            text=spec.get("text", ""), session_id=spec.get("sid"),
            provider=provider, model=f"{provider}-model",
            error_kind=spec.get("error_kind"),
            error_detail=spec.get("error_detail", ""),
            tokens={"input_tokens": 5},
        )

    J._run_judge_turn = _fake


# Every stage survives a raising attempt, and bills it.
for stage in ("prejudge", "supervise", "postjudge"):
    CALLS.clear()
    jid = f"raise-{stage}"
    make_job(jid, agent_provider="claude")
    raising({"claude": RuntimeError("wrapper exploded")})
    out = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage=stage, resume=False)
    check(f"{stage}: judge_turn does not propagate", isinstance(out, J.JudgeTurnResult), True)
    check(f"{stage}: the failure is classified", out.error_kind, "transport_error")
    check(f"{stage}: the provider is the one that was TRIED", out.provider, "claude")
    rows = UL.read_usage(jid)
    check(f"{stage}: the dead attempt is billed", len(rows), 1)
    check(f"{stage}: under its own stage", rows[0].get("stage") if rows else None, stage)

# A raising ALTERNATE must not take the primary's row with it, and must not be
# attributed to the primary's provider.
CALLS.clear()
jid = "raise-alt"
make_job(jid, agent_provider="claude")
raising({
    "claude": {"error_kind": "policy_refusal", "error_detail": "blocked"},
    "gpt": RuntimeError("alternate exploded"),
})
out = J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="prejudge", resume=False)
arows = UL.read_usage(jid)
check("both attempts are billed even when the alternate raised", len(arows), 2)
check("...the primary's refusal row survives",
      [r.get("provider") for r in arows], ["claude", "gpt"])
check("...the primary keeps its own kind",
      arows[0].get("error_kind") if arows else None, "policy_refusal")
check("...and the exception is attributed to the ALTERNATE",
      arows[1].get("error_kind") if len(arows) > 1 else None, "transport_error")
check("the caller still sees the original refusal", out.error_kind, "policy_refusal")
check("...diagnosed as inconclusive, not provider-specific",
      out.failover_diagnosis, "inconclusive")

# ---------------------------------------------------------------------------
# 6. BOTH turns are billed. Hiding the refused one makes a failover look free.
# ---------------------------------------------------------------------------
CALLS.clear()
jid = "fo-ledger"
make_job(jid, agent_provider="claude")
scripted({
    "claude": {"error_kind": "policy_refusal", "error_detail": "blocked",
               "tokens": {"input_tokens": 500}},
    "gpt": {"text": "{}", "sid": "g9", "tokens": {"input_tokens": 700}},
})
J.judge_turn("p", cwd=DATA / "jobs" / jid, job_id=jid, stage="prejudge", resume=False)
rows = UL.read_usage(jid)
check("both turns are in the ledger", len(rows), 2)
# Indexed defensively: a mutation that drops a row should NAME the contract it
# broke, not die with an IndexError and hide which one.
check("the refused turn is recorded too",
      rows[0].get("error_kind") if rows else "NO ROWS", "policy_refusal")
check("...on the provider that refused",
      rows[0].get("provider") if rows else "NO ROWS", "claude")
check("the retry is recorded on the target",
      rows[1].get("provider") if len(rows) > 1 else "MISSING ROW", "gpt")
check("both are the same stage", {r["stage"] for r in rows}, {"prejudge"})
check(
    "the two providers are billed separately",
    sorted(UL.aggregate_usage(jid)["providers"]),
    ["claude", "gpt"],
)

# ---------------------------------------------------------------------------
# 7. turn 0029 D1 — the diagnosis has to OUTLIVE the call that made it.
#    In memory it dies with the run; it is only useful if the ledger and the
#    caller's verdict carry it.
# ---------------------------------------------------------------------------
CALLS.clear()
jid = "fo-serialize"
jd = make_job(jid, agent_provider="claude")
(jd / "exploit.py").write_text("print(1)\n")
scripted({
    "claude": {"error_kind": "policy_refusal", "error_detail": "blocked"},
    "gpt": {"text": '{"ok": true, "severity": "low", "flag_likelihood": 0.9}',
            "sid": "g7"},
})
verdict = J.prejudge_script(jd, "exploit.py", None, lambda *_: None, job_id=jid)
check("the public verdict says a fallback was used", verdict.get("fallback_used"), True)
check("...naming where it came from", verdict.get("failover_from"), "claude")
check("...and where it went", verdict.get("failover_to"), "gpt")
check("...with the diagnosis", verdict.get("failover_diagnosis"), "provider_specific")
check("the verdict itself still works", verdict.get("ok"), True)

lrows = UL.read_usage(jid)
check("both turns on the ledger", len(lrows), 2)
check(
    "the diagnosis is on the ledger row too",
    [r.get("failover_diagnosis") for r in lrows],
    ["provider_specific", "provider_specific"],
)
check(
    "with its origin",
    {r.get("failover_from") for r in lrows},
    {"claude"},
)

# D1 through the PUBLIC path: both providers blocked.
CALLS.clear()
jid = "fo-both-public"
jdb = make_job(jid, agent_provider="claude")
(jdb / "exploit.py").write_text("print(1)\n")
scripted({
    "claude": {"error_kind": "policy_refusal", "error_detail": "blocked A"},
    "gpt": {"error_kind": "policy_refusal", "error_detail": "blocked B"},
})
vb = J.prejudge_script(jdb, "exploit.py", None, lambda *_: None, job_id=jid)
check("both blocked: the verdict still reports the real target",
      vb.get("failover_to"), "gpt")
check("both blocked: and the real origin", vb.get("failover_from"), "claude")
check("both blocked: diagnosed as content", vb.get("failover_diagnosis"), "content_or_prompt")

# A turn with no failover must not grow the keys.
CALLS.clear()
jid = "fo-none"
jd2 = make_job(jid, agent_provider="claude")
(jd2 / "exploit.py").write_text("print(1)\n")
scripted({"claude": {"text": '{"ok": true, "severity": "low"}', "sid": "c9"}})
plain = J.prejudge_script(jd2, "exploit.py", None, lambda *_: None, job_id=jid)
check("no failover -> no fallback_used key", "fallback_used" in plain, False)
check("no failover -> no diagnosis key", "failover_diagnosis" in plain, False)
check(
    "no failover -> the ledger row has no diagnosis either",
    "failover_diagnosis" in (UL.read_usage(jid)[0] if UL.read_usage(jid) else {}),
    False,
)

# ---------------------------------------------------------------------------
# 8. turn 0029 D3 — a routed/failover provider uses ITS OWN judge preset.
#    resolve_judge_model runs before the provider is known, so a routed judge
#    arrives holding a model from the wrong family; coercing that to the
#    target's GLOBAL default silently ignored the target's active preset.
# ---------------------------------------------------------------------------
PRESETS.write_text(json.dumps({
    "version": 2,
    "providers": {
        "gpt": {"active": "p", "presets": {"p": {"judge": "gpt-5.6-terra"}}},
        "claude": {"active": "p", "presets": {"p": {"judge": "claude-opus-4-8"}}},
    },
}))
SETTINGS.write_text(json.dumps({"agent_provider": "claude", "gpt_model": "gpt-global-default"}))
check(
    "a wrong-family request resolves to the TARGET's preset, not its default",
    J._judge_model_for("gpt", "claude-sonnet-4-6"),
    "gpt-5.6-terra",
)
check(
    "no request at all also resolves to the target's preset",
    J._judge_model_for("gpt", None),
    "gpt-5.6-terra",
)
check(
    "a same-family request is honoured as given",
    J._judge_model_for("gpt", "gpt-5.6-luna"),
    "gpt-5.6-luna",
)
check(
    "claude resolves against its own preset",
    J._judge_model_for("claude", None),
    "claude-opus-4-8",
)
PRESETS.write_text(json.dumps({"version": 2, "providers": {}}))
check(
    "with no preset it falls back to the provider default",
    J._judge_model_for("gpt", "claude-sonnet-4-6"),
    "gpt-global-default",
)

J._run_judge_turn = _orig_turn
AP.has_provider_auth = _orig_auth

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
