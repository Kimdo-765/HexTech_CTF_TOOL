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

check("grok is never a failover target", J._failover_target("claude") != "grok", True)
check("claude fails over to gpt", J._failover_target("claude"), "gpt")
check("gpt fails over to claude", J._failover_target("gpt"), "claude")
check("a provider with no other option gets None", J._failover_target("gpt") != "gpt", True)

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
check("the refused turn is recorded too", rows[0].get("error_kind"), "policy_refusal")
check("...on the provider that refused", rows[0].get("provider"), "claude")
check("the retry is recorded on the target", rows[1].get("provider"), "gpt")
check("both are the same stage", {r["stage"] for r in rows}, {"prejudge"})
check(
    "the two providers are billed separately",
    sorted(UL.aggregate_usage(jid)["providers"]),
    ["claude", "gpt"],
)

J._run_judge_turn = _orig_turn
AP.has_provider_auth = _orig_auth

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
