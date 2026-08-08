#!/usr/bin/env python3
"""The /retry reviewer: routed like a role, billed like one, failed over like one.

The reviewer is one of the two roles v1 routes, and it was wired for none of
it — it read live `active_provider()` instead of the job's snapshot, resolved
its model against a global default instead of the target's preset, wrote no
ledger rows, and had no failover. That last one matters most here: this repo
has had a reviewer refuse nearly every job over its OWN prompt scaffolding,
which is exactly the case a cross-provider retry distinguishes.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="reviewer-routing-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
PRESETS = DATA / "model_presets.json"
SETTINGS.write_text(json.dumps({"agent_provider": "gpt", "gpt_model": "gpt-5.6-sol"}))
PRESETS.write_text(json.dumps({
    "version": 2,
    "providers": {
        "claude": {"active": "p", "presets": {"p": {"reviewer": "claude-opus-4-8"}}},
        "gpt": {"active": "p", "presets": {"p": {"reviewer": "gpt-5.6-terra"}}},
    },
}))
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


STUBBED = [n for n in ("claude_agent_sdk", "fastapi", "redis", "rq") if _missing(n)]
if _missing("claude_agent_sdk"):
    _sdk = types.ModuleType("claude_agent_sdk")
    for _n in ("AssistantMessage", "ClaudeAgentOptions", "ResultMessage", "TextBlock",
               "SystemMessage", "ClaudeSDKClient", "UserMessage"):
        setattr(_sdk, _n, type(_n, (), {}))
    _sdk.HookMatcher = type("HookMatcher", (), {"__init__": lambda s, **k: None})
    _sdk.ClaudeAgentOptions = type(
        "ClaudeAgentOptions", (), {"__init__": lambda s, **k: s.__dict__.update(k)}
    )
    _sdk.AgentDefinition = type("AgentDefinition", (), {"__init__": lambda s, **k: None})
    _sdk.create_sdk_mcp_server = lambda *a, **k: None
    _sdk.tool = lambda *a, **k: (lambda fn: fn)

    async def _query(*a, **k):  # pragma: no cover
        if False:
            yield None

    _sdk.query = _query
    _sdk.project_key_for_directory = lambda *a, **k: ""
    sys.modules["claude_agent_sdk"] = _sdk
if _missing("fastapi"):
    _fa = types.ModuleType("fastapi")

    class _Router:
        def __getattr__(self, _n):
            return lambda *a, **k: (lambda fn: fn)

    _fa.APIRouter = lambda *a, **k: _Router()
    _fa.HTTPException = type(
        "HTTPException", (Exception,),
        {"__init__": lambda self, **k: Exception.__init__(self, k.get("detail", ""))},
    )
    _fa.Request = type("Request", (), {})
    _resp = types.ModuleType("fastapi.responses")
    _resp.StreamingResponse = type("StreamingResponse", (), {})
    _fa.responses = _resp
    sys.modules["fastapi"] = _fa
    sys.modules["fastapi.responses"] = _resp
if _missing("redis"):
    _r = types.ModuleType("redis")
    _r.Redis = type("Redis", (), {"from_url": staticmethod(lambda *a, **k: object())})
    sys.modules["redis"] = _r
if _missing("rq"):
    _rq = types.ModuleType("rq")
    _rq.Queue = type("Queue", (), {"__init__": lambda self, *a, **k: None})
    sys.modules["rq"] = _rq

from api.routes import retry as R  # noqa: E402
import modules.agent_provider as AP  # noqa: E402
import modules.gpt_agent as GA  # noqa: E402
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


def make_job(job_id: str, **meta) -> str:
    d = DATA / "jobs" / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps({"id": job_id, **meta}))
    return job_id


# ---------------------------------------------------------------------------
# 1. D3 — the reviewer follows the job's SNAPSHOT, and the TARGET's preset.
# ---------------------------------------------------------------------------
routed = make_job("rv-routed", agent_provider="gpt",
                  agent_role_providers={"reviewer": "claude"})
check(
    "a routed reviewer runs on the routed provider, not live Settings",
    R._reviewer_provider_and_model(None, routed)[0],
    "claude",
)
check(
    "...with the TARGET provider's own preset model",
    R._reviewer_provider_and_model(None, routed)[1],
    "claude-opus-4-8",
)
check(
    "an explicit model is still honoured",
    R._reviewer_provider_and_model("claude-opus-4-6", routed),
    ("claude", "claude-opus-4-6"),
)
plain = make_job("rv-plain", agent_provider="gpt")
check(
    "an unrouted reviewer follows the job provider",
    R._reviewer_provider_and_model(None, plain),
    ("gpt", "gpt-5.6-terra"),
)
check(
    "with no job in hand, live Settings is all there is",
    R._reviewer_provider_and_model(None)[0],
    "gpt",
)

# ---------------------------------------------------------------------------
# 2. D4 — a reviewer turn is billed. It was the last role spending real money
#    with nothing recording it.
# ---------------------------------------------------------------------------
_orig_once = GA.query_gpt_once


def gpt_returns(text="reviewer hint", error=None, usage=None, model_usage=None, cost=None):
    async def _fake(**kw):
        return {
            "text": text, "error": error,
            "usage": usage or {"input_tokens": 50},
            "model_usage": model_usage or {"gpt-5.6-terra": {"input_tokens": 50,
                                                             "output_tokens": 5}},
            "total_cost_usd": cost,
        }

    GA.query_gpt_once = _fake


billed = make_job("rv-billed", agent_provider="gpt")
gpt_returns()
hint = asyncio.run(R._ask_reviewer("ctx", job_id=billed))
check("the reviewer returns its hint", hint, "reviewer hint")
rows = UL.read_usage(billed)
check("one ledger row for the turn", len(rows), 1)
check("role is reviewer", rows[0].get("role") if rows else None, "reviewer")
check("stage is reviewer", rows[0].get("stage") if rows else None, "reviewer")
check("the model is the resolved one", rows[0].get("model") if rows else None,
      "gpt-5.6-terra")
# The per-model map wins over the streamed `usage` even for one model — the
# ledger and agent_heartbeat now agree on which number is authoritative.
check("tokens come from the authoritative per-model map",
      rows[0].get("tokens") if rows else None,
      {"input_tokens": 50, "output_tokens": 5})

# A FAILED turn is billed too — it spent tokens either way.
failed = make_job("rv-failed", agent_provider="gpt")
gpt_returns(error="violates our usage policy")
try:
    asyncio.run(R._ask_reviewer("ctx", job_id=failed))
    check("a refused reviewer raises", False, True)
except R.ReviewerError as e:
    check("a refused reviewer raises", True, True)
    check("...classified as a policy refusal", e.kind, "policy_refusal")
check("the failed turn is billed too", len(UL.read_usage(failed)), 1)

# No job id -> nothing to bill against, and no crash.
gpt_returns()
check("no job id: still returns a hint", asyncio.run(R._ask_reviewer("ctx")), "reviewer hint")

# ---------------------------------------------------------------------------
# 3. D2 — a policy block retries ONCE on the other provider.
# ---------------------------------------------------------------------------
CALLS: list[str] = []


def scripted_by_provider(outcomes: dict):
    async def _fake(context, *, model=None, job_id=None, provider_override=None, usage_sink=None):
        provider = provider_override or (
            AP.provider_for_role(job_id, "reviewer") if job_id
            else AP.active_provider()
        )
        CALLS.append(provider)
        if usage_sink is not None:
            usage_sink.append({"provider": provider, "model": f"{provider}-model",
                               "usage_out": {"usage": {"input_tokens": 7}},
                               "error_kind": (outcomes.get(provider) or {}).get("error_kind")})
        spec = outcomes.get(provider) or {}
        if spec.get("error_kind"):
            raise R.ReviewerError(spec.get("detail", "blocked"), spec["error_kind"])
        return spec.get("text", "hint")

    R._ask_reviewer = _fake


_orig_ask = R._ask_reviewer
AP.has_provider_auth = lambda p=None: True

# Only a policy block retries.
for kind in ("timeout", "api_error", "auth"):
    CALLS.clear()
    jid = make_job(f"rv-{kind}", agent_provider="claude")
    scripted_by_provider({"claude": {"error_kind": kind}})
    try:
        asyncio.run(R._ask_reviewer_with_failover("ctx", job_id=jid))
        check(f"{kind}: raises", False, True)
    except R.ReviewerError as e:
        check(f"{kind}: raises with its own kind", e.kind, kind)
    check(f"{kind}: no retry on the other provider", CALLS, ["claude"])

CALLS.clear()
jid = make_job("rv-fo-ok", agent_provider="claude")
scripted_by_provider({
    "claude": {"error_kind": "policy_refusal"},
    "gpt": {"text": "recovered hint"},
})
# The retry has to actually reach the other provider, which it does by the job
# being re-resolved — so route the job's reviewer at gpt for the second call.
# The double now keys on the provider it is TOLD, which is the whole point:
# a retry that re-resolves instead of being told the target never leaves the
# first vendor. The earlier counter-based double hid exactly that.
async def _fake2(context, *, model=None, job_id=None, provider_override=None, usage_sink=None):
    provider = provider_override or (
        AP.provider_for_role(job_id, "reviewer") if job_id else AP.active_provider()
    )
    CALLS.append(provider)
    if usage_sink is not None:
        usage_sink.append({"provider": provider, "model": f"{provider}-model",
                           "usage_out": {"usage": {"input_tokens": 7}},
                           "error_kind": "policy_refusal" if provider == "claude" else None})
    if provider == "claude":
        raise R.ReviewerError("blocked", "policy_refusal")
    return "recovered hint"


R._ask_reviewer = _fake2
got = asyncio.run(R._ask_reviewer_with_failover("ctx", job_id=jid))
check("a policy block is retried on the other provider", CALLS, ["claude", "gpt"])
check("and the retry's hint is returned", got, "recovered hint")
frows = UL.read_usage(jid)
check("exactly TWO rows — one per real attempt, no synthetic third", len(frows), 2)
check("attempts are 1 and 2, not inflated", sorted(r["attempt"] for r in frows), [1, 2])
check("the refusal row keeps its error_kind",
      [r.get("error_kind") for r in frows], ["policy_refusal", None])
check("each row names its own provider",
      [r.get("provider") for r in frows], ["claude", "gpt"])
check(
    "...with the diagnosis",
    {r.get("failover_diagnosis") for r in frows},
    {"provider_specific"},
)
check("...naming both ends",
      {(r.get("failover_from"), r.get("failover_to")) for r in frows},
      {("claude", "gpt")})

# No authed target -> no retry, original error preserved.
CALLS.clear()
AP.has_provider_auth = lambda p=None: p == "claude"
jid = make_job("rv-fo-noauth", agent_provider="claude")
scripted_by_provider({"claude": {"error_kind": "policy_refusal"}})
try:
    asyncio.run(R._ask_reviewer_with_failover("ctx", job_id=jid))
    check("no target: raises", False, True)
except R.ReviewerError as e:
    check("no target: the original refusal is preserved", e.kind, "policy_refusal")
check("no target: exactly one attempt", CALLS, ["claude"])
# Restore: leaving the auth double narrowed silently disabled every failover
# in the sections below, which is how eight streaming assertions "failed".
AP.has_provider_auth = lambda p=None: True

# ---------------------------------------------------------------------------
# 4. turn 0033 D1 — the STREAMING path gets the same three things.
#    It had none of them: no job id reached it, so it resolved against live
#    Settings, wrote no rows, and ended a policy block as a terminal error —
#    the one failure a second vendor can actually cure.
# ---------------------------------------------------------------------------
R._ask_reviewer = _orig_ask
SCALLS: list[str] = []


def scripted_stream(outcomes: dict):
    async def _fake(context, *, model=None, job_id=None, provider_override=None,
                    usage_sink=None):
        provider = provider_override or AP.provider_for_role(job_id, "reviewer")
        SCALLS.append(provider)
        if usage_sink is not None:
            usage_sink.append({"provider": provider, "model": f"{provider}-m",
                               "usage_out": {"usage": {"input_tokens": 11}},
                               "error_kind": (outcomes.get(provider) or {}).get("kind")})
        spec = outcomes.get(provider) or {}
        if spec.get("kind"):
            # The real adapters put the block's own text through the SAME
            # `token` events as a hint — that is exactly why streaming the
            # first attempt live let a refusal reach the UI.
            yield "token", {"delta": spec.get("text", "BLOCKED: policy text")}
            yield "error", {"message": "blocked", "kind": spec["kind"]}
            return
        yield "token", {"delta": spec.get("text", "hint")}
        yield "done", {"hint": spec.get("text", "hint")}

    R._stream_reviewer_once = _fake


async def _drain(job_id):
    out = []
    async for k, p_ in R._ask_reviewer_streaming("ctx", job_id=job_id):
        out.append((k, p_))
    return out


_orig_stream = R._stream_reviewer_once

# A clean stream: routed provider, one billed row, no note.
sj = make_job("sv-ok", agent_provider="gpt",
              agent_role_providers={"reviewer": "claude"})
SCALLS.clear()
scripted_stream({"claude": {"text": "streamed hint"}})
ev = asyncio.run(_drain(sj))
check("streaming follows the job snapshot", SCALLS, ["claude"])
check("streaming yields its hint", [k for k, _ in ev], ["token", "done"])
check("streaming bills the turn", len(UL.read_usage(sj)), 1)
check("...on the routed provider",
      UL.read_usage(sj)[0].get("provider") if UL.read_usage(sj) else None, "claude")

# A policy block fails over, and the client is NOT shown a failure that is
# about to be retried.
sj2 = make_job("sv-fo", agent_provider="claude")
SCALLS.clear()
scripted_stream({"claude": {"kind": "policy_refusal"}, "gpt": {"text": "recovered"}})
ev = asyncio.run(_drain(sj2))
check("streaming retries on the other provider", SCALLS, ["claude", "gpt"])
check("no error is streamed before the retry",
      [k for k, _ in ev], ["note", "token", "done"])
srows = UL.read_usage(sj2)
check("both streamed attempts are billed", len(srows), 2)
check("attempts are 1 and 2", sorted(r["attempt"] for r in srows), [1, 2])
check("the refusal row keeps its kind",
      [r.get("error_kind") for r in srows], ["policy_refusal", None])
check("the diagnosis is on both rows",
      {r.get("failover_diagnosis") for r in srows}, {"provider_specific"})

# Both blocked: the ORIGINAL refusal surfaces, so the caller still refuses to
# enqueue.
sj3 = make_job("sv-both", agent_provider="claude")
SCALLS.clear()
scripted_stream({"claude": {"kind": "policy_refusal"}, "gpt": {"kind": "policy_refusal"}})
ev = asyncio.run(_drain(sj3))
check("both blocked: an error is streamed", [k for k, _ in ev][-1], "error")
check("both blocked: it is the ORIGINAL refusal",
      ev[-1][1].get("kind"), "policy_refusal")
check("both blocked: still two billed rows", len(UL.read_usage(sj3)), 2)
check("both blocked: diagnosed as content",
      {r.get("failover_diagnosis") for r in UL.read_usage(sj3)}, {"content_or_prompt"})

# A non-policy error never retries.
sj4 = make_job("sv-timeout", agent_provider="claude")
SCALLS.clear()
scripted_stream({"claude": {"kind": "timeout"}})
ev = asyncio.run(_drain(sj4))
check("a timeout is not retried", SCALLS, ["claude"])
check("...and surfaces immediately", ev[-1][0], "error")

R._stream_reviewer_once = _orig_stream

# ---------------------------------------------------------------------------
# 5. The REAL `_stream_reviewer_once` and the REAL Grok branch.
#    The section above replaces `_stream_reviewer_once` wholesale, so the
#    routing and billing INSIDE it were never executed — two mutations
#    (job_id ignored; grok usage discarded) passed 47/47 underneath. These
#    drive the production functions with only the ADAPTER faked.
# ---------------------------------------------------------------------------
real_sj = make_job("sv-real", agent_provider="gpt",
                   agent_role_providers={"reviewer": "claude"})
_orig_claude_iter = R._iter_reviewer_messages


class _Blk:
    def __init__(self, t):
        self.text = t


class _Asst:
    def __init__(self, t):
        self.content = [_Blk(t)]


class _Res:
    def __init__(self):
        self.is_error = False
        self.model_usage = {"claude-opus-4-8": {"input_tokens": 21, "output_tokens": 3}}
        self.usage = {"input_tokens": 21}
        self.total_cost_usd = 0.11


async def _fake_iter(framed, options, timeout):
    yield _Asst("real hint")
    yield _Res()


# The production function type-checks messages, so bind the doubles to the
# names it actually compares against.
R.AssistantMessage = _Asst
R.TextBlock = _Blk
R.ResultMessage = _Res
R._iter_reviewer_messages = _fake_iter
try:
    ev = asyncio.run(_drain(real_sj))
    rrows = UL.read_usage(real_sj)
    check("the REAL streamer honours the job's route", 
          rrows[0].get("provider") if rrows else None, "claude")
    check("...and its preset model",
          rrows[0].get("model") if rrows else None, "claude-opus-4-8")
    check("the REAL streamer bills exactly one row", len(rrows), 1)
    check("...with the adapter's tokens",
          rrows[0].get("tokens") if rrows else None,
          {"input_tokens": 21, "output_tokens": 3})
    check("...and its reported cost", rrows[0].get("cost_usd") if rrows else None, 0.11)
finally:
    R._iter_reviewer_messages = _orig_claude_iter

# The REAL Grok branch of the synchronous path.
import modules.grok_acp as GK  # noqa: E402

_orig_grok_once = GK.query_grok_once


async def _fake_grok(**kw):
    return {"text": "grok hint", "session_id": "gs", "error": None,
            "usage": {"input_tokens": 13, "output_tokens": 5}}


GK.query_grok_once = _fake_grok
grok_job = make_job("rv-grok", agent_provider="grok")
try:
    hint = asyncio.run(R._ask_reviewer("ctx", job_id=grok_job))
    grows = UL.read_usage(grok_job)
    check("the REAL grok reviewer returns its hint", hint, "grok hint")
    check("...and bills a row", len(grows), 1)
    check("...on the grok provider", grows[0].get("provider") if grows else None, "grok")
    check("...carrying the adapter's usage",
          grows[0].get("tokens") if grows else None,
          {"input_tokens": 13, "output_tokens": 5})
finally:
    GK.query_grok_once = _orig_grok_once

GA.query_gpt_once = _orig_once

# ---------------------------------------------------------------------------
# 6. turn 0035 — auth gate, error kinds, held stream, announced model.
# ---------------------------------------------------------------------------
# D1: the gate must check the provider the REVIEWER will use. Checking the
# whole-job provider rejected jobs whose reviewer was routed to an authed
# backend, and admitted jobs whose routed reviewer had no auth at all — where
# the failure then surfaces as an auth error, which the policy-refusal
# failover is deliberately not allowed to retry.
gate_ok = make_job("gate-ok", module="pwn", status="no_flag",
                   agent_provider="claude",
                   agent_role_providers={"reviewer": "gpt"})
gate_bad = make_job("gate-bad", module="pwn", status="no_flag",
                    agent_provider="gpt",
                    agent_role_providers={"reviewer": "claude"})
AP.has_provider_auth = lambda p=None: p == "gpt"   # only GPT is configured
try:
    R._validate_retry(gate_ok)
    check("a reviewer routed to the AUTHED backend is admitted", True, True)
except Exception as e:
    check(f"a reviewer routed to the AUTHED backend is admitted ({e})", False, True)
try:
    R._validate_retry(gate_bad)
    check("a reviewer routed to an UNAUTHED backend is refused", False, True)
except Exception:
    check("a reviewer routed to an UNAUTHED backend is refused", True, True)
AP.has_provider_auth = lambda p=None: True

# D2: every failure path records its classified kind.
_orig_iter2 = R._iter_reviewer_messages


def _iter_raising(exc):
    async def _f(framed, options, timeout):
        raise exc
        yield  # pragma: no cover

    return _f


for exc, want in ((asyncio.TimeoutError(), "timeout"),
                  (RuntimeError("boom"), "api_error")):
    jk = make_job(f"kind-{want}", agent_provider="claude")
    R._iter_reviewer_messages = _iter_raising(exc)
    try:
        asyncio.run(R._ask_reviewer("ctx", job_id=jk))
    except R.ReviewerError:
        pass
    krows = UL.read_usage(jk)
    check(f"a {want} failure is billed", len(krows), 1)
    check(f"...with its kind on the row",
          krows[0].get("error_kind") if krows else None, want)

# A clean Result whose TEXT is a refusal: diagnosed INSIDE the billed block.
async def _iter_text_refusal(framed, options, timeout):
    yield _Asst('{"type":"error","error":{"message":"violates our usage policy"}}')
    yield _Res()


jt = make_job("kind-textrefusal", agent_provider="claude")
R._iter_reviewer_messages = _iter_text_refusal
try:
    asyncio.run(R._ask_reviewer("ctx", job_id=jt))
except R.ReviewerError:
    pass
trows = UL.read_usage(jt)
check("a text-level refusal is billed", len(trows), 1)
check("...and the row carries a kind, not None",
      (trows[0].get("error_kind") is not None) if trows else False, True)
R._iter_reviewer_messages = _orig_iter2

# D3: the first attempt is HELD, so a refusal never reaches the client when a
# retry is about to recover it.
SCALLS.clear()
scripted_stream({"claude": {"kind": "policy_refusal"}, "gpt": {"text": "recovered"}})
hj = make_job("held", agent_provider="claude")
ev = asyncio.run(_drain(hj))
check("no token from the blocked attempt is emitted",
      [p_.get("delta") for k, p_ in ev if k == "token"], ["recovered"])
check("the note precedes the recovered output", [k for k, _ in ev][0], "note")

# ...and a clean stream still emits its tokens.
SCALLS.clear()
scripted_stream({"claude": {"text": "plain hint"}})
cj = make_job("held-clean", agent_provider="claude")
ev = asyncio.run(_drain(cj))
check("a clean stream still yields its token",
      [p_.get("delta") for k, p_ in ev if k == "token"], ["plain hint"])
check("...and no note", [k for k, _ in ev], ["token", "done"])
R._stream_reviewer_once = _orig_stream

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
