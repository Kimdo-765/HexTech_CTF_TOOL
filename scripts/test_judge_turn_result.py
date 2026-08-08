#!/usr/bin/env python3
"""`JudgeTurnResult` — a failed judge turn must say WHY it failed.

Every failure path used to collapse to `("", sid)`. That is enough for the
permissive fallback the judge always takes, but stage 4 fails over to the
other provider ONLY on `policy_refusal`: a transport blip mislabelled as a
refusal sends a healthy job to the second provider, and a refusal mislabelled
as transport leaves the AUP class stuck exactly where it is today.

The other half is usage. Judge spend was invisible — `meta.cost_usd` is main's
session and `summary["cost_usd"]` is subagents — so a cross-provider judge
burned a second vendor's meter with nothing recording it.
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

_TMP = tempfile.TemporaryDirectory(prefix="judge-turn-result-")
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
    # _judge imports the SDK at module scope for the Claude branch. The
    # branches under test here are provider-agnostic or GPT; stub only the
    # names it binds, and only when the real package is absent (see
    # test_retry_provider_snapshot.py for why the guard is find_spec).
    _sdk = types.ModuleType("claude_agent_sdk")
    for _n in (
        "AssistantMessage",
        "ClaudeAgentOptions",
        "ResultMessage",
        "SystemMessage",
        "TextBlock",
    ):
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
    return d


# ---------------------------------------------------------------------------
# 1. "ran and said nothing" is a DIFFERENT fact from "never ran".
# ---------------------------------------------------------------------------
check("empty text with no error is not ok", J.JudgeTurnResult().ok, False)
check("text with no error is ok", J.JudgeTurnResult(text="x").ok, True)
check("text WITH an error is not ok", J.JudgeTurnResult(text="x", error_kind="e").ok, False)
check(
    "a silent success carries no error_kind",
    J.JudgeTurnResult(text="", session_id="s").error_kind,
    None,
)

# ---------------------------------------------------------------------------
# 2. Error classification — only policy_refusal may trigger a failover.
# ---------------------------------------------------------------------------
# The wording here is the SERVER's, matched by _common.REFUSAL_HINTS — not a
# phrase a model would choose. A model politely declining is not the same
# event as the API-side classifier blocking the call, and only the second one
# is what a provider failover can cure.
check(
    "a server-side AUP block is classified as policy_refusal",
    J._classify("Output blocked by content filtering policy: violates our usage policy",
                "transport_error"),
    "policy_refusal",
)
check(
    "a model's own polite decline is NOT a policy_refusal",
    J._classify("I'm not able to help with that", "transport_error"),
    "transport_error",
)
check(
    "a timeout is NOT a refusal",
    J._classify("operation timed out after 600s", "transport_error"),
    "timeout",
)
check(
    "an auth failure is NOT a refusal",
    J._classify("401 invalid credential", "transport_error"),
    "auth",
)
check(
    "an unrecognised error keeps the caller's fallback tag",
    J._classify("kaboom", "transport_error"),
    "transport_error",
)
check("an empty detail keeps the fallback too", J._classify("", "agent_error"), "agent_error")

# ---------------------------------------------------------------------------
# 3. Usage extraction — model_usage preferred, usage as fallback.
# ---------------------------------------------------------------------------
class _R:
    def __init__(self, **kw):
        self.__dict__.update(kw)


tok, cost = J._usage_from_result(
    _R(model_usage={"m": {"input_tokens": 10, "output_tokens": 2}}, total_cost_usd=0.5)
)
check("model_usage is folded into the token schema", tok, {"input_tokens": 10, "output_tokens": 2})
check("a reported cost is carried", cost, 0.5)

tok2, cost2 = J._usage_from_result(
    _R(usage={"input_tokens": 7, "output_tokens": 1}, total_cost_usd=None)
)
check("usage is the fallback when model_usage is absent", tok2, {"input_tokens": 7, "output_tokens": 1})
check("a missing cost stays None, not 0.0", cost2, None)

tok3, cost3 = J._usage_from_result(_R())
check("neither present -> empty, not a crash", (tok3, cost3), ({}, None))

# ---------------------------------------------------------------------------
# 4. The ledger row: role=judge, keyed by STAGE, with the error kind on it.
# ---------------------------------------------------------------------------
jid = "jt1"
make_job(jid, agent_provider="claude")
J._record_judge_usage(
    jid,
    "prejudge",
    J.JudgeTurnResult(
        text="{}", provider="claude", model="claude-opus-4-8",
        tokens={"input_tokens": 1000, "output_tokens": 100},
    ),
)
rows = UL.read_usage(jid)
check("a judge turn writes one row", len(rows), 1)
check("role is judge", rows[0]["role"], "judge")
check("stage is the judge stage, not 'judge' again", rows[0]["stage"], "prejudge")
check("a priced claude judge gets an estimate", rows[0]["cost_basis"], "estimated")
check("...and it is above zero", (rows[0]["cost_usd"] or 0) > 0, True)

# supervise fires repeatedly: the attempt counter must separate the calls.
for expected in (1, 2, 3):
    J._record_judge_usage(jid, "supervise", J.JudgeTurnResult(provider="claude"))
check(
    "supervise attempts are numbered",
    [r["attempt"] for r in UL.read_usage(jid) if r["stage"] == "supervise"],
    [1, 2, 3],
)
check(
    "prejudge keeps its own counter",
    [r["attempt"] for r in UL.read_usage(jid) if r["stage"] == "prejudge"],
    [1],
)

# A failed turn is still recorded — with the reason.
J._record_judge_usage(
    jid, "postjudge",
    J.JudgeTurnResult(provider="claude", error_kind="policy_refusal",
                      error_detail="refused"),
)
last = UL.read_usage(jid)[-1]
check("a failed turn is recorded, not dropped", last["stage"], "postjudge")
check("with its error kind", last.get("error_kind"), "policy_refusal")
check("and no invented dollars", last["cost_usd"], None)

# ---------------------------------------------------------------------------
# 5. Codex judge — the cost contract applies here exactly as it does to main.
# ---------------------------------------------------------------------------
jid2 = "jt2"
make_job(jid2, agent_provider="gpt")
J._record_judge_usage(
    jid2, "prejudge",
    J.JudgeTurnResult(provider="gpt", model="gpt-5.6", runtime="codex",
                      tokens={"input_tokens": 5000, "output_tokens": 800}),
)
r2 = UL.read_usage(jid2)[-1]
check("a codex judge books no dollars", r2["cost_usd"], None)
check("basis none", r2["cost_basis"], "none")
check("runtime recorded", r2.get("runtime"), "codex")
check(
    "the gpt bucket is flagged incomplete",
    UL.aggregate_usage(jid2)["providers"]["gpt"]["usd_complete"],
    False,
)

# ---------------------------------------------------------------------------
# 6. The REAL `_run_judge_turn` GPT and Grok branches, driven with the REAL
#    adapter message classes.
#
#    turn 0017: the first version of this section defined its own Result class
#    with a `.result` attribute. Production has no such field — gpt_responses
#    and grok_acp both carry `stop_reason` — so the test drove the production
#    control flow through a message shape that does not exist, and every
#    failure classified as the generic `agent_error` underneath it. Importing
#    the adapters' own classes is what makes the isinstance checks and the
#    attribute contract both real.
# ---------------------------------------------------------------------------
from modules.gpt_responses import (  # noqa: E402
    AssistantMessage as RealGptAssistant,
    ResultMessage as RealGptResult,
    TextBlock as RealGptText,
)
import modules.gpt_agent as GA  # noqa: E402
import modules.grok_acp as GK  # noqa: E402

check("the real GPT Result has no .result field", hasattr(RealGptResult(), "result"), False)
check("it carries stop_reason instead", hasattr(RealGptResult(), "stop_reason"), True)
check("the real Grok Result has no .result field", hasattr(GK.ResultMessage(), "result"), False)


def _fake_client(messages=None, raise_exc=None):
    class _Client:
        session_id = "gs1"

        def __init__(self, opts):
            self.opts = opts

        async def __aenter__(self):
            if raise_exc:
                raise raise_exc
            return self

        async def __aexit__(self, *a):
            return None

        async def query(self, prompt):
            return None

        async def receive_response(self, **kw):
            for m in (messages or []):
                yield m

    return _Client


AUP = "request violates our usage policy"

jid3 = "jt3"
jd3 = make_job(jid3, agent_provider="gpt")
SETTINGS.write_text(json.dumps({"agent_provider": "gpt", "gpt_model": "gpt-5.6"}))

_orig_gpt_client = GA.GptAgentClient
try:
    GA.GptAgentClient = _fake_client([
        RealGptAssistant(content=[RealGptText('{"ok": true}')]),
        RealGptResult(session_id="gs1", model_usage={"m": {"input_tokens": 9}}),
    ])
    ok_turn = J._run_async(J._run_judge_turn("p", cwd=jd3, resume_sid=None))
    check("a good gpt turn returns its text", ok_turn.text, '{"ok": true}')
    check("with no error kind", ok_turn.error_kind, None)
    check("the provider is recorded", ok_turn.provider, "gpt")
    check("usage survives", ok_turn.tokens, {"input_tokens": 9})
    check("the session id survives", ok_turn.session_id, "gs1")

    # The adapters emit failure detail as ASSISTANT text before the error
    # Result — so that text is a first-class classification source.
    GA.GptAgentClient = _fake_client([
        RealGptAssistant(content=[RealGptText(AUP)]),
        RealGptResult(is_error=True, stop_reason="refusal", session_id="gs1"),
    ])
    ref = J._run_async(J._run_judge_turn("p", cwd=jd3, resume_sid=None))
    check("a real GPT refusal is classified", ref.error_kind, "policy_refusal")
    check("the detail is not empty", bool(ref.error_detail.strip()), True)
    check("and names the cause", "usage policy" in ref.error_detail, True)

    GA.GptAgentClient = _fake_client([
        RealGptAssistant(content=[RealGptText("stream timed out after 600s")]),
        RealGptResult(is_error=True, stop_reason="timeout", session_id="gs1"),
    ])
    to = J._run_async(J._run_judge_turn("p", cwd=jd3, resume_sid=None))
    check("a real GPT timeout is NOT a refusal", to.error_kind, "timeout")

    # stop_reason alone must be enough when the adapter emitted no text.
    GA.GptAgentClient = _fake_client([
        RealGptResult(is_error=True, stop_reason="request timed out", session_id="gs1"),
    ])
    sr = J._run_async(J._run_judge_turn("p", cwd=jd3, resume_sid=None))
    check("stop_reason alone still classifies", sr.error_kind, "timeout")

    GA.GptAgentClient = _fake_client(raise_exc=RuntimeError("connection reset"))
    exc_turn = J._run_async(J._run_judge_turn("p", cwd=jd3, resume_sid=None))
    check("a transport exception is NOT called a refusal", exc_turn.error_kind, "transport_error")
    check("its detail names the exception", "connection reset" in exc_turn.error_detail, True)
finally:
    GA.GptAgentClient = _orig_gpt_client

# ---- the Grok branch, same contract -----------------------------------------
jid3g = "jt3g"
jd3g = make_job(jid3g, agent_provider="grok")
SETTINGS.write_text(json.dumps({"agent_provider": "grok", "grok_model": "grok-build"}))

_orig_grok_client = GK.GrokACPClient
try:
    GK.GrokACPClient = _fake_client([
        GK.AssistantMessage(content=[GK.TextBlock(AUP)]),
        GK.ResultMessage(is_error=True, stop_reason="refusal", session_id="ks1"),
    ])
    gref = J._run_async(J._run_judge_turn("p", cwd=jd3g, resume_sid=None))
    check("a real Grok refusal is classified", gref.error_kind, "policy_refusal")
    check("the Grok detail is not empty", bool(gref.error_detail.strip()), True)

    GK.GrokACPClient = _fake_client([
        GK.AssistantMessage(content=[GK.TextBlock('{"ok": true}')]),
        GK.ResultMessage(
            session_id="ks1",
            model_usage={"grok-build": {"input_tokens": 17, "output_tokens": 3}},
            total_cost_usd=0.2,
        ),
    ])
    gok = J._run_async(J._run_judge_turn("p", cwd=jd3g, resume_sid=None))
    check("a good Grok turn returns its text", gok.text, '{"ok": true}')
    check("its reported cost survives", gok.reported_cost, 0.2)
    check("its usage survives", gok.tokens, {"input_tokens": 17, "output_tokens": 3})
finally:
    GK.GrokACPClient = _orig_grok_client

# ---- turn 0019: structured signal FIRST, and never classify a truncated blob
# Joining every source into one blob and classifying that was wrong in BOTH
# directions at once, from the same cause — prose and structured fields were
# treated as interchangeable.
AUP = "request violates our usage policy"

# D1: the Claude SDK puts the wire's error payload in `errors`, a LIST.
# Reading only scalar attributes dropped it, so a Claude refusal — the exact
# thing stage 4 exists to fail over on — came back as a generic agent_error.
# The attribute behaviour is checked with a duck-typed object so it runs
# everywhere; the real SDK's CONTRACT is asserted separately, and only where
# the real package is installed — a stub cannot testify about a real field.
if not STUBBED:
    import inspect as _inspect

    from claude_agent_sdk import ResultMessage as SdkResult  # noqa: E402

    _params = _inspect.signature(SdkResult).parameters
    check("the real SDK ResultMessage HAS an `errors` field", "errors" in _params, True)
    check("...and a `result` field (unlike GPT/Grok)", "result" in _params, True)

_k, _d = J.classify_failure(_R(errors=[AUP]), [], "agent_error")
check("D1 the SDK's `errors` list is classified", _k, "policy_refusal")
check("D1 and lands in the stored detail", "usage policy" in _d, True)

# D2a: a real refusal must not be TRUNCATED AWAY. The adapter emits normal
# output first and the failure detail last, so a long turn pushed the block's
# own words past a fixed cut and it was filed as agent_error.
_long = J.classify_failure(
    RealGptResult(is_error=True, stop_reason="turn_failed", session_id="s"),
    ["ordinary judge analysis " * 60, "[Codex CLI turn_failed] " + AUP],
    "agent_error",
)
check("D2a a refusal after 1000+ chars of output is still found", _long[0], "policy_refusal")

# D2b: a generic failure must not be POISONED. `process_error` names its own
# category, so prose that merely discusses policy cannot override it — that
# would be a spurious failover on a broken pipe.
_poison = J.classify_failure(
    RealGptResult(is_error=True, stop_reason="process_error", session_id="s"),
    ["The challenge description discusses a usage policy.",
     "[Codex CLI exited 1] broken pipe"],
    "agent_error",
)
check("D2b a process_error is NOT poisoned into a refusal", _poison[0], "transport_error")

# The cases that already worked must keep working.
check(
    "a short refusal is still classified",
    J.classify_failure(
        RealGptResult(is_error=True, stop_reason="turn_failed", session_id="s"),
        ["[Codex CLI turn_failed] " + AUP], "agent_error")[0],
    "policy_refusal",
)
check(
    "stop_reason=timeout names its own category",
    J.classify_failure(
        RealGptResult(is_error=True, stop_reason="timeout", session_id="s"),
        ["[Codex CLI turn timed out]"], "agent_error")[0],
    "timeout",
)
check(
    "an unrecognised failure keeps the caller's fallback",
    J.classify_failure(
        RealGptResult(is_error=True, stop_reason="turn_failed", session_id="s"),
        ["something odd happened"], "agent_error")[0],
    "agent_error",
)

# turn 0021 D3: the category map is ENUMERATED from all three adapters, not
# grown one value at a time — growing it piecemeal is what left grok's `eof`
# and `max_tokens` out, and both were then poisoned by earlier policy prose.
POLICY_PROSE = "the challenge discusses a usage policy"

for reason, want in (
    ("eof", "transport_error"),            # grok_acp
    ("process_error", "transport_error"),  # codex_cli + grok_acp
    ("unexpected_eof", "transport_error"), # codex_cli
    ("timeout", "timeout"),                # all three
    ("max_tokens", "agent_error"),         # grok_acp — a limit, not a refusal
    ("max_tool_rounds", "agent_error"),    # gpt_responses
    ("cancelled", "killed"),
):
    check(
        f"stop_reason={reason} names its own category",
        J.classify_failure(
            GK.ResultMessage(is_error=True, stop_reason=reason, session_id="s"),
            [], "agent_error")[0],
        want,
    )
    check(
        f"...and earlier policy prose cannot override it ({reason})",
        J.classify_failure(
            GK.ResultMessage(is_error=True, stop_reason=reason, session_id="s"),
            [POLICY_PROSE], "agent_error")[0],
        want,
    )

# Prose is read from the LAST message only. Every adapter emits its failure
# detail there; anything earlier is the judge's own output. This closes the
# poisoning class even for stop_reason values nobody has mapped yet — which
# matters, because an unmapped value is exactly what the map was missing.
check(
    "an UNMAPPED stop_reason still finds a real refusal in the last message",
    J.classify_failure(
        RealGptResult(is_error=True, stop_reason="brand_new_value", session_id="s"),
        [POLICY_PROSE, AUP], "agent_error")[0],
    "policy_refusal",
)
check(
    "...but earlier policy prose alone cannot make one",
    J.classify_failure(
        RealGptResult(is_error=True, stop_reason="brand_new_value", session_id="s"),
        [POLICY_PROSE, "[Codex CLI exited 1] broken pipe"], "agent_error")[0],
    "agent_error",
)
check(
    "a real refusal survives 300 preceding normal messages",
    J.classify_failure(
        RealGptResult(is_error=True, stop_reason="turn_failed", session_id="s"),
        ["normal " * 300, "[Codex CLI turn_failed] " + AUP], "agent_error")[0],
    "policy_refusal",
)

# A SUCCESSFUL turn is never classified at all, so ordinary judge output that
# discusses policy can never trigger a failover.
_orig_gpt_client2 = GA.GptAgentClient
SETTINGS.write_text(json.dumps({"agent_provider": "gpt", "gpt_model": "gpt-5.6"}))
try:
    GA.GptAgentClient = _fake_client([
        RealGptAssistant(content=[RealGptText(
            "the script would breach the target site usage policy"
        )]),
        RealGptResult(session_id="gs1"),
    ])
    fine = J._run_async(J._run_judge_turn("p", cwd=jd3, resume_sid=None))
    check("a SUCCESSFUL turn is never classified", fine.error_kind, None)
    check("...and its text is returned intact", "usage policy" in fine.text, True)
finally:
    GA.GptAgentClient = _orig_gpt_client2

SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))

# ---------------------------------------------------------------------------
# 7. The call sites are wired: prejudge records under its own stage.
# ---------------------------------------------------------------------------
jid4 = "jt4"
jd4 = make_job(jid4, agent_provider="claude")
(jd4 / "exploit.py").write_text("print(1)\n")
SETTINGS.write_text(json.dumps({"agent_provider": "claude"}))

_orig = J._run_judge_turn


async def _fake_turn(*a, **k):
    return J.JudgeTurnResult(
        text='{"ok": true, "severity": "low", "flag_likelihood": 0.9}',
        session_id="cs1", provider="claude", model="claude-opus-4-8",
        tokens={"input_tokens": 500, "output_tokens": 50},
    )


J._run_judge_turn = _fake_turn
try:
    out = J.prejudge_script(jd4, "exploit.py", None, lambda *_: None, job_id=jid4)
finally:
    J._run_judge_turn = _orig
check("prejudge still returns its verdict dict", out.get("ok"), True)
rows4 = UL.read_usage(jid4)
check("prejudge wrote a ledger row", len(rows4), 1)
check("under the prejudge stage", rows4[0]["stage"], "prejudge")
check("the session id still round-trips to _recall_sid", J._recall_sid(jid4), "cs1")

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    + (f"  [stubbed: {', '.join(STUBBED)}]" if STUBBED else "  [all real deps]")
)
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
