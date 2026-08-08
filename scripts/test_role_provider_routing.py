#!/usr/bin/env python3
"""Per-role provider routing (`provider_for_role`) — stage 1 of the hybrid work.

The load-bearing property is NEGATIVE: with no override configured anywhere,
every role must resolve exactly as `provider_for_job` did before this existed.
`scripts/test_provider_role_baseline.py` pins that for the resolved MODELS;
this file pins the PROVIDER resolution plus the override paths themselves.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="role-provider-routing-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
PRESETS = DATA / "model_presets.json"
SETTINGS.write_text("{}")
PRESETS.write_text(json.dumps({"version": 2, "providers": {}}))

os.environ["DATA_DIR"] = str(DATA)
os.environ["SETTINGS_PATH"] = str(SETTINGS)
os.environ["MODEL_PRESETS_PATH"] = str(PRESETS)
# SCHEMA env fallbacks would otherwise leak the developer's real shell config
# into the assertions below.
for _k in ("AGENT_PROVIDER", "CLAUDE_MODEL", "GROK_MODEL", "GPT_MODEL"):
    os.environ.pop(_k, None)

from modules.agent_provider import (  # noqa: E402
    ROLE_OVERRIDABLE,
    ROLE_TARGET_PROVIDERS,
    provider_for_job,
    provider_for_role,
    provider_meta_fields,
    role_provider_routes,
)
from modules.model_presets import CONFIGURABLE_ROLES  # noqa: E402

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def set_settings(**kw) -> None:
    SETTINGS.write_text(json.dumps(kw))


def make_job(job_id: str, **meta) -> str:
    d = DATA / "jobs" / job_id
    d.mkdir(exist_ok=True)
    (d / "meta.json").write_text(json.dumps({"id": job_id, **meta}))
    return job_id


# ---------------------------------------------------------------------------
# 1. No override anywhere  ->  identical to provider_for_job, for EVERY role.
#    This is the backward-compatibility guarantee the whole design rests on.
# ---------------------------------------------------------------------------
for provider in ("claude", "grok", "gpt"):
    set_settings(agent_provider=provider)
    job = make_job(f"noroute-{provider}", agent_provider=provider)
    for role in CONFIGURABLE_ROLES:
        check(
            f"no override / {provider} / {role} follows the job provider",
            provider_for_role(job, role),
            provider_for_job(job),
        )

# ...and with no job_id either (pre-create decisions).
set_settings(agent_provider="gpt")
for role in CONFIGURABLE_ROLES:
    check(f"no override / no job_id / {role}", provider_for_role(None, role), "gpt")

# ---------------------------------------------------------------------------
# 2. A live Settings override routes only the roles v1 allows.
# ---------------------------------------------------------------------------
set_settings(
    agent_provider="gpt",
    agent_role_providers={r: "claude" for r in CONFIGURABLE_ROLES},
)
for role in CONFIGURABLE_ROLES:
    want = "claude" if role in ROLE_OVERRIDABLE else "gpt"
    check(f"settings override / {role}", provider_for_role(None, role), want)

check(
    "main is never routable (it would fork the whole run)",
    "main" in ROLE_OVERRIDABLE,
    False,
)
for role in ("recon", "debugger", "triage"):
    check(
        f"{role} is not routable in v1 (no cross-provider child spawn)",
        role in ROLE_OVERRIDABLE,
        False,
    )

# ---------------------------------------------------------------------------
# 3. Routes that must be DROPPED rather than half-applied.
# ---------------------------------------------------------------------------
set_settings(agent_provider="gpt", agent_role_providers={"judge": "grok"})
check(
    "grok is excluded as a role target in v1",
    provider_for_role(None, "judge"),
    "gpt",
)
check("grok route is dropped from routes()", role_provider_routes("gpt"), {})
check("grok not a role target", "grok" in ROLE_TARGET_PROVIDERS, False)

set_settings(agent_provider="gpt", agent_role_providers={"judge": "gpt"})
check(
    "a no-op route (target == job provider) is dropped",
    role_provider_routes("gpt"),
    {},
)

set_settings(agent_provider="gpt", agent_role_providers={"judge": "gemini"})
check("unknown provider is dropped", role_provider_routes("gpt"), {})

set_settings(agent_provider="gpt", agent_role_providers="judge=claude")
check("malformed (non-dict) map degrades to {}", role_provider_routes("gpt"), {})
check(
    "malformed map leaves the role on the job provider",
    provider_for_role(None, "judge"),
    "gpt",
)

# ---------------------------------------------------------------------------
# 4. meta snapshot beats live Settings — a mid-run edit must not leak in.
# ---------------------------------------------------------------------------
snap = make_job(
    "snapshot", agent_provider="gpt", agent_role_providers={"judge": "claude"}
)
set_settings(agent_provider="gpt", agent_role_providers={"judge": "gpt"})
check(
    "stamped route wins over a later Settings edit",
    provider_for_role(snap, "judge"),
    "claude",
)

# A stamped map WITHOUT this role means "this role follows the job provider".
# Falling through to live Settings here would reintroduce the leak.
set_settings(agent_provider="gpt", agent_role_providers={"reviewer": "claude"})
check(
    "stamped map is authoritative even for roles it omits",
    provider_for_role(snap, "reviewer"),
    "gpt",
)

# Legacy meta (no map at all) may still consult live Settings.
legacy = make_job("legacy", agent_provider="gpt")
check(
    "pre-hybrid meta falls through to live Settings routes",
    provider_for_role(legacy, "reviewer"),
    "claude",
)

# ---------------------------------------------------------------------------
# 5. meta stamping: absent when empty (pre-hybrid meta stays byte-identical).
# ---------------------------------------------------------------------------
set_settings(agent_provider="gpt")
check(
    "no routes -> key absent from meta entirely",
    "agent_role_providers" in provider_meta_fields("gpt"),
    False,
)

set_settings(agent_provider="gpt", agent_role_providers={"judge": "claude"})
check(
    "routes -> stamped onto meta",
    provider_meta_fields("gpt").get("agent_role_providers"),
    {"judge": "claude"},
)
check(
    "the scalar agent_provider is preserved, never replaced",
    provider_meta_fields("gpt").get("agent_provider"),
    "gpt",
)

# ---------------------------------------------------------------------------
# 6. An unknown role name is inert (a typo must not route anything).
# ---------------------------------------------------------------------------
set_settings(agent_provider="gpt", agent_role_providers={"judgge": "claude"})
check("typo'd role name is dropped", role_provider_routes("gpt"), {})
check("unknown role resolves to the job provider", provider_for_role(None, "judgge"), "gpt")

print(f"== summary: {PASSED} passed, {FAILED} failed ==")
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
