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
    enrich_job_meta,
    provider_for_job,
    provider_for_role,
    provider_meta_fields,
    role_provider_intent,
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

# Legacy meta (no map at all) must NOT consult live Settings either.
# turn 0004 D1: a job created while the map was empty omits the key (to keep
# meta byte-identical), so "key absent" and "pre-hybrid job" are the same
# observation. If either fell through, adding a route in Settings would
# re-route jobs that are already running.
legacy = make_job("legacy", agent_provider="gpt")
check(
    "pre-hybrid meta stays on the job provider (no live fallthrough)",
    provider_for_role(legacy, "reviewer"),
    "gpt",
)

# D1 regression, end to end: create with an EMPTY map, then add a route.
set_settings(agent_provider="gpt")
empty_meta = {"id": "d1", **provider_meta_fields("gpt", include_routes=True)}
check("D1 empty routes -> key omitted at create", "agent_role_providers" in empty_meta, False)
d1 = make_job("d1", **{k: v for k, v in empty_meta.items() if k != "id"})
set_settings(agent_provider="gpt", agent_role_providers={"judge": "claude"})
check(
    "D1 a Settings edit cannot re-route an existing job",
    provider_for_role(d1, "judge"),
    "gpt",
)

# D2 regression: the mid-run re-stamp must not overwrite the snapshot.
set_settings(agent_provider="gpt", agent_role_providers={"judge": "claude"})
d2_created = provider_meta_fields("gpt", include_routes=True)
check(
    "D2 create-time snapshot",
    d2_created.get("agent_role_providers"),
    {"judge": "claude"},
)
set_settings(agent_provider="gpt", agent_role_providers={"reviewer": "claude"})
restamp = provider_meta_fields("gpt")  # what the orchestrator re-stamps
check(
    "D2 the re-stamp carries no route key at all",
    "agent_role_providers" in restamp,
    False,
)
check(
    "D2 the re-stamp still carries the scalar provider",
    restamp.get("agent_provider"),
    "gpt",
)

# ---------------------------------------------------------------------------
# 5. meta stamping: absent when empty (pre-hybrid meta stays byte-identical).
# ---------------------------------------------------------------------------
set_settings(agent_provider="gpt")
check(
    "no routes -> key absent from meta entirely",
    "agent_role_providers" in provider_meta_fields("gpt", include_routes=True),
    False,
)

set_settings(agent_provider="gpt", agent_role_providers={"judge": "claude"})
check(
    "routes -> stamped onto meta",
    provider_meta_fields("gpt", include_routes=True).get("agent_role_providers"),
    {"judge": "claude"},
)
check(
    "routes are opt-in: the default call omits them",
    "agent_role_providers" in provider_meta_fields("gpt"),
    False,
)
check(
    "enrich_job_meta is the create path and DOES stamp them",
    enrich_job_meta({}, "gpt").get("agent_role_providers"),
    {"judge": "claude"},
)
check(
    "the scalar agent_provider is preserved, never replaced",
    provider_meta_fields("gpt").get("agent_provider"),
    "gpt",
)

# ---------------------------------------------------------------------------
# 5b. turn 0029 D2: meta stores INTENT, not the base-pruned view.
#     `role_provider_routes` drops routes whose target equals the current base
#     because they change nothing right now — correct for resolving, wrong for
#     storing. The base moves under a job when the AUP ladder switches the
#     whole-job provider, and the pruned entries are exactly the ones that
#     become meaningful after the switch.
# ---------------------------------------------------------------------------
set_settings(agent_provider="gpt", agent_role_providers={"judge": "gpt"})
check(
    "the pruned VIEW still drops a no-op route",
    role_provider_routes("gpt"),
    {},
)
check(
    "but the stored INTENT keeps it",
    role_provider_intent(),
    {"judge": "gpt"},
)
check(
    "so meta carries it even though it changes nothing yet",
    provider_meta_fields("gpt", include_routes=True).get("agent_role_providers"),
    {"judge": "gpt"},
)

# The scenario that made this matter: created under `claude` with a
# judge->claude route (a no-op then), the job is switched to grok by the AUP
# ladder. The route must now take effect — under the old pruned storage it had
# been dropped at create and was unrecoverable.
set_settings(agent_provider="claude", agent_role_providers={"judge": "claude"})
aup = make_job(
    "aup-switch",
    agent_provider="claude",
    **{k: v for k, v in provider_meta_fields("claude", include_routes=True).items()
       if k != "agent_provider"},
)
check(
    "created under claude: judge follows the base",
    provider_for_role(aup, "judge"),
    "claude",
)
# The ladder rewrites only the scalar (modules/_common.py, other_provider rung).
_d = DATA / "jobs" / aup
_m = json.loads((_d / "meta.json").read_text())
_m["agent_provider"] = "grok"
(_d / "meta.json").write_text(json.dumps(_m))
check(
    "after the switch the base is grok",
    provider_for_job(aup),
    "grok",
)
check(
    "and the stored route now MEANS something: judge stays on claude",
    provider_for_role(aup, "judge"),
    "claude",
)
check(
    "an unrouted role follows the new base",
    provider_for_role(aup, "reviewer"),
    "grok",
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
