#!/usr/bin/env python3
"""A retry is a job CREATE, and must get the same provider stamp as one.

turn 0006 (Codex review): `_resubmit()` builds its own meta literal instead of
going through the module routes, and that literal carried no `agent_provider`
and no `agent_role_providers` — so the role routing chosen for a retry was
lost the moment the job was made.

The point of this file is that it drives the REAL `_resubmit()`. The earlier
regression built meta with `provider_meta_fields()` directly, which is exactly
why it passed over a defect in the production create path.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.TemporaryDirectory(prefix="retry-provider-snapshot-")
DATA = Path(_TMP.name)
(DATA / "jobs").mkdir()
SETTINGS = DATA / "settings.json"
PRESETS = DATA / "model_presets.json"
PRESETS.write_text(json.dumps({"version": 2, "providers": {}}))
os.environ.update(
    DATA_DIR=str(DATA),
    SETTINGS_PATH=str(SETTINGS),
    MODEL_PRESETS_PATH=str(PRESETS),
    JOBS_DIR=str(DATA / "jobs"),
)
for _k in ("AGENT_PROVIDER", "CLAUDE_MODEL", "GROK_MODEL", "GPT_MODEL"):
    os.environ.pop(_k, None)
SETTINGS.write_text(
    json.dumps(
        {"agent_provider": "gpt", "agent_role_providers": {"judge": "claude"}}
    )
)

# `api.routes.retry` imports the Claude SDK at module scope for the reviewer
# turn. That path is not under test here and the SDK is only installed in the
# worker image, so stub exactly the names it binds — running this suite must
# not depend on which container it happens to be started in.
if "claude_agent_sdk" not in sys.modules:
    _sdk = types.ModuleType("claude_agent_sdk")
    for _name in (
        "AssistantMessage",
        "ClaudeAgentOptions",
        "ResultMessage",
        "TextBlock",
    ):
        setattr(_sdk, _name, type(_name, (), {}))
    _sdk.project_key_for_directory = lambda *a, **k: ""

    async def _query(*a, **k):  # pragma: no cover — never called here
        if False:
            yield None

    _sdk.query = _query
    sys.modules["claude_agent_sdk"] = _sdk

# Same reasoning for FastAPI: it lives in the api image, `_resubmit` does not
# touch it, and only the module-level route decorators need it to exist. A
# stub keeps this suite runnable on the host, in the worker and in the api
# container alike — a test that runs in exactly one container is how dev/run
# coverage quietly disappears in this repo.
if "fastapi" not in sys.modules:
    _fa = types.ModuleType("fastapi")

    class _Router:
        def __getattr__(self, _name):
            def _decorate(*a, **k):
                return lambda fn: fn

            return _decorate

    _fa.APIRouter = lambda *a, **k: _Router()
    _fa.HTTPException = type("HTTPException", (Exception,), {})
    _fa.Request = type("Request", (), {})
    _resp = types.ModuleType("fastapi.responses")
    _resp.StreamingResponse = type("StreamingResponse", (), {})
    _fa.responses = _resp
    sys.modules["fastapi"] = _fa
    sys.modules["fastapi.responses"] = _resp

# api.queue opens a Redis handle at import time. `_resubmit`'s queue is
# replaced with a fake below, so nothing here ever talks to a broker.
if "redis" not in sys.modules:
    _redis_mod = types.ModuleType("redis")
    _redis_mod.Redis = type(
        "Redis", (), {"from_url": staticmethod(lambda *a, **k: object())}
    )
    sys.modules["redis"] = _redis_mod
if "rq" not in sys.modules:
    _rq = types.ModuleType("rq")
    _rq.Queue = type("Queue", (), {"__init__": lambda self, *a, **k: None})
    sys.modules["rq"] = _rq

from api.routes import retry as retry_mod  # noqa: E402
from modules.agent_provider import provider_for_role  # noqa: E402

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


class _FakeQueue:
    def __init__(self) -> None:
        self.jobs: list[tuple] = []

    def enqueue(self, *a, **k):
        self.jobs.append((a, k))
        return types.SimpleNamespace(id=k.get("job_id"))


_queue = _FakeQueue()
retry_mod.get_queue = lambda: _queue
retry_mod.hard_timeout_for = lambda v: v or 600
retry_mod.resolve_timeout = lambda *a, **k: 600

# A finished parent job to retry from.
parent_id = "parent00"
parent_dir = DATA / "jobs" / parent_id
(parent_dir / "work").mkdir(parents=True)
prev_meta = {
    "id": parent_id,
    "module": "pwn",
    "status": "no_flag",
    "description": "orig",
    "auto_run": True,
    "agent_provider": "gpt",
    "agent_role_providers": {"judge": "claude"},
}
(parent_dir / "meta.json").write_text(json.dumps(prev_meta))

new_id = retry_mod._resubmit(prev_meta, "retry hint", parent_dir)
new_meta = json.loads((DATA / "jobs" / new_id / "meta.json").read_text())

check("retry meta carries the provider scalar", new_meta.get("agent_provider"), "gpt")
check(
    "retry meta carries the create-time role snapshot",
    new_meta.get("agent_role_providers"),
    {"judge": "claude"},
)
check(
    "the routed role resolves on the NEW job",
    provider_for_role(new_id, "judge"),
    "claude",
)
check(
    "an unrouted role still follows the job provider",
    provider_for_role(new_id, "reviewer"),
    "gpt",
)

# And the snapshot must be pinned on the retry too: a later Settings edit
# cannot re-route a job that already exists.
SETTINGS.write_text(
    json.dumps(
        {"agent_provider": "gpt", "agent_role_providers": {"reviewer": "claude"}}
    )
)
check(
    "a later Settings edit cannot re-route the retry job",
    (provider_for_role(new_id, "judge"), provider_for_role(new_id, "reviewer")),
    ("claude", "gpt"),
)

print(f"== summary: {PASSED} passed, {FAILED} failed ==")
_TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
