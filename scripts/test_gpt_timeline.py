#!/usr/bin/env python3
"""Offline checks for the GPT-only structured timeline."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PASS = 0
FAIL = 0


def check(name: str, condition: bool) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gpt-timeline-") as tmp:
        os.environ["DATA_DIR"] = tmp
        from modules.gpt_run_events import (
            emit_gpt_event,
            read_gpt_timeline,
            summarize_agents,
        )

        job_id = "012345abcdef"
        job = Path(tmp) / "jobs" / job_id
        job.mkdir(parents=True)
        emit_gpt_event(
            job_id, "turn_started", role="main", model="gpt-5.6-sol",
            status="running", turn=1,
        )
        emit_gpt_event(
            job_id, "tool_started", role="main", model="gpt-5.6-sol",
            call_id="call-1", tool="Bash", status="running",
            input={"command": "printf ok"},
        )
        emit_gpt_event(
            job_id, "tool_completed", role="main", model="gpt-5.6-sol",
            call_id="call-1", tool="Bash", status="completed",
            duration_ms=25, summary="ok", detail="ok", output_lines=1,
        )
        emit_gpt_event(
            job_id, "message", role="main", model="gpt-5.6-sol",
            status="info", summary="verified result",
        )
        events, source = read_gpt_timeline(job_id)
        tools = [event for event in events if event.get("kind") == "tool"]
        check("structured file is selected", source == "gpt-events.jsonl")
        check("tool start and completion collapse", len(tools) == 1)
        check("collapsed tool keeps result metadata", tools[0].get("duration_ms") == 25)
        check("message remains a separate signal", any(e.get("kind") == "message" for e in events))
        check("event records are GPT scoped", all(e.get("provider") == "gpt" for e in events))
        agents = summarize_agents(events, {"debugger": "gpt-5.6-sol"})
        check("main agent card uses observed model", agents[0].get("model") == "gpt-5.6-sol")
        check("configured role card is present", any(a.get("role") == "debugger" for a in agents))

        legacy_id = "fedcba654321"
        legacy = Path(tmp) / "jobs" / legacy_id
        legacy.mkdir(parents=True)
        (legacy / "run.log").write_text(
            "[12:00:00] Launching OpenAI Codex (ChatGPT OAuth) agent (model=gpt-5.6-sol)\n"
            "[12:00:01] [main] AGENT: testing one hypothesis\n"
            "[12:00:02] [main] TOOL Bash: {\n"
            "[12:00:02] [main] TOOL Bash:   \"command\": \"printf ok\"\n"
            "[12:00:02] [main] TOOL Bash: }\n"
            "[12:00:02] [main] TOOL_RESULT: ok\n"
            "[12:00:02] [main] TOOL_RESULT: [exit_code=0]\n"
            "[12:00:03] [main] AGENT: asking debugger to validate this\n"
            "[12:00:04] [main] TOOL wait: {}\n"
            "[12:00:05] [main] TOOL_RESULT: completed\n"
        )
        projected, projected_source = read_gpt_timeline(
            legacy_id, started_at="2026-08-07T11:59:00+00:00"
        )
        check("legacy GPT job uses read-only fallback", projected_source == "run.log fallback")
        check("legacy Bash output is grouped", sum(e.get("kind") == "tool" for e in projected) == 1)
        waits = [e for e in projected if e.get("kind") == "wait"]
        check("legacy wait identifies nearby agent role", waits and waits[0].get("target_role") == "debugger")
        check("fallback does not create a structured file", not (legacy / "gpt-events.jsonl").exists())
        emit_gpt_event("not-a-job", "message", summary="must not be written")
        check("invalid job id cannot write", not (Path(tmp) / "jobs" / "not-a-job").exists())

        codex_source = (ROOT / "modules" / "codex_cli.py").read_text()
        responses_source = (ROOT / "modules" / "gpt_responses.py").read_text()
        common_source = (ROOT / "modules" / "_common.py").read_text()
        check("Codex adapter emits GPT events", "emit_gpt_event" in codex_source)
        check("Responses adapter emits GPT events", "emit_gpt_event" in responses_source)
        check("shared logger has no GPT event hook", "emit_gpt_event" not in common_source)
        from modules.agent_provider import provider_meta_fields

        claude_meta = provider_meta_fields("claude")
        gpt_meta = provider_meta_fields("gpt")
        check("Claude meta has no GPT timeline snapshot", not any(k.startswith("gpt_") for k in claude_meta))
        check("GPT meta snapshots its preset separately", "gpt_role_models" in gpt_meta)
        check("GPT snapshot omits the removed monitor role",
              "monitor" not in gpt_meta.get("gpt_role_models", {}))

    print(f"\n{PASS} checks, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
