"""GPT-only structured activity timeline.

The historical ``run.log`` remains the full, provider-neutral evidence tail.
Codex/GPT sessions additionally append compact lifecycle records to
``<job>/gpt-events.jsonl`` so the UI can render progress without changing the
Claude or Grok logging paths.  Older/in-flight GPT jobs are supported by a
read-only ``run.log`` parser; it never writes migrated data back to the job.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


_JOB_ID_RE = re.compile(r"^[a-f0-9]{12}$")
_LOG_LINE_RE = re.compile(r"^\[(\d{2}:\d{2}:\d{2})\]\s+(.*)$")
_ROLE_RE = re.compile(
    r"^\[(main|pre-recon|recon|debugger|triage|judge|reviewer|report|monitor)"
    r"(?:#\d+)?\]\s+(.*)$"
)
_TOOL_RE = re.compile(r"^TOOL\s+(\S+)\s*:\s*(.*)$")
_BACKEND_MODEL_RE = re.compile(r"\bmodel=([^\s)]+)")
_PATH_RE = re.compile(r'"path"\s*:\s*"([^"]+)"')
_EXIT_RE = re.compile(r"\[exit[_ ]code[= ](-?\d+)\]", re.IGNORECASE)


def _jobs_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "/data")) / "jobs"


def _safe_job_id(value: Any) -> str:
    job_id = str(value or "").strip().lower()
    return job_id if _JOB_ID_RE.fullmatch(job_id) else ""


def context_from_options(options: Any) -> tuple[str, str, str]:
    """Return ``(job_id, role, model)`` from a GPT session options object."""
    env = getattr(options, "env", None) or {}
    job_id = _safe_job_id(env.get("JOB_ID"))
    if not job_id:
        match = re.search(r"/jobs/([a-f0-9]{12})(?:/|$)", str(getattr(options, "cwd", "")))
        job_id = _safe_job_id(match.group(1) if match else "")
    role = str(env.get("AGENT_ROLE") or "main").strip().lower()
    if role == "pre-recon":
        role = "recon"
    if role not in {
        "main", "recon", "debugger", "triage", "judge", "reviewer",
        "report", "monitor",
    }:
        role = "main"
    return job_id, role, str(getattr(options, "model", "") or "")


def emit_gpt_event(job_id: str, kind: str, **fields: Any) -> None:
    """Best-effort append to ``gpt-events.jsonl``; never breaks a GPT turn."""
    safe = _safe_job_id(job_id)
    if not safe:
        return
    try:
        job = _jobs_dir() / safe
        if not job.is_dir():
            return
        rec: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "provider": "gpt",
            "kind": str(kind or "event"),
        }
        from modules.job_secrets import redact_job_value

        rec.update(redact_job_value(safe, fields))
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with (job / "gpt-events.jsonl").open("a") as fp:
            fp.write(line + "\n")
    except Exception:
        return


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and item.get("provider") == "gpt":
                out.append(item)
    except OSError:
        pass
    return out


def _iso_for_log_time(hms: str, started_at: str | None, state: dict[str, Any]) -> str:
    try:
        anchor = datetime.fromisoformat(str(started_at or "").replace("Z", "+00:00"))
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        anchor = anchor.astimezone(timezone.utc)
    except Exception:
        anchor = datetime.now(timezone.utc)
    hh, mm, ss = (int(piece) for piece in hms.split(":"))
    sod = hh * 3600 + mm * 60 + ss
    if state.get("last_sod", -1) >= 0 and sod < state["last_sod"] - 60:
        state["day"] = int(state.get("day", 0)) + 1
    state["last_sod"] = sod
    dt = anchor.replace(hour=hh, minute=mm, second=ss, microsecond=0)
    return (dt + timedelta(days=int(state.get("day", 0)))).isoformat()


def _compact(value: str, limit: int = 180) -> str:
    return " ".join(str(value or "").split())[:limit]


def _finish_tool(event: dict[str, Any]) -> None:
    output = event.pop("_output", [])
    detail_parts = event.pop("_detail_parts", [])
    if detail_parts:
        event["input"] = "\n".join(detail_parts)[:8000]
        if event.get("kind") == "artifact":
            paths = _PATH_RE.findall(event["input"])
            if paths:
                names = [Path(path).name for path in paths[:4]]
                event["title"] = "Artifact 수정"
                event["summary"] = ", ".join(names)
    if output:
        full = "\n".join(output)
        event["output_lines"] = len(output)
        event["output_bytes"] = len(full.encode("utf-8", errors="replace"))
        event["detail"] = full[:12000]
        exit_match = _EXIT_RE.search(full)
        if exit_match:
            event["exit_code"] = int(exit_match.group(1))
            event["status"] = "failed" if event["exit_code"] else "completed"
        elif any("TOOL_ERROR" in line or line.startswith("ERROR:") for line in output):
            event["status"] = "failed"
        else:
            event["status"] = "completed"
        useful = next((line.strip() for line in output if line.strip() and not _EXIT_RE.search(line)), "")
        if useful and event.get("kind") not in {"wait", "artifact"}:
            event["summary"] = _compact(useful)
    elif event.get("status") == "running":
        # Historical pre-recon logged tool starts but omitted their results.
        event["status"] = "observed"


def derive_gpt_events_from_run_log(
    job_id: str, *, started_at: str | None = None
) -> list[dict[str, Any]]:
    """Build a compact timeline for a GPT job created before event emission."""
    safe = _safe_job_id(job_id)
    path = _jobs_dir() / safe / "run.log"
    if not safe or not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    open_tools: dict[str, dict[str, Any]] = {}
    state: dict[str, Any] = {"last_sod": -1, "day": 0}

    def close_tool(role: str) -> None:
        tool = open_tools.pop(role, None)
        if tool is not None:
            _finish_tool(tool)

    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    for raw in lines:
        match = _LOG_LINE_RE.match(raw)
        if not match:
            if events and events[-1].get("kind") == "message" and raw.strip():
                prior = str(events[-1].get("summary") or "")
                events[-1]["summary"] = (prior + "\n" + raw.strip())[:4000]
            continue
        ts = _iso_for_log_time(match.group(1), started_at, state)
        body = match.group(2)
        role = "system"
        role_match = _ROLE_RE.match(body)
        if role_match:
            role = "recon" if role_match.group(1) == "pre-recon" else role_match.group(1)
            body = role_match.group(2)

        tool_match = _TOOL_RE.match(body)
        if tool_match:
            name, first_detail = tool_match.groups()
            current = open_tools.get(role)
            if current and current.get("tool") == name and current.get("_log_hms") == match.group(1):
                current["_detail_parts"].append(first_detail)
                continue
            close_tool(role)
            kind = "wait" if name.lower() == "wait" else "artifact" if name in {"Edit", "Write"} else "tool"
            event = {
                "ts": ts, "provider": "gpt", "kind": kind,
                "role": role, "tool": name, "status": "running",
                "title": "Subagent 작업 대기" if kind == "wait" else f"{name} 실행",
                "source": "run.log", "_log_hms": match.group(1),
                "_detail_parts": [first_detail], "_output": [],
            }
            if kind == "wait":
                target_role = ""
                for prior in reversed(events[-6:]):
                    if prior.get("kind") != "message":
                        continue
                    prior_text = str(prior.get("summary") or "").lower()
                    found = re.findall(r"\b(debugger|recon|triage|judge)\b", prior_text)
                    if found:
                        target_role = found[-1]
                        break
                if target_role:
                    event["target_role"] = target_role
                    event["title"] = f"{target_role} 작업 대기"
                event["summary"] = (
                    f"{target_role} 응답을 기다리는 중"
                    if target_role else "native subagent 응답을 기다리는 중"
                )
            events.append(event)
            open_tools[role] = event
            continue

        if body.startswith("TOOL_RESULT:") or body.startswith("TOOL_ERROR:"):
            tool = open_tools.get(role)
            if tool is not None:
                tool["_output"].append(body.split(":", 1)[1].lstrip())
                try:
                    began = datetime.fromisoformat(str(tool.get("ts") or ""))
                    ended = datetime.fromisoformat(ts)
                    tool["duration_ms"] = max(0, int((ended - began).total_seconds() * 1000))
                except Exception:
                    pass
                if tool.get("kind") == "wait" and body.endswith("completed"):
                    target_role = tool.get("target_role") or "native subagent"
                    tool["summary"] = f"{target_role} 응답 수신"
            continue

        close_tool(role)
        if body.startswith("AGENT:"):
            text = body.split(":", 1)[1].strip()
            events.append({
                "ts": ts, "provider": "gpt", "kind": "message", "role": role,
                "status": "info", "title": "분석 업데이트", "summary": text[:2000],
                "source": "run.log",
            })
            continue

        model_match = _BACKEND_MODEL_RE.search(body)
        if "backend=" in body or body.startswith("Launching OpenAI Codex"):
            events.append({
                "ts": ts, "provider": "gpt", "kind": "agent_started",
                "role": "main" if role == "system" else role,
                "model": model_match.group(1) if model_match else "",
                "status": "running", "title": "Agent 시작",
                "summary": _compact(body), "source": "run.log",
            })
        elif body.startswith("Main session turn"):
            events.append({
                "ts": ts, "provider": "gpt", "kind": "turn_started", "role": "main",
                "status": "running", "title": "Main turn 시작",
                "summary": _compact(body), "source": "run.log",
            })
        elif role == "recon" and body.startswith("reply ready"):
            events.append({
                "ts": ts, "provider": "gpt", "kind": "agent_completed",
                "role": role, "status": "completed", "title": "Recon 완료",
                "summary": _compact(body), "source": "run.log",
            })
        elif any(token in body for token in ("ERROR:", "AGENT_ERROR", "RUNAWAY_OUTPUT")):
            events.append({
                "ts": ts, "provider": "gpt", "kind": "error", "role": role,
                "status": "failed", "title": "오류", "summary": _compact(body, 500),
                "source": "run.log",
            })
        elif body.startswith(("SCAFFOLD_NUDGE", "COST_CAP", "BUDGET_ABORT", "⏰")):
            events.append({
                "ts": ts, "provider": "gpt", "kind": "warning", "role": role,
                "status": "warning", "title": "주의", "summary": _compact(body, 500),
                "source": "run.log",
            })
    for role in list(open_tools):
        close_tool(role)
    for event in events:
        event.pop("_log_hms", None)
    return events


def read_gpt_timeline(
    job_id: str, *, started_at: str | None = None, tail: int | None = None
) -> tuple[list[dict[str, Any]], str]:
    """Return emitted events, or a read-only legacy projection when absent."""
    safe = _safe_job_id(job_id)
    if not safe:
        return [], "none"
    events = _collapse_emitted_events(
        _read_jsonl(_jobs_dir() / safe / "gpt-events.jsonl")
    )
    source = "gpt-events.jsonl"
    if not events:
        events = derive_gpt_events_from_run_log(safe, started_at=started_at)
        source = "run.log fallback" if events else "none"
    if tail and tail > 0:
        events = events[-tail:]
    return events, source


def _collapse_emitted_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join live tool start/completion records into one expandable UI card."""
    out: list[dict[str, Any]] = []
    pending: dict[str, dict[str, Any]] = {}
    for original in events:
        event = dict(original)
        call_id = str(event.get("call_id") or "")
        kind = event.get("kind")
        if call_id and kind in {"tool_started", "wait", "artifact", "delegation"}:
            if kind == "tool_started":
                event["kind"] = "tool"
            pending[call_id] = event
            out.append(event)
            continue
        if call_id and kind == "tool_completed" and call_id in pending:
            started = pending.pop(call_id)
            for key in (
                "status", "duration_ms", "summary", "detail", "output_lines",
                "output_bytes", "exit_code",
            ):
                if event.get(key) is not None:
                    started[key] = event[key]
            continue
        out.append(event)
    return out


def summarize_agents(
    events: list[dict[str, Any]],
    configured_models: dict[str, str] | None = None,
    configured_providers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Fold timeline records into one current-status card per observed role.

    `configured_providers` says which backend each role actually runs on. On a
    hybrid job that is not all one value, and a card that omits it reads as
    "everything is GPT" — which is what the Timeline showed before. A role
    routed away also emits no GPT events, so its card stays `configured`
    forever; naming the provider is what makes that legible rather than
    looking like a stalled GPT agent.
    """
    configured_models = configured_models or {}
    configured_providers = configured_providers or {}
    agents: dict[str, dict[str, Any]] = {}
    for event in events:
        role = str(event.get("role") or "").strip()
        if not role or role == "system":
            continue
        card = agents.setdefault(role, {
            "role": role, "model": configured_models.get(role, ""),
            "provider": configured_providers.get(role, ""),
            "status": "configured", "last_at": "", "current": "",
        })
        if event.get("model"):
            card["model"] = event["model"]
        card["last_at"] = event.get("ts") or card["last_at"]
        kind = event.get("kind")
        status = str(event.get("status") or "")
        if kind == "wait" and status in {"running", "observed"}:
            card["status"] = "waiting"
        elif kind in {"agent_started", "turn_started"} or status == "running":
            card["status"] = "running"
        elif kind in {"turn_completed", "agent_completed"}:
            card["status"] = "completed"
        elif status == "failed" or kind == "error":
            card["status"] = "failed"
        if kind in {"message", "wait", "tool", "artifact", "warning", "error"}:
            card["current"] = event.get("summary") or event.get("title") or ""
        target_role = str(event.get("target_role") or "").strip()
        if kind == "delegation" and target_role:
            target = agents.setdefault(target_role, {
                "role": target_role, "model": configured_models.get(target_role, ""),
                "status": "configured", "last_at": "", "current": "",
            })
            target["status"] = "running" if status == "running" else status
            target["last_at"] = event.get("ts") or target["last_at"]
            target["current"] = event.get("summary") or event.get("title") or ""
    for role, model in configured_models.items():
        agents.setdefault(role, {
            "role": role, "model": model, "status": "configured",
            "last_at": "", "current": "",
        })
    order = {name: i for i, name in enumerate(
        ("main", "recon", "debugger", "triage", "judge", "reviewer", "report", "monitor")
    )}
    return sorted(agents.values(), key=lambda item: order.get(item["role"], 99))
