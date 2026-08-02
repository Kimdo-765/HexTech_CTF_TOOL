#!/usr/bin/env python3
"""Regression suite for the MONITOR feed's signal classifier.

Run from the repo root:   python3 scripts/test_monitor_classify.py

WHY THESE CASES
Every one is taken from job 7955d4ad066a, where 5 of 7 `kind=error` entries
were false. The error regex ran against the raw line with no notion of WHO
wrote it, so it fired on:

    "Exception:"  inside a Python heredoc the agent was composing
    "SIGSEGV"     inside a tool `description` ("Trigger SIGSEGV and capture …")
    "SIGSEGV"     inside a subagent prompt the agent was drafting
    "SIGSEGV"     in prose stating there is NO SIGSEGV handler — the opposite
    "SIGSEGV"     in a findings report — a success

An err badge that is wrong 5 times in 7 is worse than no badge at all: the two
REAL errors in that run were unfindable among the noise. Meanwhile two genuine
failures ("TOOL_ERROR: Exit code 1" in pre-recon) were filed as phase/info and
never surfaced.

The invariant these tests protect is small and precise:
  * a FAILURE is something the agent RECEIVED, never something it WROTE;
  * a CRASH is the goal in pwn/rev, so it is its own kind at info severity —
    but it still must appear in the feed, because "about to segfault the
    target" is exactly what an operator wants to see.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_results: list[tuple[bool, str]] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append((bool(cond), label))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 58 - len(name)))


def _load():
    spec = importlib.util.spec_from_file_location("_mon", ROOT / "modules" / "_monitor.py")
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main() -> int:
    m = _load()

    # ---------------------------------------------------------------- errors
    section("a failure is what the agent RECEIVED")
    chk("TOOL_ERROR from the orchestrator is an error",
        m.classify("[pre-recon] TOOL_ERROR: Exit code 1", "pwn") == ("error", "err"),
        m.classify("[pre-recon] TOOL_ERROR: Exit code 1", "pwn"))
    chk("a traceback in tool OUTPUT is an error",
        m.classify("[main] TOOL_RESULT: Traceback (most recent call last):", "pwn")
        == ("error", "err"))
    chk("a python exception class in OUTPUT is an error",
        m.classify("[main] TOOL_RESULT: BrokenPipeError: [Errno 32] Broken pipe", "pwn")
        == ("error", "err"))
    chk("connection refused in OUTPUT is an error",
        m.classify("[main] TOOL_RESULT: Connection refused", "pwn") == ("error", "err"))

    section("...never what the agent WROTE")
    chk("'Exception:' inside a heredoc the agent is composing",
        m.classify('[main] TOOL Bash:   "command": "cat > p.py <<PY\\nraise Exception: x"',
                   "pwn") is None,
        m.classify('[main] TOOL Bash:   "command": "raise Exception: x"', "pwn"))
    chk("an error word in the agent's own prose is not an event",
        m.classify("[main] AGENT: the parser raises ValueError: on bad input, so we avoid it",
                   "pwn") == ("agent", "info"),
        m.classify("[main] AGENT: raises ValueError: on bad input", "pwn"))

    # ---------------------------------------------------------------- crash
    section("a crash is the GOAL in pwn/rev")
    seg = '[main] TOOL Bash:   "description": "Trigger SIGSEGV and capture maps"'
    chk("pwn: segfault -> crash/info", m.classify(seg, "pwn") == ("crash", "info"),
        m.classify(seg, "pwn"))
    chk("rev: segfault -> crash/info", m.classify(seg, "rev") == ("crash", "info"))
    chk("a subagent prompt mentioning SIGSEGV is crash/info, not an error",
        m.classify('[main] TOOL mcp__team__spawn_subagent:   "prompt": "find SIGSEGV paths"',
                   "pwn") == ("crash", "info"))
    chk("prose saying there is NO SIGSEGV handler is not an error",
        m.classify("[main] AGENT: convert_sym_with_id aborts, no SIGSEGV handler",
                   "pwn") == ("crash", "info"))
    section("...but a fault elsewhere still is")
    chk("web: a segfault the runner REPORTS is an error",
        m.classify("[runner] child died with SIGSEGV", "web") == ("error", "err"),
        m.classify("[runner] child died with SIGSEGV", "web"))
    chk("web: a segfault the agent merely mentions is not",
        m.classify(seg, "web") is None, m.classify(seg, "web"))

    # ---------------------------------------------------------------- noise
    section("bookkeeping is not narratable")
    chk("'attempt 0/' is a turn boundary, not a retry",
        m.classify("Main session turn (attempt 0/∞)", "pwn") is None,
        m.classify("Main session turn (attempt 0/∞)", "pwn"))
    chk("'attempt 2/' IS a retry",
        m.classify("[orchestrator] Main session turn (attempt 2/5)", "pwn")
        == ("retry", "warn"))

    # ---------------------------------------------------------------- dedup
    section("near-duplicate narrations")
    chk("identical text is suppressed", m._too_similar("힙 레이아웃 확인 완료", "힙 레이아웃 확인 완료"))
    chk("a rephrasing is suppressed",
        m._too_similar("에이전트가 protobuf 스키마 추출을 시작",
                       "에이전트가 protobuf 스키마 추출 시작"))
    chk("genuinely different lines are kept",
        not m._too_similar("힙 레이아웃 확인: addrs.data() 플래그",
                           "도구 연결 거부됨 errno 111"))
    # The real 02:30 / 02:32 pair: related, but distinct enough to keep BOTH.
    chk("related-but-distinct narrations are NOT over-suppressed",
        not m._too_similar(
            "이벤트-ID 맵 오류 수정 후 연결 간 ASLR 결정성 검증 진행.",
            "에이전트가 이벤트 ID 수정 및 convert_sym_with_id unchecked-iterator 경로 조사; "
            "Buy.symbol이 enum이 아닌 int64임을 발견"))
    chk("too-short strings are never suppressed", not m._too_similar("ok", "ok2"))
    chk("empty is never suppressed", not m._too_similar("", "anything"))

    # ------------------------------------------------------------ unchanged
    section("signals that must keep working")
    chk("a flag candidate is still good",
        m.classify('[main] TOOL_RESULT: FLAG_CANDIDATE: DH{abc}', "pwn") == ("flag", "good"))
    chk("agent prose is still agent/info",
        m.classify("[main] AGENT: starting protobuf schema extraction", "pwn")
        == ("agent", "info"))
    chk("an exploit write is still an artifact",
        m.classify("[main] TOOL Write: exploit.py", "pwn") == ("artifact", "info"))
    chk("plain tool echo is still dropped",
        m.classify('[main] TOOL Read:   "file_path": "/x"', "pwn") is None)

    failed = [r for r in _results if not r[0]]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
