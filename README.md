# HexTech_CTF_TOOL

Docker-based web UI toolset for CTF problem solving. Six modules covering Web, Pwn,
Forensic, Misc, Crypto, and Reversing — each combines automated tooling with a
Claude Code agent that reads the challenge, identifies the vulnerability or
flag, and generates a runnable exploit/solver script.

Seven Claude-driven roles split by responsibility:

- **reviewer** — Opus 4.7, no tools. Lives in the api container. Reads
  the prior job's `run.log` / exploit / stdout-stderr / source on
  `/retry` and `/resume` and writes ONE 1500-char paragraph hint that
  is hoisted to the next agent's prompt as `⚠ PRIORITY GUIDANCE`.
- **main worker** — RQ process in the worker container. Drives the
  module pipeline and runs the main Claude agent (writer) that
  produces `exploit.py` / `solver.py` / `report.md`. Hosted in a
  single `ClaudeSDKClient` session so postjudge feedback can flow
  back as a new user turn (see [auto-retry triangle](#auto-retry-triangle)).
- **recon** — read-only static-investigation peer subagent. Returns
  a ≤2 KB summary (free-form text per question shape) so heavy disasm /
  source greps / decomp triage never pollute main.
- **triage** — read-only verifier peer subagent. Independent re-read
  of recon's candidate vuln list; re-derives severity from reachability
  + blast radius (cookbook "triage" phase: *"re-deriving them
  independently is a cheap way to catch overconfidence"*). Returns
  **strict JSON** `{verdicts:[{id, verdict, cite, severity, notes,
  dup_of}], summary:{...}}` — main parses with `json.loads`.
- **judge** — read-only quality-gate peer subagent. Two roles: (1) main
  invokes it before finalizing for hang/parse review (free-form text
  reply); (2) the orchestrator wraps every `auto_run` execution in a
  3-stage pre/supervise/post lifecycle that emits a retry hint on
  failure.
- **debugger** — dynamic-analysis peer subagent. Patchelfs the binary
  against the chal's bundled libc (auto-extracted from the Dockerfile's
  base image when needed), then runs gdb / strace / ltrace / qemu-user
  and reports observed runtime state to main. Returns **strict JSON**
  `{observed:{...}, trace:[...], conclusion, caveats:[...]}`. See
  [debugger](#debugger-modules_commonpy-debugger_agent_prompt).
- **report phase** — terminal stateless `query()` (cookbook "report"
  phase pattern). No tools, no MCP server, minimal system_prompt.
  Converts main's `report.md` + `exploit.py`/`solver.py` prose into
  the module-specific `findings.json` schema once at job end.
  Defaulted to `claude-sonnet-4-6` for cost — pure JSON transformation
  doesn't need opus reasoning.

**Subagent isolation (default ON).** All four peer subagents
(recon / triage / judge / debugger) run in their **own** `claude` CLI
subprocess via a custom MCP tool `mcp__team__spawn_subagent`. Each
invocation forks a fresh `ClaudeSDKClient`, runs the subagent to
completion, and discards the subprocess on return — main only ever
sees the subagent's final-text reply as a tool result. The SDK's
built-in `Agent`/`Task` tools are explicitly disallowed so the model
can't fall back to the in-process path. **Reply cache**: identical
`(subagent_type, normalized_prompt)` pairs hit a per-job cache file
(`<work>/.scratch/subagent_cache/<key>.json`) and return the prior
reply instantly — kills the "recon#3 + recon#4 both re-derived libc
symbol VMA→file mapping" waste documented in incident reports. Prefix
prompt with `[NOCACHE]` to force a fresh spawn. See
[Subagent isolation](#subagent-isolation-default-on).

Sibling sandbox containers (decompiler / forensic / misc / runner /
sage) are spawned per job and removed when done — orthogonal to the
seven Claude roles above.

See [Architecture](#architecture) and [Agent architecture](#agent-architecture).

Failed jobs (or finished-without-flag) can be **retried** with an automatic
reviewer-written hint, a hand-written hint, or stop-and-resume mid-run — or
**continued IN PLACE with an operator note** (same job / cwd / session, for
when the agent solved it but was blocked on an external action you've now
taken, e.g. restarting a one-shot instance). There's also an **inline
auto-retry loop** that runs without leaving the job: when the sandboxed run
fails, postjudge's retry_hint is injected back into main's same SDK session
and main patches + re-finalizes (configurable via `AUTO_RETRY_MAX`, default
unlimited). See [Retry / Resume](#retry--resume).

## Modules

| Module | Pipeline | Output |
|---|---|---|
| **Web** | Claude reads source zip → identifies vuln → writes `exploit.py` (requests/pwntools) | exploit.py + report.md |
| **Pwn** | ghiant decomp + ghiant xrefs (cached Ghidra project) + chal-libc-fix base-image lib extraction + GEF gdb + debugger agent → Claude analysis → `exploit.py` | exploit.py + report.md |
| **Forensic** | sleuthkit + qemu-img + Volatility 3 artifact sweep → optional Claude summary | summary.json + artifacts/ + report.md |
| **Misc** | binwalk + foremost + exiftool + steghide + zsteg + pngcheck + qpdf → Claude triage | findings.json + extracted/ + report.md |
| **Crypto** | Claude analyzes source → writes `solver.py` using gmpy2/sympy/z3/pycryptodome (or `solver.sage` with optional SageMath sandbox) | solver.py + report.md |
| **Reversing** | ghiant decomp + xrefs + debugger agent → Claude reverses logic → `solver.py` | solver.py + report.md |

For Web/Pwn/Crypto/Rev, an optional `auto_run` checkbox executes the produced
script in a sandboxed `runner` container (network-isolated unless a remote
target is given).

Per-job form options (optional): **🚩 Capture remote flag** (folds a
"the job is only solved when you capture the REAL remote flag" directive
into the description), **Flag format** (e.g. `DH{...}` — only this shape
counts in FLAG FOUND; see Flag-scan trusted sources), and on `/retry`,
**Fresh context** (retry in a clean SDK session instead of forking the
prior conversation). The Misc form's file upload is optional (skip it for
a description-only Claude analysis).

## Architecture

Seven Claude-driven roles, each with its own context window:

| Role | Where it runs | Tools | Purpose |
|---|---|---|---|
| **reviewer** | `api` container, inline in `/retry` & `/resume` handlers | none (diagnostic only) | Reads the failed prior job and writes a 1-paragraph hint, streamed to the browser |
| **main worker** | `worker` container, one RQ process per concurrency slot | `Read` `Write` `Edit` `Bash` `Glob` `Grep` `mcp__team__spawn_subagent` | Runs the module pipeline; writes `exploit.py` / `solver.py` / `report.md` in a single `ClaudeSDKClient` session that auto-retries on postjudge feedback. Built-in `Agent` / `Task` tools are disallowed; delegation goes through the MCP tool only |
| **recon** (peer subagent) | **own `claude` CLI subprocess** spawned via MCP, dies on return | `Read` `Bash` `Glob` `Grep` `WebSearch` `WebFetch` (read-only) | Static investigation: disasm walks, decomp triage, libc symbol lookup, ROPgadget / one_gadget filter, source-tree grep, web research. Returns ≤2 KB free-form summary |
| **triage** (peer subagent) | own `claude` CLI subprocess spawned via MCP | `Read` `Bash` `Glob` `Grep` (read-only, verdict-only) | Independent re-verification of recon's candidate list. Re-reads each cited file:line; emits **strict JSON** `{verdicts:[{verdict, cite, severity, dup_of}], summary:{}}`. Severity is RE-DERIVED, never inherited |
| **judge** (peer subagent + lifecycle gate) | own subprocess when invoked by main · separate orchestrator-owned session around every `auto_run` execution | `Read` `Bash` `Glob` `Grep` (no Write) | Pre-finalize hang/parse review when invoked by main · pre/supervise/post lifecycle around the runner sandbox · pinned to latest model |
| **debugger** (peer subagent) | own `claude` CLI subprocess spawned via MCP | `Read` `Write` `Edit` `Bash` `Glob` `Grep` | Dynamic analysis under gdb (GEF) / strace / ltrace / qemu-user. Auto-extracts the chal's libc + ld + NEEDED libs from the Dockerfile's base image via `chal-libc-fix`. Returns **strict JSON** `{observed, trace, conclusion, caveats}` |
| **report phase** | terminal stateless `query()` after main finishes (no MCP, no tools, no system_prompt bloat) | `allowed_tools=[]` (pure transformation) | Converts main's `report.md` + `exploit.py`/`solver.py` prose into module-specific `findings.json` (pwn / web / crypto / rev each have their own schema). Defaulted to sonnet for cost — rote pattern-matching doesn't need opus |

```
   browser :8000
        │  HTTP + SSE
        ▼
   ┌─── api  (FastAPI) ────┐         ┌────── redis ──────┐
   │  uploads · /retry     │ ◄─────► │  RQ queue +       │
   │  /resume · /timeout   │         │  worker liveness  │
   │  /api/collector       │         └───────────────────┘
   │                       │
   │  ┌── reviewer ──┐     │   inline · no tools · SSE stream
   │  │  Opus 4.7    │     │
   │  └──────────────┘     │
   └──────────┬────────────┘
              │ RQ
              ▼
   ┌──── main worker  (N RQ procs) ──────────────────────┐
   │  ClaudeSDKClient session → deliverables             │
   │  + auto-retry on postjudge feedback                 │
   │  + heartbeat + token/cost meter                     │
   │  + SOFT_EJECT/FINAL_DRAFT budget guard + fallback   │
   └─┬─────────────────────┬───────────┬─────────────────┘
     │ mcp__team__         │ docker.sock          
     │ spawn_subagent      │                       
     ▼                     ▼                       
   ┌─isolated subagents (each: own claude CLI subprocess)─┐
   │ recon    static, free-form text  (Node #2, dies)     │
   │ triage   verdict JSON re-verify  (Node #3, dies)     │
   │ judge    quality gate            (Node #4, dies)     │
   │ debugger gdb/strace + chal-libc  (Node #5, dies)     │
   │ → only the final-text reply (~KB) returns to main    │
   │ → reply cache by (sub_type, prompt) per job          │
   └──────────────────────────────────────────────────────┘
            │ after main exits
            ▼
   ┌─report phase (stateless query, sonnet, no tools)─────┐
   │ report.md + exploit.py → strict findings.json schema │
   │ (pwn / web / crypto / rev each have their own shape) │
   └──────────────────────────────────────────────────────┘
            ┌─sibling sandboxes─────────┐
            │ decompiler · forensic ·   │
            │ misc · runner · sage      │
            │ (per-job, removed)        │
            └───────────────────────────┘
```

### reviewer (`api/routes/retry.py`)

- Triggered by `/retry/stream` and `/resume/stream` when no manual hint is supplied.
- `_gather_context()` bundles the prior job's `meta.json`, `run.log`, `report.md`, `exploit.py` / `solver.py`, std{out,err}, `callbacks.jsonl`, and 2–3 entry-point source files.
- Replies with ONE ≤1500-char paragraph diagnosing the failure. Streams to the browser over SSE, then is hoisted into the next job's prompt as `⚠ PRIORITY GUIDANCE`.
- **Max extended-thinking budget** (`MAX_THINKING_TOKENS=31999`) is pinned on every reviewer call — the hint is the only steering signal a `/retry` gets, so depth-of-reasoning matters more than the latency. Final output is still capped at ~1500 chars by the prompt, but the thinking trace is not.
- Auth / rate / credit / policy errors surface in the panel and **block** the new job from being enqueued.

### main worker (`worker/runner.py`)

- Forks `WORKER_CONCURRENCY` (default 3) independent RQ processes named `htct-w0..N`. On boot, sweeps stale `rq:worker:htct-w*` keys from a SIGKILL'd previous life, then registers afresh.
- Each process picks a job from redis, runs the module pipeline, and drives the **main Claude agent** (writer) which produces deliverables in `/data/jobs/<id>/work/`.
- Liveness signals consumed by the browser:
  - `agent_heartbeat()` → `meta.last_agent_event_at` per SDK message (5 s throttle).
  - RQ worker key `rq:worker:<name>` (~10 s heartbeat).
  - Token + cost meter — `result.usage` summed across every turn.
  - Soft-timeout watchdog → `meta.awaiting_decision` banner.

### peer subagents — isolated `claude` CLI subprocesses, transient per spawn

When main calls `mcp__team__spawn_subagent(subagent_type, prompt)`,
the orchestrator creates a brand-new `ClaudeSDKClient` for the
subagent with role-specific options (`make_standalone_options` in
`modules/_common.py`). That client owns its own `claude` CLI Node.js
subprocess, runs the subagent to completion, and is closed on
return — the subprocess dies. Main only sees the subagent's final
text response as the MCP tool result; the subagent's intermediate
tool calls, decomp reads, gdb sessions, etc. never touch main's
conversation history.

- **recon** — Read-only (`Read` / `Bash` / `Glob` / `Grep` /
  `WebSearch` / `WebFetch`); cannot `Write` or `Edit`. Returns a ≤2 KB
  free-form text summary (question shape varies — libc offsets vs
  decomp triage vs rootfs unpack each need different output formats,
  so JSON would over-constrain). Decomp triage protocol returns
  FUNCTIONS inventory + ranked CANDIDATES (HIGH/MED/LOW with bug class
  + file:line) so main only reads the flagged files. See [Agent
  architecture](#agent-architecture).
- **triage** — Independent verdict pass over recon's candidate list.
  Read-only (`Read` / `Bash` / `Glob` / `Grep`); verdict-only — never
  proposes a fix. Re-reads each cited file:line and emits **strict
  JSON** with verdicts in `{real | duplicate | false_positive |
  out_of_scope}` and a RE-DERIVED severity (cookbook pattern: do not
  inherit the upstream severity guess). Main calls it when recon
  returns >3 candidates or before committing to a primitive based on
  recon's severity alone.
- **judge** — Quality gate. Used by main pre-finalize for hang/parse
  review, by the orchestrator around every `auto_run` execution.
  Pinned to `LATEST_JUDGE_MODEL`. Read-only; cannot cascade-spawn
  further subagents in isolated mode (preserves the "ONE level deep"
  invariant). Free-form text reply.
- **debugger** — Dynamic analysis. `gdb -batch` (GEF auto-loaded) /
  strace / ltrace / qemu-user gdbserver. Always patchelfs the binary
  against the chal's bundled libc first via `chal-libc-fix` so leaked
  addresses / heap layouts / one_gadget constraints match the remote.
  Falls back to extracting libc + ld + every `DT_NEEDED` .so directly
  from the Dockerfile's `FROM` image when no physical libs are bundled
  (the common Dreamhack / HackTheBox case). Returns **strict JSON**
  `{observed:{...}, trace:[...], conclusion, caveats:[...]}` — set
  `conclusion="BLOCKED: ..."` when the GOAL can't be answered. See
  [debugger](#debugger-modules_commonpy-debugger_agent_prompt).

**Reply cache**. `spawn_subagent` hashes `(subagent_type,
normalized_prompt)` to a key under
`<work_dir>/.scratch/subagent_cache/<key>.json`. A repeat of an
identical question returns the prior reply instantly — saves the
~$0.5–2 + 2-5 min that re-running a spawn for the same question
costs. The "recon#3 + recon#4 both re-derived libc symbol VMA→file
mapping" pattern from past jobs is exactly what this short-circuits.
Cache scope is per-job (work_dir is per-job). Force a fresh spawn
with `[NOCACHE]` prefix on the prompt; the sentinel is stripped
before the subagent sees it. The cache also carries across retries
via the same `work/` tree copy that brings forward decomp / chal-libs
/ pre-recon reply.

**JSON-typed replies** (triage + debugger only). The MCP wrapper runs
the subagent's final text through a permissive JSON extractor (pure
JSON / fenced JSON / brace-balanced span in prose). On success the
reply is re-serialized as compact JSON before reaching main; on
failure a warning is logged and main sees the raw text (graceful
degradation). Recon and judge stay free-form because their output
shape varies too much per call to fit one schema.

### Subagent isolation (default ON)

The `claude-agent-sdk` runs ALL `AgentDefinition` contexts inside a
**single** `claude` CLI Node.js subprocess. When main spawned via
the legacy `Agent(subagent_type=...)` tool, the subagent's full
conversation accumulated into main's Node.js heap — for long
heap-pwn runs this means hundreds of KB per spawn lodge into the
main session and inflate every subsequent prompt-cache hit.

The MCP-based isolation path replaces that with per-spawn `claude`
CLI subprocesses, so the heavy investigation lives in its own
context and main only sees the final-text reply (typically a few KB).
This keeps main's `cache_read` flat regardless of how many
subagents you spawn, which is the whole point of the design.

> History note: the codebase used to carry cgroup `mem_limit`s,
> `CONTEXT_COMPACTION_THRESHOLD` / `HARD_CEILING` guards, and a
> `SUBAGENT_SPAWN_CAP` hard-break. All three were defenses against
> what looked like cumulative-heap OOM kills (`exit code -9`) on
> long heap-pwn runs. Forensic investigation in May 2026 showed
> every observed exit -9 was actually fratricide: the debugger
> subagent's `pkill -9 -f "./prob"` matched its own claude CLI's
> argv (the SDK passes the system_prompt via `--system-prompt`)
> and SIGKILLed itself + sister subagents. The fix is comm-anchored
> matching (`pkill -x prob`) in the debugger prompt; the OOM
> defenses have been removed because they were responding to a
> phantom failure mode.

**How isolation works** (`make_spawn_subagent_mcp` +
`make_standalone_options` in `modules/_common.py`):

1. Main's options expose ONLY the MCP tool
   `mcp__team__spawn_subagent` for delegation. Built-in
   `Agent` / `Task` are added to `disallowed_tools=[...]` so the
   model cannot fall back to the in-process path even under
   `permission_mode=bypassPermissions`.
2. Each `spawn_subagent(subagent_type, prompt)` call:
   - increments `summary["subagent_spawns"]`,
   - builds a standalone `ClaudeAgentOptions` with the requested
     agent's system prompt + tool list + model,
   - opens a fresh `ClaudeSDKClient` (= new `claude` CLI
     subprocess) for that one invocation,
   - drains the subagent's `receive_response()` to collect its
     final text,
   - returns the text to main as the MCP tool result.
3. The subagent's subprocess exits at the `async with` boundary;
   its in-process heap is fully released by the kernel.

Main therefore only accumulates the subagent's final reply
(typically a few KB) per delegation. On a job that runs 4 spawns
the cumulative growth difference is ~1–2 MB of context (isolated)
vs. ~1–2 MB **per spawn** (legacy in-process).

**Auto-pre-recon**. The orchestrator spawns a recon subagent BEFORE
main's first turn (`run_pre_recon` in `modules/_common.py`) so main
starts with a 2 KB triage summary already in its prompt instead of
having to decide whether to delegate. Skipped for remote-only jobs
and retries that fork a prior SDK session. See [Agent
architecture](#agent-architecture).

**Pre-recon caching across retries**. The reply is persisted to
`<work_dir>/pre_recon_reply.txt`; `/retry` and `/resume` carry the
entire `work/` tree to the new job (see
`api/routes/retry.py:_resubmit`, `carry_work=True`), so the next
attempt hits the cache and skips the spawn entirely. For pwn,
`_autobootstrap_libc` likewise skips the `chal-libc-fix` subprocess
when `.chal-libs/libc_profile.json` + `prob` are already present
from the prior run. Net effect on a retry without
`resume_session_id`: ~5 min of recon + ~10 s of chal-libc-fix become
~0 s, and main starts on the retry_hint immediately.

**Spawn cap**. `SUBAGENT_SPAWN_CAP` (default `0` = unlimited) bounds
the delegation count per run only as a runaway cost guard — not as
an OOM defense. Set to a positive int (e.g. `30`) if you want to
catch infinite-recursion model bugs; leave at 0 to allow free use,
which is the recommended posture.

**Rollback**. Set `USE_ISOLATED_SUBAGENTS=0` in `.env` to revert
to the legacy `agents={}` in-process path. The spawn cap still
applies if you've set `SUBAGENT_SPAWN_CAP` to a positive int.

### sibling sandboxes — transient docker containers

`decompiler` (Ghidra), `forensic` (TSK + qemu-img + Vol3), `misc`
(binwalk + steghide + …), `runner` (exec exploit.py / solver.py),
`sage` (optional Coppersmith / LLL). Built once via `--profile tools`,
never started by `compose up`. The worker `docker run`s them per job
and removes them when done.

### judge (`modules/_judge.py`)

Quality-gate agent around every `auto_run` exploit/solver execution.
Pinned to `LATEST_JUDGE_MODEL` (currently `claude-opus-4-7` — shared
with the retry reviewer). Judge is a peer to recon: same read-only
tool set (`Read` / `Bash` / `Glob` / `Grep`) plus `Agent` so it can
delegate heavy investigation to recon. **No `Write` / `Edit`** —
judge cannot patch the script.

**main ↔ peers** quintet (isolated subagent path, default ON):

```
   ┌──────────────────── main (writer, Node #1) ─────────────────┐
   │  Read · Write · Edit · Bash · Glob · Grep                   │
   │  + mcp__team__spawn_subagent(subagent_type=…, prompt=…)     │
   │  (Agent/Task/WebSearch/WebFetch: explicitly disallowed)     │
   └─┬───────────────┬──────────────┬──────────────┬─────────────┘
     │ spawn         │ spawn        │ spawn        │ spawn
     ▼               ▼              ▼              ▼
   ┌── recon ────┐ ┌── triage ───┐ ┌── judge ───┐ ┌── debugger ──┐
   │ Node #2,    │ │ Node #3,    │ │ Node #4,   │ │ Node #5,     │
   │ dies on     │ │ dies on     │ │ dies on    │ │ dies on      │
   │ return      │ │ return      │ │ return     │ │ return       │
   │ read-only,  │ │ read-only,  │ │ read-only, │ │ Read/Write/  │
   │ ≤2 KB       │ │ verdict     │ │ no cascade │ │ Bash         │
   │ free-form   │ │ STRICT JSON │ │ free-form  │ │ STRICT JSON  │
   │ + Web*      │ │             │ │ pinned     │ │ chal-libc +  │
   └─────────────┘ └─────────────┘ │ latest     │ │ gdb (GEF) +  │
                                   └────────────┘ │ strace etc.  │
                                                  └──────────────┘
       ↑ all four return ONLY the final-text reply to main ↑
       ↑ reply cache: (sub_type, prompt) → prior reply        ↑
   * recon owns WebSearch+WebFetch so heavy result bodies stay
     in its subprocess and never inflate main's cache_read.
```

After main exits its session, the orchestrator runs the **report
phase** — a stateless `query()` with no tools and a minimal
system_prompt that converts main's `report.md` + `exploit.py` (or
`solver.py`) into a strict-schema `findings.json` for the module.
Defaulted to sonnet for cost (rote pattern-matching). See
[Architecture table](#architecture) for per-role tool sets.

**Decision flow — main owns the gate, judge is the advisor**

The mission stanza in `mission_block()` makes a judge consult
**mandatory before main finalizes**. After main writes its draft
exploit/solver, it MUST call:

```python
mcp__team__spawn_subagent(
    subagent_type="judge",
    prompt="review ./exploit.py for hang/parse risks (recvuntil
            without timeout, wrong prompt, wrong tube, missing
            argv, infinite loop). Return: per-line FINDINGS,
            SEVERITY, RECOMMEND patch|proceed|abort, REASON.",
)
```

Judge replies with structured findings (see `JUDGE_AGENT_PROMPT`).
**Main reads them and decides**:

| Main's choice | Action |
|---|---|
| **patch** | `Edit` exploit.py to fix HIGH findings → call judge again until clean. Up to ~3 rounds. |
| **proceed** | Findings are LOW/MED, or main judges a HIGH to be a false positive. End the turn; orchestrator runs the script. |
| **abort** | `Bash(rm -f ./exploit.py)` to delete the deliverable, write report.md explaining the block. Orchestrator detects the missing file and skips the runner. |

The orchestrator does **not** override main's decision. Two
backstops still run around the runner:

- **prejudge (advisory)** — runs *before* the container. Findings
  are recorded into `result.json` so the retry reviewer can
  reference them. **Never blocks** the run — main already
  owned the gate.
- **supervise** — single one-shot when output stalls 60 s while
  still alive. Same Claude session as prejudge (resumed via
  `session_id`), so judge sees its earlier findings while making
  the kill/continue call.
- **postjudge** — categorize the finished run as one of `success` /
  `partial` / `hung` / `parse_error` / `network_error` / `crash` /
  `timeout` / `unknown` and emit a retry-ready hint.

Three orchestrator stages share **one Claude session** (prejudge
captures `session_id`; supervise + postjudge resume via
`fork_session=False`).

Each judge stage is best-effort: a judge auth/rate/empty failure
degrades to permissive defaults (prejudge ok, supervise continue,
postjudge unknown) so the runner is never harder to use because of a
flaky judge call. All output prefixed `[judge]` in `run.log`.

Toggle in **Settings → Enable judge for auto-run** (default on); off
reverts to plain blocking wait + bare `exit_code`. The `judge`
subagent stays registered for main — the toggle only gates the
orchestrator's pre/super/post lifecycle wrapping.

### Auto-retry triangle

The analyzer runs main inside a single `ClaudeSDKClient` session, not
fire-and-forget `query()`. After main writes its draft and ends the
turn, the orchestrator runs the sandbox + judge stages — and on a
non-success postjudge verdict, **injects the retry_hint as a fresh
user turn back into the same SDK session** (`run_main_agent_session`
in `modules/_common.py`). Main reads it like any user follow-up,
patches the script, re-invokes the JUDGE GATE on the patched file,
and ends the turn again. Cache prefix preserved across the loop.

```
   main  ──draft──►  orchestrator  ──run──►  judge  ──verdict──┐
    ▲                                                          │
    │                                                          ▼
    └───── new user turn (retry_hint) ◄── postjudge!=success ──┘
```

Loop terminates on the FIRST hit among:
- flag captured / postjudge `verdict == "success"`
- judge emitted `next_action: "stop"` (explicit "this approach is
  unrecoverable" verdict — final authority, overrides remaining budget)
- postjudge produced no actionable retry_hint
- main's SDK session errored / hit `INVESTIGATION_BUDGET`
- `AUTO_RETRY_MAX` cap reached (when configured to a non-negative N)
- user pressed Stop / soft / hard timeout

### WHY_STOPPED.md — stop-decision explainer

Any time the auto-retry loop exits **without** a flag, the
orchestrator writes a human-readable `WHY_STOPPED.md` into the work
tree (carried to the job dir alongside `report.md` / `findings.json`
/ `THREAT_MODEL.md`). One of four reason classes is recorded — each
maps to a different operator playbook the file spells out:

| `stop_kind` | Trigger | Operator playbook the doc suggests |
|---|---|---|
| `judge_stop` | Judge's explicit `next_action="stop"` (unsolvable as approached) | `/retry` with manual hint steering to one of judge's `alternative_paths`, or `/resume` to let main re-think |
| `budget_exhausted` | `AUTO_RETRY_MAX` cap hit; judge was still cooperative | `/retry` for another budget, or raise `AUTO_RETRY_MAX` if convergence looks plausible |
| `no_hint` | Postjudge couldn't propose a concrete fix | `/retry` with manual hint, or run exploit.py against the live target outside the sandbox |
| `agent_error` | Main's SDK session died (SIGKILL / timeout / transport) | `/retry` — the carried work tree + fresh session usually clears transient SDK issues |

Each `WHY_STOPPED.md` consolidates the judge's structured fields —
`stop_reason`, `failure_code`, `specific_diagnosis`, `what_worked`,
`what_failed`, `alternative_paths`, and the verbatim `retry_hint` —
plus the last sandbox `stdout`/`stderr` tail, so a human operator
doesn't have to reconstruct the picture from `run.log` + `meta.json`.
The `/retry` flow copies the file along with the rest of `work/`, so
the next attempt's reviewer sees the prior diagnosis as context.

### Fallback artifact safety net

When something stops main mid-run before it produced an artifact —
budget exhausted, SDK transport killed, soft timeout — the
orchestrator does **not** abort the job. Instead
`write_fallback_artifacts(work_dir, log_fn)`
(in `modules/_common.py`) drops a probe-only `exploit.py` + a brief
`report.md` into the work dir, then **continues into the sandbox +
judge dispatch** as if main had finished normally. The job ends as
`no_flag` (or `partial` if the probe extracted something) instead of
`failed`, and postjudge's `retry_hint` is still emitted so a manual
`/retry` has actionable feedback.

The fallback exploit.py:
- loads `./.chal-libs/libc_profile.json` if present (so chal-libc-
  fix's structured glibc snapshot is preserved across the retry),
- connects to the remote target if one was passed via `argv[1]`,
- sends a single newline + reads back what the server prints,
- writes the response to stdout so the runner captures it.

It is intentionally **not** an exploit — it's a minimal scaffold
that keeps the sandbox+judge cycle traversed so the retry path has
data to work with. `write_fallback_artifacts` is idempotent: it
only writes files that don't already exist, so a partial drop (main
wrote exploit.py but not report.md) still gets a companion report.

`AUTO_RETRY_MAX` env var (default `-1` = unlimited). Set to `0` to
disable the loop, or to a positive int to cap. The natural exit
conditions above mean unlimited is usually safe — same retry_hint
back-to-back will quickly land on "no actionable hint" and stop.

### debugger (`modules/_common.py` `DEBUGGER_AGENT_PROMPT`)

Dynamic-analysis peer subagent. Main delegates to it whenever the
answer depends on observed runtime state rather than disasm —
canary values, leaked addresses, heap chunk layouts at a breakpoint,
which one_gadget actually fires given post-leak register state.

Workflow inside one debugger turn:

1. **`chal-libc-fix <bin>`** patches the binary's interpreter +
   RUNPATH so it loads the chal's bundled libc instead of the
   worker's system libc (Debian glibc 2.41 at the time of writing).
   Lookup priority:
   - explicit `--libs <dir>`,
   - any `Dockerfile COPY libc-* /…` referencing physical files,
   - any `lib/` / `libs/` / `glibc/` dir with `libc.so.6` + `ld-linux-*`,
   - **base-image fallback**: if none of the above hit and a
     Dockerfile `FROM` line is present, `docker pull` the base image
     and `docker run --rm -v <stage>:/out` to copy out
     `/lib*/libc.so.6` + `/lib64/ld-linux-*` + every `DT_NEEDED` SONAME
     (`readelf -d` the binary, then `ldconfig -p` inside the chal
     image to resolve each name → real path → `cp -L`). This is the
     common Dreamhack / HackTheBox pattern: bundle = `Dockerfile +
     prob`, libs only inside the base image.
2. **One of three gdb session shapes** (the prompt makes this
   explicit since the Bash tool is one-shot):
   - **Pattern A** — short `-ex` chain (≤5 commands).
   - **Pattern B (recommended)** — `gdb -batch -x /tmp/probe.py`
     where `probe.py` runs `gdb.execute(...)` in sequence, branches
     on `gdb.parse_and_eval("$reg")`, and uses GEF helpers
     (`heap chunks`, `vmmap`, `canary`, `pattern …`, `xinfo`). One
     gdb session, full programmatic control — the closest thing to
     interactive REPL the SDK supports.
   - **Pattern C** — `gdbserver` + multiple `gdb -batch` attaches when
     state must persist across Bash calls.
3. **Reply ≤2 KB** in the `OBSERVED / TRACE / CONCLUSION / CAVEATS`
   shape so main can paste the conclusion directly into its
   reasoning.

GEF (single-file modern gdb plugin) is auto-loaded via
`/etc/gdb/gdbinit`; `gdb -nx` disables it for plain gdb. Worker also
ships `gdb-multiarch`, `qemu-aarch64-static` / `qemu-arm-static` for
foreign-arch chals, `patchelf`, `strace`, `ltrace`.

## Agent architecture

For web / pwn / crypto / rev jobs, the **main worker** spins up a
multi-peer Claude agent team — main agent (writer) plus `recon` /
`triage` / `judge` / `debugger` subagents. Each peer runs in its own
`claude` CLI subprocess (`Subagent isolation`, default ON), and the
terminal `report phase` runs as a stateless `query()` once main
finishes:

```
   main agent (writer, Node #1)    recon (static, free-form, Node #2)
   ────────────────────────────    ──────────────────────────────────
   • drives reasoning              • libc symbol/offset lookup
   • writes exploit.py /           • decomp triage protocol
     solver.py / report.md           (FUNCTIONS + CANDIDATES)
   • Read/Write/Edit/Bash/         • ROPgadget / one_gadget filter
     Glob/Grep                     • WebSearch / WebFetch routed here
   • + mcp__team__                 • returns ≤2 KB free-form summary
     spawn_subagent                • subprocess dies on return
   • single ClaudeSDKClient
     session (auto-retries on     triage (verdict JSON, Node #3)
     postjudge feedback)          ─────────────────────────────────
              │                   • re-reads recon's candidates
              │ spawn               independently
              ▼                   • re-derives severity
   mcp__team__spawn_subagent(     • STRICT JSON reply
     subagent_type="recon"          {verdicts:[...], summary:{...}}
     | "triage" | "judge"         • subprocess dies on return
     | "debugger",                
     prompt="<q>",                judge (quality gate, Node #4)
   )                              ─────────────────────────────────
              │                   • pre-finalize hang/parse review
              ▼                   • orchestrator pre/supervise/post
        compact reply               around the runner sandbox
        (cached by                • emits retry_hint that loops back
         sub_type+prompt           into main's session
         per job)                 • pinned to LATEST_JUDGE_MODEL

                                  debugger (dynamic state, Node #5)
                                  ─────────────────────────────────
                                  • chal-libc-fix base-image extract
                                  • gdb (GEF) / strace / ltrace /
                                    qemu-user gdbserver
                                  • STRICT JSON reply
                                    {observed, trace, conclusion,
                                     caveats}
                                  • subprocess dies on return

   ┌─── after main exits ────────────────────────────────────────┐
   │ report phase: stateless query(), no tools, sonnet default   │
   │   inputs:  report.md + exploit.py/solver.py + THREAT_MODEL  │
   │   outputs: findings.json (per-module strict schema)         │
   └─────────────────────────────────────────────────────────────┘
```

Same model on the writer side and recon/triage/debugger so cache
prefixes align across spawns (the new subprocess still gets
prompt-cache hits from prior identical system-prompt prefixes).
Judge is pinned to `LATEST_JUDGE_MODEL`; the report phase is pinned
to `REPORT_PHASE_MODEL` (sonnet, override per call). Each peer
exists so its own working set lives in its own subprocess — only the
≤2 KB summary lands back in main. See [Subagent
isolation](#subagent-isolation-default-on) for details.

All peers share the same Bash environment as `main`, so anything in
the worker image is reachable: cross-arch binutils
(`aarch64-linux-gnu-{objdump,readelf,nm}`, `arm-linux-gnueabi-*`),
`qemu-aarch64-static` / `qemu-arm-static` (for running foreign-arch
ELFs and `qemu-aarch64-static -g 1234` gdbserver), `gdb` / `gdb-multiarch`
(GEF auto-loaded), `strace`, `ltrace`, `patchelf`, `chal-libc-fix`,
`cpio`, `ROPgadget` with `capstone>=5`, `one_gadget`, `pwntools`,
`ghiant` (Ghidra-headless wrapper into `./decomp/`), `ghiant xrefs`
(cross-reference query against the cached Ghidra project), plus
`jq` / `xxd` / `7z`. The recon and debugger system prompts ship
copy-pasteable invocation guides grouped by intent.

**Ghiant project caching**: the first `ghiant <bin>` call decompiles
into `./decomp/*.c` AND saves the analyzed Ghidra project under
`<jobdir>/.ghidra_proj/` (~10s extra). All later `ghiant <bin>`
re-decomp calls and every `ghiant xrefs <bin> <sym|addr>` query
reuse that project — cold call ~14s, warm call ~7s on a small ELF.

**Decomp triage protocol**: when `./decomp/` is empty and raw disasm
is dense, main delegates a single recon call ("run ghiant if empty,
return FUNCTIONS inventory + ranked CANDIDATES with bug class +
file:line + NEXT recommendation, skip libc/Go-runtime helpers"), and
reads only the .c files recon flagged. Walking the whole 50-500 file
tree is reserved for recon; main does the narrow read.

Each turn the main agent emits an `init` SystemMessage whose `session_id`
the worker captures into `meta.claude_session_id`. On retry / resume
`_resubmit()` propagates that into `meta.resume_session_id` and copies
the prior `~/.claude/projects/<project_key>/<sid>.jsonl` (and any
`subagents/`) into the new job's project-key directory, so SDK
`fork_session=True` actually finds the prior conversation.

An optional **trip-wire** in each analyzer (`INVESTIGATION_BUDGET`,
default `0` = disabled) can abort a job cleanly if the agent has burned
that many tool calls without producing `exploit.py` / `solver.py` —
useful when you want a hard ceiling instead of letting the SDK exhaust
its context window with `Prompt is too long`. Set
`INVESTIGATION_BUDGET=<positive int>` in `.env` to enable.

Each module's SYSTEM_PROMPT opens with the **MISSION** stanza
(`mission_block()` in `modules/_common.py`) that tells the model up
front: write the deliverables to cwd, delegate STATIC investigation
to recon and DYNAMIC analysis to debugger, mandatory JUDGE GATE
before finalize, write a draft within ~10 tool calls, never
disassemble libc/framework internals, never re-slice saved disasm,
STOP if a Bash result starts with "Output too large (NNN MB)". Long
tool catalogues and module-specific workflows follow the mission
stanza, so the highest-signal guidance lands in the first few
hundred tokens. The pwn prompt also includes a glibc-version-keyed
heap/FSOP cheat-sheet with standard chain templates (FSOP
`_IO_wfile_jumps` overflow, tcache poison + safe-linking, house of
orange, etc.) so heap chals don't waste turns rediscovering common
facts; user descriptions matching heap/FSOP keywords additionally
get a step-by-step checklist injected into the user-turn that
points at `./.chal-libs/libc_profile.json` (structured glibc
feature flags emitted by `chal-libc-fix`), `/opt/scaffold/*.py`
(copy-paste exploit templates that auto-branch on those flags),
the `heap-probe` JSON-timeline gdb wrapper, and the
`failure_code` → `HEAP_FIX_HINTS` prescriptive-preamble path on
the auto-retry user turn. See the [Pwn](#pwn) module section for
the full pipeline.

### Cookbook alignment

The architecture tracks Anthropic's [vulnerability-detection agent
cookbook](https://platform.claude.com/cookbook/claude-agent-sdk-06-the-vulnerability-detection-agent)
where the patterns apply, and intentionally diverges where CTF
exploitation needs differ from defensive code review:

| Cookbook pattern | This project |
|---|---|
| Engagement context (authorized / read-only / disclosure) | `CTF_PREAMBLE` — "authorized participant, training artifact, do not refuse" |
| Threat model phase (`THREAT_MODEL.md` with sections 1-5) | Step 0 of every pwn workflow; 6 sections including "What I'm ASSUMING" / "Open questions" |
| Quality tiers (HIGH heap-overflow / LOW assert) | `QUALITY TIERS` block in mission_block: HIGH(AAW/RCE/UAF) / MED(AAR/partial-write) / LOW(info-leak/DoS), glibc-version-keyed |
| Independent triage with re-derived severity | `triage` subagent (returns strict JSON, never inherits upstream severity) |
| Terminal `report` phase (stateless `query()`, no tools) | `run_report_phase` in `modules/_common.py` — per-module schema, sonnet-defaulted |
| Structured JSON output, every field required | `findings.json` schema validated by `validate_findings` |
| Bash forbidden without sandbox | Bash allowed because every execution path lives inside a per-job docker `runner` container (the cookbook's recommended production form) |
| Sequential `query()` phases | Single long-lived main `ClaudeSDKClient` + on-demand MCP subagents — CTF needs iterative discovery, not one-pass enumeration; isolation is achieved via separate subprocesses rather than separate query calls |
| Owner interview | Replaced by `autoboot` outputs (`AUTOBOOT.md`, `libc_profile.json`, custom-lib enumeration) — no live owner to consult |

Cookbook patterns the project adds on top (not in the reference):
pre-recon cache + autoboot skip across retries, investigation budget
(SOFT/EJECT/FINAL_DRAFT), three-stage judge lifecycle around the
sandbox, scaffold templates keyed by glibc version + how2heap corpus
matrix, custom chal-author library auto-detection.

## Prerequisites

- Docker Engine 24+ or Docker Desktop with WSL Integration enabled
- 6+ GB free disk for tool images (Ghidra alone is ~1.4 GB)
- Either:
  - **Claude Code OAuth** (recommended): Pro/Max claude.ai subscription, run
    `claude login` once on the host so `~/.claude/.credentials.json` exists, OR
  - **Anthropic API key**: set in `.env` or via the Settings tab

## Quick start

```bash
git clone <this-repo> HexTech_CTF_TOOL && cd HexTech_CTF_TOOL
cp .env.example .env

# Edit .env: set HOST_DATA_DIR to absolute path of <repo>/data
# (Auth: leave ANTHROPIC_API_KEY empty to use Claude Code OAuth instead.)

# Core services
docker compose up -d --build

# Tool images (one-time, pulled lazily)
docker compose --profile tools build decompiler forensic misc runner

# (Optional) SageMath solver sandbox for crypto module
docker compose --profile tools-sage pull sage
```

Open <http://localhost:8000>.

## Configuration

All knobs live in two places:

1. **`.env`** — read at container startup, applied to compose substitution:

   | Variable | Default | Purpose |
   |---|---|---|
   | `HOST_DATA_DIR` | `./data` | absolute host path for sibling-container bind mounts |
   | `WORKER_CONCURRENCY` | `3` | parallel job slots |
   | `JOB_TTL_DAYS` | `7` | auto-delete jobs older than N days (`0`=keep) |
   | `JOB_TIMEOUT` | `6000` | soft job timeout in seconds — see [Timeout & soft-deadline decision](#timeout--soft-deadline-decision) |
   | `WEB_PORT` | `8000` | host port |
   | `GHIDRA_VERSION` / `GHIDRA_BUILD_DATE` | `12.0.4` / `20260303` | Ghidra release used by decompiler image |
   | `ANTHROPIC_API_KEY` | empty | leave empty for OAuth |
   | `AUTH_TOKEN` | empty | shared token; empty = no auth (dev) |
   | `HOST_CLAUDE_HOME` | `${HOME}/.claude` | host path of Claude Code config |
   | `CLAUDE_CODE_MAX_OUTPUT_TOKENS` | `999999` | per-turn SDK output cap (the model's own ceiling, ~64k for Sonnet/Opus, becomes the effective limit) |
   | `INVESTIGATION_BUDGET` | `150` | tool-call budget for the main agent. At 80% (`SOFT_EJECT`) the orchestrator injects a "finalize now" user-turn; at 100% it triggers `FINAL_DRAFT` last-chance, then falls back to a probe-only skeleton via `write_fallback_artifacts` so sandbox + postjudge still runs. `0` disables. |
   | `ENABLE_JUDGE` | `1` | wrap every `auto_run` runner execution with the 3-stage judge (pre / stall-supervise / post). Set to `0` to skip judge calls entirely. See [judge](#judge-modules_judgepy). |
   | `AUTO_RETRY_MAX` | `-1` | postjudge-driven inline retries within a single job. `0` disables the loop (legacy fire-and-forget). Positive int caps at exactly N retries on top of the initial run. `-1` / `inf` / `unlimited` lets the loop run until natural exit (success, no actionable hint, error, user Stop, timeout). See [auto-retry triangle](#auto-retry-triangle). |
   | `USE_ISOLATED_SUBAGENTS` | `1` | when `1` (default), main delegates via the MCP tool `mcp__team__spawn_subagent` — each subagent runs in its own `claude` CLI subprocess and only the final-text reply lands in main's history. Set to `0` for the legacy in-process `agents={}` path (kept as a fast rollback). See [Subagent isolation](#subagent-isolation-default-on). |
   | `SUBAGENT_SPAWN_CAP` | `0` | runaway cost guard. `0` = unlimited (recommended — aggressive delegation is encouraged for context efficiency, and the orchestrator already auto-spawns a recon subagent before main's first turn). Set to a positive int to bound how many delegations one run can make. |
   | `ENABLE_EXPLOIT_LIBRARY_HINT` | `0` | when `1`, every job's user prompt is prepended with a short paragraph listing same-module entries from the operator-curated [Exploit Library](#exploit-library) at `/data/exploits/`. OFF by default — flip on once the library has curated entries you trust. |

2. **Settings tab** in the UI — writes to `/data/settings.json`, overrides `.env`
   without restart for: Anthropic API key, Claude model, Auth token, Job TTL,
   Job timeout, Worker concurrency, Callback URL, **Enable judge**, **Use Exploit Library hints**.
   (Concurrency change requires `docker compose restart worker`.)

Precedence: `settings.json` > `.env` > defaults.

## Authentication options

- **Claude Code OAuth** (default): host's `~/.claude/` is bind-mounted into the
  worker (rw) and api (ro). The bundled `claude` CLI uses the existing OAuth
  token from `claude login`. Settings tab shows `✓ Claude Code OAuth detected`.
- **Anthropic API key**: paste into Settings → Anthropic API Key (or set
  `ANTHROPIC_API_KEY` in `.env`). Overrides OAuth when present.

UI access can additionally be gated by a shared **Auth Token** (`/login`,
cookie-based). Empty = no auth (dev mode).

## Concurrency

The worker container forks `WORKER_CONCURRENCY` independent RQ worker
processes, all subscribed to the same Redis queue. Jobs distribute
automatically. Each job can launch its own sibling sandbox container, so the
practical upper bound is host RAM/CPU (5–8 is usually fine).

The UI header shows `<busy>/<total> workers · <queued>` in real time.

## Job lifecycle

```
upload ──► /data/jobs/<id>/         ─► RQ enqueue
                 │
                 ▼
       worker process picks up
                 │
                 ▼
       (per module pipeline)
       e.g. Pwn:
        decompiler container ──► decomp.zip
                 │
                 ▼
       Claude Agent SDK (in worker)
       reads source, writes exploit.py + report.md
                 │
                 ▼
       (if auto_run) runner container
       executes exploit.py with the target as argv,
       captures stdout/stderr to <id>/exploit.py.std{out,err}
                 │
                 ▼
       result.json + meta.json updated
       UI polls /api/jobs/<id> every 2s
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | health probe |
| GET | `/api/modules` | module catalog |
| GET | `/api/jobs` | list all jobs |
| GET | `/api/jobs/{id}` | job meta |
| GET | `/api/jobs/{id}/log[?tail=N]` | run log (text). `?tail=N` returns only the trailing N bytes (newline-aligned, used by the polling UI). |
| GET | `/api/jobs/{id}/stream` | Server-Sent Events: live multiplex of `log` (every run.log line), `meta` (status / flag / token+turn deltas), and `sdk` (raw assistant blocks: text / thinking / tool_use / tool_result). On connect: replays current meta + the last ~256 KB of run.log marked `backfill:true`, then streams new events. 15 s `: ping` heartbeats; auto-closes on terminal status. Cookie/token auth via the standard middleware. |
| GET | `/api/jobs/{id}/result` | result JSON |
| GET | `/api/jobs/{id}/file/{name}` | any artifact under the job dir |
| DELETE | `/api/jobs/{id}` | delete one job (cancels queued/running) |
| DELETE | `/api/jobs?status=…&module=…&all=…` | bulk delete (default: finished+failed only) |
| GET | `/api/jobs/queue` | live worker + queue snapshot |
| GET | `/api/jobs/stats` | aggregate cost + counts |
| GET / PUT | `/api/settings` | settings view + patch |
| POST | `/api/modules/web/analyze` | upload source zip → enqueue |
| POST | `/api/modules/pwn/analyze` | upload binary → enqueue |
| POST | `/api/modules/forensic/collect` | upload disk/memory image → enqueue |
| POST | `/api/modules/misc/analyze` | upload file → enqueue |
| POST | `/api/modules/crypto/analyze` | upload zip → enqueue |
| POST | `/api/modules/rev/analyze` | upload binary → enqueue |
| POST | `/api/jobs/{id}/run` | re-run produced exploit/solver in a fresh sandbox |
| PATCH | `/api/jobs/{id}/target` | update only `target_url` on the job's meta — no retry, no resume, no new job. Body `{"target": "<new>"}` (use `(none)` or `""` to clear). The next manual `/run` (and the default of any future `/retry`) picks up the new value. Audit-logged to `run.log`. |
| POST | `/api/jobs/{id}/retry` | regenerate the job. JSON body fields all optional: `hint` (skip reviewer if present), `target` (override prior target_url; sentinel `(none)` clears it). Empty body = auto reviewer + keep prior target. |
| POST | `/api/jobs/{id}/retry/stream` | same as `/retry` but Server-Sent Events stream the reviewer text live |
| POST | `/api/jobs/{id}/resume` | hard-stop a queued/running job, then enqueue a fresh one with the same body shape as `/retry`; `hint` required here. Carries `./work/` + forks the prior SDK session. |
| POST | `/api/jobs/{id}/resume/stream` | SSE-streamed resume. With `{"hint":"…"}` works exactly like `/resume`. With an empty body, calls the reviewer to write the hint first. Both modes carry `./work/`, fork the prior session, and prepend the `[RESUMING]` preamble. |
| POST | `/api/jobs/{id}/continue` | continue a finished job IN PLACE (same job id / cwd / work tree / SDK session) with an operator note. Body `{"comment": "...", "target?": "..."}` — `comment` required. NOT a retry: no new job, no re-investigation. The note is folded in as priority guidance; the optional `target` updates `meta.target_url`. 409 if the job is still active (use Stop & resume instead). |
| POST | `/api/jobs/{id}/timeout/continue` | acknowledge the soft timeout — let the agent keep running |
| POST | `/api/jobs/{id}/timeout/kill` | acknowledge the soft timeout — hard-stop the job |
| POST | `/api/exploits/save` | copy a finished job's `report.md` + `exploit.py`/`solver.py` into the operator-curated library. Body `{"job_id": "...", "tags": [...], "notes": "...", "overwrite": true}`. Refuses jobs with no captured flag |
| GET | `/api/exploits[?module=&tag=&search=]` | list library entries (filterable by module / tag / chal-substring / technique-substring / notes-substring) |
| GET | `/api/exploits/{id}` | one entry's meta + file list |
| GET | `/api/exploits/{id}/file/{name}` | download `report.md` / `exploit.py` / `solver.py` / `solver.sage` |
| DELETE | `/api/exploits/{id}` | remove an entry |
| GET | `/api/exploits/export` | stream the entire library as a single `.tar.gz` for cross-machine transport |
| POST | `/api/exploits/import` | restore entries from a `.tar.gz` produced by `/export`. Multipart: `file=<archive>`, `mode=skip\|overwrite` (default `skip`). Returns per-entry imported/skipped/rejected counts |

## File layout

```
HexTech_CTF_TOOL/
├── docker-compose.yml
├── .env  /  .env.example
├── api/                 # FastAPI app
│   ├── auth.py          # Token middleware
│   ├── main.py
│   ├── queue.py         # RQ helpers
│   ├── routes/          # one router per module + jobs + settings
│   └── storage.py
├── worker/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── runner.py        # multi-process RQ worker + cleanup loop
├── modules/             # mounted into both api & worker (live-edit)
│   ├── _common.py       # shared helpers (cost, paths, meta)
│   ├── _runner.py       # sandbox container helper
│   ├── settings_io.py   # /data/settings.json read/write + OAuth detection
│   ├── web/             # SYSTEM_PROMPT + analyzer.run_job
│   ├── pwn/             # SYSTEM_PROMPT + decompile + analyzer
│   ├── crypto/
│   ├── rev/
│   ├── forensic/
│   └── misc/
├── decompiler/          # Ghidra image (ghiant scripts vendored)
├── forensic/            # sleuthkit + qemu-utils + Volatility 3
├── misc/                # binwalk + foremost + steghide + zsteg + ...
├── runner/              # Python + crypto libs + pwntools (sandbox)
├── web-ui/              # static HTML/CSS/JS
├── scripts/             # one-off operator tools (e.g. job-status.sh)
└── data/                # job uploads + outputs (gitignored)
    ├── jobs/<id>/
    │   ├── meta.json    # status + tokens + cost
    │   ├── run.log      # timestamped agent transcript
    │   ├── result.json  # final summary (post-judge)
    │   ├── bin/ src/    # upload (per module — zips auto-extracted)
    │   └── work/        # agent cwd — exploit.py, report.md, …
    │       └── tmp/     # per-job TMPDIR — `TMPDIR`/`TMP`/`TEMP`
    │                    #   are injected into every agent + sandbox
    │                    #   subprocess so concurrent jobs never share
    │                    #   `/tmp/*`. Auto-cleaned on `DELETE /api/jobs/<id>`.
    └── exploits/<id>/   # operator-curated exploit library (see § below)
        ├── meta.json    # module · tags · arch · glibc · technique · …
        ├── report.md    # copied verbatim from the source job
        └── exploit.py   # or solver.py / solver.sage
```

## Module-specific notes

### Web
- Accepts a zip of source code or a single file.
- Optionally a `target_url` to test against.
- Auto-run runs the produced `exploit.py <url>` in a sandboxed runner.
- The exploit must **normalize the target**: the orchestrator passes a
  bare `host:port`, so `exploit.py` prepends `http://` when no scheme is
  present (a raw `requests.get("host:port/…")` raises "No connection
  adapters found" and captures nothing).
- Web flags often arrive **encoded** (base64 in an error/`message` field,
  url-encoded cookie, hex). The exploit decodes them and emits
  `FLAG_CANDIDATE: <plaintext>` so the trusted-tier scan records the real
  flag.
- The auto-fallback skeleton (when a session ends without an exploit) is
  **web-shaped** — an HTTP probe of the target, not a pwntools socket
  skeleton.

### Pwn
- **Upload**: zip preferred (any zip / tar bundle containing the
  challenge ELF — Dreamhack-style packaging works as-is) or a bare
  single ELF/PE. Remote-only jobs (host:port without a binary) are
  also accepted. The analyzer's `_find_elf_or_unzip` auto-unpacks
  bundles into `./chal/` and stages the largest ELF as the canonical
  target — the agent never sees a `.zip` it has to unpack manually.
- Requires the `decompiler` image (Ghidra 12.0.4 by default; override
  `GHIDRA_VERSION`/`GHIDRA_BUILD_DATE` in `.env`).
- Per-job timeline: ~2–3 min initial decompile + Claude analysis time.
  Subsequent `ghiant` / `ghiant xrefs` calls reuse the cached Ghidra
  project under `<jobdir>/.ghidra_proj/` (~5–10s warm).
- Worker container ships cross-arch CLIs the agent expects from Bash:
  `aarch64-linux-gnu-{objdump,nm,readelf}`, `arm-linux-gnueabi-*`,
  `qemu-aarch64-static` / `qemu-arm-static`, `gdb` / `gdb-multiarch`
  with **GEF** auto-loaded (`/etc/gdb/gdbinit`; use `gdb -nx` to
  disable), `strace`, `ltrace`, `patchelf`, `cpio`, `ROPgadget`
  (`capstone>=5` so ARM64 gadget search returns hits), `one_gadget`,
  `pwn checksec`.
- **`gdb-clean`** — drop-in `gdb` wrapper that strips GEF's
  per-invocation banner (`X commands loaded and Y functions added`,
  `[!] To get gef-extras …`) and ANSI/readline escape codes from
  stdout+stderr. The debugger subagent runs `gdb -batch -x probe.py`
  dozens of times per session; without this the banner alone burns
  ~52 log lines and ~1 KB of cache tokens per call. Anything you'd
  pass to `gdb` works (`gdb-clean -nh -batch -x probe.py`); use
  `/usr/bin/gdb` directly when you actually want the banner. Paired
  with `/opt/scaffold/gdb-init.py`, which disables GEF's auto-context
  panel (registers / stack / code / trace) so per-stop output stays
  terse — source it first in every probe (`-ex 'source
  /opt/scaffold/gdb-init.py'`).
- **`ghiant xrefs <bin> <sym|addr>`** — cross-reference query against
  the cached Ghidra project. Returns JSON with every reference site
  (UNCONDITIONAL_CALL / DATA_READ / DATA_WRITE / etc.) — strictly
  better than grepping `./decomp/*.c` for an address since Ghidra
  knows the ref_type. Auto-bootstraps full analysis if the cache
  isn't present yet, so it's safe to call before `ghiant <bin>`.
- **`chal-libc-fix <bin>`** — patches the binary's interpreter +
  RUNPATH so it loads the chal's bundled libc instead of the
  worker's system libc. Auto-discovers libs from (1) `Dockerfile
  COPY libc-* /…` lines, (2) `lib/` / `libs/` / `glibc/` dirs in
  the bundle, (3) **the Dockerfile's `FROM` base image** (docker
  pulls + extracts `libc.so.6` + `ld-linux-*` + every `DT_NEEDED`
  SONAME via `ldconfig -p`). Critical for heap/FSOP analysis
  where offsets shift between glibc versions; the debugger
  subagent calls it automatically before any gdb session. Pass
  `--no-image` to skip the base-image fallback.
  **Also emits `./.chal-libs/libc_profile.json`** — a structured
  snapshot of `{version, version_tuple, arch, safe_linking,
  tcache_key, tcache_present, hooks_alive,
  io_str_jumps_finish_patched, preferred_fsop_chain,
  recommended_techniques, blacklisted_techniques, symbols,
  one_gadget}`. Main agent / judge / `exploit.py` all `json.load`
  this instead of re-deriving glibc-version facts from `strings`
  every retry. Recommended/blacklisted technique lists drive the
  matrix-based branching (e.g. `__free_hook` is blacklisted on
  glibc ≥ 2.34; `_IO_str_jumps __finish` on ≥ 2.37).
- **`/opt/scaffold/` exploit templates** for heap chals (copied
  into the worker image at build time):
  - `heap_menu.py` — menu-driven (alloc / free / edit / show)
    chal scaffold. `cp /opt/scaffold/heap_menu.py ./exploit.py`,
    then fill the prompt strings + exploit body. Auto-loads
    `libc_profile.json`, ships `safe_link()`, `assert_libc_base()`,
    `assert_heap_base()` helpers.
  - `fsop_wfile.py` — `_IO_FILE_plus` / `_IO_wide_data` /
    `_wide_vtable` builders for glibc ≥ 2.34 FSOP. Encodes the
    "vtable LAST" invariant by returning the body with the
    vtable slot zeroed — caller flips the vtable pointer
    separately AFTER the rest of the chain is in place.
  - `tcache_poison.py` — `safe_link()` / `alignment_ok()` /
    `needs_key_bypass()` / `assert_techniques_match()` — auto-
    branches on `safe_linking` / `tcache_key` from the profile.
  - `aslr_retry.py` — `aslr_retry(exploit_one, max_attempts=64)`
    + `expected_attempts_for(success_rate)` for nibble-race
    chains (typical 1/16 success → ~72 attempts).
- **`heap-probe <bin> --break <bp> --dump tcache,fastbin,unsorted,chunks`**
  — gdb-batch harness that emits a JSON timeline of heap state at
  each breakpoint hit. Standardizes the "alloc a few, free a few,
  inspect tcache" recipe so the debugger subagent doesn't re-roll
  the gdb session every call. JSON shape:
  `{events: [{pc, function, hit, dumps: {tcache, fastbin, …}}, …]}`.
  Use `--gdb gdb-multiarch` for aarch64/arm.
- **pwndbg opt-in**: image build defaults to `INSTALL_PWNDBG=1`,
  installing pwndbg alongside GEF at `/opt/pwndbg/`. Switch at
  runtime via `GDB_USE_PWNDBG=1 gdb …` (otherwise GEF auto-loads).
  Use `--build-arg INSTALL_PWNDBG=0` if you want a leaner image.
- **`scaffold.aslr_retry` + `heap-probe` + spawn hygiene** —
  `DEBUGGER_AGENT_PROMPT` mandates AT MOST ONE inferior process
  alive at a time. Cleanup uses comm-anchored matching
  (`pkill -9 -x prob`, `pkill -9 -x gdbserver`) — **never** `pkill -f`,
  because the SDK passes `system_prompt` as a CLI argv and `-f` would
  match the agent's own claude CLI process. That fratricide accounted
  for every observed `exit code -9` in prior heap-pwn runs; the
  comm-anchored fix eliminates it.
- **Decompile-vs-assembly workflow** (WORKFLOW step 3.5 in
  `modules/pwn/prompts.py`): for heap / int-overflow / signedness
  / OOB-index chals, *primitive validation* is mandatory before
  writing exploit code. Recon's CANDIDATES output now carries a
  `verify: objdump -d …` line per HIGH/MED candidate of those bug
  classes; main MUST run that disasm to confirm `movzx`/`movsx`,
  `lea` scale+displacement, `cmp`+`jXX` predicate, and C++ vtable
  slot number before locking in the primitive. Skipping this step
  is the documented cause of the 1d00be30d4e9 / a914ca943ed2
  failures (decompile said `int idx`, real code was unsigned,
  sentinel byte pattern wrong, all one_gadget retries SIGSEGV'd).
- **Postjudge `failure_code` classification** for heap chals (13
  codes: `heap.libc_version_mismatch`, `unaligned_libc_base`,
  `safe_linking_missing`, `safe_linking_misapplied`,
  `hook_on_modern_libc`, `str_finish_patched`,
  `vtable_write_order_violated`, `tcache_key_not_bypassed`,
  `aslr_unstable`, `unaligned_tcache_target`,
  `whitespace_in_address`, `interactive_in_sandbox`,
  `unbounded_recv`). When postjudge emits one, the orchestrator
  prepends a deterministic prescriptive fix snippet
  (`HEAP_FIX_HINTS` in `modules/_common.py`) ahead of the model-
  authored `retry_hint` in the next auto-retry user turn, so the
  fix is harder for main to phrase away.
- **C++ binaries**: full Ghidra demangler (`/opt/ghidra/GPL/DemanglerGnu`)
  + `c++filt` + `nm -C` / `objdump -d -C`. Decompiled output uses
  unmangled names (`MyClass::method()` not `_ZN7MyClass…`).
- **Go binaries**: Ghidra 12 ships Go runtime type databases for Go
  1.15–1.23 — ghiant decompiles named or stripped Go binaries with
  function/type recovery automatically. Plus `redress` (amd64 only)
  for first-pass triage: `redress info <bin>` reads Go version +
  module + package counts via pclntab, `redress packages`
  / `types` / `source` for deeper recovery.
- **Dynamic analysis** for foreign-arch ELFs:
  `qemu-aarch64-static -g 1234 ./bin/x &` followed by
  `gdb-multiarch -batch -ex 'set arch aarch64' -ex 'target remote
  :1234' -ex 'b *0x...' -ex 'continue' …` — the debugger subagent
  uses this pattern to break/inspect inside QEMU-user without a
  full system VM.

### Forensic
- Auto-detects qcow2 / vmdk / vhd / vhdx / e01 / raw / memory / **log**.
- E01 is converted to raw via `ewfexport`; vmdk/qcow2/vhd via `qemu-img`.
- Memory dumps run a curated Volatility 3 plugin set per detected OS.
- **Image type `log`** is a fast path for raw log uploads: skip
  disk/memory analysis and run only the log-mining stage. Accepts a
  single text file (`.log`, `.txt`, …), a `.gz` of one, or any
  `.zip` / `.tar` / `.tar.gz` / `.tgz` of logs. The archive is unpacked
  into `artifacts/logs/` and `log_miner` mines every text file
  underneath (`force=True` — name hints are ignored). Auto-detect picks
  this kind for plain `.log/.txt/.csv/.json/...` uploads or anything
  the `file(1)` command labels as ASCII/UTF-8 text.
- After artifacts are extracted, `log_miner` scans every log/history file
  (Apache/Nginx access + error logs, `auth.log`, `syslog`, `bash_history`,
  PowerShell `ConsoleHost_history.txt`, Volatility `linux.bash` output, …)
  and writes `log_findings.json` with categorized hits:
  - **passwords** — credentials leaked in URL params, JSON bodies,
    `mysql -p<pw>`, `curl -u user:pass`, HTTP `Authorization: Basic …`.
  - **sqli_attempts / xss_attempts / lfi_attempts / rce_attempts** —
    classic web-attack signatures (`UNION SELECT`, `' OR 1=1`, `<script>`,
    `../../etc/passwd`, ``$(…)`` , …). Lines are URL-decoded before
    matching so encoded payloads register.
  - **auth_events** — sshd Accepted/Failed/Invalid-user lines and sudo
    auth events. Useful for spotting brute-force-then-success sequences.
  - **flag_candidates** — anything matching the project's CTF flag regex.

  The job detail panel shows category counts as colored chips; the full
  report is one click away (`log_findings.json`). The Claude summarizer
  is told to read `log_findings.json` first since it's the highest-signal
  source for web-CTF disk images.

### Misc
- File upload is **optional** — skip it to run a description-only Claude
  analysis (the misc tool sweep is skipped when no file is given).
- Unifies binwalk extraction, exiftool, zsteg LSB, steghide, pngcheck, pdf
  parsing. Common flag patterns are auto-extracted.
- bulk_extractor is **not** included (Ubuntu 22.04 dropped the package).

### Crypto
- Solver runs in the worker by default; check **Use SageMath sandbox** to
  execute via the `sagemath/sagemath` image (supports lattice/Coppersmith).
- Available libs in the runner sandbox: pycryptodome, gmpy2, sympy, z3-solver,
  ecdsa, pwntools.

### Reversing
- **Upload**: zip preferred (the API auto-extracts and picks the
  largest ELF/PE inside as the canonical `binary_name`, flattening
  it into `bin/` so the agent's `./bin/<name>` reference resolves
  cleanly) or a bare single ELF/PE.
- Reuses the `decompiler` image.
- Solver auto-runs in the runner container if requested.

## Operational commands

```bash
docker compose up -d              # start core services
docker compose down               # stop
docker compose logs -f worker     # tail worker logs
docker compose ps                 # status

# Source-code changes — restart is enough (no rebuild) because api,
# worker, and modules are all bind-mounted:
docker compose restart api        # api/routes/*, api/main.py changes
docker compose restart worker     # modules/*, worker/runner.py changes

# IMPORTANT — verify a deploy via a LIVE HOST route, not `docker exec
# python3` (which always fresh-imports and masks a stale serving
# process). On WSL2 / Docker Desktop, `docker compose up -d
# --force-recreate` can LEAK the old container's processes — the
# container record is removed but the orphaned uvicorn keeps holding
# host:8000 (serving STALE code) and an orphaned rq-worker tree keeps
# pulling redis jobs with stale modules/. Symptom: container-internal
# curl shows new code, host `curl localhost:8000` shows old code. Detect
# with `ps -eo pid,cmd | grep 'uvicorn api.main'` (a PID that is NOT the
# current api container's `.State.Pid`); fix by killing the orphan PIDs
# (needs root) or restarting Docker Desktop, then re-bind with
# `docker compose up -d --force-recreate api`.

# web-ui/*.js changes — there is no build step (served static), so a
# syntax error breaks the WHOLE UI (no buttons work). The host node is
# too old to --check modern JS; validate with a modern node image:
docker run --rm -v "$PWD/web-ui":/w node:20-slim node --check /w/app.js

# Image rebuilds — needed only for Dockerfile, requirements.txt, or
# tool-image (decompiler/forensic/misc/runner/sage) changes:
docker compose build api worker
docker compose --profile tools build  # tool images

# Wipe all jobs (UI also has a Bulk Delete button)
curl -X DELETE 'http://localhost:8000/api/jobs?all=true'
```

### Full update (base images + source rebuild)

Periodically (Python security patches, glibc / Ghidra major bumps,
Sage updates, etc.) you'll want to refresh every layer from the
internet AND rebuild every local image so the new base actually
takes effect. Six commands, in order:

```bash
# 1. Pull the latest source from origin (so local Dockerfiles match)
git pull --ff-only

# 2. Pull all external base images that compose declares directly
#    (redis:7-alpine, sagemath/sagemath:latest). Build images
#    in this project are local-only and report "pull access denied"
#    here — that is EXPECTED, not a failure.
docker compose --profile tools --profile tools-sage pull

# 3. Rebuild every local image with --pull so each Dockerfile's
#    FROM directive also fetches the latest base (python:3.12-slim,
#    ubuntu:22.04, etc.) instead of using the cached layer. This is
#    the slow step — Ghidra alone re-downloads ~1.4 GB.
docker compose --profile tools --profile tools-sage build --pull

# 4. Recreate core services so they pick up the new images. The
#    bind-mounted source (./api, ./worker, ./modules) stays in
#    place — only the underlying image layer changes.
docker compose up -d --force-recreate api worker redis

# 5. Verify everything came back healthy.
docker compose ps
curl -sS -m 3 -o /dev/null -w "api: HTTP %{http_code}\n" http://localhost:8000/

# 6. (optional) Reclaim disk space from the now-orphaned old image
#    layers. Be deliberate — `prune` is destructive across ALL docker
#    objects on the host, not just this project.
docker image prune -f
```

Tool images (decompiler, forensic, misc, runner, sage) are spawned
on-demand per job by the worker and removed when done — they are
NOT long-running containers, so step 4 doesn't recreate them. The
next job that needs e.g. `runner` will use the fresh image
automatically. If you want to verify they boot at all without a
real job: `docker compose --profile tools run --rm runner --version`.

Storage footprint after a full rebuild: expect ~6 GB of new image
layers (Ghidra is the bulk). The old layers stay reachable through
the existing tag aliases until step 6's `prune` removes them.

### Bind-mount layout

| Container | Mounted from host | Purpose |
|---|---|---|
| `api` | `./api:/app/api:ro`, `./modules:/app/modules:ro`, `./web-ui:/app/web-ui:ro` | hot-reload source on `restart api` |
| `worker` | `./worker:/app/worker:ro`, `./modules:/app/modules:ro` | hot-reload source on `restart worker` |
| both | `./data:/data` (rw), `~/.claude:/root/.claude` (rw — session jsonl carry on /retry) | persistence |

Without `./api:/app/api:ro` an `api/routes/*.py` edit silently has
no effect until you `docker compose build api`. Concrete incident
2026-05-17: a `_carry_work_ignore` fix in `api/routes/retry.py`
took >1 hour to surface because the api container was running
image-baked code from May 15.

## Operational hygiene (boot + per-job)

The worker container's `/tmp` is shared across every job + every
subagent + every retry. Without housekeeping it accumulates dozens
of stale `.py`/`.bin`/`.txt` files (gdb probe scripts, cpio extracts,
ROPgadget dumps, …) and easily reaches 30+ MB; concurrent jobs also
collide there. Two layers of defense:

1. **Per-job isolation** — `make_standalone_options()` pre-sets
   `$TMPDIR` to `./tmp/` (under the job's cwd) for every subagent's
   env. Python `tempfile.*`, pwntools, etc. follow it. Each subagent
   prompt (recon, debugger, judge, triage) has a "scratch path
   discipline" section reminding the agent to write
   `$TMPDIR/probe.py` in Bash rather than the absolute
   `/tmp/probe.py`.
2. **Boot sweep** — `worker/runner.py:_sweep_stale_tmp()` runs
   once on every `docker compose restart worker` and removes files
   in `/tmp` older than 24h. Skips dirs + symlinks +
   `.X*`/`systemd-*`/`snap-*` patterns. Logs `[worker] swept N
   stale /tmp file(s) (N.N KB freed)` on cleanup.

When a job ends (success or failure), each analyzer's `finally`
block calls `cleanup_job_processes()` which walks `/proc` and
SIGTERM (then SIGKILL after 2s) any orphan `qemu-system-*`,
`qemu-aarch64-*`, `qemu-arm-*`, or `gdbserver` left running. The
matcher uses `/proc/<pid>/comm` substrings, not `pkill -f`, for two
reasons:
- Linux `comm` is capped at 15 chars so `pkill -x qemu-system-aarch64`
  silently matches zero processes;
- the SDK passes our system_prompt to the bundled `claude` CLI as
  argv, so `pkill -f` regexes risk self-kill.
Zombies (`State: Z`) are skipped — they're already dead and the
container's init reaps them.

Concrete incident 2026-05-17 on job 9a240a221f1b: the kernel-pwn
debugger spawned `qemu-system-aarch64 ... -nographic &` for
dynamic analysis and never reaped it. Without the cleanup hook,
two jobs deep the worker container had TWO qemu instances both
holding port forwards on `:18000` and ~512 MB combined.

## Timeout & soft-deadline decision

Default job timeout is **6000s** (≈100 min). Override per-job from each
Analyze form, or globally in Settings (`job_timeout_seconds`).

The timeout is **soft**: when it elapses while the agent is still working,
the job is **not** killed. Instead a yellow banner appears on the job
detail panel showing two buttons:

| Button | What happens |
|---|---|
| **▶ Continue running** | Acknowledges the timeout and lets the agent run to completion. The watchdog does not fire again — your acknowledgment carries through to the natural end of the job. |
| **■ Stop now** | Hard-kills the job: signals the worker, removes any sibling containers, marks `meta.status = failed` with `error: "Stopped by user at soft timeout"`. |

Internally:
- The worker spawns an `asyncio` watchdog at the start of the agent loop
  that sleeps the user-set soft timeout, then sets `meta.awaiting_decision`
  and logs a single line. The agent loop is never interrupted.
- RQ's hard timeout is set automatically to **4× the soft budget (min 24 h,
  max 7 d)** so the worker has plenty of runway after a `continue` decision
  before RQ's safety net fires.
- If the agent finishes naturally before the soft timeout, the watchdog is
  cancelled silently and no banner ever appears.

## Retry / Resume

Three flavors:

1. **Inline auto-retry** (no user click) — driven by postjudge inside
   the same job. See [Auto-retry triangle](#auto-retry-triangle). Cap
   via `AUTO_RETRY_MAX` env (default unlimited). The same SDK session
   is reused, so cache prefix is preserved across retries.
2. **User-triggered retry / resume** — described below. Spawns a NEW
   job (new id, new RQ enqueue) and forks the prior SDK session.
3. **Continue-in-place (operator note)** — re-runs the SAME job id with
   an operator note, for the "agent solved it but was blocked on an
   EXTERNAL action" case. See below.

Web / Pwn / Crypto / Rev jobs can be re-issued at any terminal status
(`failed`, `no_flag`, `finished`, `stopped`) — and Stop&resume can also
fire while the job is still `queued` / `running`. Buttons:

| Button | What happens |
|---|---|
| **↻ Retry with reviewer hint** | A separate Claude (Opus 4.7 by default) reads the prior job's `run.log`, exploit/solver, stdout/stderr, and key source files, then writes a one-paragraph diagnosis. That hint is appended to the original description as `[retry-hint] …` and a fresh job is enqueued. Reviewer output streams into the UI live (SSE). |
| **✏ Retry with my hint** | Inline textarea. Whatever you type is appended as `[retry-hint]` — the reviewer is **not** called. |
| **💬 Continue (operator note)** | `POST /api/jobs/{id}/continue {comment, target?}`. Re-runs the SAME job id (no new job, no new cwd) resuming the prior SDK session, with the operator note folded in as priority guidance under a "this is NOT a re-investigation — act on the note now; spend a one-shot resource on your COMPLETE exploit, don't probe" framing. Because the cwd is unchanged, the forked conversation's paths stay valid and there is no stale-path re-orientation. For when the agent fully solved the chal but waited on an external action (you restarted a one-shot DreamHack instance, the remote came back, a credential was handed over). The optional target updates `meta.target_url` (a restarted instance usually comes back on a new port — put it in the **New target** field, not the note). |
| **↻ Stop & resume with reviewer hint** | Only visible while the job is `queued`/`running`. Halts the in-flight job, asks the reviewer to write a diagnosis from the partial run, and submits the new job with that hint. SSE streams progress. |
| **✋ Stop & resume with my hint** | Same as the reviewer variant but you write the hint yourself. |

**Continue vs Retry — why both.** A `/retry` forks into a NEW job id →
NEW cwd, so the carried session's tool-history paths (`/data/jobs/<old>/
work/...`) go stale and the preamble has to tell the agent "your cwd
changed, re-read the artifacts to reconstruct where you were" — which
makes the agent re-investigate (and, in one case, manually re-probe and
burn a precious one-shot registration slot with a wrong value). `/continue`
keeps the SAME job id / cwd / work tree / SDK session, so the agent picks
up exactly where it left off and acts on the note immediately — no
re-orientation. Validated on job e15333348597: the agent resumed, instantly
recognized "the operator restarted the instance — fresh slot, this was the
one remaining blocker", and went straight to grab the slot with its existing
exploit.

**What carries forward** (all four paths):

- the previous job's `./work/` directory (partial `exploit.py` / `solver.py`
  / `report.md` / notes / decomp output) is copied into the new job, so
  the new agent literally sees the files the prior agent wrote.
  `_carry_work_ignore` in `api/routes/retry.py` skips `tmp/` and
  `__pycache__/` at every depth; `symlinks=True` preserves symlinks
  instead of dereferencing them. Without this filter, pwn jobs that
  extracted a Linux rootfs (cpio) into `./tmp/rootfs/` would hang
  copytree on the embedded `dev/console` character device or the
  `dev/log` symlink to a host syslog socket — concrete incident
  2026-05-17 on job 9f93bc8dcd0d left a half-copied work tree, no
  meta.json, and no rq enqueue every time the user clicked retry;
- the prior Claude SDK conversation: `meta.claude_session_id` is captured
  by `capture_session_id()` whenever the SDK emits an `init` SystemMessage,
  propagated to `meta.resume_session_id` of the new job, and the prior
  session's transcript jsonl (plus any `subagents/`) is copied into the
  new cwd's project-key directory. The new analyzer launches with
  `ClaudeAgentOptions(resume=<sid>, fork_session=True)`, so the new agent
  inherits the prior reasoning, thinking, and tool history — not just
  the work tree;
- the user-supplied (or reviewer-written) hint is hoisted to the **top**
  of the new agent's user prompt as `⚠ PRIORITY GUIDANCE` so it isn't
  buried under the original challenge description;
- module / target / model / timeout / source-or-binary upload / auto_run
  are inherited automatically. The retry chain is recorded as
  `meta.retry_of`; resume additionally records `meta.resumed_from`.

**Optional target override**: every retry/resume button accepts an optional
new target. Reviewer-mode buttons prompt via `window.prompt()` (prefilled
with the prior target); inline-form buttons add a one-line input under the
hint textarea. Empty input keeps the prior target; the sentinel `(none)`
clears it.

If the SDK can't locate the prior session for any reason, the new agent
boots fresh — `./work/` + the priority-guidance hint are still sufficient
context. The fallback is documented inside the preamble itself.

**Stale-absolute-path recovery**: a forked SDK session occasionally
re-uses absolute paths like `/data/jobs/<prev_id>/work/...` from its
prior tool history, so the new agent's `Write`/`Edit` calls land in the
**old** job dir while the new `work/` keeps the untouched carry-copy.
On finalize the analyzers walk the `retry_of` / `resumed_from` lineage
(up to 8 hops) via `prior_work_dirs()` and treat those dirs as fallback
candidates in `collect_outputs()`. When the same filename appears in
multiple candidates the most-recent mtime wins; the chosen file is then
mirrored back into the current `work/` so the next retry's carry step
picks up the freshest version. Each analyzer also exports `JOB_ID` into
the agent env so future preambles can anchor on it.

Errors from the reviewer (Claude API auth/rate-limit/credit failures,
policy refusals, empty responses) are surfaced in the panel with a red
"no new job created" header and the error body. The new job is **not**
enqueued in that case.

## Exploit Library

Operator-curated repository of past `report.md` + `exploit.py` /
`solver.py` pairs, stored under `data/exploits/<id>/` and surfaced via
the **📚 Exploits** tab in the UI. Designed for the "I just solved a
similar chal — I wish the agent could look at that prior solution"
case: leak-vector picks, FSOP variants, technique aliasing, etc.

### Saving from a job

Every finished job that has at least one captured flag gets a
**💾 Save to exploit DB** button next to the flag banner in its detail
panel. Clicking it prompts for tags (comma-separated) + a one-line note,
then `POST /api/exploits/save` copies:

- `report.md` (verbatim from the job dir)
- `exploit.py` (or whichever of `exploit.py` / `solver.py` /
  `solver.sage` exists — first hit wins)
- A `meta.json` with:
  - `id` — `<module>-<uuid12>`, used as the URL slug + filesystem dir
  - `source_job_id`, `chal_filename`, `target_url`, `script_filename`,
    `binary_sha256` (when a binary exists in the source job)
  - Auto-extracted from the job's `findings.json`: `arch`,
    `glibc_version`, `mitigations`, `bug_classes`, `technique_name`
  - Operator-supplied: `tags`, `notes`
  - `flags` — the captured flag list (see § *Flag-scan trusted sources*
    below for why this is reliable)
  - `saved_at`

Re-saving the same `source_job_id` updates the existing entry in-place
(preserves the id / URL) by default. Pass `overwrite=false` to refuse
duplicates.

### Browsing / managing

The **📚 Exploits** tab lists every entry as a card with module
color-pill, technique, bug class, arch/glibc, mitigations, captured
flags, notes, tags. Per-card actions: view `report.md` / view script
(both open in the existing file modal with syntax highlighting), jump
to the source job, delete.

Filters: module dropdown + free-text search across
`chal_filename` / `technique_name` / `bug_classes` / `notes`
(debounced 250 ms).

### Export / import (cross-machine portability)

The library is filesystem-backed (no SQLite), so a single
`.tar.gz` of `data/exploits/` is a complete portable dump.

- **Export** — `⬇ Export .tar.gz` button on the Exploits tab (also
  `GET /api/exploits/export`) streams the entire library as
  `exploits-YYYYMMDD-HHMMSS.tar.gz`.
- **Import** — `⬆ Import .tar.gz` file picker (also
  `POST /api/exploits/import` with `mode=skip|overwrite`). The server
  validates each tar member against a strict allow-list
  (`<id>/{meta.json,report.md,exploit.py,solver.py,solver.sage}`,
  no path traversal, no nested dirs) before committing.

### Agent activation — `enable_exploit_library_hint` setting

OFF by default. When toggled ON in Settings (or set as the env var
`ENABLE_EXPLOIT_LIBRARY_HINT=1`), every job's user prompt is prepended
with a short paragraph listing same-module library entries
(`module` filter, newest first, capped at 12) — each row shows
`id · chal · arch · glibc · bug · technique · tags · notes`. The agent
then has plain Bash access to the library at `/data/exploits/` and is
told to `cat /data/exploits/<id>/report.md` (or the script) when
stuck on technique / leak-vector / chain choice.

The activation hint:

- Filters to **same-module** entries only (a pwn chal sees only pwn
  exploits). Cross-module borrowing isn't useful and would just
  inflate the prompt.
- Returns the **empty string** when the toggle is off OR when the
  library has no entries for this module — no prompt change at all.
- Lives in `modules/_common.py:build_exploit_library_hint(module)` and
  is wired into every module orchestrator
  (`pwn` / `web` / `crypto` / `rev` / `misc` / `forensic`) immediately
  before the agent launch, right after the recon-reply prepend.
- Doesn't change the system prompt — only the user message. Toggling
  the setting OFF takes effect on the next job (no restart needed).

Default OFF is deliberate: encoding a single-chal pattern as a broad
prompt nudge over-fits the system (cf. the `heap_state_evolution_gap`
incident). Curate the library first, flip the toggle once entries are
trusted.

### Flag-scan trusted sources

`scan_job_for_flags` in `modules/_common.py` scans in priority order:

1. **Authoritative marker tier** — an explicit `FLAG_CANDIDATE: <flag>`
   line the exploit/solver printed on a genuine run (read ONLY from the
   trusted files below, never narrative prose). The agent is *declaring*
   "this exact string is the flag I captured", so it is honored verbatim,
   format-agnostic. Web exploits decode encoded flags (base64/url/hex)
   inside `exploit.py` before emitting the marker, so the trusted stdout
   carries the final plaintext flag, not a blob.
2. **Trusted tier** — files produced by the actual runner / OOB
   collector: `exploit.py.stdout`, `solver.py.stdout`,
   `callbacks.jsonl`, `summary.json`, `result.json`. If ANY
   non-placeholder flag appears here, return ONLY those.
3. **Narrative tier** — `report.md`, `run.log`, `findings.json`.
   Consulted ONLY when the trusted/marker tiers are empty.

**Operator flag format (optional, per job).** A `Flag format` input on
every job form (e.g. `DH{...}`) is stored as `meta.flag_format` and
becomes the *authoritative matcher*: when set, ONLY flags of that prefix
shape count, so a real `DH{<64 hex>}` is kept while strings in another
format are ignored. The agent is told to plant local/test flags in a
DIFFERENT format (`LOCAL{...}` / `TEST{...}`) — the format mismatch is
itself the filter, so a stand-in can never be mistaken for a capture.

**Placeholder filter.** `_is_placeholder_flag` drops template echoes
(`this_is_a_flag`, `fake_flag`, `<sha256>`, `DH{%s}`, embedded `...`
ellipsis abbreviations, empty-input hashes) but, in the narrative tier,
only treats hex blobs LONGER than 100 chars as junk — real Dreamhack
flags are `DH{<32|40|64 hex>}` and must be kept. Trusted-tier captures
bypass the hash-width heuristic entirely.

This is what makes the Save button trustworthy: the API refuses to
save into the library unless `scan_job_for_flags` returns at least one
real flag, so placeholder-only jobs never enter the curated set.

## UI niceties

- **Job detail modal**. Clicking a job opens a centered overlay (~96vw),
  not an inline panel. Esc / backdrop / ✕ closes; background scroll is
  locked while open.
- **Run log frame**. The run log lives in a macOS-style terminal window
  with traffic-light buttons and a green block caret that blinks while
  the job is `running` / `queued` (steady when terminal). Each line is
  classified by prefix and colored:
  `AGENT` (lavender) · `TOOL <name>` (blue + orange tool name) ·
  `TOOL_RESULT` (green) · `TOOL_ERROR` (red) · `THINK` (yellow italic) ·
  `DONE` (light blue) · `AGENT_ERROR` / `ERROR` (red bold) ·
  `BUDGET_ABORT` / `RUNAWAY_OUTPUT` (amber, raised) · system notes
  (dim italic). Each line also gets an **agent tag chip** indicating
  who emitted it: `main` (purple), `recon` (orange), `judge` (green),
  `debugger` (blue) — subagent lines additionally indented with a `↳`
  so a delegation reads visually like a nested call. Isolated
  subagents include a per-spawn index in the chip
  (`recon#1`, `debugger#2`, …) so multiple delegations to the same
  role are visually distinct.
- **Run-log search / filter**. A 🔎 box in the run-log titlebar filters
  the displayed log (the 256 KB tail the poll fetches) to matching lines
  (case-insensitive), highlights hits with `<mark>`, and shows a match
  count. Highlight is applied only to TEXT segments of the colored HTML
  so the spans aren't mangled. Per-job state survives the poll re-render;
  the poll is skipped while the box is focused so typing isn't cut off.
- **`[FLAG?]` live candidate box**. While a job runs, `agent_heartbeat`
  passively regex-scans each streamed main-agent message for flag
  candidates (the operator `flag_format` if set, else `FLAG_RE`, plus
  explicit `FLAG_CANDIDATE:` markers; placeholders and `LOCAL{...}`
  test flags filtered out) and accumulates them in `meta.flag_candidates`
  WITHOUT touching the curated `meta.flags`. An amber `[FLAG?]` box
  surfaces them above the green 🚩 Flag-found banner (each with a Copy
  button) so the operator can submit fast in a CTF — a newly-found
  candidate bypasses the 5 s heartbeat throttle and is pushed on the SSE
  `meta` delta so it appears at once. This is a deterministic framework
  scan (zero extra LLM tokens), not something the agent does.
- **UTC ↔ Local timestamp toggle**. Run-log titlebar has a button
  flipping `[HH:MM:SS]` between UTC (default, what the orchestrator
  writes to disk) and the user's local timezone. Choice persists in
  `localStorage`; multi-day jobs handle midnight rollover by
  anchoring on `meta.started_at`.
- **Runaway-output guard**. When a Bash result starts with "Output
  too large (NNN MB)" — typical when the binary loops on its prompt
  past stdin EOF — an explicit `RUNAWAY_OUTPUT detected (NNN MB)`
  warning line is appended to run.log and rendered in amber. The
  agent's system prompt also tells it to STOP and re-examine the
  command (`| head -c 65536`, `| head -200`, `| grep -m1 PATTERN`)
  rather than acting on the truncated 2 KB preview.
- **Live elapsed / duration pill**. Right next to the status badge the
  job header carries a colored pill (`⏱ 12m 45s`):
    - yellow with a soft pulse + `running` tag while live (ticks every
      second from a dedicated 1 s timer that ignores the polling
      pause used by selection / open forms — so the counter stays
      smooth while you're copying log text or typing a hint),
    - green when finished, red when failed, etc.,
    - dim gray `⏱ queued` before the worker picks the job up.
  Auto-stamped by the backend the first time status flips to running
  / a terminal value.
- **Liveness chip + token/cost meter**. The run-log footer carries
  two ground-truth pills updated on the same 1 s timer:
    - **liveness** — `active` (green, ≤30 s since last SDK message),
      `silent` (amber, >30 s but RQ worker still heartbeating —
      thinking / first-token wait), `warming` (blue, worker alive but
      no agent event yet), `dead` (red, blinking, >60 s since RQ
      worker heartbeat → process gone, retry/stop now).
    - **tokens / cost** — sums `result.usage` across every turn in
      the run (input + cache_read + cache_creation + output) and the
      cumulative USD cost. Survives long runs without resetting on
      each turn boundary.
  Read together: yellow timing + active liveness = real progress;
  yellow + silent = thinking; yellow + dead = the process died.
- **File preview modal**. Clicking `result.json` / `report.md` /
  `exploit.py` / `solver.py` / `summary.json` / `findings.json` /
  `log_findings.json` etc. opens a syntax-highlighted overlay
  (highlight.js + marked from jsDelivr CDN). JSON is pretty-printed,
  Markdown is rendered with embedded code blocks highlighted, source
  files (`.py` / `.sage` / `.sh` / `.c` / …) are highlighted by
  extension, logs are plain text. `Open raw` / `Copy` / Esc / backdrop.
  Modifier-clicks (`Ctrl/Cmd/Shift/middle`) skip the modal.
- **Polling that respects user input**. The 2-second poll re-render
  is suppressed while you have an inline retry/resume form open OR
  while you have a non-collapsed selection inside the run log — so
  a copy-paste mid-run isn't clobbered by an incoming line.
- **Live SSE stream**. Selecting a job opens an `EventSource` against
  `/api/jobs/<id>/stream` in addition to the 2-second poll. The worker
  publishes every run-log line, meta delta, and raw SDK block to
  Redis pub/sub (`job:<id>:{log,meta,sdk}`); the api multiplexes them
  back out as SSE events. The frontend appends log lines in place
  (preserves scroll + text selection) and updates the tokens-pill
  delta the same tick the agent emits a message, so the "↓ X k
  tokens" counter feels live the way Claude Code's status line does.
  When the stream is connected the 2 s poller widens to 8 s; if
  EventSource fails, the fast poller resumes automatically (graceful
  degradation, no UI surgery required).
- **Live agent activity panel**. A fixed-height (200 px) panel above
  the run-log window shows each AssistantMessage block as a single
  log-tail row: `[tag] AGENT|THINK|TOOL <name>|RESULT: <preview>`,
  color-coded per kind (text=blue, think=gray italic, tool=yellow,
  result=green, error=red). 60-line FIFO, auto-tails to bottom when
  scrolled there, holds position when scrolled up. Click `hide` in
  the header to collapse; preference persists in `localStorage`.
- **CLI live status (`scripts/job-status.sh <job_id>`)**. Single
  carriage-return-refreshed terminal line carrying status / stage /
  turns / token deltas (`↓in ↑out ⟳cache`) / cost / worker / log
  growth. Polls `/api/jobs/<id>` every 2 s — useful when you want a
  glanceable status without opening the browser. `API=http://host:port
  scripts/job-status.sh <id>` for a remote api.

## Out-of-band callbacks (XSS / SSRF / blind RCE)

CTFs that exfiltrate via a remote bot need a publicly-reachable
listener. HexTech_CTF_TOOL has a built-in collector that takes any HTTP
request, logs it, and auto-extracts flag-shaped strings.

Setup once:

```bash
# 1. Expose port 8000 publicly
ngrok http 8000     # or any tunnel: cloudflared, frp, ssh -R, …

# 2. Settings tab → Callback URL = https://<your-tunnel-host>
#    (the orchestrator appends /api/collector/<job_id> per job)
```

Then any agent-produced exploit can use `os.environ["COLLECTOR_URL"]`
as its callback. The collector:

- writes every hit to `<jobdir>/callbacks.jsonl`
- re-scans for FLAG/CTF/DH-style patterns in the URL/query/body
- flips meta.status to `finished` and surfaces flags the moment a
  match arrives — even if the exploit has already exited

`/api/collector/<job_id>` is intentionally exempt from the auth
token. Treat the job_id as a secret if you care.

## Security notes

- Sibling containers spawned by the worker run as root and share the Docker
  socket — treat the worker host as part of the trust boundary.
- `runner` (the sandbox for produced exploit/solver scripts) runs with a
  bridge network by default. For local-only crypto challenges the network
  could be disabled with `network_mode="none"` in `modules/_runner.py`.
- The worker bind-mounts the host's `~/.claude` (rw, so OAuth tokens can
  refresh). Don't run untrusted code as the worker.
- Only the `/api/health` route bypasses auth when an Auth Token is set.

## Troubleshooting

- **`ERR_EMPTY_RESPONSE` from browser**: WSL2 + Docker Desktop port forwarding
  glitch. Try `http://127.0.0.1:8000` or the WSL distro's IP.
- **`docker-credential-desktop.exe: exec format error`** during build: WSL
  interop disabled. Either enable interop, or write `~/.docker/config.json`
  to `{}` to drop the Windows credential helper.
- **`Unable to locate package` (forensic build)**: `bulk-extractor` is no
  longer in Ubuntu 22.04. The Dockerfile already excludes it; if you
  re-add tools, install from a third-party repo.
- **Claude returns 401**: Check Settings tab. `claude_oauth_detected` should
  be `true`, OR a real `ANTHROPIC_API_KEY` should be set. The placeholder
  `sk-ant-...` is automatically ignored.
- **Long-running job stuck**: `GET /api/jobs/queue` shows worker state. If a
  worker is in `busy` for too long, `docker compose restart worker` to recycle.

## License

MIT.
