# Ogamdo — cross AI view

여러 AI의 시선을 교차시켜 푸는 CTF 자동화 플랫폼.

The name is the design: no single model's reading of a challenge is trusted on
its own. Roles are routed to different providers — `main`, `judge`, `reviewer`,
`recon`, `debugger`, `triage`, `report` can each sit on Claude, GPT (Codex), or
Grok — so the agent that writes an exploit is not the one that decides whether
it is sound. The same principle runs above the pipeline: build and adversarial
review are handed between models, and a finding only counts once a second
viewpoint has tried to refute it against the code.

Docker-based web UI toolset for CTF problem solving. Six core modules covering
Web, Pwn, Forensic, Misc, Crypto, and Reversing — each combines automated
tooling with a Claude Code agent that reads the challenge, identifies the
vulnerability or flag, and generates a runnable exploit/solver script. Three
more ship alongside them and are advertised by `GET /api/modules`: **Web3 /
Smart Contract**, a full loop module (retry, continue, `auto_run`, report
phase); **Hybrid Chain**, a parent that fans out to two hidden children (see
[Hybrid parent/child lifecycle](#hybrid-parentchild-lifecycle)); and
**Live-fire Patch**.

Seven Claude-driven roles split by responsibility:

- **reviewer** — no tools, always max extended thinking. Lives in the api
  container. Reads the prior job's `run.log` / exploit / stdout-stderr /
  module-relevant source on `/retry` and `/resume` and writes one compact,
  evidence-labelled retry plan (≤2500 chars). The plan separates verified
  facts from refuted and untested hypotheses so the next attempt does not
  overfit to the previous agent's theory.
  Its model is resolved per job (`resolve_reviewer_model`): preset
  `reviewer` slot > preset `judge` slot > the job's main-derived model —
  a blank `reviewer` slot behaves exactly like the old "reviewer follows
  judge". See [Model presets](#model-presets-datamodel_presetsjson).
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
  reply); (2) the orchestrator wraps an `auto_run` execution in a
  pre/post lifecycle that emits a retry hint on failure — for the
  modules `judge_mode=enforce` covers, and only those. The third
  stage (`supervise`) is implemented but not driven; see below.
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
  `REPORT_PHASE_MODEL` (`claude-sonnet-4-6`) was chosen for cost — pure JSON
  transformation doesn't need opus reasoning — but it is only the fallback
  for a caller that supplies no model, and no production path does: all five
  analyzers pass the job's own model, so the report phase **follows main**
  (opus by default). The stale comment above `modules/pwn/analyzer.py:2432`
  says the opposite of the line beneath it.

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
| **Crypto** | deterministic no-LLM pre-analysis (RSA auto-factor, cipher/param extraction, remote-banner probe) → Claude analyzes source → writes `solver.py` using gmpy2/sympy/z3/pycryptodome/fpylll (or `solver.sage` with optional SageMath sandbox) | solver.py + report.md |
| **Reversing** | ghiant decomp + xrefs + debugger agent → Claude reverses logic → `solver.py`. ELF plus Windows/PE & managed-.NET (mono / ilspycmd) and headless native-PE run under Wine (experimental) | solver.py + report.md |

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

**Multiple targets.** The target field (Web/Pwn/Crypto) is a dynamic list —
click **`+ add target`** to add another input row (`×` removes one) to register
several (mirrored instances that expire fast, or distinct services in one
chain). The first row is the **primary**
(`meta.target_url`, passed to `exploit.py` as `argv[1]`); all of them are
stored in `meta.target_urls` and handed to the exploit at run time via the
`TARGETS` env var (primary first, newline-separated). The prompt tells the
agent to drive off `argv[1]`/`TARGETS` and try each until one responds, so
no host:port is hard-coded. `/retry`, continue-in-place, and
`PATCH /jobs/{id}/target` all accept multiple too (newline **or** comma
separated). The job detail shows `target: <primary> +N more` (hover for the
full list).

## Architecture

Eight Claude-driven roles, each with its own context window:

| Role | Where it runs | Tools | Purpose |
|---|---|---|---|
| **reviewer** | `api` container, inline in `/retry` & `/resume` handlers | none (diagnostic only) | Reads the failed prior job and writes a 1-paragraph hint, streamed to the browser |
| **main worker** | `worker` container, one RQ process per concurrency slot | `Read` `Write` `Edit` `Bash` `Glob` `Grep` `mcp__team__spawn_subagent` | Runs the module pipeline; writes `exploit.py` / `solver.py` / `report.md` in a single `ClaudeSDKClient` session that auto-retries on postjudge feedback. Built-in `Agent` / `Task` tools are disallowed; delegation goes through the MCP tool only |
| **recon** (peer subagent) | **own `claude` CLI subprocess** spawned via MCP, dies on return | `Read` `Bash` `Glob` `Grep` `WebSearch` `WebFetch` (read-only) | Static investigation: disasm walks, decomp triage, libc symbol lookup, ROPgadget / one_gadget filter, source-tree grep, web research. Returns ≤2 KB free-form summary |
| **triage** (peer subagent) | own `claude` CLI subprocess spawned via MCP | `Read` `Bash` `Glob` `Grep` (read-only, verdict-only) | Independent re-verification of recon's candidate list. Re-reads each cited file:line; emits **strict JSON** `{verdicts:[{verdict, cite, severity, dup_of}], summary:{}}`. Severity is RE-DERIVED, never inherited |
| **judge** (peer subagent + lifecycle gate) | own subprocess when invoked by main · separate orchestrator-owned session around every `auto_run` execution | `Read` `Bash` `Glob` `Grep` (no Write) | Pre-finalize hang/parse review when invoked by main · pre/post lifecycle around the runner sandbox (supervise not driven) · the subagent path is pinned to `LATEST_JUDGE_MODEL`; the orchestrator lifecycle path follows the job's main model via `resolve_judge_model` |
| **debugger** (peer subagent) | own `claude` CLI subprocess spawned via MCP | `Read` `Write` `Edit` `Bash` `Glob` `Grep` | Dynamic analysis under gdb (GEF) / strace / ltrace / qemu-user. Auto-extracts the chal's libc + ld + NEEDED libs from the Dockerfile's base image via `chal-libc-fix`. Returns **strict JSON** `{observed, trace, conclusion, caveats}` |
| **report phase** | terminal stateless `query()` after main finishes (no MCP, no tools, no system_prompt bloat) | `allowed_tools=[]` (pure transformation) | Converts main's `report.md` + `exploit.py`/`solver.py` prose into module-specific `findings.json` (pwn / web / crypto / rev each have their own schema). Runs on MAIN's model, per job — every analyzer passes `model=model` and `REPORT_PHASE_MODEL` (sonnet) is only the fallback for a caller that passes none, which no production path does. An active preset's `report` slot overrides it. |
| **monitor** | `api` container, always-on supervisor (one background task per running job) | `allowed_tools=[]` (narration only) | Filters `run.log` to meaningful SIGNAL events and narrates "what just happened" in one line per configured language. Pinned to a cheap model (`MONITOR_MODEL`, default sonnet — NEVER the job's opus). Output → `<job>/monitor.jsonl` + Redis `job:<id>:monitor` for the live UI panel. See [MONITOR](#monitor-modules_monitorpy) |

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
   ┌─report phase (stateless query, no tools)─────────────┐
   │ report.md + exploit.py → strict findings.json schema │
   │ (pwn / web / crypto / rev each have their own shape) │
   └──────────────────────────────────────────────────────┘
            ┌─sibling sandboxes─────────┐
            │ decompiler · forensic ·   │
            │ misc · runner · sage      │
            │ (per-job, removed)        │
            └───────────────────────────┘
```

Not shown above: an always-on **monitor** in the `api` container — one
background narration task per running job that turns the raw `run.log`
into a curated, per-language commentary feed (see
[monitor](#monitor-modules_monitorpy)).

### reviewer (`api/routes/retry.py`)

- Triggered by `/retry/stream` and `/resume/stream` when no manual hint is supplied.
- `_gather_context()` bundles the prior job's `meta.json`, `run.log`, `report.md`, `exploit.py` / `solver.py`, std{out,err}, `callbacks.jsonl`, and up to six module-relevant entry-point source files (including PHP/JS for Web).
- Replies with one ≤2500-char plan containing `CLASS`, `VERIFIED`, `REFUTED`, `NEXT`, and `PRESERVE`. Strategy/unknown failures require 2–3 materially distinct untested hypotheses with discriminating tests; unsupported “intended path” claims and repetition of refuted branches are forbidden. The plan streams over SSE and is appended to the next job as `[retry-hint]`.
- **Max extended-thinking budget** (`MAX_THINKING_TOKENS=31999`) is pinned on every reviewer call — the hint is the only steering signal a `/retry` gets, so depth-of-reasoning matters more than the latency. Final output is capped at ~2500 chars by the prompt, but the thinking trace is not.
- Auth / rate / credit / policy errors surface in the panel and **block** the new job from being enqueued.

### main worker (`worker/runner.py`)

- **One container per SLOT.** `worker-1`, `worker-2`, ... are separate compose services (see the `x-worker-*` anchors in `docker-compose.yml`), each running exactly ONE RQ process named `htct-s<slot>-w0`. `WORKER_CONCURRENCY` is forced to 1 inside a slot and the stored setting is ignored — parallel jobs is now the slot COUNT.
- On boot each slot sweeps stale `rq:worker:htct-s<slot>-w*` keys from a SIGKILL'd previous life, then registers afresh. The sweep is **scoped to the slot's own prefix**: the pre-split version matched `htct-w*` unconditionally, which becomes a live-data deletion with two slots — slot 2 booting would wipe slot 1's registration mid-job. Slot 1 additionally reaps legacy flat `htct-w*` keys, which nothing else would ever clean up.
- Each process picks a job from redis, runs the module pipeline, and drives the **main Claude agent** (writer) which produces deliverables in `/data/jobs/<id>/work/`.
- Signals consumed by the browser:
  - `agent_heartbeat()` → `meta.last_agent_event_at` per SDK message (5 s throttle).
  - Token + cost meter — `result.usage` summed across every turn.
  - `rq_status` from RQ, per job.

  **There is deliberately no liveness chip.** One existed (active / silent /
  warming / dead) and was removed. Measured on job `e601cd358ad6` — 3303 agent
  events over 5.7 h — emission gaps have a median of 0 s but a p99 of 121 s and
  a max of 16 min, and eighteen silences over five minutes make up 52 % of the
  run. Time-weighted, a perfectly healthy job showed amber "silent" **75.3 %**
  of the time and green "active" only 24.7 %. A warning colour that is the
  normal state for three quarters of a run is noise, and no single threshold
  separates "thinking" from "stuck" on a distribution that skewed.
  Its one actionable state, "dead", was also the least trustworthy: it read
  `rq:worker:<name>`, a name permanently bound to a slot and reused by every
  job that runs there, so it answered "is `htct-sN-w0` alive?" rather than "is
  this job alive?". If a per-job heartbeat is ever needed, RQ keeps one at
  `rq:job:<id>.last_heartbeat` (written by `Worker.maintain_heartbeats` for
  that job) — read that, not the worker's.
  - `meta.worker_slot` — stamped by `write_meta()` from the slot's `WORKER_SLOT`
    env. This is what `deploy.sh` reads to restart only the idle slots;
    `rq_worker_name` cannot serve that purpose because it is computed live by
    `GET /api/jobs` and never persisted to disk.

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
  review, by the orchestrator around every `auto_run` execution. The two
  paths take DIFFERENT models: the subagent main spawns is pinned to
  `LATEST_JUDGE_MODEL` (`modules/_common.py:2711`), while the orchestrator
  lifecycle stages call `resolve_judge_model(job_id)`, whose whole purpose is
  to FOLLOW the job's main-agent model and never diverge from it
  (`_common.py:3807-3818`). An active preset's `judge` slot overrides either.
  review, by the orchestrator around every `auto_run` execution.
  Defaults to `LATEST_JUDGE_MODEL`, overridden by an active preset's
  `judge` slot. Read-only; cannot cascade-spawn
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
> matching (`pkill -x prob`) in the debugger prompt. The context guards
> (`CONTEXT_COMPACTION_THRESHOLD` / `HARD_CEILING`) are gone for good and
> `SUBAGENT_SPAWN_CAP` was never reimplemented — those really were answering
> a phantom. **Cgroup `mem_limit` is back**, on different evidence and with a
> different job: not a heap-OOM defense but a bound on a slot that can
> otherwise take the VM down (a 15 GB `python3` once froze the whole WSL VM),
> now with a per-job sampler and an optional governor on top. See
> [Concurrency](#concurrency).

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

**Spawn cap — not implemented.** `SUBAGENT_SPAWN_CAP` exists in `.env` and in
the prompt text shown to the model, and nowhere else: a case-insensitive
repo-wide search finds no code that reads it, and the guard the surrounding
comments name (`_maybe_subagent_cap()`) has no definition. The counter
`summary["subagent_spawns"]` still increments but is consumed only as a log
index. Setting it to a positive int does nothing today. Delegation is
unbounded in both the isolated and legacy paths; the intent was a runaway-cost
guard, never an OOM defense.

**Rollback**. Set `USE_ISOLATED_SUBAGENTS=0` in `.env` to revert
to the legacy `agents={}` in-process path.
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
`sage` (optional Coppersmith / LLL). The first four are built once via
`--profile tools`; `sage` is a different profile and a different verb — it is
PULLED (`sagemath/sagemath:latest`) under `--profile tools-sage`, and only
when `start.sh` is given `--with-sage`. None of them is started by
`compose up`: the worker `docker run`s them per job and removes them when done.

### dev/run parity — the runner is NOT the worker

The agent develops in the **worker** container but its deliverable auto-runs
in a **separate, ephemeral runner** container (`.sage` files run in the
`sagemath/sagemath` image instead). A tool present in one and missing in the
other is invisible during development and kills the job at auto-run — often
after the flag has already been found by hand. This class has fired four
times, each with a DIFFERENT tool; `runner/Dockerfile` records each one in a
comment next to the package that fixed it:

| Job | Tool | Symptom |
|---|---|---|
| `a15ff70a6ed5` | `cpp` | pwntools `asm()` → `FileNotFoundError` before the exploit ever connected |
| `bedf6b58bfd2` | `gdb` | rev solver shelled out to gdb → 2.6 s crash → judge STOP → `no_flag` |
| `c1edf9e91910` | `sage` | decisive Gröbner step shipped UNTESTED (the worker has no sage at all) |
| `e1b933afc137` | `libc6-dev` | **`which gcc` SUCCEEDS while every compile fails** |

The last shape is the nastiest and worth internalizing: Debian's `gcc` only
*Recommends* `libc6-dev` and the runner's apt line uses
`--no-install-recommends`, so the image had `/usr/bin/gcc` but no
`/usr/include/stdio.h` and no `crt1.o`. A presence check passes; the compile
dies. The runner now installs **`build-essential`** (which also brings `g++`
and `make`, both previously absent) plus `gdb qemu-user-static ltrace strace
binutils`.

**The gap re-widened after this was written.** `9a5f496` and `354a920` added about ten tools to the WORKER and none to the runner: chromium + chromium-driver, tshark, tcpdump, wabt (`wasm2wat`), ffuf, dirb (for its wordlist), gawk — now the default `awk`, so `strtonum` resolves — seccomp-tools, volatility3, scapy and keystone-engine. A solver that imports `scapy` or shells out to `wasm2wat` works when the agent tries it in `./work/` and fails when the runner executes it. `scripts/test_worker_slots.py` and `worker/solver_smoke.py` are where that class of drift gets caught; neither covers the new ten.

**Smoke-test in the REAL runner before shipping** — the general defence,
because the package list will always lag:

```bash
python3 -m worker.solver_smoke solver.py [args] [--timeout N]   # any module
python3 -m worker.sage_smoke   solver.sage [args] [--timeout N] # crypto/.sage
```

Both run the script through the SAME `run_in_sandbox` path auto-run uses
(judge disabled, image auto-selected by extension) and print exit code, wall
time and clipped stdout/stderr — so a missing tool surfaces as a
`FileNotFoundError` you can still fix. Honest caveat: only `rev`'s prompt
MANDATES `solver_smoke` and only `crypto`'s mandates `sage_smoke`; elsewhere
they are available but not enforced.

**Changing the runner needs a real image build** — `deploy.sh` restarts
bind-mounted code only and will say so; see
[Operational commands](#operational-commands).

### gdb + ASLR (targeted seccomp profile)

gdb disables per-inferior ASLR via `personality(ADDR_NO_RANDOMIZE)`, which
Docker's DEFAULT seccomp profile rejects with `EPERM` — so gdb printed
`Error disabling address space randomization` and every run moved its
addresses, defeating a fixed-address oracle (job `c70160244e53` had to pivot
to a from-scratch Unicorn emulation, ~1h43 of extra work).

`modules/seccomp_gdb_aslr.json` is the Docker default profile **plus** the
one `personality` argument gdb needs. It is applied to the worker
(`docker-compose.yml` `security_opt`) and to every runner spawn
(`modules/_runner.py`). `seccomp=unconfined` was the first fix and was
deliberately replaced: unconfined also re-enabled unprivileged user
namespaces on the runner — the container that executes agent-authored code
and, unlike the worker, mounts no docker socket. Under the targeted profile
`setarch -R` succeeds while `unshare -U` and `keyctl` stay blocked.

> `security_opt` applies at container CREATE. `docker compose restart` will
> NOT pick it up — the worker needs `docker compose up -d worker-1 worker-2`.

### judge (`modules/_judge.py`)

Quality-gate agent around every `auto_run` exploit/solver execution.
Model: the orchestrator stages (`resolve_judge_model`) derive a base from
the job's main model and fold the preset `judge` slot over it; the judge
SUBAGENT defaults to `LATEST_JUDGE_MODEL` and the same slot overrides it.
Judge is a peer to recon: same read-only
tool set (`Read` / `Bash` / `Glob` / `Grep`). On the DEFAULT path it does NOT
get `Agent`: isolated subagents are on by default and an isolated judge cannot
cascade-spawn (`modules/_common.py:2425-2429`), which is what the "no cascade"
in the diagram below means. Only the legacy in-process `AgentDefinition` and
the orchestrator-invoked judge session register recon as a delegate. **No
`Write` / `Edit`** —
judge cannot patch the script.

**main ↔ peers** quintet (isolated subagent path, default ON):

```
   ┌──────────────────── main (writer, Node #1) ─────────────────┐
   │  Read · Write · Edit · Bash · Glob · Grep                   │
   │  + mcp__team__spawn_subagent(subagent_type=…, prompt=…)     │
   │  (Agent/Task disallowed — WebSearch/WebFetch ARE allowed)   │
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

#### `judge_mode` — three states, and only two of them are reachable by accident

Settings exposes `judge_mode` as `off | shadow | enforce`. The legacy
`ENABLE_JUDGE` boolean still derives `off`/`enforce`; **`shadow` is deliberately
NOT derivable** — a mode that changes what the operator believes is running
should never be entered by inference.

- **off** — plain runner, no judge calls.
- **enforce** — the gate below, scoped to pwn and web (see
  `settings_io.JUDGE_ENFORCE_MODULES`). A module outside that scope runs as
  **shadow**, not off: only the GATING is scoped, so the modules with no
  measurable negative class keep accumulating one.
- **shadow** — during the run the orchestrator only APPENDS the judge's
  *inputs* to `judge_shadow.jsonl`. No model call, no gating; a shadow run is
  byte-identical to the same run with the judge off, down to `run.log`.
  Verdicts are produced afterwards by an out-of-band sweep
  (`judge_shadow.evaluate`), never on the run path.

Three bounds on reading a shadow ledger, because it looks like a measurement
facility and is a narrower one than it appears:

1. **The rule is hash identity, not recency.** Each recorded input is
   fingerprinted against the artifacts it describes, and evaluation refuses
   unless every one of them still matches. In practice a retry rewrites
   `exploit.py` and `exploit.py.stdout` under the same names, so earlier
   cycles usually cannot be replayed and the sample collapses to one attempt
   per job — but that is a consequence, not the rule: a retry whose artifacts
   come out byte-identical leaves BOTH cycles evaluable. Read a refusal as
   "these bytes moved", never as "this was not the last attempt".
2. **Zero `supervise` rows means the stage never fired**, not that shadow did
   not look. supervise is off in every mode (below). Before stage 8 the same
   emptiness was ambiguous.
3. **"Faithful replay" holds at the prompt level only.** The out-of-band judge
   has Read/Bash and can observe that it is replaying — stale artifact mtimes,
   a challenge instance that has since expired. enforce's postjudge sees
   neither.

Two backstops run around the runner when this job's effective mode
gates it — i.e. `judge_mode=enforce` **and** a module in the enforce
scope (pwn, web). In every other case they record and decide nothing:

- **prejudge** — runs *before* the container. Findings are recorded
  into `result.json` so the retry reviewer can reference them. It
  **blocks at `severity=high` only**: the run is abandoned before the
  container starts and the attempt returns
  `{error: "prejudge_blocked", judge_aborted: True}`. Anything below
  high is advisory and the run proceeds. So the orchestrator does
  override main's decision, but only on the one severity, and only
  where the gate is in scope.
- **supervise — implemented, NOT driven.** It would ask judge whether
  to kill when output stalls 60 s while still alive. It is excluded
  from the enforce scope and `attempt_sandbox_run` passes
  `enable_supervise=False` unconditionally, so **it does not run in any
  mode**. Two reasons, both structural: its evidence is a *live*
  container's stalled output, which no after-the-fact replay can
  reconstruct — so it is the one stage that has never been evaluated —
  and it is the only stage that kills a container. A genuinely stuck
  run is ended by the hard timeout, as it always was.
- **postjudge** — categorize the finished run as one of `success` /
  `partial` / `hung` / `parse_error` / `network_error` / `crash` /
  `timeout` / `unknown` and emit a retry-ready hint.

The orchestrator stages share **one judge session, and it is
provider-local** (prejudge captures a `session_id`; the later stage
resumes it with `fork_session=False`). It is not necessarily a Claude
session: if prejudge failed over to the other backend, the stage after
it resumes THAT backend's session, not a Claude one.

Each judge stage is best-effort: a judge auth/rate/empty failure
degrades to permissive defaults (prejudge ok, postjudge unknown) so the runner is never harder to use because of a
flaky judge call. All output prefixed `[judge]` in `run.log`.

Controlled by **Settings → Judge mode** (`off | shadow | enforce`, see
above); `off` reverts to plain blocking wait + bare `exit_code`. The
`judge` subagent stays registered for main — the setting only gates the
orchestrator's pre/post lifecycle wrapping (supervise does not run).

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

**One method-change retry on a STOP (`retry_worthwhile`).** A postjudge
`stop` is no longer unconditionally final. Postjudge may set
`retry_worthwhile: true` — *"this SCRIPT is finished, but a DIFFERENT method
is worth one shot"* — and the orchestrator converts that STOP into one more
`continue`, prefixing the hint with a `METHOD CHANGE REQUIRED` preamble.
Gates, all of which must hold:

- postjudge set `retry_worthwhile` to a real boolean `true` (parsed with a
  strict `is True`, so a stringified `"false"` does NOT count);
- it has fired **at most once** in this job;
- there is an actionable `retry_hint` or `alternative_paths`;
- the verdict is not `network_error` (a dead remote is not a method problem).

Applies to the five loop modules (crypto / pwn / web / rev / web3); `misc` and
`forensic` are one-shot pipelines with no retry loop. The judge prompt lists
explicit exclusions — success, a dead remote, environment limits, a proven
true-negative, and "same method, tweaked" — so this stays a genuine change of
approach rather than a free extra attempt.

Loop terminates on the FIRST hit among:
- flag captured / postjudge `verdict == "success"`
- judge emitted `next_action: "stop"` (explicit "this approach is
  unrecoverable" verdict — final authority, overrides remaining budget)
- postjudge produced no actionable retry_hint
- main's SDK session errored / hit `INVESTIGATION_BUDGET`
- total spend (main + subagents + reviewer calls) hit the cost-cap circuit breaker
  (`COST_CAP_USD`) — recoverable halt, see [circuit breaker](#anti-anchoring-circuit-breaker)
- `AUTO_RETRY_MAX` cap reached (when configured to a non-negative N)
- user pressed Stop / soft / hard timeout

### WHY_STOPPED.md — stop-decision explainer

Any time the auto-retry loop exits **without** a flag, the
orchestrator writes a human-readable `WHY_STOPPED.md` into the work
tree (carried to the job dir alongside `report.md` / `findings.json`
/ `THREAT_MODEL.md`). One of several reason classes is recorded — each
maps to a different operator playbook the file spells out:

#### Unreproduced flag candidates

When `meta.flag_candidates` is non-empty but nothing was promoted,
`WHY_STOPPED.md` **leads** with a `⚑ Unreproduced flag candidate(s) — CHECK
THESE FIRST` section, and the job-list card shows an amber `⚑ N` badge (only
when `flags` is empty — `finished` jobs routinely carry decoy candidates like
`DH{**fake_flag**}`, so badging them would be noise).

This is a VISIBILITY layer and **promotes nothing** — flag curation stays
manual (📌 / 🗑️). It exists because a genuine capture can be stranded: the
agent reads the real flag during its own testing, the auto-run then fails for
an ENVIRONMENT reason, and since only a TRUSTED source promotes a flag the
job renders as a total failure with the answer sitting in its metadata (job
`e1b933afc137`, an operator-confirmed flag). The text labels candidates
machine-unverified and warns against handing one to a solver to print back —
a decoy echoed by a later run would look like a capture.

| `stop_kind` | Trigger | Operator playbook the doc suggests |
|---|---|---|
| `judge_stop` | Judge's explicit `next_action="stop"` (unsolvable as approached) | `/retry` with manual hint steering to one of judge's `alternative_paths`, or `/resume` to let main re-think |
| `budget_exhausted` | `AUTO_RETRY_MAX` cap hit; judge was still cooperative | `/retry` for another budget, or raise `AUTO_RETRY_MAX` if convergence looks plausible |
| `no_hint` | Postjudge couldn't propose a concrete fix | `/retry` with manual hint, or run exploit.py against the live target outside the sandbox |
| `agent_error` | Main's SDK session died (SIGKILL / timeout / transport) | `/retry` — the carried work tree + fresh session usually clears transient SDK issues |
| `retry_hint_ignored` | Main returned without editing the script after a postjudge hint (a re-run would be a guaranteed-fail repeat) | `/retry` with a manual hint, or read the script + diagnosis and edit by hand |
| `unsolvable_by_analysis` | Artifacts self-admit no working chain and prejudge `flag_likelihood≈0` (confident true-negative, not a near-miss) | Read `report.md` / `chain.json` — any `verified=true` primitive is still real; `/retry` only with a demonstrably-missed primitive |
| `policy_refusal` | Main's turn was blocked by the server-side Usage-Policy classifier (AUP) — retrying in place re-blocks | `/retry` — a fresh SDK session is force-started automatically and usually sheds the poison |
| `cost_cap` | Total spend (main + subagents + reviewer calls) hit `COST_CAP_USD` — bounds a non-converging / anchored run | `/retry` (fresh start breaks an anchored frame), or raise `COST_CAP_USD` if the chal legitimately needs the spend |

Each `WHY_STOPPED.md` consolidates the judge's structured fields —
`stop_reason`, `failure_code`, `specific_diagnosis`, `what_worked`,
`what_failed`, `alternative_paths`, and the verbatim `retry_hint` —
plus the last sandbox `stdout`/`stderr` tail, so a human operator
doesn't have to reconstruct the picture from `run.log` + `meta.json`.
The `/retry` flow copies the file along with the rest of `work/`, so
the next attempt's reviewer sees the prior diagnosis as context.

### Anti-anchoring circuit breaker

A mid-run guard against the failure mode where an anchored agent keeps
grinding a frame that the evidence has already disconfirmed (e.g. an
anti-AI chal that names a known challenge to bait the "intended"
solution, then modifies one line so it no longer applies). Two mechanical
teeth in `run_main_agent_session`, both operating on the shared running
cost meter (main + every subagent + reviewer calls):

- **Cost cap (framing-independent backstop) — $40 by default.**
  `DEFAULT_COST_CAP_USD`, `.env.example`, the deployed `.env`, and Compose's
  worker environment agree on `40`. The value preserves headroom above the
  observed $30+ hard heap/kernel solves; one reviewer averages $0.19 across 28
  measured calls ($5.33 total), so reviews do not meaningfully consume that
  headroom. It still bounds the observed $131.70 non-converging lineage far
  below its eventual loss. Crossing the cap HALTS the loop with a
  recoverable `WHY_STOPPED.md` (`stop_kind=cost_cap`) so the operator can
  `/retry`, ideally fresh-start, instead of paying for more of the same. Set
  `COST_CAP_USD<=0` only as an explicit override to disable the ceiling.
- **Contrarian reframe (targeted).** When an isolated subagent returns a
  premise-refuted / dead-end signal AND the job is *easy-/shortcut-framed*
  (the operator description leans on difficulty-minimizing words) AND
  total spend is past `CONTRARIAN_MIN_COST_USD` (default **6**), the loop
  injects ONE contrarian user-turn that de-commits main from its current
  frame and points it at a genuinely independent subagent or a
  reframe/concede. One-shot per job.

Both are env-overridable. The cost cap provides the stock deployment's hard
bound; the contrarian reframe can still fire earlier and is advisory (one
injected turn). Neither guarantees a solve; the value is
*reframe-or-bound-the-loss*, not a fix.

### Fallback artifact safety net

When something stops main mid-run before it produced an artifact —
budget exhausted, SDK transport killed, an agent exception classified
`killed`/`timeout` — the
orchestrator does **not** abort the job. Instead
`write_fallback_artifacts(work_dir, log_fn, module=None)`
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
- sends the literal `help` and reads back what the server prints (both the
  banner and the follow-up land in the log via `log.info`, not bare stdout),
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
   - **Pattern B (recommended)** — `gdb -batch -x $TMPDIR/probe.py`
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

### monitor (`modules/_monitor.py`)

A live, LLM-narrated commentary feed over `run.log`. A raw run log is
~96% `TOOL` / `TOOL_RESULT` echo, so reading it live to understand "what
is the agent actually doing" means eyeballing noise. The monitor filters
`run.log` to meaningful SIGNAL events (stage/status changes, `AGENT:`
prose, subagent lifecycle, judge / prejudge / retry, errors,
`FLAG_CANDIDATE`), batches them, and asks a cheap model to narrate WHAT
JUST HAPPENED in one short line — in every configured language.

- **HYBRID.** Structured meta changes (stage / status / flag) get a
  deterministic, localized entry (no LLM); prose signal batches get an
  LLM narration.
- **Always-on.** An async supervisor started from `api.main` sweeps
  running jobs every few seconds and ensures one monitor task per job, so
  commentary is generated even if nobody is watching. It never spins a
  task for a job that is already terminal. Opt out with `MONITOR_ENABLED=0`.
- **Cheap + clean.** Pinned to `MONITOR_MODEL` (default `claude-sonnet-4-6`,
  NEVER the job's own opus). Runs in the `api` container (has SDK + auth +
  redis, free of the worker's exploit-run glibc pollution).
- **Output.** Appended to `<job>/monitor.jsonl` (each entry a `{lang: line}`
  map keyed by `MONITOR_LANGS`, default `ko,en`) and published to Redis
  `job:<id>:monitor` for the SSE stream. The UI renders it beside the raw
  run log with a language selector — switching language is instant, no
  refetch. Best-effort: every failure is swallowed and never touches
  `run.log` / `meta.json`.

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
              ▼                   • orchestrator pre/post (scoped)
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
(`mission_block()` in `modules/_prompts.py`) that tells the model up
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

### Agent providers

The loop above is provider-agnostic. `agent_provider` (Settings, or
`AGENT_PROVIDER` in `.env`) picks which backend actually runs it:

| | `claude` (default) | `grok` | `gpt` |
|---|---|---|---|
| Backend | Claude Agent SDK, `claude` CLI subprocess per peer | `grok agent --always-approve --no-leader stdio`, driven over [ACP](https://agentclientprotocol.com) | OpenAI [`codex exec --json`](https://learn.chatgpt.com/docs/non-interactive-mode) by default; direct Responses API is optional |
| Code | the SDK | `modules/grok_acp.py` | `modules/codex_cli.py` via `modules/gpt_agent.py` (`modules/gpt_responses.py` fallback) |
| Credentials | `~/.claude` bind-mount, or `ANTHROPIC_API_KEY` | `~/.grok` from `grok login`, or `XAI_API_KEY` | OAuth bootstrapped from `~/.codex/auth.json` into isolated `~/.codex-hextech` (default), or `OPENAI_API_KEY` in Responses mode |
| Default model | `claude-opus-4-7` | `grok-build` | `gpt-5.6-sol` |

#### Per-role routing (hybrid)

`agent_provider` picks the backend for the whole job. Four roles can be routed
away from it independently — **judge, reviewer, report, monitor**
(`agent_provider.ROLE_OVERRIDABLE`) — and only onto **claude or gpt**
(`ROLE_TARGET_PROVIDERS`; grok is not a routing target). Settings exposes this
as *Per-role override*, and the **hybrid** preset is the common shape: run main
on gpt while judge and reviewer stay on claude.

`provider_for_role(job_id, role)` resolves in this order:

1. `meta.agent_role_providers[role]`, **snapshotted at job create**;
2. live Settings routes — reachable ONLY when there is no `job_id` yet
   (a pre-create decision);
3. the job's own `provider_for_job(job_id)`.

For an existing job, the live **role map** is never consulted — not even when
the role key is absent. An absent key means "this job has no role routing",
never "look it up now"; otherwise a Settings edit could re-route a job that is
already running, or half-route it mid-`/retry`.

That guarantee is about the role map only, and the distinction matters. Step 3
is `provider_for_job(job_id)`, which prefers `meta.agent_provider` but falls
through to the live global `agent_provider` when meta has no stamp or cannot be
read. So a job created before that field was stamped, or whose meta is
unreadable, still picks up a live Settings change — through the BASE, not
through role routing. With an override nowhere and a stamped base, every role
resolves to exactly `provider_for_job(job_id)`, which is the pre-hybrid
behaviour a characterization gate pins over stored jobs.

Two related pieces of that work are Codex's and are described here only in
outline — see `modules/_judge.py` and `modules/usage_ledger.py` for the
authoritative behaviour: a judge/reviewer turn that comes back as a provider
**policy refusal** can fail over to the other backend rather than dying, and the
usage ledger records one row per model, keyed on provider / role / stage /
**attempt**, so a routed job's spend is attributable per backend and per retry
rather than pooled.

The default GPT runtime is Codex CLI with ChatGPT subscription OAuth. Run
`codex login` on the host, choose **Sign in with ChatGPT**, and make sure
`~/.codex/auth.json` exists. `start.sh` copies only that credential into
`~/.codex-hextech` on first use, and `HOST_CODEX_HOME` bind-mounts the isolated
directory read-write so Codex can refresh tokens and persist sessions without
changing the host TUI's `~/.codex/config.toml`, locks, or rollouts. The app never returns token
values from its status endpoint or copies them into prompts. If
`codex login status` succeeds but `auth.json` is absent because credentials
are stored in an OS keyring, set `cli_auth_credentials_store = "file"` in
`~/.codex/config.toml` and sign in again. It also removes inherited
`OPENAI_API_KEY` / `CODEX_API_KEY` from Codex child processes so OAuth cannot
silently become API-key billing. Main, pre-recon, forensic and misc phases follow the
selected provider. judge, reviewer, report and monitor follow it too **unless
routed away per role** — see [Per-role routing](#per-role-routing-hybrid).
When Compose is invoked directly without the launch scripts or an explicit
`HOST_CODEX_HOME`, its safe fallback is project-local `./data/codex-home`—it
never falls back to the live TUI directory.

Set `GPT_RUNTIME=responses` (or choose it in Settings) only when direct
usage-billed Responses API behavior is wanted; that mode requires
`OPENAI_API_KEY`. Configure the OAuth path with `AGENT_PROVIDER=gpt`,
`GPT_RUNTIME=codex`, and optionally `GPT_MODEL` / `GPT_EFFORT`.

`grok_acp.py` names its message classes after the SDK's (`AssistantMessage`,
`ToolUseBlock`, `ToolResultBlock`, `ResultMessage`, …), so
`run_main_agent_session`'s `isinstance` dispatch, the heartbeat, the live flag
scan and the judge all work unchanged on either provider.

**Parity is not complete.** An 8-lens adversarial review of the Grok path
confirmed 27 findings; three were fixed on the spot (tool results never
reaching the orchestrator, which silently disabled the live flag scan; zero
token/cost accounting, which also made `COST_CAP_USD` inert; text-only roles
running unrestricted). What a `grok` job still does **not** get:

- **No PreToolUse hooks.** `GrokSessionOptions` has no `hooks` field and the
  session runs `yoloMode` with empty `clientCapabilities`, so there is no
  in-process interception point. The read-only-source Write guard and the
  mid-turn stale-target guard are Claude-only. Only a kill-guard is installed,
  as an external hook file.
- **Global hook config.** That kill-guard is written into the operator's real
  `~/.grok/hooks` on every session start, non-atomically — so it cannot be
  scoped per role or per session, and concurrent sessions race.
- **No turn cancellation.** No `session/cancel` is ever sent, so a turn
  abandoned at a budget break keeps running while the next injection opens a
  second prompt on the same session.
- **Silent session fallback.** A rejected `session/load` starts a blank
  session, so a retry or continue can run with zero prior context and nothing
  says so.

Treat `grok` as usable-but-watched, and prefer `claude` when a run depends on
those guards. All providers share the runner, the judge, the monitor and the
whole artifact/flag pipeline.

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
(SOFT/EJECT/FINAL_DRAFT), the judge lifecycle around the
sandbox, scaffold templates keyed by glibc version + how2heap corpus
matrix, custom chal-author library auto-detection.

## Prerequisites

- Docker Engine 24+ or Docker Desktop with WSL Integration enabled
- 6+ GB free disk for tool images (Ghidra alone is ~1.4 GB)
- One of:
  - **Claude Code OAuth** (recommended): Pro/Max claude.ai subscription, run
    `claude login` once on the host so `~/.claude/.credentials.json` exists, OR
  - **Anthropic API key**: set in `.env` or via the Settings tab, OR
  - **Grok Build**: run `grok login` once on the host so `~/.grok/` exists, then
    set `AGENT_PROVIDER=grok`. See [Agent providers](#agent-providers) for what
    that path does and does not give you, OR
  - **OpenAI Codex OAuth**: run `codex login` on the host, choose ChatGPT
    sign-in, then select `AGENT_PROVIDER=gpt` (the default `GPT_RUNTIME=codex`
    uses your ChatGPT subscription rather than Platform API billing), OR
  - **OpenAI Responses API**: set `GPT_RUNTIME=responses` plus
    `OPENAI_API_KEY` when usage-based API billing is explicitly desired.

## Quick start

The repository was renamed from `HexTech_CTF_TOOL` to `Ogamdo`. GitHub keeps a
redirect, so an existing clone and its `origin` remote keep working — but the
remote still prints the old path, so update it once:
`git remote set-url origin git@github.com:Kimdo-765/Ogamdo.git`. An existing
checkout directory does not need renaming; nothing reads the project name off
the filesystem.

```bash
git clone git@github.com:Kimdo-765/Ogamdo.git && cd Ogamdo
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
   | `WORKER_CONCURRENCY` | `3` | **legacy / ignored.** Parallel jobs is the number of `worker-N` services in `docker-compose.yml`; each slot runs exactly one. Kept only for a pre-split compose file. |
   | `JOB_TTL_DAYS` | `7` | auto-delete jobs older than N days (`0`=keep) |
   | `JOB_TIMEOUT` | `900` | **not a deadline** — only scales RQ's hard ceiling (`×4`, floor 24 h, cap 7 d). See [Timeouts](#timeouts) |
   | `WORKER_SLOT_MEM` | `4g` | cgroup cap on **each** worker slot container. `4g × 2 slots = 8g`, the same whole-worker budget the single container had. Also editable live from Settings (a change there applies to every slot via `docker update`, no restart) — where it is refused if `slots × value` exceeds 70 % of VM RAM, or if it would leave a running job no headroom. A 15 GB `python3` once froze the whole WSL VM with no cap. **Renamed from `WORKER_MEM_LIMIT`, deliberately**: that key meant "cap for the ONE worker" and held `8g`, so reusing it would have reinterpreted 8g as *per slot* and pushed 16 GiB of cap into a 15.99 GiB VM on the next settings save. **Since `5570961` this is the BASE, not the last word**: every job start re-applies it via `docker update` (idempotent — it heals a slot an earlier run left raised), and with `dynamic_worker_mem` ON the governor may raise it to `base × 2` for `rev`/`crypto`, or after a cgroup OOM (1.5× per kill, at most twice, never past `base × 4`). See [Concurrency](#concurrency). |
   | `AGENT_PROVIDER` | `claude` | which agent backend runs jobs: `claude`, `grok`, or `gpt`. See [Agent providers](#agent-providers) |
   | `GROK_MODEL` / `GROK_EFFORT` | `grok-build` / empty | model + reasoning effort used when `AGENT_PROVIDER=grok` |
   | `GPT_RUNTIME` | `codex` | `codex` = Codex CLI + ChatGPT OAuth; `responses` = direct Platform API-key billing |
   | `OPENAI_API_KEY` | empty | only used when `GPT_RUNTIME=responses`; never passed to the Codex OAuth subprocess |
   | `GPT_MODEL` / `GPT_EFFORT` | `gpt-5.6-sol` / `medium` | model + reasoning effort used by Codex CLI (or the optional Responses backend) |
   | `HOST_CODEX_HOME` | `./data/codex-home` | Ogamdo-only Codex auth/session directory, bind-mounted rw into api + workers. `start.sh` bootstraps only OAuth from the host TUI's `~/.codex/auth.json`; keeping the homes separate prevents root containers from breaking the live TUI's `config.toml` ownership. |
   | `HOST_GROK_HOME` | `${HOME}/.grok` | host path of the Grok Build config, bind-mounted into api + worker. **Pin it explicitly.** A snap-confined `docker` CLI reports `HOME` as `~/snap/docker/<rev>`, so `docker compose up -d` through `/snap/bin/docker` resolves the default to an empty directory and silently mounts that — the worker then has no `grok` binary and no auth, with no error anywhere. (`docker compose restart` keeps the old mount, so only a *recreate* exposes it.) Same reason `HOST_CLAUDE_HOME` is pinned. |
   | `WEB_PORT` | `8000` | host port |
   | `GHIDRA_VERSION` / `GHIDRA_BUILD_DATE` | `12.0.4` / `20260303` | Ghidra release used by decompiler image |
   | `ANTHROPIC_API_KEY` | empty | leave empty for OAuth |
   | `AUTH_TOKEN` | empty | shared token; empty = no auth (dev) |
   | `HOST_CLAUDE_HOME` | `${HOME}/.claude` | host path of Claude Code config |
   | `CLAUDE_CODE_MAX_OUTPUT_TOKENS` | `999999` | per-turn SDK output cap (the model's own ceiling, ~64k for Sonnet/Opus, becomes the effective limit) |
   | `INVESTIGATION_BUDGET` | `150` | tool-call budget for the main agent. At 80% (`SOFT_EJECT`) the orchestrator injects a "finalize now" user-turn; at 100% it triggers `FINAL_DRAFT` last-chance, then falls back to a probe-only skeleton via `write_fallback_artifacts` so sandbox + postjudge still runs. `0` disables. |
   | `ENABLE_JUDGE` | `1` | legacy boolean behind `judge_mode`. When the effective mode gates, wraps an `auto_run` execution with **two** judge stages (pre / post) — the stall-detection stage is excluded and never runs. Gating is per module: `enforce` covers pwn and web; everything else records instead. Set to `0` to skip judge calls entirely. See [judge](#judge-modules_judgepy). |
   | `AUTO_RETRY_MAX` | `-1` | postjudge-driven inline retries within a single job. `0` disables the loop (legacy fire-and-forget). Positive int caps at exactly N retries on top of the initial run. `-1` / `inf` / `unlimited` lets the loop run until natural exit (success, no actionable hint, error, user Stop, timeout). See [auto-retry triangle](#auto-retry-triangle). |
   | `USE_ISOLATED_SUBAGENTS` | `1` | when `1` (default), main delegates via the MCP tool `mcp__team__spawn_subagent` — each subagent runs in its own `claude` CLI subprocess and only the final-text reply lands in main's history. Set to `0` for the legacy in-process `agents={}` path (kept as a fast rollback). See [Subagent isolation](#subagent-isolation-default-on). |
   | `SUBAGENT_SPAWN_CAP` | `0` | **inert — nothing reads it.** The name appears in `.env` and in prompt text shown to the model (`modules/_prompts.py`), but no code path consults it: the guard the comments name, `_maybe_subagent_cap()`, has no definition in the repo. Setting a positive int changes nothing. Delegation is unbounded in practice — see [Spawn cap — not implemented](#subagent-isolation-default-on). |
   | `ENABLE_EXPLOIT_LIBRARY_HINT` | `0` | when `1`, every job's user prompt is prepended with a short paragraph listing same-module entries from the operator-curated [Exploit Library](#exploit-library) at `/data/exploits/`. OFF by default — flip on once the library has curated entries you trust. |
   | `COST_CAP_USD` | `40` | total-spend circuit breaker (main + subagents + reviewer calls). On breach the run halts recoverably (`stop_kind=cost_cap`, `/retry`-able). Set `0` or a negative value only to disable it explicitly. See [circuit breaker](#anti-anchoring-circuit-breaker). |
   | `CONTRARIAN_MIN_COST_USD` | `6` | minimum total spend before a subagent dead-end signal can arm the one-shot contrarian-reframe user-turn (only on easy-/shortcut-framed jobs). See [circuit breaker](#anti-anchoring-circuit-breaker). |
   | `MONITOR_ENABLED` | `1` | live per-job [monitor](#monitor-modules_monitorpy) narration feed. `0` disables the always-on supervisor and all narration. |
   | `MONITOR_MODEL` | `claude-sonnet-4-6` | cheap model pinned for monitor narration — never the job's opus. |
   | `MONITOR_LANGS` | `ko,en` | comma-separated languages the monitor narrates each signal batch in (the UI picks which to show). |
   | `DYNAMIC_WORKER_MEM` | `0` | lets the memory governor raise a slot's cgroup cap to `base × 2` for `rev` / `crypto` jobs, and again after a real cgroup OOM (1.5×, at most twice, capped at `base × 4`). OFF by default; the per-job sampler runs either way. Normally set from Settings rather than here — the key ships in neither `.env` nor `.env.example`. See [Concurrency](#concurrency). |

2. **Settings tab** in the UI — writes to `/data/settings.json`, overrides
   `.env` without restart. Since `10e3208` it is **six sections behind a
   vertical menu**, not one flat page: *Agent & routing* · *Providers &
   models* · *Model presets* · *Judge & hints* · *Jobs, workers & spend* ·
   *Access, callbacks & tunnel*. They are panes of ONE `<form>` with ONE Save,
   shown and hidden by class — so a Save posts every section, including edits
   in a pane that is off-screen. Per-pane dirty dots show which hidden section
   holds unsaved edits; Reload asks for confirmation because it discards edits
   in every section, not just the visible one; the form is `novalidate` with a
   manual `checkValidity()` so an invalid control in a hidden pane cannot make
   Save a silent no-op. The Save footer hides on *Model presets*, which has its
   own Save writing `model_presets.json`. Two readouts refresh only when their
   pane is opened (tunnel status on *Access*, live worker memory on *Jobs,
   workers & spend*), so a stale number on a pane you have not visited is
   expected, not a bug. The chosen section persists in `localStorage`. Oracle:
   `scripts/test_settings_sections_ui.js`.

   What it overrides: Anthropic API key, Claude model + effort, Auth token,
   Job TTL, Job timeout, Callback URL, **Spend budget (USD)**, **Judge mode**
   (`off` / `shadow` / `enforce` — the old **Enable judge** checkbox is gone;
   the boolean is derived from the select on save), **Use Exploit Library
   hints**, **Agent provider** (`claude` / `grok` / `gpt`) with its per-role
   provider overrides and the Grok/GPT key + model + effort fields, **Worker
   memory limit**, and **Dynamic per-slot memory** (see
   [Concurrency](#concurrency)). **Worker concurrency is displayed read-only
   and the input is `disabled`** — the worker forces it to 1 and logs that it
   ignored the stored value; parallelism is the slot COUNT. The memory limit is
   applied live via `docker update` — no restart.
   without restart for: Anthropic API key, Claude model, Auth token, Job TTL,
   Job timeout, Worker concurrency, Callback URL, **Spend budget (USD)**,
   **Enable judge**, **Use Exploit Library hints**, **Agent provider**
   (`claude` / `grok` / `gpt`) and **Worker memory limit**. It also hosts the
   **Model presets** and **Cloudflared tunnel** panels (below).
   (Concurrency is the slot COUNT — edit `docker-compose.yml`. The memory
   limit is applied live via `docker update` — no restart.)

Precedence: `settings.json` > `.env` > defaults.

### Model presets (`/data/model_presets.json`)

**Settings → Provider model presets** stores several NAMED per-agent presets.
Claude, Grok, and GPT each have an independent preset collection and active
selection; changing the job provider automatically uses that provider's active
preset. They live outside `settings.json` because the flat
`(key, env, type, default)` SCHEMA in `modules/settings_io.py` cannot hold a
nested structure. Configurable slots, in UI order:

| Slot | Drives | Blank = inherit |
|---|---|---|
| `main` | the CTF agent itself | per-job pick → provider global model (`claude_model` / `grok_model` / `gpt_model`) → provider default |
| `judge` | prejudge / postjudge, **and** the `judge` peer subagent | orchestrator stages follow main; the subagent falls back to `LATEST_JUDGE_MODEL` |
| `reviewer` | the `/retry` + `/resume` hint writer ONLY | the `judge` slot, then main |
| `recon` / `debugger` / `triage` | peer subagents | the spawner's model (main) |
| `report` | terminal `findings.json` transform | main |
| `monitor` | live narrator | `MONITOR_MODEL` |
| `effort` | reasoning effort of the MAIN session — a sibling key, not a role | per-job `effort` → provider global effort → SDK/CLI default |

An explicit per-job model/effort still wins over the preset, and with no
active preset every resolver is byte-identical to the pre-preset behaviour.
`GET/PUT /api/model-presets`; the v2 PUT replaces the whole provider store (the
UI edits client-side, then PUTs). Existing flat v1 files are migrated by their
recognizable model family (falling back to the provider selected in Settings
for inherited/custom-only presets), and legacy PUT requests update only the
selected provider without deleting the others. Changes apply to the NEXT job.

> The UI warns that pinning `recon`/`debugger`/`triage` off main's model
> costs prompt-cache alignment. That rationale belongs to the LEGACY
> in-process path (`USE_ISOLATED_SUBAGENTS=0`); on the default isolated path
> each subagent is already a separate CLI subprocess with its own system
> prompt, so there is no shared prefix to lose.

**Model catalog.** Preset dropdowns use the selected provider's catalog:
`CLAUDE_MODELS`, `GROK_MODELS`, or `GPT_MODELS` in `web-ui/app.js`. The Claude
catalog includes Opus 5 / Fable 5 / Sonnet 5, Opus 4.8/4.7/4.6/4.1, Sonnet
4.6/4.5, Haiku 4.5, dated snapshots, and supported `[1m]` variants.
**Adding a model is a one-line edit in the matching provider array;
there is no server-side allowlist** (the upload routes take `model` as a
free-form string and Settings filters by key, not value), and a Settings
free-text field accepts a custom id. Entries are added only after a real
round-trip on this deployment's plan — Sonnet 4.x / Haiku `[1m]` are
deliberately absent because they answer *"Usage credits are required for
long context requests"* here.

### Usage widgets

The top bar shows a budget pill plus provider usage chips, all best-effort:

- **Budget pill** — `budget_usd` from Settings vs summed job spend
  (`GET /api/jobs/usage`). Purely informational: **nothing enforces it**
  (the separately configured `$40` cost cap is the enforcement mechanism).
  Reviewer ledger dollars are added as a role-only subtotal instead of summing
  the entire ledger and duplicating main rows; `spent_usd_complete=false`
  remains visible when a terminal main job or reviewer has no authoritative
  dollar figure (for example Codex OAuth).
- **Claude quota chip** — actively polls the mounted Claude Code OAuth
  account's five-hour / seven-day usage, showing the most constrained ordinary
  window and caching the sanitized result in `/data/rate_limit.json` for 15
  seconds. API-key-only setups fall back to the SDK's passive `RateLimitEvent`.
- **Grok quota chip** — polls the mounted SuperGrok OAuth account's weekly
  billing pool and caches the sanitized result for 60 seconds. Failed refreshes
  remain visible as `stale` rather than presenting old quota as current.
- **Codex quota chip** — asks Codex CLI app-server for the mounted ChatGPT
  OAuth account's rate-limit windows, then displays the most constrained
  ordinary Codex window as `⏳ Codex 94% left · resets 6d21h`. The sanitized
  response is cached in `/data/codex_rate_limit.json` for 15 seconds; OAuth
  tokens and raw auth data never enter the API response.

## Authentication options

- **Claude Code OAuth** (default): host's `~/.claude/` is bind-mounted into the
  worker (rw) and api (ro). The bundled `claude` CLI uses the existing OAuth
  token from `claude login`. Settings tab shows `✓ Claude Code OAuth detected`.
- **Anthropic API key**: paste into Settings → Anthropic API Key (or set
  `ANTHROPIC_API_KEY` in `.env`). Overrides OAuth when present.
- **Grok Build** (when `agent_provider=grok`): host's `~/.grok/` is bind-mounted
  into worker + api and `/root/.grok/bin` is put on `PATH`, so the credentials
  from `grok login` are used directly — no key in `.env`. Settings shows the
  detected state, and the top bar carries a rate-limit chip fed by the billing
  proxy (`/data/grok_rate_limit.json`).
- **OpenAI Codex OAuth** (default GPT runtime): host login stays in
  `~/.codex/`, while worker + api mount an isolated `~/.codex-hextech/` rw.
  `start.sh` imports only `auth.json` on first use. Run `codex login` on the host;
  Settings shows `✓ ChatGPT OAuth ready`, and the top bar reads the remaining
  Codex subscription window through the installed CLI app-server.

UI access can additionally be gated by a shared **Auth Token** (`/login`,
cookie-based). Empty = no auth (dev mode).

## Concurrency

The worker is **N containers, one per slot** (`worker-1`, `worker-2`, ...),
each running a single RQ worker subscribed to the same Redis queue. Jobs
distribute automatically. The Settings field is read-only, because
`worker/runner.py` forces concurrency to 1 whenever `WORKER_SLOT` is set:
parallelism IS the number of `worker-N` services in `docker-compose.yml`.

**Change it with `scripts/worker-slots.sh`**, not by hand:

```bash
./scripts/worker-slots.sh              # current slots, caps, and what fits
./scripts/worker-slots.sh set 3        # change and apply
./scripts/worker-slots.sh set 3 --dry-run
```

Editing the file and running `docker compose up -d` yourself is the one path
that can over-commit the VM, and it walks past four separate guards:

- **the budget gate never runs.** The 70 % ceiling lives in `PUT /api/settings`
  and gates `docker update`; compose sets `mem_limit` at container CREATE and
  never reaches that code. On a 16 GB VM, 3 slots × 4g is 12 GiB against a
  10.93 GiB ceiling — the state that froze WSL on 2026-07-29 and 08-01. The
  script refuses by default and prints the cap that would fit.
- **`start.sh` exports the home mounts.** A bare `up` leaves
  `HOST_CODEX_HOME` / `HOST_CLAUDE_HOME` / `HOST_GROK_HOME` unset, which mounts
  an empty Codex home and kills every GPT job on a missing login.
- **`docker-compose.override.yml` grants `/dev/kvm`**, and `start.sh`
  regenerates it from the worker services it finds. A hand-added slot silently
  has none, and kernel-pwn jobs that land there lose KVM.
- **shrinking leaves an ORPHAN.** `up -d` does not delete a vanished service:
  the container keeps running, keeps its cgroup cap, and keeps an RQ
  registration nobody sweeps, since each slot only sweeps its own
  `htct-s<N>-w*` prefix. (The key does expire on its own — measured TTL 364 s —
  but until it does, the UI and `restart.sh` both count a worker that is gone.)

The script does each of those, then verifies: per-slot state, `WORKER_SLOT`,
cap with `memswap` equal, Codex auth mounted, RQ registration, and that the
container count matches the slot count with no orphan left.

The UI header shows `<busy>/<total> workers · <queued>` in real time.

**Why slots and not one container with N processes:**

| | shared container | per-slot containers |
|---|---|---|
| memory bound | one cgroup over the SUM of jobs; a heavy job starves the others | one cgroup per job |
| PID isolation | `ps` sees every concurrent job's processes, and every orphan they left | a job sees only its own |
| deploy | restarting the worker kills every in-flight job | `deploy.sh` restarts only the idle slots |

`rq.Worker` already forks a work horse per job, so process isolation *within* a
job was never the gap. The gap was that when the horse exits, everything the
agent spawned (wine, Xvfb, bash, python3) is reparented to PID 1 and never
reaped — 29 zombies out of 42 processes, measured 2026-08-02 — and those
leftovers stay visible to the NEXT job in that container. Job `fd844946db78`
ran `ps | awk | kill -9` and killed its own `claude` CLI. `init: true` (tini as
PID 1) reaps the orphans; slots stop a job from seeing a concurrent job's.

**Sizing.** `WORKER_SLOT_MEM` × slot count must fit the VM alongside the
challenge containers, which are SIBLING cgroups (`worker/docker_memguard.sh`,
`CHAL_CONTAINER_MEM` = 2g each) and are *not* charged to any slot. On a 16 GB
VM that is 2 slots × 4g. A single heavy pwn job peaked at 3222 MiB, so 4096
clears it; an even 3-way split of 8g would not have. `memswap_limit` is pinned
EQUAL to `mem_limit` at all three places the cap is set
(`docker-compose.yml:130-131`, `api/routes/settings.py:236`,
`modules/worker_mem.py:308`): with `mem` alone Docker permits swap up to 2× the
cap, and slow swap thrash is the state that wedged the VM on 2026-07-29 and
2026-08-01. A hand-rolled `docker update --memory` without `--memory-swap`
reintroduces exactly that.

**Per-slot memory is measured on every job and moved on none of them by
default** (`modules/worker_mem.py`, wired at `worker/runner.py` by overriding
`rq.Worker.execute_job` — the parent process, so the bracket survives the work
horse being SIGKILLed).

- A **sampler** runs unconditionally, flag or no flag. It polls the slot's own
  cgroup every 5 s into `data/jobs/<id>/worker_mem.jsonl` and merges
  `{peak_bytes, oom_kill_delta, cap_bytes}` into `meta.worker_mem` at the end.
  That is the evidence to size `WORKER_SLOT_MEM` from — and it is the one
  artifact the TTL sweep does NOT promote to `data/job-measurements/`
  (`MEASUREMENT_ARTIFACTS`, `worker/runner.py:19`), so copy it out first.
- Every job start also re-applies the slot's **base** cap via `docker update`,
  flag or no flag. Idempotent; its job is to heal a slot an earlier run left
  raised. So the worker now needs the docker socket and the `docker` SDK for a
  normal start, and says `[worker-mem] cap not applied: …` when it has neither.
- A **governor** changes the cap only when `dynamic_worker_mem` is ON (default
  OFF). It wants `base × 2` for `rev` / `crypto` — a MULTIPLE of the operator's
  setting, so lowering the base lowers the expansion with it. A fixed
  `max(base, 8 GiB)` floor used to ignore the base entirely below 8 GiB, which
  meant setting slots to 2g moved rev and crypto not at all. `web` was removed
  from this list on 2026-08-25; it now starts at the base and can only reach
  more through the OOM ladder, which needs BOTH escalations to pass 4 GiB from
  a 2g base. pwn is deliberately absent: every pwn OOM in the 88-job census was the QEMU guest or
  the target binary, neither of which lives in the slot's cgroup. Each change
  is taken under one flock at `/data/.worker-memory.lock` and gated on
  `sum(other slots' caps) + want ≤ 70 % of VM RAM` and on
  `want ≥ unreclaimable × 1.5`.
- **That precondition is now met.** On the 16 GiB VM this feature could only
  write refusals: 70 % was 10.93 GiB and the other slot's 4 GiB plus a wanted
  8 GiB was 12.00 GiB, so it never applied anything. `.wslconfig` went to
  `memory=80GB` on 2026-08-25 (the physical 96 GB was invisible until that
  line changed), and the VM is 78.5 GiB with 12 slots. 70 % is 54.98 GiB;
  twelve slots at a 2g base is 24 GiB, and expanding one to 4 GiB asks for
  26 GiB. The gate now ALLOWS the common case rather than refusing it — even
  all twelve at 4 GiB (48 GiB) fits. Note the sum walks
  `containers.list(all=True)` and reads `HostConfig.Memory`, so a STOPPED slot
  still counts against the budget.
- On a real cgroup OOM the escalator raises the cap 1.5×, at most
  `MAX_ESCALATIONS = 2` times, and **never past `base × MAX_CAP_FACTOR` (4)**.
  That absolute ceiling exists because the step count does not bound the
  maximum on its own: the ladder starts from the slot's CURRENT cap, and an
  expansion module already starts at `base × 2`, so from a 2g base it ran
  4 → 6 → 9 GiB — `base × 4.5`, a number nobody chose. It is clamped to 8 GiB
  now. A non-expansion module (2 → 3 → 4.5) never reaches the ceiling. The
  counter increments only on an APPLIED change
  (`modules/worker_mem.py`), so a step refused by the budget gate is retried on
  the next OOM rather than consuming the allowance.
- The end-of-job **restore** goes through the same shrink floor, so a slot
  whose unreclaimable footprint is still large refuses to shrink and logs
  `[worker-mem] cap NOT restored to base (…) — the next job's start will heal
  it`. Between two jobs a slot can legitimately be bigger than you believe,
  and that one line is the only symptom.

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

### Hybrid parent/child lifecycle

A hybrid chain has one public `module=hybrid` parent and up to two scalar
children marked by the conjunction `internal=true`, `parent_job_id`, and an
integer `hybrid_stage`. `GET /api/jobs` and `/stats` hide those internal
children. Their cost is projected onto the parent once, while the parent detail
shows each stage's module, child id, live/terminal status, cost, and canonical
`stage_flag_evidence` provenance.

Stop cascades from a running/queued parent to every active validated child.
The deletion policy is deliberately stronger: deleting a hybrid parent stops
active children and then deletes **all** validated linked child directories;
the parent's separately stored upload is deleted too, and no internal child
artifact is retained implicitly. A forged stage id is not
authority to stop or delete another job—the child metadata must point back to
the same parent, stage, and module. Parent Retry/Continue/Resume controls stay
hidden until parent retry is translated to a scalar stage; the scalar retry API
continues to reject `module=hybrid`.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | health probe |
| GET | `/api/modules` | module catalog |
| GET | `/api/jobs` | list all jobs |
| GET | `/api/jobs/{id}` | job meta |
| GET | `/api/jobs/{id}/log[?tail=N]` | run log (text). `?tail=N` returns only the trailing N bytes (newline-aligned, used by the polling UI). |
| GET | `/api/jobs/{id}/stream` | Server-Sent Events: live multiplex of `log` (every run.log line), `meta` (status / flag / token+turn deltas), and `sdk` (raw assistant blocks: text / thinking / tool_use / tool_result). On connect: replays current meta + the last ~256 KB of run.log marked `backfill:true`, then streams new events. 15 s `: ping` heartbeats; auto-closes on terminal status. Cookie/token auth via the standard middleware. |
| GET | `/api/jobs/{id}/monitor[?tail=N]` | curated [monitor](#monitor-modules_monitorpy) feed — the filtered, LLM-narrated signal entries from `<job>/monitor.jsonl`. Each entry carries a `text` map keyed by language, so the client switches language with no refetch. `?tail=N` returns only the last N. |
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
| POST | `/api/modules/web3/analyze` | upload contract sources → enqueue |
| POST | `/api/modules/hybrid/analyze` | upload a chained challenge → enqueue one public parent + up to two `internal=true` children (see [Hybrid parent/child lifecycle](#hybrid-parentchild-lifecycle)) |
| POST | `/api/modules/live-fire/analyze` | live-fire patch loop |
| POST | `/api/modules/pwn/analyze` | upload binary → enqueue |
| POST | `/api/modules/forensic/collect` | upload disk/memory image → enqueue |
| POST | `/api/modules/misc/analyze` | upload file → enqueue |
| POST | `/api/modules/crypto/analyze` | upload zip → enqueue |
| POST | `/api/modules/rev/analyze` | upload binary → enqueue |
| POST | `/api/jobs/{id}/run` | re-run produced exploit/solver in a fresh sandbox |
| PATCH | `/api/jobs/{id}/target` | update only `target_url` (+ `target_urls`) on the job's meta — no retry, no resume, no new job. Body `{"target": "<new>"}` (newline/comma-separate for several; use `(none)` or `""` to clear). The next manual `/run` (and the default of any future `/retry`) picks up the new value. Audit-logged to `run.log`. |
| POST | `/api/jobs/{id}/retry` | regenerate the job. JSON body fields all optional: `hint` (skip reviewer if present), `target` (override prior target_url; newline/comma-separate for several; sentinel `(none)` clears it), `challenge_secret_key` + `challenge_secret_value`. Empty body = auto reviewer + keep prior target. Returns **409 `stop_ack_timeout`** if the source job's Codex turn has not released its lock — no successor job is created, so a retry that 409s has changed nothing. |
| POST | `/api/jobs/{id}/retry/stream` | same as `/retry` but Server-Sent Events stream the reviewer text live |
| POST | `/api/jobs/{id}/resume` | hard-stop a queued/running job, then enqueue a fresh one with the same body shape as `/retry`; `hint` required here. Carries `./work/` + forks the prior SDK session. |
| POST | `/api/jobs/{id}/resume/stream` | SSE-streamed resume. With `{"hint":"…"}` works exactly like `/resume`. With an empty body, calls the reviewer to write the hint first. Both modes carry `./work/`, fork the prior session, and prepend the `[RESUMING]` preamble. |
| POST | `/api/jobs/{id}/continue` | continue a finished job IN PLACE (same job id / cwd / work tree / SDK session) with an operator note. Body `{"comment": "...", "target?": "..."}` — `comment` required. NOT a retry: no new job, no re-investigation. The note is folded in as priority guidance; the optional `target` updates `meta.target_url`. 409 if the job is still active (use Stop & resume instead). |
| POST | `/api/jobs/{id}/stop` | halt a running/queued job WITHOUT deleting it — flips status to `stopped`, keeps the record + `./work/` so you can inspect, `/retry`, or `/resume` afterward |
| POST | `/api/jobs/{id}/timeout/{continue,kill}` | **dead.** The soft deadline they acknowledged was removed in `3a06349`; nothing sets `awaiting_decision` any more, so these are unreachable no-ops kept only so an old bookmark 404s instead of 500s. See [Timeouts](#timeouts) |
| POST | `/api/exploits/save` | copy a finished job's `report.md` + `exploit.py`/`solver.py` into the operator-curated library. Body `{"job_id": "...", "tags": [...], "notes": "...", "overwrite": true}`. Refuses jobs with no captured flag |
| GET | `/api/exploits[?module=&tag=&search=]` | list library entries (filterable by module / tag / chal-substring / technique-substring / notes-substring) |
| GET | `/api/exploits/{id}` | one entry's meta + file list |
| GET | `/api/exploits/{id}/file/{name}` | download `report.md` / `exploit.py` / `solver.py` / `solver.sage` |
| DELETE | `/api/exploits/{id}` | remove an entry |
| GET | `/api/exploits/export` | stream the entire library as a single `.tar.gz` for cross-machine transport |
| POST | `/api/exploits/import` | restore entries from a `.tar.gz` produced by `/export`. Multipart: `file=<archive>`, `mode=skip\|overwrite` (default `skip`). Returns per-entry imported/skipped/rejected counts |

## File layout

```
Ogamdo/
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
│   ├── worker_mem.py    # per-slot cgroup sampler + governor + OomEscalator
│   ├── job_secrets.py   # challenge-credential store + exact-value redaction
│   ├── codex_turn_guard.py  # inherited flock + stop fence for Codex turns
│   ├── storage.py
│   ├── hybrid/          # parent that fans out to two hidden children
│   ├── web3/            # SYSTEM_PROMPT + analyzer.run_job (full loop module)
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
├── scaffold/            # /opt/scaffold/ exploit templates, baked into the
│                        #   worker image
├── scripts/             # operator tools (job-status.sh, sim_worker_mem.py)
│                        #   AND the oracle suite — ~70 files, mostly
│                        #   test_*.py / test_*.js
└── data/                # job uploads + outputs (gitignored)
    ├── .worker-memory.lock  # slot-wide flock; the memory budget is a
    │                        #   VM-wide resource, so it cannot live in
    │                        #   any one job's work dir
    ├── job-secrets/<id>.json   # challenge credential, 0600 under a 0700
    │                           #   dir — a SIBLING of jobs/, on purpose
    ├── job-measurements/<id>/  # TTL-sweep promotion: events.jsonl,
    │                           #   meta.json, run.log ONLY
    ├── uploads/                # parent-job uploads (hybrid keeps its here)
    ├── jobs/<id>/
    │   ├── meta.json    # status + tokens + cost (+ worker_mem,
    │   │                #   operator_stop_audit)
    │   ├── run.log      # timestamped agent transcript
    │   ├── result.json  # final summary (post-judge) — deliberately NOT a
    │   │                #   flag-scan input
    │   ├── worker_mem.jsonl  # one cgroup sample every 5 s, EVERY job,
    │   │                     #   flag or no flag. Not in the measurement
    │   │                     #   promotion list — copy it out before the
    │   │                     #   TTL deletes the job dir.
    │   ├── bin/ src/    # upload (per module — zips auto-extracted)
    │   └── work/        # agent cwd — exploit.py, report.md, …
    │       ├── .codex-turn.lock        # held for the Codex CLI's whole
    │       │                           #   lifetime; the fd is inherited
    │       │                           #   so killing the horse can't
    │       │                           #   fake a release
    │       ├── .codex-stop-requested   # fence. Durable on purpose — a
    │       │                           #   stale one makes EVERY future
    │       │                           #   Codex launch for this job
    │       │                           #   raise. Only /continue clears it.
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

### 🐳 Docker challenge (opt-in: every module — web / pwn / rev / crypto / misc / forensic / web3, and per-stage on hybrid)

Some challenges ship their own `Dockerfile` and only behave correctly inside
it. Job `d8c717ba5b03` shipped one plus a README saying *"This binary must be
executed in a Docker container"* — and the agent never ran it: it did a
static-only reconstruction, called it *provably correct* from PNG chunk CRCs,
and conceded. Running the challenge's own container shows the binary REJECTS
that reconstruction.

Ticking **🐳 Docker challenge** on any module form that offers it sets
`meta.docker_challenge`, which:

1. **deterministically detects** a bundled `Dockerfile` / compose file —
   scanning the job-dir top level plus `bin/`, `src/` and `work/chal/`, with
   scratch dirs pruned. The scope is deliberate: misc/forensic run their
   collector with `--out /job` BEFORE the prompt is built, so a recursive scan
   would happily present a Dockerfile **carved out of the evidence image** as
   the challenge bundle. `work/chal/` is the one exemption from that pruning —
   it is where pwn's autoboot unpacks the operator's own archive, so without it
   a ticked box answered *"found NOTHING"* about a bundle that shipped one
   (job `b914889c1f9c`). The rest of `work/` stays pruned;
2. injects build/run mechanics with the correct build context, an *"ENTRYPOINT
   usually needs the RIGHT input"* note (running is agent-driven — a blind run
   rarely yields a flag), and a **VERIFY, DON'T ASSUME** rule: a static
   derivation is not a confirmation until the container accepts it;
3. tells the agent **how to reach the container from the worker**, which is
   not obvious and cost job `1ede2b4d8ac3` several turns: you run inside the
   worker while the docker daemon is the HOST's, so `-p 127.0.0.1::8080`
   publishes on a loopback that is not yours, the container's own bridge IP is
   on a different network, and `docker top`'s host pids do not exist in your
   PID namespace. The working recipe — publish with `-p 8080`, read it back
   with `docker port`, connect to the default-route gateway from
   `/proc/net/route`, inspect with `docker exec` — is in the stanza, together
   with the three dead ends, because an agent told only the working route still
   tries `127.0.0.1` first;
4. arranges for `reap_chal_containers` to run at job start **and** in a
   `finally`, so a container the agent spins up cannot orphan. Gating differs
   by module and it is worth knowing which: **pwn** reaps only when the flag is
   set (`modules/pwn/analyzer.py:2514`), while **web** reaps
   unconditionally (`modules/web/analyzer.py:499`, `:551`) — its prompt can
   start a container with the box unticked, so a flag-gated reap there would
   leave exactly the orphan this exists to prevent. The reap itself also
   consults the `reap_job_containers` setting (`modules/_common.py:1109`).

Unticked, the helper returns `""` and nothing changes.

`web` used to be excluded, because its own prompt already has a RUN THE
CHALLENGE LOCALLY section with real commands. It stopped being excluded in
`51e732f` — the commit immediately before this README's last write, so this
paragraph was stale the day it was written. Web keeps that always-available
guidance when the box is off; ticking it makes BUILD + RUN mandatory, the same
as everywhere else. **pwn used to be excluded on the same
belief, and that belief was false** — pwn's Dockerfile guidance was almost
entirely about READING one for sysctl / deploy context. It joined the opt-in on
2026-08-09, and the reason is specific to pwn: `chal-libc-fix` stages the
challenge's glibc so the binary runs against the right libc VERSION, but it
does not reproduce how that libc is MAPPED. Measured on the same binary and
host kernel, libc came out 2 MiB-aligned 5/5 under the staged libs and NOT
aligned 5/5 inside the challenge's own image — and an exploit's whole
probability model can rest on exactly that.

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
- **Sandbox timeout is 3000 s** (not the 300 s default): a bot fetch + OOB
  callback settle, a multi-request chain, or a rate-limited brute force
  routinely outlast 300 s. It's a ceiling — a fast solve exits immediately.
- **Local end-to-end test.** When the challenge ships a Dockerfile, the
  web module can spin the challenge itself in a local sibling container
  (the worker has the docker socket) for full environment fidelity and a
  true end-to-end exploit run, tearing it down afterward.
- Worker browser + discovery tooling (`9a5f496`): `chromium` with a
  version-matched `chromium-driver` (so selenium needs no matching dance) —
  **callers must pass `--no-sandbox`**, there is no user namespace in the
  container — plus `ffuf` and `dirb`'s `/usr/share/dirb/wordlists/common.txt`.
  `ffuf` and `seccomp-tools` are installed best-effort (WARN-masked), so a
  build behind a blocked network ships WITHOUT them and still succeeds; the
  build log (`ffuf OK …` vs `[WARN] ffuf unavailable`) is the only way to tell.
  `wabt`/`wasm2wat` is there too, for the misc/rev wasm cases.

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
  `pwn checksec`, `seccomp-tools` (dump a filter instead of reading BPF by
  hand) and `keystone-engine` (assemble at runtime without shelling to `as`).
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
    `key_bypass_needed()` / `assert_techniques_match()` — auto-
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
  `gdb-multiarch -nx -batch -ex 'set arch aarch64' -ex 'target remote
  :1234' -ex 'b *0x...' -ex 'continue' …` — the debugger subagent
  uses this pattern to break/inspect inside QEMU-user without a
  full system VM. **Always pass `-nx` to a batch gdb**: `/etc/gdb/gdbinit`
  auto-loads GEF and the banner lands ahead of what you asked for, which a
  `| head -60` then eats. Use `gdb-clean` — or
  `GDB_BIN=/usr/bin/gdb-multiarch gdb-clean` for a foreign arch — when you
  do want GEF's commands without its banner.
- **JS-engine bundles (V8 / d8)**: a browser-pwn drop is staged as a unit, not
  as a pile of loose ELFs. `d8` resolves `snapshot_blob.bin` relative to
  **argv[0]'s directory** — not the cwd, and not through a symlink — so a bare
  copy of the shell cannot start at all. The pwn analyzer detects the bundle
  (anchored on `snapshot_blob.bin`), keeps the shell beside its runtime data,
  ignores build tooling and vendored trees when electing which binary is the
  shell, splits a supplied `.patch` into its engine-source part and the rest,
  and reaps stray engine processes on exit. See `_js_engine_dir` /
  `_pick_js_engine` in `modules/pwn/analyzer.py`.

### Forensic
- Auto-detects qcow2 / vmdk / vhd / vhdx / e01 / raw / memory / **log**.
- E01 is converted to raw via `ewfexport`; vmdk/qcow2/vhd via `qemu-img`.
- Memory dumps run a curated Volatility 3 plugin set per detected OS in the
  `forensic` sibling image.
- **The worker itself now carries network + memory tooling too** (`9a5f496`):
  `tshark` and `tcpdump` (tshark's postinst is preseeded so a non-superuser
  may NOT capture — read pcaps, don't sniff), `scapy`, and `volatility3`. So a
  pcap or a memory dump that arrives as a plain misc/pwn upload can be worked
  in-place without routing it through the forensic container.
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
- **Deterministic pre-analysis (no LLM).** Before main's first turn a
  zero-LLM pass (`modules/crypto/pre_analysis.py`) runs RSA factorization
  attempts, cipher/param extraction, auto-solve of trivial classical
  ciphers, and — for a remote target — a **banner pre-probe** that opens
  one connection, captures the server's first bytes, and injects them so
  the solver parses the REAL wire protocol instead of guessing. Results
  are injected into the prompt; being pure code, this path is also
  AUP-immune (a content-blocked classical chal can still capture the flag).
- Sandbox selection is automatic, by FILE EXTENSION: name the deliverable
  `solver.sage` and auto-run executes it in the `sagemath/sagemath` image
  (lattice / Coppersmith / Gröbner); anything else runs `python3` in the
  standard runner. The old "Use SageMath sandbox" checkbox was vestigial and
  was removed (34590ab) — `use_sage` is derived, not configured. **The
  worker has NO sage**, so a `.sage` solver is untestable in the dev
  environment: benchmark it with `python3 -m worker.sage_smoke solver.sage`
  before shipping (see [dev/run parity](#devrun-parity--the-runner-is-not-the-worker)).
- Available libs in the runner sandbox: pycryptodome, gmpy2, sympy, z3-solver,
  ecdsa, pwntools, **fpylll** (LLL / BKZ lattice reduction).
- **Sandbox timeout** for a `.sage` solver is widened past the 300 s
  default: **6000 s offline** (Gröbner / resultant / `small_roots` are
  legitimately many minutes and silent) and **900 s** when a remote target
  is set (the server's own window bounds it). Both are ceilings, overridable
  per job via `meta.exploit_timeout_seconds`.

### Reversing
- **Upload**: zip preferred (the API auto-extracts and picks the
  largest ELF/PE inside as the canonical `binary_name`, flattening
  it into `bin/` so the agent's `./bin/<name>` reference resolves
  cleanly) or a bare single ELF/PE. Also proceeds on non-ELF/PE
  artifacts and accepts a remote target (capture-remote-flag).
- Reuses the `decompiler` image.
- Solver auto-runs in the runner container if requested.
- **Windows / PE & managed-.NET (experimental).** The worker image
  carries a Windows-RE layer: `mono` (run .NET Framework 4.x assemblies),
  `dotnet` (run modern .NET 5+), and `ilspycmd` (ILSpy — decompile managed
  PE to near-source C#); plus a native-PE dynamic layer — **Wine** (x64 +
  x86) running a real Windows PE headlessly under **Xvfb**, `import` to
  screenshot a GUI PE that draws its flag, and `WINEDEBUG=+relay` to trace
  Win32/GDI+ calls (use `frida` for native-Linux-ELF instrumentation, not
  Wine shims). These tools are installed best-effort (WARN-masked) so a
  failed resolve can never break the worker image — a given build may have
  them present or absent; verified end-to-end on a real PE-hooking chal.

## Operational commands

```bash
docker compose up -d              # start core services
docker compose down               # stop
docker compose logs -f worker-1 worker-2   # tail worker logs (per-slot services)
docker compose ps                 # status

# Source-code changes — restart is enough (no rebuild) because api,
# worker, and modules are all bind-mounted. The deploy.sh helper does the
# no-rebuild "apply the latest patch to the running stack" for you:
./deploy.sh --changed             # restart only the services whose code changed
                                  # (defers the worker restart while a job is
                                  #  live; run ./deploy.sh --worker when idle)
                                  # ALSO warns + probes the LIVE runner image
                                  # when you changed a path that is BAKED IN
                                  # (runner/, forensic/, misc/, decompiler/,
                                  #  any Dockerfile, any requirements*.txt)
# ...or restart by hand:
docker compose restart api        # api/routes/*, api/main.py changes
./deploy.sh --worker              # modules/*, worker/runner.py — idle slots only

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

# ...and if you changed app.js, re-stamp the `?v=` cache buster in
# index.html BY HAND. `stamp-version.sh` does NOT do it, and a browser
# serving the old app.js against new HTML is the usual "my deploy did
# nothing" report. fc9bc79 moved it ad808f809 -> ab8e75f7e.

# Image rebuilds — needed for Dockerfile, requirements.txt, or tool-image
# (decompiler/forensic/misc/runner/sage) changes. deploy.sh does NOT do
# this; see the rebuild guard below.
docker compose build api worker-1 worker-2
docker compose --profile tools build            # all 4 tool images
docker compose --profile tools-sage pull sage   # sage is PULLED, not built
docker compose --profile tools build runner     # just one

# Per-slot memory: the cap-CHANGING half can only ever be REFUSED against the
# real slots on this VM, so it is exercised in its own universe — the harness
# builds its own network, redis, two containers and /data and runs a real RQ
# worker inside them. Needs docker + the worker image; non-zero on any failure.
# It ends by proving it leaked nothing: both production slots still 4 GiB,
# /data/.worker-memory.lock never created, dynamic_worker_mem still false.
python3 scripts/sim_worker_mem.py [--keep]

# Wipe all jobs (UI also has a Bulk Delete button)
curl -X DELETE 'http://localhost:8000/api/jobs?all=true'
```

### Image-rebuild guard (`deploy.sh --changed`)

`deploy.sh` **restarts bind-mounted code; it never builds an image.** Before
the guard, a change confined to `runner/` matched neither restart pattern, so
it hit the *"changed paths touch no mounted backend code"* early-exit — the
fix silently did nothing **and the deploy baseline advanced**, hiding it from
the next `--changed` run too. A runner fix could look deployed while the live
image stayed stale.

Now any changed path under `runner/`, `forensic/`, `misc/`, `decompiler/`,
any `Dockerfile`, or any `requirements*.txt` prints a loud banner, and for
`runner/` the guard **probes the LIVE image** with a real ~0.3 s compile
rather than trusting the file:

```
[deploy] WARN: IMAGE REBUILD REQUIRED — these changed paths are BAKED INTO IMAGES:
    runner/Dockerfile
[deploy] WARN: run:  ./start.sh --rebuild  (or: docker compose -p … --profile tools build <svc>)
[deploy] WARN: live runner image is STALE — a compile probe FAILED in it:
    /usr/bin/ld: cannot find Scrt1.o: No such file or directory
```

Best-effort: any docker hiccup degrades to a log line and never blocks the
deploy. This pairs with the
[dev/run parity](#devrun-parity--the-runner-is-not-the-worker) fixes — the
packages only help if the image is actually rebuilt.

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
docker compose up -d --force-recreate api worker-1 worker-2 redis

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
| `worker-N` | `./worker:/app/worker:ro`, `./modules:/app/modules:ro` | hot-reload source on a slot restart |
| both | `./data:/data` (rw), `~/.claude:/root/.claude` (rw — session jsonl carry on /retry), `/var/run/docker.sock` (sibling containers; also what the per-slot memory sampler needs at every job start), `${HOST_GROK_HOME:-~/.grok}`, `${HOST_CODEX_HOME:-./data/codex-home}` (rw) | persistence + auth |

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
   `$TMPDIR` to `./tmp/` (under the job's cwd) for every agent process's
   env — main, subagents, AND pre-recon, in `agent_job_env()`
   (`modules/_common.py:2576`). The consolidation is the point: main and
   pre-recon used to lack it, and GPT pre-recon on job `6685e3e65add`
   unpacked into container-global `/tmp` and analysed a `prob.ko` an earlier
   job had left there. Python `tempfile.*`, pwntools, etc. follow it. Each subagent
   prompt (recon, debugger, judge, triage) has a "scratch path
   discipline" section reminding the agent to write
   `$TMPDIR/probe.py` in Bash rather than the absolute
   `/tmp/probe.py`.
2. **Boot sweep** — `worker/runner.py:_sweep_stale_tmp()` runs
   once on every worker slot restart and removes files
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

## Timeouts

`JOB_TIMEOUT` defaults to **900 s**. Override per-job from each Analyze form,
or globally in Settings (`job_timeout_seconds`).

**Nothing fires when that number elapses.** It is no longer a deadline — it is
only the input to RQ's hard ceiling (`api/queue.py:hard_timeout_for`):

```
hard = min(max(JOB_TIMEOUT * 4, 24 h), 7 d)      # JOB_TIMEOUT <= 0  ->  7 d
```

So the default 900 s buys a **24 h** hard kill. What actually bounds a run is
the tool-call budget (`INVESTIGATION_BUDGET`), the spend cap (`COST_CAP_USD`),
the judge / postjudge loop, and **■ Stop** — not the clock.

> **The soft deadline was removed in `3a06349`.** A watchdog used to set
> `meta.awaiting_decision` at `JOB_TIMEOUT` and the job panel showed
> "▶ Continue running / ■ Stop now". It protected nothing: the agent was never
> interrupted, so the banner only asked the operator to re-authorise work that
> was already continuing — while interrupting every long job with a decision
> that had no wrong answer. The watchdog, the banner and the flag are gone; the
> `/timeout/continue` and `/timeout/kill` endpoints survive as unreachable
> no-ops.

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

**Retryable and continuable are not the same set.** `/retry` rebuilds the job
from its inputs — Web / Pwn / Crypto / Rev / **Web3** / **Forensic**
(`_RETRYABLE_MODULES`, `api/routes/retry.py:140`). `/continue` forks the prior
conversation in place, which forensic cannot do, so it is Web / Pwn / Crypto /
Rev / Web3 only (`_CONTINUABLE_MODULES`, `:169`). The two lists are written
out rather than derived, so a module nobody has considered defaults to
refused; parity is held by `scripts/test_flag_ready.py` and
`scripts/test_dashboard_ui.js`. Any of them can be re-issued at any terminal
status (`failed`, `no_flag`, `finished`, `stopped`) — and Stop&resume can also
fire while the job is still `queued` / `running`. `module=hybrid` is still
refused by the scalar retry API. Buttons:

| Button | What happens |
|---|---|
| **↻ Retry with reviewer hint** | The routed reviewer reads the prior job's `run.log`, exploit/solver, stdout/stderr, and module-relevant source, then writes an evidence-labelled retry plan designed to avoid repeating the previous theory. That hint is appended to the original description as `[retry-hint] …` and a fresh job is enqueued. Reviewer output streams into the UI live (SSE). |
| **✏ Retry with my hint** | Inline textarea. Whatever you type is appended as `[retry-hint]` — the reviewer is **not** called. |
| **💬 Continue (operator note)** | `POST /api/jobs/{id}/continue {comment?, target?, challenge_secret_key?, challenge_secret_value?}` — `comment` is no longer required if a challenge credential is supplied (a credential-only continuation gets a generated note). Not offered for **forensic**, which is retryable but not continuable: `/continue` forks the prior conversation in place and forensic has nothing to fork — `run_job` restarts at the collector regardless. Re-runs the SAME job id (no new job, no new cwd) resuming the prior SDK session, with the operator note folded in as priority guidance under a "this is NOT a re-investigation — act on the note now; spend a one-shot resource on your COMPLETE exploit, don't probe" framing. Because the cwd is unchanged, the forked conversation's paths stay valid and there is no stale-path re-orientation. For when the agent fully solved the chal but waited on an external action (you restarted a one-shot DreamHack instance, the remote came back, a credential was handed over). The optional target updates `meta.target_url` (a restarted instance usually comes back on a new port — put it in the **New target** field, not the note). |
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
  `_CARRY_WORK_IGNORE_NAMES` in `api/routes/retry.py:1228` skips `tmp/`,
  `__pycache__/`, `libsrc/` (re-staged deterministically each attempt, so
  carrying it just bloats the retry tree) and `.codex-stop-requested` (carry
  it and the child inherits a stop request it can never clear) at every depth;
  `symlinks=True` preserves symlinks
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
with the prior target). Since `019e7a4` every retry/resume/continue form
renders a MULTI-target row list (`+ add target` / `×`); rows are
newline-joined and split server-side. The one surviving `window.prompt()` for
a target is the **Run in sandbox** button. Empty input keeps the prior target;
the sentinel `(none)` clears it.

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

The other refusal is not the reviewer's. `/retry`, `/resume` and `/continue`
all wait for the source job's Codex CLI to release its turn lock, and return
**409 `{"kind": "stop_ack_timeout"}`** if it has not
(`CODEX_STOP_ACK_TIMEOUT_S`, default 15 s; guard in
`modules/codex_turn_guard.py`). The lock fd is inherited by the CLI, so
killing the RQ work horse cannot make it look free while the real writer still
holds the shared Codex thread store open. Operator consequence: **no successor
job is created, but on the `/resume` path the source job is already marked
`stopped`** — re-issue. Only GPT/Codex-provider jobs can hit this; a job with
no turn-lock file passes immediately.

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
   collector: `exploit.py.stdout`, `exploit.py.stderr`, `solver.py.stdout`,
   `solver.py.stderr`, `callbacks.jsonl`, `summary.json`
   (`_TRUSTED_FLAG_SOURCES`, `modules/_common.py:1424`). If ANY
   non-placeholder flag appears here, return ONLY those.

   That tuple is a floor, not the whole set: the trusted set is its UNION with
   `meta.artifacts`, which is the only reason a crypto `solver.sage.stdout` is
   trusted at all. **`result.json` is deliberately NOT a scan input**
   (`_common.py:1649-1651`) — analyzers write it *after* their final scan and
   include the flags they selected, so trusting it on a rescan would promote
   the analyzer's own narrative decision to runner evidence. And when a turn
   ends with `sandbox_started is False` plus an agent error, every
   runner-owned name in the retry chain is REMOVED from the trusted set
   (`_common.py:1763-1772`) — that is what stops a retry from inheriting its
   parent's stale `*.stdout`.
3. **Narrative tier** — `report.md`, `findings.json`. Consulted ONLY when
   the trusted/marker tiers are empty, and skipped entirely when the sandbox
   run was blocked/aborted. **`run.log` was REMOVED from this tier
   (e33e626)**: it is the raw interleaved firehose of every tool result, and
   with web research re-enabled a PUBLISHED WRITEUP's flag can land there
   verbatim — job dc981a8c4741 false-finished on a flag scraped from a recon
   WebSearch summary.

   Consequence worth knowing: a genuine flag the agent captured in its own
   testing, but which the sandbox never re-produced (e.g. the auto-run died
   on an environment gap), stays in `meta.flag_candidates` and the job ends
   `no_flag`. That is deliberate — see
   [unreproduced candidates](#unreproduced-flag-candidates).

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

- **Palette**. Themed after the terminal's *Grok Build* scheme — a neutral
  `#141414` surface ramp with Tokyo-Night accents, defined once as CSS custom
  properties in `:root` (`web-ui/style.css`). Because that scheme is a pastel
  *foreground* palette, the opaque button fills are darkened derivatives rather
  than the raw hues, each pinned so it clears 4.5:1 against the body text.
- **Spend pill + rate chip** (top bar). The pill shows cumulative spend against
  `spend_budget_usd`, escalating amber ≥80% / red ≥100%. A running job has no
  authoritative `cost_usd` yet, so its live `cost_usd_estimate` is added
  separately and rendered with a `~` — an in-flight run used to read `$0` for
  its whole life. Beside it, one chip per provider reports the rate-limit
  window as **remaining**, not used: `⏳ Claude 63% left · resets 6d6h`. Grok
  serves `remaining_pct` directly, while Codex derives it from the OAuth
  account window returned by CLI app-server. For Claude only `utilization` (a
  used fraction) comes back, so the chip derives `1 - utilization` and falls back to
  a status word when the field is absent, which the API notes is common on
  OAuth accounts. All chips render through the same two helpers so they cannot
  disagree — the Claude one used to append `utilization` as a USED percentage
  while Grok showed remaining, making the same `0.37` read as "37%" on one chip
  and "63% left" on the other.
- **Flag alarm**. A new 🚩 flag or `[FLAG?]` candidate raises a sticky
  bottom-right toast plus a beep, and an OS notification when permission is
  already granted. Tracked by VALUE per job, so a given flag alarms exactly
  once: counting instead meant an out-of-order poll re-announced the same flag,
  while a poll carrying two candidates announced only one.
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
  scan (zero extra LLM tokens), not something the agent does. The
  **FLAG FOUND / `[FLAG?]` alarms stay sticky** until you acknowledge them,
  so a capture is never scrolled past unseen.
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
- **Live monitor commentary + language selector**. Beside the raw run
  log, a curated [monitor](#monitor-modules_monitorpy) feed shows a cheap
  model's one-line "what just happened" narration of each signal batch,
  streamed over SSE. A language selector flips every entry between the
  configured languages (`MONITOR_LANGS`, default ko/en) instantly — each
  entry carries all languages, so switching is a client-side toggle with
  no refetch.
- **Stop button**. Halts a running/queued job WITHOUT deleting it — the
  status flips to `stopped` and the record + `./work/` are kept, so you
  can inspect artifacts and then `/retry` or `/resume`. Distinct from Delete
  (which removes the job). It also fences future Codex launches for that job
  before signalling RQ, and appends a bounded record to
  `meta.operator_stop_audit` (last 16, `api/stop_audit.py`): what the status
  was, whether the stop was sent, whether RQ cancelled, how many challenge
  containers were found and killed, and whether termination was acknowledged.
  That array is the first place to look when a Stop did not take.
- **Version / last-patch badge**. The header shows the running commit +
  patch timestamp (stamped by `deploy.sh`) so an operator can confirm a
  redeploy actually took effect rather than serving stale code.
- **CLI live status (`scripts/job-status.sh <job_id>`)**. Single
  carriage-return-refreshed terminal line carrying status / stage /
  turns / token deltas (`↓in ↑out ⟳cache`) / cost / worker / log
  growth. Polls `/api/jobs/<id>` every 2 s — useful when you want a
  glanceable status without opening the browser. `API=http://host:port
  scripts/job-status.sh <id>` for a remote api.

## Out-of-band callbacks (XSS / SSRF / blind RCE)

CTFs that exfiltrate via a remote bot need a publicly-reachable
listener. Ogamdo has a built-in collector that takes any HTTP
request, logs it, and auto-extracts flag-shaped strings.

Setup once:

`./start.sh` and `./restart.sh` **auto-start** this tunnel for you (set
`AUTO_TUNNEL=0` in `.env` to opt out), so the Callback URL is normally set the
moment the stack is up. To drive it by hand:

```bash
# Run a cloudflared quick-tunnel and auto-PUT its public URL into the settings
# (the orchestrator appends /api/collector/<job_id> per job):
./tunnel.sh          # resident; Ctrl-C stops it and restores the prior URL
./tunnel.sh stop     # stop an auto-started (backgrounded) tunnel

# Or run any tunnel yourself and set Callback URL by hand in the Settings tab:
#   cloudflared tunnel --url http://localhost:8000   # frp, ssh -R, a VPS, …
#   ngrok http 8000                                   # see the interstitial note
```

> **Why cloudflared, not ngrok?** ngrok's free tier answers with a 200 + HTML
> browser-warning *interstitial* unless the caller sends the
> `ngrok-skip-browser-warning` header — which an XSS beacon (`<img>`,
> `sendBeacon`, a bare `fetch`) cannot set, so the bot's exfil hits the warning
> page and the flag is silently lost. cloudflared `*.trycloudflare.com` tunnels
> have no interstitial, so beacons pass through transparently.

The tunnel exposes the **whole api** publicly, not just the collector. If you
don't want jobs/settings reachable from the internet, set an **Auth Token** in
the Settings tab — the `/api/collector/<job_id>` path stays public either way
(the remote bot needs it; the job_id is its secret).

Cloudflare quick-tunnels are best-effort: occasionally one never becomes
reachable (a transient route error). If beacons aren't landing, roll a fresh
URL with `./tunnel.sh stop && ./tunnel.sh` (the auto-start prints
`reachable` / `NOT reachable yet` so you know).

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
- **Seven** path prefixes bypass auth when an Auth Token is set, not one:
  `/api/health`, `/api/version`, `/login`, `/static/`, `/favicon.ico`,
  `/api/terminal/ws/` (the WebSocket authenticates inside the route) and
  `/api/collector/` (`api/auth.py:16-22`, matched with `startswith`). This
  matters because the tunnel exposes the whole api and the Auth Token is the
  only mitigation offered above.
- **Challenge credentials have their own ingress** (`modules/job_secrets.py`).
  Every analyze form and every retry/resume/continue body takes
  `challenge_secret_key` + `challenge_secret_value`; the value is stored at
  `data/job-secrets/<id>.json` (0600 under a 0700 dir) — a SIBLING of
  `data/jobs/`, deliberately outside it so hybrid parent-directory invariants
  and the measurement archive cannot sweep it up. It is injected into every
  agent process's environment, and struck out of `run.log`, `meta.json` and
  every retry hint. Three things follow:
  - redaction is **exact-value only**. The agent really does see the token in
    its env; a token it base64s, splits, or re-encodes before printing is not
    redacted.
  - deleting a job directory by hand does **not** delete its credential (the
    `DELETE /api/jobs/<id>` route does, `api/routes/jobs.py:698`), and any
    `rsync` of `data/` carries it.
  - with `job_ttl_days = 0` the cleanup loop returns early
    (`worker/runner.py:178-184`), so `cleanup_orphaned_secrets` never runs at
    all. "Retention = keep forever" silently means "credentials forever" too.

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
  worker is in `busy` for too long, `./deploy.sh --worker --force` to recycle.

## License

MIT.
