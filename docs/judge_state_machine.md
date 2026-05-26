# Judge / retry lifecycle — state-transition reference

Single reference for the verdict → next_action → retry state machine, which
is otherwise spread across `_judge.py`, `_common.py`, `_runner.py`, and
`api/routes/retry.py`. Written before the `_normalize_verdict` refactor so the
behaviour being preserved is documented, not just the code.

## Stages of one sandbox cycle (`_runner.attempt_sandbox_run`)

```
prejudge ──(severity=high)──▶ BLOCKED: no run; {error:"prejudge_blocked", judge_aborted:True}
   │ (ok / severity≤med)
   ▼
 run (sandbox) ──spawn fail──▶ {error, prejudge}
   │
   ▼
postjudge ──▶ {verdict, next_action, stop_reason, failure_code, ...}
```

Each stage emits a structured event (`modules/_events.py`): `prejudge.result`,
`prejudge.blocked`, `run.start`, `run.exit`, `postjudge.verdict`.

## Verdicts (`_judge._VALID_VERDICTS`)

`success` `partial` `hung` `parse_error` `network_error` `crash` `timeout`
`unknown`. Only **`success`** means a flag was captured. Anything the model
emits outside this set normalises to `unknown`.

## Derivation rules (the invariants `_normalize_verdict` centralises)

| field | rule |
|---|---|
| `verdict` | model value if ∈ `_VALID_VERDICTS`, else `unknown` |
| `next_action` | `stop` iff `verdict==success` OR model explicitly said `stop`; otherwise `continue` (default when omitted) |
| `stop_reason` | `""` unless `next_action=="stop"`; auto-set to `"flag captured"` when `success` and model left it empty |
| `failure_code` | model value if ∈ `_VALID_HEAP_FAILURE_CODES`, else `None` |
| `retry_hint` | `""` when `success` (no point retrying a win) |

**Success-collapse** — when `verdict==success`, the failure-side fields are all
forced empty: `retry_hint=""`, `failure_code=None`, `what_failed=[]`,
`alternative_paths=[]`, `specific_diagnosis=""`, `stop_reason="flag captured"`.
(Pre-refactor this collapse was applied in three separate places; it now lives
once in `_normalize_verdict`.)

## How the verdict propagates to /retry

```
postjudge.next_action
   │  (run_main_agent_session, _common.py: on "stop")
   ▼
meta.judge_next_action = "stop"
   │  (api/routes/retry.py:_resubmit)
   ▼
prior_stopped = (meta.judge_next_action == "stop")
   │
   ├─ True  → resume_sid = None  (do NOT fork the prior session; its
   │          conversation was told to abandon this approach — forking
   │          poisons the retry. Incident: 2d22aa9f338e forked d809a5187990,
   │          23M cache_read on a 1-turn retry.)
   └─ False → resume_sid = prior claude_session_id (fork to keep context)
```

Note: `/retry` ALWAYS re-runs pre-recon (does not reuse the cache) —
`load_cached_pre_recon` bypasses on `retry_of`. Rationale: feeding the same
static triage the prior agent already failed against repeats its dead
assumptions. Cost (~$0.50 / 2-6 min) is cheap vs a stale-assumption retry.
Incident: de15654c8f39. **Do not "optimise" this away.**

## How the verdict gates flag acceptance (`scan_job_for_flags`)

The NARRATIVE flag tier (report.md / run.log) is consulted only when the
TRUSTED tier (genuine run stdout/stderr) is empty AND the run actually
validated a capture. It is skipped when:
- `judge_aborted` / `error=="prejudge_blocked"` (never ran), or
- postjudge `verdict != "success"` (ran but did not capture).

This stops decoy/placeholder flags (e.g. `DH{qwv::...}` echoed in prose) from
populating `meta.flags` on a failed run. Incident: 8aff38ac18ac recorded 5
fake flags on a dead-remote `network_error` run before this gate.

## Failure codes (`_VALID_HEAP_FAILURE_CODES`)

Heap-specific only; drive the prescriptive fix snippet prepended to the
retry hint (`_format_postjudge_user_turn` ↔ `HEAP_FIX_HINTS`). A code outside
the set is dropped so a typo can't leak into the retry pipeline.
