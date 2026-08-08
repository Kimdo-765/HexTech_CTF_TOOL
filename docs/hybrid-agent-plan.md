# Claude + Codex 하이브리드 운용 계획

작성 2026-08-08. 대상 코드: 메인 체크아웃의 **커밋되지 않은** GPT/Codex 계층
(28 files, +2107/-375). 워크트리 `integrated-refactor`에는 아직 없음.

---

## 1. 판단: 이건 런타임 통합이 아니라 "해상도" 변경이다

읽어본 결과 하이브리드에 필요한 재료는 이미 거의 다 있다.

| 이미 되어 있는 것 | 근거 |
|---|---|
| 클라이언트 표면 통일 | `gpt_agent.GptAgentClient`가 `ClaudeSDKClient` 표면(`query`/`receive_response`/`AssistantMessage`/`ResultMessage`)을 그대로 미러 |
| 역할 단위 모델 지정 | `model_presets.CONFIGURABLE_ROLES` = main, judge, reviewer, recon, debugger, triage, report, monitor |
| provider별 프리셋 버킷 | `model_presets` v2 store: `providers.{claude,grok,gpt}` 각각 독립 active |
| 역할별 스냅샷 패턴 | `agent_provider.provider_meta_fields()`가 이미 `gpt_role_models`를 meta에 박음 |
| provider 전환 시 세션 격리 | `retry.py:346 _resume_id_for_active_provider()` — provider가 바뀌면 resume id를 버리고 fresh session |

막고 있는 것은 **딱 하나**다.

- `agent_provider`는 job당 **스칼라**이고, `enrich_job_meta()`가 생성 시 한 번 박는다.
- `coerce_model_for_provider()`의 docstring이 명시적으로 말한다 —
  *"Used by judge / reviewer / report / monitor / forensic-misc so **every**
  agent role follows the operator's choice."*
  즉 이 함수는 하이브리드를 **막으려고 만든 함수**다.

따라서 작업의 본체는 `coerce_model_for_provider(model, provider)` →
`coerce_model_for_role(model, role, job_id)` 계약 변경과 그 호출부다.

호출부 전량(= 작업의 기계적 뼈대):

```
modules/_judge.py:400
modules/_common.py:2850   (report)
modules/_common.py:3527   (main)
modules/_common.py:3553   (judge)
modules/_common.py:3573   (reviewer)
modules/misc/orchestrator.py:129
modules/forensic/orchestrator.py:139
modules/model_presets.py:258
modules/gpt_responses.py:846  (child/subagent)
api/routes/retry.py:340   (reviewer)
```

---

## 2. 착수 전에 확인한 사실 두 가지

역할 배정은 아래 두 가지에 달려 있어서 먼저 확인했다.

### 사실 1 — Codex 런타임은 스키마 있는 출력을 낼 수 있는가?

`codex_cli.py`에 `json_schema` / `response_format` / `output_schema` /
`strict` **전부 0건**. 스키마 강제가 없다.

**그런데 Claude 경로도 마찬가지다.** judge는 자유 텍스트에서 JSON을 캐낸다:

- `_judge.py:566 _parse_json()` — 3단 폴백(펜스 블록 → 통짜 → 줄 단위)
- `_judge.py:969 _normalize_verdict()` — 알 수 없는 값은 `verdict="unknown"`,
  stringified-truthy도 **fail-safe** 처리

→ judge/reviewer를 GPT로 옮기는 것은 **구조적 능력 격차가 아니라 신뢰도 문제**다.
   파서는 provider-중립이고 실패 시 안전하게 무너진다. **옮길 수 있다.**

report는 GPT 경로가 이미 `enable_tools=False` 텍스트 전용으로 구현돼 있다
(`_common.py:2896`).

### 사실 2 — 어떤 역할이 프롬프트 번역 shim에 의존하는가?

`codex_cli.py:95–98`이 `mcp__team__spawn_subagent`→`spawn_agent`,
`subagent_type=`→`agent_type=`를 치환한다. 이 shim에 의존하는 역할만 위험하다.

`enable_subagents` 실사용:

- `_judge.py:424` → **False**
- `_common.py:3195` (pre-recon) → **False**
- `_common.py:2896` (report) → tools 자체가 False
- `_monitor.py:467` → tools False
- `misc/orchestrator.py:173`, `forensic/orchestrator.py:181` → **True** ← 유일한 의존

→ shim 위험은 misc/forensic 요약 에이전트에만 국한. judge/reviewer/recon/
   monitor/report는 이미 subagent 없이 도는 bounded 역할이다.
   게다가 misc/forensic은 one-shot 모듈이라(P2 자동 재시도 대상이 아님)
   shim이 틀려도 파급이 그 job 하나로 **봉인된다**. 열린 리스크가 아니다.

**가장 미묘한 호출부**: `gpt_responses.py:846`은 부모가 띄운 **자식(subagent)**
모델을 coerce한다. 역할 맵이 생기면 — Claude main이 띄운 자식이 "judge 역할이
codex"라는 이유로 codex로 끌려가면 안 된다. 자식은 **부모 세션의 provider**를
따라야 한다(역할이 아니라). 10개 호출부 중 유일하게 규칙이 다른 지점.

---

## 3. 구조: 두 조각으로 나누고, A를 먼저 낸다

두 조각은 서로 독립이고 **가치/비용이 역전**돼 있다.

### Piece A — `policy_refusal` 자동 provider 페일오버 (역할 맵 불필요)

기존 스칼라 provider를 그대로 쓴다. `coerce_*` 계약 변경 없음.

**왜 이게 최우선인가.** 메모리 3건이 같은 것을 기록한다 —
`aup_policy_refusal_inplace_reblock`, `crypto_aup_bytecaesar_falsepos`,
`reviewer_vocab_hardblock_regression`: 특정 챌린지 클래스는 Anthropic에서
**결정론적으로** AUP 블록되고 fresh fork로도 안 낫는다.

> **정정.** 초판은 "사다리에 갈 곳이 없다"고 썼는데 **틀렸다.**
> `_common.py:6626 _AUP_RECOVERY_STEPS = ("fresh_session", "other_provider")`로
> `other_provider` 단이 **이미 존재**하고, `:7607`의 구현이 Grok을
> **하드코딩**한다(`GrokSessionOptions`, `adapt_system_prompt_for_grok`,
> `default_model_for("grok")`). 게이트도 `aup_recovery_step(..., grok_available=)`로
> Grok에 묶여 있다.
>
> 따라서 필요한 것은 **신규 기계가 아니라 목적지 하나 추가**다 — 결론(빨리 하라)은
> 오히려 강해지고, 근거만 바뀐다.
>
> 이식 시 주의: `:7630` 주석이 경고하듯 `summary["model"]`을 새 provider 모델로
> 재할당하지 않으면 후속 실행이 **이전 provider 요율로 과금 계산**된다. Codex는
> USD를 아예 보고하지 않으므로(`codex_cli.py:758`) 이 지점은 추정치 처리 정책이
> 따로 필요하다.

사다리: `claude → codex → responses(opt-in, 유료) → 포기`

- `responses` 단은 API 키 과금이므로 **명시적 opt-in**으로 둔다.
- 이미 되어 있는 것: `retry.py:958 prior_aup_blocked` → fresh_session 강제,
  `:346`이 provider 변경 시 resume id를 버림. **페일오버가 필요로 하는 세션
  격리는 이미 정확히 동작한다.**
- 손댈 곳: `_common.py` AUP 사다리(~:9150, crash-hint 합성과 give-up 사이),
  `api/routes/retry.py`에 provider override, meta에 `provider_failover_from`.

### Piece B — 역할별 provider 맵

- `coerce_model_for_role(model, role, job_id)`로 계약 변경 + 위 10개 호출부.
- meta 스키마: 스칼라 `agent_provider`를 **절대 대체하지 말 것**
  (`_monitor.py:785`가 문자열로 읽고 `:790`에서 이전 meta로 폴백).
  스칼라는 job 기본값으로 남기고 옵셔널 `agent_role_providers` 맵을 **추가**한다.
  `gpt_role_models` 스냅샷과 같은 모양으로.
- **Grok은 v1에서 역할 맵 제외** — whole-job provider로만 유지. 안 그러면
  아무도 설계하지 않은 세 번째 열이 조용히 생긴다.

A → 실전 job 검증 → B 순서는 B의 리스크도 낮춘다. A가 codex 런타임을 실제
job에 먼저 태워보므로, judge를 거기에 걸기 전에 증거가 쌓인다.

---

## 4. 역할 배정 (판단)

| 역할 | 담당 | 근거 |
|---|---|---|
| **main** | **Claude** | 34k자 SYSTEM_PROMPT, `mission_block`, judge gate 스캐폴딩 전부 Claude에 맞춰 튜닝됨. 교체 위험 최대, 보상 없음 |
| **judge** (prejudge/postjudge) | **codex** | 하이브리드의 최대 명분. 확증편향 메모리 4건(`judge_subagent_confirmation_bias`, `postjudge_stop_loop_false_positive`, `adversarial_skeptic_prompt_bias`, `antiai_anchoring_circuit_breaker`). **다른 벤더의 prior = 공유 편향 제거.** 파서는 provider-중립 + fail-safe(사실 1) |
| **reviewer** (/retry 힌트) | **codex** | 같은 논리 + "나쁜 힌트 하나가 $15+ retry를 태운다". main이 Claude인데 reviewer도 Claude면 사실상 자기 세션을 자기가 리뷰하는 구조 |
| **recon / triage / monitor** | **codex** | bounded, 산출물이 산문, 이미 tools/subagents off, 호출량 큼 → 쿼터 완화 즉효이고 위험 최소 |
| **report** | **Claude** (v1) | 스키마 보유 + 메모리에 "report phase emits invalid JSON" **OPEN**. 이미 제일 무른 단계 위에 provider 변경을 쌓지 말 것 |
| **debugger** | **Claude** | gdb/pwndbg 역량이 경험적으로 확립(gdb ASLR seccomp, pwndbg 충돌 등 전부 Claude 경로에서 다듬어짐) |

핵심 한 줄: **Claude가 만들고, Codex가 심판한다.**
main·debugger·report는 Claude에, 검증·정찰·감시는 Codex에.

---

## 5. 같이 안 가면 조용히 깨지는 것들

### (a) 비용 회계가 단위 두 개가 된다 — 필수 동반 변경

- `codex_cli.py:758` → `total_cost_usd=None`. Codex OAuth는 구독 과금이라
  달러를 보고하지 않는다.
- `_common.py:8048 _total_spend()`는 subagent `cost_usd` + main
  `result.total_cost_usd`, 즉 **달러만** 더한다.
- 완화 요인: `DEFAULT_COST_CAP_USD = 0.0` — 캡은 **기본적으로 이미 꺼져 있다**.
  문제는 `COST_CAP_USD>0`로 다시 켤 때 provider-blind가 된다는 것.
- Codex 쪽 단위는 `codex_rate_limit.py`의 윈도우 `used_pct`/`remaining_pct`.
  → 캡을 "달러 **또는** 윈도우 %" 둘 다로 만들어야 한다. 어떤 유닛 테스트도
  이걸 잡지 못한다.

### (b) 토큰 원장이 둘이 된다

메모리 `token_double_count_and_cost_ledger`: `agent_tokens`가 정확히 2배였던
전력이 있다(`ResultMessage.usage` 재합산). provider 둘이면 원장도 둘.
`model_usage`가 authoritative라는 규칙을 유지할 것.

### (c) UI

job 상세에 "역할별로 무엇이 돌았나"가 보여야 한다. `gpt_role_models`
스냅샷 패턴이 이미 있으니 그대로 확장. Codex 잔여 쿼터 칩은 이미 있음.

### (d) 트리 소유권 — 구현 전 결정 필요

GPT 계층은 **메인 체크아웃에 커밋되지 않은 채** 있고 워크트리엔 없다.
이번 세션에 이미 같은 함정(워크트리의 Dockerfile 수정을 두고 메인에서 이미지
빌드)을 밟았다. 구현 착수 전에 먼저 커밋하거나 워크트리로 옮길지 정할 것.

---

## 6. 순서

1. **트리 정리** — GPT 계층을 커밋(또는 워크트리로 이동).
   테스트 스위트 7종은 **2026-08-08 메인 체크아웃에서 실제로 돌려 전부 그린**:

   | 스위트 | 결과 |
   |---|---|
   | `test_codex_cli` | 34 passed, 0 failed |
   | `test_codex_rate_limit` | 12 checks, 0 failed |
   | `test_gpt_responses` | 29 passed, 0 failed |
   | `test_gpt_timeline` | 18 checks, 0 failed |
   | `test_gpt_provider_ui` | 58 checks, 0 failed |
   | `test_model_presets` | OK |
   | `test_grok_acp` | 48 passed, 0 failed, 0 skipped |

   단, 이건 **단위 수준**이다. codex가 실제 CTF job을 끝까지 도는지는 아직
   증거가 없다 — 그래서 3단계(실전 검증)가 별도로 있다.
2. **Piece A** — AUP 페일오버 사다리. 가장 싸고 가장 값이 크다.
3. **실전 검증** — AUP로 막히던 챌린지(Search The Flag XSS, Byte-Caesar)를
   재투입해 codex로 넘어가는지 확인.
4. **Piece B-1** — recon / triage / monitor를 codex로. 저위험 쿼터 완화.
5. **Piece B-2** — judge / reviewer를 codex로. 교차 벤더 심판.
6. **회계** — 달러 + 윈도우% 이중 단위 캡, 토큰 원장 분리, UI 역할 표시.

report / main / debugger는 v1 범위 밖으로 남긴다.

---

## 7. 부록 — 라이브 설정 실측 (2026-08-08) 과 Codex 대안 검토

`/data/settings.json` 실측:

```
agent_provider = 'gpt'     gpt_runtime = 'codex'
gpt_effort     = 'xhigh'   enable_judge = False
```

프리셋: claude active=`ctf-optimized`, gpt active=`gpt-ctf-optimized`.

이 두 값이 위 계획의 전제를 바꾼다.

1. **judge는 지금 꺼져 있다.** "judge를 Codex로"는 `enable_judge`를 다시 켜기
   전까지 **아무 동작 변화가 없다.** 역할 이동보다 판정 게이트 재가동이 선행.
2. **현재 main은 이미 Codex다.** 따라서 "Claude main + Codex specialist" 구조는
   Codex를 *추가*하는 것이 아니라 **main을 Claude로 되돌리는** 변경이다. 그 변경은
   AUP 하드블록 클래스에 job을 다시 노출시키므로, Piece A(페일오버)는 선택 사항이
   아니라 **그 변경의 전제 조건**이다.

### 이미 구현되어 있어 새로 만들 필요가 없는 것들

Codex 대안이 "새 불변조건"으로 제시한 항목 다수가 이미 코드에 있다.

| 제안된 불변조건 | 실제 상태 |
|---|---|
| canonical 파일 작성자는 main 하나 | `_common.py:2013` recon subagent `tools=["Read","Bash","Glob","Grep"]` + 주석 "main keeps the only Write/Edit hand on exploit.py / solver.py / report.md"; `main_session_hooks()`는 main에만 Write/Edit 가드 부여 |
| 타 provider session ID resume 금지 | `retry.py:346 _resume_id_for_active_provider()` 이미 그렇게 동작 |
| job 생성 시 routing snapshot | `provider_meta_fields()`의 `gpt_role_models` 패턴 존재 |
| Settings 변경은 다음 job부터 | `provider_for_job()`가 meta 스탬프 우선 |

### 별도 `hybrid_role_runner` / `make_hybrid_spawn_mcp` / `hybrid-events.jsonl`
### 을 새로 만들면 안 되는 이유

전제가 거짓이다. `coerce_model_for_provider`를 역할 인지형으로 바꾸는 것은
**구성상 하위호환**이다 — meta에 역할 맵이 없으면 모든 역할에서
`role_provider(role) == provider_for_job(job)`이라 바이트 단위로 동일하게 동작한다.
기존 199+ 체크가 single-provider 경로를 이미 고정하고 있다.

반면 병렬 스택은 **동기화 대상 4쌍**을 새로 만든다(runner, spawner, preset store,
event stream). 이 저장소의 최빈·최고가 버그 클래스가 정확히 그것이다 —
`rev_runner_devrun_parity`는 스스로를 "**the 4th dev/run-parity firing**"이라 부르고,
`runner_toolchain_parity_and_deploy_guard`, `crypto_sage_solver_untestable_in_dev`,
`worker_slot_containers`가 같은 계열이다. 20줄짜리 함수 하나를 안 건드리려고
네 개의 서브시스템을 복제하는 거래는 성립하지 않는다.

### 기계 비용 기준 올바른 순서

- **judge**: `_judge.py:392–412`가 **이미 provider 분기**(gpt/grok/claude)를 한다.
  `provider_for_job(job_id)` → 역할 인지 resolver로 교체하면 끝. 신규 기계 0.
- **recon/debugger/triage subagent**: `make_spawn_subagent_mcp()`
  (`_common.py:3948`)가 MCP 툴 안에서 `ClaudeSDKClient`를 **직접 생성**한다.
  교차 provider 자식 spawn은 진짜 신규 기계다.

→ 신규 기계가 필요 없는 judge가 먼저, subagent 교차 spawn이 나중.

### Monitor — 정정

**초판의 "Monitor를 유지하라"는 GPT job에 대해 이미 무의미했다.**
`_monitor.py:776 _monitor_enabled_for_job()`:

> *"Return False only for GPT jobs, whose Timeline replaces Monitor."*

즉 `agent_provider='gpt'`인 현재, GPT job의 Monitor는 **이미 꺼져 있다**.
초판이 인용한 "이미 provider 인지형"이라는 근거는 맞았지만, 그 provider 인지의
내용이 정확히 *gpt에서 끄는 것*이었다. 방향을 반대로 읽었다.

살아남는 부분만 남기면:

- Monitor는 제어기가 아니라 **서술형 신호 피드**다(run.log ~1000줄, 96%가 TOOL
  에코 → ko+en 한 줄). API 컨테이너, 고정 저가 모델, best-effort,
  "must never touch run.log/meta.json".
- deterministic timeline은 *구조*를 주지 *서술*을 주지 않는다 — 대체재가 아니라
  다른 물건이다. 다만 GPT job에서는 이미 timeline만 쓰고 있다.
- **세 번째 이벤트 스트림(hybrid-events.jsonl)을 만들지 말 것**은 유효하다.
- 저가 narrator도 토큰/쿼터는 쓴다 — "공짜"는 과장이었다.
- **액션 아이템**: `_monitor.py` 상단 docstring이 이 GPT 예외를 반영하지 않아
  낡았다. 고칠 것.

hybrid v1에서 Monitor 정책은 **건드리지 않는다**(GPT-main = timeline,
Claude job = Monitor 유지). 복원 여부는 별도 운영 결정.

## 8. v1 추가 실행 조건 (2026-08-08 확정)

### 8.1 [필수] shadow judge 산문이 flag 스캐너에 닿으면 안 된다

**shadow가 조용히 shadow가 아니게 되는 경로가 실재한다.**

`_common.py:1420` — NARRATIVE tier의 소스는 `report.md`, **`run.log`**,
`findings.json`이다. 그리고 `:1936` 주석에 전례가 박혀 있다:

> job a15ff70a6ed5: **judge가** "captured the REAL flag DH{...20207ea}"를
> prejudge issue에 썼고, 그 축약형이 **run.log에서 스캔되어 `meta.flags[0]`으로
> 저장**됐다 — 진짜 `DH{<40 hex>}`는 hash-width 규칙에 걸려 버려진 채로.

shadow judge는 **judge가 꺼져 있던 job에 새 LLM 산문을 run.log에 주입**하는
것이다. 게다가 shadow로 관찰하려는 대상이 정확히 *TRUSTED tier가 비어 있는 실패
케이스*인데, 그때가 바로 NARRATIVE fallback이 발동하는 조건이다.

기존 방어(메타변수 규칙, 따옴표 규칙, 생략부호 규칙, `sandbox_result` 게이팅)는
**Claude judge 산문에 맞춰 튜닝**됐다. v1은 (a) Codex 산출물을 심판하는 Claude와
(b) fallback Codex judge — **새로운 산문 형태 둘**을 도입한다.

→ **조건**: shadow judge 출력은 `run.log`에 넣지 않고 `judge_shadow.jsonl`로
분리하거나, `scan_job_for_flags`에서 명시적으로 제외한다. `meta.flags`가 바뀌면
`status`가 바뀌고, 그러면 "오늘의 실행 결과 유지"라는 shadow의 전제가 깨진다.

### 8.2 [필수] shadow는 out-of-band여야 실험이 오염되지 않는다

prejudge/supervise/postjudge는 auto_run 사이클 **안**에 있다. shadow가 동기
호출이면 judge가 꺼진 오늘 대비 **wall-clock이 늘어난다**. supervise는 컨테이너
watchdog이고(`killed_by_supervise`), `runner_timeout_default_300s` 기록처럼 이
프로젝트는 타임아웃에 여러 번 물렸다. "kill 금지"는 *행동*을 막지 *타이밍*을 막지
않는다. shadow 판정은 비동기/사후 실행으로 실행 경로에서 떼어낼 것.

### 8.3 canary보다 **과거 job 리플레이**가 먼저

"3–5개 canary 비교"에는 **대조군이 없다.** 반면 `/data/jobs/<id>/`에는 이미
결과를 아는 완료 job이 쌓여 있다(report.md / findings.json / run.log / exploit.py).
리플레이하면 대조군이 공짜다 — 실제 결과를 이미 알기 때문이다.

**단, 초판의 두 표현은 과장이었다.**

- "비용 0"이 아니다. **컨테이너 실행 비용**이 0이고 추론 비용은 그대로 든다.
- "n이 훨씬 큼"도 실측하면 과장이다.

`/data/jobs` 실측 (2026-08-08):

```
total = 49    flags 보유 = 31 (63%)    judge 필드 보유 = 0
status = finished 31 / no_flag 10 / stopped 6 / running 1 / failed 1
module = pwn 15 / rev 14 / web 9 / crypto 8 / web3 1 / misc 1 / forensic 1
```

여기서 나오는 설계 제약 셋:

1. **accuracy 숫자를 쓰지 말 것.** 63%가 성공이므로 "항상 success"라고 답하는
   judge가 63%를 받는다. **결과별로 층화한 confusion matrix**만 유효하다.
2. **judge 필드 보유 job = 0.** 저장된 어떤 job에도 judge 산출물이 없다. 즉
   과거 judge 동작의 baseline이 **존재하지 않는다** — 리플레이는 "Claude judge
   vs 이전 judge"가 아니라 "Claude judge vs 최종 결과"만 잴 수 있고, 이는 judge
   정확도와 결과 자체의 모호성을 섞는다. 해석 시 반드시 구분할 것.
3. **모듈 편중.** pwn/rev가 29/49다. web3·misc·forensic은 각 1건이라
   **n<5인 모듈은 enforce 대상에서 제외**해야 한다.

`decoy_flag_false_success`, `orchestrator_false_success_stale_log_flag`가 가리키는
false-success 사례는 meta에 라벨이 없으므로 **수동 라벨링이 선행**돼야 한다.

→ 리플레이(층화 confusion matrix) → 라이브 canary 순서.

### 8.3b supervise는 v1에서 평가 불가 — enforce 대상에서 제외

합의된 shadow 설계(라이브에서는 스냅샷만, 모델 호출은 사후)에서 supervise만
구조적으로 예외다. supervise의 판단 근거는 **실행 중인 컨테이너의 정체된 출력**이라
사후 스냅샷으로는 원리적으로 복원되지 않는다(Codex가 리플레이에 대해 지적한
"reconstructed" 문제가 라이브 shadow에도 그대로 적용된다).

따라서 supervise의 shadow 수치는 prejudge/postjudge와 **인식론적 지위가 달라
평균 내면 안 된다**. 그리고 supervise는 셋 중 유일하게 **컨테이너를 kill**하는,
blast radius가 가장 큰 게이트다 — 가장 검증하기 어려운 게이트가 가장 위험하다.

→ **v1 enforce 판단 대상은 prejudge / postjudge 뿐. supervise는 off 유지.**

### 8.4 fallback을 진단으로 쓴다 (공짜)

`reviewer_vocab_hardblock_regression`의 AUP 블록은 아티팩트가 아니라 **우리 자신의
프롬프트 스캐폴딩** 때문이었다. Claude가 거부한 **동일 입력**에 Codex가 성공하면,
그 블록은 콘텐츠가 아니라 provider/프롬프트 특유라는 증거다. `fallback_used`와
함께 이 판별 결과를 남기면 복구 경로가 곧 측정이 된다 — cb62183을 더 빨리 잡았을
바로 그 진단이다.

### 8.5 원장은 role이 아니라 **role × stage**

prejudge / supervise / postjudge가 전부 `role="judge"`인데 supervise는 여러 번
발화한다. role 단위 집계는 judge를 이유 없이 비싸 보이게 만들고 어느 stage인지
말해주지 않는다. `provider × role × stage`로 쪼갤 것.

### 8.6 `enable_judge`를 덮어쓰지 말 것

`enable_judge=False`는 그대로 off를 의미하게 두고
`judge_mode ∈ {off, shadow, enforce}`를 **추가**한다. 불리언을 3상태로 재해석하면
기존 settings/meta가 깨진다(1절의 `agent_provider` 스칼라 보존과 같은 원칙).

---

### `.scratch/codex/debugger/` 는 이미 값을 치른 버그의 재도입

`_common.py:283–300` 주석: job cb6e7896d1ec가 **정상 동작하는 solver**를 소스
디렉터리에 썼고, auto-run이 못 찾아 job이 `no_flag`로 끝났다. 그래서 PreToolUse
하드 deny를 넣었다(메모리 `autorun_solver_location_mismatch`도 같은 계열).
exploit 형태의 산출물에 **새 합법 쓰기 위치**를 만들고 main이 다시 옮겨 적게 하는
설계는 그 실패 모드를 의도적으로 되살린다. 최소한 가드 갱신이 동반돼야 한다.
