# 적대적 테스트 결과 (2026-08-15) — 배포본 `84c3b3c`

대상: 커밋 `84c3b3c` 배포 후 라이브 코드. 목적은 통과 확인이 아니라 **깨뜨리기**다.
각 수정에 대해 "이게 실패하려면 무엇이 참이어야 하는가"를 세우고 그 조건을 만들었다.

배포 확인(선행): `/api/version` → `84c3b3c`,
`/api/jobs/usage` → `terminal_unpriced_estimate_usd = 810.4762` · `spent_usd_complete = false`,
컨테이너 **내부** 임포트로 `scan_job_for_flags`의 새 인자 2종 확인 (worker-1·api 둘 다),
`MEASUREMENT_ARCHIVE_DIR = /data/job-measurements` 대 `JOBS_DIR = /data/jobs` → 순회 밖.

---

## 새로 찾은 것

### A11 — 스테일 stdout 이 최상위 신뢰 티어로 크래시를 세탁한다  ★ 중요

A0 게이트는 크래시+미실행일 때 narrative 를 막지만, **`trusted_only` 경로로 보낸다**:

```
modules/_common.py:1783  crashed_before_sandbox = sandbox_started is False and bool(agent_error)
modules/_common.py:1784  if sandbox_skipped or crashed_before_sandbox or trusted_only:
```

그런데 `_TRUSTED_FLAG_SOURCES` 에 `exploit.py.stdout` / `solver.py.stdout` 이 들어 있다.
재현:

```
sandbox_started=False, agent_error=True
  report.md        -> []                        차단
  findings.json    -> []                        차단
  chain.json       -> []                        차단
  run.log          -> []                        차단
  solver.py.stdout -> ['DH{...}'] tier='marker'  ← 통과. 최상위 티어
```

**도달 경로**: 러너는 stdout 을 `work_dir` 에 쓰고(`modules/_runner.py:1347`),
`/retry` 는 `work/` 를 새 job 으로 복사한다(`api/routes/retry.py:1232`).
따라서 **이전 시도가 남긴 stdout 을 들고 재시도했다가 이번엔 샌드박스 전에 크래시하면**,
아무도 실행하지 않은 flag 가 `marker` 로 채택된다.

이것은 `0d88d50ad167` 과 **같은 모양이 다른 문으로 살아남은 것**이고,
narrative 보다 신뢰 티어가 높아 A0 원본보다 나쁘다.

**제안**: 크래시+미실행일 때 trusted 소스도 **이번 시도의 산출물임을 요구**한다
(mtime 이 현재 시도 창 안 / `sandbox_started` 가 True 인 경우에만 채택).
집계기 하드닝에서 쓴 입력-출처 규칙과 같은 원리다.

### A12 — 빈 오류 메시지가 A0 게이트를 끈다  ※ 경미

게이트가 `bool(agent_error)` 다. 실측:

```
agent_error=True/'boom'/1   -> 차단
agent_error=''/0/False/None -> 통과
```

에이전트가 **빈 메시지로 크래시**하면(`raise ValueError("")` 류) 게이트가 꺼진다.
"오류가 있었는가"가 아니라 "오류 문구가 비어 있지 않은가"로 판정하고 있다.
**제안**: 오류 발생 여부를 별도 boolean 으로 넘긴다.

※ `sandbox_started is False` 의 타입 엄격성(`0`/`""` 은 통과)은 **결함이 아니다** —
`None`(unknown)을 차단으로 접지 않기 위한 의도된 설계다. 다만 미래 호출자가 `0` 을 넘기면
조용히 게이트가 꺼지므로 경계에서 정규화하면 안전하다.

### A6 — 필터가 사건 모양에 특화돼 있다  ※ 범위 한계

`_REGEX_SOURCE_TAIL_RE` 는 잘린 match 뒤의 `]` + 수량자 + `}` 만 잡는다.

```
DH{[^}]*}       잡힘      사건 원형
DH{[^}]+}       잡힘
DH{[^}]{1,}}    잡힘
DH{[^}]}        놓침      수량자 없음        -> 'DH{[^}' 가 후보로 남음
DH{[^}][^}]*}   놓침      첫 ] 뒤 수량자 없음 -> 'DH{[^}'
DH{.*}          놓침      문자클래스 없음 — FLAG_RE 에 **완전 일치**해 진짜 flag 와 구분 불가
DH{\w+}         놓침      동상
DH{[a-z]+}      놓침      동상
```

뒤 세 개는 **모양만으로는 진짜 flag 와 구분할 수 없다** — 패턴 매칭으로 풀 수 없는 부류다.
수동 큐레이션 방침을 감안하면 남겨두는 것이 맞을 수 있다.

**부수 확인**: `DH{y]{2,3}}` 이 `DH{y]{2,3}` 으로 **잘리는 것은 A6 가 아니라 기존 `FLAG_RE`**
동작이다 (`[^\s}]{1,200}` 이 첫 `}` 에서 멈춘다). A6 가 만든 회귀가 아니다.

### B1 — 보관본에 보존 상한이 없다  ※ 경미

승격은 견고하다(형제 디렉터리 · 같은 디렉터리 임시파일 → `os.replace` 원자적 ·
pid+tid 로 슬롯 충돌 회피 · 실패 전건 기록 · 회수를 막지 않음).
다만 **보관 디렉터리 자체에는 어떤 회수 정책도 없다** — 무한 증가한다.
job 당 `run.log` 가 수백 KB 인 사례를 확인했다(294 KB). 운영자의 선택(보존 우선)의
직접적 귀결이지만, 상한이나 주기적 압축을 언젠가는 정해야 한다.

---

## 공격을 견딘 것

### A1 — 5개 공격 전부 방어

```
hard cap 초과 후 다음 event 복귀        DROP → 정상 event 2개 온전
연속 초과 event 2개                    DROP·DROP → 정상 event
개행 없이 EOF 로 끝나는 초과 event       DROP → EOF. 예외·행 없음
cap 경계 ±2                            LINE (버리지 않음) — 정확
2 MB event (전송한계 초과·cap 이하)      **온전 보존** len=2000010 → 다음 event 정상
```

마지막이 핵심이다. 전송 한계(1 MiB)와 응용 상한(8 MiB)을 분리한 설계가 실제로 작동한다 —
`readline` 만 고쳤다면 이 event 는 조용히 사라졌을 것이다.

### A7 — 회수 순서와 오류 경로 모두 방어

`finally` 가 `_stop_process()` 를 **먼저** 부르고 그 다음에 handle 을 지운다.
`_stop_process` 는 이미 죽은 자식(`returncode is not None`), `ProcessLookupError`,
`PermissionError`(→ `terminate()`/`kill()` 폴백), 마지막 `wait()` 예외까지 모두 처리한다.

※ `await self._stop_process()` 자체는 try 로 감싸져 있지 않다. 예외가 나면 handle 이
남으므로 이후 `close()` 가 재시도한다 — 지우는 것보다 안전한 방향이라 결함으로 보지 않는다.

### A8 — 파서가 fail-safe

```
"dead"  -> dead      에스컬레이션
"DEAD"  -> dead      (.lower())
" dead" -> unknown   앞뒤 공백은 집합에 없어 unknown 으로 닫힌다
True/1  -> unknown
""/None -> unknown
"d3ad"  -> unknown
```

예상 밖 입력은 전부 `unknown` 으로 떨어져 에스컬레이션하지 않는다. 안전한 방향이다.
(단 A10 은 그대로 유효하다 — 값의 출처가 모델이라는 사실은 파서가 해결하지 않는다.)

### A0 — 자기 세탁 경로는 닫혔다

`result.json` 을 손으로 심어 신뢰 소스로 되돌리려 했으나 **차단**됐다.
`findings.json` / `chain.json` / `run.log` 우회도 전부 차단.
뚫린 것은 위 A11 의 stdout 경로 하나뿐이다.

---

## 정리

| 항목 | 결과 |
|---|---|
| A1 | 5/5 방어 |
| A7 | 방어 (순서·오류 경로) |
| A8 | 파서 fail-safe (A10 은 유효) |
| A0 | 4/5 방어 — **A11 로 1건 관통** |
| A6 | 사건 모양은 방어, 일반화 안 됨 |
| B1 | 승격 견고, 보존 상한 없음 |

**신규 백로그**: A11(★ 스테일 stdout marker 세탁) · A12(빈 오류 메시지) ·
A6 범위 확대(선택) · B1 보관 상한.
기존 백로그 A9(misc raw) · A10(target_liveness 프로브 확인)은 그대로.

A11 은 A0 과 같은 부류(크래시가 성공으로 위장)이고 신뢰 티어가 더 높으므로
백로그 중 우선순위가 가장 높다.
