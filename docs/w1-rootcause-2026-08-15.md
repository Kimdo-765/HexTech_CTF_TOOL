# W1 — 워커 슬롯 좌초 근본 원인 (2026-08-15)

`5c26b3b02654`(crypto)가 큐에서 안 나간다는 라이브 장애로 시작. 원인은 그 job 이
아니라 **슬롯 하나가 이미 끝난 job 에 50분간 묶여 있던 것**이었다.

Codex 조사(0643) + Claude 독립 검증. 조사 중 **Claude 주장 네 건이 반증**됐다.

---

## 근본 원인 — 3단 합성 결함

```
06:07:10  run/start                                    timeout_s=3000
06:07:32  OOB flag callback 도착 (+22초)
          → api/routes/collector.py:133  write_meta(status="finished")
          → modules/_common.py:1105      terminal 전이 감지
          → modules/_common.py:989       label 로 컨테이너 force 제거
06:07:32  [reap] removed 1 container(s): cranky_aryabhata   ← **러너 자신**
06:57:11  [runner] timeout after 3000s — killing container
06:57:11  run/spawn_failed  404 No such container
```

사슬을 닫는 코드 세 줄:

| 위치 | 내용 |
|---|---|
| `modules/_runner.py:737` | 러너 컨테이너가 `labels={"hextech_ctf_tool_job_id": job_id, ...}` 를 단다 |
| `modules/_common.py:989` | terminal reaper 가 **그 라벨 전체**를 `force=True, v=True` 로 제거 |
| `modules/_runner.py:79` | `WEB_TIMEOUT_S = 3000` — **50분은 우연이 아니라 상한값 그 자체** |

그리고 `modules/_runner.py:475-517` 이 `container.reload()` 의 404 를
`status="unknown"` 으로 삼켜 **사라진 컨테이너를 상한까지 폴링**한다.

즉 **OOB flag 콜백이 실행 중인 러너를 자기 job 의 정리 대상으로 만들었다.**

## 발동 조건 — 두 가지가 함께 필요하다

콜백을 받은 job 2건을 대조해 정확히 갈렸다.

```
6cfe18c4130e  콜백 run/start +22초   flag 있음 → status=finished 기록 → 좌초
5a2e729d3802  콜백 run/start −70초   flag 없음 → status 불변          → 무사
```

1. **콜백이 러너 실행 중에 도착** (`run/start` 후 `run/exit` 전)
2. **콜백이 새 flag 를 담아** collector 가 terminal 을 쓴다
   (`collector.py:132` — `if flags and set(flags) != set(meta.flags)`)

`5a2e729d3802` 는 콜백을 받고도 flag 가 없어 전이가 없었고 러너는 정상 exit 했다.
자연 대조군이다.

## 빈도 — 드물지만 낮게 보면 안 된다

```
보존 코퍼스 19건 중 정확한 서명(reap → timeout → 404)  1건
부분 일치                                              0건
콜백 수신 job                                          2건
```

⚠ **전제가 드문 것과 위험이 낮은 것은 다르다.** web 모듈에서 OOB 콜백은
**정상 성공 경로**다 — 원격 봇이 flag 를 보내는 유일한 방법이 collector 콜백이다
(`web_remote_bot_oob_callback_only`). 즉 **web 에서 봇 익스플로잇이 성공할 때마다**
이 조건이 성립할 수 있고, 그때 러너가 아직 돌면 슬롯이 50분 묶인다.
**성공했을 때 벌어지는 일**이라 더 나쁘다. TTL 7일이라 과거 사례는 소실됐을 수 있다.

## 왜 아무도 못 알아챘는가

```
RQ            work horse 는 살아 있는 프로세스 → status='started', heartbeat 정상 갱신
meta          collector 가 별도 프로세스에서 finished 로 기록
API           rq_status 를 노출하지만 두 상태를 대조하지 않는다
UI            meta 가 terminal 이면 polling 중단 (web-ui/app.js:484-491)
```

**두 상태 평면이 동시에 "정상"으로 렌더링됐다.** 고아 감지도 안 걸린다 —
rq_status 도 heartbeat 도 정직하게 "살아 있다"고 말하고, 실제로 프로세스는 살아 있다.

## 조사 중 반증된 것 — 전부 Claude 주장

| 주장 | 반증 |
|---|---|
| asyncgen 에러가 원인 | 정상 완료 3건에서도 같은 에러 발생 (Claude 자가 반증) |
| 좌초가 안 풀린다 | 50분 뒤 풀림 |
| 재발 3건 | `d5e…`·`c09…` 는 명시적 `stopped`, `67b…` 는 옛 hybrid import 실패 — 전부 별개 |
| 좀비가 원인 | Codex 격리 재현에서 `claude` 자식 0개로도 3001초 발생 |

**UNVERIFIABLE 로 남은 것**: 걸린 프로세스의 파이썬 스택(프로세스 소멸).
Codex 가 지어내지 않고 그대로 적었다.

## 수정 방향 (미구현 — operator 결정 사항)

1. **terminal reaper 가 러너를 지우지 않게** — `hextech_ctf_tool_role=runner` 라벨을
   제외하거나, 러너 자신이 도는 동안은 회수 대상에서 뺀다. 가장 직접적이다.
2. **404 를 종료로 해석** — `_runner.py:475-517` 이 `NotFound` 를 `unknown` 이 아니라
   "컨테이너가 사라짐"으로 처리해 즉시 반환. 1번이 막혀도 50분이 몇 초가 된다.
3. **감지 축** — `meta terminal + rq started + 미종결 run 이벤트 + grace 초과`.
   Claude 가 코퍼스 19건에 돌려 **오탐 0**을 확인했으나 좌초가 이미 풀려
   **민감도는 미검증**이다. 조기 콜백의 짧은 창이 같은 조합이 되므로
   **나이 임계가 반드시 함께 필요하다** (Codex·Claude 독립 동일 결론).
   ⚠ 경고 조건이지 자동 kill 조건이 아니다.

1과 2는 독립이고 **둘 다 하는 것이 맞다** — 1은 원인, 2는 안전망이다.
