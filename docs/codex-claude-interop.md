# Codex ↔ Claude 무인 협업 브리핑

이 파일을 **Codex 세션에 그대로 읽히면 된다.** 운영자의 중간 중계 없이 두
세션이 주고받기 위해 Codex가 알아야 할 Claude 쪽 사실과, 공유 프로토콜.

---

## 0. 먼저 — 지금 없는 것은 "정보"가 아니라 "채널"이다

현재 유일한 채널은 **운영자의 복사·붙여넣기**다. Claude와 Codex는 서로의
출력을 볼 수 없다. 따라서 필요한 것은 Claude에 대한 설명이 아니라
**공유 매체 + 프로토콜**이고, 설명은 그 위에 얹힌다.

다행히 **두 세션은 같은 파일시스템을 본다**(Codex는 이미
`docs/hybrid-agent-plan.md`를 줄 번호까지 읽었다). 새 인프라 없이 파일 기반
프로토콜이 오늘 바로 성립한다.

---

## 1. Claude 쪽 사실 (Codex가 알아야 할 것)

### 1.1 정체와 위치

| 항목 | 값 |
|---|---|
| 모델 | Claude Opus 5 (1M context), Claude Code CLI |
| 실행 형태 | **백그라운드 job** — 운영자가 자리를 비워도 계속 진행 |
| cwd | `/home/yadohyun/HexTech_CTF_TOOL/.claude/worktrees/integrated-refactor` |
| 트리 소유 | Claude = **worktree**, Codex = **메인 체크아웃**. 상호 침범 금지 |

**cwd는 하드 제약이다.** Claude는 메인 체크아웃 루트로 `cd`하지 않는다(읽기는
가능, 쓰기는 하지 않음). Codex가 "Claude가 메인 트리에서 X를 해달라"는 식의
핸드오프를 설계하면 그 단계는 반드시 막힌다.

### 1.2 Claude가 운영자 승인 없이 **하지 않는** 것

핸드오프 설계에서 이걸 Claude에게 요구하면 루프가 멈춘다.

- `main`에 직접 push / force-push / merge
- `gh pr create` (자율 실행이 차단돼 있음)
- 실행 중인 job을 kill 하거나 강제 재시작
- 운영자 본인 체크아웃에서의 commit / 브랜치 전환
- 커밋·푸시·머지 일반 — **명시적 지시가 있을 때만**

→ 그래서 baseline은 `main`이 아니라 **브랜치**여야 한다.

### 1.3 Claude가 자율로 **하는** 것

- 저장소 전체 읽기, grep, 테스트 실행
- docker 빌드/실행, 컨테이너 exec (`DOCKER_HOST=unix:///var/run/docker.sock
  /snap/bin/docker` — 호스트 `docker`는 Windows 바이너리에 가려져 있음)
- 자기 worktree 브랜치에서의 구현 작업
- **Codex의 사실 주장을 코드로 검증하고 반박**

### 1.4 [중요] Claude의 컨텍스트는 휘발한다

Claude 세션은 길어지면 **압축(compaction)** 된다. 즉:

> **디스크에 없는 것은 존재하지 않는다.**

- "앞서 합의한 대로"는 유효한 참조가 아니다. 매 턴은 **자기완결적**이어야 한다.
- 모든 결정·근거·상태는 파일에 남긴다.
- Codex가 이전 턴을 인용할 때는 **파일 경로 + 줄 번호**로 인용한다.

Codex 쪽 세션도 `codex resume --last`로 이어지긴 하지만, 같은 원칙을 지키면
어느 쪽이 죽어도 루프가 복구된다.

---

## 2. 검증 프로토콜 — 실제로 겪은 실패에서 뽑은 규칙

이 규칙들은 이론이 아니라 **이번 설계 대화에서 양쪽이 실제로 낸 오류**다.

### R1. 주장에는 `file:line`을 붙인다. 없으면 가설이지 발견이 아니다.

### R2. 상대의 파일 상태를 단언하기 전에 **다시 읽는다**

- 실제 사례: Codex가 "Claude의 정정본이 디스크에 저장되지 않았다"고 단언했으나
  실제로는 `docs/hybrid-agent-plan.md:279`에 있었다(오래된 사본을 읽음).
- 파일 기반 채널의 **1번 실패 모드**다. 턴 파일은 **append-only**로 하고, 매
  턴에 `git rev-parse HEAD`와 참조 파일의 mtime을 찍는다.

### R3. 메커니즘을 읽었다고 방향까지 안 것은 아니다

- 실제 사례: Claude가 `_monitor.py`의 provider 인지 로직을 인용하면서 그 내용이
  *gpt에서 끄는 것*임을 반대로 읽었다. 또 `_AUP_RECOVERY_STEPS`에 `other_provider`
  단이 이미 있는데 "갈 곳이 없다"고 썼다.
- 인용한 코드는 **그 자리에서 읽어 인용문을 붙인다**.

### R4. 분쟁 해결: 실행 가능한 증거가 이긴다

양쪽 다 코드를 인용하면 **실행해서** 정한다(테스트, 컨테이너 exec, 실측).
어느 쪽도 실행 증거가 없으면 운영자에게 올린다.

### R5. 검수 게이트는 "읽기"가 아니라 **실행 산출물**로 닫는다

diff를 읽어서 검증 불가능한 항목은 기계적 아티팩트를 요구한다
(characterization test / raise하는 test double / 거부 assert).
합의된 목록은 `docs/hybrid-agent-plan.md` §8 참조.

### R6. [필수] 종료 규칙 — 무한 핑퐁 방지

이번 설계는 **4라운드** 돌았고 매 라운드가 실질 개선을 냈지만, 코드는 한 줄도
쓰이지 않았다. 서로 "한 가지 더" 찾도록 보상받는 두 에이전트는 **스스로 멈추지
않는다.** 그래서:

- **한 라운드가 코드로 검증된 결함을 0건 내면 그 단계는 통과**로 닫는다.
- 단계당 **최대 3라운드**. 초과하면 진행하지 말고 운영자에게 에스컬레이션한다.
- 새 요구를 추가하려면 **기존 요구 하나를 빼거나** 운영자 승인을 받는다
  (scope creep 방지).

### R7. 상대가 응답하지 않으면 조용히 기다리지 않는다

Codex는 ChatGPT OAuth의 **5시간 / 주간 윈도우**에 묶여 있다
(`modules/codex_rate_limit.py`). 윈도우가 소진되면 Codex 턴이 그냥 안 온다.
**턴 타임아웃(예: 30분)** 을 넘기면 대기하지 말고 `.handoff/STATE.md`에
`blocked_on: codex-timeout`을 적고 운영자에게 알린다.

---

## 3. 채널 설계

```
.handoff/
  PROTOCOL.md        ← 이 파일로의 포인터 + 규칙 요약 (양쪽이 먼저 읽음)
  STATE.md           ← 단일 진실: 현재 단계, 소유자, 게이트 상태
  turns/
    0001-codex.md
    0002-claude.md
    ...
```

**턴 파일 규약** (append-only, 절대 이전 턴 수정 금지):

```markdown
# turn 0002 — claude
sha: <git rev-parse HEAD>
stage: 1  (provider_for_role)
verdict: <done | blocked | defect-found>
findings:
  - file: modules/agent_provider.py:380
    claim: ...
    evidence: <실행한 명령과 출력, 또는 인용문>
artifacts:
  - scripts/test_role_routing.py  (12 checks, 0 failed)
next_owner: codex
blocked_on: <없으면 빈칸>
```

`verdict`와 `next_owner`가 기계적으로 읽히므로, 감시 스크립트가 이걸로 기동한다.

### 3.1 Claude 쪽 자동 대기 — 가능

Claude는 `Monitor`(persistent) + `inotifywait -m`로 `.handoff/turns/`를 감시해
Codex 턴 파일이 생기면 **스스로 깨어난다.** 폴링도, 운영자 개입도 필요 없다.

### 3.2 Codex 쪽 자동 기동 — 래퍼 한 장이 필요

Codex CLI는 상주 감시자가 아니다. 다만 `codex exec`(비대화)와
`codex resume --last`(직전 세션 이어받기)가 있으므로 **~15줄 래퍼**로 해결된다.

```bash
#!/usr/bin/env bash
# codex-watch.sh — claude 턴이 생기면 codex를 깨운다
cd /home/yadohyun/HexTech_CTF_TOOL
while inotifywait -q -e create,close_write .handoff/turns; do
  latest=$(ls -1 .handoff/turns | tail -1)
  case "$latest" in *-claude.md) ;; *) continue ;; esac
  codex exec --json "$(cat <<EOF
.handoff/PROTOCOL.md 와 .handoff/STATE.md 를 읽고,
.handoff/turns/$latest 에 응답하는 새 턴 파일을 append 하라.
규칙: 주장에는 file:line 을 붙이고, 상대 파일을 단언하기 전에 다시 읽어라.
EOF
)"
done
```

**정직한 한계**: 이 래퍼가 없으면 루프는 **1.5방향**이다 — Claude는 Codex를
기다릴 수 있지만 Codex는 누군가 기동해 줘야 한다.

### 3.3 대안 — `codex mcp-server`, 그러나 권장하지 않는다

Codex는 `codex mcp-server`로 stdio MCP 서버가 될 수 있고, 그러면 Claude가
Codex를 **도구처럼 직접 호출**할 수 있다. 채널로는 가장 깔끔하다.

**그런데 이 설계의 전제를 깨뜨린다.** 하이브리드의 근거는 "다른 벤더의 prior가
공유 편향을 제거한다"였다. Claude가 Codex를 호출하면 **Claude가 질문의 틀을
정한다** — 독립 검수자가 아니라 하위 에이전트가 된다. 이 저장소에는 이미
`adversarial_skeptic_prompt_bias`(치우친 검증 프롬프트가 36/36을 기각) 기록이
있다.

→ **검수 게이트는 파일 기반 피어 프로토콜**로(각자 아티팩트를 직접 읽음),
   MCP는 쓰더라도 기계적 질의에만.

---

## 4. Codex가 Claude에게 **알려줘야** 할 것 (역방향)

대칭으로 필요하다. Codex 첫 턴에 적어 두면 좋다.

- Codex 모델 / effort / **샌드박스 모드**(read-only vs full access)
- 메인 체크아웃에 **쓰기·커밋이 가능한지**
- docker / 테스트 실행이 가능한지
- **현재 5h·주간 윈도우 잔여율** (`codex exec` 로 소진되면 루프가 멈춘다)
- 컨텍스트 유지 방식(`resume --last` 사용 여부)

---

## 5. 최소 시작 절차

1. 운영자가 `.handoff/` 를 만들고 이 파일을 `PROTOCOL.md`에서 가리킨다.
2. Codex 세션에 이 파일 경로를 준다 → Codex가 §4 항목을 담아 `0001-codex.md`
   작성 (0단계 baseline 커밋 결과 포함).
3. Claude가 Monitor로 감지 → `0002-claude.md` 응답.
4. `codex-watch.sh` 를 띄우면 그때부터 운영자 개입 없이 순환한다.
5. **R6 종료 규칙**과 **R7 타임아웃**이 루프를 끝내거나 에스컬레이션한다.
