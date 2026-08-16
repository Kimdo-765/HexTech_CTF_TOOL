# 워커 슬롯 좌초 — `6cfe18c4130e` 현장 보존 (2026-08-15T06:54:02+00:00)

슬롯을 풀면 사라지는 휘발성 증거다. 조사 재현의 유일한 사례이므로 먼저 남긴다.

## RQ 상태
```
rq:worker:htct-s2-w0
  state='busy' current_job='eab2c5b5ad8e'
  last_heartbeat='2026-08-15T06:53:52.545684Z'
rq:worker:htct-s1-w0
  state='busy' current_job='6cfe18c4130e'
  last_heartbeat='2026-08-15T06:53:50.399841Z'
rq:job:6cfe18c4130e status          = 'started'
rq:job:6cfe18c4130e started_at      = '2026-08-15T05:35:20.298882Z'
rq:job:6cfe18c4130e ended_at        = ''
rq:job:6cfe18c4130e worker_name     = 'htct-s1-w0'
rq:job:6cfe18c4130e last_heartbeat  = '2026-08-15T06:53:50.399900Z'
큐 대기 = ['5c26b3b02654']
```

## 프로세스 트리 (worker-1)
```
1       0 Ss      05:41:17 00:00:00 /sbin/docker-init -- python -m worker.runner
      7       1 Sl      05:41:17 00:00:01 python -m worker.runner
      9       7 S       05:41:17 00:00:00 /usr/local/bin/python -c from multiprocessing.resource_tracker import main;main(3)
     10       7 Sl      05:41:17 00:00:06 /usr/local/bin/python -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=4, pipe_handle=6) --multiprocessing-fork
     12      10 S       05:41:17 00:00:05 /usr/local/bin/python -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=4, pipe_handle=11) --multiprocessing-fork
  58100      10 Sl      01:18:43 00:00:04 /usr/local/bin/python -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=4, pipe_handle=6) --multiprocessing-fork
  62985   58100 Z          55:06 00:00:11 [claude] <defunct>
  63445       0 Rs         00:00 00:00:00 ps -eo pid,ppid,stat,etime,time,args --no-headers
```

## 좀비와 부모의 커널 상태
```
좀비 자식 pid=62985 comm=(claude) state=Z ppid=58100 wchan=0
job 프로세스 pid=58100 comm=(python) state=S ppid=10 wchan=do_epoll_wait
Name:	claude
State:	Z (zombie)
PPid:	58100
Threads:	1
```

## meta 최종 상태 (job 은 성공했다)
```
status           = finished
stage            = sandbox-run
module           = web
agent_turns      = 50
flags            = ['DH{want_it?_go_through_me/FubWdrbGFkc21nbGFka25nbWFk}']
finished_at      = 2026-08-15T06:07:32.497229+00:00
updated_at       = 2026-08-15T06:07:32.497229+00:00
agent_provider   = gpt
gpt_runtime      = codex
```

## run.log 마지막 6줄
```
[06:07:10] [judge] prejudge issue: Composer exec() fallback is only reached if the PHAR bootstrap throws; if admin-app has egress and the phar loads, 
[06:07:10] [judge] prejudge issue: VERIFIED GOOD: /get-account auth bypass (endpoint name is 'hello'/'set', never 'set-secret'), remove() lacks isVali
[06:07:10] [judge] prejudge issue: No hang risk: runtime bounded ~6min, daemon threads, cmd.Start() returns immediately, upload measured 12 MiB/s so t
[06:07:10] [runner] sandbox timeout: 3000s (module=web, sage=False, remote=True, override=None)
[06:07:10] [runner] executing exploit.py (target=http://host3.dreamhack.games:15565/, sage=False, judge=True, timeout=3000s) ...
[06:07:32] [reap] removed 1 container(s): cranky_aryabhata
```

## asyncgen 에러는 원인이 아니다 (반증 완료)

워커 로그의 `RuntimeError: aclose(): asynchronous generator is already running` 을 처음엔 원인으로 봤으나 틀렸다. 같은 에러가 정상 완료한 job 들에서도 반복 발생했다:

```
f3a67cd86353  aclose 발생 → Job OK
eb18a95f4399  aclose 발생 → Successfully completed
5a2e729d3802  aclose 발생 → 정상 완료 (87턴, no_flag)
6cfe18c4130e  aclose 발생 → 걸림
```
4건 중 3건이 같은 에러를 내고도 슬롯을 반환했다. 이걸 원인으로 지목했다면 틀린 곳을 고쳤을 것이다.

