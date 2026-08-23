#!/usr/bin/env python3
"""Simulation harness for dynamic per-slot memory.

WHY A SIMULATION AT ALL. Everything this feature does that matters happens
across a process boundary — a forked work horse, a SIGKILL from another
container, two slots contending on one lock, a cgroup killing a child. The unit
suite covers the arithmetic with in-process fakes; none of those fakes can fail
the way production would. `data/.worker-memory.lock` does not exist on this
machine and no job directory contains a `worker_mem.jsonl`, so before this
harness the cap-changing half of the feature had never executed anywhere.

WHY IT CANNOT JUST POINT AT THE REAL SLOTS. `_worker_containers` sums every
container whose name carries the slot fragment. Run the governor inside a real
slot and `others` is the other real slot's 4 GiB against a 10.93 GiB budget: only
REFUSALS are reachable, never an allowed expansion, and half the behaviour stays
untested while the harness reports success. So the sim builds its own budget
universe — its own containers, its own redis, its own /data — and points the
governor at it with WORKER_SLOT_NAME_MATCH.

WHY THE MATCH IS AN ENV VAR AND NOT A PATCHED CONSTANT. `run_one_worker` is
launched with multiprocessing "spawn"; the child re-imports the module from
source, so a patched attribute is gone by the time the governor runs. A harness
that patched the constant would silently fall back to "worker-" INSIDE the
dispatching process and aim at production. An env var survives spawn.

Run: python3 scripts/sim_worker_mem.py [--keep]
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MiB = 1024 ** 2
GiB = 1024 ** 3

NET = "simnet-workermem"
REDIS = "simredis-workermem"
SLOTS = ("simslot-1", "simslot-2")
IMAGE = "hextech_ctf_tool-worker"
LABEL = "htct_sim=1"
QUEUE = "simqueue"

# G1: nothing the harness creates may carry the production slot fragment, or a
# leaked container counts against every future real job's heal-on-start.
PROD_FRAGMENT = "worker-"
SIM_FRAGMENT = "simslot-"
assert PROD_FRAGMENT not in NET + REDIS + "".join(SLOTS)

checks = 0
fails = 0
KEEP = "--keep" in sys.argv


def chk(label: str, cond: bool, got=None) -> bool:
    global checks, fails
    checks += 1
    if cond:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got=%r" % (label, got))
    return bool(cond)


def note(msg: str) -> None:
    print("      %s" % msg)


def sh(*args: str, check: bool = True, timeout: int = 120) -> str:
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError("%s -> rc=%d\n%s\n%s"
                           % (" ".join(args), p.returncode, p.stdout, p.stderr))
    return (p.stdout or "") + (p.stderr or "")


def dexec(container: str, code: str, *, check: bool = True) -> str:
    return sh("docker", "exec", container, "python3", "-c", code, check=check)


def cap_of(container: str) -> tuple[int, int]:
    out = sh("docker", "inspect", "-f",
             "{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}", container).split()
    return int(out[0]), int(out[1])


# --------------------------------------------------------------------------
# fixture
# --------------------------------------------------------------------------

class Fixture:
    def __init__(self) -> None:
        # NOT /tmp. A bind mount of a /tmp path silently produces an EMPTY
        # directory in the container here (docker's mount namespace does not
        # share it), and an empty /app/modules is a namespace package: `import
        # modules` then succeeds while every submodule is missing. The harness
        # would be testing the image's baked copy, not the tree under test.
        base = Path.home() / ".hextech-sim"
        base.mkdir(parents=True, exist_ok=True)
        self.host = Path(tempfile.mkdtemp(prefix="simwm-", dir=str(base)))
        self.tree = self.host / "tree"
        self.data = self.host / "data"

    def build(self) -> None:
        # G5: a COPY. ./modules is :ro inside the live slots but rw on the host,
        # and execute_job imports modules.worker_mem at call time — editing the
        # real tree would retarget the live governor on the next real job.
        (self.tree).mkdir(parents=True)
        shutil.copytree(ROOT / "modules", self.tree / "modules")
        shutil.copytree(ROOT / "worker", self.tree / "worker")
        (self.data / "jobs").mkdir(parents=True)
        # A dispatchable job, written into the COPY only so production never
        # gains a module that exists for a test. It lives under modules/crypto/
        # so `func_name.split(".")[1]` is "crypto", which IS an expansion module
        # - naming it anything else would silently exercise only the base path.
        (self.tree / "modules/crypto/simprobe.py").write_text(
            "import time\n"
            "from modules._common import write_meta\n"
            "def run_job(job_id, seconds=1.0):\n"
            "    write_meta(job_id, status='running')\n"
            "    time.sleep(float(seconds))\n"
            "    write_meta(job_id, status='finished')\n"
            "    return {'ok': True}\n")
        # G9: the sim's own settings file. settings_io precedence is file > env,
        # and production's file already pins dynamic_worker_mem=false, so an env
        # var alone would be dead. Never PUT to the live API.
        (self.data / "settings.json").write_text(json.dumps(
            {"worker_slot_mem": "256m", "dynamic_worker_mem": True}, indent=2))

        sh("docker", "network", "create", NET, check=False)
        sh("docker", "rm", "-f", REDIS, *SLOTS, check=False)
        # G3: its own redis. A sim RQ worker on the production DB would pop real
        # jobs, and the boot sweep would delete real registrations.
        sh("docker", "run", "-d", "--name", REDIS, "--network", NET,
           "--label", LABEL, "redis:7-alpine")
        for i, name in enumerate(SLOTS, start=1):
            sh("docker", "run", "-d", "--name", name, "--network", NET,
               "--label", LABEL,
               # G7: launched from the HOST. docker_memguard.sh is on PATH
               # inside a slot and would inject its own --memory.
               "--memory", "256m", "--memory-swap", "256m",
               # G4: never empty, never "1" — an empty WORKER_SLOT makes
               # _runs_cleanup() true and starts a loop that rmtree's /data/jobs.
               "-e", "WORKER_SLOT=%d" % (90 + i),
               "-e", "WORKER_SLOT_NAME_MATCH=%s" % SIM_FRAGMENT,
               "-e", "REDIS_URL=redis://%s:6379/0" % REDIS,
               "-e", "PYTHONPATH=/app",
               # G2: /data isolated by MOUNT, at the same in-container path.
               # runner.py hardcodes /data/jobs while storage.py honours
               # DATA_DIR, so isolating by env would split artifacts across two
               # trees and "the sampler wrote a file" would pass while writing
               # into production.
               "-v", "%s:/data" % self.data,
               "-v", "%s/modules:/app/modules:ro" % self.tree,
               "-v", "%s/worker:/app/worker:ro" % self.tree,
               "-v", "/var/run/docker.sock:/var/run/docker.sock",
               "-w", "/app", IMAGE, "sleep", "3600")
        for _ in range(40):
            if all("running" in sh("docker", "inspect", "-f",
                                   "{{.State.Status}}", n, check=False)
                   for n in SLOTS):
                break
            time.sleep(0.25)
        # A silently-empty mount is the failure mode this guards. Without it the
        # scenarios below exercise whatever modules/ the IMAGE happens to carry
        # and the harness reports on code that is not under test.
        for name in SLOTS:
            got = sh("docker", "exec", name, "sh", "-c",
                     "test -f /app/modules/worker_mem.py && echo MOUNTED || echo EMPTY",
                     check=False)
            if "MOUNTED" not in got:
                raise RuntimeError(
                    "%s: the tree mount did not take (%s). The scenarios would "
                    "have tested the image's baked modules/ instead."
                    % (name, got.strip()))

    def destroy(self) -> None:
        sh("docker", "rm", "-f", REDIS, *SLOTS, check=False)
        sh("docker", "network", "rm", NET, check=False)
        shutil.rmtree(self.host, ignore_errors=True)
        try:                      # leave no empty base dir behind either
            self.host.parent.rmdir()
        except OSError:
            pass


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------

PRELUDE = (
    "import sys,os,pathlib; sys.path.insert(0,'/app');"
    "import modules.worker_mem as wm;"
    # G8: nothing writes a cgroup until it has proved which cgroup it is.
    "assert (wm.own_container_name() or '').startswith('%s'), wm.own_container_name();"
    % SIM_FRAGMENT
)


def s_universe(fx: Fixture) -> None:
    """The harness sees only its own slots; production still sees only its own."""
    out = dexec(SLOTS[0], PRELUDE + "import docker;"
                "print(sorted(c.name for c in wm._worker_containers(docker.from_env())))")
    names = out.strip().splitlines()[-1]
    chk("sim universe is exactly the sim slots", names == str(list(SLOTS)), names)

    out = dexec(SLOTS[0],
                "import sys,os; sys.path.insert(0,'/app');"
                "os.environ.pop('WORKER_SLOT_NAME_MATCH',None);"
                "import modules.worker_mem as wm, docker;"
                "print(sorted(c.name for c in wm._worker_containers(docker.from_env())))")
    prod = out.strip().splitlines()[-1]
    chk("with the override removed, the sim sees ONLY the real slots "
        "(i.e. the sim containers are invisible to production)",
        "simslot" not in prod and "hextech_ctf_tool-worker-1" in prod, prod)


def s_expand_and_gate(fx: Fixture) -> None:
    """An allowed expansion is reachable, and the total gate still refuses."""
    before = cap_of(SLOTS[0])
    out = dexec(SLOTS[0], PRELUDE +
                "r=wm.apply_cap(512*1024*1024); print('R', r.get('applied'), r.get('reason'))")
    chk("an ALLOWED expansion happens (unreachable without the sim universe)",
        "R True" in out, out.strip().splitlines()[-1])
    mem, swap = cap_of(SLOTS[0])
    chk("the expansion landed on the cgroup", mem == 512 * MiB, mem)
    chk("memswap == mem after an expansion", swap == mem, (mem, swap))
    note("before=%r after=%r" % (before, (mem, swap)))

    # 200, not 90: the first version sliced the reason at 90 chars and then
    # asserted on a word that the slice had cut off, so a correct refusal
    # reported as a failure.
    out = dexec(SLOTS[0], PRELUDE +
                "r=wm.apply_cap(64*1024**3); print('R', r.get('applied'), (r.get('reason') or '')[:200])")
    chk("the total gate refuses a want that will not fit the budget",
        "R False" in out and "budget" in out, out.strip().splitlines()[-1])

    # restore for the next scenario
    dexec(SLOTS[0], PRELUDE + "wm.apply_cap(256*1024*1024)")


def s_flock(fx: Fixture) -> None:
    """Two PROCESSES, not two threads. The second must see the first's write.

    Without the lock both read the same pre-lock snapshot of `others` and both
    write; the assertion is that the second one's view already contains the
    first one's cap.
    """
    code = (PRELUDE +
            "import json,time,sys;"
            "want=int(sys.argv[1]);"
            "import docker;"
            "cl=docker.from_env();"
            "pre=sorted((c.name,int((c.attrs.get('HostConfig') or {}).get('Memory') or 0))"
            " for c in wm._worker_containers(cl));"
            "r=wm.apply_cap(want);"
            "print(json.dumps({'want':want,'pre':pre,'applied':r.get('applied'),"
            "'reason':(r.get('reason') or '')[:80]}))")
    procs = []
    for slot, want in ((SLOTS[0], 400 * MiB), (SLOTS[1], 400 * MiB)):
        procs.append(subprocess.Popen(
            ["docker", "exec", slot, "python3", "-c", code, str(want)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    outs = []
    for p in procs:
        o, e = p.communicate(timeout=120)
        line = [l for l in (o or "").splitlines() if l.startswith("{")]
        outs.append(json.loads(line[-1]) if line else {"error": (e or "")[-200:]})

    ran = [o for o in outs if "applied" in o]
    # Without this the whole scenario is vacuous: when both execs die the
    # `applied` values are None, `both_applied` is False, and the serialisation
    # assertion below passes by default while nothing was ever serialised. That
    # is exactly what this harness printed on its first run.
    if not chk("both concurrent apply_cap processes actually ran", len(ran) == 2,
               outs):
        return
    both_applied = all(o.get("applied") for o in outs)
    caps = [cap_of(s)[0] for s in SLOTS]
    note("final caps: %r  results: %r" % (caps, [o.get("applied") for o in outs]))
    # The real assertion: whatever the outcome, the two writers did not both act
    # on a stale snapshot. At least one of them must have observed the other's
    # already-written cap, OR one was refused.
    saw_peer = any(any(v >= 400 * MiB for n, v in o.get("pre", []) if n not in (None,))
                   for o in outs)
    chk("serialised: a writer either saw the peer's new cap or was refused "
        "(both acting on the pre-lock snapshot is the failure)",
        saw_peer or not both_applied, [o.get("pre") for o in outs])

    for s in SLOTS:
        dexec(s, PRELUDE + "wm.apply_cap(256*1024*1024)")


def s_oom_and_escalation(fx: Fixture) -> None:
    """A real cgroup OOM raises oom_kill, the sampler sees it, the escalator acts."""
    code = (PRELUDE +
            "import pathlib,time;"
            "before=wm.sample().get('oom_kill');"
            "seen=[];"
            "esc=wm.OomEscalator();"
            "s=wm.JobSampler('simjob', pathlib.Path('/data/jobs/simjob/worker_mem.jsonl'),"
            "  on_oom=lambda d:(seen.append(d), esc(d)), interval_s=0.2).start();"
            "import subprocess;"
            "rc=subprocess.run(['python3','-c','b=bytearray()\\nfor _ in range(4000): b+=bytearray(1024*1024)']).returncode;"
            "time.sleep(1.5);"
            "summ=s.stop();"
            "print('OOMRESULT', before, wm.sample().get('oom_kill'), rc, seen, "
            "summ.get('oom_kill_delta'), esc.count)")
    out = dexec(SLOTS[0], code, check=False)
    line = [l for l in out.splitlines() if l.startswith("OOMRESULT")]
    chk("the OOM scenario produced a result line", bool(line), out[-400:])
    if not line:
        return
    parts = line[-1].split(None, 4)
    before, after, rc = parts[1], parts[2], parts[3]
    note(line[-1][:200])
    chk("the child was killed by the cgroup, not by a Python MemoryError",
        rc == "-9" or rc == "137", rc)
    chk("this slot's own memory.events:oom_kill rose", int(after) > int(before),
        (before, after))
    chk("the sampler observed the rise and fired on_oom", "seen=[]" not in line[-1]
        and "[]" not in line[-1].split("]")[0] + "]", line[-1])
    chk("with the flag ON the escalator raised the cap",
        cap_of(SLOTS[0])[0] > 256 * MiB, cap_of(SLOTS[0]))
    m, s = cap_of(SLOTS[0])
    chk("memswap == mem after an escalation", m == s, (m, s))

    dexec(SLOTS[0], PRELUDE + "wm.apply_cap(256*1024*1024)")


def s_flag_off_is_inert(fx: Fixture) -> None:
    """With the flag OFF nothing moves — the claim the whole default rests on."""
    settings = fx.data / "settings.json"
    settings.write_text(json.dumps(
        {"worker_slot_mem": "256m", "dynamic_worker_mem": False}, indent=2))
    before = cap_of(SLOTS[0])
    out = dexec(SLOTS[0], PRELUDE +
                "print('D', wm.dynamic_enabled(), wm.desired_cap_bytes('rev'));"
                "e=wm.OomEscalator(); e(1); print('C', e.count)")
    chk("flag OFF: dynamic_enabled() is False in a real container",
        "D False" in out, out.strip().splitlines()[-2:])
    chk("flag OFF: a rev job's desired cap is the base, not 8 GiB",
        "D False %d" % (256 * MiB) in out, out)
    chk("flag OFF: an OOM does not escalate", "C 0" in out, out)
    chk("flag OFF: the cgroup did not move", cap_of(SLOTS[0]) == before,
        (before, cap_of(SLOTS[0])))
    settings.write_text(json.dumps(
        {"worker_slot_mem": "256m", "dynamic_worker_mem": True}, indent=2))


def _start_worker(slot: str) -> None:
    sh("docker", "exec", "-d", slot, "sh", "-c",
       "cd /app && python3 -m worker.runner > /data/worker-%s.log 2>&1" % slot)


def _enqueue(fx: "Fixture", job_id: str, seconds: float) -> None:
    (fx.data / "jobs" / job_id).mkdir(parents=True, exist_ok=True)
    (fx.data / "jobs" / job_id / "meta.json").write_text(
        json.dumps({"module": "crypto", "status": "queued"}))
    code = ("import sys; sys.path.insert(0,'/app');"
            "from redis import Redis; from rq import Queue;"
            "q=Queue('hextech_ctf_tool', connection=Redis.from_url('redis://%s:6379/0'));"
            "j=q.enqueue('modules.crypto.simprobe.run_job', '%s', %r, job_timeout=600);"
            "print('ENQ', j.id)" % (REDIS, job_id, seconds))
    dexec(SLOTS[0], code)


def _wait(fn, timeout=90.0, interval=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def s_dispatch_sampler(fx: Fixture) -> None:
    """A REAL dispatched job must leave worker_mem.jsonl and meta.worker_mem."""
    _start_worker(SLOTS[0])
    job = "simjob-sampler"
    _enqueue(fx, job, 2.0)
    jd = fx.data / "jobs" / job
    got = _wait(lambda: (jd / "worker_mem.jsonl").exists())
    chk("a dispatched job produced worker_mem.jsonl", bool(got),
        sorted(x.name for x in jd.iterdir()) if jd.exists() else "no job dir")
    meta = _wait(lambda: json.loads((jd / "meta.json").read_text()).get("worker_mem"))
    chk("and the summary was merged into meta.worker_mem", bool(meta), meta)
    if meta:
        note("meta.worker_mem = %r" % meta)
        chk("the summary carries a peak", meta.get("peak_bytes", 0) > 0, meta)
    rows = []
    if (jd / "worker_mem.jsonl").exists():
        rows = [json.loads(l) for l in
                (jd / "worker_mem.jsonl").read_text().splitlines() if l.strip()]
    chk("the sample file has a start and a stop row",
        bool(rows) and rows[0].get("event") == "start"
        and rows[-1].get("event") == "stop",
        [r.get("event") for r in rows[:2] + rows[-1:]])


def s_dispatch_sigkill_restore(fx: Fixture) -> None:
    """THE claim the design was upgraded on: an operator Stop SIGKILLs the work
    horse, and the parent's finally still restores the cap."""
    base = 256 * MiB
    job = "simjob-stop"
    _enqueue(fx, job, 120.0)

    raised = _wait(lambda: cap_of(SLOTS[0])[0] > base, timeout=60)
    chk("the dispatched crypto job RAISED this slot's cap (expansion path ran "
        "inside a real worker, not a fake)", bool(raised), cap_of(SLOTS[0]))
    if not raised:
        return
    note("cap during the job: %r" % (cap_of(SLOTS[0]),))

    # A REAL operator Stop.
    #
    # The id must be split. rq 2.0's started_job_registry returns a COMPOSITE
    # `<job_id>:<execution_id>`, and send_stop_job_command with that string is
    # not an error - the worker logs "Not working on job ..., command ignored."
    # and carries on. The first version of this scenario passed the composite,
    # no Stop ever happened, and the harness reported the restore as BROKEN.
    # A false negative about production, produced entirely by the test. So the
    # stop is now verified from the worker's own log before the cap is judged.
    code = ("import sys; sys.path.insert(0,'/app');"
            "from redis import Redis; from rq.command import send_stop_job_command;"
            "from rq import Queue;"
            "c=Redis.from_url('redis://%s:6379/0');"
            "q=Queue('hextech_ctf_tool', connection=c);"
            "ids=[i.split(':')[0] for i in q.started_job_registry.get_job_ids()];"
            "print('STOPPING', ids);"
            "[send_stop_job_command(c, i) for i in ids]" % REDIS)
    out = dexec(SLOTS[0], code, check=False)
    note(out.strip().splitlines()[-1] if out.strip() else "(no output)")

    log = fx.data / ("worker-%s.log" % SLOTS[0])
    killed = _wait(lambda: log.exists() and "Killed horse pid" in log.read_text(),
                   timeout=60)
    if not chk("the Stop was ACCEPTED by the worker (log says it killed the "
               "horse; 'command ignored' means the test proved nothing)",
               bool(killed),
               log.read_text()[-300:] if log.exists() else "no worker log"):
        return

    back = _wait(lambda: cap_of(SLOTS[0])[0] == base, timeout=60)
    chk("after a real Stop (SIGKILL to the work horse) the PARENT restored the "
        "cap to base — the whole reason the restore lives in execute_job",
        bool(back), cap_of(SLOTS[0]))
    m, sw = cap_of(SLOTS[0])
    chk("memswap == mem after the restore", m == sw, (m, sw))


def s_leak_proof(fx: Fixture) -> None:
    """Nothing the harness made is visible to production, and the real slots
    are exactly as they were."""
    out = sh("docker", "ps", "-a", "--format", "{{.Names}}")
    leaked = [n for n in out.split() if PROD_FRAGMENT in n
              and not n.startswith("hextech_ctf_tool-worker-")]
    chk("no container carrying the production slot fragment was created",
        leaked == [], leaked)
    for name in ("hextech_ctf_tool-worker-1", "hextech_ctf_tool-worker-2"):
        m, s = cap_of(name)
        chk("%s untouched at 4 GiB" % name, m == 4 * GiB and s == m, (m, s))
    prod_lock = Path("/home/yadohyun/HexTech_CTF_TOOL/data/.worker-memory.lock")
    chk("the harness did not create the production lock file",
        not prod_lock.exists(), prod_lock.exists())
    prod_settings = json.loads(
        Path("/home/yadohyun/HexTech_CTF_TOOL/data/settings.json").read_text())
    chk("production settings still have the flag OFF",
        prod_settings.get("dynamic_worker_mem") is False,
        prod_settings.get("dynamic_worker_mem"))


SCENARIOS = [
    ("universe isolation", s_universe),
    ("expansion + total gate", s_expand_and_gate),
    ("two-process flock", s_flock),
    ("real cgroup OOM + escalation", s_oom_and_escalation),
    # dispatch scenarios last: they start a real RQ worker in the slot, which
    # from then on reacts to every job, so nothing that inspects caps by hand
    # may run after them.
    ("real dispatch: sampler artifacts", s_dispatch_sampler),
    ("real dispatch: SIGKILL then restore", s_dispatch_sigkill_restore),
    ("flag OFF is inert", s_flag_off_is_inert),
]


def main() -> int:
    fx = Fixture()
    try:
        print("=== building fixture in %s" % fx.host)
        fx.build()
        for title, fn in SCENARIOS:
            print("\n--- %s" % title)
            try:
                fn(fx)
            except Exception as e:
                chk("scenario %r completed without an exception" % title, False,
                    "%s: %s" % (type(e).__name__, e))
        print("\n--- leak proof")
        s_leak_proof(fx)
    finally:
        if KEEP:
            print("\n[--keep] fixture left at %s (containers still up)" % fx.host)
        else:
            fx.destroy()
            print("\n=== fixture destroyed")

    print("\n%d checks, %d failed" % (checks, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
