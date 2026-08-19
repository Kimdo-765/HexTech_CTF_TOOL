#!/usr/bin/env python3
"""Pin web's opt-in Docker force without breaking its optional baseline.

The system prompt always offers a bundled Dockerfile as an agent-decided
runtime-fidelity check.  The ``docker_challenge`` form/meta switch is additive:
ON appends the shared mandatory BUILD+RUN block, while OFF leaves the prompt
baseline unchanged.  ``run_job`` sweeps/reaps labelled containers in both cases.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import importlib.util
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = (
    "none",
    "drop-optional-prompt",
    "drop-web-checkbox",
    "drop-web-acceptance",
    "drop-web-persistence",
    "drop-web-injection",
    "gate-startup-reap",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

route_src = (ROOT / "api" / "routes" / "web_module.py").read_text()
html_src = (ROOT / "web-ui" / "index.html").read_text()
prompt_src = (ROOT / "modules" / "web" / "prompts.py").read_text()
analyzer_src = (ROOT / "modules" / "web" / "analyzer.py").read_text()
common_src = (ROOT / "modules" / "_common.py").read_text()

if args.mutate == "drop-optional-prompt":
    prompt_src = prompt_src.replace("RUN THE CHALLENGE LOCALLY", "REMOVED", 1)
elif args.mutate == "drop-web-checkbox":
    html_src = html_src.replace('name="docker_challenge"', 'name="docker_challenge_removed"', 1)
elif args.mutate == "drop-web-acceptance":
    route_src = route_src.replace(
        "docker_challenge: bool = Form(False),",
        "docker_challenge: bool = False,",
        1,
    )
elif args.mutate == "drop-web-persistence":
    route_src = route_src.replace(
        '"docker_challenge": docker_challenge,',
        '"docker_challenge_removed": docker_challenge,',
        1,
    )
elif args.mutate == "drop-web-injection":
    analyzer_src = analyzer_src.replace(
        "_docker_block = docker_challenge_block(job_id)",
        '_docker_block = ""',
        1,
    )
elif args.mutate == "gate-startup-reap":
    marker = (
        '    reap_chal_containers(job_id, lambda s: log_line(job_id, s), '
        'reason="startup sweep")'
    )
    analyzer_src = analyzer_src.replace(
        marker,
        '    if read_meta(job_id).get("docker_challenge"):\n'
        '        reap_chal_containers(job_id, lambda s: log_line(job_id, s), '
        'reason="startup sweep")',
        1,
    )

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def function(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function not found: {name}")


def call_name(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


route_tree = ast.parse(route_src)
analyze_web = function(route_tree, "analyze_web")
route_arguments = [*analyze_web.args.args, *analyze_web.args.kwonlyargs]
route_defaults = [
    *([None] * (len(analyze_web.args.args) - len(analyze_web.args.defaults))),
    *analyze_web.args.defaults,
    *analyze_web.args.kw_defaults,
]
route_parameter_defaults = dict(zip((arg.arg for arg in route_arguments), route_defaults))
docker_default = route_parameter_defaults.get("docker_challenge")
docker_is_opt_in_form = (
    isinstance(docker_default, ast.Call)
    and call_name(docker_default) == "Form"
    and len(docker_default.args) == 1
    and isinstance(docker_default.args[0], ast.Constant)
    and docker_default.args[0].value is False
)
persisted_pairs = {
    (key.value, value.id)
    for node in ast.walk(analyze_web)
    if isinstance(node, ast.Dict)
    for key, value in zip(node.keys, node.values)
    if isinstance(key, ast.Constant)
    and isinstance(key.value, str)
    and isinstance(value, ast.Name)
}

web_start = html_src.index('<section id="panel-web"')
web_end = html_src.index('<section id="panel-', web_start + 1)
web_panel = html_src[web_start:web_end]

check("standalone web form offers the Docker opt-in",
      bool(re.search(r'name=["\']docker_challenge["\']', web_panel)), True)
check("standalone web route accepts the box as Form(False)",
      docker_is_opt_in_form, True)
check("standalone web meta persists the accepted value",
      ("docker_challenge", "docker_challenge") in persisted_pairs, True)
check("the UI explains ON is mandatory and OFF preserves agent choice",
      "require build &amp; run" in web_panel and "agent-decided optional" in web_panel, True)
check("the route explains the additive force and unconditional cleanup",
      "opt-in is additive" in route_src and "startup/finally label reaps" in route_src, True)

check("web's system prompt always contains the local-Docker section",
      "RUN THE CHALLENGE LOCALLY" in prompt_src, True)
check("the prompt leaves execution agent-decided rather than mandatory",
      "This is OPTIONAL" in prompt_src, True)
check("the prompt specifies the reaper's job label",
      "--label hextech_job=$JOB_ID" in prompt_src, True)
check("the shared helper documents web's OFF/ON split",
      "Web retains its always-available optional system guidance" in common_src
      and "mandatory when it is on" in common_src, True)

analyzer_tree = ast.parse(analyzer_src)
run_agent = function(analyzer_tree, "_run_agent")
system_prompt_values = []
for node in ast.walk(run_agent):
    if call_name(node) != "make_main_session_options":
        continue
    for keyword in node.keywords:
        if keyword.arg == "system_prompt":
            system_prompt_values.append(
                keyword.value.id if isinstance(keyword.value, ast.Name) else None
            )
check("_run_agent passes SYSTEM_PROMPT without consulting meta",
      system_prompt_values, ["SYSTEM_PROMPT"])
docker_calls = [
    node
    for node in ast.walk(run_agent)
    if call_name(node) == "docker_challenge_block"
    and len(node.args) == 1
    and isinstance(node.args[0], ast.Name)
    and node.args[0].id == "job_id"
]
check("_run_agent reads the shared force block for this job",
      len(docker_calls), 1)
check("_run_agent appends the non-empty force block to the user prompt",
      '_docker_block = docker_challenge_block(job_id)' in analyzer_src
      and 'user_prompt = user_prompt + "\\n\\n" + _docker_block' in analyzer_src, True)

run_job = function(analyzer_tree, "run_job")
startup_reaps = [
    statement
    for statement in run_job.body
    if isinstance(statement, ast.Expr)
    and call_name(statement.value) == "reap_chal_containers"
]
tries = [statement for statement in run_job.body if isinstance(statement, ast.Try)]
finally_reaps = [
    statement
    for try_node in tries
    for statement in try_node.finalbody
    if isinstance(statement, ast.Expr)
    and call_name(statement.value) == "reap_chal_containers"
]
check("run_job performs an unconditional top-level startup sweep",
      len(startup_reaps), 1)
check("run_job performs an unconditional finally reap",
      len(finally_reaps), 1)

# Execute the real reaper against a deterministic fake Docker CLI.  This pins
# label discovery, deduplication, force-removal, network cleanup and logging
# without requiring a daemon in the ordinary offline test suite.
with tempfile.TemporaryDirectory(prefix="web-docker-contract-") as td:
    temp = Path(td)
    jobs = temp / "jobs"
    jobs.mkdir()
    settings = temp / "settings.json"
    settings.write_text("{}")
    os.environ.update(
        DATA_DIR=str(temp), JOBS_DIR=str(jobs), SETTINGS_PATH=str(settings)
    )

    if importlib.util.find_spec("docker") is None:
        docker_stub = types.ModuleType("docker")
        docker_stub.from_env = lambda *a, **k: None
        docker_stub.DockerClient = type("DockerClient", (), {})
        docker_errors = types.ModuleType("docker.errors")
        for error_name in (
            "APIError", "NotFound", "ImageNotFound", "DockerException",
            "NullResource",
        ):
            setattr(docker_errors, error_name, type(error_name, (Exception,), {}))
        docker_types = types.ModuleType("docker.types")
        docker_types.Mount = type(
            "Mount", (), {"__init__": lambda self, **kwargs: None}
        )
        docker_stub.errors = docker_errors
        docker_stub.types = docker_types
        sys.modules.update({
            "docker": docker_stub,
            "docker.errors": docker_errors,
            "docker.types": docker_types,
        })

    sys.path.insert(0, str(ROOT))
    from modules._common import docker_challenge_block, reap_chal_containers

    # Execute the real ON/OFF helper contract against deterministic web jobs.
    # OFF must be byte-for-byte additive (empty block); ON must issue commands,
    # not merely echo the value persisted in meta.
    for job_id, enabled in (("web-off", False), ("web-on", True)):
        root = jobs / job_id
        (root / "src").mkdir(parents=True)
        (root / "src" / "Dockerfile").write_text("FROM busybox\nCMD httpd -f -p 8080\n")
        (root / "meta.json").write_text(json.dumps({
            "id": job_id, "module": "web", "docker_challenge": enabled,
        }))
    off_block = docker_challenge_block("web-off")
    on_block = docker_challenge_block("web-on")
    check("OFF emits no force block at all", off_block, "")
    check("ON detects web's bundled Dockerfile",
          "/data/jobs/$JOB_ID/src/Dockerfile" in on_block, True)
    check("ON requires both build and run instead of leaving agent discretion",
          "BUILD IT AND RUN IT" in on_block
          and "docker build" in on_block
          and "docker run" in on_block, True)

    # Drive the real web prompt assembler with the expensive agent/report paths
    # replaced by recorders.  This proves the block reaches the actual
    # ``initial_prompt`` boundary, not only that the helper can render in
    # isolation.  The system prompt must stay byte-identical across the switch.
    if importlib.util.find_spec("anyio") is None:
        sys.modules["anyio"] = types.ModuleType("anyio")
    if "modules._runner" not in sys.modules:
        runner_stub = types.ModuleType("modules._runner")
        runner_stub.attempt_sandbox_run = lambda *a, **k: None
        sys.modules["modules._runner"] = runner_stub
    from modules.web import analyzer as web_analyzer

    captured_prompts: dict[str, str] = {}
    captured_system_prompts: dict[str, str] = {}

    def fake_options(*, job_id, system_prompt, **kwargs):
        captured_system_prompts[job_id] = system_prompt
        return object()

    async def fake_main(job_id, **kwargs):
        captured_prompts[job_id] = kwargs["initial_prompt"]
        return None

    async def fake_report(**kwargs):
        return None

    web_analyzer.make_main_session_options = fake_options
    web_analyzer.run_main_agent_session = fake_main
    web_analyzer.run_report_phase = fake_report
    web_analyzer.cleanup_job_processes = lambda *a, **k: None
    web_analyzer.collect_outputs = lambda *a, **k: {}
    web_analyzer.log_line = lambda *a, **k: None

    for job_id in ("web-off", "web-on"):
        asyncio.run(web_analyzer._run_agent(
            job_id, None, "http://example.test", None, False,
        ))

    check("OFF final user prompt contains no force stanza",
          "DOCKER CHALLENGE (you opted in" in captured_prompts["web-off"], False)
    check("ON final user prompt reaches the agent with the mandatory stanza",
          "BUILD IT AND RUN IT" in captured_prompts["web-on"], True)
    check("ON/OFF preserve the same optional system prompt",
          captured_system_prompts["web-on"] == captured_system_prompts["web-off"]
          and "This is OPTIONAL" in captured_system_prompts["web-off"], True)

    calls = temp / "docker.calls"
    fake_bin = temp / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "with open(os.environ['FAKE_DOCKER_CALLS'], 'a') as f:\n"
        "    f.write(' '.join(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1:4] == ['ps', '-aq', '--filter']:\n"
        "    value = sys.argv[4] if len(sys.argv) > 4 else ''\n"
        "    if value == 'label=hextech_job=web-contract':\n"
        "        print('container-b\\ncontainer-a')\n"
        "    elif value == 'name=^chal_web-contract':\n"
        "        print('container-a')\n"
    )
    fake_docker.chmod(0o755)
    os.environ["FAKE_DOCKER_CALLS"] = str(calls)
    os.environ["PATH"] = str(fake_bin) + os.pathsep + os.environ.get("PATH", "")

    logs: list[str] = []
    removed = reap_chal_containers("web-contract", logs.append, reason="contract test")
    call_lines = calls.read_text().splitlines()
    check("the real reaper deduplicates and removes labelled containers",
          removed, 2)
    check("the real reaper force-removes the sorted ids",
          "rm -f container-a container-b" in call_lines, True)
    check("the real reaper disconnects and removes the job network",
          all(any(expected in line for line in call_lines) for expected in (
              "network disconnect -f chal_web-contract_net",
              "network rm chal_web-contract_net",
          )), True)
    check("the real reaper reports the completed cleanup",
          len(logs) == 1 and "reaped 2" in logs[0] and "contract test" in logs[0], True)

print(
    f"== summary: {PASSED} passed, {FAILED} failed =="
    f"  [mutation: {args.mutate}]"
)
raise SystemExit(1 if FAILED else 0)
