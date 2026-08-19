#!/usr/bin/env python3
"""Pin web's intentional always-available, agent-decided Docker contract.

Web predates the operator-gated ``docker_challenge`` helper.  Its system prompt
always offers a bundled Dockerfile as an optional runtime-fidelity check, while
``run_job`` always sweeps/reaps labelled containers.  A standalone web checkbox
would therefore be misleading: it would change neither prompt nor cleanup.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = ("none", "drop-prompt", "add-web-checkbox", "gate-startup-reap")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

route_src = (ROOT / "api" / "routes" / "web_module.py").read_text()
html_src = (ROOT / "web-ui" / "index.html").read_text()
prompt_src = (ROOT / "modules" / "web" / "prompts.py").read_text()
analyzer_src = (ROOT / "modules" / "web" / "analyzer.py").read_text()
common_src = (ROOT / "modules" / "_common.py").read_text()

if args.mutate == "drop-prompt":
    prompt_src = prompt_src.replace("RUN THE CHALLENGE LOCALLY", "REMOVED", 1)
elif args.mutate == "add-web-checkbox":
    marker = '<form id="web-form">'
    html_src = html_src.replace(
        marker,
        marker + '\n<input type="checkbox" name="docker_challenge" />',
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
route_parameters = {
    arg.arg for arg in [*analyze_web.args.args, *analyze_web.args.kwonlyargs]
}
persisted_keys = {
    key.value
    for node in ast.walk(analyze_web)
    if isinstance(node, ast.Dict)
    for key in node.keys
    if isinstance(key, ast.Constant) and isinstance(key.value, str)
}

web_start = html_src.index('<section id="panel-web"')
web_end = html_src.index('<section id="panel-', web_start + 1)
web_panel = html_src[web_start:web_end]

check("standalone web route has no docker_challenge parameter",
      "docker_challenge" in route_parameters, False)
check("standalone web meta has no redundant docker_challenge key",
      "docker_challenge" in persisted_keys, False)
check("standalone web form has no misleading Docker checkbox",
      bool(re.search(r'name=["\']docker_challenge["\']', web_panel)), False)
check("the route explains the intentional asymmetric contract",
      "Web deliberately has no ``docker_challenge`` Form/meta switch" in route_src, True)
check("the form explains why the checkbox is absent",
      "No docker_challenge checkbox by design" in web_panel, True)

check("web's system prompt always contains the local-Docker section",
      "RUN THE CHALLENGE LOCALLY" in prompt_src, True)
check("the prompt leaves execution agent-decided rather than mandatory",
      "This is OPTIONAL" in prompt_src, True)
check("the prompt specifies the reaper's job label",
      "--label hextech_job=$JOB_ID" in prompt_src, True)
check("the shared opt-in helper explicitly excludes web",
      "web is still excluded — its own prompt already covers this" in common_src, True)

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
    from modules._common import reap_chal_containers

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
