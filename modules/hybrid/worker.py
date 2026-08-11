"""RQ entrypoint for the bounded, sequential hybrid solver.

The worker is orchestration only: it creates scalar child jobs through the
coordinator and calls the existing scalar analyzer entrypoints synchronously.
The coordinator remains the sole writer of public parent lifecycle/evidence.
"""

from __future__ import annotations

import importlib
import json
import shutil
import zipfile
from contextlib import suppress
from pathlib import Path
from typing import Any, Callable, Mapping

from modules.hybrid.coordinator import (
    HANDOFF_DIRECTORIES,
    HANDOFF_FILES,
    TERMINAL_STATUSES,
    HybridCoordinator,
    HybridStateError,
    is_confirmed_capture,
)
from modules.storage import JOBS_DIR, UPLOADS_DIR, extract_if_archive, new_job_id


_SCALAR_RUNNERS = {
    "rev": "modules.rev.analyzer.run_job",
    "web": "modules.web.analyzer.run_job",
    "pwn": "modules.pwn.analyzer.run_job",
}

_PROVIDER_META_FIELDS = (
    "agent_provider",
    "agent_provider_label",
    "agent_role_providers",
    "gpt_runtime",
    "gpt_preset",
    "gpt_role_models",
    "gpt_preset_effort",
)

_ARCHIVE_EXTENSIONS = (
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".tbz2",
    ".xz",
    ".7z",
    ".rar",
)


def _read_meta(job_id: str) -> dict[str, Any]:
    path = JOBS_DIR / job_id / "meta.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HybridStateError(f"cannot read hybrid worker metadata: {path}") from exc
    if not isinstance(value, dict):
        raise HybridStateError(f"hybrid worker metadata is not an object: {path}")
    return value


def _write_meta(job_id: str, meta: Mapping[str, Any]) -> None:
    path = JOBS_DIR / job_id / "meta.json"
    path.write_text(
        json.dumps(dict(meta), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _source_bundle(parent_job_id: str, parent: Mapping[str, Any]) -> Path | None:
    """Resolve only the upload path owned by this parent.

    ``src_bundle`` is persisted for observability, but it is not authority to
    read an arbitrary worker path.  The upload root, parent id, and safe
    filename reconstruct the only accepted source path.
    """

    filename = parent.get("filename")
    if filename is None:
        if parent.get("src_bundle") is not None:
            raise HybridStateError("hybrid parent has src_bundle without filename")
        return None
    if not isinstance(filename, str) or not filename:
        raise HybridStateError("hybrid parent filename must be a non-empty string")
    if Path(filename).name != filename:
        raise HybridStateError("hybrid parent filename must be one path component")
    if "\\" in filename:
        raise HybridStateError("hybrid parent filename must not contain backslashes")

    stored = parent.get("src_bundle")
    if not isinstance(stored, str) or not stored:
        raise HybridStateError("hybrid parent upload is missing src_bundle")
    expected = UPLOADS_DIR / parent_job_id / filename
    try:
        stored_path = Path(stored).resolve(strict=True)
        expected_path = expected.resolve(strict=True)
    except OSError as exc:
        raise HybridStateError("hybrid parent upload cannot be resolved") from exc
    if stored_path != expected_path:
        raise HybridStateError("hybrid parent src_bundle is outside its upload directory")
    if not expected_path.is_file():
        raise HybridStateError("hybrid parent src_bundle is not a regular file")
    return expected_path


def _module_input(parent: Mapping[str, Any], module: str) -> dict[str, Any]:
    inputs = parent.get("inputs")
    if not isinstance(inputs, dict):
        raise HybridStateError("hybrid parent inputs must be an object")
    value = inputs.get(module)
    if not isinstance(value, dict):
        raise HybridStateError(f"hybrid parent has no scalar inputs for {module}")
    return value


def _child_meta(
    parent_job_id: str,
    parent: Mapping[str, Any],
    child_job_id: str,
    module: str,
) -> dict[str, Any]:
    module_input = _module_input(parent, module)
    filename = parent.get("filename")
    child: dict[str, Any] = {
        "filename": filename,
        "description": parent.get("description"),
        "auto_run": True,
        "job_timeout": parent.get("job_timeout"),
        "model": parent.get("model"),
        "effort": parent.get("effort"),
        "flag_format": parent.get("flag_format"),
        "docker_challenge": module_input.get("docker_challenge") is True,
        "remote_only": filename is None,
    }
    for field in _PROVIDER_META_FIELDS:
        if field in parent:
            child[field] = json.loads(json.dumps(parent[field]))

    if module == "web":
        child["target_url"] = module_input.get("target_url")
        child["target_urls"] = module_input.get("target_urls")
        if filename is None:
            child["src_root"] = None
        else:
            src_dir = JOBS_DIR / child_job_id / "src"
            child["src_root"] = str(
                src_dir / "extracted"
                if str(filename).lower().endswith(".zip")
                else src_dir
            )
    elif module in {"rev", "pwn"}:
        child["target_url"] = module_input.get("target")
        child["target_urls"] = module_input.get("targets")
    else:
        raise HybridStateError(f"hybrid worker has no scalar adapter for {module}")
    return child


def _stage_bundle(
    parent_job_id: str,
    parent: Mapping[str, Any],
    child_job_id: str,
    module: str,
) -> None:
    child_dir = JOBS_DIR / child_job_id
    if module in {"rev", "pwn"}:
        # Scalar rev/pwn ingest creates bin/ even for remote-only jobs; their
        # analyzers unconditionally copy that directory into the work tree.
        (child_dir / "bin").mkdir(parents=True, exist_ok=True)
    source = _source_bundle(parent_job_id, parent)
    if source is None:
        return
    filename = source.name

    if module == "web":
        src_dir = child_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        saved = src_dir / filename
        shutil.copy2(source, saved)
        actual_root = extract_if_archive(saved)
        child = _read_meta(child_job_id)
        child["src_root"] = str(actual_root)
        _write_meta(child_job_id, child)
        return

    bin_dir = child_dir / "bin"
    target = bin_dir / filename
    shutil.copy2(source, target)
    target.chmod(0o755)
    if module != "rev" or target.suffix.lower() != ".zip":
        return

    try:
        with zipfile.ZipFile(target, "r") as archive:
            archive.extractall(bin_dir)
    except zipfile.BadZipFile as exc:
        raise HybridStateError("invalid rev challenge ZIP") from exc
    target.unlink(missing_ok=True)
    picked = _first_binary_in(bin_dir) or _largest_non_archive(bin_dir)
    binary_name = None
    if picked is not None:
        flattened = bin_dir / picked.name
        if picked.resolve() != flattened.resolve():
            shutil.move(str(picked), str(flattened))
        flattened.chmod(0o755)
        binary_name = flattened.name
    child = _read_meta(child_job_id)
    child["filename"] = binary_name
    _write_meta(child_job_id, child)


def _first_binary_in(directory: Path) -> Path | None:
    """Match scalar rev ingest: prefer the largest recursive ELF/PE file."""

    candidates: list[Path] = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        try:
            magic = path.read_bytes()[:4]
        except OSError:
            continue
        if magic.startswith(b"\x7fELF") or magic[:2] == b"MZ":
            candidates.append(path)
    if not candidates:
        return None
    candidates.sort(key=lambda path: path.stat().st_size, reverse=True)
    return candidates[0]


def _largest_non_archive(directory: Path) -> Path | None:
    """Match scalar rev ingest's non-native fallback selection."""

    candidates = [
        path
        for path in directory.rglob("*")
        if path.is_file() and not path.name.lower().endswith(_ARCHIVE_EXTENSIONS)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda path: path.stat().st_size, reverse=True)
    return candidates[0]


def _runner_for(module: str) -> Callable[..., Any]:
    target = _SCALAR_RUNNERS.get(module)
    if target is None:
        raise HybridStateError(f"hybrid worker has no scalar runner for {module}")
    module_name, function_name = target.rsplit(".", 1)
    runner = getattr(importlib.import_module(module_name), function_name, None)
    if not callable(runner):
        raise HybridStateError(f"hybrid scalar runner is not callable: {target}")
    return runner


def _mark_failed(child_job_id: str, error: BaseException) -> None:
    child = _read_meta(child_job_id)
    if child.get("status") not in TERMINAL_STATUSES:
        child["status"] = "failed"
        child["error"] = str(error)
        _write_meta(child_job_id, child)


def _execute_child(
    parent_job_id: str,
    parent: Mapping[str, Any],
    child_job_id: str,
    module: str,
) -> dict[str, Any]:
    try:
        _stage_bundle(parent_job_id, parent, child_job_id, module)
        child = _read_meta(child_job_id)
        runner = _runner_for(module)
        if module == "web":
            runner(
                child_job_id,
                child.get("src_root"),
                child.get("target_url"),
                child.get("description"),
                True,
                child.get("model"),
            )
        elif module == "rev":
            runner(
                child_job_id,
                child.get("filename"),
                child.get("description"),
                True,
                child.get("model"),
            )
        else:
            runner(
                child_job_id,
                child.get("filename"),
                child.get("target_url"),
                child.get("description"),
                True,
                child.get("model"),
            )
        child = _read_meta(child_job_id)
        if child.get("status") not in TERMINAL_STATUSES:
            raise HybridStateError(
                f"scalar {module} runner returned before writing a terminal status"
            )
        return child
    except Exception as exc:
        with suppress(Exception):
            _mark_failed(child_job_id, exc)
        raise


def _handoff_paths(child_job_id: str) -> tuple[str, ...]:
    child_dir = JOBS_DIR / child_job_id
    names = sorted(HANDOFF_FILES | HANDOFF_DIRECTORIES)
    return tuple(name for name in names if (child_dir / name).exists())


def _stage_verified_handoff(child_job_id: str) -> None:
    """Expose a verified stage-A snapshot inside the scalar stage-B cwd."""

    child_dir = JOBS_DIR / child_job_id
    source = child_dir / "handoff"
    if not source.is_dir() or source.is_symlink():
        raise HybridStateError("verified hybrid handoff directory is unavailable")
    work_dir = child_dir / "work"
    work_dir.mkdir(exist_ok=True)
    # Keep prior-stage report/solver names below the scalar collector's existing
    # src/ exclusion.  A root work/handoff/report.md would be deep-recovered as
    # stage B's own report when B produced none, silently re-attributing weak A
    # prose to B.
    target = work_dir / "src" / "hybrid_handoff"
    if target.exists():
        raise HybridStateError("scalar work directory already contains a handoff")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)

    child = _read_meta(child_job_id)
    context = (
        "HYBRID STAGE B: stage-A artifacts were hash-verified and copied to "
        "./src/hybrid_handoff/. Treat every prior-stage flag observation as an unverified "
        "hypothesis; confirm capture only from this stage's own execution."
    )
    description = str(child.get("description") or "").strip()
    child["description"] = f"{description}\n\n{context}" if description else context
    _write_meta(child_job_id, child)


def run_job(parent_job_id: str) -> dict[str, Any]:
    """Run at most two scalar analyzers and return the terminal parent meta."""

    coordinator = HybridCoordinator(JOBS_DIR)
    parent: dict[str, Any] | None = None
    active_child_job_id: str | None = None
    try:
        parent = _read_meta(parent_job_id)
        modules = parent.get("modules")
        if not isinstance(modules, list) or len(modules) != 2:
            raise HybridStateError("hybrid worker requires exactly two ordered modules")
        first_module, second_module = modules
        if first_module not in {"rev", "web"}:
            raise HybridStateError("hybrid first stage must be rev or web")
        if second_module != "pwn":
            raise HybridStateError("hybrid second stage must be pwn")

        first_child_job_id = new_job_id()
        active_child_job_id = first_child_job_id
        parent = coordinator.start(
            parent_job_id,
            first_child_job_id,
            child_meta=_child_meta(
                parent_job_id, parent, first_child_job_id, first_module
            ),
        )
        try:
            first_meta = _execute_child(
                parent_job_id, parent, first_child_job_id, first_module
            )
        except Exception:
            # Preserve the richer normal projection when it is still valid,
            # but never let a recovery transition replace the scalar error.
            with suppress(Exception):
                coordinator.advance(parent_job_id)
            raise

        if first_meta.get("status") in {"failed", "stopped"}:
            return coordinator.advance(parent_job_id)
        if is_confirmed_capture(first_meta):
            return coordinator.advance(parent_job_id)

        second_child_job_id = new_job_id()
        active_child_job_id = second_child_job_id
        second_child_meta = _child_meta(
            parent_job_id, parent, second_child_job_id, second_module
        )
        handoff_paths = _handoff_paths(first_child_job_id)
        parent = coordinator.advance(
            parent_job_id,
            next_child_job_id=second_child_job_id,
            next_child_meta=second_child_meta,
            handoff_paths=handoff_paths,
        )
        coordinator.verify_handoff(second_child_job_id)
        _stage_verified_handoff(second_child_job_id)
        _execute_child(parent_job_id, parent, second_child_job_id, second_module)
        return coordinator.advance(parent_job_id)
    except Exception as exc:
        if active_child_job_id is not None:
            with suppress(Exception):
                _mark_failed(active_child_job_id, exc)
        with suppress(Exception):
            coordinator.fail_parent(parent_job_id, exc, fallback=parent)
        raise


__all__ = ["run_job"]
