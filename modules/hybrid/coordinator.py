"""Filesystem coordinator for the bounded two-stage hybrid solver.

The coordinator owns only the public parent ``meta.json``.  Scalar analyzers
continue to own their private child directories and metadata; this module
observes terminal child metadata, projects evidence onto the parent, and
creates a copied, hash-verified handoff for the second stage.

HTTP/RQ integration intentionally lives in later stages.  The API here is
small enough for S1's standalone harness and for the future route to call:

``create_parent`` -> ``start`` -> child runs -> ``advance`` -> optional child
runs -> ``advance``.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


HYBRID_VERSION = 1
RECIPES: dict[str, tuple[str, str]] = {
    "rev-pwn": ("rev", "pwn"),
    "web-pwn": ("web", "pwn"),
}
TERMINAL_STATUSES = frozenset({"finished", "failed", "no_flag", "stopped"})

# The handoff is deliberately narrower than a child job directory.  Challenge
# inputs remain under src/, decompiler output under decomp/, and only named
# solver/report artifacts may cross at the root.
HANDOFF_FILES = frozenset(
    {"report.md", "findings.json", "exploit.py", "solver.py", "solver.sage"}
)
HANDOFF_DIRECTORIES = frozenset({"decomp", "src"})

_PARENT_RESERVED = frozenset(
    {"id", "module", "modules", "status", "flags", "flag_candidates", "hybrid"}
)
_CHILD_RESERVED = frozenset(
    {"id", "module", "status", "internal", "parent_job_id", "hybrid_stage", "hybrid_handoff"}
)


class HybridCoordinatorError(RuntimeError):
    """Base class for a rejected hybrid state transition."""


class HybridStateError(HybridCoordinatorError):
    """The on-disk parent/child state does not satisfy the lifecycle."""


class HandoffValidationError(HybridCoordinatorError):
    """A requested or stored stage handoff is unsafe or inconsistent."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_job_id(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise HybridStateError(f"{field} must be a non-empty job id")
    if Path(value).name != value or "/" in value or "\\" in value:
        raise HybridStateError(f"{field} must be one path component")
    return value


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HybridStateError(f"missing metadata: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise HybridStateError(f"unreadable metadata: {path}") from exc
    if not isinstance(value, dict):
        raise HybridStateError(f"metadata is not an object: {path}")
    return value


def _write_object(path: Path, value: Mapping[str, Any]) -> None:
    """Write JSON without creating a second file beside parent meta.json.

    Existing metadata writers in this repository use the same one-file
    boundary.  Avoiding a temporary sibling is intentional here: the S1
    contract says the coordinator creates no parent artifact other than
    ``meta.json``.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dict(value), indent=2, ensure_ascii=False) + "\n"
    path.write_text(payload, encoding="utf-8")


def _stable_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item and item not in out:
            out.append(item)
    return out


def is_confirmed_capture(child_meta: Mapping[str, Any]) -> bool:
    """Return the exact marker-only predicate agreed for stage completion."""

    return (
        child_meta.get("status") == "finished"
        and bool(child_meta.get("flags"))
        and child_meta.get("flag_provenance") == "marker"
        and child_meta.get("flag_sweep_suppressed") is not True
    )


def _evidence_records(
    stage: int,
    module: str,
    child_job_id: str,
    child_meta: Mapping[str, Any],
) -> list[dict[str, Any]]:
    flags = _stable_strings(child_meta.get("flags"))
    candidates = _stable_strings(child_meta.get("flag_candidates"))
    confirmed = is_confirmed_capture(child_meta)
    records: list[dict[str, Any]] = []

    for value in flags:
        records.append(
            {
                "stage": stage,
                "module": module,
                "child_job_id": child_job_id,
                "value": value,
                "provenance": {
                    "field": "flags",
                    "tier": child_meta.get("flag_provenance"),
                    "sweep_suppressed": child_meta.get("flag_sweep_suppressed"),
                },
                "disposition": "confirmed" if confirmed else "unverified",
            }
        )

    # Within one child the explicit flags observation is the stronger record.
    # Across children/stages, duplicates remain distinct canonical records.
    for value in candidates:
        if value in flags:
            continue
        records.append(
            {
                "stage": stage,
                "module": module,
                "child_job_id": child_job_id,
                "value": value,
                "provenance": {
                    "field": "flag_candidates",
                    "tier": None,
                    "sweep_suppressed": None,
                },
                "disposition": "unverified",
            }
        )
    return records


def _project_evidence(records: Iterable[Mapping[str, Any]]) -> tuple[list[str], list[str]]:
    confirmed: list[str] = []
    unverified: list[str] = []
    for record in records:
        value = record.get("value")
        if not isinstance(value, str) or not value:
            continue
        if record.get("disposition") == "confirmed":
            if value not in confirmed:
                confirmed.append(value)
        elif record.get("disposition") == "unverified" and value not in unverified:
            unverified.append(value)
    return confirmed, [value for value in unverified if value not in confirmed]


def _terminal_parent_status(records: Sequence[Mapping[str, Any]]) -> str:
    return "finished" if any(r.get("disposition") == "confirmed" for r in records) else "no_flag"


def _normalise_manifest_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise HandoffValidationError("handoff path must be a non-empty POSIX relative path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HandoffValidationError(f"handoff path must stay relative: {raw!r}")
    normalised = path.as_posix()
    if normalised != raw.rstrip("/"):
        raise HandoffValidationError(f"handoff path is not canonical: {raw!r}")
    return normalised


def _path_allowed(relative: str) -> bool:
    path = PurePosixPath(relative)
    return relative in HANDOFF_FILES or (len(path.parts) >= 1 and path.parts[0] in HANDOFF_DIRECTORIES)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_digest(document: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class HybridCoordinator:
    """Coordinate one public parent and at most two isolated scalar children."""

    def __init__(self, jobs_dir: Path | str):
        self.jobs_dir = Path(jobs_dir)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)

    def _job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / _safe_job_id(job_id, field="job_id")

    def _meta_path(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "meta.json"

    def _read_meta(self, job_id: str) -> dict[str, Any]:
        return _read_object(self._meta_path(job_id))

    def _assert_parent_directory(self, parent_job_id: str) -> None:
        parent_dir = self._job_dir(parent_job_id)
        if not parent_dir.exists():
            return
        extras = sorted(path.name for path in parent_dir.iterdir() if path.name != "meta.json")
        if extras:
            raise HybridStateError(
                "hybrid parent directory may contain only meta.json; found " + ", ".join(extras)
            )

    def _write_parent(self, parent_job_id: str, meta: Mapping[str, Any]) -> None:
        self._assert_parent_directory(parent_job_id)
        _write_object(self._meta_path(parent_job_id), meta)
        self._assert_parent_directory(parent_job_id)

    def _validate_parent(self, parent_job_id: str, meta: Mapping[str, Any]) -> tuple[str, tuple[str, str]]:
        if meta.get("id") != parent_job_id or meta.get("module") != "hybrid":
            raise HybridStateError("parent id/module does not match the hybrid job")
        hybrid = meta.get("hybrid")
        if not isinstance(hybrid, dict) or hybrid.get("version") != HYBRID_VERSION:
            raise HybridStateError("parent hybrid metadata has an unsupported version")
        recipe = hybrid.get("recipe")
        if recipe not in RECIPES:
            raise HybridStateError("parent hybrid recipe is not supported")
        modules = RECIPES[recipe]
        if meta.get("modules") != list(modules):
            raise HybridStateError("parent modules do not match the canonical recipe order")
        stages = hybrid.get("stages")
        if not isinstance(stages, list) or len(stages) != len(modules):
            raise HybridStateError("parent must have exactly two stage records")
        for index, (stage, module) in enumerate(zip(stages, modules)):
            if not isinstance(stage, dict) or stage.get("stage") != index or stage.get("module") != module:
                raise HybridStateError("parent stage schema/order is invalid")
        return recipe, modules

    def create_parent(
        self,
        parent_job_id: str,
        recipe: str,
        *,
        meta: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a queued public parent without creating any child artifact."""

        parent_job_id = _safe_job_id(parent_job_id, field="parent_job_id")
        if recipe not in RECIPES:
            raise HybridStateError(f"unsupported hybrid recipe: {recipe!r}")
        extra = dict(meta or {})
        conflicts = sorted(_PARENT_RESERVED.intersection(extra))
        if conflicts:
            raise HybridStateError("reserved parent metadata: " + ", ".join(conflicts))
        parent_dir = self._job_dir(parent_job_id)
        if parent_dir.exists() and any(parent_dir.iterdir()):
            raise HybridStateError(f"parent job already exists: {parent_job_id}")
        modules = RECIPES[recipe]
        now = _now_iso()
        parent = {
            **extra,
            "id": parent_job_id,
            "module": "hybrid",
            "modules": list(modules),
            "status": "queued",
            "flags": [],
            "flag_candidates": [],
            "hybrid": {
                "version": HYBRID_VERSION,
                "recipe": recipe,
                "active_stage": 0,
                "stages": [
                    {"stage": index, "module": module, "child_job_id": None, "status": "pending"}
                    for index, module in enumerate(modules)
                ],
                "stage_flag_evidence": [],
            },
            "created_at": extra.get("created_at", now),
            "updated_at": now,
        }
        self._write_parent(parent_job_id, parent)
        return parent

    def _create_child(
        self,
        parent_job_id: str,
        child_job_id: str,
        stage: int,
        module: str,
        child_meta: Mapping[str, Any] | None,
        *,
        handoff: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        child_job_id = _safe_job_id(child_job_id, field="child_job_id")
        if child_job_id == parent_job_id:
            raise HybridStateError("parent and child job ids must differ")
        extra = dict(child_meta or {})
        conflicts = sorted(_CHILD_RESERVED.intersection(extra))
        if conflicts:
            raise HybridStateError("reserved child metadata: " + ", ".join(conflicts))
        child_dir = self._job_dir(child_job_id)
        if child_dir.exists() and any(child_dir.iterdir()):
            # The handoff is copied before metadata is created for stage B.
            allowed = {"handoff"} if handoff is not None else set()
            actual = {path.name for path in child_dir.iterdir()}
            if actual != allowed:
                raise HybridStateError(f"child job already exists: {child_job_id}")
        now = _now_iso()
        child = {
            **extra,
            "id": child_job_id,
            "module": module,
            "status": "queued",
            "internal": True,
            "parent_job_id": parent_job_id,
            "hybrid_stage": stage,
            "created_at": extra.get("created_at", now),
            "updated_at": now,
        }
        if handoff is not None:
            child["hybrid_handoff"] = dict(handoff)
        _write_object(self._meta_path(child_job_id), child)
        return child

    def start(
        self,
        parent_job_id: str,
        child_job_id: str,
        *,
        child_meta: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create stage A and move a queued parent to running."""

        parent = self._read_meta(parent_job_id)
        _, modules = self._validate_parent(parent_job_id, parent)
        self._assert_parent_directory(parent_job_id)
        if parent.get("status") != "queued":
            raise HybridStateError("only a queued parent can start")
        self._create_child(parent_job_id, child_job_id, 0, modules[0], child_meta)
        now = _now_iso()
        parent["status"] = "running"
        parent.setdefault("started_at", now)
        parent["updated_at"] = now
        hybrid = parent["hybrid"]
        hybrid["active_stage"] = 0
        hybrid["stages"][0].update(child_job_id=child_job_id, status="queued")
        self._write_parent(parent_job_id, parent)
        return parent

    def fail_parent(
        self,
        parent_job_id: str,
        error: BaseException,
        *,
        fallback: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Terminalize a worker failure without replaying transition guards.

        This is deliberately narrower than ``advance``: it records only the
        public failure boundary and does not validate or project a child.  A
        failed transition may have been caused by the parent-directory or
        child-state guards themselves, so rerunning those guards here would
        leave the parent live and could replace the original exception.

        ``fallback`` is the worker's last successfully read parent snapshot.
        It is used only when the current metadata cannot be read after a
        partial transition; a terminal state already written by another path
        is never overwritten.
        """

        try:
            parent = self._read_meta(parent_job_id)
        except HybridStateError:
            if fallback is None or fallback.get("id") != parent_job_id:
                raise
            parent = json.loads(json.dumps(dict(fallback)))
        if parent.get("status") in TERMINAL_STATUSES:
            return parent
        now = _now_iso()
        parent["status"] = "failed"
        parent["error"] = str(error)
        parent.setdefault("finished_at", now)
        parent["updated_at"] = now
        # Do not call _write_parent(): its directory assertion may be the
        # transition precondition that just failed.
        _write_object(self._meta_path(parent_job_id), parent)
        return parent

    @staticmethod
    def _validate_child(
        parent_job_id: str, stage: Mapping[str, Any], child: Mapping[str, Any]
    ) -> None:
        if (
            child.get("id") != stage.get("child_job_id")
            or child.get("module") != stage.get("module")
            or child.get("internal") is not True
            or child.get("parent_job_id") != parent_job_id
            or child.get("hybrid_stage") != stage.get("stage")
        ):
            raise HybridStateError("child metadata does not match its parent stage")

    def _declared_source_files(self, source_dir: Path, declared_paths: Sequence[str]) -> list[tuple[str, Path]]:
        if isinstance(declared_paths, (str, bytes)):
            raise HandoffValidationError("handoff paths must be a sequence, not a string")

        def _assert_contained_without_symlinks(path: Path, relative: str) -> None:
            current = source_dir
            for part in PurePosixPath(relative).parts:
                current = current / part
                if current.is_symlink():
                    raise HandoffValidationError(
                        f"handoff path may not traverse a symlink: {relative}"
                    )
            try:
                if not path.resolve(strict=True).is_relative_to(source_dir.resolve(strict=True)):
                    raise HandoffValidationError(
                        f"handoff path escapes the source child: {relative}"
                    )
            except OSError as exc:
                raise HandoffValidationError(
                    f"handoff path cannot be resolved safely: {relative}"
                ) from exc

        files: dict[str, Path] = {}
        for raw in declared_paths:
            relative = _normalise_manifest_path(raw)
            if not _path_allowed(relative):
                raise HandoffValidationError(f"handoff path is not allowlisted: {relative}")
            source = source_dir.joinpath(*PurePosixPath(relative).parts)
            if source.is_symlink():
                raise HandoffValidationError(f"handoff path may not be a symlink: {relative}")
            if not source.exists():
                raise HandoffValidationError(f"declared handoff path does not exist: {relative}")
            _assert_contained_without_symlinks(source, relative)
            if not source.is_file() and not source.is_dir():
                raise HandoffValidationError(f"handoff path has an unsupported file type: {relative}")
            candidates = [source] if source.is_file() else sorted(source.rglob("*"))
            for candidate in candidates:
                candidate_relative = candidate.relative_to(source_dir).as_posix()
                _assert_contained_without_symlinks(candidate, candidate_relative)
                if candidate.is_symlink():
                    raise HandoffValidationError(
                        f"handoff tree may not contain symlinks: {candidate_relative}"
                    )
                if candidate.is_dir():
                    continue
                if not candidate.is_file() or not _path_allowed(candidate_relative):
                    raise HandoffValidationError(
                        f"handoff tree contains an undeclared file type/path: {candidate_relative}"
                    )
                files[candidate_relative] = candidate
        return sorted(files.items())

    def _copy_handoff(
        self,
        source_child_job_id: str,
        target_child_job_id: str,
        target_module: str,
        declared_paths: Sequence[str],
        unverified_flag_candidates: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        source_dir = self._job_dir(source_child_job_id)
        target_dir = self._job_dir(target_child_job_id)
        if source_dir == target_dir:
            raise HandoffValidationError("stages may not share a read/write job directory")
        if target_dir.exists() and any(target_dir.iterdir()):
            raise HandoffValidationError("target child directory must be new and isolated")
        files = self._declared_source_files(source_dir, declared_paths)
        handoff_dir = target_dir / "handoff"
        handoff_dir.mkdir(parents=True, exist_ok=False)
        entries: list[dict[str, Any]] = []
        for relative, source in files:
            target = handoff_dir.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            size = 0
            with source.open("rb") as reader, target.open("xb") as writer:
                for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                    writer.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
            expected = digest.hexdigest()
            if _file_sha256(target) != expected:
                raise HandoffValidationError(f"handoff copy hash mismatch: {relative}")
            entries.append({"path": relative, "sha256": expected, "size": size})

        body: dict[str, Any] = {
            "version": HYBRID_VERSION,
            "source_child_job_id": source_child_job_id,
            "target_module": target_module,
            "files": entries,
            # B may use weak A observations as hypotheses, but the canonical
            # disposition/provenance travels with them so they cannot become
            # confirmed merely by crossing the stage boundary.
            "unverified_flag_candidates": [
                json.loads(json.dumps(dict(record)))
                for record in unverified_flag_candidates
            ],
        }
        body["sha256"] = _manifest_digest(body)
        return body

    def verify_handoff(self, child_job_id: str) -> dict[str, Any]:
        """Fail closed unless a child handoff exactly matches its signed manifest."""

        child = self._read_meta(child_job_id)
        manifest = child.get("hybrid_handoff")
        if not isinstance(manifest, dict):
            raise HandoffValidationError("child has no handoff manifest")
        body = {key: value for key, value in manifest.items() if key != "sha256"}
        if manifest.get("sha256") != _manifest_digest(body):
            raise HandoffValidationError("handoff manifest hash mismatch")
        if manifest.get("version") != HYBRID_VERSION or manifest.get("target_module") != child.get("module"):
            raise HandoffValidationError("handoff manifest target/version mismatch")
        source_child_job_id = manifest.get("source_child_job_id")
        try:
            _safe_job_id(source_child_job_id, field="source_child_job_id")
        except HybridStateError as exc:
            raise HandoffValidationError(str(exc)) from exc
        parent_job_id = child.get("parent_job_id")
        if not isinstance(parent_job_id, str) or not parent_job_id:
            raise HandoffValidationError("handoff child has no parent")
        parent = self._read_meta(parent_job_id)
        self._validate_parent(parent_job_id, parent)
        stages = parent["hybrid"]["stages"]
        if (
            child.get("hybrid_stage") != 1
            or stages[0].get("child_job_id") != source_child_job_id
            or stages[1].get("child_job_id") != child_job_id
        ):
            raise HandoffValidationError("handoff source/target does not match the parent chain")
        candidates = manifest.get("unverified_flag_candidates")
        if not isinstance(candidates, list):
            raise HandoffValidationError("handoff candidates must be a list")
        for record in candidates:
            if (
                not isinstance(record, dict)
                or record.get("stage") != 0
                or record.get("module") != stages[0].get("module")
                or record.get("child_job_id") != source_child_job_id
                or not isinstance(record.get("value"), str)
                or not record.get("value")
                or record.get("disposition") != "unverified"
                or not isinstance(record.get("provenance"), dict)
            ):
                raise HandoffValidationError("handoff candidate evidence schema is invalid")
        entries = manifest.get("files")
        if not isinstance(entries, list):
            raise HandoffValidationError("handoff manifest files must be a list")
        expected: dict[str, Mapping[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise HandoffValidationError("handoff manifest file entry must be an object")
            relative = _normalise_manifest_path(entry.get("path"))
            if not _path_allowed(relative) or relative in expected:
                raise HandoffValidationError(f"invalid/duplicate handoff manifest path: {relative}")
            if not isinstance(entry.get("size"), int) or entry["size"] < 0:
                raise HandoffValidationError(f"invalid handoff size: {relative}")
            if not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64:
                raise HandoffValidationError(f"invalid handoff hash: {relative}")
            expected[relative] = entry

        handoff_dir = self._job_dir(child_job_id) / "handoff"
        actual: dict[str, Path] = {}
        if not handoff_dir.is_dir() or handoff_dir.is_symlink():
            raise HandoffValidationError("child handoff directory is missing or unsafe")
        for path in sorted(handoff_dir.rglob("*")):
            relative = path.relative_to(handoff_dir).as_posix()
            if path.is_symlink():
                raise HandoffValidationError(f"handoff contains a symlink: {relative}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise HandoffValidationError(f"handoff contains a special file: {relative}")
            actual[relative] = path
        if set(actual) != set(expected):
            raise HandoffValidationError("handoff files do not exactly match the manifest")
        for relative, entry in expected.items():
            path = actual[relative]
            if path.stat().st_size != entry["size"]:
                raise HandoffValidationError(f"handoff size mismatch: {relative}")
            if _file_sha256(path) != entry["sha256"]:
                raise HandoffValidationError(f"handoff file hash mismatch: {relative}")
        return dict(manifest)

    def _materialize_evidence(
        self,
        parent: dict[str, Any],
        stage: Mapping[str, Any],
        child: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        stage_index = stage["stage"]
        existing = parent["hybrid"].get("stage_flag_evidence")
        if not isinstance(existing, list):
            raise HybridStateError("parent stage evidence must be a list")
        prior: list[dict[str, Any]] = []
        for record in existing:
            if (
                not isinstance(record, dict)
                or not isinstance(record.get("stage"), int)
                or record["stage"] >= stage_index
            ):
                raise HybridStateError("parent contains invalid/future stage evidence")
            prior.append(json.loads(json.dumps(record)))
        records = prior + _evidence_records(
            stage_index,
            stage["module"],
            stage["child_job_id"],
            child,
        )
        flags, candidates = _project_evidence(records)
        parent["hybrid"]["stage_flag_evidence"] = records
        parent["flags"] = flags
        parent["flag_candidates"] = candidates
        return records

    def advance(
        self,
        parent_job_id: str,
        *,
        next_child_job_id: str | None = None,
        next_child_meta: Mapping[str, Any] | None = None,
        handoff_paths: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Consume the active terminal child and advance or finish its parent."""

        parent = self._read_meta(parent_job_id)
        _, modules = self._validate_parent(parent_job_id, parent)
        self._assert_parent_directory(parent_job_id)
        if parent.get("status") != "running":
            raise HybridStateError("only a running parent can advance")
        hybrid = parent["hybrid"]
        stage_index = hybrid.get("active_stage")
        if not isinstance(stage_index, int) or stage_index not in range(len(modules)):
            raise HybridStateError("parent active_stage is invalid")
        stage = hybrid["stages"][stage_index]
        child_job_id = stage.get("child_job_id")
        if not isinstance(child_job_id, str) or not child_job_id:
            raise HybridStateError("active stage has no child")
        child = self._read_meta(child_job_id)
        self._validate_child(parent_job_id, stage, child)
        child_status = child.get("status")
        if child_status not in TERMINAL_STATUSES:
            raise HybridStateError("active child is not terminal")
        stage["status"] = child_status
        records = self._materialize_evidence(parent, stage, child)
        now = _now_iso()

        if child_status in {"failed", "stopped"}:
            if next_child_job_id is not None or next_child_meta is not None or handoff_paths:
                raise HybridStateError("a failed/stopped stage cannot create another child")
            parent["status"] = child_status
            parent.setdefault("finished_at", now)
        elif stage_index == 0 and is_confirmed_capture(child):
            if next_child_job_id is not None or next_child_meta is not None or handoff_paths:
                raise HybridStateError("a confirmed first stage must skip the second stage")
            parent["status"] = "finished"
            parent.setdefault("finished_at", now)
        elif stage_index == 0:
            if next_child_job_id is None:
                raise HybridStateError("an unconfirmed first stage requires the second child id")
            manifest = self._copy_handoff(
                child_job_id,
                next_child_job_id,
                modules[1],
                handoff_paths,
                [
                    record
                    for record in records
                    if record.get("stage") == 0
                    and record.get("disposition") == "unverified"
                ],
            )
            self._create_child(
                parent_job_id,
                next_child_job_id,
                1,
                modules[1],
                next_child_meta,
                handoff=manifest,
            )
            stage["handoff_sha256"] = manifest["sha256"]
            hybrid["active_stage"] = 1
            hybrid["stages"][1].update(
                child_job_id=next_child_job_id, status="queued"
            )
        else:
            if next_child_job_id is not None or next_child_meta is not None or handoff_paths:
                raise HybridStateError("the final stage cannot create another child")
            parent["status"] = _terminal_parent_status(records)
            parent.setdefault("finished_at", now)

        parent["updated_at"] = now
        self._write_parent(parent_job_id, parent)
        return parent


def fail_parent_on_rq_failure(
    job: Any,
    _connection: Any,
    _exc_type: Any,
    exc_value: Any,
    _traceback: Any,
    *_args: Any,
    **_kwargs: Any,
) -> None:
    """Terminalize a hybrid parent when RQ fails before ``run_job`` can.

    RQ resolves the job function before entering ``run_job``.  Import and
    deserialization failures therefore cannot reach the entrypoint's own
    ``try``/``except`` boundary.  This callback deliberately lives beside the
    dependency-light coordinator, not in the entrypoint module whose import may
    be the failure, and writes the same terminal parent transition.
    """

    parent_job_id = getattr(job, "id", None)
    if not isinstance(parent_job_id, str) or not parent_job_id:
        raise HybridStateError("failed hybrid RQ job has no parent job id")
    if isinstance(exc_value, BaseException):
        error = exc_value
    else:
        type_name = getattr(_exc_type, "__name__", "RQJobError")
        error = RuntimeError(f"{type_name}: {exc_value}")
    jobs_dir = Path(os.environ.get("DATA_DIR", "/data")) / "jobs"
    HybridCoordinator(jobs_dir).fail_parent(parent_job_id, error)


__all__ = [
    "HANDOFF_DIRECTORIES",
    "HANDOFF_FILES",
    "HYBRID_VERSION",
    "RECIPES",
    "HandoffValidationError",
    "HybridCoordinator",
    "HybridCoordinatorError",
    "HybridStateError",
    "fail_parent_on_rq_failure",
    "is_confirmed_capture",
]
