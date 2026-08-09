"""Fail-closed ZIP ingest and roundtrip support for live-fire jobs.

This module is intentionally separate from :mod:`api.storage`: live-fire input is
untrusted source code and needs a manifest-backed allow-list, bounded extraction,
and two physically separate trees.  It does not execute challenge code; network
policy belongs to the LF-2 verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


MANIFEST_NAME = "archive-manifest.json"
MANIFEST_SCHEMA = 1
_CHUNK_SIZE = 1024 * 1024
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:($|/)")


@dataclass(frozen=True)
class ZipLimits:
    """Generous source-archive limits with a finite resource envelope.

    Normal A/D service source is generally a few MiB.  The defaults retain at
    least two orders of magnitude of byte headroom while bounding inode, disk,
    and decompression-amplification costs for an untrusted upload.
    """

    max_members: int = 10_000
    max_file_uncompressed: int = 128 * 1024 * 1024
    max_total_uncompressed: int = 1024 * 1024 * 1024
    max_compression_ratio: float = 200.0

    def __post_init__(self) -> None:
        if self.max_members < 1:
            raise ValueError("max_members must be positive")
        if self.max_file_uncompressed < 1:
            raise ValueError("max_file_uncompressed must be positive")
        if self.max_total_uncompressed < self.max_file_uncompressed:
            raise ValueError("total limit must be at least the per-file limit")
        if self.max_compression_ratio < 1:
            raise ValueError("max_compression_ratio must be at least 1")

    def as_dict(self) -> dict[str, int | float]:
        return {
            "max_members": self.max_members,
            "max_file_uncompressed": self.max_file_uncompressed,
            "max_total_uncompressed": self.max_total_uncompressed,
            "max_compression_ratio": self.max_compression_ratio,
        }


class LiveFireArchiveError(ValueError):
    """An archive or candidate tree violated the live-fire contract."""

    def __init__(self, code: str, message: str, member: str | None = None):
        self.code = code
        self.member = member
        suffix = f" ({member!r})" if member is not None else ""
        super().__init__(f"{code}: {message}{suffix}")


class OriginalTreeChangedError(LiveFireArchiveError):
    def __init__(self, expected: str, actual: str):
        super().__init__(
            "original-tree-changed",
            f"original oracle digest changed: expected {expected}, got {actual}",
        )


@dataclass(frozen=True)
class LiveFireWorkspace:
    root: Path
    original: Path
    candidate: Path
    manifest_path: Path
    manifest: dict[str, Any]
    original_digest: str


def _extra_fields(extra: bytes, member: str) -> list[tuple[int, bytes]]:
    fields: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(extra):
        if len(extra) - offset < 4:
            raise LiveFireArchiveError(
                "malformed-extra", "truncated ZIP extra-field header", member
            )
        field_id, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if size > len(extra) - offset:
            raise LiveFireArchiveError(
                "malformed-extra", "ZIP extra-field payload exceeds its record", member
            )
        fields.append((field_id, extra[offset : offset + size]))
        offset += size
    return fields


def _pkware_unix_link(info: zipfile.ZipInfo, raw_name: str) -> bytes | None:
    """Return the APPNOTE 0x000d linked-to name, if present.

    APPNOTE 4.5.7 reserves bytes after the 12-byte Unix metadata prefix for
    the original linked-to filename of a symbolic or hard link.  File type is
    taken from the Unix mode in ``external_attr``.
    """

    found: bytes | None = None
    for field_id, payload in _extra_fields(info.extra, raw_name):
        if field_id != 0x000D or len(payload) <= 12:
            continue
        if found is not None:
            raise LiveFireArchiveError(
                "malformed-extra", "multiple PKWARE Unix link targets", raw_name
            )
        found = payload[12:]
    return found


def _replace_pkware_unix_link(extra: bytes, target: bytes, raw_name: str) -> bytes:
    rebuilt = bytearray()
    replaced = False
    for field_id, payload in _extra_fields(extra, raw_name):
        if field_id == 0x000D and len(payload) > 12:
            if replaced:
                raise LiveFireArchiveError(
                    "malformed-extra", "multiple PKWARE Unix link targets", raw_name
                )
            payload = payload[:12] + target
            replaced = True
        rebuilt.extend(struct.pack("<HH", field_id, len(payload)))
        rebuilt.extend(payload)
    if not replaced:
        raise LiveFireArchiveError(
            "manifest-schema", "missing PKWARE Unix link target field", raw_name
        )
    return bytes(rebuilt)


def _guard_nul(raw_name: str) -> None:
    if "\x00" in raw_name:
        raise LiveFireArchiveError("nul-member", "NUL byte in member name", raw_name)


def _guard_absolute(raw_name: str) -> None:
    normalized = raw_name.replace("\\", "/")
    if normalized.startswith("/") or _WINDOWS_DRIVE.match(normalized):
        raise LiveFireArchiveError(
            "absolute-member", "absolute member path is forbidden", raw_name
        )


def _guard_traversal(raw_name: str) -> None:
    normalized = raw_name.replace("\\", "/")
    if ".." in PurePosixPath(normalized).parts:
        raise LiveFireArchiveError(
            "traversal-member", "parent traversal in member path", raw_name
        )


def _guard_duplicate(key: str, seen: set[str], raw_name: str) -> None:
    if key in seen:
        raise LiveFireArchiveError(
            "duplicate-member", "duplicate filesystem destination", raw_name
        )
    seen.add(key)


def _guard_encrypted(info: zipfile.ZipInfo, raw_name: str) -> None:
    extra_ids = {field_id for field_id, _ in _extra_fields(info.extra, raw_name)}
    if (
        info.flag_bits & ((1 << 0) | (1 << 6))
        or info.compress_type == 99
        or 0x9901 in extra_ids
    ):
        raise LiveFireArchiveError(
            "encrypted-member", "encrypted ZIP members are not accepted", raw_name
        )


def _guard_special(mode: int, raw_name: str) -> None:
    file_type = stat.S_IFMT(mode)
    allowed = {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}
    if file_type not in allowed:
        raise LiveFireArchiveError(
            "special-file", "device, FIFO, socket, or unknown file type", raw_name
        )


def _link_resolution(member_path: str, target: str) -> tuple[bool, str]:
    normalized = target.replace("\\", "/")
    if normalized.startswith("/") or _WINDOWS_DRIVE.match(normalized):
        return True, normalized
    parts = list(PurePosixPath(member_path).parent.parts)
    for part in PurePosixPath(normalized).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return True, normalized
            parts.pop()
        else:
            parts.append(part)
    return False, "/".join(parts)


def _guard_link(member_path: str, target: str, raw_name: str) -> str:
    if "\x00" in target:
        raise LiveFireArchiveError("outside-link", "NUL byte in link target", raw_name)
    escapes, resolved = _link_resolution(member_path, target)
    if escapes:
        raise LiveFireArchiveError(
            "outside-link", "link target escapes the extracted tree", raw_name
        )
    return resolved


def _filesystem_path(raw_name: str) -> str:
    normalized = raw_name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    return "/".join(parts)


def _decoded_link_target(data: bytes, raw_name: str) -> str:
    if len(data) > 64 * 1024:
        raise LiveFireArchiveError(
            "invalid-link", "link target exceeds 64 KiB", raw_name
        )
    return os.fsdecode(data)


def _read_link_payload(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, raw_name: str
) -> bytes:
    try:
        return zf.read(info)
    except (RuntimeError, NotImplementedError, OSError, zipfile.BadZipFile) as exc:
        raise LiveFireArchiveError("archive-read-error", str(exc), raw_name) from exc


def _inspect_archive(
    zf: zipfile.ZipFile, archive_path: Path, limits: ZipLimits
) -> tuple[dict[str, Any], list[tuple[zipfile.ZipInfo, dict[str, Any]]]]:
    infos = zf.infolist()
    if len(infos) > limits.max_members:
        raise LiveFireArchiveError(
            "member-limit", f"{len(infos)} members exceeds {limits.max_members}"
        )

    seen: set[str] = set()
    total = 0
    inspected: list[tuple[zipfile.ZipInfo, dict[str, Any]]] = []
    path_kinds: dict[str, str] = {}

    for index, info in enumerate(infos):
        raw_name = info.orig_filename
        _guard_nul(raw_name)
        _guard_absolute(raw_name)
        _guard_traversal(raw_name)
        _guard_encrypted(info, raw_name)

        path = _filesystem_path(info.filename)
        if not path:
            raise LiveFireArchiveError("invalid-member", "empty member path", raw_name)
        _guard_duplicate(path, seen, raw_name)

        mode = (info.external_attr >> 16) & 0xFFFF
        _guard_special(mode, raw_name)
        file_type = stat.S_IFMT(mode)
        unix_link = _pkware_unix_link(info, raw_name)

        if file_type == stat.S_IFLNK:
            kind = "symlink"
        elif file_type == stat.S_IFDIR or info.is_dir():
            kind = "directory"
        elif file_type in (0, stat.S_IFREG):
            kind = "hardlink" if unix_link is not None else "regular"
        else:
            # Reached only by a deliberate guard-removal mutation.
            kind = "regular"

        if kind == "directory" and info.file_size != 0:
            raise LiveFireArchiveError(
                "invalid-directory", "directory entry has a non-empty body", raw_name
            )
        if kind == "symlink" and unix_link is None and info.file_size > 64 * 1024:
            raise LiveFireArchiveError(
                "invalid-link", "link target exceeds 64 KiB", raw_name
            )
        if kind == "symlink" and unix_link is not None and info.file_size != 0:
            raise LiveFireArchiveError(
                "invalid-link", "extra-field link also has a hidden body", raw_name
            )

        if info.file_size > limits.max_file_uncompressed:
            raise LiveFireArchiveError(
                "file-size-limit",
                f"declared size {info.file_size} exceeds {limits.max_file_uncompressed}",
                raw_name,
            )
        total += info.file_size
        if total > limits.max_total_uncompressed:
            raise LiveFireArchiveError(
                "total-size-limit",
                f"declared total {total} exceeds {limits.max_total_uncompressed}",
                raw_name,
            )
        if kind != "directory" and info.file_size:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > limits.max_compression_ratio:
                raise LiveFireArchiveError(
                    "compression-ratio-limit",
                    f"compression ratio {ratio:.2f} exceeds {limits.max_compression_ratio}",
                    raw_name,
                )

        link_target: str | None = None
        link_resolved: str | None = None
        link_storage: str | None = None
        if kind == "symlink":
            payload = (
                unix_link
                if unix_link is not None
                else _read_link_payload(zf, info, raw_name)
            )
            link_target = _decoded_link_target(payload, raw_name)
            link_resolved = _guard_link(path, link_target, raw_name)
            link_storage = (
                "pkware-unix-extra" if unix_link is not None else "entry-body"
            )
        elif kind == "hardlink":
            if info.file_size != 0:
                raise LiveFireArchiveError(
                    "invalid-hardlink",
                    "hardlink entry must have an empty body",
                    raw_name,
                )
            link_target = _decoded_link_target(unix_link or b"", raw_name)
            link_resolved = _guard_link(path, link_target, raw_name)
            link_storage = "pkware-unix-extra"

        member = {
            "index": index,
            "name": raw_name,
            "path": path,
            "kind": kind,
            "mode": mode,
            "timestamp": list(info.date_time),
            "compression": {
                "method": info.compress_type,
                "compressed_size": info.compress_size,
                "uncompressed_size": info.file_size,
                "crc32": info.CRC,
                "flag_bits": info.flag_bits,
            },
            "zip_metadata": {
                "create_system": info.create_system,
                "create_version": info.create_version,
                "extract_version": info.extract_version,
                "volume": info.volume,
                "internal_attr": info.internal_attr,
                "external_attr": info.external_attr,
                "comment_b64": base64.b64encode(info.comment).decode("ascii"),
                "extra_b64": base64.b64encode(info.extra).decode("ascii"),
            },
            "link_target": link_target,
            "link_resolved_path": link_resolved,
            "link_storage": link_storage,
            "content_sha256": None,
        }
        inspected.append((info, member))
        path_kinds[path] = kind

    link_paths = {
        path for path, kind in path_kinds.items() if kind in {"symlink", "hardlink"}
    }
    for _, member in inspected:
        parts = PurePosixPath(member["path"]).parts
        for depth in range(1, len(parts)):
            ancestor = "/".join(parts[:depth])
            if ancestor in link_paths:
                raise LiveFireArchiveError(
                    "link-ancestor",
                    "an archive member is nested below a link entry",
                    member["name"],
                )
        if member["kind"] == "hardlink":
            target_kind = path_kinds.get(member["link_resolved_path"])
            if target_kind != "regular":
                raise LiveFireArchiveError(
                    "invalid-hardlink",
                    "hardlink target must be a regular archive member",
                    member["name"],
                )

    archive_sha = hashlib.sha256()
    with archive_path.open("rb") as source:
        for chunk in iter(lambda: source.read(_CHUNK_SIZE), b""):
            archive_sha.update(chunk)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "source_archive_sha256": archive_sha.hexdigest(),
        "archive_comment_b64": base64.b64encode(zf.comment).decode("ascii"),
        "limits": limits.as_dict(),
        "members": [member for _, member in inspected],
        "original_tree_sha256": None,
    }
    return manifest, inspected


def _member_destination(root: Path, path: str) -> Path:
    return root.joinpath(*PurePosixPath(path).parts)


def _safe_open_for_write(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.fdopen(os.open(path, flags, 0o600), "wb")


def _stream_regular_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    limit: int,
    raw_name: str,
) -> str:
    digest = hashlib.sha256()
    count = 0
    try:
        with zf.open(info, "r") as source, _safe_open_for_write(destination) as target:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                count += len(chunk)
                if count > limit or count > info.file_size:
                    raise LiveFireArchiveError(
                        "file-size-limit",
                        "stream exceeded its declared or configured size",
                        raw_name,
                    )
                digest.update(chunk)
                target.write(chunk)
    except LiveFireArchiveError:
        raise
    except (RuntimeError, NotImplementedError, OSError, zipfile.BadZipFile) as exc:
        raise LiveFireArchiveError("archive-read-error", str(exc), raw_name) from exc
    if count != info.file_size:
        raise LiveFireArchiveError(
            "archive-read-error",
            f"read {count} bytes, expected {info.file_size}",
            raw_name,
        )
    return digest.hexdigest()


def _apply_archive_mode(path: Path, member: dict[str, Any], *, writable: bool) -> None:
    mode = int(member["mode"]) & 0o7777
    if member["kind"] == "directory":
        mode = mode or 0o755
        mode |= stat.S_IRUSR | stat.S_IXUSR
        if writable:
            mode |= stat.S_IWUSR
        else:
            mode &= ~0o222
    elif member["kind"] == "regular":
        mode = mode or 0o644
        mode |= stat.S_IRUSR
        if writable:
            mode |= stat.S_IWUSR
        else:
            mode &= ~0o222
    else:
        return
    os.chmod(path, mode, follow_symlinks=False)


def _populate_original(
    zf: zipfile.ZipFile,
    inspected: list[tuple[zipfile.ZipInfo, dict[str, Any]]],
    original: Path,
    limits: ZipLimits,
) -> None:
    for _, member in sorted(
        inspected, key=lambda item: len(PurePosixPath(item[1]["path"]).parts)
    ):
        destination = _member_destination(original, member["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        if member["kind"] == "directory":
            destination.mkdir(exist_ok=True)

    for info, member in inspected:
        if member["kind"] != "regular":
            continue
        destination = _member_destination(original, member["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        member["content_sha256"] = _stream_regular_member(
            zf, info, destination, limits.max_file_uncompressed, member["name"]
        )

    for _, member in inspected:
        if member["kind"] != "symlink":
            continue
        destination = _member_destination(original, member["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(member["link_target"], destination)
        member["content_sha256"] = hashlib.sha256(
            os.fsencode(member["link_target"])
        ).hexdigest()

    for _, member in inspected:
        if member["kind"] != "hardlink":
            continue
        destination = _member_destination(original, member["path"])
        target = _member_destination(original, member["link_resolved_path"])
        os.link(target, destination, follow_symlinks=False)
        digest = hashlib.sha256()
        with target.open("rb") as source:
            for chunk in iter(lambda: source.read(_CHUNK_SIZE), b""):
                digest.update(chunk)
        member["content_sha256"] = digest.hexdigest()

    for _, member in sorted(
        inspected,
        key=lambda item: len(PurePosixPath(item[1]["path"]).parts),
        reverse=True,
    ):
        _apply_archive_mode(
            _member_destination(original, member["path"]), member, writable=True
        )


def _copy_candidate(
    inspected: list[tuple[zipfile.ZipInfo, dict[str, Any]]],
    original: Path,
    candidate: Path,
) -> None:
    for _, member in sorted(
        inspected, key=lambda item: len(PurePosixPath(item[1]["path"]).parts)
    ):
        destination = _member_destination(candidate, member["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        if member["kind"] == "directory":
            destination.mkdir(exist_ok=True)

    for _, member in inspected:
        source = _member_destination(original, member["path"])
        destination = _member_destination(candidate, member["path"])
        if member["kind"] == "regular":
            shutil.copyfile(source, destination, follow_symlinks=False)
        elif member["kind"] == "symlink":
            os.symlink(os.readlink(source), destination)
        elif member["kind"] == "hardlink":
            target = _member_destination(candidate, member["link_resolved_path"])
            os.link(target, destination, follow_symlinks=False)

    for _, member in sorted(
        inspected,
        key=lambda item: len(PurePosixPath(item[1]["path"]).parts),
        reverse=True,
    ):
        _apply_archive_mode(
            _member_destination(candidate, member["path"]), member, writable=True
        )


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    hardlink_groups: dict[tuple[int, int], str] = {}

    def add_record(tag: bytes, payload: bytes) -> None:
        digest.update(tag)
        digest.update(struct.pack("<Q", len(payload)))
        digest.update(payload)

    def visit(directory: Path, relative: PurePosixPath) -> None:
        with os.scandir(directory) as entries:
            ordered = sorted(entries, key=lambda entry: os.fsencode(entry.name))
        for entry in ordered:
            child_rel = relative / entry.name
            child_path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            relative_bytes = os.fsencode(child_rel.as_posix())
            add_record(b"P", relative_bytes)
            add_record(b"M", struct.pack("<I", stat.S_IMODE(metadata.st_mode)))
            if stat.S_ISLNK(metadata.st_mode):
                add_record(b"L", os.fsencode(os.readlink(child_path)))
            elif stat.S_ISDIR(metadata.st_mode):
                add_record(b"D", b"")
                visit(child_path, child_rel)
            elif stat.S_ISREG(metadata.st_mode):
                inode = (metadata.st_dev, metadata.st_ino)
                group = hardlink_groups.setdefault(inode, child_rel.as_posix())
                add_record(b"H", os.fsencode(group))
                content_digest = hashlib.sha256()
                with child_path.open("rb") as source:
                    for chunk in iter(lambda: source.read(_CHUNK_SIZE), b""):
                        content_digest.update(chunk)
                add_record(b"F", content_digest.digest())
            else:
                raise LiveFireArchiveError(
                    "special-file",
                    "unexpected file type in workspace",
                    child_rel.as_posix(),
                )

    visit(root, PurePosixPath())
    return digest.hexdigest()


def _set_original_read_only(
    inspected: list[tuple[zipfile.ZipInfo, dict[str, Any]]], original: Path
) -> None:
    for _, member in sorted(
        inspected,
        key=lambda item: len(PurePosixPath(item[1]["path"]).parts),
        reverse=True,
    ):
        _apply_archive_mode(
            _member_destination(original, member["path"]), member, writable=False
        )
    for directory, dirnames, _ in os.walk(original, topdown=False, followlinks=False):
        for dirname in dirnames:
            path = Path(directory) / dirname
            if not path.is_symlink():
                os.chmod(path, (stat.S_IMODE(path.stat().st_mode) | 0o500) & ~0o222)
    os.chmod(original, 0o500)


def _make_tree_removable(root: Path) -> None:
    if not root.exists():
        return
    for directory, dirnames, filenames in os.walk(
        root, topdown=False, followlinks=False
    ):
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
        for name in dirnames:
            path = Path(directory) / name
            if not path.is_symlink():
                try:
                    os.chmod(path, 0o700)
                except OSError:
                    pass
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass


def create_workspace(
    archive_path: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str],
    *,
    limits: ZipLimits | None = None,
) -> LiveFireWorkspace:
    """Validate ``archive_path`` and create ``original``/``candidate`` trees.

    The manifest is written beside the trees, never into either source tree.
    Existing workspace artifacts are not overwritten.
    """

    archive = Path(archive_path)
    root = Path(workspace_root)
    limits = limits or ZipLimits()
    original = root / "original"
    candidate = root / "candidate"
    manifest_path = root / MANIFEST_NAME
    for path in (original, candidate, manifest_path):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"workspace artifact already exists: {path}")
    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".live-fire-ingest-", dir=root))
    staged_original = staging / "original"
    staged_candidate = staging / "candidate"
    staged_original.mkdir()
    staged_candidate.mkdir()
    published: list[Path] = []
    try:
        try:
            with zipfile.ZipFile(archive, "r") as zf:
                manifest, inspected = _inspect_archive(zf, archive, limits)
                _populate_original(zf, inspected, staged_original, limits)
                _copy_candidate(inspected, staged_original, staged_candidate)
        except LiveFireArchiveError:
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise LiveFireArchiveError("invalid-archive", str(exc)) from exc

        _set_original_read_only(inspected, staged_original)
        original_digest = _tree_digest(staged_original)
        manifest["original_tree_sha256"] = original_digest
        staged_manifest = staging / MANIFEST_NAME
        staged_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        # Some managed filesystems require write permission on the directory
        # inode being renamed.  The digest excludes the workspace-root mode;
        # restore the read-only root immediately after the atomic move.
        os.chmod(staged_original, 0o700)
        os.replace(staged_original, original)
        published.append(original)
        os.chmod(original, 0o500)
        os.replace(staged_candidate, candidate)
        published.append(candidate)
        os.replace(staged_manifest, manifest_path)
        published.append(manifest_path)
        os.chmod(manifest_path, 0o400)
        staging.rmdir()
    except Exception:
        _make_tree_removable(staging)
        shutil.rmtree(staging, ignore_errors=True)
        for path in reversed(published):
            if path.is_dir() and not path.is_symlink():
                _make_tree_removable(path)
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    path.chmod(0o600)
                except OSError:
                    pass
                path.unlink(missing_ok=True)
        raise
    return LiveFireWorkspace(
        root, original, candidate, manifest_path, manifest, original_digest
    )


def load_workspace(workspace_root: str | os.PathLike[str]) -> LiveFireWorkspace:
    root = Path(workspace_root)
    manifest_path = root / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise LiveFireArchiveError(
            "manifest-schema", "unsupported archive manifest schema"
        )
    try:
        members = manifest["members"]
        stored_limits = ZipLimits(**manifest["limits"])
        base64.b64decode(manifest["archive_comment_b64"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveFireArchiveError(
            "manifest-schema", "malformed manifest header"
        ) from exc
    if not isinstance(members, list) or len(members) > stored_limits.max_members:
        raise LiveFireArchiveError("manifest-schema", "invalid manifest member list")
    seen: set[str] = set()
    kinds: dict[str, str] = {}
    try:
        for member in members:
            raw_name = member["name"]
            path = member["path"]
            kind = member["kind"]
            if not isinstance(raw_name, str) or not isinstance(path, str):
                raise TypeError("member name/path is not text")
            _guard_nul(raw_name)
            _guard_absolute(raw_name)
            _guard_traversal(raw_name)
            if path != _filesystem_path(raw_name) or not path:
                raise LiveFireArchiveError(
                    "manifest-schema",
                    "member path does not match its ZIP name",
                    raw_name,
                )
            _guard_duplicate(path, seen, raw_name)
            if kind not in {"regular", "directory", "symlink", "hardlink"}:
                raise LiveFireArchiveError(
                    "manifest-schema", f"unknown member kind {kind!r}", raw_name
                )
            metadata = member["zip_metadata"]
            base64.b64decode(metadata["comment_b64"], validate=True)
            base64.b64decode(metadata["extra_b64"], validate=True)
            if kind in {"symlink", "hardlink"}:
                target = member["link_target"]
                if not isinstance(target, str):
                    raise TypeError("link target is not text")
                resolved = _guard_link(path, target, raw_name)
                if resolved != member["link_resolved_path"]:
                    raise LiveFireArchiveError(
                        "manifest-schema",
                        "stored link resolution is inconsistent",
                        raw_name,
                    )
                expected_storage = (
                    {"entry-body", "pkware-unix-extra"}
                    if kind == "symlink"
                    else {"pkware-unix-extra"}
                )
                if member["link_storage"] not in expected_storage:
                    raise LiveFireArchiveError(
                        "manifest-schema", "invalid link storage encoding", raw_name
                    )
            kinds[path] = kind
        for member in members:
            if (
                member["kind"] == "hardlink"
                and kinds.get(member["link_resolved_path"]) != "regular"
            ):
                raise LiveFireArchiveError(
                    "manifest-schema",
                    "hardlink target is not a regular member",
                    member["name"],
                )
    except LiveFireArchiveError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveFireArchiveError(
            "manifest-schema", "malformed manifest member"
        ) from exc
    digest = manifest.get("original_tree_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise LiveFireArchiveError("manifest-schema", "missing original tree digest")
    return LiveFireWorkspace(
        root=root,
        original=root / "original",
        candidate=root / "candidate",
        manifest_path=manifest_path,
        manifest=manifest,
        original_digest=digest,
    )


def assert_original_unchanged(
    workspace: LiveFireWorkspace | str | os.PathLike[str],
) -> str:
    ws = (
        load_workspace(workspace)
        if not isinstance(workspace, LiveFireWorkspace)
        else workspace
    )
    actual = _tree_digest(ws.original)
    if actual != ws.original_digest:
        raise OriginalTreeChangedError(ws.original_digest, actual)
    return actual


def _zipinfo_from_manifest(member: dict[str, Any]) -> zipfile.ZipInfo:
    metadata = member["zip_metadata"]
    info = zipfile.ZipInfo(member["name"], tuple(member["timestamp"]))
    info.compress_type = int(member["compression"]["method"])
    info.create_system = int(metadata["create_system"])
    info.create_version = int(metadata["create_version"])
    info.extract_version = int(metadata["extract_version"])
    info.volume = int(metadata["volume"])
    info.internal_attr = int(metadata["internal_attr"])
    info.external_attr = int(metadata["external_attr"])
    info.comment = base64.b64decode(metadata["comment_b64"], validate=True)
    info.extra = base64.b64decode(metadata["extra_b64"], validate=True)
    return info


def _guard_candidate_ancestors(
    ws: LiveFireWorkspace, member_path: str, raw_name: str
) -> None:
    """Reject implicit or explicit candidate parents replaced by links/files."""

    root_stat = ws.candidate.lstat()
    if not stat.S_ISDIR(root_stat.st_mode):
        raise LiveFireArchiveError(
            "candidate-ancestor", "candidate root is not a directory"
        )
    current = ws.candidate
    parts = PurePosixPath(member_path).parts
    for part in parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise LiveFireArchiveError(
                "candidate-ancestor", "candidate parent directory is missing", raw_name
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise LiveFireArchiveError(
                "candidate-ancestor",
                "candidate parent is not a real directory",
                raw_name,
            )


def _candidate_member_data(
    ws: LiveFireWorkspace, member: dict[str, Any]
) -> bytes | Path:
    _guard_candidate_ancestors(ws, member["path"], member["name"])
    path = _member_destination(ws.candidate, member["path"])
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise LiveFireArchiveError(
            "candidate-missing", "manifest member is missing", member["name"]
        ) from exc
    kind = member["kind"]
    if kind == "directory":
        if not stat.S_ISDIR(metadata.st_mode):
            raise LiveFireArchiveError(
                "candidate-type", "expected directory", member["name"]
            )
        return b""
    if kind == "regular":
        if not stat.S_ISREG(metadata.st_mode):
            raise LiveFireArchiveError(
                "candidate-type", "expected regular file", member["name"]
            )
        return path
    if kind == "symlink":
        if not stat.S_ISLNK(metadata.st_mode):
            raise LiveFireArchiveError(
                "candidate-type", "expected symbolic link", member["name"]
            )
        target = os.readlink(path)
        _guard_link(member["path"], target, member["name"])
        return os.fsencode(target)
    if kind == "hardlink":
        _guard_candidate_ancestors(ws, member["link_resolved_path"], member["name"])
        target_path = _member_destination(ws.candidate, member["link_resolved_path"])
        target_stat = target_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or (
            metadata.st_dev,
            metadata.st_ino,
        ) != (target_stat.st_dev, target_stat.st_ino):
            raise LiveFireArchiveError(
                "candidate-type",
                "hardlink no longer links to its manifest target",
                member["name"],
            )
        return b""
    raise LiveFireArchiveError(
        "manifest-schema", f"unknown member kind {kind!r}", member["name"]
    )


def _guard_candidate_hardlinks(ws: LiveFireWorkspace) -> None:
    groups: dict[str, set[str]] = {}
    for member in ws.manifest["members"]:
        if member["kind"] == "hardlink":
            groups.setdefault(
                member["link_resolved_path"], {member["link_resolved_path"]}
            ).add(member["path"])
    allowed_by_inode: dict[tuple[int, int], set[str]] = {}
    for paths in groups.values():
        example = next(iter(paths))
        _guard_candidate_ancestors(ws, example, example)
        target = _member_destination(ws.candidate, example).lstat()
        allowed_by_inode[(target.st_dev, target.st_ino)] = paths
    for member in ws.manifest["members"]:
        if member["kind"] != "regular":
            continue
        _guard_candidate_ancestors(ws, member["path"], member["name"])
        path = _member_destination(ws.candidate, member["path"])
        metadata = path.lstat()
        if metadata.st_nlink <= 1:
            continue
        allowed = allowed_by_inode.get((metadata.st_dev, metadata.st_ino), set())
        if member["path"] not in allowed or metadata.st_nlink != len(allowed):
            raise LiveFireArchiveError(
                "candidate-hardlink",
                "unexpected hardlink reaches outside the manifest group",
                member["name"],
            )


def _preflight_candidate(ws: LiveFireWorkspace) -> dict[str, bytes | Path]:
    limits = ZipLimits(**ws.manifest["limits"])
    total = 0
    data_by_path: dict[str, bytes | Path] = {}
    for member in ws.manifest["members"]:
        data = _candidate_member_data(ws, member)
        if isinstance(data, Path):
            size = data.lstat().st_size
        else:
            size = len(data)
        if size > limits.max_file_uncompressed:
            raise LiveFireArchiveError(
                "file-size-limit",
                f"candidate size {size} exceeds {limits.max_file_uncompressed}",
                member["name"],
            )
        total += size
        if total > limits.max_total_uncompressed:
            raise LiveFireArchiveError(
                "total-size-limit",
                f"candidate total {total} exceeds {limits.max_total_uncompressed}",
                member["name"],
            )
        data_by_path[member["path"]] = data
    _guard_candidate_hardlinks(ws)
    return data_by_path


def _copy_file_into_zip(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, source: Path
) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        with os.fdopen(descriptor, "rb") as input_file, zf.open(info, "w") as output:
            descriptor = -1
            shutil.copyfileobj(input_file, output, _CHUNK_SIZE)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build_patched_zip(
    workspace: LiveFireWorkspace | str | os.PathLike[str],
    output_path: str | os.PathLike[str],
) -> Path:
    """Write a patched ZIP from manifest members only.

    Added diagnostics, tests, caches, and VCS metadata in ``candidate`` are
    ignored because they are absent from the immutable input manifest.
    """

    ws = (
        load_workspace(workspace)
        if not isinstance(workspace, LiveFireWorkspace)
        else workspace
    )
    assert_original_unchanged(ws)
    data_by_path = _preflight_candidate(ws)
    limits = ZipLimits(**ws.manifest["limits"])
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    if temporary.exists():
        raise FileExistsError(temporary)
    try:
        with zipfile.ZipFile(temporary, "w", allowZip64=True) as zf:
            zf.comment = base64.b64decode(
                ws.manifest["archive_comment_b64"], validate=True
            )
            for member in ws.manifest["members"]:
                info = _zipinfo_from_manifest(member)
                data = data_by_path[member["path"]]
                if (
                    member["kind"] == "symlink"
                    and member["link_storage"] == "pkware-unix-extra"
                ):
                    if not isinstance(data, bytes):
                        raise LiveFireArchiveError(
                            "candidate-type",
                            "expected symbolic-link target bytes",
                            member["name"],
                        )
                    info.extra = _replace_pkware_unix_link(
                        info.extra, data, member["name"]
                    )
                    data = b""
                if isinstance(data, Path):
                    _copy_file_into_zip(zf, info, data)
                else:
                    zf.writestr(info, data)
        with zipfile.ZipFile(temporary, "r") as validation_zip:
            _inspect_archive(validation_zip, temporary, limits)
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return output


__all__ = [
    "LiveFireArchiveError",
    "LiveFireWorkspace",
    "OriginalTreeChangedError",
    "ZipLimits",
    "assert_original_unchanged",
    "build_patched_zip",
    "create_workspace",
    "load_workspace",
]
