#!/usr/bin/env python3
"""Executable LF-1 gate, including seven guard-removal mutations.

Run the normal suite with no arguments.  ``--mutate GUARD`` replaces exactly
one rejection guard with a no-op, so the same fixtures must report failures.
The production module contains no mutation switch.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import live_fire_workspace as live_fire  # noqa: E402


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mutate",
    choices=(
        "absolute",
        "traversal",
        "nul",
        "duplicate",
        "encrypted",
        "special",
        "link",
    ),
)
args = parser.parse_args()

if args.mutate == "absolute":
    live_fire._guard_absolute = lambda raw_name: None
elif args.mutate == "traversal":
    live_fire._guard_traversal = lambda raw_name: None
elif args.mutate == "nul":
    live_fire._guard_nul = lambda raw_name: None
elif args.mutate == "duplicate":
    live_fire._guard_duplicate = lambda key, seen, raw_name: None
elif args.mutate == "encrypted":
    live_fire._guard_encrypted = lambda info, raw_name: None
elif args.mutate == "special":
    live_fire._guard_special = lambda mode, raw_name: None
elif args.mutate == "link":
    live_fire._guard_link = lambda member_path, target, raw_name: (
        live_fire._link_resolution(member_path, target)[1]
    )


TMP = tempfile.TemporaryDirectory(prefix="live-fire-workspace-")
BASE = Path(TMP.name)
P = F = 0
_case = 0
STAMP = (2025, 7, 6, 5, 4, 2)


def check(label, got, want):
    global P, F
    if got == want:
        P += 1
    else:
        F += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


def next_path(label: str, suffix: str = ".zip") -> Path:
    global _case
    _case += 1
    return BASE / f"{_case:02d}-{label}{suffix}"


def zip_info(
    name: str,
    mode: int,
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    extra: bytes = b"",
    comment: bytes = b"",
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, STAMP)
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    if stat.S_ISDIR(mode):
        info.external_attr |= 0x10
    info.compress_type = compression
    info.extra = extra
    info.comment = comment
    return info


def write_archive(path: Path, entries, *, comment: bytes = b"") -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.comment = comment
        for info, payload in entries:
            zf.writestr(info, payload)
    return path


def unix_link_extra(target: str) -> bytes:
    # APPNOTE 4.5.7: atime, mtime, uid, gid (12 bytes), then linked-to name.
    payload = struct.pack("<IIHH", 0, 0, 1000, 1000) + os.fsencode(target)
    return struct.pack("<HH", 0x000D, len(payload)) + payload


def ordinary_archive(path: Path) -> Path:
    return write_archive(
        path,
        [
            (zip_info("service/", stat.S_IFDIR | 0o755, comment=b"root-dir"), b""),
            (
                zip_info(
                    "service/app.py",
                    stat.S_IFREG | 0o750,
                    compression=zipfile.ZIP_DEFLATED,
                    comment=b"entry-comment",
                ),
                b"print('original')\n",
            ),
            (
                zip_info(
                    "service/config.txt",
                    stat.S_IFREG | 0o640,
                    compression=zipfile.ZIP_STORED,
                ),
                b"PORT=31337\n",
            ),
            (
                zip_info("service/current.py", stat.S_IFLNK | 0o777),
                b"app.py",
            ),
            (
                zip_info(
                    "service/extra-current.py",
                    stat.S_IFLNK | 0o777,
                    extra=unix_link_extra("config.txt"),
                ),
                b"",
            ),
            (
                zip_info(
                    "service/app-hard.py",
                    stat.S_IFREG | 0o750,
                    extra=unix_link_extra("app.py"),
                ),
                b"",
            ),
        ],
        comment=b"source-archive-comment",
    )


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for directory, dirnames, filenames in os.walk(
        root, topdown=False, followlinks=False
    ):
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass
        for name in dirnames:
            path = Path(directory) / name
            if not path.is_symlink():
                try:
                    path.chmod(0o700)
                except OSError:
                    pass
        try:
            Path(directory).chmod(0o700)
        except OSError:
            pass


def expect_reject(
    label: str,
    archive: Path,
    code: str,
    *,
    limits: live_fire.ZipLimits | None = None,
    workspace: Path | None = None,
) -> None:
    root = workspace or next_path(f"ws-{label}", "")
    try:
        live_fire.create_workspace(archive, root, limits=limits)
    except live_fire.LiveFireArchiveError as exc:
        check(label, exc.code, code)
    except Exception as exc:
        check(label, f"unexpected:{type(exc).__name__}", code)
    else:
        check(label, "accepted", code)


# Positive control: a normal tree with internal symbolic and hard links.
source_zip = ordinary_archive(next_path("ordinary"))
workspace_root = next_path("workspace", "")
workspace = live_fire.create_workspace(source_zip, workspace_root)
manifest_disk = json.loads(workspace.manifest_path.read_text(encoding="utf-8"))
members = {member["name"]: member for member in manifest_disk["members"]}

check("positive control creates original", workspace.original.is_dir(), True)
check("positive control creates candidate", workspace.candidate.is_dir(), True)
check(
    "manifest records input names",
    list(members),
    [
        "service/",
        "service/app.py",
        "service/config.txt",
        "service/current.py",
        "service/extra-current.py",
        "service/app-hard.py",
    ],
)
check(
    "manifest records directory structure",
    members["service/app.py"]["path"],
    "service/app.py",
)
check(
    "manifest records mode", members["service/config.txt"]["mode"], stat.S_IFREG | 0o640
)
check(
    "manifest records timestamp",
    members["service/config.txt"]["timestamp"],
    list(STAMP),
)
check(
    "manifest records compression",
    members["service/config.txt"]["compression"]["method"],
    zipfile.ZIP_STORED,
)
check(
    "manifest records symbolic link",
    members["service/current.py"]["link_target"],
    "app.py",
)
check(
    "manifest records extra-field symbolic link",
    members["service/extra-current.py"]["link_storage"],
    "pkware-unix-extra",
)
check(
    "manifest records hardlink",
    members["service/app-hard.py"]["link_resolved_path"],
    "service/app.py",
)

original_app = workspace.original / "service" / "app.py"
candidate_app = workspace.candidate / "service" / "app.py"
original_hard = workspace.original / "service" / "app-hard.py"
candidate_hard = workspace.candidate / "service" / "app-hard.py"
check(
    "original and candidate are distinct files",
    original_app.stat().st_ino != candidate_app.stat().st_ino,
    True,
)
check(
    "original hardlink remains inside original",
    original_app.stat().st_ino,
    original_hard.stat().st_ino,
)
check(
    "candidate hardlink remains inside candidate",
    candidate_app.stat().st_ino,
    candidate_hard.stat().st_ino,
)
check(
    "trees do not share hardlink inodes",
    original_hard.stat().st_ino != candidate_hard.stat().st_ino,
    True,
)
check(
    "original regular file is read-only",
    stat.S_IMODE(original_app.stat().st_mode) & 0o222,
    0,
)
check(
    "original directory is read-only",
    stat.S_IMODE(workspace.original.stat().st_mode) & 0o222,
    0,
)
check(
    "manifest is read-only",
    stat.S_IMODE(workspace.manifest_path.stat().st_mode) & 0o222,
    0,
)
check(
    "candidate regular file is writable",
    bool(stat.S_IMODE(candidate_app.stat().st_mode) & 0o200),
    True,
)
check(
    "original digest initially matches",
    live_fire.assert_original_unchanged(workspace),
    workspace.original_digest,
)

# The digest gate must detect changes even if a caller temporarily chmods the oracle.
original_bytes = original_app.read_bytes()
original_mode = stat.S_IMODE(original_app.stat().st_mode)
original_app.chmod(original_mode | 0o200)
original_app.write_bytes(b"tampered\n")
try:
    live_fire.assert_original_unchanged(workspace)
except live_fire.OriginalTreeChangedError as exc:
    check("original mutation is detected", exc.code, "original-tree-changed")
else:
    check("original mutation is detected", "accepted", "original-tree-changed")
original_app.write_bytes(original_bytes)
original_app.chmod(original_mode)
check(
    "restored original digest matches",
    live_fire.assert_original_unchanged(workspace),
    workspace.original_digest,
)

# Content equality is insufficient for hardlinks: breaking the inode relation
# changes the original tree topology and must also trip the oracle digest.
original_root_mode = stat.S_IMODE(workspace.original.stat().st_mode)
original_service = workspace.original / "service"
original_service_mode = stat.S_IMODE(original_service.stat().st_mode)
workspace.original.chmod(original_root_mode | 0o200)
original_service.chmod(original_service_mode | 0o200)
original_hard.unlink()
original_hard.write_bytes(original_bytes)
original_hard.chmod(original_mode)
try:
    live_fire.assert_original_unchanged(workspace)
except live_fire.OriginalTreeChangedError as exc:
    check(
        "original hardlink topology change is detected",
        exc.code,
        "original-tree-changed",
    )
else:
    check(
        "original hardlink topology change is detected",
        "accepted",
        "original-tree-changed",
    )
original_hard.unlink()
os.link(original_app, original_hard)
original_service.chmod(original_service_mode)
workspace.original.chmod(original_root_mode)
check(
    "restored hardlink topology matches",
    live_fire.assert_original_unchanged(workspace),
    workspace.original_digest,
)

# Candidate edits stay at the input path; generated diagnostics and cache/VCS files
# are absent because build_patched_zip writes the manifest allow-list only.
candidate_app.write_text("print('patched')\n", encoding="utf-8")
candidate_extra_link = workspace.candidate / "service" / "extra-current.py"
candidate_extra_link.unlink()
os.symlink("app.py", candidate_extra_link)
(workspace.candidate / "report.md").write_text("diagnostic", encoding="utf-8")
(workspace.candidate / "verification.json").write_text("{}", encoding="utf-8")
(workspace.candidate / "tests").mkdir()
(workspace.candidate / "tests" / "test_patch.py").write_text("pass", encoding="utf-8")
(workspace.candidate / "__pycache__").mkdir()
(workspace.candidate / "__pycache__" / "cache.pyc").write_bytes(b"cache")
(workspace.candidate / ".git").mkdir()
(workspace.candidate / ".git" / "config").write_text("metadata", encoding="utf-8")

patched_zip = next_path("patched")
live_fire.build_patched_zip(workspace_root, patched_zip)
with zipfile.ZipFile(source_zip) as source, zipfile.ZipFile(patched_zip) as patched:
    source_infos = {info.filename: info for info in source.infolist()}
    patched_infos = {info.filename: info for info in patched.infolist()}
    check("patched ZIP preserves root layout", list(patched_infos), list(source_infos))
    check(
        "patched source stays at same path",
        patched.read("service/app.py"),
        b"print('patched')\n",
    )
    check(
        "unchanged file bytes survive",
        patched.read("service/config.txt"),
        source.read("service/config.txt"),
    )
    check("archive comment is preserved", patched.comment, source.comment)
    for field in ("date_time", "compress_type", "external_attr", "comment", "extra"):
        check(
            f"unchanged metadata preserves {field}",
            getattr(patched_infos["service/config.txt"], field),
            getattr(source_infos["service/config.txt"], field),
        )
    check("diagnostics are excluded", "report.md" in patched_infos, False)
    check(
        "verification output is excluded", "verification.json" in patched_infos, False
    )
    check(
        "tests are excluded",
        any(name.startswith("tests/") for name in patched_infos),
        False,
    )
    check(
        "caches are excluded",
        any("__pycache__" in name for name in patched_infos),
        False,
    )
    check(
        "git metadata is excluded",
        any(name.startswith(".git/") for name in patched_infos),
        False,
    )

roundtrip = live_fire.create_workspace(patched_zip, next_path("roundtrip", ""))
check(
    "patched ZIP reopens through safe ingest",
    (roundtrip.original / "service" / "app.py").read_bytes(),
    b"print('patched')\n",
)
check(
    "roundtrip preserves internal hardlink",
    (roundtrip.original / "service" / "app.py").stat().st_ino,
    (roundtrip.original / "service" / "app-hard.py").stat().st_ino,
)
check(
    "roundtrip updates extra-field symbolic link",
    os.readlink(roundtrip.original / "service" / "extra-current.py"),
    "app.py",
)

# An archive need not contain explicit directory entries.  Replacing such an
# implicit candidate parent with a symlink must not make the ZIP builder read
# a same-named file outside candidate.
implicit_zip = write_archive(
    next_path("implicit-parent"),
    [(zip_info("nested/app.py", stat.S_IFREG | 0o644), b"inside")],
)
implicit_ws = live_fire.create_workspace(implicit_zip, next_path("implicit-ws", ""))
shutil.rmtree(implicit_ws.candidate / "nested")
outside_directory = next_path("outside-directory", "")
outside_directory.mkdir()
(outside_directory / "app.py").write_bytes(b"outside")
os.symlink(outside_directory, implicit_ws.candidate / "nested")
try:
    live_fire.build_patched_zip(implicit_ws, next_path("implicit-escape-output"))
except live_fire.LiveFireArchiveError as exc:
    check(
        "implicit candidate parent symlink is rejected", exc.code, "candidate-ancestor"
    )
else:
    check(
        "implicit candidate parent symlink is rejected",
        "accepted",
        "candidate-ancestor",
    )

# A reloaded manifest is untrusted control data too: changing its member path
# must be rejected before candidate path resolution.
manifest_tamper_zip = write_archive(
    next_path("manifest-tamper"),
    [(zip_info("safe.py", stat.S_IFREG | 0o644), b"safe")],
)
manifest_tamper_ws = live_fire.create_workspace(
    manifest_tamper_zip, next_path("manifest-tamper-ws", "")
)
manifest_tamper_ws.manifest_path.chmod(0o600)
tampered_manifest = json.loads(
    manifest_tamper_ws.manifest_path.read_text(encoding="utf-8")
)
tampered_manifest["members"][0]["name"] = "../../outside.py"
tampered_manifest["members"][0]["path"] = "../../outside.py"
manifest_tamper_ws.manifest_path.write_text(
    json.dumps(tampered_manifest), encoding="utf-8"
)
try:
    live_fire.build_patched_zip(
        manifest_tamper_ws.root, next_path("tampered-manifest-output")
    )
except live_fire.LiveFireArchiveError as exc:
    check("tampered manifest traversal is rejected", exc.code, "traversal-member")
else:
    check("tampered manifest traversal is rejected", "accepted", "traversal-member")

# A regular candidate member hardlinked to a non-manifest file would otherwise
# let outside writes change the patched source after preflight.
unexpected_link_zip = write_archive(
    next_path("unexpected-candidate-hardlink"),
    [(zip_info("app.py", stat.S_IFREG | 0o644), b"inside")],
)
unexpected_link_ws = live_fire.create_workspace(
    unexpected_link_zip, next_path("unexpected-candidate-hardlink-ws", "")
)
external_hardlink_source = next_path("external-hardlink-source", "")
external_hardlink_source.write_bytes(b"outside")
(unexpected_link_ws.candidate / "app.py").unlink()
os.link(external_hardlink_source, unexpected_link_ws.candidate / "app.py")
try:
    live_fire.build_patched_zip(
        unexpected_link_ws, next_path("unexpected-hardlink-output")
    )
except live_fire.LiveFireArchiveError as exc:
    check("unexpected candidate hardlink is rejected", exc.code, "candidate-hardlink")
else:
    check("unexpected candidate hardlink is rejected", "accepted", "candidate-hardlink")


# Seven required rejection categories.
absolute_zip = write_archive(
    next_path("absolute"),
    [(zip_info("/etc/passwd", stat.S_IFREG | 0o644), b"x")],
)
expect_reject("absolute member", absolute_zip, "absolute-member")

windows_absolute_zip = write_archive(
    next_path("windows-absolute"),
    [(zip_info("C:\\Windows\\win.ini", stat.S_IFREG | 0o644), b"x")],
)
expect_reject("Windows absolute member", windows_absolute_zip, "absolute-member")

traversal_zip = write_archive(
    next_path("traversal"),
    [(zip_info("../../etc/hostname", stat.S_IFREG | 0o644), b"x")],
)
expect_reject("traversal member", traversal_zip, "traversal-member")

backslash_traversal_zip = write_archive(
    next_path("backslash-traversal"),
    [(zip_info("..\\..\\outside", stat.S_IFREG | 0o644), b"x")],
)
expect_reject("backslash traversal member", backslash_traversal_zip, "traversal-member")

nul_zip = write_archive(
    next_path("nul"),
    [(zip_info("nulXname.txt", stat.S_IFREG | 0o644), b"x")],
)
nul_zip.write_bytes(nul_zip.read_bytes().replace(b"nulXname.txt", b"nul\x00name.txt"))
expect_reject("NUL member", nul_zip, "nul-member")

duplicate_zip = write_archive(
    next_path("duplicate"),
    [
        (zip_info("same.txt", stat.S_IFREG | 0o644), b"first"),
        (zip_info("same.txt", stat.S_IFREG | 0o644), b"second"),
    ],
)
expect_reject("duplicate member", duplicate_zip, "duplicate-member")

encrypted_zip = write_archive(
    next_path("encrypted"),
    [
        (
            zip_info(
                "secret.txt", stat.S_IFREG | 0o644, compression=zipfile.ZIP_STORED
            ),
            b"secret",
        )
    ],
)
encrypted_data = bytearray(encrypted_zip.read_bytes())
for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
    offset = encrypted_data.find(signature)
    flags = struct.unpack_from("<H", encrypted_data, offset + flag_offset)[0]
    struct.pack_into("<H", encrypted_data, offset + flag_offset, flags | 1)
encrypted_zip.write_bytes(encrypted_data)
expect_reject("encrypted member", encrypted_zip, "encrypted-member")

for special_name, special_mode in (
    ("FIFO", stat.S_IFIFO),
    ("character device", stat.S_IFCHR),
    ("block device", stat.S_IFBLK),
    ("socket", stat.S_IFSOCK),
):
    special_zip = write_archive(
        next_path(special_name.replace(" ", "-")),
        [(zip_info("special", special_mode | 0o644), b"not-a-node")],
    )
    expect_reject(f"special file: {special_name}", special_zip, "special-file")

outside_symlink_zip = write_archive(
    next_path("outside-symlink"),
    [(zip_info("links/bad", stat.S_IFLNK | 0o777), b"../../outside")],
)
expect_reject("outside symbolic link", outside_symlink_zip, "outside-link")

outside_hardlink_zip = write_archive(
    next_path("outside-hardlink"),
    [
        (
            zip_info(
                "links/bad-hard",
                stat.S_IFREG | 0o644,
                extra=unix_link_extra("../../outside-hard.txt"),
            ),
            b"",
        )
    ],
)
outside_hard_ws = next_path("ws-outside-hardlink", "")
outside_hard_ws.mkdir()
(outside_hard_ws / "outside-hard.txt").write_text("outside", encoding="utf-8")
expect_reject(
    "outside hard link",
    outside_hardlink_zip,
    "outside-link",
    workspace=outside_hard_ws,
)


# Four independent resource ceilings.
member_limit_zip = write_archive(
    next_path("member-limit"),
    [
        (zip_info("one", stat.S_IFREG | 0o644), b"1"),
        (zip_info("two", stat.S_IFREG | 0o644), b"2"),
    ],
)
expect_reject(
    "member count limit",
    member_limit_zip,
    "member-limit",
    limits=live_fire.ZipLimits(
        max_members=1,
        max_file_uncompressed=10,
        max_total_uncompressed=20,
        max_compression_ratio=200,
    ),
)

file_limit_zip = write_archive(
    next_path("file-limit"),
    [(zip_info("large", stat.S_IFREG | 0o644), b"1234")],
)
expect_reject(
    "single file limit",
    file_limit_zip,
    "file-size-limit",
    limits=live_fire.ZipLimits(
        max_members=10,
        max_file_uncompressed=3,
        max_total_uncompressed=10,
        max_compression_ratio=200,
    ),
)

total_limit_zip = write_archive(
    next_path("total-limit"),
    [
        (zip_info("one", stat.S_IFREG | 0o644), b"1234"),
        (zip_info("two", stat.S_IFREG | 0o644), b"5678"),
    ],
)
expect_reject(
    "total extraction limit",
    total_limit_zip,
    "total-size-limit",
    limits=live_fire.ZipLimits(
        max_members=10,
        max_file_uncompressed=6,
        max_total_uncompressed=6,
        max_compression_ratio=200,
    ),
)

ratio_limit_zip = write_archive(
    next_path("ratio-limit"),
    [(zip_info("zeros", stat.S_IFREG | 0o644), b"0" * 4096)],
)
expect_reject(
    "compression ratio limit",
    ratio_limit_zip,
    "compression-ratio-limit",
    limits=live_fire.ZipLimits(
        max_members=10,
        max_file_uncompressed=4096,
        max_total_uncompressed=4096,
        max_compression_ratio=2,
    ),
)


print(f"== summary: {P} passed, {F} failed; mutation={args.mutate or 'none'} ==")
make_writable(BASE)
TMP.cleanup()
raise SystemExit(1 if F else 0)
