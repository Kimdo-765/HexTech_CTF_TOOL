"""Disk image artifact extraction using sleuthkit (mmls/fsstat/fls/icat).

Algorithm:
1. Convert qcow2/vmdk to raw via qemu-img if needed
2. mmls -> partition list with offsets
3. For each filesystem partition:
     fsstat -o <off> -> detect FS type
     fls -r -p -o <off> -> recursive listing (path + inode)
4. Match listing against curated artifact patterns (Linux + Windows)
5. icat each matching inode to artifacts/<sanitized_path>
"""
from __future__ import annotations

import fnmatch
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable

LINUX_PATTERNS = [
    "etc/passwd", "etc/shadow", "etc/group", "etc/gshadow",
    "etc/hostname", "etc/hosts", "etc/resolv.conf",
    "etc/sudoers",
    "etc/sudoers.d/*",
    "etc/ssh/sshd_config", "etc/ssh/ssh_config",
    "etc/ssh/ssh_host_*key*",
    "etc/crontab",
    "etc/cron.d/*", "etc/cron.daily/*", "etc/cron.hourly/*",
    "etc/cron.weekly/*", "etc/cron.monthly/*",
    "var/spool/cron/*", "var/spool/cron/crontabs/*",
    "etc/systemd/system/*.service",
    "etc/rc.local",
    "var/log/auth.log*", "var/log/syslog*", "var/log/messages*",
    "var/log/secure*", "var/log/wtmp*", "var/log/btmp*",
    "var/log/lastlog", "var/log/dmesg*",
    "var/log/audit/audit.log*",
    "var/log/apache2/*", "var/log/nginx/*",
    "root/.bash_history", "root/.zsh_history",
    "root/.profile", "root/.bashrc", "root/.zshrc",
    "root/.ssh/*",
    "home/*/.bash_history", "home/*/.zsh_history",
    "home/*/.profile", "home/*/.bashrc", "home/*/.zshrc",
    "home/*/.ssh/*",
    "tmp/*", "var/tmp/*",
]

WINDOWS_PATTERNS = [
    "Windows/System32/config/SAM",
    "Windows/System32/config/SAM.LOG*",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SYSTEM.LOG*",
    "Windows/System32/config/SOFTWARE",
    "Windows/System32/config/SOFTWARE.LOG*",
    "Windows/System32/config/SECURITY",
    "Windows/System32/config/SECURITY.LOG*",
    "Windows/System32/config/DEFAULT",
    "Users/*/NTUSER.DAT",
    "Users/*/NTUSER.DAT.LOG*",
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG*",
    "Windows/System32/winevt/Logs/Security.evtx",
    "Windows/System32/winevt/Logs/System.evtx",
    "Windows/System32/winevt/Logs/Application.evtx",
    "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell*",
    "Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler*",
    "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon*",
    "Windows/Prefetch/*.pf",
    "Windows/System32/Tasks/*",
    "Windows/Tasks/*",
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk",
    "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
    "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
    "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History",
    "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
    "$MFT", "$LogFile",
]


# Whole-image conversion (qemu-img / ewfexport) is the single heaviest op and,
# unlike the per-artifact tools, a timeout there RAISES (fatal to the job) — so
# it gets a much larger dedicated budget than the 300s per-probe default; the
# container wall (FORENSIC_TIMEOUT_S) still backstops it.
CONVERT_TIMEOUT = 1500


def _run(cmd: list[str], log_fn: Callable[[str], None], timeout: int = 300) -> tuple[int, str, str]:
    log_fn(f"$ {' '.join(cmd)}")
    # Per-op timeout: one hung sleuthkit/qemu-img op must not block until the
    # whole-container wall fires and takes the job + all later ops down with it.
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        log_fn(f"[timeout] {cmd[0]} …{cmd[-1]} exceeded {timeout}s — skipping")
        return 124, "", f"timed out after {timeout}s"
    except Exception as e:  # tool missing / spawn failure — record + continue
        log_fn(f"[error] {cmd[0]} …{cmd[-1]}: {e!r}")
        return 1, "", str(e)


def _convert_to_raw(src: Path, kind: str, log_fn) -> Path:
    if kind in ("raw", "raw_disk"):
        return src
    dst = src.with_suffix(src.suffix + ".raw") if src.suffix else src.with_name(src.name + ".raw")
    if kind == "e01":
        # ewfexport produces "<output>.raw" or split chunks named "<output>.raw.001" etc.
        # Simplest: ewfexport with -t and rely on the .raw output.
        prefix = str(dst.with_suffix(""))
        rc, out, err = _run(
            ["ewfexport", "-t", prefix, "-f", "raw", "-q", "-u", str(src)], log_fn,
            timeout=CONVERT_TIMEOUT,
        )
        # ewfexport actual output is `<prefix>.raw` (single chunk) when -B is not set
        candidates = [Path(prefix + ".raw"), dst]
        for c in candidates:
            if c.is_file():
                return c
        # Try chunked output (ewfexport sometimes splits)
        chunks = sorted(Path(dst.parent).glob(Path(prefix).name + ".raw.*"))
        if chunks:
            with dst.open("wb") as merged:
                for c in chunks:
                    merged.write(c.read_bytes())
            return dst
        raise RuntimeError(f"ewfexport produced no raw output: {err[-500:]}")
    # qemu-img handles qcow2 / vmdk / vhd / vhdx natively
    rc, out, err = _run(["qemu-img", "convert", "-O", "raw", str(src), str(dst)], log_fn,
                        timeout=CONVERT_TIMEOUT)
    if rc != 0:
        raise RuntimeError(f"qemu-img convert failed ({kind}): {err}")
    return dst


def _mmls(image: Path, log_fn):
    """Return list of (offset_sectors, length, description). Empty if no partition table."""
    rc, out, _ = _run(["mmls", str(image)], log_fn)
    if rc != 0:
        return []
    parts = []
    for line in out.splitlines():
        m = re.match(r"^\s*\d+:\s*\S+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$", line)
        if m:
            parts.append((int(m.group(1)), int(m.group(2)), m.group(3).strip()))
    return parts


def _fsstat(image: Path, offset_sectors: int, log_fn) -> str:
    rc, out, _ = _run(["fsstat", "-o", str(offset_sectors), str(image)], log_fn)
    if rc != 0:
        return ""
    for line in out.splitlines():
        if line.lower().startswith("file system type:"):
            return line.split(":", 1)[1].strip()
    return ""


def _fls_listing(image: Path, offset_sectors: int, log_fn) -> list[tuple[str, str]]:
    """Return list of (inode_id, full_path). Inode id is the first column joined,
    e.g. '128-1' or '12345-128-1'. Used directly with icat -o <off> image <inode>.
    """
    rc, out, _ = _run(
        ["fls", "-r", "-p", "-F", "-o", str(offset_sectors), str(image)],
        log_fn,
    )
    if rc != 0:
        return []
    files = []
    for line in out.splitlines():
        # format: r/r 12345-128-1: path/to/file
        m = re.match(r"^\s*[a-z?]/[a-z?]\s+([\d\-]+)\s*:\s+(.+)$", line)
        if m:
            inode_id = m.group(1).rstrip("-:")
            path = m.group(2).strip()
            if path == "":
                continue
            files.append((inode_id, path))
    return files


def _sanitize(p: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/\-]", "_", p)


def _matches_any(path: str, patterns: list[str]) -> bool:
    norm = path.lstrip("/").replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(norm, pat):
            return True
        if fnmatch.fnmatch(norm.lower(), pat.lower()):
            return True
    return False


def _icat(image: Path, offset_sectors: int, inode_id: str, dst: Path, log_fn) -> bool:
    dst.parent.mkdir(parents=True, exist_ok=True)
    rc, out, err = _run(
        ["icat", "-o", str(offset_sectors), str(image), inode_id],
        log_fn,
    )
    if rc != 0 or not out:
        return False
    dst.write_bytes(out.encode("latin-1") if isinstance(out, str) else out)
    return True


def _icat_binary(image: Path, offset_sectors: int, inode_id: str, dst: Path, log_fn) -> bool:
    """Like _icat but uses subprocess.run with bytes capture for binary safety."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["icat", "-o", str(offset_sectors), str(image), inode_id]
    log_fn(f"$ {' '.join(cmd)} > {dst}")
    try:
        cp = subprocess.run(cmd, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired:
        log_fn(f"[timeout] icat {inode_id} exceeded 180s — skipping")
        return False
    if cp.returncode != 0 or not cp.stdout:
        return False
    dst.write_bytes(cp.stdout)
    return True


def process_disk(
    image_in: Path,
    kind: str,
    out_dir: Path,
    target_os: str,
    bulk_extractor: bool,
    log_fn: Callable[[str], None],
) -> dict:
    artifacts_dir = out_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    raw = _convert_to_raw(image_in, kind, log_fn)

    # Discover filesystems. If mmls returns nothing, treat the whole image as a single FS at offset 0.
    parts = _mmls(raw, log_fn)
    fs_partitions: list[tuple[int, str]] = []
    if parts:
        for off, _length, desc in parts:
            fs_type = _fsstat(raw, off, log_fn)
            if fs_type:
                fs_partitions.append((off, fs_type))
                log_fn(f"partition @ sector {off}: {fs_type} ({desc})")
    else:
        fs_type = _fsstat(raw, 0, log_fn)
        if fs_type:
            fs_partitions.append((0, fs_type))
            log_fn(f"single filesystem (no MBR/GPT): {fs_type}")

    summary = {
        "raw_image": str(raw),
        "partitions": [
            {"offset_sectors": off, "fs_type": ft} for off, ft in fs_partitions
        ],
        "extracted": [],
        "errors": [],
    }

    for off, fs_type in fs_partitions:
        # Choose pattern set
        if target_os == "linux":
            patterns = LINUX_PATTERNS
        elif target_os == "windows":
            patterns = WINDOWS_PATTERNS
        else:
            ft_low = fs_type.lower()
            if "ntfs" in ft_low:
                patterns = WINDOWS_PATTERNS
            elif "ext" in ft_low or "xfs" in ft_low or "btrfs" in ft_low:
                patterns = LINUX_PATTERNS
            else:
                patterns = LINUX_PATTERNS + WINDOWS_PATTERNS

        listing = _fls_listing(raw, off, log_fn)
        log_fn(f"partition off={off}: {len(listing)} entries listed")

        for inode_id, path in listing:
            if not _matches_any(path, patterns):
                continue
            sanitized = _sanitize(path)
            dst = artifacts_dir / f"part_{off}" / sanitized
            ok = _icat_binary(raw, off, inode_id, dst, log_fn)
            if ok:
                summary["extracted"].append({
                    "partition_offset": off,
                    "fs_type": fs_type,
                    "path": path,
                    "inode": inode_id,
                    "extracted_to": str(dst.relative_to(out_dir)),
                    "size": dst.stat().st_size,
                })
            else:
                summary["errors"].append({
                    "partition_offset": off,
                    "path": path,
                    "inode": inode_id,
                    "reason": "icat failed or empty",
                })

    if bulk_extractor:
        if shutil.which("bulk_extractor"):
            be_out = out_dir / "bulk_extractor"
            be_out.mkdir(exist_ok=True)
            rc, _, err = _run(
                ["bulk_extractor", "-o", str(be_out), str(raw)], log_fn
            )
            summary["bulk_extractor"] = {"rc": rc, "stderr_tail": err[-500:]}
        else:
            log_fn("bulk_extractor not installed in this image; skipping")
            summary["bulk_extractor"] = {"skipped": "binary not present"}

    return summary
