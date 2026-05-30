#!/usr/bin/env python3
"""Run Ghidra in headless mode for the orchestrator.

Two modes:

  decomp (default — backward compatible)
      Auto-analyze a binary (or skip analysis if already cached) and
      bundle every function's decompiled .c into a zip. Saves the
      project directory under <binary parent>/.ghidra_proj/ so later
      `xrefs` calls reuse it without re-analyzing.

      legacy form: <ghidra> <binary> [-o <zip>]
      explicit:    <ghidra> decomp <binary> [-o <zip>]

  xrefs
      Reuse the cached project to query cross-references to a symbol
      or address. Auto-bootstraps a full analysis if no cached project
      is present yet.

      form: <ghidra> xrefs <binary> <target> -o <out_json> [--limit N]

Layout (binary at /job/bin/foo, project cache at /job/.ghidra_proj):

    /job/.ghidra_proj/decomp_proj.gpr       # Ghidra project file
    /job/.ghidra_proj/decomp_proj.rep/...   # repository directory
"""

import argparse
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


PROJECT_NAME = "decomp_proj"
PROJECT_SUBDIR = ".ghidra_proj"


def find_headless(ghidra_root: Path) -> Path:
    candidate = ghidra_root / "support" / "analyzeHeadless"
    if candidate.is_file():
        return candidate
    sys.exit("analyzeHeadless not found at {}".format(candidate))


def project_dir_for(binary: Path) -> Path:
    """Stable per-job project location. Bind-mounted /job is the binary's
    grand-parent (binary lives at /job/bin/<name>); the project goes one
    level above so multiple binaries in the same job can share it.
    """
    job_root = binary.parent.parent if binary.parent.name == "bin" else binary.parent
    return (job_root / PROJECT_SUBDIR).resolve()


def project_is_cached(project_dir: Path) -> bool:
    return (project_dir / (PROJECT_NAME + ".gpr")).is_file()


def _run_subprocess(cmd):
    print("[*] running:", " ".join(str(c) for c in cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        sys.exit("Ghidra headless failed (exit {})".format(rc))


def import_and_decompile(headless: Path, project_dir: Path, binary: Path,
                         script_dir: Path, decomp_dir: Path) -> None:
    """First-time analysis path: import + auto-analyze + ExportDecompiled.
    Project is preserved in `project_dir` for later xrefs calls.
    """
    project_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(headless),
        str(project_dir), PROJECT_NAME,
        "-import", str(binary),
        "-overwrite",
        "-scriptPath", str(script_dir),
        "-postScript", "ExportDecompiled.py", str(decomp_dir),
        # NOTE: no -deleteProject — we keep it for xrefs.
    ]
    _run_subprocess(cmd)


def reuse_and_decompile(headless: Path, project_dir: Path, binary_name: str,
                        script_dir: Path, decomp_dir: Path) -> None:
    """Repeat-decomp path: re-run ExportDecompiled against cached project.
    Skips auto-analysis (much faster than the first call).
    """
    cmd = [
        str(headless),
        str(project_dir), PROJECT_NAME,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(script_dir),
        "-postScript", "ExportDecompiled.py", str(decomp_dir),
    ]
    _run_subprocess(cmd)


def reuse_xrefs(headless: Path, project_dir: Path, binary_name: str,
                script_dir: Path, target: str, out_path: Path,
                limit: int) -> None:
    """Run Xrefs.py against the cached project."""
    cmd = [
        str(headless),
        str(project_dir), PROJECT_NAME,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(script_dir),
        "-postScript", "Xrefs.py", target, str(out_path), str(limit),
    ]
    _run_subprocess(cmd)


def make_zip(src_dir: Path, zip_path: Path) -> int:
    files = sorted(src_dir.glob("*.c"))
    if not files:
        sys.exit("no decompiled .c files were produced")
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, arcname=f.name)
    return len(files)


def cmd_decomp(ghidra_root: Path, script_dir: Path,
               binary_arg: str, output_arg: str | None) -> None:
    binary = Path(binary_arg).expanduser().resolve()
    if not binary.is_file():
        sys.exit("binary not found: {}".format(binary))

    headless = find_headless(ghidra_root)
    output_zip = (
        Path(output_arg).expanduser().resolve()
        if output_arg
        else binary.with_name(binary.name + "_decompiled.zip")
    )
    project_dir = project_dir_for(binary)

    with tempfile.TemporaryDirectory(prefix="ghidra_decomp_") as tmp:
        decomp_dir = Path(tmp) / "decompiled"
        decomp_dir.mkdir()

        if project_is_cached(project_dir):
            print("[*] reusing cached project at {}".format(project_dir))
            reuse_and_decompile(
                headless, project_dir, binary.name,
                script_dir, decomp_dir,
            )
        else:
            print("[*] no cached project — analyzing fresh into {}".format(project_dir))
            import_and_decompile(
                headless, project_dir, binary,
                script_dir, decomp_dir,
            )

        count = make_zip(decomp_dir, output_zip)

    print("[+] {} functions -> {}".format(count, output_zip))


def cmd_xrefs(ghidra_root: Path, script_dir: Path,
              binary_arg: str, target_arg: str,
              output_arg: str, limit: int) -> None:
    binary = Path(binary_arg).expanduser().resolve()
    if not binary.is_file():
        sys.exit("binary not found: {}".format(binary))

    headless = find_headless(ghidra_root)
    out_path = Path(output_arg).expanduser().resolve()
    project_dir = project_dir_for(binary)

    # Auto-bootstrap: if no cached project exists, run a full import/analyze
    # first. Cheaper to do once now than to fail and force the agent to
    # learn the ordering. The .c files from this bootstrap are discarded;
    # the project itself is what we needed to materialize.
    if not project_is_cached(project_dir):
        print("[*] xrefs requested but no cached project — bootstrapping analysis first")
        with tempfile.TemporaryDirectory(prefix="ghidra_decomp_") as tmp:
            decomp_dir = Path(tmp) / "decompiled"
            decomp_dir.mkdir()
            import_and_decompile(
                headless, project_dir, binary,
                script_dir, decomp_dir,
            )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    reuse_xrefs(
        headless, project_dir, binary.name,
        script_dir, target_arg, out_path, limit,
    )

    if not out_path.is_file():
        sys.exit("Xrefs.py did not produce an output file at {}".format(out_path))
    print("[+] xrefs -> {}".format(out_path))


def parse_args(argv):
    """Hand-rolled dispatch — argparse subparsers don't play nicely with
    legacy positional fallback (`<ghidra> <binary>` with no subcommand).
    """
    if len(argv) < 2:
        sys.exit("usage: <ghidra_path> [decomp|xrefs] <binary> [...]")
    ghidra_path = argv[1]
    rest = argv[2:]

    # Detect explicit subcommand vs legacy form.
    if rest and rest[0] in ("decomp", "xrefs"):
        mode = rest[0]
        rest = rest[1:]
    else:
        mode = "decomp"

    parser = argparse.ArgumentParser(prog="ghidra_decompile.py {}".format(mode))
    if mode == "decomp":
        parser.add_argument("binary")
        parser.add_argument("-o", "--output")
        ns = parser.parse_args(rest)
        return mode, ghidra_path, ns
    elif mode == "xrefs":
        parser.add_argument("binary")
        parser.add_argument("target")
        parser.add_argument("-o", "--output", required=True)
        parser.add_argument("--limit", type=int, default=50)
        ns = parser.parse_args(rest)
        return mode, ghidra_path, ns
    else:  # unreachable
        sys.exit("unknown mode: {}".format(mode))


def main():
    mode, ghidra_path, ns = parse_args(sys.argv)
    ghidra_root = Path(ghidra_path).expanduser().resolve()
    script_dir = Path(__file__).resolve().parent

    if mode == "decomp":
        cmd_decomp(ghidra_root, script_dir, ns.binary, ns.output)
    elif mode == "xrefs":
        cmd_xrefs(
            ghidra_root, script_dir,
            ns.binary, ns.target, ns.output, ns.limit,
        )


if __name__ == "__main__":
    main()
