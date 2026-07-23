#!/usr/bin/env python3
"""Dev-time TARGETED re-carve for the misc agent.

The misc extraction tools (zsteg / steghide / binwalk / foremost / stegseek /
outguess / …) live ONLY in the sibling `hextech_ctf_tool-misc` image — the
worker container the agent runs in does NOT have them (verified: only exiftool
is present). The one-shot collector (`misc/analyze.py`) runs a FIXED sweep, but
the agent frequently needs a TARGETED re-run the sweep didn't do: a specific
zsteg bit-plane, `steghide extract -p <passphrase discovered mid-analysis>`, an
offset/format-specific binwalk. This wrapper shells the sibling image with an
entrypoint override so the agent can run any tool the image already has, against
files in the job dir, WITHOUT an image rebuild.

USAGE (from the agent's Bash; cwd = the job work dir):
    python3 -m worker.misc_recarve <tool> [tool-args...]

The job dir is bind-mounted at /job inside the container, so refer to files by
their /job path, e.g.:
    python3 -m worker.misc_recarve zsteg -E 'b1,rgb,lsb,xy' /job/image.png
    python3 -m worker.misc_recarve steghide extract -sf /job/s.jpg -p hunter2 -xf /job/out.bin
    python3 -m worker.misc_recarve binwalk -e --dd '.*' /job/blob.bin

Runs with `--network none` + a memory cap; the mount is rw (tools may write
extractions into the job dir). Prints the tool's combined output; exit code is
the tool's exit code.
"""
import os
import sys


MISC_IMAGE = "hextech_ctf_tool-misc"


def _usage(msg: str = "") -> int:
    if msg:
        print(f"[misc_recarve] {msg}", file=sys.stderr)
    print(
        "usage: python3 -m worker.misc_recarve <tool> [args...]  "
        "(file paths resolve at /job inside the container)",
        file=sys.stderr,
    )
    return 2


def main(argv: list[str]) -> int:
    if not argv:
        return _usage("no tool given")
    tool = argv[0]
    tool_args = argv[1:]

    job_id = os.environ.get("JOB_ID", "").strip()
    if not job_id:
        return _usage("JOB_ID env not set — run this from the job's agent Bash")
    host_root = os.environ.get("HOST_DATA_DIR", "").rstrip("/")
    if not host_root:
        return _usage("HOST_DATA_DIR env not set on the worker")
    host_job = f"{host_root}/jobs/{job_id}"  # matches misc orchestrator _host_path

    try:
        import docker
    except Exception as e:  # pragma: no cover
        return _usage(f"docker SDK unavailable: {e!r}")

    client = docker.from_env()
    print(
        f"[misc_recarve] {tool} {' '.join(tool_args)}  "
        f"(image={MISC_IMAGE}, /job={host_job})",
        flush=True,
    )
    try:
        out = client.containers.run(
            image=MISC_IMAGE,
            entrypoint=[tool],
            command=tool_args,
            volumes={host_job: {"bind": "/job", "mode": "rw"}},
            network_mode="none",
            mem_limit="2g",
            remove=True,
            stdout=True,
            stderr=True,
        )
        if isinstance(out, bytes):
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()
        else:
            print(out)
        return 0
    except docker.errors.ContainerError as e:
        # Non-zero tool exit — still surface stdout/stderr so the agent sees why.
        blob = e.stderr if isinstance(e.stderr, bytes) else (e.stderr or "").encode()
        if blob:
            sys.stdout.buffer.write(blob)
            sys.stdout.buffer.flush()
        print(f"[misc_recarve] {tool} exited {e.exit_status}", file=sys.stderr)
        return e.exit_status or 1
    except docker.errors.ImageNotFound:
        return _usage(f"{MISC_IMAGE} image not found — build it (start.sh) first")
    except Exception as e:
        print(f"[misc_recarve] failed: {e!r}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
