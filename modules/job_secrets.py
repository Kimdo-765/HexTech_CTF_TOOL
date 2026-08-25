"""Job-scoped challenge credential storage and exact-value redaction.

Secrets live outside ``jobs/<id>`` so hybrid parent-directory invariants and
measurement archives cannot accidentally include them.  The API and worker
share ``DATA_DIR/job-secrets``; deletion and TTL cleanup remove the sibling
file explicitly.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


# THREE DIFFERENT QUESTIONS, AND THEY ARE NOT THE SAME SET.
#
# One frozenset used to answer all three, and adding MISC_PASSPHRASE to it for
# the first answer silently changed the other two. Both regressions were
# reproduced before this split existed:
#
#   * `_validate_explicit` gates the operator's key/value ingress on the list,
#     so the new key became accepted there — and `prepare_job_secret` threw the
#     validated key away and hardcoded CTFD_ACCESS_TOKEN, so a request with
#     secret_key=MISC_PASSPHRASE OVERWROTE a real CTFd token with the
#     passphrase. Measured: a job holding `ctfd_<64hex>` came back holding
#     `zipPassword1`, and the passphrase was not stored under its own key
#     either. Reachable from every module's /analyze and from /continue, which
#     rewrites the job's own file in place with no retry lineage involved.
#
#   * redaction is a plain substring replace over descriptions, log payloads
#     AND meta.json, so the passphrase became a needle over the job's own
#     metadata. Measured: passphrase `hunter2024` turned
#     meta['filename'] = "hunter2024_challenge.zip" into
#     "[REDACTED_JOB_SECRET]_challenge.zip" — and the misc retry rebuilds from
#     meta['filename'], so the feature destroyed its own input.
#
# Storage/read is the only one MISC_PASSPHRASE belongs in.
ALLOWED_SECRET_KEYS = frozenset({"CTFD_ACCESS_TOKEN", "MISC_PASSPHRASE"})

# What the operator-facing key/value form may set. The passphrase has its own
# typed entry point (`store_misc_passphrase`) and must not be reachable here.
_OPERATOR_INGRESS_KEYS = frozenset({"CTFD_ACCESS_TOKEN"})

# What may be used as a search-and-replace NEEDLE over free text and metadata.
# A credential the agent must not see belongs here; a passphrase the agent is
# handed anyway (it is exported into the sandbox with every other stored key,
# and passed to the misc container on its command line) buys nothing by being
# masked and costs the metadata it collides with. This set is exactly what was
# redacted before MISC_PASSPHRASE existed, so redaction behaviour is unchanged.
_REDACTABLE_KEYS = frozenset({"CTFD_ACCESS_TOKEN"})
RESERVED_SECRET_KEYS = frozenset({
    "AUTH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "CODEX_API_KEY",
})
REDACTION_MARKER = "[challenge credential moved to secret ingress]"
_JOB_ID_RE = re.compile(r"^[a-f0-9]{12}$")
_CTFD_TOKEN_RE = re.compile(r"\bctfd_[0-9a-fA-F]{64}\b")
_NAMED_CTFD_RE = re.compile(
    r"(?i)\bCTFD_ACCESS_TOKEN\s*[:=]\s*([^\s,;]+)"
)
_RESERVED_AUTH_RE = re.compile(r"(?i)\bAUTH_TOKEN\s*[:=]\s*([^\s,;]+)")


class SecretIngressError(ValueError):
    pass


def _root() -> Path:
    return Path(os.environ.get("DATA_DIR", "/data")) / "job-secrets"


def _path(job_id: str) -> Path:
    safe = str(job_id or "").strip().lower()
    if not _JOB_ID_RE.fullmatch(safe):
        raise SecretIngressError("invalid job id for secret ingress")
    return _root() / f"{safe}.json"


def read_job_secrets(job_id: str) -> dict[str, str]:
    try:
        raw = json.loads(_path(job_id).read_text())
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in raw.items()
        if key in ALLOWED_SECRET_KEYS and isinstance(value, str) and value
    }


def _write_job_secrets(job_id: str, secrets: dict[str, str]) -> None:
    path = _path(job_id)
    root = path.parent
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    temporary = root / f".{path.name}.{os.getpid()}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fp:
            json.dump(secrets, fp, separators=(",", ":"), ensure_ascii=False)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_explicit(key: str | None, value: str | None) -> tuple[str, str] | None:
    raw_key = str(key or "").strip()
    raw_value = str(value or "").strip()
    if not raw_key and not raw_value:
        return None
    if not raw_key or not raw_value:
        raise SecretIngressError("challenge secret key and value are both required")
    normalized = raw_key.upper()
    if normalized in RESERVED_SECRET_KEYS:
        raise SecretIngressError(
            f"reserved secret key {normalized}; use CTFD_ACCESS_TOKEN"
        )
    if normalized not in _OPERATOR_INGRESS_KEYS:
        raise SecretIngressError("unsupported challenge secret key")
    if not 8 <= len(raw_value) <= 8192:
        raise SecretIngressError("challenge secret value must be 8..8192 characters")
    return normalized, raw_value


def prepare_job_secret(
    job_id: str,
    description: str | None,
    *,
    secret_key: str | None = None,
    secret_value: str | None = None,
    copy_from: str | None = None,
) -> str | None:
    """Store explicit/legacy CTFd credentials and return safe description."""

    text = str(description or "")
    if _RESERVED_AUTH_RE.search(text):
        raise SecretIngressError(
            "AUTH_TOKEN is reserved; use the dedicated CTFD_ACCESS_TOKEN ingress"
        )

    secrets = read_job_secrets(copy_from) if copy_from else read_job_secrets(job_id)
    candidates: list[str] = []
    explicit = _validate_explicit(secret_key, secret_value)
    explicit_key = None
    if explicit is not None:
        explicit_key, candidate = explicit
        candidates.append(candidate)
    candidates.extend(match.group(1) for match in _NAMED_CTFD_RE.finditer(text))
    candidates.extend(_CTFD_TOKEN_RE.findall(text))
    unique = list(dict.fromkeys(candidate for candidate in candidates if candidate))
    if len(unique) > 1:
        raise SecretIngressError("conflicting CTFd credentials were supplied")
    if unique:
        candidate = unique[0]
        if not 8 <= len(candidate) <= 8192:
            raise SecretIngressError("challenge secret value must be 8..8192 characters")
        # Store under the key that was VALIDATED, not under a hardcoded one.
        # The literal here discarded `explicit_key` entirely, which is what
        # turned "the ingress accepts one more key name" into "the ingress
        # overwrites the CTFd token". Harmless while the ingress admits exactly
        # one key — and this is the line that makes that a design property
        # instead of a coincidence.
        secrets[explicit_key or "CTFD_ACCESS_TOKEN"] = candidate

    redacted = _NAMED_CTFD_RE.sub(REDACTION_MARKER, text)
    redacted = _CTFD_TOKEN_RE.sub(REDACTION_MARKER, redacted)
    for key, value in secrets.items():
        if value and key in _REDACTABLE_KEYS:
            redacted = redacted.replace(value, REDACTION_MARKER)
    if secrets:
        _write_job_secrets(job_id, secrets)
    return redacted.strip() or None


def store_misc_passphrase(job_id: str, value: str | None) -> None:
    """Park the misc archive passphrase on the same rail as CTFd credentials.

    WHY IT LIVES HERE AND NOT IN meta.json. The passphrase used to reach the
    orchestrator only as an RQ argument, so nothing outlived the first run and
    `misc` had to be excluded from _RETRYABLE_MODULES — a rebuilt job would
    have re-run without it and failed in a way that reads as a capability
    problem. Putting it here makes retry work by the mechanism that already
    exists: `prepare_job_secret(new_id, ..., copy_from=prev_id)` carries a
    job's secrets to its retry child, so nothing in the retry route has to know
    what a passphrase is.

    IT IS NOT REDACTED, DELIBERATELY. `_REDACTABLE_KEYS` excludes it, so it is
    never used as a search-and-replace needle over descriptions, logs or
    meta.json. Masking it would buy nothing — every stored key is exported into
    the sandbox (`env.update(read_job_secrets(job_id))` in modules/_runner.py
    and modules/_common.py) and the value is on the misc container's command
    line either way — and it costs whatever text it collides with. Measured:
    with the passphrase as a needle, `hunter2024` rewrote
    meta['filename'] = "hunter2024_challenge.zip" to
    "[REDACTED_JOB_SECRET]_challenge.zip", and the retry rebuilds from
    meta['filename'].

    What it does get is the storage discipline: 0600 inside a 0700 directory,
    OUTSIDE `jobs/<id>` so archives and hybrid parent-directory sweeps cannot
    pick it up, and deleted with the job.

    NOT routed through `_validate_explicit`: that is the OPERATOR-facing
    key/value ingress, whose allowlist (`_OPERATOR_INGRESS_KEYS`) deliberately
    does not include this key, and which requires 8..8192 characters — a
    sensible floor for an API token and a wrong one for a passphrase
    (`hunter2` is seven). The only bound that matters here is the upper one.
    """
    text = str(value or "")
    if not text:
        return
    if len(text) > 8192:
        raise SecretIngressError("misc passphrase must be at most 8192 characters")
    secrets = read_job_secrets(job_id)
    secrets["MISC_PASSPHRASE"] = text
    _write_job_secrets(job_id, secrets)


def read_misc_passphrase(job_id: str) -> str | None:
    """The stored passphrase, or None. Read by the orchestrator when its own
    argument is empty, which is exactly the retry case."""
    return read_job_secrets(job_id).get("MISC_PASSPHRASE") or None


def copy_job_secrets(source_job_id: str, destination_job_id: str) -> None:
    secrets = read_job_secrets(source_job_id)
    if secrets:
        _write_job_secrets(destination_job_id, secrets)


def delete_job_secrets(job_id: str) -> None:
    try:
        _path(job_id).unlink(missing_ok=True)
    except (OSError, ValueError):
        return


def cleanup_orphaned_secrets(*, older_than_epoch: float) -> int:
    """Delete aged secret files whose owning job directory no longer exists."""

    root = _root()
    jobs = root.parent / "jobs"
    removed = 0
    try:
        paths = list(root.glob("*.json"))
    except OSError:
        return 0
    for path in paths:
        job_id = path.stem
        if not _JOB_ID_RE.fullmatch(job_id) or (jobs / job_id).exists():
            continue
        try:
            if path.stat().st_mtime >= older_than_epoch:
                continue
            path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def redact_job_value(job_id: str, value: Any) -> Any:
    """Recursively replace exact stored secret values in log/event payloads."""

    secrets = tuple(v for k, v in read_job_secrets(job_id).items()
                    if v and k in _REDACTABLE_KEYS)
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED_JOB_SECRET]")
        return value
    if isinstance(value, dict):
        return {key: redact_job_value(job_id, item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_job_value(job_id, item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_job_value(job_id, item) for item in value)
    return value
