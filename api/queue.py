import os

from redis import Redis
from rq import Queue

from modules.settings_io import get_setting

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

_redis = Redis.from_url(REDIS_URL)


DEFAULT_SOFT_TIMEOUT_S = 6000

# Hard ceiling sent to RQ. Must be far greater than the user's "soft" budget
# so the worker-internal wall-clock watchdog fires first and the user gets
# a chance to decide continue/kill. This is the absolute upper bound RQ will
# allow before sending SIGTERM to the worker no matter what.
_HARD_TIMEOUT_CEILING_S = 7 * 24 * 3600  # 7 days


def _job_timeout() -> int:
    """Read user-set soft timeout from settings on each call so changes via
    the Settings tab apply to subsequent enqueues without an api restart."""
    try:
        return int(get_setting("job_timeout_seconds") or DEFAULT_SOFT_TIMEOUT_S)
    except (TypeError, ValueError):
        return DEFAULT_SOFT_TIMEOUT_S


def resolve_timeout(per_job: int | None) -> int:
    """Soft (user-facing) timeout. Per-job override > global setting > default.

    This is the deadline the in-worker watchdog fires at; once reached the
    UI prompts the user to continue or kill. RQ's hard timeout — see
    `hard_timeout_for` — is larger.
    """
    if per_job and per_job > 0:
        return int(per_job)
    return _job_timeout()


def hard_timeout_for(soft: int) -> int:
    """Translate a user-set soft timeout into the value passed to RQ as the
    hard kill ceiling. We pad generously so the watchdog window is long
    enough for a human to react and so a 'continue' decision still has
    plenty of runway.
    """
    if soft <= 0:
        return _HARD_TIMEOUT_CEILING_S
    return min(max(int(soft) * 4, 86400), _HARD_TIMEOUT_CEILING_S)


_VALID_EFFORTS = frozenset(("low", "medium", "high", "max"))


def normalize_effort(raw: str | None) -> str | None:
    """Validate the operator-supplied effort value.

    Empty / None → return None (caller will fall back to the global
    setting or the SDK default). A non-empty value not in the
    SDK's accepted set is silently coerced to None as well; this
    keeps a typo from blocking the job submit and instead pushes
    the run onto the safe default. Accepted values mirror
    ``ClaudeAgentOptions(effort=...)``: low / medium / high / max.
    """
    if raw is None:
        return None
    s = raw.strip().lower()
    if not s:
        return None
    return s if s in _VALID_EFFORTS else None


def get_queue() -> Queue:
    return Queue(
        "hextech_ctf_tool",
        connection=_redis,
        default_timeout=hard_timeout_for(_job_timeout()),
    )


def get_redis() -> Redis:
    return _redis
