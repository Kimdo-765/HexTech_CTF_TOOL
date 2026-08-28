"""Agent output-language policy shared by API routes and worker roles.

The setting is snapshotted onto job metadata at submission time.  Worker
roles read only that snapshot, never the live setting, so changing Settings
cannot make a running job switch languages halfway through a retry chain.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

OUTPUT_LANGUAGES = ("auto", "ko", "en")


def normalize_output_language(value: Any, *, fallback: str = "auto") -> str:
    """Return a canonical output-language id.

    Empty and unknown values use ``fallback``.  API submissions intentionally
    resolve an empty value through Settings before calling this helper, while
    an explicit ``auto`` remains auto and can preserve an older job's behavior
    across /retry even if the global setting later changes.
    """
    raw = str(value or "").strip().lower()
    aliases = {
        "automatic": "auto",
        "default": "auto",
        "korean": "ko",
        "kr": "ko",
        "kor": "ko",
        "한국어": "ko",
        "english": "en",
        "eng": "en",
        "영어": "en",
    }
    raw = aliases.get(raw, raw)
    return raw if raw in OUTPUT_LANGUAGES else fallback


def resolve_output_language(override: Any = None) -> str:
    """Resolve a submission override against the global Settings value."""
    if override is not None and str(override).strip() != "":
        resolved = normalize_output_language(override, fallback="")
        if resolved:
            return resolved
    try:
        from modules.settings_io import get_setting

        return normalize_output_language(get_setting("agent_output_language"))
    except Exception:
        return "auto"


def _jobs_dir() -> Path:
    return Path(
        os.environ.get("JOBS_DIR")
        or (Path(os.environ.get("DATA_DIR", "/data")) / "jobs")
    )


def output_language_for_job(job_id: str | None) -> str:
    """Read the immutable language snapshot for ``job_id``.

    Missing metadata means ``auto`` rather than a live Settings lookup.  This
    keeps old/running jobs stable when the operator changes the global default.
    """
    if not job_id:
        return "auto"
    try:
        meta = json.loads((_jobs_dir() / str(job_id) / "meta.json").read_text())
    except Exception:
        return "auto"
    return normalize_output_language(meta.get("output_language"))


def output_language_instruction(language: Any) -> str:
    """System/developer instruction for human-facing prose.

    Machine-readable contracts and evidence are explicitly excluded so a
    language preference cannot translate a flag, command, path, schema key, or
    error string and thereby corrupt the CTF result.
    """
    lang = normalize_output_language(language)
    if lang == "auto":
        return ""
    target = "Korean (한국어)" if lang == "ko" else "English"
    return (
        "## OUTPUT LANGUAGE\n"
        f"Write all operator-facing prose in {target}, including analysis "
        "updates, delegated-agent summaries, verdict explanations, and report "
        "prose. When delegating work, require the delegated agent to use the "
        "same output language. Do not translate or rewrite code, shell "
        "commands, paths, filenames, identifiers, protocol literals, JSON or "
        "schema keys, quoted evidence, error messages, or flags; preserve those "
        "verbatim. Required machine-readable formats and sentinel tokens take "
        "priority over this prose-language preference."
    )


def instruction_for_job(job_id: str | None) -> str:
    return output_language_instruction(output_language_for_job(job_id))


def with_output_language(prompt: str | None, job_id: str | None) -> str:
    """Append the job's language policy once to a prompt."""
    base = str(prompt or "")
    instruction = instruction_for_job(job_id)
    if not instruction or "## OUTPUT LANGUAGE" in base:
        return base
    return base.rstrip() + "\n\n" + instruction


__all__ = [
    "OUTPUT_LANGUAGES",
    "instruction_for_job",
    "normalize_output_language",
    "output_language_for_job",
    "output_language_instruction",
    "resolve_output_language",
    "with_output_language",
]
