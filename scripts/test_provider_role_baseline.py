#!/usr/bin/env python3
"""Characterize role resolution before hybrid provider overrides exist.

The fixture is a sanitized capture of all 49 readable job metadata records on
2026-08-08.  It intentionally stores only job ids, provider/model inputs and
resolved provider/model pairs.  Future role-routing work must keep this output
byte-identical whenever no role-provider override is present.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scripts" / "fixtures" / "provider_role_baseline.json"
sys.path.insert(0, str(ROOT))


def _bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def main() -> int:
    fixture = json.loads(FIXTURE.read_text())
    with tempfile.TemporaryDirectory(prefix="provider-role-baseline-") as tmp:
        data = Path(tmp)
        jobs_dir = data / "jobs"
        jobs_dir.mkdir()
        (data / "settings.json").write_text(json.dumps(fixture["settings"]))
        (data / "model_presets.json").write_text(
            json.dumps(fixture["model_presets"])
        )

        expected: dict[str, dict[str, list[str]]] = {}
        for provider, group in fixture["jobs"].items():
            profile = fixture["profiles"][provider]
            for bucket in ("explicit", "inherited"):
                for job_id in group[bucket]:
                    job_dir = jobs_dir / job_id
                    job_dir.mkdir()
                    model = group["model"] if bucket == "explicit" else None
                    (job_dir / "meta.json").write_text(
                        json.dumps(
                            {"id": job_id, "agent_provider": provider, "model": model}
                        )
                    )
                    expected[job_id] = profile

        os.environ["DATA_DIR"] = str(data)
        os.environ["SETTINGS_PATH"] = str(data / "settings.json")
        os.environ["MODEL_PRESETS_PATH"] = str(data / "model_presets.json")

        from modules._common import (
            resolve_judge_model,
            resolve_main_model,
            resolve_reviewer_model,
        )
        from modules._monitor import MONITOR_MODEL
        from modules.agent_provider import (
            coerce_model_for_provider,
            provider_for_job,
        )
        from modules.model_presets import resolve_role_model

        actual: dict[str, dict[str, list[str]]] = {}
        for job_id in sorted(expected):
            meta = json.loads((jobs_dir / job_id / "meta.json").read_text())
            provider = provider_for_job(job_id)
            main_model = resolve_main_model(meta.get("model"), provider)
            role_models = {
                "main": main_model,
                "judge": resolve_judge_model(job_id),
                "reviewer": resolve_reviewer_model(job_id),
                "recon": resolve_role_model("recon", main_model, provider),
                "debugger": resolve_role_model("debugger", main_model, provider),
                "triage": resolve_role_model("triage", main_model, provider),
                "report": resolve_role_model("report", main_model, provider),
                "monitor": resolve_role_model("monitor", MONITOR_MODEL, provider),
            }
            actual[job_id] = {
                role: [provider, coerce_model_for_provider(model, provider)]
                for role, model in role_models.items()
            }

    count = len(actual)
    ok = count == fixture["source_job_count"] and _bytes(actual) == _bytes(expected)
    print(
        f"{'PASS' if ok else 'FAIL'}  no-override provider/model resolution "
        f"is byte-identical for {count} historical jobs"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
