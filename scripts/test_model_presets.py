#!/usr/bin/env python3
"""Offline regression checks for provider-scoped model presets."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import modules.model_presets as presets


def _preset(model: str, effort: str = "") -> dict[str, str]:
    return {"main": model, "judge": model, "effort": effort}


class ModelPresetStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = presets.MODEL_PRESETS_PATH
        presets.MODEL_PRESETS_PATH = Path(self.tmp.name) / "model_presets.json"

    def tearDown(self) -> None:
        presets.MODEL_PRESETS_PATH = self.old_path
        self.tmp.cleanup()

    def test_provider_buckets_have_independent_active_presets(self) -> None:
        stored = presets.save_store({
            "version": 2,
            "providers": {
                "claude": {
                    "active": "quality",
                    "presets": {"quality": _preset("claude-opus-5", "max")},
                },
                "grok": {
                    "active": "fast",
                    "presets": {"fast": _preset("grok-code-fast-1", "low")},
                },
                "gpt": {
                    "active": "balanced",
                    "presets": {"balanced": _preset("gpt-5.6-terra", "medium")},
                },
            },
        })

        self.assertEqual(stored["version"], 2)
        self.assertEqual(
            presets.get_role_model("main", "claude"), "claude-opus-5"
        )
        self.assertEqual(
            presets.get_role_model("main", "grok"), "grok-code-fast-1"
        )
        self.assertEqual(
            presets.get_role_model("main", "gpt"), "gpt-5.6-terra"
        )
        self.assertEqual(presets.get_preset_effort("claude"), "max")
        self.assertEqual(presets.get_preset_effort("grok"), "low")
        self.assertEqual(presets.get_preset_effort("gpt"), "medium")

    def test_legacy_file_migrates_to_selected_provider(self) -> None:
        presets.MODEL_PRESETS_PATH.write_text(json.dumps({
            "active": "legacy",
            "presets": {"legacy": _preset("grok-build", "high")},
        }))

        with patch.object(presets, "_provider_name", return_value="grok"):
            loaded = presets.load_store()

        self.assertEqual(loaded["providers"]["grok"]["active"], "legacy")
        self.assertEqual(loaded["providers"]["claude"]["presets"], {})
        self.assertEqual(loaded["providers"]["gpt"]["presets"], {})

    def test_legacy_model_family_beats_changed_live_setting(self) -> None:
        presets.MODEL_PRESETS_PATH.write_text(json.dumps({
            "active": "old-claude",
            "presets": {"old-claude": _preset("claude-opus-4-7", "high")},
        }))

        # The operator may have selected GPT immediately before upgrading.
        # A clearly Claude v1 file must still migrate to Claude.
        with patch.object(presets, "_provider_name", return_value="gpt"):
            loaded = presets.load_store()

        self.assertEqual(
            loaded["providers"]["claude"]["active"], "old-claude"
        )
        self.assertEqual(loaded["providers"]["gpt"]["presets"], {})

    def test_legacy_put_preserves_other_provider_buckets(self) -> None:
        presets.save_store({
            "version": 2,
            "providers": {
                "claude": {
                    "active": "c",
                    "presets": {"c": _preset("claude-opus-5")},
                },
                "gpt": {
                    "active": "o",
                    "presets": {"o": _preset("gpt-5.6-sol")},
                },
            },
        })

        with patch.object(presets, "_provider_name", return_value="grok"):
            stored = presets.save_store({
                "active": "x",
                "presets": {"x": _preset("grok-4.5")},
            })

        self.assertEqual(stored["providers"]["grok"]["active"], "x")
        self.assertIn("c", stored["providers"]["claude"]["presets"])
        self.assertIn("o", stored["providers"]["gpt"]["presets"])

    def test_normalization_drops_unknown_fields_and_invalid_active(self) -> None:
        stored = presets.save_store({
            "version": 2,
            "providers": {
                "claude": {
                    "active": "missing",
                    "presets": {
                        "safe": {
                            "main": "  claude-sonnet-5  ",
                            "effort": "impossible",
                            "unknown_role": "must-disappear",
                        }
                    },
                },
                "unknown_provider": {
                    "active": "bad",
                    "presets": {"bad": _preset("other")},
                },
            },
        })

        claude = stored["providers"]["claude"]
        self.assertEqual(claude["active"], "")
        self.assertEqual(claude["presets"]["safe"]["main"], "claude-sonnet-5")
        self.assertEqual(claude["presets"]["safe"]["effort"], "")
        self.assertNotIn("unknown_role", claude["presets"]["safe"])
        self.assertNotIn("unknown_provider", stored["providers"])

    def test_view_exposes_ui_metadata(self) -> None:
        view = presets.view()
        self.assertEqual(view["model_providers"], ["claude", "grok", "gpt"])
        self.assertIn("main", view["configurable_roles"])
        self.assertIn("max", view["valid_efforts"])

    def test_main_resolver_can_target_provider_independent_of_live_setting(self) -> None:
        from modules import settings_io
        from modules._common import resolve_effort, resolve_main_model

        old_settings_path = settings_io.SETTINGS_PATH
        settings_io.SETTINGS_PATH = Path(self.tmp.name) / "settings.json"
        try:
            settings_io.update_settings({
                "agent_provider": "gpt",
                "claude_model": "claude-sonnet-4-6",
                "claude_effort": "low",
                "gpt_model": "gpt-5.6-sol",
                "gpt_effort": "medium",
            })
            presets.save_store({
                "version": 2,
                "providers": {
                    "claude": {
                        "active": "c",
                        "presets": {"c": _preset("claude-opus-5", "max")},
                    },
                    "gpt": {
                        "active": "o",
                        "presets": {"o": _preset("gpt-5.6-terra", "high")},
                    },
                },
            })

            self.assertEqual(
                resolve_main_model(None, "claude"), "claude-opus-5"
            )
            self.assertEqual(resolve_effort(None, "claude"), "max")
            self.assertEqual(
                resolve_main_model(None, "gpt"), "gpt-5.6-terra"
            )
            self.assertEqual(resolve_effort(None, "gpt"), "high")
        finally:
            settings_io.SETTINGS_PATH = old_settings_path

    def test_gpt_pre_recon_uses_recon_role_model(self) -> None:
        from modules._common import run_pre_recon
        from modules import gpt_agent

        presets.save_store({
            "version": 2,
            "providers": {
                "gpt": {
                    "active": "roles",
                    "presets": {
                        "roles": {
                            "main": "gpt-5.6-sol",
                            "recon": "gpt-5.6-terra",
                        }
                    },
                }
            },
        })
        captured = []

        class FakeClient:
            def __init__(self, options):
                captured.append(options)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return None

            async def query(self, _prompt):
                return None

            async def receive_response(self):
                if False:
                    yield None

        logs: list[str] = []
        with (
            patch("modules.agent_provider.active_provider", return_value="gpt"),
            patch.object(gpt_agent, "GptAgentClient", FakeClient),
        ):
            asyncio.run(run_pre_recon(
                job_id="preset-recon-test",
                work_dir=Path(self.tmp.name),
                model="gpt-5.6-sol",
                prompt="inspect",
                log_fn=logs.append,
            ))

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].model, "gpt-5.6-terra")
        self.assertTrue(any("model=gpt-5.6-terra" in line for line in logs))


if __name__ == "__main__":
    unittest.main()
