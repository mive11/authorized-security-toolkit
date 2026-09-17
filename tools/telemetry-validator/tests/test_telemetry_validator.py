from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "telemetry_validator.py"
PROFILE = ROOT / "profiles" / "windows-logging-health.json"

SPEC = importlib.util.spec_from_file_location("telemetry_validator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
tv = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tv
SPEC.loader.exec_module(tv)


class CliTests(unittest.TestCase):
    def invoke(self, fixture: str, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--events",
                str(ROOT / "fixtures" / fixture),
                "--profile",
                str(PROFILE),
                "--output",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_complete_fixture_is_observed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            result = self.invoke("events-complete.jsonl", output)
            self.assertEqual(result.returncode, tv.EXIT_OK, result.stderr)
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "observed")
            self.assertEqual(report["summary"], {"invalid": 0, "missing": 0, "observed": 7})
            rendered = json.dumps(report)
            for private_value in (
                "training-shell",
                "LAB\\analyst",
                "synthetic fixture content",
                "fixture-token",
                "benign.exe --fixture",
            ):
                self.assertNotIn(private_value, rendered)
            for signal in report["signals"]:
                for evidence in signal["evidence"]:
                    self.assertEqual(set(evidence), {"event_index", "timestamp"})

    def test_missing_fixture_returns_three(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            result = self.invoke("events-missing.jsonl", output)
            self.assertEqual(result.returncode, tv.EXIT_MISSING, result.stderr)
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "missing")
            self.assertGreater(report["summary"]["missing"], 0)

    def test_invalid_fixture_returns_two_without_payload_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            result = self.invoke("events-invalid.jsonl", output)
            self.assertEqual(result.returncode, tv.EXIT_INVALID, result.stderr)
            rendered = (output / "report.json").read_text(encoding="utf-8")
            rendered += (output / "report.md").read_text(encoding="utf-8")
            self.assertNotIn("never-copy-this-secret", rendered)
            self.assertNotIn("also-never-copy-this-secret", rendered)
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "invalid")
            self.assertEqual(report["summary"]["invalid"], 7)

    def test_reports_are_private_deterministic_and_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first"
            second = Path(temp) / "second"
            self.assertEqual(self.invoke("events-complete.jsonl", first).returncode, tv.EXIT_OK)
            self.assertEqual(self.invoke("events-complete.jsonl", second).returncode, tv.EXIT_OK)
            self.assertEqual(
                (first / "report.json").read_bytes(), (second / "report.json").read_bytes()
            )
            self.assertEqual(
                (first / "report.md").read_bytes(), (second / "report.md").read_bytes()
            )
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((first / "report.json").stat().st_mode), 0o600)
            before = (first / "report.json").read_bytes()
            self.assertEqual(self.invoke("events-complete.jsonl", first).returncode, tv.EXIT_INVALID)
            self.assertEqual((first / "report.json").read_bytes(), before)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_report_symlink_does_not_overwrite_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "report"
            output.mkdir(mode=0o700)
            victim = root / "victim.txt"
            victim.write_text("keep-me", encoding="utf-8")
            (output / "report.json").symlink_to(victim)
            result = self.invoke("events-complete.jsonl", output)
            self.assertEqual(result.returncode, tv.EXIT_INVALID)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep-me")


class ValidationTests(unittest.TestCase):
    def minimal_profile(self, matcher: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "id": "test-profile",
            "title": "Test profile",
            "signals": [
                {
                    "id": "test-signal",
                    "title": "Test signal",
                    "attack_techniques": ["T1059.001"],
                    "any_of": [{"fields": {"Image": matcher}}],
                    "min_count": 1,
                }
            ],
        }

    def test_unsafe_regex_is_rejected(self) -> None:
        with self.assertRaises(tv.ValidationError) as context:
            tv.parse_profile(self.minimal_profile({"regex": "(a+)+$"}))
        self.assertEqual(context.exception.code, "unsafe_regex")

    def test_ambiguous_optional_regex_is_rejected(self) -> None:
        with self.assertRaises(tv.ValidationError) as context:
            tv.parse_profile(self.minimal_profile({"regex": "a?a?a?a?a?a?z"}))
        self.assertEqual(context.exception.code, "unsafe_regex")

    def test_multiple_bounded_quantifiers_are_rejected(self) -> None:
        with self.assertRaises(tv.ValidationError) as context:
            tv.parse_profile(self.minimal_profile({"regex": "a{0,64}a{0,64}z"}))
        self.assertEqual(context.exception.code, "unsafe_regex")

    def test_safe_bounded_regex_matches(self) -> None:
        profile = tv.parse_profile(self.minimal_profile({"regex": "^tool[0-9]{1,3}\\.exe$"}))
        event = tv._parse_event(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "provider": "Fixture",
                "event_id": 1,
                "channel": "Fixture",
                "data": {"Image": "Tool42.exe", "Password": "not-reported"},
            },
            1,
        )
        results = tv.evaluate(profile, [event], False)
        self.assertEqual(results[0]["status"], "observed")
        self.assertEqual(results[0]["evidence"], [{"event_index": 1, "timestamp": "2026-01-01T00:00:00Z"}])

    def test_window_requires_minimum_inside_same_interval(self) -> None:
        raw = self.minimal_profile({"equals": "fixture.exe"})
        raw["signals"][0]["min_count"] = 2
        raw["signals"][0]["window"] = {"seconds": 60}
        profile = tv.parse_profile(raw)
        events = [
            tv._parse_event(
                {
                    "timestamp": timestamp,
                    "provider": "Fixture",
                    "event_id": 1,
                    "channel": "Fixture",
                    "data": {"Image": "fixture.exe"},
                },
                index,
            )
            for index, timestamp in enumerate(
                ["2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z"], start=1
            )
        ]
        result = tv.evaluate(profile, events, False)[0]
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["matched_event_count"], 2)
        self.assertEqual(result["qualifying_event_count"], 1)

    def test_duplicate_json_keys_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            path.write_text(
                '{"timestamp":"2026-01-01T00:00:00Z","provider":"A","provider":"B",'
                '"event_id":1,"channel":"C","data":{}}\n',
                encoding="utf-8",
            )
            events, issues, count = tv.load_events(path)
            self.assertEqual(count, 1)
            self.assertEqual(events, [])
            self.assertEqual(issues[0].code, "event_json")

    def test_non_finite_json_number_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            path.write_text(
                '{"timestamp":"2026-01-01T00:00:00Z","provider":"A",'
                '"event_id":1,"channel":"C","data":{"score":NaN}}\n',
                encoding="utf-8",
            )
            events, issues, count = tv.load_events(path)
            self.assertEqual(count, 1)
            self.assertEqual(events, [])
            self.assertEqual(issues[0].code, "event_json")

    def test_casefold_colliding_event_keys_are_rejected_in_any_order(self) -> None:
        for data in (
            {"Image": "no", "image": "yes"},
            {"image": "yes", "Image": "no"},
            {"nested": {"Token": "a", "token": "b"}},
        ):
            with self.subTest(data=data), self.assertRaises(tv.ValidationError) as context:
                tv._parse_event(
                    {
                        "timestamp": "2026-01-01T00:00:00Z",
                        "provider": "Fixture",
                        "event_id": 1,
                        "channel": "Fixture",
                        "data": data,
                    },
                    1,
                )
            self.assertEqual(context.exception.code, "event_schema")

    def test_profile_titles_cannot_activate_remote_markdown(self) -> None:
        raw = self.minimal_profile({"equals": "fixture.exe"})
        raw["title"] = "![remote](https://example.test/profile-pixel)"
        raw["signals"][0]["title"] = "<img src=https://example.test/signal-pixel>"
        profile = tv.parse_profile(raw)
        report = tv.build_report(profile, tv.evaluate(profile, [], False), [], 0, 0)
        markdown = tv.markdown_report(report)
        self.assertNotIn("![remote](", markdown)
        self.assertNotIn("### <img", markdown)
        self.assertIn(r"\!\[remote\]", markdown)
        self.assertIn(r"### \<img", markdown)

    def test_event_record_and_line_limits_fail_closed(self) -> None:
        event = (
            '{"timestamp":"2026-01-01T00:00:00Z","provider":"A",'
            '"event_id":1,"channel":"C","data":{}}\n'
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            path.write_text(event * 2, encoding="utf-8")
            original_records = tv.MAX_EVENT_RECORDS
            try:
                tv.MAX_EVENT_RECORDS = 1
                with self.assertRaises(tv.ValidationError) as context:
                    tv.load_events(path)
                self.assertEqual(context.exception.code, "event_limit")
            finally:
                tv.MAX_EVENT_RECORDS = original_records

            original_line = tv.MAX_JSONL_LINE_BYTES
            try:
                tv.MAX_JSONL_LINE_BYTES = 32
                with self.assertRaises(tv.ValidationError) as context:
                    tv.load_events(path)
                self.assertEqual(context.exception.code, "event_limit")
            finally:
                tv.MAX_JSONL_LINE_BYTES = original_line

    def test_evaluation_budget_is_enforced(self) -> None:
        profile = tv.parse_profile(self.minimal_profile({"equals": "fixture.exe"}))
        event = tv._parse_event(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "provider": "Fixture",
                "event_id": 1,
                "channel": "Fixture",
                "data": {"Image": "fixture.exe"},
            },
            1,
        )
        original = tv.MAX_EVALUATION_STEPS
        try:
            tv.MAX_EVALUATION_STEPS = 0
            with self.assertRaises(tv.ValidationError) as context:
                tv.evaluate(profile, [event], False)
            self.assertEqual(context.exception.code, "evaluation_limit")
        finally:
            tv.MAX_EVALUATION_STEPS = original

    def test_evaluation_budget_counts_casefold_mapping_walks(self) -> None:
        profile = tv.parse_profile(self.minimal_profile({"equals": "fixture.exe"}))
        data = {f"unrelated_{index}": "x" for index in range(200)}
        data["image"] = "fixture.exe"
        event = tv._parse_event(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "provider": "Fixture",
                "event_id": 1,
                "channel": "Fixture",
                "data": data,
            },
            1,
        )
        original = tv.MAX_EVALUATION_STEPS
        try:
            tv.MAX_EVALUATION_STEPS = 50
            with self.assertRaises(tv.ValidationError) as context:
                tv.evaluate(profile, [event], False)
            self.assertEqual(context.exception.code, "evaluation_limit")
        finally:
            tv.MAX_EVALUATION_STEPS = original


if __name__ == "__main__":
    unittest.main()
