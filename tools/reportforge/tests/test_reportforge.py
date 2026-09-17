from __future__ import annotations

import copy
import contextlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest


TOOL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIR))

import reportforge  # noqa: E402


def sample_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "engagement": {
            "id": "ENG-2026-001",
            "name": "Authorized Control Validation",
            "client": "Example Organization",
            "assessment_type": "Red team control validation",
            "start_date": "2026-08-03",
            "end_date": "2026-08-07",
            "report_date": "2026-08-10",
            "classification": "confidential",
            "scope": ["tenant.example.test"],
            "authors": ["Assessment Team"],
        },
        "findings": [
            {
                "id": "FIND-002",
                "title": "Alert routing needs validation",
                "severity": "medium",
                "status": "in_progress",
                "asset": "test tenant",
                "description": "An approved test change did not produce the expected central alert.",
                "evidence": ["Change CR-TEST-1042 was present in the supplied audit export."],
                "remediation": "Route the alert to the monitored queue and repeat the approved test case.",
                "references": ["https://attack.mitre.org/techniques/T1098/"],
                "attack_techniques": ["T1098"],
                "cves": [],
            },
            {
                "id": "FIND-001",
                "title": "Privileged MFA policy needs strengthening",
                "severity": "high",
                "status": "open",
                "asset": "tenant.example.test",
                "description": "An approved test account could use a weaker authentication factor.",
                "evidence": ["Approved account admin-review-01 used a legacy factor."],
                "remediation": "Require phishing-resistant MFA for privileged roles.",
                "references": ["https://attack.mitre.org/techniques/T1078/"],
                "attack_techniques": ["T1078"],
            },
        ],
    }


def validated(document: dict[str, object] | None = None) -> dict[str, object]:
    return reportforge.sanitize_document(
        reportforge.validate_document(copy.deepcopy(document or sample_document()))
    )


class ReportForgeTests(unittest.TestCase):
    def test_outputs_are_deterministic_and_private(self) -> None:
        data = validated()
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            first_paths = reportforge.write_reports(data, first)
            second_paths = reportforge.write_reports(data, second)
            self.assertEqual(first_paths[0].read_bytes(), second_paths[0].read_bytes())
            self.assertEqual(first_paths[1].read_bytes(), second_paths[1].read_bytes())
            for path in first_paths + second_paths:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_executive_summary_has_complete_severity_counts(self) -> None:
        markdown = reportforge.build_markdown(validated())
        self.assertIn("| Critical | 0 |", markdown)
        self.assertIn("| High | 1 |", markdown)
        self.assertIn("| Medium | 1 |", markdown)
        self.assertIn("| Low | 0 |", markdown)
        self.assertIn("| Informational | 0 |", markdown)
        self.assertIn("| **Total** | **2** |", markdown)
        self.assertLess(markdown.index("FIND-001"), markdown.index("FIND-002"))

    def test_sarif_21_shape_and_stable_rule_links(self) -> None:
        sarif = reportforge.build_sarif(validated())
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", sarif["$schema"])
        self.assertEqual(len(sarif["runs"]), 1)
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ReportForge")
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]
        self.assertEqual([rule["id"] for rule in rules], ["FIND-001", "FIND-002"])
        self.assertEqual([result["ruleIndex"] for result in results], [0, 1])
        self.assertEqual([result["ruleId"] for result in results], ["FIND-001", "FIND-002"])
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(len(results[0]["partialFingerprints"]["reportforge/v1"]), 64)

    def test_secrets_are_redacted_and_evidence_paths_are_never_read(self) -> None:
        document = sample_document()
        with tempfile.TemporaryDirectory() as temporary:
            local_evidence = Path(temporary) / "private-evidence.txt"
            local_evidence.write_text("LOCAL-CONTENT-MUST-NOT-APPEAR", encoding="utf-8")
            finding = document["findings"][0]
            finding["evidence"] = [
                "Authorization: Bearer auth-secret",
                "Cookie: session=cookie-secret",
                "password=hunter2",
                "request=https://example.test/a?token=query-secret&mode=review",
                "api_key=api-secret",
                "response body: {\"access_token\":\"json-secret\"}",
                "request=https://reviewer:embedded-password@example.test/status",
                "Bearer standalone-secret-value",
                str(local_evidence),
            ]
            data = validated(document)
            markdown = reportforge.build_markdown(data)
            sarif_text = reportforge.serialize_sarif(data)
            combined = markdown + sarif_text
            for secret in (
                "auth-secret",
                "cookie-secret",
                "hunter2",
                "query-secret",
                "api-secret",
                "json-secret",
                "embedded-password",
                "standalone-secret-value",
            ):
                self.assertNotIn(secret, combined)
            self.assertGreaterEqual(combined.count("REDACTED"), 8)
            self.assertIn(str(local_evidence), sarif_text)
            self.assertNotIn("LOCAL-CONTENT-MUST-NOT-APPEAR", combined)

    def test_multword_and_session_secrets_preserve_nonsecret_context(self) -> None:
        cases = {
            "Authorization: Bearer header-secret": "Authorization: [REDACTED]",
            "password=two words": "password=[REDACTED]",
            "client_secret=alpha beta; status=denied": "client_secret=[REDACTED]; status=denied",
            "sessionid=session value, response=401": "sessionid=[REDACTED], response=401",
            "session_token=one two state=expired": "session_token=[REDACTED] state=expired",
            "aws_secret_access_key=AWS-LEAK&code=OAUTH-CODE": (
                "aws_secret_access_key=[REDACTED]&code=[REDACTED]"
            ),
            "secret=standalone sensitive value": "secret=[REDACTED]",
            "request=https://example.test/callback?code=OAUTH&state=FIXTURE": (
                "request=https://example.test/callback?code=[REDACTED]&state=[REDACTED]"
            ),
            'client_secret="quoted value" result=blocked': (
                'client_secret="[REDACTED]" result=blocked'
            ),
            "password=two words. Authentication failed": (
                "password=[REDACTED]. Authentication failed"
            ),
            "note=ordinary text and the token bucket was exhausted": (
                "note=ordinary text and the token bucket was exhausted"
            ),
        }
        for evidence, expected in cases.items():
            with self.subTest(evidence=evidence):
                self.assertEqual(reportforge.scrub_secrets(evidence), expected)

    def test_path_traversal_symlinks_and_overwrite_are_rejected(self) -> None:
        data = validated()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(reportforge.ReportForgeError, "traversal"):
                reportforge.write_reports(data, root / "reports" / ".." / "escaped")

            output = root / "output"
            markdown_path, _ = reportforge.write_reports(data, output)
            original = markdown_path.read_bytes()
            with self.assertRaisesRegex(reportforge.ReportForgeError, "already exists"):
                reportforge.write_reports(data, output)
            self.assertEqual(markdown_path.read_bytes(), original)

            markdown_path.write_text("replacement marker", encoding="utf-8")
            reportforge.write_reports(data, output, force=True)
            self.assertNotIn("replacement marker", markdown_path.read_text(encoding="utf-8"))

            symlink_output = root / "linked-output"
            try:
                symlink_output.symlink_to(output, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaisesRegex(reportforge.ReportForgeError, "symlink"):
                reportforge.write_reports(data, symlink_output, force=True)

    def test_strict_schema_rejects_html_controls_unknowns_and_bad_identifiers(self) -> None:
        cases: list[dict[str, object]] = []
        html = sample_document()
        html["findings"][0]["description"] = "Unsafe <script>alert(1)</script>"
        cases.append(html)
        control = sample_document()
        control["findings"][0]["title"] = "Embedded\nline"
        cases.append(control)
        unknown = sample_document()
        unknown["findings"][0]["unexpected"] = "value"
        cases.append(unknown)
        bad_technique = sample_document()
        bad_technique["findings"][0]["attack_techniques"] = ["TA0001"]
        cases.append(bad_technique)
        bad_cve = sample_document()
        bad_cve["findings"][0]["cves"] = ["cve-2026-1234"]
        cases.append(bad_cve)
        duplicate_id = sample_document()
        duplicate_id["findings"][1]["id"] = "FIND-002"
        cases.append(duplicate_id)
        for case in cases:
            with self.subTest(case=cases.index(case)):
                with self.assertRaises(reportforge.ReportForgeError):
                    reportforge.validate_document(case)

    def test_loader_rejects_duplicate_keys_and_nonstandard_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
            with self.assertRaisesRegex(reportforge.ReportForgeError, "duplicate JSON key"):
                reportforge.load_input(path)
            path.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(reportforge.ReportForgeError, "non-standard JSON"):
                reportforge.load_input(path)

    def test_cli_returns_zero_for_success_and_two_for_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_path = root / "valid.json"
            invalid_path = root / "invalid.json"
            valid_path.write_text(json.dumps(sample_document()), encoding="utf-8")
            invalid_path.write_text('{"schema_version":"1.0"}', encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                success = reportforge.main(
                    [str(valid_path), "--output-dir", str(root / "valid-output")]
                )
                invalid = reportforge.main(
                    [str(invalid_path), "--output-dir", str(root / "invalid-output")]
                )
            self.assertEqual(success, 0)
            self.assertEqual(invalid, 2)
            self.assertIn("Wrote", stdout.getvalue())
            self.assertIn("reportforge: error:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
