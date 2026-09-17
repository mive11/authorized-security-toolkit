from __future__ import annotations

import datetime as dt
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_DIR))

import scopeguard  # noqa: E402


NOW = dt.datetime(2026, 9, 17, 12, 0, 0, tzinfo=dt.timezone.utc)


def policy_document() -> dict:
    return {
        "schema_version": 1,
        "engagement_id": "ENG-TEST-001",
        "expires_at": "2030-01-01T00:00:00Z",
        "allow": {
            "domains": ["example.com", "*.example.com", "bücher.example"],
            "cidrs": ["192.0.2.0/24", "2001:db8::/32"],
            "ports": [80, 443, "8000-8010"],
        },
        "deny": {
            "domains": ["admin.example.com", "*.blocked.example.com"],
            "cidrs": ["192.0.2.240/28", "2001:db8:ffff::/48"],
            "ports": [8005],
        },
    }


class TempPolicyMixin:
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.policy_path = self.root / "policy.json"
        self.write_policy(policy_document())

    def write_policy(self, document: dict) -> None:
        self.policy_path.write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8"
        )

    def load(self) -> scopeguard.Policy:
        return scopeguard.load_policy(self.policy_path, now=NOW)


class PolicyTests(TempPolicyMixin, unittest.TestCase):
    def test_loads_strict_policy_and_normalizes_idna(self) -> None:
        policy = self.load()
        self.assertEqual(policy.engagement_id, "ENG-TEST-001")
        self.assertIn("xn--bcher-kva.example", [rule.text for rule in policy.allow_domains])
        self.assertEqual(policy.expires_at_text, "2030-01-01T00:00:00Z")
        self.assertEqual(len(policy.sha256), 64)

    def test_expired_policy_is_rejected(self) -> None:
        document = policy_document()
        document["expires_at"] = "2026-09-17T11:59:59Z"
        self.write_policy(document)
        with self.assertRaisesRegex(scopeguard.PolicyError, "expired"):
            self.load()

    def test_expiry_must_be_explicit_utc(self) -> None:
        document = policy_document()
        document["expires_at"] = "2030-01-01T01:00:00+01:00"
        self.write_policy(document)
        with self.assertRaisesRegex(scopeguard.PolicyError, "ending in 'Z'"):
            self.load()

    def test_unknown_policy_key_is_rejected(self) -> None:
        document = policy_document()
        document["surprise"] = True
        self.write_policy(document)
        with self.assertRaisesRegex(scopeguard.PolicyError, "unknown keys"):
            self.load()

    def test_duplicate_json_key_is_rejected(self) -> None:
        self.policy_path.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        with self.assertRaisesRegex(scopeguard.PolicyError, "duplicate JSON key"):
            self.load()

    def test_noncanonical_cidr_is_rejected(self) -> None:
        document = policy_document()
        document["allow"]["cidrs"] = ["192.0.2.7/24"]
        self.write_policy(document)
        with self.assertRaisesRegex(scopeguard.PolicyError, "non-canonical CIDR"):
            self.load()

    def test_bad_port_ranges_and_booleans_are_rejected(self) -> None:
        for invalid in (["080-443"], [True], ["9000-8000"], [0], [65536]):
            with self.subTest(invalid=invalid):
                document = policy_document()
                document["allow"]["ports"] = invalid
                self.write_policy(document)
                with self.assertRaises(scopeguard.PolicyError):
                    self.load()

    def test_policy_needs_an_allowed_host_scope(self) -> None:
        document = policy_document()
        document["allow"]["domains"] = []
        document["allow"]["cidrs"] = []
        self.write_policy(document)
        with self.assertRaisesRegex(scopeguard.PolicyError, "at least one"):
            self.load()

    def test_legacy_ip_spelling_is_not_a_domain_rule(self) -> None:
        document = policy_document()
        document["allow"]["domains"] = ["127.1"]
        self.write_policy(document)
        with self.assertRaisesRegex(scopeguard.PolicyError, "canonical CIDR"):
            self.load()

    def test_port_entry_count_is_bounded(self) -> None:
        document = policy_document()
        document["allow"]["ports"] = [
            1 for _ in range(scopeguard.MAX_PORT_RULE_ENTRIES + 1)
        ]
        self.write_policy(document)
        with self.assertRaisesRegex(scopeguard.PolicyError, "exceeds the limit"):
            self.load()

    def test_domain_and_cidr_rule_counts_are_bounded(self) -> None:
        for section, key, value, limit in (
            ("allow", "domains", "example.com", scopeguard.MAX_DOMAIN_RULES),
            ("allow", "cidrs", "192.0.2.0/24", scopeguard.MAX_CIDR_RULES),
        ):
            with self.subTest(key=key):
                document = policy_document()
                document[section][key] = [value] * (limit + 1)
                self.write_policy(document)
                with self.assertRaisesRegex(scopeguard.PolicyError, "exceeds the limit"):
                    self.load()

    def test_large_and_repeated_port_ranges_remain_compact(self) -> None:
        document = policy_document()
        document["allow"]["ports"] = ["1-65535", "1-65535", "80-443", 443]
        self.write_policy(document)
        policy = self.load()
        self.assertEqual(policy.allow_ports.ranges, ((1, 65535),))
        self.assertIn(1, policy.allow_ports)
        self.assertIn(65535, policy.allow_ports)

    def test_policy_read_is_bounded(self) -> None:
        with self.policy_path.open("wb") as stream:
            stream.truncate(scopeguard.MAX_POLICY_BYTES + 1)
        with self.assertRaisesRegex(scopeguard.PolicyError, "policy exceeds"):
            self.load()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO fixture unavailable")
    def test_policy_fifo_is_rejected_without_blocking(self) -> None:
        fifo = self.root / "policy.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(scopeguard.PolicyError, "regular file"):
            scopeguard.load_policy(fifo, now=NOW)


class TargetParsingTests(unittest.TestCase):
    def test_domain_is_casefolded_and_idna_normalized(self) -> None:
        self.assertEqual(scopeguard.parse_target("EXAMPLE.COM.").normalized, "example.com")
        self.assertEqual(
            scopeguard.parse_target("BÜCHER.example").normalized,
            "xn--bcher-kva.example",
        )

    def test_ipv4_and_ipv6_are_canonicalized_without_dns(self) -> None:
        ipv4 = scopeguard.parse_target("192.0.2.9")
        ipv6 = scopeguard.parse_target("2001:0db8:0:0::1")
        self.assertEqual((ipv4.kind, ipv4.normalized), ("ip", "192.0.2.9"))
        self.assertEqual((ipv6.kind, ipv6.normalized), ("ip", "2001:db8::1"))

    def test_url_normalizes_host_scheme_and_default_port(self) -> None:
        target = scopeguard.parse_target("HTTPS://EXAMPLE.COM:443/a?q=1")
        self.assertEqual(target.normalized, "https://example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.host, "example.com")

    def test_ipv6_url_requires_brackets_and_is_normalized(self) -> None:
        target = scopeguard.parse_target("https://[2001:0db8::1]:8443/x")
        self.assertEqual(target.normalized, "https://[2001:db8::1]:8443")
        self.assertEqual(target.port, 8443)
        with self.assertRaises(scopeguard.CandidateError):
            scopeguard.parse_target("https://2001:db8::1/x")

    def test_rejects_unicode_spelling_that_changes_during_idna_roundtrip(self) -> None:
        with self.assertRaises(scopeguard.CandidateError) as caught:
            scopeguard.parse_target("faß.example")
        self.assertEqual(caught.exception.reason_code, "invalid_domain")

    def test_rejects_ambiguous_or_hostile_targets(self) -> None:
        cases = {
            "example.com:443": "ambiguous_target",
            "http://user@example.com/": "userinfo_not_allowed",
            "http://example.com/#": "fragment_not_allowed",
            "http://example.com\\@evil.test/": "ambiguous_target",
            "http://example.com:": "invalid_port",
            "http://example.com:99999": "invalid_port",
            "http://example.com/a b": "whitespace_or_control",
            "http://example.com/\x00": "whitespace_or_control",
            "ftp://example.com/": "unsupported_scheme",
            "010.000.000.001": "malformed_ip_literal",
            "127.1": "malformed_ip_literal",
            "2130706433": "malformed_ip_literal",
            "0x7f000001": "malformed_ip_literal",
            "0x7f.0.0.1": "malformed_ip_literal",
            "fe80::1%eth0": "zone_id_not_allowed",
        }
        for raw, reason in cases.items():
            with self.subTest(raw=raw):
                with self.assertRaises(scopeguard.CandidateError) as caught:
                    scopeguard.parse_target(raw)
                self.assertEqual(caught.exception.reason_code, reason)

    def test_rejects_domain_wildcards_and_invalid_labels(self) -> None:
        for raw in ("*.example.com", "bad_label.example", "-bad.example"):
            with self.subTest(raw=raw):
                with self.assertRaises(scopeguard.CandidateError):
                    scopeguard.parse_target(raw)


class DecisionTests(TempPolicyMixin, unittest.TestCase):
    def decision(self, raw: str) -> dict:
        return scopeguard.decide(self.load(), scopeguard.parse_target(raw))

    def test_policy_target_comparison_budget_is_enforced(self) -> None:
        with mock.patch.object(scopeguard, "MAX_SCOPE_COMPARISONS", 0):
            with self.assertRaisesRegex(scopeguard.InputError, "comparison budget"):
                scopeguard.evaluate(self.load(), ["example.com"], now=NOW)

    def test_exact_and_wildcard_domain_boundaries(self) -> None:
        self.assertTrue(self.decision("example.com")["allowed"])
        self.assertTrue(self.decision("api.example.com")["allowed"])
        for target in ("notexample.com", "example.com.attacker.test"):
            with self.subTest(target=target):
                decision = self.decision(target)
                self.assertFalse(decision["allowed"])
                self.assertEqual(decision["reason_code"], "domain_not_allowed")

    def test_exact_rule_does_not_implicitly_authorize_children(self) -> None:
        document = policy_document()
        document["allow"]["domains"] = ["example.com"]
        self.write_policy(document)
        self.assertTrue(self.decision("example.com")["allowed"])
        self.assertFalse(self.decision("api.example.com")["allowed"])

    def test_domain_deny_wins_over_wildcard_allow(self) -> None:
        decision = self.decision("admin.example.com")
        self.assertEqual(decision["reason_code"], "denied_domain")
        self.assertEqual(decision["matched_rule"], "admin.example.com")

        nested = self.decision("x.blocked.example.com")
        self.assertEqual(nested["reason_code"], "denied_domain")

    def test_overlapping_ipv4_and_ipv6_denies_win(self) -> None:
        allowed = self.decision("192.0.2.20")
        denied = self.decision("192.0.2.250")
        denied_v6 = self.decision("2001:db8:ffff::1")
        self.assertTrue(allowed["allowed"])
        self.assertEqual(denied["reason_code"], "denied_cidr")
        self.assertEqual(denied_v6["reason_code"], "denied_cidr")

    def test_url_effective_ports_are_checked(self) -> None:
        self.assertTrue(self.decision("http://api.example.com")["allowed"])
        self.assertTrue(self.decision("https://api.example.com")["allowed"])
        self.assertEqual(
            self.decision("https://api.example.com:8443")["reason_code"],
            "port_not_allowed",
        )
        self.assertEqual(
            self.decision("https://api.example.com:8005")["reason_code"],
            "denied_port",
        )

    def test_denied_port_wins_even_when_host_is_not_allowed(self) -> None:
        decision = self.decision("https://outside.test:8005")
        self.assertEqual(decision["reason_code"], "denied_port")

    def test_bare_host_has_no_port_decision(self) -> None:
        decision = self.decision("api.example.com")
        self.assertTrue(decision["allowed"])
        self.assertIsNone(decision["port"])


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.audit_path = self.root / "audit.jsonl"

    def test_creates_private_log_and_chains_records(self) -> None:
        first = scopeguard.append_audit(self.audit_path, {"run": 1})
        second = scopeguard.append_audit(self.audit_path, {"run": 2})
        mode = stat.S_IMODE(self.audit_path.stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(second["previous_hash"], first["entry_hash"])

        data = self.audit_path.read_bytes()
        self.assertEqual(scopeguard._verify_audit(data), (2, second["entry_hash"]))

    def test_detects_tampered_event_before_append(self) -> None:
        scopeguard.append_audit(self.audit_path, {"allowed": True})
        record = json.loads(self.audit_path.read_text(encoding="utf-8"))
        record["event"]["allowed"] = False
        self.audit_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        os.chmod(self.audit_path, 0o600)
        with self.assertRaisesRegex(scopeguard.AuditError, "hash mismatch"):
            scopeguard.append_audit(self.audit_path, {"next": True})

    def test_rejects_truncated_or_public_existing_log(self) -> None:
        self.audit_path.write_text("{}", encoding="utf-8")
        os.chmod(self.audit_path, 0o600)
        with self.assertRaisesRegex(scopeguard.AuditError, "final newline"):
            scopeguard.append_audit(self.audit_path, {"next": True})

        self.audit_path.write_text("", encoding="utf-8")
        os.chmod(self.audit_path, 0o644)
        with self.assertRaisesRegex(scopeguard.AuditError, "group or other"):
            scopeguard.append_audit(self.audit_path, {"next": True})

    def test_rejects_nonfinite_constants_in_existing_log(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                data = (
                    '{"sequence":1,"previous_hash":"'
                    + scopeguard.GENESIS_HASH
                    + '","event":{"value":'
                    + constant
                    + '},"entry_hash":"'
                    + ("0" * 64)
                    + '"}\n'
                ).encode("utf-8")
                with self.assertRaisesRegex(scopeguard.AuditError, "invalid audit JSON"):
                    scopeguard._verify_audit(data)

    def test_rejects_duplicate_keys_in_existing_log(self) -> None:
        data = (
            '{"sequence":1,"sequence":1,"previous_hash":"'
            + scopeguard.GENESIS_HASH
            + '","event":{},"entry_hash":"'
            + ("0" * 64)
            + '"}\n'
        ).encode("utf-8")
        with self.assertRaisesRegex(scopeguard.AuditError, "invalid audit JSON"):
            scopeguard._verify_audit(data)

    def test_rejects_noncanonicalizable_new_event_as_audit_error(self) -> None:
        with self.assertRaisesRegex(scopeguard.AuditError, "cannot be canonicalized"):
            scopeguard.append_audit(self.audit_path, {"value": float("nan")})

    def test_audit_read_is_bounded(self) -> None:
        with self.audit_path.open("wb") as stream:
            stream.truncate(scopeguard.MAX_AUDIT_BYTES + 1)
        os.chmod(self.audit_path, 0o600)
        with self.assertRaisesRegex(scopeguard.AuditError, "audit log exceeds"):
            scopeguard.append_audit(self.audit_path, {"next": True})

    def test_append_cannot_push_audit_past_limit(self) -> None:
        with mock.patch.object(scopeguard, "MAX_AUDIT_BYTES", 256):
            with self.assertRaisesRegex(scopeguard.AuditError, "append would exceed"):
                scopeguard.append_audit(self.audit_path, {"large": "x" * 512})
        self.assertEqual(self.audit_path.read_bytes(), b"")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_rejects_symlink_audit_path(self) -> None:
        real = self.root / "real.jsonl"
        real.write_text("", encoding="utf-8")
        os.chmod(real, 0o600)
        link = self.root / "link.jsonl"
        link.symlink_to(real)
        with self.assertRaisesRegex(scopeguard.AuditError, "securely open"):
            scopeguard.append_audit(link, {"next": True})


class CliTests(TempPolicyMixin, unittest.TestCase):
    def run_cli(self, *args: str, stdin_text: str = "") -> tuple[int, dict]:
        output = io.StringIO()
        code = scopeguard.main(
            list(args),
            stdin=io.StringIO(stdin_text),
            stdout=output,
            stderr=io.StringIO(),
            now=NOW,
        )
        return code, json.loads(output.getvalue())

    def test_all_allowed_returns_zero(self) -> None:
        code, result = self.run_cli(
            "--policy", str(self.policy_path), "example.com", "192.0.2.9"
        )
        self.assertEqual(code, scopeguard.EXIT_ALLOWED)
        self.assertTrue(result["all_allowed"])
        self.assertEqual(result["summary"]["allowed"], 2)

    def test_denied_returns_three(self) -> None:
        code, result = self.run_cli(
            "--policy", str(self.policy_path), "admin.example.com"
        )
        self.assertEqual(code, scopeguard.EXIT_DENIED)
        self.assertEqual(result["decisions"][0]["status"], "denied")

    def test_invalid_takes_exit_precedence_over_denied(self) -> None:
        code, result = self.run_cli(
            "--policy",
            str(self.policy_path),
            "outside.test",
            "example.com:443",
        )
        self.assertEqual(code, scopeguard.EXIT_INVALID)
        self.assertEqual(result["summary"], {"total": 2, "allowed": 0, "denied": 1, "invalid": 1})

    def test_combines_cli_and_newline_file_inputs(self) -> None:
        target_file = self.root / "targets.txt"
        target_file.write_text("\napi.example.com\r\n192.0.2.10\n", encoding="utf-8")
        code, result = self.run_cli(
            "--policy",
            str(self.policy_path),
            "--input-file",
            str(target_file),
            "example.com",
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["summary"]["total"], 3)

    def test_oversized_target_file_line_fails_closed(self) -> None:
        target_file = self.root / "oversized-target.txt"
        target_file.write_text("a" * (scopeguard.MAX_TARGET_LENGTH + 10), encoding="utf-8")
        code, result = self.run_cli(
            "--policy",
            str(self.policy_path),
            "--input-file",
            str(target_file),
        )
        self.assertEqual(code, scopeguard.EXIT_INVALID)
        self.assertEqual(result["error"]["code"], "invalid_input")

    @unittest.skipUnless(Path("/dev/zero").exists(), "POSIX device fixture unavailable")
    def test_nonregular_target_input_is_rejected_without_reading(self) -> None:
        code, result = self.run_cli(
            "--policy",
            str(self.policy_path),
            "--input-file",
            "/dev/zero",
        )
        self.assertEqual(code, scopeguard.EXIT_INVALID)
        self.assertEqual(result["error"]["code"], "invalid_input")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO fixture unavailable")
    def test_target_fifo_is_rejected_without_blocking(self) -> None:
        fifo = self.root / "targets.fifo"
        os.mkfifo(fifo)
        code, result = self.run_cli(
            "--policy",
            str(self.policy_path),
            "--input-file",
            str(fifo),
        )
        self.assertEqual(code, scopeguard.EXIT_INVALID)
        self.assertEqual(result["error"]["code"], "invalid_input")

    def test_reads_stdin_and_appends_audit(self) -> None:
        audit = self.root / "run.jsonl"
        code, result = self.run_cli(
            "--policy",
            str(self.policy_path),
            "--input-file",
            "-",
            "--audit-log",
            str(audit),
            stdin_text="https://example.com\n",
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["audit"]["status"], "appended")
        self.assertEqual(result["audit"]["sequence"], 1)

    def test_policy_error_and_missing_targets_are_json_exit_two(self) -> None:
        code, result = self.run_cli("--policy", str(self.policy_path))
        self.assertEqual(code, 2)
        self.assertEqual(result["error"]["code"], "invalid_input")

        code, result = self.run_cli("example.com")
        self.assertEqual(code, 2)
        self.assertEqual(result["error"]["code"], "usage_error")

    def test_audit_integrity_failure_changes_exit_to_two(self) -> None:
        audit = self.root / "audit.jsonl"
        audit.write_text("not-json\n", encoding="utf-8")
        os.chmod(audit, 0o600)
        code, result = self.run_cli(
            "--policy",
            str(self.policy_path),
            "--audit-log",
            str(audit),
            "example.com",
        )
        self.assertEqual(code, 2)
        self.assertEqual(result["audit"]["status"], "error")

    def test_nonfinite_audit_record_returns_json_exit_two_without_traceback(self) -> None:
        audit = self.root / "nonfinite.jsonl"
        audit.write_text(
            '{"sequence":1,"previous_hash":"'
            + scopeguard.GENESIS_HASH
            + '","event":{"value":NaN},"entry_hash":"'
            + ("0" * 64)
            + '"}\n',
            encoding="utf-8",
        )
        os.chmod(audit, 0o600)
        output = io.StringIO()
        code = scopeguard.main(
            [
                "--policy",
                str(self.policy_path),
                "--audit-log",
                str(audit),
                "example.com",
            ],
            stdin=io.StringIO(),
            stdout=output,
            stderr=io.StringIO(),
            now=NOW,
        )
        self.assertEqual(code, scopeguard.EXIT_INVALID)
        self.assertNotIn("Traceback", output.getvalue())
        result = json.loads(output.getvalue(), parse_constant=lambda value: self.fail(value))
        self.assertEqual(result["audit"]["status"], "error")
        self.assertEqual(result["audit"]["code"], "audit_error")

    def test_raw_secrets_never_appear_in_output_or_audit(self) -> None:
        audit = self.root / "private-audit.jsonl"
        secrets = [
            "USERINFOLEAK",
            "PASSWORDLEAK",
            "PATHLEAK",
            "QUERYLEAK",
            "INVALIDLEAK",
        ]
        candidates = [
            "https://example.com/PATHLEAK?token=QUERYLEAK",
            "https://USERINFOLEAK:PASSWORDLEAK@example.com/",
            "INVALIDLEAK_.example",
        ]
        output = io.StringIO()
        code = scopeguard.main(
            [
                "--policy",
                str(self.policy_path),
                "--audit-log",
                str(audit),
                *candidates,
            ],
            stdin=io.StringIO(),
            stdout=output,
            stderr=io.StringIO(),
            now=NOW,
        )
        self.assertEqual(code, scopeguard.EXIT_INVALID)
        output_text = output.getvalue()
        audit_text = audit.read_text(encoding="utf-8")
        for secret in secrets:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, output_text)
                self.assertNotIn(secret, audit_text)

        result = json.loads(output_text)
        self.assertEqual(result["decisions"][0]["normalized"], "https://example.com")
        for index, decision in enumerate(result["decisions"], start=1):
            self.assertEqual(decision["candidate_index"], index)
            self.assertEqual(len(decision["input_sha256"]), 64)
            self.assertNotIn("input", decision)


if __name__ == "__main__":
    unittest.main()
