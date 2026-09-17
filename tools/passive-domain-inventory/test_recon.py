"""Offline contract tests for the standalone passive inventory entrypoint.

Run with: python3 -m unittest discover -s recon-passive -p 'test_*.py' -v
Every test denies network access, including during module import.
"""

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit


SCRIPT = Path(__file__).with_name("recon.sh")


@contextmanager
def deny_network():
    with ExitStack() as stack:
        denied = []
        for operation in (
            "socket.getaddrinfo",
            "socket.create_connection",
            "socket.socket.connect",
            "socket.socket.connect_ex",
            "urllib.request.urlopen",
            "urllib.request.OpenerDirector.open",
        ):
            denied.append(stack.enter_context(
                patch(operation, side_effect=AssertionError("Network access forbidden in offline tests"))
            ))
        yield
        for operation in denied:
            operation.assert_not_called()


def load_embedded_module():
    source = SCRIPT.read_text(encoding="utf-8")
    embedded = source.split("<<'PY_RECON'\n", 1)[1].rsplit("\nPY_RECON", 1)[0]
    module = types.ModuleType("recon_passive_under_test")
    module.__file__ = str(SCRIPT)
    sys.modules[module.__name__] = module
    with deny_network():
        exec(compile(embedded, str(SCRIPT), "exec"), module.__dict__)
    return module


class PassiveReconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recon = load_embedded_module()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="recon-passive-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        self.output = self.root / "output"
        self.write_default_fixtures()

    def write_json(self, name, data):
        (self.fixtures / name).write_text(json.dumps(data), encoding="utf-8")

    def write_default_fixtures(self):
        self.write_json(
            "crtsh-apex.json",
            [
                {
                    "id": 101,
                    "name_value": "example.com\nwww.example.com\n*.example.com\nevil-example.com\nexample.com.evil.test",
                    "not_before": "2026-01-01T00:00:00",
                    "not_after": "2026-04-01T00:00:00",
                },
                {
                    "id": 102,
                    "name_value": "*.wild.example.com\nsub.wild.example.com",
                    "not_before": "2026-01-02T00:00:00",
                    "not_after": "2026-04-02T00:00:00",
                },
            ],
        )
        self.write_json(
            "crtsh-subdomains.json",
            [{"id": 103, "name_value": "api.example.com\nEXAMPLE.COM.\n*.example.com"}],
        )
        self.write_json(
            "wayback.json",
            [
                ["original", "timestamp", "statuscode", "mimetype"],
                ["https://archive.example.com/manual?QUERY_SECRET_384=yes#FRAGMENT_SECRET_384", "20260101000000", "200", "text/html"],
                ["https://archive.example.com/reset/PATH_SECRET_384?token=QUERY_SECRET_384", "20260102000000", "200", "text/html"],
                ["https://USER_SECRET_384:PASS_SECRET_384@login.example.com/path", "20260103000000", "200", "text/html"],
                ["https://example.com.evil.test/outside", "20260104000000", "200", "text/html"],
            ],
        )
        self.write_json("commoncrawl-catalog.json", [{"id": "CC-MAIN-2026-01"}])
        records = [
            {"url": "https://crawl.example.com/docs?key=CRAWL_SECRET_384", "timestamp": "20260105000000", "status": "200", "mime": "text/html"},
            {"url": "https://evil-example.com/outside", "timestamp": "20260106000000", "status": "200", "mime": "text/html"},
        ]
        (self.fixtures / "commoncrawl-0.jsonl").write_text(
            "\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8"
        )
        self.write_json(
            "rdap-bootstrap.json",
            {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]},
        )
        self.write_json(
            "rdap.json",
            {
                "objectClassName": "domain",
                "ldhName": "EXAMPLE.COM",
                "status": ["active"],
                "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
                "nameservers": [{"ldhName": "ns1.example.com"}],
                "entities": [{"handle": "CONTACT_SECRET_384", "vcardArray": ["vcard", [["email", {}, "text", "PERSON_SECRET_384@example.com"]]]}],
                "remarks": [{"description": ["REMARK_SECRET_384"]}],
            },
        )

    def invoke(self, *extra, target="example.com"):
        argv = [target, "--offline", str(self.fixtures), "--output", str(self.output), *extra]
        stdout, stderr = io.StringIO(), io.StringIO()
        with deny_network(), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = self.recon.main(argv)
            except SystemExit as exception:
                code = exception.code
        return code, stdout.getvalue(), stderr.getvalue()

    def reports(self):
        return sorted(self.output.rglob("report.json")) if self.output.exists() else []

    def only_report(self):
        reports = self.reports()
        self.assertEqual(len(reports), 1)
        return reports[0], json.loads(reports[0].read_text(encoding="utf-8"))

    def test_domain_normalization_and_scope_boundary(self):
        self.assertEqual(self.recon.normalize_domain("EXAMPLE.COM."), "example.com")
        for valid in ("example.com", "www.example.com", "deep.www.example.com"):
            with self.subTest(valid=valid):
                self.assertTrue(self.recon.in_scope(valid, "example.com"))
        for invalid in ("evil-example.com", "example.com.evil.test", "examplecom", "com"):
            with self.subTest(invalid=invalid):
                self.assertFalse(self.recon.in_scope(invalid, "example.com"))

    def test_invalid_domains_are_rejected(self):
        invalid = (
            "", "https://example.com", "example.com/path", "../example.com",
            "a..example.com", "example.com:443", "user@example.com",
            "-bad.example.com", "bad-.example.com", "127.0.0.1",
            "exam\nple.com", "foo.*.example.com", "a" * 64 + ".com",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.recon.normalize_domain(value)

    def test_idna_preserves_identity_or_requires_explicit_punycode(self):
        self.assertEqual(self.recon.normalize_domain("bücher.de"), "xn--bcher-kva.de")
        self.assertEqual(self.recon.normalize_domain("xn--bcher-kva.de"), "xn--bcher-kva.de")
        self.assertEqual(self.recon.normalize_domain("xn--fa-hia.de"), "xn--fa-hia.de")
        with self.assertRaises(ValueError):
            self.recon.normalize_domain("faß.de")
        with self.assertRaises(ValueError):
            self.recon.normalize_domain("xn--a.com")

    def test_offline_inventory_is_scoped_and_keeps_wildcards_separate(self):
        code, stdout, stderr = self.invoke()
        self.assertEqual(code, 0, stdout + stderr)
        path, report = self.only_report()
        self.assertEqual(report["target"], "example.com")
        names = [host["name"] for host in report["hosts"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({"example.com", "www.example.com", "api.example.com", "archive.example.com", "crawl.example.com"}.issubset(names))
        self.assertTrue(all(self.recon.in_scope(name, "example.com") for name in names))
        self.assertTrue(all("*" not in name for name in names))
        self.assertNotIn("wild.example.com", names)
        wildcards = [host["name"] for host in report["wildcards"]]
        self.assertEqual(set(wildcards), {"*.example.com", "*.wild.example.com"})
        self.assertEqual(len(wildcards), len(set(wildcards)))
        self.assertTrue((path.parent / "informe.md").is_file())
        self.assertTrue((path.parent / "subdominios_totales.txt").is_file())
        self.assertTrue((path.parent / "comodines.txt").is_file())

    def test_default_artifacts_omit_urls_paths_and_contact_secrets(self):
        code, stdout, stderr = self.invoke()
        self.assertEqual(code, 0, stdout + stderr)
        path, report = self.only_report()
        self.assertEqual(report["urls"], [])
        self.assertFalse((path.parent / "urls_historicas.txt").exists())
        contents = "\n".join(
            item.read_text(encoding="utf-8") for item in path.parent.rglob("*") if item.is_file()
        ) + stdout + stderr
        for secret in (
            "QUERY_SECRET_384", "FRAGMENT_SECRET_384", "PATH_SECRET_384",
            "USER_SECRET_384", "PASS_SECRET_384", "CRAWL_SECRET_384",
            "CONTACT_SECRET_384", "PERSON_SECRET_384", "REMARK_SECRET_384",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, contents)

    def test_explicit_path_export_removes_credentials_queries_and_fragments(self):
        code, stdout, stderr = self.invoke("--include-paths", "--sources", "wayback,commoncrawl")
        self.assertEqual(code, 0, stdout + stderr)
        path, report = self.only_report()
        urls = [entry["url"] for entry in report["urls"]]
        self.assertIn("https://archive.example.com/manual", urls)
        self.assertTrue((path.parent / "urls_historicas.txt").is_file())
        for url in urls:
            parsed = urlsplit(url)
            self.assertIsNone(parsed.username)
            self.assertIsNone(parsed.password)
            self.assertEqual(parsed.query, "")
            self.assertEqual(parsed.fragment, "")
            self.assertTrue(self.recon.in_scope(parsed.hostname, "example.com"))
        contents = "\n".join(
            item.read_text(encoding="utf-8") for item in path.parent.rglob("*") if item.is_file()
        )
        for secret in ("QUERY_SECRET_384", "FRAGMENT_SECRET_384", "USER_SECRET_384", "PASS_SECRET_384", "CRAWL_SECRET_384"):
            self.assertNotIn(secret, contents)

    def test_missing_fixture_fails_closed_and_retains_other_source_results(self):
        (self.fixtures / "wayback.json").unlink()
        code, stdout, stderr = self.invoke("--sources", "crtsh,wayback")
        self.assertEqual(code, 3, stdout + stderr)
        _, report = self.only_report()
        sources = {source["name"]: source for source in report["sources"]}
        self.assertEqual(sources["crtsh"]["status"], "ok")
        self.assertEqual(sources["wayback"]["status"], "error")
        self.assertIn("api.example.com", [host["name"] for host in report["hosts"]])

    def test_invalid_json_is_source_error_without_raw_body_disclosure(self):
        (self.fixtures / "wayback.json").write_text("BODY_SECRET_384 invalid JSON", encoding="utf-8")
        code, stdout, stderr = self.invoke("--sources", "crtsh,wayback")
        self.assertEqual(code, 3, stdout + stderr)
        path, report = self.only_report()
        statuses = {source["name"]: source["status"] for source in report["sources"]}
        self.assertEqual(statuses["wayback"], "error")
        self.assertEqual(statuses["crtsh"], "ok")
        self.assertNotIn("BODY_SECRET_384", path.read_text(encoding="utf-8") + stdout + stderr)

    def test_record_limit_reports_partial_and_bounds_inventory(self):
        rows = [{"id": i, "name_value": f"host{i}.example.com"} for i in range(20)]
        self.write_json("crtsh-apex.json", rows)
        self.write_json("crtsh-subdomains.json", rows)
        code, stdout, stderr = self.invoke("--sources", "crtsh", "--limit", "2")
        self.assertEqual(code, 3, stdout + stderr)
        _, report = self.only_report()
        self.assertEqual(report["sources"][0]["status"], "partial")
        self.assertLessEqual(len(report["hosts"]), 2)
        self.assertGreater(len(report["hosts"]), 0)

    def test_provider_within_target_scope_is_skipped(self):
        code, stdout, stderr = self.invoke("--sources", "wayback", target="archive.org")
        self.assertEqual(code, 3, stdout + stderr)
        _, report = self.only_report()
        self.assertEqual(report["sources"][0]["status"], "skipped")
        self.assertEqual(report["hosts"], [])

    def test_runs_are_unique_and_private(self):
        for _ in range(2):
            code, stdout, stderr = self.invoke("--sources", "crtsh")
            self.assertEqual(code, 0, stdout + stderr)
        reports = self.reports()
        self.assertEqual(len(reports), 2)
        self.assertNotEqual(reports[0].parent, reports[1].parent)
        for report in reports:
            self.assertEqual(stat.S_IMODE(report.parent.stat().st_mode), 0o700)
            for item in report.parent.rglob("*"):
                if item.is_file():
                    self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)

    def test_dry_run_creates_no_output(self):
        code, stdout, stderr = self.invoke("--dry-run")
        self.assertEqual(code, 0, stdout + stderr)
        self.assertFalse(self.output.exists())

    def test_invalid_cli_arguments_create_no_output(self):
        for args in (("--limit", "0"), ("--sources", "unknown")):
            with self.subTest(args=args):
                code, stdout, stderr = self.invoke(*args)
                self.assertEqual(code, 2, stdout + stderr)
                self.assertFalse(self.output.exists())

    def transport(self, *extra):
        args = self.recon.arguments(["example.com", "--retries", "0", *extra])
        return self.recon.Transport(args, args.domain)

    def response(self, status=200, body=b"[]", headers=None):
        response = Mock()
        response.status = status
        response.read.return_value = body
        headers = headers or {}
        response.getheader.side_effect = lambda name, default=None: headers.get(name, default)
        return response

    def test_redirect_response_is_not_followed_or_read(self):
        tx = self.transport()
        response = self.response(302, headers={"Location": "https://example.com/redirect-secret"})
        conn = Mock()
        conn.getresponse.return_value = response
        with deny_network(), patch.object(self.recon, "ProviderHTTPS", return_value=conn) as factory:
            with self.assertRaises(self.recon.SourceError):
                tx.get("wayback", "https://web.archive.org/cdx/search/cdx?url=example.com", "unused.json")
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(factory.call_args.args[0], "web.archive.org")
        conn.request.assert_called_once()
        response.read.assert_not_called()
        conn.close.assert_called()
        self.assertEqual(tx.used, 1)
        self.assertNotIn("redirect-secret", json.dumps(tx.requests))

    def test_byte_and_encoding_limits_stop_before_unbounded_reads(self):
        for headers, body, read_expected in (
            ({"Content-Length": "1025"}, b"", False),
            ({"Content-Encoding": "gzip"}, b"", False),
            ({}, b"x" * 1025, True),
        ):
            with self.subTest(headers=headers):
                tx = self.transport("--max-bytes", "1024")
                response = self.response(body=body, headers=headers)
                conn = Mock()
                conn.getresponse.return_value = response
                with deny_network(), patch.object(self.recon, "ProviderHTTPS", return_value=conn):
                    with self.assertRaises(self.recon.SourceError):
                        tx.get("crtsh", "https://crt.sh/?q=example.com", "unused.json")
                if read_expected:
                    response.read.assert_called_once_with(1025)
                else:
                    response.read.assert_not_called()
                conn.close.assert_called()

    def test_retries_cannot_exceed_global_request_budget(self):
        tx = self.transport("--request-budget", "1", "--retries", "1")
        response = self.response(503)
        conn = Mock()
        conn.getresponse.return_value = response
        with deny_network(), patch.object(self.recon, "ProviderHTTPS", return_value=conn) as factory, patch.object(self.recon.time, "sleep"):
            with self.assertRaises(self.recon.SourceError):
                tx.get("crtsh", "https://crt.sh/?q=example.com", "unused.json")
        self.assertEqual(tx.used, 1)
        self.assertEqual(factory.call_count, 1)
        response.read.assert_not_called()

    def test_environment_proxies_do_not_change_provider_connection(self):
        tx = self.transport()
        conn = Mock()
        conn.getresponse.return_value = self.response()
        proxies = {name: "http://proxy.example.com:8080" for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy")}
        with deny_network(), patch.dict(os.environ, proxies), patch.object(self.recon, "ProviderHTTPS", return_value=conn) as factory:
            self.assertEqual(tx.get("crtsh", "https://crt.sh/?q=example.com", "unused.json"), b"[]")
        self.assertEqual(factory.call_args.args[0], "crt.sh")
        self.assertEqual(conn.request.call_args.args, ("GET", "/?q=example.com"))

    def test_unapproved_endpoints_are_rejected_before_connection(self):
        cases = (
            ("crtsh", "http://crt.sh/?q=example.com"),
            ("crtsh", "https://crt.sh/unapproved-path"),
            ("crtsh", "https://crt.sh:8443/"),
            ("crtsh", "https://user:secret@crt.sh/"),
            ("cc_index", "https://example.com/CC-MAIN-2026-01-index"),
            ("cc_index", "https://index.commoncrawl.org/../../target"),
            ("wayback", "https://web.archive.org/web/2026/https://example.com/"),
        )
        for kind, url in cases:
            with self.subTest(url=url), deny_network(), patch.object(self.recon, "ProviderHTTPS") as factory:
                with self.assertRaises(self.recon.SourceError):
                    self.transport().get(kind, url, "unused.json")
                factory.assert_not_called()

    def test_connect_deadline_is_not_swallowed_as_retryable_error(self):
        answers = [
            (self.recon.socket.AF_INET, self.recon.socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (self.recon.socket.AF_INET, self.recon.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ]
        fake_socket = Mock()
        fake_socket.connect.side_effect = self.recon.DeadlineExceeded("source deadline")
        with deny_network(), patch.object(self.recon.socket, "getaddrinfo", return_value=answers) as resolve, patch.object(self.recon.socket, "socket", return_value=fake_socket) as factory:
            conn = self.recon.ProviderHTTPS("crt.sh", timeout=1)
            with self.assertRaises(self.recon.DeadlineExceeded):
                conn.connect()
        resolve.assert_called_once_with("crt.sh", 443, type=self.recon.socket.SOCK_STREAM)
        self.assertEqual(factory.call_count, 1)
        fake_socket.connect.assert_called_once_with(("1.1.1.1", 443))
        fake_socket.close.assert_called_once()

    def test_provider_dns_answers_must_all_be_public(self):
        answers = [
            (self.recon.socket.AF_INET, self.recon.socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (self.recon.socket.AF_INET, self.recon.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with deny_network(), patch.object(self.recon.socket, "getaddrinfo", return_value=answers), patch.object(self.recon.socket, "socket") as factory:
            conn = self.recon.ProviderHTTPS("crt.sh", timeout=1)
            with self.assertRaises(self.recon.SourceError):
                conn.connect()
            factory.assert_not_called()

    def test_rdap_referral_links_and_contacts_are_not_followed_or_exported(self):
        data = json.loads((self.fixtures / "rdap.json").read_text(encoding="utf-8"))
        data["links"] = [{"rel": "related", "href": "https://example.com/REFERRAL_SECRET_384"}]
        self.write_json("rdap.json", data)
        code, stdout, stderr = self.invoke("--sources", "rdap")
        self.assertEqual(code, 0, stdout + stderr)
        path, report = self.only_report()
        self.assertEqual(len(report["requests"]), 2)
        self.assertEqual({item["provider"] for item in report["requests"]}, {"data.iana.org", "rdap.verisign.com"})
        self.assertNotIn("REFERRAL_SECRET_384", path.read_text(encoding="utf-8"))

    def test_rdap_metadata_obeys_record_limit_and_marks_partial(self):
        data = json.loads((self.fixtures / "rdap.json").read_text(encoding="utf-8"))
        data["nameservers"] = [
            {"ldhName": f"ns{index}.external.test"} for index in range(5)
        ]
        data["events"] = [
            {"eventAction": "registration", "eventDate": f"200{index}-01-01T00:00:00Z"}
            for index in range(5)
        ]
        data["status"] = [f"status-{index}" for index in range(5)]
        self.write_json("rdap.json", data)
        code, stdout, stderr = self.invoke("--sources", "rdap", "--limit", "2")
        self.assertEqual(code, 3, stdout + stderr)
        _, report = self.only_report()
        self.assertEqual(report["sources"][0]["status"], "partial")
        self.assertEqual(len(report["registration"]["nameservers"]), 2)
        self.assertEqual(len(report["registration"]["events"]), 2)
        self.assertEqual(len(report["registration"]["status"]), 2)

    def test_rdap_endpoint_under_target_is_skipped(self):
        self.write_json("rdap-bootstrap.json", {"services": [[["com"], ["https://rdap.example.com/"]]]})
        code, stdout, stderr = self.invoke("--sources", "rdap")
        self.assertEqual(code, 3, stdout + stderr)
        _, report = self.only_report()
        self.assertEqual(report["sources"][0]["status"], "skipped")
        self.assertEqual([item["provider"] for item in report["requests"]], ["data.iana.org"])
        self.assertIsNone(report["registration"])


if __name__ == "__main__":
    unittest.main()
