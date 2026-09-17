#!/usr/bin/env python3
"""Build deterministic, sanitized Markdown and SARIF assessment reports."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unicodedata
from urllib.parse import urlsplit


VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
MAX_INPUT_BYTES = 5 * 1024 * 1024

SEVERITIES = ("critical", "high", "medium", "low", "informational")
STATUSES = ("open", "in_progress", "accepted_risk", "remediated", "false_positive")
CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
SECURITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
    "informational": "0.0",
}

STABLE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,15}-[A-Z0-9][A-Z0-9._-]{0,31}$")
MITRE_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
HTML_RE = re.compile(r"(?:<!--|<!DOCTYPE\b|<\?\w|<\s*/?\s*[A-Za-z][^>]*>)", re.IGNORECASE)

_SECRET_NAMES = (
    r"authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|password|passwd|pwd|"
    r"passphrase|token|access[-_]?token|refresh[-_]?token|id[-_]?token|auth[-_]?token|"
    r"bearer[-_]?token|api[-_]?key|client[-_]?secret|client[-_]?token|session|sessionid|"
    r"session[-_]?id|session[-_]?key|session[-_]?token|private[-_]?key|secret[-_]?key|"
    r"access[-_]?key|aws[-_]?secret[-_]?access[-_]?key|aws[-_]?session[-_]?token|"
    r"secret[-_]?access[-_]?key|csrf[-_]?token|xsrf[-_]?token|secret"
)
HEADER_SECRET_RE = re.compile(
    r"\b(authorization|proxy[-_]?authorization|cookie|set[-_]?cookie)\s*:\s*[^\r\n]+",
    re.IGNORECASE,
)
ASSIGNMENT_START_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<quote>[\"']?)(?P<key>{_SECRET_NAMES})(?P=quote)"
    rf"(?P<separator>\s*(?:=|:)\s*)",
    re.IGNORECASE,
)
NEXT_FIELD_RE = re.compile(r"\s+[A-Za-z][A-Za-z0-9_.-]{0,63}\s*[:=]")
URL_USERINFO_RE = re.compile(
    r"\b(?P<scheme>https?://)(?P<username>[^:/@\s]+):(?P<password>[^@\s]+)@",
    re.IGNORECASE,
)
AUTH_SCHEME_RE = re.compile(
    r"\b(?P<scheme>Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE
)
QUERY_VALUE_RE = re.compile(
    r"(?P<prefix>[?&])(?P<key>[A-Za-z0-9_.~-]{1,128})=(?P<value>[^&#\s]*)"
)


class ReportForgeError(ValueError):
    """A user-correctable input or output validation error."""


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReportForgeError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ReportForgeError(f"non-standard JSON value is not allowed: {value}")


def load_input(path: Path) -> dict[str, object]:
    """Read one bounded JSON document without following any evidence references."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise ReportForgeError(f"cannot read input file: {exc}") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise ReportForgeError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportForgeError("input must be UTF-8") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ReportForgeError(f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    except RecursionError as exc:
        raise ReportForgeError("input JSON is nested too deeply") from exc
    if type(data) is not dict:
        raise ReportForgeError("document: expected an object")
    return data


def _expect_object(value: object, path: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ReportForgeError(f"{path}: expected an object")
    return value


def _expect_list(value: object, path: str, *, maximum: int, minimum: int = 0) -> list[object]:
    if type(value) is not list:
        raise ReportForgeError(f"{path}: expected an array")
    if not minimum <= len(value) <= maximum:
        raise ReportForgeError(f"{path}: expected {minimum}..{maximum} items")
    return value


def _expect_exact_keys(
    value: dict[str, object],
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - optional)
    if missing:
        raise ReportForgeError(f"{path}: missing field(s): {', '.join(missing)}")
    if unknown:
        raise ReportForgeError(f"{path}: unknown field(s): {', '.join(unknown)}")


def _validate_safe_text(value: object, path: str, minimum: int, maximum: int) -> str:
    if type(value) is not str:
        raise ReportForgeError(f"{path}: expected a string")
    if not minimum <= len(value) <= maximum:
        raise ReportForgeError(f"{path}: expected {minimum}..{maximum} characters")
    if value != value.strip():
        raise ReportForgeError(f"{path}: leading or trailing whitespace is not allowed")
    for char in value:
        if unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
            raise ReportForgeError(f"{path}: control or formatting characters are not allowed")
    if HTML_RE.search(value):
        raise ReportForgeError(f"{path}: HTML is not allowed")
    return value


def _validate_string_list(
    value: object,
    path: str,
    *,
    maximum_items: int,
    minimum_items: int = 0,
    maximum_length: int,
) -> list[str]:
    items = _expect_list(value, path, maximum=maximum_items, minimum=minimum_items)
    result = [
        _validate_safe_text(item, f"{path}[{index}]", 1, maximum_length)
        for index, item in enumerate(items)
    ]
    if len(set(result)) != len(result):
        raise ReportForgeError(f"{path}: duplicate items are not allowed")
    return result


def _validate_date(value: object, path: str) -> str:
    text = _validate_safe_text(value, path, 10, 10)
    try:
        parsed = dt.date.fromisoformat(text)
    except ValueError as exc:
        raise ReportForgeError(f"{path}: expected a valid YYYY-MM-DD date") from exc
    if parsed.isoformat() != text:
        raise ReportForgeError(f"{path}: expected canonical YYYY-MM-DD form")
    return text


def _validate_stable_id(value: object, path: str) -> str:
    text = _validate_safe_text(value, path, 3, 48)
    if not STABLE_ID_RE.fullmatch(text):
        raise ReportForgeError(
            f"{path}: expected an uppercase stable ID such as ENG-2026-001 or FIND-001"
        )
    return text


def _validate_reference(value: object, path: str) -> str:
    text = _validate_safe_text(value, path, 1, 2048)
    if CVE_ID_RE.fullmatch(text):
        return text
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise ReportForgeError(f"{path}: malformed URL") from exc
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ReportForgeError(f"{path}: expected a CVE ID or credential-free HTTPS URL")
    if any(char.isspace() for char in text):
        raise ReportForgeError(f"{path}: URL whitespace is not allowed")
    return text


def validate_document(data: dict[str, object]) -> dict[str, object]:
    """Validate and return a deep copy conforming to schema version 1.0."""
    root = _expect_object(data, "document")
    _expect_exact_keys(root, "document", {"schema_version", "engagement", "findings"})
    if root["schema_version"] != SCHEMA_VERSION:
        raise ReportForgeError(f"schema_version: expected {SCHEMA_VERSION!r}")

    engagement = _expect_object(root["engagement"], "engagement")
    _expect_exact_keys(
        engagement,
        "engagement",
        {
            "id",
            "name",
            "client",
            "assessment_type",
            "start_date",
            "end_date",
            "report_date",
            "classification",
            "scope",
            "authors",
        },
    )
    validated_engagement: dict[str, object] = {
        "id": _validate_stable_id(engagement["id"], "engagement.id"),
        "name": _validate_safe_text(engagement["name"], "engagement.name", 1, 160),
        "client": _validate_safe_text(engagement["client"], "engagement.client", 1, 160),
        "assessment_type": _validate_safe_text(
            engagement["assessment_type"], "engagement.assessment_type", 1, 100
        ),
        "start_date": _validate_date(engagement["start_date"], "engagement.start_date"),
        "end_date": _validate_date(engagement["end_date"], "engagement.end_date"),
        "report_date": _validate_date(engagement["report_date"], "engagement.report_date"),
        "classification": _validate_safe_text(
            engagement["classification"], "engagement.classification", 1, 20
        ),
        "scope": _validate_string_list(
            engagement["scope"],
            "engagement.scope",
            maximum_items=100,
            minimum_items=1,
            maximum_length=255,
        ),
        "authors": _validate_string_list(
            engagement["authors"],
            "engagement.authors",
            maximum_items=20,
            minimum_items=1,
            maximum_length=120,
        ),
    }
    if validated_engagement["classification"] not in CLASSIFICATIONS:
        raise ReportForgeError(
            "engagement.classification: expected one of " + ", ".join(CLASSIFICATIONS)
        )
    start = dt.date.fromisoformat(str(validated_engagement["start_date"]))
    end = dt.date.fromisoformat(str(validated_engagement["end_date"]))
    report_date = dt.date.fromisoformat(str(validated_engagement["report_date"]))
    if end < start:
        raise ReportForgeError("engagement.end_date: cannot precede start_date")
    if report_date < start:
        raise ReportForgeError("engagement.report_date: cannot precede start_date")

    finding_items = _expect_list(root["findings"], "findings", maximum=1000)
    validated_findings: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    required_fields = {
        "id",
        "title",
        "severity",
        "status",
        "asset",
        "description",
        "evidence",
        "remediation",
        "references",
        "attack_techniques",
    }
    for index, raw_finding in enumerate(finding_items):
        path = f"findings[{index}]"
        finding = _expect_object(raw_finding, path)
        _expect_exact_keys(finding, path, required_fields, {"cves"})
        finding_id = _validate_stable_id(finding["id"], f"{path}.id")
        if finding_id in seen_ids:
            raise ReportForgeError(f"{path}.id: duplicate finding ID {finding_id!r}")
        seen_ids.add(finding_id)
        severity = _validate_safe_text(finding["severity"], f"{path}.severity", 3, 20)
        if severity not in SEVERITIES:
            raise ReportForgeError(f"{path}.severity: expected one of {', '.join(SEVERITIES)}")
        status = _validate_safe_text(finding["status"], f"{path}.status", 3, 30)
        if status not in STATUSES:
            raise ReportForgeError(f"{path}.status: expected one of {', '.join(STATUSES)}")
        references_raw = _expect_list(finding["references"], f"{path}.references", maximum=50)
        references = [
            _validate_reference(item, f"{path}.references[{item_index}]")
            for item_index, item in enumerate(references_raw)
        ]
        if len(set(references)) != len(references):
            raise ReportForgeError(f"{path}.references: duplicate items are not allowed")
        techniques = _validate_string_list(
            finding["attack_techniques"],
            f"{path}.attack_techniques",
            maximum_items=50,
            maximum_length=9,
        )
        for item_index, technique in enumerate(techniques):
            if not MITRE_ID_RE.fullmatch(technique):
                raise ReportForgeError(
                    f"{path}.attack_techniques[{item_index}]: expected T1234 or T1234.001"
                )
        cves = _validate_string_list(
            finding.get("cves", []),
            f"{path}.cves",
            maximum_items=50,
            maximum_length=32,
        )
        for item_index, cve in enumerate(cves):
            if not CVE_ID_RE.fullmatch(cve):
                raise ReportForgeError(
                    f"{path}.cves[{item_index}]: expected an uppercase CVE-YYYY-NNNN identifier"
                )
        validated_findings.append(
            {
                "id": finding_id,
                "title": _validate_safe_text(finding["title"], f"{path}.title", 1, 200),
                "severity": severity,
                "status": status,
                "asset": _validate_safe_text(finding["asset"], f"{path}.asset", 1, 500),
                "description": _validate_safe_text(
                    finding["description"], f"{path}.description", 1, 8000
                ),
                "evidence": _validate_string_list(
                    finding["evidence"],
                    f"{path}.evidence",
                    maximum_items=100,
                    maximum_length=8000,
                ),
                "remediation": _validate_safe_text(
                    finding["remediation"], f"{path}.remediation", 1, 8000
                ),
                "references": references,
                "attack_techniques": techniques,
                "cves": cves,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "engagement": validated_engagement,
        "findings": validated_findings,
    }


def scrub_secrets(text: str) -> str:
    """Redact keyed credentials while preserving enough context for review."""
    pieces: list[str] = []
    cursor = 0
    while True:
        match = ASSIGNMENT_START_RE.search(text, cursor)
        if match is None:
            pieces.append(text[cursor:])
            break
        pieces.append(text[cursor : match.end()])
        value_start = match.end()
        value_end = value_start
        value_quote = text[value_start : value_start + 1]
        if value_quote in {"\"", "'"}:
            closing = value_start + 1
            while closing < len(text):
                if text[closing] == value_quote and text[closing - 1] != "\\":
                    break
                closing += 1
            pieces.append(value_quote + "[REDACTED]")
            if closing < len(text):
                pieces.append(value_quote)
                value_end = closing + 1
            else:
                value_end = len(text)
        else:
            value_end = len(text)
            scan = value_start
            while scan < len(text):
                if text[scan] in "&;,#)}]":
                    value_end = scan
                    break
                if text[scan] in ".!?" and scan + 1 < len(text):
                    sentence_tail = text[scan + 1 :]
                    if re.match(r"\s+[A-Z]", sentence_tail):
                        value_end = scan
                        break
                if text[scan].isspace():
                    next_field = NEXT_FIELD_RE.match(text, scan)
                    if next_field is not None:
                        value_end = scan
                        break
                scan += 1
            pieces.append("[REDACTED]")
        cursor = value_end
    text = "".join(pieces)
    text = HEADER_SECRET_RE.sub(lambda match: f"{match.group(1)}: [REDACTED]", text)
    text = URL_USERINFO_RE.sub(
        lambda match: (
            f"{match.group('scheme')}{match.group('username')}:[REDACTED]@"
        ),
        text,
    )
    text = AUTH_SCHEME_RE.sub(
        lambda match: f"{match.group('scheme')} [REDACTED]", text
    )
    return QUERY_VALUE_RE.sub(
        lambda match: f"{match.group('prefix')}{match.group('key')}=[REDACTED]",
        text,
    )


def sanitize_document(data: dict[str, object]) -> dict[str, object]:
    sanitized = copy.deepcopy(data)
    findings = sanitized["findings"]
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, dict)
        finding["evidence"] = [scrub_secrets(item) for item in finding["evidence"]]
    return sanitized


def _markdown(text: object) -> str:
    value = str(text)
    for char in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "#", "|", "~"):
        value = value.replace(char, "\\" + char)
    return value


def _display_enum(value: str) -> str:
    return value.replace("_", " ").title()


def _sorted_findings(data: dict[str, object]) -> list[dict[str, object]]:
    findings = data["findings"]
    assert isinstance(findings, list)
    return sorted(findings, key=lambda item: (SEVERITIES.index(str(item["severity"])), str(item["id"])))


def build_markdown(data: dict[str, object]) -> str:
    engagement = data["engagement"]
    assert isinstance(engagement, dict)
    findings = _sorted_findings(data)
    counts = {severity: 0 for severity in SEVERITIES}
    status_counts = {status: 0 for status in STATUSES}
    for finding in findings:
        counts[str(finding["severity"])] += 1
        status_counts[str(finding["status"])] += 1

    lines = [
        f"# {_markdown(engagement['name'])}",
        "",
        f"**Report ID:** {_markdown(engagement['id'])}  ",
        f"**Client:** {_markdown(engagement['client'])}  ",
        f"**Assessment type:** {_markdown(engagement['assessment_type'])}  ",
        f"**Assessment window:** {_markdown(engagement['start_date'])} to {_markdown(engagement['end_date'])}  ",
        f"**Report date:** {_markdown(engagement['report_date'])}  ",
        f"**Classification:** {_display_enum(str(engagement['classification']))}  ",
        f"**Authors:** {', '.join(_markdown(item) for item in engagement['authors'])}",
        "",
        "## Executive summary",
        "",
        f"The assessment documented {len(findings)} finding(s) across the declared scope.",
        "",
        "| Severity | Findings |",
        "| --- | ---: |",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {_display_enum(severity)} | {counts[severity]} |")
    lines.extend(["| **Total** | **%d** |" % len(findings), "", "| Status | Findings |", "| --- | ---: |"])
    for status in STATUSES:
        lines.append(f"| {_display_enum(status)} | {status_counts[status]} |")
    lines.extend(["", "## Scope", ""])
    lines.extend(f"- {_markdown(item)}" for item in engagement["scope"])
    lines.extend(["", "## Technical findings", ""])

    if not findings:
        lines.extend(["No findings were supplied.", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {_markdown(finding['id'])}: {_markdown(finding['title'])}",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| Severity | {_display_enum(str(finding['severity']))} |",
                f"| Status | {_display_enum(str(finding['status']))} |",
                f"| Asset | {_markdown(finding['asset'])} |",
                "",
                "#### Description",
                "",
                _markdown(finding["description"]),
                "",
                "#### Evidence",
                "",
            ]
        )
        evidence = finding["evidence"]
        assert isinstance(evidence, list)
        lines.extend(f"- {_markdown(item)}" for item in evidence)
        if not evidence:
            lines.append("- No evidence supplied.")
        lines.extend(["", "#### Remediation", "", _markdown(finding["remediation"]), ""])
        techniques = finding["attack_techniques"]
        cves = finding["cves"]
        references = finding["references"]
        assert isinstance(techniques, list) and isinstance(cves, list) and isinstance(references, list)
        lines.extend(
            [
                f"**MITRE ATT&CK:** {', '.join(_markdown(item) for item in techniques) if techniques else 'None supplied'}  ",
                f"**CVEs:** {', '.join(_markdown(item) for item in cves) if cves else 'None supplied'}",
                "",
                "#### References",
                "",
            ]
        )
        lines.extend(f"- {_markdown(item)}" for item in references)
        if not references:
            lines.append("- No references supplied.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_sarif(data: dict[str, object]) -> dict[str, object]:
    findings = _sorted_findings(data)
    rules: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    for rule_index, finding in enumerate(findings):
        cves = list(finding["cves"])
        for reference in finding["references"]:
            if CVE_ID_RE.fullmatch(str(reference)) and reference not in cves:
                cves.append(reference)
        rules.append(
            {
                "id": finding["id"],
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["description"]},
                "help": {"text": finding["remediation"]},
                "properties": {
                    "severity": finding["severity"],
                    "security-severity": SECURITY_SCORE[str(finding["severity"])],
                    "attack_techniques": finding["attack_techniques"],
                    "cves": cves,
                    "references": finding["references"],
                },
            }
        )
        fingerprint_material = "\x00".join(
            (str(finding["id"]), str(finding["asset"]), str(finding["title"]))
        ).encode("utf-8")
        results.append(
            {
                "ruleId": finding["id"],
                "ruleIndex": rule_index,
                "level": SARIF_LEVEL[str(finding["severity"])],
                "message": {"text": finding["description"]},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": finding["asset"],
                                "kind": "resource",
                            }
                        ]
                    }
                ],
                "partialFingerprints": {
                    "reportforge/v1": hashlib.sha256(fingerprint_material).hexdigest()
                },
                "properties": {
                    "severity": finding["severity"],
                    "status": finding["status"],
                    "asset": finding["asset"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                    "references": finding["references"],
                    "attack_techniques": finding["attack_techniques"],
                    "cves": cves,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReportForge",
                        "semanticVersion": VERSION,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def serialize_sarif(data: dict[str, object]) -> str:
    return json.dumps(build_sarif(data), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _output_directory(raw_path: str | os.PathLike[str]) -> Path:
    supplied = Path(raw_path).expanduser()
    if ".." in supplied.parts:
        raise ReportForgeError("output directory: '..' path traversal is not allowed")
    path = supplied if supplied.is_absolute() else Path.cwd() / supplied
    path = Path(os.path.abspath(path))
    anchor = Path(path.anchor)
    current = anchor
    for part in path.parts[1:]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except OSError as exc:
                raise ReportForgeError(f"cannot create output directory {current}: {exc}") from exc
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ReportForgeError(f"output directory: symlink component is not allowed: {current}")
        if not stat.S_ISDIR(info.st_mode):
            raise ReportForgeError(f"output directory component is not a directory: {current}")
    return path


def _validate_existing_target(target: Path, force: bool) -> None:
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ReportForgeError(f"refusing symlink output target: {target}")
    if not stat.S_ISREG(info.st_mode):
        raise ReportForgeError(f"refusing non-regular output target: {target}")
    if not force:
        raise ReportForgeError(f"output already exists (use --force to replace): {target}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ReportForgeError(f"refusing to replace output owned by another user: {target}")


def _atomic_write(target: Path, content: str, force: bool) -> None:
    _validate_existing_target(target, force)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            _validate_existing_target(target, True)
            os.replace(temporary, target)
        else:
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError as exc:
                raise ReportForgeError(f"output already exists: {target}") from exc
            os.unlink(temporary)
        os.chmod(target, 0o600, follow_symlinks=False)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_reports(
    data: dict[str, object], output_directory: str | os.PathLike[str], *, force: bool = False
) -> tuple[Path, Path]:
    data = sanitize_document(data)
    directory = _output_directory(output_directory)
    markdown_target = directory / "report.md"
    sarif_target = directory / "report.sarif.json"
    # Validate both destinations before committing either file during normal use.
    _validate_existing_target(markdown_target, force)
    _validate_existing_target(sarif_target, force)
    _atomic_write(markdown_target, build_markdown(data), force)
    _atomic_write(sarif_target, serialize_sarif(data), force)
    try:
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass
    return markdown_target, sarif_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reportforge",
        description="Generate deterministic, sanitized Markdown and SARIF reports offline.",
    )
    parser.add_argument("input", type=Path, help="UTF-8 JSON input conforming to schema 1.0")
    parser.add_argument(
        "-o", "--output-dir", required=True, help="directory for report.md and report.sarif.json"
    )
    parser.add_argument(
        "--force", action="store_true", help="replace owned regular output files after validation"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        input_path = args.input.expanduser()
        document = sanitize_document(validate_document(load_input(input_path)))
        directory = _output_directory(args.output_dir)
        for name in ("report.md", "report.sarif.json"):
            target = directory / name
            try:
                if target.exists() and input_path.samefile(target):
                    raise ReportForgeError("input file cannot also be an output target")
            except OSError:
                pass
        markdown_path, sarif_path = write_reports(document, directory, force=args.force)
    except (ReportForgeError, OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"reportforge: error: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {markdown_path}")
    print(f"Wrote {sarif_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
