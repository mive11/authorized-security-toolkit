#!/usr/bin/env python3
"""Offline validator for normalized Windows security telemetry exports.

The tool reads local JSON/JSONL files only. It does not execute techniques,
alter security controls, resolve hosts, or perform network operations.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


EXIT_OK = 0
EXIT_INVALID = 2
EXIT_MISSING = 3

MAX_PROFILE_BYTES = 1_000_000
MAX_JSONL_LINE_BYTES = 1_000_000
MAX_EVENT_FILE_BYTES = 128 * 1024 * 1024
MAX_EVENT_RECORDS = 100_000
MAX_EVALUATION_STEPS = 10_000_000
MAX_SIGNALS = 256
MAX_RULES_PER_SIGNAL = 64
MAX_FIELD_RULES = 64
MAX_TEXT_LENGTH = 4096
MAX_REGEX_LENGTH = 128
MAX_EVIDENCE = 25
MAX_WINDOW_SECONDS = 31_536_000
MAX_DATA_DEPTH = 32
MAX_DATA_CONTAINERS = 4096

ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
FIELD_PATH = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
BOUNDED_QUANTIFIER = re.compile(r"\{(\d+)(?:,(\d+))?\}")

DISCLAIMER = (
    "This report checks whether expected records are present in the supplied "
    "export. Presence or absence is not proof that a security control worked, "
    "failed, or was bypassed; export scope, retention, forwarding, and workload "
    "activity can all affect the result."
)


class ValidationError(Exception):
    """Raised for invalid, unsafe, or unsupported input."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class DuplicateKeyError(ValueError):
    pass


class NonFiniteNumberError(ValueError):
    pass


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    line: int | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.line is not None:
            result["line"] = self.line
        return result


@dataclass(frozen=True)
class FieldMatcher:
    operation: str
    expected: Any
    compiled: re.Pattern[str] | None = None


@dataclass(frozen=True)
class MatchRule:
    providers: tuple[str, ...] | None
    event_ids: tuple[int, ...] | None
    channels: tuple[str, ...] | None
    fields: tuple[tuple[str, FieldMatcher], ...]


@dataclass(frozen=True)
class Signal:
    signal_id: str
    title: str
    attack_techniques: tuple[str, ...]
    rules: tuple[MatchRule, ...]
    min_count: int
    window_seconds: int | None


@dataclass(frozen=True)
class Profile:
    profile_id: str
    title: str
    description: str
    signals: tuple[Signal, ...]


@dataclass(frozen=True)
class Event:
    index: int
    timestamp: str
    timestamp_value: datetime
    provider: str
    event_id: int
    channel: str
    data: dict[str, Any]


@dataclass
class EvaluationBudget:
    remaining: int

    def consume(self, amount: int = 1) -> None:
        if amount < 0 or amount > self.remaining:
            raise ValidationError(
                "evaluation_limit",
                "events and profile exceed the bounded evaluation budget",
            )
        self.remaining -= amount


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate object key")
        result[key] = value
    return result


def _reject_non_finite(_: str) -> None:
    raise NonFiniteNumberError("non-finite JSON number")


def _json_loads(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_non_finite,
    )


def _required_text(obj: dict[str, Any], key: str, maximum: int = 200) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("profile_schema", f"{key} must be a non-empty string")
    if len(value) > maximum:
        raise ValidationError("profile_limit", f"{key} exceeds {maximum} characters")
    value = value.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValidationError("profile_schema", f"{key} contains control characters")
    return value


def _string_choices(value: Any, key: str) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    if not values or any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValidationError("profile_schema", f"{key} must contain non-empty strings")
    if len(values) > 64 or any(len(item) > 512 for item in values):
        raise ValidationError("profile_limit", f"{key} exceeds the allowed size")
    return tuple(item.strip().casefold() for item in values)


def _event_id_choices(value: Any) -> tuple[int, ...]:
    values = value if isinstance(value, list) else [value]
    if not values or len(values) > 64:
        raise ValidationError("profile_schema", "event_id must contain one to 64 IDs")
    result: list[int] = []
    for item in values:
        if isinstance(item, bool):
            raise ValidationError("profile_schema", "event_id must be an integer")
        if isinstance(item, str) and item.isdecimal():
            item = int(item)
        if not isinstance(item, int) or not 0 <= item <= 4_294_967_295:
            raise ValidationError("profile_schema", "event_id must be a non-negative integer")
        result.append(item)
    return tuple(result)


def _validate_safe_regex(pattern: str) -> re.Pattern[str]:
    if not pattern or len(pattern) > MAX_REGEX_LENGTH:
        raise ValidationError(
            "unsafe_regex", f"regex must contain 1 to {MAX_REGEX_LENGTH} characters"
        )
    if any(token in pattern for token in ("(", ")", "|", "*", "+", "?")):
        raise ValidationError(
            "unsafe_regex",
            "regex groups, alternation, and open-ended or optional quantifiers are not supported",
        )
    if re.search(r"\\[1-9]", pattern):
        raise ValidationError("unsafe_regex", "regex backreferences are not supported")

    # Remove recognized bounded quantifiers, then reject stray braces.
    def check_quantifier(match: re.Match[str]) -> str:
        lower = int(match.group(1))
        upper = int(match.group(2) or lower)
        if lower > upper or upper > 64:
            raise ValidationError(
                "unsafe_regex", "regex quantifier bounds must be ordered and at most 64"
            )
        return ""

    quantifiers = list(BOUNDED_QUANTIFIER.finditer(pattern))
    if len(quantifiers) > 1:
        raise ValidationError("unsafe_regex", "regex may contain at most one bounded quantifier")
    without_quantifiers = BOUNDED_QUANTIFIER.sub(check_quantifier, pattern)
    if "{" in without_quantifiers or "}" in without_quantifiers:
        raise ValidationError("unsafe_regex", "regex contains an invalid quantifier")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValidationError("unsafe_regex", "regex syntax is invalid") from exc


def _parse_field_matcher(value: Any) -> FieldMatcher:
    if not isinstance(value, dict) or len(value) != 1:
        raise ValidationError(
            "profile_schema", "a field matcher must define exactly one operation"
        )
    operation, expected = next(iter(value.items()))
    if operation not in {"equals", "contains", "glob", "regex"}:
        raise ValidationError(
            "profile_schema", "field matcher operation must be equals, contains, glob, or regex"
        )
    if operation == "equals":
        if not isinstance(expected, (str, int, float, bool)) or isinstance(expected, float) and (
            expected != expected or expected in (float("inf"), float("-inf"))
        ):
            raise ValidationError("profile_schema", "equals requires a finite scalar value")
        if isinstance(expected, str) and len(expected) > MAX_TEXT_LENGTH:
            raise ValidationError("profile_limit", "equals value is too long")
        return FieldMatcher(operation, expected)
    if not isinstance(expected, str) or not expected:
        raise ValidationError("profile_schema", f"{operation} requires a non-empty string")
    if operation == "regex":
        return FieldMatcher(operation, expected, _validate_safe_regex(expected))
    if len(expected) > 256:
        raise ValidationError("profile_limit", f"{operation} value is too long")
    if operation == "glob" and expected.count("*") + expected.count("?") > 16:
        raise ValidationError("profile_limit", "glob contains too many wildcards")
    return FieldMatcher(operation, expected)


def _parse_rule(raw: Any) -> MatchRule:
    if not isinstance(raw, dict):
        raise ValidationError("profile_schema", "each any_of entry must be an object")
    unknown = set(raw) - {"provider", "event_id", "channel", "fields"}
    if unknown:
        raise ValidationError("profile_schema", "match rule contains unsupported keys")
    if not raw:
        raise ValidationError("profile_schema", "match rule cannot be empty")
    providers = _string_choices(raw["provider"], "provider") if "provider" in raw else None
    event_ids = _event_id_choices(raw["event_id"]) if "event_id" in raw else None
    channels = _string_choices(raw["channel"], "channel") if "channel" in raw else None
    raw_fields = raw.get("fields", {})
    if not isinstance(raw_fields, dict) or len(raw_fields) > MAX_FIELD_RULES:
        raise ValidationError("profile_schema", "fields must be an object of limited size")
    fields: list[tuple[str, FieldMatcher]] = []
    for path, matcher in raw_fields.items():
        if not isinstance(path, str) or len(path) > 128 or not FIELD_PATH.fullmatch(path):
            raise ValidationError("profile_schema", "field path is invalid")
        fields.append((path, _parse_field_matcher(matcher)))
    if providers is None and event_ids is None and channels is None and not fields:
        raise ValidationError("profile_schema", "match rule needs at least one condition")
    return MatchRule(providers, event_ids, channels, tuple(fields))


def _parse_window(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, dict) and set(value) == {"seconds"}:
        value = value["seconds"]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("profile_schema", "window must be seconds or {seconds: integer}")
    if not 1 <= value <= MAX_WINDOW_SECONDS:
        raise ValidationError(
            "profile_schema", f"window must be between 1 and {MAX_WINDOW_SECONDS} seconds"
        )
    return value


def parse_profile(raw: Any) -> Profile:
    if not isinstance(raw, dict):
        raise ValidationError("profile_schema", "profile must be a JSON object")
    if set(raw) - {"schema_version", "id", "title", "description", "signals"}:
        raise ValidationError("profile_schema", "profile contains unsupported keys")
    if raw.get("schema_version") != 1:
        raise ValidationError("profile_schema", "schema_version must be 1")
    profile_id = _required_text(raw, "id", 64)
    if not IDENTIFIER.fullmatch(profile_id):
        raise ValidationError("profile_schema", "profile id has an invalid format")
    title = _required_text(raw, "title")
    description = raw.get("description", "")
    if not isinstance(description, str) or len(description) > 2000:
        raise ValidationError("profile_schema", "description must be a string of limited size")
    raw_signals = raw.get("signals")
    if not isinstance(raw_signals, list) or not 1 <= len(raw_signals) <= MAX_SIGNALS:
        raise ValidationError("profile_schema", "signals must contain one to 256 entries")

    signals: list[Signal] = []
    seen_ids: set[str] = set()
    for raw_signal in raw_signals:
        if not isinstance(raw_signal, dict):
            raise ValidationError("profile_schema", "each signal must be an object")
        if set(raw_signal) - {
            "id",
            "title",
            "attack_techniques",
            "any_of",
            "min_count",
            "window",
        }:
            raise ValidationError("profile_schema", "signal contains unsupported keys")
        signal_id = _required_text(raw_signal, "id", 64)
        if not IDENTIFIER.fullmatch(signal_id) or signal_id in seen_ids:
            raise ValidationError("profile_schema", "signal id is invalid or duplicated")
        seen_ids.add(signal_id)
        signal_title = _required_text(raw_signal, "title")
        techniques = raw_signal.get("attack_techniques", [])
        if (
            not isinstance(techniques, list)
            or len(techniques) > 64
            or any(not isinstance(item, str) or not ATTACK_ID.fullmatch(item) for item in techniques)
        ):
            raise ValidationError("profile_schema", "attack_techniques contains an invalid ID")
        raw_rules = raw_signal.get("any_of")
        if not isinstance(raw_rules, list) or not 1 <= len(raw_rules) <= MAX_RULES_PER_SIGNAL:
            raise ValidationError("profile_schema", "any_of must contain one to 64 match rules")
        min_count = raw_signal.get("min_count", 1)
        if isinstance(min_count, bool) or not isinstance(min_count, int) or not 1 <= min_count <= 1_000_000:
            raise ValidationError("profile_schema", "min_count must be a positive integer")
        signals.append(
            Signal(
                signal_id,
                signal_title,
                tuple(techniques),
                tuple(_parse_rule(rule) for rule in raw_rules),
                min_count,
                _parse_window(raw_signal.get("window")),
            )
        )
    return Profile(profile_id, title, description.strip(), tuple(signals))


def load_profile(path: Path) -> Profile:
    try:
        if path.stat().st_size > MAX_PROFILE_BYTES:
            raise ValidationError("profile_limit", "profile file exceeds 1 MB")
        raw = _json_loads(path.read_text(encoding="utf-8"))
    except ValidationError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValidationError("profile_io", "profile could not be read as UTF-8") from exc
    except (json.JSONDecodeError, DuplicateKeyError, NonFiniteNumberError, RecursionError) as exc:
        raise ValidationError("profile_json", "profile is not valid unambiguous JSON") from exc
    return parse_profile(raw)


def _parse_timestamp(value: Any) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        raise ValidationError("event_schema", "timestamp must be a short ISO-8601 string")
    normalized = value.strip()
    parse_value = normalized[:-1] + "+00:00" if normalized.endswith(("Z", "z")) else normalized
    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as exc:
        raise ValidationError("event_schema", "timestamp is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return normalized, parsed.astimezone(timezone.utc)


def _validate_event_data(data: dict[str, Any]) -> None:
    stack: list[tuple[Any, int]] = [(data, 0)]
    seen: set[int] = set()
    containers = 0
    while stack:
        value, depth = stack.pop()
        if not isinstance(value, (dict, list)):
            continue
        identity = id(value)
        if identity in seen:
            raise ValidationError("event_schema", "data contains a repeated or cyclic container")
        seen.add(identity)
        containers += 1
        if containers > MAX_DATA_CONTAINERS or depth > MAX_DATA_DEPTH:
            raise ValidationError("event_limit", "data nesting or container count exceeds limits")
        if isinstance(value, list):
            stack.extend((item, depth + 1) for item in value if isinstance(item, (dict, list)))
            continue
        folded: dict[str, str] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 512:
                raise ValidationError("event_schema", "data keys must be short non-empty strings")
            normalized = key.casefold()
            if normalized in folded:
                raise ValidationError(
                    "event_schema", "data contains keys that collide case-insensitively"
                )
            folded[normalized] = key
            if isinstance(item, (dict, list)):
                stack.append((item, depth + 1))


def _parse_event(raw: Any, index: int) -> Event:
    if not isinstance(raw, dict):
        raise ValidationError("event_schema", "event must be a JSON object")
    timestamp, timestamp_value = _parse_timestamp(raw.get("timestamp"))
    provider = raw.get("provider")
    channel = raw.get("channel")
    if not isinstance(provider, str) or not provider.strip() or len(provider) > 512:
        raise ValidationError("event_schema", "provider must be a non-empty string")
    if not isinstance(channel, str) or not channel.strip() or len(channel) > 512:
        raise ValidationError("event_schema", "channel must be a non-empty string")
    event_id = raw.get("event_id")
    if isinstance(event_id, str) and event_id.isdecimal():
        event_id = int(event_id)
    if isinstance(event_id, bool) or not isinstance(event_id, int) or not 0 <= event_id <= 4_294_967_295:
        raise ValidationError("event_schema", "event_id must be a non-negative integer")
    data = raw.get("data")
    if not isinstance(data, dict):
        raise ValidationError("event_schema", "data must be a JSON object")
    _validate_event_data(data)
    return Event(
        index=index,
        timestamp=timestamp,
        timestamp_value=timestamp_value,
        provider=provider.strip(),
        event_id=event_id,
        channel=channel.strip(),
        data=data,
    )


def load_events(path: Path) -> tuple[list[Event], list[Issue], int]:
    events: list[Event] = []
    issues: list[Issue] = []
    nonblank_lines = 0
    total_bytes = 0
    try:
        file_stat = path.stat()
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValidationError("events_io", "events input must be a regular file")
        if file_stat.st_size > MAX_EVENT_FILE_BYTES:
            raise ValidationError(
                "event_limit", f"events file exceeds {MAX_EVENT_FILE_BYTES} bytes"
            )
        handle = path.open("rb")
    except ValidationError:
        raise
    except OSError as exc:
        raise ValidationError("events_io", "events file could not be opened") from exc
    try:
        line_number = 0
        while True:
            raw_line = handle.readline(MAX_JSONL_LINE_BYTES + 1)
            if not raw_line:
                break
            line_number += 1
            total_bytes += len(raw_line)
            if total_bytes > MAX_EVENT_FILE_BYTES:
                raise ValidationError(
                    "event_limit", f"events input exceeds {MAX_EVENT_FILE_BYTES} bytes"
                )
            if len(raw_line) > MAX_JSONL_LINE_BYTES:
                raise ValidationError("event_limit", "event line exceeds 1 MB")
            try:
                line = raw_line.decode("utf-8")
            except UnicodeDecodeError:
                issues.append(Issue("event_encoding", "line is not valid UTF-8", line_number))
                continue
            if not line.strip():
                continue
            nonblank_lines += 1
            if nonblank_lines > MAX_EVENT_RECORDS:
                raise ValidationError(
                    "event_limit", f"events input exceeds {MAX_EVENT_RECORDS} records"
                )
            try:
                raw = _json_loads(line)
                events.append(_parse_event(raw, line_number))
            except (json.JSONDecodeError, DuplicateKeyError, NonFiniteNumberError, RecursionError):
                issues.append(Issue("event_json", "line is not valid unambiguous JSON", line_number))
            except ValidationError as exc:
                issues.append(Issue(exc.code, exc.message, line_number))
    except OSError as exc:
        raise ValidationError("events_io", "events file could not be read") from exc
    finally:
        handle.close()
    if nonblank_lines == 0:
        issues.append(Issue("events_empty", "events file contains no records"))
    return events, issues, nonblank_lines


def _lookup_casefold(mapping: dict[str, Any], key: str, budget: EvaluationBudget) -> Any:
    budget.consume()
    if key in mapping:
        return mapping[key]
    wanted = key.casefold()
    for candidate, value in mapping.items():
        budget.consume()
        if isinstance(candidate, str) and candidate.casefold() == wanted:
            return value
    raise KeyError(key)


def _field_value(data: dict[str, Any], path: str, budget: EvaluationBudget) -> Any:
    parts = path.split(".")
    if parts[0].casefold() == "data":
        parts = parts[1:]
    current: Any = data
    for part in parts:
        if not isinstance(current, dict):
            raise KeyError(path)
        current = _lookup_casefold(current, part, budget)
    return current


def _candidate_values(value: Any, budget: EvaluationBudget) -> Iterable[Any]:
    stack = [value]
    yielded = 0
    while stack and yielded < 256:
        budget.consume()
        candidate = stack.pop()
        if isinstance(candidate, list):
            stack.extend(reversed(candidate[:256]))
            continue
        if not isinstance(candidate, dict):
            yielded += 1
            yield candidate


def _matches_field(value: Any, matcher: FieldMatcher, budget: EvaluationBudget) -> bool:
    for candidate in _candidate_values(value, budget):
        if matcher.operation == "equals":
            budget.consume(1 + (len(candidate) // 64 if isinstance(candidate, str) else 0))
            if isinstance(candidate, str) and isinstance(matcher.expected, str):
                if candidate.casefold() == matcher.expected.casefold():
                    return True
            elif candidate == matcher.expected:
                return True
            continue
        text = str(candidate)[:MAX_TEXT_LENGTH]
        expected = str(matcher.expected)
        budget.consume(1 + len(text) // 64 + len(expected) // 64)
        if matcher.operation == "contains" and expected.casefold() in text.casefold():
            return True
        if matcher.operation == "glob" and fnmatch.fnmatchcase(text.casefold(), expected.casefold()):
            return True
        if matcher.operation == "regex" and matcher.compiled is not None and matcher.compiled.search(text):
            return True
    return False


def _matches_rule(event: Event, rule: MatchRule, budget: EvaluationBudget) -> bool:
    budget.consume()
    if rule.providers is not None:
        budget.consume(len(rule.providers))
    if rule.providers is not None and event.provider.casefold() not in rule.providers:
        return False
    if rule.event_ids is not None:
        budget.consume(len(rule.event_ids))
    if rule.event_ids is not None and event.event_id not in rule.event_ids:
        return False
    if rule.channels is not None:
        budget.consume(len(rule.channels))
    if rule.channels is not None and event.channel.casefold() not in rule.channels:
        return False
    for path, matcher in rule.fields:
        budget.consume()
        try:
            value = _field_value(event.data, path, budget)
        except KeyError:
            return False
        if not _matches_field(value, matcher, budget):
            return False
    return True


def _best_window(
    events: list[Event], seconds: int, budget: EvaluationBudget
) -> list[Event]:
    budget.consume(len(events) * max(1, len(events).bit_length()))
    ordered = sorted(events, key=lambda item: (item.timestamp_value, item.index))
    best_left = 0
    best_right = 0
    best_size = 0
    left = 0
    for right, event in enumerate(ordered):
        budget.consume()
        while (event.timestamp_value - ordered[left].timestamp_value).total_seconds() > seconds:
            budget.consume()
            left += 1
        size = right - left + 1
        if size > best_size:
            best_left = left
            best_right = right + 1
            best_size = size
    return ordered[best_left:best_right]


def evaluate(profile: Profile, events: list[Event], invalid_input: bool) -> list[dict[str, Any]]:
    budget = EvaluationBudget(MAX_EVALUATION_STEPS)
    results: list[dict[str, Any]] = []
    for signal in profile.signals:
        matched: list[Event] = []
        for event in events:
            budget.consume()
            for rule in signal.rules:
                if _matches_rule(event, rule, budget):
                    matched.append(event)
                    break
        qualifying = matched
        if signal.window_seconds is not None:
            qualifying = _best_window(matched, signal.window_seconds, budget)
        observed = len(qualifying) >= signal.min_count
        evidence_source = qualifying if signal.window_seconds is not None else matched
        result: dict[str, Any] = {
            "id": signal.signal_id,
            "title": signal.title,
            "status": "invalid" if invalid_input else ("observed" if observed else "missing"),
            "attack_techniques": list(signal.attack_techniques),
            "min_count": signal.min_count,
            "matched_event_count": len(matched),
            "qualifying_event_count": len(qualifying),
            "evidence": [
                {"event_index": event.index, "timestamp": event.timestamp}
                for event in evidence_source[:MAX_EVIDENCE]
            ],
        }
        if signal.window_seconds is not None:
            result["window_seconds"] = signal.window_seconds
        results.append(result)
    return results


def _invalid_report(profile_path: Path, issues: Sequence[Issue]) -> dict[str, Any]:
    del profile_path
    return {
        "schema_version": 1,
        "status": "invalid",
        "profile": {"id": None, "title": "Invalid profile"},
        "disclaimer": DISCLAIMER,
        "input": {
            "record_count": 0,
            "valid_event_count": 0,
            "invalid_event_count": 0,
            "issue_count": len(issues),
        },
        "summary": {"observed": 0, "missing": 0, "invalid": 0},
        "signals": [],
        "issues": [issue.as_dict() for issue in issues],
    }


def build_report(
    profile: Profile,
    results: list[dict[str, Any]],
    issues: Sequence[Issue],
    record_count: int,
    valid_event_count: int,
) -> dict[str, Any]:
    counts = {
        state: sum(result["status"] == state for result in results)
        for state in ("observed", "missing", "invalid")
    }
    status = "invalid" if issues else ("missing" if counts["missing"] else "observed")
    return {
        "schema_version": 1,
        "status": status,
        "profile": {
            "id": profile.profile_id,
            "title": profile.title,
            "description": profile.description,
        },
        "disclaimer": DISCLAIMER,
        "input": {
            "record_count": record_count,
            "valid_event_count": valid_event_count,
            "invalid_event_count": record_count - valid_event_count,
            "issue_count": len(issues),
        },
        "summary": counts,
        "signals": results,
        "issues": [issue.as_dict() for issue in issues],
    }


def _markdown_text(value: Any) -> str:
    """Render untrusted display text without active Markdown or raw HTML."""

    text = str(value).replace("\r", " ").replace("\n", " ")
    text = "".join(character if ord(character) >= 32 and ord(character) != 127 else " " for character in text)
    return re.sub(r"([\\`*_{}\[\]()<>#+.!|~-])", r"\\\1", text)


def markdown_report(report: dict[str, Any]) -> str:
    profile = report["profile"]
    lines = [
        f"# {_markdown_text(profile.get('title') or 'Telemetry validation')}",
        "",
        f"**Assessment:** `{report['status']}`  ",
        f"**Profile ID:** `{profile.get('id') or 'invalid'}`  ",
        "",
        report["disclaimer"],
        "",
        "## Summary",
        "",
        "| Observed | Missing | Invalid | Valid events | Invalid events | Input issues |",
        "|---:|---:|---:|---:|---:|---:|",
        (
            f"| {report['summary']['observed']} | {report['summary']['missing']} | "
            f"{report['summary']['invalid']} | {report['input']['valid_event_count']} | "
            f"{report['input']['invalid_event_count']} | {report['input']['issue_count']} |"
        ),
        "",
    ]
    if report["signals"]:
        lines.extend(["## Signals", ""])
        for signal in report["signals"]:
            techniques = ", ".join(f"`{item}`" for item in signal["attack_techniques"]) or "None"
            lines.extend(
                [
                    f"### {_markdown_text(signal['title'])}",
                    "",
                    f"- ID: `{signal['id']}`",
                    f"- Status: `{signal['status']}`",
                    f"- ATT&CK techniques: {techniques}",
                    f"- Matches: {signal['matched_event_count']} (minimum {signal['min_count']})",
                ]
            )
            if "window_seconds" in signal:
                lines.append(
                    f"- Best window: {signal['qualifying_event_count']} records within "
                    f"{signal['window_seconds']} seconds"
                )
            if signal["evidence"]:
                lines.extend(["- Evidence (index and timestamp only):", ""])
                for item in signal["evidence"]:
                    lines.append(f"  - Event {item['event_index']}: `{item['timestamp']}`")
            else:
                lines.append("- Evidence: none")
            lines.append("")
    if report["issues"]:
        lines.extend(["## Input issues", ""])
        for issue in report["issues"]:
            location = f" on line {issue['line']}" if "line" in issue else ""
            lines.append(f"- `{issue['code']}`{location}: {issue['message']}")
        lines.append("")
    lines.extend(
        [
            "## Privacy",
            "",
            "The report contains no event payload values. Evidence is limited to input line indexes and timestamps.",
            "",
        ]
    )
    return "\n".join(lines)


def _prepare_private_output_dir(output_dir: Path) -> None:
    if ".." in output_dir.parts:
        raise ValidationError("output_io", "output path cannot contain '..'")
    absolute = output_dir if output_dir.is_absolute() else Path.cwd() / output_dir
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            item_stat = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(item_stat.st_mode):
            raise ValidationError("output_io", "output path cannot contain symlinks")
        if not stat.S_ISDIR(item_stat.st_mode):
            raise ValidationError("output_io", "output path component is not a directory")

    try:
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_stat = output_dir.lstat()
    except OSError as exc:
        raise ValidationError("output_io", "output directory could not be created") from exc
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
        raise ValidationError("output_io", "output path must be a real directory")
    if hasattr(os, "getuid") and directory_stat.st_uid != os.getuid():
        raise ValidationError("output_io", "output directory must be owned by the current user")
    if stat.S_IMODE(directory_stat.st_mode) & 0o077:
        raise ValidationError("output_io", "output directory must not grant group/other permissions")


def _write_private_exclusive(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_reports(output_dir: Path, report: dict[str, Any]) -> None:
    created: list[Path] = []
    try:
        _prepare_private_output_dir(output_dir)
        json_path = output_dir / "report.json"
        markdown_path = output_dir / "report.md"
        for path in (json_path, markdown_path):
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise ValidationError("output_io", "report output already exists")
        _write_private_exclusive(
            json_path,
            json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
        )
        created.append(json_path)
        _write_private_exclusive(markdown_path, markdown_report(report))
        created.append(markdown_path)
    except ValidationError:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    except (OSError, UnicodeError) as exc:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ValidationError("output_io", "reports could not be written") from exc


def _default_profile_path() -> Path:
    return Path(__file__).resolve().parent / "profiles" / "windows-logging-health.json"


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline validation of normalized Windows security event JSONL exports."
    )
    parser.add_argument("--events", required=True, type=Path, help="local normalized JSONL export")
    parser.add_argument(
        "--profile", type=Path, default=_default_profile_path(), help="local profile JSON"
    )
    parser.add_argument("--output", required=True, type=Path, help="directory for report.json and report.md")
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    try:
        profile = load_profile(args.profile)
    except ValidationError as exc:
        report = _invalid_report(args.profile, [Issue(exc.code, exc.message)])
        try:
            write_reports(args.output, report)
        except ValidationError as output_exc:
            print(f"error: {output_exc.message}", file=sys.stderr)
        print(f"invalid profile: {exc.message}", file=sys.stderr)
        return EXIT_INVALID

    try:
        events, issues, record_count = load_events(args.events)
        results = evaluate(profile, events, bool(issues))
        report = build_report(profile, results, issues, record_count, len(events))
        write_reports(args.output, report)
    except ValidationError as exc:
        report = _invalid_report(args.profile, [Issue(exc.code, exc.message)])
        try:
            write_reports(args.output, report)
        except ValidationError:
            pass
        print(f"invalid input: {exc.message}", file=sys.stderr)
        return EXIT_INVALID

    print(
        f"{report['status']}: {report['summary']['observed']} observed, "
        f"{report['summary']['missing']} missing, {report['summary']['invalid']} invalid"
    )
    if issues:
        return EXIT_INVALID
    if report["summary"]["missing"]:
        return EXIT_MISSING
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(run())
