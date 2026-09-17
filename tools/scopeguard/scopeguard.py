#!/usr/bin/env python3
"""ScopeGuard: offline, fail-closed authorization checks for red-team targets.

ScopeGuard never resolves a hostname and never opens a network connection.  It
only compares normalized candidate targets with a local JSON policy.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any, Iterable, Sequence, TextIO


EXIT_ALLOWED = 0
EXIT_INVALID = 2
EXIT_DENIED = 3
SCHEMA_VERSION = 1
MAX_POLICY_BYTES = 1024 * 1024
MAX_AUDIT_BYTES = 16 * 1024 * 1024
MAX_PORT_RULE_ENTRIES = 1024
MAX_DOMAIN_RULES = 1024
MAX_CIDR_RULES = 1024
MAX_TARGETS = 10_000
MAX_TARGET_LENGTH = 4096
MAX_TARGET_LINE_BYTES = MAX_TARGET_LENGTH * 4 + 2
MAX_TARGET_FILE_BYTES = MAX_TARGETS * MAX_TARGET_LINE_BYTES
MAX_SCOPE_COMPARISONS = 5_000_000
GENESIS_HASH = "0" * 64
SUPPORTED_SCHEMES = {"http": 80, "https": 443}
ENGAGEMENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
ASCII_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
LEGACY_IP_RE = re.compile(
    r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}\Z",
    re.IGNORECASE,
)
UTC_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z"
)


class ScopeGuardError(Exception):
    """Base class for controlled ScopeGuard failures."""

    code = "scopeguard_error"


class PolicyError(ScopeGuardError):
    code = "invalid_policy"


class CandidateError(ScopeGuardError):
    code = "invalid_target"

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class InputError(ScopeGuardError):
    code = "invalid_input"


class AuditError(ScopeGuardError):
    code = "audit_error"


class CliUsageError(ScopeGuardError):
    code = "usage_error"


class JsonArgumentParser(argparse.ArgumentParser):
    """Make argument failures available to the JSON error path."""

    def error(self, message: str) -> None:
        del message
        raise CliUsageError("invalid command-line arguments; use --help for usage")


@dataclasses.dataclass(frozen=True)
class DomainRule:
    base: str
    wildcard: bool

    @property
    def text(self) -> str:
        return f"*.{self.base}" if self.wildcard else self.base

    def matches(self, host: str) -> bool:
        if self.wildcard:
            return host != self.base and host.endswith("." + self.base)
        return host == self.base


@dataclasses.dataclass(frozen=True)
class PortRules:
    """Compact, sorted, non-overlapping inclusive port intervals."""

    ranges: tuple[tuple[int, int], ...]

    def __contains__(self, port: object) -> bool:
        if isinstance(port, bool) or not isinstance(port, int):
            return False
        for start, end in self.ranges:
            if port < start:
                return False
            if port <= end:
                return True
        return False


@dataclasses.dataclass(frozen=True)
class Policy:
    engagement_id: str
    expires_at: dt.datetime
    expires_at_text: str
    allow_domains: tuple[DomainRule, ...]
    deny_domains: tuple[DomainRule, ...]
    allow_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    deny_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allow_ports: PortRules
    deny_ports: PortRules
    sha256: str


@dataclasses.dataclass(frozen=True)
class Target:
    raw: str
    kind: str
    normalized: str
    host: str
    port: int | None
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    scheme: str | None = None


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _format_utc(value: dt.datetime) -> str:
    value = value.astimezone(dt.timezone.utc)
    if value.microsecond:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _contains_control_or_whitespace(value: str) -> bool:
    return any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> None:
    """Reject JSON extensions such as NaN and Infinity."""

    raise ValueError(f"non-finite JSON constant is not allowed: {value}")


def _require_object_keys(
    value: Any, expected: set[str], location: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{location} must be a JSON object")
    keys = set(value)
    missing = sorted(expected - keys)
    unknown = sorted(keys - expected)
    if missing:
        raise PolicyError(f"{location} is missing keys: {', '.join(missing)}")
    if unknown:
        raise PolicyError(f"{location} has unknown keys: {', '.join(unknown)}")
    return value


def _require_list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"{location} must be a JSON array")
    return value


def _normalize_domain_text(value: str, *, wildcard_ok: bool) -> DomainRule:
    if not isinstance(value, str):
        raise PolicyError("domain rules must be strings")
    if not value or value != value.strip():
        raise PolicyError(f"domain rule has empty or surrounding whitespace: {value!r}")
    if _contains_control_or_whitespace(value):
        raise PolicyError(f"domain rule contains whitespace or control characters: {value!r}")

    wildcard = value.startswith("*.")
    if wildcard:
        if not wildcard_ok:
            raise PolicyError("wildcards are not valid candidate targets")
        value = value[2:]
    if "*" in value:
        raise PolicyError("only a leading '*.' wildcard is supported in domain rules")
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > 253:
        raise PolicyError("domain rule is empty or longer than 253 characters")

    try:
        ascii_domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError(f"domain rule is not valid IDNA: {value!r}") from exc

    # Python's built-in codec follows IDNA 2003 and can map distinct Unicode
    # input to a different spelling (for example, sharp-s to "ss"). Reject
    # non-ASCII input unless its Unicode spelling survives a decode round-trip.
    try:
        decoded_domain = ascii_domain.encode("ascii").decode("idna")
        reencoded_domain = decoded_domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError(f"domain rule fails IDNA round-trip: {value!r}") from exc
    if reencoded_domain != ascii_domain:
        raise PolicyError(f"domain rule fails IDNA round-trip: {value!r}")
    if any(ord(char) > 127 for char in value):
        original_unicode = unicodedata.normalize("NFC", value).lower()
        decoded_unicode = unicodedata.normalize("NFC", decoded_domain).lower()
        if original_unicode != decoded_unicode:
            raise PolicyError(f"domain rule is ambiguous under IDNA normalization: {value!r}")

    labels = ascii_domain.split(".")
    if any(not ASCII_LABEL_RE.fullmatch(label) for label in labels):
        raise PolicyError(f"domain rule has an invalid label: {value!r}")
    if len(ascii_domain) > 253:
        raise PolicyError("normalized domain rule is longer than 253 characters")
    if LEGACY_IP_RE.fullmatch(ascii_domain):
        raise PolicyError("IP-like values belong in canonical CIDR rules")
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        raise PolicyError("IP literals belong in CIDR rules, not domain rules")
    return DomainRule(ascii_domain, wildcard)


def _load_domain_rules(value: Any, location: str) -> tuple[DomainRule, ...]:
    items = _require_list(value, location)
    if len(items) > MAX_DOMAIN_RULES:
        raise PolicyError(f"{location} exceeds the limit of {MAX_DOMAIN_RULES} entries")
    rules = []
    seen = set()
    for item in items:
        rule = _normalize_domain_text(item, wildcard_ok=True)
        if rule.text not in seen:
            rules.append(rule)
            seen.add(rule.text)
    return tuple(rules)


def _load_cidrs(
    value: Any, location: str
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    items = _require_list(value, location)
    if len(items) > MAX_CIDR_RULES:
        raise PolicyError(f"{location} exceeds the limit of {MAX_CIDR_RULES} entries")
    networks = []
    seen = set()
    for item in items:
        if not isinstance(item, str) or not item or item != item.strip():
            raise PolicyError(f"{location} entries must be non-empty strings")
        if "%" in item or _contains_control_or_whitespace(item):
            raise PolicyError(f"invalid CIDR in {location}: {item!r}")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise PolicyError(f"invalid or non-canonical CIDR in {location}: {item!r}") from exc
        key = (network.version, network.network_address, network.prefixlen)
        if key not in seen:
            networks.append(network)
            seen.add(key)
    return tuple(networks)


def _load_ports(value: Any, location: str) -> PortRules:
    items = _require_list(value, location)
    if len(items) > MAX_PORT_RULE_ENTRIES:
        raise PolicyError(
            f"{location} exceeds the limit of {MAX_PORT_RULE_ENTRIES} entries"
        )
    intervals: list[tuple[int, int]] = []
    for item in items:
        if isinstance(item, bool):
            raise PolicyError(f"boolean is not a valid port in {location}")
        if isinstance(item, int):
            start = end = item
        elif isinstance(item, str) and re.fullmatch(r"[0-9]+-[0-9]+", item):
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if str(start) != start_text or str(end) != end_text:
                raise PolicyError(f"non-canonical port range in {location}: {item!r}")
        else:
            raise PolicyError(
                f"ports in {location} must be integers or canonical 'start-end' ranges"
            )
        if not 1 <= start <= end <= 65535:
            raise PolicyError(f"port or range outside 1..65535 in {location}: {item!r}")
        intervals.append((start, end))

    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return PortRules(tuple(merged))


def _parse_expiry(value: Any) -> tuple[dt.datetime, str]:
    if not isinstance(value, str) or not UTC_TIMESTAMP_RE.fullmatch(value):
        raise PolicyError("expires_at must be an RFC 3339 UTC timestamp ending in 'Z'")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PolicyError("expires_at is not a valid UTC timestamp") from exc
    return parsed, _format_utc(parsed)


def load_policy(path: str | os.PathLike[str], *, now: dt.datetime | None = None) -> Policy:
    """Read and strictly validate a ScopeGuard JSON policy."""

    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        file_info = os.fstat(descriptor)
        if not stat.S_ISREG(file_info.st_mode):
            raise PolicyError("policy input must be a regular file")
        file_size = file_info.st_size
        if file_size > MAX_POLICY_BYTES:
            raise PolicyError(f"policy exceeds {MAX_POLICY_BYTES} bytes")
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            raw = stream.read(MAX_POLICY_BYTES + 1)
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(f"cannot read policy: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy exceeds {MAX_POLICY_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError("policy must be UTF-8") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except PolicyError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from exc

    top = _require_object_keys(
        document,
        {"schema_version", "engagement_id", "expires_at", "allow", "deny"},
        "policy",
    )
    if isinstance(top["schema_version"], bool) or top["schema_version"] != SCHEMA_VERSION:
        raise PolicyError(f"schema_version must be {SCHEMA_VERSION}")
    engagement_id = top["engagement_id"]
    if not isinstance(engagement_id, str) or not ENGAGEMENT_ID_RE.fullmatch(engagement_id):
        raise PolicyError(
            "engagement_id must be 1..128 safe ASCII characters and start alphanumeric"
        )

    expires_at, expires_at_text = _parse_expiry(top["expires_at"])
    current = now or _utc_now()
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if expires_at <= current.astimezone(dt.timezone.utc):
        raise PolicyError("policy has expired")

    allow = _require_object_keys(top["allow"], {"domains", "cidrs", "ports"}, "allow")
    deny = _require_object_keys(top["deny"], {"domains", "cidrs", "ports"}, "deny")
    allow_domains = _load_domain_rules(allow["domains"], "allow.domains")
    deny_domains = _load_domain_rules(deny["domains"], "deny.domains")
    allow_cidrs = _load_cidrs(allow["cidrs"], "allow.cidrs")
    deny_cidrs = _load_cidrs(deny["cidrs"], "deny.cidrs")
    allow_ports = _load_ports(allow["ports"], "allow.ports")
    deny_ports = _load_ports(deny["ports"], "deny.ports")

    if not allow_domains and not allow_cidrs:
        raise PolicyError("allow must contain at least one domain or CIDR rule")

    policy_hash = hashlib.sha256(_canonical_json(document).encode("utf-8")).hexdigest()
    return Policy(
        engagement_id=engagement_id,
        expires_at=expires_at,
        expires_at_text=expires_at_text,
        allow_domains=allow_domains,
        deny_domains=deny_domains,
        allow_cidrs=allow_cidrs,
        deny_cidrs=deny_cidrs,
        allow_ports=allow_ports,
        deny_ports=deny_ports,
        sha256=policy_hash,
    )


def _candidate_domain(value: str) -> str:
    if LEGACY_IP_RE.fullmatch(value.rstrip(".")):
        raise CandidateError(
            "malformed_ip_literal",
            "IP-like target is not a canonical IPv4 address",
        )
    try:
        return _normalize_domain_text(value, wildcard_ok=False).base
    except PolicyError as exc:
        raise CandidateError("invalid_domain", "target is not a valid unambiguous IDNA domain") from exc


def _candidate_host(
    value: str,
) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    if "%" in value:
        raise CandidateError("zone_id_not_allowed", "IPv6 zone identifiers are not allowed")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return _candidate_domain(value), None
    return address.compressed, address


def _validate_url_authority(netloc: str) -> None:
    if "@" in netloc:
        raise CandidateError("userinfo_not_allowed", "URL userinfo is not allowed")
    if netloc.startswith("["):
        closing = netloc.find("]")
        if closing < 0:
            raise CandidateError("invalid_url", "IPv6 URL host is missing a closing bracket")
        suffix = netloc[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            raise CandidateError("invalid_port", "URL has an invalid port")
        if suffix == ":":
            raise CandidateError("invalid_port", "URL has an empty port")
    else:
        if netloc.count(":") > 1:
            raise CandidateError("ambiguous_target", "IPv6 URL hosts must use brackets")
        if ":" in netloc:
            port_text = netloc.rsplit(":", 1)[1]
            if not port_text or not port_text.isdigit():
                raise CandidateError("invalid_port", "URL has an invalid port")


def _parse_url(raw: str) -> Target:
    if "\\" in raw:
        raise CandidateError("ambiguous_target", "backslashes are not allowed in URLs")
    if "#" in raw:
        raise CandidateError("fragment_not_allowed", "URL fragments are not allowed")
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        raise CandidateError("invalid_url", "URL cannot be parsed safely") from exc
    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise CandidateError("unsupported_scheme", "only http and https URLs are supported")
    if not parts.netloc:
        raise CandidateError("invalid_url", "URL must include a host")
    _validate_url_authority(parts.netloc)
    try:
        hostname = parts.hostname
        parsed_port = parts.port
    except ValueError as exc:
        raise CandidateError("invalid_port", "URL has an invalid port") from exc
    if not hostname:
        raise CandidateError("invalid_url", "URL must include a host")
    host, address = _candidate_host(hostname)
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise CandidateError("invalid_port", "URL port must be in 1..65535")
    effective_port = parsed_port or SUPPORTED_SCHEMES[scheme]

    display_host = f"[{host}]" if isinstance(address, ipaddress.IPv6Address) else host
    include_port = parsed_port is not None and parsed_port != SUPPORTED_SCHEMES[scheme]
    authority = f"{display_host}:{parsed_port}" if include_port else display_host
    # Authorization is scoped to authority only. Paths and queries may contain
    # credentials or tokens and are intentionally neither echoed nor audited.
    normalized = f"{scheme}://{authority}"
    return Target(
        raw=raw,
        kind="url",
        normalized=normalized,
        host=host,
        port=effective_port,
        address=address,
        scheme=scheme,
    )


def parse_target(raw: str) -> Target:
    """Parse a target without DNS resolution or any other network activity."""

    if not isinstance(raw, str) or not raw:
        raise CandidateError("empty_target", "target is empty")
    if len(raw) > MAX_TARGET_LENGTH:
        raise CandidateError("target_too_long", f"target exceeds {MAX_TARGET_LENGTH} characters")
    if raw != raw.strip() or _contains_control_or_whitespace(raw):
        raise CandidateError(
            "whitespace_or_control", "target contains whitespace or control characters"
        )
    if "%" in raw and "://" not in raw:
        raise CandidateError("zone_id_not_allowed", "zone identifiers are not allowed")

    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is not None:
        return Target(
            raw=raw,
            kind="ip",
            normalized=address.compressed,
            host=address.compressed,
            port=None,
            address=address,
        )
    if "://" in raw:
        return _parse_url(raw)
    if ":" in raw or any(char in raw for char in "/?#@\\"):
        raise CandidateError(
            "ambiguous_target",
            "ambiguous target; use a full http(s) URL for a host and port",
        )
    domain = _candidate_domain(raw)
    return Target(raw=raw, kind="domain", normalized=domain, host=domain, port=None)


def _matching_domain(host: str, rules: Iterable[DomainRule]) -> DomainRule | None:
    return next((rule for rule in rules if rule.matches(host)), None)


def _matching_network(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    return next(
        (
            network
            for network in networks
            if network.version == address.version and address in network
        ),
        None,
    )


def decide(policy: Policy, target: Target) -> dict[str, Any]:
    """Return a deterministic authorization decision. Explicit deny always wins."""

    decision: dict[str, Any] = {
        "input_sha256": hashlib.sha256(target.raw.encode("utf-8")).hexdigest(),
        "normalized": target.normalized,
        "kind": target.kind,
        "host": target.host,
        "port": target.port,
        "status": "denied",
        "allowed": False,
        "reason_code": "",
        "reason": "",
        "matched_rule": None,
    }

    if target.address is None:
        denied = _matching_domain(target.host, policy.deny_domains)
        if denied:
            decision.update(
                reason_code="denied_domain",
                reason="target host matches an explicit domain deny rule",
                matched_rule=denied.text,
            )
            return decision
        allowed = _matching_domain(target.host, policy.allow_domains)
        allow_failure = "domain_not_allowed"
        allow_failure_message = "target host does not match a domain allow rule"
    else:
        denied_network = _matching_network(target.address, policy.deny_cidrs)
        if denied_network:
            decision.update(
                reason_code="denied_cidr",
                reason="target address matches an explicit CIDR deny rule",
                matched_rule=str(denied_network),
            )
            return decision
        allowed = _matching_network(target.address, policy.allow_cidrs)
        allow_failure = "ip_not_allowed"
        allow_failure_message = "target address does not match a CIDR allow rule"

    if target.port is not None and target.port in policy.deny_ports:
        decision.update(
            reason_code="denied_port",
            reason="target port matches an explicit port deny rule",
            matched_rule=str(target.port),
        )
        return decision
    if allowed is None:
        decision.update(reason_code=allow_failure, reason=allow_failure_message)
        return decision
    if target.port is not None and target.port not in policy.allow_ports:
        decision.update(
            reason_code="port_not_allowed",
            reason="target port does not match a port allow rule",
        )
        return decision

    matched = allowed.text if isinstance(allowed, DomainRule) else str(allowed)
    decision.update(
        status="allowed",
        allowed=True,
        reason_code="allowed_by_policy",
        reason="target host and effective port are authorized by policy",
        matched_rule=matched,
    )
    return decision


def evaluate(policy: Policy, candidates: Sequence[str], *, now: dt.datetime) -> dict[str, Any]:
    rule_count = (
        len(policy.allow_domains)
        + len(policy.deny_domains)
        + len(policy.allow_cidrs)
        + len(policy.deny_cidrs)
        + len(policy.allow_ports.ranges)
        + len(policy.deny_ports.ranges)
    )
    if len(candidates) * max(1, rule_count) > MAX_SCOPE_COMPARISONS:
        raise InputError("targets and policy exceed the bounded comparison budget")
    decisions = []
    for candidate_index, raw in enumerate(candidates, start=1):
        try:
            target = parse_target(raw)
            decision = decide(policy, target)
        except CandidateError as exc:
            decision = {
                "input_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "normalized": None,
                "kind": None,
                "host": None,
                "port": None,
                "status": "invalid",
                "allowed": False,
                "reason_code": exc.reason_code,
                "reason": str(exc),
                "matched_rule": None,
            }
        decision["candidate_index"] = candidate_index
        decisions.append(decision)

    allowed_count = sum(item["status"] == "allowed" for item in decisions)
    denied_count = sum(item["status"] == "denied" for item in decisions)
    invalid_count = sum(item["status"] == "invalid" for item in decisions)
    return {
        "schema_version": SCHEMA_VERSION,
        "engagement_id": policy.engagement_id,
        "policy_expires_at": policy.expires_at_text,
        "policy_sha256": policy.sha256,
        "evaluated_at": _format_utc(now),
        "all_allowed": denied_count == 0 and invalid_count == 0,
        "summary": {
            "total": len(decisions),
            "allowed": allowed_count,
            "denied": denied_count,
            "invalid": invalid_count,
        },
        "decisions": decisions,
    }


def result_exit_code(result: dict[str, Any]) -> int:
    if result["summary"]["invalid"]:
        return EXIT_INVALID
    if result["summary"]["denied"]:
        return EXIT_DENIED
    return EXIT_ALLOWED


def _check_audit_fd(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise AuditError("audit log must be a regular file")
    if info.st_nlink != 1:
        raise AuditError("audit log must have exactly one hard link")
    if info.st_mode & 0o077:
        raise AuditError("existing audit log must not grant group or other permissions")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise AuditError("audit log must be owned by the current user")


def _read_fd(fd: int) -> bytes:
    file_size = os.fstat(fd).st_size
    if file_size > MAX_AUDIT_BYTES:
        raise AuditError(f"audit log exceeds {MAX_AUDIT_BYTES} bytes")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while True:
        remaining = MAX_AUDIT_BYTES + 1 - total
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_AUDIT_BYTES:
            raise AuditError(f"audit log exceeds {MAX_AUDIT_BYTES} bytes")
    return b"".join(chunks)


def _verify_audit(data: bytes) -> tuple[int, str]:
    if not data:
        return 0, GENESIS_HASH
    if not data.endswith(b"\n"):
        raise AuditError("audit log is truncated: final newline is missing")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditError("audit log is not UTF-8") from exc

    previous_hash = GENESIS_HASH
    sequence = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise AuditError(f"audit log contains a blank line at {line_number}")
        try:
            record = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_json_constant,
            )
        except Exception as exc:
            raise AuditError(f"invalid audit JSON at line {line_number}") from exc
        if not isinstance(record, dict) or set(record) != {
            "sequence",
            "previous_hash",
            "event",
            "entry_hash",
        }:
            raise AuditError(f"invalid audit record shape at line {line_number}")
        if record["sequence"] != sequence + 1:
            raise AuditError(f"invalid audit sequence at line {line_number}")
        if record["previous_hash"] != previous_hash:
            raise AuditError(f"broken audit hash chain at line {line_number}")
        if not isinstance(record["event"], dict):
            raise AuditError(f"audit event must be an object at line {line_number}")
        base = {
            "sequence": record["sequence"],
            "previous_hash": record["previous_hash"],
            "event": record["event"],
        }
        try:
            canonical_base = _canonical_json(base).encode("utf-8")
        except Exception as exc:
            raise AuditError(
                f"audit record cannot be canonicalized at line {line_number}"
            ) from exc
        expected = hashlib.sha256(canonical_base).hexdigest()
        if record["entry_hash"] != expected:
            raise AuditError(f"audit hash mismatch at line {line_number}")
        sequence = record["sequence"]
        previous_hash = expected
    return sequence, previous_hash


def append_audit(path: str | os.PathLike[str], event: dict[str, Any]) -> dict[str, Any]:
    """Verify and append to a private, locked SHA-256 JSONL hash chain."""

    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - ScopeGuard targets POSIX systems.
        raise AuditError("exclusive audit locking is unavailable on this platform") from exc

    flags = os.O_RDWR | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            fd = os.open(path, flags)
    except OSError as exc:
        raise AuditError(f"cannot securely open audit log: {exc}") from exc

    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        _check_audit_fd(fd)
        data = _read_fd(fd)
        sequence, previous_hash = _verify_audit(data)
        base = {
            "sequence": sequence + 1,
            "previous_hash": previous_hash,
            "event": event,
        }
        try:
            canonical_base = _canonical_json(base).encode("utf-8")
        except Exception as exc:
            raise AuditError("new audit event cannot be canonicalized") from exc
        entry_hash = hashlib.sha256(canonical_base).hexdigest()
        record = dict(base)
        record["entry_hash"] = entry_hash
        try:
            encoded = (_canonical_json(record) + "\n").encode("utf-8")
        except Exception as exc:
            raise AuditError("new audit record cannot be serialized") from exc
        if len(data) + len(encoded) > MAX_AUDIT_BYTES:
            raise AuditError(
                f"audit append would exceed the {MAX_AUDIT_BYTES}-byte limit"
            )
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise AuditError("short write while appending audit log")
            view = view[written:]
        os.fsync(fd)
        return {
            "status": "appended",
            "path": os.path.abspath(os.fspath(path)),
            "created": created,
            "sequence": sequence + 1,
            "entry_hash": entry_hash,
            "previous_hash": previous_hash,
        }
    except AuditError:
        raise
    except OSError as exc:
        raise AuditError(f"cannot append audit log: {exc}") from exc
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _read_candidates(
    positional: Sequence[str], input_file: str | None, stdin: TextIO
) -> list[str]:
    candidates = list(positional)

    def add_line(line: str, line_number: int) -> None:
        if line.endswith("\n"):
            line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
        if line == "":
            return
        if len(line) > MAX_TARGET_LENGTH:
            raise InputError(
                f"target file line {line_number} exceeds {MAX_TARGET_LENGTH} characters"
            )
        candidates.append(line)
        if len(candidates) > MAX_TARGETS:
            raise InputError(f"more than {MAX_TARGETS} targets were provided")

    if input_file is not None:
        if input_file == "-":
            line_number = 0
            try:
                while True:
                    line = stdin.readline(MAX_TARGET_LENGTH + 2)
                    if line == "":
                        break
                    line_number += 1
                    if len(line) > MAX_TARGET_LENGTH + 1 and not line.endswith("\n"):
                        raise InputError(
                            f"target file line {line_number} exceeds {MAX_TARGET_LENGTH} characters"
                        )
                    add_line(line, line_number)
            except UnicodeDecodeError as exc:
                raise InputError("target file must be UTF-8") from exc
        else:
            descriptor = -1
            try:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(input_file, flags)
                file_info = os.fstat(descriptor)
                if not stat.S_ISREG(file_info.st_mode):
                    raise InputError("target input must be a regular file")
                if file_info.st_size > MAX_TARGET_FILE_BYTES:
                    raise InputError(
                        f"target file exceeds {MAX_TARGET_FILE_BYTES} bytes"
                    )
                stream = os.fdopen(descriptor, "rb")
                descriptor = -1
            except InputError:
                raise
            except OSError as exc:
                raise InputError(f"cannot read target file: {exc}") from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            try:
                total_bytes = 0
                line_number = 0
                while True:
                    raw_line = stream.readline(MAX_TARGET_LINE_BYTES + 1)
                    if not raw_line:
                        break
                    line_number += 1
                    total_bytes += len(raw_line)
                    if total_bytes > MAX_TARGET_FILE_BYTES:
                        raise InputError(
                            f"target file exceeds {MAX_TARGET_FILE_BYTES} bytes"
                        )
                    if len(raw_line) > MAX_TARGET_LINE_BYTES:
                        raise InputError(
                            f"target file line {line_number} exceeds the byte limit"
                        )
                    try:
                        line = raw_line.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise InputError("target file must be UTF-8") from exc
                    add_line(line, line_number)
            except OSError as exc:
                raise InputError(f"cannot read target file: {exc}") from exc
            finally:
                stream.close()
    if not candidates:
        raise InputError("provide at least one target argument or --input-file")
    if len(candidates) > MAX_TARGETS:
        raise InputError(f"more than {MAX_TARGETS} targets were provided")
    return candidates


def _build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        prog="scopeguard",
        description="Offline, fail-closed authorization gate for red-team targets.",
    )
    parser.add_argument("--policy", required=True, help="strict JSON authorization policy")
    parser.add_argument(
        "--input-file",
        metavar="PATH",
        help="newline-delimited targets; use '-' for standard input",
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help="append a private, tamper-evident JSONL audit record",
    )
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    parser.add_argument("targets", nargs="*", help="URL, domain, or literal IP candidates")
    return parser


def _error_document(exc: ScopeGuardError) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "error": {"code": exc.code, "message": str(exc)},
    }


def _write_json(document: dict[str, Any], stream: TextIO, *, pretty: bool) -> None:
    json.dump(
        document,
        stream,
        ensure_ascii=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        allow_nan=False,
    )
    stream.write("\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    now: dt.datetime | None = None,
) -> int:
    """CLI entry point. Controlled failures are emitted as JSON on stdout."""

    del stderr  # Reserved for a future diagnostics channel; stdout stays machine-readable.
    pretty = False
    try:
        args = _build_parser().parse_args(argv)
        pretty = args.pretty
        evaluated_at = now or _utc_now()
        if evaluated_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        policy = load_policy(args.policy, now=evaluated_at)
        candidates = _read_candidates(args.targets, args.input_file, stdin)
        result = evaluate(policy, candidates, now=evaluated_at)
        exit_code = result_exit_code(result)
        if args.audit_log:
            event = {
                "event_type": "scopeguard_evaluation",
                "engagement_id": policy.engagement_id,
                "evaluated_at": result["evaluated_at"],
                "policy_sha256": policy.sha256,
                "exit_code": exit_code,
                "summary": result["summary"],
                "decisions": result["decisions"],
            }
            try:
                result["audit"] = append_audit(args.audit_log, event)
            except AuditError as exc:
                result["audit"] = {
                    "status": "error",
                    "code": exc.code,
                    "message": str(exc),
                }
                exit_code = EXIT_INVALID
        _write_json(result, stdout, pretty=pretty)
        return exit_code
    except ScopeGuardError as exc:
        _write_json(_error_document(exc), stdout, pretty=pretty)
        return EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
