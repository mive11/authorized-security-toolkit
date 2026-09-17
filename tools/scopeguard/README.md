# ScopeGuard

ScopeGuard is a small, portfolio-ready authorization gate for red-team workflows. It answers one narrow question before another tool acts: **is this exact target authorized by the current engagement policy?**

ScopeGuard es local y *fail closed*. No resuelve DNS, no abre sockets, no escanea y no ejecuta otras herramientas. Solo analiza URLs, dominios e IPs literales y los compara con una política JSON local. Un objetivo inválido, una política caducada o una auditoría manipulada producen error y nunca una autorización.

## Quick start / inicio rápido

Requires Python 3.10+ and uses only the standard library.

```bash
cd redteam-portfolio/tools/scopeguard
python3 scopeguard.py \
  --policy example-policy.json \
  --pretty \
  example.com https://api.example.com 192.0.2.10
```

Targets can also come from a UTF-8 newline file. Positional targets and file targets are combined; blank lines are ignored.
Target files must be regular files and are read with bounded lines. Policies accept at most 1,024 entries in each domain, CIDR and port rule list, and a global comparison budget rejects oversized policy/target combinations before evaluation.

```bash
python3 scopeguard.py \
  --policy example-policy.json \
  --input-file targets.txt \
  --audit-log scopeguard-audit.jsonl
```

To use standard input:

```bash
printf '%s\n' 'https://example.com' '192.0.2.25' | \
  python3 scopeguard.py --policy example-policy.json --input-file -
```

The command always writes a JSON document to standard output. Raw candidate strings are never echoed or written to the audit log. Each decision carries a 1-based `candidate_index` and an `input_sha256` fingerprint; a URL's displayed `normalized` value contains only its scheme and authority, never its path or query. This makes results correlatable without persisting credentials or tokens embedded in input. Exit codes are stable and designed for shell/CI gates:

| Exit | Meaning |
|---:|---|
| `0` | Every candidate is valid and allowed |
| `2` | Invalid target, policy/configuration error, input error, or audit failure |
| `3` | At least one valid candidate is denied and none is invalid |

If invalid and denied candidates appear together, exit `2` wins. This keeps malformed input from being treated as an ordinary out-of-scope result.

## Policy model / modelo de política

See [`example-policy.json`](example-policy.json). The schema is intentionally strict: required and unknown keys, duplicate JSON keys, malformed CIDRs, invalid ranges, and expired policies are rejected. Policy reads are bounded to 1 MiB. Each `ports` array accepts at most 1,024 entries; ranges are merged into compact intervals instead of being expanded into individual ports.

```json
{
  "schema_version": 1,
  "engagement_id": "ENG-2026-042",
  "expires_at": "2099-12-31T23:59:59Z",
  "allow": {
    "domains": ["example.com", "*.example.com"],
    "cidrs": ["192.0.2.0/24", "2001:db8::/32"],
    "ports": [80, 443, "8000-8010"]
  },
  "deny": {
    "domains": ["admin.example.com"],
    "cidrs": ["192.0.2.240/28"],
    "ports": [8005]
  }
}
```

Domain rules are explicit:

- `example.com` matches only that exact normalized domain.
- `*.example.com` matches descendants such as `api.example.com`, but not the apex itself.
- Matching uses DNS label boundaries, so neither rule matches `notexample.com` or `example.com.attacker.test`.
- Unicode domain names are normalized to lowercase IDNA ASCII. A single final DNS dot is removed.

CIDRs must be canonical networks: `192.0.2.0/24` is accepted, while `192.0.2.7/24` is rejected because host bits are set. Literal IPv4 and IPv6 candidates are compared directly; hostnames are never resolved.

Port rules apply to URLs. ScopeGuard derives the effective port (`80` for HTTP, `443` for HTTPS) when a URL omits it. Bare domains and bare IPs represent host scope only and therefore have `port: null`; use a URL when a workflow needs host-and-port authorization. The ambiguous shorthand `example.com:443` is rejected.

`deny` always wins. This includes overlapping ranges, such as an allowed `/24` containing a denied `/28`, and a denied port on an otherwise allowed host.

## URL hardening

Only `http://` and `https://` URLs are accepted. ScopeGuard rejects URL userinfo, fragments (including empty `#` fragments), backslashes, control/whitespace characters, empty or invalid ports, unbracketed IPv6 URL hosts, IPv6 zone identifiers, IDNA spellings that change under a Unicode round-trip, and ambiguous host/port strings. URL hosts are normalized before matching. Paths and queries do not expand authorization: the decision is based on normalized host plus effective port, and path/query values are never emitted.

These rules deliberately favor a false denial over accidentally authorizing a confusing target.

## Tamper-evident audit / auditoría encadenada

`--audit-log PATH` appends one JSONL record per run. Each record contains the prior SHA-256 hash and its own hash over canonical JSON. Before appending, ScopeGuard locks and verifies the complete chain.

New logs are created atomically with mode `0600`. Existing logs must be regular files owned by the current user, have exactly one hard link, and grant no group/other permissions. Symlinks are rejected on supported POSIX systems. Audit verification is bounded to 16 MiB; rotate or anchor the log before it reaches that size. Non-finite JSON constants such as `NaN` and `Infinity` are rejected. Any failed integrity, resource-limit, serialization, or file-safety check makes the command exit `2` with JSON output.

The chain reveals edits, insertion, and reordering within the file. Like any unanchored local hash chain, it cannot by itself prove that an attacker with write access did not replace or truncate the entire file. For stronger evidence, periodically store the latest `entry_hash` in a separate trusted system.

## Tests

The suite uses no network and no subprocesses:

```bash
python3 -m unittest discover -s tests -v
```

It covers IDNA normalization, exact wildcard boundaries, IPv4/IPv6 scopes, overlapping deny rules, effective/default ports, hostile or ambiguous URLs, expiration, CLI exit precedence, private audit permissions, chaining, and tamper detection.

## Portfolio note

This project demonstrates a useful defensive control around authorized security testing: strict parsing, deterministic policy evaluation, auditability, machine-readable output, and tests. It contains no discovery, exploitation, persistence, evasion, payload, or command-execution capability. Use it only as part of an engagement with documented permission and scope.
