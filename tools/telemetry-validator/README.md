# Telemetry Validator

`telemetry-validator` is an offline portfolio tool that checks a normalized Windows event export against an explicit evidence profile. It helps an analyst answer a narrow question: *does this export contain the records the profile expects?*

It never executes adversary techniques, changes security controls, invokes PowerShell, resolves hosts, or opens network connections. It only reads local JSON/JSONL and writes two local reports.

Presence or absence of records is not proof that an EDR, AMSI, ETW, Defender, or another control worked, failed, or was bypassed. Export filters, retention, collection gaps, forwarding configuration, and ordinary workload activity can all change the result.

## Quick start

Python 3.10 or newer is sufficient; there are no third-party dependencies.

```bash
python3 telemetry_validator.py \
  --events fixtures/events-complete.jsonl \
  --output ./out
```

The included `windows-logging-health` profile is used by default. Select a custom profile with `--profile profile.json`.

The command writes:

- `report.json`, suitable for CI or later processing;
- `report.md`, a CV/portfolio-friendly human review.

The output directory must be private (`0700`), owned by the current user and free of symlink components. A new directory is created with private permissions when needed. Report files are created exclusively as `0600`; existing files are never overwritten. Use a new output directory for each run.

Reports contain profile metadata, aggregate counts, ATT&CK technique IDs, and evidence limited to event line indexes and timestamps. They never copy event payload values into either report.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Every expected signal was observed. |
| `2` | The profile or at least one input record was invalid, or a file could not be processed. |
| `3` | Input was valid, but one or more expected signals were missing or partial. |

Invalid input takes precedence. When any JSONL record is invalid, signal results are marked `invalid` because the export cannot be treated as a complete valid dataset.

## Normalized event format

Each non-blank JSONL line must be one JSON object:

```json
{
  "timestamp": "2026-01-15T12:00:02Z",
  "provider": "Microsoft-Windows-Sysmon",
  "event_id": 1,
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "data": {
    "Image": "C:\\Lab\\benign.exe"
  }
}
```

`timestamp` must be ISO-8601. A timezone-free timestamp is interpreted as UTC. `event_id` may be a non-negative integer or decimal string. `data` must be an object; its contents remain local and are never copied into reports.
Keys inside `data` are matched case-insensitively. An object containing colliding spellings such as `Image` and `image` is rejected at any nesting level so input order cannot change a result.

Blank lines are ignored. Duplicate JSON keys, malformed records, files with no records, and lines larger than 1 MB are invalid.
The complete file is limited to 128 MiB and 100,000 non-blank records. Evaluation also has a fixed work budget, so an oversized combination of events, signals, rules and fields fails closed instead of consuming unbounded CPU or memory.

## Profile format

```json
{
  "schema_version": 1,
  "id": "example-health",
  "title": "Example logging health",
  "description": "Expected records for a controlled validation export.",
  "signals": [
    {
      "id": "process-create",
      "title": "Process creation telemetry",
      "attack_techniques": ["T1059"],
      "any_of": [
        {
          "provider": "Microsoft-Windows-Sysmon",
          "event_id": 1,
          "channel": "Microsoft-Windows-Sysmon/Operational",
          "fields": {
            "Image": {"glob": "*\\fixture.exe"}
          }
        },
        {
          "provider": "Microsoft-Windows-Security-Auditing",
          "event_id": 4688,
          "channel": "Security"
        }
      ],
      "min_count": 2,
      "window": {"seconds": 300}
    }
  ]
}
```

Each `any_of` rule is an alternative; every condition inside one rule must match. `provider` and `channel` are case-insensitive exact matches and may be a string or list. `event_id` may be an integer, decimal string, or list. Field paths are case-insensitive and start within `data`; both `Image` and `data.Image` work. Nested paths use dots.

Field matchers support exactly one operation:

- `equals`: case-insensitive for strings and exact for other scalar values;
- `contains`: case-insensitive substring;
- `glob`: case-insensitive shell-style `*` and `?` matching;
- `regex`: a deliberately small, case-insensitive regular-expression subset.

The regex subset is limited to 128 characters and rejects groups, lookarounds, alternation, backreferences, `*`, `+`, and `?`. It permits anchors, character classes, `.`, common escapes, and at most one bounded repetition such as `{1,3}` with an upper bound of 64. Matching is limited to the first 4,096 characters of a value. Prefer `equals`, `contains`, or `glob` for most profiles.

`min_count` defaults to one. Optional `window` can be an integer number of seconds or `{"seconds": 300}`. With a window, the threshold must be met inside one sliding interval rather than across the whole export.

## Built-in profile

The bundled profile checks record presence for PowerShell 4103/4104, Sysmon process creation 1, Security process creation 4688, Microsoft Defender's operational provider, AMSI-related providers, and ETW infrastructure providers. These are evidence-presence checks. A missing result can simply mean that the export did not include the relevant provider or that no triggering workload occurred.

The ATT&CK IDs are coverage context for portfolio review, not a claim that the event proves a technique occurred or was detected.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The fixtures are synthetic. They exercise complete, missing, and invalid exports without interacting with Windows controls or a network.
For identical valid inputs, the JSON and Markdown reports are byte-identical; runtime timestamps are intentionally excluded.
