# ReportForge

ReportForge converts a strictly validated assessment JSON file into a deterministic Markdown report and SARIF 2.1.0. It uses only the Python standard library, makes no network calls, and is intended for authorized assessment reporting.

It treats every evidence item as text. It never opens, expands, fetches, or embeds a path or URL found in evidence. Common keyed secrets in evidence are redacted before either report is built, including authorization and cookie headers; password, passphrase, token, API key, client secret, session, private key, access key, and CSRF assignments; URL query values; URL userinfo passwords; and standalone Basic or Bearer credentials. Quoted values and unquoted multiword values are handled. Structured delimiters and following non-secret fields are preserved.

## Run it

Python 3.10 or newer is required.

```bash
python3 reportforge.py example.sanitized.json --output-dir ./report-output
```

The command writes `report.md` and `report.sarif.json`. Output files are created with mode `0600` through a same-directory temporary file and atomic commit. Existing files cause exit code `2`; use `--force` to replace owned regular files after symlink and type checks.

```bash
python3 reportforge.py example.sanitized.json --output-dir ./report-output --force
```

Success returns `0`. Invalid JSON, schema errors, unsafe output paths, and I/O failures return `2`. Validation errors go to standard error. Output directory paths containing `..`, symlink directory components, and symlink output files are rejected.

## Input schema 1.0

The machine-readable shape is in [`schema.json`](schema.json). The built-in validator remains authoritative because it also enforces cross-field dates, HTTPS reference rules, HTML/control-character rejection, unique finding IDs, and safe output behavior without requiring a JSON Schema package.

The root object has exactly three fields:

| Field | Type | Rules |
| --- | --- | --- |
| `schema_version` | string | Exactly `1.0` |
| `engagement` | object | Exact metadata object described below |
| `findings` | array | 0 to 1,000 strict finding objects |

`engagement` has exactly these required fields:

| Field | Type | Rules |
| --- | --- | --- |
| `id` | string | Stable uppercase ID, for example `ENG-2026-001` |
| `name` | string | 1 to 160 characters |
| `client` | string | 1 to 160 characters |
| `assessment_type` | string | 1 to 100 characters |
| `start_date` | string | Canonical `YYYY-MM-DD` |
| `end_date` | string | Canonical `YYYY-MM-DD`, not before start |
| `report_date` | string | Canonical `YYYY-MM-DD`, not before start |
| `classification` | string | `public`, `internal`, `confidential`, or `restricted` |
| `scope` | string array | 1 to 100 unique items; each at most 255 characters |
| `authors` | string array | 1 to 20 unique items; each at most 120 characters |

Every finding requires the following fields. `cves` is the only optional field; unknown fields are rejected.

| Field | Type | Rules |
| --- | --- | --- |
| `id` | string | Unique stable uppercase ID, for example `FIND-001` |
| `title` | string | 1 to 200 characters |
| `severity` | string | `critical`, `high`, `medium`, `low`, or `informational` |
| `status` | string | `open`, `in_progress`, `accepted_risk`, `remediated`, or `false_positive` |
| `asset` | string | 1 to 500 characters |
| `description` | string | 1 to 8,000 characters |
| `evidence` | string array | Up to 100 unique items, each at most 8,000 characters |
| `remediation` | string | 1 to 8,000 characters |
| `references` | string array | Up to 50 unique CVE IDs or credential-free HTTPS URLs |
| `attack_techniques` | string array | Up to 50 unique MITRE ATT&CK IDs in `T1234` or `T1234.001` form |
| `cves` | string array | Optional; up to 50 unique IDs in `CVE-YYYY-NNNN` form |

All strings are single-line, trimmed UTF-8 text. Control/formatting characters and HTML are rejected. IDs, enum values, ATT&CK IDs, and CVEs are case-sensitive. Duplicate JSON keys are rejected, as are `NaN` and other non-standard JSON constants. The input file is limited to 5 MiB.

Reports are sorted by severity and finding ID. They contain no runtime timestamp or random report data, so identical validated input produces byte-identical Markdown and SARIF. The supplied report date is the only report date used.

## Test it

```bash
python3 -m unittest discover -s tests -v
```

The tests cover deterministic output, executive severity counts, SARIF shape, secret redaction, evidence non-dereferencing, strict validation, private permissions, traversal rejection, symlink rejection, and overwrite handling.
