# Architecture and trust boundaries

The toolkit treats configuration, target strings, exported telemetry and finding evidence as untrusted input. Each utility performs one job and exchanges JSON or line-oriented text through documented files rather than importing another tool's internals.

```text
engagement policy ──> ScopeGuard ──> allow/deny decision + audit chain

public providers ──> Passive Inventory ──> evidence-backed host observations

exported events ──> Telemetry Validator ──> observed/missing ATT&CK signals

sanitized findings ──> ReportForge ──> Markdown + SARIF
```

## Invariants

1. Scope decisions are fail-closed and deny rules take precedence.
2. Offline tools do not perform DNS resolution or network access.
3. Passive inventory has a closed provider list, blocks redirects and never connects to target names.
4. An absent event or asset is reported as missing or unknown; collection errors never become clean results.
5. Raw event bodies, command lines, credentials and tokens are excluded from evidence output.
6. Generated artifacts use private permissions and are written atomically or exclusively.
7. Synthetic fixtures are the only data used by tests and demonstrations.

## Threats considered

- target confusion through Unicode, URL userinfo, suffix tricks, ports or CIDR boundaries;
- path traversal and accidental overwrite of reports or policies;
- secret leakage through URLs, event fields, exception strings or report evidence;
- forged or malformed JSON/JSONL and unexpectedly large provider responses;
- partial provider failure and misleading “zero result” conclusions;
- ambient proxy variables and redirect-based changes in network destination;
- audit-log deletion, reordering or modification after a scope decision.

## Trust assumptions

- The operator controls the local account and protects engagement input files.
- Public data providers can observe queries and can return malformed or incomplete data.
- A valid policy describes authorization but does not replace a signed rules-of-engagement document.
- Synthetic telemetry proves parser and expectation behavior, not the completeness of a real sensor deployment.
- SARIF consumers may render Markdown differently and should treat report strings as untrusted text.

## Evidence model

Evidence answers three questions: what was observed, where it came from and when it was observed. A source failure stays attached to its source. Historical records carry historical timestamps. Scope audit entries bind normalized input and policy identity to a decision. Reports use stable finding identifiers so later versions can be compared without relying on titles.
