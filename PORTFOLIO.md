# Portfolio guide and roadmap

## How to present the projects

Lead with the security problem, the engineering constraint and the evidence:

1. **ScopeGuard:** “A deny-first gate makes the authorization decision before any scanner receives a target. Tests cover suffix confusion, CIDR boundaries, expired engagements and audit tampering.”
2. **Passive Domain Inventory:** “The collector contacts only fixed external data providers, preserves source attribution and labels timeouts as incomplete coverage rather than zero findings.”
3. **Telemetry Validator:** “Synthetic Windows events prove the evaluator can distinguish present, missing and malformed signals without running an attack or disabling controls.”
4. **ReportForge:** “One validated finding model produces deterministic human and SARIF reports while removing credentials, tokens and unsafe markup.”

For LinkedIn or a README demo, publish architecture, test output and synthetic evidence. Do not claim that a payload is “undetectable” or “100% FUD”: those claims are not testable across products and encourage unsafe use.

## Demonstration checklist

- Run `python3 scripts/test_all.py` and show the passing boundary tests.
- Use the synthetic demo; never publish client domains, credentials, flags or unredacted logs.
- Explain one failure case, such as a provider timeout or an expired scope policy.
- Include the exact code version and commands needed to reproduce the result.
- Discuss one limitation honestly. Passive sources are incomplete; telemetry presence does not prove perfect detection; SARIF consumers vary.

## Next high-value projects

The following additions would broaden the portfolio while keeping a detection and validation focus:

- **Offline AD path reviewer:** consume a sanitized BloodHound-style export and explain risky permission paths without performing LDAP queries or lateral movement.
- **Cloud IAM policy linter:** inspect exported AWS/Azure/GCP policy documents for privilege escalation relationships and excessive wildcard permissions.
- **Detection-as-code quality gate:** lint Sigma rules, validate event-field assumptions against fixtures and measure rule coverage.
- **PCAP exposure triage:** offline classification of plaintext authentication metadata, encryption coverage and protocol inventory without exporting credentials.
- **Web evidence recorder:** scope-gated, low-rate HTTP/TLS observations with content hashes and no exploit payloads.
- **Lab regression harness:** launch intentionally vulnerable local fixtures and compare expected detections across scanner versions.
- **Attack-surface change monitor:** compare two passive inventories and emit only evidence-backed additions/removals, marking collection failures separately.
- **SBOM exposure correlator:** match a local SBOM to a pinned vulnerability feed and distinguish version evidence from unverified fingerprints.

Each project should include a threat model, non-goals, fixture-based tests, explicit resource budgets and a machine-readable output contract.
