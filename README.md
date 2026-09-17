# Authorized Security Toolkit

[Versión en español](README_ES.md) · [CV text (ES/EN)](CV_TEXT_ES_EN.md)

A small, evidence-driven toolkit for authorized red and purple team engagements. The projects focus on the parts that distinguish professional security work from running isolated commands: scope enforcement, passive asset inventory, telemetry validation and reproducible reporting.

All tools are local-first, dependency-free Python/Bash utilities. They are deliberately designed without payload generation, persistence, credential theft, security-control bypasses or stealth features.

## Included projects

| Project | What it demonstrates | Network behavior |
|---|---|---|
| [Passive Domain Inventory](tools/passive-domain-inventory/) | Certificate Transparency, web archive indexes, RDAP, bounded collection and evidence provenance | Queries approved public data providers; never requests or resolves the target |
| [ScopeGuard](tools/scopeguard/) | Fail-closed authorization, normalized targets, deny precedence and tamper-evident audit logs | Offline only |
| [Telemetry Validator](tools/telemetry-validator/) | Purple-team validation of Windows/Sysmon/PowerShell/Defender logging against ATT&CK-mapped expectations | Offline only; analyzes exported normalized JSONL |
| [ReportForge](tools/reportforge/) | Strict finding validation, secret redaction, executive Markdown and SARIF 2.1.0 output | Offline only |

## Quick validation

```bash
python3 scripts/test_all.py
# Optional: keep a private copy of the synthetic demo artifacts.
python3 scripts/portfolio_demo.py
```

The test runner discovers each project's offline tests, runs them in isolated subprocesses, and then executes the integrated demo in a temporary directory. The optional second command keeps a private demo run under `demo-output/`. Both paths use only the synthetic fixtures bundled with each tool.

## Portfolio narrative

These projects are intended to support concrete interview discussions:

- how a scope gate prevents a valid command from reaching an unauthorized target;
- why Certificate Transparency and archive indexes are historical evidence rather than proof of a live service;
- how a purple team distinguishes “the test executed” from “the expected telemetry was observed”;
- how reports preserve reproducible evidence while stripping secrets;
- how partial provider failure is represented without silently claiming a clean result.

Suggested CV entry:

> Built a Python/Bash authorized-security toolkit covering fail-closed target scoping, passive asset inventory from CT/archive/RDAP metadata, ATT&CK-mapped telemetry validation, and deterministic Markdown/SARIF reporting. Added offline fixtures, secret redaction, evidence provenance and automated tests for failure and boundary conditions.

## Safety and authorization

Use the toolkit only for systems you own or have explicit authorization to assess. The suite does not interpret a target supplied on the command line as proof of authorization: `ScopeGuard` exists to bind engagement policy to every target decision.

The repository does not contain AMSI/ETW patches, EDR bypasses, polymorphic payloads, reverse shells, credential collection, persistence or lateral-movement automation. A useful purple-team counterpart is to validate that security telemetry remains observable and complete; that is the role of Telemetry Validator.

See [SECURITY.md](SECURITY.md) for reporting issues, [PORTFOLIO.md](PORTFOLIO.md) for the development roadmap, and [GUIA_CV_ES.md](GUIA_CV_ES.md) for CV, interview and public-demo material in Spanish.

## Requirements

- Linux with Python 3.10+ for the verified complete workflow
- Bash and POSIX `SIGALRM` support for Passive Domain Inventory
- POSIX `fcntl` support when ScopeGuard audit chaining is enabled
- No third-party Python packages

GitHub Actions validates the suite on Ubuntu. On Windows, use WSL for the complete workflow; native Windows support is not claimed because the passive collector and audit lock rely on POSIX facilities. macOS is expected to provide those facilities but is not part of the current CI matrix.

## License

MIT. See [LICENSE](LICENSE).
