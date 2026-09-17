# Security policy

This repository processes target identifiers, exported events and finding evidence. Treat those inputs as untrusted and potentially sensitive.

## Supported usage

- authorized security assessments and owned labs;
- offline analysis of data the operator is allowed to possess;
- synthetic demonstrations and detection validation;
- public-data-provider queries performed by Passive Domain Inventory.

## Non-goals

The project does not accept features whose main purpose is endpoint-security bypass, log suppression, stealth execution, persistence, credential theft, phishing delivery, destructive action or autonomous exploitation.

## Reporting a vulnerability

Open a GitHub issue containing a minimal synthetic reproducer. Do not include real credentials, client data, private targets, access tokens or production logs. If a report would expose such data, replace each value with a stable placeholder and describe the affected code path.

## Data handling

- Keep engagement policies, event exports and generated reports out of public repositories.
- Use the supplied synthetic fixtures for screenshots and demonstrations.
- Review generated reports before sharing them.
- Rotate any credential accidentally included in an input file; redaction reduces exposure but is not a substitute for rotation.
