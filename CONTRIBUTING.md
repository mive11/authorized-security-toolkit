# Contributing

Contributions should improve authorized assessment, detection, validation or reporting workflows.

## Requirements

- Add fixture-based offline tests for success, malformed input, limits and partial failure.
- Keep runtime dependencies at zero unless a feature cannot be implemented safely with the standard library.
- Document all network destinations, write locations, resource budgets and exit codes.
- Preserve deny-first scope behavior and evidence provenance.
- Use synthetic examples without client names, credentials, flags, real employee information or production logs.

Features for security-control bypass, stealth payload delivery, persistence, credential theft, destructive actions or autonomous exploitation are outside the repository's scope.

Run the full suite before proposing a change:

```bash
python3 scripts/test_all.py
```

Explain the concrete security problem, the final behavior and the validation performed. Include limitations that affect how an operator should interpret the output.
