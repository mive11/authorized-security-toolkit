#!/usr/bin/env python3
"""Run every project test file in a separate process."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    tests = sorted((ROOT / "tools").glob("**/test_*.py"))
    if not tests:
        print("No test files found", file=sys.stderr)
        return 2
    failures = []
    for test in tests:
        relative = test.relative_to(ROOT)
        print(f"\n=== {relative} ===", flush=True)
        result = subprocess.run(
            [sys.executable, "-B", str(test)],
            cwd=test.parent,
            check=False,
        )
        if result.returncode:
            failures.append((str(relative), result.returncode))

    print("\n=== offline portfolio demo ===", flush=True)
    with tempfile.TemporaryDirectory(prefix="portfolio-test-") as temp:
        demo = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "portfolio_demo.py"),
                "--output",
                temp,
            ],
            cwd=ROOT,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
    if demo.returncode:
        failures.append(("scripts/portfolio_demo.py", demo.returncode))

    print(f"\nRan {len(tests)} test files plus the offline demo; failures: {len(failures)}")
    for path, code in failures:
        print(f"- {path}: exit {code}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
