#!/usr/bin/env python3
"""Run a fully synthetic, offline demonstration of every portfolio tool."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


class DemoError(Exception):
    pass


def run(label: str, command: list[str], expected: set[int], output: Path) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    (output / f"{label}.log").write_text(result.stdout, encoding="utf-8")
    if result.returncode not in expected:
        raise DemoError(f"{label} returned {result.returncode}; inspect {label}.log")
    print(f"[ok] {label}: exit {result.returncode}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic portfolio demonstration")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "demo-output",
        help="base directory for a new private demo run",
    )
    args = parser.parse_args(argv)
    old_umask = os.umask(0o077)
    try:
        args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
        output = Path(tempfile.mkdtemp(prefix=stamp, dir=args.output))

        passive = ROOT / "tools" / "passive-domain-inventory"
        run(
            "passive-inventory",
            [
                "bash", str(passive / "recon.sh"), "example.com", "--offline",
                str(passive / "fixtures"), "--output", str(output / "passive"),
            ],
            {0}, output,
        )

        scope = ROOT / "tools" / "scopeguard"
        run(
            "scopeguard",
            [
                sys.executable, "-B", str(scope / "scopeguard.py"), "--policy",
                str(scope / "example-policy.json"), "--audit-log", str(output / "scope-audit.jsonl"),
                "example.com", "https://api.example.com/never-saved?token=SYNTHETIC_SECRET",
                "192.0.2.10",
            ],
            {0}, output,
        )

        telemetry = ROOT / "tools" / "telemetry-validator"
        run(
            "telemetry-validator",
            [
                sys.executable, "-B", str(telemetry / "telemetry_validator.py"), "--events",
                str(telemetry / "fixtures" / "events-complete.jsonl"), "--output",
                str(output / "telemetry"),
            ],
            {0}, output,
        )

        report = ROOT / "tools" / "reportforge"
        run(
            "reportforge",
            [
                sys.executable, "-B", str(report / "reportforge.py"),
                str(report / "example.sanitized.json"), "--output-dir", str(output / "report"),
            ],
            {0}, output,
        )

        expected = [
            output / "scope-audit.jsonl",
            output / "telemetry" / "report.json",
            output / "telemetry" / "report.md",
            output / "report" / "report.md",
            output / "report" / "report.sarif.json",
        ]
        missing = [str(path) for path in expected if not path.is_file()]
        if missing:
            raise DemoError("expected artifacts missing: " + ", ".join(missing))
        combined = "\n".join(path.read_text(encoding="utf-8") for path in output.rglob("*") if path.is_file())
        if "SYNTHETIC_SECRET" in combined:
            raise DemoError("ScopeGuard leaked a synthetic URL token into demo artifacts")
        manifest = {
            "mode": "offline-synthetic",
            "tools": ["passive-domain-inventory", "scopeguard", "telemetry-validator", "reportforge"],
            "output": str(output.resolve()),
            "network_expected": False,
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print("Artifacts: " + str(output.resolve()))
        return 0
    except (OSError, DemoError) as exc:
        print("demo error: " + str(exc), file=sys.stderr)
        return 2
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
