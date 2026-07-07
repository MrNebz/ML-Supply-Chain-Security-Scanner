"""
Generates a live, interactive HTML test report (pass/fail detail per test)
plus an HTML coverage report, from the actual current test suite -- not a
static snapshot. Re-run any time after changing code or tests.

Run with: python scripts/generate_test_report.py
Then open: test_report.html and htmlcov/index.html
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--html=test_report.html",
            "--self-contained-html",
            "--cov=mlscan",
            "--cov-report=html",
            "-v",
        ],
        cwd=ROOT,
    )
    print(f"\nWrote {ROOT / 'test_report.html'}")
    print(f"Wrote {ROOT / 'htmlcov' / 'index.html'}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
