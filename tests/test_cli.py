"""
CLI-level tests: everything else in this suite calls scan_pickle/scan_onnx/
scan_h5 directly as Python functions. Nothing exercised the actual `mlscan`
command a real user or CI pipeline invokes -- argument parsing, exit
codes, --json output shape. These run the CLI as a real subprocess,
exactly like a CI step would.
"""

import json
import subprocess
import sys
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "mlscan.cli", *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )


def test_cli_exits_zero_on_benign_file():
    result = _run_cli(str(FIXTURES_DIR / "benign" / "benign_dict.pkl"))
    assert result.returncode == 0
    assert "no findings" in result.stdout


def test_cli_exits_nonzero_on_malicious_file():
    result = _run_cli(str(FIXTURES_DIR / "malicious" / "reduce_os_system.pkl"))
    assert result.returncode == 1
    assert "CRITICAL" in result.stdout


def test_cli_exits_nonzero_on_unrecognizable_file(tmp_path):
    path = tmp_path / "model.xyz"
    path.write_bytes(b"whatever")
    result = _run_cli(str(path))
    assert result.returncode == 2
    assert "could not determine file format" in result.stdout


def test_cli_json_mode_produces_valid_json_with_expected_shape():
    result = _run_cli("--json", str(FIXTURES_DIR / "malicious" / "reduce_os_system.pkl"))
    assert result.returncode == 1

    report = json.loads(result.stdout)
    assert report["format"] == "pickle"
    assert report["summary"]["total"] == 1
    assert report["summary"]["critical"] == 1
    assert report["findings"][0]["rule_id"] == "PICKLE_DANGEROUS_REDUCE"


def test_cli_json_mode_on_benign_file_has_empty_findings():
    result = _run_cli("--json", str(FIXTURES_DIR / "benign" / "benign_identity.onnx"))
    assert result.returncode == 0

    report = json.loads(result.stdout)
    assert report["findings"] == []
    assert report["summary"]["total"] == 0


def test_cli_detects_renamed_pickle_via_content_sniffing(tmp_path):
    disguised = tmp_path / "totally_a_model.onnx"
    disguised.write_bytes((FIXTURES_DIR / "malicious" / "reduce_os_system.pkl").read_bytes())

    result = _run_cli(str(disguised))
    assert result.returncode == 1
    assert "FORMAT_EXTENSION_MISMATCH" in result.stdout
    assert "PICKLE_DANGEROUS_REDUCE" in result.stdout
