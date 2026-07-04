"""
Regression tests for a real bug class: all three scanners used to crash
with an unhandled exception on malformed/garbage input (discovered while
preparing fuzz testing -- see test_fuzzing.py). Every scanner must now
fail gracefully with a *_PARSE_ERROR finding instead.
"""

from mlscan.report import Severity
from mlscan.scanners.h5_scanner import scan_h5
from mlscan.scanners.onnx_scanner import scan_onnx

_GARBAGE = bytes((i * 37 + 11) % 256 for i in range(200))


def test_onnx_scanner_does_not_crash_on_garbage(tmp_path):
    path = tmp_path / "garbage.onnx"
    path.write_bytes(_GARBAGE)

    findings = scan_onnx(path)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "ONNX_PARSE_ERROR"


def test_h5_scanner_does_not_crash_on_garbage(tmp_path):
    path = tmp_path / "garbage.h5"
    path.write_bytes(_GARBAGE)

    findings = scan_h5(path)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "H5_PARSE_ERROR"


def test_h5_scanner_does_not_crash_on_invalid_model_config_json(tmp_path):
    import h5py

    path = tmp_path / "bad_config.h5"
    with h5py.File(path, "w") as f:
        f.attrs["model_config"] = "{not valid json"

    findings = scan_h5(path)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].rule_id == "H5_PARSE_ERROR"


def test_onnx_scanner_does_not_crash_on_invalid_utf8_external_data_location(tmp_path):
    # Regression test for a real bug found via fuzz-testing (mutating a
    # real external_data fixture): protobuf can hand back raw `bytes`
    # instead of `str` for a "string" field when the underlying bytes
    # aren't valid UTF-8 (the C++/upb parser doesn't always validate
    # strictly). This is directly attacker-craftable, not just a fuzzing
    # curiosity -- an attacker could corrupt external_data.location's
    # UTF-8 specifically to crash a scanner that assumes str, as an
    # evasion technique.
    #
    # We corrupt real serialized bytes (rather than assigning through the
    # high-level protobuf API, which enforces str) to faithfully
    # reproduce how the fuzz harness found this: by mutating an
    # already-valid fixture's raw bytes on disk.
    from pathlib import Path

    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    original = (fixtures_dir / "malicious" / "external_data_path_traversal.onnx").read_bytes()

    marker = b"../../../../etc/passwd"
    offset = original.index(marker)
    corrupted = bytearray(original)
    corrupted[offset + 2] = 0x89  # invalid UTF-8 continuation byte, no leading byte
    path = tmp_path / "invalid_utf8.onnx"
    path.write_bytes(bytes(corrupted))

    from mlscan.scanners.onnx_scanner import scan_onnx

    findings = scan_onnx(path)
    assert isinstance(findings, list)  # must not crash; content may vary post-mutation
