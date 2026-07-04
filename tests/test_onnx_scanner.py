from pathlib import Path

from mlscan.report import Severity
from mlscan.scanners.onnx_scanner import scan_onnx

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_benign_identity_has_no_findings():
    findings = scan_onnx(FIXTURES_DIR / "benign" / "benign_identity.onnx")
    assert findings == []


def test_external_data_path_traversal_is_flagged_critical():
    findings = scan_onnx(FIXTURES_DIR / "malicious" / "external_data_path_traversal.onnx")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "ONNX_EXTERNAL_DATA_PATH_TRAVERSAL"


def test_custom_domain_op_is_flagged_high():
    findings = scan_onnx(FIXTURES_DIR / "malicious" / "custom_domain_op.onnx")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "ONNX_CUSTOM_OPERATOR_DOMAIN"


def test_oversized_tensor_dim_is_flagged_medium():
    # The fixture declares two oversized dimensions ([2**31-1, 2**31-1]),
    # so each dimension is flagged as its own finding.
    findings = scan_onnx(FIXTURES_DIR / "malicious" / "oversized_tensor_dim.onnx")
    assert len(findings) == 2
    assert all(f.severity == Severity.MEDIUM for f in findings)
    assert all(f.rule_id == "ONNX_SUSPICIOUS_TENSOR_DIM" for f in findings)
