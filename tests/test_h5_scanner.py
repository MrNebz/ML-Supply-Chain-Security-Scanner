from pathlib import Path

from mlscan.report import Severity
from mlscan.scanners.h5_scanner import scan_h5

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_benign_dense_model_has_no_findings():
    findings = scan_h5(FIXTURES_DIR / "benign" / "benign_dense_model.h5")
    assert findings == []


def test_lambda_marshalled_bytecode_is_flagged_critical():
    findings = scan_h5(FIXTURES_DIR / "malicious" / "lambda_marshalled_bytecode.h5")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "H5_LAMBDA_MARSHALLED_BYTECODE"


def test_lambda_named_function_ref_is_flagged_medium():
    findings = scan_h5(FIXTURES_DIR / "malicious" / "lambda_named_function_ref.h5")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].rule_id == "H5_LAMBDA_NAMED_FUNCTION_REF"
