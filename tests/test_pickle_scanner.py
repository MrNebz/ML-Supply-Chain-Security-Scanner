from pathlib import Path

from mlscan.report import Severity
from mlscan.scanners.pickle_scanner import scan_pickle

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_benign_dict_has_no_findings():
    findings = scan_pickle(FIXTURES_DIR / "benign" / "benign_dict.pkl")
    assert findings == []


def test_os_system_reduce_is_flagged_critical():
    findings = scan_pickle(FIXTURES_DIR / "malicious" / "reduce_os_system.pkl")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "PICKLE_DANGEROUS_REDUCE"
    assert "system" in findings[0].message


def test_subprocess_call_reduce_is_flagged_critical():
    findings = scan_pickle(FIXTURES_DIR / "malicious" / "reduce_subprocess_call.pkl")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "PICKLE_DANGEROUS_REDUCE"


def test_gadget_chain_subclasses_is_flagged_critical():
    # Real gadget-chain technique (Huang, Huang & Huang, "Pain Pickle",
    # IEEE QRS 2022): pickle.dumps(int.__subclasses__) naturally produces
    # a getattr(int, "__subclasses__") reduce call -- the standard way to
    # escape restricted unpicklers/sandboxes by walking the live class
    # hierarchy, regardless of which module first exposed it.
    findings = scan_pickle(FIXTURES_DIR / "malicious" / "gadget_chain_subclasses.pkl")
    rule_ids = {f.rule_id for f in findings}
    assert "PICKLE_GADGET_CHAIN_ATTRIBUTE" in rule_ids
    gadget_finding = next(f for f in findings if f.rule_id == "PICKLE_GADGET_CHAIN_ATTRIBUTE")
    assert gadget_finding.severity == Severity.CRITICAL
    assert "__subclasses__" in gadget_finding.message


def test_int_opcode_hex_evasion_is_flagged_not_crashed():
    # Regression test for a real pickletools/pickle discrepancy: this
    # payload crashes pickletools.genops() with a ValueError, but the
    # real deserializers execute it fine. The scanner must surface this
    # as a finding rather than raising, and must not silently report
    # "no findings" either.
    findings = scan_pickle(FIXTURES_DIR / "malicious" / "int_opcode_hex_evasion.pkl")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "PICKLE_PARSE_ERROR"
