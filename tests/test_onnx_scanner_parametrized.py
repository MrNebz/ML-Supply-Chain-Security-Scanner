"""
Programmatic coverage for ONNX domain classification: every known vendor
extension domain must produce a MEDIUM finding, and a spread of
plausible unknown/attacker-chosen domain names must produce a HIGH
finding -- verified individually rather than trusting one example of each.
"""

import pytest
from onnx import TensorProto, helper

from mlscan.report import Severity
from mlscan.scanners.onnx_scanner import scan_onnx
from mlscan.scanners.onnx_scanner.rules import KNOWN_VENDOR_EXTENSION_DOMAINS

UNKNOWN_DOMAINS = [
    "com.evil.customops",
    "org.attacker.payload",
    "net.malicious.ops",
    "io.suspicious.customlib",
]


def _make_single_node_model(tmp_path, domain: str, index: int):
    node = helper.make_node("CustomOp", ["X"], ["Y"], domain=domain)
    graph = helper.make_graph(
        [node],
        "test_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 3])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 3])],
    )
    model = helper.make_model(graph, producer_name="mlscan-fixtures")
    model.opset_import[0].version = 13
    path = tmp_path / f"model_{index}.onnx"
    import onnx

    onnx.save(model, str(path))
    return path


@pytest.mark.parametrize("domain", sorted(KNOWN_VENDOR_EXTENSION_DOMAINS))
def test_known_vendor_domains_are_medium(tmp_path, domain):
    path = _make_single_node_model(tmp_path, domain, index=0)
    findings = scan_onnx(path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].rule_id == "ONNX_VENDOR_EXTENSION_DOMAIN"


@pytest.mark.parametrize("domain", UNKNOWN_DOMAINS)
def test_unknown_domains_are_high(tmp_path, domain):
    path = _make_single_node_model(tmp_path, domain, index=1)
    findings = scan_onnx(path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "ONNX_CUSTOM_OPERATOR_DOMAIN"
