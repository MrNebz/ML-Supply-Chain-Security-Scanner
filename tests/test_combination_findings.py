"""
Combination fixtures: a single file with more than one distinct issue at
once, verifying findings don't interfere with, mask, or double-count
each other. All prior fixtures test exactly one rule per file -- these
are the case where a real attacker (or just a messy real model) triggers
several rules simultaneously.
"""

import pickle

import onnx
from onnx import TensorProto, helper

from mlscan.report import Severity
from mlscan.scanners.h5_scanner import scan_h5
from mlscan.scanners.onnx_scanner import scan_onnx
from mlscan.scanners.pickle_scanner import scan_pickle


def test_onnx_path_traversal_and_custom_domain_both_reported(tmp_path):
    tensor = onnx.TensorProto()
    tensor.name = "W"
    tensor.data_type = TensorProto.FLOAT
    tensor.dims.extend([1])
    tensor.data_location = TensorProto.EXTERNAL
    entry = tensor.external_data.add()
    entry.key = "location"
    entry.value = "../../../../etc/passwd"

    node = helper.make_node("EvilOp", ["X"], ["Y"], domain="com.evil.customops")
    graph = helper.make_graph(
        [node],
        "test_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 3])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 3])],
        initializer=[tensor],
    )
    model = helper.make_model(graph, producer_name="mlscan-fixtures")
    model.opset_import[0].version = 13

    path = tmp_path / "combo.onnx"
    onnx.save(model, str(path))

    findings = scan_onnx(path)
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"ONNX_EXTERNAL_DATA_PATH_TRAVERSAL", "ONNX_CUSTOM_OPERATOR_DOMAIN"}
    severities = {f.rule_id: f.severity for f in findings}
    assert severities["ONNX_EXTERNAL_DATA_PATH_TRAVERSAL"] == Severity.CRITICAL
    assert severities["ONNX_CUSTOM_OPERATOR_DOMAIN"] == Severity.HIGH


def test_pickle_with_two_independent_reduce_exploits_reports_both(tmp_path):
    class _OsSystemExploit:
        def __reduce__(self):
            import os

            return (os.system, ("echo one",))

    class _SubprocessExploit:
        def __reduce__(self):
            import subprocess

            return (subprocess.call, (["echo", "two"],))

    # Both objects in one top-level list -- a single pickle stream with
    # two distinct GLOBAL/STACK_GLOBAL+REDUCE dangerous calls.
    payload = [_OsSystemExploit(), _SubprocessExploit()]
    path = tmp_path / "combo.pkl"
    with open(path, "wb") as f:
        pickle.dump(payload, f)

    findings = scan_pickle(path)
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 2
    assert all(f.rule_id == "PICKLE_DANGEROUS_REDUCE" for f in critical_findings)
    messages = " ".join(f.message for f in critical_findings)
    assert "system" in messages
    assert "call" in messages


def test_h5_with_marshalled_and_named_lambda_reports_both(tmp_path):
    import base64
    import json
    import marshal

    import h5py

    def _payload(x):
        return x * 2

    encoded = base64.b64encode(marshal.dumps(_payload.__code__)).decode("ascii")

    config = {
        "class_name": "Sequential",
        "config": {
            "name": "combo_model",
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "evil_lambda",
                        "function_type": "lambda",
                        "function": [encoded, None, None],
                    },
                },
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "named_lambda",
                        "function_type": "function",
                        "function": "some_external_function",
                    },
                },
            ],
        },
    }

    path = tmp_path / "combo.h5"
    with h5py.File(path, "w") as f:
        f.attrs["model_config"] = json.dumps(config)

    findings = scan_h5(path)
    assert len(findings) == 2
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["H5_LAMBDA_MARSHALLED_BYTECODE"].severity == Severity.CRITICAL
    assert by_rule["H5_LAMBDA_NAMED_FUNCTION_REF"].severity == Severity.MEDIUM
