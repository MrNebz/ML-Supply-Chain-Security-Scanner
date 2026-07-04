"""
Generates ground-truth ONNX fixtures for tests/fixtures/{benign,malicious}.

Run once with: python scripts/generate_onnx_fixtures.py

These models are minimal hand-built graphs (via onnx.helper), not trained
networks -- we only need structurally valid protobuf, not a working model.
"""

from pathlib import Path

import onnx
from onnx import TensorProto, helper

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _make_model(nodes, initializers=None) -> onnx.ModelProto:
    graph = helper.make_graph(
        nodes,
        "test_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 3])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 3])],
        initializer=initializers or [],
    )
    model = helper.make_model(graph, producer_name="mlscan-fixtures")
    model.opset_import[0].version = 13
    return model


def write_benign_identity():
    model = _make_model([helper.make_node("Identity", ["X"], ["Y"])])
    path = FIXTURES_DIR / "benign" / "benign_identity.onnx"
    onnx.save(model, str(path))
    print(f"wrote {path}")


def write_malicious_external_data_traversal():
    tensor = onnx.TensorProto()
    tensor.name = "W"
    tensor.data_type = TensorProto.FLOAT
    tensor.dims.extend([1])
    tensor.data_location = TensorProto.EXTERNAL
    entry = tensor.external_data.add()
    entry.key = "location"
    entry.value = "../../../../etc/passwd"

    model = _make_model(
        [helper.make_node("Identity", ["X"], ["Y"])],
        initializers=[tensor],
    )
    path = FIXTURES_DIR / "malicious" / "external_data_path_traversal.onnx"
    onnx.save(model, str(path))
    print(f"wrote {path}")


def write_malicious_custom_domain():
    node = helper.make_node("EvilOp", ["X"], ["Y"], domain="com.evil.customops")
    model = _make_model([node])
    path = FIXTURES_DIR / "malicious" / "custom_domain_op.onnx"
    onnx.save(model, str(path))
    print(f"wrote {path}")


def write_malicious_oversized_dim():
    node = helper.make_node("Identity", ["X"], ["Y"])
    graph = helper.make_graph(
        [node],
        "test_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 3])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [2**31 - 1, 2**31 - 1])],
    )
    model = helper.make_model(graph, producer_name="mlscan-fixtures")
    model.opset_import[0].version = 13
    path = FIXTURES_DIR / "malicious" / "oversized_tensor_dim.onnx"
    onnx.save(model, str(path))
    print(f"wrote {path}")


if __name__ == "__main__":
    write_benign_identity()
    write_malicious_external_data_traversal()
    write_malicious_custom_domain()
    write_malicious_oversized_dim()
