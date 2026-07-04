"""
Generates ground-truth Keras HDF5 fixtures for tests/fixtures/{benign,malicious}.

Run once with: python scripts/generate_h5_fixtures.py

These are hand-built HDF5 attributes mimicking Keras' real model_config
schema -- we don't need TensorFlow/Keras installed to produce them, only
h5py + json (+ marshal/base64 for the malicious payload, exactly as
Keras' own func_dump() does internally). Nothing here is ever loaded back
via keras.models.load_model(), so no bytecode is ever executed.
"""

import base64
import json
import marshal
from pathlib import Path

import h5py

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _write_h5_with_config(path: Path, model_config: dict) -> None:
    with h5py.File(path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)
        f.attrs["keras_version"] = "2.15.0"
        f.attrs["backend"] = "tensorflow"


def write_benign_dense_model():
    config = {
        "class_name": "Sequential",
        "config": {
            "name": "benign_model",
            "layers": [
                {
                    "class_name": "Dense",
                    "config": {"name": "dense_1", "units": 8, "activation": "relu"},
                },
                {
                    "class_name": "Dense",
                    "config": {"name": "dense_2", "units": 1, "activation": "sigmoid"},
                },
            ],
        },
    }
    path = FIXTURES_DIR / "benign" / "benign_dense_model.h5"
    _write_h5_with_config(path, config)
    print(f"wrote {path}")


def _payload(x):
    import os

    os.system("echo pwned")
    return x


def write_malicious_lambda_marshalled():
    code_bytes = marshal.dumps(_payload.__code__)
    encoded = base64.b64encode(code_bytes).decode("ascii")

    config = {
        "class_name": "Sequential",
        "config": {
            "name": "malicious_model",
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "evil_lambda",
                        "function_type": "lambda",
                        "function": [encoded, None, None],
                        "output_shape_type": "raw",
                    },
                }
            ],
        },
    }
    path = FIXTURES_DIR / "malicious" / "lambda_marshalled_bytecode.h5"
    _write_h5_with_config(path, config)
    print(f"wrote {path}")


def write_malicious_lambda_named_function():
    config = {
        "class_name": "Sequential",
        "config": {
            "name": "named_fn_model",
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "named_lambda",
                        "function_type": "function",
                        "function": "custom_scaling_function",
                    },
                }
            ],
        },
    }
    path = FIXTURES_DIR / "malicious" / "lambda_named_function_ref.h5"
    _write_h5_with_config(path, config)
    print(f"wrote {path}")


if __name__ == "__main__":
    write_benign_dense_model()
    write_malicious_lambda_marshalled()
    write_malicious_lambda_named_function()
