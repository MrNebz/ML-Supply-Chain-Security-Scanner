"""
Programmatic coverage for the Keras Lambda-layer rule: several distinct
marshalled payload bodies (not just one) confirmed CRITICAL, and several
distinct named-function references confirmed MEDIUM.
"""

import base64
import json
import marshal

import h5py
import pytest

from mlscan.report import Severity
from mlscan.scanners.h5_scanner import scan_h5


def _write_model(path, config: dict) -> None:
    with h5py.File(path, "w") as f:
        f.attrs["model_config"] = json.dumps(config)
        f.attrs["keras_version"] = "2.15.0"
        f.attrs["backend"] = "tensorflow"


def _lambda_config(name: str, *, function_type: str, function_field) -> dict:
    return {
        "class_name": "Sequential",
        "config": {
            "name": f"model_{name}",
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": name,
                        "function_type": function_type,
                        "function": function_field,
                    },
                }
            ],
        },
    }


def _double(x):
    return x * 2


def _square(x):
    return x**2


def _identity_plus_one(x):
    return x + 1


MARSHALLED_PAYLOADS = [_double, _square, _identity_plus_one]
NAMED_FUNCTION_REFS = ["scale_layer", "custom_norm", "external_activation"]


@pytest.mark.parametrize("func", MARSHALLED_PAYLOADS, ids=lambda f: f.__name__)
def test_marshalled_lambda_variants_are_critical(tmp_path, func):
    encoded = base64.b64encode(marshal.dumps(func.__code__)).decode("ascii")
    config = _lambda_config(func.__name__, function_type="lambda", function_field=[encoded, None, None])
    path = tmp_path / f"{func.__name__}.h5"
    _write_model(path, config)

    findings = scan_h5(path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "H5_LAMBDA_MARSHALLED_BYTECODE"


@pytest.mark.parametrize("function_name", NAMED_FUNCTION_REFS)
def test_named_function_ref_variants_are_medium(tmp_path, function_name):
    config = _lambda_config(function_name, function_type="function", function_field=function_name)
    path = tmp_path / f"{function_name}.h5"
    _write_model(path, config)

    findings = scan_h5(path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].rule_id == "H5_LAMBDA_NAMED_FUNCTION_REF"
