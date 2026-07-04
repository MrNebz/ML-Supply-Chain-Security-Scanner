"""
Static inspection of a Keras HDF5 (.h5) model file.

We only ever read HDF5 attributes and parse the model_config JSON text --
we never call keras.models.load_model(), so no Lambda layer code is ever
marshal.loads()'d or executed.
"""

import json

import h5py

from mlscan.report import Finding, Severity


def scan_h5(path) -> list[Finding]:
    try:
        with h5py.File(str(path), "r") as f:
            raw_config = f.attrs.get("model_config")
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        # A file with a .h5 extension that isn't actually a valid HDF5
        # container (h5py raises OSError on bad signatures) shouldn't
        # crash the scan -- same fail-safe posture as the other two
        # scanners.
        return [
            Finding(
                severity=Severity.HIGH,
                rule_id="H5_PARSE_ERROR",
                message=(
                    f"Could not open this file as a valid HDF5 container "
                    f"({type(exc).__name__}: {exc}). Malformed, corrupted, or "
                    "not actually an HDF5 file -- treat as suspicious."
                ),
                location="file",
            )
        ]

    if raw_config is None:
        return []

    if isinstance(raw_config, bytes):
        raw_config = raw_config.decode("utf-8")

    try:
        model_config = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        return [
            Finding(
                severity=Severity.MEDIUM,
                rule_id="H5_PARSE_ERROR",
                message=(
                    f"model_config attribute is not valid JSON ({exc}) -- "
                    "cannot inspect layer configuration for this file."
                ),
                location="attribute 'model_config'",
            )
        ]

    findings: list[Finding] = []
    for lambda_config in _iter_lambda_layer_configs(model_config):
        finding = _check_lambda_layer(lambda_config)
        if finding is not None:
            findings.append(finding)
    return findings


def _iter_lambda_layer_configs(node):
    """
    Recursively walk the parsed model_config looking for any layer entry
    with class_name == "Lambda". Models can nest sub-models (a Functional
    model containing a Sequential model, etc.), so a flat top-level scan
    isn't enough -- we walk every dict/list in the structure.
    """
    if isinstance(node, dict):
        if node.get("class_name") == "Lambda" and isinstance(node.get("config"), dict):
            yield node["config"]
        for value in node.values():
            yield from _iter_lambda_layer_configs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_lambda_layer_configs(item)


def _check_lambda_layer(config: dict) -> Finding | None:
    name = config.get("name", "<unnamed>")
    function_type = config.get("function_type")
    function_field = config.get("function")

    # Keras' func_dump() serializes a raw Python lambda/function as
    # [base64_marshalled_bytecode, defaults, closure] and sets
    # function_type == "lambda". This is the arbitrary-code case.
    if function_type == "lambda" or isinstance(function_field, list):
        return Finding(
            severity=Severity.CRITICAL,
            rule_id="H5_LAMBDA_MARSHALLED_BYTECODE",
            message=(
                f"Lambda layer '{name}' embeds marshalled Python bytecode that "
                "executes when the layer runs"
            ),
            location=f"layer '{name}'",
        )

    # function_type == "function" means Keras stored just a name string,
    # to be resolved later via a trusted custom_objects mapping supplied
    # by the caller of load_model(). Less severe, but still worth flagging
    # since it depends entirely on caller-supplied trust.
    if function_type == "function":
        return Finding(
            severity=Severity.MEDIUM,
            rule_id="H5_LAMBDA_NAMED_FUNCTION_REF",
            message=(
                f"Lambda layer '{name}' references an external function by name "
                "-- requires trusted custom_objects at load time"
            ),
            location=f"layer '{name}'",
        )

    return None
