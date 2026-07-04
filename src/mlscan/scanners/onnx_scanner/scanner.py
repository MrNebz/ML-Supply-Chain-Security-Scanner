"""
Static, structure-only inspection of an ONNX model file.

We parse the file as a protobuf message (onnx.load) and only ever read
fields -- we never run inference, and we explicitly disable loading of
externally-referenced tensor data (load_external_data=False) so that a
malicious external_data path can't make the scanner itself read an
arbitrary file off disk while we're busy checking for exactly that attack.
"""

from pathlib import Path

import onnx

from mlscan.report import Finding, Severity
from mlscan.scanners.onnx_scanner.rules import (
    KNOWN_VENDOR_EXTENSION_DOMAINS,
    MAX_REASONABLE_DIM,
    SAFE_DOMAINS,
)


def scan_onnx(path) -> list[Finding]:
    try:
        model = onnx.load(str(path), load_external_data=False)
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        # A file with a .onnx extension (or content-sniffed as protobuf-like
        # elsewhere) that fails to parse as a valid ModelProto is, at
        # minimum, not what it claims to be. Surface that as a finding
        # instead of letting protobuf's DecodeError (or any other parse
        # failure) crash the whole scan -- same fail-safe posture as the
        # pickle scanner's PICKLE_PARSE_ERROR.
        return [
            Finding(
                severity=Severity.HIGH,
                rule_id="ONNX_PARSE_ERROR",
                message=(
                    f"Could not parse this file as a valid ONNX ModelProto "
                    f"({type(exc).__name__}: {exc}). Malformed, corrupted, or "
                    "not actually an ONNX file -- treat as suspicious."
                ),
                location="file",
            )
        ]

    findings: list[Finding] = []
    findings.extend(_check_external_data(model))
    findings.extend(_check_custom_domains(model))
    findings.extend(_check_oversized_dims(model))
    return findings


def _check_external_data(model: "onnx.ModelProto") -> list[Finding]:
    findings = []
    for tensor in model.graph.initializer:
        if tensor.data_location != onnx.TensorProto.EXTERNAL:
            continue
        for entry in tensor.external_data:
            if entry.key != "location":
                continue
            # protobuf's "string" fields are supposed to always decode to
            # str, but when the underlying bytes aren't valid UTF-8 (found
            # via fuzz-testing a mutated fixture; also directly
            # attacker-craftable, not just a fuzzing curiosity), the
            # protobuf library can hand back raw bytes instead of raising.
            # Normalize defensively rather than assume the type.
            location = _to_str(entry.value)
            if _is_path_traversal(location):
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        rule_id="ONNX_EXTERNAL_DATA_PATH_TRAVERSAL",
                        message=(
                            f"Tensor '{tensor.name}' external_data location "
                            f"escapes the model's directory: '{location}'"
                        ),
                        location=f"initializer '{tensor.name}'",
                    )
                )
    return findings


def _to_str(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _is_path_traversal(location: str) -> bool:
    if location.startswith("/") or location.startswith("\\"):
        return True
    if len(location) > 1 and location[1] == ":":  # e.g. "C:\..."
        return True
    return ".." in Path(location).parts


def _check_custom_domains(model: "onnx.ModelProto") -> list[Finding]:
    findings = []
    seen: set[tuple[str, str]] = set()
    for node in model.graph.node:
        domain = node.domain
        if domain in SAFE_DOMAINS:
            continue
        key = (node.op_type, domain)
        if key in seen:
            continue
        seen.add(key)

        if domain in KNOWN_VENDOR_EXTENSION_DOMAINS:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule_id="ONNX_VENDOR_EXTENSION_DOMAIN",
                    message=(
                        f"Node op '{node.op_type}' comes from known vendor extension "
                        f"domain '{domain}' (e.g. ONNX Runtime) -- not part of the "
                        "core ONNX operator set, but a recognized, maintained extension"
                    ),
                    location=f"node '{node.name or node.op_type}'",
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    rule_id="ONNX_CUSTOM_OPERATOR_DOMAIN",
                    message=(
                        f"Node op '{node.op_type}' comes from unrecognized non-standard "
                        f"domain '{domain}' -- requires an external native op library "
                        "to execute"
                    ),
                    location=f"node '{node.name or node.op_type}'",
                )
            )
    return findings


def _check_oversized_dims(model: "onnx.ModelProto") -> list[Finding]:
    findings = []
    value_infos = list(model.graph.input) + list(model.graph.output) + list(model.graph.value_info)

    for value_info in value_infos:
        if not value_info.type.HasField("tensor_type"):
            continue
        shape = value_info.type.tensor_type.shape
        for dim in shape.dim:
            if dim.HasField("dim_value") and dim.dim_value > MAX_REASONABLE_DIM:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        rule_id="ONNX_SUSPICIOUS_TENSOR_DIM",
                        message=(
                            f"Tensor '{value_info.name}' declares an implausibly "
                            f"large dimension ({dim.dim_value}) -- possible "
                            "resource-exhaustion attempt"
                        ),
                        location=f"value_info '{value_info.name}'",
                    )
                )
    return findings
