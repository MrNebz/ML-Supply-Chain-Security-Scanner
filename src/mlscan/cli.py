import argparse
import json
import sys
from pathlib import Path

from mlscan.detect import detect_format_from_content, format_from_extension
from mlscan.report import Finding, Severity
from mlscan.scanners.h5_scanner import scan_h5
from mlscan.scanners.onnx_scanner import scan_onnx
from mlscan.scanners.pickle_scanner import scan_pickle
from mlscan.scanners.pickle_scanner.anomaly import (
    AnomalyModelUnavailable,
    ensure_available,
    score_pickle_anomaly,
)

_EXIT_SEVERITY = {Severity.CRITICAL, Severity.HIGH}

_SCANNERS = {
    "pickle": scan_pickle,
    "onnx": scan_onnx,
    "h5": scan_h5,
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="mlscan",
        description="Static security scanner for ML model files (.pkl, .onnx, .h5)",
    )
    parser.add_argument("path", help="Path to a model file to scan")
    parser.add_argument(
        "--json", action="store_true", help="Emit findings as JSON instead of human-readable text"
    )
    parser.add_argument(
        "--ml",
        action="store_true",
        help=(
            "Also run the experimental ML anomaly-detection layer for pickle "
            "files (requires the 'ml' extra: pip install -e \".[ml]\")"
        ),
    )
    args = parser.parse_args(argv)

    path = Path(args.path)

    detected_format = detect_format_from_content(path)
    extension_format = format_from_extension(path)
    file_format = detected_format or extension_format

    if file_format is None:
        message = f"error: could not determine file format for '{path}'"
        if args.json:
            print(json.dumps({"path": str(path), "error": message}))
        else:
            print(message)
        return 2

    findings: list[Finding] = []

    if detected_format and extension_format and detected_format != extension_format:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                rule_id="FORMAT_EXTENSION_MISMATCH",
                message=(
                    f"File extension implies '{extension_format}' but content is "
                    f"actually '{detected_format}' -- possible attempt to evade "
                    "extension-based scanning"
                ),
                location=str(path),
            )
        )

    findings.extend(_SCANNERS[file_format](path))

    if args.ml:
        if file_format == "pickle":
            try:
                ensure_available()
                anomaly_finding = score_pickle_anomaly(path)
                if anomaly_finding is not None:
                    findings.append(anomaly_finding)
            except AnomalyModelUnavailable as exc:
                print(f"warning: --ml requested but unavailable: {exc}", file=sys.stderr)
        else:
            print(
                f"warning: --ml is currently only implemented for pickle files, "
                f"skipping for format '{file_format}'",
                file=sys.stderr,
            )

    if args.json:
        _print_json(path, file_format, findings)
    else:
        _print_text(path, findings)

    if any(f.severity in _EXIT_SEVERITY for f in findings):
        return 1
    return 0


def _print_text(path: Path, findings: list[Finding]) -> None:
    if not findings:
        print(f"{path}: no findings")
        return
    print(f"{path}: {len(findings)} finding(s)")
    for finding in findings:
        print(f"  {finding}")


def _print_json(path: Path, file_format: str, findings: list[Finding]) -> None:
    report = {
        "path": str(path),
        "format": file_format,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "critical": sum(f.severity == Severity.CRITICAL for f in findings),
            "high": sum(f.severity == Severity.HIGH for f in findings),
            "medium": sum(f.severity == Severity.MEDIUM for f in findings),
            "low": sum(f.severity == Severity.LOW for f in findings),
        },
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    sys.exit(main())
