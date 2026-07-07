"""
mlscan interactive scanner -- upload a .pkl/.pt/.pth, .onnx, or .h5 file and
scan it with the real mlscan detection engine (not a simulation: this calls
the exact same scan_pickle/scan_onnx/scan_h5 functions the CLI uses).

Run with: streamlit run ui/app.py
"""

import json
import sys
import tempfile
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mlscan.detect import detect_format_from_content, format_from_extension  # noqa: E402
from mlscan.report import Finding, Severity  # noqa: E402
from mlscan.scanners.h5_scanner import scan_h5  # noqa: E402
from mlscan.scanners.onnx_scanner import scan_onnx  # noqa: E402
from mlscan.scanners.pickle_scanner import scan_pickle  # noqa: E402

SCANNERS = {"pickle": scan_pickle, "onnx": scan_onnx, "h5": scan_h5}

#  emoji, streamlit named color (used with the ":color[text]" markdown syntax)
SEVERITY_STYLE = {
    Severity.CRITICAL: ("🔴", "red"),
    Severity.HIGH: ("🟠", "orange"),
    Severity.MEDIUM: ("🟡", "orange"),
    Severity.LOW: ("🔵", "blue"),
}

# Severity is a plain string enum with no inherent ordering -- max() on it
# would sort alphabetically ("CRITICAL" < "HIGH" < "LOW" < "MEDIUM"), which
# is not severity order. This explicit rank is the correct way to find the
# "worst" finding.
SEVERITY_RANK = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.LOW: 0}

st.set_page_config(page_title="mlscan", page_icon="🛡️", layout="centered")

st.title("🛡️ mlscan — ML Model Supply-Chain Scanner")
st.caption(
    "Upload a pickle (`.pkl`/`.pt`/`.pth`), ONNX (`.onnx`), or HDF5/Keras (`.h5`) "
    "file. This runs the real static-analysis engine locally — nothing is "
    "uploaded anywhere, and the file is never executed, only parsed as structured data."
)

uploaded = st.file_uploader(
    "Choose a model file",
    type=["pkl", "pickle", "pt", "pth", "onnx", "h5", "hdf5", "keras"],
)

if uploaded is not None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / uploaded.name
        tmp_path.write_bytes(uploaded.getvalue())

        detected_format = detect_format_from_content(tmp_path)
        extension_format = format_from_extension(tmp_path)
        file_format = detected_format or extension_format

        st.divider()

        if file_format is None:
            st.error("Could not determine file format from content or extension.")
        else:
            findings: list[Finding] = []

            if detected_format and extension_format and detected_format != extension_format:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        rule_id="FORMAT_EXTENSION_MISMATCH",
                        message=(
                            f"File extension implies '{extension_format}' but content "
                            f"is actually '{detected_format}' -- possible attempt to "
                            "evade extension-based scanning"
                        ),
                        location=uploaded.name,
                    )
                )

            findings.extend(SCANNERS[file_format](tmp_path))

            col1, col2 = st.columns(2)
            col1.metric("Detected format", file_format.upper())
            col2.metric("Findings", len(findings))

            if not findings:
                st.success("✅ No findings — this file looks clean.")
            else:
                worst = max(findings, key=lambda f: SEVERITY_RANK[f.severity]).severity
                if worst in (Severity.CRITICAL, Severity.HIGH):
                    st.error(f"⚠️ {len(findings)} finding(s) — this file is suspicious.")
                else:
                    st.warning(f"⚠️ {len(findings)} finding(s) — review recommended.")

                for finding in findings:
                    emoji, color = SEVERITY_STYLE[finding.severity]
                    with st.container(border=True):
                        st.markdown(
                            f"{emoji} **:{color}[{finding.severity.value}]** `{finding.rule_id}`"
                        )
                        st.write(finding.message)
                        st.caption(f"Location: {finding.location}")

            report = {
                "filename": uploaded.name,
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
            st.download_button(
                "Download JSON report",
                data=json.dumps(report, indent=2),
                file_name=f"{uploaded.name}.mlscan.json",
                mime="application/json",
            )

st.divider()
st.caption(
    "mlscan detects: pickle GLOBAL/REDUCE code-execution patterns, gadget-chain "
    "attributes, and a disclosed pickletools bypass technique; ONNX external-data "
    "path traversal, custom operator domains, and oversized tensor dimensions; "
    "and Keras Lambda-layer marshalled bytecode. See PROJECT_REPORT.md for the full "
    "technical writeup."
)
