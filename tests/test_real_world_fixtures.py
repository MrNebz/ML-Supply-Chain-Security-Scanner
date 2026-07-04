"""
Validates mlscan against real, unmodified files pulled from HuggingFace
Hub (see scripts/download_real_world_fixtures.py) -- these are the
false-positive check that hand-crafted fixtures can't give us: real
files, real complexity, no ground truth we invented ourselves.
"""

from pathlib import Path

import pytest

from mlscan.report import Severity
from mlscan.scanners.h5_scanner import scan_h5
from mlscan.scanners.onnx_scanner import scan_onnx
from mlscan.scanners.pickle_scanner import scan_pickle

REAL_WORLD_DIR = Path(__file__).resolve().parent / "fixtures" / "benign" / "real_world"


def test_real_h5_model_has_no_findings():
    findings = scan_h5(REAL_WORLD_DIR / "Newt007__bin_cls_att.h5.h5")
    assert findings == []


def test_real_tiny_pickle_model_has_no_findings():
    findings = scan_pickle(REAL_WORLD_DIR / "RashidIqbal__houserent_model.pkl.pkl")
    assert findings == []


@pytest.mark.parametrize(
    "filename",
    ["aapot__bge-m3-onnx.onnx", "LiquidAI__LFM2.5-230M-ONNX.onnx"],
)
def test_real_onnx_runtime_optimized_models_only_flag_vendor_extension(filename):
    # These models use ONNX Runtime's own com.microsoft extension ops
    # (Attention, BiasGelu, RotaryEmbedding, ...) -- common in real
    # optimized/quantized models. They must be flagged as a known,
    # lower-severity vendor extension, NOT as an unrecognized custom
    # domain (which would be a false positive at HIGH severity).
    findings = scan_onnx(REAL_WORLD_DIR / filename)
    assert len(findings) > 0
    assert all(f.rule_id == "ONNX_VENDOR_EXTENSION_DOMAIN" for f in findings)
    assert all(f.severity == Severity.MEDIUM for f in findings)


@pytest.mark.xfail(
    reason=(
        "KNOWN LIMITATION, root-caused via real-world testing: this legitimate "
        "LightGBM pickle serializes a joblib.numpy_pickle.NumpyArrayWrapper "
        "object (via NEWOBJ+BUILD), then joblib writes the *raw numpy array "
        "bytes directly into the file stream* -- bypassing pickle opcodes "
        "entirely, so its custom loader can read/mmap the array straight "
        "from the file handle. pickletools has no way to know to skip N raw "
        "bytes there; it tries to interpret them as opcodes and fails "
        "('opcode unknown'), which triggers our PICKLE_PARSE_ERROR rule as "
        "a false positive on this legitimate file. This is a structural "
        "limitation of pure opcode-stream analysis when the on-disk format "
        "is 'pickle + a custom binary-embedding convention', not a bug in "
        "our detection logic and not an attacker technique. A real fix "
        "would require joblib-format-aware recovery (detect "
        "NumpyArrayWrapper, compute the byte length from its shape/dtype, "
        "skip that many raw bytes, resume opcode parsing) -- a scoped "
        "future enhancement, documented in README under Known Limitations "
        "rather than silently worked around."
    ),
    strict=True,
)
def test_real_lightgbm_pickle_has_no_findings():
    findings = scan_pickle(REAL_WORLD_DIR / "kojongmo__LightGBM_Q1_model.pkl.pkl")
    assert findings == []
