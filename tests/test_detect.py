import shutil
from pathlib import Path

from mlscan.detect import detect_format_from_content, format_from_extension

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_extension_map_matches_real_extensions():
    assert format_from_extension("model.pkl") == "pickle"
    assert format_from_extension("model.pt") == "pickle"
    assert format_from_extension("model.onnx") == "onnx"
    assert format_from_extension("model.h5") == "h5"
    assert format_from_extension("model.xyz") is None


def test_content_detection_matches_real_files():
    assert (
        detect_format_from_content(FIXTURES_DIR / "malicious" / "reduce_os_system.pkl")
        == "pickle"
    )
    assert (
        detect_format_from_content(FIXTURES_DIR / "benign" / "benign_identity.onnx") == "onnx"
    )
    assert (
        detect_format_from_content(FIXTURES_DIR / "benign" / "benign_dense_model.h5") == "h5"
    )


def test_content_detection_catches_renamed_pickle(tmp_path):
    # Simulates an attacker renaming a malicious pickle to a .onnx
    # extension to dodge extension-based dispatch.
    disguised = tmp_path / "totally_a_model.onnx"
    shutil.copyfile(FIXTURES_DIR / "malicious" / "reduce_os_system.pkl", disguised)

    assert format_from_extension(disguised) == "onnx"
    assert detect_format_from_content(disguised) == "pickle"
