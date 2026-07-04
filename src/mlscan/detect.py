"""
Content-based file format detection, independent of the file extension.

Trusting only the extension means renaming evil.pkl to model.onnx would
skip the pickle scanner entirely -- a trivial evasion. HDF5 has a real,
documented magic number we can check directly; pickle protocols >= 2
always start with a PROTO opcode we can recognize; ONNX has no magic
number (it's raw protobuf), so the only reliable check is attempting to
parse it as one.
"""

from pathlib import Path

from mlscan.scanners.pickle_scanner.container import is_zip_wrapped_pickle

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

_EXTENSION_TO_FORMAT = {
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".pt": "pickle",
    ".pth": "pickle",
    ".onnx": "onnx",
    ".h5": "h5",
    ".hdf5": "h5",
    ".keras": "h5",
}


def format_from_extension(path) -> str | None:
    return _EXTENSION_TO_FORMAT.get(Path(path).suffix.lower())


def detect_format_from_content(path) -> str | None:
    head = Path(path).read_bytes()[:16]

    if head.startswith(HDF5_MAGIC):
        return "h5"

    # PROTO opcode (0x80) followed by a protocol number byte (0-5 for all
    # protocols in current use) is how every pickle stream from protocol 2
    # onward begins. Protocol 0/1 pickles are ASCII-based and have no
    # reliable magic number -- a known limitation of this heuristic.
    if len(head) >= 2 and head[0] == 0x80 and 0 <= head[1] <= 5:
        return "pickle"

    if is_zip_wrapped_pickle(path):
        return "pickle"

    if _parses_as_onnx(path):
        return "onnx"

    return None


def _parses_as_onnx(path) -> bool:
    import onnx

    try:
        onnx.load(str(path), load_external_data=False)
        return True
    except Exception:
        return False
