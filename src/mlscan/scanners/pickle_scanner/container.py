"""
Support for zip-wrapped PyTorch checkpoints.

Since PyTorch 1.6, torch.save() defaults to a zip archive containing a
"<archive_name>/data.pkl" member (the actual pickled object graph) plus
separate tensor storage files ("<archive_name>/data/0", "data/1", ...).
A raw-pickle-stream scanner pointed at the outer .pt/.pth file would just
see zip central-directory bytes, not opcodes -- this module extracts the
inner data.pkl bytes so the existing opcode scanner can inspect them
unchanged.
"""

import zipfile
from pathlib import Path


def is_zip_wrapped_pickle(path) -> bool:
    path = Path(path)
    if not zipfile.is_zipfile(path):
        return False
    with zipfile.ZipFile(path) as zf:
        return _find_data_pkl_member(zf) is not None


def load_pickle_bytes(path) -> bytes:
    """
    Returns the raw pickle opcode-stream bytes to scan: the inner
    data.pkl member if this is a zip-wrapped PyTorch checkpoint,
    otherwise the file's own bytes unchanged.
    """
    path = Path(path)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            member = _find_data_pkl_member(zf)
            if member is not None:
                return zf.read(member)
    return path.read_bytes()


def _find_data_pkl_member(zf: zipfile.ZipFile) -> str | None:
    candidates = [name for name in zf.namelist() if name.endswith("data.pkl")]
    return candidates[0] if candidates else None
