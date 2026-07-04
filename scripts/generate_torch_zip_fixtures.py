"""
Generates zip-wrapped "PyTorch checkpoint" fixtures for
tests/fixtures/{benign,malicious} -- mimicking the zip layout
torch.save() has produced by default since PyTorch 1.6:
    <archive_name>/data.pkl      <- the actual pickled object graph
    <archive_name>/data/0        <- raw tensor storage bytes
    <archive_name>/version       <- format version marker

We don't need PyTorch installed to produce this layout: it's a plain zip
archive built with the stdlib zipfile module, containing a real pickle
stream (benign or malicious) as data.pkl.

Run with: python scripts/generate_torch_zip_fixtures.py
"""

import pickle
import zipfile
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _write_torch_style_zip(path: Path, data_pkl_bytes: bytes, archive_name: str = "archive") -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{archive_name}/data.pkl", data_pkl_bytes)
        zf.writestr(f"{archive_name}/data/0", b"\x00" * 32)  # dummy tensor storage
        zf.writestr(f"{archive_name}/version", "3\n")


def write_benign_zip_checkpoint():
    data_pkl = pickle.dumps({"state_dict": {"weight": [0.1, 0.2, 0.3]}, "epoch": 5})
    path = FIXTURES_DIR / "benign" / "benign_torch_checkpoint.pt"
    _write_torch_style_zip(path, data_pkl)
    print(f"wrote {path}")


class _OsSystemExploit:
    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


def write_malicious_zip_checkpoint():
    data_pkl = pickle.dumps(_OsSystemExploit())
    path = FIXTURES_DIR / "malicious" / "zip_wrapped_reduce_os_system.pt"
    _write_torch_style_zip(path, data_pkl)
    print(f"wrote {path}")


if __name__ == "__main__":
    write_benign_zip_checkpoint()
    write_malicious_zip_checkpoint()
