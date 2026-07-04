"""
Downloads a small set of real, unmodified model files from HuggingFace
Hub into tests/fixtures/benign/real_world/ -- these serve as a
false-positive check that hand-crafted fixtures can't provide: real
files with real structural complexity, not ground truth we invented.

Requires: pip install huggingface_hub (dev-only, not a runtime dependency
of mlscan itself -- this script is a one-time/occasional fixture-refresh
tool, not part of the package).

Run with: python scripts/download_real_world_fixtures.py
"""

import shutil
from pathlib import Path

from huggingface_hub import hf_hub_download

DEST_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "benign" / "real_world"

# (repo_id, filename in repo, local extension) -- picked via HfApi search
# for real files under ~2MB in each target format.
TARGETS = [
    ("aapot/bge-m3-onnx", "model.onnx", "onnx"),
    ("LiquidAI/LFM2.5-230M-ONNX", "onnx/model.onnx", "onnx"),
    ("Newt007/bin_cls_att.h5", "web_model.h5", "h5"),
    ("RashidIqbal/houserent_model.pkl", "houserent_model.pkl", "pkl"),
    ("kojongmo/LightGBM_Q1_model.pkl", "LightGBM_Q1_model.pkl", "pkl"),
]


def main():
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    for repo_id, filename, ext in TARGETS:
        try:
            cached_path = hf_hub_download(repo_id=repo_id, filename=filename)
        except Exception as exc:
            print(f"FAILED {repo_id}: {exc}")
            continue
        dest_name = repo_id.replace("/", "__") + "." + ext
        dest_path = DEST_DIR / dest_name
        shutil.copyfile(cached_path, dest_path)
        print(f"wrote {dest_path}")


if __name__ == "__main__":
    main()
