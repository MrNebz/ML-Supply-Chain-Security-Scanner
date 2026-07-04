"""
Downloads a broader corpus of real, benign pickle files from HuggingFace
Hub, used ONLY to train the optional ML anomaly-detection layer
(scripts/train_pickle_anomaly_model.py) -- not part of the test fixture
set, and not committed to the repo (regenerable via this script, like a
build artifact).

Our test fixtures alone (~4 benign pickle files) are far too small a
sample to model "normal" pickle structure -- an anomaly detector needs
enough real examples to actually learn a distribution, not just
memorize a handful of files.

Run with: python scripts/download_ml_training_corpus.py
"""

from pathlib import Path

from huggingface_hub import HfApi, hf_hub_download

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "training_data" / "benign_pickles"
MAX_FILE_SIZE = 2_000_000
TARGET_COUNT = 40


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    api = HfApi()

    downloaded = 0
    seen_repos = set()

    for model in api.list_models(search="pkl", limit=200):
        if downloaded >= TARGET_COUNT:
            break
        if model.id in seen_repos:
            continue
        seen_repos.add(model.id)

        try:
            info = api.model_info(model.id, files_metadata=True)
        except Exception:
            continue

        for sibling in info.siblings:
            if not sibling.rfilename.endswith((".pkl", ".pickle")):
                continue
            if not sibling.size or sibling.size > MAX_FILE_SIZE:
                continue
            try:
                cached_path = hf_hub_download(repo_id=model.id, filename=sibling.rfilename)
            except Exception as exc:
                print(f"skip {model.id}/{sibling.rfilename}: {exc}")
                continue

            dest_name = f"{model.id.replace('/', '__')}__{Path(sibling.rfilename).name}"
            dest_path = OUTPUT_DIR / dest_name
            dest_path.write_bytes(Path(cached_path).read_bytes())
            print(f"[{downloaded + 1}/{TARGET_COUNT}] wrote {dest_path}")
            downloaded += 1
            break  # one file per repo, prioritize breadth over depth

    print(f"\nDownloaded {downloaded} benign pickle files to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
