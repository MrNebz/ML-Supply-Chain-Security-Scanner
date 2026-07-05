"""
Trains the optional ML anomaly-detection layer: an IsolationForest over
opcode-derived features, fit on BENIGN pickle files only (no malicious
labels needed -- this is novelty/anomaly detection, not classification).

This is a secondary, experimental signal layered on top of the primary
rule-based scanners, not a replacement for them. Requires the `ml` extra:
    pip install -e ".[ml]"

Training data:
  - tests/fixtures/benign/** (our own hand-crafted + real-world fixtures)
  - training_data/benign_pickles/** (broader HuggingFace sample, pulled
    via scripts/download_ml_training_corpus.py -- run that first)

Run with: python scripts/train_pickle_anomaly_model.py
"""

from pathlib import Path

import numpy as np
import skops.io as sio
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from mlscan.scanners.pickle_scanner import scan_pickle
from mlscan.scanners.pickle_scanner.container import load_pickle_bytes
from mlscan.scanners.pickle_scanner.features import extract_features

ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "src" / "mlscan" / "models"
MODEL_PATH = MODEL_DIR / "pickle_anomaly.skops"

TRAINING_SOURCES = [
    ROOT / "tests" / "fixtures" / "benign",
    ROOT / "training_data" / "benign_pickles",
]

PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth"}


def _collect_benign_pickle_paths() -> list[Path]:
    paths = []
    for source in TRAINING_SOURCES:
        if not source.exists():
            continue
        for path in source.rglob("*"):
            if path.is_file() and path.suffix.lower() in PICKLE_EXTENSIONS:
                paths.append(path)
    return paths


def main():
    paths = _collect_benign_pickle_paths()
    print(f"Found {len(paths)} candidate benign pickle files.")

    features = []
    used_paths = []
    rejected = 0
    for path in paths:
        try:
            # Data-quality gate: HuggingFace Hub search results for terms
            # like "pkl"/"pickle" surface a lot of genuinely malicious/PoC
            # pickle files published by security researchers (repos named
            # things like "pickle-scanner-bypass-*", "poc_rce_*",
            # "malicious_model.pkl") right alongside real benign models --
            # discovered by inspecting actual download output, not
            # hypothetically. Training an anomaly detector on a "benign"
            # set contaminated with real attacks would defeat the entire
            # point, so we use our OWN rule-based scanner to certify each
            # candidate is clean before it's allowed into the training set.
            findings = scan_pickle(path)
            if findings:
                rejected += 1
                continue

            data = load_pickle_bytes(path)
            features.append(extract_features(data))
            used_paths.append(path)
        except Exception as exc:
            print(f"skip {path}: {exc}")

    if rejected:
        print(
            f"Rejected {rejected} candidate file(s) that our own scanner flagged "
            "(likely malicious/PoC files mixed into the HuggingFace search results, "
            "not genuine benign models)."
        )

    if len(features) < 10:
        raise SystemExit(
            f"Only {len(features)} usable training samples found -- too few to "
            "train a meaningful anomaly model. Run "
            "scripts/download_ml_training_corpus.py first to broaden the corpus."
        )

    X = np.array(features)
    print(f"Training on {X.shape[0]} samples, {X.shape[1]} features each.")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    model.fit(X_scaled)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    sio.dump({"scaler": scaler, "model": model, "n_training_samples": len(used_paths)}, MODEL_PATH)
    print(f"Wrote {MODEL_PATH}")


if __name__ == "__main__":
    main()
