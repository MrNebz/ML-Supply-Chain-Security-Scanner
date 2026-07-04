"""
Tests for the optional ML anomaly-detection layer. Skipped entirely if
the `ml` extra (scikit-learn, skops) isn't installed or the model
hasn't been trained yet -- this layer is opt-in, not part of the core
tool's required functionality.
"""

from pathlib import Path

import pytest

pytest.importorskip("sklearn")
pytest.importorskip("skops")

from mlscan.scanners.pickle_scanner.anomaly import (  # noqa: E402
    AnomalyModelUnavailable,
    score_pickle_anomaly,
)
from mlscan.scanners.pickle_scanner.features import extract_features, feature_names  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

try:
    from mlscan.scanners.pickle_scanner.anomaly import ensure_available

    ensure_available()
    _MODEL_AVAILABLE = True
except AnomalyModelUnavailable:
    _MODEL_AVAILABLE = False

requires_trained_model = pytest.mark.skipif(
    not _MODEL_AVAILABLE, reason="anomaly model not trained -- run scripts/train_pickle_anomaly_model.py"
)


def test_feature_vector_has_stable_length_matching_feature_names():
    data = (FIXTURES_DIR / "benign" / "benign_dict.pkl").read_bytes()
    features = extract_features(data)
    assert len(features) == len(feature_names())


def test_feature_extraction_never_crashes_on_malformed_bytes():
    features = extract_features(b"\x00\x01\x02not a real pickle")
    assert len(features) == len(feature_names())
    assert all(isinstance(f, float) for f in features)


@requires_trained_model
def test_score_pickle_anomaly_runs_on_all_local_fixtures():
    # Not asserting specific benign/malicious outcomes here -- this is an
    # experimental layer trained on a small corpus, precision/recall is
    # tracked honestly via scripts/evaluate_anomaly_model.py, not hard
    # pass/fail assertions in the test suite. We only assert it runs
    # without crashing and returns the right type.
    for subdir in ("benign", "malicious"):
        for path in (FIXTURES_DIR / subdir).rglob("*"):
            if path.is_file() and path.suffix.lower() in {".pkl", ".pickle", ".pt", ".pth"}:
                result = score_pickle_anomaly(path)
                assert result is None or result.rule_id == "PICKLE_ANOMALOUS_STRUCTURE"
