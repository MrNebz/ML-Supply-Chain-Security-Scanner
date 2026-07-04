"""
Optional ML anomaly-detection layer for pickle files: scores a file's
opcode-derived feature vector against an IsolationForest trained on
benign pickle structure only (see scripts/train_pickle_anomaly_model.py).

This is a secondary, EXPERIMENTAL signal on top of the primary
rule-based scanners in this package -- it never replaces a rule-based
finding, only supplements it, and is opt-in (mlscan --ml) since it
requires the `ml` extra (scikit-learn, skops) which the core tool does
not depend on.

The trained model is stored via skops, not pickle/joblib -- deliberately,
given this entire project's thesis that pickle-based artifact storage is
a real risk. skops.io.load() performs its own type-allowlist validation
before reconstructing objects, unlike raw pickle.load().
"""

from pathlib import Path

from mlscan.report import Finding, Severity
from mlscan.scanners.pickle_scanner.container import load_pickle_bytes
from mlscan.scanners.pickle_scanner.features import extract_features

_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "pickle_anomaly.skops"

_cached_artifact = None


class AnomalyModelUnavailable(Exception):
    pass


def _load_artifact():
    global _cached_artifact
    if _cached_artifact is not None:
        return _cached_artifact

    try:
        import skops.io as sio
    except ImportError as exc:
        raise AnomalyModelUnavailable(
            "The ml extra is not installed. Run: pip install -e \".[ml]\""
        ) from exc

    if not _MODEL_PATH.exists():
        raise AnomalyModelUnavailable(
            f"No trained anomaly model found at {_MODEL_PATH}. Run "
            "scripts/train_pickle_anomaly_model.py first."
        )

    trusted_types = sio.get_untrusted_types(file=_MODEL_PATH)
    _cached_artifact = sio.load(_MODEL_PATH, trusted=trusted_types)
    return _cached_artifact


def ensure_available() -> None:
    """Raises AnomalyModelUnavailable with a clear reason, or returns silently."""
    _load_artifact()


def score_pickle_anomaly(path) -> Finding | None:
    """
    Returns a LOW-severity PICKLE_ANOMALOUS_STRUCTURE finding if the file's
    opcode structure looks statistically unusual versus the benign
    training corpus, or None if it looks normal (or the model isn't
    available -- callers should treat that as "no additional signal",
    not as an error, since this layer is optional).
    """
    try:
        artifact = _load_artifact()
    except AnomalyModelUnavailable:
        return None

    data = load_pickle_bytes(path)
    features = [extract_features(data)]

    scaled = artifact["scaler"].transform(features)
    prediction = artifact["model"].predict(scaled)[0]  # -1 = anomaly, 1 = normal
    score = float(artifact["model"].decision_function(scaled)[0])

    if prediction != -1:
        return None

    return Finding(
        severity=Severity.LOW,
        rule_id="PICKLE_ANOMALOUS_STRUCTURE",
        message=(
            f"Opcode structure is statistically unusual versus a benign training "
            f"corpus (anomaly score {score:.3f}, more negative = more unusual). "
            "This is an experimental secondary signal, not a rule-based finding -- "
            "it does not by itself indicate malicious content."
        ),
        location="file",
    )
