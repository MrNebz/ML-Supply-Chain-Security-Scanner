"""
Evaluates the trained pickle anomaly model against our fixture set:
benign fixtures SHOULD score "normal", malicious fixtures MAY score
"anomalous" (this is a secondary/experimental signal, not expected to
match the precision of the rule-based scanners -- reported honestly,
including on a training set this small).

Run with: python scripts/evaluate_anomaly_model.py
"""

from pathlib import Path

from mlscan.scanners.pickle_scanner.anomaly import AnomalyModelUnavailable, score_pickle_anomaly

ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT / "tests" / "fixtures"

PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth"}


def _pickle_files(subdir: str) -> list[Path]:
    root = FIXTURES_DIR / subdir
    return [
        p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in PICKLE_EXTENSIONS
    ]


def main():
    benign = _pickle_files("benign")
    malicious = _pickle_files("malicious")

    print(f"Benign pickle fixtures: {len(benign)}")
    print(f"Malicious pickle fixtures: {len(malicious)}")
    print()

    try:
        benign_flagged = 0
        for path in benign:
            finding = score_pickle_anomaly(path)
            flagged = finding is not None
            benign_flagged += flagged
            print(f"  benign    {'ANOMALOUS' if flagged else 'normal   '}  {path.name}")

        print()
        malicious_flagged = 0
        for path in malicious:
            finding = score_pickle_anomaly(path)
            flagged = finding is not None
            malicious_flagged += flagged
            print(f"  malicious {'ANOMALOUS' if flagged else 'normal   '}  {path.name}")

    except AnomalyModelUnavailable as exc:
        raise SystemExit(f"Model unavailable: {exc}")

    print()
    false_positive_rate = benign_flagged / len(benign) if benign else 0.0
    detection_rate = malicious_flagged / len(malicious) if malicious else 0.0
    print(f"False positive rate (benign flagged as anomalous): {false_positive_rate:.0%}")
    print(f"Detection rate (malicious flagged as anomalous):    {detection_rate:.0%}")


if __name__ == "__main__":
    main()
