"""
Property-based fuzz testing: applies the same methodology as the
PickleFuzzer paper we cite (throw generated/mutated bytes at a parser,
watch for crashes) against our own tool instead of CPython's pickle
modules. This is how the two real crash bugs in scan_onnx/scan_h5 were
first suspected before being confirmed manually (garbage bytes with a
.onnx/.h5 extension) -- these tests make that check permanent and much
broader than the handful of cases we could check by hand.

We deliberately avoid pytest's tmp_path fixture together with @given
(hypothesis warns against function-scoped fixtures being re-used across
many generated examples) -- instead each test manages its own scratch
file path directly.

Settings (max_examples, deadline, health check suppression) come from
the active hypothesis profile registered in conftest.py, not hardcoded
here -- see conftest.py for why (a hung CI run with no per-example
deadline at all was the reason this changed).
"""

import random
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from mlscan.scanners.h5_scanner import scan_h5
from mlscan.scanners.onnx_scanner import scan_onnx
from mlscan.scanners.pickle_scanner import scan_pickle

_SCRATCH_DIR = Path(tempfile.mkdtemp(prefix="mlscan_fuzz_"))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _write_and_scan(scanner, suffix: str, data: bytes):
    path = _SCRATCH_DIR / f"fuzz{suffix}"
    path.write_bytes(data)
    return scanner(path)


@given(st.binary(min_size=0, max_size=4096))
def test_pickle_scanner_never_crashes_on_random_bytes(data):
    findings = _write_and_scan(scan_pickle, ".pkl", data)
    assert isinstance(findings, list)


@given(st.binary(min_size=0, max_size=4096))
def test_onnx_scanner_never_crashes_on_random_bytes(data):
    findings = _write_and_scan(scan_onnx, ".onnx", data)
    assert isinstance(findings, list)


@given(st.binary(min_size=0, max_size=4096))
def test_h5_scanner_never_crashes_on_random_bytes(data):
    findings = _write_and_scan(scan_h5, ".h5", data)
    assert isinstance(findings, list)


def _mutate(original: bytes, rng: random.Random, num_flips: int) -> bytes:
    buf = bytearray(original)
    for _ in range(num_flips):
        if not buf:
            break
        pos = rng.randrange(len(buf))
        buf[pos] = rng.randrange(256)
    return bytes(buf)


_REAL_FIXTURE_FILES = [
    FIXTURES_DIR / "benign" / "benign_dict.pkl",
    FIXTURES_DIR / "malicious" / "reduce_os_system.pkl",
    FIXTURES_DIR / "malicious" / "gadget_chain_subclasses.pkl",
    FIXTURES_DIR / "benign" / "benign_identity.onnx",
    FIXTURES_DIR / "malicious" / "external_data_path_traversal.onnx",
    FIXTURES_DIR / "benign" / "benign_dense_model.h5",
    FIXTURES_DIR / "malicious" / "lambda_marshalled_bytecode.h5",
]

_SCANNER_BY_SUFFIX = {
    ".pkl": scan_pickle,
    ".onnx": scan_onnx,
    ".h5": scan_h5,
}


@given(
    fixture_index=st.integers(min_value=0, max_value=len(_REAL_FIXTURE_FILES) - 1),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
    num_flips=st.integers(min_value=1, max_value=20),
)
def test_scanners_never_crash_on_mutated_real_files(fixture_index, seed, num_flips):
    # Mutation-based fuzzing (bit/byte flips on real valid files) explores
    # "almost-valid" structure that pure random bytes rarely reach --
    # complementary to the random-bytes tests above, same idea the
    # PickleFuzzer paper's discussion section recommends (grammar/valid
    # seeding + mutation covers more than either alone).
    original_path = _REAL_FIXTURE_FILES[fixture_index]
    original = original_path.read_bytes()
    mutated = _mutate(original, random.Random(seed), num_flips)

    scanner = _SCANNER_BY_SUFFIX[original_path.suffix]
    findings = _write_and_scan(scanner, original_path.suffix, mutated)
    assert isinstance(findings, list)
