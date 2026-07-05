"""
Fixed-length numeric feature vector for a pickle opcode stream.

Used only by the optional ML anomaly-detection layer (the `mlscan[ml]`
extra, enabled with --ml) -- this is a secondary, experimental signal
layered on top of the primary rule-based detection. It never runs
unless explicitly requested, and it never replaces or overrides a
rule-based finding; see anomaly.py.

No sklearn/skops import here -- this module has zero extra dependencies
beyond the stdlib, so importing it (e.g. from a training script) doesn't
require the ml extra to be installed.
"""

import math
from collections import Counter

from mlscan.scanners.pickle_scanner.opcodes import parse_opcodes

# Deliberately NOT every opcode pickletools knows about (~68 of them) --
# with a training corpus in the hundreds of samples, a ~77-dimensional
# feature vector puts sample count below dimension count, which makes
# any unsupervised model closer to memorizing training points than
# learning a real distribution. Keeping only the opcodes that actually
# carry security signal (code-execution / external-reference primitives)
# cuts this to a dimensionality a few-hundred-sample corpus can support:
#   - GLOBAL / STACK_GLOBAL: module/class reference -- the core of the
#     __reduce__ exploit pattern
#   - REDUCE: function call -- the other half of that pattern
#   - BUILD: __setstate__ application (a documented alternate gadget path,
#     see Huang, Huang & Huang "Pain Pickle", IEEE QRS 2022)
#   - INST / OBJ: older (pre-protocol-2) instance-creation opcodes
#   - NEWOBJ / NEWOBJ_EX: modern instance-creation opcodes
#   - PERSID / BINPERSID: persistent-id external-reference mechanism
#   - EXT1 / EXT2 / EXT4: the extension-registry mechanism -- obscure,
#     but another way to reference code outside the pickle stream itself
_SECURITY_RELEVANT_OPCODE_NAMES = sorted(
    {
        "GLOBAL",
        "STACK_GLOBAL",
        "REDUCE",
        "BUILD",
        "INST",
        "OBJ",
        "NEWOBJ",
        "NEWOBJ_EX",
        "PERSID",
        "BINPERSID",
        "EXT1",
        "EXT2",
        "EXT4",
    }
)

_GLOBAL_OPCODE_NAMES = {"GLOBAL", "STACK_GLOBAL"}

_STRING_PUSH_OPCODE_NAMES = {
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "UNICODE",
    "SHORT_BINSTRING",
    "BINSTRING",
    "STRING",
}

_SCALAR_FEATURE_NAMES = [
    "byte_length",
    "opcode_count",
    "unique_opcode_ratio",
    "global_count",
    "reduce_count",
    "reduce_to_global_ratio",
    "byte_entropy",
    "max_string_length",
    "parse_error",
]


def feature_names() -> list[str]:
    return _SCALAR_FEATURE_NAMES + [
        f"opcode_freq::{name}" for name in _SECURITY_RELEVANT_OPCODE_NAMES
    ]


def extract_features(data: bytes) -> list[float]:
    ops, parse_error = parse_opcodes(data)
    opcode_count = len(ops)

    counts = Counter(opcode.name for opcode, _arg, _pos in ops)
    global_count = sum(counts.get(name, 0) for name in _GLOBAL_OPCODE_NAMES)
    reduce_count = counts.get("REDUCE", 0)
    unique_ratio = (len(counts) / opcode_count) if opcode_count else 0.0
    reduce_ratio = (reduce_count / global_count) if global_count else 0.0

    string_lengths = [
        len(arg)
        for opcode, arg, _pos in ops
        if opcode.name in _STRING_PUSH_OPCODE_NAMES and isinstance(arg, str)
    ]
    max_string_length = float(max(string_lengths)) if string_lengths else 0.0

    scalars = [
        float(len(data)),
        float(opcode_count),
        unique_ratio,
        float(global_count),
        float(reduce_count),
        reduce_ratio,
        _byte_entropy(data),
        max_string_length,
        1.0 if parse_error is not None else 0.0,
    ]

    opcode_freqs = [
        (counts.get(name, 0) / opcode_count) if opcode_count else 0.0
        for name in _SECURITY_RELEVANT_OPCODE_NAMES
    ]

    return scalars + opcode_freqs


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
