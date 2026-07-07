# mlscan — ML Model Supply-Chain Security Scanner

Static analysis tool that scans ML model files (`.pkl`/`.pt`, `.onnx`, `.h5`) for
embedded malicious payloads and unsafe deserialization patterns, without ever
executing the file.

## Why

- **Pickle** (`.pkl`, and PyTorch's `.pt`/`.pth`) is a bytecode format — loading one
  can execute arbitrary code via crafted `GLOBAL`/`REDUCE` opcodes.
- **ONNX** files are protobuf computation graphs — safe from code execution by
  design, but can hide oversized nodes, path-traversal via external data
  references, or malicious custom operators.
- **HDF5/Keras** (`.h5`) models can embed `Lambda` layers whose config contains
  marshalled Python bytecode, executed on load if `custom_objects` trust isn't
  restricted.

`mlscan` parses each format as structured data and flags dangerous patterns —
similar in spirit to how `Trivy` scans container images, applied to the ML
model supply chain.

## Status

🚧 Active development — pickle (incl. zip-wrapped PyTorch checkpoints), ONNX,
and HDF5/Keras scanners implemented and tested (82 tests: hand-crafted,
parametrized, real-world, fuzzed, CLI-level, and multi-finding combinations).
An optional, experimental ML anomaly layer also exists (see below) — trained
and evaluated, currently shows no measurable benefit over the rule-based
scanners and is documented honestly as a negative result.

## Install (dev)

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -e ".[dev]"
```

## Usage

```bash
mlscan path/to/model.pkl
mlscan --json path/to/model.onnx
```

File format is detected from actual file content (magic bytes / protobuf
parse / zip structure), not just the extension — a malicious pickle
renamed to `.onnx`, or a malicious zip-wrapped PyTorch checkpoint renamed
to any other extension, is still caught and scanned as a pickle.

## Interactive scanner (Streamlit)

```bash
pip install -e ".[ui]"
streamlit run ui/app.py
```

Opens a local browser page with drag-and-drop file upload. This calls the
exact same `scan_pickle`/`scan_onnx`/`scan_h5` functions the CLI uses —
nothing is uploaded anywhere, and the file is only parsed, never executed.

## Testing

```bash
pytest -v
```

For an interactive HTML test report (pass/fail per test) and an HTML
coverage report, generated fresh from the current test suite:

```bash
python scripts/generate_test_report.py
# then open test_report.html and htmlcov/index.html
```

Coverage combines five sources, deliberately not just hand-crafted fixtures:
- **Hand-crafted fixtures** (`tests/fixtures/`) — one example per detection
  rule, generated via `scripts/generate_*_fixtures.py`.
- **Parametrized coverage** (`test_*_scanner_parametrized.py`) — every entry
  in each rule table (every dangerous pickle import, every ONNX domain
  tier, several Lambda payload variants) is verified individually, not
  just 1-2 examples.
- **Real-world fixtures** (`tests/fixtures/benign/real_world/`, pulled via
  `scripts/download_real_world_fixtures.py`) — real, unmodified files from
  HuggingFace Hub, used as a false-positive check hand-crafted fixtures
  can't provide. This is how the ONNX vendor-domain false positive and the
  joblib parsing limitation below were found.
- **Fuzz testing** (`test_fuzzing.py`, via `hypothesis`) — random bytes and
  mutated real fixtures thrown at all three scanners, asserting they never
  crash. This is the same methodology used by the PickleFuzzer paper cited
  below, applied to our own tool instead of CPython's pickle modules — it
  found two real crash bugs (ONNX/H5 scanners crashing on malformed input,
  and a bytes-vs-str protobuf edge case), both fixed.
- **CLI-level tests** (`test_cli.py`) — the actual `mlscan` command run as a
  subprocess, checking exit codes and `--json` output shape, not just the
  internal Python functions.
- **Combination fixtures** (`test_combination_findings.py`) — single files
  triggering more than one rule at once, verifying findings don't mask or
  interfere with each other.

## Known limitations (found via real-world testing, not hypothetical)

- **Pickle protocol 0/1 detection**: content-based format sniffing relies
  on the `PROTO` opcode (protocol ≥ 2). Older ASCII-based pickle protocols
  have no reliable magic number and fall back to extension-based detection.
- **joblib's raw-array-embedding convention breaks pure opcode parsing**: a
  real LightGBM model pulled from HuggingFace Hub
  (`kojongmo/LightGBM_Q1_model.pkl`) serializes a
  `joblib.numpy_pickle.NumpyArrayWrapper` object, after which joblib writes
  the *raw numpy array bytes directly into the file stream* (bypassing
  pickle opcodes entirely, so its custom loader can mmap the array straight
  from the file handle). `pickletools` has no way to know to skip those raw
  bytes, so it tries to interpret them as opcodes and fails — triggering
  our `PICKLE_PARSE_ERROR` rule as a false positive on this legitimate
  file. This is a structural limitation of pure opcode-stream analysis
  when the on-disk format is "pickle + a custom binary-embedding
  convention," not a bug in our detection logic. **Confirmed this isn't
  specific to our tool**: ModelScan 0.8.8 hits the exact same parse
  failure on the same file (see benchmark below). A real fix would require
  joblib-format-aware recovery (detect `NumpyArrayWrapper`, compute the
  byte length from its `shape`/`dtype`, skip that many raw bytes, resume
  opcode parsing) — deliberately not implemented as a blind byte-skip,
  since that would itself be an evasion vector (nothing stops an attacker
  emitting a fake `NumpyArrayWrapper` reference specifically to make a
  scanner treat subsequent bytes as "safe to skip" unchecked). Documented
  and regression-tested (`tests/test_real_world_fixtures.py`, marked
  `xfail`) rather than silently worked around.

## Known techniques this tool defends against

**pickletools/pickle base-10 vs base-0 discrepancy.** `pickletools` (used by
most pickle scanners, including this one and `picklescan`) parses `INT`/`LONG`
opcode arguments strictly as base-10, while the real `pickle` and `_pickle`
deserializers parse them as base-0 (accepting hex, e.g. `0x1337`). A payload
built around that mismatch crashes `pickletools` while still executing fine
under the real unpickler — a disclosed, bug-bounty-confirmed technique for
bypassing `pickletools`-based scanners. `mlscan` treats a mid-stream parse
failure as a `PICKLE_PARSE_ERROR` finding rather than crashing or silently
reporting a clean scan.
Source: Applegate & Kellas, *"PICKLEFUZZER: A Case Study in Fuzzing for
Discrepancies Between Python Pickle Implementations"* (2026).

**Restricted-unpickler gadget chains.** Even when a pickle only references
"safe" modules/classes, `getattr`-style gadgets can walk the live class
hierarchy (`int.__subclasses__()` → find a class whose
`__init__.__globals__` exposes `__builtins__` → reach `eval`/`exec`/
`os.system`) without ever directly referencing a dangerous function.
`mlscan` flags `builtins.getattr`/`setattr`/`vars`/`operator.attrgetter` as
dangerous callables, and independently flags gadget-chain attribute names
(`__subclasses__`, `__globals__`, `__builtins__`, `__base__`, `__bases__`,
`__mro__`) appearing anywhere in the opcode stream as `PICKLE_GADGET_CHAIN_ATTRIBUTE`
(CRITICAL), regardless of which module exposed them.
Source: Huang, Huang & Huang, *"Pain Pickle: Bypassing Python Restricted
Unpickler for Automatic Exploit Generation"*, IEEE QRS (2022).

## Benchmark vs. ModelScan (Protect AI, v0.8.8)

Ran `modelscan -p tests/fixtures` against our full fixture set:

| Finding | mlscan | ModelScan 0.8.8 |
|---|---|---|
| ONNX support at all | ✅ 3 rules (path traversal, custom domains, oversized dims) | ❌ every `.onnx` fixture silently skipped — no ONNX scanner in this version |
| `int_opcode_hex_evasion.pkl` (base-10/base-0 discrepancy) | ✅ flagged `PICKLE_PARSE_ERROR`, HIGH | ⚠️ logged as a top-level "Error", **not counted in Total Issues** — a real malicious file that produces zero reported issues |
| joblib `NumpyArrayWrapper` real-world false positive | ⚠️ flagged, documented `xfail` limitation | ⚠️ hits the identical parse error, also excluded from Issues — confirms this is a genuine `pickletools` limitation, not specific to either tool |
| Keras Lambda severity granularity | ✅ distinguishes marshalled bytecode (CRITICAL) from named-function reference (MEDIUM) | Both reported as a single MEDIUM "unsafe operator", no distinction |
| Zip-wrapped PyTorch checkpoints (`torch.save()` since 1.6) | ✅ unwraps and scans `data.pkl` | ✅ also unwraps and scans correctly |
| `gadget_chain_subclasses.pkl` (`int.__subclasses__` gadget) | ✅ flagged CRITICAL `PICKLE_GADGET_CHAIN_ATTRIBUTE` | Not tested against this version — not included in the standard scan output categories observed |

Reproduce: `pip install modelscan && modelscan -p tests/fixtures --show-skipped`

## Optional ML anomaly-detection layer (experimental — `--ml`)

A secondary, opt-in signal layered on top of the rule-based pickle scanner:
an `IsolationForest` trained on opcode-derived structural features
(22 dimensions — 9 scalars like byte length/entropy/opcode counts, plus
frequency counts for 13 security-relevant opcodes such as `GLOBAL`,
`REDUCE`, `BUILD`, `NEWOBJ`), fit on benign pickle files only. Requires
`pip install -e ".[ml]"`; degrades gracefully to "no additional finding"
if that extra isn't installed.

**Training data required real cleanup.** `scripts/download_ml_training_corpus.py`
pulls benign pickle files from HuggingFace Hub — but naive keyword search
(`pkl`, `pickle`, `joblib`, ...) surfaces a large amount of genuinely
malicious/proof-of-concept content published by security researchers
(repos named things like `pickle-scanner-bypass-*`, `*-rce-poc`,
`malicious_model.pkl`), not just real benign models. Of 214 candidate
files collected, **our own rule-based scanner flagged and rejected 75
of them (35%)** before training — using `mlscan` itself as a
data-quality gate on its own training data. 139 genuine samples survived
to train on.

**Honest result: this layer currently adds no measurable detection
power.** Evaluated against our fixture set
(`scripts/evaluate_anomaly_model.py`), the model's raw anomaly scores
show no separation between benign and malicious pickle files — the
known-malicious fixtures actually scored *slightly more "normal"* than
one of the benign files. This isn't a calibration/threshold issue (we
checked the raw `decision_function` scores directly, not just the
pass/fail label). The root cause: our malicious fixtures are minimal,
single-`GLOBAL`+`REDUCE` payloads that are structurally simple — low
opcode diversity, small size — which doesn't register as "unusual" by
any of the 22 gross structural statistics this layer tracks. What makes
them dangerous is *semantic* (which specific callable is referenced),
not *structural*, and that's exactly what the rule-based scanner already
checks directly. This is a legitimate negative result, not a bug: it
demonstrates concretely why gross structural/statistical ML features
can't substitute for rule-based semantic checks on this kind of file,
rather than just asserting that claim.

Reproduce: `python scripts/download_ml_training_corpus.py && python
scripts/train_pickle_anomaly_model.py && python
scripts/evaluate_anomaly_model.py`

## References

- E. Sultanik, *"Never a dill moment: Exploiting machine learning pickle
  files"*, Trail of Bits (2021) — [`fickling`](https://github.com/trailofbits/fickling)
- Protect AI — [`modelscan`](https://github.com/protectai/modelscan)
- Huang, Huang & Huang, *"Pain Pickle: Bypassing Python Restricted
  Unpickler for Automatic Exploit Generation"*, IEEE QRS (2022)
- Applegate & Kellas, *"PICKLEFUZZER: A Case Study in Fuzzing for
  Discrepancies Between Python Pickle Implementations"* (2026)

## License

MIT
