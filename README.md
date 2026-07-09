# mlscan — ML Model Supply-Chain Security Scanner

[![CI](https://github.com/MrNebz/ML-Supply-Chain-Security-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/MrNebz/ML-Supply-Chain-Security-Scanner/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#requirements)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A static-analysis security scanner for machine-learning model files —
**pickle** (`.pkl`, PyTorch `.pt`/`.pth`), **ONNX** (`.onnx`), and
**HDF5/Keras** (`.h5`). It inspects each file as structured data and flags
dangerous patterns (arbitrary code execution, path traversal, gadget chains,
malicious operators) **without ever loading or executing the model** — the
same idea as `Trivy` or `Grype` for container images, applied to the ML
model supply chain.

> **📖 Read this first:** the full technical write-up — how each format's
> vulnerability class works from first principles, every bug found during
> development and how it was found, the design rationale, the benchmark
> against ModelScan, and the ML anomaly-detection experiment (including its
> honest negative result) — lives in **[`PROJECT_REPORT.md`](PROJECT_REPORT.md)**.
> This README only covers *how to get the project running*. If you want to
> understand *what it does and why it works the way it does*, start there.

---

## Table of contents

- [What this project is](#what-this-project-is)
- [Threats detected, by format](#threats-detected-by-format)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start (CLI)](#quick-start-cli)
- [Interactive scanner (Streamlit UI)](#interactive-scanner-streamlit-ui)
- [Optional ML anomaly-detection layer](#optional-ml-anomaly-detection-layer)
- [Running the tests](#running-the-tests)
- [Benchmark vs. ModelScan](#benchmark-vs-modelscan)
- [Known limitations](#known-limitations)
- [Continuous integration](#continuous-integration)
- [Reference material](#reference-material)
- [License](#license)

## What this project is

Loading an ML model file isn't a neutral operation for every format:

| Format | Risk | mlscan's approach |
|---|---|---|
| Pickle / PyTorch (`.pkl`, `.pt`, `.pth`) | It's a bytecode format — deserializing one can execute arbitrary code | Disassembles the opcode stream and flags dangerous `GLOBAL`/`REDUCE` calls, restricted-unpickler gadget chains, and known scanner-bypass techniques, **without calling `pickle.load`** |
| ONNX (`.onnx`) | Protobuf graph, safe from code execution by design, but can hide path traversal, oversized tensors, or malicious custom operators | Parses the protobuf graph structure directly |
| HDF5 / Keras (`.h5`) | Can embed a `Lambda` layer whose config contains marshalled Python bytecode, executed on load | Inspects the HDF5 model config for unsafe `Lambda` payloads |

Detection is **content-based, not extension-based**: a malicious pickle
renamed to `.onnx`, or a malicious zip-wrapped PyTorch checkpoint renamed to
anything else, is still identified by its actual content and scanned
correctly.

For the *why* and *how* behind every rule above, see
**[`PROJECT_REPORT.md`](PROJECT_REPORT.md)**.

## Threats detected, by format

<details>
<summary>Pickle / PyTorch</summary>

- Dangerous `GLOBAL`+`REDUCE` calls (e.g. `os.system`, `subprocess.*`, `eval`, `exec`)
- Restricted-unpickler gadget chains (`__subclasses__`, `__globals__`, `__builtins__`, `__base__`, `__bases__`, `__mro__`)
- The disclosed `pickletools` base-10 vs. base-0 integer-parsing bypass
- Zip-wrapped PyTorch checkpoints (`torch.save()` since 1.6) — unwrapped and scanned
- Malformed/truncated streams reported as a finding, not a silent pass or a crash

</details>

<details>
<summary>ONNX</summary>

- External-data path traversal
- Malicious/unexpected custom operator domains
- Oversized declared tensor dimensions

</details>

<details>
<summary>HDF5 / Keras</summary>

- `Lambda` layers containing marshalled Python bytecode (CRITICAL)
- `Lambda` layers referencing a named function by string (MEDIUM)

</details>

## Repository layout

```
.
├── src/mlscan/                  # the library + CLI
│   ├── cli.py                  # `mlscan` command entry point
│   ├── detect.py                # content-based format sniffing
│   ├── report.py                # Finding / Severity data model
│   ├── models/pickle_anomaly.skops   # trained optional ML model artifact
│   └── scanners/
│       ├── pickle_scanner/      # opcode disassembly, rules, gadget-chain + anomaly detection
│       ├── onnx_scanner/        # protobuf graph inspection + rules
│       └── h5_scanner/          # HDF5 Lambda-layer inspection
├── scripts/                      # fixture generation, HF corpus download, ML training/eval, test-report generation
├── tests/                        # pytest suite (unit, parametrized, fuzz, CLI, real-world fixtures)
│   └── fixtures/                 # benign + malicious sample files used by tests
├── ui/app.py                     # local Streamlit drag-and-drop scanner
├── related materials/            # source papers referenced in PROJECT_REPORT.md
├── PROJECT_REPORT.md              # full technical write-up — read this for the "why"
├── README.md                      # this file — the "how to run it" guide
└── pyproject.toml                 # packaging, dependencies, optional extras
```

## Requirements

- Python **3.10+**
- Git
- (Optional) a virtual environment tool — `venv` is used below, but `conda`/`uv` work identically

## Installation

Clone the repository and install it in editable mode inside a virtual
environment:

```bash
git clone https://github.com/MrNebz/ML-Supply-Chain-Security-Scanner.git
cd ML-Supply-Chain-Security-Scanner

python -m venv .venv

# Activate the virtual environment
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS / Linux

pip install -e ".[dev]"
```

This installs the core scanner plus everything needed to run the test
suite. Two more optional extras exist and can be combined as needed:

```bash
pip install -e ".[ml]"   # optional ML anomaly-detection layer (scikit-learn, skops)
pip install -e ".[ui]"   # interactive Streamlit scanner
pip install -e ".[dev,ml,ui]"   # everything at once
```

Verify the install:

```bash
mlscan --help
```

## Quick start (CLI)

```bash
# Scan a single file — human-readable output
mlscan path/to/model.pkl

# Machine-readable JSON output (for CI pipelines / tooling integration)
mlscan --json path/to/model.onnx

# Also run the optional ML anomaly-detection layer on a pickle file
# (requires: pip install -e ".[ml]")
mlscan --ml path/to/model.pkl
```

**Exit codes**: `mlscan` returns `1` if any `CRITICAL` or `HIGH` severity
finding is reported, and `0` otherwise — safe to wire directly into a CI
pipeline as a gate. Format-detection failure returns `2`.

Example output:

```
$ mlscan tests/fixtures/malicious/reduce_os_system.pkl
tests/fixtures/malicious/reduce_os_system.pkl: 1 finding(s)
  [CRITICAL] PICKLE_DANGEROUS_CALL: os.system referenced via GLOBAL+REDUCE
```

## Interactive scanner (Streamlit UI)

A local, browser-based drag-and-drop scanner that calls the exact same
`scan_pickle` / `scan_onnx` / `scan_h5` functions as the CLI — nothing is
uploaded anywhere, and files are only parsed, never executed.

```bash
pip install -e ".[ui]"
streamlit run ui/app.py
```

This opens the app in your default browser (typically `http://localhost:8501`).
Drag a `.pkl`/`.pt`/`.pth`, `.onnx`, or `.h5` file onto the page to see its
findings rendered live.

## Optional ML anomaly-detection layer

An experimental, opt-in secondary signal for pickle files — an
`IsolationForest` trained on opcode-derived structural features. It is
**not a replacement for the rule-based scanner**, and honestly, in its
current state, **adds no measurable detection power** (see
[`PROJECT_REPORT.md`, §10](PROJECT_REPORT.md) for the full negative-result
writeup and why). It ships mainly as a documented, reproducible experiment.

```bash
pip install -e ".[ml]"

# Reproduce the full pipeline from scratch:
python scripts/download_ml_training_corpus.py
python scripts/train_pickle_anomaly_model.py
python scripts/evaluate_anomaly_model.py
```

## Running the tests

```bash
pytest -v
```

For a live, interactive HTML test report and an HTML coverage report,
generated fresh from the current test suite:

```bash
python scripts/generate_test_report.py
# then open test_report.html and htmlcov/index.html in a browser
```

The suite (80+ tests) combines hand-crafted fixtures, exhaustive
parametrized rule-table coverage, real unmodified files pulled from
HuggingFace Hub, `hypothesis`-based fuzz testing, CLI-level subprocess
tests, and multi-finding combination fixtures. See
[`PROJECT_REPORT.md`, §7](PROJECT_REPORT.md) for the full testing
methodology and what each layer caught.

## Benchmark vs. ModelScan

Benchmarked against [Protect AI's `modelscan`](https://github.com/protectai/modelscan)
(v0.8.8) on the full fixture set — `mlscan` adds ONNX support entirely
absent from that ModelScan version, correctly flags a disclosed
`pickletools` bypass technique that ModelScan silently excludes from its
issue count, and distinguishes Keras `Lambda`-layer severities that
ModelScan reports as a single undifferentiated finding.

Reproduce it yourself:

```bash
pip install modelscan
modelscan -p tests/fixtures --show-skipped
```

Full comparison table: [`PROJECT_REPORT.md`, §8](PROJECT_REPORT.md).

## Known limitations

- Pickle protocol 0/1 (no `PROTO` opcode) has no reliable content-based
  signature and falls back to extension-based detection.
- `joblib`'s raw-array-embedding convention (used by some scikit-learn/LightGBM
  exports) breaks pure opcode-stream parsing and produces a false-positive
  parse-error finding — confirmed to affect ModelScan identically, not a
  bug specific to this tool.

Full explanation and reasoning: [`PROJECT_REPORT.md`, §9](PROJECT_REPORT.md).

## Continuous integration

Every push and pull request runs, via GitHub Actions
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
ruff check src tests
pytest
```

## Reference material

Primary sources behind the detection rules (full PDFs in
[`related materials/`](related%20materials/)):

- E. Sultanik, *"Never a dill moment: Exploiting machine learning pickle
  files"*, Trail of Bits (2021) — [`fickling`](https://github.com/trailofbits/fickling)
- Huang, Huang & Huang, *"Pain Pickle: Bypassing Python Restricted
  Unpickler for Automatic Exploit Generation"*, IEEE QRS (2022)
- Applegate & Kellas, *"PickleFuzzer: A Case Study in Fuzzing for
  Discrepancies Between Python Pickle Implementations"* (2026)
- *"Interoperability in Deep Learning: A User Survey and Failure Analysis
  of ONNX Model Converters"*
- *"An overview of the HDF5 technology suite and its applications"*
- Protect AI — [`modelscan`](https://github.com/protectai/modelscan)

For how each of these informed a specific detection rule, see
[`PROJECT_REPORT.md`, §11](PROJECT_REPORT.md).

## License

[MIT](LICENSE)
