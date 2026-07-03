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

🚧 Early development — pickle scanner in progress.

## Install (dev)

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -e ".[dev]"
```

## Usage

```bash
mlscan path/to/model.pkl
```

## License

MIT
