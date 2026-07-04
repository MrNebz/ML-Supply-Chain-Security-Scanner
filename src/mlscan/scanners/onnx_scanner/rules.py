"""
Known-safe ONNX operator domains, and thresholds used to flag suspicious
tensor shapes.

An empty domain string and "ai.onnx"/"ai.onnx.ml"/"ai.onnx.preview.training"
are the standard operator sets ONNX runtimes implement natively -- anything
else means the model requires a custom (often native/compiled) operator
library to even run.
"""

SAFE_DOMAINS: set[str] = {
    "",
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.preview.training",
    "ai.onnx.training",
}

# Domains published and maintained by known vendors as officially supported
# ONNX Runtime extensions -- not arbitrary third-party native code, but
# still not part of the core ONNX operator set, so worth a lower-severity
# distinct finding rather than either silence or a false HIGH alarm.
# Discovered via real-world testing: com.microsoft is extremely common in
# ONNX-Runtime-optimized/quantized models (Attention, BiasGelu,
# RotaryEmbedding, GroupQueryAttention, ...) pulled from HuggingFace Hub --
# treating it identically to a fully unknown custom domain produced false
# positives on legitimate, widely-used models.
KNOWN_VENDOR_EXTENSION_DOMAINS: set[str] = {
    "com.microsoft",
    "com.microsoft.experimental",
    "org.pytorch.aten",
}

# A single tensor dimension this large has no realistic legitimate use in a
# small/medium model and is a plausible resource-exhaustion (allocation
# bomb) attempt via a metadata field rather than actual stored data.
MAX_REASONABLE_DIM = 10**8
