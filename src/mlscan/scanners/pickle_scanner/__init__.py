from mlscan.report import Finding, Severity
from mlscan.scanners.pickle_scanner.container import load_pickle_bytes
from mlscan.scanners.pickle_scanner.opcodes import extract_global_refs, extract_string_literals
from mlscan.scanners.pickle_scanner.rules import (
    DANGEROUS_IMPORTS,
    DANGEROUS_MODULE_PREFIXES,
    GADGET_CHAIN_ATTRIBUTES,
)


def scan_pickle(path) -> list[Finding]:
    # Transparently unwraps zip-wrapped PyTorch checkpoints (torch.save()
    # since PyTorch 1.6) to their inner data.pkl opcode stream; returns
    # the file's own bytes unchanged for a plain pickle/.pt/.pth file.
    data = load_pickle_bytes(path)
    findings: list[Finding] = []

    refs, parse_error = extract_global_refs(data)

    if parse_error is not None:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                rule_id="PICKLE_PARSE_ERROR",
                message=_parse_error_message(parse_error, refs),
                location="opcode stream",
            )
        )

    for ref in refs:
        key = (ref.module, ref.name)
        is_known_dangerous = key in DANGEROUS_IMPORTS
        top_level_module = ref.module.split(".")[0]
        is_suspicious_prefix = top_level_module in DANGEROUS_MODULE_PREFIXES

        if is_known_dangerous and ref.followed_by_reduce:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    rule_id="PICKLE_DANGEROUS_REDUCE",
                    message=(
                        f"Pickle calls {ref.module}.{ref.name}(...) automatically "
                        "on load (GLOBAL/STACK_GLOBAL followed by REDUCE)"
                    ),
                    location=f"opcode offset {ref.offset}",
                )
            )
        elif is_known_dangerous:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    rule_id="PICKLE_DANGEROUS_IMPORT",
                    message=f"Pickle references dangerous callable {ref.module}.{ref.name}",
                    location=f"opcode offset {ref.offset}",
                )
            )
        elif is_suspicious_prefix:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule_id="PICKLE_SUSPICIOUS_MODULE",
                    message=f"Pickle references module '{ref.module}' from a sensitive package",
                    location=f"opcode offset {ref.offset}",
                )
            )

    for literal, offset in extract_string_literals(data):
        if literal in GADGET_CHAIN_ATTRIBUTES:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    rule_id="PICKLE_GADGET_CHAIN_ATTRIBUTE",
                    message=(
                        f"Pickle references attribute '{literal}' -- a standard "
                        "gadget-chain building block for escaping restricted "
                        "unpicklers/sandboxes by walking the live class hierarchy "
                        "(e.g. getattr(int, '__subclasses__')() -> find a class "
                        "whose __init__.__globals__ exposes __builtins__ -> reach "
                        "eval/exec/os.system), regardless of which allowed module "
                        "first exposed it"
                    ),
                    location=f"opcode offset {offset}",
                )
            )

    return findings


# Names used by joblib.numpy_pickle's raw-array-embedding convention: it
# pickles a lightweight NumpyArrayWrapper describing shape/dtype, then
# writes the actual array bytes directly into the file stream (bypassing
# pickle opcodes so its own loader can mmap them). pickletools has no way
# to know to skip those raw bytes and fails trying to parse them as
# opcodes -- a real false-positive source found via real-world testing
# (see tests/test_real_world_fixtures.py), not an attacker technique.
_KNOWN_BENIGN_PARSE_FAILURE_MARKERS = {"NumpyArrayWrapper"}


def _parse_error_message(parse_error: Exception, refs: list) -> str:
    base = (
        f"pickletools could not fully parse this opcode stream "
        f"({type(parse_error).__name__}: {parse_error}). Malformed or "
        "non-standard opcode encoding (e.g. hex-formatted integer "
        "arguments) is a disclosed technique for bypassing "
        "pickletools-based scanners while the real pickle/_pickle "
        "deserializers still load and execute the payload -- treat "
        "this file as suspicious regardless of what was found before "
        "the parse failure."
    )

    if any(ref.name in _KNOWN_BENIGN_PARSE_FAILURE_MARKERS for ref in refs):
        # NOTE: we deliberately do NOT suppress or downgrade this finding
        # just because a NumpyArrayWrapper reference appears earlier in
        # the stream. Doing so would itself be an evasion vector: nothing
        # stops an attacker from emitting a fake NumpyArrayWrapper-like
        # GLOBAL reference specifically to make a scanner treat whatever
        # raw bytes follow as "safe to skip" without actually verifying
        # the skipped length against real shape/dtype math. A safe fix
        # would require reconstructing the exact byte length from the
        # wrapper's own state and verifying it -- out of scope here, so
        # we surface this context for a human reviewer but keep the
        # finding at full severity.
        base += (
            " Note: this stream references a NumpyArrayWrapper "
            "(joblib.numpy_pickle's raw-array-embedding convention) shortly "
            "before the parse failure, which often indicates a legitimate "
            "large embedded array rather than an attack -- but this tool "
            "does not verify that automatically (doing so unsafely would "
            "itself be a bypass vector), so manual review is recommended."
        )

    return base
