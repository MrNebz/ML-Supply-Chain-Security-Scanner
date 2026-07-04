"""
Programmatic coverage: instead of hand-writing one static fixture per
dangerous (module, name) pair, generate a minimal pickle payload for
every entry in DANGEROUS_IMPORTS and confirm each one is actually
detected. This is the difference between "we tested os.system" and
"we verified every rule we claim to enforce."

pickle.dump() only needs to serialize a reference to the callable plus a
pickleable argument -- it never calls the callable, so a dummy argument
is fine even for functions that would need different real arguments.
"""

import importlib
import pickle

import pytest

from mlscan.report import Severity
from mlscan.scanners.pickle_scanner import scan_pickle
from mlscan.scanners.pickle_scanner.rules import DANGEROUS_IMPORTS


def _dump_reduce_payload(tmp_path, module: str, name: str, index: int):
    target = getattr(importlib.import_module(module), name)

    class _Exploit:
        def __reduce__(self):
            return (target, ("dummy-arg",))

    path = tmp_path / f"payload_{index}.pkl"
    with open(path, "wb") as f:
        pickle.dump(_Exploit(), f)
    return path


@pytest.mark.parametrize("module,name", sorted(DANGEROUS_IMPORTS))
def test_every_dangerous_import_is_detected_via_reduce(tmp_path, module, name):
    try:
        importlib.import_module(module)
    except ModuleNotFoundError:
        pytest.skip(f"{module} not available on this platform")

    path = _dump_reduce_payload(tmp_path, module, name, index=0)
    findings = scan_pickle(path)

    # We don't assert the exact module string in the message: pickle
    # serializes a reference using the callable's *actual* __module__,
    # which can differ from the module we imported it through (e.g.
    # os.system round-trips as nt.system on Windows, pickle.loads as
    # _pickle.loads) -- that aliasing is exactly what DANGEROUS_IMPORTS
    # accounts for. What matters is that *some* CRITICAL finding fires.
    assert len(findings) == 1, (
        f"expected exactly one finding for {module}.{name}, got {findings}"
    )
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "PICKLE_DANGEROUS_REDUCE"
    assert name in findings[0].message
