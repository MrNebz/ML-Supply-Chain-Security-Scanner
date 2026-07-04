"""
Shared pytest/hypothesis configuration.

Registers two hypothesis profiles instead of hardcoding max_examples/
deadline in every fuzz test: "default" (thorough, for local runs) and
"ci" (fewer examples, loaded automatically when the CI env var is set --
GitHub Actions sets this by default). This is centralized here so tuning
CI speed doesn't require touching test logic.

Also see [tool.pytest.ini_options] in pyproject.toml for the global
per-test timeout (pytest-timeout) -- a hard outer safety net independent
of hypothesis's own deadline, since a hypothesis `deadline` can only
detect slowness in code that eventually returns control to Python; it
cannot interrupt a genuine block in a C-level call (e.g. inside h5py/
onnx). pytest-timeout's signal-based interruption can.
"""

import os

from hypothesis import HealthCheck, settings

_COMMON = {
    "deadline": 2000,  # ms per example; was None, which meant no per-example
    # timeout existed at all -- a real gap given CI hung for 1.5h+ with zero
    # indication of which example (if any) was slow.
    "suppress_health_check": [HealthCheck.function_scoped_fixture],
}

settings.register_profile("default", max_examples=200, **_COMMON)
settings.register_profile("ci", max_examples=50, **_COMMON)

settings.load_profile("ci" if os.environ.get("CI") else "default")
