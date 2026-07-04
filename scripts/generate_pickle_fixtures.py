"""
Generates ground-truth pickle fixtures for tests/fixtures/{benign,malicious}.

Run once with: python scripts/generate_pickle_fixtures.py

Note: this script CREATES malicious pickle files but never LOADS them.
Nothing here executes attacker code -- these files are only ever meant
to be fed to mlscan's static scanner, never to pickle.load().
"""

import pickle
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def write_benign_dict():
    data = {"weights": [0.1, 0.2, 0.3], "name": "tiny_model", "bias": 0.01}
    path = FIXTURES_DIR / "benign" / "benign_dict.pkl"
    with open(path, "wb") as f:
        pickle.dump(data, f)
    print(f"wrote {path}")


class _OsSystemExploit:
    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


def write_malicious_os_system():
    path = FIXTURES_DIR / "malicious" / "reduce_os_system.pkl"
    with open(path, "wb") as f:
        pickle.dump(_OsSystemExploit(), f)
    print(f"wrote {path}")


class _SubprocessExploit:
    def __reduce__(self):
        import subprocess

        return (subprocess.call, (["echo", "pwned"],))


def write_malicious_subprocess():
    path = FIXTURES_DIR / "malicious" / "reduce_subprocess_call.pkl"
    with open(path, "wb") as f:
        pickle.dump(_SubprocessExploit(), f)
    print(f"wrote {path}")


class _SubclassesGadgetChain:
    def __reduce__(self):
        # Real gadget-chain technique for escaping restricted unpicklers
        # even when only "safe" modules are allowlisted: walk the live
        # class hierarchy via __subclasses__() to find a class whose
        # __init__.__globals__ exposes __builtins__, reaching eval/exec/
        # os.system without ever directly referencing them.
        # Source: Huang, Huang & Huang, "Pain Pickle: Bypassing Python
        # Restricted Unpickler for Automatic Exploit Generation",
        # IEEE QRS 2022, Listing 6.
        return (int.__subclasses__, ())


def write_malicious_gadget_chain_subclasses():
    path = FIXTURES_DIR / "malicious" / "gadget_chain_subclasses.pkl"
    with open(path, "wb") as f:
        pickle.dump(_SubclassesGadgetChain(), f)
    print(f"wrote {path}")


def write_malicious_int_opcode_hex_evasion():
    """
    Hand-built raw opcode stream (not produced by pickle.dump -- no
    Python object naturally serializes to this). Exploits a disclosed
    discrepancy: pickletools parses INT/LONG opcode arguments strictly
    as base-10, while the real pickle/_pickle deserializers parse them
    as base-0 (accepting hex like "0x1337"). pickletools crashes trying
    to disassemble this stream, while pickle.load()/_pickle would
    happily call posix.system("whoami").

    Source: Applegate & Kellas, "PICKLEFUZZER: A Case Study in Fuzzing
    for Discrepancies Between Python Pickle Implementations" (2026),
    Discrepancy #1 -- confirmed via huntr.com bug bounty as a working
    bypass against pickletools-based scanners (e.g. picklescan).
    """
    payload = b"I0x1337\n\x8c\x05posix\x8c\x06system\x93\x8c\x06whoami\x85R."
    path = FIXTURES_DIR / "malicious" / "int_opcode_hex_evasion.pkl"
    with open(path, "wb") as f:
        f.write(payload)
    print(f"wrote {path}")


if __name__ == "__main__":
    write_benign_dict()
    write_malicious_gadget_chain_subclasses()
    write_malicious_os_system()
    write_malicious_subprocess()
    write_malicious_int_opcode_hex_evasion()
