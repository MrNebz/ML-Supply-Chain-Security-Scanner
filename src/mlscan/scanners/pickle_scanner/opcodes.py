"""
Safe, read-only inspection of a pickle byte stream.

Nothing in this module ever calls pickle.load()/loads(). We only use
pickletools.genops(), which parses the opcode stream as data and never
executes any of the opcodes it finds.
"""

from dataclasses import dataclass, field

import pickletools

# Opcodes that memoize/tag the current stack top without pushing or
# popping anything -- they must be skipped when walking backwards to find
# the actual string-producing opcodes that feed STACK_GLOBAL.
_NON_CONSUMING_OPCODES = {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}

_STRING_PUSH_OPCODES = {
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "UNICODE",
    "SHORT_BINSTRING",
    "BINSTRING",
    "STRING",
}

_PUT_OPCODES = {"PUT", "BINPUT", "LONG_BINPUT"}
_GET_OPCODES = {"GET", "BINGET", "LONG_BINGET"}


@dataclass
class GlobalRef:
    module: str
    name: str
    offset: int
    followed_by_reduce: bool = field(default=False)


def extract_global_refs(data: bytes) -> tuple[list[GlobalRef], Exception | None]:
    """
    Returns (refs, parse_error). parse_error is set if pickletools failed
    partway through the stream -- see _safe_genops() for why we don't
    just let that propagate as a crash.
    """
    ops, parse_error = _safe_genops(data)
    resolved_strings = _resolve_string_pushes(ops)
    refs: list[GlobalRef] = []

    for i, (opcode, arg, pos) in enumerate(ops):
        if opcode.name == "GLOBAL":
            module, _, name = arg.partition(" ")
            refs.append(_build_ref(ops, i, module, name, pos))

        elif opcode.name == "STACK_GLOBAL":
            strings = _preceding_resolved_strings(ops, resolved_strings, i, count=2)
            if len(strings) == 2:
                module, name = strings
                refs.append(_build_ref(ops, i, module, name, pos))

    return refs, parse_error


def extract_string_literals(data: bytes) -> list[tuple[str, int]]:
    """
    Every plain string literal pushed anywhere in the stream, with its
    byte offset. Used to catch gadget-chain attribute names (e.g.
    "__subclasses__", "__globals__") passed as a getattr()-style
    argument -- these are dangerous regardless of which (possibly
    "safe") module/class they're read off of, so they're checked
    independently of the GLOBAL/STACK_GLOBAL module/name resolution
    above.
    """
    ops, _parse_error = _safe_genops(data)
    return [(arg, pos) for opcode, arg, pos in ops if opcode.name in _STRING_PUSH_OPCODES]


def _resolve_string_pushes(ops) -> dict:
    """
    Single forward pass that tracks the pickle memo table well enough to
    resolve which opcode indices produce a *string* value on the stack --
    including indirectly, via GET/BINGET/LONG_BINGET retrieving a
    previously memoized string.

    This matters because CPython's pickler deduplicates repeated strings:
    if a class's module and qualname happen to be identical (e.g.
    "socket.socket" -- module "socket", class "socket"), the second
    occurrence is emitted as a memo GET instead of a second string-push
    opcode. Only checking for direct string-push opcodes misses the
    module/name for STACK_GLOBAL in that case -- a real false negative,
    not just a hypothetical one (found via parametrized testing across
    every entry in our dangerous-import rule table).
    """
    resolved: dict = {}
    memo: dict = {}
    last_string = None
    next_memo_index = 0

    for i, (opcode, arg, _pos) in enumerate(ops):
        if opcode.name in _STRING_PUSH_OPCODES:
            last_string = arg
            resolved[i] = arg
        elif opcode.name in _GET_OPCODES:
            value = memo.get(int(arg))
            if value is not None:
                resolved[i] = value
            last_string = value

        if opcode.name == "MEMOIZE":
            memo[next_memo_index] = last_string
            next_memo_index += 1
        elif opcode.name in _PUT_OPCODES:
            memo[int(arg)] = last_string

    return resolved


def _safe_genops(data: bytes) -> tuple[list, Exception | None]:
    """
    pickletools.genops() is a generator that can raise partway through a
    malformed stream. A documented real-world example: pickletools parses
    INT/LONG opcode arguments strictly as base-10, while the actual
    pickle/_pickle deserializers parse them as base-0 (accepting hex like
    "0x1337"). A payload built around that mismatch makes pickletools
    crash while the real unpickler loads and executes it fine -- a
    disclosed technique for bypassing pickletools-based scanners
    (Applegate & Kellas, "PickleFuzzer", 2026; huntr.com bug bounty).

    We must not let one bad opcode abort the entire scan (that would
    either crash the tool or, worse, silently report zero findings if a
    caller swallows the exception) -- so we collect every opcode read
    successfully up to the failure point and report the failure itself
    as a finding instead.
    """
    ops = []
    stream = pickletools.genops(data)
    while True:
        try:
            ops.append(next(stream))
        except StopIteration:
            return ops, None
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
            return ops, exc


def _preceding_resolved_strings(ops, resolved: dict, before_index: int, count: int) -> list[str]:
    """
    Walk backwards from `before_index`, skipping non-consuming opcodes
    (MEMOIZE etc.), collecting the `count` nearest opcodes whose resolved
    string value we know -- either a direct string push or a memo GET
    that resolved to one. Returns them in original (forward) order.
    """
    found: list[str] = []
    i = before_index - 1
    while i >= 0 and len(found) < count:
        opcode, _, _ = ops[i]
        if opcode.name in _NON_CONSUMING_OPCODES:
            i -= 1
            continue
        if i in resolved:
            found.append(resolved[i])
            i -= 1
            continue
        break
    found.reverse()
    return found


def _build_ref(ops, index: int, module: str, name: str, pos: int) -> GlobalRef:
    ref = GlobalRef(module=module, name=name, offset=pos)
    # Scan forward with no fixed window: argument construction (lists,
    # dicts, nested tuples) can take arbitrarily many opcodes. Stop at
    # REDUCE (this call happens), STOP (stream ends), or another
    # GLOBAL/STACK_GLOBAL (a different call started, so this one was
    # never reduced -- e.g. it was only stored, not invoked).
    for opcode, _, _ in ops[index + 1 :]:
        if opcode.name == "REDUCE":
            ref.followed_by_reduce = True
            break
        if opcode.name in ("STOP", "GLOBAL", "STACK_GLOBAL"):
            break
    return ref
