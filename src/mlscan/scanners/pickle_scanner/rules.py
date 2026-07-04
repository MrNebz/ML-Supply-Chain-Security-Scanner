"""
Known-dangerous (module, callable) pairs, and module prefixes that are
suspicious even if the specific callable isn't in the explicit list.

Note pickle serializes a GLOBAL/STACK_GLOBAL reference using the
callable's *actual* __module__ attribute, not the module path a human
imported it from -- and several of these differ:
  - os.system/popen/execv/execve are thin re-exports of "nt" (Windows) or
    "posix" (Unix) internals; the pickled reference names nt/posix, not os.
  - pickle.loads is a re-export of the C accelerator module's function,
    whose __module__ is "_pickle", not "pickle".
Both aliases resolve to the exact same dangerous behavior, so both must
be listed, or a scanner checking only the "friendly" name misses them.
"""

DANGEROUS_IMPORTS: set[tuple[str, str]] = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("nt", "system"),
    ("nt", "execv"),
    ("nt", "execve"),
    ("posix", "system"),
    ("posix", "execv"),
    ("posix", "execve"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
    ("builtins", "compile"),
    # Generic attribute-read/write gadgets. Not dangerous by themselves,
    # but they are the standard building block for escaping restricted
    # unpicklers even when only "safe" modules/classes are allowlisted:
    # e.g. getattr(int, "__subclasses__")() -> walk all loaded classes ->
    # find one whose __init__.__globals__ exposes __builtins__ -> reach
    # eval/exec/os.system despite never directly referencing them.
    # (Huang, Huang & Huang, "Pain Pickle", IEEE QRS 2022, Type 2 gadgets
    # and the __subclasses__/__builtins__ bypass chain in Listing 6.)
    # Confirmed this is what real Python pickle.dumps() actually emits
    # when serializing a reference like int.__subclasses__ -- not a
    # theoretical construction.
    ("builtins", "getattr"),
    ("builtins", "setattr"),
    ("builtins", "vars"),
    ("operator", "attrgetter"),
    ("socket", "socket"),
    ("shutil", "rmtree"),
    ("pickle", "loads"),
    ("_pickle", "loads"),
    ("importlib", "import_module"),
    ("ctypes", "CDLL"),
}

# Attribute names that are the standard "gadget chain" building blocks for
# escaping restricted unpicklers/sandboxes by walking the live class
# hierarchy, regardless of which (allowed) module first exposed them.
# Appearing as a plain string argument immediately before/after a
# getattr-style call is a strong signal on its own.
GADGET_CHAIN_ATTRIBUTES: set[str] = {
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__base__",
    "__bases__",
    "__mro__",
}

DANGEROUS_MODULE_PREFIXES: set[str] = {
    "os",
    "nt",
    "posix",
    "subprocess",
    "socket",
    "shutil",
    "sys",
    "builtins",
    "importlib",
    "ctypes",
    "_pickle",
}
