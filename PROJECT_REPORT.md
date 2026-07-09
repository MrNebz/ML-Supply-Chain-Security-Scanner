# mlscan: A Static Security Scanner for the ML Model Supply Chain
### Final Project Report

**Author:** Naji Bou Zeid
**LinkedIn:** [www.linkedin.com/in/naji-bou-zeid-a4aa99332]
**Email:** naji.elia.bouzeid@gmail.com
**Context:** Independent research project at the intersection of artificial intelligence and applied cybersecurity

---

## Abstract

Machine learning models are routinely distributed as serialized files — pickle,
ONNX, HDF5 — and loaded by downstream code with an implicit trust that a "model
file" is inert data. This assumption is false for at least two of these three
formats, and partially false for the third. This report documents the design,
implementation, and evaluation of `mlscan`, a static analysis tool that
inspects `.pkl`/`.pt`/`.pth` (pickle), `.onnx` (protobuf), and `.h5` (HDF5/Keras)
files for supply-chain attack patterns without ever executing them — in the
same spirit as container-image scanners like Trivy, applied to the ML model
supply chain instead.

The project is deliberately scoped as **cybersecurity applied to AI artifacts**,
not AI applied to cybersecurity: the tool itself contains no trained model in
its primary detection path. An optional, secondary ML layer was built and
evaluated separately, and its results — both positive and negative ones — are
reported in the final section.

Over the course of development, five real bugs were found and fixed through
adversarial testing (fuzzing, real-world data, and benchmarking) rather than
through code review alone — this report treats *how* those bugs were found as
seriously as the fixes themselves, since the methodology is the actual
transferable skill.

---

## 1. Motivation

### 1.1 Why this project exists

The broader goal behind this work is to grow deliberately within the
intersection of artificial intelligence and cybersecurity — a space that is
still comparatively young, and within which most public effort concentrates
on one specific direction: using AI as a tool for security tasks (malware
classifiers, anomaly-detection systems, and the like). This project instead
targets a much rarer and less-explored niche within that intersection:
securing the AI development lifecycle itself, by treating ML model artifacts
as untrusted input and applying classical software-security engineering —
static analysis, file-format reverse engineering, fuzzing — to them.

This project requires no training dataset and no GPU, which keeps the engineering loop tight; it sits almost entirely outside the well-trodden "train a classifier" pattern that dominates most AI-security work; and it demands a genuinely different skill set — file-format internals, static analysis design, and adversarial testing methodology — that complements, rather than duplicates,
more conventional machine-learning work.


### 1.2 The supply-chain problem, concretely

The premise of the project is simple to state and easy to underestimate:
when you download a "pretrained model" from a hub, a colleague's repository,
or an internal artifact store, and load it into your Python process, you are
trusting that the *deserialization step itself* is safe. For at least one of
the three formats studied here, that trust is completely unfounded — loading
a pickle file can execute arbitrary code, full stop, no exploit chain
required beyond "someone crafted the bytes." This is not a theoretical
concern: documented incidents of malicious models on HuggingFace Hub exist,
and — as this report documents in Section 6 — a small but active community of
security researchers publishes proof-of-concept malicious pickle files
publicly on HuggingFace Hub itself, which this project encountered directly
while collecting what was supposed to be a "benign" training corpus.

---

## 2. Pickle, from zero

### 2.1 What serialization is, and why pickle is different

Serialization converts an in-memory object graph into a flat byte sequence
that can be written to disk or sent over a network, and deserialization
reverses this. Python's `pickle` module does this for *arbitrary* Python
objects — not just simple data like JSON's strings/numbers/lists/objects, but
full class instances with arbitrary internal state.

This generality is exactly the source of the vulnerability. JSON has no
instruction meaning "run a function" — it can only ever describe passive
values. Pickle, to support reconstructing arbitrary objects (including
objects that need custom logic to rebuild, such as a class instance whose
`__init__` shouldn't be called directly), is not a data format at all. It is
a **small stack-based bytecode language**, and deserializing a pickle stream
means running a tiny virtual machine — the **Pickle Virtual Machine (PVM)** —
that executes one instruction (opcode) at a time.

### 2.2 The Pickle Virtual Machine

The PVM has three components:

- **Opcode engine** — reads one opcode at a time from the byte stream and
  executes it.
- **Stack** — a standard push/pop stack; almost every opcode either pushes a
  value or pops some values and pushes a combined result.
- **Memo** — an indexed scratchpad (a dictionary in practice) that lets the
  stream refer back to previously-built objects by index, so repeated
  references to the same object don't need to be re-serialized. This detail
  matters more than it first appears — see Section 6.2.

Opcodes fall into six functional categories: creating constants, setting an
index/key value, setting an attribute, calling a function or constructing an
object, referencing an object from a module, and internal bookkeeping. Most
opcodes are inert with respect to security — they only ever build passive
Python values (dicts, lists, strings, floats). Exactly **two** opcodes are not:

- **`GLOBAL` / `STACK_GLOBAL`** — "resolve a name from a module and push a
  reference to the actual object (function/class), not a value." This exists
  so pickle can find the right class to reconstruct a custom object. Nothing
  about this opcode is inherently code-execution — it is a lookup.
- **`REDUCE`** — "pop a callable and an argument tuple off the stack, **call
  the callable**, push the result." This is the only opcode in the entire
  language that invokes anything.

The vulnerability is precisely the *combination*: a `GLOBAL`/`STACK_GLOBAL`
that resolves to a dangerous callable, immediately or eventually followed by
a `REDUCE` that invokes it with attacker-chosen arguments.

### 2.3 A benign disassembly, read literally

Serializing `{"weights": [0.1, 0.2, 0.3], "name": "tiny_model"}` with
`pickle.dumps` produces (annotated):

```
PROTO      4                          # protocol version marker
FRAME      66                         # payload length (perf hint)
EMPTY_DICT                            # push: {}
MEMOIZE                               # memo[0] = {} (bookkeeping only)
MARK                                  # push a marker onto the stack
SHORT_BINUNICODE 'weights'            # push: 'weights'
MEMOIZE
EMPTY_LIST                            # push: []
MEMOIZE
MARK
BINFLOAT   0.1                        # push: 0.1
BINFLOAT   0.2
BINFLOAT   0.3
APPENDS    (MARK at ...)              # pop to mark, append all into the list
SHORT_BINUNICODE 'name'
MEMOIZE
SHORT_BINUNICODE 'tiny_model'
MEMOIZE
SETITEMS   (MARK at ...)              # pop to mark, use as key/value pairs
STOP                                  # done
```

Every single opcode here builds a passive value. There is no `GLOBAL`, no
`REDUCE`, anywhere. This is the pattern `mlscan`'s pickle scanner treats as
its "nothing to see here" baseline.

### 2.4 A malicious disassembly, read literally

The canonical exploit — documented since Marco Slaviero's 2011 BlackHat talk
— is a class whose `__reduce__` method (the hook pickle calls to ask "how do
I serialize you?") returns `(callable, args_tuple)` instead of normal object
state:

```python
class Exploit:
    def __reduce__(self):
        return (os.system, ("echo pwned",))
```

Disassembling `pickle.dumps(Exploit())` (Windows, where `os.system` is
actually implemented in the internal `nt` module and merely re-exported by
`os` — a detail that matters, see Section 6.1):

```
PROTO      4
FRAME      34
SHORT_BINUNICODE 'nt'                 # push: 'nt'
MEMOIZE
SHORT_BINUNICODE 'system'             # push: 'system'
MEMOIZE
STACK_GLOBAL                          # pop 'nt','system' -> resolve nt.system
MEMOIZE                               #   stack: [ nt.system ]
SHORT_BINUNICODE 'echo pwned'         # push: 'echo pwned'
MEMOIZE
TUPLE1                                # pop 1, wrap in tuple -> ('echo pwned',)
MEMOIZE                               #   stack: [ nt.system, ('echo pwned',) ]
REDUCE                                # pop both, CALL nt.system('echo pwned')
MEMOIZE
STOP
```

Six lines, entirely readable by a human once the two-opcode pattern is known.
No obfuscation is required — this is what a naive exploit looks like in the
clear, and it is the exact pattern `mlscan`'s `PICKLE_DANGEROUS_REDUCE` rule
(CRITICAL) is built to detect: walk every `GLOBAL`/`STACK_GLOBAL`, resolve
its `(module, name)`, and check whether a `REDUCE` follows.

### 2.5 Beyond the textbook case: restricted-unpickler gadget chains

A common mitigation is **Restricting Globals** — overriding `Unpickler.find_class`
to allow only an explicit allowlist of "safe" modules/classes. Huang, Huang &
Huang ("Pain Pickle: Bypassing Python Restricted Unpickler for Automatic
Exploit Generation," IEEE QRS 2022) show this is frequently insufficient,
because *reading an attribute off an allowed object* is itself a powerful
primitive. The canonical chain:

```
getattr(int, "__subclasses__")()      # walk every loaded class in the process
    -> find one whose __init__.__globals__ exposes "__builtins__"
    -> reach eval / exec / os.system
```

None of `int`, `getattr`, or `__subclasses__` need to be "dangerous" by any
naive allowlist — `int` is about as safe-looking as a name gets. We verified
this is not merely a theoretical construction: `pickle.dumps(int.__subclasses__)`
on a real Python installation produces exactly this pattern, using
`builtins.getattr(int, "__subclasses__")` as the resolution mechanism (Python's
pickler falls back to `getattr`-based resolution when a bound method can't be
referenced directly). Disassembly confirms it: a `STACK_GLOBAL` for
`builtins.getattr`, a `STACK_GLOBAL` for `builtins.int`, the string
`"__subclasses__"`, a `TUPLE2`, a `REDUCE` (this call performs the `getattr`),
an `EMPTY_TUPLE`, and a second `REDUCE` (this call invokes the result).

`mlscan` addresses this two ways: `builtins.getattr`/`setattr`/`vars` and
`operator.attrgetter` are listed as dangerous callables in their own right
(since a pickle stream has essentially no legitimate reason to reference the
introspection primitives directly), and independently, any occurrence of a
known gadget-chain attribute name (`__subclasses__`, `__globals__`,
`__builtins__`, `__base__`, `__bases__`, `__mro__`) anywhere in the opcode
stream is flagged CRITICAL (`PICKLE_GADGET_CHAIN_ATTRIBUTE`) regardless of
which module exposed it — because the danger is in the attribute name
itself, not in which nominally-safe object it was read from.

### 2.6 A disclosed scanner-bypass technique, and why it matters that we defend against it

Every public pickle-scanning tool we are aware of — including this one,
`picklescan`, and (by observation, see Section 7) `ModelScan` — relies on
`pickletools.genops()` to walk the opcode stream. Applegate & Kellas
("PICKLEFUZZER: A Case Study in Fuzzing for Discrepancies Between Python
Pickle Implementations," 2026) used differential fuzzing across `pickle`,
`_pickle` (the C accelerator), and `pickletools` to find 14 behavioral
discrepancies between these three implementations, four of which are
security-critical: cases where `pickletools` *fails to parse* a stream that
`pickle`/`_pickle` load and execute successfully. The clearest example: `INT`/
`LONG` opcode arguments are parsed strictly as base-10 by `pickletools`, but
as base-0 (auto-detecting `0x`-prefixed hex) by the real deserializers. A
payload containing the literal text `0x1337` as an `INT` argument makes
`pickletools` raise `ValueError` and abort, while `pickle.load()` parses it
as hex and executes the payload fine. The authors demonstrated this against
`picklescan` directly — the malicious file produces **zero reported issues**,
a scanner bypass confirmed via a $750 huntr.com bug bounty award.

We reproduced this exact payload (`b"I0x1337\n\x8c\x05posix\x8c\x06system..."`)
and confirmed `pickletools.genops()` crashes on it in our own environment.
Rather than let a parse failure propagate as an unhandled crash — or worse,
be silently swallowed and reported as "no findings," which is what happened
to `picklescan` — `mlscan` treats any mid-stream parse failure as a
`PICKLE_PARSE_ERROR` finding (HIGH severity), explicitly citing that
malformed opcode encoding is a known scanner-evasion technique. This is
arguably the single most important design decision in the pickle scanner:
**a parser that can fail must fail loudly, not silently.**

---

## 3. ONNX, from zero

### 3.1 What ONNX is, and why it is a fundamentally different problem

ONNX (Open Neural Network Exchange) is a cross-framework interchange format:
a `.onnx` file is a serialized **Protocol Buffer (protobuf)** message
describing a computation graph — nodes (operations like `Conv`, `MatMul`),
tensors (weights), and metadata. Protobuf is a schema-driven binary format;
deserializing it can only ever populate the fields the schema defines. There
is no opcode virtual machine, no "call this function" primitive anywhere in
the format. **This means ONNX has no pickle-style code-execution
vulnerability by design.**

The attack surface therefore shifts entirely — from "code execution during
parsing" to **structural and resource abuse, and downstream exploitation**.
`mlscan` implements three checks corresponding to three distinct attack
classes.

### 3.2 External data path traversal

Large models often store weight tensors in a separate file, referenced from
the `.onnx` file by a relative path (`external_data`), so the graph
description itself stays small. That path is attacker-controlled text with
no inherent validation — nothing stops it being `../../../../etc/passwd` or
an absolute path. When a downstream tool actually loads the tensor's real
bytes, it opens whatever that string says: a textbook path-traversal
vulnerability wearing an ML costume.

`mlscan` checks every `external_data` `location` field for absolute paths,
Windows drive letters, and `..` as an actual path *segment* (using
`Path(location).parts`, not a substring check — a filename genuinely
containing `..` as text, e.g. `results..v2.bin`, must not false-positive).
A confirmed traversal is CRITICAL (`ONNX_EXTERNAL_DATA_PATH_TRAVERSAL`).

One deliberate engineering decision here: we call `onnx.load(path,
load_external_data=False)`. If external data were loaded eagerly during the
scan itself, the exact vulnerability we are checking for could make our own
scanner read arbitrary files off disk while it is busy looking for that
behavior. **A security tool must never be exploitable by the thing it scans
for.**

### 3.3 Custom operator domains, and a false positive we found and fixed

Every graph node has an `op_type` and a `domain`. An empty domain, or
`ai.onnx`/`ai.onnx.ml`, means "a standard operator every ONNX runtime
implements natively." Any other domain means the model requires an external
native operator library to even run — the model file cannot contain
executable machine code directly, but it can *demand* code that lives
outside itself, and what that code does is entirely opaque to a static
scanner.

Initial implementation flagged any non-standard domain as HIGH severity.
Testing against real HuggingFace models (Section 7.2) surfaced a false
positive: `com.microsoft`, ONNX Runtime's own officially maintained
extension domain, is extremely common in real, legitimately optimized models
(`Attention`, `BiasGelu`, `RotaryEmbedding`, `GroupQueryAttention`), and was
being flagged identically to a fully unknown, attacker-chosen domain. We
introduced a trust tier: known vendor extensions (`com.microsoft`,
`com.microsoft.experimental`, `org.pytorch.aten`) are flagged MEDIUM
(`ONNX_VENDOR_EXTENSION_DOMAIN` — "worth knowing, not alarming"), while
genuinely unrecognized domains remain HIGH (`ONNX_CUSTOM_OPERATOR_DOMAIN`).

### 3.4 Oversized declared dimensions

A tensor's declared shape (`dim_value`) is just an integer field; nothing
constrains it to match the size of any actually-stored data. A model that
declares an input/output/intermediate tensor with an absurd dimension (e.g.
2³¹−1) can cause a downstream tool that naively pre-allocates memory based on
declared shape, before validating it against real data, to attempt a
multi-gigabyte allocation purely by the file existing — a resource-exhaustion
vector. `mlscan` flags any single dimension above 10⁸ as
`ONNX_SUSPICIOUS_TENSOR_DIM` (MEDIUM) — deliberately the lowest-confidence
rule in the tool, since a legitimately large production model could, in
principle, have a large dimension; this is presented as "worth review," not
"definitely malicious."

### 3.5 A crash bug found through fuzzing, and why it is security-relevant, not just a robustness nicety

Protobuf "string" fields are documented to always decode to Python `str`.
Mutation-based fuzzing (Section 8.3) — flipping single bytes in a real,
valid `external_data` fixture — produced a case where the mutated byte made
the field's content invalid UTF-8, and protobuf's parser returned raw
`bytes` instead of raising or coercing. Our path-traversal check assumed
`str` and crashed with `TypeError` on `.startswith()`.

This is not merely a fuzzing curiosity: an attacker can trivially craft
invalid UTF-8 in this exact field on purpose, specifically to crash a
scanner that assumes `str`, as a deliberate evasion technique — a smaller
sibling of the pickle base-10/base-0 discrepancy in Section 2.6. The fix
normalizes the field defensively (`bytes.decode("utf-8", errors="replace")`
when needed) before running the traversal check, and a regression test
reproduces the exact byte-level corruption rather than testing through the
high-level API (which would enforce `str` and never reproduce the bug).

We also added a general `ONNX_PARSE_ERROR` (HIGH) for any file that fails to
parse as a valid `ModelProto` at all — the same fail-loud philosophy as
Section 2.6, applied to a different format.

---

## 4. HDF5 / Keras, from zero

### 4.1 What HDF5 is

HDF5 (Hierarchical Data Format 5) is a general-purpose hierarchical binary
container — conceptually a filesystem inside a single file, with groups
(folders), datasets (files, holding numeric arrays), and attributes (small
metadata key/value pairs attachable to either). It predates and is unrelated
to machine learning; it is used across scientific computing generally. Keras
reuses it for its legacy `model.save("model.h5")` format: trained weight
arrays become HDF5 datasets, and the architecture description becomes a
single attribute, `model_config`, holding a **JSON string**.

### 4.2 Where inert data stops being inert: the `Lambda` layer

`model_config` being JSON text is, by itself, completely safe — JSON cannot
express executable code. The problem is a single Keras feature: the `Lambda`
layer, which lets a user define a layer's computation as an arbitrary Python
function (`Lambda(lambda x: x * 2)`). A live function object cannot be
represented in JSON directly, so Keras's internal `func_dump()` converts it
by taking the function's compiled bytecode (`function.__code__`), serializing
*that* with Python's `marshal` module (the same mechanism used for `.pyc`
files), base64-encoding the result, and storing it as
`[base64_string, defaults, closure]` in the layer's `function` field, with
`function_type` set to `"lambda"`.

When `keras.models.load_model()` encounters `function_type == "lambda"`, it
reads that string back, `marshal.loads()`s it into a code object, and wraps
it in a live callable — **which then executes** whenever the layer runs.
This is structurally the same category of bug as the pickle vulnerability
described in Section 2: **a field whose only stated purpose is passive
metadata secretly carries a serialized program**, just via a different
serialization primitive (`marshal` instead of pickle opcodes) and gated
behind one specific feature instead of the entire format.

We reproduced this authentically rather than faking it — the test fixture
generator uses `marshal.dumps(function.__code__)` and `base64.b64encode()`
directly, the exact primitives Keras' own `func_dump()` uses, so the fixture
is structurally identical to what a real malicious `.h5` file would contain.

### 4.3 Two severities, and why they differ

`mlscan` distinguishes two cases, walking the parsed `model_config`
recursively (since a Functional model can nest a Sequential sub-model
arbitrarily deep, so a flat top-level scan is insufficient):

- `function_type == "lambda"` (or `function` is a list, the structural
  signature of the marshalled form) — **CRITICAL**
  (`H5_LAMBDA_MARSHALLED_BYTECODE`). Bytecode sits directly in the file; it
  runs with no further trust decision required from the loader.
- `function_type == "function"` — **MEDIUM**
  (`H5_LAMBDA_NAMED_FUNCTION_REF`). Only a *name* is stored; execution
  requires the caller to separately supply a `custom_objects` mapping
  resolving that name to a real function. The file alone cannot force
  execution — it depends on what the loading code chooses to trust. Still
  worth flagging (it signals "this model expects external trust"), but
  structurally weaker, hence the lower severity — the same reasoning
  applied to ONNX's vendor-vs-unknown domain distinction in Section 3.3.

### 4.4 A crash bug, and a general robustness pattern

As with ONNX, malformed input (a `.h5`-named file that is not actually a
valid HDF5 container, or one whose `model_config` attribute is present but
not valid JSON) originally crashed the scanner (`OSError` from `h5py`,
`JSONDecodeError` from `json.loads`). Both are now caught and reported as
`H5_PARSE_ERROR` (HIGH for the container-level failure, MEDIUM for the
JSON-level one) — the third and final application of the same fail-loud
principle established in Sections 2.6 and 3.5.

---

## 5. System design

### 5.1 Architecture

```
src/mlscan/
    cli.py              # argument parsing, format dispatch, --json / --ml
    detect.py            # content-based format sniffing
    report.py            # Finding/Severity data model
    scanners/
        pickle_scanner/
            opcodes.py    # safe opcode-stream walking (never calls pickle.load)
            container.py  # zip-wrapped PyTorch checkpoint unwrapping
            rules.py      # dangerous-import and gadget-chain tables
            features.py   # optional ML feature extraction
            anomaly.py    # optional ML inference (lazy-imports sklearn/skops)
        onnx_scanner/
            scanner.py    # protobuf graph inspection
            rules.py      # domain trust tiers, size thresholds
        h5_scanner/
            scanner.py    # HDF5 attribute + model_config inspection
```

Every scanner returns a list of `Finding(severity, rule_id, message,
location)` objects; the CLI aggregates these, supports human-readable and
`--json` output, and exits non-zero on any CRITICAL/HIGH finding — making it
usable as a CI pipeline gate, in the same style as Trivy.

### 5.2 Content-based format detection

Relying on file extension alone is trivially defeated — nothing stops
renaming `evil.pkl` to `model.onnx`. `detect.py` sniffs actual content: the
`PROTO` opcode byte pattern for pickle (protocol ≥ 2), the documented HDF5
magic number (`\x89HDF\r\n\x1a\n`), zip-archive structure containing a
`data.pkl` member (for PyTorch checkpoints), and a fallback attempt to parse
as ONNX protobuf. When detected content disagrees with the extension, a
`FORMAT_EXTENSION_MISMATCH` finding (MEDIUM) is raised *in addition to*
scanning the file as whatever it actually is — the disguise itself is
signal, not just noise to route around.

### 5.3 Zip-wrapped PyTorch checkpoints

Since PyTorch 1.6, `torch.save()` defaults to a zip archive containing
`<name>/data.pkl` (the real pickle stream) alongside separate tensor storage
files. `container.py` transparently unwraps this — detecting the zip
structure, locating the `data.pkl` member, and handing its raw bytes to the
same opcode scanner used for plain `.pkl` files — so a malicious zip-wrapped
checkpoint is caught exactly as a plain malicious pickle would be, including
under a disguised extension.

---

## 6. Bugs found, and how they were found

A central finding of this project is methodological: **every non-trivial
bug was found through adversarial testing, not code review.** This section
documents each one, because the discovery method is the transferable
lesson, not just the fix.

### 6.1 Pickle memo-deduplication false negative (`socket.socket`)

**Found via:** parametrized testing of every entry in the dangerous-imports
table (not just 2-3 hand-picked examples).

CPython's pickler deduplicates repeated strings via the memo table. When a
class's module and qualified name are textually identical — `socket.socket`,
module `"socket"`, class `"socket"` — the second occurrence is emitted as a
memo `GET`/`BINGET` rather than a second string-push opcode. The original
opcode walker only recognized direct string-push opcodes when resolving
`STACK_GLOBAL`'s two string arguments, silently missing the module string
whenever it was retrieved via memo instead. Fixed by implementing proper
memo-table tracking: a single forward pass records which memo index maps to
which string value (assigned by `MEMOIZE`/`PUT` in order, retrieved by
`GET`/`BINGET`), so a `GET` that resolves to a string is treated identically
to a direct string push.

### 6.2 ONNX crash on malformed input

**Found via:** deliberately feeding random garbage bytes with a `.onnx`
extension, in preparation for systematic fuzz testing.

`onnx.load()` raised an uncaught `google.protobuf.message.DecodeError` on
malformed input. Fixed by wrapping the parse call and reporting
`ONNX_PARSE_ERROR` instead — see Section 3.5 for the security relevance
(this is not merely a robustness fix).

### 6.3 HDF5 crash on malformed input

**Found via:** the same deliberate garbage-byte test as 6.2, applied to `.h5`.

`h5py.File()` raised `OSError` on a non-HDF5 file; a malformed
(non-JSON) `model_config` attribute raised `json.JSONDecodeError`. Both are
now caught and reported as `H5_PARSE_ERROR` (Section 4.4).

### 6.4 ONNX vendor-domain false positive

**Found via:** real-world testing against actual models pulled from
HuggingFace Hub.

Documented in full in Section 3.3. This is the clearest illustration in the
whole project of why testing against real, unmodified files matters:
hand-crafted fixtures cannot produce a false positive on a pattern
(`com.microsoft`) that only appears in genuinely optimized real models.

### 6.5 Gadget-chain technique under-detected

**Found via:** mining a specific published research paper (Pain Pickle,
Section 2.5) for concrete attack patterns beyond the textbook
`__reduce__`-to-`os.system` case, then verifying the pattern against a real
Python pickle disassembly rather than assuming the paper's description
translated directly.

Before this fix, `pickle.dumps(int.__subclasses__)` was flagged only at
MEDIUM severity (via the generic "references a sensitive module" fallback
rule), not recognized as the specific RCE-capable gadget chain it is. Fixed
by adding `getattr`/`setattr`/`vars`/`attrgetter` to the dangerous-callables
table and adding an independent check for gadget-chain attribute names
appearing anywhere in the opcode stream (Section 2.5).

### 6.6 A CI hang, root-caused rather than worked around

**Found via:** the CI pipeline hanging for over 90 minutes, twice, on
GitHub's hosted Linux runner, while the identical test suite ran in under
10 seconds locally on Windows.

Live log inspection (via GitHub's web UI, since the public API does not
expose logs for an in-progress run) showed execution halting precisely at
the fuzz-testing module, with no further output — not a crash, not an error,
simply nothing. The root cause: the fuzz tests used `deadline=None` in their
`hypothesis` settings, which **disables hypothesis's own per-example
timeout entirely**. If any single one of several hundred generated examples
triggered slow or genuinely blocking behavior specific to the Linux runner
environment, nothing was watching for it. `hypothesis`'s `deadline`
mechanism can only detect slowness in code that eventually returns control
to Python — it cannot interrupt a true block inside a C-level call (such as
inside `h5py` or `onnx`). We fixed this at two levels: a hard, global
per-test timeout via `pytest-timeout` (which uses signal-based interruption
on Linux, capable of breaking even a genuine C-level block), and a proper
`hypothesis` profile system (`tests/conftest.py`) restoring a finite
per-example deadline (2000ms) and separately reducing example counts for CI
via the `CI` environment variable GitHub Actions sets by default. The fix
was verified by simulating the CI profile locally and confirming the
previously-hanging suite now completes in under 3 seconds, then verified
again for real by watching a subsequent GitHub Actions run complete
successfully.

### 6.7 A network-generator crash in the ML training-data downloader

**Found via:** the download script crashing mid-run on a genuinely flaky
connection.

`huggingface_hub.HfApi.list_models()` is a lazy generator that performs
network I/O as it is iterated; a transient failure (in this case, a 429 rate
limit from HuggingFace's API) raised an exception *during iteration*, which
is not caught by any of the narrower `try`/`except` blocks wrapping
individual per-file downloads, and crashed the entire script — discarding
all progress. Fixed by materializing each search term's result list inside
its own `try`/`except`, so a failure on one search term is logged and
skipped rather than terminating the run.

---

## 7. Testing methodology

Five distinct sources of test coverage were used deliberately, because each
catches a different class of defect that the others cannot:

1. **Hand-crafted fixtures** — one authored example per detection rule.
   Necessary but insufficient: they only prove the code does what its
   author intended, not that the author's intentions were complete.
2. **Parametrized coverage** — every entry in every rule table (every
   dangerous pickle import, every ONNX domain tier, several Lambda payload
   variants) tested individually, generating the actual payload
   programmatically rather than trusting 2-3 hand-picked examples. This is
   what surfaced the `socket.socket` memo bug (Section 6.1).
3. **Real-world fixtures** — small real files pulled from HuggingFace Hub,
   used purely as a false-positive check hand-crafted fixtures structurally
   cannot provide. This is what surfaced the ONNX vendor-domain false
   positive (Section 6.4) and a genuine `pickletools` parsing limitation on
   a real LightGBM/joblib model (documented as a known limitation, Section
   9), independently confirmed by observing that ModelScan hits the
   identical failure on the same file.
4. **Fuzz testing** (`hypothesis`) — random bytes and byte-level mutations
   of real fixtures thrown at all three scanners, asserting they never
   crash. This directly mirrors the differential-fuzzing methodology of the
   PickleFuzzer paper (Section 2.6), applied to our own tool instead of
   CPython's pickle modules. It found the ONNX/H5 crash bugs (Sections 6.2,
   6.3), the bytes-vs-str ONNX bug (Section 3.5), and indirectly, the CI
   hang (Section 6.6).
5. **CLI-level (subprocess) tests** — the actual `mlscan` command invoked as
   a real subprocess, verifying exit codes and `--json` output shape, not
   just internal Python function calls.
6. **Combination fixtures** — single files engineered to trigger more than
   one rule simultaneously, verifying findings do not mask or interfere with
   each other.

Final state: **82 automated tests**, all passing, CI green on GitHub
Actions, growing from an initial 13 hand-crafted tests over the course of
the project specifically because each additional testing *method* (not just
additional test *count*) found a real defect the previous methods had missed.

---

## 8. Benchmark against ModelScan (Protect AI, v0.8.8)

`ModelScan` is the closest real industry equivalent to this project. Running
it against our full fixture set surfaced a genuine, citable comparison:

| Dimension | mlscan | ModelScan 0.8.8 |
|---|---|---|
| ONNX support | 3 rules (path traversal, custom domains, oversized dims) | **No ONNX scanner at all** — every `.onnx` fixture silently skipped |
| Base-10/base-0 discrepancy payload | Flagged `PICKLE_PARSE_ERROR`, HIGH | Logged as a top-level "Error", **not counted among reported Issues** — a real malicious file produces zero flagged issues |
| joblib `NumpyArrayWrapper` false positive | Flagged, documented `xfail` limitation | Hits the *identical* parse failure, also excluded from Issues — independently confirms this is a genuine `pickletools` limitation, not specific to either tool |
| Keras Lambda severity granularity | Distinguishes marshalled bytecode (CRITICAL) from named-function reference (MEDIUM) | Both reported as one undifferentiated MEDIUM finding |
| Zip-wrapped PyTorch checkpoints | Unwraps and scans `data.pkl` | Also unwraps and scans correctly |

The complete absence of ONNX coverage in ModelScan is the single most
significant differentiator, and the shared failure on the joblib file is
independently valuable: it converts what could have been read as "our tool
has a bug" into "this is a known, external limitation of the standard
Python tooling that both tools rely on."

---

## 9. Known limitations


- **Pickle protocol 0/1 detection**: content-sniffing relies on the `PROTO`
  opcode, present only in protocol ≥ 2. Older ASCII-based protocols have no
  reliable magic number and fall back to extension-based detection.
- **joblib's raw-array-embedding convention** (Section 7, item 3): a real
  LightGBM/joblib model serializes a `NumpyArrayWrapper` object via
  `NEWOBJ`+`BUILD`, after which joblib writes the *raw numpy array bytes
  directly into the file stream*, bypassing pickle opcodes entirely so its
  own loader can memory-map the array. `pickletools` cannot know to skip
  those raw bytes and fails trying to parse them as opcodes — a false
  positive on a legitimate file. We deliberately did **not** implement blind
  recovery (detect the `NumpyArrayWrapper` marker and skip N bytes
  unconditionally), because doing so would itself be an evasion vector:
  nothing prevents an attacker from emitting a fake `NumpyArrayWrapper`
  reference specifically to make a scanner treat subsequent attacker bytes
  as "safe to skip." A safe fix would require reconstructing the exact byte
  length from the wrapper's own declared `shape`/`dtype` and verifying it —
  scoped as a future enhancement, not a shortcut.

---

## 10. The ML anomaly-detection experiment

### 10.1 Rationale and scope

An optional, secondary, opt-in (`--ml`) layer was built specifically to
explore whether a lightweight anomaly-detection model over opcode-derived
statistics could add value on top of the rule-based scanners, without
displacing them as the primary detection mechanism. This was scoped
narrowly and deliberately: unsupervised novelty detection (an
`IsolationForest` trained on benign samples only) rather than a supervised
classifier, both because malicious samples are inherently rare and
non-representative, and because a supervised classifier trained on our own
~15 hand-authored malicious fixtures would risk simply re-deriving our own
rules through a far more expensive and less interpretable path — a real
methodological trap this project avoided by design.

### 10.2 Feature engineering, and a dimensionality correction

The first feature-vector design extracted 9 scalar statistics (byte length,
opcode count, unique-opcode ratio, `GLOBAL` count, `REDUCE` count, their
ratio, byte entropy, max string length, parse-error flag) plus a frequency
count for **every** opcode `pickletools` recognizes — roughly 68 of them,
for a 77-dimensional vector.

This was corrected before training, for a concrete statistical reason: with
a training corpus in the low hundreds of samples, a 77-dimensional feature
space puts the sample count below the dimension count, which makes any
unsupervised density-style model closer to memorizing individual training
points than learning a real distribution (a defensible rule of thumb is that
sample count should exceed dimension count by roughly an order of
magnitude). The fix was to cut dimensionality rather than only grow the
corpus: the opcode-frequency features were trimmed to 13 opcodes carrying
actual security signal — `GLOBAL`, `STACK_GLOBAL`, `REDUCE`, `BUILD` (the
`__setstate__` gadget path documented in Pain Pickle), `INST`/`OBJ` (older
instance-creation opcodes), `NEWOBJ`/`NEWOBJ_EX` (modern instance-creation),
`PERSID`/`BINPERSID` (the persistent-id external-reference mechanism), and
`EXT1`/`EXT2`/`EXT4` (the extension-registry mechanism) — reducing the
vector to 22 dimensions total.

### 10.3 Model persistence: a deliberate choice of `skops` over pickle/joblib

The trained model is persisted via `skops.io.dump`/`load`, not `pickle` or
`joblib.dump` (which itself uses pickle internally). This is not incidental:
given the entire premise of this project is that pickle-based artifact
storage is a real risk, storing our own defensive model using the exact
mechanism we are warning against would be a direct contradiction. `skops` is
purpose-built by the scikit-learn/HuggingFace ecosystem specifically to
persist sklearn-family models without pickle's arbitrary-code-execution
surface, performing its own type-allowlist validation before reconstructing
objects.

### 10.4 Training data collection, and an unplanned but important discovery

`scripts/download_ml_training_corpus.py` collects benign pickle files from
HuggingFace Hub across seven search terms (`pkl`, `pickle`, `sklearn`,
`joblib`, `scikit-learn`, `lightgbm`, `xgboost`), targeting 300 samples.

Running this surfaced a significant, unplanned finding: naive keyword search
returns a substantial volume of **genuinely malicious and proof-of-concept
pickle files**, published openly by security researchers under
self-descriptive names (`pickle-scanner-bypass-*`, `*-rce-poc`,
`malicious_model.pkl`, and — most strikingly — one contributor's systematic
catalog of dozens of repositories, each targeting a different standard-library
module as a scanner-bypass gadget: `ftplib`, `smtplib`, `xmlrpc`, `sqlite3`,
`multiprocessing`, and more). This is not a data-quality edge case; it is
direct, first-hand evidence that HuggingFace Hub hosts an active,
identifiable body of applied pickle-exploitation research, publicly
searchable, which is itself a validating data point for why this entire
project's premise matters.

Practically, this meant the "benign" corpus could not be trusted as
collected. We addressed this by using `mlscan`'s own rule-based scanner as a
data-quality gate: every candidate file is scanned before being admitted to
the training set, and anything flagged is rejected. Of 214 candidate files
collected (210 downloaded plus 4 local fixtures), **75 (35%) were rejected**
by this gate — a striking confirmation of how contaminated naive web-scale
collection can be, and a legitimate use of the tool we built to validate its
own training pipeline. 139 genuine samples survived to train on, giving an
n/d ratio of roughly 6, short of the ideal ~10-15 but a substantial
improvement over the uncorrected design's ratio of roughly 0.5.

### 10.5 Evaluation and result

The trained model was evaluated against the project's own benign and
malicious fixture sets. The result: **zero measurable separation** between
the two groups. This was verified at the level of raw `decision_function`
scores, not merely the binary anomaly/normal label, specifically to rule out
a threshold-calibration explanation — and the scores confirm there is
genuinely no signal to threshold. If anything, the known-malicious fixtures
scored marginally *more* "normal" than one of the benign files.

**Root cause analysis:** the malicious fixtures used for evaluation are
minimal, single-`GLOBAL`+`REDUCE` payloads — deliberately small and
structurally simple, by design, since they exist to test one rule at a time.
None of the 22 gross structural statistics this feature space tracks (size,
entropy, opcode-frequency ratios) captures *which specific callable* is
being referenced — that is a semantic question, not a structural one, and it
is precisely the question the rule-based scanner already answers directly
by resolving `(module, name)` pairs against an explicit dangerous-callables
table. A small, simple, low-entropy pickle stream does not look unusual by
gross statistics whether it is benign or malicious; the two classes are
distinguished by *meaning*, not by *shape*.

This is reported as a legitimate, informative negative result. It demonstrates concretely — not merely by assertion — why purely structural/statistical ML features cannot always substitute for rule-based semantic analysis on this class of file.

---

## 11. References

- M. Slaviero, "Playing with Python Pickle," SensePost (2010); "Sour Pickles," BlackHat (2011).
- E. Sultanik, "Never a dill moment: Exploiting machine learning pickle files," Trail of Bits (2021) — [`fickling`](https://github.com/trailofbits/fickling)
- Protect AI — [`modelscan`](https://github.com/protectai/modelscan)
- N.-J. Huang, C.-J. Huang, S.-K. Huang, "Pain Pickle: Bypassing Python Restricted Unpickler for Automatic Exploit Generation," IEEE QRS (2022)
- J. Applegate, A. Kellas, "PICKLEFUZZER: A Case Study in Fuzzing for Discrepancies Between Python Pickle Implementations" (2026)
- ONNX project documentation and reference materials.
- The HDF Group, "An Overview of the HDF5 Technology Suite and its Applications."

---

*LinkedIn: [www.linkedin.com/in/naji-bou-zeid-a4aa99332]. See `README.md` for installation and usage instructions; this document is the project's technical narrative and rationale, not its operating manual.*
