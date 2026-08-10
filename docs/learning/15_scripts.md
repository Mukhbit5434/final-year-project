# 15 — Standalone Scripts: `scripts/`

Every file in `scripts/` is a small, independent command-line program built
on top of the application code covered in files 03–12, but run directly
from a terminal rather than through the web app. This file covers all
fifteen of them: what each one does, when a real person would actually run
it, and why it exists as a separate script rather than a web route.

A recurring pattern worth noticing up front: nearly every script starts
with

```python
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
```

— the same "find the project root from this file's own location" idiom
introduced in file 03's `config.py`, followed by adding that root
directory to Python's own module search path (`sys.path`), which is what
lets a script sitting in `scripts/` still write `from app.inference import
disk` and have Python find the `app` package correctly, even though the
script itself isn't located inside it.

## Environment setup and verification

### `check_env.py` — "is everything actually installed and working correctly?"

Run this first, on a new machine, or any time something seems subtly wrong.
It checks, in order: whether the pinned libraries (`xgboost`, `lightgbm`,
`sklearn`) match the exact versions recorded in each model's own
`metadata.json` (file 08's `_check_versions()` does this same check at
Flask startup — this script does it standalone, without needing to boot
the whole web app); whether every other library imports at all; whether
the model artifact files have the right shapes (feature counts, subset
index non-monotonicity, thresholds not equal to `0.5` — all the same
checks file 08 covers in the real loaders, run here independently); whether
the reference `.npy` files have the right shape and the right
all-zero/zero-variance column counts (file 08 again); and, finally, an
actual **end-to-end smoke test** of the `ember` extraction pipeline —
running `patch_ember.load_features().PEFeatureExtractor(...)` against the
running Python interpreter's own `.exe` file (`sys.executable` — a real,
guaranteed-to-exist PE file on any Windows machine) and confirming it
produces exactly 2,381 features. The whole script prints a clean, readable
`RESULT: OK` or `RESULT: FAILURES PRESENT` at the very end.

### `setup_env.py` — installing everything, in the one specific order that works

This is a thin wrapper around a sequence of `pip install` commands, and its
entire value is capturing an order and a set of flags that genuinely
matters and isn't obvious from the requirements files alone (file 01
already covered *why* this order is necessary). It installs
`requirements.txt`, then `requirements-forensics.txt`, then — critically —
**uninstalls and reinstalls `lief` at the exact pinned `1.0.0` version**
before installing `ember` itself with `--no-deps`. The comment explains
why that specific sequence: `ember`'s own `setup.py` would otherwise pull
in and silently downgrade `lief` to `0.9.0`, clobbering the exact version
this project's models were actually trained against. It installs `ember`
from a GitHub tarball URL rather than `git+https://...`, specifically so
this step works even on a machine without `git` itself on its `PATH`.
Finally, it calls `patch_ember.apply()` (below) to fix `ember`'s source so
it actually runs under this newer `lief`/`numpy`.

### `patch_ember.py` — the three source patches `ember` needs, and how they're managed safely

Already introduced in file 01 and file 09; here's the mechanism in full.
`PATCHES` is a tuple of `(name, broken_text, fixed_text)` triples — three
exact snippets of `ember`'s own `features.py` source, each with a broken
version and its fix:

1. **`featurehasher`** — fixes `FeatureHasher(...).transform([raw_obj
   ['entry']])` (which crashes with `ValueError: Samples can not be a
   single string`, a real upstream bug tracked as elastic/ember PR #109)
   into the correctly-nested `transform([[raw_obj['entry']]])`.
2. **`lief_errors`** — `lief` 1.0 removed several exception classes
   (`bad_format`, `bad_file`, etc.) that `ember`'s original code assumed
   would always exist, causing an immediate `AttributeError` before any
   real parsing could happen. The fix resolves whichever of those names the
   *actually installed* `lief` version still exposes, using `getattr(lief,
   name, None)` for each and filtering to only the ones that really exist,
   always including plain `RuntimeError` as a catch-all — a genuinely
   version-tolerant fix, not a hardcoded assumption about exactly which
   names exist.
3. **`np_int`** — `np.int` was removed in NumPy 1.24 (deprecated first,
   then removed); the fix replaces it with the plain Python builtin `int`,
   which the comment notes is "what the alias always meant," so the
   resulting dtype is genuinely unchanged.

`state()` reads the real, installed `ember/features.py` file's actual text
and reports, per patch, whether it's `"patched"`, `"unpatched"`, or
`"unknown"` (the target text wasn't found at all — meaning upstream `ember`
itself changed in a way these patches no longer recognise). `verify()` —
called from application startup, not this script — simply checks that
every patch reads as `"patched"` and refuses to boot otherwise, with a
clear message pointing at this script. The comment explains a real,
deliberate design decision directly: **patching happens only at install
time** (when you actually run this script, e.g. as part of `setup_env.py`),
never automatically at application startup, because rewriting files inside
`site-packages` while the actual web server is running is fragile —
read-only installs, restricted service accounts, and a write race between
multiple concurrent worker processes could all break it in ways that would
be far harder to diagnose than a clear "please run this script" refusal.
`load_features()` is the function actually used at runtime (file 09) — it
loads `ember/features.py` as a **standalone module**, bypassing `ember`'s
own `__init__.py` entirely (and, with it, `pandas`/`lightgbm`/`sklearn.
model_selection`, none of which the extraction path needs, and one of
which — `pandas` — is blocked outright on the deployment target).

### `fetch_symbols.py` — staging Windows kernel symbols for offline use

Already introduced conceptually in file 10; here's the mechanism.
`_isf_url(dump)` calls `build_context(dump)` (the *exact same* function
`extractors/memory.py` uses for real extraction) purely to force Volatility
3's automagic system to resolve which symbol table this specific dump
needs, then reads that symbol table's own configuration to find either an
`isf_url` (a network location) or an `isf_filepath` (a local one).
`_load_isf(blob, name)` handles the fact that Volatility ships these symbol
files compressed in one of several formats (`.gz`, `.xz`, `.zip`, or
uncompressed `.json`), decompressing just enough to confirm the file is
genuinely intact and parseable JSON — but `stage(url)` itself writes the
file to `symbols/windows/` **verbatim, still compressed** (the comment
notes precisely why: Volatility itself reads `.json.xz` directly from a
symbols directory without needing it pre-expanded, and the staged file is
roughly 0.6 MB compressed against roughly 100 MB expanded — expanding it
on disk would be needless bloat). Run with `--list`, it simply reports
what's already staged; run with a dump path, it resolves and stages
whatever that specific dump needs; the resulting `symbols/` folder (file
02, gitignored — machine and build specific) is what lets
`extractors/memory.py:_use_local_symbols()` (file 10) find everything it
needs with zero network access on every subsequent run.

## Direct command-line access to each pipeline

### `scan_image.py` — run the disk pipeline against a real image, no web app needed

```
scripts\scan_image.py evidence.dd
scripts\scan_image.py evidence.E01 --no-predict
```

Calls `extractor.scan(...)` (file 09) directly, prints acquisition metadata
if the image is an E01 (`extractor.ewf_metadata`), then — unless
`--no-predict` was passed — loads the disk model (`model.load(...)`, file
08) and runs every found file through `model.subset()` and `model.predict
()`, printing a sorted table of every result (most probable first) with
each flagged file's SHA-256 printed directly beneath it. This is exactly
the tool a developer or operator reaches for to check disk extraction and
inference behaviour on a real image without needing a running server, a
database, or a browser at all — genuinely useful during development and
debugging, distinct from the full web-app path.

### `dump_memory_features.py` — the diagnostic tool for eyeballing memory extraction

```
scripts\dump_memory_features.py capture.raw --json out.json
```

Calls `extractor.extract(...)` (file 10) directly and prints **all 55
features, one per line**, each one shown next to its training-data minimum
and maximum (loaded from `reference_data/memory_sample.npy`, file 08),
flagged `OUT` if the extracted value falls outside that range — this is the
literal implementation of the "write a small script that prints each of the
55 values next to that column's training min/max, so they can be eyeballed"
requirement CLAUDE.md states directly. It also runs the value through the
real model, reports the probability, verdict, and out-of-distribution
count, and — specifically when the four `DOMINANT` features (file 08) are
themselves out of range — prints an explicit, readable statement that the
model's verdict isn't reliable for this particular capture, naming exactly
which of the four features and their individual training ranges. Every
extraction gap is printed too. The optional `--json` flag writes the same
data out as a file for later reference or comparison.

### `predict_vector.py` — the entry point for labelled, pre-extracted data

Already introduced in file 07's discussion of why a dedicated web route for
this was considered and rejected. This script exists to solve a genuine
gap: the web app only ever accepts raw *artifacts*, but two of this
project's most important demonstrations — a labelled CIC-MalMem-2022 row,
and a labelled EMBER test row — start life as **already-extracted feature
vectors**, not raw files. `predict_vector.py memory --csv malmem.csv --row
12` (matching CSV columns **by name**, never positionally — the docstring
is explicit about this, tying directly back to hard rule 2) or
`predict_vector.py disk --npy ember_row.npy` runs that one vector through
the exact same loaders, thresholds, LIME explainer, and severity/tag
functions the real job pipeline uses (`_memory()`/`_disk()` in this script
mirror `jobs.py`'s own functions closely, file 07) — genuinely exercising
the shipped inference and forensics code, not a reimplementation of it.

One deliberate, important restriction: **memory severity is never computed
here, under any circumstances.** The comment states exactly why: severity
needs a real capture of the reference machine to compare against a
baseline (file 11); a bare, pre-extracted vector carries no provenance at
all — no way to confirm which machine, or even what kind of capture, it
actually came from — so scoring it against the reference baseline would
produce a confident-*looking*, but essentially meaningless, answer, which
this script refuses to do, printing "severity: not scored" with an honest
explanation instead. A `--reference N` option exists too, for pulling a raw
row directly out of `reference_data/` — but the script prints an explicit,
impossible-to-miss warning every time this option is used, because those
rows are *unlabelled* training samples, not verified true positives, and
must never be mistaken for one.

## Producing genuinely held-out, labelled demo data

### `malmem_holdout.py` — reproducing the exact training split

The comment at the top of the real file states the core problem directly:
a convincing demo needs a labelled row the memory model has genuinely never
seen during training — and the only way to be *certain* a given CSV row
was never seen is to reproduce the exact same train/validation/test split
the original training process used, then only ever draw from the
reproduced *test* portion. This script does exactly that: `dedupe(rows)`
performs a plain `drop_duplicates()`-equivalent (keeping the first
occurrence of any exact row, across every column) using nothing but the
standard library's `csv` module (no `pandas` — file 01's "what's not here"
section), `group_keys(rows)` builds the grouping key `StratifiedGroupKFold`
needs (every genuinely distinct malware sample gets one group; every
benign row, having no distinguishing category information at all, gets its
**own individual group** — the comment explains precisely why that last
part matters: grouping benign rows on their shared `"Benign"` category
string alone would collapse the entire benign half of the dataset into a
single group, which `StratifiedGroupKFold` would then have no choice but
to place entirely on one side of the split), and `split(...)` runs the
same two-stage `StratifiedGroupKFold` process (outer split into
rest/test, then inner split of "rest" into train/validation) with the
exact same `random_state=42` the original training run used.

Crucially, `check(...)` then verifies the *result* against the real,
recorded numbers in `models/memory/metadata.json` — exact row counts,
exact test-set class balance, exact deduplicated total, and, most
importantly, **zero shared groups between any two of the three splits**.
`main()` refuses to write out any demo rows at all unless every one of
those checks passes (`--force` exists but the script's own message states
plainly why it shouldn't be used: "emitting nothing is worse than no row
at all" is the wrong way round — actually, emitting a row that *might* be
contaminated from training is worse than emitting nothing at all). Only
once verification passes does it pick the first malicious and first
benign row from the genuinely-reproduced test split, run each through the
real model, and write both the raw `.npy` vector and a sidecar `.json`
recording the label, the model's own prediction, and whether the split was
successfully verified — into `data/holdout/`, which, unlike the rest of
`data/`, actually is committed to the repository (file 02).

### `ember_holdout.py` — a genuine true positive, with no PE file ever opened

Solves a parallel problem for the disk pipeline: every artifact this
project can run end-to-end through the real filesystem/PE-parsing path is
known-clean (the CFReDS test image), so the actual malware-detection path
had never been demonstrated on real malicious data. EMBER's own published
test set ships **already-extracted raw feature *objects*** (not PE files
at all) with real labels attached. `rows(tar_path, wanted, limit)` streams
directly through the (roughly 1 GB expanded) `test_features.jsonl` member
inside the published tarball, reading it line by line without ever fully
extracting the whole archive to disk, stopping the moment it's found one
example of each wanted label. `extractor.process_raw_features(obj)` (a
different `ember` entry point from the one `extractors/disk.py` uses,
file 09 — this one starts from an already-parsed feature object rather
than raw PE bytes) turns that object straight into the full 2,381-value
vector. The result is written to `data/holdout/` exactly like
`malmem_holdout.py`'s output, with the sidecar JSON recording the true
label and whether the model's prediction agreed with it — the docstring
states the key property directly: "no PE binary is opened, no malware is
handled, and lief never parses anything," since the starting point is
already-extracted numbers, not a real executable file.

## Building the clean-machine baseline

### `baseline_extract.py` — running extraction once per clean capture, saving the result

Recall from file 11 that memory severity depends on comparing a new
capture against a baseline built from seven clean captures of one specific
reference machine — and recall from file 10 that a single memory
extraction genuinely takes minutes. `baseline_extract.py` exists purely so
that expensive step happens **exactly once per dump, ever** — it runs
`extractors.memory.extract(...)` (the real function, file 10) against each
of the seven named captures in turn, saves the resulting 55-value vector
as a `.npy` file under `data/baseline_vectors/` (gitignored, but locally
precious — STATUS.md notes it takes roughly 45 minutes total to
regenerate if ever lost), and records a rich summary alongside each one:
wall-clock time, confirmed bit-width, torn-row count, the model's own
probability and verdict for that clean capture, the out-of-distribution
count, and — for the captures where independently-verified ground truth
was actually recorded by hand at capture time — a direct comparison
between the extracted process/service/driver counts and that real,
external ground truth (this is the concrete data behind CLAUDE.md §5.6a's
"extraction validated in absolute terms" claim). Every subsequent baseline-
building step works purely from these saved vectors, never needing to
re-run the slow extraction again.

### `baseline_build.py` — turning seven vectors into one candidate baseline

Reads every `.npy` file `baseline_extract.py` produced, stacks them into
one matrix (`np.vstack(mats)`), and computes, per feature, the median,
interquartile range, minimum, and — the one that actually matters for
severity — the observed **maximum** (file 11's `ceiling()` reads exactly
this value). It prints two small diagnostic tables directly to the
terminal: the twelve *most* variable features (highest max/min ratio) and
the twelve *most* stable nonzero ones, letting a human sanity-check the
result before trusting it. The output — a full candidate baseline JSON,
written to `data/baseline_candidate.json` — is explicitly, deliberately
**not** the same file the live application reads (`baselines/
clean_win10_x64.json`). The docstring states this directly: promoting a
candidate to live is "a separate, deliberate step," done by a human
reviewing the candidate and manually copying it over — never automated,
specifically so a bad or premature baseline build can never silently
become what the live application scores real captures against.

## The capture-time demonstration tools

### `sim_injector.py` and `sim_spawnkill.py` — benign tools that produce genuinely real forensic artifacts

Both of these were already read and discussed in earlier work on this
project, and their purpose is worth restating precisely here, in context
with everything else this curriculum has now covered. Demonstrating the
memory pipeline's Process Injection and Rootkit/Hidden-Artifacts detection
convincingly requires a capture that genuinely contains those artifacts —
but running *real* malware to produce one would be both dangerous and,
depending on context, inappropriate. These two scripts instead produce the
**exact same low-level forensic signatures** real malware would leave,
through entirely benign, harmless means, verified directly against
`malfind`'s own real matching logic (STATUS.md records exactly what
`malfind` checks: private, non-empty, execute+write-or-dirty-execute
memory).

`sim_injector.py` calls the real Windows `VirtualAlloc` API (via `ctypes`,
Python's standard foreign-function interface — no external library needed)
to allocate 30 private `PAGE_EXECUTE_READWRITE` memory regions **inside its
own process**, writes a plain, readable marker string into each one (never
executes it, and the comment explains precisely why the write matters:
`malfind`'s own `is_vad_empty` check skips any region whose first page is
entirely zero-filled, so an allocation with nothing written into it
wouldn't even register as a hit at all), and then waits, printing "READY
FOR CAPTURE," for the analyst to actually take the memory capture while it
holds those regions open. `sim_spawnkill.py` launches 100 trivial `cmd /c
exit` processes and **deliberately keeps their process handles open** even
after each one has already exited — and file 10's discussion of "silent
bug #8" already covered, in full, the real, measured mechanism this
produces (not what an earlier draft of this same script predicted): holding
the handle keeps the terminated `EPROCESS` object linked in the same list
`pslist` itself walks, so it does *not* disappear from `pslist` the way
the original theory assumed — what actually and reliably goes missing,
regardless of the held handle, are the terminated process's thread
objects and its CSRSS session entry, which is why this technique reliably
elevates `psxview.not_in_ethread_pool` and `psxview.not_in_csrss_handles`
specifically.

Both scripts are explicitly, repeatedly labelled **"NOT malware"** in their
own docstrings, and both wait for an explicit `Enter` keypress before
releasing their held resources — giving the analyst full, deliberate
control over exactly when the actual memory capture happens relative to
each tool's state.

## Check your understanding

**Q1. Why does `patch_ember.py` apply its three source patches only at
install time (when a human explicitly runs `setup_env.py` or this script
directly), rather than automatically, every time the application starts
up?**

A: Rewriting files inside an installed package while the real application
might be running is fragile in ways that would be far harder to diagnose
than a clear refusal: a read-only installation, a restricted service
account without write permission, or a race between multiple concurrent
worker processes all trying to patch the same file simultaneously could
each break silently or confusingly. Instead, the application only ever
*verifies* the patches are already present at startup, and refuses to boot
with a clear message if they aren't — pushing the actual, one-time file
modification to a deliberate, human-run installation step instead.

**Q2. Why does `predict_vector.py` refuse to compute a severity score for
a memory vector under any circumstances, even though it happily computes
and shows the model's probability and its MITRE tag matches?**

A: Because memory severity scoring is calibrated against a specific,
known, clean-machine baseline (file 11), and that comparison is only
meaningful for a genuine capture of that specific reference machine. A
bare, pre-extracted feature vector — whether from a CSV row or a `.npy`
file — carries no provenance at all: there's no way to confirm it actually
came from that machine, or even from a real capture rather than a
synthetic or interpolated data point. Scoring it anyway would produce a
confident-*looking* but essentially meaningless severity, which this
script deliberately refuses to do, printing an honest "not scored" instead.

**Q3. What real, practical problem does `baseline_extract.py` solve by
existing as a separate script from `baseline_build.py`, rather than the
whole seven-capture baseline being built in one combined step?**

A: Extraction (running Volatility 3 against a real, multi-gigabyte memory
dump) is genuinely slow — minutes per capture, roughly 45 minutes total
across all seven. Separating it into its own script means that expensive
work only ever has to happen once, ever, with its results saved to disk;
`baseline_build.py` can then be run, re-run, and experimented with
(different aggregation choices, different diagnostic output) as many times
as needed, working purely from the already-saved vectors, without ever
needing to re-run the slow extraction step again.

**Q4. `sim_spawnkill.py`'s own docstring records that an earlier version
of its documented mechanism turned out to be wrong once measured against a
real capture. What was originally predicted, what was actually measured,
and why does the script's current docstring matter as a record, not just
as a fix?**

A: It was originally predicted that holding a handle to a terminated
process would hide that process from `pslist` specifically, driving up
`psxview.not_in_pslist`. Measured directly on a real capture, that's not
what happens — the held handle keeps the terminated process genuinely
linked in the same list `pslist` itself walks, so it does *not* disappear
from `pslist`; what actually and reliably disappears are its thread
objects and CSRSS session entry. The corrected docstring matters as a
record because it's a concrete, honest example of this whole project's
recurring lesson: a plausible theory about how something *should* work,
based on design intent alone, can be measurably wrong, and the only way to
find out is to run a real artifact through the real pipeline and read the
actual numbers.

**Q5. Both `malmem_holdout.py` and `ember_holdout.py` exist to produce
"genuinely held-out, labelled" demo data. What specifically distinguishes
data produced by these two scripts from a row pulled directly out of
`reference_data/memory_sample.npy` via `predict_vector.py --reference N`?**

A: `reference_data/*.npy` contains **unlabelled samples of the training
distribution itself** — rows the model may well have been fitted on
directly, with no ground-truth label attached at all. `malmem_holdout.py`
and `ember_holdout.py`, by contrast, either reproduce the exact original
train/test split and verify a chosen row genuinely landed in the *test*
portion (never seen during training) before emitting it, or pull directly
from a dataset's own published, pre-labelled *held-out* test file. Both
produce a row with a real, verified, known-correct label attached — which
is exactly what makes their output usable as evidence of a genuine true
positive or true negative, something a `--reference` row explicitly must
never be presented as.
