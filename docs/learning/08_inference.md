# 08 — Inference: `app/inference/`

This file covers exactly how a feature vector — a plain list of numbers —
turns into a probability, for both pipelines. By the time you finish this
file, you'll understand every check that runs before a single prediction is
trusted, and why so many of them exist.

## Why feature *order* is the single most dangerous thing in this whole project

Both trained models are, underneath, a large collection of decision trees.
A decision tree doesn't know that "column 12" means `malfind.ninjections` —
it only knows "look at whatever value sits at position 12, and branch based
on whether it's above or below some number." If you hand a model a feature
vector where the values are in a **different order** than the one it was
trained on, nothing crashes. There's no error, no warning. The model
happily produces a confident-looking probability — it's just answering a
completely different, meaningless question, because "position 12" now
holds a totally different real-world measurement than it did during
training. This is exactly the danger CLAUDE.md calls "the feature-naming
trap," and it's why this file (and the two extractor files, 09 and 10)
treat feature-name bookkeeping as seriously as they do — a silent ordering
bug produces *wrong answers forever*, with nothing in the system's normal
operation ever revealing that anything went wrong.

Two extra complications make this harder here than it might sound:

1. **The disk model's internal feature names are useless.** The saved
   LightGBM model file literally calls its inputs `Column_0` through
   `Column_149` — it was trained on a bare NumPy array, not a named table,
   so there is no way to ask the loaded model object itself "what does
   column 12 mean?" The *only* place real names exist is in the separate
   JSON feature-list files.
2. **The memory model's internal names are real** — but this project
   deliberately never relies on that, because trusting a model object's own
   embedded names in one pipeline and not the other would be exactly the
   kind of inconsistency that lets a mistake slip through unnoticed later.

The rule that follows from all of this, applied without exception in both
`disk.py` and `memory.py` below: **feature names come only from the JSON
files, vectors are built and indexed purely by position (never by name
lookup at prediction time), and every model's expected feature count is
checked against the JSON list's length at startup.**

## `app/inference/disk.py`, in full

```python
import json

import lightgbm as lgb
import numpy as np

_booster = None
_selected = None
_idx = None
_threshold = None

FULL_DIM = 2381
SELECTED_DIM = 150


class ModelError(RuntimeError):
    pass
```

Four **module-level** variables (`_booster`, `_selected`, `_idx`,
`_threshold`), all starting as `None` and filled in exactly once by
`load()`. Because this is module-level state rather than something
recreated per request, the loaded model and its computed index list are
built once at application startup and simply reused for every prediction
for the rest of the process's life — file 05 covered why this matters for
performance. `ModelError` is a small **custom exception class** — inheriting
from `RuntimeError` means it behaves exactly like any other Python
exception, but code that specifically wants to catch *this* project's own
model-related failures (as opposed to some unrelated bug) can catch
`ModelError` specifically.

### `load()` — everything checked before this model is trusted

```python
def load(models_dir, reference_dir):
    global _booster, _selected, _idx, _threshold

    here = models_dir / "disk"
    _selected = json.loads((here / "feature_list_selected.json").read_text())
    full = json.loads((here / "feature_list_full_2381.json").read_text())
    meta = json.loads((here / "metadata.json").read_text())
    _threshold = meta["threshold"]

    if _threshold == 0.5:
        raise ModelError("disk threshold read as 0.5 - metadata.json is wrong")
    if len(full) != FULL_DIM:
        raise ModelError(f"full feature list has {len(full)} names, expected {FULL_DIM}")
```

`global _booster, ...` tells Python that the assignments inside this
function should modify the module-level variables declared above, rather
than creating new local ones that vanish when the function returns. Three
JSON files get read: the 150 selected feature names, the full 2,381-name
schema, and the metadata (which records training details, but the *only*
value actually used at runtime is `threshold`). The very first sanity check
is almost comically simple but load-bearing: **if the threshold reads as
exactly `0.5`, refuse to load.** This isn't paranoia for its own sake —
`0.5` is the *default* value a probability threshold would silently take if
something went wrong reading it from the metadata file (a missing key, a
typo in the JSON) and code elsewhere fell back to a naive default without
anyone noticing. Since this project's real operating threshold
(`0.5010602922493019`) happens to be extremely close to but *not* exactly
`0.5`, catching the exact value `0.5` here is a cheap, reliable trip-wire
for "the real threshold wasn't actually loaded."

```python
    _booster = lgb.Booster(model_file=str(here / "lightgbm_model.txt"))

    n = _booster.num_feature()
    if n != len(_selected) or n != SELECTED_DIM:
        raise ModelError(f"disk model has {n} features, selected list has {len(_selected)}")
```

The actual LightGBM model file gets loaded (file 01 covered this API call).
Immediately, its own reported input width (`num_feature()`) is checked
against *both* the JSON list's length *and* the hardcoded `SELECTED_DIM =
150` constant — three independent numbers that all have to agree, catching
either a corrupted/wrong model file or a corrupted/wrong feature list, not
just one or the other.

```python
    pos = {name: i for i, name in enumerate(full)}
    missing = [name for name in _selected if name not in pos]
    if missing:
        raise ModelError(f"{len(missing)} selected features absent from the 2381 list: "
                         f"{missing[:3]}")

    _idx = [pos[name] for name in _selected]
    if _idx == sorted(_idx):
        raise ModelError("subset indices came out sorted; the selected list order was lost")
```

This is where the crucial subset-index computation happens, and it's worth
walking through carefully. `{name: i for i, name in enumerate(full)}` is a
**dictionary comprehension** — a compact way of building a dictionary by
looping — that produces `pos`, mapping every one of the 2,381 full feature
names to its position in that full list. `enumerate(full)` pairs each item
with its index automatically (`0, name0`, `1, name1`, ...) so you don't
have to track a counter by hand.

`_idx = [pos[name] for name in _selected]` then builds a **list
comprehension** (the same looping idea, but producing a list instead of a
dictionary): for each of the 150 selected feature names, in the exact order
`feature_list_selected.json` lists them, look up where that name sits in
the full 2,381-length vector. The resulting `_idx` is exactly 150 integers
— this is the "subset index list" CLAUDE.md refers to constantly, and it's
computed **once, here, at startup**, then reused for every single
prediction going forward (see `subset()` below) rather than recomputed
per-request.

The very last check here — `if _idx == sorted(_idx): raise ModelError(...)`
— is one of the sharpest, most specific correctness guards in the entire
codebase, and it deserves real attention. CLAUDE.md states, as a measured
fact rather than a guess, that the real 150 selected indices genuinely are
**not** in ascending order — they range from roughly 1 to 2377 but jump
around non-monotonically. Both `vec_2381[sorted(idx)]` and `vec_2381[idx]`
(the correct one) would run without crashing and produce a valid-*looking*
150-length vector — but only one of them is right, because sorting the
indices would silently pair each selected feature with the wrong value,
one that happened to sit at that *sorted* position instead of the *real*
one. This assertion catches the specific, easy-to-make mistake of someone
adding a `.sort()` somewhere in a "cleanup," believing indices ought to be
in order — an assumption that happens to be false here, and dangerous if
acted on. Because it's an inherent property of the real committed data
(not something that could ever legitimately change), this check should
never fire in a correct system — its entire value is as a tripwire against
a *future* mistake.

```python
    ref = np.load(reference_dir / "disk_sample.npy")
    if ref.shape[1] != SELECTED_DIM:
        raise ModelError(f"disk_sample.npy has {ref.shape[1]} columns, expected {SELECTED_DIM}")
    if not np.isfinite(ref).all():
        raise ModelError("disk_sample.npy contains NaN or Inf")

    _check_reference(ref)
    return len(_selected)
```

The reference sample (5,000 real rows from the actual disk training
distribution, in the 150-feature selected space) gets loaded and checked
for the right shape and for the absence of `NaN`/infinite values (which
would silently corrupt any statistic computed from it, including LIME's own
setup). Then `_check_reference(ref)` runs the single most powerful
correctness check in this whole module — covered next — before `load()`
finally returns the feature count as a simple confirmation of success.

### `_check_reference()` — the one check that catches a scrambled column order

```python
def _check_reference(ref):
    p = predict_batch(ref)
    above = float((p >= _threshold).mean())
    mid = float(((p > 0.05) & (p < 0.95)).mean())
    if not 0.45 <= above <= 0.55 or mid > 0.25:
        raise ModelError(
            f"disk reference distribution looks wrong: {above:.3f} above threshold "
            f"(expect ~0.49), {mid:.3f} in the 0.05-0.95 band (expect ~0.13). "
            "A permuted feature order is the usual cause.")
```

Here's the idea, stated plainly: **the disk model's training set was
balanced 50/50 between benign and malicious examples.** So if you run all
5,000 reference rows through the model *correctly*, roughly half of them
should score above the operating threshold, and — because a well-trained
model tends to be *confident*, pushing most predictions toward the extreme
ends of the 0-to-1 probability range rather than sitting vaguely in the
middle — only a modest fraction should land in the ambiguous "mid-band"
between 0.05 and 0.95.

If the feature columns were ever scrambled (by a bug in how a vector gets
assembled, for instance), the model would essentially be looking at
meaningless, randomly-recombined numbers for every row. It would no longer
be able to confidently separate the two classes, and the whole distribution
of its output would collapse toward the uninformative middle. CLAUDE.md
records the measured numbers directly: correctly ordered, roughly 49% of
disk reference rows land above threshold with about 13% in the mid-band;
scrambled, those numbers become roughly 30% above threshold and 85% in the
mid-band — a dramatic, easily-detected shift. This single statistical check
(verified against 200 random column permutations, rejecting all 200) is
what catches a *wholesale* reordering that no simple "does it load, does it
predict a number" smoke test ever would, because a scrambled model still
loads fine and still produces syntactically valid probabilities — they're
just wrong.

**Its known limitation, stated honestly rather than glossed over:** this
check catches wholesale scrambling, but *not* a small transposition — e.g.
swapping two adjacent columns barely moves the aggregate distribution at
all (measured: caught in only 0 of 149 cases on disk, 5 of 54 on memory).
The real defence against *that* narrower failure mode is structural, not
statistical: building every vector as a dictionary keyed by feature name
and only emitting it in the JSON's exact order at the very last step, which
is exactly what the two extractor files (09 and 10) do, and which their own
tests verify directly by comparing the emitted order to the JSON order.

### `subset()`, `predict_batch()`, `predict()` — the actual prediction path

```python
def subset(vec_2381):
    vec = np.asarray(vec_2381)
    if vec.shape[-1] != FULL_DIM:
        raise ModelError(f"expected {FULL_DIM} features from EMBER, got {vec.shape[-1]}")
    return vec[..., _idx]


def predict_batch(mat):
    mat = np.ascontiguousarray(mat, dtype=np.float64)
    return _booster.predict(mat)


def predict(vec_150):
    if len(vec_150) != SELECTED_DIM:
        raise ModelError(f"expected a {SELECTED_DIM}-length vector, got {len(vec_150)}")
    p = float(predict_batch(np.asarray(vec_150).reshape(1, -1))[0])
    return p, p >= _threshold
```

`subset(vec_2381)` is the function `jobs.py`'s `_disk()` calls on every
single extracted file (file 07). `vec[..., _idx]` uses NumPy's **fancy
indexing** — handing it a *list* of positions (the precomputed `_idx` from
`load()`) instead of a single number picks out exactly those 150 positions,
in exactly that order, in one operation. This is deliberately the *only*
place in the whole prediction path where the full 2,381-length vector ever
gets reduced down to the model's real input size.

`predict_batch(mat)` is the raw call into LightGBM — `np.ascontiguousarray`
ensures the array is laid out in memory the way LightGBM's underlying C
code expects (a NumPy array can sometimes be a non-contiguous "view" into
another array, which native code libraries often can't safely accept
directly), and `dtype=np.float64` forces double-precision floating point.
`predict(vec_150)` is the single-vector convenience wrapper `jobs.py`
actually calls: check the length is exactly 150, reshape a flat 150-length
vector into a `(1, 150)` two-dimensional array (`.reshape(1, -1)` — "one
row, however many columns is needed," which LightGBM's batch-oriented API
expects even for a single prediction), predict, and pull the single
resulting number back out with `[0]`. It returns a **tuple**: the raw
probability, and a boolean of whether it's at or above the threshold.
Notice `p >= _threshold`, never a hardcoded `p >= 0.5` — this is hard rule
1 made concrete in code.

## `app/inference/memory.py`, in full

Structurally similar to the disk module, but with two extra pieces the
memory pipeline specifically needs: a pinned tree-iteration range, and the
out-of-distribution machinery.

```python
TREES = (0, 173)

DOMINANT = ("svcscan.nservices", "handles.nmutant",
            "svcscan.shared_process_services", "svcscan.kernel_drivers")
```

`TREES = (0, 173)` addresses a real, subtle ambiguity recorded directly in
the comment: the saved memory model file carries a metadata field saying it
has 173 trees total, but *also* records that early stopping during training
found its best result at tree 122 — so which count should inference
actually use? The comment states the resolution precisely: under the
pinned XGBoost version, the library's own default behaviour for
`inplace_predict` already uses all 173 trees (verified to produce identical
output to explicitly requesting `iteration_range=(0, 173)`), and using only
123 trees instead flips **zero** of 5,000 reference verdicts — so the
practical difference is negligible either way. But the choice is still
pinned **explicitly**, rather than left to rely on whatever the installed
library version's default happens to be, because that default is "not
contractual across versions" — a future XGBoost upgrade could quietly
change its own default without anyone noticing, and this project would
rather fail loudly on a version mismatch (via the separate version check in
`inference/__init__.py`, below) than silently start using a different tree
count than the one that was actually validated.

`DOMINANT` names the four specific features (measured directly from the
trained model, not guessed) that together carry roughly 98% of its total
decision-making weight, with the next-most-important feature contributing
roughly 80 times less. Three of the four are literally counts of installed
services and drivers — properties of how a machine happens to be
*configured*, not of what any process actually *did*. This tuple is the
concrete implementation of one of CLAUDE.md's most important findings about
this specific model, used directly by `dominant_ood()` below.

### `load()` — largely mirrors disk's, with one extra, very specific check

```python
    zeros = int(sum(1 for i in range(55) if not ref[:, i].any()))
    flat = int(sum(1 for i in range(55) if ref[:, i].std() == 0))
    if (zeros, flat) != (3, 4):
        raise ModelError(f"memory_sample.npy has {zeros} all-zero and {flat} "
                         f"zero-variance columns, expected 3 and 4")
```

This check looks oddly specific until you know the story behind it. Three
of the 55 memory features are genuinely, always zero across the entire
training distribution (e.g. `pslist.nprocs64bit` — file 10 explains why).
But a **fourth** feature, `callbacks.ngeneric`, is also zero-*variance*
(every single training row has the exact same value) — except that value
is a constant `8.0`, never `0.0`. Checking only "how many columns have zero
variance" and expecting that number to equal 3 would be the wrong test —
it would actually equal 4, and a check written carelessly around "3
zero-variance columns" would fail at boot on perfectly correct data. This
line checks **both** numbers, deliberately distinguishing "always literally
zero" from "constant, but not necessarily zero," which is exactly the
distinction that matters here, and is exactly the kind of subtlety
CLAUDE.md insists on getting right rather than glossing over.

```python
    _lo, _hi = ref.min(0), ref.max(0)
    _check_reference(ref)
    return len(_names)
```

`ref.min(0)` and `ref.max(0)` compute, for each of the 55 columns
independently (`axis=0` means "collapse down the rows, keep the columns"),
the minimum and maximum value seen anywhere in the 5,000 reference training
rows. These two arrays (`_lo`, `_hi`) are stored as module-level state and
are the entire basis for the out-of-distribution check below —
`_check_reference` runs the identical bimodal-distribution sanity check
already explained in detail in the disk section above (with memory's own
measured expected numbers: ~49% above threshold, ~0.1% in the mid-band
correctly ordered, versus 0% above threshold and ~99.9% in the mid-band
scrambled — an even more dramatic collapse than disk's).

### `predict_batch()` — why `inplace_predict`, specifically, and not the more common `DMatrix` path

```python
def predict_batch(mat):
    mat = np.ascontiguousarray(mat, dtype=np.float32)
    return _booster.inplace_predict(mat, iteration_range=TREES)
```

Most XGBoost tutorials show predictions going through `DMatrix` — a
special, optimised data container XGBoost normally expects. This project
deliberately uses `inplace_predict` instead, running directly against a
plain NumPy array, and the reason is a direct, practical consequence of the
feature-naming trap discussed at the top of this file: **the memory model
happens to carry its 55 real feature names internally** (unlike the disk
model's meaningless `Column_0..149`). `Booster.predict(DMatrix(arr))`
*validates* those names against whatever the `DMatrix` was told they are —
and a plain positional NumPy array, with no names attached to it at all,
would make that validation immediately raise `ValueError: data did not
contain feature names`. `inplace_predict` skips that name-validation step
entirely, working purely positionally — which is exactly what makes hard
rule 2 ("feature names come only from the JSON list, never from a model
object") actually *workable* in practice for this specific model, rather
than fighting XGBoost's own built-in validation the whole way.

### `ood()` and `dominant_ood()` — the out-of-distribution guard

```python
def ood(vec):
    vec = np.asarray(vec, dtype=np.float64)
    outside = (vec < _lo) | (vec > _hi)
    return int(outside.sum()), [_names[i] for i in np.flatnonzero(outside)]


def dominant_ood(vec):
    _, names = ood(vec)
    return [n for n in DOMINANT if n in names]
```

`(vec < _lo) | (vec > _hi)` is a single NumPy expression computing, for
*every one of the 55 features at once*, whether this capture's value falls
below the minimum or above the maximum ever seen in the training data — `|`
here is a NumPy element-wise "or," not Python's usual boolean `or`, which
lets it operate across a whole array at once rather than one value at a
time. `outside.sum()` counts how many `True`s there are (Python treats
`True` as `1` and `False` as `0` when summed), and
`[_names[i] for i in np.flatnonzero(outside)]` (file 01's NumPy section)
turns the positions where that's `True` back into actual feature names.

The comment on `ood()` states the "why" directly and links straight back to
hard rule 17: CIC-MalMem-2022 (the training dataset) came from a single VM
build, so on a genuinely real, modern dump, *most* features will land
outside that narrow training range, and the tree ensemble is, in that
region, essentially **extrapolating** rather than interpolating within
territory it actually learned from — tree models don't gracefully degrade
outside their training range the way some other model types might; they
just keep returning whatever a leaf at the edge of the tree happens to say,
with no signal attached that says "I'm guessing here."

`dominant_ood()` narrows that same check down to just the four `DOMINANT`
features — and this is the sharper, more consequential version of the same
idea. `jobs.py`'s `_memory()` (file 07) uses exactly this function's result
to decide `reliable = not dominant`, which in turn decides whether the
model's probability is trusted for severity at all, and whether LIME is
even run. It's entirely possible (and, per CLAUDE.md's measurements, is
what actually happens on a real capture) for a large fraction of all 55
features to read as technically "out of distribution" while still being
worth reporting — but the moment the four features the model *actually
leans on* fall outside their training range, the model's own score is
treated as essentially arbitrary and demoted to a secondary, clearly-labelled
signal rather than the headline of the report (hard rule 22).

## `app/inference/__init__.py` — loading both, and checking library versions

```python
def init(models_dir, reference_dir):
    global _loaded

    n_mem = memory.load(models_dir, reference_dir)
    n_disk = disk.load(models_dir, reference_dir)
    _check_versions(models_dir)

    log.info("models loaded: memory %d features (threshold %.6f), "
             "disk %d of 2381 features (threshold %.6f)",
             n_mem, memory.threshold(), n_disk, disk.threshold())
    _loaded = True
```

This is the single function `app/__init__.py`'s `create_app()` calls (file
05). It's deliberately **not** a shared base class or a generic "load a
model" helper applied twice — the comment states this decision directly:
"XGBoost and LightGBM disagree on how to load, how to predict and what a
feature name is, and papering over that is how the two get swapped." Two
separate, independent `load()` calls, one per pipeline, each with its own
full set of checks, is considered safer than any shared abstraction that
might blur the real differences between the two.

```python
def _check_versions(models_dir):
    import lightgbm
    import sklearn
    import xgboost

    running = {"xgboost": xgboost.__version__, "lightgbm": lightgbm.__version__,
               "sklearn": sklearn.__version__}
    for pipeline in ("memory", "disk"):
        meta = json.loads((models_dir / pipeline / "metadata.json").read_text())
        for lib, want in meta.get("library_versions", {}).items():
            got = running.get(lib)
            if got and got != want:
                log.warning("%s %s is installed but the %s model was saved under %s",
                            lib, got, pipeline, want)
```

A final startup check comparing the *actually installed* versions of
`xgboost`, `lightgbm`, and `sklearn` against whatever each model's own
`metadata.json` recorded as the versions it was trained/saved under. Note
this only **warns** (`log.warning`), it doesn't refuse to boot the way the
threshold and feature-count checks do — the comment explains the
reasoning: "a patch bump is usually harmless, a major one can change split
evaluation." A minor version mismatch is common and rarely dangerous, so
this is a "someone should look at this" signal rather than a hard failure,
which would make routine dependency updates unnecessarily painful.

## Check your understanding

**Q1. Why does `disk.py:load()` refuse to load if the threshold reads as
exactly `0.5`, when `0.5010602922493019` (the real value) is so close to
it?**

A: Because `0.5` is a common silent fallback value — if something went
wrong reading the real threshold from `metadata.json` (a missing key, a
malformed file), naive code elsewhere might default to `0.5` without
raising any error at all. Since the real operating threshold is close to
but never exactly `0.5`, catching that one specific value is a cheap,
reliable way to detect "the real threshold was never actually loaded,"
rather than silently using the wrong number forever.

**Q2. What specific, real mistake does the `if _idx == sorted(_idx):`
assertion in `disk.py` guard against, and why would that mistake otherwise
go completely unnoticed?**

A: It guards against someone (in a future code change) sorting the
150-element subset index list, perhaps out of a mistaken assumption that
indices "ought" to be in ascending order. Sorting them would silently pair
each selected feature name with the *wrong* value from the full 2,381-
length vector — every one of the 150 slots would still get *some* number,
the model would still run and still produce a confident-looking
probability, and nothing about the process would raise an error or a
warning. It would just be quietly, permanently wrong.

**Q3. What real statistical fact about the training data does
`_check_reference()` rely on, and what does it measure that reveals a
scrambled feature order?**

A: It relies on both models' training sets being balanced 50/50 between
benign and malicious examples. Run correctly, roughly half of the 5,000
reference rows should score above the operating threshold, and a well-
trained model should be confident about most of them (few landing in the
ambiguous middle of the probability range). A scrambled column order feeds
the model effectively meaningless, randomly recombined numbers, so it can
no longer separate the two classes — the fraction above threshold collapses
toward an uninformative value and the fraction in the mid-band spikes
dramatically, both measurable in one pass over the reference data.

**Q4. Why does the memory pipeline use `inplace_predict` instead of the
more commonly documented `DMatrix`-based prediction path?**

A: Because the memory model happens to carry its 55 real, semantic feature
names embedded internally (unlike the disk model). XGBoost's `DMatrix`-based
`predict()` validates incoming feature names against what it's told the
model expects, and a plain positional NumPy array with no names attached
would fail that validation outright. `inplace_predict` skips name
validation entirely and works purely by position, which is exactly what
lets this project follow hard rule 2 (names only ever come from the JSON
list, never from a model object) without fighting XGBoost's own built-in
checks.

**Q5. What's the practical difference between `ood()` and
`dominant_ood()`, and why does `jobs.py` specifically use the result of
`dominant_ood()` — not `ood()` — to decide whether the model's probability
can be trusted for a given memory capture?**

A: `ood()` checks all 55 features and returns how many, and which ones,
fall outside the training range — a broad measure that, on a real capture,
is very often a large number, and isn't by itself a reason to distrust the
score (this model was trained on one narrow VM configuration, so *most*
features being technically out of range is expected and not fatal).
`dominant_ood()` narrows that check to just the four features the model
actually leans on for ~98% of its decision. It's specifically *those* four
being in range or not that determines whether the model's own probability
means anything at all for this input — which is why `reliable = not
dominant` in `jobs.py` is built from `dominant_ood()`, not the much broader
`ood()` count.
