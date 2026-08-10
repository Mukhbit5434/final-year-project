# 11 — Explainability and Forensics: `app/explain.py` and `app/forensics/`

This file covers how a bare probability becomes something an analyst can
actually act on: a list of plain-English findings, MITRE ATT&CK tags, and a
deterministic, visible severity score. Nothing in this whole layer is
machine learning — it's lookup tables and plain functions applied to the
model's output and the extractor's raw measurements.

## `app/explain.py` — building and calling LIME

### Building the explainers, once, at startup

```python
CLASSES = ["Benign", "Malware"]

_memory = None
_disk = None

def _explainer(sample, names, discretize=True):
    from lime.lime_tabular import LimeTabularExplainer

    return LimeTabularExplainer(
        sample, feature_names=list(names), class_names=CLASSES,
        discretize_continuous=discretize, mode="classification",
        random_state=42)
```

`_explainer(...)` is a small factory function wrapping LIME's constructor
(file 01 covers this call). `random_state=42` fixes the random seed LIME
uses internally, which matters for a specific, practical reason: LIME
builds its local explanation by generating random perturbations around the
input it's explaining, and without a fixed seed, running the exact same
prediction through LIME twice could produce subtly different-looking
explanations each time — pinning the seed makes results reproducible,
which matters both for testing and for an analyst's trust that reloading a
report page shows consistent findings.

```python
def init(models_dir, reference_dir):
    global _memory, _disk
    from .inference import disk, memory

    mem_sample = np.load(reference_dir / "memory_sample.npy")
    disk_sample = np.load(reference_dir / "disk_sample.npy")

    try:
        _memory = _explainer(mem_sample, memory.names())
        _memory.explain_instance(mem_sample[0], _proba(memory), num_features=1,
                                 num_samples=20)
    except (ValueError, IndexError) as e:
        log.warning("LIME quartile discretiser failed on the memory sample (%s); "
                    "falling back to discretize_continuous=False", e)
        _memory = _explainer(mem_sample, memory.names(), discretize=False)

    _disk = _explainer(disk_sample, disk.names())
```

This is the function `create_app()` calls at startup (file 05), gated
behind the same `LOAD_MODELS` setting as the model loaders themselves. Two
separate `LimeTabularExplainer` instances are built — one per pipeline —
each seeded with that pipeline's own reference sample data (the same
`reference_data/*.npy` files the model loaders use for their own sanity
checks, file 08). Building an explainer is the genuinely expensive setup
step LIME needs (it computes statistics over the whole reference sample to
understand what a "typical" range of values looks like for every feature);
doing it once here, rather than per-prediction, is what makes actually
*using* LIME on a real result comparatively cheap.

The `try`/`except` around the memory explainer's construction is a real,
specific defensive measure, not boilerplate. LIME's default behaviour
(`discretize_continuous=True`) tries to bucket each feature's values into
quartiles for its internal explanation model — and file 08 already
established that the memory reference sample has **four genuinely
zero-variance columns** (three always exactly `0.0`, one, `callbacks.
ngeneric`, constant at `8.0`). Trying to compute *quartiles* of a column
that never varies at all is a real edge case LIME's own discretiser can
fail on. Rather than assuming it will work, this code actually **tests**
it — calling `explain_instance(...)` once, immediately, with a tiny,
cheap `num_samples=20` — and if that raises `ValueError` or `IndexError`,
falls back to building a second explainer with discretisation turned off
entirely, logging a clear warning either way. This is a good example of
this codebase's general discipline: don't assume a library handles an edge
case gracefully just because it usually does — test the specific edge case
this project's own data actually has, and have a real fallback ready.

### `_proba()` — bridging this project's two-value output to LIME's expected shape

```python
def _proba(model):
    def predict(matrix):
        p = np.asarray(model.predict_batch(matrix), dtype=np.float64)
        return np.column_stack([1.0 - p, p])
    return predict
```

LIME expects a `predict_proba`-shaped function: given a batch of feature
vectors, return, for **each** row, the probability of *every* class — here,
`[P(benign), P(malware)]` — not just the single "probability of malware"
number this project's own `predict_batch()` (file 08) returns.
`_proba(model)` wraps whichever model (memory or disk) LIME needs, calling
its real `predict_batch`, and then `np.column_stack([1.0 - p, p])` builds
the required two-column array by simple subtraction (since there are only
two classes here, "probability of benign" is just one minus "probability
of malware"). This is a small, self-contained adapter — LIME never has to
know anything at all about how this project's actual models work
internally.

### `_top()` — the one place a raw LIME result becomes a real finding

```python
def _top(explanation, names, limit):
    from .forensics import meanings

    out = []
    for index, weight in explanation.as_map()[1]:
        if weight <= 0:
            continue
        described = meanings.describe(names[index])
        if described is None:
            continue
        described["weight"] = float(weight)
        described["rank"] = len(out) + 1
        out.append(described)
        if len(out) >= limit:
            break
    return out
```

This function embodies one of the sharpest, most specific rules in the
whole codebase, and it's worth being precise about exactly what it's
avoiding. LIME's `explain_instance(...)` result offers two different ways
to read its findings: `as_list()`, which returns human-readable but
**discretised condition strings** like `"malfind.ninjections > 5.00"`, and
`as_map()`, which returns plain `(feature_index, weight)` pairs. The
comment states directly why `as_map()` is the only one ever used here:
looking a condition string like `"malfind.ninjections > 5.00"` up against a
lookup table keyed on bare feature names (`meanings.MEMORY`, covered below)
would **never match anything at all** — the string simply isn't the same
shape as the dictionary's keys — and the failure would be silent: an empty
findings list that looks exactly like "the model found nothing worth
explaining," when in reality the lookup itself was broken from the start.

`explanation.as_map()[1]` specifically asks for the explanation of class
index `1` — recall `CLASSES = ["Benign", "Malware"]`, so index `1` is
"Malware." Each `(index, weight)` pair is a raw feature position and how
much that feature contributed to pushing the prediction toward malware. A
`weight <= 0` is filtered out entirely — the comment is explicit that a
negative weight is "evidence the file is benign," not a finding worth
surfacing as a reason something was flagged. `meanings.describe(names[index])`
(covered next) turns the raw feature name at that position into an actual
plain-English description, and features this project's own lookup tables
don't recognise (`described is None`) are silently skipped rather than
shown as raw, meaningless names. Everything that survives gets a `rank`
(its position in the finding list, starting at 1) and the loop stops early
once `limit` findings have been collected (`jobs.py`, file 07, calls this
with `num_features=15, display=8` — LIME is asked to consider up to 15
candidate features, but only the top 8 that actually resolve to a known
meaning are kept). Notice too that resolving names purely through
`names[index]` (the project's own JSON-derived feature list, passed in as
an argument) rather than through anything LIME or the model object itself
produced is what satisfies hard rule 2 here "for free," as the code
comment puts it.

### The two public entry points

```python
def memory_findings(vec, num_features=15, display=8):
    from .inference import memory
    exp = _memory.explain_instance(np.asarray(vec, dtype=np.float64),
                                   _proba(memory), num_features=num_features,
                                   labels=(1,))
    return _top(exp, memory.names(), display)


def disk_findings(vec_150, num_features=15, display=8):
    from .inference import disk
    exp = _disk.explain_instance(np.asarray(vec_150, dtype=np.float64),
                                 _proba(disk), num_features=num_features,
                                 labels=(1,))
    return _top(exp, disk.names(), display)
```

These are the two functions `jobs.py` (file 07) actually calls, once per
malicious result, never for a benign one (that cost-saving decision was
already covered in file 07). `labels=(1,)` tells LIME to only bother
computing an explanation for class 1 (malware) — there's no need to spend
time explaining the benign side of a result that's already been flagged
malicious.

## `app/forensics/meanings.py` — turning a raw feature name into plain English

### Named memory features

```python
MEMORY = {
    "malfind.ninjections": (
        "Injected executable memory regions",
        "Private memory marked executable with no backing file on disk. This is how "
        "injected code is normally staged, though JIT compilers and browsers allocate "
        "it legitimately too."),
    ...
}
```

`MEMORY` is a plain dictionary mapping a feature name to a `(label,
explanation)` **tuple**. Every entry follows the same honest pattern worth
noticing throughout: state what was measured, then immediately state the
**legitimate, non-malicious reason** that same measurement can also occur
— never a bare claim of maliciousness. This isn't incidental wording; it's
the direct textual expression of the same evidence-led philosophy the
severity function (below) and CLAUDE.md §9.6 build the entire memory
report around: these are Volatility's genuine, standalone measurements of
the dump, but many of them are also completely ordinary on a healthy
machine, and a report that hides that fact would mislead an analyst into
reading routine activity as compromise.

### Disk features: three genuinely exact groups, and several hashed ones

```python
GENERAL = ["file size", "virtual size", "debug directory present", ...]
DATA_DIRS = ["export table", "import table", "resource table", ...]
SECTION_NAMED = ["section count", "zero-length sections", ...]
SECTION_BLOCKS = [(5, 55, "section size"), (55, 105, "section entropy"), ...]
HEADER_NAMED = {0: "compile timestamp", 51: "major image version", ...}
HEADER_BLOCKS = [(1, 11, "COFF machine type"), ...]
```

Recall from file 09 that disk features come from EMBER's 2,381-value
schema, most of which are **feature-hashed** — many different real values
(API names, section names) get compressed down into a fixed-size numeric
bucket via a hash function, which is irreversible: you cannot recover which
specific API name landed in bucket 1198, only that *something* did. But
CLAUDE.md notes something worth taking seriously: **not every disk feature
group is a hash** — three groups (`general_feat`, `datadirectory_feat`, and
part of `section_feat`) are genuinely **named, per-index recoverable
scalars**, verified directly against the installed `ember` source rather
than assumed. These four tables encode exactly that verified structure:
`GENERAL` and `HEADER_NAMED` list, by exact index, what each specific
scalar slot means; `DATA_DIRS` lists the 15 real PE data directories in
their real order (each one occupying two consecutive feature slots — size,
then virtual address); `SECTION_NAMED` lists five genuinely exact,
per-index section-table counts; and `SECTION_BLOCKS`/`HEADER_BLOCKS` mark
the *remaining* index ranges within those same two groups as hashed blocks,
each labelled with what general kind of information was hashed into it
(without claiming to know any specific value inside).

```python
GROUPS = {
    "byte_histogram": (
        "Byte-value frequency distribution",
        "How often each byte value occurs across the file. Skew toward high-entropy or "
        "non-ASCII ranges is consistent with packing, encryption or embedded compressed "
        "data."),
    ...
}
```

`GROUPS` covers the remaining, purely hash-bucketed feature families
(`byte_histogram`, `byte_entropy`, `string_feat`, `imports_hash`,
`exports_hash`) — for these, only a group-level meaning is ever given,
deliberately, because nothing more specific can honestly be claimed.

### `describe()` — the single resolver every finding goes through

```python
def _index(name):
    return int(name.rsplit("_", 1)[1])

def _block(index, blocks):
    for lo, hi, label in blocks:
        if lo <= index < hi:
            return label
    return None

def describe(feature):
    if feature in MEMORY:
        label, why = MEMORY[feature]
        return {"feature": feature, "group": feature.split(".")[0], "exact": True,
                "label": label, "why": why}

    group = feature.rsplit("_", 1)[0]

    if group == "general_feat":
        i = _index(feature)
        return {"feature": feature, "group": group, "exact": True,
                "label": GENERAL[i].capitalize(),
                "why": f"PE metadata: {GENERAL[i]}."}
    ...
```

Every finding this project ever shows an analyst — whether from a direct
memory observation (`jobs.py`, file 07) or from a LIME explanation (this
file, above) — passes through this exact function. `_index(name)` pulls
the trailing number off a name like `"general_feat_7"` (using
`rsplit("_", 1)` — split from the *right*, at most once, which correctly
handles multi-word group names like `"datadirectory_feat"` that themselves
contain underscores). `_block(index, blocks)` checks which labelled range a
given index falls into, for the hashed portions of the header/section
groups.

`describe()` dispatches, first checking the exact `MEMORY` dictionary,
then working through each disk group in turn. For `datadirectory_feat`
specifically, notice the extra, genuinely useful piece of context baked
directly into its `why` text — a comment inside the real function explains
it: "A zero certificate table means the binary carries no authenticode
signature," directly grounding the unsigned-binary MITRE indicator
(covered below) in a concrete, checkable feature reading, rather than a
vague inference. For `section_feat` and `header_feat`, `describe()`
first tries the *named* index tables, and only falls back to the *hashed
block* lookup for indices those named tables don't cover — exactly
mirroring the real, verified structure of those two feature groups. If a
feature genuinely resolves to nothing at all (not in any table, no group
matches), `describe()` returns `None`, and every caller (in `explain.py`
above, and in `jobs.py`, file 07) is written to skip that finding entirely
rather than show something meaningless.

### `observed()` — the memory pipeline's independent, model-free measurements

```python
BEHAVIOURAL = [
    "malfind.ninjections", "malfind.commitCharge", "malfind.uniqueInjections",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool", "psxview.not_in_csrss_handles",
    "callbacks.nanonymous",
]

def observed(vec, names):
    index = {n: i for i, n in enumerate(names)}
    return {f: float(vec[index[f]]) for f in BEHAVIOURAL
            if f in index and vec[index[f]] > 0}
```

`BEHAVIOURAL` is a deliberately curated subset of the full 55 features —
eleven features that describe something a machine *did* (injected regions,
loader-list mismatches, hidden processes, anonymous kernel callbacks)
rather than how it happens to be *configured* (service counts, driver
counts, process counts — the "volumetric" features covered later in this
file). `observed(vec, names)` returns only the ones that are actually
**greater than zero** for this specific capture — a feature that measured
exactly zero (e.g. no injected regions found at all) simply isn't a finding
worth reporting, positive or negative. This function's return value is
completely independent of what the trained model predicted — it's called
by `jobs.py:_memory()` (file 07) and used to build the memory report's
evidence-led findings *regardless* of the model's own verdict, which is the
concrete implementation of hard rule 22.

## `app/forensics/mitre.py` — the indicator-tag lookup table

```python
TAGS = [
    {"tag": "Process Injection", "id": "T1055", "name": "Process Injection",
     "confidence": HIGH, "pipeline": "memory",
     "features": ["malfind.ninjections", "malfind.commitCharge",
                  "malfind.uniqueInjections", "malfind.protection"]},
    {"tag": "Process Hollowing", "id": "T1055.012", ...,
     "features": ["ldrmodules.not_in_load"], "requires": ["malfind.ninjections"]},
    ...
]
```

`TAGS` is a plain Python list of dictionaries — a **human-authored**
interpretation layer, CLAUDE.md is explicit, "no model, no inference."
Every entry names: which indicator category it represents, its real MITRE
ATT&CK technique ID and name, a confidence level (`HIGH`, `MODERATE`, or
`LOW`), which pipeline it applies to, and which feature name(s) (or, for
disk, which hashed feature *group* prefixes) would trigger it. Notice
`"Process Hollowing"` additionally carries a `"requires"` key — this
particular technique needs **both** loader-list inconsistency *and*
injection activity to be a meaningful claim; either alone isn't the same
observation. Also notice the comment embedded directly in the real source,
sitting between two entries, explicitly recording something this table
*used to* contain and deliberately no longer does: a "Persistence -
Services" tag on raw service counts, removed specifically because a MITRE
tag asserts a technique was *observed*, and "more services than the
baseline" is evidence that software was installed, not evidence of a
technique — service/driver/process counts are handled entirely separately,
as "volumetric context" (covered below), which is structurally incapable of
ever driving severity.

```python
    {"tag": "Defense Evasion - Unsigned Binary", "id": "T1553.002", ...,
     "features": ["general_feat_7", "datadirectory_feat_8", "datadirectory_feat_9"],
     "when": lambda v: (v.get("general_feat_7", 0) == 0
                        and v.get("datadirectory_feat_8", 0) == 0)},
```

This one entry carries something none of the others do: a `"when"` key
holding an actual small function (a `lambda`) that checks the *real
values* of specific features, not just whether those features happen to
appear among a set of matched names. The comment explains exactly why:
these three particular disk features are among the small set that are
genuinely exact, per-index recoverable scalars (from `meanings.py`, above)
— `general_feat_7` is literally "does this binary carry an authenticode
signature," and `datadirectory_feat_8`/`9` are literally the certificate
table's size and address. Because their real values are actually readable
(unlike a hashed bucket), this tag can and does check that they genuinely
say "unsigned" (`== 0`, meaning zero-sized/absent) before firing — matching
purely on the feature *name* being present in a LIME explanation would be
wrong, because LIME can rank the certificate table highly in its
explanation for *either* a signed or an unsigned binary (it's simply an
important feature to the model either way), and firing this specific tag
on a signed binary would be a straightforwardly false claim.

Right below the table, three specific MITRE technique IDs are permanently
banned from this codebase, and the comment states the corrected reasoning
for each: **T1179** is deprecated/revoked in the current ATT&CK framework
entirely, so citing it dates the report to an outdated version of the
standard. **T1547.006** genuinely means "Kernel Modules and Extensions,"
but that technique is documented as covering Linux and macOS platforms —
it simply does not describe Windows kernel-callback or driver persistence
at all, despite superficially sounding like it might. **T1574** is "Hijack
Execution Flow" — a real technique, but one about loading the *wrong* DLL
(search-order hijacking, side-loading), which is a genuinely different
behaviour from DLL *concealment* (a module present but hidden from the
loader's own lists), which is what `ldrmodules` actually measures. Getting
technique attribution wrong in either direction — over-claiming or
mis-naming — is exactly the kind of error that would undermine an
analyst's trust in every other tag this table produces, so these three
corrections are treated as permanent, tested constraints (file 14 covers
the specific test enforcing this).

### `match()` — applying the table to a real result

```python
def match(features, pipeline, values=None):
    present = set(features)
    values = values or {}
    out = []
    for entry in TAGS:
        if entry["pipeline"] != pipeline:
            continue

        hits = [f for f in entry.get("features", []) if f in present]
        for group in entry.get("groups", []):
            hits += [f for f in present if f.rsplit("_", 1)[0] == group]
        if not hits:
            continue
        if any(r not in present for r in entry.get("requires", [])):
            continue
        predicate = entry.get("when")
        if predicate is not None and not (values and predicate(values)):
            continue

        out.append({"tag": entry["tag"], "mitre_id": entry["id"],
                    "mitre_name": entry["name"], "confidence": entry["confidence"],
                    "features": sorted(set(hits)), "url": url(entry["id"])})

    return out
```

`match(features, pipeline, values=None)` is called from `jobs.py` (file 07)
with the specific set of feature names actually present in a given result
(or, for the memory pipeline's severity computation, only the *elevated*
subset — file 07 already covered exactly why that distinction exists).
`present = set(features)` converts the input into a set for fast
membership checks. For every entry that applies to the right pipeline: does
it name any specific feature that's actually present (`hits`), or, for
disk's hashed groups, does any present feature's group prefix match one of
the entry's named groups (`f.rsplit("_", 1)[0] == group`)? If neither
produces any hits at all, this entry doesn't apply and the loop moves on.
If it does have hits, but also lists `"requires"` and one of those required
features *isn't* present, it's rejected too (Process Hollowing needing both
signals, above). And if it carries a `"when"` predicate, that predicate
only gets consulted (and must return true) when real `values` were
actually supplied — the comment is explicit that a value-aware tag stays
silent rather than asserting something it has no way to check when no
values were given at all (this matters for callers, like
`scripts/predict_vector.py`'s memory path, that intentionally don't have
per-feature values available).

The final, crucial design decision — stated directly in the comment and
enforced by a dedicated test (file 14) — is that this function returns
**every single matching tag**, not just the single "best" one. The real
reasoning: a genuine artifact commonly shows several behaviours
simultaneously (injection plus hidden modules plus service persistence is
described as "an ordinary combination, not an edge case"), and collapsing
to one "best" tag would both discard real findings *and* break the
severity function below, which depends on counting how many distinct
high-risk categories matched.

## `app/forensics/severity.py` — two functions, two different philosophies

```python
HIGH_RISK = {"Process Injection", "Process Hollowing", "Rootkit / Hidden Artifacts",
             "Hidden Modules / DLL Concealment", "Persistence - Services",
             "Kernel Callbacks / Driver Persistence"}

def _bucket(score):
    if score >= 6:
        return CRITICAL
    if score >= 4:
        return HIGH
    if score >= 2:
        return MEDIUM
    return LOW
```

`HIGH_RISK` names which of the tag categories count as genuinely hostile
capabilities (as opposed to a lower-confidence or purely observational
tag). `_bucket(score)` is a small, shared, purely mechanical function that
turns a numeric score into one of the four named severity levels — both
functions below compute their own score by different logic, then hand it
to (a variant of) this same bucketing idea.

### `for_disk()` — verdict-led, because the disk model is trustworthy

```python
def for_disk(probability, matched, threshold):
    risky = len({m["mitre_id"] for m in matched if m["tag"] in HIGH_RISK})

    score = 0
    if probability >= threshold:
        score += 2
    if probability >= 0.9:
        score += 2
    elif probability >= 0.75:
        score += 1
    score += min(risky, 3)

    sev = _bucket(score)
    note = (f"model confidence {probability:.2f} against threshold {threshold:.2f}, "
            f"{risky} high-risk indicator categor{'y' if risky == 1 else 'ies'} matched")
    return sev, note
```

The comment directly explains why disk severity is built this way: "the
disk model is validated against the official EMBER baseline and its
probability is trustworthy, so it carries the score." The score is built
additively and transparently — crossing the operating threshold at all
contributes 2 points, being very confident (≥0.9) contributes 2 more (or a
smaller bump at ≥0.75), and each distinct matched high-risk *technique*
(`{m["mitre_id"] for m in matched if ...}` — a set comprehension, so
matching the same technique via two different tags only counts once)
contributes up to 3 more points. Every number here is a small, fixed,
visible constant — nothing about this computation is hidden inside a model;
an analyst reading the returned `note` string sees exactly the inputs that
produced the final bucket, matching CLAUDE.md's explicit requirement that
severity be "deterministic, and visible in the report... not a black box
on top of a black box."

### `for_memory()` — evidence-led, on a genuinely different scale

```python
def for_memory(observed, matched, probability=None, model_reliable=False,
               baselined=True):
    risky = len({m["mitre_id"] for m in matched if m["tag"] in HIGH_RISK})
    elevated = sum(1 for v in observed.values() if v)

    level = 0 if risky == 0 else 1 if risky == 1 else 2 if risky <= 3 else 3
    basis = ("elevated against the clean-system baseline" if baselined else
             "present, with no clean-system baseline available for comparison")
    reason = [f"{risky} high-risk indicator categor{'y' if risky == 1 else 'ies'} "
              f"{basis}"]
```

The docstring right above this function in the real source states its
whole philosophy plainly: "categories drive the bucket directly — three
hidden modules plus injected memory is High because of what was found, not
because a number crossed a threshold." Notice this function takes
`observed` and `matched` as its **first two** arguments, and `probability`
only third, defaulting to `None` — a structural reflection, in the
function's own signature, of hard rule 22: the model's score is not the
primary input here at all.

`level` is computed directly from `risky` (how many distinct high-risk
*techniques* matched) using a small, explicit mapping (0 categories → Low,
exactly 1 → Medium, up to 3 → High, more than that → Critical, expressed
compactly as a chained conditional expression) — genuinely different
scoring logic from disk's additive point system, which is exactly why the
function-level docstring calls this "deliberately on a different scale."

```python
    if not baselined:
        level = min(level, 1)

    if elevated >= 2:
        level = min(level + 1, 3)
        reason.append(f"{elevated} indicators elevated against baseline")
    elif elevated:
        reason.append("1 indicator elevated against baseline")

    if probability is None:
        pass
    elif not model_reliable:
        reason.append("model score withheld from severity: capture is out of "
                      "distribution")
    elif probability >= 0.9 and level >= 1:
        level = max(level, min(level + 1, 2))
        reason.append(f"model confidence {probability:.2f}, in distribution")

    return LEVELS[level], "; ".join(reason)
```

Three more adjustments, each with real, specific reasoning. First, if no
baseline was loaded at all (`baselined=False`), the *entire claim* is
capped at Medium (`level = min(level, 1)`) — the comment explains why:
without a clean baseline for comparison, everything looks merely "present,"
and most Windows machines legitimately show *some* of these indicators, so
asserting anything stronger than Medium with no comparison point at all
would be an overclaim. Second, if two or more indicators are elevated
(`elevated >= 2`), the level gets bumped up by one (capped at 3, Critical)
— genuinely elevated *volume* of evidence matters, on top of which
*categories* matched. Third, and this is the concrete implementation of
"the model score is at most a tie-breaker": the model's probability is
**only** ever consulted when it's both present and considered reliable
(`model_reliable`, computed from `dominant_ood()`, file 08) — and even
then, `level = max(level, min(level + 1, 2))` can only ever *raise* the
level, and only up to a ceiling of 2 (High) on its own — it can never push
a result all the way to Critical by itself, and it can never lower a
severity the evidence already established. When the model's score genuinely
isn't reliable for this capture, the returned reason string says so
explicitly ("model score withheld from severity: capture is out of
distribution") rather than silently ignoring it with no explanation.

## `app/forensics/baseline.py` — what "elevated" actually means

```python
MARGIN = 1.2

def ceiling(feature):
    if not _data:
        return None
    mx = _data.get("max")
    if mx and feature in mx:
        base = float(mx[feature])
    else:
        ref = _data.get("features") or {}
        af = _data.get("all_features") or {}
        base = ref.get(feature, af.get(feature))
        if base is None:
            return None
        base = float(base)
    return max(base, 1.0) * MARGIN
```

This is where "elevated" gets a precise, numeric definition, and the
comment tells the real story behind why it's built this specific way. An
earlier version of this logic flagged a feature as elevated whenever it
exceeded three times its *median* value across the clean-baseline captures
— and that rule produced a genuine false positive: a perfectly clean
fresh-boot capture of the reference machine legitimately reaches
`psxview.not_in_pslist = 33` (because `psscan` still finds terminated boot
processes that haven't been cleaned up yet), and three times a typical
median was nowhere near high enough to avoid flagging that entirely normal
state as suspicious *against its own machine's baseline*.

`ceiling(feature)` instead uses the **highest value observed across all
seven clean reference captures** (`_data["max"]`, prioritised over an
older single-value fallback for backward compatibility with an older
baseline format), multiplied by a small margin (`MARGIN = 1.2`, twenty
percent) to absorb ordinary capture-to-capture noise without inventing a
statistical percentile that seven data points genuinely cannot support
with any real confidence. `max(base, 1.0)` guards against a feature whose
observed maximum happens to be `0` — multiplying zero by any margin is
still zero, which would make *any* nonzero value on a new capture read as
"elevated," an unintentionally oversensitive result for a feature that's
simply always been zero on this machine so far.

```python
def compare(observed):
    if not _data:
        return {}
    out = {}
    for feature, value in observed.items():
        cap = ceiling(feature)
        if cap is None:
            continue
        out[feature] = value > cap
    return out
```

`compare(observed)` is what `jobs.py:_memory()` (file 07) calls, feeding it
the plain-English-observed indicators from `meanings.observed()` (above).
For each one, it checks whether this capture's value genuinely exceeds
that feature's ceiling — returning a dictionary of `{feature: True/False}`,
which is exactly what feeds the second, narrower `mitre.match()` call in
`jobs.py` (the one that drives severity, as opposed to the one that labels
every finding).

```python
def phrase(feature, value):
    if not _data:
        return f"{value:g} observed; no clean-system baseline is loaded for comparison"
    hi = _observed_max(feature)
    if hi is None:
        return f"{value:g} observed; this indicator is not in the baseline"
    n = _n_captures()
    span = (f"the highest value ({hi:g}) observed across {n} clean captures of this "
            f"machine")
    if value > ceiling(feature):
        return f"{value:g} observed - exceeds {span} - substantially elevated"
    return f"{value:g} observed - within {span} - consistent with this machine"
```

`phrase(feature, value)` generates the actual sentence that ends up
attached to a finding (`jobs.py`'s `_memory()` appends this directly onto
`d["why"]` — file 07). This is the concrete, textual expression of the
docstring/note recorded at the bottom of `baseline.py` itself: injected
memory regions, loader-list mismatches, and process-enumeration
discrepancies "all occur on uninfected Windows systems," and are meaningful
only when substantially elevated against a known-clean baseline of *the
same machine*. This function is what makes that context concrete and
specific for every single finding, rather than an abstract disclaimer
mentioned once and then forgotten — every finding's own sentence names the
real comparison value it's being judged against.

### Volumetric context — configuration counts, structurally kept away from severity

```python
VOLUMETRIC = [
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
    "svcscan.shared_process_services", "svcscan.nactive",
    "pslist.nproc", "dlllist.ndlls", "handles.nhandles", "handles.nmutant",
    "modules.nmodules",
]

def volumetric_context(vec, names, behavioural_elevated):
    if not _data:
        return [], None
    ...
    if not raised:
        return [], None

    named = ", ".join(...)
    if any(behavioural_elevated.values()):
        note = (f"Configuration counts are also elevated ({named}). Read alongside the "
                "behavioural indicators above rather than as an indicator in itself.")
    else:
        note = (f"Configuration counts are elevated ({named}) with no behavioural "
                "indicators present; consistent with additional software rather than "
                "compromise. This does not contribute to severity.")
    return raised, note
```

`VOLUMETRIC` is a *separate* list of features from `meanings.BEHAVIOURAL`
— these ten describe how a machine happens to be **configured** (how many
services, drivers, processes, handles it has), not what any process
actually *did*. The comment above the list states the structural guarantee
directly: "these are reported as context and are structurally incapable of
reaching severity" — and it's worth being precise about *why* that
guarantee actually holds, not just asserting it. It holds because
`severity.for_memory()` only ever receives `elevated`/`matched` data built
from `meanings.BEHAVIOURAL` features (via `mitre.match()`), and — as noted
in the comment — **no MITRE tag in the whole `TAGS` table maps to any
volumetric feature at all** (that's exactly the "Persistence - Services"
tag that was deliberately removed, discussed above). So even if every
single volumetric feature were sky-high, there is no code path by which
that fact could ever reach the severity function's inputs — the separation
isn't just a convention being followed carefully, it's architecturally
impossible to violate by accident, which file 14 covers being tested
directly.

`volumetric_context()`'s wording deliberately changes based on whether any
*behavioural* indicator is also elevated at the same time (`if any
(behavioural_elevated.values())`) — when nothing behavioural is elevated at
all, the note goes out of its way to state the mundane, most likely
explanation plainly ("consistent with additional software rather than
compromise"), rather than leaving a bare list of elevated numbers for an
analyst to draw their own, possibly alarmist, conclusion from.

## Check your understanding

**Q1. Why does `explain.py:_top()` use `explanation.as_map()` and never
`explanation.as_list()`, even though `as_list()` produces more
human-readable output on its own?**

A: Because `as_list()` returns discretised condition strings (like
`"malfind.ninjections > 5.00"`), not bare feature names, and this
project's meaning-lookup table (`meanings.describe()`) is keyed on exact
feature names. Looking a condition string up in that table would never
match anything, and the failure would be completely silent — producing an
empty findings list indistinguishable from "the model genuinely found
nothing to explain." `as_map()` returns plain `(feature_index, weight)`
pairs, which resolve correctly and unambiguously against the project's own
JSON-derived feature list.

**Q2. What real problem does the "Defense Evasion - Unsigned Binary" tag's
`"when"` predicate solve, that simply listing its trigger features in
`"features"` alone would not?**

A: LIME can rank the certificate-table features highly in its explanation
for a file regardless of whether that file is actually signed or unsigned
— it's simply an important feature to the model either way. If the tag
fired purely because those features were *present* in a LIME explanation
(without checking their real values), it could falsely claim a signed
binary was unsigned. The `"when"` predicate checks the genuine, exact
values of those specific (non-hashed) features before allowing the tag to
fire, so it only ever claims "unsigned" when the data actually says so.

**Q3. `mitre.match()` deliberately returns every matching tag rather than
just the single "best" one. What real functionality would break if it only
returned one?**

A: The severity functions (both `for_disk()` and `for_memory()`) work by
counting how many *distinct high-risk categories* matched — collapsing to
a single tag would make that count always be at most 1, breaking severity
scoring's ability to distinguish, say, one matched technique from four. It
would also simply discard real findings: a genuine artifact commonly shows
several behaviours simultaneously (injection plus hidden modules plus
service persistence, for instance), and reporting only one would hide the
others from the analyst entirely.

**Q4. Why does `baseline.ceiling()` use the *maximum* value observed
across the seven clean captures (times a small margin), rather than, say,
three times the *median* value, which an earlier version of this logic
actually used?**

A: Because the median-times-a-constant approach produced a real false
positive: a perfectly clean fresh-boot capture of the reference machine
legitimately reaches a much higher `psxview.not_in_pslist` value than a
typical capture (because `psscan` still finds terminated boot processes
during that window), and three times the *typical* value wasn't high
enough to avoid flagging that entirely normal state as elevated against
its own machine's own baseline. The observed maximum across all seven
clean states, with a modest margin for ordinary noise, is the real ceiling
that a clean capture of this exact machine has actually reached — which is
what "elevated" should honestly mean here.

**Q5. Why is it architecturally impossible (not just a coding convention)
for the ten "volumetric" features (service counts, process counts, etc.)
to ever affect a memory job's severity score?**

A: `severity.for_memory()` never receives volumetric data directly at all
— it only receives `elevated`/`matched` values built entirely from
`meanings.BEHAVIOURAL` features, via `mitre.match()`. And critically, the
`TAGS` table in `mitre.py` contains no entry at all that maps any
volumetric feature name to any MITRE tag (the one entry that once did,
"Persistence - Services," was deliberately removed). Since there is no code
path connecting a volumetric feature's value to anything the severity
function reads, no matter how elevated that value is, there is structurally
no way for it to influence severity — the separation isn't enforced by
convention or discipline alone, it's a property of what data actually flows
where.
