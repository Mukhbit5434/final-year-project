# 34 — Viva Deep Dive: Thresholds

File 08 already covers the *code* around thresholds in real depth —
`load()`'s "refuse to boot on exactly 0.5" trip-wire, `_check_reference()`,
the whole `ood()`/`dominant_ood()` machinery. This file's job is narrower
and more exam-shaped: where did these two specific numbers actually come
from, why are they so different from each other, and — a distinction worth
being able to draw cleanly under questioning — how does the threshold
relate to, and differ from, the memory pipeline's out-of-distribution gate.

## A brief refresher: what a threshold is

A trained model doesn't output "malicious" or "benign" directly — it
outputs a single number between 0 and 1 (file 33 covers exactly how that
number gets computed, tree by tree). The **threshold** is the cutoff point:
at or above it, call the result malicious; below it, call it benign. The
simplest possible choice is `0.5` — the exact midpoint — but nothing
requires that to be the *right* cutoff for a specific trained model on a
specific dataset, and this project's own two thresholds prove the point:
neither one is 0.5.

## The two real numbers, read directly from the committed files

| Pipeline | Threshold | Source |
|---|---|---|
| Memory | `0.2336726188659668` | `models/memory/metadata.json`, top-level `"threshold"` key |
| Disk | `0.5010602922493019` | `models/disk/metadata.json`, top-level `"threshold"` key |

Both numbers carry far more decimal precision than anyone would type by
hand — a strong, direct signal that each one is the literal output of some
numerical optimization procedure run against real validation data, not a
value someone picked and rounded.

## Where these exact numbers came from — verified honestly

Here's a place where precision matters more than confidence: **this
project's own committed files do not record which specific statistical
procedure was used to arrive at these exact numbers.** There's no training
notebook, no training script, and no comment in either `metadata.json`
anywhere in this repository that names the selection method — `CLAUDE.md`
and `STATUS.md` both treat the threshold values as settled, validated
facts to be read and enforced, not re-derived, which matches hard rule 7
(never retrain, never re-derive what training already settled). If a viva
question demands the *exact* named procedure (F1-maximization, Youden's J
statistic, or some other criterion), the honest answer is that this
specific detail isn't part of the committed record this guide could verify
against, and shouldn't be asserted with more confidence than that.

What **is** directly verifiable from the structure of `metadata.json`
itself, for both pipelines: every candidate model's own `validation_metrics`
block (LightGBM, XGBoost, and the ensemble) reports `"threshold_used": 0.5`
— a flat, common cutoff used purely to compare the three candidates against
each other on equal footing. The real operating threshold that actually
ships — `0.2336726188659668` for memory, `0.5010602922493019` for disk —
only appears once, separately, in each file's own top-level `"threshold"`
key and in `test_metrics.threshold_used`. That structure is itself good
evidence of the general shape of what happened: the three models were
first compared fairly at a flat 0.5, a winner was picked (file 33), and
*then*, separately, a genuinely tuned operating threshold was chosen for
whichever model actually shipped — the kind of two-stage process where a
threshold-optimization step (of some kind, over predicted probabilities
against known labels on a validation set) is exactly what would produce a
number this specific.

## Why the two thresholds ended up so different from each other

Disk's threshold, `0.5010602922493019`, sits almost exactly on the
naive default. Memory's, `0.2336726188659668`, sits well below it — the
model calls something malicious at less than a quarter of the way up its
own probability scale. What does that gap actually say about the two
underlying models?

The most defensible reading connects directly to a fact this guide's
companion files already establish independently, not a new, separately
documented explanation: `CLAUDE.md` §2 traces the memory model's dataset
(CIC-MalMem-2022) to a benign half that's substantially **SMOTE-synthesized**
— tightly clustered, interpolated points sitting close to their real seed
examples, rather than as broadly spread as genuinely independent captures
would be. A model trained on two classes that separate this cleanly (file
33's near-1.0 validation AUC numbers are the direct evidence) can end up
with a probability distribution shaped very differently from the "smooth
bell curve on each side of 0.5" that a threshold of exactly 0.5 implicitly
assumes — whatever criterion picked the real operating point evidently
found that a lower cutoff better balanced this particular model's
error rates on its particular validation distribution. Disk's threshold
landing almost exactly at 0.5, by contrast, is consistent with a model
trained on a much larger, more conventionally-shaped real-world dataset
(EMBER 2018's 600,000+ rows) producing probabilities that are already
close to symmetric around the naive midpoint. This is a reasoned
interpretation grounded in facts independently verified elsewhere in this
project (the SMOTE finding, the dataset sizes) — not a separately
documented explanation of the threshold gap itself, and it should be
presented that way rather than as settled fact.

## The hard rule, and exactly where it's enforced in real code

`CLAUDE.md` hard rule 1: **never hardcode `0.5` anywhere in this
application; always read the threshold from `metadata.json`.** This isn't
just a style preference — it's enforced as an actual boot-time check, in
both `app/inference/memory.py` and `app/inference/disk.py`:

```python
_threshold = meta["threshold"]

if _threshold == 0.5:
    raise ModelError("memory threshold read as 0.5 - metadata.json is wrong")
```

Read literally, this looks almost backwards — the code refuses to load if
the threshold happens to equal exactly `0.5`. The reasoning: `0.5` is
precisely the value a threshold variable would silently take on if
something went wrong reading it from the metadata file (a missing key, a
typo, a bug that left it at some naive Python default) and nothing else in
the code caught the failure. Since neither of this project's real
operating thresholds is ever exactly `0.5` — one is `0.2336726188659668`,
the other is `0.5010602922493019`, close to but never equal to `0.5` —
catching that one specific value is a cheap, reliable trip-wire for "the
real threshold was never actually loaded," rather than a philosophical
objection to the number `0.5` itself.

**What would actually go wrong if someone hardcoded `p >= 0.5` instead of
`p >= threshold()` somewhere in the app?** For disk, the practical damage
would be small — `0.5` and `0.5010602922493019` are close enough that only
predictions landing in that narrow sliver would flip. For memory, the
damage would be severe and systematic: every prediction with a probability
between `0.2336726188659668` and `0.5` — a wide band — would silently flip
from "malicious" to "benign," with no error, no warning, and a
confident-looking (wrong) verdict on every single one. This is precisely
the "feature-naming trap" pattern (file 08) applied to thresholds instead
of feature order: a plausible-looking number, quietly wrong, forever.

## Two separate mechanisms, easy to conflate, that must not be confused

This is the single point a viva panel is most likely to probe if they
sense any fuzziness: **the threshold and the memory pipeline's
out-of-distribution (OOD) gate are two completely independent
mechanisms, answering two different questions, computed by two different
functions.**

- **The threshold answers**: *given that the model's probability is
  trustworthy, is this specific number high enough to call the result
  malicious?* This is `predict(vec)` in `app/inference/memory.py` —
  `p >= _threshold`, nothing more.
- **The OOD gate answers a completely different, prior question**: *is
  this model's probability trustworthy at all, for this specific input?*
  This is `dominant_ood(vec)` — a separate function that checks whether the
  four features the model leans on hardest (`svcscan.nservices`,
  `handles.nmutant`, `svcscan.shared_process_services`,
  `svcscan.kernel_drivers` — file 31 covers exactly why these four) fall
  outside the range the model was ever trained on.

Concretely, in code, these run as genuinely separate steps: `predict(vec)`
computes a probability and compares it to the threshold, entirely
mechanically, regardless of whether the input looks anything like the
training data. `dominant_ood(vec)` runs completely independently and
returns which of the four dominant features (if any) are out of range.
`jobs.py`'s `_memory()` then combines the *result* of the OOD check — not
the probability, not the threshold comparison — into a `reliable = not
dominant` flag, and it's *that* flag which decides whether the model's
probability is allowed to drive severity at all, or gets demoted to "shown
for reference only" (hard rule 22, `CLAUDE.md` §9.6).

A concrete illustration: a captured memory dump could score `p = 0.93`
(comfortably above the `0.2336726188659668` threshold, so the threshold
comparison alone says "malicious") while *also* having all four dominant
features out of range — in which case `reliable` is `False`, and the
report is required to say, plainly, that the model's own verdict is
withheld from severity because the capture is out of distribution, even
though the raw probability crossed the threshold easily. This exact
scenario isn't hypothetical — it's what actually happened on this
project's own real malicious capture (`sample/memory/malicious_1.raw`,
`STATUS.md`): probability `0.4740`, comfortably above threshold, **and**
all four dominant features out of range, **and** severity was still
correctly driven entirely by direct Volatility evidence (elevated
`malfind` and `psxview` indicators) rather than by that probability.

**Disk has no equivalent second gate.** There's no `ood()`/`dominant_ood()`
pair in `app/inference/disk.py` at all — disk severity is verdict-led,
straightforwardly comparing the model's probability against its threshold,
because the disk model doesn't carry the same single-VM training-distribution
problem the memory model does (`CLAUDE.md` §9.6: "Disk severity is
unaffected and stays verdict-led — that pipeline has no equivalent
problem"). The OOD gate is a memory-pipeline-specific answer to a
memory-pipeline-specific dataset problem, not a general feature of "how
this project handles model confidence."

## Check your understanding

**Q1. Both threshold values carry sixteen-plus digits of decimal
precision. What does that level of precision suggest about how they were
chosen, and what can this guide honestly confirm about the exact method?**

A: That level of precision is a strong signal that each threshold is the
direct, unrounded output of some numerical optimization run against real
validation data — not a value anyone typed by hand. What this guide can
honestly confirm, directly from the structure of `metadata.json`: every
candidate model's own comparison metrics use a flat `0.5` cutoff (for
comparing the three candidates fairly), while the real operating threshold
appears separately, once, as the model's own tuned value. The exact named
statistical criterion used to tune it isn't recorded anywhere in this
project's committed files, so this guide states that gap honestly rather
than asserting a specific method with more confidence than the evidence
supports.

**Q2. What specific, concrete harm would result from hardcoding
`p >= 0.5` somewhere in the memory pipeline instead of reading the real
threshold?**

A: Severe, systematic, and silent. Every memory capture whose real
probability lands between `0.2336726188659668` and `0.5` — a wide band —
would flip from a correct "malicious" verdict to an incorrect "benign"
one, with no error or warning anywhere, because `0.5` is a syntactically
valid number a comparison would happily run against. This is exactly why
`load()` in `app/inference/memory.py` refuses to boot at all if the
threshold it read happens to equal exactly `0.5` — it's a cheap trip-wire
against precisely this failure mode.

**Q3. A memory capture scores a probability comfortably above the
threshold, but the four dominant features are all out of range. Is the
final verdict "malicious," "benign," or something else — and why?**

A: Neither, cleanly — this is exactly the scenario the OOD gate exists to
handle, and it's not hypothetical: it's what happened on this project's
own real malicious capture. The threshold comparison by itself would say
"malicious" (`0.4740 >= 0.2336726188659668`), but `dominant_ood()` finding
all four dominant features out of range sets `reliable = False`, which
means the model's probability is withheld from driving severity — it's
still shown in the report, but only for reference. Severity in that case
is instead driven entirely by directly-observed Volatility evidence
(elevated `malfind` and `psxview` indicators), which is what actually
produced the correct `Critical` verdict on that real capture.

**Q4. Why doesn't the disk pipeline have an equivalent out-of-distribution
gate?**

A: Because the OOD gate is a targeted answer to a problem specific to the
memory model: it was trained on one narrow VM configuration
(CIC-MalMem-2022), so a real-world capture routinely lands outside the
range it ever saw during training, and its four most-relied-on features
are largely machine-configuration counts rather than behavioural
measurements (file 31, file 33). The disk model doesn't share that
problem — EMBER 2018 is a large, diverse, real-world corpus — so disk
severity stays straightforwardly verdict-led: compare the probability to
the threshold, no second gate needed.

**Q5. Someone claims "the OOD gate is really just a second, stricter
threshold." Is that framing accurate?**

A: No, and this is worth correcting precisely. A threshold is a cutoff
applied to the model's own output (the probability) to decide malicious
vs. benign. The OOD gate never looks at the probability at all — it
compares the *raw input feature values* against the range the model was
trained on, entirely independently of whatever probability the model
happens to produce. They answer genuinely different questions ("is this
score high enough" vs. "is this score trustworthy in the first place") and
are computed by entirely separate functions (`predict()` vs.
`dominant_ood()`) that don't call into each other. Collapsing them into
"one gate" would misdescribe both the code and the reasoning behind it.
