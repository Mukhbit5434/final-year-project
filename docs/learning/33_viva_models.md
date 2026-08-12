# 33 — Viva Deep Dive: The Models — Why These, How They Decide

Files 01 and 08 already introduce LightGBM and XGBoost as libraries and
walk through the inference code that calls them. This file goes one level
deeper on the questions a viva is actually likely to ask: why these two
model *types* specifically, why each pipeline ended up shipping the
library it did, and — the thing no code file actually shows — what's
mechanically happening inside a tree-based model when it turns a feature
vector into a probability.

## A brief refresher: what LightGBM and XGBoost actually are

Both are **gradient-boosted decision tree** libraries. A single decision
tree is a small flowchart: look at one feature, ask a yes/no question about
it ("is `svcscan.nservices` above 310?"), go left or right, repeat, until
you land on a leaf that holds a number. "Gradient boosting" builds **many**
such trees, one after another, where each new tree is trained specifically
to correct the mistakes the trees before it were still making — not many
independent trees voting (that's a *different* technique, Random Forest),
but a sequence where each tree's whole job is "fix what's still wrong."
LightGBM and XGBoost are two separate, independently-built implementations
of that same general idea, from two different teams, with different
internal optimizations and — as file 04 covers — different Python APIs and
different conventions for storing feature names inside the saved model
file.

## Why gradient-boosted trees, and not something else

This project's own records are honest about the scope of this question:
there is no documented formal bake-off in this codebase against neural
networks, support vector machines, or logistic regression — `CLAUDE.md`,
`BUILD_PLAN.md`, and the FYP report draft all describe a comparison
**between LightGBM and XGBoost specifically**, not a wider survey. So the
honest answer to "why not try a neural network" is: that comparison isn't
recorded as having been run, and this guide won't invent one that didn't
happen.

What *is* a genuinely well-grounded reason, and worth stating plainly in a
viva: gradient-boosted trees are a well-established, standard choice for
exactly this **shape** of data — a fixed-length vector of real-valued
numeric measurements (55 memory counts, or 150 disk numbers), with no
inherent spatial structure (unlike an image, where nearby pixels are
related) and no sequential structure (unlike text or a time series). Tree
models split directly on raw feature values, need no feature scaling (hard
rule 13 — this project applies none, anywhere), handle very different
feature scales natively (a `handles.nmutant` count in the hundreds sitting
next to a `malfind.protection` sum in the thousands is not a problem for a
tree, but would be for many other model families without normalization),
and tend to do very well on tabular data specifically. It's not a
coincidence that EMBER's own official published baseline model — the
benchmark this project's disk model is directly compared against in
`CLAUDE.md` §2 — is also LightGBM. This is the field's own standard
practice for this kind of security-relevant tabular data, not an
idiosyncratic choice unique to this project.

## Why compare LightGBM against XGBoost specifically — and how the pipelines actually decided

Both pipelines' training pinned an **identical, pre-committed decision
rule**, read directly from both metadata files:

> Train LightGBM, XGBoost, and a simple ensemble of the two. Whichever
> single model scores higher validation ROC-AUC becomes the "best single
> model." Only ship the ensemble instead if it beats that best single model
> by **at least 0.005 AUC** — otherwise ship the better single model, since
> an ensemble adds real complexity (two models to load, two libraries to
> keep working) that isn't worth carrying for a marginal or negative gain.

The same rule, applied identically to both pipelines, produced two
different outcomes — and the real numbers explain exactly why:

**Memory — a genuine near-tie.** Read directly from `models/memory/metadata.json`:

| Model | Validation ROC-AUC |
|---|---:|
| LightGBM | 0.999999010003334 |
| **XGBoost** | **0.999999650589412** |
| Ensemble | 0.999999592354314 |

XGBoost edges out LightGBM by about **0.00000064** of AUC — a difference so
small it's well within ordinary run-to-run noise, genuinely a coin-flip in
practical terms, but XGBoost was the number that came out on top, so
XGBoost became the "best single model." The ensemble scored *below* even
that (a `gain` of `-5.8e-8`, i.e. slightly negative), so the pre-committed
rule shipped the single best model: **XGBoost**.

**Disk — LightGBM won clearly, on every metric measured.** Read directly
from `models/disk/metadata.json`:

| Model | Validation ROC-AUC | FPR | FNR |
|---|---:|---:|---:|
| **LightGBM** | **0.99765** | **0.01871** | **0.02302** |
| XGBoost | 0.99684 | 0.02378 | 0.02813 |
| Ensemble | 0.99740 | 0.02038 | 0.02473 |

LightGBM beats XGBoost by a real, measurable margin (about 0.0008 AUC — over
a thousand times larger than memory's margin), and beats it on false
positive rate *and* false negative rate too, not just the headline AUC
number. The ensemble again scored below the best single model (`gain`
`-0.00025`), so the same rule shipped the single best model again — this
time, **LightGBM**.

**The two pipelines shipping two different libraries is not a mistake and
not something to normalize away** — it's the direct, mechanical output of
running the identical decision procedure twice against two different
datasets, and getting a genuine near-tie in one case and a clear winner in
the other. `app/inference/`'s decision to write two entirely separate
loader/predict modules, rather than one shared abstraction, is the direct
consequence: XGBoost and LightGBM disagree on how to load a model, how to
run a prediction, and what a feature name even is internally, and forcing
a shared abstraction over that difference is exactly the kind of thing
that creates a silent mismatch bug (file 08, hard rule 4).

## How a trained tree model actually decides, mechanically

A viva question worth being able to answer without hand-waving: given a
finished, already-trained model, what actually happens, step by step, when
a real feature vector goes in and a probability comes out?

Each of the (up to 173, for the memory model — file 08 covers why that
exact number matters) individual trees is walked, independently, from its
root:

```
                    svcscan.nservices > 310?
                    /                      \
                  no                       yes
                  /                          \
     handles.nmutant > 400?          svcscan.kernel_drivers > 250?
       /            \                      /            \
     no             yes                  no             yes
      |               |                    |               |
   leaf: -0.02     leaf: +0.31         leaf: +0.05      leaf: +0.44
```

(This tree is a made-up, simplified illustration for teaching purposes —
not a real branch pulled from the shipped model file, which has far more
splits and far more trees than any one diagram could usefully show.) A
concrete walk-through, with made-up feature values: suppose a captured
vector has `svcscan.nservices = 340`, `handles.nmutant = 250`, and
`svcscan.kernel_drivers = 260`. Starting at the root: is `nservices > 310`?
340 is, so go **right**. Is `kernel_drivers > 250`? 260 is, so go
**right** again, landing on the leaf `+0.44`. That single number is this
one tree's own small contribution to the final answer — not a probability
by itself, just a signed adjustment.

Every one of the model's trees gets walked the same way, each contributing
its own small leaf value, and — this is the "boosting" part — **all of
those contributions get summed together** into one raw score. That raw
sum then gets passed through a **sigmoid function**
(`1 / (1 + e^-x)`), which squashes any real number into the 0-to-1 range —
this is the actual final step that turns "a sum of small tree
contributions" into something that looks and behaves like a probability.
`booster.inplace_predict(...)` (memory) and `booster.predict(...)` (disk)
are doing exactly this — walking every tree, summing every leaf, applying
the sigmoid — and handing back the single resulting number.

## What the resulting number actually represents

It's tempting to read the output, say `0.94`, as "94% chance this is
malware" in a strict statistical sense. That's not quite right, and it's
worth being precise about the distinction in a viva. What comes out of a
gradient-boosted tree model is a **calibrated confidence score** — a
number trained so that, roughly, among all the training examples the model
gave a score near 0.94, about 94% of them really were malicious. It's
*not* a literal, first-principles probability computed from any underlying
statistical model of "malware in the world" — it's an empirical score
fitted to separate the two classes as cleanly as possible on the training
data, and its numerical value is meaningful only in relation to the
**threshold** it's compared against (file 34 covers exactly where that
threshold number comes from, and why it's never 0.5). This is precisely
why `CLAUDE.md` §2 insists the memory model's `1.0000` test AUC not be
presented as a mark of exceptional quality on its own — a very high score
on data drawn from the same narrow distribution the model was trained on
says less about real-world malware detection than it appears to, which is
exactly the SMOTE-saturation story `CLAUDE.md` traces in depth.

## Check your understanding

**Q1. Both pipelines used the identical rule — "ship the ensemble only if
it beats the best single model by at least 0.005 AUC" — and both ended up
shipping a single model, not the ensemble. Why?**

A: Because in both cases the ensemble scored *below* the better single
model on validation AUC (memory: ensemble 0.999999592 vs XGBoost's
0.999999651; disk: ensemble 0.997397 vs LightGBM's 0.997650) — a negative
gain in both cases, nowhere close to clearing the required +0.005 margin.
The rule was designed so an ensemble only ships when it earns its added
complexity with a real, meaningful improvement; here it didn't, in either
pipeline, so the simpler, better-performing single model shipped both
times.

**Q2. Memory shipped XGBoost by a margin of about 0.00000064 AUC. Is that
a meaningful, reliable difference, or something else?**

A: Honestly, it's not a meaningful difference in any practical sense — it's
close enough to be ordinary training noise, genuinely a near-tie. XGBoost
happened to score marginally higher on this particular validation run, so
it became the "best single model" under the pre-committed rule, but a
different random seed or a re-run could plausibly have tipped the other
way. This is worth stating exactly this honestly in a viva rather than
implying XGBoost demonstrably outperforms LightGBM on memory data — the
real, measured margin doesn't support that stronger claim.

**Q3. Walk through, mechanically, what happens between "a 55-number vector
goes in" and "a probability comes out" for the memory model.**

A: Every one of the model's trees (up to 173, per the pinned
`iteration_range=(0, 173)`) is walked independently from its root: at each
node, look up the one specific feature that node splits on, compare it
against that node's learned threshold, and go left or right accordingly,
until a leaf is reached. Each tree's leaf holds one small learned number.
Every tree's leaf value gets summed together into one raw score, and that
raw sum is passed through a sigmoid function, squashing it into the 0-to-1
range — which is the number `predict()` actually returns.

**Q4. Is the number a trained model outputs literally "the probability
this file is malware," in a strict statistical sense?**

A: Not quite, and the distinction matters. It's a **calibrated confidence
score** — trained so that, empirically, among training examples that
scored near some value like 0.94, roughly 94% really were malicious. It's
not derived from any first-principles statistical model of malware
prevalence in the world; it's an empirical fit to the training data, and
its meaning depends entirely on the specific threshold it's compared
against. This is also exactly why a very high test-set score (like
memory's 1.0000 AUC) has to be read in the context of what the training
data actually looked like, rather than taken at face value as proof of
real-world detection quality.

**Q5. This project's own records don't show a documented comparison
against neural networks or SVMs. Is it fair to say gradient-boosted trees
were simply the "correct" choice, then?**

A: The honest answer avoids over-claiming in either direction. It's fair
to say gradient-boosted trees are a well-established, standard, defensible
choice for this exact shape of problem — fixed-length numeric tabular
data, no spatial or sequential structure, features on very different
scales with no normalization applied (matching how EMBER's own official
baseline model is also LightGBM). It would **not** be fair to claim this
project ran a formal comparison against other model families and
gradient-boosted trees won — that comparison isn't recorded anywhere in
this project's own history, and claiming otherwise in a viva would be
inventing a justification the project doesn't actually have.
