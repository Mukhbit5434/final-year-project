# 36 — Viva Deep Dive: Rapid-Fire Q&A

Thirty questions, in three difficulty tiers, covering the whole project.
Every answer points at a specific number, a specific test, or a specific
piece of code rather than a vague claim — the same standard files 30–35
hold themselves to. If you only have time for one file before a viva, make
it this one; it's built to stand on its own.

---

## Tier 1 — Basic understanding

**Q1. What does this project actually do, in one sentence?**

A: An analyst uploads a raw disk image or a raw memory dump into a web
application, which extracts a fixed set of numeric measurements from it,
runs those measurements through an already-trained machine-learning model,
and produces a human-readable report explaining what was found, how
confident the system is, and why — without the analyst ever having to run
Volatility, The Sleuth Tool Kit, or any forensic tool by hand.

**Q2. Why two completely separate pipelines instead of one?**

A: Because a disk image and a memory dump are structurally nothing alike —
different file formats, different extraction tools (`pytsk3`/EMBER for
disk, Volatility 3 for memory), different feature schemas (150 numbers vs.
55), different trained models (LightGBM vs. XGBoost), and different
thresholds. `CLAUDE.md` states this as a deliberate scoping decision: never
build a "generic" abstraction that tries to serve both, because the two
domains genuinely don't share enough in common for that abstraction to be
honest.

**Q3. What is a "feature," in plain terms?**

A: A single numeric measurement of some property of the thing being
analysed — how many processes are running, how often a particular byte
value appears in a file, whether a certificate table is empty. A "feature
vector" is just a fixed-length, fixed-order list of these numbers — 55 of
them for a memory dump, 150 for a disk file — that together describe the
artifact well enough for a trained model to make a decision from.

**Q4. What is a "model," in plain terms, and what does this project's
model actually output?**

A: A mathematical object, already fitted to a large collection of
labelled real examples, that takes a feature vector and produces a single
number between 0 and 1 — a confidence score that the input is malicious.
It doesn't output a plain "yes" or "no" directly; a separate threshold
comparison (file 34) is what turns that number into a verdict.

**Q5. Both pipelines' models are "gradient-boosted decision trees." What
does that actually mean?**

A: Many small decision trees — each just a sequence of yes/no questions
about specific feature values — chained together so that each new tree is
trained specifically to correct the errors the trees before it were still
making. The final prediction sums every tree's small contribution and
passes that sum through a function that squashes it into a 0-to-1 range.
File 33 walks a concrete toy example of exactly this happening.

**Q6. What does LIME actually do in this system?**

A: It explains *why* a specific malicious verdict was reached, after the
fact — it's not part of training and doesn't affect the verdict itself. It
runs only when a result is already flagged malicious, perturbs the input
slightly many times, watches how the model's output changes, and reports
which specific features contributed most to that particular prediction —
turned, by a lookup table, into plain-English findings rather than shown
as raw numbers.

**Q7. What does "severity" mean here, and is it the same thing as the
model's probability?**

A: No — severity (Low/Medium/High/Critical) is a separate, deterministic
function of the matched forensic indicators (and, for disk, the model
probability too), not a repackaging of the raw probability alone. For
memory specifically, severity is driven mainly by directly-observed
Volatility evidence rather than the model's score at all (hard rule 22) —
files 33 and 34 cover exactly why.

**Q8. In plain terms, what is MITRE ATT&CK, and what does this project use
it for?**

A: A shared, industry-standard vocabulary that names specific attacker and
malware behaviours with stable IDs (like `T1055`, "Process Injection").
This project maps a small, deliberately limited set of its own measured
features to nine specific ATT&CK techniques it can actually back with
real evidence — file 35 covers every one of the nine, and why the list
stops there rather than trying to cover more of the framework.

**Q9. Why does a disk scan produce a *list* of results instead of one
verdict for the whole image?**

A: Because a disk image can contain hundreds of separate executable files,
and the whole point of this tool is triage — narrowing hundreds of files
down to the few worth a human's attention. One verdict per file, with full
path and SHA-256 (hard rule 16) attached to every flagged one, is what
actually lets an analyst go find the file afterward; a single boolean for
the whole image would be operationally useless.

**Q10. What is a "threshold," and why isn't it just 0.5 for both models?**

A: The cutoff probability above which a result is called malicious. `0.5`
is the naive default, but nothing requires it to be the *right* cutoff for
a specific trained model on its specific dataset — this project's own two
real thresholds, `0.2336726188659668` (memory) and `0.5010602922493019`
(disk), are both measurably different from `0.5`, and reading them from
each model's own `metadata.json` (never hardcoding `0.5`) is enforced as
hard rule 1. File 34 covers exactly where these numbers come from and why
they differ from each other.

---

## Tier 2 — Methodology and reasoning

**Q11. Why did the memory model's training use a group-aware split
(`StratifiedGroupKFold`, grouped by source sample) instead of a simple
random split?**

A: Because the underlying dataset (CIC-MalMem-2022) captured **10 memory
dumps per malware sample, 15 seconds apart** (per the dataset's own
published paper, ICISSP 2022 §4.2) — meaning many rows in the dataset are
near-identical siblings of each other. A random split could easily put
nine of a sample's ten near-identical dumps in the training set and the
tenth in the test set, letting the model effectively "memorize" that
specific sample rather than genuinely generalize — an inflated, misleading
test score. Grouping by source sample (so all ten dumps from one sample
land entirely in the same split) closes that leak, and `models/memory/metadata.json`
confirms this was the actual method used.

**Q12. Both pipelines used an identical, pre-committed ensemble decision
rule. What was it, and why commit to it in advance rather than just
picking whichever result looked best afterward?**

A: The rule, read directly from both metadata files: train LightGBM,
XGBoost, and a simple ensemble of the two; only ship the ensemble instead
of the better single model if it beats that single model by at least
**0.005 AUC**. Committing to a fixed rule *before* seeing the results is
what prevents cherry-picking — if the choice were made after the fact by
eyeballing which number "looks better," there'd be no principled way to
resist shipping whichever model happened to win by an arbitrarily tiny,
possibly noise-driven margin (exactly the ~0.0000006 AUC margin the memory
pipeline actually saw — file 33).

**Q13. The memory model's test-set ROC-AUC is a perfect 1.0000. Why did
this project treat that as something to investigate rather than a result
to celebrate?**

A: Because a perfect score on held-out data from the *same* narrow source
is a classic warning sign, not a trophy — and investigating it (leakage
check, then dominant-feature ablation, then a univariate sweep) is exactly
what found the real explanation: `CLAUDE.md` traces it to the dataset's
own construction, where the benign half was substantially SMOTE-balanced
(synthetically interpolated) against a mostly-real malicious half. The
model partly learned to separate *real capture from synthetic point* —
trivially easy — rather than purely benign from malicious behaviour. Q21
below goes deeper on the implications of this finding.

**Q14. Why does the memory pipeline have an out-of-distribution (OOD)
gate at all, when the disk pipeline doesn't?**

A: Because the memory model was trained on captures from **one single VM
configuration**, so a real, modern Windows dump routinely falls outside
the range of values the model ever saw during training — and tree models
don't gracefully degrade outside their training range, they just keep
returning whatever a leaf near the edge of the tree happens to say, with
no built-in signal that says "I'm extrapolating here." The disk model
(EMBER 2018, a large, diverse, real-world corpus) doesn't share this
narrow-training-distribution problem, so it has no equivalent gate. File
34 covers, in detail, why the gate and the threshold are two separate
mechanisms.

**Q15. Why does this project scope the memory pipeline to a single
controlled reference machine (Windows 10 x64) instead of trying to
generalize to any Windows machine?**

A: Two independent reasons converge on the same decision. First, the
architecture itself: `build_context()` can only reliably determine a raw
memory dump's architecture by constructing its actual memory layer, and it
rejects anything that isn't 64-bit before running any real analysis.
Second, and more fundamentally: the clean baseline severity comparison is
explicitly *per-machine by design* (`CLAUDE.md` §11.1) — comparing a
capture against another machine's baseline is stated as misuse of the
system, not a supported use case, because service counts, driver counts,
and process counts genuinely differ by machine in ways that have nothing
to do with compromise. Scoping to one controlled, well-characterised
reference machine is what makes the baseline comparison meaningful at all.

**Q16. Six of the 55 memory features can't be produced by this project's
extractor at all. Why disclose that honestly (in `extraction_gaps`)
instead of just omitting the gap from the report?**

A: Because hard rule 8 forbids fabricating a value to fill a gap — a zero
with an honest disclosure is truthful, a fabricated plausible-looking
number is not. This project measured the actual cost of the gap rather
than assuming it was harmless or catastrophic: those six features, freshly
computed for file 31, carry just 0.21% of the model's total gain — small,
but the point of disclosing it isn't "prove it doesn't matter," it's
letting an analyst reading the report know exactly which measurements are
real and which are structurally unavailable, so they can weigh the report
accordingly rather than trusting a silently incomplete picture.

**Q17. Why does inference code source feature names *only* from the JSON
feature-list files, never from the loaded model object itself — even
though the memory model happens to carry real, readable names internally?**

A: Because trusting a model's own embedded names in one pipeline while
refusing to in the other would itself be an inconsistency dangerous enough
to let a mistake slip through unnoticed. The disk model's internal names
are literally meaningless (`Column_0` through `Column_149` — it was
trained on a bare NumPy array), so there's no working alternative there at
all; applying the same one rule to both pipelines uniformly, rather than
letting memory take a shortcut disk can't, is what keeps the rule
trustworthy everywhere it's applied (hard rule 2).

**Q18. Why does disk-file vectorization run inside a separate
`ProcessPoolExecutor`, in its own worker processes, rather than directly
inside the main Flask application?**

A: Because `lief` (called deep inside EMBER's feature extractor) is native
code parsing potentially hostile, deliberately malformed input by design —
a crash there (a segfault) can take down the entire process it's running
in, not just the one file being analysed. Running it in a separate process
pool means a crash costs exactly one worker and produces a clean, specific
"vectorization failed" skip entry for that one file — never the whole
Flask application, which would otherwise mean one malformed file could
take down every other analyst's in-progress job too.

**Q19. Memory severity counts indicators only when they're *elevated*
against a clean baseline, never merely *present*. Why does that specific
distinction matter, and how was it discovered?**

A: Because it was measured to matter, not assumed: the earlier
presence-based approach scored this project's own **clean, healthy**
reference capture as **Critical** severity — every healthy Windows machine
produces some `malfind`, `ldrmodules`, and `psxview` hits (the clean
capture alone showed 16 injected regions, all in Windows Defender's own
scanning engine, and 267 module rows absent from at least one of the
three PEB loader lists) — while each individual finding in that same
report read "consistent with a healthy system." Fixing this meant running the MITRE matching function
**twice**: once over everything observed (to label findings so an analyst
sees what they map to), and once over only the subset that's elevated
against the seven-capture clean baseline (to actually drive severity).

**Q20. Why does the project keep a scrambled-column-order test
permanently in its test suite, rather than treating it as a one-off bug
check once fixed?**

A: Because a scrambled feature order is exactly the kind of bug that
produces **no error and no warning** — the model still loads, still runs,
still returns a syntactically valid probability, just a meaningless one.
That failure mode can be silently reintroduced by any future refactor that
touches how a vector gets assembled, with nothing in normal operation ever
revealing it happened. Keeping the check permanently — and measured
against 200 random permutations, rejecting all 200 on both models — is
what continues to catch that specific class of regression rather than
relying on it never happening again.

---

## Tier 3 — Deep and adversarial

**Q21. If the memory model's benign class is substantially synthetic
(SMOTE-interpolated), what does that actually imply about trusting a
"malicious" verdict from this model on a brand-new, real-world capture?**

A: It implies the raw probability should not be trusted as the primary
signal — which is exactly why this project doesn't treat it that way. The
model partly learned "real capture vs. synthetic point," which is a much
easier separation than "benign vs. malicious behaviour," so a high
probability on a real dump doesn't carry the same evidentiary weight the
1.0000 test AUC might suggest at a glance. This project's actual response
is structural, not cosmetic: the memory report is positioned as a
forensic triage engine (hard rule 22), leading with directly-observed
Volatility evidence and demoting the model's own score to a secondary,
clearly-labelled signal — precisely because the SMOTE finding shows the
score alone isn't reliable evidence of maliciousness on real data.

**Q22. Suppose someone deploys this memory pipeline against a completely
different machine — a laptop, a server, a different Windows build —
outside the one reference machine it was calibrated against. What
actually happens, and is that a supported use case?**

A: It's explicitly **not** a supported use case (`CLAUDE.md` §11.1 states
this as a binding scope decision, and `STATUS.md`'s "known limitations"
section describes exactly this trap). Concretely, what happens is worse
than an obvious failure: severity is calibrated against *this specific
machine's* clean baseline, so scoring an unrelated machine's capture
against it doesn't crash or refuse — it silently produces a plausible-
looking Low severity with every indicator reading "consistent with a
healthy system," because the reference machine simply runs more of
everything than whatever the foreign capture came from. `STATUS.md`
documents this measured directly: even a real CIC-MalMem-2022 malware row,
scored against this project's own clean baseline, reads as Low. The system
is behaving exactly as designed — cross-machine comparison is misuse — but
the trap is that the misuse fails quietly rather than loudly, which is
exactly why the scope restriction is enforced architecturally (the x64
gate) as well as stated as policy.

**Q23. Given everything documented about the memory model's dataset
issues, are this project's memory results "real," or is the whole memory
pipeline essentially demonstrating nothing?**

A: Neither extreme is accurate, and the honest position sits between them.
The *model's probability* on real data is genuinely weak evidence — that's
established, not disputed, and this project says so in its own reports
rather than hiding it. But the *Volatility measurements themselves* — 46
injected memory regions in a specific process at specific addresses, 55
processes missing from one enumeration method, a specific exit timestamp
on a specific hidden process — are direct, real observations of the dump
under analysis, entirely independent of the training distribution or the
model's score. Those observations carry standalone forensic value, and
this project's own real malicious capture (`sample/memory/malicious_1.raw`)
demonstrates the whole evidence-led pipeline working correctly end to end:
severity reached Critical, confirmed by two independent MITRE techniques,
driven entirely by real measurements — while the model's own probability
was simultaneously and correctly withheld as unreliable, because the
capture was out of distribution on the four features the model leans on
most. That's the pipeline behaving exactly as designed, not failing.

**Q24. If a malware author knew the memory model's four dominant features
(three `svcscan` counts and `handles.nmutant`, together 98.24% of total
gain), could they trivially evade detection by, say, installing extra
legitimate-looking services to manipulate those counts?**

A: This is a genuinely fair challenge, and the honest answer has two
parts. First: this project's own severity mechanism *doesn't* rely on
those four features at all — memory severity is driven by direct
behavioural evidence (`malfind`, `ldrmodules`, `psxview`), not the model's
score, specifically because those four dominant features are configuration
counts an attacker (or just a busy machine) could always move, not genuine
behavioural signal (`CLAUDE.md` §5.4a says this plainly). Second: even
granting the premise, manipulating `svcscan.nservices` or
`handles.nmutant` upward doesn't touch `malfind.ninjections` or
`psxview.not_in_pslist` at all — those measure what a process's memory
actually contains and how consistently different enumeration methods agree
about what's running, properties an attacker attempting to hide code in
memory can't simply pad away by installing unrelated services. The
model's own score being gameable this way is a real property of that one
signal, and it's precisely why this project doesn't let that signal drive
the decision that actually matters.

**Q25. Is the disk pipeline strictly more trustworthy than the memory
pipeline, given everything documented here?**

A: In the specific, narrow sense that matters — how much the *model's own
probability* can be trusted as evidence — yes, and this project says so
directly (`CLAUDE.md` §9.6 positions the disk pipeline as "the primary
detection capability," unchanged and validated against the official EMBER
baseline). The disk model was trained on real-world malware at real scale
(600,000 training rows, temporal train/test split, zero SHA-256 overlap
verified between them) and its test performance (0.9940 ROC-AUC) sits only
0.0024 below the official published EMBER baseline evaluated on the exact
same test set — a credible, externally-anchored comparison the memory
pipeline has no equivalent of. That said, "more trustworthy" isn't the
same as "the only trustworthy one" — the memory pipeline's forensic
*measurements* (not its model score) are just as real and just as usable
as evidence; the pipelines simply lead with different things for good,
specific reasons (verdict-led vs. evidence-led).

**Q26. Would this system detect a genuinely novel malware family it's
never seen anything like before?**

A: Only as well as its features generalize to genuinely new behaviour, and
that answer differs by pipeline. For memory, the strongest evidence this
project has of real, novel-to-training detection is the simulated
malicious capture — process injection and hidden processes the model
itself never saw during training, correctly flagged Critical through
directly observed indicators, entirely independent of what the model's
own probability said. That's a reasonable proxy for "would this catch
genuinely new bad behaviour," because the *detection mechanism* (elevated
`malfind`/`psxview` counts against a clean baseline) doesn't require the
new malware to resemble anything in the training set at all — it only
requires the new malware to actually inject code or hide processes, which
is a behavioural, not a family-specific, signal. For disk, the model's own
score is the primary mechanism, and gradient-boosted trees, like any
supervised model, generalize best to malware that shares statistical
structure with what they were trained on — a family using genuinely novel
packing/obfuscation or import patterns unlike anything in EMBER's training
distribution is a real, acknowledged limit this project doesn't claim to
have solved.

**Q27. If Volatility 3 changes its plugin output format in a future
version — say, `psxview` gains a fifth enumeration column — would this
project silently start producing wrong numbers?**

A: The honest answer depends on which failure mode you mean. A **format**
change (a column renamed, or the plugin's structure changing) would likely
surface as a loud, immediate failure — `run_plugin()` reads columns by
name from Volatility's own grid, so a renamed column would produce a
`KeyError`/`None` rather than a silently wrong number. A genuinely new
**column being added** (like a hypothetical fifth `psxview` source) would
be a quieter risk: nothing in the current code would automatically start
using it, since `PSXVIEW_SOURCE`'s mapping table is hand-maintained — the
gap would simply persist even though a fix became newly possible, until
someone updates the mapping. `CLAUDE.md` explicitly calls this out as a
standing instruction: "confirm these column names still hold when
volatility3 is upgraded; build the mapping from the installed source,
never from Vol2 documentation" — i.e., this project treats a Volatility
upgrade as something that must be re-verified against the real, installed
library, not assumed to keep working.

**Q28. The memory model's dominant features (~98% of gain) are largely
machine-configuration counts. Does that mean the model has learned
nothing genuinely useful at all?**

A: Not quite that strong a claim, and it's worth being precise here rather
than overcorrecting. The model demonstrably *can* separate the training
data's two classes near-perfectly (file 33's near-1.0 validation AUC), and
it does genuinely discriminate this project's own real malicious capture
from its seven clean ones — 0.4740 vs. 0.0077–0.0081, roughly 60× higher,
a real, measured, sixty-fold separation. What the SMOTE finding actually
shows is narrower: that separation is happening substantially *because*
the benign class is synthetically interpolated and tightly clustered, not
purely because the model learned generalizable malicious *behaviour* —
which is exactly why this project doesn't let that number drive severity
on its own, while still reporting it for reference rather than hiding it
entirely.

**Q29. What specifically can this system prove about an artifact, and
what can it never prove, regardless of how confident its output looks?**

A: It can prove, with hard evidence, things like: this specific file's raw
bytes produced these specific measured feature values; this trained
model, given those values, computed this specific probability; these
specific Volatility plugins found these specific memory regions, at these
specific addresses, in this specific process, at capture time. What it
cannot prove, ever, regardless of confidence: that a flagged file is
*definitely* malware (a packed benign binary, per this project's own UPX
demonstration, gets flagged too — 0.0010 to 0.6607, a real, disclosed
false positive), that an unsigned binary is definitely malicious (most
unsigned software is entirely legitimate), or that any specific API/DLL
name is involved in a disk verdict (hard rule 15 — hash buckets are
one-way). This project's own standing position, throughout its
documentation, is that it performs triage, narrowing attention toward
what's worth a human's time — not final, conclusive forensic
determination.

**Q30. The memory model's threshold, 0.2336726188659668, is well below
0.5 — meaning it calls something "malicious" at a much lower confidence
bar than the disk model does. Doesn't that make the memory pipeline more
likely to produce false positives?**

A: It's a fair intuition, but the honest answer is that the threshold
number alone doesn't tell you that — it has to be read against what
*else* is gating the verdict. A lower threshold, by itself, would indeed
tend to increase the false-positive rate of the raw probability
comparison in isolation. But the memory pipeline's real verdict isn't
"probability crosses this specific low bar, done" — hard rule 22 means the
probability is demoted to secondary the moment the model's own dominant
features fall out of distribution, which this project's evidence shows
happens routinely on real captures (all seven clean reference captures
read out-of-distribution on 22–27 of 55 features, and the real malicious
capture on 27 of 55). So in practice, on a real dump, the threshold
comparison alone rarely gets to be the deciding factor at all — severity
is instead driven by whether directly-observed indicators clear a
*separate*, per-machine baseline ceiling (file 34's `MARGIN` mechanism),
which is a different, and in this project's own telling, more reliable
gate than the threshold comparison by itself.
