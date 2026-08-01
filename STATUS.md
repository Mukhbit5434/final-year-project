# STATUS — where the project is right now

Last updated 2026-07-31. `CLAUDE.md` is the spec and the binding rules; this file is the
handoff state. If the two disagree, CLAUDE.md wins on *what to build* and this file wins
on *what exists*.

## Build state: all ten steps complete, 175 tests passing

```
.venv\Scripts\python -m pytest tests -q      ->  175 passed
```

| Step | State |
|---|---|
| 0 Environment | Done. `scripts/check_env.py` prints `RESULT: OK` |
| 1 Skeleton, config, DB, migrations | Done |
| 2 Auth, upload, jobs, audit, rate limit | Done |
| 3 Inference + column-order guards | Done |
| 4 Disk extractor | Done, verified on real evidence |
| 5 Memory extractor | Done, verified on the x64 capture |
| 6 Job pipeline | Done, verified end to end |
| 7 LIME, meanings, MITRE, severity | Done |
| 8 Dashboard | Done |
| 9 PDF reports + CSV/JSON export | Done |
| 10 Tests, concurrency, docs | Done |

## Verified against real artifacts, not just unit tests

**Disk** — CFReDS `2020JimmyWilson.E01`: 3,817 files examined, all 19 PE files found by
content (including two named `.db` and `.regtrans-ms`), 13 unique after SHA-256 dedupe,
0 flagged, 11–27 s. Correct: the image holds only signed Microsoft and OpenOffice binaries.

**Memory x64** — `win10_memory.raw`, **202–409 s** through the job layer. Ground truth
measured inside the VM at capture time: processes 67 vs 67 exact, drivers 360 vs 362,
services+drivers 632 vs 615. Extraction is correct in absolute terms; the training range
really is far below reality. Clean capture scored **p=0.0084, severity Low** — correctly
benign despite 21 of 55 features being out of range.

**Runtime — job-layer overhead resolved; run-to-run variance NOT explained.** Standalone
extraction 401 s against 409 s end to end, minutes apart: **the job layer costs about 2%**,
and the old "2.3× overhead" was a fast standalone run compared against a slow job run.

But the same memory job ran in **202 s** the next day and the disk job has ranged
**11–27 s** on identical input. **Cause not identified.** Only wall-clock was ever
recorded — no page-cache state, no background-load sampling, no per-plugin timing. A cold
ISF download is the one thing ruled out (it adds ~4 min and would dwarf this). Say
"varies roughly 2× between runs, cause not identified"; do not quote a range, which would
imply a distribution nobody measured.

`Job.plugin_seconds` now records per-plugin cost on every memory job and
`verify_pipeline.py` prints the slowest five, so the next real run should localise it.

**Web** — every route returns against real data; PDFs render for both pipelines; uploaded
artifacts are unreachable over HTTP.

## Test artifacts

Live in `sample/`, which is **gitignored** — they are hundreds of MB and are not in the
repo.

| Path | What |
|---|---|
| `sample/disk/2020JimmyWilson.E01` | NIST CFReDS evidence image, 295 MB |
| `sample/memory/win10_memory.raw` | Win10 21H2 x64 19044.1288, 2 GB, Magnet RAM Capture. **The only memory dump this project has.** |

`baselines/clean_win10_x64.json` is committed and holds the x64 capture's 55 features,
its behavioural baseline and its ground-truth numbers.

## Uploaded artifacts are retained indefinitely — decided 2026-07-31

**This is policy, not an oversight.** `uploads/` (gitignored, outside the web root, never
served) keeps every uploaded artifact for good. Evidence retention is the forensic norm:
an analyst must be able to re-run an artifact without re-acquiring it, and the SHA-256 in
the chain-of-custody header is only verifiable against the artifact it was computed from.
A report whose hash nobody can check is worth less.

**There is no purge mechanism, no retention window and no delete route, by choice.** Do
not add one as a tidy-up — removing evidence is a policy change, not housekeeping.

Cost, stated rather than avoided: ~2 GB per memory capture, kept forever, on top of the 2×
transient during upload (CLAUDE.md §10). A two-analyst lab tool will not fill a disk this
semester; if it ever matters, the answer is more disk or a policy change made on purpose.

The application itself never needs the artifact again — `report.render()` builds from
stored results and job metadata and never reopens it. Retention serves the analyst.
Disclosed in the report: the chain-of-custody section carries a "Retention" row naming the
stored artifact, so a reader of the report knows the evidence was kept and under what name.

## Running it

```
.venv\Scripts\python scripts\check_env.py            # verify the environment
set FLASK_APP=wsgi.py
.venv\Scripts\python -m flask db upgrade
.venv\Scripts\python run.py                          # http://127.0.0.1:5000
.venv\Scripts\python -m pytest tests -q

scripts\verify_pipeline.py                           # end-to-end against sample/
scripts\scan_image.py <image>                        # disk extraction + predictions
scripts\dump_memory_features.py <dump>               # 55 values vs training ranges
scripts\predict_vector.py disk --reference 0         # one vector through inference
scripts\fetch_symbols.py <dump>                      # stage kernel ISF for offline use
scripts\malmem_holdout.py --csv data\Obfuscated-MalMem2022.csv
scripts\ember_holdout.py --tar data\ember_dataset_2018_2.tar.bz2
```

`verify_pipeline.py` is the one that matters after any change to extraction, inference or
reporting. It runs whatever is in `sample/` through the real job pipeline, checks the
mandatory report strings against the rendered PDF, exercises every route, and confirms
uploaded artifacts stay unreachable. It carries the last-verified numbers inline so drift
is visible. Unit tests do not catch what this catches — every one of the six bugs below
came from it.

Run `run.py`, never `python -m flask run` with a module that builds the app at import —
see CLAUDE.md §10 on Windows spawn.

## Six silent bugs found by running real artifacts

None of these would have been caught by unit tests; all produced plausible numbers and
raised nothing. Kept here because the pattern is the argument for testing on real inputs.

1. **Missing `PE\0\0` check** — MZ and `e_lfanew` were validated, the signature never
   read. Anything starting with "MZ" would have been vectorized as an executable.
2. **`pslist.avg_handlers` = 0.0** — averaged an empty list, because Volatility 3 leaves
   `pslist`'s Handles column unpopulated.
3. **`pslist.nprocs64bit` inverted** — counted 64-bit processes; VolMemLyzer counts
   *WOW64* processes despite the name.
4. **Torn `EPROCESS` from live acquisition** — one row with 333,494,799 threads moved
   `avg_threads` from 13.1 to 4,977,547.
5. **Unsigned-binary tag fired on signed binaries** — matched the feature name without
   reading the value, and LIME ranks the certificate table highly either way.
6. **Clean capture scored Critical** — severity counted indicators that were merely
   present. Every healthy Windows box has malfind, ldrmodules and psxview hits.

## Known limitations, all disclosed in the reports

- The memory model's probability is weak on any real capture. CIC-MalMem-2022's benign
  half was SMOTE-balanced, so its ranges are compressed. 21 of 55 features are out of
  range on the clean x64 capture, including 3 of the 4 the model leans on. **This is
  closed — do not reopen the distribution investigation.**
- Six of the 55 memory features cannot be produced by Volatility 3 (its `psxview`
  enumerates four ways, not seven). Emitted as 0.0, recorded as gaps, 0.2% of model gain.
- `lief` 1.0.0 vs the 0.9.0 EMBER was validated against; disclosed in every disk report.
- The clean baseline is **per-machine by design** (CLAUDE.md §11.1). It anchors order of
  magnitude, not a threshold — `malfind.commitCharge` spans 200× across captures of a
  single machine, so more captures of the reference machine are still needed. Comparing a
  capture against another machine's baseline is misuse and the scope forbids it; the x64
  dump against its own baseline correctly yields Low.
- A UPX-packed benign binary is flagged (0.0010 → 0.6607). Useful for demonstrating the
  detection path; it is a false positive and must be worded as one.
- **Memory severity is only meaningful for captures of the reference machine.** Scoring a
  CIC-MalMem-2022 row against `clean_win10_x64.json` returns Low with every indicator
  reading "consistent with a healthy system", because the dataset VM was far smaller than
  the reference box. The code is behaving as designed (§11.1 forbids cross-machine
  comparison); the trap is that it fails *quietly* — a plausible-looking Low rather than a
  refusal. Nothing outside the reference machine should be severity-scored.

## Outstanding

**Everything that does not need new artifacts is done.** What remains is items 1 and 2,
both of which wait on captures from the reference machine, plus the write-up. Testing of
the supplied artifacts happens in **one pass** once they all land — clean `.raw` set,
simulated-malicious `.raw`, and a disk image with simulated malicious elements. Test
infrastructure for those is deliberately **not** built yet; it gets specified together
with the captures.

The MalMem CSV landed on 2026-08-01 and `malmem_holdout.py` has been run — all four gates
passed, rows committed. Nothing else is pending from the user except the captures.

### 1. Captures from the reference machine — user supplies

**A. Clean baseline set, five captures across states:**

| State | Note |
|---|---|
| Fresh boot | 2–3 min settle |
| Idle | 20–30 min after boot, so SearchIndexer / NGEN / Update have finished |
| Browser open | |
| Two or three apps running | |
| Within ~30 s of closing several applications | Drives `psxview.not_in_pslist`, the worst-variance indicator — no other state reaches its peak |

Plus **two captures 15 s apart in one state**, to separate capture noise from state noise
and mirror the dataset's own cadence (ICISSP 2022 §4.2).

**B. Simulated-malicious capture, same machine.** Genuine forensic artifacts without live
malware: process injection (`CreateRemoteThread` / `VirtualAllocEx`, producing real
`malfind` RWX regions), a running UPX-packed binary, and/or a hidden process.
**The specific safe simulation method is subject to supervisor approval.**

*Open question for next session:* which artifacts the malicious capture must exhibit for
the findings → tags → severity path to demonstrate well, and which safe simulation method
is recommended for each.

### 2. Empirical test of the OOD gate — planned experiment, not a decision

The x64 clean capture scored p=0.0084 — correctly benign — despite 21 of 55 features being
out of range. The model extrapolated and landed correctly. **One correct result is not a
pattern**, but it is worth measuring properly.

When the five clean captures exist, run all five through the model and record their
probabilities, then run the malicious capture.

- **All five clean below threshold and the malicious substantially higher** → the model
  discriminates meaningfully on this reference machine despite being technically out of
  distribution. That would justify *showing* the verdict with a stated caveat rather than
  withholding it.
- **Any clean capture above threshold** → withholding is confirmed correct, and we have a
  measured false-positive rate on a machine known to be clean.

**The OOD gate stays exactly as it is until this data exists. Do not unlock it on
optimism.** This is not reopening the distribution investigation — the SMOTE root cause is
closed and stays closed. It only measures whether the gate is correctly calibrated for the
reference machine.

### 3. Symbol cache — **done 2026-08-01**

`scripts/fetch_symbols.py` stages the ISF into repo-local `symbols/`; the extractor
prepends it to volatility's search path. Verified with `constants.OFFLINE = True`: the
Win10 19044 capture resolves in 1.9 s with no network. Documented in README and CLAUDE.md
§5.6.

### 4. Enforce the reference-environment scope statement — **done 2026-07-31**

`report.SCOPE_STATEMENT` holds the §11.1 wording, `report.limitations()` emits it for
memory jobs as "Reference environment and scope", and `report.REQUIRED_MEMORY` asserts
two fragments of it. Verified by adding the required strings first and watching
`test_mandatory_limitation_strings_survive_into_a_memory_report` fail on
`'controlled reference environment'`, then passing once the emission was added.

The asserted fragments deliberately contain **no parentheses**. `verify_pipeline.py`
matches mandatory strings against the raw uncompressed PDF stream, where ReportLab
escapes `(` as `\(` — so a fragment spanning "(Windows 10 x64)" would pass pytest, whose
`text_of` strips parens, and fail the pipeline check. Both fragments were confirmed
against the raw-byte path as well as the collapsed-text one.

### 5. Runtime — job-layer question closed, variance still open

The *job-layer* discrepancy was not real: standalone 401 s vs 409 s through the job layer,
same machine, minutes apart, so the supervisor adds ~2%. Confirmed the next day when the
same job ran in 202 s — roughly the original "standalone" figure the phantom penalty was
inferred from.

**Still open: why identical input varies ~2× run to run.** Not investigated, not
characterised, and the docs say so rather than implying otherwise. `plugin_seconds` is now
captured on every memory job; read it on the next real run before theorising.

## Known rough edges — deliberate, but write them down

None of these block anything. They are recorded so they are found here rather than in a
viva.

1. **The memory severity path has never produced a non-Low result on a malicious input.**
   `severity.for_memory` counts indicators *elevated against the baseline*, and the only
   malicious memory data we have is CIC-MalMem rows, which are cross-machine and therefore
   read Low. Unit tests drive the function directly, but no real artifact has ever taken it
   to High or Critical. The simulated-malicious capture is the first thing that will.
2. **The four-check refusal gate in `malmem_holdout.py` has never been seen to refuse.**
   It passed on the first run, so the failure path is untested. A test feeding a
   deliberately wrong split and asserting refusal is the obvious missing piece.
3. **Five of seven scripts have no tests** — `malmem_holdout`, `ember_holdout`,
   `predict_vector`, `fetch_symbols`, `scan_image`, `dump_memory_features`. Only
   `verify_pipeline` is exercised. They are operator tools, but two of them now produce
   committed artifacts.
4. **`predict_vector.py` prints severity for memory vectors that are not from the
   reference machine**, where it is meaningless (see the limitation above). It should
   suppress or caveat it; today it just prints Low. Known, not fixed.
5. **The UI has no visual regression testing.** Route tests assert strings, not layout — a
   CSS mistake would keep every test green.
6. **`recover_orphans` does not clear `stage` / `progress_pct` or the orphaned
   `instance/progress/<id>.json`** after a crash. Harmless (the progress card only renders
   for PENDING/RUNNING) but untidy.
7. **Disk progress is indeterminate** — "Vectorising executable N" with no percentage,
   because the PE count is unknown until the walk finishes.
8. **Held-out rows are the first matching row of each class**, not randomly sampled. Fine
   for a demo, recorded in the sidecar JSON, but it is one arbitrary row per class.
9. **Per-plugin timing is memory-only.** The disk extractor has no equivalent.
10. **Upload rate limit is 10/hour, hardcoded** in `routes.py`. A one-pass session with
    five clean captures, a malicious one, a disk image and any retries will approach it.

## Demo plan

**Memory — two parts, plus a comparison:**

1. **A held-out row from CIC-MalMem-2022** fed straight through the inference path.
   In-distribution, OOD count zero, verdict displayed. *Proves the model works.*
   **Ready:** `data/holdout/malmem_test_{malicious,benign}.npy`, p=0.997147 / 0.002813,
   both correct, OOD 0/55. **Show probability and OOD only — not severity**, which is
   calibrated to a different machine and reads Low on this row.
2. **A real capture from the reference machine.** OOD fires (unless item 2 above shows
   otherwise); forensic findings and MITRE mapping still deliver value. *Proves the guard
   works.*
3. **Clean vs simulated-malicious** from the same machine, against that machine's own
   baseline — the before/after that makes the baseline design legible.

**Disk — three parts:**

1. **Clean CFReDS image** — 0 of 13 flagged. Correct negative.
2. **UPX-packed benign binary** — flagged. Framed explicitly as packing/obfuscation
   detection and a **known false positive**, never as malware detection.
3. **A known-malicious row from EMBER's test set** fed straight through the disk inference
   path — a genuine true positive on real malware data, with no malware files handled.
   **Ready:** `data/holdout/ember_test_malicious.npy`, p=0.999838, correct against its
   label. The benign counterpart scores 0.017917, also correct.

**Prerequisite — built 2026-08-01.** `scripts/predict_vector.py` is the entry point for a
raw vector. It runs the same loaders, thresholds, LIME explainer, tag table and severity
functions the job layer uses, so it demonstrates the shipped path rather than a
reimplementation. Sources: `--csv` (CIC-MalMem-2022 export, matched **by column name**,
never positionally), `--npy`, or `--reference N`.

Verified on both pipelines: memory reference row 41 → p=0.0028, **0 of 55 out of range**,
severity Low; disk reference row 0 → p=0.8226, MALWARE, severity Medium, with LIME
findings and MITRE tags. The contrast that matters for demo 1 is the OOD count — 0 on an
in-distribution row against 21 on a real capture.

**Labelled held-out rows now have their own tooling.** `reference_data/` rows are
*unlabelled training samples* — `predict_vector.py` says so on every `--reference` run and
they must never be presented as a verified true positive. The two scripts below produce
genuinely held-out, labelled rows into `data/holdout/`, which **is** committed:

- `scripts/malmem_holdout.py` reproduces the memory training split exactly —
  StratifiedGroupKFold(7) then (6), first fold each, `random_state=42`, groups = Category
  minus the `-N.raw` suffix, **each benign row its own group** (benign Category values are
  indistinguishable, so keying on the string alone collapses them into one group and drops
  the whole benign half into one fold). Dedup is `drop_duplicates()` over all columns
  before group keys are built. It **refuses to emit anything** unless row counts
  (41,456/8,288/8,318), test class balance (4,174/4,144), dedup total (58,062) and
  group disjointness all match `models/memory/metadata.json`.
- `scripts/ember_holdout.py` pulls a labelled row from EMBER 2018's published
  `test_features.jsonl` and vectorises it with `process_raw_features()` — **no PE is
  opened and lief never parses anything**.

**Both pipelines now classify their own held-out data correctly** (2026-08-01).

`malmem_holdout.py` passed all four gates on the first run: 58,596 → **58,062** after
dedup, split **41,456 / 8,288 / 8,318** exactly, test balance 4,174/4,144, zero group
overlap. 32,137 distinct groups — 29,231 benign (one per row) plus 2,906 malware samples,
which lines up with the paper's 2,916 before dedup. The dedup variant that lands on 58,062
is **`drop_duplicates()` across all columns, whole frame, before group keys are built**.

| Row | Label | Probability | Verdict | OOD | |
|---|---|---:|---|---|---|
| `malmem_test_malicious` (Ransomware-Ako) | Malware | **0.997147** | MALWARE | **0/55** | correct |
| `malmem_test_benign` | Benign | **0.002813** | BENIGN | **0/55** | correct |

**OOD 0 of 55 on both confirms the gate is doing what it claims** — it fires on real
captures (21/55) and stays silent on in-distribution rows.

**But severity on a dataset row is meaningless, and the demo must not show it.** The
Ransomware row scores severity **Low**, with every indicator reading *"consistent with a
healthy system"* — because severity compares against `baselines/clean_win10_x64.json`, a
*different machine* that simply runs more of everything (ldrmodules 89 vs 267,
`malfind.commitCharge` 49 vs 1611). That is precisely the cross-machine comparison §11.1
forbids. **Demo 1 shows probability and OOD only.** The findings → tags → severity path
can only be demonstrated by the simulated-malicious capture from the reference machine.

Worth noting for the write-up: LIME's top driver on this true positive is
`svcscan.nservices`, then `psxview.not_in_eprocess_pool` and
`svcscan.shared_process_services` — the model leaning on service counts exactly as §5.4a
says, even when it is right.

**The disk true positive is done and it is genuine** (2026-08-01). Both held-out EMBER
test rows classify correctly through the shipped inference path:

| Row | Label | Probability | Verdict | |
|---|---|---:|---|---|
| `ember_test_malicious` | 1 | **0.999838** | MALWARE | correct |
| `ember_test_benign` | 0 | **0.017917** | BENIGN | correct |

Through `predict_vector.py` the malicious row gives severity **High**, tags T1106 and
T1553.002, and LIME findings led by `section_feat_122` and the certificate-table entry.
This is real malware data from the published held-out split, classified by the model that
scores 0.9940 against the official baseline — and no malicious binary was ever opened.
`predict_vector.py --npy` reads the sidecar `.json` so the ground-truth label prints next
to the verdict.

**A web route for this was considered and rejected.** Rendering a vector result through
the job pages would mean creating a `Job` row with a fabricated `stored_name`, `sha256`
and size, which would put false chain-of-custody data — including the retention line —
into a forensic report. Not worth it for a demo convenience; the script is the honest
form.

## The exact next task

**Items 3 and 4 are closed** (2026-07-31). Everything that remains needs the
reference-machine captures.

**Track B (needs the captures):** once the five clean captures from item 1A arrive, extend
`baselines/clean_win10_x64.json` into a multi-capture distribution (median and IQR per
indicator rather than a single value), then run the OOD experiment in item 2 and record
the five probabilities before touching the gate.