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
| 5 Memory extractor | Done, verified on x86 and x64 captures |
| 6 Job pipeline | Done, verified end to end |
| 7 LIME, meanings, MITRE, severity | Done |
| 8 Dashboard | Done |
| 9 PDF reports + CSV/JSON export | Done |
| 10 Tests, concurrency, docs | Done |

## Verified against real artifacts, not just unit tests

**Disk** — CFReDS `2020JimmyWilson.E01`: 3,817 files examined, all 19 PE files found by
content (including two named `.db` and `.regtrans-ms`), 13 unique after SHA-256 dedupe,
0 flagged, ~11 s. Correct: the image holds only signed Microsoft and OpenOffice binaries.

**Memory x64** — `win10_memory.raw`, **489 s** through the job layer. Ground truth
measured inside the VM at capture time: processes 67 vs 67 exact, drivers 360 vs 362,
services+drivers 632 vs 615. Extraction is correct in absolute terms; the training range
really is far below reality. Clean capture scored **p=0.0084, severity Low** — correctly
benign despite 21 of 55 features being out of range.

**Memory x86** — `Windows 10-32-f7257ea7.vmem`, **384 s**, needs the custom PAE layer that
stock Volatility cannot build. Clean capture scored **p=0.3701, severity Medium** — above
the 0.2337 threshold, i.e. a false positive on a machine known to be clean. Retained as a
test artifact only; 32-bit is out of scope (CLAUDE.md §11.1).

**Runtime discrepancy — investigate next session.** Standalone extraction timed 211 s
(3.5 min) on both captures; through `verify_pipeline.py` the same work took 489 s and
384 s, roughly 2.3×. Unexplained. Candidates: the banded PAE scan, the added verification
work in-process, LIME and report rendering, or machine load from three artifacts run back
to back. Quote 6–8 minutes end to end until resolved, not 3.5.

**Web** — every route returns against real data; PDFs render for both pipelines; uploaded
artifacts are unreachable over HTTP.

## Test artifacts

Live in `sample/`, which is **gitignored** — they are hundreds of MB and are not in the
repo.

| Path | What |
|---|---|
| `sample/disk/2020JimmyWilson.E01` | NIST CFReDS evidence image, 295 MB |
| `sample/memory/win10_memory.raw` | Win10 21H2 x64 19044.1288, 2 GB, Magnet RAM Capture. **The primary demo dump.** |
| `sample/memory/Windows 10-32-f7257ea7.vmem` (+ `.vmss`) | 32-bit VM, a *different machine* — never compare its counts to the x64 one |

`baselines/clean_win10_x64.json` is committed and holds the x64 capture's 55 features,
its behavioural baseline and its ground-truth numbers.

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
  single machine, so more captures of the reference machine are still needed.
  **Evidence for the scope decision:** running the x86 dump against the x64 machine's
  baseline yields severity **Medium** on a system known to be clean, because that machine
  simply runs more (ldrmodules 230 vs 203, `psxview.not_in_pslist` 9 vs 3). The x64 dump
  against its own baseline correctly yields Low. That is cross-machine misuse, which the
  scope now forbids — not an outstanding defect.
- A UPX-packed benign binary is flagged (0.0010 → 0.6607). Useful for demonstrating the
  detection path; it is a false positive and must be worded as one.

## Outstanding

Nothing blocks the build. Four items, in the order they should be tackled — item 3 is
now done, the other three remain.

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
  measured false-positive rate on a machine known to be clean. Note the x86 dump already
  scored 0.3701 on a clean system, which is evidence in this direction.

**The OOD gate stays exactly as it is until this data exists. Do not unlock it on
optimism.** This is not reopening the distribution investigation — the SMOTE root cause is
closed and stays closed. It only measures whether the gate is correctly calibrated for the
reference machine.

### 3. Enforce the reference-environment scope statement — **done 2026-07-31**

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

### 4. Investigate the runtime discrepancy

211 s standalone vs 489 s / 384 s through `verify_pipeline.py`. See the runtime note above.

## Demo plan

**Memory — two parts, plus a comparison:**

1. **A held-out row from CIC-MalMem-2022** fed straight through the inference path.
   In-distribution, OOD count zero, verdict displayed. *Proves the model works.*
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

**Prerequisite — already satisfied at the inference layer.** `memory.predict(vec)` takes a
55-vector and `disk.predict(vec_150)` takes a 150-vector directly; `disk.subset()` reduces
a 2381-vector when needed. The existing tests already drive both this way with hand-built
and reference-row vectors, so demos 1 and 3 need no new inference capability. What does
not exist is an **application entry point** for a raw vector — the web app only accepts
artifact uploads. A small script or route is needed to feed a stored vector through and
render a result. That is the only build work these demos require.

## The exact next task

**Track A is complete** (item 3 above, 2026-07-31). Track B is what remains, plus items
1, 2 and 4.

**Track B (needs the captures):** once the five clean captures from item 1A arrive, extend
`baselines/clean_win10_x64.json` into a multi-capture distribution (median and IQR per
indicator rather than a single value), then run the OOD experiment in item 2 and record
the five probabilities before touching the gate.