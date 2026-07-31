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
0 flagged, 27 s. Correct: the image holds only signed Microsoft and OpenOffice binaries.

**Memory x64** — `win10_memory.raw`, **409 s** through the job layer. Ground truth
measured inside the VM at capture time: processes 67 vs 67 exact, drivers 360 vs 362,
services+drivers 632 vs 615. Extraction is correct in absolute terms; the training range
really is far below reality. Clean capture scored **p=0.0084, severity Low** — correctly
benign despite 21 of 55 features being out of range.

**Runtime — resolved 2026-07-31.** Standalone extraction 401 s, end to end through the job
layer 409 s, measured minutes apart on the same machine. **The job layer costs 8 s, about
2%.** The old "2.3× overhead" compared two runs taken under different machine conditions —
over the same period the disk artifact moved from ~11 s to 27 s on identical input. Quote
**about 7 minutes** for a 2 GB capture.

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

## Uploaded artifacts are retained forever — currently unmanaged

**Stated so it is a choice rather than a discovery.** `uploads/` (gitignored, outside the
web root, never served) keeps every uploaded artifact indefinitely. `artifacts.store`
writes it, `jobs.run` reads it once, and **nothing ever deletes it** — there is no cleanup
pass, no retention setting, no delete route, and CLAUDE.md §10's data flow never specified
one. So today this is unmanaged growth, not a deliberate custody policy.

The application does not need the file after a job completes: `report.render()` builds
from stored results and job metadata alone and never reopens the artifact. What retention
does buy is genuinely forensic — re-analysis without re-acquiring, and the SHA-256 in the
chain-of-custody header is only checkable against the artifact it was computed from.

The cost is a memory capture per job, at ~2 GB each, kept forever, on top of the 2×
transient documented in §10. Two defensible resolutions, either of which makes it a
decision: **keep** retention and say so in the docs plus the report's custody section, or
add an explicit retention window with an audit-logged purge. Not urgent — a lab tool with
two analysts will not fill a disk this semester — but it should not stay accidental.

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
  single machine, so more captures of the reference machine are still needed. Comparing a
  capture against another machine's baseline is misuse and the scope forbids it; the x64
  dump against its own baseline correctly yields Low.
- A UPX-packed benign binary is flagged (0.0010 → 0.6607). Useful for demonstrating the
  detection path; it is a false positive and must be worded as one.

## Outstanding

Nothing blocks the build. Four items — 3 and 4 are done; 1 and 2 remain and both need the
reference-machine captures.

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

### 4. Investigate the runtime discrepancy — **closed 2026-07-31**

There was no discrepancy. Standalone 401 s vs 409 s through the job layer, same machine,
minutes apart: the job layer adds 2%. The old figures were taken under different machine
conditions and were never comparable.

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

**Items 3 and 4 are closed** (2026-07-31). Everything that remains needs the
reference-machine captures.

**Track B (needs the captures):** once the five clean captures from item 1A arrive, extend
`baselines/clean_win10_x64.json` into a multi-capture distribution (median and IQR per
indicator rather than a single value), then run the OOD experiment in item 2 and record
the five probabilities before touching the gate.