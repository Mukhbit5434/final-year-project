# Automated Malware Analysis System for Disk & Memory Forensics

Final Year Project — BSIT, Faculty of Computing & IT, International Islamic University
Islamabad. Muhammad Farooq (831-FOC/BSIT/F22), Mukhbit Ilahi (955-FOC/BSIT/F22).

A locally-run web application. An analyst uploads a raw disk image or a memory dump; the
system extracts the features itself, runs them through a pre-trained model, and produces
an analyst-readable report. No Volatility or Sleuth Kit commands are run by hand and no
feature CSV is ever uploaded.

Two independent pipelines share the web layer, the database and the report generator, and
nothing else.

**The memory pipeline is scoped to one controlled reference machine — Windows 10 x64**,
matching the environment the CIC-MalMem-2022 authors documented. Severity is calibrated
against that machine's own clean baseline. This is a deliberate scope decision for a
demonstration project, not a general-purpose tool for arbitrary hosts. See CLAUDE.md §11.1.

| | Disk | Memory |
|---|---|---|
| Input | `.dd .raw .img .E01 .EX01` | `.raw .mem .dmp .vmem` — **Windows 10 x64 only** |
| Extractor | pytsk3 / libewf + EMBER | Volatility 3 |
| Features | 150 of 2,381 | 55 |
| Model | LightGBM | XGBoost |
| Threshold | 0.5010602922493019 | 0.2336726188659668 |
| Positioning | primary detection capability | forensic triage engine with a confidence-gated ML layer |

---

## Setup

Python **3.11** is required — `pytsk3` and `lief` wheel coverage is the constraint.

```
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python scripts\setup_env.py      # forensics deps + ember + patches
.venv\Scripts\python scripts\check_env.py      # must print RESULT: OK
```

`setup_env.py` installs EMBER from a tarball rather than `git+https://` (so git is not
required) with `--no-deps`, because ember's own metadata pins `lief==0.9.0` and would
clobber the 1.0.0 install that produced the training features. It then applies three
patches to `ember/features.py`. The application only ever *verifies* those patches at
startup; it never rewrites site-packages at runtime.

Then:

```
set FLASK_APP=wsgi.py
.venv\Scripts\python -m flask db upgrade
.venv\Scripts\python run.py                     # http://127.0.0.1:5000
```

`wsgi.py` and `run.py` are deliberately separate. Windows spawns extraction workers by
re-importing the main module, so anything at module level runs again in every worker —
with a single entry point, each worker built a second Flask app and reloaded both models.

### Offline use — stage the kernel symbols first

Volatility downloads a Windows symbol table (ISF) on first encounter with an unseen build,
and caches it under the *user's* AppData rather than in the project. Stage it into the
repo instead, once per build, while online:

```
.venv\Scripts\python scripts\fetch_symbols.py sample\memory\win10_memory.raw
.venv\Scripts\python scripts\fetch_symbols.py --list
```

That writes `symbols/windows/<GUID>.json.xz` (0.6 MB — volatility reads ISFs compressed),
which the extractor puts at the front of its symbol search path. After this the build
analyses with no network at all; verified with volatility's own `OFFLINE` flag, resolving
in 1.9 s. `symbols/` is gitignored, so populate it on each machine.

Without this, an offline machine fails several minutes into a job with a symbol error that
does not obviously say "no network".

---

## What the numbers actually mean

The project's conclusions are measured, not assumed. The ones that matter:

**The disk pipeline is sound.** Validated against the official EMBER 2018 baseline
(ours 0.9940 ROC-AUC against the baseline's 0.9964, using 6% of the features). On a real
CFReDS evidence image it examined 3,817 files, identified all 19 PE files by content —
including two named `.db` and `.regtrans-ms` — and flagged none of them, which is correct
for an image containing only signed Microsoft and OpenOffice binaries.

**The memory model's probability is weak on any real capture, and the reports say so.**
The benign half of CIC-MalMem-2022 was balanced with SMOTE (ICISSP 2022, §4.2), so much
of it is interpolated rather than captured. Interpolated points cannot exceed the range of
their seeds, which is why the training data spans 195–395 services where Windows itself
reports 615 on an ordinary desktop. Every memory result therefore ships with a count of
how many of its 55 features fall outside the training range, and the report leads with
Volatility's observations rather than the score.

**Extraction itself is correct in absolute terms.** Measured against ground truth taken
inside the VM at capture time:

| | Ours | Windows | |
|---|---:|---:|---|
| Processes | 67 | 67 (`Get-Process`) | exact |
| Drivers | 360 | 362 (`driverquery`) | −0.6% |
| Services + drivers | 632 | 615 (`Get-Service` + `driverquery`) | +2.8% |

`Get-Service` lists Win32 services only, so 615 — not 253 — is the valid comparison for a
tool that enumerates both.

**Findings are reported against a clean-system baseline, never as bare counts.** A healthy
Windows 10 machine produces 16 injected memory regions, 203 modules absent from the loader
list and 3 processes invisible to `pslist`. Printed raw, those read as compromise.
`baselines/clean_win10_x64.json` is the reference; severity counts only indicators that
are substantially elevated against it.

---

## Layout

```
app/
  extractors/disk.py      pytsk3/libewf walk, PE identification, EMBER vectorization
  extractors/memory.py    nine Volatility 3 plugins -> 55 features, gap tracking
  inference/disk.py       LightGBM, 150-feature subset, startup guards
  inference/memory.py     XGBoost, out-of-distribution check
  forensics/              feature meanings, MITRE mapping, severity, baseline
  explain.py              LIME, resolved through as_map() indices
  report.py               ReportLab PDF; limitations defined once, shared with the UI
  jobs.py                 Flask-Executor supervisor + ProcessPoolExecutor extraction
  static/app.css          design tokens and the severity colour scale, shared with charts
  templates/              landing page, dashboard, jobs, job detail, upload
models/  reference_data/  trained artifacts and training distributions - never modify
baselines/               clean-system reference captures
data/holdout/            labelled held-out rows; the rest of data/ is gitignored
symbols/                 repo-local kernel ISF cache, gitignored, per-deployment
scripts/                 environment setup, verification, manual extraction runs
```

Extraction always runs out of process: lief parses hostile PEs in native code and a
segfault must not take the web server with it, and Volatility is CPU-bound Python that
would otherwise hold the GIL for minutes.

---

## Verification

```
.venv\Scripts\python -m pytest tests -q
```

The checks worth knowing about:

- **Column-order controls.** A feature-count assertion catches a missing column but not a
  permuted one, so the 5,000 saved training rows are run through each model at startup and
  the probability distribution must stay bimodal and roughly balanced. Measured over 200
  random permutations it rejects 200/200. It does *not* catch adjacent swaps (5 of 54 on
  memory, 0 of 149 on disk), which is why the memory extractor emits its vector by
  indexing `feature_list.json` rather than by hand.
- **Mandatory report strings.** Every limitation the reports must carry is asserted
  against the rendered PDF. Removing one fails the build.
- **Concurrency** runs against a file-backed SQLite database in WAL, matching production —
  the in-memory database shares one connection across threads and would be testing
  something we do not ship.

Useful scripts:

```
scripts\verify_pipeline.py                 end-to-end against everything in sample/
scripts\scan_image.py <image>              disk extraction + predictions
scripts\dump_memory_features.py <dump>     all 55 values against their training ranges
scripts\predict_vector.py <pipeline> ...   one pre-extracted vector through inference
scripts\fetch_symbols.py <dump>            stage kernel symbols for offline use
scripts\malmem_holdout.py --csv ...        labelled held-out CIC-MalMem-2022 rows
scripts\ember_holdout.py --tar ...         labelled held-out EMBER 2018 rows
```

`verify_pipeline.py` is the one that matters after any change to extraction, inference or
reporting — unit tests do not catch what it catches.

**Runtime varies roughly 2× between runs on identical input and the cause is not
identified.** A 2 GB memory capture has taken 202 s, 352 s, 357 s and 409 s across four
runs on the same machine with the symbol cache warm, and the same disk image has ranged
11–27 s. Only wall-clock was ever measured, so this is stated rather than characterised;
`Job.plugin_seconds` records per-plugin cost on every memory job so the next run can
localise it. The job layer itself accounts for about 2%.

---

## Scope

Not included, by design: live acquisition, malware family classification, reverse
engineering, non-Windows malware, cloud deployment, and anti-obfuscation beyond what
packing detection infers.

Known limits, stated plainly:

- Six of the 55 memory features cannot be produced by Volatility 3 at all — its `psxview`
  enumerates processes four ways where Volatility 2 used seven. They are emitted as 0.0
  and recorded as gaps, never estimated. Measured impact: 0.2% of model gain.
- Memory input is Windows 10 x64 only. A raw dump carries no header identifying its
  architecture, so the check happens where the kernel layer is built — before any
  Volatility plugin runs — and anything else is refused with a stated error.
- The installed `lief` (1.0.0) differs from the 0.9.0 release EMBER was validated against,
  so feature values may differ slightly from the official benchmark. Disclosed in every
  disk report.
- A packed benign binary will often be flagged. UPX-packing `python.exe` moves it from
  0.0010 to 0.6607. That is a property of EMBER's training distribution, in which the
  malicious class is heavily packed — useful for demonstrating the detection path, but it
  is a false positive and should not be presented as a detection.
- The clean-system baseline is a single capture. It anchors order of magnitude, not a
  threshold: across 5,000 captures of one machine, `malfind.commitCharge` spans 200×.

This system performs triage. It narrows an investigation to the artifacts worth a human's
attention; it does not produce conclusive findings.