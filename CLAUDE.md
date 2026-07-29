# CLAUDE.md — Automated Malware Analysis System for Disk & Memory Forensics

Final Year Project — BSIT, Faculty of Computing & IT, International Islamic University Islamabad.
Team: Muhammad Farooq (831-FOC/BSIT/F22), Mukhbit Ilahi (955-FOC/BSIT/F22). Fall 2025.

This file is the complete context for building this system. The ML models are
**already trained and finished**. Do not retrain them. Do not modify them. This
project is now about building the extraction layer, the inference layer, the
reporting layer, and the web application around those finished models.

---

## 1. WHAT THIS SYSTEM IS

A locally-run web application. A forensic analyst uploads **a raw disk image or a
raw memory dump**. The system extracts the required features itself, runs them
through the correct pre-trained model, and produces an analyst-readable report
explaining what was found and why.

The analyst never runs Volatility, Sleuth Kit, or any CLI tool by hand. They never
upload a feature CSV. They upload the artifact; the system does everything else.

**Two completely independent pipelines.** Disk and memory share the web UI, the
database, and the report generator. They share nothing else — different extractors,
different feature schemas, different model libraries, different thresholds. Never
merge them, never build a "generic" pipeline abstraction that tries to serve both.
They are separate on purpose.

---

## 2. WHAT IS ALREADY DONE (DO NOT REDO)

Both models are trained, validated, and saved. The full training history, decisions,
and investigations are settled. Key facts you must not contradict:

**Memory pipeline** — trained on CIC-MalMem-2022 (58,062 rows after dedup, 55
features, 50/50 balanced). Shipped model is **XGBoost**. Test set: ROC-AUC 1.0000,
FPR 0.0000, FNR 0.0000. That perfect score was investigated (leakage check →
dominant-feature ablation → univariate sweep) and traced to genuine dataset-level
saturation — 21 of 55 features individually exceed 0.95 AUC. It is a documented
property of CIC-MalMem-2022, not a bug. Do not "fix" it. Do not present it as
exceptional model quality anywhere in the UI or reports.

**Disk pipeline** — trained on full EMBER 2018 (600,000 labeled train rows,
200,000 test rows). Shipped model is **LightGBM**, using 150 features selected from
the original 2,381 via combined LightGBM/XGBoost importance ranking plus ablation
validation. Test set: ROC-AUC 0.9940, PR-AUC 0.9949, FPR 0.0303, FNR 0.0358.
Official EMBER baseline on the same test set scored 0.9964 — our model is 0.0024
lower while using ~6% of the features. That gap is expected and acceptable.

**The two pipelines shipped different model types.** Memory won with XGBoost. Disk
won with LightGBM. This is not a mistake and not something to normalize. Your
inference code must handle two different libraries with two different load and
predict APIs.

---

## 3. MODEL ARTIFACTS — EXACT INVENTORY

Repo layout. Everything below `models/` and `reference_data/` already exists and is
final — it was produced by the (completed) training phase. Application code you
create goes alongside these, never inside them.

```
Final Year Project/
├── CLAUDE.md
├── models/
│   ├── memory/
│   │   ├── xgboost_model.json
│   │   ├── feature_list.json
│   │   ├── metadata.json
│   │   └── lightgbm_model.txt        (archival — never loaded)
│   └── disk/
│       ├── lightgbm_model.txt
│       ├── feature_list_selected.json
│       ├── feature_list_full_2381.json
│       ├── metadata.json
│       └── importance_ranking.json   (archival — never loaded)
└── reference_data/
    ├── memory_sample.npy
    └── disk_sample.npy
```

There is no version subdirectory. Paths are exactly `models/memory/<file>` and
`models/disk/<file>`. Do not introduce a `v1/` level or reorganize these folders.

Note the project root contains spaces (`Final Year Project`). Quote paths in shell
commands and use `pathlib.Path` rather than string concatenation when building paths
in Python.

### `models/memory/`

| File | Role |
|---|---|
| `xgboost_model.json` | **LOAD THIS.** Production model. XGBoost native JSON. 55 features. |
| `feature_list.json` | **LOAD THIS.** The 55 feature names in exact model input order. |
| `metadata.json` | **READ `threshold` ONLY** → `0.2336726188659668`. Rest is documentation. |
| `lightgbm_model.txt` | **DO NOT LOAD.** Trained for comparison, lost the decision. Archival only. |

### `models/disk/`

| File | Role |
|---|---|
| `lightgbm_model.txt` | **LOAD THIS.** Production model. LightGBM native text. 150 features. |
| `feature_list_selected.json` | **LOAD THIS.** The 150 feature names in exact model input order. |
| `feature_list_full_2381.json` | **LOAD THIS.** The full 2,381-name extraction schema, in extractor order. Needed to compute subset indices. |
| `metadata.json` | **READ `threshold` ONLY** → `0.5010602922493019`. Rest is documentation. |
| `importance_ranking.json` | **DO NOT LOAD.** Feature-selection evidence trail. Archival only. |

### `reference_data/`

| File | Role |
|---|---|
| `memory_sample.npy` | **LOAD THIS.** `(5000, 55)` float32. Required to construct the memory LIME explainer. See Section 8.1. |
| `disk_sample.npy` | **LOAD THIS.** `(5000, 150)` float32. Required to construct the disk LIME explainer. See Section 8.1. |

These cannot be regenerated from anything in this repo — the original training
matrices are gone. Treat them as irreplaceable inputs and commit them to version
control.

Thresholds are **not** 0.5. Never hardcode 0.5. Always read the threshold from
`metadata.json`. The memory threshold in particular (0.2337) is far from default and
using 0.5 instead would silently change classification behavior away from what was
actually validated.

---

## 4. THE FEATURE-NAMING TRAP — READ THIS TWICE

The disk model file `lightgbm_model.txt` has **generic internal feature names**:
`Column_0` through `Column_149`. Not `header_feat_11`, not `byte_entropy_247`.
This happened because it was trained on a raw numpy array rather than a named
DataFrame. The memory model `xgboost_model.json` happens to carry real semantic
names internally — but **do not rely on that difference**.

**Why this is dangerous:** if inference code assembles the input vector in the wrong
order, both libraries will still run and still return a confident-looking
probability. It fails silently. There is no exception, no warning, just wrong
answers forever.

**Mandatory rules, both pipelines, no exceptions:**

1. Feature names come from the JSON feature-list files. **Never** from a loaded
   model object. `booster.feature_name()` and `model.feature_names` are forbidden as
   name sources anywhere in this codebase, including in LIME and report code.
2. Build input vectors **positionally** as plain numpy arrays. Never pass a pandas
   DataFrame to `predict()` and never rely on name-based column matching.
3. For disk: compute the 150 subset indices **once at startup** by looking up each
   name from `feature_list_selected.json` against its index in
   `feature_list_full_2381.json`. Cache that integer index list. Reuse it on every
   inference. Never recompute per-request, never reorder.
4. At application startup, assert the loaded model's expected feature count matches
   the feature list length (memory: 55; disk: 150). Fail loudly at boot rather than
   silently mispredicting at runtime.

---

## 5. EXTRACTION LAYER — MEMORY

Input: raw memory dump (`.raw`, `.mem`, `.dmp`, `.vmem`).
Output: a 55-length float vector matching `feature_list.json` order exactly.

Use **Volatility 3** as a Python library (not subprocess shelling if avoidable).
The 55 features come from these plugin families:

- `pslist` → nproc, nppid, avg_threads, nprocs64bit, avg_handlers
- `dlllist` → ndlls, avg_dlls_per_proc
- `handles` → nhandles, avg_handles_per_proc, and per-type counts (nport, nfile,
  nevent, ndesktop, nkey, nthread, ndirectory, nsemaphore, ntimer, nsection, nmutant)
- `ldrmodules` → not_in_load, not_in_init, not_in_mem and their `_avg` variants
- `malfind` → ninjections, commitCharge, protection, uniqueInjections
- `psxview` → seven `not_in_*` counts plus seven `*_false_avg` variants
- `modules` → nmodules
- `svcscan` → nservices, kernel_drivers, fs_drivers, process_services,
  shared_process_services, interactive_process_services, nactive
- `callbacks` → ncallbacks, nanonymous, ngeneric

**Known hard problem — do not paper over this.** CIC-MalMem-2022 was generated using
**Volatility 2**. Some plugins changed output format between Vol2 and Vol3, and the
derivation of the `*_avg` / `*_false_avg` fields was never documented by the dataset
authors. What follows was established empirically against `reference_data/memory_sample.npy`
during planning — see BUILD_PLAN.md Part 2.1 for the evidence.

### 5.1 psxview — the largest single risk (14 of 55 features)

**Enumerated against the installed volatility3 2.28 — this is measured, not predicted.**
All nine required plugins exist: `windows.pslist`, `windows.dlllist`, `windows.handles`,
`windows.ldrmodules`, `windows.malfind`, `windows.psxview`, `windows.modules`,
`windows.svcscan`, `windows.callbacks`. (`ldrmodules`, `malfind` and `psxview` also
appear under `windows.malware.*` — same columns, newer canonical location.)

`windows.psxview.PsXView` emits exactly **four** enumeration columns —
`pslist`, `psscan`, `thrdscan`, `csrss` — against Vol2's seven. The mapping is therefore
fixed:

| Feature | Vol3 column | Status |
|---|---|---|
| `psxview.not_in_pslist` | `pslist` | available |
| `psxview.not_in_eprocess_pool` | `psscan` | available |
| `psxview.not_in_ethread_pool` | `thrdscan` | available |
| `psxview.not_in_csrss_handles` | `csrss` | available |
| `psxview.not_in_pspcid_list` | — | **gap → 0.0** |
| `psxview.not_in_session` | — | **gap → 0.0** |
| `psxview.not_in_deskthrd` | — | **gap → 0.0** |

Plus the three paired `_false_avg` variants — **six of the 55 features are permanently
zero.**

**Measured, and the impact is small.** Those six carry **0.2% of the model's total gain**.
Forcing them to 0.0 across all 5,000 reference rows changes **1 verdict in 5,000
(0.02%)** and leaves the distribution bimodal. The four training-constant features in 5.3
have **zero splits** in the model — a constant column yields no information gain, so it
is never selected, and what we emit for them cannot affect the prediction at all.

So the psxview gap is a disclosure item, not a correctness problem. Report it; do not
treat it as the reason memory verdicts are weak. The real reason is 5.4a.

Confirm these column names still hold when volatility3 is upgraded; build the mapping
from the installed source, never from Vol2 documentation.

### 5.2 Derived fields — established formulas

- `dlllist.avg_dlls_per_proc = dlllist.ndlls / pslist.nproc` — confirmed exact
  (median relative error 2.8e-8, float32 rounding only). Confidence: high.
- **Every `_avg` / `_false_avg` field divides by its own plugin's row count, never
  another plugin's.** `ldrmodules.*_avg` uses the ldrmodules row count (testing against
  `dlllist.ndlls` leaves a consistent 1.8% error). `psxview.*_false_avg` uses psxview's
  own union-of-sources process count (testing against `pslist.nproc` leaves a uniform
  2.27% error across five of seven columns — psxview sees ~2.3% more processes than
  pslist because psscan finds terminated ones). Confidence: moderate.
- `malfind.protection` is the **sum of Volatility 2's numeric protection *index***, not
  the Win32 constant. Mean protection ÷ mean ninjections ≈ 6.0, and index 6 in Vol2's
  `PROTECT_FLAGS` list is `PAGE_EXECUTE_READWRITE` — exactly what malfind hits.
  `PAGE_EXECUTE_READWRITE` as a Win32 constant is 0x40 = 64, which does not fit. Vol3
  emits protection as a *string*, so build an explicit string → Vol2-index table.
  Confidence: **moderate — this reading is inferred, and must be recorded in
  `extraction_gaps` as inferred even when a value is emitted.**
- `pslist.nppid` — most likely a count of *distinct* PPIDs (mean 14.7 against nproc 41.5),
  but "processes with a live parent" also fits. Not resolvable from the reference data.
  Confidence: moderate.
- `handles.avg_handles_per_proc` and `pslist.avg_handlers` are near-identical but diverge
  on some rows by up to 168 — two different denominators for the same numerator. Map both
  to `handles.nhandles / pslist.nproc` and disclose that they are not independently
  derivable. Confidence: moderate.
- `malfind.uniqueInjections` — fractional (max 68.25), so not a count, and not
  `ninjections/nproc` (12× off). Best hypothesis is injections per *injected* process.
  **Unresolved** — emit the best available reading and record it as inferred.

### 5.3 Fields that are constant in the training data

These are dead or near-dead inputs. They are documented here so nobody "fixes" them:

| Field | Training value | Reality |
|---|---|---|
| `pslist.nprocs64bit` | always 0 | The dataset was captured on a 32-bit VM. **Emit the honest value from the dump anyway** (~40 on a modern x64 host) — hard rule 8 governs. The OOD check in 5.4 is what covers the resulting out-of-range input. |
| `handles.nport` | always 0 | The `Port` object type is XP/2003-era and does not exist on modern Windows. Emitting 0 is both correct and training-consistent. |
| `svcscan.interactive_process_services` | always 0 | Vol3 does expose `SERVICE_INTERACTIVE_PROCESS`, so a real dump may produce a nonzero value the model has never seen. Emit honestly. |
| `callbacks.ngeneric` | always 8.0 | Constant, not zero. The model learned nothing from it. |
| `modules.nmodules` | ∈ {137, 138} | A single OS build. A real dump gives ~400. |

### 5.4a What the memory model actually keys on — measured

Four features carry essentially the whole decision:

| Feature | gain | benign median | malware median |
|---|---:|---:|---:|
| `svcscan.nservices` | 3346 | 395 | 389 |
| `handles.nmutant` | 3238 | 366 | 259 |
| `svcscan.shared_process_services` | 3133 | 118 | 116 |
| `svcscan.kernel_drivers` | 2317 | 222 | 221 |
| *next feature down* | *39* | | |

An 80× cliff after the fourth. Three of the four are **counts of installed services and
drivers** — properties of how a machine is *configured*, not of what malware *does* — and
their class medians differ by 1–6 while separating almost perfectly. That only happens
when the two classes are tight clusters at slightly different values, i.e. the benign and
malicious captures came from differently configured VMs and the model learned to tell the
**VMs** apart.

Meanwhile the genuinely behavioural features overlap almost completely between classes:
`malfind.ninjections` 4 vs 3 (100% overlap), `ldrmodules.not_in_load` 74 vs 46 (99.9%),
`psxview.not_in_pslist` 0 vs 1 (100%). `malfind.ninjections` is actually *higher* in the
benign group.

And every dominant feature is out of range on a modern host: `svcscan.nservices` trains on
[195, 395] where real Win10/11 gives ~600; `kernel_drivers` [108, 222] vs ~350;
`shared_process_services` [65, 118] vs ~180; `handles.nmutant` [168, 565] vs ~900.

**Consequence: on a real dump the memory model's probability is not trustworthy.** This is
the dataset artifact `models/memory/metadata.json` already warns about, now with a
mechanism. It is not fixable here — retraining is out of scope (hard rule 7) — so the
memory report must be **evidence-led, not verdict-led**. See 9.6.

### 5.4 Out-of-distribution check — MANDATORY

CIC-MalMem-2022 was captured from **one Windows build on one VM configuration**, and
`reference_data/memory_sample.npy` proves it: `modules.nmodules` spans two values,
`callbacks.ngeneric` never varies, `malfind.ninjections` never drops below 1. A real
Windows 11 x64 dump lands past the outermost split threshold the trees ever learned on
most features. Tree models extrapolate as a constant beyond their training range, so the
model will return a confident-looking probability that is **essentially arbitrary**. The
1.0000 test AUC says nothing about this, because the test set came from the same VM.

So, on every memory analysis:

1. Compare each extracted feature against its per-column min/max in
   `reference_data/memory_sample.npy`.
2. Count how many of the 55 fall outside that range, and store the count and the field
   names on the result.
3. Surface it in the UI and in the report: *"N of 55 features fall outside the range
   observed in the training data; this verdict is extrapolation and should be treated as
   low-confidence."*
4. Include it in the report's limitations section alongside the saturation caveat.

This is not optional and not a stretch goal. Without it the memory pipeline demos
beautifully on a CIC-MalMem sample and produces meaningless output on a real dump, with
nothing to distinguish the two cases.

### 5.5 Mechanics

- Build the mapping as **data** — a dict of field → `(plugin, extractor_fn, confidence)` —
  so the gap list is generated from the table rather than hand-maintained, and it is
  impossible to add a field without declaring its confidence.
- Where a Volatility 3 equivalent is uncertain or missing, emit `0.0` and record the
  field in `extraction_gaps`.
- `extraction_gaps` entries are `{field, reason, plugin, confidence}` — not bare names —
  so the report can explain *why*. Fields whose value is emitted but whose derivation is
  inferred (`malfind.protection`, `malfind.uniqueInjections`, the `_avg` family) also
  belong in the list, flagged as inferred rather than missing.
- Surface `extraction_gaps` in the report as a stated limitation. Do not hide it.
- Do **not** invent plausible-looking values to fill gaps. A zero with a disclosure
  is honest; a fabricated number is not.
- Write a small script that runs the extractor against a known memory dump and prints
  each of the 55 values next to that column's training min/max, so they can be eyeballed
  before trusting the pipeline end to end.

### 5.6 volatility3 cannot auto-detect a 32-bit PAE page directory — worked around

**Measured against volatility3 2.28.0 on a Windows 10 x86 capture.** Stock automagic
fails on every 32-bit PAE image, and the stock `vol` CLI fails identically, so this is
upstream and not a harness problem:

```
No suitable kernels found during pdbscan
Unsatisfied requirement plugins.Info.kernel.layer_name
```

`WindowsIntelStacker.stack` guards against Windows' small dummy page tables by reading
the candidate's 4 KB page and discarding it if fewer than 10 pointers are valid
(`automagic/windows.py`, `page_table_is_dummy`). **A PAE page-directory-pointer table
has exactly four entries by architecture.** So every genuine PAE DTB is thrown away, no
Intel layer is ever built, and `determine_valid_kernel` then has no layer to scan.

Confirmed on the sample capture: the real DTB is at `0x1a8000`, holds exactly 4 valid
pointers, and is rejected. Constructing `WindowsIntelPAE` at that offset by hand resolves
`ntkrpamp.pdb` immediately with the kernel at `0x8186c000`, and all nine plugins then run.

`extractors/memory.py:find_pae_dtb` and `build_context` do exactly that. Stock automagic
is still tried first, so 64-bit images and crash dumps keep the supported path; the manual
construction is the fallback. Do not "simplify" this away — without it the memory pipeline
cannot read a 32-bit dump at all, and 32-bit is the configuration closest to what
CIC-MalMem-2022 was captured on.

Note also that a VMware `.vmem` whose `.vmss` reports `regionsCount == 0` makes
`VmwareLayer` raise `VmwareFormatException: VMware VMEM is not split into regions`. That
is not an error condition — it means memory is one flat block and the `.vmem` should be
read directly as a raw image, which is what the fallback does.

Volatility 3 resolves Windows kernel symbols by downloading PDB-derived ISF JSON from
`downloads.volatilityfoundation.org` on first encounter with an unseen build. On an
offline machine memory extraction fails with a confusing symbol error. **Pre-populate the
symbol cache** for the builds being analysed, ship it alongside the app, and document it.

**Measured: 3.7 minutes** for all nine plugins on a 2 GB Windows 10 x86 capture (78
processes, 34,323 handles), symbol cache already warm. The first run on an unseen build
adds ~4 minutes of ISF download. Earlier drafts of this file guessed 15–45 minutes;
that was pessimistic, but the runtime scales with dump size and process count and a
large multi-socket capture will be far slower. Hard rule 10 still stands — say minutes,
never seconds — and keep the per-plugin progress indicator.

---

## 6. EXTRACTION LAYER — DISK

Input: raw disk image (`.dd`, `.raw`, `.img`, `.E01`, `.EX01`).
Output: for each candidate PE file found, a 2,381-length vector reduced to the 150
selected features.

Pipeline:
1. Open the image with `pytsk3` (raw) or `pyewf` + `pytsk3` (E01). The pip
   distribution for `import pyewf` is **`libewf-python`**, not `pyewf` — there is no
   PyPI package by that name. If `libewf-python` will not build on Windows, drop
   `.E01`/`.EX01` from the upload allowlist rather than fighting it; raw images cover
   every demo case.
2. Walk the filesystem. For each regular file, read the first bytes and check for the
   `MZ` DOS header, then confirm the `PE\0\0` signature at the offset in the DOS
   header. Do not trust file extensions.
3. For each confirmed PE, read the full file bytes into memory.
4. Run through EMBER's `PEFeatureExtractor(feature_version=2).feature_vector(bytes)`
   → 2,381 float32 values.
5. Subset to the 150 selected indices (cached at startup — Section 4, rule 3).
6. Predict. One verdict **per file**, not per image.

**Disk results are a list, not a single verdict.** A disk image can contain hundreds
of executables. The result schema, the dashboard, and the report all need to handle
"N files scanned, M flagged" rather than one boolean.

**Practical caps (implement these, make them configurable):**
- Max files analyzed per image (default ~500) — prevents a huge image from hanging
  the job queue.
- Max individual file size to vectorize (default ~64 MB).
- Skip files whose SHA-256 already appeared in this run (dedupe).
- Record how many files were skipped and why; surface that in the report.

### EMBER environment setup — required, non-obvious

`pip install ember` alone will not work. Reproduce exactly what was done during
training:

```
pip uninstall -y lief
pip install lief
pip install git+https://github.com/elastic/ember.git --no-deps
```

The originally pinned `lief==0.11.5` has no Python 3.12 wheel and fails to build.

Use the tarball URL rather than `git+https://` — setup then works without git on PATH:

```
pip install https://github.com/elastic/ember/archive/refs/heads/master.tar.gz --no-deps
```

**`ember/features.py` needs THREE patches, not one.** `models/disk/metadata.json` records
only the FeatureHasher one; the other two were evidently applied during training and
never written down. All three live in `scripts/patch_ember.py`, are applied at install
time, and are verified at startup. None changes a feature value — they only make
extraction run at all.

| Patch | Cause |
|---|---|
| `featurehasher` | elastic/ember PR #109 — detailed below. |
| `lief_errors` | lief 1.0 removed `bad_format`, `bad_file`, `pe_error`, `parser_error`, `read_out_of_bound`. `raw_features` builds a tuple of them and raises `AttributeError` before parsing anything. The patch resolves whichever names the installed lief still exposes and always includes `RuntimeError`. Catch-set only; parse behaviour unchanged. |
| `np_int` | `np.int` was removed in numpy 1.24. Pinning numpy back isn't available — xgboost 3.2.0 and sklearn 1.6.1 both need newer. `int` is what the alias always meant, so the dtype is identical. |

**Do not `import ember`.** `ember/__init__.py` pulls in pandas, lightgbm and
`sklearn.model_selection` for ember's training helpers, none of which this project uses —
and pandas' C extensions are blocked outright by Windows Application Control on the
target machine. Load `ember/features.py` standalone via
`scripts/patch_ember.py:load_features()`; it needs only re/lief/hashlib/numpy/os/json.
That keeps pandas out of the dependency tree entirely, which suits hard rule 3.

The FeatureHasher bug (elastic/ember PR #109). This line:

```python
FeatureHasher(50, input_type="string").transform([raw_obj['entry']]).toarray()[0]
```

must become:

```python
FeatureHasher(50, input_type="string").transform([[raw_obj['entry']]]).toarray()[0]
```

Without it, extraction raises `ValueError: Samples can not be a single string`.

**Apply the patches at install time, not at startup.** `scripts/patch_ember.py` rewrites
`ember/features.py` once, as part of environment setup. At application startup, only
**verify** the patched strings are present and refuse to boot if they are not. Rewriting
site-packages during startup is fragile — read-only installs, restricted service
accounts, and a write race between concurrent workers all break it, and none of those
failures are obvious. Verify-and-refuse gives the same self-healing outcome with no
runtime mutation. Log the patch state either way.

**Never let lief parse a PE inside the Flask process.** lief 1.0 is native code being
fed hostile input by design; a malformed PE can segfault the interpreter and take down
every other running job, not just the one that hit it. Run EMBER vectorization in a
`concurrent.futures.ProcessPoolExecutor` with a per-file timeout, so a crash costs one
worker. This is stdlib — it is not the Celery/Redis that Section 10 rejects.

**Also record this caveat in every disk report:** the installed `lief` (1.0.x)
differs from the version EMBER's extractor was validated against (0.9.0), so feature
values may differ slightly from the official benchmark. This was accepted during
training and must be disclosed, not hidden.

---

## 7. INFERENCE LAYER

Two loaders, two predict paths. Do not abstract them into one clever generic class —
the libraries are not interchangeable and forcing them together creates exactly the
kind of silent-mismatch bug Section 4 warns about.

**Memory:**
```
booster = xgb.Booster(); booster.load_model("models/memory/xgboost_model.json")
prob = booster.inplace_predict(vec.reshape(1, -1))[0]
verdict = prob >= 0.2336726188659668
```

**Disk:**
```
booster = lgb.Booster(model_file="models/disk/lightgbm_model.txt")
prob = booster.predict(vec_150.reshape(1, -1))[0]
verdict = prob >= 0.5010602922493019
```

Load both models **once** at application startup, hold them in module-level state.
Never load per request — model load is expensive and per-request loading will make
the app unusable under concurrent uploads.

**Use `inplace_predict` for the memory model, never `DMatrix`.** The memory model
carries its 55 semantic feature names internally, and `Booster.predict(DMatrix(arr))`
validates them — a positional numpy array raises `ValueError: data did not contain
feature names`. `inplace_predict` skips that validation, which is what makes hard rule 3
workable here. Verified.

**Memory tree count — measured, resolved.** `xgboost_model.json` carries
`num_trees=173` but `best_iteration=122`, so which trees get used was ambiguous. Under
xgboost 3.2.0 the `inplace_predict` default is **all 173 trees** (verified identical
output to `iteration_range=(0, 173)`), and 123 trees flips **0 of 5,000** verdicts on the
reference set. Pin `iteration_range=(0, 173)` explicitly anyway — the default is not
contractual across versions and the assertion is free.

**The disk subset index list is NOT ascending.** The 150 selected names map to indices
spanning 1…2377 in non-monotonic order. `vec_2381[sorted(idx)]` and `vec_2381[idx]` both
produce a valid 150-vector and both predict without raising. Only one is right. Assert
`idx != sorted(idx)` at startup — it genuinely is not sorted, so the assertion catches an
accidental sort.

**Startup verification — the reference-distribution check.** A feature-count assertion
catches a *missing* column; it does not catch a *permuted* one. Run all 5,000 rows of the
matching file in `reference_data/` through each model and confirm the probability
distribution is bimodal and splits roughly 50/50 at the operating threshold — both
training sets were balanced.

Measured, so the expected values are known rather than guessed:

| | above threshold | in 0.05–0.95 mid-band |
|---|---|---|
| memory, correct order | 0.493 | 0.001 |
| memory, columns scrambled | **0.000** | **0.999** |
| disk, correct order | 0.490 | 0.129 |
| disk, columns scrambled | 0.297 | 0.849 |

**Keep a scrambled-column control in the test suite permanently**, not as a one-off.
Measured over 200 random permutations, the check rejects **200/200 on both models**. The
failure signature varies though — some permutations squash everything into 0.04–0.20,
others push 99% above the threshold — so assert *"the startup check refuses this"*, never
a fixed statistic.

**Know its limit.** The check catches wholesale reordering. It does **not** catch small
transpositions: swapping two adjacent columns is caught in only **5 of 54** cases on
memory and **0 of 149** on disk, because the aggregate distribution barely moves. So a
two-field mix-up in an extractor mapping will sail straight through.

The guard against *that* is structural, not statistical, and it is binding on Section 5:
**build the vector as a dict keyed by feature name, then emit it in `feature_list.json`
order.** Never hand-sequence the fields, and unit-test that the emitted order equals the
JSON order. For disk this is already the case — the subset indices are derived from the
names — and an `np.arange(2381)` probe pins it exactly.

---

## 8. EXPLAINABILITY — LIME

LIME runs **per prediction, at inference time**. It is not part of training.

Setup, once at startup, per pipeline:
- Build `LimeTabularExplainer` with the saved reference training samples in
  `reference_data/` (Section 8.1), the feature names from the JSON list, and
  `class_names=["Benign", "Malware"]`.
- Wrap the model as a single `predict_proba`-shaped function returning
  `[[P(benign), P(malware)]]`.
- Cache the explainer. Constructing it is the expensive part.

Per prediction:
- `explain_instance(vec, predict_fn, num_features=15)` — ask for more than you'll
  display.
- Take **`as_map()[1]` → `[(feature_index, weight), ...]`** and resolve each index
  against your own JSON feature list. Do **not** use `as_list()`: it returns discretized
  *condition strings* like `"malfind.ninjections > 5.00"`, not bare feature names, so a
  `MEANINGS[name]` lookup against it misses every single time and yields an empty
  findings list that looks exactly like "nothing matched." Going through `as_map()` also
  satisfies hard rule 2 for free, since the names come from the JSON list rather than
  from anything LIME or the model produced.
- **Never show raw LIME weights to the user.** Pass them through the lookup table in
  Section 9 and display only matched, human-meaningful findings.

Only run LIME when the verdict is malicious. Benign results don't need an
explanation and it wastes runtime.

For disk: LIME runs against the **150-feature** space, not 2,381. That was a
deliberate design goal of the feature reduction.

### 8.1 Reference training data — `reference_data/`

LIME cannot be built without these. They are samples of the actual training data
each model was fitted on, exported from the training notebooks. They are the only
surviving copy — the original training matrices no longer exist anywhere else.

| File | Shape | dtype | Notes |
|---|---|---|---|
| `reference_data/memory_sample.npy` | `(5000, 55)` | float32 | 5,000 rows sampled from the memory model's training set. Column order matches `feature_list.json` exactly. |
| `reference_data/disk_sample.npy` | `(5000, 150)` | float32 | 5,000 rows sampled from the **feature-selected** training matrix. Column order matches `feature_list_selected.json` exactly — this is the 150-feature space, NOT the full 2,381. |

Load with `np.load(path)`. Pass directly as `training_data` to
`LimeTabularExplainer`. Load once at startup alongside the models; never per request.

Verified properties — assert these at startup and fail loudly on mismatch:
- No NaN, no Inf in either file
- `memory_sample.shape[1] == 55` and `disk_sample.shape[1] == 150`
- Column count must equal the corresponding feature-list length

Expected characteristics, so they are not mistaken for corruption:
- `memory_sample.npy` contains **3 all-zero columns and 4 zero-variance columns** —
  assert both numbers, because they differ. All-zero: `pslist.nprocs64bit`,
  `handles.nport`, `svcscan.interactive_process_services`. The fourth zero-variance
  column is `callbacks.ngeneric`, constant at **8.0**, not 0. Asserting "exactly 3
  zero-variance columns" fails at boot. These features are genuinely constant across
  CIC-MalMem-2022. This is correct data, not a defect. LIME tolerates zero-variance
  features; do not filter or "repair" them — but do unit-test that LIME's quartile
  discretizer does not degenerate on them, and fall back to `discretize_continuous=False`
  if it does.
- `disk_sample.npy` spans roughly −4.5e7 to 4.29e9. EMBER features include raw
  unscaled values (virtual addresses, timestamps, sizes). **No scaler was used
  anywhere in training** — tree models split on raw values. Do not add
  normalization at inference or LIME time; it would silently invalidate both the
  predictions and the explanations.

---

## 9. REPORTING LAYER — WHAT MAKES THIS WORTH USING

A bare "malicious, 94% confident" is not a forensic report. Three layers turn model
output into something an analyst can act on. All three are lookup tables and simple
functions — **no additional models**.

### 9.1 Feature → forensic meaning lookup

A static table mapping feature names to plain-English significance. Build it as a
Python dict in one module.

**Memory examples:**
- `malfind.ninjections`, `malfind.commitCharge` → injected executable memory regions;
  indicates process injection
- `ldrmodules.not_in_load`, `not_in_init`, `not_in_mem` → module present in memory but
  absent from PEB loader lists; indicates DLL hiding or process hollowing
- `psxview.not_in_pslist`, `not_in_eprocess_pool` etc. → process visible to one
  enumeration method but hidden from another; classic rootkit behavior
- `handles.nmutant` → mutex usage; malware commonly creates named mutexes for
  single-instance checks
- `svcscan.kernel_drivers`, `svcscan.nservices` → service/driver registration; possible
  persistence
- `callbacks.ncallbacks`, `nanonymous` → kernel notification routines; kernel-level
  persistence

**Disk examples (map by feature group prefix):**
- `byte_histogram_*` → byte-value frequency distribution; skew toward high-entropy or
  non-ASCII ranges is consistent with packing, encryption, or embedded compressed data.
  **26 of the 150 selected features are byte_histogram — do not omit this group.**
- `byte_entropy_*` high values → packing, encryption, or obfuscation
- `imports_hash_*` → suspicious API import patterns (injection, hooking, process
  manipulation capability)
- `section_feat_*` → anomalous section characteristics, e.g. writable+executable
- `header_feat_*` → PE header anomalies, suspicious timestamps, unusual subsystem
- `string_feat_*` → suspicious embedded strings (URLs, IPs, encoded commands)
- `datadirectory_feat_*` → import/resource/relocation table anomalies
- `general_feat_*` → missing digital signature, size/overlay mismatch

The selected 150 break down as: imports_hash 33, byte_histogram 26, byte_entropy 24,
string_feat 20, header_feat 15, section_feat 15, datadirectory_feat 13, general_feat 4,
**exports_hash 0**.

**Not every disk group is a hash.** Three of them are named, per-index recoverable
scalars in EMBER v2 and may be reported precisely:

- `general_feat_0…9` — size, vsize, has_debug, exports, imports, has_relocations,
  has_resources, has_signature, has_tls, symbols
- `datadirectory_feat_0…29` — the 15 data directories in order, two values each
  (size, virtual address). The certificate-table entries directly ground the
  unsigned-binary indicator.
- `section_feat_0…4` — section count, zero-size count, nameless count, RX count,
  W count. `section_feat_3` and `section_feat_4` are literally the readable+executable
  and writable section counts, which is what the "writable+executable" wording wants.

**Verify the exact index order against the installed ember source before relying on
any of this**, then use it. The remaining groups — `imports_hash`, `exports_hash`, and
the hashed portions of `header_feat` and `section_feat` — are positional hash buckets
where meanings are **group-level, not per-index**. Hard rule 15 binds those groups
unchanged. Be honest about the granularity in the report wording — say "byte entropy
distribution indicates packing," not a fake precise claim about index 247 specifically.

### 9.2 Indicator tags + MITRE ATT&CK

A static lookup table mapping indicator categories to ATT&CK techniques. No model,
no inference — this is a human-authored interpretation layer.

| Tag | MITRE | Confidence | Typical triggering features |
|---|---|---|---|
| Process Injection | T1055 | high | `malfind.ninjections`, `malfind.commitCharge`, `malfind.uniqueInjections`, `malfind.protection` |
| Process Hollowing | T1055.012 | high | `ldrmodules.not_in_load` combined with `malfind` activity |
| Obfuscated / Packed Files | T1027 | moderate | `byte_entropy_*` and `byte_histogram_*` groups, section entropy |
| Rootkit / Hidden Artifacts | T1014 | high | `psxview.not_in_*` family, `ldrmodules.not_in_mem` |
| Hidden Modules / DLL Concealment | T1055.001 | high | `ldrmodules.not_in_init`, `not_in_mem`, their `_avg` variants |
| Persistence — Services | T1543.003 | high | `svcscan.nservices`, `kernel_drivers`, `nactive` |
| Persistence — Boot/Logon Autostart | T1547 | moderate | `svcscan` autostart-related counts |
| Kernel Callbacks / Driver Persistence | T1543.003 / T1014 | moderate | `callbacks.ncallbacks`, `nanonymous`, `ngeneric` |
| Defense Evasion — Unsigned Binary | T1553.002 | **low** | `general_feat_*` signature fields, certificate `datadirectory_feat_*` |
| Suspicious API Imports | T1106 | moderate | `imports_hash_*` group |
| Credential API Hooking | T1056.004 | low | `handles` anomalies, `imports_hash_*` group |

**Three IDs were corrected from an earlier draft of this file — do not revert them:**

- **T1179 is deprecated** in current ATT&CK; it was retired and split, with hooking
  behaviours landing largely under T1056.004. Citing a revoked ID dates the report, and
  "handles anomalies" is thin evidence for hooking regardless — hence `confidence: low`.
- **T1547.006 is *Kernel Modules and Extensions*, platforms Linux and macOS.** It does
  not cover Windows kernel-callback or driver persistence. T1543.003 and T1014 do.
- **T1574 is *Hijack Execution Flow*** — search-order hijacking and side-loading, i.e.
  loading the *wrong* DLL. `ldrmodules.not_in_init` / `not_in_mem` is DLL *concealment*,
  a different behaviour; T1055.001 fits.

**Unsigned-binary is `confidence: low` deliberately.** T1553.002 is about *subverting*
code signing — stolen certificates, self-signing — not about a binary simply lacking a
signature, and a large fraction of legitimate software is unsigned. Word it as an
observation, never as a technique attribution.

**Emit ALL matched tags, not one.** A single artifact commonly exhibits several
behaviors simultaneously — injection plus hidden modules plus service persistence is
an ordinary combination, not an edge case. Picking a single "best" tag discards real
findings, and the severity function in 9.3 depends on counting matched high-risk
categories, so collapsing to one breaks it. Deduplicate identical techniques; keep
the rest.

**Confidence differs sharply between the two pipelines. Reflect that in wording.**

- **Memory features are semantically named.** `malfind.ninjections` unambiguously
  measures injected memory regions. Mapping it to T1055 is well-grounded. Mark these
  `confidence: high` and word them directly: "Injected executable memory regions
  detected in N processes (T1055 — Process Injection)."
- **Disk features are positional hash buckets.** `imports_hash_1198` is bucket 1198
  of a 1,280-bin feature hash. You **cannot** know which specific API landed there —
  hash collisions make that unrecoverable. Mark these `confidence: moderate` and word
  them at group level only: "Import table characteristics contributed significantly
  to this classification, consistent with suspicious API usage (T1106)." **Never**
  write "the file imports CreateRemoteThread" — that is a fabricated claim the data
  cannot support, and an examiner who understands feature hashing will catch it.

Every report containing MITRE references must carry this line in the limitations
section: *MITRE ATT&CK mappings are inferred from statistical feature indicators, not
from observed runtime behavior. They indicate which technique categories the
detection is consistent with, and should be treated as investigative leads rather
than confirmed technique attribution.*

Store per mapping: technique ID, technique name, confidence level, and the features
that triggered it. Link to `https://attack.mitre.org/techniques/<ID>/`.

Keep the table small and defensible. Do not expand it to cover more of ATT&CK than
the feature semantics genuinely support — 55 named memory features and 150 hashed
disk features cannot ground 600+ sub-techniques, and reaching further would make the
report less credible, not more.

### 9.3 Severity scoring

```
disk:   severity = f(model_confidence, count and weight of matched high-risk tags)
memory: severity = f(observed indicators, count and weight of matched high-risk tags)
                   with model_confidence as at most a tie-breaker — see 9.6
```
Buckets: Low / Medium / High / Critical. Keep the function simple, deterministic, and
**visible in the report** ("High — model confidence 0.94, 3 high-risk indicator
categories matched"). An analyst must be able to see why something scored what it
scored. Do not make this a black box on top of a black box.

### 9.4 Report structure (PDF + dashboard)

1. **Header / chain of custody** — filename, SHA-256 of the uploaded artifact, size,
   upload timestamp, analyst identity, job ID, analysis duration
2. **Executive summary** — verdict, severity, one-paragraph plain-English summary
   auto-composed from the matched tags. Written for someone non-technical.
3. **Verdict detail** — model probability, operating threshold used, model type and
   version (`disk` or `memory`)
4. **Findings** — the matched forensic indicators, each with: what was observed, why
   it matters, indicator tag, MITRE reference
5. **For disk images:** per-file findings — see 9.5 below. This is the most
   operationally important part of a disk report and must not be reduced to a
   verdict count.
6. **Scope & limitations** — mandatory section, always present:
   - files skipped and why (caps, size, unreadable)
   - `extraction_gaps` for memory (Section 5), separating fields that are *missing*
     from fields whose derivation is *inferred*
   - the `lief` version caveat for disk
   - for memory results, the **out-of-distribution count** from Section 5.4 —
     "N of 55 features fall outside the range observed in the training data"
   - for memory results, a one-line statement that the underlying benchmark dataset
     shows unusually high separability and that real-world performance may differ

   The section renders unconditionally, with explicit "none recorded" text when a list
   is empty. A test must fail if any mandatory string is absent.
7. **Appendix** — full feature contribution list, environment/library versions,
   model metadata

### 9.6 Memory reports are evidence-led, not verdict-led

Because of 5.4a the memory model's probability is weak evidence on any dump that is not
from the CIC-MalMem capture VM. The extracted Volatility observations are **not** weak —
they are direct measurements of the dump and are true regardless of what the model says.
So the memory report inverts the usual order.

**Lead with what was observed.** Injected executable regions and the processes holding
them; modules in memory but absent from the PEB loader lists; processes visible to one
enumeration method and not another; kernel callbacks with unbacked modules; registered
services and drivers. Each with counts and, where the plugin exposes them, process names
and PIDs. This is the substance of the report and it is what an analyst acts on.

**Demote the model score to a secondary triage signal.** Still show it — it is the
project's trained model and it belongs there — but next to the OOD count from 5.4, never
as the headline. When the four dominant features of 5.4a fall outside their training
range, print that plainly instead of a confident percentage:

> Model verdict: not reliable for this capture. 4 of the 4 features this model depends on
> most fall outside the range it was trained on.

**Severity for memory comes from the observed indicators, not the probability.** Three
hidden modules plus injected memory is High because of what was found. The probability
may contribute, but it must never be the sole driver. Disk severity is unaffected and
stays verdict-led — that pipeline has no equivalent problem.

This is not a workaround for a broken model. Evidence-first is how memory forensics is
actually practised, and it makes the report useful even when the model is not.

### 9.5 Per-file findings for disk images — locating the artifact

This system is **triage, not final analysis**. Its job is narrowing hundreds of PE
files down to the few worth a human's attention, and then handing the analyst enough
information to go straight to those files in their own tooling. A verdict without
location data is operationally useless.

For **every flagged file**, capture and report:

| Field | Why the analyst needs it |
|---|---|
| Full path inside the image | e.g. `/Windows/System32/svchost.exe` — where to look. Include the volume/partition identifier if the image has multiple. |
| **SHA-256 of the file** | The pivot point for VirusTotal, threat-intel lookups, and cross-case correlation. Distinct from the uploaded image's hash. |
| MD5 of the file | Still required by many legacy forensic tools and hash sets. |
| File size in bytes | Triage and comparison against known-good copies. |
| MFT record / inode number | Lets the analyst jump directly to the entry in Autopsy, FTK, or TSK. |
| MACB timestamps | Modified / Accessed / Changed / Born, from the filesystem metadata. Essential for timeline reconstruction. |
| Byte offset of file data within the image | Enables direct carving. Include where `pytsk3` exposes it; omit the field rather than guessing if unavailable. |
| Model probability + severity + matched indicators | Why it was flagged. |

Sort most-severe first. Also record files that were **skipped** (size cap, file-count
cap, unreadable, parse failure) with the reason — an analyst must be able to tell the
difference between "scanned and clean" and "never examined."

Include a short standing note that flagged files warrant manual verification, and
that this tool narrows scope rather than producing conclusive findings. Make the
per-file table exportable (CSV or JSON) alongside the PDF so results can be fed into
other tooling.

The limitations section is what makes this credible rather than a toy. Never omit it,
never make it optional, never bury it.

---

## 10. WEB APPLICATION

**Stack — use exactly this. Do not add to it.**

- Flask (routing, auth), SQLAlchemy (ORM), PostgreSQL (SQLite acceptable in dev)
- **Flask-Executor** for background jobs — a thread pool, used as the job *supervisor*
- **`concurrent.futures.ProcessPoolExecutor`** (stdlib) for the extraction work itself.
  Two reasons, both load-bearing: lief parses hostile PEs in native code and a segfault
  would kill the whole Flask process, and Volatility 3 is CPU-bound Python so a thread
  pool lets the GIL serialize jobs and starve the web thread. This is not the
  Celery/Redis rejected below — it ships with Python and adds no infrastructure.
- HTML5 / CSS3 / Bootstrap / vanilla JS / Chart.js — vendored as static files, not CDN
  (this is an offline tool)
- **ReportLab** for PDF. Not WeasyPrint: it needs GTK/Pango/Cairo native DLLs on
  Windows and is a well-known install failure. ReportLab is pure Python. Decided.
- PyTest

**Explicitly rejected — do not introduce:** Celery, Redis, Docker, Nginx, Gunicorn,
React, any SPA framework, any cloud service, any external API. This was a deliberate
scoping decision to keep a two-person semester project shippable. Adding
infrastructure is scope creep, not improvement.

**Data flow:**

1. `POST /upload` → validate extension/size → stream to disk (never load a
   multi-GB image fully into memory) → compute SHA-256 → create job row, status
   `PENDING`
2. Detect artifact type. **Positive identification only.** A raw disk image has an MBR
   `0x55AA` at offset 510 or `EFI PART` at 512; a raw memory dump has no reliable magic
   at all — crash dumps carry `PAGEDUMP`/`PAGEDU64`, but `.raw`/`.mem`/`.vmem` carry
   nothing. So absence of a disk signature is **not** evidence of a memory dump. Fall
   back to extension, and where that is ambiguous ask the user. Expect asking to be the
   common path for `.raw`.
3. Dispatch to Flask-Executor; status → `RUNNING`
4. Extract → subset/order features → predict → LIME if malicious → tag → score
5. Persist results; status → `COMPLETED` (or `FAILED` with a readable error)
6. Frontend polls `GET /jobs/<id>/status`
7. `GET /jobs/<id>/report.pdf` renders on demand from stored results

**Schema sketch:** `users`, `jobs` (artifact metadata, hash, type, status, timings,
error), `results` (per-job verdict/confidence/severity; for disk, one row per file),
`findings` (per-result matched indicators + tags), `audit_log` (user, action,
timestamp, job). Design `results` around the disk shape first — it is the harder case —
and let memory use a single row.

**Operational constraints that bite in practice:**
- SQLite plus a thread pool running 30-minute jobs produces `database is locked`. Enable
  WAL mode and a 30s busy timeout in the engine `connect_args` from day one. Use
  `scoped_session`; never share a session between the request thread and a worker.
- Flask-Executor tasks run with no app context. Wrap every task body in
  `with app.app_context():` and `remove()` the scoped session in a `finally`.
- Werkzeug spools multipart bodies to a temp file, so a multi-GB upload needs **2× the
  image size** in free disk. Set `MAX_CONTENT_LENGTH`, run with `threaded=True`, and
  document this as a lab-tool constraint — Gunicorn and Nginx are out of scope, so there
  is no way around it.
- Detect jobs left `RUNNING` by a crashed process at next boot and mark them `FAILED`.

**Security — implement properly, this is a forensics tool:**
- Password hashing (`werkzeug.security` or `passlib`) — never plaintext
- CSRF protection on all state-changing forms
- Upload validation: extension allowlist, size cap, path traversal prevention on
  stored filenames
- Uploaded artifacts stored **outside** the web root, served never — only analyzed
- Parameterized queries everywhere (SQLAlchemy handles this; do not hand-build SQL)
- Session cookies: `HttpOnly`, `SameSite=Lax`, `Secure` when TLS is on
- Audit-log every upload, analysis, and report download
- Rate-limit uploads per user
- **Never execute an uploaded artifact.** Parse only. This system reads bytes; it does
  not run anything it ingests.

---

## 11. WHAT THIS PROJECT DOES NOT INCLUDE

State these as scope, not gaps:
- Live/real-time acquisition (analyst uploads an already-captured artifact)
- Malware family classification (replaced by indicator tagging + MITRE)
- Reverse engineering or disassembly
- Non-Windows malware
- Cloud deployment, containers, multi-node scale
- Integration with Autopsy or Volatility as external tools (Volatility 3 is used as a
  library internally, which is different)
- Anti-obfuscation beyond what packing detection infers

---

## 12. CODE STYLE

Write like an experienced developer shipping a real project under deadline, not like
a tutorial generator. Concretely:

- **Compact, specific identifiers.** `job`, `vec`, `probs`, `feat_idx`, `sev`,
  `pe_files`. Not `analysisJobDatabaseRecord`, not
  `extractedFeatureVectorForModelInference`.
- **Group related helpers in the same module.** One `extractors/memory.py` holding
  all its plugin parsers beats eleven single-function files. Don't build a deep
  package tree for a project this size.
- **No narration comments.** Delete "# Step 1: load the model", "# Now we predict",
  "# Helper function to...". Comment only where a reader would otherwise ask *why* —
  the ember patch, the threshold not being 0.5, the Volatility 2/3 mismatch, a
  non-obvious workaround. Those comments are valuable; restating what the next line
  plainly does is noise.
- **No preamble or summary blocks** at the top of files. No "This module provides..."
  docstring on every function. Docstrings on genuinely non-obvious public functions
  only.
- **Natural inconsistency is fine.** Real codebases have some functions returning
  dicts and others returning tuples, some early-return guard clauses and some
  nested ifs, occasional slightly-too-long functions. Don't sand everything into
  identical shape.
- **Handle errors where they actually occur**, with specific exceptions, not a
  blanket `try/except Exception` wrapper around every function.
- **Don't over-abstract.** No base classes with one subclass. No config-driven
  indirection for things that never change. No interface layer "for future
  extensibility" that will never be extended.
- Write the config, the constants, and the wiring the way someone who has been
  living in this codebase for two months would — direct, a bit terse, occasionally
  opinionated.

---

## 13. HARD RULES — VIOLATING THESE BREAKS THE SYSTEM

1. Never hardcode threshold `0.5`. Read from `metadata.json`. Memory `0.2336726188659668`,
   disk `0.5010602922493019`.
2. Never source feature names from a model object. Only from the JSON feature lists.
3. Never pass a DataFrame to `predict()`. Positional numpy arrays only.
4. Never merge the disk and memory pipelines.
5. Never load `models/memory/lightgbm_model.txt` — memory ships XGBoost.
6. Never assume disk ships XGBoost — disk ships **LightGBM**.
7. Never retrain, fine-tune, or "improve" the saved models.
8. Never fabricate a feature value to fill an extraction gap. Emit 0.0 and disclose.
9. Never execute an uploaded artifact.
10. Never claim "seconds" for raw-artifact analysis. It takes minutes. Say so.
11. Never present the memory pipeline's 1.0000 metrics without the dataset-saturation
    caveat.
12. Never omit the limitations section from a report.
13. Never apply scaling, normalization, or standardization anywhere. No scaler was
    used in training. Adding one at inference or LIME time silently corrupts both
    predictions and explanations without raising an error.
14. Never regenerate, resample, or "clean" the files in `reference_data/`. They are
    the only surviving copy of the training distributions.
15. Never claim a specific API, DLL, or string from a `imports_hash_*` /
    `exports_hash_*` feature. They are hash buckets; the original value is
    unrecoverable. Group-level wording only.
16. Never report a flagged disk file without its full path and SHA-256. A verdict
    the analyst cannot act on is worthless.
17. Never ship a memory verdict without the out-of-distribution count (Section 5.4).
    The training data is one VM configuration; on a real dump the model is
    extrapolating, and the report must say so.
18. Never sort the disk subset index list. It is genuinely non-monotonic, and sorting it
    silently produces wrong predictions.
19. Never take LIME findings from `as_list()`. Use `as_map()` indices resolved against
    the JSON feature list (Section 8).
20. Never parse an uploaded PE or run a Volatility plugin inside the Flask process.
    Extraction goes in a `ProcessPoolExecutor` — a native segfault must not be able to
    kill unrelated jobs.
21. Never cite MITRE T1179, T1547.006, or T1574 in this project's mappings. See the
    corrections in Section 9.2.
22. Never headline a memory report with the model probability. Memory reports lead with
    observed Volatility findings; the score is secondary and carries the OOD count with
    it (Sections 5.4a and 9.6).

---

## 14. BUILD ORDER

The step-by-step plan with per-step done-criteria, verification, and risk guards lives
in `BUILD_PLAN.md`. This is the summary.

0. Environment and repo: `git init`, venv on Python 3.11.9, pinned requirements,
   `scripts/patch_ember.py`, `scripts/check_env.py`. Do this before any app code —
   the point is to find out on day 1 whether `pytsk3` and `libewf-python` build here.
1. Project skeleton, config, DB models, migrations
2. Auth + upload + job records + audit logging (no analysis yet — get the plumbing solid)
3. Inference module: load both models, feature-list handling, index caching, startup
   assertions. **Test with hand-built vectors before any extractor exists.**
4. Disk extractor (ember env + patch, pytsk3/pyewf, PE discovery, vectorize, subset)
5. Memory extractor (Volatility 3, 55-field mapping, gap tracking)
6. Wire extractors → inference → persist results
7. LIME + lookup tables + tags + severity
8. Dashboard (Chart.js, per-file table for disk, polling)
9. PDF report generation
10. Tests, load test with concurrent uploads, docs

Step 3 before steps 4–5 is deliberate: prove the model layer is correct with
synthetic input before adding extraction complexity on top. If a bug appears later
you'll know it's in extraction, not inference.

---

## 15. VERIFICATION BEFORE CALLING ANYTHING DONE

- Startup asserts pass: memory model reports 55 features, disk reports 150
- `reference_data` asserts pass: no NaN/Inf, correct column counts, **3 all-zero and 4
  zero-variance** columns in the memory sample
- The 5,000 reference rows produce a bimodal, roughly 50/50 probability split through
  each model — the only check that catches a *permuted* feature order
- The disk subset index list has 150 entries in selected-list order and is not sorted
- The memory model's `iteration_range` is pinned explicitly and the choice is justified
- A hand-built 55-vector through the memory path returns a plausible probability
- A hand-built 150-vector through the disk path returns a plausible probability
- Feature-list order matches between JSON and what the extractor emits — verify by
  printing both side by side, not by assuming
- Disk extractor finds PE files in a test image and none are misidentified by
  extension alone; at least one extensionless PE is found and one misnamed non-PE
  rejected
- Memory extractor's `extraction_gaps` list is populated honestly, not empty by
  default, and distinguishes missing fields from inferred ones
- The out-of-distribution count appears on every memory result and in its report
- A report renders with all seven sections including limitations, and a test fails if
  any mandatory limitation string is missing
- Concurrent uploads don't corrupt job state
- Uploaded artifacts are not reachable via any URL

---

## 16. ENVIRONMENT — PINNED

**Python 3.11.9.** Not 3.13 — `pytsk3` and `lief` wheel coverage is the constraint, and
not the Windows Store build, which has site-packages redirection quirks.

Inference pins govern prediction semantics and are not negotiable:

```
xgboost==3.2.0          # matches models/memory/metadata.json library_versions
lightgbm==4.6.0         # matches models/disk/metadata.json
scikit-learn==1.6.1     # ember's FeatureHasher path depends on it
numpy>=1.26,<3
scipy>=1.11
lime==0.2.0.1           # unmaintained since 2020; the only real option. Test it
                        # against the chosen numpy/sklearn at step 3, not step 7
```

Forensics:

```
lief==1.0.0             # exactly. metadata records 1.0.0-d05b3499b as what produced
                        # the training features. NOT 0.11.5 (no py3.12+ wheel) and
                        # NOT 0.9.0 (what ember expects — hence the report caveat)
pytsk3
libewf-python           # the pip name for `import pyewf`
volatility3==2.28.0
```

Verified on the target machine: `lief`, `pytsk3`, `libewf-python` and `volatility3` all
install from prebuilt `cp311-win_amd64` wheels. **No MSVC toolchain is needed and E01
support is viable** — the main Step 0 unknown, resolved.

**No pandas.** See Section 6.

Web: Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF, Flask-Executor, Flask-Migrate,
Flask-Limiter (in-memory backend — no Redis), SQLAlchemy 2.x, psycopg2-binary,
reportlab. Test: pytest, pytest-flask.

Assert at startup that the running xgboost/lightgbm/sklearn versions match the
`library_versions` block in each metadata.json, and log loudly on mismatch.
