# BUILD PLAN — Automated Malware Analysis System for Disk & Memory Forensics

> **This document is historical.** All ten steps are complete. It is kept for the
> planning record — the risk analysis and per-step reasoning are still worth reading, but
> several of its predictions were wrong and are corrected elsewhere: the psxview gap
> turned out to be 6 features rather than 14, the "differently configured VMs" theory was
> superseded by SMOTE, the 32-bit dataset inference was wrong, and the x64 automagic
> branch worked rather than breaking as predicted. **`STATUS.md` is the current state and
> `CLAUDE.md` is the binding spec.**

Companion to [CLAUDE.md](CLAUDE.md). Planning document only — no code written yet.
Everything below is grounded in the actual artifacts in this repo, probed before
planning. Several findings contradict or complete what CLAUDE.md says; those are in
Parts 2 and 3.

---

## Part 0 — What was verified in the repo first

| Check | Result |
|---|---|
| Disk model header | `max_feature_idx=149`, `feature_names=Column_0…Column_149`, `objective=binary sigmoid:1` — Section 4's warning confirmed verbatim |
| Memory model JSON | `num_feature=55`, `objective=binary:logistic`, real semantic names present, **`num_trees=173` but `best_iteration=122`** |
| All 150 selected names ∈ full 2381 list | True. Indices span 1…2377 and are **not** ascending — order matters |
| Full 2381 group layout | byte_histogram 256, byte_entropy 256, string_feat 104, general_feat 10, header_feat 62, section_feat 255, imports_hash 1280, exports_hash 128, datadirectory_feat 30 — matches EMBER v2 extractor order exactly |
| Selected 150 group split | imports_hash 33, byte_histogram 26, byte_entropy 24, string_feat 20, header_feat 15, section_feat 15, datadirectory_feat 13, general_feat 4, **exports_hash 0** |
| reference_data | Both load clean. disk (5000,150) f32, range −4.50e7…4.29e9. memory (5000,55) f32, range 0…220850. No NaN/Inf |
| Memory zero-variance cols | **4**, not 3: `pslist.nprocs64bit`=0, `handles.nport`=0, `svcscan.interactive_process_services`=0 (all-zero, as documented), plus `callbacks.ngeneric`=**8.0 constant** |
| Local environment | Python 3.13 (Store) + 3.11.9. **Nothing installed** — no xgboost, lightgbm, lime, lief, ember, volatility3, pytsk3, Flask. Only numpy 2.4.1 / pandas 3.0.0 on 3.13 |
| Repo is not under git | Confirmed — CLAUDE.md §3 says commit reference_data, but there's no repo yet |

---

## Part 1 — Build plan

### Step 0 — Environment + repo (not in §14, but blocking)

**Build:** `git init`; venv on **Python 3.11.9** (not 3.13 — best wheel coverage for
pytsk3/lief/volatility3); requirements.txt + requirements-forensics.txt; .gitignore
excluding uploads/ and instance/ but **explicitly not** models/ or reference_data/.

**Files:** [requirements.txt](requirements.txt), [requirements-forensics.txt](requirements-forensics.txt), [.gitignore](.gitignore), [scripts/setup_env.py](scripts/setup_env.py)

**Done:** `pip install -r` succeeds on a clean venv; `import xgboost, lightgbm, lime,
ember, lief, pytsk3, volatility3` all succeed.

**Verify:** A single `scripts/check_env.py` printing every library version, compared
against `library_versions` in both metadata.json files.

**Risk:** Silent version drift. xgboost 3.2.0 saved the memory model; loading under a
different major version can change prediction semantics.
**Guard:** pin `xgboost==3.2.0`, `lightgbm==4.6.0`, `scikit-learn==1.6.1`,
`lief==1.0.0` exactly, and assert at startup that the running versions match
metadata's `library_versions`, logging a loud warning (not a hard fail) on mismatch.

**Risk:** pytsk3 / libewf-python may not have a Windows wheel for your Python.
**Guard:** do this on day 1, before writing any app code. `pyewf` is **not** a PyPI
package name — the distribution is `libewf-python` (latest 20240506); CLAUDE.md §6
names the import, not the package. If libewf-python won't install on Windows, drop
E01 support from the allowlist rather than burning a week on it (see Part 4).

---

### Step 1 — Skeleton, config, DB models

**Build:** Flask app factory, config object, SQLAlchemy models for `users` / `jobs` /
`results` / `findings` / `audit_log`. `results` needs a nullable per-file block so one
row = one PE for disk and one row = whole dump for memory.

**Files:** [app/\_\_init\_\_.py](app/__init__.py), [app/config.py](app/config.py), [app/models.py](app/models.py), [app/db.py](app/db.py), [migrations/](migrations/)

**Done:** `flask db upgrade` creates all tables on SQLite; a scripted insert of a fake
disk job with 3 file-results and 5 findings round-trips.

**Verify:** PyTest fixture creating an in-memory DB and asserting the relationship
cascade.

**Risk:** SQLite + a thread pool running 30-minute jobs = `database is locked`.
**Guard:** enable WAL mode and a 30s busy timeout in the engine `connect_args` from day
one; use `scoped_session` and never share a session across the request thread and the
executor thread. Document Postgres as the demo target.

**Risk:** Designing `results` around a single verdict then retrofitting per-file rows.
**Guard:** write the disk-shaped schema first (the harder case) and let memory use one row.

---

### Step 2 — Auth, upload, jobs, audit (no analysis)

**Build:** login/register with `werkzeug.security`, Flask-WTF CSRF, streaming upload
with SHA-256 computed **during** the stream, artifact-type detection, job creation,
audit logging, per-user upload rate limit.

**Files:** [app/auth.py](app/auth.py), [app/uploads.py](app/uploads.py), [app/routes.py](app/routes.py), [app/audit.py](app/audit.py), [app/templates/](app/templates/)

**Done:** A 2 GB file uploads without the process exceeding ~200 MB RSS; job row lands
`PENDING` with correct hash; no route can return the stored artifact.

**Verify:** Hash the file with `certutil -hashfile` and compare. Attempt
`GET /uploads/<name>`, `../` traversal in the filename, and an unauthenticated upload —
all must fail. Grep the route table for any `send_file` pointing at the upload dir.

**Risk:** Multi-GB upload through the Werkzeug dev server. CLAUDE.md forbids
Gunicorn/Nginx, so there's no way around it.
**Guard:** run with `threaded=True`, set `MAX_CONTENT_LENGTH`, and note that Werkzeug
spools multipart bodies to a temp file — you need **2× the image size** in free disk.
Document this as a lab-tool constraint in the README.

**Risk:** Artifact-type auto-detection will be ambiguous far more often than §10
implies. A raw disk image has MBR `0x55AA` at offset 510 or `EFI PART` at 512; a raw
memory dump has **no reliable magic at all** (crash dumps have `PAGEDU64`, but
`.raw`/`.mem`/`.vmem` have nothing).
**Guard:** implement detection as positive-identification-only — if no disk signature is
found, don't infer "memory," ask. Expect asking to be the common path for `.raw`.

---

### Step 3 — Inference layer (do this before any extractor — §14 is right)

**Build:** [app/inference/memory.py](app/inference/memory.py) and [app/inference/disk.py](app/inference/disk.py), deliberately not
sharing a base class. Each loads its model + feature list + threshold at import; disk
additionally computes and caches the 150 subset indices.

**Done:** All startup assertions pass; hand-built vectors return probabilities.

**Verify — this is the most important verification gate in the project:**

1. Assert `learner_model_param.num_feature == 55` and `len(feature_list) == 55`;
   assert `booster.num_feature() == 150` and `len(selected) == 150`.
2. Assert every selected name resolves in the 2381 list, that the cached index list has
   **150 entries in selected-list order**, and that `idx != sorted(idx)` (it genuinely
   isn't — a defensive assertion that catches an accidental sort).
3. **Run all 5,000 reference rows through each model and check the probability
   distribution is bimodal and roughly 50/50 split at the threshold.** Both training
   sets were balanced. If column order were scrambled, this collapses to a unimodal
   blob near 0.5. This is a vastly stronger guard than a feature-count assertion and is
   the only end-to-end order check available to you — the count assertion catches a
   missing column, this catches a *permuted* one.
4. Print the feature list and the vector side by side for one hand-built case.

**Risk — the big one:** silent order mismatch. Guarded by (2) and (3) above.

**Risk — specific and easy to miss:** the disk subset indices are **not ascending**.
`vec_2381[sorted(idx)]` and `vec_2381[idx]` both produce a valid 150-vector and both
predict without error. Only one is right.
**Guard:** assertion (2), plus a unit test that feeds a `np.arange(2381)` vector and
asserts the output equals the expected index sequence exactly.

**Risk — undocumented in CLAUDE.md:** the memory model has `best_iteration=122` but
ships **173 trees**. XGBoost's default `iteration_range` behaviour around
`best_iteration` has changed across versions; if inference uses 173 trees and the
threshold 0.2337 was tuned on 123, every probability shifts and the operating point you
validated is gone.
**Guard:** pin the tree count explicitly in the predict call, and use check (3) as the
arbiter — try both and keep whichever reproduces a clean bimodal 50/50 split. Record
the choice in a comment. Do not leave this to the library default.

**Risk:** hardcoding 0.5.
**Guard:** thresholds read from metadata.json at load; a unit test asserts the loaded
values are 0.2336726188659668 and 0.5010602922493019 and that the literal `0.5` appears
nowhere in the inference modules.

---

### Step 4 — Disk extractor

**Build:** [app/extractors/disk.py](app/extractors/disk.py) — image open (pytsk3 / libewf), partition
enumeration, recursive walk, MZ+PE confirmation, per-file metadata capture (path,
SHA-256, MD5, size, inode/MFT, MACB, byte offset), EMBER vectorization, subset, caps
and skip-reason recording. Plus [scripts/patch_ember.py](scripts/patch_ember.py).

**Done:** Runs against a small test image (build one from a Windows VM or use a public
NIST CFReDS image) and produces a per-file list where every PE found is a real PE and
no `.exe`-named text file is included.

**Verify:** Cross-check the file count and paths against `fls`/Autopsy on the same
image. Assert every returned vector is exactly 2381 long before subsetting. Confirm at
least one extensionless PE is found and at least one misnamed non-PE is rejected.

**Risk:** lief 1.0 is native code parsing hostile input. A malformed PE can **segfault
the whole Flask process**, killing unrelated jobs. This is not theoretical for a
malware-analysis tool.
**Guard:** run the EMBER vectorization step in a `ProcessPoolExecutor` (stdlib — not the
Celery/Redis that §10 forbids) with a per-file timeout, so a crash kills one worker
instead of the server. Treat this as required, not optional.

**Risk:** §6 says patch `ember/features.py` at startup by rewriting site-packages and
reloading the module. That's fragile — read-only installs, permission errors under a
service account, and a race if two workers patch concurrently.
**Guard:** move the patch to install time ([scripts/patch_ember.py](scripts/patch_ember.py), run from setup);
at **startup only verify** the patched string is present and refuse to boot if it isn't.
Same self-healing outcome, no runtime mutation of site-packages. Flagged because it is
a deliberate deviation from CLAUDE.md.

**Risk:** MACB timestamps and byte offsets are filesystem-dependent — NTFS gives all
four, FAT gives partial, and `pytsk3` exposes the data offset only for non-resident files.
**Guard:** §9.5 already says omit rather than guess; make the field genuinely nullable in
the schema and render "not available" in the report, never 0.

**Risk:** unallocated/deleted files. pytsk3 will surface them; their content may be
partially overwritten and vectorize to garbage.
**Guard:** record allocation status per file and either skip unallocated by default
(configurable) or flag them clearly in the report.

---

### Step 5 — Memory extractor

**Build:** [app/extractors/memory.py](app/extractors/memory.py) — one function per plugin family, an explicit
55-field mapping table, gap tracking, plus [scripts/dump_memory_features.py](scripts/dump_memory_features.py) (the
eyeball script §5 requires).

**Done:** Produces a 55-vector on a real dump with an honestly populated
`extraction_gaps`, and the eyeball script prints each name, extracted value, and the
training-sample min/max side by side.

**Verify:** The side-by-side range comparison is the verification. Anything outside the
training range gets flagged in the output — expect many (see Part 3).

**Risk:** This is the highest-risk step in the project. See Part 2 for the full
per-feature breakdown.

**Guard:** build the mapping table as data (a dict of field →
`(plugin, extractor_fn, confidence)`), so the gap list is generated from the table
rather than hand-maintained, and it's impossible to add a field without declaring its
confidence.

---

### Step 6 — Wire extractors → inference → persistence

**Build:** [app/jobs.py](app/jobs.py) — Flask-Executor dispatch, status transitions, per-file
result persistence, error capture.

**Done:** Upload → COMPLETED with rows in `results` for both artifact types.

**Verify:** Three concurrent uploads (2 disk, 1 memory) all reach COMPLETED with
correct, non-interleaved results. Kill the process mid-job and confirm the orphaned
RUNNING job is detected and marked FAILED at next boot.

**Risk:** Flask-Executor tasks run without an app context, so SQLAlchemy calls inside
them fail or bind to the wrong session.
**Guard:** wrap every task body in `with app.app_context():` and use `scoped_session`
with an explicit `remove()` in a finally block.

**Risk:** A thread pool with CPU-bound Volatility 3 work means the GIL serializes jobs
and starves the web thread — the dashboard will hang during analysis.
**Guard:** offload extraction to a process pool (same reasoning as step 4); keep the
Flask-Executor thread pool as the job *supervisor* only.

---

### Step 7 — LIME + lookup tables + tags + severity

**Build:** [app/explain.py](app/explain.py), [app/forensics/meanings.py](app/forensics/meanings.py), [app/forensics/mitre.py](app/forensics/mitre.py),
[app/forensics/severity.py](app/forensics/severity.py)

**Done:** A malicious verdict yields matched findings with MITRE IDs and a severity with
a visible justification string; a benign verdict runs no LIME.

**Verify:** Feed a synthetic memory vector with `malfind.*` spiked and assert T1055
appears; assert no raw LIME weight appears in any rendered template.

**Risk — concrete and easy to miss:** `explanation.as_list()` returns **discretized
condition strings** like `"malfind.ninjections > 5.00"`, not bare feature names. A naive
`MEANINGS[name]` lookup misses 100% of the time and you get an empty findings list that
looks like "nothing matched."
**Guard:** use `as_map()[1]` → `[(index, weight)]` and resolve the index against *your*
JSON feature list. This also satisfies hard rule 2 for free.

**Risk:** LIME's quartile discretizer on the 4 constant memory columns.
**Guard:** unit-test explaining a vector with those columns present; if the discretizer
degenerates, fall back to `discretize_continuous=False` and document it. Do **not** drop
the columns (hard rule 14/13 territory).

**Risk:** Accidentally introducing a scaler because the disk feature ranges (up to
4.29e9) look wrong next to LIME's perturbation output.
**Guard:** an explicit test asserting the vector passed to `explain_instance` is
bit-identical to the one passed to `predict`.

---

### Step 8 — Dashboard

**Build:** job list, job detail with polling, Chart.js summary, sortable/filterable
per-file table for disk, CSV/JSON export.

**Done:** Per-file table sorts severity-desc by default and shows path + SHA-256 in the
default column set (hard rule 16).

**Verify:** Render a job with 500 file results and confirm the page is usable; confirm
skipped files are visible and distinguishable from clean ones.

**Risk:** 500 rows of JSON per poll.
**Guard:** the status endpoint returns status + counts only; the file table loads once
on completion.

---

### Step 9 — PDF report

**Build:** [app/report.py](app/report.py) + templates, all seven §9.4 sections.

**Done:** All seven sections render for both pipelines, including limitations.

**Verify:** A test that renders a report and asserts the presence of each mandatory
limitation string — the MITRE disclaimer, the lief caveat (disk), extraction_gaps
(memory), and the dataset-saturation line (memory). Make it fail if any are absent.

**Risk:** WeasyPrint on Windows needs GTK/Pango/Cairo native DLLs and is a well-known
install nightmare.
**Guard:** use **ReportLab** — §10 permits either, and ReportLab is pure-Python with no
system deps. Decide this now, not in week 9.

**Risk:** Limitations silently omitted when a list is empty.
**Guard:** the section renders unconditionally with explicit "none recorded" text; the
test above enforces it.

---

### Step 10 — Tests, load test, docs

**Build:** PyTest suite, concurrency test, README with the honest performance and
accuracy statements.

**Verify:** Full §15 checklist, run top to bottom, results written down.

---

## Part 2 — Underspecified, and where a judgment call is needed

### 2.1 The Volatility 3 mapping — the real state of it

Derived empirically from `reference_data/memory_sample.npy` rather than guessed. Status
per field:

**Green — direct, safe (26 fields)**
`pslist.nproc`, `pslist.avg_threads`, `dlllist.ndlls`, `handles.nhandles`, the 10 usable
per-type handle counts, `ldrmodules.not_in_load/init/mem`, `malfind.ninjections`,
`malfind.commitCharge`, `modules.nmodules`, all 7 `svcscan.*`, `callbacks.ncallbacks`.
These are row counts or column filters that map cleanly onto Volatility 3 output.

**Derivable — formulas worked out from the reference data:**

- `dlllist.avg_dlls_per_proc = ndlls / nproc` — **confirmed exact** (median relative
  error 2.8e-8, i.e. float32 rounding only).
- `ldrmodules.*_avg` — ratio against the **ldrmodules row count**, not `dlllist.ndlls`.
  Testing against `ndlls` gives a consistent 1.8% median error; the denominator is the
  plugin's own row count. Same shape for `psxview.*_false_avg`: tested against
  `pslist.nproc` it gives a **uniform 2.27% median error across five of the seven
  columns**, which is exactly what you'd expect if the denominator is psxview's own
  union-of-sources process count (psxview sees ~2.3% more processes than pslist because
  psscan finds terminated ones). So the rule is: **each `_avg`/`_false_avg` divides by
  its own plugin's row count, never another plugin's.** That resolves the "not fully
  documented by the dataset authors" gap in §5 with evidence.
- `malfind.protection` — most likely the **sum of Volatility 2's numeric protection
  index**, not the Win32 constant. Mean protection ÷ mean ninjections ≈ 6.0, and index 6
  in Vol2's `PROTECT_FLAGS` list is `PAGE_EXECUTE_READWRITE` — exactly what malfind hits
  on. `PAGE_EXECUTE_READWRITE` as a Win32 constant is 0x40 = 64, which doesn't fit at
  all. Vol3 emits the protection as a **string**, so an explicit string → Vol2-index
  table is needed. **Judgment call requiring confirmation**, because getting it wrong
  silently changes a feature the model uses.

**Amber — definition genuinely ambiguous (4 fields)**

| Field | Problem |
|---|---|
| `pslist.nppid` | mean 14.7 vs nproc 41.5 → almost certainly *distinct* PPID count, but could be "processes with a live parent." Unverifiable from the sample. |
| `handles.avg_handles_per_proc` vs `pslist.avg_handlers` | These are near-identical (median relative difference 0) but diverge on some rows by up to 168. Two different denominators for the same numerator. Map both to `nhandles / nproc` and disclose that they're not independently derivable. |
| `malfind.uniqueInjections` | Fractional values (max 68.25) rule out a simple count. Not `ninjections/nproc` (12× off). Best guess: injections per *injected* process. Unresolved. |
| `callbacks.nanonymous` / `ngeneric` | `ngeneric` is **constant 8.0** across all 5,000 training rows. Whatever it counted, the model learned nothing from it. `nanonymous` is 0/1 only. |

**Red — no Volatility 3 equivalent (dead or gap)**

| Field | Status |
|---|---|
| `psxview.not_in_*` — roughly 3 of the 7 sources, plus their paired `_false_avg` | Vol3's psxview enumerates by ~4 methods against Vol2's 7. `pspcid` is the confirmed casualty; the others must be identified from the installed source on day 1 of step 5. → 0.0 + gap, ~6 fields. |
| `pslist.nprocs64bit` | Constant 0 in all training data. The dataset was captured on a 32-bit VM (or Vol2 never populated it). On a modern x64 dump the honest value is ~40 — which is **outside the entire training distribution**. Emitting the honest value may be *worse* than emitting 0. See Part 3.1. |
| `handles.nport` | Constant 0. The `Port` object type is XP/2003-era and doesn't exist on modern Windows. Emitting 0 is correct *and* matches training — the one happy case. |
| `svcscan.interactive_process_services` | Constant 0 in training. Vol3 does expose `SERVICE_INTERACTIVE_PROCESS`, so a real dump could produce a nonzero value the model has never seen. |

**Resolved externally — corrected.** `windows.psxview` **does exist** in volatility3
2.28 (also reachable as `windows.malware.psxview`, marked deprecated/renamed in newer
builds), so the 14-feature risk is not total. The real problem is narrower but still
significant: **Vol3 enumerates processes by roughly four methods where Vol2 used seven**
(pslist, psscan, thrdproc, pspcid, csrss, session, deskthrd). Expect around **three** of
the seven `not_in_*` sources to be unavailable, not just `pspcid` — so roughly 6 of the
55 features (3 counts + 3 paired `_false_avg`) go to 0.0 + gap, rather than 14.

Still must be resolved on day 1 of step 5 by enumerating the actual column names from
the **installed** volatility3 source, before any mapping code is written. Build the
mapping from that enumeration, not from this document and not from Vol2 documentation.

### 2.2 Other underspecified items

- **§9.1 has no entry for `byte_histogram_*`, but 26 of the 150 selected disk features
  are byte_histogram.** That's 17% of the model's input with no forensic meaning
  defined. Proposed addition: byte-value frequency distribution — skew toward
  high-entropy or non-ASCII ranges is consistent with packing/encryption. Needs sign-off.
- **§9.1 is more pessimistic than it needs to be for 5 of 8 disk groups.** Only
  `imports_hash` (33 selected) and `exports_hash` (0 selected) are true hash buckets.
  `general_feat_0…9`, `datadirectory_feat_0…29` (15 directories × size,VA in order), and
  `section_feat_0…4` are **named, per-index recoverable scalars** in EMBER v2. The 4
  selected general_feats and 13 datadirectory_feats can be reported precisely and
  defensibly — e.g. the certificate-directory entries directly ground "unsigned binary,"
  and `section_feat_3/4` are literally the RX-section and W-section counts that §9.1's
  "writable+executable" wording wants. Verify the exact index order against ember's
  source, then use it. Hard rule 15 is unaffected — it only covers the hash groups.
- **Severity function weights** are entirely unspecified ("simple, deterministic"). A
  concrete table will be proposed for approval rather than invented silently.
- **Memory verdict granularity** is undefined. The memory model gives one probability per
  *dump*, but the findings are per-process phenomena. The report cannot say
  "svchost.exe was injected" — only "the dump shows injection activity." Worth being
  explicit about in the UI.
- **`extraction_gaps` has no schema.** Proposed: `[{field, reason, plugin}]`, not a bare
  list of names, so the report can explain *why*.
- **No test artifacts exist.** A memory dump and a disk image are needed. Neither is in
  the repo and both are large. This is a real schedule dependency — sort it before step 4.

---

## Part 3 — What is wrong or won't work

Ordered by how much damage each does.

### 3.1 The memory model was trained on one VM image, and the pipeline's core premise doesn't survive that

The most important finding here. From the reference data:

- `modules.nmodules` ∈ {137, 138} across all 5,000 rows
- `callbacks.ngeneric` = 8.0, always
- `svcscan.kernel_drivers` mean 221.4, range [108, 222]
- `svcscan.nservices` mean 391.4, range [195, 395]
- `pslist.nprocs64bit` = 0, always
- **`malfind.ninjections` minimum = 1.0** — the dataset contains no sample with zero
  injected regions
- `psxview.not_in_csrss_handles` minimum = 4

That is not a distribution of Windows systems. That's **one Windows build, one VM
configuration, captured repeatedly**. CIC-MalMem-2022 is documented as VM-generated, and
`models/memory/metadata.json` already says the separability "likely reflect[s] systematic
differences in VM/capture conditions." The reference data confirms it concretely.

The consequence: when an analyst uploads a real Windows 11 x64 dump, `nmodules` will be
~400 not 137, `nprocs64bit` will be ~40 not 0, `nservices` will be ~600 not 391. Every
one of those lands past the outermost split threshold the trees ever learned. The model
will still return a confident probability — tree models extrapolate as a constant beyond
their training range — and that probability will be **essentially arbitrary**. The 1.0000
test AUC tells you nothing about this, because the test set came from the same VM.

Not a proposal to retrain anything (hard rule 7) or change the model. Three proposals:

1. **Build an out-of-distribution check into the memory pipeline.** The training
   distribution is in `reference_data/memory_sample.npy`. At inference, compare each
   extracted feature against its training min/max and count how many fall outside. ~15
   lines, no new model.
2. **Surface the count in the report and the UI.** "38 of 55 features fall outside the
   range observed in the training data; this verdict is extrapolation and should be
   treated as low-confidence."
3. **State it in the limitations section** alongside the saturation caveat §9.4 already
   mandates.

This turns the project's biggest weakness into evidence of rigour — worth more in a viva
than a silent 99% confidence an examiner can dismantle in one question. Without it, the
memory pipeline demos beautifully on a CIC-MalMem sample and produces meaningless output
on anything real, with no way to tell the difference.

Related, needing a decision: **for `pslist.nprocs64bit`, is the honest value or the
training-consistent value correct?** A modern dump honestly yields ~40; training only
ever saw 0. Hard rule 8 says never fabricate — so emit the real value. But that
guarantees an out-of-range input. Recommendation: emit the honest value and let the OOD
check flag it.

### 3.2 CLAUDE.md says 3 all-zero columns; there are 4 zero-variance columns

Three are all-zero as documented. `callbacks.ngeneric` is a fourth zero-variance column
that is constant at **8.0**, not 0. If the §8.1 startup assertion is written as "exactly
3 zero-variance columns," it fails at boot. Assert "3 all-zero **and** 4 zero-variance,"
or the check is wrong. Minor, but boot-blocking.

### 3.3 Three of the eleven MITRE mappings in §9.2 don't hold up

An examiner who knows ATT&CK will check these.

| §9.2 entry | Problem |
|---|---|
| Hooking → **T1179** | T1179 is **deprecated** in current ATT&CK. It was retired and split (T1056.004 Credential API Hooking, and others). Citing a revoked ID dates the report. Recommend T1056.004 or drop the tag — "handles anomalies" is thin evidence for hooking anyway. |
| Kernel Callbacks → **T1547.006** | T1547.006 is *Kernel Modules and Extensions*, platforms **Linux and macOS**. For Windows kernel-callback/driver persistence the defensible IDs are T1543.003 or T1014. |
| Hidden Modules → **T1574** | T1574 is *Hijack Execution Flow* — search-order hijacking and side-loading, i.e. loading the **wrong** DLL. `ldrmodules.not_in_init/not_in_mem` is DLL **concealment**, a different behaviour. T1055.001 or T1027 fits better. |

Also, "Defense Evasion — Unsigned Binary → T1553": T1553.002 is about *subverting* code
signing (stolen certs, self-signing). Merely being unsigned isn't that technique, and
it's an extremely weak indicator — a large fraction of legitimate binaries are unsigned.
Keep it but mark it `confidence: low` and word it as an observation, not a technique
attribution.

Everything else in the table (T1055, T1055.012, T1027, T1014, T1543.003, T1547, T1106)
is sound.

### 3.4 §6's runtime site-packages patching should be install-time

Covered in step 4. Rewriting installed library source at startup and
`importlib.reload`-ing is fragile under read-only installs, restricted service accounts,
and concurrent workers. Patch at install, verify at boot, refuse to start if unpatched.
Same self-healing property, no runtime mutation.

### 3.5 A thread pool is the wrong isolation boundary for this workload

§10 mandates Flask-Executor and rejects Celery/Redis — fine, and neither is proposed. But
two problems follow from threads specifically:

- lief parsing hostile PEs is native code; a segfault takes down the entire Flask
  process, not one job. For a tool whose input is by definition malware, that's a matter
  of when.
- Volatility 3 is CPU-bound Python; the GIL serializes jobs and starves the web thread,
  so the dashboard freezes during analysis.

Both are solved by `concurrent.futures.ProcessPoolExecutor` — standard library, no new
infrastructure, no violation of the "no Celery/Redis/Docker" rule. Flask-Executor still
supervises. Treat as required.

### 3.6 The `iteration_range` ambiguity on the memory model

`best_iteration=122`, `num_trees=173`. XGBoost's default behaviour here has shifted
between versions, and the two settings give different probabilities against a threshold
tuned on exactly one of them. Nothing in CLAUDE.md addresses it. Cheap to resolve at step
3 using the reference-sample distribution check — but if it isn't resolved deliberately
it will be resolved accidentally, and wrongly.

### 3.7 Volatility 3 needs symbol tables, which it downloads from the internet

Vol3 resolves Windows kernel symbols by fetching PDB-derived ISF JSON from
`downloads.volatilityfoundation.org` on first encounter with an unseen build. §1 says
"locally-run"; §11 says no external APIs. Nothing in CLAUDE.md mentions this dependency.
On an offline demo machine, memory extraction will simply fail with a confusing symbol
error. Pre-populate the symbol cache for whatever builds will be demoed, ship it
alongside, and document it.

### 3.8 Runtime honesty

§13 rule 10 says never claim seconds. Realistically: memory is **15–45 minutes**
dominated by `windows.handles`, which is by far the slowest plugin and which is needed
for 13 of the 55 features. Disk is a few minutes for 500 PEs plus image-walk time. Say
minutes-to-tens-of-minutes in the UI, and consider a per-plugin progress indicator so a
40-minute job doesn't look hung.

### 3.9 Smaller things

- `pyewf` isn't installable — the package is `libewf-python`. If it won't build on
  Windows, drop `.E01`/`.EX01` from the allowlist rather than fighting it; raw images
  cover the demo.
- lime 0.2.0.1 was released in 2020 and is unmaintained. It's the only real option, but
  pin it and test it against the chosen numpy/sklearn versions early, at step 3, not step 7.
- Deleted/unallocated files recovered by pytsk3 may be partially overwritten and will
  vectorize to noise. Decide the policy now.
- Nothing is under version control yet, and `reference_data/` (4 MB) is irreplaceable per
  §3/§8.1. `git init` before anything else — 18 MB total, no LFS needed.

---

## Part 4 — Dependencies

**Python 3.11.9** (already installed at
`C:\Users\ALAM-PC\AppData\Local\Programs\Python\Python311`). Not 3.13 — pytsk3 and lief
wheel coverage is the constraint. Not the Store Python, which has site-packages
redirection quirks.

### Model/inference — pin exactly, these govern prediction semantics

```
xgboost==3.2.0          # matches models/memory/metadata.json library_versions
lightgbm==4.6.0         # matches models/disk/metadata.json
scikit-learn==1.6.1     # ember's FeatureHasher path depends on it
numpy>=1.26,<3
lime==0.2.0.1
scipy>=1.11
```

### Disk extraction — the constrained part

```
lief==1.0.0             # exactly. metadata records 1.0.0-d05b3499b as what
                        # produced the training features. NOT 0.11.5 (no py3.12+
                        # wheel) and NOT 0.9.0 (what ember expects — hence the
                        # mandatory report caveat)
pytsk3==20260715
libewf-python==20240506 # the pip name for `import pyewf`; drop E01 support if
                        # it won't build on Windows
```

EMBER — install order matters and it is not a normal pip install:

```
pip uninstall -y lief
pip install lief==1.0.0
pip install git+https://github.com/elastic/ember.git --no-deps
python scripts/patch_ember.py     # elastic/ember PR #109 FeatureHasher fix
```

`--no-deps` is essential: ember's setup.py pins lief 0.9.0 and will clobber the working
install.

### Memory extraction

```
volatility3==2.28.0
pefile                  # volatility3 dependency
capstone                # volatility3 dependency (malfind disasm)
```

Plus the pre-downloaded symbol cache (§3.7) — not a pip dependency but a hard runtime one.

### Web

```
Flask>=3.0
Flask-SQLAlchemy>=3.1
Flask-Login>=0.6
Flask-WTF>=1.2         # CSRF
Flask-Executor>=1.0
Flask-Migrate>=4.0
Flask-Limiter>=3.5     # per-user upload rate limit, in-memory backend (no Redis)
SQLAlchemy>=2.0
psycopg2-binary        # prod; SQLite for dev
reportlab>=4.0         # NOT WeasyPrint — see 3.9 / step 9
```

Bootstrap and Chart.js as vendored static files, not CDN (offline tool).

### Test

```
pytest>=8.0
pytest-flask
```

---

## Decisions — RESOLVED

All approved. Every item below is now reflected in [CLAUDE.md](CLAUDE.md), which is
again the source of truth.

| Item | Decision |
|---|---|
| `malfind.protection` | Accept the Vol2 protection-index reading. Confidence **moderate**; record as *inferred* in `extraction_gaps` even when a value is emitted. |
| `pslist.nprocs64bit` | Emit the **honest** value from the dump. The OOD check covers the resulting out-of-range input. |
| OOD check (3.1) | **In. Required, not optional.** Hard rule 17. |
| Disk feature semantics (2.2) | Approved — `byte_histogram_*` meaning added; per-index semantics for `general_feat`, `datadirectory_feat`, `section_feat_0-4` after verifying index order against ember's source. Hard rule 15 still binds the hash groups. |
| MITRE corrections (3.3) | All three approved: T1179 → T1056.004, T1547.006 → T1543.003/T1014, T1574 → T1055.001. Unsigned-binary downgraded to `confidence: low`. Hard rule 21. |
| psxview (2.1) | Corrected — plugin exists; ~3 of 7 enumeration sources unavailable, not 1. Enumerate from installed source on day 1 of step 5. |
| ember patching (3.4) | Install-time, verify-at-boot. |
| Extraction isolation (3.5) | `ProcessPoolExecutor`. Hard rule 20. |
| `iteration_range` (3.6) | Pin explicitly; resolve via the reference-distribution check. |
| Symbol cache (3.7) | Pre-populate and ship. |
| PDF engine | ReportLab. |
| Zero-variance assertion (3.2) | Assert **3 all-zero AND 4 zero-variance**. |
| Test artifacts | Being sourced separately. Proceed through step 4 without them. |
