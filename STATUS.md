# STATUS — where the project is right now

Last updated 2026-08-04. `CLAUDE.md` is the spec and the binding rules; this file is the
handoff state. If the two disagree, CLAUDE.md wins on *what to build* and this file wins
on *what exists*.

## SESSION HANDOFF — read this first

All ten build steps are complete, the app runs, **232 tests pass**, and both pipelines are
validated on real held-out data. The code is frozen; what remains is empirical (one memory
capture, disk test images) and the write-up. Do **not** change code unless something below
is genuinely broken.

**State in one screen:**

- **Disk pipeline** — the validated one, LightGBM, 150 features, threshold 0.5010602922493019,
  ROC-AUC 0.9940 vs the official EMBER baseline 0.9964. True positive proven on a labelled
  EMBER 2018 held-out row: `data/holdout/ember_test_malicious.npy` → **p=0.999838** (correct),
  benign counterpart 0.017917 (correct). No PE was parsed — `process_raw_features` from the
  published feature JSON.
- **Memory pipeline** — XGBoost, 55 features, threshold 0.2336726188659668. Positioned as a
  **forensic triage engine, not a detector** (hard rule 22): reports lead with observed
  Volatility evidence, the model score is secondary and always carries the OOD count. Its
  own held-out data classifies correctly: `data/holdout/malmem_test_{malicious,benign}.npy`
  → p=0.997147 / 0.002813, both correct, OOD 0/55 (in-distribution).
- **Clean baseline (committed, 2026-08-03)** — `baselines/clean_win10_x64.json` is now
  **seven captures** of the reference machine (Win10 x64 build **19044.7548**) across
  freshboot/idle/browser/apps/afterclose + a 15–30 s pair. Stored: per-feature median
  (`features`/`all_features`) and observed **max** per feature. Severity flags a feature
  only when it exceeds **observed max × MARGIN (1.2)** — the ceiling — *not* the old
  median×3. All seven clean captures score **Low** (p 0.0077–0.0081, OOD 22–27/55, all
  benign); nothing false-positives. Extraction validated same-machine: kernel+fs drivers
  363 vs ground-truth 363–364 (near exact), services +2.9% (enumerates drivers too), procs
  within ±7% except the volatile freshboot (60 vs 80).
- **Unreachable-on-this-baseline indicators (state openly in the write-up, not defects):**
  `psxview.not_in_pslist` ceiling ~40 (freshboot alone hits 33), `ldrmodules.*` ceilings
  500+. On this machine `malfind` (injection) is the one reliable behavioural indicator.
- **The malicious capture landed and confirms the headline claim — Critical, measured
  2026-08-04.** `sample/memory/malicious_1.raw`, captured with `scripts/sim_injector.py`
  (30 RWX regions) and `scripts/sim_spawnkill.py` (100 held-open `cmd /c exit`) both
  running. All four target indicators cleared their ceilings; severity reached **Critical**
  via T1055 (Process Injection) + T1014 (Rootkit / Hidden Artifacts), confirmed both
  standalone and through a full app run (job 3, PDF verified). Full numbers, the three
  prediction deviations (all explained), and a corrected theory of how the spawn-kill
  simulation actually works are under "The malicious capture — measured 2026-08-04" below.

## NEXT SESSION — in order

1. ~~Receive `malicious_1.raw`~~ **Done 2026-08-04.** Result: **Critical**, confirmed twice
   (standalone forensics functions + full app run, job 3) and robust to indicator
   reduction. See "The malicious capture — measured 2026-08-04" below for every number.
2. **Receive the malicious disk image(s), if still wanted.** The disk pipeline already has
   two genuine positive demonstrations — the EMBER held-out true positive (p=0.999838) and
   the UPX-packing false-positive demo — so a third capture is optional polish, not a gap.
   Check with the supervisor whether it is still required before spending capture time on
   it. If yes: run disk detection, confirm it flags the planted PE(s) with path + SHA-256
   (hard rule 16), record results.
3. **Assemble the demo set** — see "Demo plan" below. Wire the three memory parts and three
   disk parts into a runnable sequence; the held-out vectors, `predict_vector.py`, and now
   `malicious_1.raw` already cover every demo that needs no further capture.
4. **Write-up** — the FYP report, screenshots, and the settled findings (SMOTE saturation,
   the eight silent bugs, the ceiling design, the unreachable-indicator honesty, and the
   psxview mechanism correction below).

Test infrastructure for the malicious artifacts is deliberately **not** built yet; specify
it together with the captures so it matches what actually lands.

**`verify_pipeline.py` does not scan `sample/`** — it runs two pinned, named artifacts with
recorded expected results (see the script's own docstring, corrected 2026-08-04). It never
picked up the seven clean captures or `malicious_1.raw`; those were run through the app
directly, which is also the more realistic path since it exercises upload, sniffing and the
job queue rather than a synthetic Job row.

## Build state: all ten steps complete, 232 tests passing

```
.venv\Scripts\python -m pytest tests -q      ->  232 passed
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

**Memory x64** — validated on two machines' worth of captures. The original `win10_memory.raw`
(build 19044.1288, now retired from baseline duty, kept as test artifact): processes 67 vs
67 exact, drivers 360 vs 362, services+drivers 632 vs 615, **202–409 s** through the job
layer. The **seven-capture reference set** (build 19044.7548, the live baseline): all seven
benign p 0.0077–0.0081, OOD 22–27/55, kernel+fs drivers 363 vs ground-truth 363–364,
services +2.9%, procs within ±7% except the volatile freshboot (60 vs 80). Extraction is
correct in absolute terms; the training range really is far below reality.

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
`verify_pipeline.py` prints the slowest five. **First two instrumented runs, 2026-08-02:**

| Run | total | malfind | handles | svcscan | psxview | ldrmodules |
|---|---:|---:|---:|---:|---:|---:|
| A | 352 s | 128.2 | 77.1 | 38.7 | 37.7 | 32.9 |
| B | 357 s | 124.1 | 86.7 | 38.3 | 37.1 | 33.6 |

`malfind` alone is ~35% of the job. But **both runs are from the slow regime** — the fast
~200 s regime has not yet been captured with instrumentation, so the 2× variance is still
unattributed. Do not theorise from these two; get a fast run's timings first.

**Web** — every route returns against real data; PDFs render for both pipelines; uploaded
artifacts are unreachable over HTTP.

## Test artifacts

Live in `sample/`, which is **gitignored** — they are hundreds of MB and are not in the
repo.

| Path | What |
|---|---|
| `sample/disk/2020JimmyWilson.E01` | NIST CFReDS evidence image, 295 MB |
| `sample/memory/clean_1..7_*.raw` | Seven clean captures of the reference machine, Win10 21H2 x64 build 19044.7548, 2 GB each. The baseline is built from these. |
| `sample/memory/win10_memory.raw` | Win10 21H2 x64 **19044.1288**, 2 GB. **Retired from baseline duty** (2026-08-03); kept only as the pipeline test artifact the evidence/timing checks were validated against. See the note below on same-vs-different machine. |
| `sample/memory/malicious_1.raw` | Same reference machine, captured 2026-08-04 with `sim_injector.py` + `sim_spawnkill.py` both running. 2 GB. SHA-256 `b10325d8…d1def6`. Scores **Critical** — see "The malicious capture — measured 2026-08-04". |

`baselines/clean_win10_x64.json` is committed and, since 2026-08-03, holds the **seven-
capture** reference baseline: per-feature median (`features`/`all_features`) and the
observed **max** per feature that the severity ceiling uses. `data/baseline_vectors/`
(gitignored) holds the seven extracted 55-vectors and their summary.

**win10_memory.raw — same or different machine, unresolved.** Its service/driver counts
(632/321) sit inside the seven captures' range (635-636/324-325), which points at the
*same* physical machine at an earlier patch level (19044.1288 vs .7548); its behavioural
profile differs (`malfind.ninjections` 16 vs the new median 6), which could be state or
drift. The user left this unconfirmed. It does not matter for the action taken — retired
from baseline either way, kept as a test artifact — but if it is confirmed same-machine it
could later be added as an eighth capture; do not fold it in until that is confirmed
*and* the software state matches.

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
is visible. Unit tests do not catch what this catches — every one of the seven bugs below
came from it.

Run `run.py`, never `python -m flask run` with a module that builds the app at import —
see CLAUDE.md §10 on Windows spawn.

### Operational gotchas a fresh session will otherwise hit blind

- **Git has no committer identity configured.** Commits fail with "Author identity unknown"
  unless you pass it inline. Every commit this project used:
  `git -c user.name="Muhammad Farooq" -c user.email="muhammadfarooq1034@gmail.com" commit ...`
- **PowerShell mangles multi-line commit messages** passed with `-m` (it splits on the
  text). Write the message to a file and use `git commit -F <file>`, or a single-line `-m`.
- **The baseline is rebuilt in two steps, and the final copy is manual.**
  `baseline_extract.py` writes the seven 55-vectors to `data/baseline_vectors/` (gitignored,
  **not** committed — if that folder is empty the vectors must be re-extracted, ~5–15 min
  each, ~45 min total). `baseline_build.py` writes `data/baseline_candidate.json`; making it
  live is a deliberate `copy` over `baselines/clean_win10_x64.json`, not automatic.
- **Memory extraction is slow and variable (~3.5–7 min, sometimes 15).** Background it and
  wait; do not assume it hung. `nohup cmd &` *inside* an already-backgrounded shell orphans
  the child when the wrapper returns — run the python command directly under the tool's own
  backgrounding instead.
- **To check a capture's numbers without the web app:** `scripts\dump_memory_features.py
  <dump>` prints all 55 values against training ranges; the per-process evidence lands in
  `Job.evidence` when run through the job layer (`verify_pipeline.py` or an upload). For a
  bare vector, `scripts\predict_vector.py memory --npy <file>` (severity is suppressed there
  by design — a bare vector has no provenance).
- **`sample/` and `data/` (except `data/holdout/`) are gitignored** — the dumps, the CSV, the
  EMBER tarball and the baseline vectors are all local-only. The four held-out `.npy`/`.json`
  in `data/holdout/` and `baselines/clean_win10_x64.json` **are** committed.

## Eight silent bugs found by running real artifacts

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
7. **Renderer objects killed the whole worker pool** — volatility returns `BitField` and
   `UnreadableValue`, not ints. They pickle *inside* the worker and fail on the way back
   out, so the failure surfaces as `BrokenProcessPool` — every job lost, not one — with a
   traceback pointing at `concurrent.futures`, nowhere near the cause. The unit tests
   passed throughout because their fixtures used plain ints. **The clearest case yet for
   `verify_pipeline.py`:** nothing else in the suite touches a real dump, so nothing else
   could have caught it. Fixed by coercing every extracted field to a builtin, with a test
   that feeds an object refusing `int()` and asserts a pickle round-trip.
8. **Wrong theory of the `sim_spawnkill.py` mechanism** — predicted that holding a handle
   to a terminated process would hide it from `pslist` (driving `psxview.not_in_pslist`).
   Measured on `malicious_1.raw` (2026-08-04): holding the handle keeps the process
   *linked in pslist itself* (nproc 182 vs a clean 60–92), and what actually goes missing
   is thread objects and the CSRSS session entry — `not_in_ethread_pool` (21.8× its
   ceiling) and `not_in_csrss_handles` (8.1×), not `not_in_pslist` (a weak 1.39×). Outcome
   unaffected — Rootkit / Hidden Artifacts still elevated, Critical still reached — but
   the stated mechanism was wrong until a real artifact was run and the numbers read
   directly rather than assumed from the design intent. See "Silent bug #8" above for the
   full measurement and the corrected docstring in `sim_spawnkill.py`.

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

**All memory-side empirical work is done.** The clean baseline set and the simulated-
malicious capture have both landed and been fully validated — see "The malicious capture
— measured 2026-08-04" above. What remains is the malicious disk image, **optional and
pending supervisor confirmation** since the disk pipeline already has two genuine
demonstrations without it, plus the write-up. Test infrastructure for a disk malicious
image is deliberately **not** built yet; it gets specified together with that capture if
it is still wanted.

The MalMem CSV landed on 2026-08-01 and `malmem_holdout.py` has been run — all four gates
passed, rows committed. Nothing else is pending from the user except, possibly, the
disk image.

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

**Finalised malicious-capture recipe (2026-08-03), one capture for Critical.**

- *Injection (→ Process Injection T1055, reliable):* **30 allocations**, each
  `VirtualAlloc(NULL, 512 KB, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`, **write a
  non-zero stub into the first bytes of every one** (mandatory — malfind's `is_vad_empty`
  skips zero-filled VADs), and **keep the process alive** at capture. Self-allocation into
  the injector's own process is sufficient; malfind walks every process's VAD tree.
  Targeting `notepad.exe` is optional flavour only. Produces ninjections 30, uniqueInjections
  30, commitCharge 3840 — all three clear their ceilings (10.8 / 5.4 / 2215).
- *Hidden processes (→ Rootkit T1014, the second technique for Critical):* **spawn-and-kill
  ~100 trivial processes** (`cmd /c exit`) and **hold their handles open**, which pins the
  terminated EPROCESS objects in pool — psscan finds them, pslist does not. Need
  `not_in_pslist` > 39.6; holding handles makes the count ≈ 100 deterministically, with
  **no timing race** (this improves on the earlier "capture within 10 s" — the artifacts
  stay resident as long as the tool window is open).
- *The two tools are written and smoke-tested:* `scripts/sim_injector.py` and
  `scripts/sim_spawnkill.py`. Both are benign — the injector writes a marker string and
  never executes the RWX region; the spawn-kill only launches `cmd /c exit`. Run each in
  its own window, leave both open, capture, then press Enter in each to release.
- *Sequence:* start `sim_injector.py` (holds 30 RWX) → start `sim_spawnkill.py` (holds ~100
  terminated) → both report "READY FOR CAPTURE" → run Magnet → release. Injection alone →
  High; injection + spawn-kill → **Critical**.
- Capture at least one clean dump under the **same Defender configuration** (exclusion
  folder) used for the malicious one, so the two are comparable.

**Earlier framing, kept for context.** Genuine forensic artifacts without live
malware: process injection (`CreateRemoteThread` / `VirtualAllocEx`, producing real
`malfind` RWX regions), a running UPX-packed binary, and/or a hidden process.
**The specific safe simulation method is subject to supervisor approval.**

**What it takes to move severity — recomputed 2026-08-03 against the seven-capture
ceilings.** An indicator counts only when it exceeds the highest value seen across the
seven clean captures × 1.2 (`baseline.MARGIN`). The `max` block in the baseline JSON holds
those maxima:

| Indicator | clean max /7 | ×1.2 ceiling | Reachable by simulation? |
|---|---:|---:|---|
| `malfind.ninjections` | 9 | **10.8** | **yes, easily** — 30 regions → ~30 |
| `malfind.uniqueInjections` | 4 | **5.4** | **yes, easily** — 30 regions in 1–2 procs |
| `malfind.commitCharge` | 1,846 | **2,215** | yes, with large allocations |
| `psxview.not_in_pslist` | 33 | **39.6** | **no** — 15–20 spawn/kill stays well under 40 |
| `psxview.not_in_eprocess_pool` | 3 | **3.6** | marginal |
| `ldrmodules.not_in_init` | 510 | **612** | **no** — a reflective load adds 1–3 |
| `ldrmodules.not_in_load` | 432 | **518** | **no** |

**The demo lands on High, not Critical, and that is the honest result.** ~30 injected
regions clears the three `malfind` ceilings → Process Injection (T1055) elevated, and the
≥2-elevated bump makes it **High**. Verified against the live baseline in
`test_baseline_ceiling.py`. Critical needs a *second* high-risk technique, and on this
machine none is reachable: the fresh-boot peak of 33 puts `not_in_pslist` at ~40 (so 15–20
spawn/kill does nothing — pinned by a test), and `ldrmodules` sits at 500+. This is the
same "unreachable on this baseline" property already recorded for ldrmodules, now also
true for psxview because of fresh-boot volatility. **Lean the demo on injection; do not
rely on spawn/kill for a second technique.** To force Critical you would need ~40+
processes spawned-and-killed immediately before capture.

**What malfind actually counts, read from the installed source (2026-08-02).** A VAD is
reported when it is (a) `EXECUTE`+`WRITE`, or a dirty `EXECUTE`-only page; **and** (b)
private memory tagged `VadS`, or non-private that is not `PAGE_EXECUTE_WRITECOPY`; **and**
(c) not entirely paged-out or zero. Consequences for the capture:

- **A self-allocating `VirtualAlloc(PAGE_EXECUTE_READWRITE)` loop DOES register.** malfind
  does not require cross-process injection — it walks every process's VAD tree and reports
  any process holding qualifying regions. A single process that allocates its own RWX VADs
  counts, and `uniqueInjections = len(malfind) / distinct injected PIDs`, so **many regions
  in one process drives `uniqueInjections` hardest**. That is the cheapest indicator to
  trip: >24 needs ~25 qualifying regions in one PID.
- **The regions must be non-zero.** Allocate then **write executable-looking bytes into
  each** (even a memcpy of a few bytes per page) — `is_vad_empty` skips any VAD that is all
  zeroes or paged out, so a bare `VirtualAlloc` with no write is dropped.
- **`commitCharge` is the sum of CommitCharge across reported VADs**, needing >4,833. One
  ~19 MB committed RWX region, or many smaller committed ones, reaches it — but commit only
  counts once the pages are actually touched.
- **Cross-process injection is not needed for the count, but it is the honest artifact.** A
  self-RWX loop trips the numbers; `CreateRemoteThread`/`VirtualAllocEx` into a real target
  (e.g. `notepad.exe`) produces the same malfind hit *plus* a genuine remote-injection
  story and shows the target PID in the per-process evidence. Prefer it for the
  demonstration even though the self-loop would satisfy the threshold.

**Concrete recipe:** ~30 RWX allocations of ~64 KB each (writing a stub into every one)
into one or two target processes gives `ninjections ≈ 30` (short of 48 on its own but
contributing), `uniqueInjections ≈ 15–30` (**past 24**), and if the allocations are large
enough, `commitCharge` past 4,833. Combined with 15–20 spawned-and-killed processes for
`psxview`, that is two high-risk techniques → **Critical**.

**Two things to state openly in the write-up rather than hide. Both are report material,
not defects.**

1. **`ldrmodules` is unreachable as an elevated indicator on this baseline.** The ceilings
   are 518–612 (max/7 × 1.2); a reflective DLL load adds 1–3. The reference machine already
   sits at 291–389 legitimately, so the loader-list indicators can only fire on a machine
   with a much quieter baseline. They still appear in the findings and per-process evidence
   with their locators — they just cannot drive severity here.
2. **`psxview.not_in_pslist` is also unreachable on this baseline, and for an instructive
   reason.** The fresh-boot capture legitimately reaches 33 (psscan sees terminated boot
   processes), so its ceiling is ~40. A realistic hidden-process signal adds a handful —
   nowhere near 40. Spawning 15–20 processes and capturing within seconds, which was the
   plan for a second technique, is *exactly what one of the seven clean states already
   does*, so it cannot separate malicious from clean here. This is why the demo lands on
   High from injection alone; forcing Critical would need ~40+ spawned/killed processes.
   `malfind` is the one behavioural family with a tight enough clean ceiling to be a
   reliable indicator on this machine.

### 2. Empirical test of the OOD gate — **measured 2026-08-03**

All seven clean captures pushed through the model:

| capture | p | OOD | verdict |
|---|---:|---:|---|
| freshboot | 0.0081 | 23 | benign |
| idle | 0.0077 | 22 | benign |
| browser | 0.0077 | 27 | benign |
| apps | 0.0077 | 25 | benign |
| afterclose | 0.0077 | 24 | benign |
| pair_a | 0.0077 | 24 | benign |
| pair_b | 0.0077 | 23 | benign |

**All seven benign, all far below the 0.2337 threshold, OOD 22–27 of 55 — the gate
behaves consistently and none lands differently.** So the model discriminates cleanly on
clean captures of the reference machine even while technically out of distribution. This is
one half of the experiment; it does **not** yet justify unlocking the gate — that needs the
malicious capture to score substantially higher. The gate stays as it is until then. This
is not reopening the SMOTE investigation, which is closed.

Note the OOD count (22–27) is a property of the model-vs-training-range check and is
separate from the severity ceiling; both held up. Evidence-led severity scored all seven
**Low** against the new baseline (below), the outcome that matters most — no clean capture
reads as a threat.

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

## Per-process evidence — what the clean capture actually shows

`Job.evidence` records the locators behind each indicator (CLAUDE.md §9.6). On the clean
x64 reference capture it produces, at no extra runtime:

- **16 injected regions, every one in `MsMpEng.exe`** — Windows Defender's own scanning
  engine, holding 1–2 MB `PAGE_EXECUTE_READWRITE` private regions. The single best
  illustration of why `malfind` counts are not evidence.
- **267 module rows absent from any of the three PEB lists** (this is the evidence-table
  union, not the `not_in_load` feature, which is 203), led by `ntdll.dll` in `System` and
  `smss.exe` missing from all three — early-boot processes whose PEB is not yet populated.
- **12 processes missing from an enumeration method**, most carrying an exit time
  (`SearchFilterHo` exited 09:04:43, `userinit.exe` 07:20:52) — the terminated-process
  explanation, now demonstrated with timestamps instead of asserted.
- **0 unbacked callbacks.**

This is what makes the baseline argument concrete in the write-up: every indicator the
model leans on has a mundane explanation visible in the locators.

## Known rough edges — deliberate, but write them down

None of these block anything. They are recorded so they are found here rather than in a
viva.

1. ~~The memory severity path has never produced a non-Low result on a malicious
   input.~~ **Closed 2026-08-04.** `malicious_1.raw` took it to Critical, confirmed
   standalone and through the app — see "The malicious capture — measured 2026-08-04".
2. **5 of 10 scripts have no unit tests, by decision** — `ember_holdout`,
   `predict_vector`, `fetch_symbols`, `scan_image`, `dump_memory_features`. These are
   demo and operator utilities, not on the request path, so they are intentionally
   untested rather than overlooked; the effort belongs in the pipeline that ships.
   `malmem_holdout` and `verify_pipeline` are covered, and `patch_ember`, `check_env`,
   `setup_env` are environment tooling exercised by `check_env` itself.
3. **The UI has no visual regression testing.** Route tests assert strings, not layout — a
   CSS mistake would keep every test green.
4. **Disk progress is indeterminate** — "Vectorising executable N" with no percentage,
   because the PE count is unknown until the walk finishes.
5. **Held-out rows are the first matching row of each class**, not randomly sampled. Fine
   for a demo, recorded in the sidecar JSON, but it is one arbitrary row per class.
6. **Per-plugin timing is memory-only.** The disk extractor has no equivalent.

### Closed 2026-08-02

- **The refusal gate has now been exercised failing.** Against the real CSV: wrong outer
  `n_splits` (5), wrong inner (4), `random_state=0`, collapsed benign group keys and a
  one-row dedup error were each refused. `random_state=0` is the instructive one — it
  produces 41,533/8,257/8,272, within 80 rows of correct, which no eyeball would catch. A
  group-ignoring random split produced the **exactly correct** row counts and was caught by
  class balance plus **2,277 shared groups** between train and test, so the disjointness
  gate is load-bearing rather than redundant. `tests/test_malmem_holdout.py` pins each
  failure path without needing the 19 MB CSV.
- **Upload rate limit is configurable** — `UPLOAD_RATE_LIMIT`, env-overridable, default
  `60 per hour` (was a hardcoded 10). Read per request via a callable, so it can be raised
  for a capture session without editing `routes.py`. `TestConfig` pins it low so the
  limiter is still exercised.
- **`recover_orphans` now clears `stage` / `progress_pct` and unlinks the orphaned
  progress file.**
- **`predict_vector.py` no longer prints memory severity at all.** A bare vector carries no
  provenance, so severity is suppressed with a stated reason rather than computed against a
  foreign baseline.

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

**See "NEXT SESSION — in order" at the top of this file for the ordered checklist.** The
seven clean captures are in and processed (2026-08-03): baseline rebuilt from them with the
observed-max ceiling, OOD experiment run (§2), all seven verified Low. Extraction/build
scripts: `scripts/baseline_extract.py` (extract once, save vectors to
`data/baseline_vectors/`, gitignored) and `scripts/baseline_build.py` (median + max →
candidate JSON, then copy over `baselines/clean_win10_x64.json`).

The malicious memory capture landed and was fully validated 2026-08-04 — see the next
section. What remains: the malicious disk image, **optional pending supervisor
confirmation** (the disk pipeline already has a genuine EMBER true positive and the UPX
false-positive demo, so a third capture is polish, not a gap), the demo assembly, and the
write-up.

### The malicious capture — measured 2026-08-04

Captured with `scripts/sim_injector.py` (30 RWX regions) and `scripts/sim_spawnkill.py`
(100 held-open `cmd /c exit`) both running simultaneously, both windows showing
`READY FOR CAPTURE` before the capture started. `sample/memory/malicious_1.raw`, 2 GiB,
SHA-256 `b10325d8…d1def6` — confirmed twice: once by hashing the file on disk directly,
once independently by the app's own `artifacts.store()` during upload. Extraction took
4.2 minutes standalone (27 of 55 features out of training range).

**All four target indicators cleared their ceilings, three by more than predicted:**

| Indicator | Predicted | Measured | Ceiling | Ratio |
|---|---:|---:|---:|---:|
| `malfind.ninjections` | ~30 | **46** | 10.8 | 4.26× |
| `malfind.uniqueInjections` | ~30 | **9.2** | 5.4 | 1.70× |
| `malfind.commitCharge` | ~3840 | **5445** | 2215.2 | 2.46× |
| `psxview.not_in_pslist` | ~100 | **55** | 39.6 | 1.39× |

Per-process malfind breakdown (counted directly from a standalone plugin run, not
inferred): `python.exe` PID 4400 — **exactly 30 regions, exactly 3840 commit pages** — the
injector performed to the unit. The remaining 16 regions and 1605 commit pages are
legitimate: `MsMpEng.exe` (Defender, 5 regions), two `powershell.exe` hosts (5 each),
`smartscreen.exe` (1). Two deviations explained by that alone:

- **46, not 30** — three other processes also held qualifying RWX memory at capture time;
  the prediction assumed the injector would be the only one.
- **9.2, not 30** — `uniqueInjections = len(malfind) / distinct injected PIDs` = 46 / 5.
  The predicted value of 30 required the injector to be the *sole* PID holding RWX
  memory; whenever any other process legitimately does too, 30 is unreachable by
  construction. This is a documentation error in the original prediction, not a defect
  in the simulation or the extractor.
- **5445, not 3840** — 3840 injector + 1605 from the same three legitimate processes.

**`psxview.not_in_pslist` landed weakest of the four (1.39×) and for a real reason — see
silent bug #8 below.** The spawn-kill's intended mechanism was measured to be wrong.

**Severity reached Critical, confirmed twice and robust to indicator reduction.** Run once
via the shipped forensics functions directly over the extracted vector, and once through a
full app run (register → login → 2 GB streamed upload → sniff → confirm type → job 3 →
PDF). Identical result both times:

```
2 high-risk indicator categories elevated against the clean-system baseline;
6 indicators elevated against baseline;
model score withheld from severity: capture is out of distribution
```

Techniques: **T1055 Process Injection** (`malfind.ninjections`, `commitCharge`,
`uniqueInjections`, all elevated) and **T1014 Rootkit / Hidden Artifacts**
(`psxview.not_in_pslist`, `not_in_ethread_pool`, `not_in_csrss_handles`, all elevated).
Tested against reduced indicator sets rather than assumed:

| Scenario | Severity |
|---|---|
| As measured (6 indicators elevated) | **Critical** |
| Only the originally predicted set (malfind + `not_in_pslist`) | **Critical** |
| malfind only, as if the spawn-kill had produced nothing | High |

So Critical does not depend on the two indicators the spawn-kill hit unpredictedly (see
below); "injection alone → High" from the pre-capture analysis is confirmed exactly.

**Per-process evidence — both simulations are individually visible.** Injected regions
name `python.exe` PID 4400 at its actual addresses (e.g. `0x17610710000`, 512 KB,
`PAGE_EXECUTE_READWRITE`, 128 commit pages). Hidden processes are all `conhost.exe`,
missing from `pslist`/`thrdscan`/`csrss`, with exit times `19:53:48–49 UTC` — about
3.5 minutes before the capture file was written, i.e. legibly the spawn-kill's timeline.
`unbacked_callbacks: 0`. Volumetric context correctly flagged process count 182 vs clean
max 92 (2.0×) as configuration context that cannot reach severity on its own.

**Model score: probability 0.4740 (threshold 0.2337), OOD 27/55, 4 of 4 dominant features
out of range → withheld from severity, as designed.** This completes the OOD experiment
(§2): the seven clean captures scored 0.0077–0.0081; this one scores 0.4740, roughly
**60× higher**. The model does discriminate this capture from clean ones, but it stayed
correctly gated regardless — the gate is not being unlocked, this is not reopening the
SMOTE investigation, and severity was driven entirely by the evidence-led path.

**End to end through the app, verified rather than assumed.** Real HTTP against `run.py`
(no test client): 2 GB streamed upload at 535 MB/s; `artifacts.sniff()` correctly returned
`NEEDS_TYPE` (raw memory carries no magic bytes, exactly as designed); confirmed as
memory; job 3 completed in 180s. The rendered PDF (17,863 bytes) carries every mandatory
limitation string plus `Critical`, `T1055`, `T1014`, and the evidence tables. The
executive summary correctly attributes severity to the behavioural engine rather than the
model: *"This report leads with what was observed in the capture rather than with a model
score... The model's own verdict is reported for reference only."* Verdict detail
separately states the model score was "withheld from severity" — hard rule 22 holds.
Artifact confirmed unreachable on `/uploads/<name>`, `/static/<name>`, `/uploads/` and bare
`/<name>` (all 404), stored outside the web root as `a0a8189…1def6.raw`.

**A runtime observation, stated as an observation and not a conclusion.** First
instrumented run in the fast regime: 180s total, malfind 64.3s / handles 37.6s / psxview
26.6s / svcscan 15.2s / ldrmodules 14.3s / callbacks 12.8s. Against the two previously
recorded slow runs (352–357s: malfind ~126s, handles ~82s, svcscan ~38s, ldrmodules ~33s)
every plugin scales by roughly the same **2.0–2.5×**, not concentrated in one plugin. This
is **not a controlled comparison** — this capture also has 2.7× more processes than the
earlier instrumented runs, which independently costs some of that time — so the uniform
ratio is worth recording, not concluding from. The run-to-run variance is still
unattributed.

### Silent bug #8 — a wrong theory about `psxview`, corrected by measurement

`sim_spawnkill.py`'s original docstring, and the "finalised malicious-capture recipe" in
an earlier version of this file, predicted that holding a handle to a terminated process
keeps its `EPROCESS` resident in pool while it drops out of `pslist` — i.e. that the
technique would drive `psxview.not_in_pslist`. **Measured on `malicious_1.raw`, that is
not what happens.**

`pslist.nproc` jumped from a clean 60–92 to **182** — the ~100 zombies are *counted as
live processes*, not hidden from pslist. Comparing process counts derivable from the
psxview family against the clean range makes this concrete:

| | Clean range (7 captures) | Malicious |
|---|---|---:|
| `pslist.nproc` | 60–92 | **182** |
| Processes with live thread objects (`nproc + not_in_pslist − not_in_ethread_pool`) | 76–91 | **80** |
| Processes with CSRSS session entries | 70–82 | **71** |

The machine had a perfectly ordinary number of *real* processes throughout (80, 71) —
squarely inside the clean range. Holding a handle keeps a terminated `EPROCESS` linked in
the same list `pslist` walks, so it does not go missing from pslist; what it does lose,
regardless of who holds a handle to it, is its thread objects and its CSRSS session entry,
because those are torn down at process exit independent of reference count. That is why
the two indicators that actually spiked were ones nobody predicted:

- `psxview.not_in_ethread_pool` — 157, **21.8× its ceiling** (no thread objects survive)
- `psxview.not_in_csrss_handles` — 166, **8.1× its ceiling** (CSRSS entry dropped)

while `not_in_pslist` — the one the whole recipe was built around — only reached **1.39×**
its ceiling, the weakest of the six elevated indicators. It is genuinely the hardest of
the three to move on this baseline: a clean fresh boot alone already reaches 33 (psscan
still finds terminated boot processes), so its ceiling of 39.6 was always going to be
close to what state noise alone produces.

**This does not change the outcome — Rootkit / Hidden Artifacts still elevated, Critical
still reached, confirmed robust above — but it changes the *reason*, and the mechanism
written into `sim_spawnkill.py`, this file, and CLAUDE.md's build history was wrong until
this measurement.** `scripts/sim_spawnkill.py`'s docstring is corrected as of 2026-08-04
to describe the mechanism as measured. Filed alongside the other seven silent bugs below,
because it is the same shape as all of them: a plausible theory about internals that
looked right, produced a correct-looking outcome for the wrong stated reason, and was only
caught by running a real artifact through the pipeline and reading the actual numbers
rather than trusting the prediction.

### Disk — optional, pending confirmation

The disk malicious image and its test infrastructure remain deliberately unbuilt. Check
with the supervisor whether it is still wanted: the disk pipeline already has a genuine
EMBER-held-out true positive (§ "Demo plan", p=0.999838) and the UPX-packing
false-positive demonstration, both real evidence with no malware file ever opened. A
purpose-built malicious image would be a third, more elaborate demonstration of a path
that is already proven, not a missing capability.