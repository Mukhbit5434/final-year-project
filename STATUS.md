# STATUS — where the project is right now

Last updated 2026-08-03. `CLAUDE.md` is the spec and the binding rules; this file is the
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
- **The malicious capture is the last empirical piece.** Two benign simulation tools are
  written, smoke-tested and committed: `scripts/sim_injector.py` (30 RWX regions, marker
  written, nothing executed) and `scripts/sim_spawnkill.py` (100 `cmd /c exit`, handles
  held so the terminated EPROCESS stay in pool). See the run order and expected results
  under "The exact next task".

## NEXT SESSION — in order

1. **Receive `malicious_1.raw`** (the user runs both sim tools, captures with both windows
   open). Run it through the full pipeline (`scripts/verify_pipeline.py` picks up anything
   in `sample/`, or upload via the web app). **Confirm the expected result:**
   ninjections 30, uniqueInjections 30, commitCharge ~3840, not_in_pslist ~100 →
   Process Injection (T1055) + Rootkit (T1014) → **Critical**. This is the first time
   severity reaches High/Critical on real evidence — the memory pipeline's headline claim.
   Record the actual numbers here. Also completes the OOD experiment (§2): confirm the
   malicious capture scores materially different from the seven clean ones.
2. **Receive the malicious disk image(s).** Run disk detection; confirm it flags the
   planted malicious PE(s) with path + SHA-256 (hard rule 16). Record results.
3. **Assemble the demo set** — see "Demo plan" below. Wire the three memory parts and three
   disk parts into a runnable sequence; the held-out vectors and `predict_vector.py` already
   cover demos that need no new capture.
4. **Write-up** — the FYP report, screenshots, and the settled findings (SMOTE saturation,
   the seven silent bugs, the ceiling design, the unreachable-indicator honesty).

Test infrastructure for the malicious artifacts is deliberately **not** built yet; specify
it together with the captures so it matches what actually lands.

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

## Seven silent bugs found by running real artifacts

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

1. **The memory severity path has never produced a non-Low result on a malicious input.**
   `severity.for_memory` counts indicators *elevated against the baseline*, and the only
   malicious memory data we have is CIC-MalMem rows, which are cross-machine and therefore
   read Low. Unit tests drive the function directly, but no real artifact has ever taken it
   to High or Critical. The simulated-malicious capture is the first thing that will.
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

### The malicious capture — run order and expected results (survives to the capture session)

Tools committed and smoke-tested: `scripts/sim_injector.py`, `scripts/sim_spawnkill.py`.

1. Defender: put the scripts' folder in the exclusion list (the injector allocates 30 RWX
   regions and may trip behaviour monitoring). Capture at least one clean dump under the
   **same** Defender config so it is comparable to the malicious one.
2. Terminal 1: `.venv\Scripts\python scripts\sim_injector.py` → note the PID it prints →
   wait for `READY FOR CAPTURE`, leave open.
3. Terminal 2: `.venv\Scripts\python scripts\sim_spawnkill.py` → wait for `READY FOR
   CAPTURE`, leave open. Handles are held, so there is **no timing race** — the terminated
   processes stay resident while the window is open.
4. With both windows open, run Magnet RAM Capture → save as `sample/memory/malicious_1.raw`.
5. After the file is written, press Enter in each terminal to release.

Expected on the capture (clean ceilings in parentheses): `malfind.ninjections` 30 (10.8),
`malfind.uniqueInjections` 30 (5.4), `malfind.commitCharge` ~3840 (2215),
`psxview.not_in_pslist` ~100 (39.6) → **T1055 + T1014, two high-risk techniques, ≥2
elevated → Critical**. The injector shows as `python.exe` at the noted PID holding 30 RWX
regions in the per-process evidence; ~100 hidden `cmd.exe` appear as processes missing from
pslist. Injection alone would give High; the spawn-kill provides the second technique for
Critical.

The disk malicious image and the test infrastructure for both are still deliberately
unbuilt; specify them with the captures.