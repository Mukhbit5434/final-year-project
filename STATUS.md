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

**Memory x64** — `win10_memory.raw`, 3.5 min. Ground truth measured inside the VM at
capture time: processes 67 vs 67 exact, drivers 360 vs 362, services+drivers 632 vs 615.
Extraction is correct in absolute terms; the training range really is far below reality.

**Memory x86** — `Windows 10-32-f7257ea7.vmem`, 3.5 min, needs the custom PAE layer that
stock Volatility cannot build.

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
- The clean baseline is **one capture**. It anchors order of magnitude, not a threshold —
  `malfind.commitCharge` spans 200× across captures of a single machine.
- A UPX-packed benign binary is flagged (0.0010 → 0.6607). Useful for demonstrating the
  detection path; it is a false positive and must be worded as one.

## Outstanding

**Nothing is blocking.** Two optional items, both waiting on the user:

1. **More clean captures** for the variance distribution — fresh boot, idle, browser open,
   during a Defender scan, and *within ~30 s of closing several applications* (that last
   state drives `psxview.not_in_pslist`, the worst-variance indicator, and none of the
   others reach its peak). Two captures 15 s apart in one state separate capture noise
   from state noise. `baselines/` takes additional entries.
2. **A demo positive for the disk pipeline** — build a small raw image containing
   UPX-packed benign binaries so the findings → tags → severity → report path can be shown
   producing a detection. Confirmed to work; not yet built.

## The exact next task

Build the demo image for item 2 above: create a small raw disk image, place two or three
UPX-packed benign binaries on it alongside unpacked ones, run it through the pipeline, and
confirm the report renders a flagged file with its path, SHA-256, `T1027` tag and severity
— with the wording making clear it is packing, not malware. Everything needed for this
already works; it is assembly, not new capability.