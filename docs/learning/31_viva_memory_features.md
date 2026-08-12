# 31 — Viva Deep Dive: All 55 Memory Features

Every number below is read straight from `models/memory/feature_list.json`
(the exact 55 names, in the exact order the model expects them) and
cross-checked against `app/extractors/memory.py` (which actually computes
them) and `app/forensics/meanings.py` (which explains the ones the report
surfaces to an analyst). File 10 (`10_extraction_memory.md`) already walks
the extractor's source code line by line — this file's job is different:
it's organised **feature by feature**, as an exam would ask about them, not
function by function.

## The shape of the whole list, before the detail

55 features come from **nine Volatility 3 plugins**, in these group sizes:

| Group | Count | Plugin (Volatility 3 class) |
|---|---:|---|
| `pslist` | 5 | `windows.pslist.PsList` |
| `dlllist` | 2 | `windows.dlllist.DllList` |
| `handles` | 13 | `windows.handles.Handles` |
| `ldrmodules` | 6 | `windows.malware.ldrmodules.LdrModules` |
| `malfind` | 4 | `windows.malware.malfind.Malfind` |
| `psxview` | 14 | `windows.malware.psxview.PsXView` |
| `modules` | 1 | `windows.modules.Modules` |
| `svcscan` | 7 | `windows.svcscan.SvcScan` |
| `callbacks` | 3 | `windows.callbacks.Callbacks` |
| **Total** | **55** | |

Every group's real-world question, in one line each, before the per-feature
detail: **pslist** — what processes exist and how big are they? **dlllist**
— what's loaded into each process? **handles** — what kernel objects is
each process holding open? **ldrmodules** — does what's loaded match what
Windows' own bookkeeping says should be loaded? **malfind** — is there
executable code sitting in memory with no file behind it? **psxview** — do
different ways of listing "every process" actually agree with each other?
**modules** — what's loaded at the kernel level? **svcscan** — what
services and drivers are registered? **callbacks** — what kernel-level
hooks has anything installed?

## `pslist` — the process list itself (5 features)

**What it measures:** the basic shape of the running system — how many
processes exist, how big they are, and a couple of properties about their
parent-child relationships. **Plugin:** `windows.pslist.PsList`, the most
fundamental Volatility plugin there is — it walks the kernel's own doubly-
linked list of `EPROCESS` structures (`PsActiveProcessHead`), the same list
Task Manager itself ultimately reads from.

1. **`pslist.nproc`** — the total number of process rows found. Simply
   `len(rows)`. Forensically, this is the closest thing to "how big is this
   machine, workload-wise" — a huge jump against a clean baseline (this
   project's malicious capture hit 182 against a clean range of 60–92) is
   worth investigating even before looking at anything more specific.
2. **`pslist.nppid`** — the number of **distinct** parent process IDs
   across all processes (`{r.get("PPID") for r in rows}` — a Python `set`,
   which automatically discards duplicates). `pslist.avg_threads` divides by
   `nproc`; this one is a plain count. It's flagged `inferred` in this
   project's own gap list — two equally plausible readings of the original
   training feature fit the data (`distinct parent count` vs `processes
   with a live parent`), and this project settled on the reading
   VolMemLyzer's own source code actually computes.
3. **`pslist.avg_threads`** — total thread count summed across every
   process, divided by the process count. This is where "torn rows" from
   live acquisition (file 10 covers this in depth) matter most: one garbage
   row with a thread count of 333 million would make this average
   meaningless, so it's computed only from rows that pass a basic sanity
   check first.
4. **`pslist.nprocs64bit`** — despite the name, this counts **WOW64**
   processes: 32-bit processes running under emulation on a 64-bit kernel,
   not 64-bit processes. It's a genuine naming trap in the reference
   implementation this project deliberately reproduces rather than "fixes"
   (hard rule 24) — always `0` in training, because the training VM never
   ran a 32-bit process. This feature received **zero splits** in the
   shipped model (verified directly from the model file — see the
   "Features the model actually uses" section below), so getting this
   value wrong would not currently change a single prediction, but it's
   still computed correctly on principle.
5. **`pslist.avg_handlers`** — total open handles (from the separate
   `handles` plugin, not from `pslist` itself) divided by process count.
   Volatility 3 simply leaves `pslist`'s own `Handles` column empty, so this
   feature has to borrow its numerator from a different plugin's output
   entirely — a good example of why every derivation in this file was
   checked against the real reference implementation rather than assumed
   from the feature's name.

## `dlllist` — loaded modules per process (2 features)

**What it measures:** how many DLLs (dynamically loaded libraries) are
mapped into running processes, and how concentrated that loading is.
**Plugin:** `windows.dlllist.DllList`, which walks each process's own
loaded-module list.

1. **`dlllist.ndlls`** — total DLL-loaded-into-a-process rows, across every
   process in the dump.
2. **`dlllist.avg_dlls_per_proc`** — `ndlls` divided by the number of
   **distinct processes that actually appear in `dlllist`'s own output** —
   not by `pslist.nproc`. This matters: a process whose module list simply
   couldn't be read never shows up in `dlllist` at all, and dividing by the
   wrong denominator produces a measurably different (about 1.8% off)
   number than the real reference implementation computes.

## `handles` — open kernel object handles, by type (13 features)

**What it measures:** what kinds of kernel objects each process is
currently holding a reference to. **Plugin:** `windows.handles.Handles`,
which walks every process's handle table.

1. **`handles.nhandles`** — the total handle count across every process, of
   every type.
2. **`handles.avg_handles_per_proc`** — `nhandles` divided by the number of
   distinct processes appearing in the handles output itself (same
   "denominator from this plugin's own rows, not `pslist.nproc`" pattern as
   `dlllist` above).
3. **`handles.nport`** — always `0.0`, hardcoded. `Port` objects are an
   XP/2003-era Windows concept that doesn't exist on any modern Windows
   build, so this is honestly always zero rather than an extraction gap.
   Received **zero splits** in the shipped model.
4. **`handles.nfile`** — open **File** object handles. How many files each
   process currently has open — a very ordinary thing for almost any
   process to have some of, so this one is more useful in combination with
   other indicators than alone.
5. **`handles.nevent`** — open **Event** object handles, a synchronization
   primitive processes use to signal each other. Legitimate everywhere, but
   also a common building block for coordinating multiple pieces of
   malware or multiple stages of an attack.
6. **`handles.ndesktop`** — open **Desktop** object handles. Windows lets a
   process create and attach to an alternate, invisible desktop — a
   technique some malware families use to run a hidden GUI (a "hidden VNC"
   style attack) where the user never sees the window at all.
7. **`handles.nkey`** — open **registry key** handles. Persistence (making
   malware survive a reboot) is very often written through a registry key,
   so a process holding an unusually large number of key handles open,
   especially autorun-related ones, is a mundane-until-it-isn't signal.
8. **`handles.nthread`** — open **Thread** object handles (a handle
   *referencing* a thread, not the thread count itself — that's
   `pslist.avg_threads`). Relevant to injection: to inject code into
   another process's thread, or to remotely start a new one, you generally
   need a handle to a thread first.
9. **`handles.ndirectory`** — open **Directory** object handles. This is
   the Windows **object manager's** own namespace directories (like
   `\BaseNamedObjects`), a kernel bookkeeping concept — not filesystem
   folders. A weaker standalone signal than most of the others here.
10. **`handles.nsemaphore`** — open **Semaphore** object handles, another
    synchronization primitive (like a mutex, but allowing more than one
    owner at a time) — commonly used to limit how many threads run a piece
    of work concurrently. Received **zero splits** in the shipped model.
11. **`handles.ntimer`** — open **Timer** object handles. Kernel timers can
    be used to schedule code to run after a delay — a known evasion trick
    ("sleep, then act") to dodge short-duration sandboxed analysis.
12. **`handles.nsection`** — open **Section** object handles. Section
    objects are how Windows maps shared memory (including a file's own
    executable image) between processes — one of the actual underlying
    mechanisms process injection can use to move code from one process into
    another.
13. **`handles.nmutant`** — open **Mutant** (mutex) handles. This is one of
    the four features the shipped model leans on hardest (see below).
    Malware very commonly creates a named mutex purely as a "have I already
    infected this machine" single-instance check — the value shows up
    constantly in real-world threat intelligence as a literal identifying
    string for a malware family. Ordinary software uses mutexes too, so
    this is suggestive, not conclusive, on its own.

## `ldrmodules` — does the loader's own bookkeeping agree with itself? (6 features)

**What it measures:** for every module mapped into every process, whether
it's consistently present across **three separate linked lists** the
Windows loader (the PEB, Process Environment Block) is supposed to keep in
sync: the load-order list, the initialization-order list, and the
memory-order list. **Plugin:** `windows.malware.ldrmodules.LdrModules`.

A module that's genuinely mapped into memory but missing from one or more
of these lists is a classic sign of **DLL hiding or process hollowing** —
malware that manually maps its own code into a process without going
through the normal loader path leaves exactly this kind of inconsistency
behind, because the normal loader is what keeps all three lists updated
together. That said, ordinary loading also produces some of these
mismatches (early-boot processes especially), so this project's own clean
baseline shows real, non-zero counts here too — it's an indicator to weigh
against a known-clean baseline, not a binary "found or not."

1. **`ldrmodules.not_in_load`** — missing from the load-order list.
2. **`ldrmodules.not_in_init`** — missing from the initialization-order
   list. The comment in the extractor notes this one specifically as what
   "unlinking" rootkit techniques commonly leave inconsistent.
3. **`ldrmodules.not_in_mem`** — missing from the memory-order list, the
   third of the three lists an unlinking technique would have to patch
   consistently to hide completely. Received **zero splits** in the
   shipped model, despite being one of the three raw counts here — its
   `_avg` sibling below carries the weight instead.
4. **`ldrmodules.not_in_load_avg`**, **5. `not_in_init_avg`**,
   **6. `not_in_mem_avg`** — each raw count above, divided by `ldrmodules`'s
   own total row count (confirmed the correct denominator — dividing by
   `dlllist.ndlls` instead leaves a consistent, measurable error). This
   turns a raw count into a rate that's comparable across captures with
   very different total module counts.

**Known limit, worth stating honestly in a viva:** on this project's own
reference machine, these features are effectively **unreachable** as a
severity-driving indicator. Their clean-baseline ceilings sit at 500+
(`STATUS.md`, measured across seven clean captures), and a real reflective
DLL load only adds 1–3 to the count — nowhere close. That's a property of
this specific reference machine's baseline, not a flaw in the features
themselves; a quieter machine would make them far more discriminating.

## `malfind` — executable code with no file behind it (4 features)

**What it measures:** private memory regions marked executable that don't
correspond to any file mapped from disk — the classic shape of injected
shellcode or a manually-mapped payload. **Plugin:**
`windows.malware.malfind.Malfind`, which walks every process's VAD (Virtual
Address Descriptor) tree and flags regions matching a specific set of
criteria (executable-and-writable, or a dirty executable-only page; private
memory or non-copy-on-write; not entirely paged out or empty — CLAUDE.md
§9.5's "malfind actually counts" section spells this out in full).

CLAUDE.md calls this the single most reliable **behavioural** indicator
this whole pipeline has, and this project's own real malicious capture
(`sample/memory/malicious_1.raw`) backs that up directly: all three
`malfind`-family features cleared their baseline ceilings, by 1.7×–4.3×,
while the actual injecting process (`python.exe`, in the simulation) held
exactly 30 regions and exactly 3,840 committed pages — the tool performed
to the exact number it was designed to hit.

1. **`malfind.ninjections`** — the count of flagged regions across the
   whole dump.
2. **`malfind.commitCharge`** — the sum of committed pages across every
   flagged region. Large values mean substantial injected content, not
   just a few stray pages.
3. **`malfind.protection`** — the sum of each flagged region's page
   protection, expressed as **Volatility 2's own small numeric index**
   (0–7) into its protection-flag list, not the real Win32 constant — a
   fact only recoverable by reverse-engineering the training data itself,
   since the dataset authors never documented it (flagged `inferred`).
4. **`malfind.uniqueInjections`** — regions divided by the number of
   distinct **injected** processes (processes that appear at all in
   `malfind`'s own output). This measures *concentration*: many regions in
   one process reads differently from one region scattered across many
   processes. Also flagged `inferred` — its true original derivation was
   never documented, and this is the best-fitting hypothesis against the
   real training data (values as high as 68.25, ruling out any simple
   integer count).

## `psxview` — do different ways of enumerating processes agree? (14 features)

**What it measures:** whether a process that shows up under one detection
method also shows up under every other independent method. **Plugin:**
`windows.malware.psxview.PsXView`. The idea: malware hiding a process from
the *normal* process list often fails to hide it from a completely
different enumeration method (like scanning raw memory pools for leftover
process structures) — a mismatch between methods is a classic rootkit
indicator (Direct Kernel Object Manipulation, DKOM).

Volatility 2 (what the training dataset's tool used) checked **seven**
independent sources; Volatility 3 (what this project runs) checks only
**four** — confirmed against the actually-installed library, not
documentation. That leaves **six of these fourteen features structurally
unreachable** and honestly emitted as `0.0`:

| Feature | Volatility 3 source | Available? |
|---|---|---|
| `psxview.not_in_pslist` | `pslist` column | yes |
| `psxview.not_in_eprocess_pool` | `psscan` column | yes |
| `psxview.not_in_ethread_pool` | `thrdscan` column | yes |
| `psxview.not_in_pspcid_list` | — | **no → 0.0** |
| `psxview.not_in_csrss_handles` | `csrss` column | yes |
| `psxview.not_in_session` | — | **no → 0.0** |
| `psxview.not_in_deskthrd` | — | **no → 0.0** |

Plus the seven paired `_false_avg` variants (each raw count divided by
`psxview`'s own total row count — confirmed correct: dividing by
`pslist.nproc` instead leaves a consistent ~2.27% error, because `psscan`
legitimately finds some terminated processes `pslist` doesn't) — so three
more of those, `not_in_pspcid_list_false_avg`, `not_in_session_false_avg`
and `not_in_deskthrd_false_avg`, are also always `0.0`.

1. **`psxview.not_in_pslist`** — found by another method but missing from
   the standard process list. The classic DKOM signature — but a
   terminated process that `psscan` still finds sitting in freed memory
   looks *identical* to a genuinely hidden one, so this needs a clean
   baseline to interpret. Measured directly on this project's own clean
   captures: a **fresh boot alone** legitimately reaches 33 (`psscan` still
   sees terminated boot processes), which sets this feature's usable
   ceiling around 40 on this specific machine.
2. **`psxview.not_in_eprocess_pool`** — visible to list-walking but not
   found by pool scanning.
3. **`psxview.not_in_ethread_pool`** — no matching thread objects were
   found by pool scanning for this process. This was the single biggest
   mover on this project's real malicious capture — **21.8× its ceiling**
   — because holding a handle to a terminated process keeps the process
   entry itself resident, but its thread objects still get torn down at
   exit regardless (see the "Silent bug #8" story in `STATUS.md` — the
   originally-predicted mechanism for the simulated attack was wrong, and
   this measurement corrected it).
4. **`psxview.not_in_pspcid_list`** — structural gap, always `0.0`.
5. **`psxview.not_in_csrss_handles`** — missing from the Windows subsystem
   process's own handle table, which normally holds a handle to every
   session process. One of the older hiding indicators; on the same real
   malicious capture this reached **8.1× its ceiling**.
6. **`psxview.not_in_session`** — structural gap, always `0.0`.
7. **`psxview.not_in_deskthrd`** — structural gap, always `0.0`.
8–14. **The seven `_false_avg` variants**, in the same order as their base
   features above — each is the raw count divided by `psxview`'s own row
   count, so three of these seven are also always `0.0` for the same
   structural reason as their base features.

## `modules` — loaded kernel modules (1 feature)

**What it measures:** how many kernel-mode modules (drivers) are currently
loaded, system-wide. **Plugin:** `windows.modules.Modules`, which walks the
kernel's own `PsLoadedModuleList`.

1. **`modules.nmodules`** — simply the row count. This is a genuinely
   different enumeration from `svcscan.kernel_drivers` below: `modules`
   lists what the kernel currently has **actually loaded in memory** right
   now, while `svcscan` lists what's **registered** in the Service Control
   Manager's own database (which can include drivers that are registered
   but not currently loaded, or vice versa for some load types). This
   feature's training range is only **137–138** — a two-value range that's
   a direct symptom of the dataset's SMOTE-balanced benign half (see file
   33 and `CLAUDE.md` §2), not a real property of any actual Windows
   machine; a real capture reads roughly **163–400**.

## `svcscan` — registered services and drivers (7 features)

**What it measures:** what's registered in the Service Control Manager's
own database — the standard, most common way malware achieves persistence
on Windows (a service that starts automatically survives reboots without
the user having to do anything). **Plugin:** `windows.svcscan.SvcScan`.

A real, measured bug in Volatility 3 itself lives directly upstream of this
group: `svcscan` scans every process's memory for a specific tag marking
the service list, and can find and re-walk the *same* list from more than
one process's memory, producing genuine duplicate rows (measured: 1,311 raw
rows for only 594 real services on one real capture). This project
deduplicates on each service's `Order` field (its position in the list,
genuinely unique per real service) before computing any of the seven
features below.

1. **`svcscan.nservices`** — total distinct services and drivers, **after**
   deduplication, with **no filter on running state** (confirmed: `nactive`
   is always smaller than `nservices` across all 5,000 reference rows, and
   the code takes the plain row count, not a running-only subset). This is
   the single highest-gain feature in the entire model (see below) — but
   it's a **configuration** count (how much software/how many drivers this
   machine has installed) rather than a **behavioural** one.
2. **`svcscan.kernel_drivers`** — services of type `SERVICE_KERNEL_DRIVER`,
   exact string match. Kernel-mode drivers run with full system privilege.
3. **`svcscan.fs_drivers`** — services of type `SERVICE_FILE_SYSTEM_DRIVER`.
4. **`svcscan.process_services`** — services of type
   `SERVICE_WIN32_OWN_PROCESS` — a service that runs in its own dedicated
   process, as opposed to sharing one.
5. **`svcscan.shared_process_services`** — services of type
   `SERVICE_WIN32_SHARE_PROCESS` — hosted inside a shared `svchost.exe`
   process alongside other, unrelated services. This is a routine place to
   hide a malicious service among entirely legitimate ones, since dozens of
   real Windows services already share `svchost` processes by design.
6. **`svcscan.interactive_process_services`** — **structurally always
   `0.0`**, by design, not by accident. Windows only ever exposes
   "interactive" as part of a **combined** flag string (something like
   `SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS`), never as the
   bare standalone string this project's exact-equality check looks for —
   so the comparison genuinely can never match. This reproduces
   VolMemLyzer's own real behaviour exactly (hard rule 24); "fixing" it
   with a substring match would un-zero a feature the model has literally
   never seen vary. Received **zero splits** in the shipped model.
7. **`svcscan.nactive`** — services literally in the `SERVICE_RUNNING`
   state at capture time. Always smaller than `nservices` (confirmed across
   5,000 reference rows), which itself ruled out an earlier, plausible
   alternative theory that `nservices` might already mean "running
   services only."

## `callbacks` — kernel notification routines (3 features)

**What it measures:** routines the Windows kernel invokes automatically on
events like process creation, thread creation, or image (module) loading —
a legitimate mechanism (antivirus and EDR products use it constantly), but
also one malware can register itself into for kernel-level monitoring or
persistence. **Plugin:** `windows.callbacks.Callbacks`.

1. **`callbacks.ncallbacks`** — total registered callback routines found.
2. **`callbacks.nanonymous`** — callbacks whose owning module Volatility
   couldn't resolve at all, reported literally as the string `"UNKNOWN"`
   (exact match, not a substring check, to avoid also counting blank or
   `"N/A"` values). A callback whose target module can't be resolved
   suggests the module was unloaded or hidden *after* registering the
   callback — the hook survives even though its owner is now gone.
3. **`callbacks.ngeneric`** — callbacks of a specific
   `GenericKernelCallback` type. Constant at exactly `8.0` across every row
   of the training data — computed honestly here rather than hardcoded
   (the reasoning: a constant *input* doesn't excuse incorrect *logic*),
   but a feature the model never once saw vary during training was never
   used to split any of its trees either — confirmed: **zero splits** in
   the shipped model.

## How the extractor actually turns a raw dump into these 55 numbers

Walking the real path, start to finish (full code detail in file 10):

1. **A raw dump goes into `extract(dump, feature_names, progress=None)`**
   in `app/extractors/memory.py`, running inside a background worker
   process (never inside the Flask web process itself).
2. **`build_context(dump, catalog)`** builds a Volatility 3 context pointed
   at the file, and — using Volatility's own "automagic" profile detection
   — resolves just enough of one lightweight plugin (`PsList`) to determine
   the memory layer's actual class. If that class isn't `Intel32e` (64-bit
   x86), extraction stops immediately with a clear error — this is the
   concrete enforcement of "Windows 10 x64 only" (`CLAUDE.md` §11.1),
   happening **before** any of the nine real plugins run at all.
3. **Nine plugins run, one after another**, via `run_plugin()`, each
   reusing the already-resolved memory layer rather than re-resolving it
   from scratch nine times. Every plugin's raw output — Volatility's own
   internal "tree grid" object model — gets converted immediately into
   plain Python dictionaries (`dict(zip(cols, node.values))`), so nothing
   downstream of this point ever touches Volatility's own objects again.
4. **`svcscan`'s rows get deduplicated** (`dedupe_services()`, keyed on
   `Order`) before anything else touches them, fixing the real duplication
   bug described above.
5. **Nine `from_*()` functions**, one per plugin family, each turn that
   plugin's plain-dictionary rows into a small `{feature_name: value}`
   dictionary — `from_pslist()`, `from_dlllist()`, `from_handles()`,
   `from_ldrmodules()`, `from_malfind()`, `from_psxview()`,
   `from_modules()`, `from_svcscan()`, `from_callbacks()`.
6. **`assemble()` merges all nine dictionaries together**, keyed by name —
   **not** by position, at any point up to here — then, on its very last
   line, builds the final ordered list by looking each of the 55 names in
   `feature_list.json` up **by name**: `[float(values[name]) for name in
   feature_names]`. This is the concrete implementation of the rule that
   ordering is never hand-sequenced anywhere along the way — it's imposed
   exactly once, at the very end, directly from the model's own JSON list.
7. **The result**: a plain Python list of 55 floats, in the exact order
   `models/memory/xgboost_model.json` expects them, plus an honestly
   populated `extraction_gaps` list documenting every feature that's
   missing or inferred rather than measured with full confidence.

## Features the model actually uses — the concentration finding, freshly verified

This project's own documentation (`CLAUDE.md` §5.4a) describes four
features carrying "roughly 98% of total gain" with "an 80× cliff after the
fourth." For this guide, that claim was re-derived directly from the
shipped model file rather than just quoted — `models/memory/xgboost_model.json`
was loaded and its real per-feature gain was computed:

| Rank | Feature | Gain | Cumulative % of total |
|---:|---|---:|---:|
| 1 | `svcscan.nservices` | 3346.20 | 27.32% |
| 2 | `handles.nmutant` | 3238.32 | 53.75% |
| 3 | `svcscan.shared_process_services` | 3132.61 | 79.32% |
| 4 | `svcscan.kernel_drivers` | 2317.06 | **98.24%** |
| 5 | `svcscan.process_services` | 39.49 | 98.56% |

The top four really do carry **98.24%** of total gain — confirmed, not
approximated — and the average gain of those top four is **76.2×** the
5th-ranked feature's gain, matching the documented "80× cliff" closely.
Three of those four dominant features are counts of *installed services
and drivers* — a property of how a machine is configured, not of what it
did — which is the mechanical reason `app/inference/memory.py`'s
`dominant_ood()` check exists: when those four specific features fall
outside their training range, the model's probability is demoted to a
secondary signal rather than trusted as the headline (file 34 covers this
gate in full).

**Also freshly computed for this guide:** of the 55 features, **12 never
received a single split anywhere in the entire trained ensemble** — they
contributed literally nothing to any prediction the model has ever made:
`pslist.nprocs64bit`, `handles.nport`, `handles.nsection`,
`ldrmodules.not_in_mem`, `psxview.not_in_eprocess_pool`,
`psxview.not_in_session`, `psxview.not_in_eprocess_pool_false_avg`,
`modules.nmodules`, `svcscan.fs_drivers`,
`svcscan.interactive_process_services`, `callbacks.nanonymous`,
`callbacks.ngeneric`. Four of those twelve are the training-constant
features `CLAUDE.md` §5.3 already documents by name
(`pslist.nprocs64bit`, `handles.nport`, `svcscan.interactive_process_services`,
`callbacks.ngeneric`) — a constant column carries zero information gain, so
it was mathematically guaranteed never to be split on, and this
computation confirms it directly rather than just trusting the reasoning.

**The six structurally-missing `psxview` features (the Volatility 2→3 gap)
carry, together, exactly 0.21% of total model gain** — also freshly
computed, matching `CLAUDE.md`'s "0.2% of the model's total gain" claim
almost exactly. That's the quantitative backing for why this project treats
the psxview gap as "a disclosure item, not a correctness problem" — it's a
real, honestly-reported gap, but it was never going to move a verdict by
more than a fraction of a percent even in principle.

## Check your understanding

**Q1. `pslist.nprocs64bit` sounds like it should count 64-bit processes,
but it doesn't. What does it actually count, and does getting this feature
wrong matter to the model's real-world predictions?**

A: It counts **WOW64** processes — 32-bit processes running under
emulation on a 64-bit kernel — the near-opposite of what its name suggests.
This project reproduces that reference-implementation behaviour exactly
rather than "fixing" it (hard rule 24), because the model was trained on
the real, if oddly-named, VolMemLyzer output. In practice it barely
matters either way: this feature received zero splits in the shipped
model, confirmed directly from the model file — it has never once
contributed to a prediction.

**Q2. Why are six of the fourteen `psxview` features always `0.0` on this
project's extractor, and how much does that actually cost the model?**

A: Volatility 2 (what the training dataset's tool used) enumerated
processes through seven independent sources; Volatility 3 (what this
project runs, confirmed against the installed library) only exposes four.
The three sources with no Volatility 3 equivalent — `not_in_pspcid_list`,
`not_in_session`, `not_in_deskthrd` — plus their three `_false_avg`
variants are honestly emitted as `0.0` and disclosed as a structural gap,
never guessed. Freshly computed directly from the model file for this
guide: together, all six carry just 0.21% of the model's total gain — a
real, disclosed gap, but one that was never capable of swinging a verdict
by more than a fraction of a percent.

**Q3. Three of the four features the model leans on most are `svcscan`
counts — registered services and drivers. Is that actually a behavioural
signal of malware, or something else?**

A: Something else, and this project says so explicitly rather than
overselling it. Service and driver counts describe how a machine is
**configured** — how much software is installed — not what any process
actually *did*. `CLAUDE.md` §5.4a traces this to the training dataset's own
construction: the benign half of CIC-MalMem-2022 was heavily SMOTE-balanced
(file 33 covers this), so the two classes separate almost too cleanly on
service counts whose medians differ by only one or two, which is exactly
what synthetic, tightly-clustered points produce. This is precisely why
`app/inference/memory.py` gates the model's own probability behind an
out-of-distribution check on these four specific features (file 34), and
why memory severity is driven by direct Volatility evidence rather than the
model's score (hard rule 22).

**Q4. Where, exactly, does feature *ordering* get imposed in the memory
extractor, and why does it matter that it happens in exactly one place?**

A: In the very last line of `assemble()`:
`[float(values[name]) for name in feature_names]`, which looks each of the
55 required names up **by name** against a merged dictionary built from all
nine plugins' output. Every step before that line works purely by
name-keyed dictionary, never by position — so there is no point earlier in
the pipeline where a bug could silently produce a vector whose values are
correct but whose *order* is wrong relative to the model's expectations.
That single, final, explicit lookup is what makes the "feature-naming trap"
(file 08 and `CLAUDE.md` §4) structurally hard to get wrong here, rather
than relying on every one of the nine `from_*()` functions happening to run
in the right order.

**Q5. `modules.nmodules` and `svcscan.kernel_drivers` sound like they might
be measuring the same thing — loaded drivers. Are they?**

A: No, and this is a genuinely useful distinction to be able to state in a
viva. `modules.nmodules` comes from `windows.modules.Modules`, which walks
the kernel's own `PsLoadedModuleList` — what's **actually loaded in memory
right now**. `svcscan.kernel_drivers` comes from `windows.svcscan.SvcScan`,
which reads the Service Control Manager's own **registration database** —
what's **registered** as a kernel-driver-type service, which can differ
from what's currently loaded. They're related, overlapping measurements
from two structurally different sources, not duplicates of each other.
