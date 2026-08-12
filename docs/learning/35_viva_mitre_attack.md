# 35 — Viva Deep Dive: MITRE ATT&CK

**Everything in this file was verified directly against the current
`app/forensics/mitre.py` source, not against `CLAUDE.md`'s own summary
table** — and doing that turned up a real, worth-knowing discrepancy
between the two, covered in its own section below. Where the two disagree,
this file follows the real code, per this guide's own standing rule.

## What MITRE ATT&CK actually is, for someone who's never heard of it

MITRE ATT&CK is a large, publicly maintained, industry-standard
**vocabulary** for naming specific attacker and malware behaviours —
things like "inject code into another running process" or "hide a file
from normal directory listings." Security teams worldwide use it as a
shared language: instead of one analyst writing "the malware messed with
another process's memory" and a different analyst writing "code was
smuggled into a foreign process," both describe the same behaviour using
the same standardised ID — `T1055`, "Process Injection." Every technique
has a stable ID (a main technique like `T1055`, or a more specific
sub-technique like `T1055.012`), a name, a description, and — critically
for this project — real-world detection guidance security tooling can be
built against. It's maintained by MITRE (a US non-profit that runs several
foundational cybersecurity standards) and is genuinely the *de facto*
standard reference framework the security industry organises detection
and threat-intelligence work around.

## Every technique this project actually cites today

Read directly out of the live `TAGS` list in `app/forensics/mitre.py` —
**nine** tags total, six on the memory side and three on the disk side:

### Memory-side tags (6) — `confidence: high` unless noted

| Tag | ID | Confidence | Triggering feature(s) |
|---|---|---|---|
| Process Injection | `T1055` | high | `malfind.ninjections`, `malfind.commitCharge`, `malfind.uniqueInjections`, `malfind.protection` |
| Process Hollowing | `T1055.012` | high | `ldrmodules.not_in_load` (**requires** `malfind.ninjections` also present) |
| Hidden Modules / DLL Concealment | `T1055.001` | high | `ldrmodules.not_in_init`, `not_in_mem`, and their `_avg` variants |
| Rootkit / Hidden Artifacts | `T1014` | high | `psxview.not_in_pslist`, `not_in_eprocess_pool`, `not_in_ethread_pool`, `not_in_csrss_handles`, `ldrmodules.not_in_mem` |
| Kernel Callbacks / Driver Persistence | `T1543.003` | **moderate** | `callbacks.ncallbacks`, `callbacks.nanonymous`, `callbacks.ngeneric` |
| Credential API Hooking | `T1056.004` | **low** | `handles.nkey`, `handles.nsection` |

### Disk-side tags (3) — `confidence: moderate` unless noted

| Tag | ID | Confidence | Triggering feature(s) |
|---|---|---|---|
| Obfuscated / Packed Files | `T1027` | moderate | the whole `byte_entropy` and `byte_histogram` groups |
| Suspicious API Imports | `T1106` | moderate | the whole `imports_hash` group |
| Defense Evasion — Unsigned Binary | `T1553.002` | **low** | `general_feat_7`, `datadirectory_feat_8`, `datadirectory_feat_9` (value-checked — see below) |

## Why each specific feature maps to each specific technique

**T1055 (Process Injection)** — `malfind` measures private, executable
memory regions with no file backing them on disk, which *is*, almost by
definition, what injected code looks like once it's resident in memory.
This is the most directly-grounded mapping in the whole table: the
feature's measurement and the technique's definition are nearly the same
statement.

**T1055.012 (Process Hollowing)** — a `ldrmodules.not_in_load` mismatch
*by itself* just means some module is missing from the load-order list,
which happens for mundane reasons too (file 31 covers this). Process
hollowing specifically is the technique of replacing a legitimately-started
process's own code with malicious code — so this tag requires *both* a
loader-list inconsistency *and* independent evidence of injection activity
(`malfind.ninjections` also present) before it fires, via the `requires`
mechanism in `match()` (below). One signal alone isn't the technique;
both together is a much stronger match to what hollowing actually looks
like.

**T1055.001 (Hidden Modules / DLL Concealment)** — `ldrmodules.not_in_init`
and `not_in_mem` (plus their `_avg` rates) measure a module that's mapped
into memory but missing from the initialization- or memory-order lists
specifically — the concrete signature of a DLL that was manually mapped in
rather than loaded through the normal, fully-tracked loader path.

**T1014 (Rootkit / Hidden Artifacts)** — the whole `psxview` family
(different enumeration methods disagreeing with each other) plus
`ldrmodules.not_in_mem` together are almost a textbook description of
Direct Kernel Object Manipulation: something is visible to one detection
method and invisibly hidden from another, which is the defining mechanism
of a rootkit, not just a side effect of one.

**T1543.003 (Kernel Callbacks / Driver Persistence)** — its real MITRE
name is *"Create or Modify System Process: Windows Service,"* which reads
oddly next to "kernel callbacks" until you connect the mechanism: a kernel
callback (something the kernel invokes automatically on process/thread/
image-load events) is normally registered *by a loaded kernel driver*, and
a kernel driver that's meant to persist across reboots is itself
registered as a Windows service. So `callbacks.ncallbacks`/`nanonymous`
are evidence of the *mechanism* (a kernel-level hook exists), which is
consistent with — but doesn't directly prove — the *persistence* half of
the technique (that the driver providing it survives reboot via service
registration). That gap between "mechanism observed" and "persistence
confirmed" is exactly why this tag is `confidence: moderate`, not `high`.

**T1056.004 (Credential API Hooking)** — `handles.nkey` (registry key
handles) and `handles.nsection` (shared-memory section handles, one
mechanism for moving code or data between processes) are both genuinely
weak, indirect evidence for API hooking specifically — plenty of ordinary
software holds registry and section handles for reasons that have nothing
to do with credential theft. `CLAUDE.md` §9.2 states this plainly: "handles
anomalies is thin evidence for hooking regardless," which is exactly why
this tag is deliberately `confidence: low`.

**T1027 (Obfuscated / Packed Files, disk)** — sustained high values across
the `byte_entropy`/`byte_histogram` groups are the direct signature of
packing or encryption (file 32's finding that 15 of the 24 selected
byte-entropy features sit at the single highest entropy bucket is the
concrete evidence behind this). `confidence: moderate`, not high, because
this is a statistical pattern across a whole feature group, not a single
unambiguous behavioural observation the way `malfind` is for memory.

**T1106 (Suspicious API Imports, disk)** — the `imports_hash` group
contributing strongly to a verdict is consistent with an unusual API
capability profile, but — hard rule 15, file 32 — a specific API can never
be named from a hash bucket, so this stays firmly group-level,
`confidence: moderate`.

**T1553.002 (Unsigned Binary, disk)** — deliberately `confidence: low`,
and deliberately **value-checked**, not just feature-presence-checked.
`app/forensics/mitre.py`'s own comment explains exactly why the extra care
was needed:

```python
# These three are exact, not hashed, so their values are readable - and the
# tag is only true when they say the binary is *un*signed. Matching on the
# feature name alone would report a signed binary as unsigned whenever LIME
# ranked the certificate table highly, which it does either way.
"when": lambda v: (v.get("general_feat_7", 0) == 0
                   and v.get("datadirectory_feat_8", 0) == 0)
```

`general_feat_7` and `datadirectory_feat_8` are individually readable
(file 32 confirms this against the real EMBER source), so this tag can
check their **actual values**, not just whether they appear in a LIME
findings list — and the certificate table ranks highly in LIME's output
for signed and unsigned binaries alike, so checking presence alone would
have reported plenty of properly-signed software as unsigned. Even with
that value check, `confidence` stays `low`: T1553.002 is specifically about
*subverting* code signing — stolen or self-signed certificates — not about
a binary simply never having been signed at all, and a large share of
entirely legitimate software ships unsigned. This tag is worded as an
observation, never as an attribution.

## How `match()` actually decides which tags fire — the mechanics

Two features of `app/forensics/mitre.py:match()` are worth being able to
describe precisely:

1. **Every matching tag fires, not just the single "best" one.** The
   function's own docstring states the reasoning directly: "a single
   artifact commonly shows several behaviours at once — injection plus
   hidden modules plus service persistence is ordinary, not an edge case."
   Collapsing to one tag would silently discard real findings, and the
   severity function (files elsewhere in this curriculum) depends on
   counting how many distinct high-risk categories matched — a count that
   breaks if only one tag can ever be reported.
2. **`requires` and `when` let a tag demand more than simple feature
   presence.** `requires` (used by Process Hollowing) means a second
   feature must *also* be present in the findings before the tag fires.
   `when` (used by Unsigned Binary) is a predicate function that gets the
   *actual values*, not just which features appeared, letting a tag check
   what those values actually say — value-aware matching is what's needed
   whenever presence alone would produce false positives, as the unsigned-
   binary comment explains directly.

`techniques(matched)` then collects the **distinct** MITRE IDs out of
whatever tags matched — the same underlying technique showing up under two
different tags doesn't get to inflate a high-risk-category count twice.

## Techniques this project deliberately refuses to cite — and why

Three IDs are explicitly banned, named directly in `mitre.py`'s own module
docstring and enforced as hard rule 21:

- **`T1179`** — this ID is **revoked/deprecated** in the current version of
  ATT&CK; citing it would date the report against a framework that's moved
  on. Hooking-adjacent behaviours it used to cover largely landed under
  `T1056.004` instead, which is why that ID exists in this project's table
  today.
- **`T1547.006`** — this ID genuinely means *"Kernel Modules and
  Extensions,"* but is scoped to **Linux and macOS** platforms in the real
  ATT&CK framework. It does not cover Windows kernel-callback or driver
  persistence at all, no matter how similar the name sounds — `T1543.003`
  is the correct Windows-scoped ID for that behaviour, and is what this
  project actually uses.
- **`T1574`** — this is *"Hijack Execution Flow"*, which in ATT&CK's own
  definition covers search-order hijacking and DLL side-loading — tricking
  a program into loading the **wrong** DLL from an unexpected location.
  That's a genuinely different behaviour from what `ldrmodules` actually
  measures (a module that's loaded but **concealed** from the loader's own
  bookkeeping) — `T1055.001` is the correct fit for concealment, and is
  what this project uses instead.

## A real discrepancy this verification pass found — flagged, not repeated

**`CLAUDE.md` §9.2's own summary table is stale in one row, relative to
the actual current code, and this guide follows the real code rather than
repeating the stale row.** The table (embedded in this project's own
CLAUDE.md) still lists:

> `Persistence — Boot/Logon Autostart | T1547 | moderate | svcscan autostart-related counts`

But there is **no such tag anywhere in the real, current `TAGS` list** —
and `mitre.py`'s own comment, sitting directly in the source, confirms this
was a deliberate, dated removal, not an oversight:

```python
# There is deliberately NO "Persistence - Services" tag on svcscan counts.
# It was removed 2026-08-02 and must not be re-added. A MITRE tag asserts a
# technique was *observed*; "more services than the baseline" is evidence of
# installed software, not of service-based persistence.
```

`CLAUDE.md`'s own later prose (its §9.2 section, further down the same
document) independently confirms the removal in the same words — so this
is a case of one part of `CLAUDE.md` (a summary table written earlier)
going stale relative to another part of the *same document* written later,
which the real code now matches. Service, driver, process, module and
handle counts are reported today purely as **volumetric context** (via
`baseline.volumetric_context()`), explicitly worded as "consistent with
additional software rather than compromise," and — by design — that
context can never assert a MITRE technique or drive severity on its own.

A second, smaller discrepancy worth knowing precisely: `CLAUDE.md`'s table
lists Credential API Hooking (`T1056.004`)'s triggering features as
*"handles anomalies, `imports_hash_*` group"* — but the real, current tag
in `mitre.py` only checks `handles.nkey` and `handles.nsection`, is
`pipeline: "memory"` only, and has **no** `groups` entry referencing
`imports_hash` at all. There is currently no disk-side credential-hooking
tag in this project.

## Why this project didn't try to cover more of ATT&CK

The full ATT&CK framework names 600+ techniques and sub-techniques. This
project maps to **nine**. `mitre.py`'s own module docstring states the
reasoning in almost exactly these words: 55 named memory features and 150
mostly-hashed disk features simply cannot ground 600+ sub-techniques with
real evidence behind each one — and reaching further than the feature
semantics genuinely support "would make the report less credible rather
than more." Every mapping in this table traces back to a feature this
project can actually measure and explain; expanding the table to cite
techniques with no corresponding measurable feature would turn a
defensible, narrow set of claims into a much larger set of unsupported
ones — exactly the kind of overreach the project's own confidence-labelling
discipline (`high`/`moderate`/`low` on every single tag) is built to avoid.

## Check your understanding

**Q1. What real difference does `CLAUDE.md`'s stale summary-table row
claim about a "Persistence — Boot/Logon Autostart" tag, and what does the
actual current code do instead?**

A: The stale table row implies a live tag citing `T1547` on elevated
`svcscan` service/driver counts. The real, current `app/forensics/mitre.py`
has no such tag at all — it was deliberately removed, with the exact
removal date recorded directly in the source's own comment, because a
MITRE tag asserts an *observed* technique, and "more services than a
clean baseline" is evidence of installed software, not evidence that a
persistence technique was actually used. Elevated service/driver counts
are reported today as volumetric context only, which is structurally
incapable of asserting a technique or driving severity.

**Q2. Why does the Process Hollowing tag (`T1055.012`) require
`malfind.ninjections` to also be present, rather than firing on
`ldrmodules.not_in_load` alone?**

A: Because a loader-list mismatch by itself has mundane explanations too
common to treat as hollowing on its own (file 31 covers several — early-
boot processes, ordinary loading quirks). Process hollowing specifically
means malicious code replaced a legitimately-started process's own code,
which is a combination of "something's off in the loader bookkeeping" and
"there's independent evidence of injection activity" — so the tag's
`requires` field demands both signals before it fires, matching the
technique's real definition more closely than either signal alone would.

**Q3. Why is the Unsigned Binary tag `confidence: low` even though it
checks the exact, non-hashed values of `general_feat_7` and
`datadirectory_feat_8`, rather than a hash bucket?**

A: Because the confidence level here isn't about how precisely the
underlying data can be read — it genuinely can be read exactly — it's about
how strong the *technique claim* is. T1553.002 specifically covers
*subverting* code signing (stolen or self-issued certificates), not merely
lacking a signature, and a large share of entirely legitimate software is
unsigned. So even with an exact, value-checked reading, calling this
"Defense Evasion" would overstate what the data actually proves; it's
worded and confidence-rated as an observation, never an attribution.

**Q4. Why does `match()` return every tag that fires instead of picking
the single strongest one?**

A: Because a real artifact commonly exhibits several distinct behaviours
simultaneously — process injection alongside hidden modules alongside
service persistence is an ordinary combination, not a rare edge case — and
picking one "best" tag would silently discard genuinely separate findings.
It also matters mechanically: the severity function counts how many
distinct high-risk MITRE categories matched, and that count would be
structurally wrong if `match()` only ever returned one tag no matter how
many behaviours were actually present.

**Q5. Both `T1547.006` and `T1543.003` have names that sound like they
could describe kernel-level persistence. Why does this project use one and
explicitly ban the other?**

A: Because their real ATT&CK scopes differ in a way the similar-sounding
names hide. `T1547.006`, "Kernel Modules and Extensions," is scoped to
Linux and macOS in the actual framework — it does not cover Windows driver
persistence at all, regardless of how applicable the name appears.
`T1543.003`, "Create or Modify System Process: Windows Service," is the
technique actually scoped to Windows and actually covers a persistent
kernel driver registered as a service — which is what this project's
`callbacks`-based tag is really describing. Citing `T1547.006` here would
be citing a technique from the wrong operating system entirely, which is
exactly why hard rule 21 bans it outright.
