# 32 — Viva Deep Dive: All 150 Disk Features

Every fact below was checked against three real files: `models/disk/feature_list_selected.json`
(the 150 names, in the model's real input order), `models/disk/feature_list_full_2381.json`
(the full 2,381-name schema, in extractor order), and the actual installed
`ember` library's own `ember/features.py` — read directly, line by line, for
this file, not assumed from documentation. Where a feature turns out to be
individually readable, the exact index math below was computed and verified
against the real 150-item list, not estimated.

## The two-tier structure: 2,381 raw numbers, 150 actually used

Every PE file this project examines gets vectorized into **2,381** raw
numbers by EMBER's `PEFeatureExtractor` — that's the complete feature space
EMBER version 2 defines. But the shipped LightGBM model was only ever
trained on **150** of them.

How the narrowing happened, briefly (this project didn't do the training —
it only loads the finished result, so this is a summary, not a re-derivation):
combined feature-importance rankings from both LightGBM and XGBoost were
computed over the full 2,381-feature space, and an **ablation test** — try
the top *k* features for several values of *k*, measure validation ROC-AUC
at each — showed clearly diminishing returns past a certain point. The real
numbers, read directly from `models/disk/metadata.json`:

| Top-*k* features kept | Validation ROC-AUC |
|---:|---:|
| 50 | 0.99348 |
| 100 | 0.99569 |
| 150 | **0.99632** |
| 200 | 0.99666 |
| 300 | 0.99688 |

Going from 150 to 300 features — doubling the feature count — only buys
another 0.00056 of AUC. 150 was chosen as the point of clearly diminishing
returns: keep the accuracy, cut the feature count to about **6%** of the
original 2,381. One more real, verified number worth knowing: LightGBM's
and XGBoost's own top-200 importance rankings only overlapped by **54.5%**
(`lgb_xgb_top200_overlap_pct` in the same file) — the two model types don't
fully agree on what matters most, which is itself part of why the final
150 were chosen from a **combined** ranking rather than either model's
list alone.

## The nine EMBER feature families, and where each one's numbers sit in the 2,381

This is the layout of `PEFeatureExtractor`, confirmed directly against the
installed `ember/features.py` and cross-checked against the exact line
numbers in `feature_list_full_2381.json`:

| Family | Width | Index range in the full 2,381 |
|---|---:|---|
| `byte_histogram` | 256 | 0–255 |
| `byte_entropy` | 256 | 256–511 |
| `string_feat` | 104 | 512–615 |
| `general_feat` | 10 | 616–625 |
| `header_feat` | 62 | 626–687 |
| `section_feat` | 255 | 688–942 |
| `imports_hash` | 1,280 | 943–2,222 |
| `exports_hash` | 128 | 2,223–2,350 |
| `datadirectory_feat` | 30 | 2,351–2,380 |

(`imports_hash` and `exports_hash` together make up 1,408 of the 2,381 —
well over half the entire raw feature space is hashed import/export data.)

The 150 selected features break down by family like this (counted directly
from the real selected list):

| Family | Selected count | Individually readable? |
|---|---:|---|
| `imports_hash` | 33 | No — hash buckets (hard rule 15) |
| `byte_histogram` | 26 | Yes — one exact byte value per index |
| `byte_entropy` | 24 | Partially — a joint (entropy, byte-range) bucket |
| `string_feat` | 20 | Mostly — see below |
| `header_feat` | 15 | 6 of the 15 are exact scalars, 9 are hash buckets |
| `section_feat` | 15 | 3 of the 15 are exact scalars, 12 are hash buckets |
| `datadirectory_feat` | 13 | Yes — all 13 |
| `general_feat` | 4 | Yes — all 4 |
| `exports_hash` | 0 | — (none selected at all) |

Not one `exports_hash` feature made the final 150 — exported functions
turned out not to carry enough discriminating signal for this model to
bother with, out of a possible 128.

## `general_feat` — 4 selected, all exactly readable

`GeneralFileInfo` produces 10 plain scalars, in this fixed order (confirmed
directly against `ember/features.py:GeneralFileInfo.process_raw_features`):
`size, vsize, has_debug, exports, imports, has_relocations, has_resources,
has_signature, has_tls, symbols`. This project's own `app/forensics/meanings.py`
carries this identical order, independently confirming it.

The four actually selected:

| Feature | Meaning | Why it matters |
|---|---|---|
| `general_feat_0` | File size in bytes | Trivial but real — extreme sizes in either direction are unusual for ordinary software. |
| `general_feat_2` | Has a debug directory (0/1) | Legitimate compiled software commonly carries one; its absence is weakly suggestive of stripping. |
| `general_feat_4` | Count of imported functions | How many external API functions this file pulls in — a very coarse capability signal on its own. |
| `general_feat_7` | Has an Authenticode signature (0/1) | **This is one of the three features driving the "Defense Evasion — Unsigned Binary" MITRE tag** (file 35) — directly, not by inference: `app/forensics/mitre.py`'s T1553.002 tag checks `general_feat_7 == 0` explicitly. |

## `datadirectory_feat` — 13 selected, all exactly readable

`DataDirectories` records the size and virtual address of the first 15 PE
data directories, in this fixed order (`ember/features.py`'s own
`_name_order`): export table, import table, resource table, exception
table, **certificate table**, base relocation table, debug directory,
architecture directory, global pointer, TLS directory, load config table,
bound import table, import address table, delay import descriptor, CLR
runtime header. Even-numbered feature indices are always a directory's
**size**, odd-numbered indices are always its **virtual address**
(`features[2*i]=size, features[2*i+1]=virtual_address` — confirmed directly
in `ember/features.py:DataDirectories.process_raw_features`).

All 13 selected, decoded exactly:

| Feature | Directory | Which value |
|---|---|---|
| `datadirectory_feat_0` | Export table | size |
| `datadirectory_feat_1` | Export table | virtual address |
| `datadirectory_feat_2` | Import table | size |
| `datadirectory_feat_3` | Import table | virtual address |
| `datadirectory_feat_4` | Resource table | size |
| `datadirectory_feat_5` | Resource table | virtual address |
| `datadirectory_feat_8` | **Certificate table** | size |
| `datadirectory_feat_9` | **Certificate table** | virtual address |
| `datadirectory_feat_10` | Base relocation table | size |
| `datadirectory_feat_12` | Debug directory | size |
| `datadirectory_feat_13` | Debug directory | virtual address |
| `datadirectory_feat_24` | Import address table | size |
| `datadirectory_feat_26` | Delay import descriptor | size |

**Both** certificate-table features (`_8` and `_9`) made the cut — this is
the second, independent piece of the unsigned-binary picture alongside
`general_feat_7`: a genuine authenticode-signed binary carries a non-zero
certificate table size and address; an unsigned one reads `0` on both. This
is exactly what `app/forensics/mitre.py`'s T1553.002 `when` predicate
checks (`datadirectory_feat_8 == 0`, alongside `general_feat_7 == 0`) —
grounded in two independently-readable, un-hashed features, not a guess.

## `section_feat` — 15 selected, 3 exact scalars + 12 hash buckets

`SectionInfo` produces 255 numbers: **5 plain scalars first**, then **five
separate 50-wide hashed blocks** (confirmed against
`ember/features.py:SectionInfo.process_raw_features`, and independently
against `app/forensics/meanings.py`'s own `SECTION_NAMED`/`SECTION_BLOCKS`
tables, which match exactly):

| Index range | What it is |
|---|---|
| 0–4 | Plain scalars: section count, zero-size count, unnamed-section count, RX (readable+executable) count, W (writable) count |
| 5–54 | Hashed: (section name, section size) pairs |
| 55–104 | Hashed: (section name, section entropy) pairs |
| 105–154 | Hashed: (section name, virtual size) pairs |
| 155–204 | Hashed: entry-point section's own name |
| 205–254 | Hashed: entry-point section's own characteristics |

The three exactly-readable ones selected:

| Feature | Meaning |
|---|---|
| `section_feat_1` | Count of zero-size sections |
| `section_feat_3` | Count of sections that are readable **and** executable (RX) |
| `section_feat_4` | Count of writable sections |

`section_feat_3` and `section_feat_4` together are what CLAUDE.md's
"writable+executable is anomalous compiler output" wording is grounded in —
though note they're two separate counts (RX sections, and W sections), not
one combined "writable-and-executable" count; a section carrying both
properties would be counted in both.

The remaining 12 selected (`section_feat_48, 83, 90, 96, 97, 98, 122, 146,
147, 148, 233, 242`) all fall past index 4, so each is a bucket inside one
of the four 50-wide hashed blocks above — for example, `section_feat_96`
and `section_feat_97` and `section_feat_98` all fall in the 55–104 range,
so they're three buckets of the **(section name, entropy)** hash — real
signal about section entropy patterns, but not attributable to any single
named section. Group-level wording only for these twelve, per the same
reasoning hard rule 15 applies to the hashed import/export features below.

## `header_feat` — 15 selected, 6 exact scalars + 9 hash buckets

`HeaderFileInfo` produces 62 numbers: **one plain scalar**, then **five
separate 10-wide hashed blocks**, then **eleven more plain scalars**
(confirmed directly against `ember/features.py:HeaderFileInfo`, and
independently against `app/forensics/meanings.py`'s own `HEADER_NAMED`/
`HEADER_BLOCKS` tables, which match):

| Index | What it is |
|---|---|
| 0 | Plain scalar: COFF compile timestamp |
| 1–10 | Hashed: COFF machine type string |
| 11–20 | Hashed: COFF characteristics flags |
| 21–30 | Hashed: subsystem string |
| 31–40 | Hashed: DLL characteristics flags |
| 41–50 | Hashed: PE "magic" (PE32 vs PE32+) |
| 51–61 | Plain scalars: image/linker/OS/subsystem version numbers, `sizeof_code`, `sizeof_headers`, `sizeof_heap_commit` |

**`CLAUDE.md` §9.1 doesn't explicitly list `header_feat` among the
individually-readable groups** — only `general_feat`, `datadirectory_feat`
and `section_feat` are named there. This guide verified `header_feat`
directly against the real, installed `ember` source rather than relying on
that document's own list, and it genuinely does have readable positions
too — six of them, among the fifteen actually selected:

| Feature | Meaning |
|---|---|
| `header_feat_0` | COFF compile/link timestamp (raw, seconds since 1970) |
| `header_feat_53` | Major linker version |
| `header_feat_55` | Major OS version the PE declares it targets |
| `header_feat_56` | Minor OS version |
| `header_feat_57` | Major subsystem version |
| `header_feat_59` | `sizeof_code` — size of the code section(s), from the PE optional header |

The remaining nine selected (`header_feat_11, 13, 14, 15, 28, 29, 30, 32,
39`) all fall inside one of the five 10-wide hashed blocks — `11, 13, 14,
15` are COFF-characteristics-flag hash buckets, `28, 29, 30` are
subsystem-string hash buckets, and `32, 39` are DLL-characteristics-flag
hash buckets. Group-level wording only for these nine.

## `string_feat` — 20 selected, mostly individually readable

`StringExtractor` produces 104 numbers, in this exact order (confirmed
against `ember/features.py:StringExtractor`): `numstrings, avlength,
printables, printabledist[96], entropy, paths, urls, registry, MZ`.

| Index | What it is |
|---|---|
| 0 | Count of extracted ASCII strings (5+ consecutive printable characters) |
| 1 | Average length of those strings |
| 2 | Total printable-character count across all of them |
| 3–98 | A 96-bucket histogram: bucket *j* is the (normalized) frequency of ASCII character `0x20+j` among every extracted string |
| 99 | Shannon entropy of that same character distribution |
| 100 | Count of the literal substring `"c:\"` (case-insensitive) |
| 101 | Count of `"http://"` or `"https://"` |
| 102 | Count of `"HKEY_"` (registry key prefix) |
| 103 | Count of the two-byte sequence `"MZ"` anywhere in the raw file — a crude "is there an embedded executable in here" heuristic (a second PE header hiding inside this one, e.g. a dropper carrying its payload embedded) |

Four of the 20 selected are the specially-named scalars, not histogram
buckets:

| Feature | Meaning |
|---|---|
| `string_feat_99` | String-character entropy |
| `string_feat_100` | Count of `"c:\"` occurrences |
| `string_feat_101` | Count of URL prefixes |
| `string_feat_103` | Count of embedded `"MZ"` sequences |

(`string_feat_102`, the registry-prefix counter, was **not** selected —
worth knowing precisely, since it's easy to assume all four of the
"suspicious string" counters made the cut when only three did.)

The other sixteen selected (`string_feat_3, 14, 15, 21, 22, 42, 52, 55, 58,
60, 66, 75, 77, 80, 84, 93`) are all character-histogram buckets — and
because that histogram is a **direct, un-hashed** frequency table (not a
lossy hash), each one decodes to one exact printable character:

| Feature | Character | Feature | Character |
|---|---|---|---|
| `string_feat_3` | `' '` (space) | `string_feat_58` | `'W'` |
| `string_feat_14` | `'+'` | `string_feat_60` | `'Y'` |
| `string_feat_15` | `','` | `string_feat_66` | `'_'` |
| `string_feat_21` | `'2'` | `string_feat_75` | `'h'` |
| `string_feat_22` | `'3'` | `string_feat_77` | `'j'` |
| `string_feat_42` | `'G'` | `string_feat_80` | `'m'` |
| `string_feat_52` | `'Q'` | `string_feat_84` | `'q'` |
| `string_feat_55` | `'T'` | `string_feat_93` | `'z'` |

These are genuinely readable, unlike the import/export hashes below — the
model literally sees "how often does the underscore character appear
across every printable string in this file," which is a real, if narrow,
signal (underscores and digits are common in identifier-heavy or
Base64/encoded-looking strings, for instance).

## `byte_histogram` — 26 selected, exactly readable per index

`ByteHistogram` is the simplest family in the whole feature set: index *N*
is the **normalized frequency of raw byte value *N*** (0–255) across the
entire file (`np.bincount(bytez, minlength=256)`, then divided by the
total byte count). No hashing, no aggregation — completely literal.

The 26 selected span the low end (`byte_histogram_1, 21, 25, 32, 43, 51,
53, 55, 57`), the middle (`89, 95, 105, 109, 112, 113, 123, 125, 126,
128`), and the high end (`163, 219, 220, 221, 223, 232, 255`) of the byte
range. `byte_histogram_255` — the frequency of raw byte value `0xFF` — is
a genuinely meaningful one to know by name: a file that's substantially
packed or encrypted tends to have byte values spread close to uniformly
across the full 0–255 range (including `0xFF`), rather than clustered the
way ordinary compiled code and readable strings are.

## `byte_entropy` — 24 selected, a joint (entropy, byte-range) histogram

`ByteEntropyHistogram` is a **2D** histogram: it slides a 2 KB window
across the file, computes the local Shannon entropy in each window,
buckets that entropy into one of 16 levels, and *also* buckets which
16-value byte range dominated that window — then flattens the resulting
16×16 grid into 256 numbers. Index *i* decodes as `entropy_level = i // 16`
(0 = lowest local entropy, 15 = highest) and `byte_range = i % 16` (bucket
*b* covers raw byte values `16b` to `16b+15`).

Decoded exactly, the 24 selected split heavily toward the high-entropy end:

| Entropy level | Selected indices at this level | Byte-value ranges covered |
|---:|---|---|
| 0 (lowest) | `byte_entropy_0` | 0x00–0x0f |
| 3 | `byte_entropy_56` | 0x80–0x8f |
| 7 | `byte_entropy_113, 117, 118, 119` | 0x10–0x1f, 0x50–0x5f, 0x60–0x6f, 0x70–0x7f |
| 8 | `byte_entropy_128, 133` | 0x00–0x0f, 0x50–0x5f |
| 11 | `byte_entropy_186` | 0xa0–0xaf |
| 14 | `byte_entropy_235, 237` | 0xb0–0xbf, 0xd0–0xdf |
| **15 (highest)** | `byte_entropy_240, 241, 244, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255` | nearly the entire byte range (0x00–0x1f, 0x40–0xff) |

**Fifteen of the 24 selected byte-entropy features sit at entropy level
15 — the single highest bucket the histogram has.** That's a strong,
directly-verified confirmation of what `CLAUDE.md` §6.1's UPX-packing
demonstration shows empirically: this model leans heavily on **sustained
high local entropy**, spread across nearly every byte-value range, as its
packing/encryption signal — not a narrow slice of the byte space, but
"is most of this file locally close to random," measured in thirteen
different byte-value neighborhoods at once.

## `imports_hash` — 33 selected, genuinely irrecoverable (hard rule 15)

`ImportsInfo` produces 1,280 numbers as **two separate hashed blocks**,
concatenated (confirmed directly against `ember/features.py:ImportsInfo`):

| Index range | What's hashed into it |
|---|---|
| 0–255 | The set of **unique library names** this file imports from (e.g. `kernel32.dll`), via a 256-wide feature hash |
| 256–1279 | Every **fully-qualified import** — `"library.dll:FunctionName"` strings — via a 1,024-wide feature hash |

Of the 33 selected, only **4** (`imports_hash_8, 51, 117, 247`) fall in the
library-name block; the other **29** fall in the fully-qualified
function-import block — so this model leans overwhelmingly on *which
specific functions* a file imports, not just which DLLs it links against.

**This is where hard rule 15 is binding, and it's worth being able to
state exactly why in a viva.** A feature hash (scikit-learn's
`FeatureHasher`, the "hashing trick") deliberately maps an unbounded set of
possible strings down into a small, fixed number of output buckets by
running each string through a hash function and taking the result modulo
the bucket count. Multiple different, unrelated import strings can and do
land in the same bucket — a **collision** — and the hash is one-way: given
that `imports_hash_1198` has a high value for some file, there is no
operation that recovers *which* library:function string(s) produced it.
So this project can truthfully say "the import-table hash contributed
strongly to this classification, consistent with a suspicious API usage
profile" (group-level, and that's exactly the wording `app/forensics/mitre.py`
uses for T1106), but it can **never** truthfully say "this file imports
`CreateRemoteThread`" from a hash bucket value — that specific a claim is
exactly what hard rule 15 forbids, because the data genuinely cannot
support it.

## `exports_hash` — 0 selected

`ExportsInfo` hashes exported function names into 128 buckets, the same
lossy way `imports_hash` works — but **none of the 128** made the final
150. Exported functions matter far more for DLLs than for the
typical EXE-heavy training distribution, and evidently didn't carry enough
independent signal once combined with everything else to earn a place.

## How the extractor actually turns a raw disk image into these numbers

Walking the real path (full code detail in file 09):

1. **A raw disk image goes into `scan(image_path, ...)`** in
   `app/extractors/disk.py`. `pytsk3` (raw/`.dd`/`.img`) or `pyewf` +
   `pytsk3` (`.E01`) opens it; `filesystems(img)` finds every mountable
   partition inside.
2. **`walk()`** — a generator function — traverses every directory in every
   found filesystem, using an explicit stack rather than recursive function
   calls (so an unusually deep directory tree can't hit Python's recursion
   limit).
3. **`looks_like_pe()`** decides, for every regular file with content,
   whether it's really a PE executable — by content, never by filename
   extension. It checks for the `"MZ"` DOS-header bytes **and** follows the
   `e_lfanew` pointer inside that header to confirm the real `"PE\x00\x00"`
   signature actually sits where it should. (Checking only for `"MZ"` was a
   real, fixed bug in this project — silent bug #1 in `STATUS.md` — because
   plenty of non-executable files coincidentally start with those two
   bytes, and real executables in this project's own test image were found
   named things like `.db` and `.regtrans-ms`, with no hint from their name
   at all.)
4. **Every confirmed PE's full bytes get read**, hashed (SHA-256 and MD5),
   and its forensic locator fields captured (path, partition, inode, MACB
   timestamps, byte offset where possible) — everything hard rule 16
   requires for a flagged file to be actionable later.
5. **Vectorization runs in a separate phase, after the whole walk finishes**
   (so the file-count cap and content-hash deduplication can see the
   complete candidate set first) — inside a `ProcessPoolExecutor`, never
   inside the main Flask process, specifically because `lief` (called deep
   inside EMBER's extractor) is native code parsing potentially hostile,
   malformed input, and a crash there must cost one worker, never the whole
   application.
6. **`patch_ember.load_features().PEFeatureExtractor(feature_version=2).feature_vector(data)`**
   runs EMBER's own nine `FeatureType` classes in order, producing the full
   2,381-value vector — this is the exact function call whose internals
   (`ember/features.py`) this whole file was verified against.
7. **`app/inference/disk.py:subset(vec_2381)`** reduces that 2,381-value
   vector down to the model's real 150-value input, using a **precomputed
   index list** built once at startup by looking each of the 150 selected
   names up by position in the full 2,381-name list — and that index list
   is genuinely **not sorted** (hard rule 18); sorting it would silently
   pair each selected feature with the wrong raw value.
8. **One verdict per file**, not per image — a disk result is a list, and
   the report and dashboard both have to handle "N files scanned, M
   flagged" rather than a single boolean.

## Check your understanding

**Q1. `general_feat_7` and `datadirectory_feat_8`/`datadirectory_feat_9`
are all involved in the same MITRE tag. What tag, and why does it need all
three rather than just one?**

A: T1553.002, "Defense Evasion — Unsigned Binary." `general_feat_7` is
whether the file carries an Authenticode signature at all (`has_signature`,
0 or 1); `datadirectory_feat_8` and `_9` are the certificate table's size
and virtual address — a genuinely signed file has a non-zero certificate
table, an unsigned one reads zero on both. `app/forensics/mitre.py`'s tag
checks `general_feat_7 == 0 AND datadirectory_feat_8 == 0` together,
specifically so the tag can only fire when the file is *actually*
unsigned, not merely whenever LIME happens to rank the certificate table
highly (which it does for signed and unsigned files alike, since it's
always a strong feature either way).

**Q2. Why can this project say "the import-table hash contributed strongly
to this verdict, consistent with suspicious API usage" but never "this
file imports `CreateRemoteThread`"?**

A: Because `imports_hash_*` values come from scikit-learn's `FeatureHasher`
— a many-to-one hashing trick that maps an effectively unbounded space of
possible `"library:function"` strings down into a fixed 1,024-wide (plus a
separate 256-wide library-only) space. Different, unrelated strings
genuinely collide into the same bucket, and the hash is one-way — there is
no operation that recovers which specific string(s) produced a given
bucket's value. Group-level wording is the most the data can honestly
support; naming a specific API from a hash bucket is a fabricated claim
the data cannot back up (hard rule 15).

**Q3. Fifteen of the 24 selected `byte_entropy` features sit at the single
highest entropy bucket (level 15 of 15). What does that concentration
actually tell you about what this model has learned to detect?**

A: That the model leans heavily on **sustained high local entropy**, and
specifically on that signal appearing across many different byte-value
neighborhoods at once (nearly the whole 0x00–0xff range is represented
among those fifteen high-entropy buckets) — not a narrow slice of it. This
is the concrete, index-level confirmation of what CLAUDE.md's UPX-packing
demonstration shows empirically: packing a benign binary raises its
entropy from 6.49 to 7.29 and its predicted probability from 0.001 to
0.66. High, broadly-distributed local entropy really is a large part of
what this specific model has learned to key on.

**Q4. Why did the feature-selection process settle on exactly 150 rather
than, say, 300 (which scored a slightly higher validation AUC)?**

A: Diminishing returns, measured directly: going from 150 to 300 selected
features (doubling the count) only improved validation ROC-AUC from
0.99632 to 0.99688 — a gain of 0.00056. 150 features already captures
essentially all of the achievable accuracy while keeping the feature space
down to about 6% of the full 2,381 EMBER produces, which matters directly
for `app/inference/disk.py`'s runtime cost and for keeping LIME's
explanations over a genuinely tractable feature space rather than 2,381
raw numbers.

**Q5. `looks_like_pe()` checks two separate things — the `"MZ"` bytes and
the `"PE\x00\x00"` signature. Why does checking only the first one produce
wrong results in practice, not just in theory?**

A: Because plenty of files that are not executables at all can
coincidentally start with the two bytes `"MZ"` — it's not a rare
coincidence, it's a real, measured problem: this project's own real test
image (a NIST CFReDS evidence image) contains genuine executables named
things like `.db` and `.regtrans-ms`, and checking only the first two bytes
was an actual, fixed bug (silent bug #1) that would have caused any file
merely starting with those two bytes to be treated as a PE and sent through
EMBER's vectorizer, whether or not it really was one. Following `e_lfanew`
to confirm the real, second `"PE\x00\x00"` signature is what makes the
check trustworthy — and, deliberately, extensions are never consulted at
all: a file named `readme.txt` whose real bytes are a PE gets analysed, and
a file named `virus.exe` whose real bytes are plain text does not.
