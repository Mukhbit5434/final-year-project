# 30 — Viva Deep Dive: Overview

This is a different kind of curriculum from files 00–29. Those walk the
**code** — what each file does, line by line. This one walks the **exam** —
the questions a viva panel actually asks, answered in exhaustive, verified
depth, with every number checked against the real committed files rather
than remembered or approximated.

Four topics, each big enough on its own to be worth getting cold-confident
on, plus a fifth file of rapid-fire questions and answers pulling the whole
project together:

| # | File | What it covers |
|---|---|---|
| 31 | `31_viva_memory_features.md` | All 55 memory features, one at a time: what each one measures, which Volatility 3 plugin actually produces it, and why it's forensically meaningful. |
| 32 | `32_viva_disk_features.md` | All 150 disk features the model actually uses (out of 2,381 EMBER produces), grouped by family, with the readable ones decoded exactly and the hashed ones explained honestly. |
| 33 | `33_viva_models.md` | What LightGBM and XGBoost actually are, why they were the two compared, why each pipeline shipped the model it did, and a worked toy example of a tree actually making a decision. |
| 34 | `34_viva_thresholds.md` | Where both threshold numbers came from, why they're so different from each other, and why the threshold and the memory pipeline's out-of-distribution gate are two separate mechanisms, not one. |
| 35 | `35_viva_mitre_attack.md` | Every MITRE ATT&CK technique this project actually cites today, why each specific feature maps to each specific technique, and the three technique IDs this project deliberately refuses to use. |
| 36 | `36_viva_rapid_fire_qa.md` | 30 question-and-answer pairs across three difficulty tiers, covering the whole project end to end. |

## How this curriculum was built

Every fact, every number, and every code quote below was checked directly
against the real files in this repository during the same session that
wrote it — the JSON feature lists, the actual model files (by loading them
and computing real gain statistics, not quoting a remembered figure), the
actual source of `app/forensics/mitre.py`, and the installed `ember`
library's own `features.py`. Where something in `CLAUDE.md` turned out to
be slightly stale against the real current code (this happened once, in
the MITRE file — see its own note), that's flagged explicitly rather than
silently repeated.

A few numbers in these files go a layer deeper than `CLAUDE.md` itself
documents — for instance, exactly which 12 of the 55 memory features the
shipped model never once split on, computed directly from the model file
rather than approximated. Where that happens, it's noted as "freshly
computed for this guide" so it's clear the number came from re-deriving it
against the real artifact, not from a document that might drift out of
date.

## How to use this if you have limited time before a viva

- If you only read one file, read **36 (rapid-fire Q&A)** — it's built to
  stand alone and covers the whole project, just without the full depth
  behind each answer.
- If a panel member is likely to open the actual feature list or model file
  and ask "what does column 40 actually mean" — that's exactly what files
  31 and 32 are for.
- If the question is "why does this project even use two different model
  libraries" or "why is your threshold not 0.5" — that's files 33 and 34.
- If the question is about MITRE ATT&CK specifically, or challenges whether
  a technique mapping is really justified — that's file 35.

## Ground rules carried over from files 00–29

Same standard as the rest of this curriculum: zero assumed background,
plain language, analogies for anything abstract, and a "Check your
understanding" section wherever one earns its place. Nothing here
contradicts `CLAUDE.md` or `STATUS.md` on what the system actually *does*;
where this curriculum goes further, it's because a real number was computed
that those documents only described qualitatively.
