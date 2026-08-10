# 00 — Start Here

## What this project actually is

Imagine a detective who has been handed a hard drive or a snapshot of a computer's
live memory, and is told: "something on here might be malware — figure out what,
and explain your reasoning." Doing that by hand takes real forensic expertise and
hours of specialist tool use. This project is a piece of software that does the
first pass of that detective work automatically. A user uploads a raw disk image
(a byte-for-byte copy of a hard drive) or a raw memory dump (a byte-for-byte copy
of a computer's RAM at the moment it was captured), and the system: pulls
structured measurements out of that raw data, feeds those measurements into a
machine-learning model that has already been trained to recognise malicious
patterns, and then writes a human-readable report explaining what it found, how
confident it is, and why. There are two completely separate versions of this
pipeline — one for disk images, one for memory dumps — because the two kinds of
evidence are structurally nothing alike and need different tools to read them.

This curriculum is about the **application** — the web server, the database, the
code that turns raw bytes into a PDF report. It assumes the machine-learning
models themselves are already built and simply *used* here, not trained here.
(If you need the model-training story, that is documented elsewhere — this
curriculum starts from "the models already exist as files on disk.")

## The journey of one upload, in ASCII

This is the shape you'll see explained in full, piece by piece, across every file
in this curriculum, and then walked start-to-finish in the final file.

```
 ANALYST'S BROWSER
       │
       │  1. picks a file, clicks "Upload and queue"
       ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  FLASK WEB SERVER (the "request/response" layer)             │
 │                                                                │
 │  upload() route:                                              │
 │    - streams the file to disk in chunks, hashing as it goes   │
 │    - looks at the first few bytes to guess disk vs. memory    │
 │    - writes one row to the "jobs" table in the database       │
 │    - hands the job off to a background worker                 │
 │    - immediately responds to the browser: "queued, watch here"│
 └─────────────────────────────────────────────────────────────┘
       │                                            ▲
       │  2. hands off (does NOT block the browser)  │ 5. page polls
       ▼                                            │    every few seconds
 ┌─────────────────────────────────────────────────────────────┐
 │  BACKGROUND JOB (runs in a separate OS process)               │
 │                                                                │
 │  EXTRACTION                                                   │
 │    disk image  → walk the filesystem, find real PE files,     │
 │                   turn each one into ~2,381 numbers            │
 │    memory dump → run 9 Volatility 3 plugins, turn their        │
 │                   output into 55 numbers                       │
 │                                                                │
 │  INFERENCE                                                    │
 │    those numbers go into a pre-trained model (LightGBM for     │
 │    disk, XGBoost for memory) → a probability of "malicious"    │
 │                                                                │
 │  EXPLANATION + FORENSICS                                       │
 │    LIME explains *why* the model said what it said             │
 │    a lookup table turns raw feature names into plain English   │
 │    a MITRE ATT&CK tagger names the technique category          │
 │    a severity function turns all of that into Low/Medium/      │
 │    High/Critical                                                │
 │                                                                │
 │  → writes everything back into the database, marks job DONE    │
 └─────────────────────────────────────────────────────────────┘
       │
       │  6. once done, browser reloads the job page
       ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  REPORT                                                        │
 │    the same stored results can be viewed as a web page,        │
 │    exported as CSV/JSON, or rendered as a PDF — all three       │
 │    read from the same database rows                            │
 └─────────────────────────────────────────────────────────────┘
       │
       ▼
 ANALYST reads the verdict, the evidence, and the limitations
```

## Reading order, and why

Read these in order. Each one only uses ideas already explained in an earlier
file — you should never hit a wall where you need something from file 12 to
understand file 5.

| # | File | Why it comes here |
|---|---|---|
| 0 | `00_START_HERE.md` | You're reading it — the map before the terrain. |
| 1 | `01_libraries_and_why.md` | Every file after this names libraries by name (Flask, SQLAlchemy, LightGBM...). Meet them once, up front, before seeing them used. |
| 2 | `02_project_map.md` | A folder-by-folder tour so you know *where* things live before reading *what* they do. |
| 3 | `03_configuration.md` | Almost everything else reads a setting from here (database location, upload limits, thresholds). Config has to come before anything that depends on it. |
| 4 | `04_database_and_models.md` | The database tables are the shared vocabulary every other layer writes into and reads from. You cannot understand a "job" until you know what a `Job` row actually contains. |
| 5 | `05_app_factory_and_startup.md` | How the whole application boots up and wires the database, login system, and models together — the scaffolding everything else runs inside. |
| 6 | `06_authentication.md` | The first real feature a user touches: creating an account and signing in. Small, self-contained, and uses only concepts from files 1–5. |
| 7 | `07_upload_and_jobs.md` | The heart of the system: what happens the moment a file is uploaded, and how a slow job runs in the background without freezing the website. |
| 8 | `08_inference.md` | Once you know what a "job" does (file 7), you're ready for exactly how a number becomes a prediction. |
| 9 | `09_extraction_disk.md` | Where the numbers going *into* inference (file 8) actually come from, for disk images. |
| 10 | `10_extraction_memory.md` | Same question, for memory dumps — a much bigger, hairier extraction process. |
| 11 | `11_explainability_and_forensics.md` | Once you have a prediction (file 8) and the raw measurements (files 9–10), this is how they become a human-readable explanation and a severity score. |
| 12 | `12_reporting.md` | Takes everything from files 8–11 and turns it into the actual PDF/CSV/JSON a user downloads. |
| 13 | `13_web_interface.md` | The HTML templates and styling that present all of the above in a browser — comes late because it references data structures explained in every earlier file. |
| 14 | `14_tests.md` | Now that you know what the system is supposed to do, you can appreciate what the tests are checking *for*. |
| 15 | `15_scripts.md` | Standalone command-line tools built on top of everything above — makes sense only once you know the pieces they're built from. |
| 99 | `99_glue_it_together.md` | The payoff: one real upload traced through literally every file above, in the exact order the code executes. Read this last. |

## Glossary

Read this once now; you won't need to look most of these up again once you've
seen them in context.

- **Framework** — a large pre-written piece of software that provides the
  overall structure of an application, so you write the specific behaviour and
  the framework handles the repetitive plumbing (routing web requests, talking
  to databases, etc.). Flask is this project's web framework.
- **Library** — a smaller pre-written piece of code you call into to do one
  job (parse a file format, hash some bytes, draw a PDF) without writing that
  logic yourself. A framework is usually built from many libraries; a project
  also directly uses libraries that have nothing to do with its framework.
- **Function** — a named, reusable block of code that takes some inputs
  ("arguments"), does something, and usually gives back a result. You call
  it by name instead of retyping its body every time you need that behaviour.
- **Class** — a blueprint for creating objects that bundle related data and
  the functions that operate on that data together. `User` is a class; a
  specific person's account row loaded from the database is an "instance" of
  that class.
- **Import** — a statement at the top of a Python file that says "I want to
  use code that lives in a different file or library." `from .models import
  Job` means "give me the `Job` class defined in the `models.py` file next to
  this one."
- **Loop** — code that repeats itself for every item in a collection ("for
  each file in this list, do X") or until some condition changes.
- **If-statement (conditional)** — code that only runs when some condition is
  true, and can specify different code to run when it's false instead.
- **Dictionary** — a collection of `key: value` pairs, like a real dictionary
  where you look up a word (the key) to find its definition (the value). In
  this codebase, `{"stage": "Running windows.pslist", "pct": 5}` is a
  dictionary with keys `"stage"` and `"pct"`.
- **List / array** — an ordered collection of values, like a numbered list.
  `[1, 2, 3]` is a list. A **vector** in this codebase always means a plain
  list/array of numbers in a specific, meaningful order — e.g. the 55 memory
  features in exactly the order the model expects them.
- **ORM (Object-Relational Mapper)** — a library that lets you work with
  database rows as if they were ordinary objects/classes in your programming
  language, instead of writing raw SQL text by hand. SQLAlchemy is this
  project's ORM.
- **Migration** — a small, versioned script that changes a database's
  structure (adds a column, creates a table) in a repeatable, trackable way,
  so every copy of the database (yours, a teammate's, a server's) can be
  brought to the same structure by "replaying" the same migrations in order.
- **Route / endpoint** — a URL path the web server knows how to respond to,
  paired with the function that handles it. `/upload` is a route; the Python
  function that runs when someone visits it is its "view function."
- **Blueprint** — Flask's way of grouping a set of related routes (e.g.
  everything under `/login`, `/register`) into one reusable, organised unit
  instead of dumping every route into one giant file.
- **Decorator** — a line starting with `@` placed directly above a function
  definition that wraps extra behaviour around that function without
  changing its body. `@login_required` above a route function means "run
  this only if someone is signed in; otherwise redirect to the login page."
- **Background job** — work that is started but not waited for immediately;
  the program that started it moves on and the work finishes later,
  independently. Essential here because extracting features from a 2 GB
  memory dump can take several minutes — far too long to make a browser wait
  on a single web request.
- **Thread** — a lightweight, independent sequence of execution *within* the
  same running program, sharing the same memory. Cheap to create, but in
  Python only one thread can run Python code at an exact instant (see GIL
  below), so threads are good for waiting on things, not for CPU-heavy work.
- **Process** — a completely separate running instance of a program, with
  its own private memory, that the operating system manages independently.
  Heavier to create than a thread, but a crash in one process cannot take
  down another, and multiple processes really can run Python code
  simultaneously on multiple CPU cores.
- **GIL (Global Interpreter Lock)** — a lock inside the standard Python
  interpreter that only lets one thread execute Python bytecode at a time.
  It's the reason CPU-heavy work in this project is pushed into a separate
  *process* rather than just a thread — threads wouldn't actually run it in
  parallel with the web server.
- **Thread pool / process pool** — a manager that keeps a fixed number of
  threads or processes ready and hands them jobs from a queue, so you don't
  pay the cost of creating a new one for every single task.
- **Serialization** — converting a data structure in memory into a form that
  can be stored or sent elsewhere (a file, a network message, a different
  process) and reconstructed later. JSON text is one serialization format
  used throughout this project; Python's `pickle` (used automatically when
  handing data between processes) is another.
- **Session (web)** — a way for a web server to remember who a particular
  browser is across multiple separate requests, usually via a small piece of
  data (a cookie) the browser sends back on every request.
- **Cookie** — a small piece of data a web server asks a browser to store and
  send back on every future request to that site. Used here to remember that
  a browser is signed in.
- **Hash / hashing** — a one-way mathematical function that turns any input
  data into a fixed-size fingerprint, such that the same input always
  produces the same fingerprint, a tiny change in input produces a
  completely different fingerprint, and you cannot practically reverse the
  fingerprint back into the original input. Used here for two very different
  jobs: **SHA-256** fingerprints whole files for forensic identification, and
  a *different*, deliberately reversible-feeling but one-way password hash
  (via Werkzeug) protects stored passwords so the raw password is never kept
  anywhere.
- **Vector / feature vector** — see "list/array" above; specifically, a list
  of numbers, each one measuring some property of the thing being analysed,
  in a fixed order a machine-learning model was trained to expect.
- **Model (machine learning)** — a mathematical object, previously fit to a
  large collection of labelled examples, that takes a feature vector and
  produces a prediction (here: a probability that the input is malicious).
- **Threshold** — the probability value above which a prediction is called
  "malicious" rather than "benign." Not automatically 0.5 — each model here
  has its own threshold chosen during training and stored in a file.
- **Inference** — the act of running new input through an already-trained
  model to get a prediction, as opposed to *training*, which is how the
  model was built in the first place (not covered in this curriculum).

## Time estimate

This is a genuinely large curriculum covering a full multi-thousand-line
application in depth, written for someone with no prior programming
background. Realistic pacing:

- **Files 00–03** (orientation, libraries, project map, configuration): a
  relaxed evening, 2–3 hours, mostly reading.
- **Files 04–07** (database, startup, auth, upload/jobs): the conceptual core
  of "how a web app works" — budget a full day, 5–6 hours, and don't rush
  file 7, it's the most important one.
- **Files 08–12** (inference, both extractors, explainability/forensics,
  reporting): the domain-specific heart of the project — another full day,
  6–8 hours, since this is where the forensic reasoning lives.
- **Files 13–15** (web interface, tests, scripts): a shorter day, 3–4 hours.
- **File 99** (the full trace): 1–2 hours, but only truly "clicks" after
  everything above, so don't read it in isolation.

**Total: roughly 20–25 hours** spread over a week or two of study, assuming
zero prior programming background. If you already know general programming
concepts (loops, functions, classes) but not this specific stack, expect
closer to 12–15 hours.
