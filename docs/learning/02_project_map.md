# 02 — Project Map: Every Folder, Every File

This is a tour of the entire repository, folder by folder, top to bottom. For
each file: a one-line description of what it actually contains. Some folders
(gitignored ones like `sample/`, `data/`, `uploads/`, `instance/`) hold large
binary artifacts rather than source code — they're included anyway because
the brief asked for the *whole* repository, not just the source tree.

## Repository root

| File | What it is |
|---|---|
| `CLAUDE.md` | The complete governing specification for this project — every design decision, every hard rule, every investigation result. The single source of truth for *why* the code looks the way it does. |
| `STATUS.md` | The live handoff document — what's actually built, what's been verified against real evidence, what's still open. Where CLAUDE.md and STATUS.md disagree, STATUS.md wins on "what currently exists." |
| `BUILD_PLAN.md` | The original step-by-step build plan with done-criteria and risk guards, written before construction started. Historical planning record; still directly cited by CLAUDE.md for specific evidence (e.g. the psxview investigation). |
| `README.md` | The public-facing overview: what the system does, the validated performance numbers, and instructions to run it. |
| `.gitignore` | Tells Git which files/folders to never track — large binaries, local databases, caches, virtual environments. |
| `.gitattributes` | Tells Git how to treat specific file types on checkout — here, forcing binary handling for `.npy` files and the model files so Git never "helpfully" rewrites their line endings and corrupts them. |
| `requirements.txt` | The main pinned Python package list — the inference/ML-adjacent libraries and the whole Flask web stack. |
| `requirements-forensics.txt` | A second, separately-installed package list for the forensic extraction libraries (`lief`, `pytsk3`, `libewf-python`, `volatility3`) — kept separate because installing them has a specific required order that `pip install -r` alone can't express. |
| `wsgi.py` | The single-line-of-real-logic file that creates the Flask app object for any WSGI server (or `flask` CLI command) to find. |
| `run.py` | The guarded launcher you actually run during development — separate from `wsgi.py` for a real, documented Windows multiprocessing reason (file 05). |

## `app/` — the actual web application

| File | What it is |
|---|---|
| `app/__init__.py` | The "application factory" — the `create_app()` function that builds and wires together the whole Flask app: database, login manager, CSRF protection, background job executor, rate limiter, model loading, blueprints, error handlers. |
| `app/config.py` | All configuration in one place — database location, upload limits, file-type allowlist, rate limits, and the separate `TestConfig` used by the test suite. |
| `app/db.py` | Creates the shared `SQLAlchemy` database object and sets SQLite-specific connection settings (WAL mode, busy timeout, foreign keys) every time a new connection opens. |
| `app/models.py` | Every database table, defined as a Python class: `User`, `Job`, `Result`, `Finding`, `AuditLog`. This is the shared vocabulary the rest of the app is built around. |
| `app/auth.py` | The login/register/logout routes — the `auth` blueprint. |
| `app/routes.py` | Everything else user-facing: landing page, dashboard, jobs list, job detail, upload, report download, CSV/JSON export, status polling — the `main` blueprint. |
| `app/forms.py` | The four form classes (`LoginForm`, `RegisterForm`, `UploadForm`, `ConfirmTypeForm`) that define what fields exist and what validation each one needs. |
| `app/artifacts.py` | Streaming file upload (hash while writing, never load the whole file into memory) and "sniffing" — guessing whether an uploaded file is a disk image or a memory dump from its raw bytes. |
| `app/audit.py` | One tiny function, `log(...)`, that writes a row to the `audit_log` table — called from every security-relevant action across the app. |
| `app/jobs.py` | The background-job engine: dispatches extraction work to a process pool, tracks job status through its full lifecycle, and turns raw extraction output into stored `Result`/`Finding` rows. The busiest, most important file in the codebase — file 07 is dedicated to it. |
| `app/explain.py` | Builds the two LIME explainers (one per pipeline) once at startup, and turns a LIME explanation into a list of plain findings. |
| `app/report.py` | Builds the PDF report with ReportLab, and defines the shared `limitations()`/`evidence_rows()` functions that both the PDF and the web job-detail page render from. |

### `app/inference/` — loading and running the two trained models

| File | What it is |
|---|---|
| `app/inference/__init__.py` | Loads both pipelines' models once at startup and checks the installed library versions against what each model was trained under. |
| `app/inference/disk.py` | Loads the LightGBM disk model, computes and caches the 150-of-2381 feature subset indices, and exposes `predict()`/`subset()`. |
| `app/inference/memory.py` | Loads the XGBoost memory model, exposes `predict()`, and the out-of-distribution check (`ood()`, `dominant_ood()`). |

### `app/extractors/` — turning raw artifacts into feature vectors

| File | What it is |
|---|---|
| `app/extractors/__init__.py` | Empty — just makes `extractors` a proper importable Python package. |
| `app/extractors/disk.py` | Opens a disk image (raw or E01), walks its filesystem, finds real PE files by content (never by extension), and vectorises each one via `ember` in a separate process pool. |
| `app/extractors/memory.py` | The largest single source file in the project — runs nine Volatility 3 plugins against a memory dump and turns their combined output into the 55-value feature vector, plus the per-process evidence used in the report. |

### `app/forensics/` — the human-meaning layer (no models, just lookup tables and logic)

| File | What it is |
|---|---|
| `app/forensics/__init__.py` | Re-exports `meanings`, `mitre`, `severity` so they can be imported as `from .forensics import ...`. |
| `app/forensics/meanings.py` | Static tables mapping a raw feature name to a plain-English label and explanation — for both the 55 named memory features and the mostly-hashed 150 disk features. |
| `app/forensics/mitre.py` | The small, deliberately conservative table mapping indicator categories to MITRE ATT&CK technique IDs, and the `match()` function that applies it. |
| `app/forensics/severity.py` | The two severity-scoring functions — `for_disk` (verdict-led) and `for_memory` (evidence-led) — and why they're different. |
| `app/forensics/baseline.py` | Loads the seven-capture clean-machine baseline and compares a new capture's indicators against it, to decide what counts as "elevated" rather than merely "present." |

### `app/templates/` — the HTML pages (Jinja2 templates)

| File | What it is |
|---|---|
| `app/templates/base.html` | The page shell every other template extends: navigation bar, flash-message area, shared `<head>`. |
| `app/templates/landing.html` | The public homepage shown to signed-out visitors. |
| `app/templates/dashboard.html` | The signed-in analyst's summary page: stat tiles, a severity chart, recent jobs. |
| `app/templates/jobs.html` | The full list of every job the signed-in analyst has ever run, filterable. |
| `app/templates/job_detail.html` | The single busiest template — one job's full result: severity hero, chain of custody, per-file table (disk), findings, evidence, and the scope/limitations section. |
| `app/templates/upload.html` | The upload form page, with drag-and-drop styling. |
| `app/templates/confirm_type.html` | Shown only when a `.raw` file's type couldn't be detected automatically — asks the analyst to say whether it's a disk image or memory dump. |
| `app/templates/error.html` | The generic error page for 404s and 413s (file too large). |
| `app/templates/_limitations.html` | A small shared partial template — loops over whatever `report.limitations(job)` returns, reused by `job_detail.html` so the web page and the PDF can never structurally drift apart. |
| `app/templates/auth/login.html` | The sign-in form. |
| `app/templates/auth/register.html` | The create-account form. |

### `app/static/` — CSS, JS, images served directly to the browser

| File | What it is |
|---|---|
| `app/static/app.css` | This project's own stylesheet — colour variables, panel/stat/hero layout, severity colour scale, status indicators. |
| `app/static/favicon.svg` | The small icon shown in the browser tab. |
| `app/static/vendor/bootstrap.min.css` | The Bootstrap CSS framework, downloaded once and stored locally (not loaded from a CDN — this is meant to work offline). |
| `app/static/vendor/bootstrap.bundle.min.js` | Bootstrap's JavaScript (dropdowns, etc.), same reasoning. |
| `app/static/vendor/chart.umd.min.js` | The Chart.js charting library, used for the severity doughnut charts. |

## `migrations/` — database schema history

| File | What it is |
|---|---|
| `migrations/env.py` | Alembic's environment setup script — mostly boilerplate connecting Alembic to this project's Flask-SQLAlchemy `db` object. |
| `migrations/alembic.ini` | Alembic's configuration file (logging format, etc.). |
| `migrations/script.py.mako` | The template new migration files get generated from. |
| `migrations/README` | A one-line note (from Flask-Migrate's own default scaffold). |
| `migrations/versions/01e40b72559d_...py` | Migration 1: creates every original table — `users`, `jobs`, `audit_log`, `results`, `findings`. |
| `migrations/versions/eb17c935e9af_...py` | Migration 2: makes `jobs.artifact` nullable (to support the `NEEDS_TYPE` state) and adds `jobs.detected_as`. |
| `migrations/versions/6c6e0759a49e_...py` | Migration 3: adds `jobs.stage` and `jobs.progress_pct` for live progress reporting. |
| `migrations/versions/fda781d38f87_...py` | Migration 4: adds `jobs.plugin_seconds` for per-plugin timing data. |
| `migrations/versions/a2aab2930966_...py` | Migration 5: adds `jobs.evidence` for per-process locator data. |
| `migrations/versions/249a2a3baaa5_...py` | Migration 6 (most recent): adds `jobs.volumetric` for configuration-context data. |

## `tests/` — the automated test suite

| File | What it is |
|---|---|
| `tests/conftest.py` | Shared pytest fixtures every other test file uses: a test Flask app, a database, a signed-up analyst account, a signed-in test client. |
| `tests/test_auth.py` | Registration, login, logout, and the security details around them (case-insensitive usernames, same error message for bad username vs. bad password, open-redirect prevention). |
| `tests/test_models.py` | The database models themselves — password hashing, uniqueness constraints, cascading deletes, relationships. |
| `tests/test_upload.py` | The upload route and `artifacts.py` — type detection, extension allowlisting, hashing, storage naming, rate limiting, unreachability over HTTP. |
| `tests/test_jobs.py` | The job lifecycle in `jobs.py` — status transitions, per-pipeline result persistence, orphan recovery, dispatching. |
| `tests/test_inference.py` | Both inference modules — feature counts, threshold sourcing, subset index correctness, the scrambled-column detection guard, hand-built vector predictions. |
| `tests/test_disk_extractor.py` | The PE-signature detection logic in `extractors/disk.py` (MZ header plus real PE signature, not extension-based). |
| `tests/test_memory_extractor.py` | The bulk of `extractors/memory.py`'s field-by-field derivation logic, plugin availability, and symbol-path wiring. |
| `tests/test_memory_torn_rows.py` | Specifically the "torn row" detection for live-acquisition artifacts (a structurally impossible process record). |
| `tests/test_evidence.py` | The per-process evidence-collection logic (`extractors/memory.py:evidence()`) and its presence in the rendered report/page. |
| `tests/test_forensics.py` | The `forensics/` package — feature-meaning resolution, MITRE tag matching, and both severity functions. |
| `tests/test_baseline_ceiling.py` | Specifically the clean-baseline ceiling logic (`observed max × MARGIN`) and its behaviour against real recorded capture numbers. |
| `tests/test_volumetric.py` | The volumetric-context wording (configuration counts reported separately from behavioural severity). |
| `tests/test_report.py` | The PDF renderer — section presence, mandatory limitation strings, ownership checks on the report route, CSV/JSON export. |
| `tests/test_views.py` | The remaining web routes not covered above — dashboard, jobs list, the progress-reporting file mechanism. |
| `tests/test_concurrency.py` | Multiple simultaneous uploads/jobs against a real file-backed database, checking nothing corrupts. |
| `tests/test_malmem_holdout.py` | The `scripts/malmem_holdout.py` reproducible-split logic, tested against a small synthetic CSV so the real 19 MB dataset isn't needed to run the suite. |

## `models/` — the finished, pre-trained model artifacts (committed to Git)

| File | What it is |
|---|---|
| `models/memory/xgboost_model.json` | The production memory model, XGBoost's native JSON format — this is the file actually loaded. |
| `models/memory/feature_list.json` | The 55 memory feature names, in the exact order the model expects them. |
| `models/memory/metadata.json` | Training record for the memory model — includes the operating threshold and the library versions it was trained under. Only the threshold is read at runtime; the rest is documentation. |
| `models/memory/lightgbm_model.txt` | The memory pipeline's *runner-up* model — trained for comparison, lost the internal decision to XGBoost. Kept for the record; **never loaded** by the application. |
| `models/disk/lightgbm_model.txt` | The production disk model, LightGBM's native text format — this is the file actually loaded. |
| `models/disk/feature_list_selected.json` | The 150 selected disk feature names, in model-input order. |
| `models/disk/feature_list_full_2381.json` | The full 2,381-name EMBER feature schema, in extractor order — needed to compute where each of the 150 selected features sits in the full vector. |
| `models/disk/metadata.json` | Training record for the disk model — same role as the memory one. |
| `models/disk/importance_ranking.json` | The feature-selection evidence trail showing how 150 were chosen from 2,381. Archival only; **never loaded** at runtime. |

## `reference_data/` — irreplaceable samples of the original training data

| File | What it is |
|---|---|
| `reference_data/memory_sample.npy` | 5,000 rows sampled from the memory model's actual training data, in `feature_list.json` column order. Used to build the memory LIME explainer and to compute the out-of-distribution range check. This is the *only surviving copy* — the original training matrices no longer exist anywhere. |
| `reference_data/disk_sample.npy` | The same, but 5,000 rows in the 150-feature *selected* space for the disk model. |

## `baselines/` — the clean reference-machine baseline

| File | What it is |
|---|---|
| `baselines/clean_win10_x64.json` | Median and observed-maximum values for every memory feature, computed from seven captures of one known-clean reference machine. This is what a new memory capture's indicators are compared against to decide what counts as "elevated" rather than just "present." |

## `docs/` — long-form documentation, not code

| File | What it is |
|---|---|
| `docs/FYP_Report_Draft.md` | The in-progress dissertation content draft, following the university's mandated structure. |
| `docs/learning/` | This curriculum — the folder you're reading right now. |

## `scripts/` — standalone command-line tools

| File | What it is |
|---|---|
| `scripts/check_env.py` | Verifies the whole environment is correctly set up — library versions, model artifact shapes, the `ember` patches, an end-to-end extractor smoke test. |
| `scripts/setup_env.py` | Installs both requirements files in the correct order, then reinstalls `lief` at the exact pinned version and applies the `ember` patches. |
| `scripts/patch_ember.py` | Defines and applies the three source patches `ember/features.py` needs to run under this project's `lief`/`numpy` versions, and lets the app verify (never re-apply) those patches at startup. |
| `scripts/fetch_symbols.py` | Downloads and stages a memory dump's Windows kernel symbol file into the repo-local `symbols/` folder, so future extraction on that machine needs no network access. |
| `scripts/scan_image.py` | Runs the disk extractor and inference directly against a real disk image from the command line — no web app, no database. |
| `scripts/dump_memory_features.py` | Runs the memory extractor directly against a real dump and prints all 55 values next to their training min/max — the tool for eyeballing extraction correctness. |
| `scripts/predict_vector.py` | Pushes one pre-extracted feature vector through the real inference/explanation/severity code path, without needing a raw artifact at all. |
| `scripts/malmem_holdout.py` | Reproduces the memory model's exact training split from the published CIC-MalMem-2022 CSV, and extracts two genuinely held-out, labelled rows for demo use. |
| `scripts/ember_holdout.py` | Pulls one labelled malicious and one labelled benign row from EMBER's own published test set and vectorises them — a real true-positive/true-negative demo with no PE file ever opened. |
| `scripts/baseline_extract.py` | Runs the memory extractor once against each of the seven clean reference captures and saves the resulting vectors (extraction is slow; this means never repeating it). |
| `scripts/baseline_build.py` | Combines the seven saved vectors into a candidate baseline JSON (median + observed max per feature) — a separate, deliberate step promotes it to the live `baselines/` file. |
| `scripts/sim_injector.py` | A benign capture-time tool that allocates real RWX memory regions (never executed) so a memory capture will genuinely trigger the malfind/Process-Injection indicator, for demo purposes. |
| `scripts/sim_spawnkill.py` | A benign capture-time tool that spawns and holds open ~100 trivial processes, to genuinely trigger rootkit/hidden-process indicators for demo purposes. |
| `scripts/verify_pipeline.py` | The single most important non-unit-test check in the project — runs two real, pinned artifacts through the *actual* job pipeline end to end and checks the results against recorded expectations. |

## Gitignored folders — present on disk, not tracked by Git

| Folder | What's actually in it |
|---|---|
| `sample/` | Real disk images and memory dumps used for testing and demos — hundreds of MB to multiple GB each, deliberately excluded from Git. |
| `data/` | Source datasets (a MalMem CSV, an EMBER tarball) and intermediate baseline-building artifacts. Only `data/holdout/` (small, derived, labelled demo rows) is actually committed — everything else here is excluded. |
| `symbols/` | The repo-local cache of Volatility 3 kernel symbol files, staged per-deployment by `fetch_symbols.py`. Machine/build-specific, so never committed. |
| `uploads/` | Where every uploaded artifact actually lives once stored by the running application — outside the web root, never served, retained indefinitely by policy. |
| `instance/` | Flask's per-deployment instance folder: the real SQLite database file (`app.db`), and the `progress/` folder used to pass live job-progress data across the process boundary. |
| `.venv/` | The Python virtual environment — every installed package, entirely reproducible from the two requirements files. |

## If you only remember one thing about each folder

- **`app/`** — the whole running application; everything else in the repo either feeds it or is built on top of it.
- **`app/inference/`** — the only place a saved model file is ever loaded or a prediction is ever made.
- **`app/extractors/`** — the only place a raw disk image or memory dump is ever actually parsed.
- **`app/forensics/`** — pure lookup tables and plain functions, zero machine learning, turning numbers into meaning.
- **`app/templates/` + `app/static/`** — everything the browser actually sees.
- **`migrations/`** — the database's own version history; never hand-edit the schema without one.
- **`tests/`** — what's known-correct by an automated check; `verify_pipeline.py` in `scripts/` is what's known-correct against *real* artifacts, which is a stronger and different guarantee.
- **`models/` + `reference_data/` + `baselines/`** — the finished, precious, non-reproducible inputs; never regenerate, retrain, or "fix" any of it.
- **`docs/`** — human-readable writing, not code the application runs.
- **`scripts/`** — every one-off or operator tool that isn't part of the live web app itself.
- **`sample/` / `data/` / `symbols/` / `uploads/` / `instance/`** — real working data, deliberately kept out of version control because it's either huge, sensitive, or purely local.
