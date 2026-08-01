"""Stage the Windows kernel ISF for a dump into the repo, so analysis works offline.

Volatility 3 resolves kernel symbols by downloading PDB-derived ISF JSON from
downloads.volatilityfoundation.org the first time it meets a build, and caches it
under the *user's* AppData - outside the project. An offline machine, or a fresh
checkout on another machine, then fails with a confusing symbol error minutes into
a job.

This copies the ISF the dump actually resolved to into symbols/windows/, which
app/__init__.py puts on volatility's search path at startup. Run it once per build
while online; after that the build analyses with no network at all.

    scripts\\fetch_symbols.py sample\\memory\\win10_memory.raw
    scripts\\fetch_symbols.py --list
"""
import argparse
import gzip
import io
import json
import lzma
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEST = ROOT / "symbols" / "windows"


def staged():
    return sorted(DEST.glob("*.json")) if DEST.is_dir() else []


def _isf_url(dump):
    from app.extractors.memory import build_context

    print(f"resolving symbols for {Path(dump).name} ...", flush=True)
    prepared = build_context(dump)
    table = prepared["ctx"].symbol_space[prepared["symbols"]]
    url = table.config.get("isf_url") or table.config.get("isf_filepath")
    if not url:
        raise SystemExit("the symbol table exposes no ISF location; "
                         f"config keys were {list(table.config)}")
    return url


def _load_isf(blob, name):
    """Volatility ships ISFs as .json, .json.gz, .json.xz or .json.zip and reads
    every one of those from a symbols directory - so they are stored verbatim,
    compressed. This only expands in memory to prove the file is intact."""
    if name.endswith(".gz"):
        blob = gzip.decompress(blob)
    elif name.endswith(".xz"):
        blob = lzma.decompress(blob)
    elif name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            blob = z.read(z.namelist()[0])
    return json.loads(blob)


def stage(url):
    DEST.mkdir(parents=True, exist_ok=True)
    parsed = urllib.parse.urlparse(url)
    name = Path(urllib.parse.unquote(parsed.path)).name
    out = DEST / name

    if out.exists():
        print(f"already staged: {out.relative_to(ROOT)}")
        return out

    if parsed.scheme in ("", "file"):
        src = Path(urllib.request.url2pathname(parsed.path)) if parsed.scheme else Path(url)
        shutil.copyfile(src, out)
    else:
        print(f"downloading {url}", flush=True)
        with urllib.request.urlopen(url) as r:
            out.write_bytes(r.read())

    meta = _load_isf(out.read_bytes(), name).get("metadata", {})
    print(f"staged {out.relative_to(ROOT)}  "
          f"({out.stat().st_size / 1024**2:.1f} MB, "
          f"producer={meta.get('producer', {}).get('name', '?')})")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", nargs="?", help="memory dump to resolve symbols for")
    ap.add_argument("--list", action="store_true", help="show what is already staged")
    args = ap.parse_args()

    if args.list or not args.dump:
        have = staged()
        if not have:
            print(f"nothing staged in {DEST.relative_to(ROOT)}")
            print("run this against a dump while online to populate it")
        for p in have:
            print(f"  {p.name}  {p.stat().st_size / 1024**2:.1f} MB")
        return 0 if args.list else 2

    stage(_isf_url(args.dump))
    print("\nthis build now resolves offline; keep symbols/ alongside the app")
    return 0


if __name__ == "__main__":
    sys.exit(main())
