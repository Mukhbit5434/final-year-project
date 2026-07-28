import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run(*args):
    print(f"\n$ {' '.join(args)}")
    return subprocess.call([PY, "-m", "pip", *args])


def main():
    if run("install", "-r", str(ROOT / "requirements.txt")):
        return 1
    if run("install", "-r", str(ROOT / "requirements-forensics.txt")):
        print("\nforensics deps failed. pytsk3/libewf-python need a working MSVC "
              "toolchain if no wheel exists for this interpreter.", file=sys.stderr)
        return 1

    # ember's setup.py pins lief==0.9.0 and will clobber the 1.0.0 install that
    # produced the training features, so --no-deps is load-bearing. Reinstalling
    # lief first guarantees a clean 1.0.0 regardless of what came before.
    run("uninstall", "-y", "lief")
    if run("install", "lief==1.0.0"):
        return 1
    # Tarball rather than git+https:// so setup works without git on PATH.
    if run("install", "https://github.com/elastic/ember/archive/refs/heads/master.tar.gz",
           "--no-deps"):
        return 1

    sys.path.insert(0, str(ROOT / "scripts"))
    import patch_ember
    return patch_ember.apply()


if __name__ == "__main__":
    sys.exit(main())