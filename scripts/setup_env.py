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

    run("uninstall", "-y", "lief")
    if run("install", "lief==1.0.0"):
        return 1
    if run("install", "https://github.com/elastic/ember/archive/refs/heads/master.tar.gz",
           "--no-deps"):
        return 1

    sys.path.insert(0, str(ROOT / "scripts"))
    import patch_ember
    return patch_ember.apply()


if __name__ == "__main__":
    sys.exit(main())