#!/usr/bin/env python3
"""Copy a tag of mccontrol-spec into spec/: its MANIFEST.sha256 and every file it lists, each
checked against its line before anything is written. tests/test_spec.py then checks the copy
offline, and tests/test_webexport.py checks that this package still writes exactly it.

    python scripts/spec_sync.py v0.1.0                     # from GitHub
    python scripts/spec_sync.py v0.1.0 --from ../mccontrol-spec    # from a local clone (git show)
    python scripts/spec_sync.py --check                    # does spec/ equal its tag on GitHub?
"""

import argparse
import hashlib
import pathlib
import shutil
import subprocess
import sys
import urllib.request

REPO = "sweden-mesh/mccontrol-spec"
ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"


def reader(tag, local):
    if local:
        return lambda path: subprocess.run(["git", "-C", str(local), "show", f"{tag}:{path}"],
                                           check=True, capture_output=True).stdout
    def fetch(path):
        with urllib.request.urlopen(f"https://raw.githubusercontent.com/{REPO}/{tag}/{path}", timeout=30) as r:
            return r.read()
    return fetch


def manifest(text):
    """`{path: sha256}` from sha256sum's format."""
    out = {}
    for line in text.splitlines():
        if line.strip():
            digest, path = line.split(None, 1)
            out[path.strip().lstrip("*")] = digest
    return out


def fetch_all(tag, local):
    read = reader(tag, local)
    raw = read("MANIFEST.sha256")
    files = {"MANIFEST.sha256": raw}
    for path, digest in manifest(raw.decode("utf-8")).items():
        body = read(path)
        if hashlib.sha256(body).hexdigest() != digest:
            sys.exit(f"{path} at {tag} does not match MANIFEST.sha256; nothing written")
        files[path] = body
    files["SOURCE"] = f"{REPO} {tag}\n".encode()
    return files


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("tag", nargs="?", help="the spec tag to copy (with --check: default spec/SOURCE's)")
    p.add_argument("--from", dest="local", type=pathlib.Path, help="a local mccontrol-spec clone")
    p.add_argument("--check", action="store_true", help="compare only; exit 1 when spec/ differs")
    a = p.parse_args(argv)
    tag = a.tag or (SPEC / "SOURCE").read_text().split()[1]
    files = fetch_all(tag, a.local)
    if a.check:
        differ = [path for path, body in files.items()
                  if not (SPEC / path).is_file() or (SPEC / path).read_bytes() != body]
        print(f"spec/ differs from {REPO} {tag}: {', '.join(differ)}" if differ else f"spec/ is {REPO} {tag}")
        return 1 if differ else 0
    shutil.rmtree(SPEC, ignore_errors=True)
    for path, body in files.items():
        (SPEC / path).parent.mkdir(parents=True, exist_ok=True)
        (SPEC / path).write_bytes(body)
    print(f"spec/: {len(files) - 2} files from {REPO} {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
