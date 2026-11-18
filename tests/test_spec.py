"""The vendored copy of mccontrol-spec (spec/, written by scripts/spec_sync.py) is the tag it
names: every file matches its MANIFEST.sha256 line, and nothing is there that the manifest
does not list. Offline; `python scripts/spec_sync.py --check` compares with GitHub."""
import hashlib
import pathlib

SPEC = pathlib.Path(__file__).resolve().parents[1] / "spec"


def _manifest():
    lines = (SPEC / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
    return {path.lstrip("*"): digest for digest, path in (l.split(None, 1) for l in lines if l.strip())}


def test_every_vendored_file_matches_the_manifest():
    bad = [p for p, d in _manifest().items() if hashlib.sha256((SPEC / p).read_bytes()).hexdigest() != d]
    assert not bad, f"edited by hand or stale: {', '.join(bad)}; run scripts/spec_sync.py"


def test_nothing_unlisted_and_a_tag_named():
    present = {p.relative_to(SPEC).as_posix() for p in SPEC.rglob("*") if p.is_file()}
    assert present - set(_manifest()) == {"MANIFEST.sha256", "SOURCE"}
    assert (SPEC / "SOURCE").read_text().split()[0] == "sweden-mesh/mccontrol-spec"
