"""The spec this package is pinned to (spec/, a tag of mccontrol-spec: data/*.json and
vectors/vectors.json, which mccontrol-web reads too) must be what `python -m mccontrol.webexport`
writes now. A change that alters them ships as a new spec tag, then scripts/spec_sync.py."""
from mccontrol import envelope, token, webexport

SPEC = webexport.ROOT / "spec"


def test_committed_json_is_current():
    stale = [rel for rel, text in webexport.files().items()
             if not (SPEC / rel).is_file()
             or (SPEC / rel).read_text(encoding="utf-8") != text]
    assert not stale, (f"differs from the pinned spec: {', '.join(stale)}; run `python -m mccontrol.webexport "
                       f"--out ../mccontrol-spec`, tag the spec, then `python scripts/spec_sync.py <tag>`")


def test_vectors_are_deterministic():
    assert webexport.files() == webexport.files()


def test_vectors_check_out_against_the_package():
    v = webexport.vectors()
    for case in v["v1"]:
        assert envelope.verify(v["public_key"], case["topic"], case["payload"])
    assert token.verify(v["token"]["password"], v["token"]["audience"], now=v["now"])[0]
    assert envelope.verify_registration(v["registration"]["payload"]) == (v["public_key"], v["now"])
    keys = v["v2_keys"]
    assert keys["shared_secret"] == keys["shared_secret_from_node_side"]

