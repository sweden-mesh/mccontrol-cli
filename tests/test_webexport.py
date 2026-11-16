"""The web app's copy of this package's behaviour (web/lib/data/*.json) and the shared test
vectors (web/test/vectors.json) must be what `python -m mccontrol.webexport` writes now."""
from mccontrol import envelope, token, webexport


def test_committed_json_is_current():
    stale = [rel for rel, text in webexport.files().items()
             if not (webexport.ROOT / rel).is_file()
             or (webexport.ROOT / rel).read_text(encoding="utf-8") != text]
    assert not stale, f"stale: {', '.join(stale)}; run `python -m mccontrol.webexport` and commit"


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

