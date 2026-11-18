"""mcc3 (lou-20): the sealed envelope keyed by the node. Every vector in the pinned spec's
`vectors/mcc3-vectors.json` is rebuilt from its inputs and opened, and every refusal gives its
outcome; the design note's own worked vectors (planning/firmware/iata2-design-20261118.md §8)
are pinned here as literals, so the spec cannot drift from them unnoticed."""
import json
import pathlib

import pytest

from mccontrol import mcc3

SPEC = pathlib.Path(__file__).resolve().parents[1] / "spec" / "vectors" / "mcc3-vectors.json"
V = json.loads(SPEC.read_text(encoding="utf-8"))
SEEDS, PUB = V["keys"]["seeds"], V["keys"]["public"]
CMD_SEED, NODE_SEED, CMD_KEY, NODE = SEEDS["command"], SEEDS["node"], PUB["command"], PUB["node"]
K = mcc3.owner_keys(CMD_SEED, NODE)


def _keys(hexes):
    return {name: bytes.fromhex(v) for name, v in hexes.items()}


# -- the design note's literals ------------------------------------------------------------------

def test_design_note_keys():
    assert CMD_KEY == "ED54A59FB1AC3A51239351362941B868E85A60E3D7B2485D828821DC7A69C279"
    assert NODE == "4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4"
    s = "FDF129BEF36C89EE567613FAE911D1019A495F941F6CC5024336A28488CE1B41"
    assert mcc3.shared_secret(CMD_SEED, NODE).hex().upper() == s
    assert mcc3.shared_secret(NODE_SEED, CMD_KEY).hex().upper() == s
    assert K["cmd"].hex().upper() == "75A338AE650E9DD3FA883459F41CE6635941A259538CC48B0FFB8BEBA66227A2"
    assert K["mesh"].hex().upper() == "6570868EF9F1A89F14F669ADD6970DD7027CB63827F4D907C7BF666B6C47072F"
    assert K["alive"].hex().upper() == "3C76F7735057A079C4FCEF5B5BD1EA0AF7F32F426488CF66A67CE2FD434AAD60"
    assert mcc3.node_keys(NODE_SEED, CMD_KEY) == K


def test_design_note_v1_v2_v4_v5():
    assert V["commands"][0]["payload"].startswith("QwAgISIjJCUmJygpKivEgvFkiDRSSgwfqFm9uQbYJax8")
    assert V["commands"][0]["payload"].endswith("Tcb8vL0naB5gSHI")
    assert V["commands"][0]["signature"].startswith("F69C9A621ECB8771")
    assert V["results"][0]["payload"].endswith("Koiqm3GSxqvtlv6jGTl")
    assert V["mesh_responses"][0]["response"] == ("00F1536552505152535455565758595A5B26ABE43386991ADD1102608FDA5CA2"
                                                  "C735EAB61A9A8598DC19BEA6")
    assert V["alive"][0]["payload"].startswith("QUBBQkNERUZHSElKS81vKOiz45K4P6rnGzXELRcN")
    assert V["alive"][0]["payload"].endswith("PC5tKj4E")


def test_mesh_request_is_the_aead_ciphertext_without_its_tag():
    """Operator decision 2026-11-18: no tag on the mesh road. The keystream is ChaCha20 from block
    1, so the first 110 bytes after the clear header are the design's tagged V3 exactly."""
    req = V["mesh_requests"][0]["request"]
    assert req.startswith("00F15365C20007000000FA5C421E7AB84644B33C7E8680B83524B2C5D93D604171406AECF3691C"
                          "349FC93C6DDE8C3894E3925AB26ADA27B88FED000F45C5")
    assert V["mesh_requests"][0]["signature"].startswith("B6B5D6861BEC26B4")


# -- the spec's vectors --------------------------------------------------------------------------

def test_keys():
    k = V["keys"]
    assert k["shared_secret"] == k["shared_secret_from_node_side"]
    assert k["owner"] == k["node_side"] == {n: v.hex().upper() for n, v in K.items()}
    assert _keys(k["other_node"]) == mcc3.owner_keys(CMD_SEED, PUB["other_node"])
    assert _keys(k["other_owner"]) == mcc3.owner_keys(SEEDS["other_owner"], NODE)


@pytest.mark.parametrize("v", V["commands"], ids=lambda v: v["name"])
def test_command(v):
    rid = bytes.fromhex(v["rid"])
    payload = mcc3.seal_command(CMD_SEED, NODE, v["counter"], v["expiry"], rid, v["command"],
                                nonce=bytes.fromhex(v["nonce"]))
    assert payload == v["payload"]
    assert len(mcc3.unb64(payload)) == v["bytes"] in mcc3.COMMAND_SIZES
    signed = mcc3.signed_bytes(NODE, mcc3.ROAD_MQTT, 0, v["counter"], v["expiry"], rid, v["command"].encode())
    assert signed.hex().upper() == v["signed"]
    assert mcc3.command_topic(NODE) == v["topic"] and mcc3.reply_topic(rid) == v["reply_topic"]
    assert mcc3.open_command(NODE_SEED, CMD_KEY, payload) == {
        "counter": v["counter"], "expiry": v["expiry"], "rid": rid, "command": v["command"]}


@pytest.mark.parametrize("v", V["results"], ids=lambda v: v["name"])
def test_result(v):
    payload = mcc3.seal_result(K, v["counter"], v["code"], v["clock"], v["command"], v["reply"],
                               nonce=bytes.fromhex(v["nonce"]))
    assert payload == v["payload"]
    assert len(mcc3.unb64(payload)) == v["bytes"] in mcc3.RESULT_SIZES
    assert mcc3.open_result(K, payload) == {"counter": v["counter"], "code": v["code"], "clock": v["clock"],
                                            "command": v["command"], "reply": v["reply_opened"]}
    assert v["reply"].startswith(v["reply_opened"])


@pytest.mark.parametrize("v", V["mesh_requests"], ids=lambda v: v["name"])
def test_mesh_request(v):
    req = mcc3.seal_mesh_request(CMD_SEED, NODE, v["counter"], v["expiry"], v["command"],
                                 companion_tag=v["companion_tag"])
    assert req.hex().upper() == v["request"] and len(req) == mcc3.MESH_REQUEST_LEN
    assert req[4:].hex().upper() == v["app_sends"]
    assert mcc3.open_mesh_request(NODE_SEED, CMD_KEY, req, last_counter=v["counter"] - 1) == {
        "tag": v["companion_tag"], "counter": v["counter"], "expiry": v["expiry"], "command": v["command"]}


def test_mesh_response():
    v = V["mesh_responses"][0]
    resp = mcc3.seal_mesh_response(K, v["companion_tag"], v["counter"], v["code"], v["clock"], v["reply"],
                                   nonce=bytes.fromhex(v["nonce"]))
    assert resp.hex().upper() == v["response"]
    assert mcc3.open_mesh_response(K, resp) == {k: v[k] for k in ("counter", "code", "clock", "reply")} | {
        "tag": v["companion_tag"]}


@pytest.mark.parametrize("v", V["alive"], ids=lambda v: v["name"])
def test_alive(v):
    payload = mcc3.seal_alive(K, v["fields"], nonce=bytes.fromhex(v["nonce"]))
    assert payload == v["payload"] and len(payload) == 252
    assert mcc3.open_alive(K, payload) == v["opened"]
    assert mcc3.alive_topic(NODE) == v["topic"]


@pytest.mark.parametrize("v", V["refusals"], ids=lambda v: v["name"])
def test_refusal(v):
    with pytest.raises(mcc3.Refused) as exc:
        if v["opened_by"] == "node":
            if v["kind"] == "command":
                mcc3.open_command(v["node_seed"], v["command_key"], v["input"])
            else:
                mcc3.open_mesh_request(v["node_seed"], v["command_key"], bytes.fromhex(v["input"]),
                                       last_counter=v.get("last_counter"))
        else:
            keys = _keys(v["keys"])
            if v["kind"] == "mesh_response":
                mcc3.open_mesh_response(keys, bytes.fromhex(v["input"]))
            else:
                {"result": mcc3.open_result, "alive": mcc3.open_alive}[v["kind"]](keys, v["input"])
    assert exc.value.outcome == v["outcome"]


@pytest.mark.parametrize("v", V["not_built"], ids=lambda v: f'{v["road"]}:{v["command"][:16]!r}')
def test_not_built(v):
    with pytest.raises(mcc3.Mcc3Error):
        if v["road"] == "mqtt":
            mcc3.seal_command(CMD_SEED, NODE, 7, 1, bytes(16), v["command"])
        else:
            mcc3.seal_mesh_request(CMD_SEED, NODE, 7, 1, v["command"])


# -- properties beyond the vectors ---------------------------------------------------------------

def test_every_bit_after_the_mesh_counter_is_covered():
    """No tag on the mesh road: a flip of any bit from the counter to the end must still be refused.
    Every byte, the lowest and highest bit (two of eight: each is one Ed25519 verify)."""
    req = bytes.fromhex(V["mesh_requests"][0]["request"])
    for offset in range(6, mcc3.MESH_REQUEST_LEN):
        for bit in (0, 7):
            bad = bytearray(req)
            bad[offset] ^= 1 << bit
            with pytest.raises(mcc3.Refused):
                mcc3.open_mesh_request(NODE_SEED, CMD_KEY, bytes(bad))


def test_random_nonces_differ_and_open():
    rid = mcc3.new_rid()
    a, b = (mcc3.seal_command(CMD_SEED, NODE, 7, 1, rid, "ver") for _ in range(2))
    assert a != b
    assert mcc3.open_command(NODE_SEED, CMD_KEY, a)["command"] == mcc3.open_command(NODE_SEED, CMD_KEY, b)["command"]
    r1, r2 = (mcc3.seal_result(K, 7, 0, 0, "ver", "x") for _ in range(2))
    assert r1 != r2 and mcc3.open_result(K, r1) == mcc3.open_result(K, r2)


def test_mesh_resend_is_identical():
    a = mcc3.seal_mesh_request(CMD_SEED, NODE, 9, 1795000000, "reboot", companion_tag=1)
    assert a == mcc3.seal_mesh_request(CMD_SEED, NODE, 9, 1795000000, "reboot", companion_tag=1)


def test_topics():
    assert mcc3.node_from_topic(mcc3.command_topic(NODE)) == NODE
    assert mcc3.node_from_topic(mcc3.alive_topic(NODE.lower())) == NODE
    assert mcc3.ping_topic(NODE) == f"mcc/ping/{NODE}"
    assert mcc3.node_from_topic(f"meshcore/JKG/{NODE}/cmd") is None
    assert mcc3.node_from_topic(f"mcc/cmd/{NODE.lower()}") is None
    with pytest.raises(mcc3.Mcc3Error):
        mcc3.command_topic(NODE[:8])
