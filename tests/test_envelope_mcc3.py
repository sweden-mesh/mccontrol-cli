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


def test_k_fwd_is_rfc_5869_by_hand():
    """The fourth label, worked with hmac alone so the vector does not rest on one library."""
    import hashlib
    import hmac
    secret = mcc3.shared_secret(CMD_SEED, NODE)
    prk = hmac.new(bytes(32), secret, hashlib.sha256).digest()
    okm = hmac.new(prk, ("mcc3/fwd/" + NODE).encode("ascii") + b"\x01", hashlib.sha256).digest()
    assert K["fwd"] == okm and K["fwd"].hex().upper() == V["keys"]["owner"]["fwd"]
    assert len({K[name] for name in ("cmd", "mesh", "alive", "fwd")}) == 4


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
                                 companion_tag=v["companion_tag"], flags=v["flags"])
    assert req.hex().upper() == v["request"] and len(req) == mcc3.MESH_REQUEST_LEN
    assert req[4:].hex().upper() == v["app_sends"] and req[5] == v["flags"]
    signed = mcc3.signed_bytes(NODE, mcc3.ROAD_MESH, v["flags"], v["counter"], v["expiry"], None,
                               v["command"].encode())
    assert signed.hex().upper() == v["signed"]
    assert mcc3.open_mesh_request(NODE_SEED, CMD_KEY, req, last_counter=v["counter"] - 1) == {
        "tag": v["companion_tag"], "flags": v["flags"], "counter": v["counter"], "expiry": v["expiry"],
        "command": v["command"]}


def test_zero_hop_flag_is_signed_and_the_only_flag():
    """V3z is V3 with flags 0x02: the same counter and command, another signature, so the flag
    cannot be set or cleared on the way. No other bit is taken, and none is built."""
    v3, v3z = (bytes.fromhex(V["mesh_requests"][i]["request"]) for i in (0, 2))
    assert V["mesh_requests"][2]["flags"] == mcc3.FLAG_ZERO_HOP == 0x02
    assert v3[:5] == v3z[:5] and v3[6:14] == v3z[6:14] and v3[14:78] != v3z[14:78]
    assert V["mesh_requests"][0]["signature"] != V["mesh_requests"][2]["signature"]
    for flags in range(1, 256):
        bad = bytearray(v3z)
        bad[5] = flags
        if flags == 0x02:
            assert mcc3.open_mesh_request(NODE_SEED, CMD_KEY, bytes(bad))["flags"] == 0x02
            continue
        with pytest.raises(mcc3.Refused) as exc:
            mcc3.open_mesh_request(NODE_SEED, CMD_KEY, bytes(bad))
        assert exc.value.outcome == "bad-version"
        with pytest.raises(mcc3.Mcc3Error):
            mcc3.seal_mesh_request(CMD_SEED, NODE, 7, 1, "ver", flags=flags)
    for req, flags in ((v3, 0x02), (v3z, 0x00)):
        bad = bytearray(req)
        bad[5] = flags
        with pytest.raises(mcc3.Refused) as exc:
            mcc3.open_mesh_request(NODE_SEED, CMD_KEY, bytes(bad))
        assert exc.value.outcome == "sig-invalid"


# -- forwards through a relay ---------------------------------------------------------------------

TARGET = PUB["other_node"]


@pytest.mark.parametrize("v", V["forwards"], ids=lambda v: v["name"][:2])
def test_forward(v):
    raw = mcc3._forward_raw(K, bytes.fromhex(v["nonce"]), v["flags"], v["counter"], v["expiry"],
                            bytes.fromhex(v["rid"]), bytes.fromhex(v["target"]), v["route"], v["path_len"],
                            bytes.fromhex(v["path_field"]), v["body_len"], bytes.fromhex(v["body"]))
    assert mcc3.b64(raw) == v["payload"]
    assert len(raw) == v["bytes"] == mcc3.FORWARD_SIZE == 278 and len(v["payload"]) == 371
    assert raw[0] == 0x46 and raw[1] == 0
    assert v["topic"] == mcc3.command_topic(NODE) and v["reply_topic"] == mcc3.reply_topic(bytes.fromhex(v["rid"]))
    got = mcc3.open_forward(NODE_SEED, CMD_KEY, v["payload"])
    assert got == {"counter": v["counter"], "expiry": v["expiry"], "rid": bytes.fromhex(v["rid"]),
                   "target": v["target"], "route": v["route"], "path_len": v["path_len"],
                   "path": bytes.fromhex(v["path"]), "body": bytes.fromhex(v["body"])}
    assert v["opened"]["body"] == v["body"] and v["opened"]["path"] == v["path"]
    if v["path_field"] == v["path"]:
        assert mcc3.seal_forward(K, NODE, v["counter"], v["expiry"], bytes.fromhex(v["rid"]), v["target"],
                                 v["route"], bytes.fromhex(v["body"]), path_len=v["path_len"],
                                 path=bytes.fromhex(v["path"]), nonce=bytes.fromhex(v["nonce"])) == v["payload"]


def test_forward_f1_and_f2_are_the_design_notes():
    f1, f2 = V["forwards"]
    assert (f1["counter"], f1["expiry"], f1["route"], f1["path_len"]) == (9, 1795000000, 0, 0)
    assert f1["rid"] == bytes(range(16)).hex().upper() and f1["nonce"] == bytes(range(0x60, 0x6C)).hex().upper()
    assert f1["target"] == TARGET != NODE
    assert f1["body"] == V["mesh_requests"][2]["app_sends"] and f1["body"][:4] == "C202"
    assert (f2["route"], f2["path_len"], f2["body_len"]) == (1, 0, 81) and f2["body"][:2] == "C1"
    assert len(f2["path_field"]) == 6 and f2["path"] == ""


@pytest.mark.parametrize("v", V["forward_results"], ids=lambda v: v["name"][:2])
def test_forward_result(v):
    payload = mcc3.seal_forward_result(K, v["counter"], v["status"], v["clock"], sent=v["sent"], snr=v["snr"],
                                       path_len=v["path_len"], path=bytes.fromhex(v["path"]),
                                       response=bytes.fromhex(v["response"]), nonce=bytes.fromhex(v["nonce"]))
    assert payload == v["payload"] and len(payload) == 380
    assert len(mcc3.unb64(payload)) == v["bytes"] == mcc3.FORWARD_RESULT_SIZE == 285
    assert mcc3.open_forward_result(K, payload) == {
        "counter": v["counter"], "status": v["status"], "name": v["status_name"], "clock": v["clock"],
        "sent": v["sent"], "snr": v["snr"], "path_len": v["path_len"], "path": bytes.fromhex(v["path"]),
        "response": bytes.fromhex(v["response"])}


def test_forward_result_f3_carries_v4():
    f3, f4 = V["forward_results"]
    r = mcc3.open_forward_result(K, f3["payload"])
    assert (r["name"], r["snr"], r["path_len"], r["sent"]) == ("answered", 22, None, 1)
    v4 = V["mesh_responses"][0]
    assert r["response"].hex().upper() == v4["response"][8:]
    assert mcc3.open_mesh_response(K, bytes(4) + r["response"])["reply"] == v4["reply"]
    r = mcc3.open_forward_result(K, f4["payload"])
    assert (r["name"], r["snr"], r["path_len"], r["path"], r["sent"], r["response"]) == (
        "no-answer", None, 2, bytes.fromhex(f4["path"]), 2, b"")


def test_forward_statuses_and_routes():
    assert mcc3.FORWARD_STATUSES == ("answered", "no-answer", "off", "expired", "replay", "bad-body", "busy",
                                     "rate-limited", "clock-unset", "send-failed", "guest-cap", "guests-full",
                                     "target-cap")
    assert mcc3.ROUTES == ("direct", "flood", "flood-wide")
    assert (mcc3.KIND_FORWARD, mcc3.KIND_FORWARD_RESULT) == (0x46, 0x66)
    assert mcc3.open_forward_result(K, mcc3.seal_forward_result(K, 1, 77, 0))["name"] is None


BODY_C2 = bytes.fromhex(V["mesh_requests"][2]["app_sends"])


@pytest.mark.parametrize("kwargs", [
    {"body": b"\xC3" + BODY_C2[1:]}, {"body": BODY_C2[:131]}, {"body": b"\xC1" + bytes(72)},
    {"body": b"\xC1" + bytes(132)}, {"body": b""}, {"route": 3}, {"path_len": 1}, {"path_len": 58, "path": bytes(58)},
    {"path_len": 0xC1, "path": bytes(4)}, {"path": b"\x01"}, {"target": NODE}, {"rid": bytes(15)}],
    ids=lambda k: next(iter(k)))
def test_forward_not_built(kwargs):
    """A sender refuses what a relay would answer bad-body, before anything is sealed."""
    a = {"rid": bytes(16), "target": TARGET, "route": 0, "body": BODY_C2, "path_len": 0, "path": b""} | kwargs
    with pytest.raises(mcc3.Mcc3Error):
        mcc3.seal_forward(K, NODE, 9, 1, a["rid"], a["target"], a["route"], a["body"], path_len=a["path_len"],
                          path=a["path"])


def test_forward_takes_a_path_and_both_bodies():
    path = bytes(range(57))
    got = mcc3.open_forward(NODE_SEED, CMD_KEY, mcc3.seal_forward(K, NODE, 9, 1, bytes(16), TARGET, 0, BODY_C2,
                                                                  path_len=57, path=path))
    assert got["path"] == path and got["path_len"] == 57
    two = mcc3.seal_forward(K, NODE, 9, 1, bytes(16), TARGET, 0, b"\xC1" + bytes(73), path_len=0x41, path=b"\xAA\xBB")
    assert mcc3.open_forward(NODE_SEED, CMD_KEY, two)["path"] == b"\xAA\xBB"
    assert mcc3.path_bytes(0x80 | 19, 57) == 57 and mcc3.path_bytes(0x80 | 20, 57) is None


def test_every_byte_of_a_forward_and_its_result_is_authenticated():
    for payload, opener in ((V["forwards"][0]["payload"], lambda p: mcc3.open_forward(NODE_SEED, CMD_KEY, p)),
                            (V["forward_results"][0]["payload"], lambda p: mcc3.open_forward_result(K, p))):
        raw = mcc3.unb64(payload)
        for offset in range(len(raw)):
            bad = bytearray(raw)
            bad[offset] ^= 0x10
            with pytest.raises(mcc3.Refused):
                opener(mcc3.b64(bytes(bad)))


def test_a_forward_is_not_a_command_and_a_forward_result_is_not_a_result():
    """278 and 285 bytes are a command's and a result's sizes too: the kind byte tells them apart."""
    with pytest.raises(mcc3.Refused) as exc:
        mcc3.open_command(NODE_SEED, CMD_KEY, V["forwards"][0]["payload"])
    assert exc.value.outcome == "bad-fields"
    with pytest.raises(mcc3.Refused) as exc:
        mcc3.open_result(K, V["forward_results"][0]["payload"])
    assert exc.value.outcome == "bad-fields"


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
            elif v["kind"] == "forward":
                mcc3.open_forward(v["node_seed"], v["command_key"], v["input"])
            else:
                mcc3.open_mesh_request(v["node_seed"], v["command_key"], bytes.fromhex(v["input"]),
                                       last_counter=v.get("last_counter"))
        else:
            keys = _keys(v["keys"])
            if v["kind"] == "mesh_response":
                mcc3.open_mesh_response(keys, bytes.fromhex(v["input"]))
            else:
                {"result": mcc3.open_result, "alive": mcc3.open_alive,
                 "forward_result": mcc3.open_forward_result}[v["kind"]](keys, v["input"])
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


@pytest.mark.parametrize("offset, value", [(76, 168), (11, 0x61), (11, 0xC1)],
                         ids=["response-168", "path-66-bytes", "path-reserved-size"])
def test_forward_result_with_an_impossible_length_is_refused(offset, value):
    """Authentic but malformed: a length that points outside its field is never followed."""
    plain = bytearray(mcc3.FORWARD_RESULT_PLAIN)
    plain[11] = mcc3.PATH_NONE
    plain[offset] = value
    header = bytes([mcc3.KIND_FORWARD_RESULT]) + bytes(12)
    sealed, tag = mcc3._aead(K["fwd"], bytes(12), header).encrypt_and_digest(bytes(plain))
    with pytest.raises(mcc3.Refused) as exc:
        mcc3.open_forward_result(K, mcc3.b64(header + sealed + tag))
    assert exc.value.outcome == "bad-fields"


@pytest.mark.parametrize("fill", range(16))
def test_mesh_response_with_the_mesh_zero_fill(fill):
    """MeshCore hands a datagram over zero-filled to the 16-byte block edge (bench 2026-11-23:
    a 55-byte response arrived as 60), so the opener finds the length by the tag."""
    v = V["mesh_responses"][0]
    resp = mcc3.seal_mesh_response(K, v["companion_tag"], v["counter"], v["code"], v["clock"], v["reply"],
                                   nonce=bytes.fromhex(v["nonce"]))
    assert mcc3.open_mesh_response(K, resp + bytes(fill))["reply"] == v["reply"]


def test_mesh_response_zero_fill_does_not_open_an_altered_one():
    v = V["mesh_responses"][0]
    resp = bytearray(mcc3.seal_mesh_response(K, v["companion_tag"], v["counter"], v["code"], v["clock"], v["reply"]))
    resp[20] ^= 1
    with pytest.raises(mcc3.Refused):
        mcc3.open_mesh_response(K, bytes(resp) + bytes(5))
    with pytest.raises(mcc3.Refused):
        mcc3.open_mesh_response(K, bytes(resp[:-1]) + b"\x01")
