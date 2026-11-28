"""The shared node store and relaying through anyone's Observer (lou-21, L21-G9). A node without
Wi-Fi signs its announce; any lou-21 Observer hands it to the command server, which keeps one
entry per node, retained on `mcc/node/<KEY>`. Here: the bytes (the first 101 still pinned by the
firmware's malive vectors, the signature, the entry and the guest forward by vectors of this
file with fixed keys, the same hex mccontrol-web's test/node-store.test.js pins, made there by
another implementation), the discovery from a FAKE broker (tag, signature, seal, the tried
cache, a forgotten node stays out), the relay choice and a guest forward through a stranger's
relay, and what a screen shows. Nothing here opens a broker or a radio."""
import datetime
import json
import pathlib
import types

import pytest

from mccontrol import actions, beacon, directory, envelope, mcc3, mesh, plane, store as _store, transport

V = json.loads((pathlib.Path(__file__).resolve().parents[1] / "spec" / "vectors" / "malive-vectors.json")
               .read_text(encoding="utf-8"))
SEEDS, PUB, C = V["keys"]["seeds"], V["keys"]["public"], V["constants"]
OWNER_SEED, OWNER = SEEDS["owner"], PUB["owner"]
NODE_SEED, NODE = SEEDS["node"], PUB["node"]
CATCHER_SEED, CATCHER = SEEDS["catcher"], PUB["catcher"]
STRANGER = PUB["other_owner"]                    # as an Observer key: someone else's node
K_MALIVE = mcc3.malive_key(mcc3.shared_secret(OWNER_SEED, NODE), NODE)
A1 = V["announces"][0]

# The vectors of this file, the same as mccontrol-web's test/node-store.test.js. X["signed"] is also
# the firmware's A1 in planning/firmware/malive-vectors-20261127.json, cross-checked 2026-11-28.
X = {
    "signed": "4F4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C44D86B8A37F07000000010000000A8929E75030C7B6"
              "1C72ED92FCFF1F24B473C950D0EA2478D42A8694CAF611F3F9C313EE64D67BACA1BD1D6715D3F7C52A87DDAC809D1BB633F252A657"
              "F66CD04673BB52C57EFD4A45468AA2F07553551EF5FA7AA1F202AD9CC579CFE313B6A8C03C42AD04EFBF883AE666CD16D6B2E2D4E3"
              "5005760F0F",
    "catchers": [{"key": CATCHER, "arrival": 1795000050, "snr": -22, "hops": 2, "via": 2, "list": 0},
                 {"key": STRANGER, "arrival": 1794990000, "snr": 30, "hops": 0, "via": 0, "list": 1}],
    "entry": "Tk_QmczUfXiT3-nsJEFOyw2bVCAjKq0w2RxGW-M8vmXETYa4o38HAAAAAQAAAAqJKedQMMe2HHLtkvz_HyS0c8lQ0OokeNQqhpTK9hHz-c"
             "MT7mTWe6yhvR1nFdP3xSqH3ayAnRu2M_JSplf2bNBGc7tSxX79SkVGiqLwdVNVHvX6eqHyAq2cxXnP4xO2qMA8Qq0E77-IOuZmzRbWsuLU4"
             "1AFdg8PAt3jvM7H86ZqERX0XXIPTcE1w658TiLco4_bHv1qSV_48ob9auoCAgBsKP0FjBjIjGzOKvmB0tEchRsSPtW2m3h2dz7Qmeo_g7Bf"
             "_WoeAAAB",
    # the guest key of OWNER_SEED (HKDF "mcc3/guestkey/"), K_gfwd with CATCHER, and a guest forward
    "guest_key": "CE91C3FE7050EC6881C9803989768080814ADA7FC90F4E9341F23E8797894852",
    "k_gfwd": "9F518025C8CFE00D01F3D63FB7C881C73348D08239B129A442E2D4D3AA05BD4A",
    "guest": "R86Rw_5wUOxogcmAOYl2gICBStp_yQ9Ok0HyPoeXiUhSYGFiY2RlZmdoaWpreKaNfLf8hapfn50oWZf29yaQ7Pwb5yvB8rap3v2v3CVQoIiEW7L1"
             "IcGgAu-MifHnV7nKvE6kz4qVPqyyq2XD2aMhXkXJs7G46KJz3ztP_upMvzYlJdz-zM9KlqUqgHoHhjwE3nYwwkQ9q_VO_Ti6lRmDjSwcvPMLhYeQ"
             "CgUn_lGxu5dtnWmD3TYUq5joe9NIdYMEPdJT2b4nfCE8I0Rt7JJN5It-A8-vOnlPGcuNorZU54vWzK8P9QSba79X9XtW548ZVieqo7OsGxy7dduR"
             "GzIz-7VcJxhhIR9FAjpeAI70MPhbkJrlvzIbCIP5AkFKOCKzlK6E9wnwQ-_OCVj7XHTj3k7GnxTW",
    "nonce": "606162636465666768696A6B", "rid": "00112233445566778899AABBCCDDEEFF",
}
GUEST_BODY = bytes([0xC2]) + bytes([7]) * 131


def announce_of(node_seed=NODE_SEED, to=OWNER, key=None, **over):
    """A signed announce of `node_seed`'s node, sealed to `to`."""
    node = envelope.public_key_hex(node_seed)
    k = key or mcc3.malive_key(mcc3.shared_secret(node_seed, to), node)
    return mcc3.sign_announce(node_seed, mcc3.seal_announce(k, to, node, dict(A1["fields"], **over)))


def entry_of(announce, catchers=None):
    return mcc3.seal_node_entry(announce, X["catchers"] if catchers is None else catchers)


def refused(raw, key=K_MALIVE, cmd=OWNER):
    try:
        mcc3.open_signed_announce(key, cmd, raw)
    except mcc3.Refused as exc:
        return exc.outcome
    return None


# -- the bytes -------------------------------------------------------------------------------

@pytest.mark.parametrize("a", V["announces"], ids=lambda a: a["name"])
def test_the_first_101_bytes_are_still_the_firmware_vectors(a):
    key, node = mcc3.malive_key(mcc3.shared_secret(OWNER_SEED, PUB[a["node"]]), PUB[a["node"]]), PUB[a["node"]]
    raw = mcc3.seal_announce(key, OWNER, node, a["fields"])
    assert raw.hex().upper() == a["payload"]
    opened = mcc3.open_announce(key, OWNER, raw)
    assert opened.pop("node_key") == node and opened == a["opened"]


@pytest.mark.parametrize("r", V["refusals"], ids=lambda r: r["name"])
def test_every_vector_refusal_is_still_refused(r):
    with pytest.raises(mcc3.Refused) as said:
        mcc3.open_announce(K_MALIVE, OWNER, bytes.fromhex(r["input"]))
    assert said.value.outcome == r["outcome"]


def test_the_signed_announce_is_165_bytes_signed_by_the_node_and_pinned():
    signed = mcc3.sign_announce(NODE_SEED, bytes.fromhex(A1["payload"]))
    assert len(signed) == mcc3.ANNOUNCE_SIGNED_SIZE == 165 and signed.hex().upper() == X["signed"]
    assert signed[:101].hex().upper() == A1["payload"]
    assert mcc3.announce_signature_ok(signed) and mcc3.announce_is_for(OWNER, signed)
    assert not mcc3.announce_is_for(STRANGER, signed)
    opened = mcc3.open_signed_announce(K_MALIVE, OWNER, signed)
    assert opened.pop("node_key") == NODE and opened == A1["opened"]
    with pytest.raises(mcc3.Mcc3Error):
        mcc3.sign_announce(CATCHER_SEED, bytes.fromhex(A1["payload"]))
    assert (mcc3.ANN_LABEL, mcc3.KIND_NODE, mcc3.NODE_CATCHER_SIZE, mcc3.NODE_FILTER) == (
        b"mcc3/ann|", 0x4E, 40, "mcc/node/+")


def test_the_checks_run_in_order_size_tag_signature_seal():
    signed = bytes.fromhex(X["signed"])
    assert refused(signed[:101]) == "not-announce"
    assert refused(signed, cmd=STRANGER) == "other-owner"
    for at, outcome in ((1, "other-owner"), (40, "other-owner"), (50, "bad-signature"), (100, "bad-signature"),
                        (101, "bad-signature"), (164, "bad-signature")):
        assert refused(signed[:at] + bytes([signed[at] ^ 1]) + signed[at + 1:]) == outcome, at
    forged = signed[:101] + mcc3._sign(CATCHER_SEED, mcc3.ANN_LABEL + signed[1:101])    # another key's signature
    assert refused(forged) == "bad-signature"
    wrong_seal = announce_of(key=bytes(32))
    assert mcc3.announce_signature_ok(wrong_seal) and refused(wrong_seal) == "does-not-open"


def test_the_node_entry_is_kind_n_with_40_byte_catchers_and_pinned():
    assert entry_of(bytes.fromhex(X["signed"])) == X["entry"]
    raw = mcc3.unb64(X["entry"])
    assert len(raw) == 166 + 2 * 40
    e = mcc3.open_node_entry(X["entry"])
    assert (e["node_key"], e["boot"], e["sequence"], e["report"]) == (NODE, 7, 1, X["signed"][202:210])
    assert e["announce"].hex().upper() == X["signed"] and e["catchers"] == X["catchers"]
    assert mcc3.node_topic(NODE) == f"mcc/node/{NODE}" and mcc3.node_entry_key(f"mcc/node/{NODE}") == NODE
    for t in (f"mcc/node/{NODE.lower()}", f"mcc/node/{NODE}/0", "mcc/node/ABCD", f"mcc/alive/{NODE}"):
        assert mcc3.node_entry_key(t) is None, t
    for bad in (mcc3.b64(raw[:-1]), mcc3.b64(b"A" + raw[1:]), "not base64 !", mcc3.b64(raw[:100])):
        with pytest.raises(mcc3.Refused):
            mcc3.open_node_entry(bad)


def test_the_guest_key_is_derived_from_the_command_key_and_is_not_it():
    seed = mcc3.guest_seed(OWNER_SEED)
    assert envelope.public_key_hex(seed) == X["guest_key"] != OWNER
    assert mcc3.guest_seed(OWNER_SEED) == seed, "the same command key, the same guest key"
    assert envelope.public_key_hex(mcc3.guest_seed(SEEDS["other_owner"])) not in (X["guest_key"], STRANGER)


def test_the_guest_forward_is_kind_g_under_k_gfwd_and_pinned():
    guest_seed = mcc3.guest_seed(OWNER_SEED)
    GUEST = X["guest_key"]
    keys = mcc3.guest_keys(mcc3.shared_secret(guest_seed, CATCHER), CATCHER)
    assert keys["fwd"].hex().upper() == X["k_gfwd"]
    assert mcc3.guest_keys(mcc3.shared_secret(CATCHER_SEED, GUEST), CATCHER) == keys        # the relay's side
    assert keys["fwd"] != mcc3.owner_keys(OWNER_SEED, CATCHER)["fwd"]
    assert keys != mcc3.guest_keys(mcc3.shared_secret(OWNER_SEED, CATCHER), CATCHER), "not under the command key"
    g = mcc3.seal_guest_forward(keys, GUEST, CATCHER, 1795000100, 1795000250, bytes.fromhex(X["rid"]), NODE, 0,
                                GUEST_BODY, nonce=bytes.fromhex(X["nonce"]))
    assert g == X["guest"]
    raw = mcc3.unb64(g)
    assert len(raw) == mcc3.GUEST_FORWARD_SIZE and raw[0] == 0x47 and raw[1:33].hex().upper() == GUEST
    o = mcc3.open_guest_forward(CATCHER_SEED, g)
    assert (o["guest"], o["counter"], o["expiry"], o["rid"].hex().upper(), o["target"], o["route"]) == (
        GUEST, 1795000100, 1795000250, X["rid"], NODE, 0)
    for at in (0, 1, 40, 50, len(raw) - 1):
        with pytest.raises(mcc3.Refused):
            mcc3.open_guest_forward(CATCHER_SEED, mcc3.b64(raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:]))
    with pytest.raises(mcc3.Refused):
        mcc3.open_forward(CATCHER_SEED, OWNER, g)
    res = mcc3.seal_forward_result(o["keys"], o["counter"], 10, 1795000101)
    assert mcc3.open_forward_result(keys, res)["name"] == "guest-cap"
    assert [mcc3.status_name(n) for n in (0, 9, 10, 11, 12, 13)] == [
        "answered", "send-failed", "guest-cap", "guests-full", "target-cap", None]


# The firmware's G1 (planning/firmware/malive-vectors-20261127.json, guest_forwards[0]): a guest
# forward with the vector's own guest key, other_owner, made byte for byte.
G1 = {
    "k_gfwd": "4D1A64FE086B0D48833C87D769EDDE0B79CE1A0F24D013CDB76EC1CC7382317A", "counter": 3, "expiry": 1795000300,
    "rid": "000102030405060708090A0B0C0D0E0F", "route": 1, "nonce": "707172737475767778797A7B",
    "body": "C2" + bytes(range(1, 132)).hex().upper(),
    "payload": "R2wo_QWMGMiMbM4q-YHS0RyFGxI-1babeHZ3PtCZ6j-DcHFyc3R1dnd4eXp7BMVj9UTz1LH0VVY3YAteLTN3I1EJ1way9D5wfyJ7QQVen7"
               "UA85jjByt54cI61yTwxFDbI7L-jB4C7XeAgPSXvz8JU16sC7CFgz7-wixuJyLCxO-4bhKATm7EFYPnstwA_JnMNzRCWW-GubYHaxkyD2R_Y"
               "eDIQGnBZg7cpJBfoRTCygqR_-yGxFY8YVrpKMtdZTJfxQKP9XjYmVxOC41KeeT8sz9I1o_RtBGE_e3kVo2TTs0MAAcuvp1sdpbcnhQB1bqY"
               "41L1Fk51lnoQjso0e2E1QcsA2gvKQ58JiXWFLFWs75eXYOOiJ00uQNROyyoVcX9K3EkxA3B6UIxnT0VWRQ6xmcme_-2K",
    "result": "ZoCBgoOEhYaHiImKiwRBZqM4JV_IkmtD4KKUBpSRyzFDwebUvncwCK2HoEXWdJ9eHrGtOxpw_8X7iNw7mExt-eadzsF2njt9Kddxg6EG"
              "SKaFZ1i7cApwrLi6cLS0QhS7tu1lQYITk5bAETdWBFsplhNe7dgnRCzf9Bq0kffy4VxZ7BgOwZEdnURvqZiBH0AAgKjj86h1HBpS-Ur0-Vbm"
              "u94OUSuKjmJWCAqsx2kT2IOYo3zHju0tRBTpvcNOtyj_hZdV5OVxVsc4CUdXVgbXI9vvwmeTi4TRe3DSyVyVnwAy--_UbIS3GNRywBItOJOE"
              "icFxe5_9G-BR0ryZFVi7Wu2dkWiP2UU1HMUISoHdy0Pc2TmO5LbrXg4aMkC9",
}


def test_the_firmwares_guest_forward_is_made_byte_for_byte_and_its_result_opens():
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
    s = mcc3.shared_secret(SEEDS["other_owner"], CATCHER)
    keys = mcc3.guest_keys(s, CATCHER.lower())
    assert keys["fwd"].hex().upper() == G1["k_gfwd"]
    # the info is "mcc3/gfwd/" and the relay's key as 64 upper-case hex characters, as for mcc3/fwd/
    assert keys["fwd"] == HKDF(s, 32, b"", SHA256, context=b"mcc3/gfwd/" + CATCHER.upper().encode("ascii"))
    assert keys["fwd"] != HKDF(s, 32, b"", SHA256, context=b"mcc3/gfwd/" + CATCHER.lower().encode("ascii"))
    g = mcc3.seal_guest_forward(keys, STRANGER, CATCHER, G1["counter"], G1["expiry"], bytes.fromhex(G1["rid"]), NODE,
                                G1["route"], bytes.fromhex(G1["body"]), nonce=bytes.fromhex(G1["nonce"]))
    assert g == G1["payload"]
    r = mcc3.open_forward_result(keys, G1["result"])
    assert (r["counter"], r["status"], r["name"], r["clock"], r["sent"]) == (3, 10, "guest-cap", 1795000010, 0)


def test_open_node_stops_at_the_tag_and_at_the_signature_without_a_key_agreement():
    cache = {}
    assert plane.open_node(OWNER_SEED, cache, NODE, entry_of(announce_of(to=STRANGER))) is None
    raw = mcc3.unb64(X["entry"])
    bent = raw[:120] + bytes([raw[120] ^ 1]) + raw[121:]
    assert plane.open_node(OWNER_SEED, cache, NODE, mcc3.b64(bent)) is None
    assert cache == {}
    assert plane.open_node(OWNER_SEED, cache, CATCHER, X["entry"]) is None          # under another key's topic
    ok = plane.open_node(OWNER_SEED, cache, NODE, X["entry"])
    assert (ok["node_key"], ok["battery_mv"], ok["name"], len(ok["catchers"])) == (NODE, 3987, A1["fields"]["name"], 2)
    assert NODE in cache


# -- the discovery ---------------------------------------------------------------------------

class FakeServer:
    """Enough of paho for the plane: the retained alive and node-store topics, and a stranger's
    lou-21 relay behind `mcc/cmd/<CATCHER>` that opens a guest forward, hands the body to the
    target and answers under K_gfwd (`guest_status` refuses instead)."""

    retained, published, subscribed, forwards = {}, [], [], []
    guest_status, target_silent = None, False

    def __init__(self, config, seed_hex=None):
        self.on_connect = self.on_message = self.on_subscribe = None

    def username_pw_set(self, user, password):
        pass

    def connect(self, *_a, **_k):
        pass

    def loop_start(self):
        self.on_connect(self, None, None, types.SimpleNamespace(is_failure=False))

    def subscribe(self, topic, qos=0):
        FakeServer.subscribed.append(topic)
        prefix = {mcc3.ALIVE_FILTER: "mcc/alive/", mcc3.NODE_FILTER: "mcc/node/"}.get(topic)
        for t, payload in self.retained.items():
            if prefix and t.startswith(prefix):
                self.on_message(self, None, types.SimpleNamespace(topic=t, payload=payload.encode()))

    def publish(self, topic, payload, qos=0, retain=False):
        FakeServer.published.append((topic, payload))
        if topic == mcc3.command_topic(CATCHER):
            f = mcc3.open_guest_forward(CATCHER_SEED, payload)
            FakeServer.forwards.append(f)
            if self.guest_status is not None:
                res = mcc3.seal_forward_result(f["keys"], f["counter"], self.guest_status, 1795000005)
            elif self.target_silent:
                res = mcc3.seal_forward_result(f["keys"], f["counter"], 1, 1795000005, sent=1)
            else:
                # the body is the owner's request to its node, signed by the command key, not the guest key
                req = mcc3.open_mesh_request(NODE_SEED, OWNER, bytes(4) + f["body"])
                answer = mcc3.seal_mesh_response(mcc3.node_keys(NODE_SEED, OWNER), 0, req["counter"], 0,
                                                 1795000000, "> " + req["command"])[4:]
                res = mcc3.seal_forward_result(f["keys"], f["counter"], 0, 1795000005, sent=1, snr=20, response=answer)
            self.on_message(self, None, types.SimpleNamespace(topic=mcc3.reply_topic(f["rid"]), payload=res.encode()))
        return types.SimpleNamespace(wait_for_publish=lambda timeout=0: None)

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture
def server(monkeypatch):
    for name in ("published", "subscribed", "forwards"):
        setattr(FakeServer, name, [])
    FakeServer.retained, FakeServer.guest_status, FakeServer.target_silent = {}, None, False
    monkeypatch.setattr(transport, "_client", FakeServer)
    monkeypatch.setattr(transport, "_wait", lambda total, done, answered, progress: None)
    monkeypatch.setattr(beacon, "stats", lambda *a, **k: (_ for _ in ()).throw(beacon.BeaconError("none")))
    plane.new_session()
    yield FakeServer
    plane.new_session()


@pytest.fixture
def store(tmp_path):
    s = _store.Store(tmp_path / "home")
    s.import_key(OWNER_SEED)
    s.save_config(broker="broker.invalid", tls=True, port=8883)
    return s


def test_a_node_in_the_store_is_found_named_and_added_with_who_heard_it(store, server):
    server.retained = {mcc3.node_topic(NODE): X["entry"]}
    asked = []
    found = actions.discover_alive(store, add=True, observer_name=lambda k: asked.append(k) or {STRANGER: "DEMO-Grannen"}.get(k))
    assert [(e["key"], e["state"], e["added"]) for e in found] == [(NODE, "heard", True)]
    assert mcc3.NODE_FILTER in server.subscribed and server.published == []         # a read: nothing sent
    assert not any(t.startswith("mcc/heard/") for t in server.subscribed)
    assert sorted(asked) == sorted([CATCHER, STRANGER])
    d = store.device(NODE[:8])
    assert (d["key"], d["mesh_only"], d["name"], d["ver"]) == (NODE, True, A1["opened"]["name"], "lou-21-arrc")
    h = d["heard"]
    assert (h["by"], h["by_name"], h["snr"], h["hops"], h["via"], h["battery_mv"]) == (CATCHER[:8], "", -5.5, 2, 2, 3987)
    assert h["at"] == datetime.datetime.fromtimestamp(1795000050).isoformat(sep=" ")
    assert [(c["node"], c["name"], c["hops"], c["list"]) for c in d["catchers"]] == [
        (CATCHER[:8], "", 2, 0), (STRANGER[:8], "DEMO-Grannen", 0, 1)]
    now = datetime.datetime.fromtimestamp(1795000050 + 9 * 3600)
    assert directory.heard_text(d, now) == f"heard by {CATCHER[:8]} 9 h ago, -5.5 dB, 2 hops"
    assert directory.relays_text(d, store.devices()) == f"DEMO-Grannen (direct, 7.5 dB), {CATCHER[:8]} (2 hops, -5.5 dB)"


def test_another_owners_entries_and_forged_ones_never_reach_the_list(store, server):
    raw = mcc3.unb64(X["entry"])
    server.retained = {mcc3.node_topic(CATCHER): entry_of(announce_of(CATCHER_SEED, to=STRANGER)),
                       mcc3.node_topic(NODE): mcc3.b64(raw[:60] + bytes([raw[60] ^ 1]) + raw[61:]),
                       mcc3.node_topic(STRANGER): X["entry"]}
    assert actions.discover_alive(store, add=True) == [] and store.devices() == []
    assert store.ecdh_cache() == {}


def test_each_entry_is_tried_once_and_yours_get_their_catchers_again(store, server):
    store.add_device("cabin", NODE, "", key=NODE)
    theirs = entry_of(announce_of(CATCHER_SEED, to=STRANGER))
    server.retained = {mcc3.node_topic(NODE): X["entry"], mcc3.node_topic(CATCHER): theirs}
    actions.discover_alive(store)
    tried = store.tried()
    assert tried[NODE] == f"7.1.{X['signed'][202:210]}!" and not tried[CATCHER].endswith("!")
    # the same announce, its seal and signature broken, and a new catcher: not opened again (it would
    # fail), its catchers taken
    signed = bytes.fromhex(X["signed"])
    broken = signed[:60] + bytes([signed[60] ^ 1]) + signed[61:]
    server.retained = {mcc3.node_topic(NODE): mcc3.seal_node_entry(broken, [
        {"key": STRANGER, "arrival": 1795000400, "snr": 12, "hops": 0, "via": 0, "list": 0}]), mcc3.node_topic(CATCHER): theirs}
    calls = []
    real = mcc3.announce_is_for
    mcc3.announce_is_for = lambda *a: calls.append(a) or real(*a)
    try:
        found = actions.discover_alive(store)
    finally:
        mcc3.announce_is_for = real
    assert calls == [], "nothing tried again"
    assert [(e["key"], e["known_as"]) for e in found] == [(NODE, "cabin")]
    d = store.device(NODE[:8])
    assert [(c["key"], c["hops"]) for c in d["catchers"]] == [(STRANGER, 0)]
    assert (d["heard"]["by"], d["heard"]["hops"], d["heard"]["battery_mv"]) == (STRANGER[:8], 0, 3987)
    # a new (boot, sequence) is tried, and the newer kept
    server.retained = {mcc3.node_topic(NODE): entry_of(announce_of(sequence=2, battery_mv=3801))}
    actions.discover_alive(store)
    assert (store.device(NODE[:8])["heard"]["sequence"], store.device(NODE[:8])["heard"]["battery_mv"]) == (2, 3801)
    server.retained = {mcc3.node_topic(NODE): X["entry"]}           # an older one changes nothing
    store.save_tried({})
    actions.discover_alive(store)
    assert store.device(NODE[:8])["heard"]["sequence"] == 2 and store.device(NODE[:8])["name"] == "cabin"


def test_a_node_you_forget_stays_out_until_you_add_it_again(store, server):
    server.retained = {mcc3.node_topic(NODE): X["entry"]}
    assert [e["added"] for e in actions.discover_alive(store, add=True)] == [True]
    store.remove_device(NODE[:8])
    assert store.hidden() == {NODE[:8]}
    found = actions.discover_alive(store, add=True)
    assert [(e["state"], e["added"]) for e in found] == [("heard", False)] and store.devices() == []
    store.add_device("cabin", NODE, "", key=NODE)                   # by hand: discover keeps it current again
    assert store.hidden() == set()


def test_a_refused_store_subscription_is_not_an_error(store, server, monkeypatch):
    """A command server without the store refuses the filter: the alive scan stands."""
    plain = server.subscribe
    mids = {mcc3.ALIVE_FILTER: 1, mcc3.NODE_FILTER: 2}

    def subscribe(self, topic, qos=0):
        plain(self, topic, qos)
        self.on_subscribe(self, None, mids[topic], [0x80 if topic == mcc3.NODE_FILTER else 0])
        return 0, mids[topic]

    monkeypatch.setattr(server, "subscribe", subscribe)
    assert actions.discover_alive(store) == []


# -- the relay choice and a guest forward ----------------------------------------------------

def _row(key, **over):
    return dict({"key": key, "node": key[:8], "name": "", "at": "2026-11-27 10:00:00", "snr": 0, "hops": 1, "via": 2,
                 "list": 0}, **over)


def test_your_own_observer_first_else_fewest_hops_then_best_snr_and_demoted_last():
    k = lambda c: c * 64
    mine = [{"node": k("A")[:8], "key": k("A"), "name": "mine"}]
    target = {"node": NODE[:8], "key": NODE, "catchers": [
        _row(k("B"), hops=3, snr=9), _row(k("C"), hops=1, snr=-2), _row(k("D"), hops=1, snr=4),
        _row(k("E"), hops=2, via=0, snr=-9), _row(k("A"), hops=4, snr=-10)]}
    assert [c["key"][0] for c in actions.rank_catchers(target, mine)] == ["A", "E", "D", "C", "B"]
    target["relay_misses"] = {k("E")[:8]: 2}
    assert [c["key"][0] for c in actions.rank_catchers(target, mine)] == ["A", "D", "C", "B", "E"]
    assert "moved down" in directory.relays_text(target, mine).split(", ")[-1]


def test_a_guest_forward_goes_through_a_strangers_observer_and_its_refusals_are_said(store, server):
    store.add_device("cabin", NODE, "", key=NODE)
    store.update_device(NODE[:8], ver="nrf52-v1.18.0-lou-21-rc-0", mesh_only=True,
                        catchers=[_row(CATCHER, name="DEMO-Grannen", hops=0, via=0, snr=5)])
    d = store.device("cabin")
    relay = actions.relay_for(store, d, "auto")
    assert relay == {"node": CATCHER[:8], "key": CATCHER, "name": "DEMO-Grannen", "guest": True}
    assert actions.relay_for(store, d, "demo-grannen") == relay == actions.relay_for(store, d, CATCHER[:8])
    assert actions.relay_for(store, d, "nobody") is None
    topic, payload, answers, lines = actions.send(store, "get name", device=d, via="relay", relay=relay)
    assert [t for t, _p in server.published] == [mcc3.command_topic(CATCHER)]
    raw = mcc3.unb64(server.published[0][1])
    assert raw[0] == 0x47 and raw[1:33].hex().upper() == X["guest_key"] == store.guest_public_key() != OWNER
    assert OWNER not in server.published[0][1] and bytes.fromhex(OWNER) not in raw, "the command key stays home"
    assert answers[NODE[:8]].reply == "> get name" and answers[NODE[:8]].verified
    assert "someone else's Observer" in lines[0]
    h = store.history(NODE[:8])[-1]
    assert (h["road"], h["relay"]["node"], h["relay"]["status"]) == ("relay", CATCHER[:8], "answered")
    assert store.device("cabin").get("relay_misses") in (None, {})
    first = server.forwards[0]["counter"]
    for status, name in ((10, "guest-cap"), (11, "guests-full"), (12, "target-cap")):
        server.guest_status = status
        _t, _p, answers, lines = actions.send(store, "get name", device=store.device("cabin"), via="relay", relay=relay)
        assert answers == {} and f"the relay says {name}: {mcc3.GUEST_HELP[status]}" in lines[1]
        assert store.history(NODE[:8])[-1]["relay"]["status"] == name
    assert [f["counter"] for f in server.forwards] == sorted(set(f["counter"] for f in server.forwards))
    assert server.forwards[-1]["counter"] > first
    assert store.device("cabin").get("relay_misses") in (None, {}), "a refusal sent nothing: no miss"
    server.guest_status, server.target_silent = None, True
    for _ in range(2):
        actions.send(store, "get name", device=store.device("cabin"), via="relay", relay=relay)
    d = store.device("cabin")
    assert d["relay_misses"] == {CATCHER[:8]: 2}
    assert actions.relay_for(store, d, "auto") is None, "auto never takes a demoted relay"
    _t, _p, _a, lines = actions.send(store, "get name", device=d, via="relay", relay=relay)
    assert "moved down for cabin" in lines[0]


def test_the_api_and_the_command_line_take_a_strangers_observer_and_auto(tmp_path, monkeypatch, capsys, server):
    from mccontrol import cli
    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path / "cli"))
    s = _store.Store(tmp_path / "cli")
    s.import_key(OWNER_SEED)
    s.save_config(broker="broker.invalid", tls=True, port=8883)
    s.add_device("cabin", NODE, "", key=NODE)
    s.update_device(NODE[:8], ver="nrf52-v1.18.0-lou-21-rc-0", mesh_only=True,
                    catchers=[_row(CATCHER, name="DEMO-Grannen", hops=0, via=0, snr=5)])
    assert cli.main(["send", "cabin", "get name", "--via", "relay:auto"]) == 0
    out = capsys.readouterr().out
    assert "through relay DEMO-Grannen" in out and "someone else's Observer" in out
    assert cli.main(["send", "cabin", "get name", "--via", f"relay:{CATCHER[:8]}"]) == 0
    assert len(server.forwards) == 2
    assert cli.main(["devices"]) == 0
    assert "relays DEMO-Grannen (direct, 5 dB)" in capsys.readouterr().out


# -- what a screen shows ---------------------------------------------------------------------

NOW = datetime.datetime(2026, 11, 27, 12, 0, 0)


def _device(**more):
    return dict({"name": "cabin", "node": NODE[:8], "region": "", "last_sent": None}, **more)


def test_the_battery_is_the_newer_reading_and_a_node_is_silent_after_two_days():
    heard = {"battery_mv": 3710, "at": "2026-11-27 03:00:00", "by": CATCHER[:8], "by_name": "DEMO-Grannen",
             "snr": 3.25, "hops": 0}
    fleet = {"battery_mv": 4011, "seen": "2026-11-27T11:30:00"}
    assert directory.battery_text(_device(heard=heard), NOW) == "3.71 V, 9 h ago, heard by DEMO-Grannen"
    assert directory.battery_text(_device(fleet=fleet, heard=heard), NOW) == "4.01 V, 30 min ago, from Beacon"
    assert directory.heard_text(_device(heard=heard), NOW) == "heard by DEMO-Grannen 9 h ago, 3.25 dB, direct"
    old = dict(heard, at="2026-11-25 10:00:00")
    assert directory.announce_silent(_device(heard=old), NOW) and not directory.announce_silent(_device(heard=heard), NOW)
    assert directory.heard_text(_device(heard=old), NOW).startswith("silent: heard by DEMO-Grannen 2 d ago")
    assert directory.ANNOUNCE_SILENT_HOURS == actions.ANNOUNCE_SILENT_HOURS == 48


def test_beacon_names_a_strangers_observer_and_says_nothing_when_it_cannot(monkeypatch):
    pages = {"/nodes": {"items": [{"publicKey": STRANGER.lower(), "name": "DEMO-Grannen"}]}}
    monkeypatch.setattr(beacon, "_get", lambda config, path, params=None: pages[path])
    assert beacon.node_name({}, STRANGER) == "DEMO-Grannen"
    assert beacon.node_name({}, CATCHER) is None
    monkeypatch.setattr(beacon, "_get", lambda *a, **k: (_ for _ in ()).throw(beacon.BeaconError("away")))
    assert beacon.node_name({}, STRANGER) is None
