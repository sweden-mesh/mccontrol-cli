"""The relay road: a node of yours on MQTT transmits the mesh-road request to another node and
returns the answer over MQTT. A FAKE broker plays the relay with the spec's own functions
(`mcc3.open_forward`, `seal_forward_result`) and the target behind it (`open_mesh_request`,
`seal_mesh_response`). Nothing here opens a broker or a radio."""
import struct
import time
import types

import pytest

from mccontrol import actions, beacon, cli, denylist, envelope, firmware, mcc3, mesh, plane, store as _store, transport

OWNER_SEED = bytes(0x11 + i for i in range(32)).hex()
OWNER = envelope.public_key_hex(OWNER_SEED)
RELAY_SEED = bytes(0xA0 + i for i in range(32)).hex()
RELAY = envelope.public_key_hex(RELAY_SEED)
TARGET_SEED = bytes(0xC0 + i for i in range(32)).hex()
TARGET = envelope.public_key_hex(TARGET_SEED)
THIRD_SEED = bytes(0x60 + i for i in range(32)).hex()
THIRD = envelope.public_key_hex(THIRD_SEED)
OBSERVER = "esp32s3-v1.18.0-lou-20-arrc-observer-1a2b3c4d"
MESH_ONLY = "esp32s3-v1.18.0-lou-20-rc-1a2b3c4d"
LOU_19 = "esp32s3-v1.18.0-lou-19-arrc-observer-1a2b3c4d"


class FakeRelay:
    """Enough of paho for the plane, with a lou-20 relay behind `mcc/cmd/<RELAY>`: it opens the
    forward as the firmware does, hands the body to the target, and answers sealed under K_fwd."""

    status, sent, snr, taught = 0, None, 22, None
    answer = (0, "OK")
    silent = False
    published, forwards, subscribed = [], [], []

    def __init__(self, config, seed_hex=None):
        self.on_connect = self.on_message = self.on_subscribe = None

    def username_pw_set(self, user, password):
        pass

    def connect(self, *_a, **_k):
        pass

    def loop_start(self):
        self.on_connect(self, None, None, types.SimpleNamespace(is_failure=False))

    def subscribe(self, topic, qos=0):
        FakeRelay.subscribed.append(topic)

    def _target(self, body):
        """The target's answer after its tag, as the relay would hear it."""
        if body[0] == 0xC2:
            req = mcc3.open_mesh_request(TARGET_SEED, OWNER, bytes(4) + body)
            return mcc3.seal_mesh_response(mcc3.node_keys(TARGET_SEED, OWNER), 0, req["counter"], self.answer[0],
                                           1795000000, self.answer[1])[4:]
        counter = struct.unpack_from("<I", body, 1)[0]
        return mesh.response(1795000000, counter, *self.answer)

    def publish(self, topic, payload, qos=0, retain=False):
        FakeRelay.published.append((topic, payload))
        if topic == mcc3.command_topic(RELAY) and not self.silent:
            f = mcc3.open_forward(RELAY_SEED, OWNER, payload)
            FakeRelay.forwards.append(f)
            keys = mcc3.node_keys(RELAY_SEED, OWNER)
            answered = self.status == mcc3.FORWARD_ANSWERED
            sent = self.sent if self.sent is not None else (0 if self.status > 1 else 1 if f["route"] == 0 else 2)
            path_len, path = self.taught or (None, b"")
            good = mcc3.seal_forward_result(keys, f["counter"], self.status, 1795000005, sent=sent,
                                            snr=self.snr if answered else None, path_len=path_len, path=path,
                                            response=self._target(f["body"]) if answered else b"")
            # first what must not count: another relay's result, and one for another forward
            strays = [mcc3.seal_forward_result(mcc3.node_keys(THIRD_SEED, OWNER), f["counter"], 5, 0),
                      mcc3.seal_forward_result(keys, f["counter"] - 1, 5, 0)]
            for body in strays + [good]:
                self.on_message(self, None, types.SimpleNamespace(topic=mcc3.reply_topic(f["rid"]),
                                                                  payload=body.encode()))
        return types.SimpleNamespace(wait_for_publish=lambda timeout=0: None)

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture
def relay(monkeypatch):
    for name in ("published", "forwards", "subscribed"):
        setattr(FakeRelay, name, [])
    FakeRelay.status, FakeRelay.sent, FakeRelay.snr, FakeRelay.taught = 0, None, 22, None
    FakeRelay.answer, FakeRelay.silent = (0, "OK"), False
    monkeypatch.setattr(transport, "_client", FakeRelay)
    monkeypatch.setattr(transport, "_wait", lambda total, done, answered, progress: None)
    monkeypatch.setattr(beacon, "stats", lambda *a, **k: (_ for _ in ()).throw(beacon.BeaconError("none")))
    plane.new_session()
    yield FakeRelay
    plane.new_session()


def _fill(s):
    s.import_key(OWNER_SEED)
    s.save_config(broker="broker.invalid")
    s.add_device("Bench", RELAY, "", key=RELAY)
    s.update_device(RELAY[:8], ver=OBSERVER)
    s.add_device("Cabin", TARGET, "", key=TARGET)
    s.update_device(TARGET[:8], ver=MESH_ONLY)
    return s


@pytest.fixture
def store(tmp_path):
    return _fill(_store.Store(tmp_path / "home"))


def through(store, command="get name", **kwargs):
    return actions.send(store, command, device=store.device("cabin"), via="relay", relay=store.device("bench"),
                        **kwargs)


# -- the forward ---------------------------------------------------------------------------

def test_a_command_goes_to_the_relays_topic_and_the_targets_answer_opens(store, relay):
    before = int(time.time())
    topic, payload, answers, lines = through(store, "set name Cabin")
    assert [t for t, _p in relay.published] == [f"mcc/cmd/{RELAY}"] and len(payload) == 371
    f = relay.forwards[0]
    assert (f["target"], f["route"], f["path_len"], f["path"]) == (TARGET, 0, 0, b"")
    assert f["rid"] == plane.session()["rid"] and relay.subscribed == [mcc3.reply_topic(f["rid"])]
    assert before < f["expiry"] <= int(time.time()) + plane.FORWARD_TTL_SECS <= before + mcc3.FORWARD_MAX_TTL
    # the body is the 0xC2 mesh request for the target, asking for a zero-hop answer
    assert len(f["body"]) == 132 and f["body"][:2] == bytes([0xC2, mcc3.FLAG_ZERO_HOP])
    req = mcc3.open_mesh_request(TARGET_SEED, OWNER, bytes(4) + f["body"])
    assert (req["command"], req["flags"], req["counter"]) == ("set name Cabin", 2, store.device("cabin")["counter"])
    r = answers[TARGET[:8]]
    assert (r.ok, r.reply, r.verified, r.clock) == (True, "OK", True, 1795000000)
    assert lines == ["through relay Bench (direct, no hops): sent direct, answer heard at 5.5 dB",
                     "Cabin        OK [signed]"]
    assert topic == f"mcc/cmd/{TARGET}"
    h = store.history(TARGET[:8])[-1]
    assert h["road"] == "relay" and h["code"] == 0 and h["topic"] == topic
    assert h["relay"] == {"node": RELAY[:8], "name": "Bench", "route": "direct", "status": "answered",
                          "sent": "direct", "snr": 5.5}
    assert store.history(RELAY[:8]) == []                               # the relay ran nothing


def test_the_forward_counter_is_per_relay_stored_before_sending_and_apart_from_commands(store, relay, monkeypatch):
    store.update_device(RELAY[:8], counter=5, forward_counter=3_000_000_000)
    through(store)
    assert relay.forwards[0]["counter"] == 3_000_000_001 == store.device("bench")["forward_counter"]
    assert store.device("bench")["counter"] == 5                        # the relay's command counter is untouched
    through(store)
    assert relay.forwards[1]["counter"] == 3_000_000_002
    store.update_device(RELAY[:8], forward_counter=7)
    through(store)
    assert relay.forwards[2]["counter"] >= int(time.time()) - 5         # max(unix now, last + 1)
    # stored even when nothing comes of the send
    monkeypatch.setattr(plane, "forward", lambda *a, **k: (_ for _ in ()).throw(transport.BrokerError("down")))
    last = store.device("bench")["forward_counter"]
    with pytest.raises(transport.BrokerError):
        through(store)
    assert store.device("bench")["forward_counter"] > last


def test_a_taught_path_is_kept_per_relay_and_is_the_next_direct_default(store, relay):
    store.remember_relay_path(TARGET[:8], THIRD[:8], 1, b"\x77")          # what another relay learnt
    relay.taught = (2, bytes.fromhex("A1B2"))
    through(store)
    assert relay.forwards[0]["path_len"] == 0                            # another relay's path is not this one's
    assert store.device("cabin")["relay_paths"][RELAY[:8]]["path"] == "A1B2"
    assert store.device("cabin")["relay_paths"][RELAY[:8]]["len"] == 2
    relay.taught = None
    _t, _p, _a, lines = through(store)
    f = relay.forwards[1]
    assert (f["route"], f["path_len"], f["path"]) == (0, 2, bytes.fromhex("A1B2"))
    assert f["body"][1] == 0                                            # hops between: no zero-hop answer
    assert lines[0].startswith("through relay Bench (direct, 2 hop(s))")
    # a path as typed wins; none is no hops again, and the flag is back
    through(store, path="2:0102A1B2")
    assert (relay.forwards[2]["path_len"], relay.forwards[2]["path"]) == (0x42, bytes.fromhex("0102A1B2"))
    through(store, path="none")
    assert relay.forwards[3]["path_len"] == 0 and relay.forwards[3]["body"][1] == mcc3.FLAG_ZERO_HOP
    assert store.device("cabin")["relay_paths"][THIRD[:8]]["path"] == "77"


@pytest.mark.parametrize("route, number, text", [("flood", 1, "flood in the relay's region"),
                                                 ("flood-wide", 2, "flood in the relay's default scope")])
def test_a_flood_is_asked_for_by_name_and_never_carries_the_zero_hop_flag(store, relay, route, number, text):
    store.remember_relay_path(TARGET[:8], RELAY[:8], 2, bytes.fromhex("A1B2"))
    _t, _p, answers, lines = through(store, route=route)
    f = relay.forwards[0]
    assert (f["route"], f["path_len"], f["path"], f["body"][1]) == (number, 0, b"", 0)
    assert lines[0] == f"through relay Bench ({text}): sent flood, answer heard at 5.5 dB" and answers
    assert store.history(TARGET[:8])[-1]["relay"]["route"] == route
    with pytest.raises(envelope.EnvelopeError, match="direct route only"):
        through(store, route=route, path="A1")
    with pytest.raises(envelope.EnvelopeError, match="route is one of"):
        through(store, route="wide")


def test_a_lou_19_target_gets_its_0xC1_request_and_its_plain_answer_is_read(store, relay):
    store.update_device(TARGET[:8], ver=LOU_19, region="JKG")
    relay.answer = (0, "> Cabin")
    _t, _p, answers, lines = through(store)
    body = relay.forwards[0]["body"]
    assert body[0] == 0xC1 and len(body) == 73 + len("get name")
    assert body == mesh.request(OWNER_SEED, f"meshcore/JKG/{TARGET}/cmd", *struct.unpack_from("<II", body, 1), "get name")
    assert answers[TARGET[:8]].reply == "> Cabin" and lines[1] == "Cabin        > Cabin [signed]"
    with pytest.raises(envelope.EnvelopeError, match="1..59 bytes"):
        through(store, "set name " + "x" * 51)


# -- what comes back -----------------------------------------------------------------------

def test_no_answer_reads_as_no_answer_never_as_refused(store, relay):
    relay.status = mcc3.FORWARD_NO_ANSWER
    _t, _p, answers, lines = through(store)
    assert answers == {} and "refused" not in " ".join(lines)
    assert lines == ["through relay Bench (direct, no hops): sent direct",
                     "Cabin        no answer (not a refusal: the node may have run the command)"]
    h = store.history(TARGET[:8])[-1]
    assert (h["code"], h["note"], h["relay"]["status"], h["relay"]["snr"]) == (None, "no-answer", "no-answer", None)
    assert store.device("cabin").get("last_heard") is None


@pytest.mark.parametrize("status", range(2, 10))
def test_a_relays_own_status_is_shown_by_name(store, relay, status):
    relay.status = status
    name = mcc3.FORWARD_STATUSES[status]
    _t, _p, answers, lines = through(store)
    assert answers == {} and lines[0] == "through relay Bench (direct, no hops)"
    assert lines[1].startswith(f"Cabin        not sent, the relay says {name}: ")
    assert mcc3.FORWARD_HELP[status] in lines[1] and "refused: " not in lines[1]
    assert store.history(TARGET[:8])[-1]["relay"]["status"] == name


def test_a_refusal_by_the_target_is_the_targets_and_a_silent_relay_is_said(store, relay):
    relay.answer = (19, "")
    _t, _p, answers, lines = through(store)
    assert answers[TARGET[:8]].code == 19 and "refused: mesh-closed" in lines[1]
    relay.silent = True
    _t, _p, answers, lines = through(store)
    assert answers == {} and lines[1].startswith("Cabin        no answer from the relay Bench")
    assert store.history(TARGET[:8])[-1]["relay"]["status"] is None


def test_an_answer_that_does_not_open_with_the_targets_key_teaches_nothing(store, relay, monkeypatch):
    monkeypatch.setattr(FakeRelay, "_target", lambda self, body: mcc3.seal_mesh_response(
        mcc3.node_keys(THIRD_SEED, OWNER), 0, 1, 0, 0, "OK")[4:])
    _t, _p, answers, lines = through(store)
    assert answers == {} and "does not open" in lines[1]
    assert store.reads(TARGET[:8]) == []


def test_a_result_opens_only_under_the_relays_key_and_for_this_forward():
    """The fake publishes another relay's result and one for another counter first; alone,
    neither is taken."""
    keys = mcc3.owner_keys(OWNER_SEED, RELAY)
    good = mcc3.seal_forward_result(mcc3.node_keys(RELAY_SEED, OWNER), 9, 1, 0)
    assert mcc3.open_forward_result(keys, good)["name"] == "no-answer"
    with pytest.raises(mcc3.Refused):
        mcc3.open_forward_result(mcc3.owner_keys(OWNER_SEED, THIRD), good)
    with pytest.raises(mcc3.Refused):
        mcc3.open_forward_result(mcc3.owner_keys(THIRD_SEED, RELAY), good)


# -- refused before anything is signed -----------------------------------------------------

@pytest.fixture
def nothing_signed(monkeypatch, relay):
    for name in ("seal_forward", "seal_mesh_request", "_sign"):
        monkeypatch.setattr(mcc3, name, lambda *a, **k: pytest.fail("signed or sealed"))
    monkeypatch.setattr(mesh, "signature", lambda *a, **k: pytest.fail("signed"))
    yield
    assert relay.published == []


def test_a_relay_must_be_on_mqtt_and_known_to_run_lou_20(store, nothing_signed):
    for ver, why in ((MESH_ONLY, "mesh only"), (LOU_19, "lou-20 or later"), (None, "lou-20 or later"),
                     ("v1.18.0", "lou-20 or later")):
        store.update_device(RELAY[:8], ver=ver)
        with pytest.raises(envelope.EnvelopeError, match=why):
            through(store)
    store.update_device(RELAY[:8], alive={"state": "not-yours"})
    with pytest.raises(envelope.EnvelopeError, match="lou-20 or later"):
        through(store)
    store.update_device(RELAY[:8], ver=OBSERVER, mesh_only=True, alive=None)
    with pytest.raises(envelope.EnvelopeError, match="mesh only"):
        through(store)
    assert store.device("bench").get("forward_counter") is None and store.device("cabin").get("counter") is None


def test_a_relay_known_by_its_alive_alone_will_do(store, relay):
    store.update_device(RELAY[:8], ver=None, alive={"state": "online", "relay": True})
    assert actions.relay_refusal(store.device("bench")) is None
    assert through(store)[2]


def test_the_mesh_roads_rules_apply_before_signing(store, nothing_signed):
    for command, why in (("set prv.key 00", "denied"), ("set mqtt.cmd off", "denied"), ("erase", "denied"),
                         ("ota check", "mesh-only"), ("set name " + "x" * 49, "1..57 bytes"), ("", "empty")):
        with pytest.raises(envelope.EnvelopeError, match=why):
            through(store, command)
    with pytest.raises(envelope.EnvelopeError, match="cannot relay to itself"):
        actions.send(store, "ver", device=store.device("bench"), via="relay", relay=store.device("bench"))
    with pytest.raises(envelope.EnvelopeError, match="name the relay"):
        actions.send(store, "ver", device=store.device("cabin"), via="relay")
    with pytest.raises(envelope.EnvelopeError, match="whole hashes|is hex"):
        through(store, path="A1B")
    with pytest.raises(envelope.EnvelopeError, match="at most 57 bytes"):
        through(store, path="AB" * 58)
    # no counter was spent on any of them
    assert store.device("bench").get("forward_counter") is None and store.device("cabin").get("counter") is None


def test_the_repair_allowance_travels_as_on_the_mesh_road(store, relay):
    store.update_device(TARGET[:8], ver=OBSERVER)
    assert through(store, "set wifi.ssid HomeNet")[2][TARGET[:8]].ok
    req = mcc3.open_mesh_request(TARGET_SEED, OWNER, bytes(4) + relay.forwards[0]["body"])
    assert req["command"] == "set wifi.ssid HomeNet"


def test_no_area_and_no_automatic_choice_goes_through_a_relay(store, nothing_signed, monkeypatch):
    for area in ({"region": "JKG"}, {"county": "se-jkp"}):
        with pytest.raises(envelope.EnvelopeError, match="one node at a time"):
            actions.send(store, "ver", via="relay", relay=store.device("bench"), **area)
    with pytest.raises(envelope.EnvelopeError, match="one node at a time"):
        actions.act(store, "ver", store.devices(), "se-jkp", via="relay")
    # auto picks MQTT or the mesh through your companion, whatever the node; never a relay
    assert "relay" not in actions.ROADS
    for d in store.devices():
        assert actions.road(store, d, "ver", "auto")[0] in ("mqtt", "mesh")
    with pytest.raises(envelope.EnvelopeError, match="road is one of"):
        actions.road(store, store.device("cabin"), "ver", "relay")
    monkeypatch.setattr(actions, "send_relay", lambda *a, **k: pytest.fail("auto chose a relay"))
    monkeypatch.setattr(actions, "send_mesh", lambda *a, **k: ("t", "p", {}, ["mesh"]))
    assert actions.send(store, "ver", device=store.device("cabin"), via="auto")[3] == ["mesh"]


def test_a_dry_run_seals_and_sends_nothing(store, relay):
    topic, payload, answers, lines = through(store, dry_run=True)
    assert answers == {} and lines[-1] == "not sent (dry run)" and relay.published == []
    assert lines[0] == "would send through relay Bench (direct, no hops)" and RELAY in lines[1]
    assert mcc3.open_forward(RELAY_SEED, OWNER, payload)["target"] == TARGET
    assert store.device("bench").get("forward_counter") is None and store.history(TARGET[:8]) == []


def test_the_plane_takes_forwards_on_tls_only(store, relay):
    store.save_config(tls=False)
    with pytest.raises(transport.BrokerError, match="TLS"):
        through(store)
    assert relay.published == []


def test_a_path_as_typed():
    assert actions.relay_path("") == actions.relay_path("none") == actions.relay_path(None) == (0, b"")
    assert actions.relay_path("a1b2") == (2, b"\xA1\xB2")
    assert actions.relay_path("2:A1B2C3D4") == (0x42, bytes.fromhex("A1B2C3D4"))
    assert actions.relay_path("3:A1B2C3") == (0x81, bytes.fromhex("A1B2C3"))
    assert actions.relay_path("AB" * 57)[0] == 57
    for bad in ("xyz", "2:A1B2C3", "4:A1B2C3D4", "0:A1", "AB" * 58, "2:" + "AB" * 58, "1:"):
        with pytest.raises(envelope.EnvelopeError):
            actions.relay_path(bad)


# -- the switch and the alive flag ---------------------------------------------------------

def test_the_relay_switch_is_an_ordinary_command_from_lou_20():
    for command in ("set mqtt.relay off", "set mqtt.relay own", "get mqtt.relay"):
        assert denylist.refusal(command) is None and denylist.mesh_refusal(command) is None
        assert firmware.needs(command) == "lou-20"
        assert firmware.admits(OBSERVER, command) and not firmware.admits(LOU_19, command)
    for command in ("set mqtt.cmd.relay own", "set mqtt.cmd relay", "set mqtt.cmd"):
        assert denylist.refusal(command)                                # the plane's own settings stay denied
    assert firmware.relays(OBSERVER) and not firmware.relays(MESH_ONLY) and not firmware.relays(LOU_19)
    assert not firmware.relays(None)


def test_the_alive_flag_says_which_nodes_relay(store, relay, monkeypatch):
    def alive(seed, flags):
        return mcc3.seal_alive(mcc3.node_keys(seed, OWNER), {
            "boot": 3, "sequence": 1, "uptime": 60, "clock": 1795000000, "last_counter": 7, "interval": 900,
            "flags": flags, "mesh": 2, "fingerprint": OWNER[:8], "via": 0, "version": "lou-20", "region": "",
            "name": "n"})
    keys = mcc3.owner_keys(OWNER_SEED, RELAY)
    assert mcc3.open_alive(keys, alive(RELAY_SEED, 0x1B))["relay"] is True
    assert mcc3.open_alive(keys, alive(RELAY_SEED, 0x0B))["relay"] is False
    monkeypatch.setattr(plane, "scan", lambda *a, **k: {
        RELAY: ("ours", mcc3.open_alive(keys, alive(RELAY_SEED, 0x1B)), 1795000000),
        TARGET: ("ours", mcc3.open_alive(mcc3.owner_keys(OWNER_SEED, TARGET), alive(TARGET_SEED, 0x09)), 1795000000)})
    actions.discover_alive(store)
    assert store.device("bench")["alive"]["relay"] is True and store.device("cabin")["alive"]["relay"] is False


# -- the command line and the API ----------------------------------------------------------

@pytest.fixture
def home(tmp_path, monkeypatch, relay):
    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path / "cli"))
    return _fill(_store.Store(tmp_path / "cli"))


def test_the_command_line_takes_a_relay_a_route_and_a_path(home, relay, capsys):
    assert cli.main(["send", "cabin", "get", "name", "--via", "relay:bench"]) == 0
    assert "through relay Bench (direct, no hops): sent direct" in capsys.readouterr().out
    assert cli.main(["send", "cabin", "ver", "--via", "relay:bench", "--route", "flood"]) == 0
    assert "flood in the relay's region" in capsys.readouterr().out
    assert cli.main(["send", "cabin", "ver", "--via", f"relay:{RELAY[:8]}", "--path", "A1B2"]) == 0
    assert [(f["route"], f["path"]) for f in relay.forwards] == [(0, b""), (1, b""), (0, b"\xA1\xB2")]
    relay.status = mcc3.FORWARD_NO_ANSWER
    assert cli.main(["send", "cabin", "ver", "--via", "relay:bench", "--path", "none"]) == 0
    relay.status = 7
    assert cli.main(["send", "cabin", "ver", "--via", "relay:bench", "--path", "none"]) == 0
    capsys.readouterr()
    assert cli.main(["history", "cabin"]) == 0
    rows = capsys.readouterr().out.splitlines()
    assert "relay get name" in rows[0] and rows[0].endswith("OK  [Bench, direct, sent direct, 5.5 dB]")
    assert rows[1].endswith("[Bench, flood, sent flood, 5.5 dB]") and rows[2].endswith("[Bench, direct, sent direct, 5.5 dB]")
    assert rows[3].endswith("no answer  [Bench, direct, sent direct]")
    assert rows[4].endswith("not sent: relay rate-limited  [Bench, direct]") and "refused" not in rows[4]


def test_the_command_line_refuses_what_a_relay_does_not_carry(home, relay, capsys):
    assert cli.main(["send", "cabin", "ver", "--via", "relay:nobody"]) == 1
    assert "no device matches 'nobody'" in capsys.readouterr().err
    for argv, why in ((["send", "JKG", "ver", "--all", "--via", "relay:bench"], "one node at a time"),
                      (["send", "se-jkp", "ver", "--county", "--via", "relay:bench"], "one node at a time"),
                      (["send", "cabin", "ver", "--route", "flood"], "go with --via relay"),
                      (["send", "cabin", "ver", "--via", "mesh", "--path", "A1"], "go with --via relay"),
                      (["send", "cabin", "ver", "--via", "relay:bench", "--route", "flood", "--path", "A1"],
                       "direct route only"),
                      (["send", "cabin", "set", "prv.key", "00", "--via", "relay:bench", "--yes"], "denied"),
                      (["send", "bench", "ver", "--via", "relay:bench"], "cannot relay to itself")):
        assert cli.main(argv) == 1, argv
        assert why in capsys.readouterr().err, argv
    for argv in (["send", "cabin", "ver", "--via", "relay:"], ["send", "cabin", "ver", "--via", "relay"],
                 ["group", "send", "g", "ver", "--via", "relay:bench"],
                 ["send", "cabin", "ver", "--via", "relay:bench", "--route", "wide"]):
        with pytest.raises(SystemExit):
            cli.main(argv)
    capsys.readouterr()
    assert relay.published == []


def test_the_api_takes_one_device_through_a_relay_and_refuses_the_rest(tmp_path, relay):
    from mccontrol.api import serve, stop
    from test_api import call, run
    s = _fill(_store.Store(tmp_path / "api"))
    s.create_group("g", [TARGET[:8]])
    s.update_device(TARGET[:8], alive={"state": "online", "region": "se-jkp"})
    server, url = serve(s)
    try:
        send = {"command": "get name", "devices": ["cabin"], "via": "relay", "relay": "bench"}
        job = run(url, "send", dict(send, route="flood"))
        assert job["outcomes"][0]["ok"] and relay.forwards[0]["route"] == 1
        assert call(url, "GET", f"/devices/{TARGET[:8]}/history")[1]["history"][-1]["relay"]["name"] == "Bench"
        relay.taught = (1, b"\xA1")
        run(url, "send", send)
        assert call(url, "GET", "/devices/cabin")[1]["relay_paths"][RELAY[:8]]["path"] == "A1"
        assert call(url, "GET", "/devices/bench")[1]["forward_counter"] == relay.forwards[1]["counter"]
        for body, status, why in (
                ({"command": "ver", "county": "se-jkp", "via": "relay", "relay": "bench"}, 400, "one node at a time"),
                ({"command": "ver", "group": "g", "via": "relay", "relay": "bench"}, 400, "one node at a time"),
                ({"command": "ver", "devices": ["cabin", "bench"], "via": "relay", "relay": "bench"}, 400,
                 "one node at a time"),
                (dict(send, relay="nobody"), 404, "no device"),
                ({k: v for k, v in send.items() if k != "relay"}, 400, "needs relay"),
                (dict(send, route="wide"), 400, "route is one of"),
                (dict(send, path="xyz"), 400, "a path is hex"),
                (dict(send, devices=["bench"]), 400, "cannot relay to itself"),
                (dict(send, command="set prv.key 00"), 400, "denied"),
                ({"command": "ver", "devices": ["cabin"], "via": "mesh", "relay": "bench"}, 400, "goes with via: relay"),
                ({"command": "ver", "devices": ["cabin"], "route": "flood"}, 400, "goes with via: relay")):
            status_, err = call(url, "POST", "/jobs/send", body, check=False)
            assert status_ == status and why in err["error"]["message"], body
        s.update_device(RELAY[:8], ver=LOU_19)
        status_, err = call(url, "POST", "/jobs/send", send, check=False)
        assert status_ == 400 and err["error"]["code"] == "refused" and "lou-20 or later" in err["error"]["message"]
        s.update_device(RELAY[:8], ver=OBSERVER)
        s.update_device(TARGET[:8], ver=OBSERVER, alive=None)             # not mesh only: still the mesh road's limit
        status_, err = call(url, "POST", "/jobs/send", dict(send, command="set name " + "x" * 51), check=False)
        assert status_ == 400 and "1..59 bytes" in err["error"]["message"]
        assert len(relay.forwards) == 2
    finally:
        stop(server)
