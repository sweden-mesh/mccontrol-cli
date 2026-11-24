"""The mesh road (OTM-2): the request bytes against the wire-format document's worked vectors,
the response parsed, the allowance and the mesh-only refusals, the auto road's choice, and a
send through a FAKE companion. Nothing here opens a radio or a broker."""
import json
import time

import pytest
from Crypto.Signature import eddsa

from mccontrol import actions, beacon, cli, denylist, envelope, firmware, mesh, store as _store, transport

DOC_SEED = bytes(0x11 + i for i in range(32)).hex()
DOC_NODE_SEED = bytes(0xA0 + i for i in range(32)).hex()
DOC_NODE = "4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4"
DOC_SIG = ("186E3F7F0129BED3A92EB737FEF09CB59DF0B03A0DCEDAFFAFD4FA3D6415F54C"
           "7B27A660E4CAA2C91E936B37B27082EC0B75697CA13ADBD4F961508C6D2C770F")
DOC_PLAINTEXT = ("00F15365" "C1" "07000000" "C086FD6A" + DOC_SIG + "73657420776966692E7373696420486F6D654E6574")
MESH_ONLY_SIG = ("D093D5E2427719074748634E73F8760E42F0D12772D74C9044D399B03202BF7B"
                 "1E375B1EE4A8BE81B190603638C3DB9DC9B4D54E5749492AF07ED609BCF23E09")


# -- bytes -----------------------------------------------------------------------------------

def test_the_request_is_the_wire_format_documents_worked_vector_byte_for_byte():
    assert envelope.public_key_hex(DOC_SEED) == "ED54A59FB1AC3A51239351362941B868E85A60E3D7B2485D828821DC7A69C279"
    assert envelope.public_key_hex(DOC_NODE_SEED) == DOC_NODE
    topic = mesh.topic("TST", DOC_NODE)
    assert topic == f"meshcore/TST/{DOC_NODE}/cmd"
    body = mesh.request(DOC_SEED, topic, 7, 1795000000, "set wifi.ssid HomeNet")
    assert len(body) == 94 and (bytes.fromhex("00F15365") + body).hex().upper() == DOC_PLAINTEXT
    # one signature, both roads: the same text on MQTT
    assert envelope.verify(envelope.public_key_hex(DOC_SEED), topic, f"v1|7|1795000000|set wifi.ssid HomeNet|{DOC_SIG}")
    assert mesh.frame(DOC_NODE, body)[:33] == bytes([57]) + bytes.fromhex(DOC_NODE)


def test_a_mesh_only_node_is_signed_for_the_region_named_mesh_whatever_the_region():
    for region in ("TST", "JKG", ""):
        topic = mesh.topic(region, DOC_NODE, mesh_only=True)
        assert topic == f"meshcore/mesh/{DOC_NODE}/cmd"
        body = mesh.request(DOC_SEED, topic, 7, 1795000000, "get name")
        assert body.hex().upper() == "C107000000C086FD6A" + MESH_ONLY_SIG + "676574206E616D65"


def test_the_road_needs_the_whole_key():
    with pytest.raises(envelope.EnvelopeError, match="whole public key"):
        mesh.topic("JKG", DOC_NODE[:8])


def test_a_command_over_59_bytes_is_refused_before_signing(monkeypatch):
    monkeypatch.setattr(mesh, "signature", lambda *a: pytest.fail("signed"))
    mesh.check_command("x" * 59)
    for command in ("x" * 60, "set wifi.ssid " + "å" * 23, ""):
        with pytest.raises(envelope.EnvelopeError, match="1..59 bytes"):
            mesh.request(DOC_SEED, mesh.topic("JKG", DOC_NODE), 1, 2, command)


def test_the_response_parses_as_the_document_shows_and_a_cut_character_is_dropped():
    data = bytes.fromhex("00F15365" "EF934466" "07000000" "00" "4F4B")[4:]     # the companion strips the tag
    r = mesh.parse_response(data, "4FD099CC", "set wifi.ssid HomeNet", counter=7)
    assert (r.ok, r.code, r.reply, r.counter, r.clock, r.verified) == (True, 0, "OK", 7, None, True)
    assert mesh.parse_response(data, counter=8) is None                       # another counter: not ours
    assert mesh.parse_response(data[:8]) is None                              # too short
    # the mesh hands a datagram over zero-filled to its 16-byte block edge (bench 2026-11-23)
    assert mesh.parse_response(data + bytes(7), counter=7).reply == r.reply
    closed = mesh.parse_response(mesh.response(1795000000, 7, 19), counter=7)
    assert (closed.code, closed.code_name, closed.clock) == (19, "mesh-closed", 1795000000)
    assert "MQTT" in closed.help
    assert mesh.parse_response(mesh.response(1795000000, 7, 0, "> Vä")[:-1]).reply == "> V"


def test_the_vectors_for_the_browser_carry_the_documents_bytes():
    from mccontrol import webexport
    v = webexport.vectors()["mesh"]
    assert v["worked"][0]["plaintext"] == DOC_PLAINTEXT
    assert v["worked"][1]["signature"] == MESH_ONLY_SIG
    c = webexport.data()["protocol.json"]["mesh"]
    assert c["max_command"] == 59 and c["subtype"] == 0xC1


# -- the allowance and the refusals --------------------------------------------------------

@pytest.mark.parametrize("command", ["set wifi.ssid HomeNet", "set wifi.pwd s3cret", "set cmd on",
                                     "set cmd on mqtt-meshcore.louie.se", "reboot", "ver"])
def test_the_mesh_road_admits_the_repair_and_mqtt_still_refuses_it(command):
    assert denylist.mesh_refusal(command) is None
    if command.startswith("set "):
        assert denylist.refusal(command)                   # never over the broker


@pytest.mark.parametrize("command", ["set wifi.ssid", "set wifi.pwdx s3cret", "SET WIFI.SSID HomeNet",
                                     "set cmd off", "set cmd.pubkey AA", "set cmd.mesh on",
                                     "get wifi.pwd", "get wifi.ssid", "set prv.key 00", "erase", "set radio 1"])
def test_everything_else_denied_stays_denied_over_the_mesh(command):
    assert denylist.mesh_refusal(command)


@pytest.mark.parametrize("command", ["ota check", "OTA UPDATE", "cmd ping", "set wifi.ssid HomeNet",
                                     "set cmd on", "set mqtt1.preset meshat.se", "SET MQTT6.PORT 1883"])
def test_a_mesh_only_node_refuses_what_needs_an_uplink(command):
    assert "mesh-only" in denylist.mesh_refusal(command, mesh_only=True)
    assert denylist.mesh_refusal("get name", mesh_only=True) is None
    assert denylist.mesh_refusal("set prv.key 00", mesh_only=True)


@pytest.mark.parametrize("command", ["set mqtt.iata GOT", "set mqtt1", "set mqttx.preset a", "get mqtt1.server"])
def test_only_a_broker_slots_setting_needs_an_uplink(command):
    assert not denylist.needs_uplink(command)


def test_with_an_uplink_the_mesh_road_reaches_the_broker_slots():
    assert denylist.mesh_refusal("set mqtt1.preset meshat.se") is None
    assert denylist.mesh_refusal("set mqtt2.server mqtt.example.org") is None


def test_mesh_only_is_read_from_the_version_or_the_devices_flag():
    assert firmware.mesh_only("nrf52-v1.18.0-lou-19-rc-1a2b3c4d")
    assert firmware.mesh_only("nrf52-v1.18.0-lou-19-arrc-1a2b3c4d")
    assert not firmware.mesh_only("esp32s3-v1.18.0-lou-19-arrc-observer-1a2b3c4d")
    assert not firmware.mesh_only("esp32s3-v1.18.0-lou-19-ar-1a2b3c4d")          # no plane at all
    assert not firmware.mesh_only("esp32s3-v1.17.1-ar-11-observer-90e86c88")
    assert firmware.device_mesh_only({"ver": "esp32s3-v1.18.0-lou-19-arrc-observer-x", "mesh_only": True})
    assert not firmware.device_mesh_only({"ver": "nrf52-v1.18.0-lou-19-rc-x", "mesh_only": False})
    assert firmware.speaks_mesh("esp32s3-v1.18.0-lou-19-arrc-observer-1") is True
    assert firmware.speaks_mesh("esp32s3-v1.17.1-lou-18-arrc-observer-1") is False
    assert firmware.speaks_mesh(None) is None


# -- a send through a fake companion -------------------------------------------------------

class FakeCompanion:
    """Stands in for the operator's radio: checks the request as a node would and answers."""

    def __init__(self, store, answer=(0, "OK"), contacts=None, clock=1795000000, silent=False, sent=None):
        self.store, self.answer, self.clock, self.silent = store, answer, clock, silent
        self.contacts = dict(contacts or {})
        self.sent = sent if sent is not None else []
        self.added = []
        self.opened = self.closed = False

    async def open(self):
        self.opened = True

    async def contact(self, key_hex):
        return self.contacts.get(key_hex)

    async def add_contact(self, key_hex, name):
        self.added.append((key_hex, name))
        self.contacts[key_hex] = {"out_path_len": -1}
        return True

    async def send(self, key_hex, body):
        self.sent.append((key_hex, body))
        return {"tag": "6553f100", "flood": self.contacts[key_hex]["out_path_len"] < 0, "timeout": 0}

    async def response(self, tag_hex, timeout):
        if self.silent:
            return None
        counter = int.from_bytes(self.sent[-1][1][1:5], "little")
        return mesh.response(self.clock, counter, *self.answer)

    async def close(self):
        self.closed = True


@pytest.fixture
def store(tmp_path, monkeypatch):
    s = _store.Store(tmp_path / "home")
    s.import_key(DOC_SEED)
    s.add_device("Bench", DOC_NODE, "TST", key=DOC_NODE)
    s.update_device(DOC_NODE[:8], ver="esp32s3-v1.18.0-lou-19-arrc-observer-1a2b3c4d")
    s.save_config(companion="tcp:companion.invalid:5000")
    monkeypatch.delenv("MCCONTROL_FAKE_RESULTS", raising=False)
    monkeypatch.setattr(transport, "send", lambda *a, **k: pytest.fail("MQTT used"))
    monkeypatch.setattr(beacon, "stats", lambda *a, **k: (_ for _ in ()).throw(beacon.BeaconError("no Beacon here")))
    return s


def _companion(monkeypatch, store, **kw):
    fake = FakeCompanion(store, **kw)
    monkeypatch.setattr(mesh, "open_companion", lambda spec: fake)
    return fake


def _node_checks(body, topic, command):
    """What the node does with the body: rebuild the text, verify the signature."""
    assert body[0] == 0xC1
    counter, expiry = int.from_bytes(body[1:5], "little"), int.from_bytes(body[5:9], "little")
    assert body[73:].decode("utf-8") == command
    signed = envelope.signed_message(topic, f"v1|{counter}|{expiry}|{command}")
    eddsa.new(eddsa.import_public_key(bytes.fromhex(envelope.public_key_hex(DOC_SEED))), "rfc8032").verify(
        signed, body[9:73])
    return counter


def test_a_send_over_the_mesh_makes_the_node_a_contact_floods_and_records_the_road(store, monkeypatch):
    fake = _companion(monkeypatch, store)
    device = store.device("bench")
    topic, payload, answers, lines = actions.send(store, "set wifi.ssid HomeNet", device=device, via="mesh")
    assert topic == f"meshcore/TST/{DOC_NODE}/cmd" and fake.opened and fake.closed
    assert fake.added == [(DOC_NODE, "Bench")]
    key, body = fake.sent[0]
    assert key == DOC_NODE and payload == body.hex().upper()
    _node_checks(body, topic, "set wifi.ssid HomeNet")
    assert answers[DOC_NODE[:8]].ok and "flood" in lines[0] and "made a contact" in lines[0]
    assert lines[1].endswith("OK [signed]")
    line = store.history(DOC_NODE[:8])[-1]
    assert (line["road"], line["code_name"], line["command"]) == ("mesh", "ok", "set wifi.ssid HomeNet")
    d = store.device("bench")
    assert d["last_heard_mesh"] and not d.get("last_heard_mqtt")


def test_a_known_path_goes_direct_and_silence_is_not_a_refusal(store, monkeypatch):
    fake = _companion(monkeypatch, store, contacts={DOC_NODE: {"out_path_len": 2}}, silent=True)
    _t, _p, answers, lines = actions.send(store, "get name", device=store.device("bench"), via="mesh", wait_secs=0.3)
    assert not fake.added and "direct, 2 hop(s)" in lines[0]
    assert answers == {} and "no answer" in lines[1] and "not a refusal" in lines[1]
    assert store.history(DOC_NODE[:8])[-1]["code"] is None


def test_a_mesh_only_node_is_signed_for_mesh_and_never_sent_over_mqtt(store, monkeypatch):
    store.update_device(DOC_NODE[:8], ver="nrf52-v1.18.0-lou-19-rc-1a2b3c4d")
    fake = _companion(monkeypatch, store)
    device = store.device("bench")
    assert actions.road(store, device, "get name", "auto") == ("mesh", "mesh only")
    with pytest.raises(envelope.EnvelopeError, match="mesh only"):
        actions.send(store, "get name", device=device, via="mqtt")
    topic, _p, _a, _l = actions.send(store, "get name", device=device, via="auto")
    assert topic == f"meshcore/mesh/{DOC_NODE}/cmd"
    _node_checks(fake.sent[0][1], topic, "get name")
    for command in ("ota check", "set wifi.ssid HomeNet"):
        with pytest.raises(envelope.EnvelopeError, match="mesh-only"):
            actions.send(store, command, device=device, via="mesh")
    assert len(fake.sent) == 1


def test_refusals_come_before_the_companion_is_opened(store, monkeypatch):
    monkeypatch.setattr(mesh, "open_companion", lambda spec: pytest.fail("companion opened"))
    device = store.device("bench")
    for command, why in (("set name " + "x" * 51, "59 bytes"), ("set prv.key 00", "refuse"),
                         ("set wifi.pwdx a", "refuse")):
        with pytest.raises(envelope.EnvelopeError, match=why):
            actions.send(store, command, device=device, via="mesh")
    with pytest.raises(envelope.EnvelopeError, match="one node at a time"):
        actions.send(store, "ver", region="TST", via="mesh")
    store.update_device(DOC_NODE[:8], ver="esp32s3-v1.17.1-lou-18-arrc-observer-1a2b3c4d")
    with pytest.raises(envelope.EnvelopeError, match="lou-19"):
        actions.send(store, "ver", device=store.device("bench"), via="mesh")
    store.update_device(DOC_NODE[:8], ver=None)
    store.save_config(companion="")
    with pytest.raises(mesh.MeshError, match="no companion set"):
        actions.send(store, "ver", device=store.device("bench"), via="mesh")


def test_a_dry_run_signs_for_the_mesh_and_opens_nothing(store, monkeypatch):
    monkeypatch.setattr(mesh, "open_companion", lambda spec: pytest.fail("companion opened"))
    topic, payload, answers, lines = actions.send(store, "reboot", device=store.device("bench"), via="mesh", dry_run=True)
    assert answers == {} and lines[-1] == "not sent (dry run)" and payload.startswith("C100000000")
    _node_checks(bytes.fromhex(payload), topic, "reboot")


def _ago(mins):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - mins * 60))


def test_auto_takes_mqtt_while_the_node_is_heard_and_the_mesh_once_it_is_silent(store):
    device = store.device("bench")
    assert actions.road(store, device, "ver", "auto") == ("mqtt", "")                 # nothing known: MQTT
    store.update_device(DOC_NODE[:8], last_heard_mqtt=_ago(5))
    assert actions.road(store, store.device("bench"), "ver", "auto") == ("mqtt", "")
    store.update_device(DOC_NODE[:8], last_heard_mqtt=_ago(20))
    road, why = actions.road(store, store.device("bench"), "ver", "auto")
    assert road == "mesh" and "not heard over MQTT for 20 min" in why
    store.save_config(mesh_after_mins=30)
    assert actions.road(store, store.device("bench"), "ver", "auto")[0] == "mqtt"
    # a command only the mesh admits takes it whatever the node's MQTT does
    store.update_device(DOC_NODE[:8], last_heard_mqtt=_ago(1))
    assert actions.road(store, store.device("bench"), "set wifi.pwd x", "auto") == ("mesh", "only the mesh road admits it")
    assert actions.road(store, None, "ver", "auto") == ("mqtt", "")


def test_auto_reads_the_status_on_beacon_first(store, monkeypatch):
    monkeypatch.setattr(beacon, "stats", lambda *a, **k: {"sampled_at": time.time() - 3600})
    store.update_device(DOC_NODE[:8], last_heard_mqtt=_ago(1))
    assert actions.road(store, store.device("bench"), "ver", "auto")[0] == "mesh"      # Beacon's word wins
    monkeypatch.setattr(beacon, "stats", lambda *a, **k: {"sampled_at": time.time() - 60})
    assert actions.road(store, store.device("bench"), "ver", "auto")[0] == "mqtt"


def test_auto_falls_back_to_the_mesh_when_the_broker_cannot_be_reached(store, monkeypatch):
    fake = _companion(monkeypatch, store)

    def unreachable(*a, **k):
        raise transport.BrokerError("cannot reach mqtt-meshcore.louie.se:8883: refused")
    monkeypatch.setattr(transport, "send", unreachable)
    _t, _p, answers, lines = actions.send(store, "ver", device=store.device("bench"), via="auto")
    assert fake.sent and answers[DOC_NODE[:8]].ok and "MQTT unreachable" in lines[0]
    assert store.history(DOC_NODE[:8])[-1]["road"] == "mesh"


def test_auto_sends_over_mqtt_again_when_the_nodes_mesh_road_is_closed(store, monkeypatch):
    store.update_device(DOC_NODE[:8], last_heard_mqtt=_ago(60))
    fake = _companion(monkeypatch, store, answer=(19, ""))
    sent = []

    def mqtt(config, seed, topic, command, nodes_to_hear=(), **k):
        sent.append(topic)
        return "p", {DOC_NODE[:8]: envelope.Result(DOC_NODE[:8], 1, 0, command, "> ok")}
    monkeypatch.setattr(transport, "send", mqtt)
    _t, _p, answers, lines = actions.send(store, "ver", device=store.device("bench"), via="auto")
    assert len(fake.sent) == 1 and sent == [f"meshcore/TST/{DOC_NODE}/cmd"]
    assert "mesh road is closed" in lines[0] and answers[DOC_NODE[:8]].ok
    assert [h["road"] for h in store.history(DOC_NODE[:8])] == ["mesh", "mqtt"]
    # chosen by hand, a closed road is reported, not routed round
    fake.answer = (19, "")
    _t, _p, answers, lines = actions.send(store, "ver", device=store.device("bench"), via="mesh")
    assert "mesh-closed" in lines[1] and len(sent) == 1


# -- the API and the command line ----------------------------------------------------------

def test_the_api_sends_over_the_mesh_and_says_the_road_in_history(api):
    _server, url, store = api
    from test_api import call as api_call
    key = "4AC61A7F" + "0" * 56
    status, _ = api_call(url, "PATCH", "/devices/Gisebo", {"key": "4AC61A7F", "mesh_only": None}, check=False)
    assert status == 400                                    # a key is the whole key
    status, d = api_call(url, "PATCH", "/devices/Gisebo", {"key": key.lower(), "mesh_only": False})
    assert d["key"] == key and d["mesh_only"] is False
    api_call(url, "PATCH", "/config", {"companion": "tcp:companion.invalid:5000", "mesh_after_mins": 15})
    status, err = api_call(url, "POST", "/jobs/send", {"command": "ver", "region": "JKG", "via": "mesh"}, check=False)
    assert status == 400 and "one node at a time" in err["error"]["message"]
    status, err = api_call(url, "POST", "/jobs/send", {"command": "ver", "devices": ["Gisebo"], "via": "air"}, check=False)
    assert status == 400
    status, err = api_call(url, "POST", "/jobs/send", {"command": "set name " + "x" * 51, "devices": ["Gisebo"], "via": "mesh"},
                           check=False)
    assert status == 400 and "59 bytes" in err["error"]["message"]
    status, err = api_call(url, "POST", "/jobs/send", {"command": "set wifi.ssid Home", "devices": ["Gisebo"]},
                           check=False)
    assert status == 400                                    # over MQTT the repair is denied
    _s, job = api_call(url, "POST", "/jobs/send", {"command": "set wifi.ssid Home", "devices": ["Gisebo"],
                                                   "via": "mesh", "confirm": True})
    job = _wait(api_call, url, job["id"])
    assert job["status"] == "done", job
    assert any("over the mesh" in line for line in job["result"]["lines"])
    _s, hist = api_call(url, "GET", "/devices/Gisebo/history")
    assert hist["history"][-1]["road"] == "mesh" and hist["history"][-1]["topic"] == f"meshcore/JKG/{key}/cmd"
    _s, check = api_call(url, "GET", "/commands/check?command=set+wifi.pwd+x&device=Gisebo")
    assert check["refusal"] and check["mesh_refusal"] is None and check["mesh_fits"] and check["mesh_only"] is False


def _wait(api_call, url, job_id):
    for _ in range(100):
        _s, job = api_call(url, "GET", f"/jobs/{job_id}")
        if job["status"] not in ("running", "queued"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_the_command_line_takes_via_and_the_companion(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path / "cli-home"))
    s = _store.Store(tmp_path / "cli-home")
    s.import_key(DOC_SEED)
    s.add_device("Bench", DOC_NODE, "TST", key=DOC_NODE)
    monkeypatch.setattr(beacon, "stats", lambda *a, **k: (_ for _ in ()).throw(beacon.BeaconError("none")))
    fake = FakeCompanion(s)
    monkeypatch.setattr(mesh, "open_companion", lambda spec: fake)
    assert cli.main(["config", "--companion", "tcp:companion.invalid:5000", "--mesh-after-mins", "20"]) == 0
    assert "tcp:companion.invalid:5000" in capsys.readouterr().out
    assert cli.main(["send", "bench", "get", "name", "--via", "mesh"]) == 0
    out = capsys.readouterr().out
    assert "over the mesh through tcp:companion.invalid:5000" in out and fake.sent
    assert cli.main(["send", "TST", "ver", "--all", "--via", "mesh"]) == 1
    assert cli.main(["history", "bench"]) == 0
    assert " mesh get name" in capsys.readouterr().out
    assert json.loads(json.dumps(s.config()))["mesh_after_mins"] == 20
