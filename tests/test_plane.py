"""mcc3 in the CLI (IATA-2 MC2, MC4, MC5): per-node sealed commands on `mcc/cmd/<KEY>`, results
on the session's reply topic, discovery from alive messages with the shared secret cached
beside the key, and the scheme chosen per node. A FAKE broker plays a lou-20 node with the
spec's own functions (`mcc3.open_command`, `seal_result`, `seal_alive`); a FAKE companion
plays the mesh road. Nothing here opens a broker or a radio."""
import json
import os
import stat
import struct
import types

import pytest

from mccontrol import actions, beacon, cli, envelope, mcc3, mesh, plane, store as _store, transport

OWNER_SEED = bytes(0x11 + i for i in range(32)).hex()
NODE_SEED = bytes(0xA0 + i for i in range(32)).hex()
NODE = envelope.public_key_hex(NODE_SEED)            # 4FD099CC...
OTHER_SEED = bytes(0x40 + i for i in range(32)).hex()   # another owner's command key
STRANGER_SEED = bytes(0x60 + i for i in range(32)).hex()
STRANGER = envelope.public_key_hex(STRANGER_SEED)


def alive(node_seed=NODE_SEED, owner_seed=OWNER_SEED, **over):
    fields = {"boot": 3, "sequence": 1, "uptime": 3600, "clock": 1795000000, "last_counter": 7, "interval": 900,
              "flags": 0x0B, "mesh": 2, "fingerprint": envelope.public_key_hex(owner_seed)[:8], "via": 0,
              "version": "lou-20", "region": "se-jkp", "name": "SE-JKG-LOUTEST"}
    fields.update(over)
    return mcc3.seal_alive(mcc3.node_keys(node_seed, envelope.public_key_hex(owner_seed)), fields)


class FakeBroker:
    """Enough of paho for the plane: a login, the retained alive topics, and a lou-20 node
    behind `mcc/cmd/<NODE>` that opens the command as the firmware does and answers sealed."""

    retained = {}
    answer = (0, "> SE-JKG-LOUTEST")
    logins, published, subscribed, tls = [], [], [], []
    silent = False

    def __init__(self, config, seed_hex=None):
        FakeBroker.tls.append(bool(config.get("tls")))
        self.on_connect = self.on_message = self.on_subscribe = None

    def username_pw_set(self, user, password):
        FakeBroker.logins.append((user, password))

    def connect(self, *_a, **_k):
        pass

    def loop_start(self):
        self.on_connect(self, None, None, types.SimpleNamespace(is_failure=False))

    def subscribe(self, topic, qos=0):
        FakeBroker.subscribed.append(topic)
        if topic == mcc3.ALIVE_FILTER:
            for t, payload in self.retained.items():
                self.on_message(self, None, types.SimpleNamespace(topic=t, payload=payload.encode()))

    def publish(self, topic, payload, qos=0, retain=False):
        FakeBroker.published.append((topic, payload))
        key = mcc3.node_from_topic(topic)
        if key == NODE and topic.startswith("mcc/cmd/") and not self.silent:
            cmd = mcc3.open_command(NODE_SEED, envelope.public_key_hex(OWNER_SEED), payload)
            keys = mcc3.node_keys(NODE_SEED, envelope.public_key_hex(OWNER_SEED))
            # another node's answer on the same RID first: it must not open, nor count
            stray = mcc3.seal_result(mcc3.node_keys(STRANGER_SEED, envelope.public_key_hex(OWNER_SEED)),
                                     cmd["counter"], 0, 0, cmd["command"], "not me")
            res = mcc3.seal_result(keys, cmd["counter"], self.answer[0], 1795000005, cmd["command"], self.answer[1])
            for body in (stray, res):
                self.on_message(self, None, types.SimpleNamespace(topic=mcc3.reply_topic(cmd["rid"]),
                                                                  payload=body.encode()))
        return types.SimpleNamespace(wait_for_publish=lambda timeout=0: None)

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture
def broker(monkeypatch):
    for name in ("logins", "published", "subscribed", "tls"):
        setattr(FakeBroker, name, [])
    FakeBroker.retained, FakeBroker.silent, FakeBroker.answer = {}, False, (0, "> SE-JKG-LOUTEST")
    monkeypatch.setattr(transport, "_client", FakeBroker)
    monkeypatch.setattr(transport, "_wait", lambda total, done, answered, progress: None)
    monkeypatch.setattr(beacon, "stats", lambda *a, **k: (_ for _ in ()).throw(beacon.BeaconError("none")))
    plane.new_session()
    yield FakeBroker
    plane.new_session()


@pytest.fixture
def store(tmp_path):
    s = _store.Store(tmp_path / "home")
    s.import_key(OWNER_SEED)
    s.save_config(broker="broker.invalid")
    return s


# -- discovery from alive (MC4) ------------------------------------------------------------

def test_discovery_opens_only_our_alive_and_shows_the_node_wherever_it_is(store, broker):
    broker.retained = {mcc3.alive_topic(NODE): alive(),
                       mcc3.alive_topic(STRANGER): alive(STRANGER_SEED, OTHER_SEED, name="theirs")}
    found = actions.discover_alive(store, add=True)
    assert [(e["key"], e["name"], e["version"], e["state"], e["added"]) for e in found] == [
        (NODE, "SE-JKG-LOUTEST", "lou-20", "online", True)]
    d = store.device(NODE[:8])
    assert d["region"] == "" and d["key"] == NODE and d["name"] == "SE-JKG-LOUTEST"
    assert d["alive"]["region"] == "se-jkp" and d["alive"]["old_scheme"] is True       # a fact of the node
    assert actions.scheme(d) == "mcc3"
    # read only: subscribed to the alive filter, published nothing; a throwaway login, never the command key
    assert broker.subscribed == [mcc3.ALIVE_FILTER] and broker.published == []
    user, password = broker.logins[-1]
    assert user.startswith("v1_") and user[3:] != store.public_key()
    assert json.loads(envelope._unb64(password.split(".")[1]))["client"] == "mccontrol"


def test_the_shared_secret_is_cached_per_command_key_private_and_reused(store, broker, monkeypatch):
    broker.retained = {mcc3.alive_topic(NODE): alive(),
                       mcc3.alive_topic(STRANGER): alive(STRANGER_SEED, OTHER_SEED)}
    actions.discover_alive(store)
    path = store.root / "ecdh" / f"{store.public_key()[:16]}.json"
    cache = json.loads(path.read_text())
    assert set(cache) == {NODE, STRANGER}                  # every key seen, ours or not
    assert cache[NODE] == mcc3.shared_secret(OWNER_SEED, NODE).hex()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    monkeypatch.setattr(mcc3, "shared_secret", lambda *a: pytest.fail("X25519 again"))
    assert [e["key"] for e in actions.discover_alive(store)] == [NODE]


def test_offline_not_yours_and_a_stale_replay(store, broker):
    store.add_device("Bench", NODE, "", key=NODE)
    broker.retained = {mcc3.alive_topic(NODE): alive(boot=4, sequence=2)}
    actions.discover_alive(store)
    assert store.device("bench")["alive"]["boot"] == 4
    broker.retained = {mcc3.alive_topic(NODE): alive(boot=4, sequence=1)}        # lower: a replay
    actions.discover_alive(store)
    assert store.device("bench")["alive"]["sequence"] == 2
    broker.retained = {mcc3.alive_topic(NODE): ""}                               # its will
    assert [e["state"] for e in actions.discover_alive(store)] == ["offline"]
    assert store.device("bench")["alive"]["state"] == "offline"
    broker.retained = {mcc3.alive_topic(NODE): alive(owner_seed=OTHER_SEED)}     # rekeyed away
    assert [e["state"] for e in actions.discover_alive(store)] == ["not-yours"]
    assert actions.scheme(store.device("bench")) == "old"


def test_a_device_kept_by_its_id_alone_learns_its_key_from_its_alive(store, broker):
    store.add_device("Old", NODE[:8], "JKG")
    broker.retained = {mcc3.alive_topic(NODE): alive()}
    found = actions.discover_alive(store, add=True)
    assert found[0]["known_as"] == "Old" and not found[0]["added"]
    assert store.device("old")["key"] == NODE and actions.scheme(store.device("old")) == "mcc3"


def test_a_refused_alive_subscription_is_said(store, broker, monkeypatch):
    class _Refuse(FakeBroker):
        def subscribe(self, topic, qos=0):
            self.on_subscribe(self, None, 1, [0x87], None)
    monkeypatch.setattr(transport, "_client", _Refuse)
    with pytest.raises(transport.BrokerError, match="refused the subscription to mcc/alive/\\+"):
        actions.discover_alive(store)


# -- sending over mcc3 (MC2) ---------------------------------------------------------------

def test_a_command_goes_sealed_to_the_nodes_own_topic_and_its_result_opens(store, broker):
    store.add_device("Bench", NODE, "", key=NODE)
    store.update_device(NODE[:8], alive={"state": "online", "last_counter": 2_000_000_000})
    topic, payload, answers, lines = actions.send(store, "get name", device=store.device("bench"))
    assert topic == f"mcc/cmd/{NODE}" and [t for t, _p in broker.published] == [topic]
    assert len(payload) in (243, 371)
    r = answers[NODE[:8]]
    assert (r.ok, r.reply, r.verified, r.counter) == (True, "> SE-JKG-LOUTEST", True, 2_000_000_001)
    assert lines == ["Bench        > SE-JKG-LOUTEST [signed]"]
    assert store.device("bench")["counter"] == 2_000_000_001             # stored before sending
    assert store.history(NODE[:8])[-1]["topic"] == topic and store.reads(NODE[:8])[0][0] == "get name"
    # the reply topic is the session's, subscribed exactly; the login is the throwaway one
    rid_topic = [t for t in broker.subscribed if t.startswith("mcc/r/")]
    assert rid_topic == [mcc3.reply_topic(plane.session()["rid"])]
    assert broker.logins[-1][0][3:] != store.public_key() and broker.tls == [True]
    # a second command: the same session, a higher counter
    actions.send(store, "ver", device=store.device("bench"))
    assert store.device("bench")["counter"] == 2_000_000_002
    assert len({u for u, _p in broker.logins}) == 1


def test_a_refusal_comes_back_sealed_and_silence_is_silence(store, broker):
    store.add_device("Bench", NODE, "", key=NODE)
    store.update_device(NODE[:8], ver="esp32s3-v1.18.0-lou-20-arrc-observer-1a2b3c4d")
    broker.answer = (14, "")
    _t, _p, answers, lines = actions.send(store, "get name", device=store.device("bench"))
    assert answers[NODE[:8]].code == 14 and "refused: not-allowed" in lines[0]
    broker.silent = True
    _t, _p, answers, lines = actions.send(store, "get name", device=store.device("bench"))
    assert answers == {} and lines[0].endswith("no answer")


def test_mcc3_needs_tls_and_never_a_password_login(store, broker):
    store.add_device("Bench", NODE, "", key=NODE)
    store.update_device(NODE[:8], alive={"state": "online"})
    store.save_config(tls=False)
    with pytest.raises(transport.BrokerError, match="TLS"):
        actions.send(store, "get name", device=store.device("bench"))
    store.save_config(tls=True, username="mcoar", password="secret")
    actions.send(store, "get name", device=store.device("bench"))
    assert broker.logins[-1][0].startswith("v1_")


def test_mcc3_refuses_before_sealing(store, broker, monkeypatch):
    store.add_device("Bench", NODE, "", key=NODE)
    store.update_device(NODE[:8], alive={"state": "online"})
    monkeypatch.setattr(mcc3, "seal_command", lambda *a, **k: pytest.fail("sealed"))
    for command, why in (("set prv.key 00", "denied"), ("set mqtt.cmd.pubkey AA", "refuse"),
                         ("set name " + "x" * 160, "at most 160")):
        with pytest.raises(envelope.EnvelopeError, match=why):
            actions.send(store, command, device=store.device("bench"))
    assert broker.published == []


def test_a_dry_run_seals_and_sends_nothing(store, broker):
    store.add_device("Bench", NODE, "", key=NODE)
    store.update_device(NODE[:8], alive={"state": "online"})
    topic, payload, answers, lines = actions.send(store, "get name", device=store.device("bench"), dry_run=True)
    assert topic == f"mcc/cmd/{NODE}" and lines[-1] == "not sent (dry run)" and answers == {}
    assert mcc3.open_command(NODE_SEED, store.public_key(), payload)["command"] == "get name"
    assert broker.published == [] and broker.logins == []


def test_a_county_act_is_one_sealed_command_per_node_never_a_broadcast(store, broker, monkeypatch):
    store.add_device("Bench", NODE, "", key=NODE)
    store.add_device("Far", STRANGER, "", key=STRANGER)
    store.update_device(NODE[:8], alive={"state": "online", "region": "se-jkp"})
    store.update_device(STRANGER[:8], alive={"state": "online", "region": "se-vgr"})
    monkeypatch.setattr(actions, "pause", lambda *a, **k: 0)
    _t, _p, answers, lines = actions.send(store, "get name", county="SE-JKP")
    assert [t for t, _p in broker.published] == [f"mcc/cmd/{NODE}"] and list(answers) == [NODE[:8]]
    with pytest.raises(envelope.EnvelopeError, match="no device of yours in se-x"):
        actions.send(store, "get name", county="se-x")
    assert not any("/all/" in t or t.endswith("/all/cmd") for t, _p in broker.published)


# -- the scheme per node (MC5) -------------------------------------------------------------

@pytest.mark.parametrize("ver, alive_, topic", [
    ("esp32s3-v1.18.0-lou-19-arrc-observer-1a2b3c4d", None, f"meshcore/JKG/{NODE}/cmd"),
    ("esp32s3-v1.18.0-lou-20-arrc-observer-1a2b3c4d", None, f"mcc/cmd/{NODE}"),
    (None, {"state": "online"}, f"mcc/cmd/{NODE}"),
    ("esp32s3-v1.18.0-lou-19-arrc-observer-1a2b3c4d", {"state": "online"}, f"mcc/cmd/{NODE}"),
    (None, {"state": "not-yours"}, f"meshcore/JKG/{NODE}/cmd"),
    (None, None, f"meshcore/JKG/{NODE}/cmd")])
def test_the_scheme_follows_the_alive_then_the_version(store, ver, alive_, topic):
    store.add_device("Bench", NODE, "JKG", key=NODE)
    store.update_device(NODE[:8], ver=ver, alive=alive_)
    assert actions.send(store, "get name", device=store.device("bench"), dry_run=True)[0] == topic


def test_an_old_node_is_upgraded_over_the_old_scheme_and_moves_to_mcc3_by_its_alive(store, broker, monkeypatch):
    store.add_device("Bench", NODE, "JKG", key=NODE)
    store.update_device(NODE[:8], ver="esp32s3-v1.18.0-lou-19-arrc-observer-1a2b3c4d")
    sent = []
    monkeypatch.setattr(transport, "send", lambda cfg, seed, topic, cmd, **k: sent.append((topic, cmd)) or ("p", {}))
    actions.send(store, "ota update", device=store.device("bench"))
    assert sent == [(f"meshcore/JKG/{NODE}/cmd", "ota update")]
    broker.retained = {mcc3.alive_topic(NODE): alive()}                       # it rebooted into lou-20
    actions.discover_alive(store)
    assert actions.send(store, "get name", device=store.device("bench"), dry_run=True)[0] == f"mcc/cmd/{NODE}"


def test_a_lou_20_node_without_its_whole_key_is_told_so(store):
    store.add_device("Short", NODE[:8], "JKG")
    store.update_device(NODE[:8], ver="esp32s3-v1.18.0-lou-20-arrc-observer-1a2b3c4d")
    with pytest.raises(envelope.EnvelopeError, match="whole"):
        actions.send(store, "get name", device=store.device("short"), dry_run=True)


def test_a_device_needs_a_region_only_without_its_whole_key(store):
    assert store.add_device("New", NODE, "")["region"] == ""
    assert store.add_device("Dash", STRANGER, "-")["region"] == ""
    with pytest.raises(_store.StoreError, match="region"):
        store.add_device("Old", "BBBBBBBB", "")


# -- the mesh road, 0xC2 (MC2) -------------------------------------------------------------

class Mcc3Companion:
    """A companion in front of a lou-20 node: opens the 0xC2 request as the node does and
    answers sealed under K_cmd."""

    def __init__(self, answer=(0, "OK")):
        self.answer, self.sent = answer, []

    async def open(self):
        pass

    async def contact(self, key_hex):
        return {"out_path_len": 1}

    async def add_contact(self, key_hex, name):
        return True

    async def send(self, key_hex, body):
        self.sent.append((key_hex, body))
        return {"tag": "6553f100", "flood": False, "timeout": 0}

    async def response(self, tag_hex, timeout):
        req = mcc3.open_mesh_request(NODE_SEED, envelope.public_key_hex(OWNER_SEED), bytes(4) + self.sent[-1][1])
        keys = mcc3.node_keys(NODE_SEED, envelope.public_key_hex(OWNER_SEED))
        return mcc3.seal_mesh_response(keys, 0, req["counter"], self.answer[0], 1795000000, self.answer[1])[4:]

    async def close(self):
        pass


def test_the_mesh_road_to_a_lou_20_node_is_0xC2_sealed_and_its_answer_opens(store, monkeypatch):
    store.add_device("Bench", NODE, "", key=NODE)
    store.update_device(NODE[:8], ver="esp32s3-v1.18.0-lou-20-arrc-observer-1a2b3c4d")
    store.save_config(companion="tcp:companion.invalid:5000")
    fake = Mcc3Companion(answer=(0, "OK"))
    monkeypatch.setattr(mesh, "open_companion", lambda spec: fake)
    topic, body, answers, lines = actions.send(store, "set wifi.ssid HomeNet", device=store.device("bench"), via="mesh")
    key, sent = fake.sent[0]
    assert key == NODE and len(sent) == 132 and sent[0] == 0xC2 and sent[1] == 0
    assert b"HomeNet" not in sent                                        # the companion cannot read it
    r = answers[NODE[:8]]
    assert (r.ok, r.reply, r.clock, r.counter) == (True, "OK", 1795000000, store.device("bench")["counter"])
    assert topic == f"mcc/cmd/{NODE}" and store.history(NODE[:8])[-1]["road"] == "mesh"
    # 57 bytes, not 59, before anything is sealed
    with pytest.raises(envelope.EnvelopeError, match="1..57 bytes"):
        actions.send(store, "set wifi.ssid " + "x" * 44, device=store.device("bench"), via="mesh")


def test_a_0xC2_answer_under_another_counter_or_key_is_not_ours():
    keys = mcc3.owner_keys(OWNER_SEED, NODE)
    good = mcc3.seal_mesh_response(keys, 0, 9, 0, 0, "OK")[4:]
    assert mesh.parse_mcc3(keys, good, counter=9).reply == "OK"
    assert mesh.parse_mcc3(keys, good, counter=8) is None
    assert mesh.parse_mcc3(mcc3.owner_keys(OTHER_SEED, NODE), good, counter=9) is None


# -- the API and the command line ----------------------------------------------------------

def test_the_command_line_adds_without_a_region_discovers_and_sends(tmp_path, monkeypatch, capsys, broker):
    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path / "cli"))
    s = _store.Store(tmp_path / "cli")
    s.import_key(OWNER_SEED)
    s.save_config(broker="broker.invalid")
    broker.retained = {mcc3.alive_topic(NODE): alive()}
    assert cli.main(["discover", "--add"]) == 0
    out = capsys.readouterr().out
    assert "4FD099CC  SE-JKG-LOUTEST" in out and "online" in out and "added" in out
    assert "se-jkp" not in out                                            # no region shown
    assert cli.main(["add", "Far", STRANGER]) == 0
    assert capsys.readouterr().out.strip() == f"added Far ({STRANGER[:8]})"
    assert cli.main(["devices"]) == 0
    rows = capsys.readouterr().out.splitlines()
    assert all(" mcc3 " in r for r in rows if r.startswith("SE-JKG-LOUTEST"))
    assert cli.main(["send", "SE-JKG-LOUTEST", "get", "name"]) == 0
    assert "> SE-JKG-LOUTEST" in capsys.readouterr().out
    monkeypatch.setattr(actions, "pause", lambda *a, **k: 0)
    assert cli.main(["send", "se-jkp", "get", "name", "--county"]) == 0
    assert [t for t, _p in broker.published] == [f"mcc/cmd/{NODE}"] * 2


def test_the_api_discovers_by_alive_without_a_region_and_takes_a_county(tmp_path, monkeypatch, broker):
    from mccontrol.api import serve, stop
    from test_api import call, run
    s = _store.Store(tmp_path / "api")
    s.import_key(OWNER_SEED)
    s.save_config(broker="broker.invalid")
    broker.retained = {mcc3.alive_topic(NODE): alive()}
    server, url = serve(s)
    try:
        job = run(url, "discover", {"add": True})
        assert job["result"]["regions"] == []
        (e,) = job["result"]["found"]
        assert (e["scheme"], e["state"], e["version"], e["added"], e["region"]) == ("mcc3", "online", "lou-20", True, "")
        d = call(url, "GET", f"/devices/{NODE[:8]}")[1]
        assert d["scheme"] == "mcc3" and d["broker"] == "broker.invalid"
        monkeypatch.setattr(actions, "pause", lambda *a, **k: 0)
        job = run(url, "send", {"command": "get name", "county": "se-jkp"})
        assert job["result"]["topics"] == [f"mcc/cmd/{NODE}"] and job["outcomes"][0]["ok"]
        status, err = call(url, "POST", "/jobs/send", {"command": "get name", "county": "se-jkp", "via": "mesh"},
                           check=False)
        assert status == 400 and "one node at a time" in err["error"]["message"]
        status, _ = call(url, "POST", "/devices", {"node": STRANGER, "name": "Far"}, check=False)
        assert status == 201
    finally:
        stop(server)
