"""RB-1: a broker per region. The shared broker serves every region with no entry of its own;
a region may name its own broker, and each device, broadcast, discovery and registration then
goes to its region's broker, with a login token signed for that broker's name."""
import json
import types

import pytest

from mccontrol import actions, cli, envelope, store as _store, token, transport

SHARED = "mqtt-meshcore.louie.se"
VGR = "mqtt.meshcore-vgr.se"


@pytest.fixture
def store(tmp_path):
    s = _store.Store(tmp_path / "home")
    s.create_key()
    s.add_device("Gisebo", "4AC61A7F", "JKG")
    s.add_device("Alingsas", "AB6B9285", "VGR")
    s.add_device("Boras", "13B58595", "VGR")
    return s


class _Broker:
    """Enough of paho for one connection: records the host and login it was given, and answers
    a publish with each node in `answers` on that node's /res, under the topic's region."""

    seen = []             # (host, username, password, subscribed, published topic)
    answers = []          # (region, node)

    def __init__(self, config, seed_hex=None):
        self.config, self.subs, self.on_connect, self.on_message = config, [], None, None

    def username_pw_set(self, user, password):
        self.user, self.password = user, password

    def connect(self, host, port, keepalive=30):
        self.host = host

    def loop_start(self):
        self.on_connect(self, None, None, types.SimpleNamespace(is_failure=False))

    def subscribe(self, topic, qos=0):
        self.subs.append(topic)

    def publish(self, topic, payload, qos=0):
        _Broker.seen.append((self.host, self.user, self.password, list(self.subs), topic))
        counter = payload.split("|")[1]
        for region, node in self.answers:          # every region on this broker answers
            self.on_message(self, None, types.SimpleNamespace(
                topic=f"meshcore/{region}/{node}/res", payload=f"r1|{counter}|0|get autoreply|on".encode()))
        return types.SimpleNamespace(wait_for_publish=lambda timeout=0: None)

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture
def broker(monkeypatch):
    _Broker.seen, _Broker.answers = [], []
    monkeypatch.setattr(transport, "_client", _Broker)
    monkeypatch.delenv("MCCONTROL_FAKE_RESULTS", raising=False)
    return _Broker


def audience(password):
    return token.verify(password)[1]["aud"]


def test_a_region_without_an_entry_uses_the_shared_broker(store):
    assert store.config()["brokers"] == {}
    assert store.broker_for("JKG") == store.broker_for("VGR") == SHARED
    assert store.brokers() == [SHARED]


def test_a_region_may_name_its_own_broker_and_go_back(store):
    assert store.set_region_broker("vgr", VGR) == {"VGR": VGR}
    assert store.broker_for("VGR") == VGR and store.broker_for("JKG") == SHARED
    assert store.brokers() == [SHARED, VGR]
    assert store.config_for("vgr")["broker"] == VGR and store.config_for("vgr")["region"] == "VGR"
    assert store.set_region_broker("VGR", SHARED) == {}          # naming the shared one is no entry
    store.set_region_broker("VGR", VGR)
    assert store.set_region_broker("VGR", "") == {}
    with pytest.raises(_store.StoreError):
        store.set_region_broker("V", VGR)
    with pytest.raises(_store.StoreError):
        store.set_region_broker("VGR", "not a host")
    assert len(store.devices()) == 3                             # moving a region loses no device


def test_two_regions_on_two_brokers_each_device_on_its_regions_broker(store, broker):
    store.set_region_broker("VGR", VGR)
    broker.answers = [("JKG", "4AC61A7F"), ("VGR", "AB6B9285")]
    actions.send(store, "get autoreply", device=store.device("gisebo"), wait_secs=0.1)
    actions.send(store, "get autoreply", device=store.device("alingsas"), wait_secs=0.1)
    (h1, _u1, p1, _s1, t1), (h2, _u2, p2, _s2, t2) = broker.seen
    assert (h1, audience(p1), t1) == (SHARED, SHARED, "meshcore/JKG/4AC61A7F/cmd")
    assert (h2, audience(p2), t2) == (VGR, VGR, "meshcore/VGR/AB6B9285/cmd")
    assert store.history("AB6B9285")[-1]["code"] == 0


def test_a_region_act_goes_to_its_regions_broker_one_node_each(store, broker, monkeypatch):
    store.set_region_broker("VGR", VGR)
    monkeypatch.setattr(actions, "pause", lambda *a, **k: 0)
    broker.answers = [("VGR", "AB6B9285"), ("VGR", "13B58595")]
    _t, _p, answers, _l = actions.send(store, "get autoreply", region="VGR", wait_secs=0.1)
    assert sorted(t for *_x, t in broker.seen) == ["meshcore/VGR/13B58595/cmd", "meshcore/VGR/AB6B9285/cmd"]
    assert {(h, audience(p)) for h, _u, p, _s, _t in broker.seen} == {(VGR, VGR)}
    assert sorted(answers) == ["13B58595", "AB6B9285"]
    assert all(s.startswith("meshcore/VGR/") for *_x, subs, _t in broker.seen for s in subs)


def test_discovery_asks_the_regions_broker_and_marks_where_it_found_them(store, broker):
    store.set_region_broker("VGR", VGR)
    broker.answers = [("VGR", "AB6B9285")]
    found = actions.discover(store, "VGR", wait_secs=0.1)
    assert [(e["node"], e["broker"]) for e in found] == [("AB6B9285", VGR)]
    assert {h for h, *_ in broker.seen} == {VGR}


def test_several_regions_on_one_broker_are_told_apart_by_iata(store, broker):
    """JKG and VGR on the shared broker: discovery and broadcasts are filtered by the region in
    the topic, never by the broker -- an answer under another IATA is not this region's."""
    broker.answers = [("JKG", "4AC61A7F"), ("VGR", "AB6B9285"), ("VGR", "13B58595")]
    found = actions.discover(store, "VGR", wait_secs=0.1)
    assert [e["node"] for e in found] == ["13B58595", "AB6B9285"]
    assert broker.seen[0][3] == ["meshcore/VGR/+/res"] and broker.seen[0][0] == SHARED
    found = actions.discover(store, "JKG", wait_secs=0.1)
    assert [e["node"] for e in found] == ["4AC61A7F"]
    broker.seen.clear()
    _t, _p, answers, _l = actions.send(store, "get autoreply", region="JKG", wait_secs=0.1)
    assert list(answers) == ["4AC61A7F"] and broker.seen[0][4] == "meshcore/JKG/4AC61A7F/cmd"


def test_registration_is_per_broker(store, monkeypatch):
    store.set_region_broker("VGR", VGR)
    asked = []

    def register(config, seed_hex, wait_secs=10, **_k):
        asked.append(config["broker"])
        return (config["broker"] == SHARED, "ok" if config["broker"] == SHARED else "refused not-approved")
    monkeypatch.setattr(transport, "register", register)
    results = actions.register_all(store)
    assert asked == [SHARED, VGR]
    assert [(b, ok) for b, ok, _d in results] == [(SHARED, True), (VGR, False)]
    assert store.registration()["broker"] == SHARED and store.registration(VGR) is None
    regs = store.registrations()
    assert list(regs) == [SHARED, VGR] and regs[SHARED] and regs[VGR] is None
    monkeypatch.setattr(transport, "register", lambda config, *_a, **_k: (True, "ok"))
    assert actions.register(store, VGR) == (True, "ok")
    assert store.registration(VGR)["broker"] == VGR
    # the shared broker's registration is also kept where mccontrol before RB-1 reads it
    on_disk = json.loads((store.root / "config.json").read_text())
    assert on_disk["registered"]["broker"] == SHARED


def test_a_stored_registration_from_before_rb1_is_kept_and_a_former_name_migrates(store):
    (store.root / "config.json").write_text(json.dumps({
        "broker": "mqtt.meshcore-jkp.se", "brokers": {"JKG": "mqtt.louie.se", "VGR": VGR},
        "registered": {"broker": "mqtt.meshcore-jkp.se", "at": "2026-11-15 10:00:00"},
        "registrations": {"mqtt.louie.se": "2026-10-08 10:00:00"}}))
    config = store.config()
    assert config["broker"] == SHARED and config["brokers"] == {"JKG": SHARED, "VGR": VGR}
    assert store.registration() == {"broker": SHARED, "at": "2026-11-15 10:00:00"}
    assert store.registrations() == {SHARED: "2026-11-15 10:00:00", VGR: None}
    assert store.broker_for("JKG") == SHARED


def test_the_api_and_the_command_line_show_the_broker_per_device(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path))
    monkeypatch.setenv("MCCONTROL_FAKE_REGISTER", "ok")
    assert cli.main(["keygen"]) == 0
    assert cli.main(["add", "Gisebo", "4AC61A7F", "JKG"]) == 0
    assert cli.main(["add", "Alingsas", "AB6B9285", "VGR"]) == 0
    assert cli.main(["config", "--region-broker", f"VGR={VGR}"]) == 0
    assert f"broker VGR   {VGR}" in capsys.readouterr().out
    assert cli.main(["devices"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert f"via {SHARED}" in out[0] and f"via {VGR}" in out[1]
    assert cli.main(["register"]) == 0
    out = capsys.readouterr().out
    assert f"registered with {SHARED}: ok" in out and f"registered with {VGR}: ok" in out
    assert cli.main(["key"]) == 0
    out = capsys.readouterr().out
    assert f"registered with {SHARED} on" in out and f"registered with {VGR} on" in out
    assert cli.main(["config", "--region-broker", "VGR="]) == 0
    assert "broker VGR" not in capsys.readouterr().out
    assert cli.main(["config", "--region-broker", "VGR"]) == 1


def test_the_api_validates_a_region_broker_change(api):
    from test_api import call
    _server, url, store = api
    status, body = call(url, "PATCH", "/config", {"brokers": {"GOT": "mqtt.meshcore-got.se"}})
    assert status == 200 and body["brokers"] == {"GOT": "mqtt.meshcore-got.se"}
    devices = {d["node"]: d["broker"] for d in call(url, "GET", "/devices")[1]["devices"]}
    assert devices == {"4AC61A7F": "127.0.0.1", "65C1D12C": "127.0.0.1", "FD700369": "mqtt.meshcore-got.se"}
    assert call(url, "GET", "/regions")[1]["brokers"] == {"JKG": "127.0.0.1", "GOT": "mqtt.meshcore-got.se"}
    assert [r["broker"] for r in call(url, "GET", "/key")[1]["registrations"]] == ["127.0.0.1", "mqtt.meshcore-got.se"]
    assert call(url, "PATCH", "/config", {"brokers": {"G": "x.se"}})[0] == 400
    assert call(url, "PATCH", "/config", {"brokers": {"GOT": "no host"}})[0] == 400
    assert call(url, "POST", "/jobs/register", {"broker": "elsewhere.se"})[0] == 400
    status, body = call(url, "PATCH", "/config", {"brokers": {"GOT": None}})
    assert status == 200 and body["brokers"] == {}
