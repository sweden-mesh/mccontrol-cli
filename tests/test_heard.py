"""A node without Wi-Fi announces itself, and an Observer node of the same owner publishes what
it caught on `mcc/heard/<KEY>/<slot>` (lou-21). The pinned spec's `vectors/malive-vectors.json`,
written by the firmware's own generator, is rebuilt and opened here byte for byte, every refusal
is dropped, and the discovery reads the entries from a FAKE broker: the newest (boot, sequence)
per node, a forged entry never a device, and with no entries everything as before. Nothing here
opens a broker or a radio."""
import datetime
import json
import pathlib

import pytest

from mccontrol import actions, directory, envelope, mcc3, plane
from test_plane import FakeBroker, alive, broker, store  # noqa: F401  (fixtures)

V = json.loads((pathlib.Path(__file__).resolve().parents[1] / "spec" / "vectors" / "malive-vectors.json")
               .read_text(encoding="utf-8"))
SEEDS, PUB, C = V["keys"]["seeds"], V["keys"]["public"], V["constants"]
OWNER_SEED, OWNER = SEEDS["owner"], PUB["owner"]
NODE, CATCHER = PUB["node"], PUB["catcher"]
S_NODE = mcc3.shared_secret(OWNER_SEED, NODE)
S_CATCHER = mcc3.shared_secret(OWNER_SEED, CATCHER)
K_MALIVE = {"node": mcc3.malive_key(S_NODE, NODE), "catcher": mcc3.malive_key(S_CATCHER, CATCHER)}
K_HEARD = mcc3.heard_key(S_CATCHER, CATCHER)
ANNOUNCES = {a["name"]: a for a in V["announces"]}
A1, H1, H2 = V["announces"][0], V["heard"][0], V["heard"][1]


# -- the bytes -------------------------------------------------------------------------------

def test_the_constants_and_the_keys_are_the_vectors():
    assert (mcc3.KIND_ANNOUNCE, mcc3.KIND_HEARD) == (C["kind"], C["kind_heard"])
    assert (mcc3.ANNOUNCE_SIZE, mcc3.ANNOUNCE_SEALED, mcc3.ANNOUNCE_TAG, mcc3.ANNOUNCE_KEPT) == (
        C["payload_bytes"], C["sealed_bytes"], C["tag_bytes"], C["kept_bytes"])
    assert (mcc3.HEARD_PLAIN, mcc3.HEARD_SIZE, mcc3.HEARD_SLOTS) == (
        C["heard_plain_bytes"], C["heard_bytes"], C["table_slots"])
    assert (mcc3.INFO_MALIVE, mcc3.INFO_HEARD, mcc3.OWN_LABEL.decode()) == (
        C["label_malive"], C["label_heard"], C["label_owner_tag"])
    assert (mcc3.ANNOUNCE_MAX_VERSION, mcc3.ANNOUNCE_MAX_NAME) == (C["max_version"], C["max_name"])
    assert S_NODE.hex().upper() == V["keys"]["shared_node_owner"]
    assert S_CATCHER.hex().upper() == V["keys"]["shared_catcher_owner"]
    assert K_MALIVE["node"].hex().upper() == V["keys"]["k_malive_node"]
    assert K_MALIVE["catcher"].hex().upper() == V["keys"]["k_malive_catcher"]
    assert K_HEARD.hex().upper() == V["keys"]["k_heard_catcher"]
    # the node's side gives the same keys: its identity seed and the owner's public key
    assert mcc3.malive_key(mcc3.shared_secret(SEEDS["node"], OWNER), NODE) == K_MALIVE["node"]


@pytest.mark.parametrize("a", V["announces"], ids=lambda a: a["name"])
def test_an_announce_is_built_and_opened_byte_for_byte(a):
    key, node = K_MALIVE[a["node"]], PUB[a["node"]]
    assert mcc3.owner_tag(OWNER, node, a["fields"]["boot"], a["fields"]["sequence"]).hex().upper() == a["owner_tag"]
    raw = mcc3.seal_announce(key, OWNER, node, a["fields"])
    assert raw.hex().upper() == a["payload"] and len(raw) == a["bytes"]
    opened = mcc3.open_announce(key, OWNER, bytes.fromhex(a["payload"]))
    assert opened.pop("node_key") == node
    assert opened == a["opened"]


@pytest.mark.parametrize("h", V["heard"], ids=lambda h: h["name"])
def test_a_heard_entry_is_built_and_opened_byte_for_byte(h):
    a = ANNOUNCES[h["announce"]]
    fields = {k: h["opened"][k] for k in mcc3.HEARD_FIELDS}
    assert mcc3.seal_heard(K_HEARD, PUB[a["node"]], bytes.fromhex(a["payload"]), fields,
                           nonce=bytes.fromhex(h["nonce"])) == h["payload"]
    assert mcc3.heard_topic(CATCHER, h["slot"]) == h["topic"]
    assert mcc3.heard_from_topic(h["topic"]) == (CATCHER, h["slot"])
    opened = mcc3.open_heard(K_HEARD, h["payload"])
    assert opened.pop("announce").hex().upper() == h["opened"].pop("announce") == a["payload"]
    assert opened == h["opened"]
    # and the whole way, as the discovery does it: the entry, then the announce inside
    whole = plane.open_heard(OWNER_SEED, {}, CATCHER, h["payload"])
    assert {k: whole[k] for k in a["opened"]} == a["opened"]
    assert whole["node_key"] == PUB[a["node"]] and whole["by"] == CATCHER
    assert {k: whole[k] for k in fields} == fields


@pytest.mark.parametrize("r", V["refusals"], ids=lambda r: r["name"])
def test_every_refusal_is_refused_with_its_outcome(r):
    with pytest.raises(mcc3.Refused) as said:
        mcc3.open_announce(K_MALIVE["node"], OWNER, bytes.fromhex(r["input"]))
    assert said.value.outcome == r["outcome"]


def _entry(announce, node=NODE, key=K_HEARD, heard_at=1795000050, snr=-22, hops=2):
    """A heard entry around any 101 bytes, sealed as the catching node seals it."""
    return mcc3.seal_heard(key, node, announce, {"heard_at": heard_at, "snr": snr, "hops": hops,
                                                 "advert_heard_at": 0, "advert_snr": 0, "advert_hops": 0})


@pytest.mark.parametrize("r", [r for r in V["refusals"] if len(r["input"]) == 202], ids=lambda r: r["name"])
def test_a_refused_announce_inside_a_good_heard_entry_is_dropped(r):
    """The catching node cannot tell: it seals what it caught. Only the tool can, and it drops it."""
    raw = bytes.fromhex(r["input"])
    assert plane.open_heard(OWNER_SEED, {}, CATCHER, _entry(raw, node=raw[1:33].hex())) is None


def test_a_heard_entry_that_does_not_open_is_dropped():
    raw = mcc3.unb64(H1["payload"])
    for at in (0, 1, 13, len(raw) - 1):                           # the kind, the nonce, the body, the tag
        bent = raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:]
        assert plane.open_heard(OWNER_SEED, {}, CATCHER, mcc3.b64(bent)) is None
    assert plane.open_heard(OWNER_SEED, {}, CATCHER, mcc3.b64(raw[:-1])) is None
    assert plane.open_heard(OWNER_SEED, {}, CATCHER, "not base64 !") is None
    assert plane.open_heard(SEEDS["other_owner"], {}, CATCHER, H1["payload"]) is None     # another owner's tool
    assert plane.open_heard(OWNER_SEED, {}, NODE, H1["payload"]) is None                  # another node's slot
    assert plane.open_heard(OWNER_SEED, {}, CATCHER, H1["payload"])["battery_mv"] == 3987


def test_the_tag_is_checked_though_it_is_cut_to_eight_bytes():
    """An announce sealed under another key, with a right owner tag, is a forgery that reaches
    the tool: the cut tag is what stops it."""
    forged = mcc3.seal_announce(bytes(32), OWNER, NODE, dict(A1["fields"], battery_mv=1))
    assert forged[:46] == bytes.fromhex(A1["payload"])[:46]       # the clear part is the real one's
    with pytest.raises(mcc3.Refused) as said:
        mcc3.open_announce(K_MALIVE["node"], OWNER, forged)
    assert said.value.outcome == "does-not-open"
    assert plane.open_heard(OWNER_SEED, {}, CATCHER, _entry(forged)) is None


def test_the_newest_boot_and_sequence_wins_whoever_caught_it():
    a1 = plane.open_heard(OWNER_SEED, {}, CATCHER, H1["payload"])             # 7.1
    a2 = plane.open_heard(OWNER_SEED, {}, CATCHER, H2["payload"])             # 7.2
    assert plane.newest_heard([a1, a2])[NODE]["sequence"] == 2
    assert plane.newest_heard([a2, a1, None])[NODE]["sequence"] == 2
    later_boot = dict(a1, boot=8, sequence=1)
    assert plane.newest_heard([a2, later_boot])[NODE]["boot"] == 8
    assert plane.newest_heard([]) == {}


@pytest.mark.parametrize("topic", ["mcc/heard/%s" % CATCHER, "mcc/heard/%s/16" % CATCHER, "mcc/heard/%s/01" % CATCHER,
                                   "mcc/heard/%s/-1" % CATCHER, "mcc/heard/%s/0/x" % CATCHER,
                                   "mcc/heard/%s/0" % CATCHER.lower(), "mcc/heard/ABCD/0", "mcc/alive/%s" % CATCHER])
def test_a_topic_that_is_no_heard_slot_names_none(topic):
    assert mcc3.heard_from_topic(topic) is None


# -- the discovery ---------------------------------------------------------------------------

@pytest.fixture
def heard_broker(broker, monkeypatch):
    """The fake broker also serves its retained heard slots to the heard filter."""
    plain = broker.subscribe

    def subscribe(self, topic, qos=0):
        plain(self, topic, qos)
        if topic == mcc3.HEARD_FILTER:
            for t, payload in self.retained.items():
                if t.startswith("mcc/heard/"):
                    self.on_message(self, None, __import__("types").SimpleNamespace(topic=t, payload=payload.encode()))

    monkeypatch.setattr(broker, "subscribe", subscribe)
    return broker


def _catcher_alive(owner_seed=OWNER_SEED, **over):
    return alive(node_seed=SEEDS["catcher"], owner_seed=owner_seed, name="DEMO-Observer", **over)


def test_an_announced_node_is_found_added_and_shown_with_its_battery(store, heard_broker):
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(), H1["topic"]: H1["payload"]}
    found = actions.discover_alive(store, add=True)
    assert [(e["key"], e["state"], e["added"]) for e in found] == [(CATCHER, "online", True), (NODE, "heard", True)]
    assert mcc3.HEARD_FILTER in heard_broker.subscribed and heard_broker.published == []     # a read: nothing sent
    d = store.device(NODE[:8])
    assert d["key"] == NODE and d["mesh_only"] is True and d["name"] == A1["opened"]["name"]
    assert not d.get("alive") and d["ver"] == A1["opened"]["version"]
    assert actions.scheme(d) == "mcc3" and actions.road(store, d, "ver", via="auto") == ("mesh", "mesh only")
    h = d["heard"]
    assert h["battery_mv"] == 3987 and (h["boot"], h["sequence"], h["uptime"]) == (7, 1, 42)
    assert (h["by"], h["by_name"], h["snr"], h["hops"]) == (CATCHER[:8], "DEMO-Observer", -5.5, 2)
    assert h["at"] == datetime.datetime.fromtimestamp(1795000050).isoformat(sep=" ") and h["at_read"] is False
    assert h["version"] == "lou-21-arrc" and "advert_at" not in h
    now = datetime.datetime.fromtimestamp(1795000050 + 9 * 3600)
    assert directory.battery_text(d, now) == "3.99 V, 9 h ago, heard by DEMO-Observer"
    assert directory.heard_text(d, now) == "heard by DEMO-Observer 9 h ago, -5.5 dB, 2 hops"
    cells = directory.cells(d, now)
    assert cells["batt"].strip() == "3.99" and cells["seen"].strip() == "9 h"
    assert directory.last_heard(d) == h["at"] and not directory.stale(d, now)


def test_without_add_it_is_listed_and_not_kept(store, heard_broker):
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(), H1["topic"]: H1["payload"]}
    found = actions.discover_alive(store)
    assert [(e["state"], e["added"], e["known_as"]) for e in found if e["key"] == NODE] == [("heard", False, None)]
    assert found[-1]["heard"]["battery_mv"] == 3987 and store.device(NODE[:8]) is None


def test_no_heard_entries_changes_nothing(store, heard_broker):
    """lou-20: no node writes mcc/heard. The discovery gives what it gave before."""
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive()}
    found = actions.discover_alive(store, add=True)
    assert [(e["key"], e["state"]) for e in found] == [(CATCHER, "online")]
    assert [d["node"] for d in store.devices()] == [CATCHER[:8]]
    assert "heard" not in store.device(CATCHER[:8]) and "heard" not in found[0]


def test_a_refused_heard_subscription_is_not_an_error(store, heard_broker, monkeypatch):
    """A command server that does not know mcc/heard refuses the filter: the alive scan stands."""
    plain = heard_broker.subscribe
    mids = {mcc3.ALIVE_FILTER: 1, mcc3.HEARD_FILTER: 2}

    def subscribe(self, topic, qos=0):
        plain(self, topic, qos)
        self.on_subscribe(self, None, mids[topic], [0x80 if topic == mcc3.HEARD_FILTER else 0])
        return 0, mids[topic]

    monkeypatch.setattr(heard_broker, "subscribe", subscribe)
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive()}
    assert [e["state"] for e in actions.discover_alive(store)] == ["online"]


def test_only_our_own_observer_nodes_are_read(store, heard_broker):
    """The same slot under a node whose alive did not open with our key is not opened at all:
    no key agreement is spent on it, and nothing is found."""
    stranger = "mcc/heard/%s/0" % PUB["other_owner"]
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(owner_seed=SEEDS["other_owner"]),
                             H1["topic"]: H1["payload"], stranger: H1["payload"]}
    assert actions.discover_alive(store, add=True) == [] and store.devices() == []
    assert PUB["other_owner"] not in store.ecdh_cache() and NODE not in store.ecdh_cache()


def test_a_forged_entry_never_reaches_the_device_list(store, heard_broker):
    forged = mcc3.seal_announce(bytes(32), OWNER, NODE, dict(A1["fields"], name="DEMO-Forged"))
    other = mcc3.seal_announce(K_MALIVE["node"], PUB["other_owner"], NODE, A1["fields"])     # another owner's tag
    raw = mcc3.unb64(H1["payload"])
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(),
                             mcc3.heard_topic(CATCHER, 1): _entry(forged),
                             mcc3.heard_topic(CATCHER, 2): _entry(other),
                             mcc3.heard_topic(CATCHER, 3): mcc3.b64(raw[:-1] + bytes([raw[-1] ^ 1])),
                             mcc3.heard_topic(CATCHER, 4): "x" * 188,
                             "mcc/heard/%s/16" % CATCHER: H1["payload"]}
    found = actions.discover_alive(store, add=True)
    assert [e["key"] for e in found] == [CATCHER]
    assert [d["node"] for d in store.devices()] == [CATCHER[:8]]


def test_the_newest_announce_is_kept_and_a_typed_name_stays(store, heard_broker):
    store.add_device("cabin", NODE, "", key=NODE)                 # added by hand, named by its owner
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(),
                             H1["topic"]: H1["payload"], H2["topic"]: H2["payload"]}
    found = actions.discover_alive(store, add=True)
    entry = [e for e in found if e["key"] == NODE][0]
    assert (entry["state"], entry["known_as"], entry["added"]) == ("heard", "cabin", False)
    d = store.device(NODE[:8])
    assert d["name"] == "cabin" and d["mesh_only"] is True
    h = d["heard"]
    assert (h["boot"], h["sequence"]) == (7, 2) and h["battery_mv"] is None          # A2: the board cannot read it
    assert h["at_read"] is True and h["advert_at"] and h["advert_snr"] == -20 and h["advert_hops"] == 5
    assert directory.battery(d) is None and directory.battery_text(d) == ""
    assert "(read then)" in directory.heard_text(d)
    # an older announce read later (the newer slot was emptied) does not replace it
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(), H1["topic"]: H1["payload"]}
    actions.discover_alive(store)
    assert store.device(NODE[:8])["heard"]["sequence"] == 2


def test_a_device_kept_by_its_id_alone_learns_its_key_and_an_observer_node_is_left_alone(store, heard_broker):
    store.add_device("", NODE[:8], "JKG")
    a4 = ANNOUNCES["A4 another node of the same owner"]           # the catching node announcing itself
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(), H1["topic"]: H1["payload"],
                             mcc3.heard_topic(CATCHER, 5): _entry(bytes.fromhex(a4["payload"]), node=CATCHER)}
    found = actions.discover_alive(store, add=True)
    assert sorted(e["state"] for e in found) == ["heard", "online"]
    assert store.device(NODE[:8])["key"] == NODE
    assert "heard" not in store.device(CATCHER[:8]) and not store.device(CATCHER[:8]).get("mesh_only")


# -- what a screen shows ---------------------------------------------------------------------

NOW = datetime.datetime(2026, 11, 27, 12, 0, 0)


def _device(**more):
    return dict({"name": "cabin", "node": NODE[:8], "region": "", "last_sent": None}, **more)


def test_the_newer_of_beacon_and_the_announce_is_the_battery_shown():
    heard = {"battery_mv": 3710, "at": "2026-11-27 03:00:00", "by": CATCHER[:8], "by_name": "DEMO-Observer",
             "snr": 3.25, "hops": 0}
    fleet = {"battery_mv": 4011, "seen": "2026-11-27T11:30:00"}
    assert directory.battery_text(_device(), NOW) == "" and directory.heard_text(_device(), NOW) == ""
    assert directory.battery_text(_device(heard=heard), NOW) == "3.71 V, 9 h ago, heard by DEMO-Observer"
    assert directory.battery_text(_device(fleet=fleet), NOW) == "4.01 V, 30 min ago, from Beacon"
    assert directory.battery_text(_device(fleet=fleet, heard=heard), NOW) == "4.01 V, 30 min ago, from Beacon"
    older = dict(fleet, seen="2026-11-26T11:30:00")
    assert directory.battery(_device(fleet=older, heard=heard))["source"] == "heard"
    assert directory.cells(_device(fleet=older, heard=heard), NOW)["batt"].strip() == "3.71"
    assert directory.cells(_device(fleet=older, heard=heard), NOW)["seen"].strip() == "9 h"
    assert directory.cells(_device(fleet=fleet), NOW)["batt"].strip() == "4.01"               # as before
    assert directory.cells(_device(), NOW)["batt"].strip() == "" == directory.cells(_device(), NOW)["seen"].strip()
    # a reading two days old is still shown, with its age
    old = dict(heard, at="2026-11-25 10:00:00")
    assert directory.battery_text(_device(heard=old), NOW) == "3.71 V, 2 d ago, heard by DEMO-Observer"
    assert directory.heard_text(_device(heard=heard), NOW) == "heard by DEMO-Observer 9 h ago, 3.25 dB, direct"
    assert directory.heard_text(_device(heard=dict(heard, by_name="", hops=1)), NOW) == (
        f"heard by {CATCHER[:8]} 9 h ago, 3.25 dB, 1 hop")


def test_the_spec_names_the_topic_and_the_first_firmware():
    from mccontrol import firmware, webexport
    block = webexport.data()["protocol.json"]["mcc3_heard"]
    assert block["filter"] == "mcc/heard/+/+" and block["size"] == 141 and block["announce"]["size"] == 101
    assert block["base64url_chars"] == len(H1["payload"]) == C["heard_base64url_chars"]
    assert firmware.ANNOUNCE_FROM == 21 == webexport.data()["firmware.json"]["announce_from"]
    assert envelope.public_key_hex(OWNER_SEED) == OWNER


def test_the_command_line_lists_it_heard_and_shows_who_heard_it_and_its_battery(tmp_path, monkeypatch, capsys,
                                                                                 heard_broker):
    from mccontrol import cli
    from mccontrol import store as _store
    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path / "cli"))
    s = _store.Store(tmp_path / "cli")
    s.import_key(OWNER_SEED)
    s.save_config(broker="broker.invalid")
    heard_broker.retained = {mcc3.alive_topic(CATCHER): _catcher_alive(), H1["topic"]: H1["payload"]}
    assert cli.main(["discover", "--add"]) == 0
    out = capsys.readouterr().out
    line = [x for x in out.splitlines() if x.startswith(NODE[:8])][0]
    assert " heard " in line and "by DEMO-Observer" in line and "3.99 V" in line and "added" in line
    assert cli.main(["devices"]) == 0
    row = [x for x in capsys.readouterr().out.splitlines() if NODE[:8] in x][0]
    assert "heard by DEMO-Observer" in row and "-5.5 dB, 2 hops" in row and "battery 3.99 V" in row
    assert "heard by DEMO-Observer" in row.split("; battery ")[1]
