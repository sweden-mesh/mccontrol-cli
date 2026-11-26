"""A18: scripts/screenshots.py -- its colour terminal, and that the fleet it shows is invented.
The PNG step needs headless Chromium and is not run here; the HTML before it is."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import screenshots  # noqa: E402


def _text(screen):
    return ["".join(ch for ch, _a in row).rstrip() for row in screen.grid]


def test_the_terminal_keeps_colour_insert_mode_scrolling_and_the_deferred_wrap():
    s = screenshots.Screen(10, 4)
    s.feed("\x1b[1;1H\x1b[38;5;214;48;5;234mAB\x1b[0mC")
    assert s.grid[0][0] == ("A", (214, 234, False, False, False, False)) and s.grid[0][2][1][0] is None
    s.feed("\x1b[1;2H\x1b[4hX\x1b[4l")                       # insert mode shifts the rest right
    assert _text(s)[0] == "AXBC"
    s.feed("\x1b[2;1Hrow2\x1b[1;4r\x1b[1T")                   # scroll down one in the region
    assert _text(s)[:3] == ["", "AXBC", "row2"]
    s.feed("\x1b[4;1H0123456789Z")                             # the 11th character wraps only when it comes
    assert _text(s)[3] == "Z" and _text(s)[2] == "0123456789"
    html = screenshots.to_html(s, "t")
    assert "#ffaf00" in html and "font:15px/18px" in html     # 256-colour 214 as the palette has it


def test_the_fleet_is_invented_and_the_board_shows_it(tmp_path):
    screenshots.check_invented()
    home, script, beacon = screenshots.build_home(tmp_path)
    devices = json.loads((home / "devices.json").read_text())
    real = {n["publicKey"][:8].upper() for n in json.loads((ROOT / "tests" / "data" / "beacon-fake.json").read_text())["/nodes"]["items"]}
    assert len(devices) == 10 and not {d["node"] for d in devices} & real
    assert {d["region"] for d in devices} == {"", screenshots.OLD_REGION}
    screen = screenshots.capture("Monolith", 80, 24, [(screenshots.DOWN, 0.4)], home, script, beacon)
    text = "\n".join(_text(screen))
    assert "Church-Spire" in text and "10 devices" in text and "HISTORY" in text and "STATS CHURCH-SPIRE" in text
    assert not any(node in text for node in real)


def test_the_fleets_home_reads_like_a_configured_install(tmp_path):
    from mccontrol import store as _store
    home, _script, _beacon = screenshots.build_home(tmp_path)
    st = _store.Store(home)
    assert (st.config()["broker"], st.config()["port"], st.config()["tls"]) == ("mqtt.example.org", 8883, True)
    assert st.registration()["broker"] == "mqtt.example.org" and st.tested()["ok"] is True


def test_the_fleet_is_a_lou_20_one(tmp_path):
    """Most nodes found by their alive message and kept without a region, one without Wi-Fi
    that a relay reaches, one on lou-18 and the old scheme; nothing sent to a whole region."""
    from mccontrol import actions, firmware, store as _store
    home, _script, _beacon = screenshots.build_home(tmp_path)
    st = _store.Store(home)
    by = {d["name"]: d for d in st.devices()}
    found = [d for d in by.values() if (d.get("alive") or {}).get("state") == "online"]
    assert len(found) == 8 and all(not d["region"] and actions.scheme(d) == "mcc3" for d in found)
    assert {d["alive"]["region"] for d in found} == set(screenshots.HOMES)
    assert all(firmware.revision(d["ver"]) == 20 and d["notes"] == "found by discovery" for d in found)
    cabin, relay, old = by[screenshots.NO_WIFI], by[screenshots.RELAY], by["Water-Tower"]
    assert firmware.device_mesh_only(cabin) and not cabin["region"] and not cabin.get("alive") and not cabin.get("observer_id")
    assert actions.scheme(cabin) == "mcc3" and actions.relay_refusal(relay) is None
    assert {h["road"] for h in st.history(cabin["node"])} == {"relay"}
    assert st.history(cabin["node"])[-1]["relay"]["node"] == relay["node"]
    assert firmware.revision(old["ver"]) == 18 and actions.scheme(old) == "old" and old["region"] == screenshots.OLD_REGION
    assert [d["name"] for d in by.values() if actions.scheme(d) == "old"] == ["Water-Tower"]
    assert not (home / "history" / "all.jsonl").exists()
    assert all(h["topic"].startswith("mcc/cmd/") for d in found for h in st.history(d["node"]))
    assert "#test-zqv" in " ".join(h["reply"] for h in st.history(old["node"]))


def test_the_command_line_pictures_show_a_key_rotation_and_a_send_through_the_relay(tmp_path):
    shots = {}
    for name, cols, prepare, commands in screenshots.CLI_STATES:
        where = tmp_path / name
        where.mkdir()
        home, script, beacon = screenshots.build_home(where)
        if prepare:
            prepare(home)
        shots[name] = _text(screenshots.capture_cli(commands, cols, home, script, beacon))
    rekey = shots["cli-rekey-status"]
    assert rekey[0] == "$ python -m mccontrol.rekey status" and len(rekey) == 11
    states = {line[:20].strip(): line[21:] for line in rekey[1:]}
    assert states["Old-Mill"] == "on the next key" and states["Ridge-East"] == "offered, not confirmed"
    assert states["Quarry-Hill"] == "on the key in use" and states["Water-Tower"].startswith("cannot: its firmware has no rekey")
    relay = shots["cli-relay-send"]
    assert relay[0] == "$ mccontrol send allotments ver --via relay:quarry-hill"
    assert relay[1] == "through relay Quarry-Hill (direct, no hops: only a node the relay hears itself): sent direct"
    assert relay[2].startswith("Allotments   > rak4631-v1.18.0-lou-20-rc-")
    assert relay[3] == "" and relay[4].endswith("--route flood")
    assert relay[5] == "through relay Quarry-Hill (flood in the relay's region): sent flood"
    assert "mesh only" in relay[6] and len(relay) == 7
