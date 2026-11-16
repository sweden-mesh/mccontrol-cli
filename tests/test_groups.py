"""Device groups (RM-4): kept beside the devices, sent to member by member on each one's own
topic and region, never as a broadcast; one member refusing does not stop the rest."""
import pytest

from mccontrol import cli, store as _store, transport
from test_api import call, run


def test_create_add_remove_delete_and_persistence_across_reload(tmp_path):
    s = _store.Store(tmp_path / "home")
    s.add_device("A", "AAAAAAAA", "JKG")
    s.add_device("B", "BBBBBBBB", "GOT")
    assert s.create_group("Canary", ["AAAAAAAA"]) == ["AAAAAAAA"]
    with pytest.raises(_store.StoreError):
        s.create_group("canary")                              # names are case-blind
    with pytest.raises(_store.StoreError):
        s.create_group("two words")
    assert s.change_group("canary", add=["BBBBBBBB", "AAAAAAAA"]) == ["AAAAAAAA", "BBBBBBBB"]
    assert s.change_group("canary", remove=["AAAAAAAA"]) == ["BBBBBBBB"]
    s.create_group("empty")
    again = _store.Store(tmp_path / "home")                   # a fresh reader of the same directory
    assert again.groups() == {"canary": ["BBBBBBBB"], "empty": []}
    assert (tmp_path / "home" / "groups.json").is_file()
    again.remove_device("BBBBBBBB")                           # a forgotten device leaves its groups
    assert _store.Store(tmp_path / "home").group("canary") == []
    again.delete_group("canary")
    assert again.group("canary") is None
    with pytest.raises(_store.StoreError):
        again.delete_group("canary")
    with pytest.raises(_store.StoreError):
        again.change_group("nope", add=["AAAAAAAA"])


def test_the_group_routes_refuse_unknown_devices_and_groups(api):
    _server, url, store = api
    assert call(url, "POST", "/groups", {"name": "site", "devices": ["nobody"]})[0] == 404
    assert store.group("site") is None                        # nothing made from a bad request
    assert call(url, "POST", "/groups", {})[0] == 400
    assert call(url, "POST", "/groups", {"name": "site"})[1] == {"name": "site", "members": []}
    assert call(url, "POST", "/groups/site/devices", {"devices": ["nobody"]})[0] == 404
    assert call(url, "POST", "/groups/nope/devices", {"devices": ["gisebo"]})[0] == 404
    assert call(url, "DELETE", "/groups/site/devices")[0] == 400
    assert call(url, "GET", "/groups/nope")[0] == 404


def test_an_empty_or_unknown_group_sends_nothing(api, monkeypatch):
    _server, url, store = api
    monkeypatch.setattr(transport, "send", lambda *a, **k: pytest.fail("sent"))
    store.create_group("empty")
    status, body = call(url, "POST", "/jobs/send", {"command": "ver", "group": "empty"})
    assert status == 400 and body["error"]["message"] == "group empty has no devices"
    assert call(url, "POST", "/jobs/send", {"command": "ver", "group": "nope"})[0] == 404
    assert call(url, "POST", "/jobs/send", {"command": "ver", "group": "empty", "tagged": True})[0] == 400
    store.change_group("empty", add=["4AC61A7F"])
    status, body = call(url, "POST", "/jobs/send", {"command": "set prv.key 00", "group": "empty"})
    assert status == 400 and body["error"]["code"] == "refused"           # the deny list, before signing
    assert call(url, "GET", "/jobs")[1]["jobs"] == []


def test_a_group_send_goes_to_each_member_on_its_own_topic_and_one_refusal_stops_nothing(api):
    _server, url, store = api
    store.create_group("mixed", ["65C1D12C", "4AC61A7F", "FD700369"])        # JKG, JKG and GOT
    job = run(url, "send", {"command": "region", "group": "mixed"})
    assert job["status"] == "done"
    assert [(o["node"], o["ok"], o["code"]) for o in job["outcomes"]] == [
        ("65C1D12C", False, 14), ("4AC61A7F", True, 0), ("FD700369", None, None)]
    assert job["result"]["topics"] == ["meshcore/JKG/65C1D12C/cmd", "meshcore/JKG/4AC61A7F/cmd",
                                       "meshcore/GOT/FD700369/cmd"]               # never meshcore/<IATA>/all/cmd
    for node in ("65C1D12C", "4AC61A7F", "FD700369"):
        assert [h["command"] for h in store.history(node)] == ["region"]
    assert store.history(None) == []                                           # no broadcast line


def test_a_member_the_command_cannot_reach_is_reported_and_the_rest_still_go(api):
    _server, url, store = api
    store.update_device("4AC61A7F", ver="esp32s3-v1.17.1-ar-11-observer-90e86c88")   # ASCII only
    store.update_device("65C1D12C", ver="esp32s3-v1.17.1-lou-17-observer-1a2b3c4d")
    store.create_group("two", ["4AC61A7F", "65C1D12C"])
    job = run(url, "send", {"command": "set name Gräshagen", "group": "two", "confirm": True})
    lines = {o["node"]: o["line"] for o in job["outcomes"]}
    assert lines["4AC61A7F"].startswith("not sent:") and "lou-17" in lines["4AC61A7F"]
    assert lines["65C1D12C"].startswith("refused")
    assert store.history("4AC61A7F") == [] and len(store.history("65C1D12C")) == 1


def test_the_command_line_makes_lists_and_sends_to_a_group(api, capsys):
    _server, url, store = api
    assert cli.main(["--api", url, "groups"]) == 0
    assert "no groups yet" in capsys.readouterr().out
    assert cli.main(["--api", url, "group", "create", "canary", "gisebo"]) == 0
    assert cli.main(["--api", url, "group", "add", "canary", "65C1D12C", "far"]) == 0
    assert cli.main(["--api", url, "group", "remove", "canary", "far"]) == 0
    assert cli.main(["--api", url, "group", "add", "canary", "nobody"]) == 1
    assert "no device matches 'nobody'" in capsys.readouterr().err
    assert cli.main(["--api", url, "groups"]) == 0
    out = capsys.readouterr().out
    assert "canary (2)" in out and "Gisebo" in out and "Far" not in out.split("canary (2)")[-1]
    assert cli.main(["--api", url, "group", "send", "canary", "region"]) == 1      # one refused
    out = capsys.readouterr().out
    assert "Gisebo             > * F" in out and "refused: not-allowed" in out
    assert out.rstrip().endswith("canary: 2 of 2 sent; 1 ok, 1 refused, 0 no answer")
    assert cli.main(["--api", url, "group", "send", "canary", "ver", "--dry-run"]) == 0
    assert "would publish to meshcore/JKG/4AC61A7F/cmd" in capsys.readouterr().out
    assert cli.main(["--api", url, "group", "delete", "canary"]) == 0
    assert store.group("canary") is None and len(store.devices()) == 3
    assert cli.main(["--api", url, "group", "send", "canary", "ver"]) == 1
    assert "no group named canary" in capsys.readouterr().err
