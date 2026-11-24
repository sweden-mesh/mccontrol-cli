"""Key rotation (`mccontrol rekey`): the store's side. The wire is the firmware's and the bench's."""
import base64
import stat

import pytest

from mccontrol import envelope, rekey, store as st

A = "A1" * 32
B = "B2" * 32
LOU20 = "esp32s3-v1.18.0-lou-20-arrc-observer-1a2b3c4d"
LOU20_MESH = "nrf52840-v1.18.0-lou-20-rc-1a2b3c4d"
LOU19 = "esp32s3-v1.18.0-lou-19-arrc-observer-1a2b3c4d"


@pytest.fixture
def store(tmp_path):
    s = st.Store(tmp_path)
    s.create_key()
    for name, key, ver in (("relay", A, LOU20), ("solar", B, LOU20_MESH), ("old", "C3" * 32, LOU19), ("unread", "D4" * 32, None)):
        s.add_device(name, key, "", key=key)
        if ver:
            s.update_device(key[:8], ver=ver)
    return s


def scripted(answers):
    """send(): answers by (signer is the next key, command's first word, node) -> ok"""
    sent = []

    def send(store, signer, command, device, **kw):
        nxt = signer.key_path.name == rekey.NEXT
        sent.append((nxt, command, device["name"], kw.get("via"), (kw.get("relay") or {}).get("name")))
        ok = answers.get((nxt, command.split()[0], device["name"]), True)
        return ok, "OK" if ok else "no answer"
    return send, sent


def test_start_makes_a_second_key_and_sends_nothing(store):
    in_use = store.public_key()
    public = rekey.start(store)
    assert public != in_use and store.public_key() == in_use
    path = store.root / rekey.NEXT
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert rekey.next_store(store).public_key() == public
    assert len(rekey.key_text(public)) == 43
    assert base64.urlsafe_b64decode(rekey.key_text(public) + "=").hex().upper() == public.upper()
    with pytest.raises(rekey.RekeyError):
        rekey.start(store)


def test_start_refuses_the_key_in_use(store):
    with pytest.raises(rekey.RekeyError, match="in use"):
        rekey.start(store, store.seed())


def test_a_node_is_offered_with_the_old_key_and_confirmed_with_the_next(store):
    public = rekey.start(store)
    send, sent = scripted({})
    state, lines = rekey.rotate(store, store.device("relay"), send=send)
    assert state == rekey.NEW
    assert sent == [(False, f"rekey {rekey.key_text(public)}", "relay", "mqtt", None), (True, "ver", "relay", "mqtt", None)]
    assert dict((d["name"], s) for d, s in rekey.status(store)) == {
        "relay": rekey.NEW, "solar": rekey.OLD, "old": rekey.CANNOT, "unread": rekey.CANNOT}


def test_an_offer_that_is_not_confirmed_stays_offered_and_is_tried_again(store):
    rekey.start(store)
    send, sent = scripted({(True, "ver", "solar"): False})
    state, lines = rekey.rotate(store, store.device("solar"), via="relay", relay=store.device("relay"), send=send)
    assert state == rekey.OFFERED and "still works" in lines[-1]
    send, sent = scripted({})
    assert rekey.rotate(store, store.device("solar"), via="relay", relay=store.device("relay"), send=send)[0] == rekey.NEW
    assert [s[1].split()[0] for s in sent] == ["rekey", "ver"], "offered again: the node may have restarted"


def test_an_offer_the_node_refuses_changes_nothing(store):
    rekey.start(store)
    send, sent = scripted({(False, "rekey", "relay"): False})
    state, lines = rekey.rotate(store, store.device("relay"), send=send)
    assert state == rekey.OLD and len(sent) == 1


def test_a_node_already_on_the_next_key_is_only_confirmed(store):
    rekey.start(store)
    send, sent = scripted({})
    rekey.rotate(store, store.device("relay"), send=send)
    del sent[:]
    rekey.rotate(store, store.device("relay"), send=send)
    assert [s[1] for s in sent] == ["ver"]


def test_older_firmware_and_unread_nodes_are_refused_with_the_reason(store):
    rekey.start(store)
    with pytest.raises(rekey.RekeyError, match="over USB"):
        rekey.rotate(store, store.device("old"), send=scripted({})[0])
    with pytest.raises(rekey.RekeyError, match="not known"):
        rekey.rotate(store, store.device("unread"), send=scripted({})[0])


def test_finish_waits_for_every_node_that_can_and_keeps_the_replaced_key(store):
    in_use, seed = store.public_key(), store.seed()
    public = rekey.start(store)
    send, _ = scripted({})
    rekey.rotate(store, store.device("relay"), send=send)
    with pytest.raises(rekey.RekeyError, match="solar"):
        rekey.finish(store)
    rekey.rotate(store, store.device("solar"), via="relay", relay=store.device("relay"), send=send)
    now, kept, left = rekey.finish(store)
    assert now == public and store.public_key() == public
    assert kept.read_text().strip() == seed and stat.S_IMODE(kept.stat().st_mode) == 0o600
    assert sorted(d["name"] for d in left) == ["old", "unread"]
    assert not rekey.started(store)
    assert envelope.public_key_hex(kept.read_text().strip()) == in_use


def test_finish_can_leave_nodes_behind_when_told_to(store):
    rekey.start(store)
    rekey.rotate(store, store.device("relay"), send=scripted({})[0])
    _now, _kept, left = rekey.finish(store, leave_behind=True)
    assert "solar" in [d["name"] for d in left]


def test_finish_with_no_node_rotated_is_refused(store):
    rekey.start(store)
    with pytest.raises(rekey.RekeyError):
        rekey.finish(store)


def test_abort_only_while_no_node_took_the_key(store):
    in_use = store.public_key()
    rekey.start(store)
    rekey.abort(store)
    assert not rekey.started(store) and store.public_key() == in_use
    rekey.start(store)
    rekey.rotate(store, store.device("relay"), send=scripted({})[0])
    with pytest.raises(rekey.RekeyError, match="already took"):
        rekey.abort(store)


def test_through_a_relay_the_hop_uses_the_key_the_relay_is_on(store):
    rekey.start(store)
    assert rekey._signer(store, store.device("relay")).key_path.name == "key.seed"
    rekey.rotate(store, store.device("relay"), send=scripted({})[0])
    assert rekey._signer(store, store.device("relay")).key_path.name == rekey.NEXT
