"""The login to the command server: one throwaway key kept some hours beside the store, one
connection for a run of commands, and a refusal said with its likely cause. The server admits
only so many new login keys an hour and new connections a minute from one address. A FAKE
broker stands in; nothing here opens a real one."""
import json
import stat
import types

import pytest

from mccontrol import actions, envelope, mcc3, plane, rekey, store as _store, transport
from test_plane import NODE, NODE_SEED, OWNER_SEED, STRANGER, STRANGER_SEED, FakeBroker, broker, store  # noqa: F401


class Counting(FakeBroker):
    """Counts connections; refuses the login keys named in `refuse` (or every one with `all`);
    plays both nodes."""

    opened, closed, refuse, down = 0, 0, set(), False

    def loop_start(self):
        Counting.opened += 1
        user = FakeBroker.logins[-1][0]
        if Counting.refuse == "all" or user in Counting.refuse:
            return self.on_connect(self, None, None, NotAuthorized())
        self.on_connect(self, None, None, types.SimpleNamespace(is_failure=False))

    def is_connected(self):
        return not Counting.down

    def disconnect(self):
        Counting.closed += 1

    def publish(self, topic, payload, qos=0, retain=False):
        FakeBroker.published.append((topic, payload))
        seed = {NODE: NODE_SEED, STRANGER: STRANGER_SEED}[mcc3.node_from_topic(topic)]
        owner = envelope.public_key_hex(OWNER_SEED)
        cmd = mcc3.open_command(seed, owner, payload)
        res = mcc3.seal_result(mcc3.node_keys(seed, owner), cmd["counter"], 0, 0, cmd["command"], "> ok")
        self.on_message(self, None, types.SimpleNamespace(topic=mcc3.reply_topic(cmd["rid"]), payload=res.encode()))
        return types.SimpleNamespace(wait_for_publish=lambda timeout=0: None)


class NotAuthorized:
    is_failure = True

    def __str__(self):
        return "Not authorized"


@pytest.fixture
def counting(broker, monkeypatch):
    Counting.opened, Counting.closed, Counting.refuse, Counting.down = 0, 0, set(), False
    monkeypatch.setattr(transport, "_client", Counting)
    monkeypatch.setattr(actions, "pause", lambda *a, **k: 0)
    return Counting


@pytest.fixture
def two(store):
    for name, key in (("Bench", NODE), ("Far", STRANGER)):
        store.add_device(name, key, "", key=key)
        store.update_device(key[:8], alive={"state": "online", "region": "se-jkp"})
    return store


def kept(store):
    return json.loads((store.root / _store.LOGIN_FILE).read_text())


def test_the_login_key_is_kept_private_between_commands_and_is_not_the_command_key(two, counting):
    for _ in range(3):
        plane.new_session()                         # as a new process would be
        actions.send(two, "get name", device=two.device("bench"))
    users = {u for u, _pw in counting.logins}
    assert len(users) == 1
    path = two.root / _store.LOGIN_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert users == {"v1_" + envelope.public_key_hex(kept(two)["seed"])}
    assert kept(two)["seed"] != OWNER_SEED and envelope.public_key_hex(OWNER_SEED) not in path.read_text()


def test_a_login_key_older_than_six_hours_is_replaced(store):
    first, new = store.login_seed(now=1_000_000)
    assert new and store.login_seed(now=1_000_000 + _store.LOGIN_KEEP_SECS - 1) == (first, False)
    second, new = store.login_seed(now=1_000_000 + _store.LOGIN_KEEP_SECS)
    assert new and second != first and kept(store) == {"seed": second, "created": 1_000_000 + _store.LOGIN_KEEP_SECS}


@pytest.mark.parametrize("spoil", ["readable", "damaged", "future"])
def test_a_login_file_others_can_read_or_that_is_damaged_is_replaced(store, spoil):
    first, _new = store.login_seed(now=1_000_000)
    path = store.root / _store.LOGIN_FILE
    if spoil == "readable":
        path.chmod(0o644)
    elif spoil == "damaged":
        path.write_text('{"seed": "zz", "created": 1000000}')
    else:
        path.write_text(json.dumps({"seed": first, "created": 2_000_000}))
    second, new = store.login_seed(now=1_000_001)
    assert new and second != first and stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_kept_key_the_server_refuses_is_replaced_once(two, counting):
    old, _new = two.login_seed()
    counting.refuse = {"v1_" + envelope.public_key_hex(old)}
    _t, _p, answers, _l = actions.send(two, "get name", device=two.device("bench"))
    assert list(answers) == [NODE[:8]] and counting.opened == 2
    assert kept(two)["seed"] != old and counting.logins[-1][0] == "v1_" + envelope.public_key_hex(kept(two)["seed"])


def test_a_refused_login_says_the_likely_cause_and_sends_nothing(two, counting):
    two.login_seed()
    counting.refuse = "all"
    with pytest.raises(transport.BrokerError) as said:
        actions.send(two, "get name", device=two.device("bench"))
    text = str(said.value)
    assert "not authorized" in text and "too many new logins from this address in the last hour" in text
    assert "Wait" in text and "broker.invalid" in text
    assert counting.opened == 2 and not counting.published      # the kept key, one new key, and no third


def test_another_refusal_is_not_given_that_cause(two, counting, monkeypatch):
    monkeypatch.setattr(NotAuthorized, "__str__", lambda self: "Server unavailable")
    counting.refuse = "all"
    with pytest.raises(transport.BrokerError, match="refused the connection: Server unavailable"):
        actions.send(two, "get name", device=two.device("bench"))
    assert counting.opened == 1


def test_an_area_act_is_one_connection_for_all_its_nodes(two, counting):
    _t, _p, answers, _l = actions.send(two, "get name", county="se-jkp")
    assert len(answers) == 2 and len(counting.published) == 2
    assert counting.opened == 1 and counting.closed == 1


def test_a_set_of_commands_and_a_refresh_are_one_connection_each(two, counting):
    lines, stopped = actions.run_set(two, ["get name", "ver", "get radio"], device=two.device("bench"))
    assert stopped is None and (counting.opened, counting.closed) == (1, 1)
    actions.refresh_names(two, two.devices())
    assert len(counting.published) == 3 + 4 and (counting.opened, counting.closed) == (2, 2)


def test_single_commands_outside_a_run_open_and_close_one_each(two, counting):
    for _ in range(2):
        actions.send(two, "get name", device=two.device("bench"))
    assert (counting.opened, counting.closed) == (2, 2)


def test_a_run_dials_again_when_its_connection_dropped_and_closes_after_an_error(two, counting):
    with plane.run():
        actions.send(two, "get name", device=two.device("bench"))
        counting.down = True
        actions.send(two, "get name", device=two.device("far"))
        assert (counting.opened, counting.closed) == (2, 1)
    assert counting.closed == 2
    counting.down = False
    with pytest.raises(RuntimeError):
        with plane.run():
            actions.send(two, "get name", device=two.device("bench"))
            raise RuntimeError("stop")
    assert (counting.opened, counting.closed) == (3, 3)
    actions.send(two, "get name", device=two.device("bench"))       # the run is over: its own connection
    assert (counting.opened, counting.closed) == (4, 4)


def test_a_job_of_the_api_is_one_connection(two, counting):
    from mccontrol.api import jobs
    registry = jobs.Registry()
    job = registry.start("send", lambda job: [actions.send(two, "get name", device=d)[3] for d in two.devices()])
    for _ in range(200):
        if job.snapshot()["status"] != "running" and counting.closed:
            break
        import time
        time.sleep(0.01)
    assert job.snapshot()["status"] == "done" and (counting.opened, counting.closed) == (1, 1)


def test_a_key_rotation_of_every_node_is_one_connection(two, counting, monkeypatch):
    monkeypatch.setenv("MCCONTROL_HOME", str(two.root))
    seen = []
    monkeypatch.setattr(rekey, "rotate", lambda store, d, **kw: (
        seen.append(actions.send(store, "ver", device=d)), (rekey.NEW, [d["name"]]))[1])
    monkeypatch.setattr(rekey, "status", lambda store: [(d, rekey.OLD) for d in store.devices()])
    assert rekey.main(["send", "--all"]) == 0
    assert len(seen) == 2 and (counting.opened, counting.closed) == (1, 1)
