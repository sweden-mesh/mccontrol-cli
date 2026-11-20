"""mcc3 on the broker: a sealed command to one node, its sealed result, and the alive scan.

The plane of lou-20 and later (IATA-2), keyed by the node alone and sealed to the owner
(`mcc3`). No IATA, no region, no broadcast: a command goes to `mcc/cmd/<KEY>` of one node,
its result comes back on `mcc/r/<RID>`, a reply topic named only inside the sealed command,
and the owner finds its nodes by opening the retained `mcc/alive/<KEY>` messages.

The command key signs and seals; it never touches the broker. The broker login is a
throwaway key drawn once per session (this process), as is the RID, so the broker sees
neither the owner nor which session belongs to whom (RC-ALIVE decision 6). The broker takes
`mcc/cmd` only on its TLS listener.
"""

import threading
import time

from . import envelope, mcc3, transport

_session = None
_session_lock = threading.Lock()


def session():
    """`{seed, rid}`: the throwaway broker login and the reply id, drawn once per process."""
    global _session
    with _session_lock:
        if _session is None:
            _session = {"seed": envelope.generate_seed(), "rid": mcc3.new_rid()}
        return _session


def new_session():
    """Forget the session: the next connection draws a new login key and RID."""
    global _session
    with _session_lock:
        _session = None


def _login_config(config):
    """The configuration for a plane connection: a token login with the throwaway key, never
    the password-file pair (the broker gives such a login nothing under `mcc/`)."""
    return dict(config, username="", password="")


def _connect(config, client_factory=None):
    s = session()
    cfg = _login_config(config)
    client = (client_factory or transport._client)(cfg, s["seed"])
    return client, cfg, s


def send(config, seed_hex, node_key_hex, command, counter, keys=None, wait_secs=20.0, ttl_secs=None,
         progress=None, script=None, client_factory=None, now=None):
    """Seal `command` for the node with `node_key_hex`, publish it on `mcc/cmd/<KEY>` and wait
    for its sealed result on this session's RID. Returns `(topic, payload, {node: Result})`;
    a missing node is silence. The result opens only under K_cmd, which only the node and
    the owner hold, so an answer that opens is the node's own (`verified` True)."""
    if not config.get("tls"):
        raise transport.BrokerError("the mcc/ plane takes commands on the broker's TLS listener only: "
                                    "mccontrol config --tls on --port 8883")
    key = envelope.node_key(node_key_hex)
    node = key[:envelope.NODE_HEX_LEN]
    keys = keys or mcc3.owner_keys(seed_hex, key)
    s = session()
    ttl = ttl_secs or config.get("ttl_secs", envelope.DEFAULT_TTL_SECS)
    expiry = int(time.time() if now is None else now) + int(ttl)
    try:
        payload = mcc3.seal_command(seed_hex, key, counter, expiry, s["rid"], command, keys=keys)
    except mcc3.Mcc3Error as exc:
        raise envelope.EnvelopeError(str(exc)) from None
    topic = mcc3.command_topic(key)
    faked = transport._fake(topic, command, counter, [node], script)
    if faked is not None:
        transport._wait(transport.FAKE_WAIT_SECS, lambda: False, lambda: list(faked), progress)
        return topic, payload, faked
    reply = mcc3.reply_topic(s["rid"])
    answers = {}
    done = threading.Event()

    def on_message(_c, _u, msg):
        if msg.topic != reply:
            return
        try:
            r = mcc3.open_result(keys, msg.payload)
        except mcc3.Refused:
            return                      # another node's answer on this RID, or altered
        if r["counter"] != counter:
            return
        answers[node] = envelope.Result(node, counter, r["code"], r["command"] or command, r["reply"], True)
        done.set()

    client, cfg, s = _connect(config, client_factory)
    client.on_message = on_message
    transport._connect(client, cfg, seed_hex=s["seed"])
    try:
        client.subscribe(reply, qos=1)
        info = client.publish(topic, payload, qos=1)
        info.wait_for_publish(timeout=10)
        transport._wait(wait_secs, done.is_set, lambda: list(answers), progress)
    finally:
        client.loop_stop()
        client.disconnect()
    return topic, payload, dict(answers)


# -- a forward through a relay ---------------------------------------------------------------

# A relay refuses an expiry more than 300 s ahead of its own clock; half of that leaves room
# for two clocks that disagree.
FORWARD_TTL_SECS = 150
# The relay waits 120 s for the target's answer before it says no-answer.
FORWARD_WAIT_SECS = 135.0


def forward_payload(relay_keys, relay_key_hex, counter, target_key_hex, route, body, path_len=0, path=b"",
                    ttl_secs=FORWARD_TTL_SECS, now=None):
    """The sealed forward for `mcc/cmd/<RELAY KEY>`, its result named to this session's RID."""
    expiry = int(time.time() if now is None else now) + min(int(ttl_secs), FORWARD_TTL_SECS)
    try:
        return mcc3.seal_forward(relay_keys, relay_key_hex, counter, expiry, session()["rid"], target_key_hex,
                                 route, body, path_len=path_len, path=path)
    except mcc3.Mcc3Error as exc:
        raise envelope.EnvelopeError(str(exc)) from None


def forward(config, relay_key_hex, relay_keys, payload, counter, wait_secs=FORWARD_WAIT_SECS, progress=None,
            client_factory=None):
    """Publish a sealed forward (`forward_payload`) on the relay's `mcc/cmd/<KEY>` and wait for
    its result on this session's RID. Returns `(topic, result)`: what `mcc3.open_forward_result`
    gives under the relay's K_fwd for this forward counter, or None when the relay said
    nothing. A result that opens is the relay's own word; the answer inside is still sealed
    to the target's owner."""
    if not config.get("tls"):
        raise transport.BrokerError("the mcc/ plane takes commands on the broker's TLS listener only: "
                                    "mccontrol config --tls on --port 8883")
    topic = mcc3.command_topic(relay_key_hex)
    reply = mcc3.reply_topic(session()["rid"])
    got = []
    done = threading.Event()

    def on_message(_c, _u, msg):
        if msg.topic != reply:
            return
        try:
            r = mcc3.open_forward_result(relay_keys, msg.payload)
        except mcc3.Refused:
            return                      # a command's result, another relay's, or altered
        if r["counter"] != counter:
            return
        got.append(r)
        done.set()

    client, cfg, s = _connect(config, client_factory)
    client.on_message = on_message
    transport._connect(client, cfg, seed_hex=s["seed"])
    try:
        client.subscribe(reply, qos=1)
        info = client.publish(topic, payload, qos=1)
        info.wait_for_publish(timeout=10)
        transport._wait(wait_secs, done.is_set, lambda: [], progress)
    finally:
        client.loop_stop()
        client.disconnect()
    return topic, got[0] if got else None


# -- alive -----------------------------------------------------------------------------------

def open_alive(seed_hex, cache, key, payload):
    """`(state, fields)` for one alive message: `("ours", fields)` when it opens under our
    command key, `("empty", None)` for the will (the node went offline), `("foreign", None)`
    when it does not open (another owner's node, or altered). `cache` maps node KEY to S hex
    and gains the S of a key not seen before (~1 ms of X25519; every later open ~10 us)."""
    if not payload:
        return "empty", None
    secret = cache.get(key)
    if secret is None:
        secret = cache[key] = mcc3.shared_secret(seed_hex, key).hex()
    try:
        return "ours", mcc3.open_alive(mcc3.derive(bytes.fromhex(secret), key), payload)
    except mcc3.Refused:
        return "foreign", None


def newer(fields, than):
    """Does an alive with `fields` replace one with `than`? A higher (boot, sequence) wins;
    anything lower is stale, a replay by the broker."""
    if not than:
        return True
    return (fields["boot"], fields["sequence"]) > (than.get("boot", -1), than.get("sequence", -1))


def scan(config, seed_hex, cache, wait_secs=10.0, progress=None, client_factory=None):
    """Subscribe `mcc/alive/+` and read the retained snapshot (and any live update) for
    `wait_secs`. Returns `{KEY: (state, fields, received_at)}`, the newest per node, states
    as `open_alive`. Reads only: nothing is published."""
    seen = {}
    lock = threading.Lock()
    refused = []

    def on_message(_c, _u, msg):
        key = mcc3.node_from_topic(msg.topic)
        if not key or not msg.topic.startswith(f"{mcc3.TOPIC_ROOT}alive/"):
            return
        state, fields = open_alive(seed_hex, cache, key, msg.payload)
        with lock:
            old = seen.get(key)
            if state == "ours" and old and old[0] == "ours" and not newer(fields, old[1]):
                return
            seen[key] = (state, fields, time.time())

    def on_subscribe(_c, _u, _mid, codes, _props=None):
        refused.extend(str(c) for c in codes
                       if (c.is_failure if hasattr(c, "is_failure") else int(c) >= 128))

    client, cfg, s = _connect(config, client_factory)
    client.on_message = on_message
    client.on_subscribe = on_subscribe
    transport._connect(client, cfg, seed_hex=s["seed"])
    try:
        client.subscribe(mcc3.ALIVE_FILTER, qos=1)
        transport._wait(wait_secs, lambda: bool(refused),
                        lambda: [k for k, v in list(seen.items()) if v[0] == "ours"], progress)
    finally:
        client.loop_stop()
        client.disconnect()
    if refused:
        raise transport.BrokerError(f"{config['broker']} refused the subscription to {mcc3.ALIVE_FILTER}: "
                                    f"{', '.join(refused)}")
    return seen
