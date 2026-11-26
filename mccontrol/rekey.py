"""Replacing the command key without visiting the nodes (lou-20 and later, `rekey`).

A node takes `rekey <new public key>` signed by the key in use; the new key then waits there
for an hour and takes over when a command it signed arrives. So a rotation is, per node: offer
the new key with the old one, then confirm with the new one. Until every node has followed, the
store holds both keys: `key.seed` (in use here) and `key.next.seed`.

    start(store)                    make the next key (or take a seed); nothing is sent
    rotate(store, device, ...)      offer and confirm on one node: (state, lines)
    status(store)                   [(device, state)]: old | offered | new | cannot
    finish(store, leave_behind)     the next key becomes the store's key; the old one is kept beside it
    abort(store)                    forget the next key, only while no node has taken it

Run it as `python -m mccontrol.rekey start | send <device> | send --all | status | finish | abort`.
It is its own program, beside `mccontrol`, because it works on the store's two keys directly.

Order matters with relays: a node that is reached through a relay is rotated before that relay,
or the relay no longer serves the old key's forwards. `rotate` handles the mixed case anyway: the
relay hop is made with whichever key that relay is on.
"""
import argparse
import base64
import datetime
import os
import sys

from . import actions, envelope, firmware, mcc3, mesh, plane, store as _store, transport

NEXT = "key.next.seed"
STATE = "rekey.json"
OLD, OFFERED, NEW, CANNOT = "old", "offered", "new", "cannot"
CONFIRM_COMMAND = "ver"


class RekeyError(Exception):
    pass


class _NextStore(_store.Store):
    """The same store, signing with the next key: devices, counters and history are shared, the
    shared-secret cache is per key already."""

    @property
    def key_path(self):
        return self.root / NEXT


def next_store(store):
    return _NextStore(store.root)


def started(store):
    return (store.root / NEXT).is_file()


def _states(store):
    return dict(store._read_json(store.root / STATE, {}))


def _set_state(store, node, state):
    states = _states(store)
    states[node] = state
    store._write_json(store.root / STATE, states)


def key_text(public_hex):
    """A public key as `rekey` takes it: 43 base64url characters."""
    return base64.urlsafe_b64encode(bytes.fromhex(public_hex)).decode().rstrip("=")


def start(store, seed_hex=None):
    """Make the next key, or take `seed_hex`. Returns its public key. Nothing is sent."""
    if started(store):
        raise RekeyError("a key rotation is already under way: python -m mccontrol.rekey status")
    seed = (seed_hex or envelope.generate_seed()).strip()
    public = envelope.public_key_hex(seed)          # validates before anything is written
    if public.upper() == store.public_key().upper():
        raise RekeyError("that is the key in use")
    store._write_private(store.root / NEXT, seed + "\n")
    store._write_json(store.root / STATE, {})
    return public


def why_not(device):
    """Why this node cannot be rotated from here, or None."""
    if not envelope.node_key(device.get("key") or ""):
        return "its whole public key is not known"
    rev = firmware.revision(device.get("ver"))
    if rev is None:
        return "its firmware version is not known: read it first (mccontrol refresh)"
    if rev < firmware.REKEY_FROM or not firmware.has(device.get("ver"), "rc"):
        return f"its firmware has no rekey (lou-{firmware.REKEY_FROM} and later): set the key over USB"
    return None


def status(store):
    if not started(store):
        raise RekeyError("no key rotation is under way: python -m mccontrol.rekey start")
    states = _states(store)
    return [(d, CANNOT if why_not(d) else states.get(d["node"], OLD)) for d in store.devices()]


def _signer(store, device):
    """The store that signs for `device` now: the next key once the node has taken it."""
    return next_store(store) if _states(store).get(device["node"]) == NEW else store


def _send(store, signer, command, device, via="mqtt", relay=None, route="direct", path=None, wait_secs=None):
    """One command to `device` signed by `signer`'s key: (answered, text). Through a relay the hop
    is sealed with the key that relay is on, which may differ from the signer's."""
    if via != "relay":
        _t, _p, results, lines = actions.send(signer, command, device=device, via=via, wait_secs=wait_secs)
        r = results.get(device["node"])
        return (r is not None and r.ok), next(l for l in reversed(lines) if not l.startswith(" "))   # not the advice under it
    if relay is None:
        raise RekeyError("name the relay")
    hop = _signer(store, relay)
    relay_key, key = actions._whole_key(relay), actions._whole_key(device)
    path_len, hops = (0, b"") if route != "direct" or path in (None, "none") else actions.relay_path(path)
    flags = mcc3.FLAG_ZERO_HOP if route == "direct" and not path_len & 63 else 0
    keys = signer.owner_keys(key)
    counter = signer.next_counter(device["node"])
    body = mesh.build_mcc3(signer.seed(), key, counter, command, keys=keys, flags=flags)
    forward_counter = hop.next_forward_counter(relay["node"])
    relay_keys = hop.owner_keys(relay_key)
    payload = plane.forward_payload(relay_keys, relay_key, forward_counter, key, mcc3.ROUTES.index(route), body,
                                    path_len=path_len, path=hops)
    _topic, got = plane.forward(hop.config(), relay_key, relay_keys, payload, forward_counter,
                                wait_secs=wait_secs or plane.FORWARD_WAIT_SECS, store=hop)
    if got is None:
        return False, "the relay said nothing"
    if got["status"] != mcc3.FORWARD_ANSWERED:
        return False, f"the relay says {mcc3.FORWARD_STATUSES[got['status']]}"
    result = mesh.parse_mcc3(keys, got["response"], device["node"], command, counter)
    if result is None:
        return False, "an answer came that does not open with this key"
    return result.ok, result.reply or actions.outcome_line(result, device.get("ver"))


def rotate(store, device, via="mqtt", relay=None, route="direct", path=None, wait_secs=None, send=_send):
    """Offer the next key to `device` with the key it has, then confirm with the next key.
    Returns `(state, lines)`. A node that already took the key is only confirmed again."""
    if not started(store):
        raise RekeyError("no key rotation is under way: python -m mccontrol.rekey start")
    why = why_not(device)
    if why:
        raise RekeyError(f"{device.get('name') or device['node']}: {why}")
    new = next_store(store)
    name = device.get("name") or device["node"]
    lines = []
    state = _states(store).get(device["node"], OLD)
    kw = dict(via=via, relay=relay, route=route, path=path, wait_secs=wait_secs)
    if state != NEW:
        ok, text = send(store, store, f"rekey {key_text(new.public_key())}", device, **kw)
        lines.append(f"{name}: offered with the key in use: {text}")
        if not ok:
            return state, lines + [f"{name}: not offered; it keeps the key in use"]
        _set_state(store, device["node"], OFFERED)
        state = OFFERED
    ok, text = send(store, new, CONFIRM_COMMAND, device, **kw)
    lines.append(f"{name}: confirmed with the next key: {text}")
    if ok:
        _set_state(store, device["node"], NEW)
        return NEW, lines + [f"{name}: on the next key"]
    return state, lines + [f"{name}: no answer under the next key. It waits there 60 minutes, or until the node "
                           f"restarts; run this again. The key in use still works on this node."]


def finish(store, leave_behind=False):
    """The next key becomes the store's key. The replaced seed is kept beside it. Returns
    `(public, kept_path, left)`, `left` the nodes still on the replaced key."""
    left = [d for d, s in status(store) if s != NEW]
    waiting = [d for d in left if not why_not(d)]
    if waiting and not leave_behind:
        names = ", ".join(d.get("name") or d["node"] for d in waiting)
        raise RekeyError(f"still on the key in use: {names}. Rotate them, or finish with --leave-behind "
                         f"(they then answer only the replaced key, kept in the store's folder)")
    if not any(s == NEW for _d, s in status(store)) and not leave_behind:
        raise RekeyError("no node has taken the next key; nothing to finish (python -m mccontrol.rekey abort forgets it)")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    kept = store.root / f"key.replaced-{stamp}.seed"
    os.replace(store.key_path, kept)
    os.replace(store.root / NEXT, store.key_path)
    os.chmod(kept, 0o600)
    (store.root / STATE).unlink(missing_ok=True)
    for d in store.devices():                       # the alive kept here was sealed to the replaced key
        if d.get("alive"):
            store.update_device(d["node"], alive=None)
    return store.public_key(), kept, left


def abort(store):
    if not started(store):
        raise RekeyError("no key rotation is under way")
    taken = [d.get("name") or d["node"] for d, s in status(store) if s == NEW]
    if taken:
        raise RekeyError(f"{', '.join(taken)} already took the next key: finish the rotation, or rotate "
                         f"those nodes back first")
    (store.root / NEXT).unlink()
    (store.root / STATE).unlink(missing_ok=True)

def _road(text):
    if text in ("mqtt", "mesh") or (text.startswith("relay:") and text[6:].strip()):
        return text
    raise argparse.ArgumentTypeError("mqtt, mesh or relay:DEVICE")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m mccontrol.rekey", description="Replace your signing key on your nodes "
                                "without visiting them (lou-20 and later).")
    p.add_argument("action", choices=("start", "send", "status", "finish", "abort"))
    p.add_argument("device", nargs="?", help="send: the node to rotate")
    p.add_argument("--all", action="store_true", help="send: every node of yours on MQTT that can, one after another")
    p.add_argument("--via", type=_road, default="mqtt", metavar="{mqtt,mesh,relay:DEVICE}", help="send: the road")
    p.add_argument("--route", choices=("direct", "flood", "flood-wide"), default="direct", help="send, with a relay")
    p.add_argument("--path", metavar="HEX", help="send, with a relay and the direct route: the hops, or none")
    p.add_argument("--seed-file", help="start: take the next key from this file (a bare seed) instead of making one")
    p.add_argument("--leave-behind", action="store_true", help="finish although some nodes are still on the key in use")
    args = p.parse_args(argv)
    store = _store.Store()
    name = lambda d: d.get("name") or d["node"]
    try:
        if args.action == "start":
            seed = open(args.seed_file, encoding="utf-8").read().strip() if args.seed_file else None
            public = start(store, seed)
            print(f"the next key: {public}")
            print("Nothing is sent yet. Rotate the nodes reached through a relay first, the relays last:")
            print("  python -m mccontrol.rekey send <device> [--via relay:<relay> | --via mesh]     one node")
            print("  python -m mccontrol.rekey send --all                                          every node on MQTT")
            print("  python -m mccontrol.rekey status, then: python -m mccontrol.rekey finish")
            return 0
        if args.action == "status":
            words = {OLD: "on the key in use", OFFERED: "offered, not confirmed", NEW: "on the next key"}
            for d, s in status(store):
                print(f"{name(d)[:20]:20} {words.get(s) or 'cannot: ' + why_not(d)}")
            return 0
        if args.action == "send":
            if args.all:
                devices = [d for d, s in status(store) if s != CANNOT and not firmware.device_mesh_only(d)]
                via, relay = "mqtt", None
            else:
                d = store.device(args.device or "")
                if d is None:
                    raise RekeyError("name the node, or --all")
                devices = [d]
                via, relay = args.via, None
                if via.startswith("relay:"):
                    relay = store.device(via[6:].strip())
                    if relay is None:
                        raise RekeyError(f"no such relay: {via[6:]}")
                    via = "relay"
            bad = 0
            with plane.run():           # one connection for every node
                for d in devices:
                    state, lines = rotate(store, d, via=via, relay=relay, route=args.route, path=args.path)
                    print("\n".join(lines))
                    bad += state != NEW
            return 1 if bad else 0
        if args.action == "finish":
            public, kept, left = finish(store, leave_behind=args.leave_behind)
            print(f"the key in use is now {public}")
            print(f"the replaced key is kept at {kept}")
            if left:
                print("still on the replaced key: " + ", ".join(name(d) for d in left))
            print("register it with the command server if you use the old scheme too: mccontrol register")
            return 0
        abort(store)
        print("the next key is forgotten; nothing was changed on any node")
        return 0
    except (RekeyError, _store.StoreError, envelope.EnvelopeError, transport.BrokerError, mesh.MeshError) as exc:
        print(f"mccontrol: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
