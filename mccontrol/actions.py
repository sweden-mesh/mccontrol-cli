"""What the screens and the command line both do, so they cannot disagree."""

import datetime
import os
import random
import time

from . import beacon, commands, denylist, envelope, firmware, mcc3, mesh, nodestats, plane, silence, store as _store, transport
from .store import _now as _store_now

# Commands that take something away from a repeater. Each is sent only after the person has
# been told what it does; the node itself does not second-guess a signed command.
CAUTIONS = (
    ("region denyf *", "stops this repeater forwarding every message that carries no scope. "
                       "It may be the only link between two places that rely on that."),
    ("region denyf", "stops this repeater forwarding that scope."),
    ("region remove", "deletes that region from the repeater. Messages scoped to it are dropped."),
    ("set autoreply off", "stops this repeater answering test requests."),
    # `set repeat off`, `erase` and `set cmd*` used to be here; the firmware's deny list of
    # 2026-10-08 refuses them outright (`denylist.py`), so there is nothing to ask.
    # Admitted since that list; each can take the node out of reach for a while or move
    # where it listens, so the person is told first.
    ("reboot", "restarts the node. It is off the air and off the control plane until it is back."),
    ("clkreboot", "restarts the node. It is off the air and off the control plane until it is back."),
    ("ota update", "downloads the newest signed firmware and restarts the node on it. It is off the air "
                   "for about a minute; if the new image never works, the node goes back to the old one."),
    ("set mqtt.iata", "moves the node to another region's topics: this tool must change its region to match."),
    ("set mqtt1*", "changes slot 1's broker or credentials; if the control plane rides this slot, it may go silent."),
    ("set mqtt2*", "changes slot 2's broker or credentials; if the control plane rides this slot, it may go silent."),
    ("set mqtt3*", "changes slot 3's broker or credentials; if the control plane rides this slot, it may go silent."),
    ("set mqtt4*", "changes slot 4's broker or credentials; if the control plane rides this slot, it may go silent."),
    ("set mqtt5*", "changes slot 5's broker or credentials; if the control plane rides this slot, it may go silent."),
    ("set mqtt6*", "changes slot 6's broker or credentials; if the control plane rides this slot, it may go silent."),
    ("set name", "renames the node as the whole mesh sees it in every advert."),
    # The mesh road's repair allowance (OTM-1): admitted over the mesh only.
    ("set wifi.ssid", "moves the node to another Wi-Fi network; a wrong one keeps it off MQTT "
                      "until the mesh road sets it again."),
    ("set wifi.pwd", "changes the Wi-Fi password the node uses; a wrong one keeps it off MQTT "
                     "until the mesh road sets it again."),
    ("set cmd on", "points the node's command slot at a broker; a wrong one keeps it off the "
                        "control plane until the mesh road sets it again."),
)


def caution(command):
    """A sentence saying what a command takes away, or None for a harmless one."""
    text = " ".join(command.lower().split())
    for prefix, why in CAUTIONS:
        if prefix.endswith("*") and not prefix.endswith(" *"):   # `set mqtt1*`: any setting of the slot
            if text.startswith(prefix[:-1]):
                return why
        elif text == prefix or text.startswith(prefix + " "):   # `region denyf *` is a literal star
            return why
    return None


def private_mismatch(store, device, command):
    """For `trigger private <key>`: a sentence when the asking node and the target speak
    different private-test sub-types -- 0xF0 from lou-14, 0x04 before it, no overlap -- so
    the request would go out and no answer could come back. None when they agree, or when
    either side's version is not known."""
    words = command.split()
    if device is None or len(words) < 3 or [w.lower() for w in words[:2]] != ["trigger", "private"]:
        return None
    key = words[2].upper()
    target = next((d for d in store.devices() if (d.get("key") or "").upper() == key), None)
    if target is None or not device.get("ver") or not target.get("ver"):
        return None
    ours, theirs = firmware.private_subtype(device["ver"]), firmware.private_subtype(target["ver"])
    if ours == theirs:
        return None
    return (f"{device['name'] or device['node']} sends the private test as 0x{ours:02X} and "
            f"{target['name'] or target['node']} answers only 0x{theirs:02X}: no answer will come "
            f"(0xF0 from lou-14, 0x04 before; flash the older one)")


def outcome_line(result, version=None):
    """One line describing a result, as the screens and the log show it. A not-allowed
    from a node whose firmware the table says admits the command is a finding -- the
    table or the version is wrong -- and is said as such rather than hidden."""
    if result is None:
        return "no answer"
    if result.verified is False:
        return "BAD SIGNATURE: the line on this node's result topic was not signed by its key -- forged or altered; reply ignored"
    tag = " [signed]" if result.verified else ""        # an r1 (older firmware) carries no mark
    if result.ok:
        return (result.reply or "OK") + tag
    line = f"refused: {result.code_name}" + tag
    if result.code == 14 and version and firmware.admits(version, result.command):
        line += f" [the table says {firmware.entry_for(version)[0]} admits this: the table or the version is wrong]"
    return line + (f" -- {result.help}" if result.help else "")


ROADS = ("mqtt", "mesh", "auto")


def _when(text):
    try:
        return datetime.datetime.fromisoformat(text).timestamp() if text else None
    except (TypeError, ValueError):
        return None


def mqtt_heard_at(store, device, now=None):
    """When the node was last heard over MQTT, as unix seconds, or None: its status on Beacon
    (asked now, a read that costs no airtime), else its last answer over MQTT, else the
    fleet's last-seen."""
    try:
        return beacon.stats(store, device, now=now)["sampled_at"]
    except beacon.BeaconError:
        pass
    seen = [_when(device.get("last_heard_mqtt")), _when((device.get("fleet") or {}).get("seen"))]
    if not device.get("last_heard_mesh") and not device.get("last_heard_relay"):
        seen.append(_when(device.get("last_heard")))      # from before roads were recorded: MQTT
    seen = [s for s in seen if s is not None]
    return max(seen) if seen else None


def road(store, device, command, via="mqtt", now=None):
    """`(road, why)`: which road a command to `device` (None: a broadcast) takes. `via` is
    the person's choice; `auto` is the mesh for a mesh-only node, for a command only the mesh
    admits, and for a node not heard over MQTT for `mesh_after_mins`; otherwise MQTT (and the
    mesh after all if the broker cannot be reached: `send` does that)."""
    via = (via or "mqtt").lower()
    if via not in ROADS:
        raise envelope.EnvelopeError(f"the road is one of {', '.join(ROADS)}")
    if device is None:
        if via == "mesh":
            raise envelope.EnvelopeError("the mesh road goes to one node at a time; a broadcast goes over MQTT")
        return "mqtt", ""
    if firmware.device_mesh_only(device):
        if via == "mqtt":
            raise envelope.EnvelopeError(f"{device.get('name') or device['node']} is mesh only (no Wi-Fi, "
                                         f"no MQTT); send it --via mesh")
        return "mesh", "mesh only"
    if via != "auto":
        return via, ""
    text = " ".join((command or "").split())
    if denylist.refusal(text) and denylist.mesh_refusal(text) is None:
        return "mesh", "only the mesh road admits it"
    mins = int(store.config().get("mesh_after_mins", 15))
    now = time.time() if now is None else now
    heard = mqtt_heard_at(store, device, now=now)
    if heard is not None and now - heard >= mins * 60:
        return "mesh", f"not heard over MQTT for {int((now - heard) // 60)} min"
    return "mqtt", ""


SCHEMES = ("mcc3", "old")


def scheme(device):
    """Which plane a node speaks (IATA-2 §7): `mcc3` when its alive opened under our key
    (and it has not since been rekeyed away) or its version is lou-20 or later; else `old`,
    the per-node IATA scheme of lou-19 and older (on its stored region). lou-20 takes both."""
    alive = (device or {}).get("alive") or {}
    if alive and alive.get("state") != "not-yours":
        return "mcc3"
    device = device or {}
    if firmware.speaks_mcc3(device.get("ver")):
        return "mcc3"
    # Added by its key, nothing read from it yet (a node without MQTT cannot say its version
    # before the first command reaches it) and no region to address the old scheme by: the old
    # scheme cannot be tried at all, so the first command goes the new way.
    if not alive and not device.get("ver") and envelope.node_key(device.get("key") or "") and not (device.get("region") or "").strip():
        return "mcc3"
    return "old"


def area_devices(store, region=None, county=None):
    """The devices an area act goes to, one command each: those in IATA `region` (the old
    scheme's region), or in `county`, a node's own `region home` from its alive (folded)."""
    if county:
        want = county.strip().lower()
        return [d for d in store.devices() if ((d.get("alive") or {}).get("region") or "").lower() == want]
    want = (region or "").strip().upper()
    return [d for d in store.devices() if (d.get("region") or "").upper() == want]


# An area act is one sealed command per node, in random order, spaced so the fleet does not
# reboot and re-announce at one instant for everyone to see (IATA-2 §6); a command that
# restarts the node is spaced wider.
ACT_SPACING = (10, 90)
ACT_SPACING_RESTART = (300, 1800)


def act_spacing(command):
    """`(low, high)` seconds between two nodes of an area act."""
    return ACT_SPACING_RESTART if denylist.broadcast_refusal(command) else ACT_SPACING


def faked(script=None):
    """Is the broker scripted (tests, the screenshots)? Then an area act waits nothing between nodes."""
    return script is not None or os.environ.get("MCCONTROL_FAKE_RESULTS") is not None


def pause(command, stop=None, script=None, rng=random):
    """Wait the spacing before the next node of an area act; `stop()` True ends it early.
    Returns the seconds drawn (0 when scripted)."""
    if faked(script):
        return 0
    secs = rng.uniform(*act_spacing(command))
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if stop and stop():
            break
        time.sleep(min(0.5, max(0.0, end - time.monotonic())))
    return secs


def area_topic(label):
    """What the history's summary line of an area act names (no topic is published): `area/<label>/act`."""
    return f"area/{label}/act"


def area_refusal(command):
    """Why `command` may not go to every node of an area, or None."""
    if envelope.is_transmit(command):
        return "a command that transmits may not be sent to every node of an area; send it to one"
    return None


@plane.run()             # one connection for the whole run
def act(store, command, devices, label, dry_run=False, wait_secs=None, progress=None, script=None, via="mqtt",
        rng=random):
    """`command` to each of `devices`, one sealed per-node command each (never a broadcast),
    in random order and spaced (`pause`). A node that cannot take it is reported and the
    rest still go. Returns `(None, None, {node: Result}, lines)`."""
    why = area_refusal(command)
    if why:
        raise envelope.EnvelopeError(why)
    if via == "mesh":
        raise envelope.EnvelopeError("the mesh road goes to one node at a time; an area act goes over MQTT")
    if via == RELAY_ROAD:
        raise envelope.EnvelopeError(RELAY_ONE_NODE)
    if not devices:
        raise envelope.EnvelopeError(f"no device of yours in {label}")
    order = list(devices)
    rng.shuffle(order)
    answers, lines = {}, []
    for i, d in enumerate(order):
        if i and not dry_run:
            pause(command, script=script, rng=rng)
        label_d = (d.get("name") or d["node"])[:12]
        try:
            _t, _p, got, l = send(store, command, device=d, dry_run=dry_run, wait_secs=wait_secs,
                                  progress=progress, script=script, via=via)
        except (envelope.EnvelopeError, mesh.MeshError) as exc:
            lines.append(f"{label_d:12} not sent: {exc}")
            continue
        answers.update(got)
        lines += l
    if not dry_run:
        store.record(None, command, area_topic(label), None, note=f"{len(answers)} of {len(devices)} answered", road=via)
    return None, None, answers, lines


def send(store, command, device=None, region=None, dry_run=False, wait_secs=None, progress=None, script=None,
         via="mqtt", county=None, relay=None, route="direct", path=None):
    """Sign and send `command` to one device; with `region` (an IATA code) or `county` (a
    node's `region home`), to each of your devices there in turn (`act`): there is no
    broadcast. `script`, here and below, stands in for the broker in tests
    (`transport._fake`). `via` picks the road (`road`): MQTT, the mesh through your
    companion, or auto. The plane is the node's (`scheme`): mcc3 for lou-20 and later, the
    old per-node IATA scheme before. `via="relay"` is asked for by name, never chosen by
    auto: `relay` (a device of yours on MQTT) transmits the request (`send_relay`).

    Returns `(topic, payload, {node: Result}, lines)`, where `lines` is what to show.
    Raises `envelope.EnvelopeError`, `transport.BrokerError`, `mesh.MeshError` or
    `store.StoreError`.
    """
    # `time now`: this computer's clock, for a node whose own fell behind (lou-20, the mesh road).
    if " ".join((command or "").split()).lower() == "time now":
        command = f"time {int(time.time())}"
    if via == RELAY_ROAD:
        if device is None:
            raise envelope.EnvelopeError(RELAY_ONE_NODE)
        return send_relay(store, command, device, relay, route=route, path=path, dry_run=dry_run,
                          wait_secs=wait_secs, progress=progress, script=script)
    if device is None:
        if not (region or county):
            raise envelope.EnvelopeError("a command goes to a device, or to each device of an area")
        devices = area_devices(store, region, county)
        label = county.strip().lower() if county else (region or "").strip().upper()
        return act(store, command, devices, label, dry_run, wait_secs, progress, script, via)
    config = store.config()
    chosen, why_road = road(store, device, command, via)
    if chosen == "mesh":
        return send_mesh(store, command, device, dry_run=dry_run, wait_secs=wait_secs, progress=progress,
                         script=script, why=why_road, fallback=via == "auto")
    if via == "auto" and not dry_run:
        try:
            return _send_mqtt(store, config, command, device, dry_run, wait_secs, progress, script)
        except transport.BrokerError as exc:
            return send_mesh(store, command, device, wait_secs=wait_secs, progress=progress, script=script,
                             why=f"MQTT unreachable: {exc}")
    return _send_mqtt(store, config, command, device, dry_run, wait_secs, progress, script)


def send_mesh(store, command, device, dry_run=False, wait_secs=None, progress=None, script=None, why="",
              fallback=False):
    """One command to one node over the mesh, through the companion in the configuration.
    With `fallback` (the auto road), a `mesh-closed` answer -- the node's road is shut
    because its MQTT works -- sends it again over MQTT."""
    config = store.config()
    text = " ".join((command or "").split())
    only = firmware.device_mesh_only(device)
    refused = denylist.mesh_refusal(text, mesh_only=only)
    if refused:
        raise envelope.EnvelopeError(f"the node would refuse {command!r} over the mesh: {refused}")
    if scheme(device) == "mcc3":
        return _send_mesh_mcc3(store, config, command, device, dry_run, wait_secs, progress, script, why, fallback)
    region = (device.get("region") or "").upper()
    topic = _mesh_topic(command, device, only)
    spec = config.get("companion") or ""
    head = f"over the mesh{f' ({why})' if why else ''}"
    if dry_run:
        body = mesh.build(store.seed(), topic, 0, command, ttl_secs=config.get("ttl_secs", envelope.DEFAULT_TTL_SECS))
        return topic, body.hex().upper(), {}, [f"would send {head} through {spec or 'your companion (none set)'}",
                                               f"signed for {topic}", body.hex().upper(), "not sent (dry run)"]
    mesh.parse_spec(spec)                   # no companion set: said now, before signing
    wait = wait_secs or max(config.get("wait_secs", 20), mesh.MESH_WAIT_SECS)
    counter = store.next_counter(device["node"])
    faked = transport._fake(topic, command, counter, [device["node"]], script)
    if faked is not None:
        transport._wait(transport.FAKE_WAIT_SECS, lambda: False, lambda: list(faked), progress)
        r = faked.get(device["node"])
        body = mesh.build(store.seed(), topic, counter, command, ttl_secs=config.get("ttl_secs", envelope.DEFAULT_TTL_SECS))
        result = None if r is None else mesh.MeshResult(r.node, counter, r.code, command, r.reply, None)
        info = {"path": "faked", "contact": "known"}
    else:
        topic, body, result, info = mesh.send(spec, store.seed(), region, device["key"], command, mesh_only=only,
                                              name=device.get("name") or "", counter=counter,
                                              ttl_secs=config.get("ttl_secs", envelope.DEFAULT_TTL_SECS),
                                              wait_secs=wait, progress=progress)
    return _mesh_done(store, config, command, device, topic, body, result, info, head, spec, why, fallback,
                      wait_secs, progress, script)


def _mesh_topic(command, device, only):
    """The topic a lou-19 mesh request is signed for, after the checks that come before any
    signing: 59 bytes, a version with the road, plain ASCII where the node takes only that."""
    mesh.check_command(command)
    if firmware.speaks_mesh(device.get("ver")) is False:
        raise envelope.EnvelopeError(f"{device['name'] or device['node']} runs {device.get('ver')}; the mesh "
                                     f"road needs lou-19 with the plane (rc)")
    if not command.isascii() and not firmware.admits_utf8(device.get("ver")):
        raise envelope.EnvelopeError(f"{device['name']} runs {device.get('ver') or 'an unknown version'}, "
                                     f"which takes plain ASCII only")
    return mesh.topic((device.get("region") or "").upper(), device.get("key"), only)


def _mesh_done(store, config, command, device, topic, body, result, info, head, spec, why, fallback, wait_secs,
               progress, script):
    if fallback and result is not None and result.code == 19:
        store.record(device["node"], command, topic, result, note="mesh closed: sent over MQTT", road="mesh")
        _advice(store, device, command, result, "mesh")
        t, p, answers, lines = _send_mqtt(store, config, command, device, False, wait_secs, progress, script)
        return t, p, answers, [f"{head}: the node's mesh road is closed (its MQTT works); sent over MQTT"] + lines
    store.record(device["node"], command, topic, result, note=why, road="mesh")
    if result is not None and result.ok and commands.is_read(command):
        store.remember_read(device["node"], command, result.reply or "OK", result.verified)
    path = info.get("path", "")
    added = "; the node was made a contact on the companion" if info.get("contact") == "added" else ""
    line = outcome_line(result, device.get("ver"))
    if result is None:
        line += " (not a refusal: the node may have run the command)"
    more = _advice(store, device, command, result, "mesh", direct=path.startswith("direct"))
    return topic, body.hex().upper(), {device["node"]: result} if result is not None else {}, [
        f"{head} through {spec}: {path}{added}",
        f"{(device.get('name') or device['node'])[:12]:12} {line}"] + more


def _send_mesh_mcc3(store, config, command, device, dry_run, wait_secs, progress, script, why, fallback):
    """The mesh road to a lou-20 node: 0xC2, sealed to the node, 57 bytes of command."""
    mesh.check_command_mcc3(command)        # before anything is signed
    key = _whole_key(device)
    topic = mcc3.command_topic(key)         # what the history names: the node, never a region
    spec = config.get("companion") or ""
    head = f"over the mesh{f' ({why})' if why else ''}"
    ttl = config.get("ttl_secs", envelope.DEFAULT_TTL_SECS)
    keys = store.owner_keys(key)
    if dry_run:
        body = mesh.build_mcc3(store.seed(), key, 0, command, keys=keys, ttl_secs=ttl)
        return topic, body.hex().upper(), {}, [f"would send {head} through {spec or 'your companion (none set)'}",
                                               f"sealed for {key[:8]} (mcc3, 0xC2)", body.hex().upper(),
                                               "not sent (dry run)"]
    mesh.parse_spec(spec)
    wait = wait_secs or max(config.get("wait_secs", 20), mesh.MESH_WAIT_SECS)
    counter = store.next_counter(device["node"])
    hit = transport._fake(topic, command, counter, [device["node"]], script)
    if hit is not None:
        transport._wait(transport.FAKE_WAIT_SECS, lambda: False, lambda: list(hit), progress)
        r = hit.get(device["node"])
        body = mesh.build_mcc3(store.seed(), key, counter, command, keys=keys, ttl_secs=ttl)
        result = None if r is None else mesh.MeshResult(r.node, counter, r.code, command, r.reply, None)
        info = {"path": "faked", "contact": "known"}
    else:
        body, result, info = mesh.send_mcc3(spec, store.seed(), key, command, counter, keys,
                                            name=device.get("name") or "", ttl_secs=ttl, wait_secs=wait,
                                            progress=progress)
    return _mesh_done(store, config, command, device, topic, body, result, info, head, spec, why, fallback,
                      wait_secs, progress, script)


def _advice(store, device, command, result, road, direct=False, unknown=False):
    """Keep the device's silence state after one send and return the lines `silence.advice`
    has for it, indented to go under the result. Uses what was read; sends nothing."""
    node = device["node"]
    outcome = ("unknown" if unknown or (result is not None and result.verified is False) else
               "silent" if result is None else "ok" if result.ok else "refused")
    read = silence.refused_count(command, result.reply) if outcome == "ok" else None
    if road not in silence.MESH_ROADS and read is None:
        return []
    kept = next((d.get("silence") for d in store.devices() if d["node"] == node), None)
    state, before, after = silence.step(kept, road, outcome, direct, read)
    store.update_device(node, silence=state)
    return [f"{'':12} {line}" for line in silence.advice(road, outcome, state["direct"], before, after)]


# -- through a relay ---------------------------------------------------------------------------
#
# A node of yours on MQTT transmits the mesh-road request to another node and returns the
# answer over MQTT. It spends the relay's airtime, so it is asked for by name, one node at a
# time, and the request is a mesh-road request: the same rules as `send_mesh`.

RELAY_ROAD = "relay"
RELAY_ONE_NODE = "a relay carries a command to one node at a time; an area or a group goes over MQTT"
ROUTE_TEXT = {"direct": "direct", "flood": "flood in the relay's region",
              "flood-wide": "flood in the relay's default scope"}


def relay_refusal(relay):
    """Why `relay` cannot carry a request, or None: it must be on MQTT and known to run
    lou-20 or later (its alive opened with your key, or its version says so)."""
    name = relay.get("name") or relay["node"]
    if firmware.device_mesh_only(relay):
        return f"{name} is mesh only (no MQTT), so it cannot relay"
    alive = relay.get("alive") or {}
    if not (alive and alive.get("state") != "not-yours") and not firmware.relays(relay.get("ver")):
        return (f"{name} is not known to run lou-20 or later, which a relay needs; "
                f"refresh it to read its version")
    return None


def relay_path(text):
    """`(path length byte, path bytes)` from a path as typed: hex of one-byte hashes
    (`A1B2`), or `2:HEX` / `3:HEX` for longer hashes; empty or `none` is no hops."""
    text = (text or "").strip()
    if text.lower() in ("", "none"):
        return 0, b""
    size, _, hops = text.rpartition(":")
    try:
        size = int(size or 1)
        path = bytes.fromhex(hops)
    except ValueError:
        raise envelope.EnvelopeError("a path is hex, e.g. A1B2 (2:A1B2C3D4 for two-byte hashes), "
                                     "or none") from None
    if size not in (1, 2, 3) or len(path) % size or not path:
        raise envelope.EnvelopeError("a path is whole hashes of 1, 2 or 3 bytes")
    path_len = (size - 1) << 6 | len(path) // size
    if len(path) // size > 63 or mcc3.path_bytes(path_len, mcc3.FORWARD_PATH) is None:
        raise envelope.EnvelopeError(f"a path through a relay is at most {mcc3.FORWARD_PATH} bytes")
    return path_len, path


def _hops(path_len, path=b""):
    """`no hops` says who can be reached that way; a path is shown, so that the one a flood's
    answer taught can be told from the one that worked before."""
    if not path_len & 63:
        return "no hops: only a node the relay hears itself"
    size = (path_len >> 6) + 1
    hops = ">".join(path[i:i + size].hex().upper() for i in range(0, len(path), size))
    return f"{path_len & 63} hop(s) via {hops}" if hops else f"{path_len & 63} hop(s)"


def send_relay(store, command, device, relay, route="direct", path=None, dry_run=False, wait_secs=None,
               progress=None, script=None):
    """One command to `device` through `relay`, a node of yours on MQTT that transmits the
    mesh-road request and returns the answer. `route` is direct (along `path`; by default the
    path the last answer taught this relay, else no hops), flood or flood-wide. Everything is
    checked before anything is signed. Returns as `send`."""
    config = store.config()
    text = " ".join((command or "").split())
    if relay is None:
        raise envelope.EnvelopeError("name the relay, a device of yours on MQTT: --via relay:<device>")
    if relay["node"] == device["node"]:
        raise envelope.EnvelopeError("a node cannot relay to itself; send it over MQTT")
    why = relay_refusal(relay)
    if why:
        raise envelope.EnvelopeError(why)
    if route not in mcc3.ROUTES:
        raise envelope.EnvelopeError(f"the route is one of {', '.join(mcc3.ROUTES)}")
    only = firmware.device_mesh_only(device)
    refused = denylist.mesh_refusal(text, mesh_only=only)
    if refused:
        raise envelope.EnvelopeError(f"the node would refuse {command!r} over the mesh: {refused}")
    relay_key = _whole_key(relay)
    # A relay carries the lou-20 request (0xC2) only: lou-21's relay refuses the older 0xC1, whose
    # only targets ran a firmware that was never released.
    if scheme(device) != "mcc3":
        raise envelope.EnvelopeError(f"{device.get('name') or device['node']} runs a firmware older than lou-20; "
                                     "a relay reaches lou-20 or later only")
    mesh.check_command_mcc3(command)
    key = _whole_key(device)
    topic = mcc3.command_topic(key)     # what the history names: the node
    keys = store.owner_keys(key)
    if route != "direct":
        if path:
            raise envelope.EnvelopeError("a path goes with the direct route only")
        path_len, hops = 0, b""
    elif path is None:
        known = (device.get("relay_paths") or {}).get(relay["node"])
        path_len, hops = (known["len"], bytes.fromhex(known["path"])) if known else (0, b"")
    else:
        path_len, hops = relay_path(path)
    # one transmission each way, and only when the relay was told the node is its neighbour
    flags = mcc3.FLAG_ZERO_HOP if route == "direct" and not path_len & 63 else 0
    ttl = config.get("ttl_secs", envelope.DEFAULT_TTL_SECS)
    relay_keys = store.owner_keys(relay_key)
    relay_name, name = relay.get("name") or relay["node"], device.get("name") or device["node"]
    how = ROUTE_TEXT[route] + (f", {_hops(path_len, hops)}" if route == "direct" else "")
    head = f"through relay {relay_name} ({how})"
    note = silence.path_note(path)          # sent as given; said under the result
    note = [f"{'':12} {note}"] if note else []

    def build(counter):
        return mesh.build_mcc3(store.seed(), key, counter, command, keys=keys, ttl_secs=ttl, flags=flags)

    def seal(forward_counter, body):
        return plane.forward_payload(relay_keys, relay_key, forward_counter, key, mcc3.ROUTES.index(route), body,
                                     path_len=path_len, path=hops, ttl_secs=ttl)

    if dry_run:
        payload = seal(0, build(0))
        return topic, payload, {}, [f"would send {head}", f"would publish to {mcc3.command_topic(relay_key)} "
                                    f"(mcc3, a sealed forward)", payload, "not sent (dry run)"] + note
    counter = store.next_counter(device["node"])
    forward_counter = store.next_forward_counter(relay["node"])
    payload = seal(forward_counter, build(counter))
    node = device["node"]
    hit = transport._fake(topic, command, counter, [node], script)
    if hit is not None:
        transport._wait(transport.FAKE_WAIT_SECS, lambda: False, lambda: list(hit), progress)
        r = hit.get(node)
        result = None if r is None else mesh.MeshResult(r.node, counter, r.code, command, r.reply, None)
        got = {"status": mcc3.FORWARD_NO_ANSWER if r is None else mcc3.FORWARD_ANSWERED, "path_len": None,
               "sent": mcc3.SENT_DIRECT if route == "direct" else mcc3.SENT_FLOOD, "snr": None}
    else:
        _topic, got = plane.forward(config, relay_key, relay_keys, payload, forward_counter,
                                    wait_secs=wait_secs or max(config.get("wait_secs", 20), plane.FORWARD_WAIT_SECS),
                                    progress=progress, store=store)
        result = None
        if got is not None and got["status"] == mcc3.FORWARD_ANSWERED:
            result = mesh.parse_mcc3(keys, got["response"], node, command, counter)
    said = {"node": relay["node"], "name": relay_name, "route": route, "status": None, "sent": None, "snr": None}
    if got is None:
        line = (f"no answer from the relay {relay_name}: is it online, on lou-20 or later, and relaying "
                f"(get relay)?")
    else:
        status = got["status"]
        said.update(status=mcc3.FORWARD_STATUSES[status] if status < len(mcc3.FORWARD_STATUSES) else f"unknown-{status}",
                    sent={mcc3.SENT_DIRECT: "direct", mcc3.SENT_FLOOD: "flood"}.get(got["sent"]),
                    snr=None if got["snr"] is None else got["snr"] / 4)
        if got["path_len"] is not None:
            store.remember_relay_path(node, relay["node"], got["path_len"], got["path"])
        if result is not None:
            line = outcome_line(result, device.get("ver"))
        elif status == mcc3.FORWARD_ANSWERED:
            line = "an answer came that does not open with this node's key; ignored"
        elif status == mcc3.FORWARD_NO_ANSWER:
            line = "no answer (not a refusal: the node may have run the command)"
        elif status in mcc3.FORWARD_HELP:
            line = f"not sent, the relay says {said['status']}: {mcc3.FORWARD_HELP[status]}"
        else:
            line = f"the relay says {said['status']}, which this version does not know"
    store.record(node, command, topic, result, road=RELAY_ROAD, relay=said,
                 note="" if result is not None else said["status"] or "the relay did not answer")
    if result is not None and result.ok and commands.is_read(command):
        store.remember_read(node, command, result.reply or "OK", result.verified)
    heard = "" if said["snr"] is None else f", answer heard at {said['snr']:g} dB"
    sent = f": sent {said['sent']}{heard}" if said["sent"] else ""
    more = []
    if got is None or got["status"] in (mcc3.FORWARD_ANSWERED, mcc3.FORWARD_NO_ANSWER):   # else nothing went on the air
        more = _advice(store, device, command, result, RELAY_ROAD, direct=route == "direct",
                       unknown=got is None or result is None and got["status"] == mcc3.FORWARD_ANSWERED)
    return topic, payload, {node: result} if result is not None else {}, [f"{head}{sent}", f"{name[:12]:12} {line}"] + more + note


def _whole_key(device):
    key = envelope.node_key(device.get("key") or "")
    if not key:
        raise envelope.EnvelopeError(f"{device.get('name') or device['node']} speaks mcc3, which needs its whole "
                                     f"public key (64 hex); discover it or change the device to add it")
    return key


def _send_mqtt(store, config, command, device, dry_run, wait_secs, progress, script):
    why = denylist.refusal(command)
    if why:
        raise envelope.EnvelopeError(f"the node would refuse {command!r}: {why}")
    if scheme(device) == "mcc3":
        return _send_mcc3(store, config, command, device, dry_run, wait_secs, progress, script)
    if not command.isascii():
        if not firmware.admits_utf8(device.get("ver")):
            raise envelope.EnvelopeError(
                f"{device['name']} runs {device.get('ver') or 'an unknown version'}, which takes "
                f"plain ASCII only; letters such as åäö need lou-17 (refresh to read its version)")
    region = (device.get("region") or "").upper()
    if not region:
        raise envelope.EnvelopeError(f"{device['name'] or device['node']} has no region, which lou-19 and older "
                                     f"need; change the device and set it")
    topic = envelope.command_topic(region, device["node"], device.get("key"))
    hear = [device["node"]]
    keys = {d["node"]: d.get("key") for d in store.devices() if d.get("key")}
    # v2, encrypted, to one node whose firmware opens it and whose whole key is known
    v2_key = None if not firmware.speaks_v2(device.get("ver")) else envelope.node_key(device.get("key") or "")
    if dry_run:
        payload = (envelope.build_v2(store.seed(), topic, 0, command, v2_key) if v2_key
                   else envelope.build(store.seed(), topic, 0, command))
        return topic, payload, {}, [f"would publish to {topic}", payload, "not sent (dry run)"]
    payload, answers = transport.send(store.config_for(region, config), store.seed(), topic, command,
                                      nodes_to_hear=hear, keys=keys, v2_key=v2_key,
                                      wait_secs=wait_secs or config.get("wait_secs", 20),
                                      progress=progress, script=script)
    lines = []
    mismatch = private_mismatch(store, device, command)
    if mismatch:
        lines.append(mismatch)
    names = {d["node"]: (d["name"] or d["node"]) for d in store.devices()}
    versions = {d["node"]: d.get("ver") for d in store.devices()}
    for node in hear:
        result = answers.get(node)
        store.record(node, command, topic, result, note="", road="mqtt")
        if result is not None and result.ok and commands.is_read(command) and node in names:
            store.remember_read(node, command, result.reply or "OK", result.verified)
        lines.append(f"{names.get(node, node[:8])[:12]:12} {outcome_line(result, versions.get(node))}")
        lines += _advice(store, device, command, result, "mqtt")
    return topic, payload, answers, lines


def _send_mcc3(store, config, command, device, dry_run, wait_secs, progress, script):
    """One sealed command to one lou-20 node on `mcc/cmd/<KEY>`, through the shared broker,
    its result on this session's reply topic. No region anywhere."""
    key = _whole_key(device)
    if len(command.encode("utf-8")) > mcc3.MAX_COMMAND:
        raise envelope.EnvelopeError(f"a command is at most {mcc3.MAX_COMMAND} bytes")
    keys = store.owner_keys(key)
    topic = mcc3.command_topic(key)
    if dry_run:
        try:
            payload = mcc3.seal_command(store.seed(), key, 0, 0, plane.session()["rid"], command, keys=keys)
        except mcc3.Mcc3Error as exc:
            raise envelope.EnvelopeError(str(exc)) from None
        return topic, payload, {}, [f"would publish to {topic} (mcc3, sealed)", payload, "not sent (dry run)"]
    counter = store.next_counter(device["node"])
    topic, payload, answers = plane.send(config, store.seed(), key, command, counter, keys=keys,
                                         wait_secs=wait_secs or config.get("wait_secs", 20),
                                         progress=progress, script=script, store=store)
    lines = []
    mismatch = private_mismatch(store, device, command)
    if mismatch:
        lines.append(mismatch)
    node = device["node"]
    result = answers.get(node)
    store.record(node, command, topic, result, note="mcc3", road="mqtt")
    if result is not None and result.ok and commands.is_read(command):
        store.remember_read(node, command, result.reply or "OK", result.verified)
    lines.append(f"{(device.get('name') or node)[:12]:12} {outcome_line(result, device.get('ver'))}")
    lines += _advice(store, device, command, result, "mqtt")
    return topic, payload, answers, lines


def fill(steps, arg):
    """The set's commands with `{arg}` filled in; refuses a set that needs one and has none."""
    if any("{arg}" in s for s in steps) and not (arg or "").strip():
        raise envelope.EnvelopeError("this set needs a value for {arg}")
    return [s.replace("{arg}", (arg or "").strip()) for s in steps]


@plane.run()             # one connection for the whole run
def run_set(store, steps, device=None, region=None, dry_run=False, wait_secs=None, on_step=None, progress=None,
            script=None, county=None):
    """Send `steps` in order to one device (or to each of your devices in `region` or
    `county`, one after another, never a broadcast), stopping at the first refusal or
    silence. Returns `(lines, stopped_at)`: what to show, and the index of the step that
    stopped it (on any device), or None when every step was answered ok."""
    if device is None:
        lines, stopped = [], None
        devices = area_devices(store, region, county)
        if not devices:
            raise envelope.EnvelopeError(f"no device of yours in {county or region}")
        for d in devices:
            l, s = run_set(store, steps, device=d, dry_run=dry_run, wait_secs=wait_secs, on_step=on_step,
                           progress=progress, script=script)
            lines += [f"== {d.get('name') or d['node']}"] + l
            stopped = s if stopped is None else stopped
        return lines, stopped
    lines, stopped = [], None
    for i, command in enumerate(steps):
        if on_step:
            on_step(i, command)
        _t, _p, answers, step_lines = send(store, command, device=device, region=region,
                                           dry_run=dry_run, wait_secs=wait_secs, progress=progress, script=script)
        lines.append(f"-- {i + 1}/{len(steps)}: {command}")
        lines += step_lines
        if dry_run:
            continue
        if len(answers) < 1 or any(not r.ok for r in answers.values()):
            stopped = i
            lines.append(f"stopped at step {i + 1}: not every node answered ok; "
                         f"{len(steps) - i - 1} step(s) not sent")
            break
    return lines, stopped


def live_statistics(store, device, progress=None, script=None):
    """One signed `get stats` to the device: `(lines, note)`. `lines` is the sample as
    `beacon.stat_lines` lays it out, headed "live, just now"; empty when the node did not
    answer or refused, with `note` saying which (older firmware answers not-allowed)."""
    try:
        _t, _p, answers, _l = send(store, "get stats", device=device, progress=progress, script=script)
    except (envelope.EnvelopeError, transport.BrokerError, _store.StoreError) as exc:
        return [], f"live: {exc}"
    r = answers.get(device["node"])
    if r is None:
        return [], "live: no answer"
    if not r.ok:
        return [], f"live: refused {r.code_name}" + (" (older firmware: the read needs the 2026-10-08 build)" if r.code == 14 else "")
    block = nodestats.parse(r.reply)
    if not block:
        return [], f"live: {r.reply[:40]}"
    sample = {"stats": block, "sampled_at": None, "age_secs": 0, "firmware": "", "model": "", "name": ""}
    lines = beacon.stat_lines(sample)
    lines[0] = "live, just now (get stats)"
    return lines, ""


def statistics(store, device, range_="24h", interval="6h", live=False, progress=None, script=None, details=False):
    """The lines to show for a device's statistics: the live sample first when asked for
    and answered, then Beacon's sample with its age and the telemetry buckets. Raises
    `beacon.BeaconError` with the reason when Beacon has none and there is no live one.
    With `details`, `(lines, sample, points)`: what Beacon gave, each None where it gave
    nothing, so a dashboard has the numbers without asking Beacon twice."""
    head = []
    if live:
        live_lines, note = live_statistics(store, device, progress=progress, script=script)
        head = live_lines + [""] if live_lines else [note, ""]
    sample = points = None
    try:
        sample = beacon.stats(store, device)
    except beacon.BeaconError as exc:
        if head and head[0].startswith("live, just now"):
            lines = head + [f"Beacon: {exc}"]
            return (lines, None, None) if details else lines
        raise
    lines = beacon.stat_lines(sample)
    lines[0] = "Beacon: " + lines[0]
    device = store.device(device["node"]) or device       # with the observer id the read above found
    try:
        points = beacon.telemetry(store, device, range_, interval)
    except beacon.BeaconError as exc:
        lines = head + lines + ["", f"no telemetry: {exc}"]
    else:
        lines = head + lines + ["", f"last {range_} at {interval}:"] + beacon.telemetry_lines(points)
    return (lines, sample, points) if details else lines


def refresh_fleet(store, devices, now=None):
    """Battery and last-seen from Beacon for each device, stored as `fleet` on the device.
    Returns `(updated, failed)` counts; a device Beacon does not know keeps nothing stale:
    its `fleet` is cleared."""
    updated = failed = 0
    for d in devices:
        try:
            sample = beacon.stats(store, d, now=now)
        except beacon.BeaconError:
            store.update_device(d["node"], fleet=None)
            failed += 1
            continue
        seen = datetime.datetime.fromtimestamp(sample["sampled_at"]).isoformat(timespec="seconds")
        store.update_device(d["node"], fleet={"battery_mv": sample["stats"].get("battery_mv"),
                                               "seen": seen, "firmware": sample["firmware"],
                                               "fetched": _store_now()})
        updated += 1
    return updated, failed


@plane.run()             # one connection for the whole run
def refresh_names(store, devices, wait_secs=None, progress=None, script=None):
    """`get name` and `ver` to each device, one signed read each: an unnamed device takes the
    fleet's name, every device stores `ver`. Returns `(named, versioned, lines)`. A node whose
    firmware admits neither answers not-allowed and keeps what it had."""
    named = versioned = 0
    lines = []
    for d in devices:
        label = d.get("name") or d["node"]
        changes = {}
        for command in ("get name", "ver"):
            try:
                _t, _p, answers, _l = send(store, command, device=d, wait_secs=wait_secs, progress=progress,
                                           script=script)
            except (envelope.EnvelopeError, transport.BrokerError, _store.StoreError) as exc:
                lines.append(f"{label[:12]:12} {command}: {exc}")
                continue
            r = answers.get(d["node"])
            if r is None or not r.ok or not r.reply:
                lines.append(f"{label[:12]:12} {command}: {outcome_line(r)}")
                continue
            value = r.reply.lstrip("> ").strip()
            if command == "ver":
                changes["ver"] = value[:40]
                versioned += 1
            elif not d.get("name") and value:
                changes["name"] = value[:40]
                named += 1
            lines.append(f"{label[:12]:12} {command}: {value[:40]}")
        if changes:
            store.update_device(d["node"], **changes)
    return named, versioned, lines


def register(store, broker=None):
    """Register the signing key with one control broker (the shared one when not given),
    once: `(ok, detail)`; remembered per broker on success so the key screens and the
    connection test can say so. The login token is signed for that broker's name."""
    config = store.config()
    broker = broker or config["broker"]
    ok, detail = transport.register(dict(config, broker=broker), store.seed(),
                                    wait_secs=min(10, config.get("wait_secs", 20)))
    if ok:
        store.remember_registration(broker)
    return ok, detail


def register_all(store, brokers=None):
    """Register with each broker in use (`store.brokers()`), or with those given:
    `[(broker, ok, detail)]`. A broker that refuses or is silent does not stop the next."""
    out = []
    for broker in brokers or store.brokers():
        try:
            ok, detail = register(store, broker)
        except transport.BrokerError as exc:
            ok, detail = False, str(exc)
        out.append((broker, ok, detail))
    return out


def regions_asked(text, store):
    """`JKG`, `JKG, GOT` or `*` (every region the directory spans) as a list of IATA codes."""
    text = (text or "").strip()
    if text == "*":
        return store.regions()
    seen = []
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        code = part.strip().upper()
        if code and code not in seen:
            seen.append(code)
    return seen


def discover(store, region, wait_secs=None, progress=None, script=None):
    """The nodes in `region` that answer a command signed with your key, marked if known.
    `region` may name several (`JKG, GOT`) or `*`; one signed read per region, one list."""
    regions = regions_asked(region, store)
    if not regions:
        raise envelope.EnvelopeError("discovery needs a region: the IATA code, e.g. JKG; "
                                     "several with commas, or * for every region you have")
    if len(regions) > 1:
        found = []
        for one in regions:
            found += discover(store, one, wait_secs, progress, script)
        return found
    region = regions[0]
    config = store.config_for(region)       # the region's own broker, or the shared one
    known = {d["node"]: d["name"] for d in store.devices()}
    found = transport.discover(config, store.seed(), region,
                               wait_secs=wait_secs or config.get("wait_secs", 20), progress=progress, script=script)
    for entry in found:
        entry["known_as"] = known.get(entry["node"])
        # a node answering on a whole-key topic (ar-11) tells us its key: keep it on a
        # device we already have, so its next command goes to the topic it listens on
        if entry.get("key") and entry["node"] in known:
            d = store.device(entry["node"])
            if d and d.get("key") != entry["key"]:
                store.update_device(entry["node"], key=entry["key"])
        entry["outcome"] = outcome_line(envelope.Result(entry["node"], 0, entry["code"],
                                                        transport.DISCOVERY_COMMAND, entry["reply"]))
        entry["name"] = ""
        entry["broker"] = config["broker"]
    if found:
        # A second read for the names, which only firmware that admits `get name` answers;
        # the rest stay unnamed and are named by hand.
        try:
            _p, names = transport.send(config, store.seed(),
                                       envelope.command_topic(region), "get name",
                                       nodes_to_hear=[e["node"] for e in found],
                                       keys={e["node"]: e["key"] for e in found if e.get("key")},
                                       wait_secs=min(10, wait_secs or config.get("wait_secs", 20)), script=script)
        except transport.BrokerError:
            names = {}
        for entry in found:
            r = names.get(entry["node"])
            if r is not None and r.ok and r.reply:
                entry["name"] = r.reply.lstrip("> ").strip()[:40]
    return found


def adopt(store, entry, name=""):
    """Remember a discovered node; unnamed until you name it, since the old plane carries no
    name (a name-plus-number is used if the name is taken). A node found by its alive has a
    whole key and no region: mcc3 needs none."""
    name = (name or "").strip()
    base, n = name, 2
    while name and any(d["name"].lower() == name.lower() for d in store.devices()):
        name = f"{base}-{n}"
        n += 1
    added = store.add_device(name, entry["node"], entry.get("region") or "", "found by discovery",
                             key=entry.get("key"))
    if entry.get("alive"):
        added = store.update_device(added["node"], alive=entry["alive"])
    return added


# -- discovery from alive (mcc3, IATA-2 §6) ------------------------------------------------

ALIVE_STATES = {"ours": "online", "empty": "offline", "foreign": "not-yours"}


def _alive_record(fields, state, at):
    rec = {"state": state, "at": datetime.datetime.fromtimestamp(at).replace(microsecond=0).isoformat(sep=" ")}
    if fields:
        rec.update({k: fields[k] for k in ("boot", "sequence", "uptime", "clock", "last_counter", "interval",
                                           "flags", "mesh", "fingerprint", "version", "region", "name")})
        rec["old_scheme"] = bool(fields["flags"] & 1)
        rec["relay"] = bool(fields["flags"] & mcc3.ALIVE_FLAG_RELAY)     # it relays for its owner
    return rec


def discover_alive(store, wait_secs=None, progress=None, add=False, client_factory=None):
    """Your nodes, wherever they are, from the retained alive messages: every `mcc/alive/<KEY>`
    is tried with your command key (the shared secret per node cached beside the key), and
    those that open are yours. A device you have whose alive is empty is offline; one whose
    alive no longer opens is no longer yours (rekeyed). Reads only; nothing is published.

    Returns `[{node, key, name, version, state, known_as, added, alive}]`, sorted by name."""
    config = store.config()
    seed = store.seed()
    cache = store.ecdh_cache()
    before = len(cache)
    seen = plane.scan(config, seed, cache, wait_secs=wait_secs or min(10, config.get("wait_secs", 20)),
                      progress=progress, client_factory=client_factory, store=store)
    if len(cache) != before:
        store.save_ecdh_cache(cache)
    by_key = {(d.get("key") or "").upper(): d for d in store.devices() if d.get("key")}
    found = []
    for key, (state, fields, at) in seen.items():
        d = by_key.get(key)
        if d is None and state == "ours":       # a device kept by its id alone: its alive gives the key
            d = next((x for x in store.devices() if x["node"] == key[:envelope.NODE_HEX_LEN]
                      and not x.get("key")), None)
            if d is not None:
                d = store.update_device(d["node"], key=key)
        if state != "ours" and d is None:
            continue                    # someone else's node, or one we never had: nothing to say
        rec = _alive_record(fields, ALIVE_STATES[state], at)
        if d is not None:
            old = d.get("alive") or {}
            if state == "ours" and old.get("state") == "online" and not plane.newer(fields, old):
                rec = old               # stale: a replay of an older message
            elif state != "ours":
                rec = dict(old, state=rec["state"], at=rec["at"])
            store.update_device(d["node"], alive=rec)
        entry = {"node": key[:envelope.NODE_HEX_LEN], "key": key, "name": (fields or {}).get("name", ""),
                 "version": (fields or {}).get("version", ""), "state": rec["state"],
                 "known_as": None if d is None else (d.get("name") or d["node"]), "added": False, "alive": rec}
        if add and d is None and store.device(entry["node"]) is None:
            adopt(store, {"node": key, "key": key, "region": "", "alive": rec}, entry["name"])
            entry["added"] = True
        found.append(entry)
    return sorted(found, key=lambda e: (e["name"] or e["node"]).lower())
