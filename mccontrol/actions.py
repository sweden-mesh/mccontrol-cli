"""What the screens and the command line both do, so they cannot disagree."""

import datetime
import time

from . import beacon, commands, denylist, envelope, firmware, mesh, nodestats, store as _store, transport
from .store import _now as _store_now

# Commands that take something away from a repeater. Each is sent only after the person has
# been told what it does; the node itself does not second-guess a signed command.
CAUTIONS = (
    ("region denyf *", "stops this repeater forwarding every message that carries no scope. "
                       "It may be the only link between two places that rely on that."),
    ("region denyf", "stops this repeater forwarding that scope."),
    ("region remove", "deletes that region from the repeater. Messages scoped to it are dropped."),
    ("set autoreply off", "stops this repeater answering test requests."),
    # `set repeat off`, `erase` and `set mqtt.cmd*` used to be here; the firmware's deny list of
    # 2026-10-08 refuses them outright (`denylist.py`), so there is nothing to ask.
    # Admitted since that list; each can take the node out of reach for a while or move
    # where it listens, so the person is told first.
    ("reboot", "restarts the node. It is off the air and off the control plane until it is back."),
    ("clkreboot", "restarts the node. It is off the air and off the control plane until it is back."),
    ("ota update", "downloads the newest signed firmware and restarts the node on it. It is off the air "
                   "for about a minute; if the new image never works, the node goes back to the old one."),
    ("set mqtt.iata", "moves the node to another region's topics: this tool must change its region to match."),
    ("set mqtt.presets", "changes how many MQTT slots run; the control plane's slot may stop."),
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
    ("set mqtt.cmd on", "points the node's command slot at a broker; a wrong one keeps it off the "
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
    if not device.get("last_heard_mesh"):
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


def send(store, command, device=None, region=None, dry_run=False, wait_secs=None, progress=None, script=None,
         via="mqtt"):
    """Sign and send `command` to one device, or with `region` to every node in that region.
    `script`, here and below, stands in for the broker in tests (`transport._fake`). `via`
    picks the road (`road`): MQTT, the mesh through your companion, or auto.

    Returns `(topic, payload, {node: Result}, lines)`, where `lines` is what to show.
    Raises `envelope.EnvelopeError`, `transport.BrokerError`, `mesh.MeshError` or
    `store.StoreError`.
    """
    config = store.config()
    chosen, why_road = road(store, device, command, via)
    if chosen == "mesh":
        return send_mesh(store, command, device, dry_run=dry_run, wait_secs=wait_secs, progress=progress,
                         script=script, why=why_road, fallback=via == "auto")
    if via == "auto" and not dry_run:
        try:
            return _send_mqtt(store, config, command, device, region, dry_run, wait_secs, progress, script)
        except transport.BrokerError as exc:
            return send_mesh(store, command, device, wait_secs=wait_secs, progress=progress, script=script,
                             why=f"MQTT unreachable: {exc}")
    return _send_mqtt(store, config, command, device, region, dry_run, wait_secs, progress, script)


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
    mesh.check_command(command)             # 59 bytes, before anything is signed
    if firmware.speaks_mesh(device.get("ver")) is False:
        raise envelope.EnvelopeError(f"{device['name'] or device['node']} runs {device.get('ver')}; the mesh "
                                     f"road needs lou-19 with the plane (rc)")
    if not command.isascii() and not firmware.admits_utf8(device.get("ver")):
        raise envelope.EnvelopeError(f"{device['name']} runs {device.get('ver') or 'an unknown version'}, "
                                     f"which takes plain ASCII only")
    region = (device.get("region") or "").upper()
    topic = mesh.topic(region, device.get("key"), only)
    spec = config.get("companion") or ""
    head = f"over the mesh{f' ({why})' if why else ''}"
    if dry_run:
        body = mesh.build(store.seed(), topic, 0, command, ttl_secs=config.get("ttl_secs", envelope.DEFAULT_TTL_SECS))
        return topic, body.hex().upper(), {}, [f"would send {head} through {spec or 'your companion (none set)'}",
                                               f"signed for {topic}", body.hex().upper(), "not sent (dry run)"]
    mesh.parse_spec(spec)                   # no companion set: said now, before signing
    wait = wait_secs or config.get("wait_secs", 20)
    counter = int(time.time())
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
    if fallback and result is not None and result.code == 19:
        store.record(device["node"], command, topic, result, note="mesh closed: sent over MQTT", road="mesh")
        t, p, answers, lines = _send_mqtt(store, config, command, device, None, False, wait_secs, progress, script)
        return t, p, answers, [f"{head}: the node's mesh road is closed (its MQTT works); sent over MQTT"] + lines
    store.record(device["node"], command, topic, result, note=why, road="mesh")
    if result is not None and result.ok and commands.is_read(command):
        store.remember_read(device["node"], command, result.reply or "OK", result.verified)
    path = info.get("path", "")
    added = "; the node was made a contact on the companion" if info.get("contact") == "added" else ""
    line = outcome_line(result, device.get("ver"))
    if result is None:
        line += " (silence over the mesh is not a refusal: a node without the road, or its budget, says nothing)"
    return topic, body.hex().upper(), {device["node"]: result} if result is not None else {}, [
        f"{head} through {spec}: {path}{added}",
        f"{(device.get('name') or device['node'])[:12]:12} {line}"]


def _send_mqtt(store, config, command, device, region, dry_run, wait_secs, progress, script):
    why = denylist.refusal(command)
    if why:
        raise envelope.EnvelopeError(f"the node would refuse {command!r}: {why}")
    broadcast = device is None
    if broadcast and not region:
        raise envelope.EnvelopeError("a broadcast needs a region")
    if broadcast and envelope.is_transmit(command):
        raise envelope.EnvelopeError("a command that transmits may not be sent to every node; "
                                     "the firmware refuses it, and so does this")
    if broadcast and denylist.broadcast_refusal(command):
        raise envelope.EnvelopeError(f"{command!r} may not be sent to every node: "
                                     f"{denylist.broadcast_refusal(command)}")
    if not command.isascii():
        if broadcast:
            raise envelope.EnvelopeError("a broadcast is plain ASCII: nodes before lou-17 refuse "
                                         "letters such as åäö; send it to each node instead")
        if not firmware.admits_utf8(device.get("ver")):
            raise envelope.EnvelopeError(
                f"{device['name']} runs {device.get('ver') or 'an unknown version'}, which takes "
                f"plain ASCII only; letters such as åäö need lou-17 (refresh to read its version)")
    region = (region or device.get("region") or "").upper()
    if not region:
        raise envelope.EnvelopeError(f"{device['name']} has no region; change the device and set it")
    topic = envelope.command_topic(region, None if broadcast else device["node"],
                                   None if broadcast else device.get("key"))
    hear = ([d["node"] for d in store.devices() if (d.get("region") or "").upper() == region]
            if broadcast else [device["node"]])
    keys = {d["node"]: d.get("key") for d in store.devices() if d.get("key")}
    # v2, encrypted, to one node whose firmware opens it and whose whole key is known
    v2_key = (None if broadcast or not firmware.speaks_v2(device.get("ver"))
              else envelope.node_key(device.get("key") or ""))
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
        store.record(node, command, topic, result, note="broadcast" if broadcast else "", road="mqtt")
        if result is not None and result.ok and commands.is_read(command) and node in names:
            store.remember_read(node, command, result.reply or "OK", result.verified)
        lines.append(f"{names.get(node, node[:8])[:12]:12} {outcome_line(result, versions.get(node))}")
    if broadcast:
        store.record(None, command, topic, None,
                     note=f"{len(answers)} of {len(hear)} answered", road="mqtt")
    return topic, payload, answers, lines


def fill(steps, arg):
    """The set's commands with `{arg}` filled in; refuses a set that needs one and has none."""
    if any("{arg}" in s for s in steps) and not (arg or "").strip():
        raise envelope.EnvelopeError("this set needs a value for {arg}")
    return [s.replace("{arg}", (arg or "").strip()) for s in steps]


def run_set(store, steps, device=None, region=None, dry_run=False, wait_secs=None, on_step=None, progress=None,
            script=None):
    """Send `steps` in order to one device (or every node in `region`), stopping at the first
    refusal or silence. Returns `(lines, stopped_at)`: what to show, and the index of the
    step that stopped it, or None when every step was answered ok."""
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
        expected = 1 if device else len([d for d in store.devices()
                                         if (d.get("region") or "").upper() == region.upper()])
        if len(answers) < expected or any(not r.ok for r in answers.values()):
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
    """Remember a discovered node; unnamed until you name it, since the control plane
    carries no name (a name-plus-number is used if the name is taken)."""
    name = (name or "").strip()
    base, n = name, 2
    while name and any(d["name"].lower() == name.lower() for d in store.devices()):
        name = f"{base}-{n}"
        n += 1
    return store.add_device(name, entry["node"], entry["region"], "found by discovery", key=entry.get("key"))
