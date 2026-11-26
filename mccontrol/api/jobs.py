"""The long-running verbs as jobs: each runs in a thread, and its record carries the status,
the progress the `progress` callbacks report ("3 of 12 answered"), the per-device outcomes
as they land, and the result. Cancelling sets a flag the next progress tick returns, which
is how Esc stops a wait in the screens: what landed is kept.

A route here checks everything that can be checked before anything is signed -- the
targets, the deny list, a caution without `confirm`, the key -- and answers that at once as
an error; only then does a thread start.
"""

import itertools
import threading
import uuid

from .. import actions, beacon, denylist, envelope, firmware, mcc3, mesh, plane, store as _store, transport
from .errors import ApiError, bad, classify, not_found
from .routes import device_of, devices_of

KEEP = 200                              # finished jobs remembered for GET /jobs
# What a cancel can interrupt: the waits that take a progress callback. The connection test
# and the registration wait on paho with none, so a cancel there is noted and nothing more;
# discovery stops its listening and the regions left, but not the name read after it.
CANCELLABLE = {"send": True, "run-set": True, "discover": True, "refresh-names": True, "refresh-fleet": True,
               "statistics": True, "test": False, "register": False}
_order = itertools.count()


class Job:
    def __init__(self, verb):
        self.id = uuid.uuid4().hex[:12]
        self.verb = verb
        self.cancellable = CANCELLABLE[verb]
        self.order = next(_order)
        self.status = "running"
        self.cancel = threading.Event()
        self.started = _store._now()
        self.finished = None
        self.progress = {"text": "starting", "answered": 0, "expected": 0, "elapsed": 0.0, "wait": 0.0, "step": 0, "steps": 1, "heard": []}
        self.outcomes = {}              # key -> outcome, in landing order
        self.result = None
        self.error = None
        self.stopped = False            # the work gave up something because of a cancel
        self.lock = threading.Lock()

    def stopping(self):
        """Asked where the work can stop early: True, and remembered, once cancelled. A job
        whose work never asks ran to the end, and is done however late the cancel came."""
        if self.cancel.is_set():
            self.stopped = True
        return self.stopped

    def update(self, **progress):
        with self.lock:
            self.progress.update(progress)

    def land(self, outcome, key=None):
        with self.lock:
            self.outcomes[key or outcome["node"]] = outcome

    def landed(self, key):
        with self.lock:
            return key in self.outcomes

    def snapshot(self):
        with self.lock:
            return {"id": self.id, "verb": self.verb, "status": self.status, "cancel_requested": self.cancel.is_set(),
                    "cancellable": self.cancellable, "started": self.started, "finished": self.finished, "progress": dict(self.progress),
                    "outcomes": list(self.outcomes.values()), "result": self.result, "error": self.error}


class Registry:
    def __init__(self):
        self.jobs = {}
        self.lock = threading.Lock()

    def start(self, verb, work):
        """Run `work(job)` in a thread; its return value is the result."""
        job = Job(verb)
        with self.lock:
            self.jobs[job.id] = job
            done = sorted((j for j in self.jobs.values() if j.status != "running"), key=lambda j: j.order)
            for old in done[:max(0, len(self.jobs) - KEEP)]:
                del self.jobs[old.id]

        @plane.run()            # the commands of one job share a connection
        def run():
            result, error = None, None
            try:
                result = work(job)
            except Exception as exc:    # the job's error, in the API's one shape
                _s, code, message = classify(exc)
                error = {"code": code, "message": message}
            with job.lock:
                job.result, job.error = result, error
                job.status = "failed" if error else ("cancelled" if job.stopped else "done")
                job.finished = _store._now()

        threading.Thread(target=run, name=f"mccontrol-job-{job.id}", daemon=True).start()
        return job

    def get(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
        if job is None:
            raise not_found(f"no job {job_id}")
        return job

    def all(self):
        with self.lock:
            return sorted(self.jobs.values(), key=lambda j: -j.order)

    def cancel_all(self):
        for job in self.all():
            job.cancel.set()


# -- what a job records ------------------------------------------------------------------

def outcome(node, name, command, result, version=None, line=None):
    return {"node": node, "name": name or node, "command": command,
            "ok": None if result is None else result.ok,
            "code": None if result is None else result.code,
            "code_name": None if result is None else result.code_name,
            "reply": None if result is None else result.reply,
            "verified": None if result is None else result.verified,
            "line": line or actions.outcome_line(result, version)}


def ticker(job, text, names=None, command=""):
    """A `progress` callback for the transport: elapsed, wait and the nodes heard into the
    record, the answered nodes landed (as "answered" until the final outcome replaces it), and the
    cancel flag back, which stops the wait."""
    names = names or {}

    def tick(elapsed, total, answered):
        job.update(elapsed=round(elapsed, 1), wait=total, text=text(len(answered)), heard=list(answered))
        if names:
            job.update(answered=len(answered))
            for node in answered:
                if not job.landed(node):
                    job.land({"node": node, "name": names.get(node) or node, "command": command, "ok": None,
                              "code": None, "code_name": None, "reply": None, "verified": None, "line": "answered"})
        return job.stopping()
    return tick


def _label(d):
    return d.get("name") or d["node"]


# -- checks before a thread starts -------------------------------------------------------

def _targets(ctx, body):
    """`(devices, area)`: exactly one of devices, tagged, group, region, county. A group is
    its members one by one, each on its own topic; a region (an IATA code, the old scheme's)
    or a county (a node's own `region home`) is each of your devices there, one sealed
    command per node, never a broadcast. `area` names the region or county, else None."""
    given = [k for k in ("devices", "tagged", "group", "region", "county") if body.get(k)]
    if len(given) != 1:
        raise bad("exactly one target: devices, tagged, group, region or county")
    if given[0] == "group":
        if not isinstance(body["group"], str):
            raise bad("group is a string")
        members = ctx.store.group(body["group"])
        if members is None:
            raise not_found(f"no group named {body['group'].strip().lower()}")
        if not members:
            raise bad(f"group {body['group'].strip().lower()} has no devices")
        return [ctx.store.device(n) for n in members], None
    if given[0] in ("region", "county"):
        kind = given[0]
        if not isinstance(body[kind], str):
            raise bad(f"{kind} is a string")
        area = body[kind].strip().upper() if kind == "region" else body[kind].strip().lower()
        devices = actions.area_devices(ctx.store, **{kind: area})
        if not devices:
            raise bad(f"no device of yours in {area}")
        return devices, area
    if given[0] == "tagged":
        devices = [d for d in ctx.store.devices() if d["node"] in ctx.tags]
        if not devices:
            raise bad("nothing is tagged")
        return devices, None
    return devices_of(ctx, body["devices"]), None


def _some(ctx, body):
    """devices, or the tagged, or every device."""
    if body.get("devices"):
        devices = devices_of(ctx, body["devices"])
    elif body.get("tagged"):
        devices = [d for d in ctx.store.devices() if d["node"] in ctx.tags]
    else:
        devices = ctx.store.devices()
    if not devices:
        raise bad("no devices to ask")
    return devices


def _wait(body):
    w = body.get("wait_secs")
    if w is not None and (isinstance(w, bool) or not isinstance(w, (int, float)) or w <= 0):
        raise bad("wait_secs is a positive number")
    return w


def _via(body, devices=None, area=None):
    """The road asked for: mqtt (the default), mesh, auto or relay. The mesh goes to one node
    at a time, so never to an area (its airtime); a relay to exactly one device, named."""
    via = body.get("via", "mqtt")
    if via == actions.RELAY_ROAD:
        if area or body.get("group") or body.get("tagged") or len(devices or ()) != 1:
            raise ApiError(400, "refused", actions.RELAY_ONE_NODE)
        return via
    if via not in actions.ROADS:
        raise bad(f"via is one of {', '.join(actions.ROADS)}, {actions.RELAY_ROAD}")
    if via == "mesh" and area:
        raise ApiError(400, "refused", "the mesh road goes to one node at a time; an area act goes over MQTT")
    return via


def _refusal(command, via, devices):
    """Why every road `via` may take would refuse `command`, or None. Over the mesh (through
    your companion or a relay) the repair allowance travels and a mesh-only node refuses what
    needs an uplink; auto refuses only what both roads refuse."""
    if via == "mqtt" or not devices:
        return denylist.refusal(command)
    for d in devices:
        only = firmware.device_mesh_only(d)
        on_mesh = denylist.mesh_refusal(command, mesh_only=only)
        if on_mesh is None and len(command.encode("utf-8")) > mesh.MAX_COMMAND:
            on_mesh = f"over the mesh a command is 1..{mesh.MAX_COMMAND} bytes"
        why = on_mesh if via in ("mesh", actions.RELAY_ROAD) or only else (on_mesh and denylist.refusal(command))
        if why:
            return why
    return None


def _vet(ctx, commands_, area, body, devices=None, via="mqtt"):
    """The deny list (the road's), the area rule and the cautions, before anything is signed."""
    for command in commands_:
        why = _refusal(command, via, devices)
        if why:
            raise ApiError(400, "refused", f"the node would refuse {command!r}: {why}")
        if area and actions.area_refusal(command):
            raise ApiError(400, "refused", actions.area_refusal(command))
    cautions = [f"'{c}' {actions.caution(c)}" for c in commands_ if actions.caution(c)]
    if cautions and not body.get("dry_run") and not body.get("confirm"):
        raise ApiError(409, "confirm_required", " ".join(cautions) + " Send again with confirm: true.",
                       cautions=[{"command": c, "caution": actions.caution(c)} for c in commands_ if actions.caution(c)])
    ctx.store.seed()                    # no key, or a readable one, is a StoreError now


def _relay(ctx, body, via, devices):
    """`{relay, route, path}` for a send through a relay, checked before anything is signed;
    empty for every other road, which takes none of them."""
    given = [k for k in ("relay", "route", "path") if body.get(k) is not None]
    if via != actions.RELAY_ROAD:
        if given:
            raise bad(f"{', '.join(given)} goes with via: relay")
        return {}
    if any(not isinstance(body[k], str) for k in given):
        raise bad("relay, route and path are strings")
    if not body.get("relay"):
        raise bad("via relay needs relay: a device of yours on MQTT")
    relay = device_of(ctx, body["relay"])
    route = body.get("route") or "direct"
    why = (actions.relay_refusal(relay) if route in mcc3.ROUTES else
           f"the route is one of {', '.join(mcc3.ROUTES)}")
    if not why and relay["node"] == devices[0]["node"]:
        why = "a node cannot relay to itself; send it over MQTT"
    if why:
        raise ApiError(400, "refused", why)
    try:
        if body.get("path") is not None:
            actions.relay_path(body["path"])
    except envelope.EnvelopeError as exc:
        raise bad(str(exc)) from None
    return {"relay": relay, "route": route, "path": body.get("path")}


# -- the verbs ---------------------------------------------------------------------------

def start_send(ctx, _p, _q, body):
    command = " ".join((body.get("command") or "").split()) if isinstance(body.get("command"), str) else ""
    if not command:
        raise bad("command is required")
    devices, area = _targets(ctx, body)
    via = _via(body, devices, area)
    through = _relay(ctx, body, via, devices)
    _vet(ctx, [command], area, body, devices, via)
    dry, wait = bool(body.get("dry_run")), _wait(body)
    group = body.get("group")
    store = ctx.store
    if area:                                # an area act: random order, spaced (actions.pause)
        devices = list(devices)
        actions.random.shuffle(devices)

    def work(job):
        answered, asked, lines, topics = 0, 0, [], []
        job.update(expected=len(devices))
        for i, d in enumerate(devices):         # one signed publish per device, to its own topic
            if job.stopping():
                break
            if area and i and not dry:
                job.update(text=f"{answered} of {len(devices)} answered; spacing before {_label(d)}")
                actions.pause(command, stop=job.stopping, script=ctx.script)
                if job.stopping():
                    break
            label = _label(d)
            text = lambda _n, a=answered, label=label, i=i: f"{a} of {len(devices)} answered; waiting for {label} ({i + 1} of {len(devices)})"
            try:
                topic, _pl, answers, l = actions.send(store, command, device=d, dry_run=dry, wait_secs=wait,
                                                      progress=ticker(job, text), script=ctx.script, via=via,
                                                      **through)
            except (envelope.EnvelopeError, mesh.MeshError) as exc:
                if not group and not area:
                    raise
                job.land({"node": d["node"], "name": label, "command": command, "ok": False, "code": None,
                          "code_name": None, "reply": None, "verified": None, "line": f"not sent: {exc}"})
                lines.append(f"{label[:12]:12} not sent: {exc}")
                continue
            r = answers.get(d["node"])
            answered += r is not None
            asked += 1
            job.land(outcome(d["node"], label, command, r, d.get("ver"), line="not sent (dry run)" if dry else None))
            job.update(answered=answered)
            lines += l
            topics.append(topic)
        job.update(text=f"{answered} of {len(devices)} answered")
        if area and not dry:
            store.record(None, command, actions.area_topic(area), None, note=f"{answered} of {len(devices)} answered", road=via)
        return {"command": command, "lines": lines, "answered": answered, "asked": asked, "dry_run": dry, "topics": topics}

    return 202, ctx.jobs.start("send", work).snapshot()


def start_run_set(ctx, _p, _q, body):
    name = (body.get("set") or "").strip().lower() if isinstance(body.get("set"), str) else ""
    steps = ctx.store.sets().get(name)
    if not steps:
        raise not_found(f"no set named {name!r}")
    steps = actions.fill(steps, body.get("arg") or "")
    devices, area = _targets(ctx, body)
    _vet(ctx, steps, area, body)
    dry, wait = bool(body.get("dry_run")), _wait(body)
    store = ctx.store

    def on_step(job, label):
        return lambda i, command: job.update(step=i, steps=len(steps), text=f"{label}: step {i + 1} of {len(steps)}, {command}")

    def work(job):
        job.update(steps=len(steps))
        lines, runs = [], []
        job.update(expected=len(devices))
        for d in devices:
            if job.stopping():
                break
            label = _label(d)
            l, stopped = actions.run_set(store, steps, device=d, dry_run=dry, wait_secs=wait, on_step=on_step(job, label),
                                         progress=ticker(job, lambda n, label=label: f"{label}: {'answered' if n else 'waiting'}"),
                                         script=ctx.script)
            lines += [f"== {label}"] + l
            runs.append({"target": d["node"], "stopped_at": stopped})
            line = (f"stopped at step {stopped + 1}: {steps[stopped]}" if stopped is not None
                    else ("not sent (dry run)" if dry else f"all {len(steps)} steps answered ok"))
            job.land({"node": d["node"], "name": label, "command": steps[-1] if stopped is None else steps[stopped],
                      "ok": None if dry else stopped is None, "code": None, "code_name": None, "reply": None,
                      "verified": None, "line": line})
        return {"steps": steps, "lines": lines, "runs": runs}

    return 202, ctx.jobs.start("run-set", work).snapshot()


def start_discover(ctx, _p, _q, body):
    """Without a region: your nodes from their alive messages (mcc3, lou-20 and later),
    wherever they are. With one: the old scheme's read broadcast to that IATA region, which
    only lou-19 and older still answer."""
    asked = body.get("region")
    if asked is not None and not isinstance(asked, str):
        raise bad("region is a string: the IATA code, e.g. JKG; several with commas, or * for every region you have")
    if not (asked or "").strip():
        return _start_discover_alive(ctx, body)
    regions = actions.regions_asked(asked, ctx.store)
    if not regions:
        raise bad("discovery needs a region: the IATA code, e.g. JKG; several with commas, or * for every region you have")
    wait, add = _wait(body), bool(body.get("add"))
    ctx.store.seed()
    store = ctx.store

    def work(job):
        found = []
        job.update(steps=len(regions))
        for i, region in enumerate(regions):
            if job.stopping():
                break
            job.update(step=i)
            part = actions.discover(store, region, wait_secs=wait,
                                    progress=ticker(job, lambda n, region=region: f"{region}: {n} answered ({i + 1} of {len(regions)} regions)"),
                                    script=ctx.script)
            for e in part:
                e = {"node": e["node"], "region": e["region"], "code": e["code"], "reply": e["reply"] or "",
                     "key": e.get("key"), "verified": e.get("verified"), "known_as": e.get("known_as"),
                     "outcome": e["outcome"], "name": e.get("name") or "", "added": False,
                     "broker": e.get("broker") or store.broker_for(e["region"])}
                if add and e["known_as"] is None and store.device(e["node"]) is None:
                    actions.adopt(store, e, e["name"])
                    e["added"] = True
                found.append(e)
                job.land({"node": e["node"], "name": e["name"] or e["known_as"] or e["node"],
                          "command": transport.DISCOVERY_COMMAND, "ok": e["code"] == 0, "code": e["code"],
                          "code_name": envelope.code_name(e["code"]), "reply": e["reply"], "verified": e["verified"],
                          "line": e["outcome"]})
        job.update(answered=len(found), text=f"{len(found)} found in {', '.join(regions)}")
        return {"regions": regions, "found": found}

    return 202, ctx.jobs.start("discover", work).snapshot()


def _start_discover_alive(ctx, body):
    wait, add = _wait(body), bool(body.get("add"))
    ctx.store.seed()
    store = ctx.store
    broker = store.config()["broker"]

    def work(job):
        found = []
        part = actions.discover_alive(store, wait_secs=wait, add=add,
                                      progress=ticker(job, lambda n: f"{n} of your nodes alive"))
        for e in part:
            e = {"node": e["node"], "region": "", "code": 0, "reply": e["version"], "key": e["key"],
                 "verified": True, "known_as": e["known_as"], "outcome": f"{e['state']} {e['version']}".strip(),
                 "name": e["name"], "added": e["added"], "broker": broker, "scheme": "mcc3",
                 "state": e["state"], "version": e["version"]}
            found.append(e)
            job.land({"node": e["node"], "name": e["name"] or e["known_as"] or e["node"], "command": "alive",
                      "ok": e["state"] == "online", "code": 0, "code_name": envelope.code_name(0),
                      "reply": e["reply"], "verified": True, "line": e["outcome"]})
        job.update(answered=len(found), text=f"{len(found)} of your nodes found by their alive messages")
        return {"regions": [], "found": found}

    return 202, ctx.jobs.start("discover", work).snapshot()


def start_refresh_names(ctx, _p, _q, body):
    devices, wait = _some(ctx, body), _wait(body)
    ctx.store.seed()
    store = ctx.store

    def work(job):
        named = versioned = asked = 0
        lines = []
        job.update(expected=len(devices))
        for i, d in enumerate(devices):
            if job.stopping():
                break
            label = _label(d)
            n, v, l = actions.refresh_names(store, [d], wait_secs=wait,
                                            progress=ticker(job, lambda _n, label=label, i=i: f"get name and ver to {label} ({i + 1} of {len(devices)})"),
                                            script=ctx.script)
            named, versioned, asked = named + n, versioned + v, asked + 1
            lines += l
            job.land({"node": d["node"], "name": label, "command": "get name, ver", "ok": v > 0, "code": None,
                      "code_name": None, "reply": None, "verified": None,
                      "line": "; ".join(x[13:] for x in l)})
            job.update(answered=versioned)
        job.update(text=f"{versioned} of {len(devices)} gave a version; {named} named")
        return {"named": named, "versioned": versioned, "asked": asked, "lines": lines}

    return 202, ctx.jobs.start("refresh-names", work).snapshot()


def start_refresh_fleet(ctx, _p, _q, body):
    devices = _some(ctx, body)
    store = ctx.store

    def work(job):
        updated = failed = 0
        job.update(expected=len(devices))
        for i, d in enumerate(devices):
            if job.stopping():
                break
            job.update(text=f"Beacon: {i} of {len(devices)} asked")
            u, f = actions.refresh_fleet(store, [d])
            updated, failed = updated + u, failed + f
            fleet = (store.device(d["node"]) or {}).get("fleet") or {}
            job.land({"node": d["node"], "name": _label(d), "command": "Beacon status", "ok": bool(u), "code": None,
                      "code_name": None, "reply": None, "verified": None,
                      "line": f"battery {fleet.get('battery_mv')} mV, seen {fleet.get('seen')}" if u else "no statistics on Beacon"})
            job.update(answered=updated)
        job.update(text=f"refreshed {updated} of {len(devices)}")
        return {"updated": updated, "failed": failed, "asked": updated + failed}

    return 202, ctx.jobs.start("refresh-fleet", work).snapshot()


def start_statistics(ctx, _p, _q, body):
    if not isinstance(body.get("device"), str):
        raise bad("device is required")
    d = device_of(ctx, body["device"])
    range_, interval = body.get("range", "24h"), body.get("interval", "6h")
    if range_ not in beacon.RANGES or interval not in beacon.INTERVALS:
        raise bad(f"range is one of {', '.join(beacon.RANGES)}; interval one of {', '.join(beacon.INTERVALS)}")
    live = body.get("live", True) is not False
    store = ctx.store

    def work(job):
        lines, sample, points = actions.statistics(store, d, range_, interval, live=live, details=True,
                                   progress=ticker(job, lambda n: "answered" if n else "waiting for the live sample"),
                                   script=ctx.script)
        if not lines[0].startswith("live"):             # a live answer is kept by send() itself
            summary = ", ".join(l.split(None, 1)[1].strip() if " " in l else l for l in lines[1:4] if l)
            store.remember_read(d["node"], "stats (Beacon)", summary[:60])
        job.update(text="done")
        return {"node": d["node"], "lines": lines, "sample": sample, "points": points}

    return 202, ctx.jobs.start("statistics", work).snapshot()


def _broker_asked(ctx, body):
    """The broker a test or a registration is for: `broker` by name, or `region`'s; None
    when neither is given."""
    broker, region = body.get("broker"), body.get("region")
    if broker is not None and not isinstance(broker, str) or region is not None and not isinstance(region, str):
        raise bad("broker and region are strings")
    if broker and region:
        raise bad("give broker or region, not both")
    if region:
        code = _store.valid_region(region)
        if not code:
            raise bad("region is its IATA code, e.g. VGR")
        return ctx.store.broker_for(code)
    if broker:
        if broker not in ctx.store.brokers():
            raise bad(f"{broker} is not a broker in use; they are {', '.join(ctx.store.brokers())}")
        return broker
    return None


def start_test(ctx, _p, _q, body):
    store = ctx.store
    broker = _broker_asked(ctx, body or {})

    def work(job):
        config = store.config()
        config["broker"] = broker or config["broker"]
        job.update(text=f"connecting to {config['broker']}")
        steps = transport.test_connection(config, seed_hex=store.seed() if store.has_key() else None)
        store.remember_test(config["broker"], config["port"], all(ok for _s, ok, _d in steps))   # kept: STATUS says it
        return {"steps": [{"step": s, "ok": ok, "detail": detail} for s, ok, detail in steps],
                "key": store.public_key() if store.has_key() else None,
                "broker": config["broker"], "registered": store.registration(config["broker"]),
                "ok": all(ok for _s, ok, _d in steps)}

    return 202, ctx.jobs.start("test", work).snapshot()


def start_register(ctx, _p, _q, body):
    ctx.store.seed()
    store = ctx.store
    broker = _broker_asked(ctx, body or {})

    def work(job):
        brokers = [broker] if broker else store.brokers()
        job.update(text=f"publishing the public key to {', '.join(brokers)}", steps=len(brokers))
        results = []
        for i, b in enumerate(brokers):
            job.update(step=i, text=f"publishing the public key to {b}")
            # One broker: its failure is the job's, as before RB-1. Several: each is tried.
            ok, detail = actions.register(store, b) if len(brokers) == 1 else actions.register_all(store, [b])[0][1:]
            results.append({"broker": b, "ok": ok, "detail": detail})
        one = len(results) == 1
        return {"ok": all(r["ok"] for r in results),
                "detail": results[0]["detail"] if one else "; ".join(f"{r['broker']}: {r['detail']}" for r in results),
                "broker": ", ".join(r["broker"] for r in results), "results": results}

    return 202, ctx.jobs.start("register", work).snapshot()


def list_jobs(ctx, _p, _q, _b):
    return 200, {"jobs": [j.snapshot() for j in ctx.jobs.all()]}


def get_job(ctx, params, _q, _b):
    return 200, ctx.jobs.get(params["id"]).snapshot()


def cancel_job(ctx, params, _q, _b):
    job = ctx.jobs.get(params["id"])
    with job.lock:
        if job.status != "running":
            raise ApiError(409, "finished", f"job {job.id} is already {job.status}")
        job.cancel.set()
    return 202, job.snapshot()


TABLE = [
    ("GET", "/jobs", list_jobs),
    ("POST", "/jobs/send", start_send),
    ("POST", "/jobs/run-set", start_run_set),
    ("POST", "/jobs/discover", start_discover),
    ("POST", "/jobs/refresh-names", start_refresh_names),
    ("POST", "/jobs/refresh-fleet", start_refresh_fleet),
    ("POST", "/jobs/statistics", start_statistics),
    ("POST", "/jobs/test", start_test),
    ("POST", "/jobs/register", start_register),
    ("GET", "/jobs/{id}", get_job),
    ("DELETE", "/jobs/{id}", cancel_job),
]
