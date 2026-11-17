"""Everything mccontrol remembers, under one directory the user owns.

    ~/.config/mccontrol/
        key.seed          the private signing seed, 64 hex, mode 0600; never printed
        config.json       brokers (the shared one, and any region's own), defaults
        devices.json      the devices you manage: name, node hex, notes, last seen
        groups.json       named groups of devices (`canary`, a site): name -> node ids
        history/<node>.jsonl   every command sent to that device and what came back

Override the directory with MCCONTROL_HOME. Nothing here is ever sent anywhere except the
signed envelope, and the seed is never part of it.
"""

import datetime
import json
import os
import pathlib
import stat

from . import envelope

# The configuration is the control brokers and nothing else: the ones that take the signed
# commands and carry the results back. A region is a property of each device, since one
# person may run repeaters in several; `broker` is the shared broker every region uses unless
# `brokers` names its own (RB-1): `{"VGR": "mqtt.meshcore-vgr.se"}`. Port, TLS and a password
# login are the same for every broker.
DEFAULT_CONFIG = {
    "broker": "mqtt-meshcore.louie.se",
    "brokers": {},
    # The command plane is TLS on 8883: the broker's plugin refuses commands and registration
    # on the plain listener, where a token could be copied off the wire.
    "port": 8883,
    "tls": True,
    "username": "",
    "password": "",
    "ttl_secs": envelope.DEFAULT_TTL_SECS,
    "wait_secs": 20,
    # Statistics come from a Beacon server (read-only HTTP, no credentials); one URL, since
    # one Beacon covers a country, and another region's Beacon is this one setting.
    "beacon_url": "https://beacon.meshcoresverige.se/api/v1",
    # Which optional columns the directory shows after name and node (directory.COLUMNS);
    # a narrow terminal shows what is chosen here rather than the first that fit.
    "columns": ["reg", "sent", "batt", "seen", "ver", "result"],
}

# Alt+1..9 on the main screen and `mccontrol alt <n>` on the command line: a command each,
# sent without a dialog. Reads by default; a user may put anything there, and a caution
# still asks.
# A command set: a named list sent in order to a device, stopping at the first refusal or
# silence. `{arg}` in a step is filled in when the set is run. One shipped as the example.
DEFAULT_SETS = {
    "add-scope": ["region put {arg} *", "region allowf {arg}", "region save", "region"],
}
SET_STEPS = 6

# Earlier names of the default broker, newest first. All name the same server, and its
# plugin accepts a token only for a name it lists, so a configuration still holding one is
# moved to the current default on load: the next login signs for the name the broker takes.
FORMER_BROKERS = ("mqtt.meshcore-jkp.se", "mqtt.louie.se")
# A saved configuration holds every default as it was when saved, so a former default Beacon
# is moved to the current one like a former broker.
FORMER_BEACONS = ("https://beacon.meshat.se/api/v1", "https://beacon.meshcore-jkp.se/api/v1")

SHORTCUT_SLOTS = 9
DEFAULT_SHORTCUTS = ["region", "ver", "get name", "get autoreply", "get radio", "get repeat"]


def _migrate_broker(stored):
    """Rename a former default broker in a stored configuration, and in its records of
    registering and testing there, to the current default, and a former default Beacon. True
    when anything changed."""
    changed = False
    if stored.get("beacon_url") in FORMER_BEACONS:
        stored["beacon_url"] = DEFAULT_CONFIG["beacon_url"]
        changed = True
    for record in (stored, stored.get("registered"), stored.get("tested")):
        if isinstance(record, dict) and record.get("broker") in FORMER_BROKERS:
            record["broker"] = DEFAULT_CONFIG["broker"]
            changed = True
    # A region pointed at a former name of the shared broker, and a registration there.
    brokers = stored.get("brokers")
    if isinstance(brokers, dict):
        for region, host in brokers.items():
            if host in FORMER_BROKERS:
                brokers[region] = DEFAULT_CONFIG["broker"]
                changed = True
    regs = stored.get("registrations")
    if isinstance(regs, dict):
        for host in [h for h in regs if h in FORMER_BROKERS]:
            at = regs.pop(host)
            regs[DEFAULT_CONFIG["broker"]] = max(at, regs.get(DEFAULT_CONFIG["broker"]) or at)
            changed = True
    # The one registration kept before RB-1 joins the per-broker record; it stays where it
    # was too, for an older mccontrol reading the same directory.
    reg = stored.get("registered")
    if isinstance(reg, dict) and reg.get("broker") and reg.get("at"):
        regs = stored.setdefault("registrations", {})
        if not isinstance(regs, dict):
            regs = stored["registrations"] = {}
        if (regs.get(reg["broker"]) or "") < reg["at"]:
            regs[reg["broker"]] = reg["at"]
            changed = True
    return changed


def valid_region(region):
    """An IATA code as the topics carry it: 2 to 8 letters or digits, upper case here."""
    region = (region or "").strip().upper()
    return region if 2 <= len(region) <= 8 and region.isalnum() and region.isascii() else None


def valid_host(host):
    """A broker's host name: letters, digits, hyphens and dots, at least one dot."""
    import re
    host = (host or "").strip().lower()
    label = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    return host if re.fullmatch(rf"{label}(\.{label})+", host) and len(host) <= 253 else None


class StoreError(Exception):
    pass


def home(env=None):
    env = os.environ if env is None else env
    path = env.get("MCCONTROL_HOME")
    if path:
        return pathlib.Path(path)
    base = env.get("XDG_CONFIG_HOME") or os.path.join(env.get("HOME", "~"), ".config")
    return pathlib.Path(os.path.expanduser(base)) / "mccontrol"


class Store:
    def __init__(self, root=None, env=None):
        self.root = pathlib.Path(root) if root else home(env)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "history").mkdir(exist_ok=True)

    # -- key ---------------------------------------------------------------------------

    @property
    def key_path(self):
        return self.root / "key.seed"

    def has_key(self):
        return self.key_path.is_file()

    def create_key(self, overwrite=False):
        """A new signing key. Refuses to replace one unless told to: every node provisioned
        with the old public key would stop listening."""
        if self.has_key() and not overwrite:
            raise StoreError(f"a key already exists at {self.key_path}; "
                             f"replacing it would silence every node provisioned with it")
        seed = envelope.generate_seed()
        self._write_private(self.key_path, seed + "\n")
        return envelope.public_key_hex(seed)

    def import_key(self, seed_hex, overwrite=False):
        if self.has_key() and not overwrite:
            raise StoreError(f"a key already exists at {self.key_path}")
        public = envelope.public_key_hex(seed_hex)      # validates before anything is written
        self._write_private(self.key_path, seed_hex.strip() + "\n")
        return public

    def seed(self):
        if not self.has_key():
            raise StoreError("no signing key yet: create one first")
        mode = stat.S_IMODE(self.key_path.stat().st_mode)
        if mode & 0o077:
            raise StoreError(f"{self.key_path} is readable by others (mode {mode:o}); "
                             f"chmod 600 it")
        return self.key_path.read_text(encoding="utf-8").strip()

    def public_key(self):
        return envelope.public_key_hex(self.seed())

    @staticmethod
    def _write_private(path, text):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(path, 0o600)

    # -- config ------------------------------------------------------------------------

    def config(self):
        data = dict(DEFAULT_CONFIG)
        stored = self._read_json(self.root / "config.json", {})
        if _migrate_broker(stored):
            self._write_json(self.root / "config.json", stored)
        data.update(stored)
        return data

    def save_config(self, **changes):
        data = self.config()
        data.update({k: v for k, v in changes.items() if v is not None})
        self._write_json(self.root / "config.json", data)
        return data

    def sets(self):
        """Named command sets, the shipped example included until it is removed or renamed."""
        sets = dict(DEFAULT_SETS)
        sets.update(self.config().get("sets", {}))
        return {n: [str(s).strip() for s in steps if str(s).strip()] for n, steps in sets.items() if steps}

    def save_set(self, name, steps):
        name = (name or "").strip().lower()
        if not name or " " in name:
            raise StoreError("a set's name is one word")
        sets = dict(self.config().get("sets", {}))
        sets.setdefault(name, [])
        sets.update({n: s for n, s in DEFAULT_SETS.items() if n not in sets})
        sets[name] = [s.strip() for s in steps if s and s.strip()]
        if not sets[name]:
            raise StoreError("a set needs at least one command")
        self.save_config(sets=sets)
        return sets[name]

    def remove_set(self, name):
        sets = dict(self.config().get("sets", {}))
        sets.update({n: s for n, s in DEFAULT_SETS.items() if n not in sets})
        if name not in sets:
            raise StoreError(f"no set named {name}")
        sets[name] = []                   # an empty list is a removed set, the shipped one included
        self.save_config(sets=sets)

    # -- brokers, per region (RB-1) -----------------------------------------------------

    def broker_for(self, region, config=None):
        """The broker a region's devices use: its own when `brokers` names one, else the
        shared broker (`broker`)."""
        config = config or self.config()
        own = (config.get("brokers") or {}).get((region or "").strip().upper())
        return own or config["broker"]

    def config_for(self, region, config=None):
        """The configuration to reach `region` with: its broker as `broker`, so the login
        token is signed for that broker's name, and the region itself."""
        config = config or self.config()
        return dict(config, broker=self.broker_for(region, config), region=(region or "").strip().upper())

    def brokers(self):
        """Every broker in use, each once: the shared one first, then each region's own."""
        config = self.config()
        return list(dict.fromkeys([config["broker"]] + list((config.get("brokers") or {}).values())))

    def set_region_broker(self, region, host):
        """Point `region` at its own broker, or with an empty host (or the shared broker's
        name) back at the shared one. A device keeps its region either way: moving a region
        between brokers loses no device, only the registration with the new broker is new."""
        code = valid_region(region)
        if not code:
            raise StoreError("a region is its IATA code: 2 to 8 letters or digits, e.g. VGR")
        brokers = dict(self.config().get("brokers") or {})
        host = (host or "").strip()
        if host and not valid_host(host):
            raise StoreError(f"{host!r} is not a host name, e.g. mqtt.meshcore-vgr.se")
        host = valid_host(host) if host else ""
        if not host or host == self.config()["broker"]:
            brokers.pop(code, None)
        else:
            brokers[code] = host
        return self.save_config(brokers=brokers)["brokers"]

    def registration(self, broker=None):
        """`{broker, at}` when this key is registered with `broker` (the shared broker when
        not given), else None."""
        config = self.config()
        broker = broker or config["broker"]
        at = (config.get("registrations") or {}).get(broker)
        return {"broker": broker, "at": at} if at else None

    def registrations(self):
        """`{broker: at or None}` for every broker in use: what the key screens show."""
        regs = self.config().get("registrations") or {}
        return {b: regs.get(b) for b in self.brokers()}

    def remember_registration(self, broker):
        config = self.config()
        regs = dict(config.get("registrations") or {})
        regs[broker] = _now()
        changes = {"registrations": regs}
        if broker == config["broker"]:
            changes["registered"] = {"broker": broker, "at": regs[broker]}   # read by mccontrol before RB-1
        self.save_config(**changes)

    def tested(self):
        """`{broker, port, ok, at}` of the last connection test, else None."""
        return self.config().get("tested") or None

    def remember_test(self, broker, port, ok):
        self.save_config(tested={"broker": broker, "port": port, "ok": bool(ok), "at": _now()})

    def shortcuts(self):
        """Nine slots, Alt+1 first; an empty string is an unused slot."""
        slots = list(self.config().get("shortcuts", DEFAULT_SHORTCUTS))
        slots = [str(s).strip() for s in slots[:SHORTCUT_SLOTS]]
        return slots + [""] * (SHORTCUT_SLOTS - len(slots))

    # -- devices -----------------------------------------------------------------------

    def devices(self):
        """Your devices, in the order you added them."""
        return self._read_json(self.root / "devices.json", [])

    def regions(self):
        """The regions your devices are in, each once, in first-seen order."""
        return list(dict.fromkeys(d.get("region", "") for d in self.devices() if d.get("region")))

    def device(self, ref):
        """By name, by node hex, or by a unique prefix of either; None if nothing matches."""
        ref = (ref or "").strip()
        if not ref:
            return None
        # A whole public key names the node by its first eight characters, like the topics.
        key = ref.upper()[:envelope.NODE_HEX_LEN] if len(ref) >= envelope.NODE_HEX_LEN and all(
            c in "0123456789abcdefABCDEF" for c in ref) else None
        exact = [d for d in self.devices() if d["name"] and d["name"].lower() == ref.lower()
                 or d["node"].upper() == ref.upper() or (key and d["node"].upper() == key)]
        if len(exact) == 1:
            return exact[0]
        prefix = [d for d in self.devices() if (d["name"] and d["name"].lower().startswith(ref.lower()))
                  or d["node"].upper().startswith(ref.upper())]
        return prefix[0] if len(prefix) == 1 else None

    def add_device(self, name, node, region, notes="", key=None):
        try:
            key = envelope.node_key(key) if key else envelope.node_key(node)   # a whole key given as the node is kept
            node = envelope.node_id(node)
        except envelope.NodeIdError as exc:
            raise StoreError(str(exc)) from None
        name = name.strip()          # empty is allowed: the id stands in until you name it
        region = valid_region(region)
        if not region:
            raise StoreError("a device needs its region: the IATA code its observers use, e.g. JKG")
        devices = self.devices()
        if name and any(d["name"].lower() == name.lower() for d in devices):
            raise StoreError(f"a device named {name!r} already exists")
        if any(d["node"] == node for d in devices):
            raise StoreError("that node is already in the list")
        entry = {"name": name, "node": node, "region": region, "notes": notes.strip(), "added": _now(),
                 "last_sent": None, "last_result": None, "key": key}
        devices.append(entry)
        self._write_json(self.root / "devices.json", devices)
        return entry

    def update_device(self, node, **changes):
        devices = self.devices()
        for entry in devices:
            if entry["node"] == node:
                entry.update(changes)
                self._write_json(self.root / "devices.json", devices)
                return entry
        raise StoreError("no such device")

    def remove_device(self, node):
        devices = [d for d in self.devices() if d["node"] != node]
        self._write_json(self.root / "devices.json", devices)
        groups = self._read_json(self.root / "groups.json", {})
        if any(node in members for members in groups.values()):      # a forgotten device leaves its groups
            self._write_json(self.root / "groups.json", {n: [m for m in ms if m != node] for n, ms in groups.items()})

    # -- groups (RM-4) -----------------------------------------------------------------
    # A group is a name and the node ids of its members, kept here and nowhere else: a send
    # to a group is one signed per-node command to each member, never a broadcast.

    def groups(self):
        """`{name: [node, ...]}`, sorted by name, each member a device still known."""
        known = {d["node"] for d in self.devices()}
        groups = self._read_json(self.root / "groups.json", {})
        return {n: [m for m in groups[n] if m in known] for n in sorted(groups)}

    def group(self, name):
        """The members of `name`, None when there is no such group."""
        return self.groups().get((name or "").strip().lower())

    def create_group(self, name, nodes=()):
        name = (name or "").strip().lower()
        if not name or not all(c.isalnum() or c in "-_." for c in name):
            raise StoreError("a group's name is one word: letters, digits, - _ .")
        groups = self._read_json(self.root / "groups.json", {})
        if name in groups:
            raise StoreError(f"a group named {name!r} already exists")
        groups[name] = list(dict.fromkeys(nodes))
        self._write_json(self.root / "groups.json", groups)
        return groups[name]

    def delete_group(self, name):
        groups = self._read_json(self.root / "groups.json", {})
        if groups.pop((name or "").strip().lower(), None) is None:
            raise StoreError(f"no group named {name}")
        self._write_json(self.root / "groups.json", groups)

    def change_group(self, name, add=(), remove=()):
        """Add `add` and take out `remove` (node ids); the members after."""
        name = (name or "").strip().lower()
        groups = self._read_json(self.root / "groups.json", {})
        if name not in groups:
            raise StoreError(f"no group named {name}")
        members = [m for m in dict.fromkeys(list(groups[name]) + list(add)) if m not in set(remove)]
        groups[name] = members
        self._write_json(self.root / "groups.json", groups)
        return self.group(name)

    # -- history -----------------------------------------------------------------------

    def remember_read(self, node, command, reply, verified=None):
        """Keep what a node answered to a read, keyed by the command text, with the time and
        whether the node signed it (True; None for an unsigned r1 from older firmware). A
        refusal, a bad signature or silence is never stored and clears nothing: the last good
        answer stays, with its age showing how old it is."""
        key = " ".join(command.split())
        devices = self.devices()
        for entry in devices:
            if entry["node"] == node:
                reads = dict(entry.get("reads") or {})
                seq = 1 + max((v.get("seq", 0) for v in reads.values()), default=0)
                reads[key] = {"reply": reply, "at": _now(), "seq": seq,     # seq orders same-second reads
                              "verified": verified}
                entry["reads"] = reads
                self._write_json(self.root / "devices.json", devices)
                return reads[key]
        raise StoreError("no such device")

    def reads(self, node):
        """`[(command, reply, at), ...]` newest first, for the reads pane."""
        d = self.device(node) if not isinstance(node, dict) else node
        reads = (d or {}).get("reads") or {}
        return [(k, v["reply"], v["at"]) for k, v in
                sorted(reads.items(), key=lambda kv: (kv[1]["at"], kv[1].get("seq", 0)), reverse=True)]

    def record(self, node, command, topic, result, note=""):
        """One line per command sent: what, where, and what came back (or nothing)."""
        line = {"at": _now(), "command": command, "topic": topic,
                "code": None if result is None else result.code,
                "code_name": None if result is None else result.code_name,
                "reply": None if result is None else result.reply,
                "verified": None if result is None else result.verified, "note": note}
        path = self.root / "history" / f"{node or 'all'}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line) + "\n")
        if node:
            changes = {"last_sent": line["at"], "last_result": (None if result is None else result.code_name)}
            if result is not None:
                changes["last_heard"] = line["at"]      # any answer, a refusal too, proves it is there
            self.update_device(node, **changes)
        return line

    def history(self, node, limit=200):
        path = self.root / "history" / f"{node or 'all'}.jsonl"
        if not path.is_file():
            return []
        lines = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            try:
                line = json.loads(raw)
            except ValueError:
                continue
            line.setdefault("verified", None)       # a line from before signatures were kept: unknown
            lines.append(line)
        return lines[-limit:] if limit else lines          # None: every line

    # -- files -------------------------------------------------------------------------

    @staticmethod
    def _read_json(path, default):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    @staticmethod
    def _write_json(path, data):
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)


def _now():
    return datetime.datetime.now().replace(microsecond=0).isoformat(sep=" ")
