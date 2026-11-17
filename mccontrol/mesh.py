"""The mesh road: a signed command carried to one node over LoRa, through your own companion.

Must match the firmware's "mesh road" (`src/helpers/MqttControlLogic.h`, OTM-1, lou-19) and
`planning/firmware/otm-wire-format-20261117.md` byte for byte. A MeshCore anonymous request
(`CMD_SEND_ANON_REQ`, 57) to the node's key carries, after the companion's own 4-byte tag:

    C1 | counter (4, LE) | expiry (4, LE) | Ed25519 signature (64, raw) | command (1..59, UTF-8)

signed exactly as on MQTT (`envelope`): `"{topic}\\n" + "v1|{counter}|{expiry}|{command}"`,
for the node's command topic with its WHOLE key -- `meshcore/{IATA}/{KEY}/cmd`, or
`meshcore/mesh/{KEY}/cmd` on a mesh-only node, which has no IATA. One signature is valid on
both roads, and the node keeps one counter, so whichever road delivers first runs it.

The answer comes back as a RESPONSE the companion hands over as `PUSH_CODE_BINARY_RESPONSE`,
after the tag: node clock (4, LE) | counter (4, LE) | result code (1) | reply (UTF-8, maybe cut).
It is encrypted to us with the node's key exchange and MAC'd, so it is the node's own word.

Silence is never a refusal: a replay, a bad signature, a node without the road, a closed
`mqtt.cmd.mesh`, the mesh budget -- all say nothing.
"""

import asyncio
import struct
import time

from . import envelope

SUBTYPE = 0xC1
CMD_SEND_ANON_REQ = 57
MAX_COMMAND = 59            # 136 bytes of plaintext in an anonymous datagram, less the 77-byte head
HEAD = 1 + 4 + 4 + 64       # what the app sends before the command (the tag is the companion's)
MESH_ONLY_REGION = "mesh"   # MQTTCTRL_MESH_ONLY_REGION
CLOCK_SET_FROM = 1735689600  # a node clock below this (2025-01-01) is unset
RESPONSE_HEAD = 4 + 4 + 1


class MeshError(Exception):
    """The companion could not be reached or could not send. Nothing went on the air unless
    the message says so."""


def check_command(command):
    """Refuse a command the road cannot carry, before anything is signed."""
    size = len((command or "").encode("utf-8"))
    if not 1 <= size <= MAX_COMMAND:
        raise envelope.EnvelopeError(f"over the mesh a command is 1..{MAX_COMMAND} bytes; "
                                     f"this one is {size}")


def topic(region, key_hex, mesh_only=False):
    """The command topic the node rebuilds and the signature covers: always the whole key."""
    key = envelope.node_key(key_hex or "")
    if not key:
        raise envelope.EnvelopeError("the mesh road needs the node's whole public key (64 hex); "
                                     "discover the node or change the device to add it")
    if mesh_only:
        return f"{envelope.TOPIC_PREFIX}{MESH_ONLY_REGION}/{key}/cmd"
    if not region:
        raise envelope.EnvelopeError("the mesh road signs for the node's region; the device has none")
    return f"{envelope.TOPIC_PREFIX}{region.upper()}/{key}/cmd"


def signature(seed_hex, topic_, counter, expiry, command):
    from Crypto.Signature import eddsa
    part = envelope.signed_part(counter, expiry, command)
    return eddsa.new(envelope.key_from_seed(seed_hex), "rfc8032").sign(envelope.signed_message(topic_, part))


def request(seed_hex, topic_, counter, expiry, command):
    """The body the app gives `CMD_SEND_ANON_REQ` after the node's key: 73 bytes + the command."""
    check_command(command)
    if not 0 <= expiry <= 0xFFFFFFFF:
        raise envelope.EnvelopeError("the expiry must fit in 32 bits")
    sig = signature(seed_hex, topic_, counter, expiry, command)
    return bytes([SUBTYPE]) + struct.pack("<II", counter, expiry) + sig + command.encode("utf-8")


def build(seed_hex, topic_, counter, command, ttl_secs=envelope.DEFAULT_TTL_SECS, now=None):
    """`request` with the expiry `now + ttl_secs`, as the MQTT road takes it."""
    now = int(time.time() if now is None else now)
    if not 0 < ttl_secs <= envelope.MAX_FUTURE_SECS:
        raise envelope.EnvelopeError(f"ttl is 1..{envelope.MAX_FUTURE_SECS} seconds")
    return request(seed_hex, topic_, counter, now + ttl_secs, command)


def frame(key_hex, body):
    """The whole companion command frame: 57, the node's 32-byte key, the body."""
    return bytes([CMD_SEND_ANON_REQ]) + bytes.fromhex(key_hex) + body


class MeshResult(envelope.Result):
    """A result that came over the mesh: `clock` is the node's clock (None when unset)."""

    __slots__ = ("clock",)

    def __init__(self, node, counter, code, command, reply, clock):
        super().__init__(node, counter, code, command, reply, True)
        self.clock = clock


def _text(data):
    """UTF-8 that may have been cut inside a sequence: the whole characters only."""
    for cut in range(0, min(4, len(data)) + 1):
        try:
            return data[:len(data) - cut].decode("utf-8")
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def parse_response(data, node=None, command="", counter=None):
    """A response as the companion hands it (after the tag) as a MeshResult, or None when it
    is too short or answers another counter."""
    data = bytes(data or b"")
    if len(data) < RESPONSE_HEAD:
        return None
    clock, got = struct.unpack("<II", data[:8])
    if counter is not None and got != counter:
        return None
    return MeshResult(node, got, data[8], command, _text(data[9:]),
                      clock if clock >= CLOCK_SET_FROM else None)


def response(clock, counter, code, reply=""):
    """The bytes a node answers with after the tag; for tests and the vectors."""
    return struct.pack("<IIB", clock, counter, code) + reply.encode("utf-8")


# -- the companion -------------------------------------------------------------------------
#
# A companion spec names the operator's own radio: `tcp:HOST:PORT`, `serial:/dev/ttyACM0`
# (`serial:PORT:BAUD`), or `ble:ADDRESS`. One connection per command, closed after it.

def parse_spec(spec):
    """`(kind, args)` from a companion spec, or MeshError."""
    text = (spec or "").strip()
    kind, _, rest = text.partition(":")
    kind = kind.lower()
    if kind == "tcp":
        host, _, port = rest.rpartition(":")
        if not host or not port.isdigit():
            raise MeshError("a TCP companion is tcp:HOST:PORT, e.g. tcp:10.0.0.5:5000")
        return kind, (host, int(port))
    if kind == "serial":
        port, _, baud = rest.partition(":")
        if not port or (baud and not baud.isdigit()):
            raise MeshError("a serial companion is serial:PORT or serial:PORT:BAUD")
        return kind, (port, int(baud) if baud else 115200)
    if kind == "ble":
        if not rest:
            raise MeshError("a Bluetooth companion is ble:ADDRESS")
        return kind, (rest,)
    raise MeshError("no companion set: mccontrol config --companion tcp:HOST:PORT "
                    "(or serial:PORT, ble:ADDRESS)" if not text else
                    f"{text!r} is not a companion: tcp:HOST:PORT, serial:PORT or ble:ADDRESS")


class Companion:
    """meshcore_py over the operator's companion. Every method is a coroutine; tests stand in
    a fake with the same five (`open`, `contact`, `add_contact`, `send`, `response`, `close`)."""

    def __init__(self, spec):
        self.kind, self.args = parse_spec(spec)
        self.mc = None
        self.answers = {}

    async def open(self):
        try:
            from meshcore import MeshCore, EventType
        except ImportError:
            raise MeshError("the mesh road needs the meshcore package: pip install 'mccontrol[mesh]'") from None
        self._events = EventType
        make = {"tcp": MeshCore.create_tcp, "serial": MeshCore.create_serial, "ble": MeshCore.create_ble}[self.kind]
        try:
            self.mc = await make(*self.args)
        except Exception as exc:            # each connection type raises its own
            raise MeshError(f"cannot reach the companion ({self.kind}): {exc}") from None
        if self.mc is None:
            raise MeshError(f"the companion ({self.kind}) did not answer")
        # every binary response, kept by tag, so one that lands before we wait is not lost
        self.mc.subscribe(EventType.BINARY_RESPONSE,
                          lambda e: self.answers.__setitem__(e.payload["tag"], bytes.fromhex(e.payload["data"])))

    async def contact(self, key_hex):
        await self.mc.commands.get_contacts()
        c = self.mc.get_contact_by_key_prefix(key_hex.lower())
        return None if c is None else {"name": c.get("adv_name", ""), "out_path_len": c.get("out_path_len", -1)}

    async def add_contact(self, key_hex, name):
        # a repeater with no path: the request floods once, and the node's path return teaches
        # the companion a path for the next one
        res = await self.mc.commands.add_contact({
            "public_key": key_hex.lower(), "type": 2, "flags": 0, "out_path_len": -1, "out_path": "",
            "out_path_hash_mode": 0, "adv_name": (name or key_hex[:8])[:31], "last_advert": int(time.time()),
            "adv_lat": 0.0, "adv_lon": 0.0})
        return res is not None and res.type != self._events.ERROR

    async def send(self, key_hex, body):
        res = await self.mc.commands.send(frame(key_hex, body), [self._events.MSG_SENT, self._events.ERROR])
        if res is None or res.type == self._events.ERROR:
            raise MeshError(f"the companion refused the request: {getattr(res, 'payload', None)}")
        return {"tag": res.payload["expected_ack"].hex(), "flood": res.payload.get("type") == 1,
                "timeout": res.payload.get("suggested_timeout", 0) / 1000.0}

    async def response(self, tag_hex, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if tag_hex in self.answers:
                return self.answers.pop(tag_hex)
            await asyncio.sleep(0.1)
        return self.answers.pop(tag_hex, None)

    async def close(self):
        if self.mc is not None:
            await self.mc.disconnect()


def open_companion(spec):
    """The companion to send through; tests replace this (and nothing here opens a radio
    unless a send over the mesh is asked for)."""
    return Companion(spec)


TICK_SECS = 0.2


async def _send(companion, key_hex, name, body, counter, command, wait_secs, progress, node):
    info = {}
    await companion.open()
    try:
        c = await companion.contact(key_hex)
        if c is None:
            if not await companion.add_contact(key_hex, name):
                raise MeshError("the companion would not take the node as a contact (its contact list may be full)")
            info["contact"] = "added"
            c = {"out_path_len": -1}
        else:
            info["contact"] = "known"
        hops = c.get("out_path_len", -1)
        info["path"] = "flood" if hops is None or hops < 0 else f"direct, {hops} hop(s)"
        sent = await companion.send(key_hex, body)
        info["path"] = "flood" if sent.get("flood") else info["path"]
        wait = max(wait_secs, sent.get("timeout") or 0)
        start = time.monotonic()
        data = None
        while data is None:
            elapsed = time.monotonic() - start
            if progress and progress(min(elapsed, wait), wait, []):
                break
            if elapsed >= wait:
                break
            data = await companion.response(sent["tag"], min(TICK_SECS, wait - elapsed))
        result = parse_response(data, node, command, counter) if data is not None else None
        return result, info
    finally:
        await companion.close()


def send(spec, seed_hex, region, key_hex, command, mesh_only=False, name="", counter=None,
         ttl_secs=envelope.DEFAULT_TTL_SECS, wait_secs=30.0, progress=None, now=None):
    """Sign `command` for the node with `key_hex` and send it through the companion at `spec`.

    Returns `(topic, body, result_or_None, info)`; `info` says whether the path was known
    (`direct, N hop(s)`) or the request flooded, and whether the node was made a contact.
    The 59-byte check comes before any signing or connecting."""
    check_command(command)
    topic_ = topic(region, key_hex, mesh_only)
    counter = int(time.time()) if counter is None else counter
    body = build(seed_hex, topic_, counter, command, ttl_secs=ttl_secs, now=now)
    key = envelope.node_key(key_hex)
    companion = open_companion(spec)
    result, info = asyncio.run(_send(companion, key, name, body, counter, command, wait_secs, progress, key[:8]))
    return topic_, body, result, info
