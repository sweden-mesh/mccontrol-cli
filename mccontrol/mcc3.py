"""mcc3: the control plane keyed by the node and sealed to the owner (lou-20 and later).

The wire format is mccontrol-spec's `docs/wire-format-mcc3.md`, and its vectors
(`vectors/mcc3-vectors.json`) pin these functions byte for byte against the firmware and the
web app. In short:

    S        X25519(node identity, owner command key)       the same from either side
    K_cmd    HKDF-SHA256(S, salt empty, "mcc3/cmd/"   + KEY)  MQTT commands and results, mesh responses
    K_mesh   HKDF-SHA256(S, salt empty, "mcc3/mesh/"  + KEY)  mesh requests (ChaCha20, no tag)
    K_alive  HKDF-SHA256(S, salt empty, "mcc3/alive/" + KEY)  alive messages
    signed   "mcc3/sig|" node key, road, flags, counter, expiry, RID (MQTT only), command

KEY is the node's public key in upper-case hex. Every integer is little-endian. MQTT payloads
are base64url without padding. Nothing here connects or sends.
"""

import hashlib
import secrets
import struct

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Signature import eddsa

from . import envelope

TOPIC_ROOT = "mcc/"
SIG_LABEL = b"mcc3/sig|"
INFO_CMD, INFO_MESH, INFO_ALIVE = "mcc3/cmd/", "mcc3/mesh/", "mcc3/alive/"
ROAD_MQTT, ROAD_MESH = 0x00, 0x01
KIND_COMMAND, KIND_RESULT, KIND_ALIVE = 0x43, 0x52, 0x41      # "C", "R", "A"
MESH_SUBTYPE = 0xC2
FLAG_DELEGATION = 0x01             # reserved: lou-20 and lou-21 refuse any non-zero flags

NONCE_LEN, TAG_LEN, SIG_LEN, RID_LEN = 12, 16, 64, 16
COMMAND_PADS = (64, 160)           # MQTT command field
MAX_COMMAND = 160
RESULT_PADS = (256, 512)
ALIVE_PLAIN = 160
COMMAND_SIZES = tuple(2 + NONCE_LEN + 4 + 4 + RID_LEN + SIG_LEN + p + TAG_LEN for p in COMMAND_PADS)   # 182, 278
RESULT_SIZES = tuple(1 + NONCE_LEN + p + TAG_LEN for p in RESULT_PADS)                                  # 285, 541
ALIVE_SIZE = 1 + NONCE_LEN + ALIVE_PLAIN + TAG_LEN                                                      # 189

# The mesh road (ANON_REQ sub-type 0xC2): 136 bytes, no AEAD tag (operator decision 2026-11-18).
MESH_REQUEST_LEN = 136
MESH_COMMAND_FIELD = 58            # zero-padded, always ends in at least one zero
MESH_MAX_COMMAND = 57
MESH_HEADER = 10                   # companion tag 4, sub-type 1, flags 1, counter 4
MESH_MAX_REPLY = 125

# alive plaintext limits
ALIVE_MAX_VERSION, ALIVE_MAX_REGION, ALIVE_MAX_NAME = 31, 29, 32


class Mcc3Error(ValueError):
    """A message could not be built. Never carries a key."""


class Refused(ValueError):
    """A message did not open. `.outcome` is the firmware's name for why (results.json)."""

    def __init__(self, outcome):
        super().__init__(outcome)
        self.outcome = outcome


# -- keys ------------------------------------------------------------------------------------

def _key_hex(value):
    key = envelope.node_key(value)
    if not key:
        raise Mcc3Error("a node is named by its whole public key, 64 hex characters")
    return key


def _seed(seed_hex):
    seed = bytes.fromhex(seed_hex.strip())
    if len(seed) != 32:
        raise Mcc3Error(f"a seed is 32 bytes, got {len(seed)}")
    return seed


def shared_secret(seed_hex, peer_key_hex):
    """S from either side: our Ed25519 seed and the peer's Ed25519 public key (MeshCore's
    `ed25519_key_exchange`). The owner passes its command seed and the node's key; the node,
    its identity seed and the command key."""
    scalar = hashlib.sha512(_seed(seed_hex)).digest()[:32]
    return envelope.x25519(scalar, envelope.montgomery_u(bytes.fromhex(_key_hex(peer_key_hex))))


def derive(secret, node_key_hex):
    """`{"cmd", "mesh", "alive"}` -> 32-byte keys, from S and the node's key."""
    node = _key_hex(node_key_hex)
    return {name: HKDF(secret, 32, b"", SHA256, context=(info + node).encode("ascii"))
            for name, info in (("cmd", INFO_CMD), ("mesh", INFO_MESH), ("alive", INFO_ALIVE))}


def owner_keys(command_seed_hex, node_key_hex):
    return derive(shared_secret(command_seed_hex, node_key_hex), node_key_hex)


def node_keys(node_seed_hex, command_key_hex):
    node = envelope.public_key_hex(node_seed_hex)
    return derive(shared_secret(node_seed_hex, command_key_hex), node)


# -- topics ----------------------------------------------------------------------------------

def new_rid():
    """A reply id: 16 random bytes, once per broker session."""
    return secrets.token_bytes(RID_LEN)


def command_topic(node_key_hex):
    return f"{TOPIC_ROOT}cmd/{_key_hex(node_key_hex)}"


def alive_topic(node_key_hex):
    return f"{TOPIC_ROOT}alive/{_key_hex(node_key_hex)}"


def ping_topic(node_key_hex):
    return f"{TOPIC_ROOT}ping/{_key_hex(node_key_hex)}"


def reply_topic(rid):
    if len(rid) != RID_LEN:
        raise Mcc3Error(f"a reply id is {RID_LEN} bytes")
    return f"{TOPIC_ROOT}r/{rid.hex().upper()}"


ALIVE_FILTER = f"{TOPIC_ROOT}alive/+"


def node_from_topic(topic):
    """The node key of `mcc/cmd|alive|ping/<KEY>`, else None."""
    parts = (topic or "").split("/")
    if len(parts) == 3 and parts[0] + "/" == TOPIC_ROOT and parts[1] in ("cmd", "alive", "ping"):
        return envelope.node_key(parts[2]) if parts[2] == parts[2].upper() else None
    return None


# -- helpers ---------------------------------------------------------------------------------

def b64(data):
    return envelope._b64(data)


def unb64(text):
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("ascii", "replace")
    try:
        return envelope._unb64(text)
    except ValueError:
        raise Refused("bad-fields") from None


def _u32(value):
    if not 0 <= value <= 0xFFFFFFFF:
        raise Mcc3Error("a counter, expiry or clock fits in 32 bits")
    return struct.pack("<I", value)


def _command_bytes(command, limit):
    """The command as UTF-8 under today's character rule, or Mcc3Error."""
    try:
        envelope.signed_part(0, 0, command)            # printable, no '|', 1..160 bytes
    except envelope.EnvelopeError as exc:
        raise Mcc3Error(str(exc)) from None
    data = command.encode("utf-8")
    if len(data) > limit:
        raise Mcc3Error(f"a command on this road is 1..{limit} bytes, this one is {len(data)}")
    return data


def _command_ok(data, limit):
    if not 1 <= len(data) <= limit:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return text.isprintable() and "|" not in text


def signed_bytes(node_key_hex, road, flags, counter, expiry, rid, command_bytes):
    """What the command key signs. `rid` is None on the mesh road."""
    return (SIG_LABEL + bytes.fromhex(_key_hex(node_key_hex)) + bytes([road, flags]) + _u32(counter)
            + _u32(expiry) + (rid or b"") + command_bytes)


def _sign(seed_hex, message):
    return eddsa.new(envelope.key_from_seed(seed_hex), "rfc8032").sign(message)


def _verify(public_hex, message, signature):
    try:
        key = eddsa.import_public_key(bytes.fromhex(public_hex))
        eddsa.new(key, "rfc8032").verify(message, signature)
        return True
    except ValueError:
        return False


def _aead(key, nonce, aad):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    return cipher


def mesh_nonce(counter):
    return bytes(8) + _u32(counter)


def _mesh_stream(key, counter, data):
    """RFC 8439 ChaCha20 from block 1, i.e. ChaCha20-Poly1305's ciphertext without its tag."""
    cipher = ChaCha20.new(key=key, nonce=mesh_nonce(counter))
    cipher.seek(64)
    return cipher.encrypt(data)


def _pad(data, sizes):
    padded = envelope.pad(data, sizes)
    if padded is None:
        raise Mcc3Error("too long")
    return padded


# -- command on MQTT (mcc/cmd/<KEY>) ---------------------------------------------------------

def seal_command(command_seed_hex, node_key_hex, counter, expiry, rid, command, nonce=None, keys=None):
    """The base64url payload for `mcc/cmd/<KEY>`. `nonce` is for test vectors only."""
    data = _command_bytes(command, MAX_COMMAND)
    if len(rid) != RID_LEN:
        raise Mcc3Error(f"a reply id is {RID_LEN} bytes")
    keys = keys or owner_keys(command_seed_hex, node_key_hex)
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    sig = _sign(command_seed_hex, signed_bytes(node_key_hex, ROAD_MQTT, 0, counter, expiry, rid, data))
    return b64(_command_raw(keys, nonce, 0, counter, expiry, rid, sig, data))


def _command_raw(keys, nonce, flags, counter, expiry, rid, sig, data):
    header = bytes([KIND_COMMAND, flags]) + nonce
    plain = _u32(counter) + _u32(expiry) + rid + sig + _pad(data, COMMAND_PADS)
    body, tag = _aead(keys["cmd"], nonce, header).encrypt_and_digest(plain)
    return header + body + tag


def open_command(node_seed_hex, command_key_hex, payload, keys=None):
    """What the node does before its policy checks (§4): `{counter, expiry, rid, command}`,
    or Refused with the outcome the node counts. Replay, expiry, deny list and rate limit
    are the node's, not the envelope's."""
    raw = unb64(payload)
    if len(raw) not in COMMAND_SIZES or raw[0] != KIND_COMMAND:
        raise Refused("bad-fields")
    if raw[1] != 0:
        raise Refused("bad-version")
    keys = keys or node_keys(node_seed_hex, command_key_hex)
    header, body, tag = raw[:14], raw[14:-TAG_LEN], raw[-TAG_LEN:]
    try:
        plain = _aead(keys["cmd"], header[2:], header).decrypt_and_verify(body, tag)
    except ValueError:
        raise Refused("sig-invalid") from None
    counter, expiry = struct.unpack_from("<II", plain, 0)
    rid, sig, data = plain[8:24], plain[24:88], plain[88:].rstrip(b"\0")
    if not _command_ok(data, MAX_COMMAND):
        raise Refused("command-chars")
    node = envelope.public_key_hex(node_seed_hex)
    if not _verify(command_key_hex, signed_bytes(node, ROAD_MQTT, 0, counter, expiry, rid, data), sig):
        raise Refused("sig-invalid")
    return {"counter": counter, "expiry": expiry, "rid": rid, "command": data.decode("utf-8")}


# -- result on MQTT (mcc/r/<RID>) ------------------------------------------------------------

def _cut(data, limit):
    """At most `limit` bytes, cut on a UTF-8 character boundary."""
    if len(data) <= limit:
        return data
    cut = data[:limit]
    return cut.decode("utf-8", "ignore").encode("utf-8")


def seal_result(keys, counter, code, clock, command, reply, nonce=None):
    """What the node publishes on `mcc/r/<RID>` (for vectors and tests; the node does this)."""
    cmd = command.encode("utf-8")
    if len(cmd) > MAX_COMMAND:
        raise Mcc3Error(f"a command is at most {MAX_COMMAND} bytes")
    body = _u32(counter) + bytes([code]) + _u32(clock) + bytes([len(cmd)]) + cmd
    body += _cut(reply.encode("utf-8"), RESULT_PADS[-1] - len(body))
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    header = bytes([KIND_RESULT]) + nonce
    sealed, tag = _aead(keys["cmd"], nonce, header).encrypt_and_digest(_pad(body, RESULT_PADS))
    return b64(header + sealed + tag)


def open_result(keys, payload):
    """`{counter, code, clock, command, reply}`, or Refused("sig-invalid") when it does not open
    under these keys (another node's, or altered). The caller tries the keys of the nodes it
    is waiting for on this RID and matches the counter."""
    raw = unb64(payload)
    if len(raw) not in RESULT_SIZES or raw[0] != KIND_RESULT:
        raise Refused("bad-fields")
    header, body, tag = raw[:13], raw[13:-TAG_LEN], raw[-TAG_LEN:]
    try:
        plain = _aead(keys["cmd"], header[1:], header).decrypt_and_verify(body, tag)
    except ValueError:
        raise Refused("sig-invalid") from None
    counter, code, clock, n = struct.unpack_from("<IBIB", plain, 0)
    if n > MAX_COMMAND:
        raise Refused("bad-fields")
    command = plain[10:10 + n]
    reply = plain[10 + n:].rstrip(b"\0")
    return {"counter": counter, "code": code, "clock": clock,
            "command": command.decode("utf-8", "replace"), "reply": reply.decode("utf-8", "replace")}


# -- the mesh road (ANON_REQ sub-type 0xC2) --------------------------------------------------

def seal_mesh_request(command_seed_hex, node_key_hex, counter, expiry, command, companion_tag=0, keys=None):
    """The 136-byte request, the companion's 4-byte tag first (the app sends the other 132).
    ChaCha20 under K_mesh with nonce 00x8 || counter, no tag: the signature inside is the
    integrity. A resend of a counter must send these same bytes."""
    data = _command_bytes(command, MESH_MAX_COMMAND)
    keys = keys or owner_keys(command_seed_hex, node_key_hex)
    sig = _sign(command_seed_hex, signed_bytes(node_key_hex, ROAD_MESH, 0, counter, expiry, None, data))
    return _mesh_raw(keys, companion_tag, 0, counter, expiry, sig, data)


def _mesh_raw(keys, companion_tag, flags, counter, expiry, sig, data):
    plain = _u32(expiry) + sig + data + bytes(MESH_COMMAND_FIELD - len(data))
    head = struct.pack("<I", companion_tag) + bytes([MESH_SUBTYPE, flags]) + _u32(counter)
    return head + _mesh_stream(keys["mesh"], counter, plain)


def open_mesh_request(node_seed_hex, command_key_hex, request, last_counter=None, keys=None):
    """The node's side, §4 mesh order up to the signature: `{tag, counter, expiry, command}` or
    Refused. Any altered byte after the counter changes the signed bytes, so it fails the
    signature; an altered counter changes the keystream and the signed counter."""
    if len(request) < MESH_REQUEST_LEN or request[4] != MESH_SUBTYPE:
        raise Refused("bad-fields")
    if request[5] != 0:
        raise Refused("bad-version")
    counter = struct.unpack_from("<I", request, 6)[0]
    if last_counter is not None and counter <= last_counter:
        raise Refused("replay")
    keys = keys or node_keys(node_seed_hex, command_key_hex)
    plain = _mesh_stream(keys["mesh"], counter, bytes(request[MESH_HEADER:MESH_REQUEST_LEN]))
    expiry = struct.unpack_from("<I", plain, 0)[0]
    sig, field = plain[4:68], plain[68:]
    data = field.rstrip(b"\0")
    if not _command_ok(data, MESH_MAX_COMMAND):
        raise Refused("command-chars")
    node = envelope.public_key_hex(node_seed_hex)
    if not _verify(command_key_hex, signed_bytes(node, ROAD_MESH, 0, counter, expiry, None, data), sig):
        raise Refused("sig-invalid")
    return {"tag": struct.unpack_from("<I", request, 0)[0], "counter": counter, "expiry": expiry,
            "command": data.decode("utf-8")}


def seal_mesh_response(keys, companion_tag, counter, code, clock, reply, nonce=None):
    """The node's response (not padded), sealed under K_cmd with a random nonce."""
    rep = reply.encode("utf-8")
    if len(rep) > MESH_MAX_REPLY:
        raise Mcc3Error(f"a mesh reply is at most {MESH_MAX_REPLY} bytes")
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    header = bytes([KIND_RESULT]) + nonce
    sealed, tag = _aead(keys["cmd"], nonce, header).encrypt_and_digest(_u32(counter) + bytes([code]) + _u32(clock) + rep)
    return struct.pack("<I", companion_tag) + header + sealed + tag


def open_mesh_response(keys, response):
    """`{tag, counter, code, clock, reply}`, or Refused."""
    if len(response) < 4 + 1 + NONCE_LEN + 9 + TAG_LEN or response[4] != KIND_RESULT:
        raise Refused("bad-fields")
    header, body, tag = response[4:17], response[17:-TAG_LEN], response[-TAG_LEN:]
    try:
        plain = _aead(keys["cmd"], header[1:], header).decrypt_and_verify(body, tag)
    except ValueError:
        raise Refused("sig-invalid") from None
    counter, code, clock = struct.unpack_from("<IBI", plain, 0)
    return {"tag": struct.unpack_from("<I", response, 0)[0], "counter": counter, "code": code,
            "clock": clock, "reply": plain[9:].decode("utf-8", "replace")}


# -- alive (mcc/alive/<KEY>, retained) -------------------------------------------------------

ALIVE_FIELDS = ("boot", "sequence", "uptime", "clock", "last_counter", "interval", "flags", "mesh",
                "fingerprint", "via", "version", "region", "name")


def _lp(text, limit):
    data = _cut(text.encode("utf-8"), limit)
    return bytes([len(data)]) + data


def seal_alive(keys, fields, nonce=None):
    """The node's alive payload (for vectors and tests). `fields` as ALIVE_FIELDS; the
    fingerprint is 8 hex characters, the region is folded to lower case."""
    f = fields
    plain = (struct.pack("<IIIIII", f["boot"], f["sequence"], f["uptime"], f["clock"], f["last_counter"],
                         f["interval"])
             + bytes([f["flags"], f["mesh"]]) + bytes.fromhex(f["fingerprint"]) + bytes([f["via"], 0])
             + _lp(f["version"], ALIVE_MAX_VERSION) + _lp(f["region"].lower(), ALIVE_MAX_REGION)
             + _lp(f["name"], ALIVE_MAX_NAME))
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    header = bytes([KIND_ALIVE]) + nonce
    sealed, tag = _aead(keys["alive"], nonce, header).encrypt_and_digest(_pad(plain, (ALIVE_PLAIN,)))
    return b64(header + sealed + tag)


def open_alive(keys, payload):
    """The fields of an alive message that opens under these keys, or Refused: one that does
    not open is another owner's node (or altered). An empty payload is the will (offline);
    the caller handles it before this."""
    raw = unb64(payload)
    if len(raw) != ALIVE_SIZE or raw[0] != KIND_ALIVE:
        raise Refused("bad-fields")
    header, body, tag = raw[:13], raw[13:-TAG_LEN], raw[-TAG_LEN:]
    try:
        p = _aead(keys["alive"], header[1:], header).decrypt_and_verify(body, tag)
    except ValueError:
        raise Refused("sig-invalid") from None
    out = dict(zip(ALIVE_FIELDS[:6], struct.unpack_from("<IIIIII", p, 0)))
    out.update(flags=p[24], mesh=p[25], fingerprint=p[26:30].hex().upper(), via=p[30])
    at = 32
    for name in ("version", "region", "name"):
        n = p[at]
        if at + 1 + n > ALIVE_PLAIN:
            raise Refused("bad-fields")
        out[name] = p[at + 1:at + 1 + n].decode("utf-8", "replace")
        at += 1 + n
    return out
