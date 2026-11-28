"""mcc3: the control plane keyed by the node and sealed to the owner (lou-20 and later).

The wire format is mccontrol-spec's `docs/wire-format-mcc3.md`, and its vectors
(`vectors/mcc3-vectors.json`) pin these functions byte for byte against the firmware and the
web app. In short:

    S        X25519(node identity, owner command key)       the same from either side
    K_cmd    HKDF-SHA256(S, salt empty, "mcc3/cmd/"   + KEY)  MQTT commands and results, mesh responses
    K_mesh   HKDF-SHA256(S, salt empty, "mcc3/mesh/"  + KEY)  mesh requests (ChaCha20, no tag)
    K_alive  HKDF-SHA256(S, salt empty, "mcc3/alive/" + KEY)  alive messages
    K_fwd    HKDF-SHA256(S, salt empty, "mcc3/fwd/"   + KEY)  forwards through a relay, and their results
    signed   "mcc3/sig|" node key, road, flags, counter, expiry, RID (MQTT only), command

KEY is the node's public key in upper-case hex. Every integer is little-endian. MQTT payloads
are base64url without padding. Nothing here connects or sends.
"""

import hashlib
import hmac
import secrets
import struct

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Signature import eddsa

from . import envelope

TOPIC_ROOT = "mcc/"
SIG_LABEL = b"mcc3/sig|"
INFO_CMD, INFO_MESH, INFO_ALIVE, INFO_FWD = "mcc3/cmd/", "mcc3/mesh/", "mcc3/alive/", "mcc3/fwd/"
ROAD_MQTT, ROAD_MESH = 0x00, 0x01
KIND_COMMAND, KIND_RESULT, KIND_ALIVE = 0x43, 0x52, 0x41      # "C", "R", "A"
KIND_FORWARD, KIND_FORWARD_RESULT = 0x46, 0x66                # "F", "f"
MESH_SUBTYPE = 0xC2
MESH_V1_SUBTYPE = 0xC1             # the lou-19 mesh request: a relay forwards it too
FLAG_DELEGATION = 0x01             # reserved: lou-20 and lou-21 refuse it
FLAG_ZERO_HOP = 0x02               # mesh requests only: answer once, directly, with an empty path
MESH_FLAGS = (0, FLAG_ZERO_HOP)    # what a mesh request may carry; on MQTT commands flags stay 0

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
MESH_BLOCK = 16                    # the mesh hands a datagram over zero-filled to this many bytes

# A forward through a relay (mcc/cmd/<RELAY KEY>) and its result (mcc/r/<RID>), sealed under K_fwd.
ROUTE_DIRECT, ROUTE_FLOOD, ROUTE_FLOOD_WIDE = 0, 1, 2
ROUTES = ("direct", "flood", "flood-wide")     # flood: the relay's region home; flood-wide: its default scope
FORWARD_PATH = 57                  # the path field of a forward
FORWARD_BODY = 132                 # the body field: a mesh request from its sub-type byte on
FORWARD_MIN_BODY = 74              # the shortest 0xC1 request (a one-byte command)
FORWARD_SIZE = 2 + NONCE_LEN + 4 + 4 + RID_LEN + 32 + 1 + 1 + FORWARD_PATH + 1 + FORWARD_BODY + TAG_LEN   # 278
FORWARD_RESULT_PLAIN = 256
FORWARD_RESULT_PATH = 64
FORWARD_MAX_RESPONSE = 167
FORWARD_RESULT_SIZE = 1 + NONCE_LEN + FORWARD_RESULT_PLAIN + TAG_LEN                                    # 285
FORWARD_STATUSES = ("answered", "no-answer", "off", "expired", "replay", "bad-body", "busy", "rate-limited",
                    "clock-unset", "send-failed")
FORWARD_ANSWERED, FORWARD_NO_ANSWER = 0, 1
# What a relay's status means to a person. No answer is never a refusal.
FORWARD_HELP = {
    0: "The relay sent the command and the node answered.",
    1: "The relay sent the command and heard no answer in two minutes. This is not a refusal: the node may "
       "have run it. If a direct send stays unanswered, send once as a flood: its answer renews the path "
       "both ways.",
    2: "Relaying is switched off on the relay. Send it: set relay own",
    3: "The relay got the request too late, or its clock and yours disagree. Nothing was sent.",
    4: "The relay has already seen a newer request. Nothing was sent. Send again.",
    5: "The relay refused the request, the route or the path. Nothing was sent.",
    6: "The relay is waiting for the answer to another command. Nothing was sent. Try again in two minutes.",
    7: "The relay has used its airtime for now, or the flood came too soon after its last one. Nothing was "
       "sent. Try again in a few minutes: get relay on the relay shows what is left.",
    8: "The relay has no time yet. Nothing was sent. Try again in a minute.",
    9: "The relay could not send right now. Nothing was sent. Try again.",
}
FORWARD_HELP_SV = {
    0: "Reläet skickade kommandot och noden svarade.",
    1: "Reläet skickade kommandot och hörde inget svar på två minuter. Det är ingen vägran: noden kan ha "
       "kört det. Om en direktsändning förblir obesvarad, skicka en gång som flood: svaret förnyar vägen åt "
       "båda håll.",
    2: "Reläfunktionen är avstängd på reläet. Skicka: set relay own",
    3: "Begäran kom för sent till reläet, eller så går dess klocka och din olika. Inget skickades.",
    4: "Reläet har redan sett en nyare begäran. Inget skickades. Skicka igen.",
    5: "Reläet nekade begäran, vägen eller sökvägen. Inget skickades.",
    6: "Reläet väntar på svaret på ett annat kommando. Inget skickades. Försök igen om två minuter.",
    7: "Reläet har använt sin sändningstid för stunden, eller så kom flooden för tätt efter den förra. Inget "
       "skickades. Försök igen om några minuter: get relay på reläet visar vad som är kvar.",
    8: "Reläet har ingen tid ännu. Inget skickades. Försök igen om en minut.",
    9: "Reläet kunde inte sända just nu. Inget skickades. Försök igen.",
}
FORWARD_MAX_TTL = 300              # a relay refuses an expiry further ahead of its clock
SENT_NOTHING, SENT_DIRECT, SENT_FLOOD = 0, 1, 2
SNR_NONE, PATH_NONE = 0x80, 0xFF

# alive plaintext limits
ALIVE_FLAG_RELAY = 0x10            # relaying is own, on an image that can relay
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
    """`{"cmd", "mesh", "alive", "fwd"}` -> 32-byte keys, from S and the node's key."""
    node = _key_hex(node_key_hex)
    return {name: HKDF(secret, 32, b"", SHA256, context=(info + node).encode("ascii"))
            for name, info in (("cmd", INFO_CMD), ("mesh", INFO_MESH), ("alive", INFO_ALIVE),
                               ("fwd", INFO_FWD))}


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

def seal_mesh_request(command_seed_hex, node_key_hex, counter, expiry, command, companion_tag=0, keys=None,
                      flags=0):
    """The 136-byte request, the companion's 4-byte tag first (the app sends the other 132).
    ChaCha20 under K_mesh with nonce 00x8 || counter, no tag: the signature inside is the
    integrity. A resend of a counter must send these same bytes. `flags` is 0, or
    FLAG_ZERO_HOP in a request a relay sends straight to its neighbour; it is signed."""
    data = _command_bytes(command, MESH_MAX_COMMAND)
    if flags not in MESH_FLAGS:
        raise Mcc3Error("a mesh request's flags are 0 or 0x02 (answer with zero hops)")
    keys = keys or owner_keys(command_seed_hex, node_key_hex)
    sig = _sign(command_seed_hex, signed_bytes(node_key_hex, ROAD_MESH, flags, counter, expiry, None, data))
    return _mesh_raw(keys, companion_tag, flags, counter, expiry, sig, data)


def _mesh_raw(keys, companion_tag, flags, counter, expiry, sig, data):
    plain = _u32(expiry) + sig + data + bytes(MESH_COMMAND_FIELD - len(data))
    head = struct.pack("<I", companion_tag) + bytes([MESH_SUBTYPE, flags]) + _u32(counter)
    return head + _mesh_stream(keys["mesh"], counter, plain)


def open_mesh_request(node_seed_hex, command_key_hex, request, last_counter=None, keys=None):
    """The node's side, §4 mesh order up to the signature: `{tag, flags, counter, expiry, command}`
    or Refused. Any altered byte after the counter changes the signed bytes, so it fails the
    signature; an altered counter changes the keystream and the signed counter."""
    if len(request) < MESH_REQUEST_LEN or request[4] != MESH_SUBTYPE:
        raise Refused("bad-fields")
    flags = request[5]
    if flags not in MESH_FLAGS:
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
    if not _verify(command_key_hex, signed_bytes(node, ROAD_MESH, flags, counter, expiry, None, data), sig):
        raise Refused("sig-invalid")
    return {"tag": struct.unpack_from("<I", request, 0)[0], "flags": flags, "counter": counter,
            "expiry": expiry, "command": data.decode("utf-8")}


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
    """`{tag, counter, code, clock, reply}`, or Refused. MeshCore carries a datagram in whole
    16-byte cipher blocks and hands it over zero-filled to the block edge, so up to 15 zero
    bytes may follow the response's tag: each shorter length is tried, and the tag says
    which one is the response."""
    if len(response) < 4 + 1 + NONCE_LEN + 9 + TAG_LEN or response[4] != KIND_RESULT:
        raise Refused("bad-fields")
    data = bytes(response)
    for _ in range(MESH_BLOCK):
        header, body, tag = data[4:17], data[17:-TAG_LEN], data[-TAG_LEN:]
        try:
            plain = _aead(keys["cmd"], header[1:], header).decrypt_and_verify(body, tag)
        except ValueError:
            if data[-1] or len(data) - 1 < 4 + 1 + NONCE_LEN + 9 + TAG_LEN:
                break
            data = data[:-1]
            continue
        counter, code, clock = struct.unpack_from("<IBI", plain, 0)
        return {"tag": struct.unpack_from("<I", response, 0)[0], "counter": counter, "code": code,
                "clock": clock, "reply": plain[9:].decode("utf-8", "replace")}
    raise Refused("sig-invalid")


# -- a forward through a relay (mcc/cmd/<RELAY KEY>) and its result (mcc/r/<RID>) ------------

def path_bytes(path_len, room):
    """How many bytes a MeshCore path length stands for (bits 6-7 hash size - 1, bits 0-5 hash
    count), or None when the size is the reserved one or the path does not fit `room`."""
    size, count = (path_len >> 6) + 1, path_len & 63
    return None if size == 4 or size * count > room else size * count


def _forward_body_ok(body):
    if body[:1] == bytes([MESH_SUBTYPE]):
        return len(body) == FORWARD_BODY
    return body[:1] == bytes([MESH_V1_SUBTYPE]) and FORWARD_MIN_BODY <= len(body) <= FORWARD_BODY


def seal_forward(keys, relay_key_hex, counter, expiry, rid, target_key_hex, route, body, path_len=0, path=b"",
                 nonce=None):
    """The base64url payload for `mcc/cmd/<RELAY KEY>` that has the relay transmit `body` (a mesh
    request from its sub-type byte on: the 132 bytes of a 0xC2, or a 0xC1) to the target.
    `keys` are the RELAY's; the AEAD under K_fwd is the whole proof, the request inside carries
    the owner's signature for the target. Refuses what a relay would answer `bad-body`."""
    target = _forward_checks(relay_key_hex, target_key_hex, rid, route, path_len, path, body)
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    return b64(_forward_raw(keys, nonce, 0, counter, expiry, rid, target, route, path_len, path,
                            len(body), body))


def _forward_checks(relay_key_hex, target_key_hex, rid, route, path_len, path, body):
    """What a relay would answer `bad-body`, refused before sealing; the target's key as bytes."""
    relay, target = _key_hex(relay_key_hex), _key_hex(target_key_hex)
    if len(rid) != RID_LEN:
        raise Mcc3Error(f"a reply id is {RID_LEN} bytes")
    if route not in (ROUTE_DIRECT, ROUTE_FLOOD, ROUTE_FLOOD_WIDE):
        raise Mcc3Error("a route is 0 (direct), 1 (flood, region home) or 2 (flood, default scope)")
    if path_bytes(path_len, FORWARD_PATH) != len(path):
        raise Mcc3Error(f"the path does not match its length byte, or is over {FORWARD_PATH} bytes")
    if not _forward_body_ok(body):
        raise Mcc3Error("a relay forwards a 0xC2 request of 132 bytes or a 0xC1 request of 74..132 bytes")
    if target == relay:
        raise Mcc3Error("a relay does not forward to itself")
    return bytes.fromhex(target)


def _forward_plain(counter, expiry, rid, target, route, path_len, path, body_len, body):
    return (_u32(counter) + _u32(expiry) + rid + target + bytes([route, path_len])
            + path + bytes(FORWARD_PATH - len(path)) + bytes([body_len]) + body + bytes(FORWARD_BODY - len(body)))


def _forward_raw(keys, nonce, flags, counter, expiry, rid, target, route, path_len, path, body_len, body):
    header = bytes([KIND_FORWARD, flags]) + nonce
    plain = _forward_plain(counter, expiry, rid, target, route, path_len, path, body_len, body)
    sealed, tag = _aead(keys["fwd"], nonce, header).encrypt_and_digest(plain)
    return header + sealed + tag


def open_forward(relay_seed_hex, command_key_hex, payload, keys=None):
    """The relay's side, the checks that need no state: `{counter, expiry, rid, target, route,
    path_len, path, body}` or Refused. `bad-fields` is "not a forward"; `bad-version` and
    `sig-invalid` are silent; `bad-body` is answered. The switch, the clock, the expiry, the
    replay guard (all judged before the body) and the budget are the relay's own."""
    raw = unb64(payload)
    if len(raw) != FORWARD_SIZE or raw[0] != KIND_FORWARD:
        raise Refused("bad-fields")
    if raw[1] != 0:
        raise Refused("bad-version")
    keys = keys or node_keys(relay_seed_hex, command_key_hex)
    header, sealed, tag = raw[:14], raw[14:-TAG_LEN], raw[-TAG_LEN:]
    try:
        p = _aead(keys["fwd"], header[2:], header).decrypt_and_verify(sealed, tag)
    except ValueError:
        raise Refused("sig-invalid") from None
    return _forward_fields(relay_seed_hex, p)


def _forward_fields(relay_seed_hex, p):
    counter, expiry = struct.unpack_from("<II", p, 0)
    rid, target, route, path_len, body_len = p[8:24], p[24:56], p[56], p[57], p[115]
    used = path_bytes(path_len, FORWARD_PATH)
    body = p[116:116 + body_len]
    if (body_len > FORWARD_BODY or not _forward_body_ok(body) or route not in (ROUTE_DIRECT, ROUTE_FLOOD,
                                                                                ROUTE_FLOOD_WIDE)
            or used is None or target.hex().upper() == envelope.public_key_hex(relay_seed_hex).upper()):
        raise Refused("bad-body")
    return {"counter": counter, "expiry": expiry, "rid": rid, "target": target.hex().upper(), "route": route,
            "path_len": path_len, "path": p[58:58 + used], "body": body}


def seal_forward_result(keys, counter, status, clock, sent=SENT_NOTHING, snr=None, path_len=None, path=b"",
                        response=b"", nonce=None):
    """What the relay publishes on `mcc/r/<RID>` (for vectors and tests; the relay does this).
    `snr` is in quarter-dB, None for none; `path_len` None when the answer taught no path;
    `response` is the target's answer after its 4-byte tag."""
    if path_len is None:
        path_len, path = PATH_NONE, b""
    elif path_bytes(path_len, FORWARD_RESULT_PATH) != len(path):
        raise Mcc3Error(f"the path does not match its length byte, or is over {FORWARD_RESULT_PATH} bytes")
    if len(response) > FORWARD_MAX_RESPONSE:
        raise Mcc3Error(f"a forwarded response is at most {FORWARD_MAX_RESPONSE} bytes")
    if snr is not None and not -127 <= snr <= 127:
        raise Mcc3Error("an SNR is -127..127 quarter-dB")
    plain = (_u32(counter) + bytes([status]) + _u32(clock) + bytes([sent, SNR_NONE if snr is None else snr & 0xFF,
                                                                    path_len])
             + path + bytes(FORWARD_RESULT_PATH - len(path)) + bytes([len(response)]) + response)
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    header = bytes([KIND_FORWARD_RESULT]) + nonce
    sealed, tag = _aead(keys["fwd"], nonce, header).encrypt_and_digest(_pad(plain, (FORWARD_RESULT_PLAIN,)))
    return b64(header + sealed + tag)


def open_forward_result(keys, payload):
    """`{counter, status, name, clock, sent, snr, path_len, path, response}` under the RELAY's
    keys, or Refused("sig-invalid") when it does not open under them (another relay's, or
    altered). `name` is the status in words (None for one not known here), `snr` quarter-dB
    or None, `path_len` None when no path was taught. `response` is the target's answer after
    its tag: `open_mesh_response(target keys, bytes(4) + response)` for a 0xC2 request."""
    raw = unb64(payload)
    if len(raw) != FORWARD_RESULT_SIZE or raw[0] != KIND_FORWARD_RESULT:
        raise Refused("bad-fields")
    header, sealed, tag = raw[:13], raw[13:-TAG_LEN], raw[-TAG_LEN:]
    try:
        p = _aead(keys["fwd"], header[1:], header).decrypt_and_verify(sealed, tag)
    except ValueError:
        raise Refused("sig-invalid") from None
    counter, status, clock, sent, snr, path_len = struct.unpack_from("<IBIBbB", p, 0)
    used = 0 if path_len == PATH_NONE else path_bytes(path_len, FORWARD_RESULT_PATH)
    n = p[76]
    if used is None or n > FORWARD_MAX_RESPONSE:
        raise Refused("bad-fields")
    return {"counter": counter, "status": status, "name": status_name(status), "clock": clock,
            "sent": sent, "snr": None if snr == -128 else snr,
            "path_len": None if path_len == PATH_NONE else path_len, "path": p[12:12 + used],
            "response": p[77:77 + n]}


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
    """The fields of an alive message that opens under these keys (and `relay`: the node
    relays for its owner), or Refused: one that does not open is another owner's node (or
    altered). An empty payload is the will (offline);
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
    out.update(flags=p[24], mesh=p[25], fingerprint=p[26:30].hex().upper(), via=p[30],
               relay=bool(p[24] & ALIVE_FLAG_RELAY))
    at = 32
    for name in ("version", "region", "name"):
        n = p[at]
        if at + 1 + n > ALIVE_PLAIN:
            raise Refused("bad-fields")
        out[name] = p[at + 1:at + 1 + n].decode("utf-8", "replace")
        at += 1 + n
    return out


# -- announce and heard (lou-21): a node without Wi-Fi finds its owner -----------------------
#
# A node without Wi-Fi floods an announce over the mesh; an Observer node of the same owner
# that catches it publishes what it heard, retained, on `mcc/heard/<its KEY>/<slot>`. Two keys
# of their own, from the same S:
#
#     K_malive  HKDF-SHA256(S, salt empty, "mcc3/malive/" + KEY)  the announce; KEY the announcing node's
#     K_heard   HKDF-SHA256(S, salt empty, "mcc3/heard/"  + KEY)  a heard entry; KEY the catching node's

INFO_MALIVE, INFO_HEARD = "mcc3/malive/", "mcc3/heard/"
OWN_LABEL = b"mcc3/own|"
KIND_ANNOUNCE, KIND_HEARD = 0x4D, 0x48                        # "M", "H"
ANNOUNCE_SIZE, ANNOUNCE_SEALED, ANNOUNCE_TAG = 101, 47, 8     # the tag is cut to its first 8 bytes
ANNOUNCE_KEPT = 68                 # what a heard entry keeps: the announce from its kind byte on
ANNOUNCE_MAX_VERSION, ANNOUNCE_MAX_NAME = 14, 16
HEARD_PLAIN = 112
HEARD_SIZE = 1 + NONCE_LEN + HEARD_PLAIN + TAG_LEN                                                      # 141
HEARD_SLOTS = 16
HEARD_FILTER = f"{TOPIC_ROOT}heard/+/+"
ANNOUNCE_FIELDS = ("boot", "sequence", "uptime", "clock", "last_counter", "flags", "battery_mv", "version",
                   "name")
HEARD_FIELDS = ("heard_at", "snr", "hops", "advert_heard_at", "advert_snr", "advert_hops")


def malive_key(secret, node_key_hex):
    """K_malive, from S and the announcing node's key."""
    return HKDF(secret, 32, b"", SHA256, context=(INFO_MALIVE + _key_hex(node_key_hex)).encode("ascii"))


def heard_key(secret, node_key_hex):
    """K_heard, from S and the catching node's key."""
    return HKDF(secret, 32, b"", SHA256, context=(INFO_HEARD + _key_hex(node_key_hex)).encode("ascii"))


def heard_topic(node_key_hex, slot):
    return f"{TOPIC_ROOT}heard/{_key_hex(node_key_hex)}/{int(slot)}"


def heard_from_topic(topic):
    """`(the catching node's KEY, slot)` of `mcc/heard/<KEY>/<slot>`, else None."""
    parts = (topic or "").split("/")
    if len(parts) != 4 or parts[0] + "/" != TOPIC_ROOT or parts[1] != "heard" or parts[2] != parts[2].upper():
        return None
    key = envelope.node_key(parts[2])
    if not key or parts[3] not in [str(n) for n in range(HEARD_SLOTS)]:
        return None
    return key, int(parts[3])


def owner_tag(command_key_hex, node_key_hex, boot, sequence):
    """The four bytes by which a catching node knows an announce is for its own command key."""
    return hashlib.sha256(OWN_LABEL + bytes.fromhex(_key_hex(command_key_hex)) + bytes.fromhex(_key_hex(node_key_hex))
                          + _u32(boot) + _u32(sequence)).digest()[:4]


def _announce_nonce(boot, sequence):
    return bytes(4) + _u32(boot) + _u32(sequence)


def seal_announce(key, command_key_hex, node_key_hex, fields):
    """The 101 bytes a node without Wi-Fi floods (for vectors and tests; the node does this).
    `key` is K_malive; `fields` as ANNOUNCE_FIELDS."""
    f = fields
    node = bytes.fromhex(_key_hex(node_key_hex))
    plain = (struct.pack("<IIIBH", f["uptime"], f["clock"], f["last_counter"], f["flags"], f["battery_mv"])
             + _lp(f["version"], ANNOUNCE_MAX_VERSION) + _lp(f["name"], ANNOUNCE_MAX_NAME))
    head = (node[:1] + node + bytes([KIND_ANNOUNCE]) + owner_tag(command_key_hex, node_key_hex, f["boot"], f["sequence"])
            + _u32(f["boot"]) + _u32(f["sequence"]))
    sealed, tag = _aead(key, _announce_nonce(f["boot"], f["sequence"]), head[1:]).encrypt_and_digest(
        _pad(plain, (ANNOUNCE_SEALED,)))
    return head + sealed + tag[:ANNOUNCE_TAG]


def open_announce(key, command_key_hex, payload):
    """The fields of an announce's first 101 bytes (and `node_key`), or Refused: `not-announce`
    for another size (101, or 165 signed: the signature is `open_signed_announce`'s) or kind, `other-owner` when its owner tag is not this command key's, `does-not-open` when
    the seal does not verify under `key` (K_malive of the node it names). The tag is the
    Poly1305 tag's first 8 bytes: it is made again here and compared."""
    raw = bytes(payload)
    if len(raw) not in (ANNOUNCE_SIZE, ANNOUNCE_SIGNED_SIZE) or raw[33] != KIND_ANNOUNCE:
        raise Refused("not-announce")
    node = raw[1:33].hex().upper()
    boot, sequence = struct.unpack_from("<II", raw, 38)
    if not hmac.compare_digest(raw[34:38], owner_tag(command_key_hex, node, boot, sequence)):
        raise Refused("other-owner")
    nonce, aad, body = _announce_nonce(boot, sequence), raw[1:46], raw[46:46 + ANNOUNCE_SEALED]
    p = _aead(key, nonce, aad).decrypt(body)
    _again, tag = _aead(key, nonce, aad).encrypt_and_digest(p)
    if not hmac.compare_digest(tag[:ANNOUNCE_TAG], raw[46 + ANNOUNCE_SEALED:ANNOUNCE_SIZE]):
        raise Refused("does-not-open")
    out = {"node_key": node, "boot": boot, "sequence": sequence}
    out.update(zip(ANNOUNCE_FIELDS[2:7], struct.unpack_from("<IIIBH", p, 0)))
    at = 15
    for name, limit in (("version", ANNOUNCE_MAX_VERSION), ("name", ANNOUNCE_MAX_NAME)):
        n = p[at]
        if n > limit or at + 1 + n > ANNOUNCE_SEALED:
            raise Refused("bad-fields")
        out[name] = p[at + 1:at + 1 + n].decode("utf-8", "replace")
        at += 1 + n
    return out


def seal_heard(key, node_key_hex, announce, fields, nonce=None):
    """A catching node's heard entry, the payload of `mcc/heard/<KEY>/<slot>` (for vectors and
    tests). `key` is K_heard; `announce` the 101 bytes it caught; `fields` as HEARD_FIELDS."""
    f = fields
    plain = (bytes.fromhex(_key_hex(node_key_hex)) + bytes(announce)[33:]
             + struct.pack("<IbBIbB", f["heard_at"], f["snr"], f["hops"], f["advert_heard_at"], f["advert_snr"],
                           f["advert_hops"]))
    if len(plain) != HEARD_PLAIN:
        raise Mcc3Error(f"an announce is {ANNOUNCE_SIZE} bytes")
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    header = bytes([KIND_HEARD]) + nonce
    sealed, tag = _aead(key, nonce, header).encrypt_and_digest(plain)
    return b64(header + sealed + tag)


def open_heard(key, payload):
    """What a heard entry says, or Refused: `node_key` (the announced node), `announce` (its
    101 bytes, built again from the 68 kept: still to be opened with `open_announce`), and
    HEARD_FIELDS: when it was heard by the catching node's clock (0 while that is unset), the
    SNR in quarter dB, the hops, and the same three for the node's last advert (0: none)."""
    raw = unb64(payload)
    if len(raw) != HEARD_SIZE or raw[0] != KIND_HEARD:
        raise Refused("bad-fields")
    header, body, tag = raw[:13], raw[13:-TAG_LEN], raw[-TAG_LEN:]
    try:
        p = _aead(key, header[1:], header).decrypt_and_verify(body, tag)
    except ValueError:
        raise Refused("sig-invalid") from None
    out = {"node_key": p[:32].hex().upper(), "announce": p[:1] + p[:32 + ANNOUNCE_KEPT]}
    out.update(zip(HEARD_FIELDS, struct.unpack_from("<IbBIbB", p, 32 + ANNOUNCE_KEPT)))
    return out


# -- the signed announce and the shared node store (lou-21, L21-G1) --------------------------
#
# From lou-21 the announce is signed by the node's identity key, and any lou-21 Observer that
# hears it hands it to the command server, which keeps one entry per node, retained on
# `mcc/node/<KEY>`: the newest signed announce and the Observers that caught it
# (planning/firmware/otm10g-shared-store-design-20261127.md, sections 1 and 6).
#
#     signature  Ed25519 by the node over "mcc3/ann|" + bytes 1..100, at bytes 101..164
#     entry      'N' ‖ announce bytes 1..164 ‖ count ‖ count x (Observer key 32 ‖ arrival u32 ‖
#                SNR i8 ‖ hops ‖ via ‖ list), 40 bytes a catcher (the note's sum says 39)
#
# TODO(L21-G2): mccontrol-spec does not carry these yet; the constants stay here (and out of
# webexport) until it does.

ANN_LABEL = b"mcc3/ann|"
ANNOUNCE_SIGNED_SIZE = ANNOUNCE_SIZE + SIG_LEN                                                        # 165
KIND_NODE = 0x4E                                                                                      # "N"
NODE_CATCHER_SIZE = 40
NODE_HEAD = 1 + ANNOUNCE_SIGNED_SIZE - 1 + 1
NODE_FILTER = f"{TOPIC_ROOT}node/+"
VIA_ZERO_HOP, VIA_DIRECT, VIA_FLOOD = 0, 1, 2      # how the catcher heard it: state packet, along a path, flood


def node_topic(node_key_hex):
    return f"{TOPIC_ROOT}node/{_key_hex(node_key_hex)}"


def node_entry_key(topic):
    """The node KEY of `mcc/node/<KEY>`, else None."""
    parts = (topic or "").split("/")
    if len(parts) != 3 or parts[0] + "/" != TOPIC_ROOT or parts[1] != "node" or parts[2] != parts[2].upper():
        return None
    return envelope.node_key(parts[2]) if len(parts[2]) == 64 else None


def _announce_signed(raw):
    return ANN_LABEL + bytes(raw[1:ANNOUNCE_SIZE])


def sign_announce(node_seed_hex, body):
    """The 165 bytes a lou-21 node floods: the 101 of `seal_announce` and its signature (for
    vectors and tests; the node does this)."""
    body = bytes(body)
    if len(body) != ANNOUNCE_SIZE:
        raise Mcc3Error(f"an unsigned announce is {ANNOUNCE_SIZE} bytes")
    if body[1:33].hex().upper() != envelope.public_key_hex(node_seed_hex).upper():
        raise Mcc3Error("an announce is signed by the node it names")
    return body + _sign(node_seed_hex, _announce_signed(body))


def is_announce(raw):
    return len(raw) == ANNOUNCE_SIGNED_SIZE and raw[33] == KIND_ANNOUNCE


def announce_is_for(command_key_hex, raw):
    """Is the announce's owner tag this command key's? One SHA-256, no X25519."""
    raw = bytes(raw)
    if not is_announce(raw):
        return False
    boot, sequence = struct.unpack_from("<II", raw, 38)
    return hmac.compare_digest(raw[34:38], owner_tag(command_key_hex, raw[1:33].hex(), boot, sequence))


def announce_signature_ok(raw):
    raw = bytes(raw)
    return is_announce(raw) and _verify(raw[1:33].hex(), _announce_signed(raw), raw[ANNOUNCE_SIZE:])


def open_signed_announce(key, command_key_hex, payload):
    """A signed announce in the note's order: size and kind (`not-announce`), the owner tag
    (`other-owner`), the node's signature (`bad-signature`, the firmware's word), then the seal (`does-not-open`)."""
    raw = bytes(payload)
    if not is_announce(raw):
        raise Refused("not-announce")
    if not announce_is_for(command_key_hex, raw):
        raise Refused("other-owner")
    if not announce_signature_ok(raw):
        raise Refused("bad-signature")
    return open_announce(key, command_key_hex, raw)


def seal_node_entry(announce, catchers=()):
    """The retained `mcc/node/<KEY>` as the command server publishes it (for tests). `catchers`:
    `[{key, arrival, snr (quarter dB), hops, via, list (0 current, 1 previous)}]`."""
    announce = bytes(announce)
    if not is_announce(announce):
        raise Mcc3Error(f"a node entry holds a signed announce of {ANNOUNCE_SIGNED_SIZE} bytes")
    out = bytes([KIND_NODE]) + announce[1:] + bytes([len(catchers)])
    for c in catchers:
        out += bytes.fromhex(_key_hex(c["key"])) + struct.pack("<IbBBB", c["arrival"], c["snr"], c["hops"], c["via"],
                                                               c["list"])
    return b64(out)


def open_node_entry(payload):
    """What a node entry says, unchecked (the caller tests the tag, the signature, the seal):
    `{node_key, boot, sequence, announce (165 bytes, byte 0 rebuilt), report (the first 4 bytes
    of the signature, hex), catchers}`, or Refused("bad-fields")."""
    raw = unb64(payload)
    if len(raw) < NODE_HEAD or raw[0] != KIND_NODE:
        raise Refused("bad-fields")
    count = raw[NODE_HEAD - 1]
    if len(raw) != NODE_HEAD + count * NODE_CATCHER_SIZE:
        raise Refused("bad-fields")
    announce = raw[1:2] + raw[1:ANNOUNCE_SIGNED_SIZE]
    if not is_announce(announce):
        raise Refused("bad-fields")
    catchers = []
    for i in range(count):
        at = NODE_HEAD + i * NODE_CATCHER_SIZE
        arrival, snr, hops, via, lst = struct.unpack_from("<IbBBB", raw, at + 32)
        catchers.append({"key": raw[at:at + 32].hex().upper(), "arrival": arrival, "snr": snr, "hops": hops,
                         "via": via, "list": lst})
    boot, sequence = struct.unpack_from("<II", announce, 38)
    return {"node_key": announce[1:33].hex().upper(), "boot": boot, "sequence": sequence, "announce": announce,
            "report": announce[ANNOUNCE_SIZE:ANNOUNCE_SIZE + 4].hex().upper(), "catchers": catchers}


# -- a guest forward: relaying through a stranger's Observer (lou-21, section 5) -------------
#
#     guest   the guest key: an Ed25519 key pair whose seed is HKDF-SHA256(command seed, salt empty,
#             "mcc3/guestkey/"), so a relay never sees the owner's command key (operator 2026-11-28,
#             L21-G12). Made again from the command seed each time; never stored, never shown.
#     K_gfwd  HKDF-SHA256(X25519(guest key, relay identity), salt empty, "mcc3/gfwd/" + relay KEY,
#             64 upper-case hex characters as for mcc3/fwd/)
#     wire    'G' ‖ guest key (32) ‖ nonce (12) ‖ ChaCha20-Poly1305[K_gfwd](the body of a forward),
#             AAD the 45 bytes before it; the result is a forward result sealed under K_gfwd.

INFO_GUEST_KEY = "mcc3/guestkey/"
INFO_GFWD = "mcc3/gfwd/"
KIND_GUEST_FORWARD = 0x47                                                                             # "G"
GUEST_FORWARD_SIZE = 1 + 32 + NONCE_LEN + (FORWARD_SIZE - 2 - NONCE_LEN)                             # 309
# lou-21's refusals of a guest forward. TODO(L21-G2): the numbers follow the order the design
# note lists them in; the spec's results.json does not carry them yet.
GUEST_STATUSES = {10: "guest-cap", 11: "guests-full", 12: "target-cap"}
GUEST_HELP = {
    10: "The relay belongs to someone else, and you have used the floods it gives one guest today. Nothing "
        "was sent. Choose another relay, or try again after midnight UTC.",
    11: "The relay belongs to someone else, and its share for guests is used up for today. Nothing was sent. "
        "Choose another relay, or try again after midnight UTC.",
    12: "This node has had all the floods from guests that the relay allows one node today. Nothing was sent. "
        "Try again after midnight UTC, or send by a direct route.",
}
GUEST_HELP_SV = {
    10: "Reläet tillhör någon annan, och du har använt de floods det ger en gäst i dag. Inget skickades. Välj "
        "ett annat relä, eller försök igen efter midnatt UTC.",
    11: "Reläet tillhör någon annan, och dess andel för gäster är slut för i dag. Inget skickades. Välj ett "
        "annat relä, eller försök igen efter midnatt UTC.",
    12: "Noden har fått alla floods från gäster som reläet tillåter en nod i dag. Inget skickades. Försök igen "
        "efter midnatt UTC, eller skicka med en direkt väg.",
}


def status_name(status):
    """A forward result's status in words, the guest refusals too; None for one not known."""
    return FORWARD_STATUSES[status] if status < len(FORWARD_STATUSES) else GUEST_STATUSES.get(status)


def guest_seed(command_seed_hex):
    """The seed of the guest key, from the command seed: the same seed always gives the same guest
    key, and the guest key tells nothing of the command key."""
    return HKDF(_seed(command_seed_hex), 32, b"", SHA256, context=INFO_GUEST_KEY.encode("ascii")).hex().upper()


def guest_keys(secret, relay_key_hex):
    """`{"fwd": K_gfwd}` from S (the guest key with the relay) and the relay's key: the
    shape `open_forward_result` takes."""
    return {"fwd": HKDF(secret, 32, b"", SHA256, context=(INFO_GFWD + _key_hex(relay_key_hex)).encode("ascii"))}


def seal_guest_forward(keys, guest_key_hex, relay_key_hex, counter, expiry, rid, target_key_hex, route, body,
                       path_len=0, path=b"", nonce=None):
    """A guest forward for `mcc/cmd/<RELAY KEY>`: as `seal_forward`, with the guest key (from
    `guest_seed`, never the command key) in clear and `keys` from `guest_keys`."""
    target = _forward_checks(relay_key_hex, target_key_hex, rid, route, path_len, path, body)
    nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    header = bytes([KIND_GUEST_FORWARD]) + bytes.fromhex(_key_hex(guest_key_hex)) + nonce
    plain = _forward_plain(counter, expiry, rid, target, route, path_len, path, len(body), body)
    sealed, tag = _aead(keys["fwd"], nonce, header).encrypt_and_digest(plain)
    return b64(header + sealed + tag)


def open_guest_forward(relay_seed_hex, payload):
    """The relay's side (for tests): `{guest, keys, counter, expiry, rid, target, route,
    path_len, path, body}` or Refused, as `open_forward`."""
    raw = unb64(payload)
    if len(raw) != GUEST_FORWARD_SIZE or raw[0] != KIND_GUEST_FORWARD:
        raise Refused("bad-fields")
    guest = raw[1:33].hex().upper()
    try:
        keys = guest_keys(shared_secret(relay_seed_hex, guest), envelope.public_key_hex(relay_seed_hex))
    except (ValueError, Mcc3Error):
        raise Refused("sig-invalid") from None
    header = raw[:45]
    try:
        p = _aead(keys["fwd"], header[33:], header).decrypt_and_verify(raw[45:-TAG_LEN], raw[-TAG_LEN:])
    except ValueError:
        raise Refused("sig-invalid") from None
    return dict(_forward_fields(relay_seed_hex, p), guest=guest, keys=keys)
