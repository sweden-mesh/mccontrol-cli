"""The key backup file: the signing seed encrypted under a passphrase, the one form in which a
seed leaves the machine. The web app writes and reads the same file (web/lib/key/backup.js),
so a key moves both ways: `mccontrol key export FILE` / `mccontrol key import FILE`.

    {"format": "mccontrol-key-backup", "version": 1,
     "public_key": "<64 upper-case hex>", "created": "<ISO 8601, informational>",
     "kdf": {"name": "PBKDF2-SHA256", "iterations": 600000, "salt": "<16 bytes, hex>"},
     "cipher": {"name": "AES-256-GCM", "nonce": "<12 bytes, hex>"},
     "ciphertext": "<32-byte seed + 16-byte tag, hex>"}

The key is PBKDF2-HMAC-SHA256 over the NFC-normalised UTF-8 passphrase. The additional data
binds every field but `created`:
`format|version|kdf name|iterations|salt|cipher name|nonce|public_key`, so a changed header
fails like a wrong passphrase, and the public key shown before opening is the one inside.

A file holding only the 64 hex characters of a seed (what `key.seed` holds) is read too.
"""

import datetime
import json
import secrets
import unicodedata

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from . import envelope

FORMAT = "mccontrol-key-backup"
VERSION = 1
KDF = "PBKDF2-SHA256"
CIPHER = "AES-256-GCM"
ITERATIONS = 600_000            # OWASP's 2023 figure for PBKDF2-HMAC-SHA256
MAX_ITERATIONS = 10_000_000     # a file may not make opening it take minutes


class KeyFileError(ValueError):
    """A file that is not a key, or a backup that does not open. Never carries the seed."""


def _aad(public_key, iterations, salt_hex, nonce_hex):
    return "|".join([FORMAT, str(VERSION), KDF, str(iterations), salt_hex, CIPHER, nonce_hex,
                     public_key]).encode("utf-8")


def _derive(passphrase, salt, iterations):
    secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    return PBKDF2(secret, salt, 32, count=iterations, hmac_hash_module=SHA256)


def seal(seed_hex, passphrase, iterations=ITERATIONS, salt=None, nonce=None, created=None):
    """The backup of `seed_hex` under `passphrase`, as a dict ready for json.dump."""
    if not passphrase:
        raise KeyFileError("a backup needs a passphrase")
    public = envelope.public_key_hex(seed_hex)
    salt = salt or secrets.token_bytes(16)
    nonce = nonce or secrets.token_bytes(12)
    cipher = AES.new(_derive(passphrase, salt, iterations), AES.MODE_GCM, nonce=nonce)
    cipher.update(_aad(public, iterations, salt.hex(), nonce.hex()))
    sealed, tag = cipher.encrypt_and_digest(bytes.fromhex(seed_hex.strip()))
    created = created or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    return {"format": FORMAT, "version": VERSION, "public_key": public, "created": created,
            "kdf": {"name": KDF, "iterations": iterations, "salt": salt.hex()},
            "cipher": {"name": CIPHER, "nonce": nonce.hex()},
            "ciphertext": (sealed + tag).hex()}


def _hex_field(value, size, what):
    try:
        raw = bytes.fromhex(value) if isinstance(value, str) else None
    except ValueError:
        raw = None
    if raw is None or len(raw) != size:
        raise KeyFileError(f"the backup's {what} is not {size} bytes of hex")
    return raw


def open_backup(data, passphrase):
    """The seed hex inside a backup dict. Refuses a wrong passphrase and a changed file alike."""
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise KeyFileError("not an mccontrol key backup")
    if data.get("version") != VERSION:
        raise KeyFileError(f"a backup of version {data.get('version')!r}; this mccontrol reads {VERSION}")
    kdf, cipher = data.get("kdf") or {}, data.get("cipher") or {}
    if kdf.get("name") != KDF or cipher.get("name") != CIPHER:
        raise KeyFileError(f"the backup uses {kdf.get('name')}/{cipher.get('name')}; this mccontrol reads {KDF}/{CIPHER}")
    iterations = kdf.get("iterations")
    if not isinstance(iterations, int) or isinstance(iterations, bool) or not 1 <= iterations <= MAX_ITERATIONS:
        raise KeyFileError("the backup's iteration count is out of range")
    public = data.get("public_key")
    _hex_field(public, 32, "public key")
    salt = _hex_field(kdf.get("salt"), 16, "salt")
    nonce = _hex_field(cipher.get("nonce"), 12, "nonce")
    sealed = _hex_field(data.get("ciphertext"), 48, "ciphertext")
    box = AES.new(_derive(passphrase or "", salt, iterations), AES.MODE_GCM, nonce=nonce)
    box.update(_aad(public, iterations, kdf["salt"], cipher["nonce"]))
    try:
        seed = box.decrypt_and_verify(sealed[:32], sealed[32:]).hex()
    except ValueError:
        raise KeyFileError("the passphrase is wrong, or the file was changed") from None
    if envelope.public_key_hex(seed) != public:
        raise KeyFileError("the backup's public key does not match the key inside it")
    return seed


def read(text, passphrase=None):
    """The seed hex in a key file's text: a backup (`passphrase` is a string, or a function
    returning one, asked only when needed) or the bare 64 hex of a seed."""
    text = (text or "").strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            raise KeyFileError("the file is not valid JSON") from None
        return open_backup(data, passphrase() if callable(passphrase) else passphrase)
    try:
        envelope.public_key_hex(text)
    except envelope.EnvelopeError:
        raise KeyFileError("the file holds neither a backup nor 64 hex characters of a seed") from None
    return text.lower()
