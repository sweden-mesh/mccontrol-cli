"""The key backup file (keyfile.py): round trips, refusals, the shared vectors the web app
reads too (spec/vectors/key-backup-vectors.json, from mccontrol-spec), and `mccontrol key export/import`."""
import copy
import getpass
import json
import pathlib
import stat
import unicodedata

import pytest

from mccontrol import cli, envelope, keyfile, store

VECTORS = json.loads((pathlib.Path(__file__).parents[1] / "spec" / "vectors" / "key-backup-vectors.json")
                     .read_text(encoding="utf-8"))
SEED = VECTORS["seed"]
PASS = VECTORS["passphrase"]


def test_the_shared_vector_is_what_python_seals():
    v = VECTORS
    again = keyfile.seal(SEED, PASS, iterations=v["iterations"], salt=bytes.fromhex(v["salt"]),
                         nonce=bytes.fromhex(v["nonce"]), created=v["created"])
    assert again == v["sealed"]
    assert keyfile.open_backup(v["sealed"], PASS) == SEED


def test_round_trip_at_the_default_cost():
    sealed = keyfile.seal(SEED, "correct horse")
    assert sealed["kdf"]["iterations"] == keyfile.ITERATIONS >= 600_000
    assert sealed["public_key"] == envelope.public_key_hex(SEED)
    assert SEED not in json.dumps(sealed)
    assert keyfile.open_backup(sealed, "correct horse") == SEED


def test_the_passphrase_is_normalised():
    nfd = unicodedata.normalize("NFD", PASS)
    assert nfd != PASS
    assert keyfile.open_backup(VECTORS["sealed"], nfd) == SEED


def test_a_wrong_passphrase_is_refused():
    with pytest.raises(keyfile.KeyFileError, match="passphrase is wrong"):
        keyfile.open_backup(VECTORS["sealed"], PASS + "x")


@pytest.mark.parametrize("path,value", [
    (("ciphertext",), "00" * 48),
    (("public_key",), envelope.public_key_hex("11" * 32)),
    (("kdf", "salt"), "00" * 16),
    (("kdf", "iterations"), 1001),
    (("cipher", "nonce"), "00" * 12),
])
def test_a_changed_file_is_refused(path, value):
    data = copy.deepcopy(VECTORS["sealed"])
    node = data
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(keyfile.KeyFileError):
        keyfile.open_backup(data, PASS)


def test_malformed_files_are_refused_readably():
    for data, match in [({"format": "x"}, "not an mccontrol"),
                        (dict(VECTORS["sealed"], version=2), "version"),
                        (dict(VECTORS["sealed"], kdf={"name": "scrypt"}), "reads PBKDF2"),
                        (dict(VECTORS["sealed"], kdf=dict(VECTORS["sealed"]["kdf"], iterations=10 ** 9)), "out of range"),
                        (dict(VECTORS["sealed"], ciphertext="zz"), "ciphertext")]:
        with pytest.raises(keyfile.KeyFileError, match=match):
            keyfile.open_backup(data, PASS)


def test_read_takes_a_backup_or_a_bare_seed():
    assert keyfile.read(json.dumps(VECTORS["sealed"]), lambda: PASS) == SEED
    assert keyfile.read(SEED.upper() + "\n") == SEED          # what key.seed holds
    asked = []
    keyfile.read(SEED, lambda: asked.append(1))
    assert not asked                                          # a bare seed asks for nothing
    with pytest.raises(keyfile.KeyFileError, match="neither"):
        keyfile.read("hello")


def test_cli_export_then_import_on_another_computer(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path / "a"))
    assert cli.main(["keygen"]) == 0
    public = store.Store().public_key()
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "long enough")
    backup = tmp_path / "mccontrol-key.json"
    capsys.readouterr()
    assert cli.main(["key", "export", str(backup)]) == 0
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert json.loads(backup.read_text())["public_key"] == public
    assert store.Store().seed() not in backup.read_text() + capsys.readouterr().out
    assert cli.main(["key", "export", str(backup)]) == 1                 # never overwrites

    monkeypatch.setenv("MCCONTROL_HOME", str(tmp_path / "b"))
    assert cli.main(["key", "import", str(backup)]) == 0
    assert store.Store().public_key() == public
    assert cli.main(["key", "import", str(backup)]) == 1                 # a key is there
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "wrong")
    assert cli.main(["key", "import", str(backup), "--force"]) == 1
    assert "passphrase is wrong" in capsys.readouterr().err


def test_cli_imports_what_the_web_app_writes(tmp_path, monkeypatch):
    path = tmp_path / "from-the-browser.json"
    path.write_text(json.dumps(VECTORS["sealed"]), encoding="utf-8")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": PASS)
    assert cli.main(["key", "import", str(path)]) == 0
    assert store.Store().public_key() == VECTORS["sealed"]["public_key"]


def test_cli_export_refuses_short_or_differing_passphrases(tmp_path, monkeypatch):
    assert cli.main(["keygen"]) == 0
    answers = iter(["long enough", "different!"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["key", "export", str(tmp_path / "x.json")]) == 1
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "short")
    assert cli.main(["key", "export", str(tmp_path / "x.json")]) == 1
    assert not (tmp_path / "x.json").exists()
