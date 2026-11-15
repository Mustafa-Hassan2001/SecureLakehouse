"""Envelope encryption and key management."""

from __future__ import annotations

import base64
import json
import pickle

import pytest
from cryptography.fernet import InvalidToken

from security.crypto import KeyManager, decrypt_with_key, encrypt_with_key

from .conftest import PASSPHRASE, TEST_ITERATIONS


def test_roundtrip(key_manager):
    ct, version = key_manager.encrypt_value("ssn", "900-11-0001")
    assert version == 1
    assert ct != "900-11-0001"
    assert key_manager.decrypt_value("ssn", ct, version) == "900-11-0001"


def test_encryption_is_randomized(key_manager):
    a, _ = key_manager.encrypt_value("ssn", "900-11-0001")
    b, _ = key_manager.encrypt_value("ssn", "900-11-0001")
    assert a != b  # fresh IV per value: equal plaintexts are not linkable


def test_none_passes_through(key_manager):
    assert key_manager.encrypt_value("ssn", None) == (None, 1)
    assert key_manager.decrypt_value("ssn", None, 1) is None


def test_reopen_with_same_passphrase_decrypts(tmp_path):
    path = tmp_path / "ks.json"
    ct, v = KeyManager(path, PASSPHRASE, iterations=TEST_ITERATIONS).encrypt_value("email", "x@example.com")
    assert KeyManager(path, PASSPHRASE).decrypt_value("email", ct, v) == "x@example.com"


def test_wrong_passphrase_cannot_unwrap(tmp_path):
    path = tmp_path / "ks.json"
    KeyManager(path, PASSPHRASE, iterations=TEST_ITERATIONS).encrypt_value("ssn", "900-11-0001")
    with pytest.raises(PermissionError):
        KeyManager(path, "wrong-passphrase")


def test_dek_unwrap_fails_if_kek_check_bypassed(tmp_path):
    """Even if an attacker swaps in a kek_check made under their own key, the
    per-DEK unwrap still refuses: the DEKs are wrapped under the real KEK."""
    path = tmp_path / "ks.json"
    KeyManager(path, PASSPHRASE, iterations=TEST_ITERATIONS).encrypt_value("ssn", "v")
    attacker = KeyManager(tmp_path / "attacker.json", "attacker", iterations=TEST_ITERATIONS)
    store = json.loads(path.read_text())
    attacker_store = json.loads((tmp_path / "attacker.json").read_text())
    store["kdf"] = attacker_store["kdf"]
    store["kek_check"] = attacker_store["kek_check"]
    path.write_text(json.dumps(store))
    km = KeyManager(path, "attacker")  # passes the (forged) check...
    with pytest.raises(PermissionError):
        km.export_key_material(["ssn"])  # ...but cannot unwrap the real DEK


def test_keystore_contains_no_plaintext_key_material(key_manager):
    key_manager.ensure_key("ssn")
    key_manager.ensure_key("salary")
    raw = key_manager.path.read_text()
    for column, material in key_manager.export_key_material(["ssn", "salary"]).items():
        for dek in material.keys.values():
            assert dek.decode() not in raw
            assert base64.urlsafe_b64decode(dek).hex() not in raw
    assert PASSPHRASE not in raw


def test_rotation_keeps_old_ciphertext_readable(key_manager):
    old_ct, old_v = key_manager.encrypt_value("salary", "100000")
    new_v = key_manager.rotate_key("salary")
    new_ct, used_v = key_manager.encrypt_value("salary", "120000")
    assert (old_v, new_v, used_v) == (1, 2, 2)  # new writes use the new version
    assert key_manager.decrypt_value("salary", old_ct, old_v) == "100000"
    assert key_manager.decrypt_value("salary", new_ct, new_v) == "120000"
    with pytest.raises(InvalidToken):  # versions really are different keys
        key_manager.decrypt_value("salary", old_ct, new_v)


def test_rotation_survives_reopen(tmp_path):
    path = tmp_path / "ks.json"
    km = KeyManager(path, PASSPHRASE, iterations=TEST_ITERATIONS)
    ct1, v1 = km.encrypt_value("ssn", "a")
    km.rotate_key("ssn")
    km2 = KeyManager(path, PASSPHRASE)
    assert km2.active_version("ssn") == 2
    assert km2.decrypt_value("ssn", ct1, v1) == "a"


def test_different_columns_get_different_keys(key_manager):
    material = key_manager.export_key_material(["ssn", "salary"], create_missing=True)
    assert material["ssn"].active_key() != material["salary"].active_key()
    ct, v = key_manager.encrypt_value("ssn", "900-11-0001")
    with pytest.raises(InvalidToken):
        key_manager.decrypt_value("salary", ct, v)  # ciphertext can't be moved across columns


def test_export_without_create_does_not_mint(key_manager):
    with pytest.raises(KeyError):
        key_manager.export_key_material(["ssn"])
    assert not key_manager.has_key("ssn")


def test_pure_primitives_match_key_manager(key_manager):
    """The functions used inside Spark UDFs are byte-compatible with the KeyManager."""
    material = key_manager.export_key_material(["ssn"], create_missing=True)["ssn"]
    ct = encrypt_with_key(material.active_key(), "900-11-0001")
    assert key_manager.decrypt_value("ssn", ct, material.active_version) == "900-11-0001"
    ct2, v = key_manager.encrypt_value("ssn", "900-11-0002")
    assert decrypt_with_key(material.keys[v], ct2) == "900-11-0002"


def test_tampered_ciphertext_is_rejected(key_manager):
    ct, v = key_manager.encrypt_value("ssn", "900-11-0001")
    raw = bytearray(base64.urlsafe_b64decode(ct))
    raw[30] ^= 0x01
    with pytest.raises(InvalidToken):
        key_manager.decrypt_value("ssn", base64.urlsafe_b64encode(bytes(raw)).decode(), v)


def test_key_manager_refuses_to_be_pickled(key_manager):
    """Guardrail for the Spark executor-isolation bug (see test_spark_key_isolation)."""
    with pytest.raises(TypeError, match="broadcast"):
        pickle.dumps(key_manager)


def test_key_material_repr_hides_key_bytes(key_manager):
    m = key_manager.export_key_material(["ssn"], create_missing=True)["ssn"]
    assert m.active_key().decode() not in repr(m)
