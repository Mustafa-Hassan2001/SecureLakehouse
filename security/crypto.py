"""Envelope encryption and key management for SecureLakehouse.

Key hierarchy (the same shape AWS KMS / GCP KMS / Vault use):

    passphrase --PBKDF2-HMAC-SHA256(salt, N iterations)--> KEK (Key Encryption Key)
    KEK --wraps--> DEK(column, version)   (one Data Encryption Key per sensitive column, per version)
    DEK --encrypts--> individual cell values

Only *wrapped* DEKs are written to the keystore JSON file. The KEK itself is never
persisted: it is re-derived from the passphrase each time the keystore is opened.
Anyone who steals the keystore file and the Parquet files still needs the
passphrase (in production: access to the KMS/HSM that would hold the KEK).

Cipher choice: Fernet (AES-128-CBC + HMAC-SHA256, encrypt-then-MAC, random IV per
token). It is authenticated, so a tampered ciphertext fails loudly instead of
decrypting to garbage, and it is randomized, so equal plaintexts produce different
ciphertexts (no equality leakage — at the cost of not being able to filter or join
on encrypted columns, which is a deliberate trade-off).

Spark note
----------
``KeyManager`` is a stateful object (it can mint and persist new keys). It must
NEVER be captured in a Spark UDF closure: every executor task would receive its
own pickled copy, and any state change (e.g. lazily minting a DEK) would happen
independently in each copy, silently producing rows encrypted under keys the
driver never sees. To make that mistake impossible, ``KeyManager`` refuses to be
pickled. The supported pattern is:

1. on the driver, call :meth:`KeyManager.export_key_material` (which creates and
   persists any missing keys *once*, centrally);
2. ship the resulting immutable ``bytes`` to executors with
   ``SparkContext.broadcast``;
3. inside the UDF, call the pure functions :func:`encrypt_with_key` /
   :func:`decrypt_with_key`, which use nothing but those bytes.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#: OWASP (2023) recommendation for PBKDF2-HMAC-SHA256. Persisted in the keystore so
#: it can be raised later without breaking existing keystores.
DEFAULT_PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
KEYSTORE_FORMAT_VERSION = 1

# A known constant wrapped under the KEK. Unwrapping it on open lets us reject a
# wrong passphrase immediately with a clear error instead of failing later on the
# first DEK unwrap. It reveals nothing: the plaintext is public by design.
_KEK_CHECK_PLAINTEXT = b"securelakehouse-kek-check-v1"


# --------------------------------------------------------------------------- #
# Pure, stateless primitives. These are the ONLY crypto functions that are safe
# to call inside Spark executors: they depend on nothing but their arguments.
# --------------------------------------------------------------------------- #
def encrypt_with_key(key: bytes, plaintext: Optional[str]) -> Optional[str]:
    """Encrypt one value with a raw Fernet key. ``None`` stays ``None``.

    Note: passing NULLs through unencrypted leaks *which* cells are empty. That is
    an accepted, documented trade-off (see docs/threat-model.md).
    """
    if plaintext is None:
        return None
    return Fernet(key).encrypt(str(plaintext).encode("utf-8")).decode("ascii")


def decrypt_with_key(key: bytes, token: Optional[str]) -> Optional[str]:
    """Decrypt one Fernet token with a raw key. Raises ``InvalidToken`` on tampering."""
    if token is None:
        return None
    return Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")


def derive_kek(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """Derive the Key Encryption Key from a passphrase (PBKDF2-HMAC-SHA256).

    Returns a url-safe base64 32-byte key, i.e. directly usable as a Fernet key.
    The high iteration count makes offline brute force of the passphrase expensive.
    """
    if not passphrase:
        raise ValueError("passphrase must be non-empty")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


@dataclass(frozen=True)
class KeyMaterial:
    """Resolved, unwrapped key bytes for one column — what gets broadcast to Spark.

    ``keys`` holds *every* version so rows written under an older key version stay
    decryptable after rotation; ``active_version`` is the one new writes must use.
    """

    column: str
    active_version: int
    keys: dict[int, bytes] = field(repr=False)  # repr=False: never print key bytes

    def active_key(self) -> bytes:
        return self.keys[self.active_version]


class KeyManager:
    """Owns the keystore file: KEK derivation, DEK creation/wrapping, rotation.

    Keystore layout (JSON, contains no plaintext key material)::

        {
          "format_version": 1,
          "kdf": {"algorithm": "PBKDF2-HMAC-SHA256", "salt": b64, "iterations": N},
          "kek_check": <Fernet token of a known constant under the KEK>,
          "columns": {
            "ssn": {"active_version": 2,
                    "versions": {"1": {"wrapped_dek": token, "created_at": iso},
                                 "2": {...}}}
          }
        }
    """

    def __init__(
        self,
        keystore_path: str | os.PathLike[str],
        passphrase: str,
        *,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    ) -> None:
        """Open an existing keystore or create a new one.

        ``iterations`` only applies when *creating* a keystore; an existing keystore
        always uses the iteration count recorded in it (otherwise the derived KEK
        would differ and nothing could be unwrapped).
        """
        self.path = Path(keystore_path)
        if self.path.exists():
            self._store = json.loads(self.path.read_text(encoding="utf-8"))
            if self._store.get("format_version") != KEYSTORE_FORMAT_VERSION:
                raise ValueError(f"unsupported keystore format in {self.path}")
            kdf = self._store["kdf"]
            salt = base64.b64decode(kdf["salt"])
            self._kek = Fernet(derive_kek(passphrase, salt, int(kdf["iterations"])))
            try:
                if self._kek.decrypt(self._store["kek_check"].encode()) != _KEK_CHECK_PLAINTEXT:
                    raise InvalidToken
            except InvalidToken:
                raise PermissionError(
                    "wrong passphrase: the KEK cannot unwrap this keystore"
                ) from None
        else:
            salt = secrets.token_bytes(SALT_BYTES)
            self._kek = Fernet(derive_kek(passphrase, salt, iterations))
            self._store = {
                "format_version": KEYSTORE_FORMAT_VERSION,
                "kdf": {
                    "algorithm": "PBKDF2-HMAC-SHA256",
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "iterations": iterations,
                },
                "kek_check": self._kek.encrypt(_KEK_CHECK_PLAINTEXT).decode("ascii"),
                "columns": {},
            }
            self._persist()
        # Unwrapped DEKs cached in memory only (never written anywhere).
        self._dek_cache: dict[tuple[str, int], bytes] = {}

    # ------------------------------------------------------------------ #
    # Guardrail: a KeyManager must never be shipped to Spark executors.
    # ------------------------------------------------------------------ #
    def __reduce__(self):  # noqa: D105 - see class docstring
        raise TypeError(
            "KeyManager must not be pickled or captured in a Spark UDF: each executor "
            "would get a diverging copy. Use export_key_material() on the driver and "
            "broadcast the resulting bytes instead."
        )

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def _persist(self) -> None:
        """Atomically rewrite the keystore (write temp file, fsync, rename).

        A crash mid-write can therefore never leave a half-written keystore — which
        would make the whole lake undecryptable.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".keystore-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._store, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # ------------------------------------------------------------------ #
    # Key lifecycle
    # ------------------------------------------------------------------ #
    def _mint(self, column: str) -> int:
        """Generate a fresh random DEK for ``column``, wrap it, persist it."""
        entry = self._store["columns"].setdefault(column, {"active_version": 0, "versions": {}})
        version = max((int(v) for v in entry["versions"]), default=0) + 1
        dek = Fernet.generate_key()
        entry["versions"][str(version)] = {
            "wrapped_dek": self._kek.encrypt(dek).decode("ascii"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        entry["active_version"] = version
        self._persist()
        self._dek_cache[(column, version)] = dek
        return version

    def columns(self) -> list[str]:
        """Columns that have at least one key version."""
        return sorted(self._store["columns"])

    def has_key(self, column: str) -> bool:
        return column in self._store["columns"]

    def ensure_key(self, column: str) -> int:
        """Return the active key version for ``column``, creating version 1 if needed."""
        if not self.has_key(column):
            return self._mint(column)
        return int(self._store["columns"][column]["active_version"])

    def active_version(self, column: str) -> int:
        if not self.has_key(column):
            raise KeyError(f"no key exists for column {column!r}")
        return int(self._store["columns"][column]["active_version"])

    def versions(self, column: str) -> list[int]:
        if not self.has_key(column):
            return []
        return sorted(int(v) for v in self._store["columns"][column]["versions"])

    def rotate_key(self, column: str) -> int:
        """Create a new key version and make it active. Old versions are kept so
        existing ciphertext stays readable (re-encryption is a separate, explicit job).
        """
        if not self.has_key(column):
            raise KeyError(f"cannot rotate: no key exists for column {column!r}")
        return self._mint(column)

    def _unwrap(self, column: str, version: int) -> bytes:
        cached = self._dek_cache.get((column, version))
        if cached is not None:
            return cached
        try:
            wrapped = self._store["columns"][column]["versions"][str(version)]["wrapped_dek"]
        except KeyError:
            raise KeyError(f"no key version {version} for column {column!r}") from None
        try:
            dek = self._kek.decrypt(wrapped.encode("ascii"))
        except InvalidToken:
            # Either the wrong KEK or a tampered keystore entry; both mean "no access".
            raise PermissionError(
                f"cannot unwrap DEK for {column!r} v{version}: wrong KEK or tampered keystore"
            ) from None
        self._dek_cache[(column, version)] = dek
        return dek

    # ------------------------------------------------------------------ #
    # Driver-side (single-value) encryption API
    # ------------------------------------------------------------------ #
    def encrypt_value(self, column: str, value: Optional[str]) -> tuple[Optional[str], int]:
        """Encrypt one value under the column's active key. Returns (ciphertext, version)."""
        version = self.ensure_key(column)
        return encrypt_with_key(self._unwrap(column, version), value), version

    def decrypt_value(self, column: str, ciphertext: Optional[str], version: int) -> Optional[str]:
        """Decrypt one value using the key version it was written with."""
        return decrypt_with_key(self._unwrap(column, int(version)), ciphertext)

    # ------------------------------------------------------------------ #
    # Spark support
    # ------------------------------------------------------------------ #
    def export_key_material(
        self, columns: Iterable[str], *, create_missing: bool = False
    ) -> dict[str, KeyMaterial]:
        """Resolve raw DEK bytes for ``columns`` on the driver, for broadcasting.

        Why this exists: Spark executors are separate OS processes (Python workers),
        even in ``local[*]`` mode. Anything a UDF closes over is pickled and shipped
        *per task*. If the UDF closed over this KeyManager and a key had to be minted,
        every task would mint its *own* DEK in its own copy, persist it racily, and
        the driver would end up able to decrypt only whichever partition's key won
        the race. Resolving everything here first — once, on the driver, with keys
        persisted before any task runs — and shipping only immutable bytes removes
        all mutable shared state from the executors.

        ``create_missing=True`` is for the write path (ingest). The read path keeps
        it False: reading must never create keys.
        """
        material: dict[str, KeyMaterial] = {}
        for column in columns:
            if create_missing:
                self.ensure_key(column)
            elif not self.has_key(column):
                raise KeyError(f"no key exists for column {column!r}")
            keys = {v: self._unwrap(column, v) for v in self.versions(column)}
            material[column] = KeyMaterial(column, self.active_version(column), keys)
        return material
