"""The distributed-systems bug this project's Spark design exists to prevent.

Spark ships a UDF's closure to executors by pickling it *per task*. Python UDFs
run in separate worker processes, even in local[*] mode. If the closure captures
a stateful KeyManager that lazily mints keys, every task deserializes its own
copy, finds "no key for ssn yet", mints its OWN random DEK, labels it version 1,
and races to persist it. The job succeeds and no error is raised, yet only the
partition whose key won the race can be decrypted afterwards.

test_naive_closure_corrupts_encryption reproduces that failure with a deliberately
picklable KeyManager subclass. test_broadcast_design_is_consistent shows that the
real design (resolve on driver -> broadcast bytes -> pure UDF) is correct with the
same data and the same partitioning.
"""

from __future__ import annotations

import sys

from cryptography.fernet import InvalidToken
from pyspark import cloudpickle
from pyspark.sql import functions as F
from pyspark.sql.types import StringType

from pipeline.ingest import encrypt_dataframe
from security.crypto import KeyManager

from .conftest import PASSPHRASE, TEST_ITERATIONS

N_ROWS, N_PARTITIONS = 40, 8


class NaivePicklableKeyManager(KeyManager):
    """What you'd get without the guardrail: a KeyManager that CAN be pickled."""

    def __reduce__(self):
        return (_rebuild_naive, (self.__dict__,))


def _rebuild_naive(state: dict) -> NaivePicklableKeyManager:
    km = NaivePicklableKeyManager.__new__(NaivePicklableKeyManager)
    km.__dict__.update(state)
    return km


# Executors cannot import the tests package, so ship this module's definitions by value.
cloudpickle.register_pickle_by_value(sys.modules[__name__])


def _frame(spark):
    return (
        spark.range(0, N_ROWS)
        .repartition(N_PARTITIONS)
        .withColumn("ssn", F.format_string("900-00-%04d", F.col("id")))
    )


def _count_decryptable(km: KeyManager, rows, ct_col: str, kv_col: str | None = None) -> tuple[int, int]:
    ok = bad = 0
    for r in rows:
        try:
            km.decrypt_value("ssn", r[ct_col], r[kv_col] if kv_col else 1)
            ok += 1
        except (InvalidToken, KeyError, PermissionError):
            bad += 1
    return ok, bad


def test_naive_closure_corrupts_encryption(spark, tmp_path):
    path = tmp_path / "keystore.json"
    naive = NaivePicklableKeyManager(path, PASSPHRASE, iterations=TEST_ITERATIONS)
    assert not naive.has_key("ssn")  # key will be minted lazily — inside executors

    encrypt = F.udf(lambda v: naive.encrypt_value("ssn", v)[0], StringType())
    rows = _frame(spark).withColumn("ct", encrypt("ssn")).collect()  # no error raised!

    # The driver's own object never saw any key being created: executors mutated copies.
    assert not naive.has_key("ssn")

    fresh = KeyManager(path, PASSPHRASE)  # whatever key won the on-disk race
    ok, bad = _count_decryptable(fresh, rows, "ct")
    assert ok + bad == N_ROWS
    assert bad > 0, "expected silently undecryptable rows from per-task key minting"
    assert ok < N_ROWS


def test_broadcast_design_is_consistent(spark, tmp_path):
    km = KeyManager(tmp_path / "keystore.json", PASSPHRASE, iterations=TEST_ITERATIONS)
    encrypted, bc = encrypt_dataframe(_frame(spark), km, ["ssn"])
    rows = encrypted.collect()
    bc.destroy()

    assert km.versions("ssn") == [1]  # minted exactly once, on the driver
    ok, bad = _count_decryptable(KeyManager(km.path, PASSPHRASE), rows, "ssn_enc", "ssn_kv")
    assert (ok, bad) == (N_ROWS, 0)
    assert {r["ssn_kv"] for r in rows} == {1}
