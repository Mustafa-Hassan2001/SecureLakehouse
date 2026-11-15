"""CSV -> encrypted Parquet ingestion.

For each sensitive column ``c`` the lake stores two physical columns:

* ``c_enc`` — Fernet ciphertext of the cell (string)
* ``c_kv``  — the key version used (int), so rotation never breaks old rows

Non-sensitive columns (employee_id, department) stay plaintext so Spark can still
filter, partition and prune on them efficiently.

A small ``_securelakehouse_meta.json`` sidecar records the original logical schema
(so the gateway can cast decrypted values back to their types). Spark ignores
files starting with ``_`` when reading a Parquet directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Mapping

from pyspark.broadcast import Broadcast
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import IntegerType, StringType

from security.crypto import KeyManager, encrypt_with_key
from security.policy import SENSITIVE_COLUMNS

META_FILE = "_securelakehouse_meta.json"


def make_encrypt_udf(key_broadcast, column: str):
    """Build a UDF that encrypts ``column`` using ONLY broadcast key bytes.

    The closure captures ``key_broadcast`` (a Broadcast handle — cheap to pickle,
    resolved to the same immutable bytes in every executor) and the column name.
    It deliberately does NOT capture a KeyManager: that object is stateful, and a
    pickled copy per task would let each executor mint its own key (the bug this
    design prevents — see tests/test_spark_key_isolation.py).
    """

    # No type hints on the inner function: PySpark >= 4 inspects UDF annotations to
    # choose an evaluation type and warns on Optional[...]; the return type is
    # given explicitly to F.udf instead.
    def _encrypt(value):
        material = key_broadcast.value[column]
        return encrypt_with_key(material["key"], value)

    return F.udf(_encrypt, StringType())


def encrypt_dataframe(
    df: DataFrame,
    key_manager: KeyManager,
    sensitive_columns: Iterable[str] = SENSITIVE_COLUMNS,
) -> tuple[DataFrame, Broadcast]:
    """Replace each sensitive column ``c`` with ``c_enc`` / ``c_kv``.

    Returns the (lazy) encrypted DataFrame and the key broadcast. The caller must
    ``destroy()`` the broadcast only *after* running an action on the DataFrame.
    """
    spark = df.sparkSession
    sensitive = [c for c in sensitive_columns if c in df.columns]

    # Step 1 (driver): create + persist any missing keys exactly once, centrally.
    material = key_manager.export_key_material(sensitive, create_missing=True)
    # Step 2: ship only plain, immutable values — the ACTIVE key per column.
    # Encryption never needs old versions, so they are not shipped (least privilege).
    payload: dict[str, dict] = {
        c: {"version": m.active_version, "key": m.active_key()} for c, m in material.items()
    }
    bc = spark.sparkContext.broadcast(payload)

    out = df
    for column in sensitive:
        enc = make_encrypt_udf(bc, column)
        out = (
            out.withColumn(f"{column}_enc", enc(F.col(column).cast("string")))
            .withColumn(f"{column}_kv", F.lit(payload[column]["version"]).cast(IntegerType()))
            .drop(column)
        )
    return out, bc


def ingest_csv(
    spark: SparkSession,
    csv_path: str | os.PathLike[str],
    lake_path: str | os.PathLike[str],
    key_manager: KeyManager,
    *,
    sensitive_columns: Iterable[str] = SENSITIVE_COLUMNS,
    mode: str = "overwrite",
) -> int:
    """Read ``csv_path``, encrypt sensitive columns cell-by-cell, write Parquet.

    Returns the number of rows written. ``mode`` is ``overwrite`` or ``append``
    (append is how new data written after a key rotation lands next to old data).
    """
    if mode not in {"overwrite", "append"}:
        raise ValueError("mode must be 'overwrite' or 'append'")
    sensitive_columns = list(sensitive_columns)
    raw = spark.read.option("header", True).option("inferSchema", True).csv(str(csv_path))
    logical_types: Mapping[str, str] = {f.name: f.dataType.simpleString() for f in raw.schema}

    encrypted, bc = encrypt_dataframe(raw, key_manager, sensitive_columns)
    try:
        encrypted.write.mode(mode).parquet(str(lake_path))
    finally:
        # Remove key bytes from executors as soon as they are no longer needed.
        bc.destroy()

    lake = Path(lake_path)
    meta_path = lake / META_FILE
    meta = {
        "sensitive_columns": [c for c in sensitive_columns if c in logical_types],
        "logical_types": dict(logical_types),
    }
    if mode == "append" and meta_path.exists():
        previous = json.loads(meta_path.read_text(encoding="utf-8"))
        if previous["logical_types"] != meta["logical_types"]:
            raise ValueError("append schema does not match the existing lake schema")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return raw.count()


def read_lake_meta(lake_path: str | os.PathLike[str]) -> dict:
    meta_path = Path(lake_path) / META_FILE
    if not meta_path.exists():
        raise FileNotFoundError(f"{lake_path} is not a SecureLakehouse lake (missing {META_FILE})")
    return json.loads(meta_path.read_text(encoding="utf-8"))
