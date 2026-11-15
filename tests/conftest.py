"""Shared pytest fixtures.

Tests use a low PBKDF2 iteration count purely for speed; production code defaults
to 600,000 (see security/crypto.py). The iteration count is stored in the keystore,
so this does not change any code path, only the cost of derivation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SAMPLE_CSV = ROOT / "data" / "raw" / "employees.csv"
TEST_ITERATIONS = 1_000
PASSPHRASE = "test-passphrase"


@pytest.fixture(scope="session")
def spark():
    from pipeline.spark_session import get_spark

    session = get_spark("local[2]")
    yield session
    session.stop()


@pytest.fixture()
def key_manager(tmp_path):
    from security.crypto import KeyManager

    return KeyManager(tmp_path / "keystore.json", PASSPHRASE, iterations=TEST_ITERATIONS)


@pytest.fixture()
def lakehouse(spark, tmp_path):
    """A freshly ingested lake from the sample CSV."""
    from pipeline.context import open_lakehouse
    from pipeline.ingest import ingest_csv

    lh = open_lakehouse(
        tmp_path / "lake", tmp_path / "state", PASSPHRASE,
        pbkdf2_iterations=TEST_ITERATIONS, spark=spark,
    )
    ingest_csv(spark, SAMPLE_CSV, lh.lake_path, lh.key_manager)
    return lh
