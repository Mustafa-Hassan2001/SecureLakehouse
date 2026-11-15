"""One place that wires the components together.

The demo, the CLI and the Streamlit app all call :func:`open_lakehouse`, so they
are guaranteed to run the same KeyManager / Policy / AuditLog / SecureGateway
code — no entry point can quietly assemble a weaker configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pyspark.sql import SparkSession

from pipeline.gateway import SecureGateway
from pipeline.spark_session import get_spark
from security.audit import AuditLog, Clock
from security.crypto import DEFAULT_PBKDF2_ITERATIONS, KeyManager
from security.policy import Policy, default_policy

PASSPHRASE_ENV = "SECURELAKEHOUSE_PASSPHRASE"


@dataclass
class Lakehouse:
    spark: SparkSession
    lake_path: Path
    state_dir: Path
    key_manager: KeyManager
    policy: Policy
    audit: AuditLog
    gateway: SecureGateway


def keystore_path(state_dir: str | os.PathLike[str]) -> Path:
    return Path(state_dir) / "keystore.json"


def audit_path(state_dir: str | os.PathLike[str]) -> Path:
    return Path(state_dir) / "audit.jsonl"


def resolve_passphrase(explicit: Optional[str] = None) -> str:
    """Passphrase from the argument or the environment — never from source code."""
    value = explicit or os.environ.get(PASSPHRASE_ENV)
    if not value:
        raise SystemExit(
            f"No passphrase: set the {PASSPHRASE_ENV} environment variable "
            "(it derives the master key; it is never stored anywhere)."
        )
    return value


def open_lakehouse(
    lake_path: str | os.PathLike[str],
    state_dir: str | os.PathLike[str],
    passphrase: str,
    *,
    clock: Optional[Clock] = None,
    policy: Optional[Policy] = None,
    pbkdf2_iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    spark: Optional[SparkSession] = None,
) -> Lakehouse:
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    spark = spark or get_spark()
    km = KeyManager(keystore_path(state), passphrase, iterations=pbkdf2_iterations)
    pol = policy or default_policy()
    audit = AuditLog(audit_path(state), clock=clock)
    gateway = SecureGateway(spark, lake_path, km, pol, audit)
    return Lakehouse(spark, Path(lake_path), state, km, pol, audit, gateway)
