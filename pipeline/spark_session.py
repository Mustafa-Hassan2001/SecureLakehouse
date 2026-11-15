"""Shared local SparkSession.

``local[*]`` runs the JVM driver and executors in one JVM, but Python UDFs still
execute in *separate Python worker processes* — which is exactly why key material
has to be broadcast rather than captured in closures (see security/crypto.py).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from pyspark.sql import SparkSession

APP_NAME = "securelakehouse"
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)


def get_spark(master: str = "local[*]") -> SparkSession:
    """Return (or create) the shared SparkSession, configured to run fully offline."""
    # Make Python workers use the same interpreter/venv as the driver.
    os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
    os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)
    os.environ.setdefault("SPARK_LOCAL_IP", "127.0.0.1")
    # Executor-side imports. UDFs reference security.crypto.* *by module name*;
    # cloudpickle does not ship the module source. Python workers are separate
    # processes spawned by the JVM, so a sys.path tweak in the driver does not reach
    # them — running from any directory other than the project root then fails
    # with "ModuleNotFoundError: No module named 'security'" inside the executor.
    # Workers inherit PYTHONPATH from the JVM's environment, which inherits ours,
    # so the project root must be on it BEFORE the JVM starts.
    parts = [p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p]
    if PROJECT_ROOT not in parts:
        os.environ["PYTHONPATH"] = os.pathsep.join([PROJECT_ROOT, *parts])
    spark = (
        SparkSession.builder.master(master)
        .appName(APP_NAME)
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.executorEnv.PYTHONPATH", os.environ["PYTHONPATH"])
        # Keep Spark from creating ./spark-warehouse in the working directory.
        .config("spark.sql.warehouse.dir", os.path.join(tempfile.gettempdir(), "spark-warehouse"))
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    return spark
