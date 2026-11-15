"""End-to-end: CSV -> encrypted Parquet -> SecureGateway, plus the central claim
that no plaintext sensitive value is present in the lake files on disk."""

from __future__ import annotations

import csv
import shutil
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from pipeline.gateway import REDACTED
from pipeline.ingest import ingest_csv
from security.policy import Subject

from .conftest import SAMPLE_CSV

ADMIN = Subject("alice.admin", "admin", "IT")
ANALYST = Subject("sam.analyst", "analyst", "Engineering")
SUPPORT = Subject("taylor.support", "support", "HR")
AUDITOR = Subject("ari.auditor", "auditor", "Compliance")


def _sample() -> list[dict]:
    with SAMPLE_CSV.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _lake_files(lake: Path) -> list[Path]:
    return [p for p in lake.rglob("*") if p.is_file()]


def _plaintext_hits(lake: Path, needles: list[str]) -> list[str]:
    """Look for plaintext two independent ways, NOT via the gateway:
    1. raw bytes of every file in the lake directory (data, metadata, CRCs);
    2. every value of every column of every Parquet file, decoded with pyarrow —
       necessary because Parquet pages may be compressed, and a compressed page
       could hide a plaintext value from a naive byte scan."""
    hits = []
    for f in _lake_files(lake):
        blob = f.read_bytes()
        hits += [f"{f.name}: raw bytes contain {n!r}" for n in needles if n.encode() in blob]
    for f in lake.rglob("*.parquet"):
        table = pq.read_table(f)
        for col in table.column_names:
            values = {str(v) for v in table.column(col).to_pylist()}
            for n in needles:
                if any(n in v for v in values):
                    hits.append(f"{f.name}: column {col!r} decodes to {n!r}")
    return hits


# --------------------------------------------------------------------------- #
def test_no_plaintext_ssn_in_parquet_files_on_disk(lakehouse):
    ssns = [r["ssn"] for r in _sample()]
    assert len(ssns) >= 8
    assert list(lakehouse.lake_path.rglob("*.parquet")), "lake should contain Parquet files"
    assert _plaintext_hits(lakehouse.lake_path, ssns) == []


def test_no_plaintext_of_any_sensitive_column_on_disk(lakehouse):
    rows = _sample()
    needles = [r[c] for r in rows for c in ("name", "email", "ssn")]
    assert _plaintext_hits(lakehouse.lake_path, needles) == []
    physical = pq.read_table(next(lakehouse.lake_path.rglob("*.parquet"))).column_names
    assert not {"name", "email", "ssn", "salary"} & set(physical)


def test_plaintext_scanner_positive_control(spark, tmp_path):
    """Guard against a vacuous pass: the same scanner DOES find SSNs in an
    unencrypted Parquet copy (same Spark writer, same default compression)."""
    lake = tmp_path / "plain_lake"
    spark.read.option("header", True).csv(str(SAMPLE_CSV)).write.parquet(str(lake))
    ssns = [r["ssn"] for r in _sample()]
    hits = _plaintext_hits(lake, ssns)
    assert any("decodes to" in h for h in hits)


def test_plaintext_columns_remain_queryable_plaintext(lakehouse):
    table = pq.read_table(next(lakehouse.lake_path.rglob("*.parquet")))
    assert "employee_id" in table.column_names and "department" in table.column_names


# --------------------------------------------------------------------------- #
def test_admin_sees_real_values(lakehouse):
    res = lakehouse.gateway.query(ADMIN, ["employee_id", "ssn", "salary"])
    assert res.outcome == "served"
    expected = {r["employee_id"]: (r["ssn"], int(r["salary"])) for r in _sample()}
    assert {r["employee_id"]: (r["ssn"], r["salary"]) for r in res.rows} == expected


def test_different_roles_get_different_results(lakehouse):
    gw = lakehouse.gateway
    admin = gw.query(ADMIN, ["employee_id", "salary"])
    analyst = gw.query(ANALYST, ["employee_id", "salary"])
    auditor = gw.query(AUDITOR, ["employee_id", "salary"])
    support = gw.query(SUPPORT, ["employee_id", "salary"])

    assert admin.outcome == "served" and admin.row_count == 12
    # analyst: real values, but only their own department (row-level ABAC)
    eng = {r["employee_id"] for r in _sample() if r["department"] == "Engineering"}
    assert analyst.outcome == "served"
    assert {r["employee_id"] for r in analyst.rows} == eng
    assert all(isinstance(r["salary"], int) for r in analyst.rows)
    # auditor: every row, every value redacted
    assert auditor.outcome == "masked" and auditor.row_count == 12
    assert {r["salary"] for r in auditor.rows} == {REDACTED}
    # support: no access to salary at all
    assert support.outcome == "denied" and support.rows == []


def test_any_denied_column_refuses_whole_query(lakehouse):
    res = lakehouse.gateway.query(ANALYST, ["employee_id", "salary", "ssn"])
    assert res.outcome == "denied"
    assert res.rows == []  # not even the ALLOWed columns leak


def test_row_cap_blocks_bulk_export(lakehouse):
    res = lakehouse.gateway.query(ANALYST, ["employee_id", "name"])
    assert res.outcome == "denied" and "cap of 5" in res.reason
    scoped = lakehouse.gateway.query(ANALYST, ["employee_id", "name"], {"department": "Engineering"})
    assert scoped.outcome == "served" and scoped.row_count == 4


def test_filter_on_sensitive_column_is_refused(lakehouse):
    res = lakehouse.gateway.query(ADMIN, ["employee_id"], {"ssn": "900-11-0001"})
    assert res.outcome == "denied"


def test_denied_query_still_produces_audit_entry(lakehouse):
    before = len(lakehouse.audit.entries())
    res = lakehouse.gateway.query(SUPPORT, ["employee_id", "ssn_enc"])
    entries = lakehouse.audit.entries()
    assert len(entries) == before + 1
    last = entries[-1]
    assert res.outcome == "denied"
    assert last["seq"] == res.audit_seq
    assert last["outcome"] == "denied" and last["user"] == "taylor.support"
    assert last["decisions"]["ssn_enc"]["effect"] == "DENY"
    assert last["requested_row_count"] == 12 and last["row_count"] == 0


def test_every_query_writes_exactly_one_event_and_chain_stays_intact(lakehouse):
    gw = lakehouse.gateway
    gw.query(ADMIN, ["ssn"])
    gw.query(AUDITOR, ["ssn"])
    gw.query(ANALYST, ["ssn"])
    entries = lakehouse.audit.entries()
    assert [e["outcome"] for e in entries] == ["served", "masked", "denied"]
    assert lakehouse.audit.verify()[0]


def test_audit_log_never_contains_decrypted_values(lakehouse):
    lakehouse.gateway.query(ADMIN, ["employee_id", "name", "email", "ssn", "salary"])
    text = lakehouse.audit.path.read_text()
    for r in _sample():
        assert r["ssn"] not in text and r["email"] not in text


def test_gateway_error_is_audited_and_fails_closed(lakehouse):
    shutil.rmtree(lakehouse.lake_path)  # lake disappears underneath the gateway
    with pytest.raises(Exception):
        lakehouse.gateway.query(ADMIN, ["employee_id"])
    last = lakehouse.audit.entries()[-1]
    assert last["outcome"] == "error" and last["row_count"] == 0


def test_rotation_then_append_reads_both_key_versions(lakehouse, spark):
    lakehouse.key_manager.rotate_key("ssn")
    extra = lakehouse.lake_path.parent / "extra.csv"
    extra.write_text(
        "employee_id,name,email,department,ssn,salary\n"
        "E013,Mona Newhire,mona.newhire@example.com,HR,900-11-0013,70000\n"
    )
    ingest_csv(spark, extra, lakehouse.lake_path, lakehouse.key_manager, mode="append")

    res = lakehouse.gateway.query(ADMIN, ["employee_id", "ssn"])
    by_id = {r["employee_id"]: r["ssn"] for r in res.rows}
    assert by_id["E001"] == "900-11-0001"   # written under ssn v1
    assert by_id["E013"] == "900-11-0013"   # written under ssn v2
    kv = {r["ssn_kv"] for f in lakehouse.lake_path.rglob("*.parquet")
          for r in pq.read_table(f, columns=["ssn_kv"]).to_pylist()}
    assert kv == {1, 2}


def test_wrong_passphrase_cannot_open_lakehouse(lakehouse, spark):
    from pipeline.context import open_lakehouse

    with pytest.raises(PermissionError):
        open_lakehouse(lakehouse.lake_path, lakehouse.state_dir, "not-the-passphrase", spark=spark)
