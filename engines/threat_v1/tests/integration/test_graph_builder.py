"""
Integration tests for the GraphBuilder pipeline (S1-08).

These tests require REAL database connections — no mocks. The test scan_run_id
must already exist in the check engine DB (use a recent production scan).

Env vars required:
  THREAT_DB_HOST / _PORT / _NAME / _USER / _PASSWORD
  CHECK_DB_HOST / _PORT / _NAME / _USER / _PASSWORD
  VULN_DB_HOST / _PORT / _NAME / _USER / _PASSWORD
  CDR_DB_HOST / _PORT / _NAME / _USER / _PASSWORD
  INVENTORY_DB_HOST / _PORT / _NAME / _USER / _PASSWORD
  NEO4J_URI / NEO4J_USERNAME / NEO4J_PASSWORD
  TEST_TENANT_ID       — tenant_id to use for all assertions
  TEST_ACCOUNT_ID      — account_id to use
  TEST_SCAN_RUN_ID     — a known scan_run_id in scan_orchestration for this tenant

Run:
  pytest engines/threat_v1/tests/integration/test_graph_builder.py -v

All assertions use ">= N" guards (not exact counts) because production data changes.
The only exact-zero assertion is for cross-tenant node leakage.
"""
from __future__ import annotations

import os

import pytest

from threat_v1.database import (
    get_cdr_conn,
    get_check_conn,
    get_inventory_conn,
    get_neo4j_driver,
    get_threat_conn,
    get_vuln_conn,
)
from threat_v1.graph.crown_jewel_classifier import CrownJewelClassifier
from threat_v1.graph.cdr_loader import CDRLoader
from threat_v1.graph.edge_builder import EdgeBuilder
from threat_v1.graph.misconfig_loader import MisconfigLoader
from threat_v1.graph.resource_resolver import ResourceResolver
from threat_v1.graph.vuln_loader import VulnLoader


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        pytest.skip(f"Integration test skipped: env var {key} not set")
    return val


@pytest.fixture(scope="module")
def tenant_id() -> str:
    return _env("TEST_TENANT_ID")


@pytest.fixture(scope="module")
def account_id() -> str:
    return _env("TEST_ACCOUNT_ID")


@pytest.fixture(scope="module")
def scan_run_id() -> str:
    return _env("TEST_SCAN_RUN_ID")


@pytest.fixture(scope="module")
def check_conn():
    conn = get_check_conn()
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def vuln_conn():
    conn = get_vuln_conn()
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def cdr_conn():
    conn = get_cdr_conn()
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def inventory_conn():
    conn = get_inventory_conn()
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def threat_conn():
    conn = get_threat_conn()
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def neo4j_driver():
    driver = get_neo4j_driver()
    yield driver
    driver.close()


# ── Test 1: ResourceResolver returns a scan_run_id for check engine ──────────


def test_resolver_returns_check_scan_run_id(
    check_conn, vuln_conn, cdr_conn, inventory_conn, tenant_id, account_id
):
    resolver = ResourceResolver(check_conn, vuln_conn, cdr_conn, inventory_conn)
    resolved = resolver.resolve(tenant_id, account_id)

    assert resolved["check"] is not None, (
        "ResourceResolver must find at least one check scan for the test tenant"
    )


# ── Test 2: MisconfigLoader creates Resource and MisconfigFinding nodes ───────


def test_misconfig_loader_creates_nodes(
    check_conn, neo4j_driver, tenant_id, account_id, scan_run_id
):
    result = MisconfigLoader(check_conn, neo4j_driver).load(
        tenant_id, account_id, scan_run_id
    )

    assert result["resource_count"] >= 1, (
        "MisconfigLoader must create at least 1 Resource node"
    )
    assert result["finding_count"] >= 1, (
        "MisconfigLoader must create at least 1 MisconfigFinding node"
    )


# ── Test 3: Resource nodes have tenant_id property set ───────────────────────


def test_resource_nodes_have_tenant_id(neo4j_driver, tenant_id):
    with neo4j_driver.session(database="threat_v1") as session:
        result = session.run(
            """
            MATCH (r:Resource {tenant_id: $tid})
            RETURN count(r) AS cnt
            """,
            tid=tenant_id,
        )
        cnt = result.single()["cnt"]

    assert cnt >= 1, (
        "At least 1 Resource node must have tenant_id property matching test tenant"
    )


# ── Test 4: No cross-tenant Resource nodes visible ────────────────────────────


def test_no_cross_tenant_resource_nodes(neo4j_driver, tenant_id):
    """Verify that no Resource nodes exist without a tenant_id.

    All nodes written by the graph builder must have tenant_id set.
    Nodes without tenant_id indicate a missing scoping bug.
    """
    with neo4j_driver.session(database="threat_v1") as session:
        result = session.run(
            """
            MATCH (r:Resource)
            WHERE r.tenant_id IS NULL
            RETURN count(r) AS cnt
            """
        )
        cnt = result.single()["cnt"]

    assert cnt == 0, (
        f"Found {cnt} Resource node(s) without tenant_id — possible cross-tenant data leak"
    )


# ── Test 5: At least one HAS_MISCONFIG edge exists ───────────────────────────


def test_has_misconfig_edge_exists(neo4j_driver, tenant_id):
    with neo4j_driver.session(database="threat_v1") as session:
        result = session.run(
            """
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_MISCONFIG]->(f:MisconfigFinding)
            RETURN count(f) AS cnt
            """,
            tid=tenant_id,
        )
        cnt = result.single()["cnt"]

    assert cnt >= 1, (
        "At least 1 HAS_MISCONFIG edge must exist between Resource and MisconfigFinding"
    )


# ── Test 6: Neo4j named database is threat_v1 (not default neo4j) ─────────────


def test_neo4j_named_database(neo4j_driver):
    """Confirm the driver is connected to the threat_v1 named DB."""
    with neo4j_driver.session(database="threat_v1") as session:
        result = session.run("CALL db.info() YIELD name RETURN name")
        db_name = result.single()["name"]

    assert db_name == "threat_v1", (
        f"Expected named DB 'threat_v1' but got '{db_name}'. "
        "All threat_v1 sessions must use database='threat_v1' explicitly."
    )


# ── Test 7: CDRLoader does not write actor_principal to Neo4j ─────────────────


def test_cdr_loader_does_not_store_actor_principal(
    cdr_conn, neo4j_driver, tenant_id
):
    """CDREvent nodes must NOT have an actor_principal property (CP1-02)."""
    # Run loader (may produce 0 events if no CDR data — that's fine)
    resolver_check = None
    try:
        cur = cdr_conn.cursor()
        cur.execute(
            """
            SELECT scan_run_id FROM cdr_findings
            WHERE tenant_id = %s
            GROUP BY scan_run_id ORDER BY count(*) DESC LIMIT 1
            """,
            (tenant_id,),
        )
        row = cur.fetchone()
        cur.close()
        resolver_check = row["scan_run_id"] if row else None
    except Exception:
        pass

    if resolver_check:
        CDRLoader(cdr_conn, neo4j_driver).load(tenant_id, resolver_check)

    with neo4j_driver.session(database="threat_v1") as session:
        result = session.run(
            """
            MATCH (e:CDREvent {tenant_id: $tid})
            WHERE e.actor_principal IS NOT NULL
            RETURN count(e) AS cnt
            """,
            tid=tenant_id,
        )
        cnt = result.single()["cnt"]

    assert cnt == 0, (
        f"Found {cnt} CDREvent node(s) with actor_principal property. "
        "CP1-02 requires only actor_hash (sha256) is stored — never raw PII."
    )
