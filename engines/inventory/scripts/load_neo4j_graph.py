#!/usr/bin/env python3
"""
Neo4j Graph Loader — Inventory Findings + Relationships
=========================================================
Reads inventory_findings and inventory_relationships from PostgreSQL
and loads them into Neo4j as a property graph.

Node types:
  (:Asset)    — one per inventory_finding (filterable by account, provider, resource_type)
  (:Account)  — one per (provider, account_id)
  (:Tenant)   — one per tenant_id
  (:Region)   — one per (provider, region)

Relationship types (dynamic, from relation_type column):
  (:Asset)-[:CONTAINED_BY]->(:Asset)
  (:Asset)-[:USES]->(:Asset)
  (:Asset)-[:ENCRYPTED_BY]->(:Asset)
  (:Asset)-[:ATTACHED_TO]->(:Asset)
  (:Asset)-[:BELONGS_TO]->(:Account)
  (:Account)-[:MEMBER_OF]->(:Tenant)
  (:Asset)-[:IN_REGION]->(:Region)
  ... (all relation_types from resource_security_relationship_rules)

Usage:
    export INVENTORY_DB_URL="postgresql://user:pass@host:5432/threat_engine_inventory"
    export NEO4J_URI="bolt://localhost:7687"
    export NEO4J_USER="neo4j"
    export NEO4J_PASSWORD="password"

    python load_neo4j_graph.py
    python load_neo4j_graph.py --account 588989875114 --provider aws
    python load_neo4j_graph.py --clear          # wipe + reload
    python load_neo4j_graph.py --incremental    # upsert only (default)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

_BATCH_SIZE = 500


# ── Neo4j helpers ─────────────────────────────────────────────────────────────

def _neo4j_driver(uri: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None):
    try:
        from neo4j import GraphDatabase
    except ImportError:
        sys.exit("Install neo4j driver: pip install neo4j")

    uri      = uri      or os.getenv("NEO4J_URI",      "bolt://localhost:7687")
    user     = user     or os.getenv("NEO4J_USER",     "neo4j")
    password = password or os.getenv("NEO4J_PASSWORD",  "password")
    return GraphDatabase.driver(uri, auth=(user, password))


def _run_batch(session, cypher: str, batch: List[Dict]) -> int:
    result = session.run(cypher, rows=batch)
    summary = result.consume()
    return summary.counters.nodes_created + summary.counters.relationships_created


# ── Schema setup ──────────────────────────────────────────────────────────────

SCHEMA_QUERIES = [
    # Uniqueness constraints (also create backing indexes)
    "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.finding_id IS UNIQUE",
    "CREATE CONSTRAINT account_id IF NOT EXISTS FOR (a:Account) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT tenant_id IF NOT EXISTS FOR (t:Tenant) REQUIRE t.id IS UNIQUE",
    "CREATE CONSTRAINT region_id IF NOT EXISTS FOR (r:Region) REQUIRE r.id IS UNIQUE",
    # Lookup indexes
    "CREATE INDEX asset_resource_uid IF NOT EXISTS FOR (a:Asset) ON (a.resource_uid)",
    "CREATE INDEX asset_account IF NOT EXISTS FOR (a:Asset) ON (a.account_id, a.provider)",
    "CREATE INDEX asset_resource_type IF NOT EXISTS FOR (a:Asset) ON (a.resource_type, a.provider)",
    "CREATE INDEX asset_tenant IF NOT EXISTS FOR (a:Asset) ON (a.tenant_id)",
    "CREATE INDEX asset_risk IF NOT EXISTS FOR (a:Asset) ON (a.risk_score)",
    "CREATE INDEX asset_region IF NOT EXISTS FOR (a:Asset) ON (a.region)",
]


def setup_schema(driver) -> None:
    log.info("Setting up Neo4j schema (constraints + indexes)…")
    with driver.session() as session:
        for q in SCHEMA_QUERIES:
            try:
                session.run(q)
            except Exception as e:
                log.warning(f"Schema query skipped ({e}): {q[:60]}")
    log.info("Schema ready.")


# ── PostgreSQL helpers ────────────────────────────────────────────────────────

def _pg_connect(dsn: Optional[str] = None) -> psycopg2.extensions.connection:
    dsn = dsn or os.getenv("INVENTORY_DB_URL")
    if not dsn:
        sys.exit("Set INVENTORY_DB_URL or pass --db-url")
    return psycopg2.connect(dsn)


def _load_findings(
    conn, account_id: Optional[str] = None,
    provider: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    conditions, params = [], []
    if account_id:
        conditions.append("account_id = %s"); params.append(account_id)
    if provider:
        conditions.append("provider = %s"); params.append(provider)
    if scan_id:
        conditions.append("scan_run_id = %s"); params.append(scan_id)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"""
            SELECT finding_id::text, tenant_id, scan_run_id,
                   resource_uid, resource_type, provider,
                   account_id, region, name, display_name, description,
                   tags, labels, properties, configuration,
                   compliance_status, risk_score, criticality,
                   environment, cost_center, owner, business_unit,
                   first_seen_at::text, last_seen_at::text, updated_at::text
            FROM inventory_findings
            {where}
        """, params)
        return [dict(r) for r in cur.fetchall()]


def _load_relationships(
    conn, account_id: Optional[str] = None,
    provider: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    conditions, params = [], []
    if account_id:
        conditions.append("account_id = %s"); params.append(account_id)
    if provider:
        conditions.append("provider = %s"); params.append(provider)
    if scan_id:
        conditions.append("scan_run_id = %s"); params.append(scan_id)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"""
            SELECT relationship_id::text,
                   from_uid, to_uid,
                   from_resource_type, to_resource_type,
                   relation_type, provider, account_id,
                   relationship_strength, bidirectional,
                   properties
            FROM inventory_relationships
            {where}
            ORDER BY provider, from_resource_type
        """, params)
        return [dict(r) for r in cur.fetchall()]


# ── Node loading ──────────────────────────────────────────────────────────────

def _safe_json(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return str(v)


def _flatten_finding(row: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a flat Neo4j-compatible property map from a finding row."""
    props = row.get("properties") or {}
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except Exception:
            props = {}

    emitted = props.get("emitted_fields") or {} if isinstance(props, dict) else {}

    return {
        "finding_id":          row["finding_id"],
        "resource_uid":      row["resource_uid"] or "",
        "resource_type":     row["resource_type"] or "",
        "provider":          row["provider"] or "",
        "csp":               row["provider"] or "",
        "account_id":        row["account_id"] or "",
        "tenant_id":         row["tenant_id"] or "",
        "scan_run_id": row["scan_run_id"] or "",
        "region":            row["region"] or "",
        "name":              row.get("name") or emitted.get("resource_name") or "",
        "display_name":      row.get("display_name") or "",
        "description":       row.get("description") or "",
        "compliance_status": row.get("compliance_status") or "",
        "risk_score":        row.get("risk_score") or 0,
        "criticality":       row.get("criticality") or "",
        "environment":       row.get("environment") or "",
        "cost_center":       row.get("cost_center") or "",
        "owner":             row.get("owner") or "",
        "business_unit":     row.get("business_unit") or "",
        "first_seen_at": row.get("first_seen_at") or "",
        "last_seen_at":    row.get("last_seen_at") or "",
        # Serialise complex fields as JSON strings for Neo4j
        "tags":              _safe_json(row.get("tags")) or "{}",
        "labels":            _safe_json(row.get("labels")) or "{}",
        # Extract service from resource_type  (e.g. "ec2.security-group" → "ec2")
        "service":           (row["resource_type"] or "").split(".")[0],
    }


def load_asset_nodes(driver, findings: List[Dict[str, Any]]) -> int:
    log.info(f"Loading {len(findings)} Asset nodes…")
    nodes = [_flatten_finding(f) for f in findings]

    cypher = """
    UNWIND $rows AS row
    MERGE (a:Asset {finding_id: row.finding_id})
    SET a += row
    """
    total = 0
    with driver.session() as session:
        for i in range(0, len(nodes), _BATCH_SIZE):
            batch = nodes[i: i + _BATCH_SIZE]
            session.run(cypher, rows=batch)
            total += len(batch)
            log.info(f"  Assets: {total}/{len(nodes)}")
    return total


def load_hierarchy_nodes(driver, findings: List[Dict[str, Any]]) -> None:
    """Create Tenant, Account, Region nodes and link Assets to them."""
    log.info("Loading hierarchy nodes (Tenant / Account / Region)…")

    tenants:  Dict[str, Dict] = {}
    accounts: Dict[str, Dict] = {}
    regions:  Dict[str, Dict] = {}

    for f in findings:
        tid = f.get("tenant_id") or ""
        pid = f.get("provider") or ""
        aid = f.get("account_id") or ""
        reg = f.get("region") or ""

        if tid:
            tenants[tid] = {"id": tid, "name": tid}
        if aid and pid:
            key = f"{pid}:{aid}"
            accounts[key] = {"id": key, "account_id": aid, "provider": pid, "name": aid}
        if reg and pid:
            key = f"{pid}:{reg}"
            regions[key] = {"id": key, "region": reg, "provider": pid, "name": reg}

    with driver.session() as session:
        # Tenants
        if tenants:
            session.run("""
                UNWIND $rows AS row
                MERGE (t:Tenant {id: row.id})
                SET t += row
            """, rows=list(tenants.values()))

        # Accounts  →  MEMBER_OF  → Tenant
        if accounts:
            session.run("""
                UNWIND $rows AS row
                MERGE (a:Account {id: row.id})
                SET a += row
            """, rows=list(accounts.values()))
            # Link accounts to tenants (need both tenant and account in same finding)
            links = [
                {"account_id": f"{(f.get('provider') or '')}:{f.get('account_id') or ''}",
                 "tenant_id": f.get("tenant_id") or ""}
                for f in findings if f.get("tenant_id") and f.get("account_id")
            ]
            if links:
                session.run("""
                    UNWIND $rows AS row
                    MATCH (a:Account {id: row.account_id})
                    MATCH (t:Tenant {id: row.tenant_id})
                    MERGE (a)-[:MEMBER_OF]->(t)
                """, rows=links)

        # Regions
        if regions:
            session.run("""
                UNWIND $rows AS row
                MERGE (r:Region {id: row.id})
                SET r += row
            """, rows=list(regions.values()))

        # Asset  → BELONGS_TO → Account
        asset_account = [
            {"finding_id": f["finding_id"],
             "account_key": f"{f.get('provider') or ''}:{f.get('account_id') or ''}"}
            for f in findings if f.get("account_id")
        ]
        for i in range(0, len(asset_account), _BATCH_SIZE):
            session.run("""
                UNWIND $rows AS row
                MATCH (a:Asset {finding_id: row.finding_id})
                MATCH (acc:Account {id: row.account_key})
                MERGE (a)-[:BELONGS_TO]->(acc)
            """, rows=asset_account[i: i + _BATCH_SIZE])

        # Asset → IN_REGION → Region
        asset_region = [
            {"finding_id": f["finding_id"],
             "region_key": f"{f.get('provider') or ''}:{f.get('region') or ''}"}
            for f in findings if f.get("region")
        ]
        for i in range(0, len(asset_region), _BATCH_SIZE):
            session.run("""
                UNWIND $rows AS row
                MATCH (a:Asset {finding_id: row.finding_id})
                MATCH (r:Region {id: row.region_key})
                MERGE (a)-[:IN_REGION]->(r)
            """, rows=asset_region[i: i + _BATCH_SIZE])

    log.info(
        f"Hierarchy: {len(tenants)} tenants, {len(accounts)} accounts, {len(regions)} regions"
    )


# ── Relationship loading ───────────────────────────────────────────────────────

def load_relationships(driver, rels: List[Dict[str, Any]]) -> int:
    """
    Load inventory_relationships as Neo4j edges.
    Relation type is uppercased and used as the edge label.
    e.g. relation_type='contained_by' → [:CONTAINED_BY]

    Since Neo4j requires static relationship types in Cypher, we use APOC
    if available, otherwise fall back to batching per relation_type.
    """
    if not rels:
        log.info("No relationships to load.")
        return 0

    log.info(f"Loading {len(rels)} relationships…")

    # Group by relation_type for static Cypher
    by_type: Dict[str, List[Dict]] = {}
    for r in rels:
        rt = (r.get("relation_type") or "related_to").upper().replace("-", "_").replace(" ", "_")
        by_type.setdefault(rt, []).append(r)

    total = 0
    with driver.session() as session:
        # First check if APOC is available
        try:
            session.run("CALL apoc.help('merge') YIELD name RETURN name LIMIT 1").consume()
            has_apoc = True
        except Exception:
            has_apoc = False

        if has_apoc:
            log.info("  Using APOC for dynamic relationship types")
            batch = [
                {
                    "from_uid": r["from_uid"],
                    "to_uid":   r["to_uid"],
                    "rel_type": (r.get("relation_type") or "related_to").upper().replace("-", "_"),
                    "props": {
                        "relationship_id":   r.get("relationship_id", ""),
                        "from_resource_type": r.get("from_resource_type", ""),
                        "to_resource_type":  r.get("to_resource_type", ""),
                        "provider":          r.get("provider", ""),
                        "account_id":        r.get("account_id", ""),
                        "strength":          r.get("relationship_strength", "strong"),
                    }
                }
                for r in rels
            ]
            cypher = """
            UNWIND $rows AS row
            MATCH (from:Asset {resource_uid: row.from_uid})
            MATCH (to:Asset   {resource_uid: row.to_uid})
            CALL apoc.merge.relationship(from, row.rel_type, {}, row.props, to, {}) YIELD rel
            RETURN count(rel)
            """
            for i in range(0, len(batch), _BATCH_SIZE):
                session.run(cypher, rows=batch[i: i + _BATCH_SIZE])
                total += len(batch[i: i + _BATCH_SIZE])
                log.info(f"  Relationships: {total}/{len(rels)}")
        else:
            log.info("  APOC not available — batching per relation_type")
            for rel_type, type_rels in by_type.items():
                # Cypher with static label requires dynamic construction
                cypher = f"""
                UNWIND $rows AS row
                MATCH (from:Asset {{resource_uid: row.from_uid}})
                MATCH (to:Asset   {{resource_uid: row.to_uid}})
                MERGE (from)-[r:{rel_type} {{relationship_id: row.relationship_id}}]->(to)
                SET r.from_resource_type = row.from_resource_type,
                    r.to_resource_type   = row.to_resource_type,
                    r.provider           = row.provider,
                    r.account_id         = row.account_id,
                    r.strength           = row.relationship_strength
                """
                batch = [
                    {
                        "from_uid":           r["from_uid"],
                        "to_uid":             r["to_uid"],
                        "relationship_id":    r.get("relationship_id", ""),
                        "from_resource_type": r.get("from_resource_type", ""),
                        "to_resource_type":   r.get("to_resource_type", ""),
                        "provider":           r.get("provider", ""),
                        "account_id":         r.get("account_id", ""),
                        "relationship_strength": r.get("relationship_strength", "strong"),
                    }
                    for r in type_rels
                ]
                for i in range(0, len(batch), _BATCH_SIZE):
                    session.run(cypher, rows=batch[i: i + _BATCH_SIZE])
                    total += len(batch[i: i + _BATCH_SIZE])
                log.info(f"  [{rel_type}] {len(type_rels)} edges")

    log.info(f"Loaded {total} relationships")
    return total


# ── Clear graph ───────────────────────────────────────────────────────────────

def clear_graph(driver, provider: Optional[str] = None, account_id: Optional[str] = None) -> None:
    """Delete nodes/edges. If scoped, delete only matching assets + their edges."""
    with driver.session() as session:
        if not provider and not account_id:
            log.warning("Clearing ALL nodes and relationships from Neo4j…")
            session.run("MATCH (n) DETACH DELETE n")
        else:
            log.info(f"Clearing assets for provider={provider} account={account_id}…")
            params = {}
            conditions = []
            if provider:
                conditions.append("a.provider = $provider")
                params["provider"] = provider
            if account_id:
                conditions.append("a.account_id = $account_id")
                params["account_id"] = account_id
            where = " AND ".join(conditions)
            session.run(f"MATCH (a:Asset) WHERE {where} DETACH DELETE a", **params)
    log.info("Clear complete.")


# ── Main ──────────────────────────────────────────────────────────────────────

def load_graph(
    pg_dsn: Optional[str] = None,
    neo4j_uri: Optional[str] = None,
    neo4j_user: Optional[str] = None,
    neo4j_password: Optional[str] = None,
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    scan_id: Optional[str] = None,
    clear: bool = False,
) -> None:
    pg_conn = _pg_connect(pg_dsn)
    driver  = _neo4j_driver(neo4j_uri, neo4j_user, neo4j_password)

    try:
        setup_schema(driver)

        if clear:
            clear_graph(driver, provider=provider, account_id=account_id)

        log.info("Loading findings from PostgreSQL…")
        findings = _load_findings(pg_conn, account_id, provider, scan_id)
        log.info(f"  {len(findings)} findings loaded")

        log.info("Loading relationships from PostgreSQL…")
        rels = _load_relationships(pg_conn, account_id, provider, scan_id)
        log.info(f"  {len(rels)} relationships loaded")

        load_asset_nodes(driver, findings)
        load_hierarchy_nodes(driver, findings)
        load_relationships(driver, rels)

        # Summary
        with driver.session() as session:
            stats = session.run("""
                MATCH (a:Asset)   WITH count(a) AS assets
                MATCH (acc:Account) WITH assets, count(acc) AS accounts
                MATCH (t:Tenant)  WITH assets, accounts, count(t) AS tenants
                RETURN assets, accounts, tenants
            """).single()
            if stats:
                log.info(
                    f"Graph summary: {stats['assets']} assets, "
                    f"{stats['accounts']} accounts, {stats['tenants']} tenants"
                )
            rel_count = session.run("MATCH ()-[r]->() RETURN count(r) AS n").single()
            if rel_count:
                log.info(f"Total edges in graph: {rel_count['n']}")

    finally:
        pg_conn.close()
        driver.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Load inventory graph into Neo4j")
    parser.add_argument("--db-url", help="PostgreSQL DSN (or INVENTORY_DB_URL env)")
    parser.add_argument("--neo4j-uri",      default=None)
    parser.add_argument("--neo4j-user",     default=None)
    parser.add_argument("--neo4j-password", default=None)
    parser.add_argument("--account",  help="Scope to account_id")
    parser.add_argument("--provider", help="Scope to provider")
    parser.add_argument("--scan-id",  dest="scan_id", help="Scope to scan_run_id")
    parser.add_argument("--clear",    action="store_true", help="Delete existing nodes first")
    args = parser.parse_args()

    load_graph(
        pg_dsn=args.db_url,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        account_id=args.account,
        provider=args.provider,
        scan_id=args.scan_id,
        clear=args.clear,
    )
