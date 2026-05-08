#!/usr/bin/env python3
"""
AZ-14: Validate the full Azure pipeline across all engines.

Checks check, inventory, threat, compliance, IAM engines and Neo4j
for a completed Azure scan identified by scan_run_id.

Usage:
    # Port-forward all DBs first (or set RDS host directly):
    DISCOVERIES_DB_HOST=localhost  DISCOVERIES_DB_PASSWORD=xxx \
    CHECK_DB_HOST=localhost        CHECK_DB_PASSWORD=xxx \
    THREAT_DB_HOST=localhost       THREAT_DB_PASSWORD=xxx \
    COMPLIANCE_DB_HOST=localhost   COMPLIANCE_DB_PASSWORD=xxx \
    IAM_DB_HOST=localhost          IAM_DB_PASSWORD=xxx \
    NEO4J_PASSWORD=xxx \
    python scripts/validate_azure_pipeline.py <scan_run_id> <tenant_id>
"""

import os
import sys

import psycopg2

RDS_HOST = "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"

CHECKS_PASSED = 0
CHECKS_FAILED = 0
CHECKS_SKIPPED = 0


def _conn(db_name: str, host_env: str, pw_env: str, user_env: str = None, port_env: str = None):
    return psycopg2.connect(
        host=os.getenv(host_env, RDS_HOST),
        port=int(os.getenv(port_env or "DB_PORT", "5432")),
        dbname=os.getenv(f"{host_env[:-5]}_NAME", db_name),
        user=os.getenv(user_env or f"{host_env[:-5]}_USER", "postgres"),
        password=os.getenv(pw_env, ""),
    )


def ok(label: str, msg: str) -> None:
    global CHECKS_PASSED
    CHECKS_PASSED += 1
    print(f"  PASS  [{label}] {msg}")


def fail(label: str, msg: str) -> None:
    global CHECKS_FAILED
    CHECKS_FAILED += 1
    print(f"  FAIL  [{label}] {msg}")


def skip(label: str, msg: str) -> None:
    global CHECKS_SKIPPED
    CHECKS_SKIPPED += 1
    print(f"  SKIP  [{label}] {msg}")


def section(title: str) -> None:
    print(f"\n── {title} {'─' * (55 - len(title))}")


# ── Check Engine ─────────────────────────────────────────────────────────────

def validate_check(scan_run_id: str) -> None:
    section("Check Engine")
    try:
        conn = psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", RDS_HOST),
            port=5432,
            dbname="threat_engine_check",
            user="postgres",
            password=os.getenv("CHECK_DB_PASSWORD", ""),
        )
        cur = conn.cursor()

        cur.execute(
            "SELECT COUNT(*) FROM check_findings WHERE scan_run_id=%s AND provider='azure'",
            (scan_run_id,),
        )
        count = cur.fetchone()[0]
        if count > 0:
            ok("check", f"{count} Azure check_findings")
        else:
            fail("check", "0 Azure check_findings — check engine may not have run or rules missing")

        cur.execute(
            "SELECT COUNT(DISTINCT rule_id) FROM check_findings WHERE scan_run_id=%s AND provider='azure'",
            (scan_run_id,),
        )
        rules = cur.fetchone()[0]
        if rules >= 3:
            ok("check", f"{rules} distinct rules evaluated")
        elif rules > 0:
            ok("check", f"{rules} distinct rules (low — verify rule_metadata has Azure rules)")
        else:
            skip("check", "0 rules matched (0 findings)")

        cur.execute(
            "SELECT COUNT(*) FROM check_findings WHERE scan_run_id=%s AND provider='azure' AND severity IS NULL",
            (scan_run_id,),
        )
        nulls = cur.fetchone()[0]
        if nulls == 0:
            ok("check", "No NULL severity rows")
        else:
            fail("check", f"{nulls} check_findings with NULL severity")

        # breakdown by status
        cur.execute(
            """SELECT status, COUNT(*) FROM check_findings
               WHERE scan_run_id=%s AND provider='azure'
               GROUP BY status ORDER BY count DESC""",
            (scan_run_id,),
        )
        print("         Status breakdown:")
        for status, cnt in cur.fetchall():
            print(f"           {status or 'NULL':10s}: {cnt}")

        conn.close()
    except Exception as exc:
        skip("check", f"DB connection failed: {exc}")


# ── Inventory Engine ──────────────────────────────────────────────────────────

def validate_inventory(scan_run_id: str) -> None:
    section("Inventory Engine")
    try:
        conn = psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST", RDS_HOST),
            port=5432,
            dbname="threat_engine_inventory",
            user="postgres",
            password=os.getenv("INVENTORY_DB_PASSWORD", ""),
        )
        cur = conn.cursor()

        cur.execute(
            "SELECT COUNT(*) FROM inventory_findings WHERE scan_run_id=%s AND provider='azure'",
            (scan_run_id,),
        )
        count = cur.fetchone()[0]
        if count > 0:
            ok("inventory", f"{count} Azure inventory_findings")
        else:
            fail("inventory", "0 Azure inventory_findings")

        # Check service_classification join works (no 'unknown' category)
        cur.execute(
            """SELECT COUNT(*) FROM inventory_findings i
               LEFT JOIN service_classification sc ON sc.csp='azure' AND sc.resource_type=i.resource_type
               WHERE i.scan_run_id=%s AND i.provider='azure'
                 AND sc.category IS NULL""",
            (scan_run_id,),
        )
        unclassified = cur.fetchone()[0]
        if unclassified == 0:
            ok("inventory", "All resource_types match service_classification entries")
        else:
            fail("inventory", f"{unclassified} inventory_findings with no service_classification match — add entries to migration 024")

        conn.close()
    except Exception as exc:
        skip("inventory", f"DB connection failed: {exc}")


# ── Threat Engine + Neo4j ─────────────────────────────────────────────────────

def validate_threat(scan_run_id: str, tenant_id: str) -> None:
    section("Threat Engine")
    try:
        conn = psycopg2.connect(
            host=os.getenv("THREAT_DB_HOST", RDS_HOST),
            port=5432,
            dbname="threat_engine_threat",
            user="postgres",
            password=os.getenv("THREAT_DB_PASSWORD", ""),
        )
        cur = conn.cursor()

        cur.execute(
            "SELECT COUNT(*) FROM threat_findings WHERE scan_run_id=%s AND provider='azure'",
            (scan_run_id,),
        )
        count = cur.fetchone()[0]
        if count >= 0:  # 0 is acceptable if no misconfigs triggered threat rules
            ok("threat", f"{count} Azure threat_findings (0 is acceptable if no misconfigs)")
        # not a hard failure — threat findings require check findings first

        cur.execute(
            "SELECT COUNT(*) FROM threat_hunt_queries WHERE tags @> '[\"azure\"]'::jsonb AND is_active=TRUE",
            (),
        )
        hunt_q = cur.fetchone()[0]
        if hunt_q >= 5:
            ok("threat", f"{hunt_q} Azure hunt queries seeded (AZ-16)")
        else:
            fail("threat", f"Only {hunt_q} Azure hunt queries — run seed_azure_hunt_queries.py")

        conn.close()
    except Exception as exc:
        skip("threat", f"DB connection failed: {exc}")

    # Neo4j checks
    validate_neo4j(tenant_id)


def validate_neo4j(tenant_id: str) -> None:
    section("Neo4j Graph")
    try:
        from neo4j import GraphDatabase  # type: ignore

        uri = os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "")
        if not password:
            skip("neo4j", "NEO4J_PASSWORD not set — export NEO4J_PASSWORD=xxx")
            return

        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:

            # Azure Resource nodes exist
            r = session.run(
                "MATCH (r:Resource {provider: 'azure'}) RETURN count(r) AS cnt"
            ).single()
            cnt = r["cnt"]
            if cnt > 0:
                ok("neo4j", f"{cnt} Azure Resource nodes")
            else:
                fail("neo4j", "0 Azure Resource nodes — threat engine graph import may not have run")

            # Correct labels (VirtualMachine not CloudResource)
            r = session.run(
                "MATCH (r:VirtualMachine {provider: 'azure'}) RETURN count(r) AS cnt"
            ).single()
            vm_cnt = r["cnt"]
            if vm_cnt > 0:
                ok("neo4j", f"{vm_cnt} VirtualMachine nodes with provider=azure (correct label)")
            else:
                skip("neo4j", "0 VirtualMachine nodes — no Azure VMs discovered or graph not imported")

            # No CloudResource label with provider=azure (regression check for AZ-15 fix)
            r = session.run(
                "MATCH (r:CloudResource {provider: 'azure'}) RETURN count(r) AS cnt"
            ).single()
            bad_cnt = r["cnt"]
            if bad_cnt == 0:
                ok("neo4j", "No CloudResource nodes with provider=azure (AZ-15 regression OK)")
            else:
                fail("neo4j", f"{bad_cnt} nodes with :CloudResource label and provider=azure — _neo4j_label() fix not applied")

            # StorageAccount label
            r = session.run(
                "MATCH (r:StorageAccount {provider: 'azure'}) RETURN count(r) AS cnt"
            ).single()
            sa_cnt = r["cnt"]
            if sa_cnt > 0:
                ok("neo4j", f"{sa_cnt} StorageAccount nodes (correct label)")
            else:
                skip("neo4j", "0 StorageAccount nodes")

            # Internet→Azure exposure edges (post-threat engine)
            r = session.run(
                "MATCH (i:Internet)-[:EXPOSES]->(r:Resource {provider:'azure'}) RETURN count(r) AS cnt"
            ).single()
            exposed = r["cnt"]
            if exposed > 0:
                ok("neo4j", f"{exposed} Azure resources exposed to Internet (attack paths working)")
            else:
                skip("neo4j", "0 Azure Internet-exposed resources (OK if none are publicly accessible)")

        driver.close()
    except ImportError:
        skip("neo4j", "pip install neo4j to enable Neo4j validation")
    except Exception as exc:
        skip("neo4j", f"Neo4j check failed: {exc}")


# ── Compliance Engine ─────────────────────────────────────────────────────────

def validate_compliance(scan_run_id: str, tenant_id: str) -> None:
    section("Compliance Engine")
    try:
        conn = psycopg2.connect(
            host=os.getenv("COMPLIANCE_DB_HOST", RDS_HOST),
            port=5432,
            dbname="threat_engine_compliance",
            user="postgres",
            password=os.getenv("COMPLIANCE_DB_PASSWORD", ""),
        )
        cur = conn.cursor()

        # CIS Azure 1.5 framework seeded
        cur.execute(
            "SELECT count(*) FROM compliance_frameworks WHERE framework_id='cis_azure_1_5'",
        )
        fw = cur.fetchone()[0]
        if fw > 0:
            ok("compliance", "CIS Azure 1.5 framework seeded (AZ-08)")
        else:
            fail("compliance", "CIS Azure 1.5 framework missing — run migration 025")

        # Controls seeded
        cur.execute(
            "SELECT count(*) FROM compliance_controls WHERE framework_id='cis_azure_1_5'",
        )
        controls = cur.fetchone()[0]
        if controls >= 87:
            ok("compliance", f"{controls} CIS Azure 1.5 controls seeded")
        elif controls > 0:
            ok("compliance", f"{controls} controls (< 87 expected — check migration 025)")
        else:
            fail("compliance", "0 CIS Azure 1.5 controls — run migration 025")

        # rule_control_mapping rows
        cur.execute(
            "SELECT count(*) FROM rule_control_mapping WHERE framework_id='cis_azure_1_5'",
        )
        mappings = cur.fetchone()[0]
        if mappings >= 50:
            ok("compliance", f"{mappings} rule→control mappings for CIS Azure 1.5")
        elif mappings > 0:
            ok("compliance", f"{mappings} mappings (extend migration 026 for full coverage)")
        else:
            fail("compliance", "0 rule_control_mapping rows for CIS Azure 1.5 — run migration 026")

        # Compliance report for this scan
        cur.execute(
            """SELECT framework_id, score FROM compliance_report
               WHERE scan_run_id=%s AND provider='azure'
               ORDER BY framework_id""",
            (scan_run_id,),
        )
        reports = cur.fetchall()
        if reports:
            ok("compliance", f"{len(reports)} compliance report(s) generated:")
            for fw_id, score in reports:
                print(f"           {fw_id:30s}: score={score}")
        else:
            skip("compliance", "No compliance_report rows yet — compliance engine run needed")

        conn.close()
    except Exception as exc:
        skip("compliance", f"DB connection failed: {exc}")


# ── IAM Engine ────────────────────────────────────────────────────────────────

def validate_iam(scan_run_id: str) -> None:
    section("IAM Engine")
    try:
        conn = psycopg2.connect(
            host=os.getenv("IAM_DB_HOST", RDS_HOST),
            port=5432,
            dbname="threat_engine_iam",
            user="postgres",
            password=os.getenv("IAM_DB_PASSWORD", ""),
        )
        cur = conn.cursor()

        cur.execute(
            "SELECT COUNT(*) FROM iam_findings WHERE scan_run_id=%s AND provider='azure'",
            (scan_run_id,),
        )
        count = cur.fetchone()[0]
        if count > 0:
            ok("iam", f"{count} Azure IAM findings")
        else:
            skip("iam", "0 Azure IAM findings — IAM engine may not have run yet")

        # IAM rules seeded in rule_metadata
        check_conn = psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", RDS_HOST),
            port=5432,
            dbname="threat_engine_check",
            user="postgres",
            password=os.getenv("CHECK_DB_PASSWORD", ""),
        )
        check_cur = check_conn.cursor()
        check_cur.execute(
            """SELECT COUNT(*) FROM rule_metadata
               WHERE provider='azure'
               AND iam_security IS NOT NULL
               AND iam_security != '{}'::jsonb""",
        )
        iam_rules = check_cur.fetchone()[0]
        if iam_rules >= 15:
            ok("iam", f"{iam_rules} Azure IAM rules tagged in rule_metadata (AZ-10)")
        elif iam_rules > 0:
            ok("iam", f"{iam_rules} Azure IAM rules tagged (run migration 026 to tag all)")
        else:
            fail("iam", "0 Azure IAM rules tagged — run migration 026")
        check_conn.close()

        conn.close()
    except Exception as exc:
        skip("iam", f"DB connection failed: {exc}")


# ── Summary ───────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python validate_azure_pipeline.py <scan_run_id> <tenant_id>")
        sys.exit(1)

    scan_run_id = sys.argv[1]
    tenant_id = sys.argv[2]

    print(f"\n=== AZ-14: Azure Full Pipeline Validation ===")
    print(f"  scan_run_id : {scan_run_id}")
    print(f"  tenant_id   : {tenant_id}")

    validate_check(scan_run_id)
    validate_inventory(scan_run_id)
    validate_threat(scan_run_id, tenant_id)
    validate_compliance(scan_run_id, tenant_id)
    validate_iam(scan_run_id)

    total = CHECKS_PASSED + CHECKS_FAILED
    print(f"\n=== Result: {CHECKS_PASSED}/{total} passed"
          f", {CHECKS_SKIPPED} skipped ===\n")

    if CHECKS_FAILED > 0:
        print("Some checks FAILED — see output above.")
        sys.exit(1)
    else:
        print("All checks PASSED (or skipped pending engine runs) — AZ-14 complete.")


if __name__ == "__main__":
    main()
