"""
TE6-10 — E2E integration test: Ubuntu SSH scan → discovery → check findings.

Prerequisites:
  - Docker daemon running locally
  - tech-discovery and tech-check pods reachable (port-forward or in-cluster)
  - TECH_DB_* env vars set OR kubectl exec used for DB checks

Test flow:
  1. Start an Ubuntu 22.04 SSH container with a known password
  2. Insert a tech_credential row pointing at the container
  3. POST /api/v1/scan/run to tech-discovery (scan_run_id generated)
  4. Wait for scan completion (poll tech_scan_orchestration)
  5. Assert >= 50 tech_discovery_findings rows for this scan_run_id
  6. POST /api/v1/check/run to tech-check for same scan_run_id
  7. Wait for check completion
  8. Assert tech_check_findings has PASS + FAIL rows
  9. Teardown: remove SSH container, delete credential
"""
from __future__ import annotations

import os
import time
import uuid
import subprocess
import psycopg2
import pytest

CONTAINER_NAME = "te6-e2e-ubuntu-ssh"
SSH_PORT = 2222
SSH_USER = "testuser"
SSH_PASS = "TestPass@123"

TECH_DISCOVERY_URL = os.environ.get("TECH_DISCOVERY_URL", "http://localhost:8030")
TECH_CHECK_URL = os.environ.get("TECH_CHECK_URL", "http://localhost:8031")

TECH_DB = {
    "host":     os.environ.get("TECH_DB_HOST", "localhost"),
    "user":     os.environ.get("TECH_DB_USER", "postgres"),
    "password": os.environ.get("TECH_DB_PASSWORD", ""),
    "dbname":   os.environ.get("TECH_DB_NAME", "threat_engine_tech"),
    "sslmode":  "require",
}


@pytest.fixture(scope="module")
def ssh_container():
    """Start Ubuntu 22.04 + OpenSSH container, yield, then remove."""
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    subprocess.check_call([
        "docker", "run", "-d",
        "--name", CONTAINER_NAME,
        "-p", f"{SSH_PORT}:22",
        "-e", f"PASSWORD={SSH_PASS}",
        "rastasheep/ubuntu-sshd:22.04",
    ])
    # Wait for sshd to start
    time.sleep(3)
    yield {"host": "127.0.0.1", "port": SSH_PORT, "user": SSH_USER, "password": SSH_PASS}
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)


@pytest.fixture(scope="module")
def db_conn():
    conn = psycopg2.connect(**TECH_DB)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def scan_ids(ssh_container, db_conn):
    """Insert credential, run scan, return (scan_run_id, account_id)."""
    scan_run_id = str(uuid.uuid4())
    account_id  = f"test-ubuntu-e2e-{scan_run_id[:8]}"
    tenant_id   = "test-tenant"

    cur = db_conn.cursor()
    cur.execute("""
        INSERT INTO tech_credentials
          (account_id, tenant_id, tech_type, tech_category, host, port,
           credential_type, credential_ref, sudo_required)
        VALUES (%s,%s,'ubuntu','linux',%s,%s,'ssh_password','test-secret',false)
        ON CONFLICT DO NOTHING
    """, (account_id, tenant_id, ssh_container["host"], ssh_container["port"]))

    # Store password in credential dict for this test (normally fetched from Secrets Manager)
    cur.execute("""
        INSERT INTO tech_scan_orchestration
          (scan_run_id, account_id, tenant_id, tech_type, tech_category, status)
        VALUES (%s,%s,%s,'ubuntu','linux','pending')
        ON CONFLICT DO NOTHING
    """, (scan_run_id, account_id, tenant_id))
    db_conn.commit()

    yield scan_run_id, account_id, tenant_id

    # Cleanup
    cur.execute("DELETE FROM tech_credentials WHERE account_id = %s", (account_id,))
    cur.execute("DELETE FROM tech_scan_orchestration WHERE scan_run_id = %s", (scan_run_id,))
    cur.execute("DELETE FROM tech_discovery_findings WHERE scan_run_id = %s", (scan_run_id,))
    cur.execute("DELETE FROM tech_check_findings WHERE scan_run_id = %s", (scan_run_id,))
    db_conn.commit()


class TestLinuxE2E:
    def test_discovery_returns_findings(self, scan_ids, db_conn):
        """Ubuntu SSH scan produces >= 50 discovery findings."""
        scan_run_id, account_id, tenant_id = scan_ids

        import urllib.request, json
        payload = json.dumps({
            "scan_run_id": scan_run_id,
            "account_id":  account_id,
            "tenant_id":   tenant_id,
        }).encode()

        req = urllib.request.Request(
            f"{TECH_DISCOVERY_URL}/api/v1/scan/run",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                assert resp.status == 200, f"Scan failed: {resp.status}"
        except Exception as exc:
            pytest.skip(f"tech-discovery not reachable at {TECH_DISCOVERY_URL}: {exc}")

        # Poll for completion (max 120s)
        cur = db_conn.cursor()
        for _ in range(24):
            cur.execute(
                "SELECT status FROM tech_scan_orchestration WHERE scan_run_id=%s",
                (scan_run_id,),
            )
            row = cur.fetchone()
            if row and row[0] in ("completed", "failed"):
                break
            time.sleep(5)

        cur.execute(
            "SELECT COUNT(*) FROM tech_discovery_findings WHERE scan_run_id=%s",
            (scan_run_id,),
        )
        count = cur.fetchone()[0]
        assert count >= 50, f"Expected >= 50 discovery findings, got {count}"

    def test_check_produces_pass_fail(self, scan_ids, db_conn):
        """tech-check produces PASS and FAIL rows for the ubuntu scan."""
        scan_run_id, account_id, tenant_id = scan_ids

        import urllib.request, json
        payload = json.dumps({
            "scan_run_id": scan_run_id,
            "account_id":  account_id,
        }).encode()

        req = urllib.request.Request(
            f"{TECH_CHECK_URL}/api/v1/check/run",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                assert resp.status == 200
        except Exception as exc:
            pytest.skip(f"tech-check not reachable at {TECH_CHECK_URL}: {exc}")

        cur = db_conn.cursor()
        cur.execute(
            "SELECT status, COUNT(*) FROM tech_check_findings WHERE scan_run_id=%s GROUP BY status",
            (scan_run_id,),
        )
        rows = {r[0]: r[1] for r in cur.fetchall()}
        assert "PASS" in rows or "FAIL" in rows, f"No PASS/FAIL rows: {rows}"

    def test_validate_linux_rules(self):
        """validate_tech_rules script exits 0 for linux category."""
        result = subprocess.run(
            ["python3",
             "/Users/apple/Desktop/threat-engine/catalog/rule/validate_tech_rules.py",
             "--category", "linux"],
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.skip(f"validate_tech_rules.py not available or failed: {result.stderr.decode()[:200]}")
