#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Real Pipeline E2E Agent — ajay-aws-testing

Simulates a full new-customer onboarding and scan flow against the live EKS cluster:
  Phase 1  — Authenticate as admin
  Phase 2  — Create tenant + cloud account (AWS 588989875114, ajay-aws-testing)
  Phase 3  — Store credentials + trigger validation
  Phase 4  — Register code-security account (GitHub: threat-engine repo)
  Phase 5  — Register vulnerability account (EC2 agent-based)
  Phase 6  — Trigger full pipeline scan (CSPM) + SecOps scan + Vuln scan
  Phase 7  — Monitor all scans until completion (max 45 min)
  Phase 8  — Report findings summary

Usage:
  py tests/e2e/real_pipeline_e2e.py
  py tests/e2e/real_pipeline_e2e.py --nlb-url <elb-url>
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import io
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Force UTF-8 so symbols render on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_NLB     = "a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com"
ADMIN_EMAIL     = os.environ.get("CSPM_ADMIN_EMAIL",    "admin@cspm.local")
ADMIN_PASSWORD  = os.environ.get("CSPM_ADMIN_PASSWORD", "Admin@12345")
COOKIE_FILE     = Path("/tmp/cspm-real-e2e-cookies.txt")

AWS_ACCOUNT_ID  = "588989875114"
AWS_ACCOUNT_NAME = "ajay-aws-testing"
AWS_REGION      = "ap-south-1"

GITHUB_REPO_URL = "https://github.com/anupyadav27/threat-engine"
GITHUB_BRANCH   = "dev"

SCAN_POLL_INTERVAL = 30   # seconds between status polls
SCAN_MAX_WAIT      = 2700 # 45 minutes

PASS = "[PASS]"
FAIL = "[FAIL]"
WARN = "[WARN]"
INFO = "[INFO]"


# ── HTTP Session ──────────────────────────────────────────────────────────────

class Session:
    """Thin wrapper around urllib with cookie persistence."""

    def __init__(self, nlb: str) -> None:
        import urllib.request
        self.base   = f"http://{nlb}"
        self.jar    = http.cookiejar.MozillaCookieJar(str(COOKIE_FILE))
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: int = 60,
    ) -> tuple[int, str]:
        import urllib.request, urllib.error
        url  = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        h    = {"Content-Type": "application/json", **(headers or {})}
        req  = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except Exception as exc:
            return 0, str(exc)

    def get(self, path: str, **kw) -> tuple[int, str]:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Optional[dict] = None, **kw) -> tuple[int, str]:
        return self.request("POST", path, body=body, **kw)

    def save_cookies(self) -> None:
        try:
            self.jar.save(ignore_discard=True)
        except Exception:
            pass


# ── Result tracking ───────────────────────────────────────────────────────────

class Results:
    def __init__(self) -> None:
        self.rows:          list[dict] = []
        self.tenant_id:     Optional[str] = None
        self.customer_id:   Optional[str] = None
        self.aws_account_id: Optional[str] = None   # UUID in DB (not AWS account number)
        self.secops_account_id: Optional[str] = None
        self.vuln_account_id:   Optional[str] = None
        self.aws_scan_run_id:    Optional[str] = None
        self.secops_scan_run_id: Optional[str] = None
        self.vuln_scan_run_id:   Optional[str] = None

    def record(self, phase: str, label: str, passed: bool, detail: str = "") -> None:
        self.rows.append({"phase": phase, "label": label, "passed": passed, "detail": detail})
        icon = PASS if passed else FAIL
        print(f"  {icon} [{label}] {detail}")

    def info(self, msg: str) -> None:
        print(f"  {INFO} {msg}")

    def summary(self) -> str:
        total  = len(self.rows)
        passed = sum(1 for r in self.rows if r["passed"])
        return f"{passed}/{total} checks passed"


# ── Helper: fetch AWS credentials from K8s secret ────────────────────────────

def fetch_aws_credentials() -> tuple[str, str]:
    """Read access key / secret from the aws-scan-credentials K8s secret.

    Returns:
        (access_key_id, secret_access_key)

    Raises:
        RuntimeError: if kubectl cannot decode the secret.
    """
    try:
        out = subprocess.check_output(
            ["kubectl", "get", "secret", "aws-scan-credentials",
             "-n", "threat-engine-engines", "-o", "json"],
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)["data"]
        access_key = base64.b64decode(data["AWS_ACCESS_KEY_ID"]).decode().strip()
        secret_key = base64.b64decode(data["AWS_SECRET_ACCESS_KEY"]).decode().strip()
        return access_key, secret_key
    except Exception as exc:
        raise RuntimeError(f"Could not read aws-scan-credentials secret: {exc}") from exc


# ── Phase 1: Authenticate ─────────────────────────────────────────────────────

def phase1_auth(s: Session, r: Results) -> bool:
    """Login as admin and capture customer_id from session."""
    print("\n=== Phase 1: Authentication ===")

    code, body = s.post("/api/auth/login/", {
        "email":    ADMIN_EMAIL,
        "password": ADMIN_PASSWORD,
    })
    ok = code in (200, 201)
    r.record("Phase1", "LOGIN", ok, f"POST /api/auth/login/ -> {code}")
    if not ok:
        return False

    s.save_cookies()

    # Resolve customer_id from whoami or tenant list
    code2, body2 = s.get("/gateway/api/v1/tenants")
    if code2 == 200:
        try:
            tenants = json.loads(body2)
            if isinstance(tenants, list) and tenants:
                r.customer_id = tenants[0].get("customer_id")
                r.info(f"Resolved customer_id={r.customer_id} from first tenant")
        except Exception:
            pass

    # Fallback: derive from Django user endpoint
    if not r.customer_id:
        code3, body3 = s.get("/api/auth/me/")
        if code3 == 200:
            try:
                me = json.loads(body3)
                r.customer_id = str(me.get("customer_id") or me.get("id") or "")
                r.info(f"Resolved customer_id={r.customer_id} from /api/auth/me/")
            except Exception:
                pass

    if not r.customer_id:
        r.customer_id = "default-customer"
        r.info(f"customer_id not resolved — using fallback: {r.customer_id}")

    return True


# ── Phase 2: Create tenant + AWS cloud account ────────────────────────────────

def phase2_onboard_aws(s: Session, r: Results) -> bool:
    """Create a dedicated tenant then register the AWS account."""
    print(f"\n=== Phase 2: Onboard AWS Account ({AWS_ACCOUNT_ID} → {AWS_ACCOUNT_NAME}) ===")

    # 2a — Scan all cloud-accounts first to find if ajay-aws-testing already exists
    code_a, body_a = s.get("/gateway/api/v1/cloud-accounts")
    existing_aws_account_id: Optional[str] = None
    if code_a == 200:
        try:
            accounts = json.loads(body_a)
            if isinstance(accounts, dict):
                accounts = accounts.get("accounts", accounts.get("items", []))
            for acct in accounts:
                if acct.get("account_name") == AWS_ACCOUNT_NAME:
                    existing_aws_account_id = acct.get("account_id") or acct.get("id")
                    r.tenant_id             = acct.get("tenant_id")
                    r.info(f"Found existing account '{AWS_ACCOUNT_NAME}' "
                           f"in tenant={r.tenant_id}, account_id={existing_aws_account_id}")
                    break
        except Exception:
            pass

    if existing_aws_account_id:
        r.aws_account_id = existing_aws_account_id
        r.record("Phase2", "CREATE_TENANT",      True, f"Reusing tenant_id={r.tenant_id}")
        r.record("Phase2", "CREATE_AWS_ACCOUNT", True,
                 f"Reusing existing aws_account_id={r.aws_account_id}")
        return True

    # 2b — Account not found: create a dedicated tenant then the account
    tenant_name = f"ajay-test-{int(time.time())}"
    code, body = s.post("/gateway/api/v1/tenants", {
        "tenant_name": tenant_name,
        "tenant_type": "cloud",
        "customer_id": r.customer_id or "",
    })
    try:
        data      = json.loads(body)
        tenant_id = data.get("tenant_id") or data.get("id")
        ok_tenant = code == 201 and bool(tenant_id)
    except Exception:
        tenant_id, ok_tenant = None, False
    r.record("Phase2", "CREATE_TENANT", ok_tenant,
             f"POST /tenants -> {code}, tenant_id={tenant_id}")
    if not ok_tenant:
        return False
    r.tenant_id = tenant_id

    code, body = s.post("/gateway/api/v1/cloud-accounts", {
        "customer_id":    r.customer_id or "",
        "tenant_id":      r.tenant_id,
        "account_name":   AWS_ACCOUNT_NAME,
        "provider":       "aws",
        "account_type":   "cloud_csp",
        "account_number": AWS_ACCOUNT_ID,
        "auth_config": {
            "regions":    [AWS_REGION, "us-east-1"],
            "account_id": AWS_ACCOUNT_ID,
        },
    })
    try:
        data       = json.loads(body)
        db_acct_id = data.get("account_id") or data.get("id")
        ok_acct    = code == 201 and bool(db_acct_id)
    except Exception:
        db_acct_id, ok_acct = None, False

    r.record("Phase2", "CREATE_AWS_ACCOUNT", ok_acct,
             f"POST /cloud-accounts -> {code}, account_id={db_acct_id}")
    if not ok_acct:
        r.info(f"Response body: {body[:300]}")
        return False
    r.aws_account_id = db_acct_id
    return True


# ── Phase 3: Store credentials + validate ────────────────────────────────────

def phase3_credentials(s: Session, r: Results) -> bool:
    """Store AWS access key and wait for validation to pass."""
    print("\n=== Phase 3: Credential Storage + Validation ===")

    if not r.aws_account_id:
        r.record("Phase3", "CREDS_STORE", False, "Skipped — no aws_account_id")
        return False

    # Fetch real credentials from K8s secret
    try:
        access_key_id, secret_access_key = fetch_aws_credentials()
        r.info(f"Fetched credentials from K8s secret (key={access_key_id[:8]}...)")
    except RuntimeError as exc:
        r.record("Phase3", "CREDS_FETCH", False, str(exc))
        return False

    # 3a — Store credentials
    code, body = s.post(
        f"/gateway/api/v1/cloud-accounts/{r.aws_account_id}/credentials",
        {
            "credential_type": "access_key",
            "credentials": {
                "access_key_id":     access_key_id,
                "secret_access_key": secret_access_key,
                "region":            AWS_REGION,
            },
        },
    )
    ok_store = code in (200, 201, 204)
    r.record("Phase3", "CREDS_STORE", ok_store,
             f"POST /credentials -> {code}")

    # 3b — Trigger validation
    code, body = s.post(
        f"/gateway/api/v1/cloud-accounts/{r.aws_account_id}/validate"
    )
    ok_trigger = code in (200, 202)
    r.record("Phase3", "VALIDATE_TRIGGER", ok_trigger,
             f"POST /validate -> {code}")

    if not ok_trigger:
        r.info(f"Validation response: {body[:300]}")

    # 3c — Poll until valid (max 3 min)
    print("  Polling for credential validation (max 3 min)...")
    for attempt in range(18):
        time.sleep(10)
        code, body = s.get(f"/gateway/api/v1/cloud-accounts/{r.aws_account_id}")
        if code == 200:
            try:
                acct   = json.loads(body)
                status = acct.get("credential_validation_status", "")
                r.info(f"  attempt {attempt+1}: validation_status={status}")
                if status in ("valid", "pass"):
                    r.record("Phase3", "VALIDATION_PASS", True,
                             f"Credential validation passed after {(attempt+1)*10}s")
                    return True
                if status == "invalid":
                    r.record("Phase3", "VALIDATION_PASS", False,
                             f"Credential validation returned invalid")
                    return False
            except Exception:
                pass

    r.record("Phase3", "VALIDATION_PASS", False, "Timed out after 3 min")
    return False


# ── Phase 4: Register code-security (SecOps) account ─────────────────────────

def phase4_secops(s: Session, r: Results) -> bool:
    """Register the GitHub repo for SAST/IaC scanning."""
    print(f"\n=== Phase 4: SecOps Code Security ({GITHUB_REPO_URL}) ===")

    if not r.tenant_id:
        r.record("Phase4", "SECOPS_ACCOUNT", False, "Skipped — no tenant_id")
        return False

    code, body = s.post("/gateway/api/v1/cloud-accounts", {
        "customer_id":  r.customer_id or "",
        "tenant_id":    r.tenant_id,
        "account_name": "threat-engine-repo",
        "provider":     "github",
        "account_type": "code_security",
        "auth_config": {
            "repo_url":       GITHUB_REPO_URL,
            "default_branch": GITHUB_BRANCH,
            "project_name":   "threat-engine",
            "vcs_platform":   "github",
            "scan_types":     ["sast", "iac"],
        },
    })
    try:
        data    = json.loads(body)
        acct_id = data.get("account_id") or data.get("id")
        ok      = code == 201 and bool(acct_id)
    except Exception:
        acct_id, ok = None, False

    r.record("Phase4", "SECOPS_ACCOUNT", ok,
             f"POST /cloud-accounts (github) -> {code}, id={acct_id}")

    if code == 409:
        r.info("SecOps account already exists — looking up to reuse...")
        code2, body2 = s.get(f"/gateway/api/v1/cloud-accounts?tenant_id={r.tenant_id}")
        if code2 == 200:
            try:
                accounts = json.loads(body2)
                if isinstance(accounts, dict):
                    accounts = accounts.get("accounts", accounts.get("items", []))
                for acct in accounts:
                    if acct.get("account_name") == "threat-engine-repo":
                        acct_id = acct.get("account_id") or acct.get("id")
                        r.info(f"Reusing secops account_id={acct_id}")
                        ok = True
                        break
            except Exception:
                pass

    if not ok:
        r.info(f"Response: {body[:300]}")
    else:
        r.secops_account_id = acct_id
    return ok


# ── Phase 5: Register vulnerability account (EC2 agent) ──────────────────────

def phase5_vuln(s: Session, r: Results) -> bool:
    """Register a vulnerability agent account for EC2 scanning."""
    print("\n=== Phase 5: Vulnerability Agent (EC2) ===")

    if not r.tenant_id:
        r.record("Phase5", "VULN_ACCOUNT", False, "Skipped — no tenant_id")
        return False

    code, body = s.post("/gateway/api/v1/cloud-accounts", {
        "customer_id":  r.customer_id or "",
        "tenant_id":    r.tenant_id,
        "account_name": f"ajay-ec2-vuln-{AWS_ACCOUNT_ID}",
        "provider":     "agent",
        "account_type": "vulnerability",
        "auth_config": {
            "cloud_account_id": AWS_ACCOUNT_ID,
            "platform":         "linux",
        },
    })
    try:
        data    = json.loads(body)
        acct_id = data.get("account_id") or data.get("id")
        token   = data.get("bootstrap_token") or data.get("agent_token")
        ok      = code == 201 and bool(acct_id)
    except Exception:
        acct_id, token, ok = None, None, False

    r.record("Phase5", "VULN_ACCOUNT", ok,
             f"POST /cloud-accounts (agent) -> {code}, id={acct_id}")

    if ok:
        r.vuln_account_id = acct_id
        print(f"\n  {'='*60}")
        print(f"  VULNERABILITY AGENT INSTALL INSTRUCTIONS")
        print(f"  {'='*60}")
        print(f"  1. SSH into each EC2 instance in account {AWS_ACCOUNT_ID}")
        print(f"  2. Run the install command:")
        print(f"     curl -sSL http://{DEFAULT_NLB}/vulnerability/agent/install.sh \\")
        print(f"       | AGENT_TOKEN={token or '<token-from-api>'} bash")
        print(f"  3. The agent will register automatically and begin scanning")
        print(f"  Bootstrap token (valid 15 min): {token or 'N/A'}")
        print(f"  {'='*60}\n")
    else:
        r.info(f"Response: {body[:300]}")

    return ok


# ── Phase 6: Trigger all scans ────────────────────────────────────────────────

def phase6_trigger(s: Session, r: Results) -> None:
    """Trigger full pipeline scan + SecOps scan (+ vuln if account registered)."""
    print("\n=== Phase 6: Trigger Scans ===")

    # 6a — Full CSPM pipeline scan for AWS account
    if r.aws_account_id:
        code, body = s.post("/gateway/api/v1/scans/run-now", {
            "account_id": r.aws_account_id,
        })
        try:
            data = json.loads(body)
            r.aws_scan_run_id = data.get("scan_run_id")
            ok = code == 202 and bool(r.aws_scan_run_id)
        except Exception:
            ok = False
        r.record("Phase6", "TRIGGER_CSPM", ok,
                 f"POST /scans/run-now (AWS) -> {code}, scan_run_id={r.aws_scan_run_id}")
    else:
        r.record("Phase6", "TRIGGER_CSPM", False, "Skipped — no aws_account_id")

    # 6b — SecOps scan for GitHub repo
    if r.secops_account_id:
        code, body = s.post("/gateway/api/v1/scans/run-now", {
            "account_id": r.secops_account_id,
        })
        try:
            data = json.loads(body)
            r.secops_scan_run_id = data.get("scan_run_id")
            ok = code == 202 and bool(r.secops_scan_run_id)
        except Exception:
            ok = False
        r.record("Phase6", "TRIGGER_SECOPS", ok,
                 f"POST /scans/run-now (SecOps) -> {code}, scan_run_id={r.secops_scan_run_id}")

    # 6c — Vulnerability scan (agent-based; triggered automatically when agent connects)
    if r.vuln_account_id:
        r.info("Vuln scan auto-triggers when EC2 agent connects — no manual trigger needed")
        r.record("Phase6", "TRIGGER_VULN", True,
                 "Vuln scan will start when agent registers on EC2")


# ── Phase 7: Monitor scans ────────────────────────────────────────────────────

def phase7_monitor(s: Session, r: Results) -> None:
    """Poll scan_run status until all complete or timeout."""
    print(f"\n=== Phase 7: Monitor Pipeline (max {SCAN_MAX_WAIT//60} min) ===")

    scans = {
        "CSPM":   r.aws_scan_run_id,
        "SecOps": r.secops_scan_run_id,
    }
    scans = {k: v for k, v in scans.items() if v}

    if not scans:
        r.record("Phase7", "MONITOR", False, "No active scan_run_ids to monitor")
        return

    completed: set[str] = set()
    start = time.time()

    while time.time() - start < SCAN_MAX_WAIT:
        for label, scan_run_id in scans.items():
            if label in completed:
                continue

            code, body = s.get(
                f"/gateway/api/v1/scans/recent?limit=20"
            )
            if code != 200:
                continue

            try:
                data = json.loads(body)
                runs = data if isinstance(data, list) else data.get("scans", [])
                for run in runs:
                    if run.get("scan_run_id") == scan_run_id:
                        status           = run.get("status", run.get("overall_status", "?"))
                        engines_done     = run.get("engines_completed", [])
                        elapsed          = int(time.time() - start)
                        print(f"  {INFO} [{label}] status={status} engines_done={len(engines_done)} t={elapsed}s")

                        if status in ("completed", "failed", "error"):
                            ok = status == "completed"
                            r.record("Phase7", f"SCAN_{label}", ok,
                                     f"scan_run_id={scan_run_id} final={status} "
                                     f"engines={engines_done}")
                            completed.add(label)
                        break
            except Exception:
                pass

        if len(completed) == len(scans):
            break

        time.sleep(SCAN_POLL_INTERVAL)

    # Any still pending = timeout
    for label in scans:
        if label not in completed:
            r.record("Phase7", f"SCAN_{label}", False,
                     f"Timed out after {SCAN_MAX_WAIT//60} min")


# ── Phase 8: Findings summary ─────────────────────────────────────────────────

def phase8_summary(s: Session, r: Results) -> None:
    """Pull counts from BFF views and print findings breakdown."""
    print("\n=== Phase 8: Findings Summary ===")

    views = [
        ("Check findings",    "/gateway/api/v1/views/misconfig"),
        ("IAM findings",      "/gateway/api/v1/views/iam"),
        ("Network findings",  "/gateway/api/v1/views/network-security"),
        ("Compliance score",  "/gateway/api/v1/views/compliance"),
        ("Risk score",        "/gateway/api/v1/views/risk"),
        ("SecOps findings",   "/gateway/api/v1/views/secops"),
        ("Vulnerability",     "/gateway/api/v1/views/vulnerability"),
    ]

    for label, path in views:
        code, body = s.get(path)
        if code == 200:
            try:
                data = json.loads(body)
                # Extract top-level counts wherever they live in the BFF response
                total = (
                    data.get("total_findings")
                    or data.get("total_count")
                    or data.get("count")
                    or data.get("total_resources")
                    or "—"
                )
                score = data.get("score") or data.get("compliance_score") or data.get("risk_score") or ""
                suffix = f", score={score}" if score else ""
                print(f"  {INFO} {label}: total={total}{suffix}")
            except Exception:
                print(f"  {WARN} {label}: parse error")
        else:
            print(f"  {WARN} {label}: HTTP {code}")

    # Scan run details from DB via onboarding API
    if r.aws_scan_run_id:
        code, body = s.get(f"/gateway/api/v1/scans/recent?limit=50")
        if code == 200:
            try:
                runs = json.loads(body)
                if isinstance(runs, dict):
                    runs = runs.get("scans", [])
                for run in runs:
                    if run.get("scan_run_id") == r.aws_scan_run_id:
                        print(f"\n  CSPM Pipeline Run: {r.aws_scan_run_id}")
                        print(f"    overall_status  : {run.get('overall_status') or run.get('status')}")
                        print(f"    engines_completed: {run.get('engines_completed', [])}")
                        print(f"    started_at       : {run.get('started_at')}")
                        print(f"    completed_at     : {run.get('completed_at')}")
                        break
            except Exception:
                pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Real Pipeline E2E Agent")
    parser.add_argument("--nlb-url", default=DEFAULT_NLB, help="ELB / NLB hostname")
    parser.add_argument("--skip-validate", action="store_true",
                        help="Skip polling credential validation (if already valid)")
    args = parser.parse_args()

    s = Session(args.nlb_url)
    r = Results()

    print("=" * 65)
    print(" CSPM Real Pipeline E2E — ajay-aws-testing")
    print(f" Target  : {args.nlb_url}")
    print(f" AWS Acct: {AWS_ACCOUNT_ID}  ({AWS_ACCOUNT_NAME})")
    print(f" Git Repo: {GITHUB_REPO_URL}  (branch: {GITHUB_BRANCH})")
    print(f" Started : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 65)

    # Run all phases
    if not phase1_auth(s, r):
        print(f"\n{FAIL} Auth failed — aborting.")
        return 1

    if not phase2_onboard_aws(s, r):
        print(f"\n{FAIL} Cloud account registration failed — aborting.")
        return 1

    if not args.skip_validate:
        phase3_credentials(s, r)
    else:
        r.info("--skip-validate set — assuming credentials already valid")

    phase4_secops(s, r)
    phase5_vuln(s, r)
    phase6_trigger(s, r)
    phase7_monitor(s, r)
    phase8_summary(s, r)

    # ── Final report ──────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print(f" RESULTS: {r.summary()}")
    print("=" * 65)

    failures = [row for row in r.rows if not row["passed"]]
    if failures:
        print(f"\nFailed checks ({len(failures)}):")
        for f in failures:
            print(f"  {FAIL} [{f['label']}] {f['detail']}")

    print(f"\n Scan run IDs:")
    print(f"   CSPM     : {r.aws_scan_run_id or 'N/A'}")
    print(f"   SecOps   : {r.secops_scan_run_id or 'N/A'}")
    print(f"   Vuln     : see agent bootstrap token above")
    print(f"\n Onboarded IDs:")
    print(f"   tenant_id       : {r.tenant_id}")
    print(f"   aws_account_id  : {r.aws_account_id}")
    print(f"   secops_acct_id  : {r.secops_account_id}")
    print(f"   vuln_acct_id    : {r.vuln_account_id}")

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
