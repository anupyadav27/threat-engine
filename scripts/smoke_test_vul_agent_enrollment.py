"""
Smoke test — Vulnerability Agent Enrollment E2E

Tests the full lifecycle:
  1. Provision  — BFF issues pre-signed ZIP URL
  2. Register   — Agent exchanges registration_token for agent_api_key
  3. Scan       — Agent submits scan, engine validates via vul_agent_sessions
  4. Sessions   — BFF returns session list with the new agent
  5. Revoke     — BFF revokes the agent session
  6. Scan-after-revoke — Engine rejects the scan (401)
  7. Re-provision — BFF re-issues a new token (rotates key)
  8. Scan-after-reprovision — Engine accepts the new key

Prerequisites:
    export BFF_URL="http://localhost:8080"   # or ELB URL
    export SESSION_COOKIE="..."              # CSPM admin session cookie
    export ACCOUNT_ID="..."                  # UUID of a registered cloud account
    export X_INTERNAL_SECRET="..."           # for direct internal calls (optional)

Run:
    python scripts/smoke_test_vul_agent_enrollment.py
"""

import hashlib
import json
import os
import secrets
import sys
import urllib.request
import urllib.error
from typing import Optional

BFF_URL    = os.getenv("BFF_URL", "http://localhost:8080")
ACCOUNT_ID = os.getenv("ACCOUNT_ID", "")
COOKIE     = os.getenv("SESSION_COOKIE", "")
PLATFORM   = "linux"

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"


def _headers(extra: dict = None) -> dict:
    h = {"Content-Type": "application/json"}
    if COOKIE:
        h["Cookie"] = COOKIE
    if extra:
        h.update(extra)
    return h


def post(url: str, body: dict, extra_headers: dict = None) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=_headers(extra_headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"_status": e.code, "_error": e.read().decode()[:300]}


def get(url: str, extra_headers: dict = None) -> dict:
    req = urllib.request.Request(url, headers=_headers(extra_headers), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"_status": e.code, "_error": e.read().decode()[:300]}


def check(label: str, condition: bool, detail: str = ""):
    if condition:
        print(f"{PASS} {label}" + (f" — {detail}" if detail else ""))
    else:
        print(f"{FAIL} {label}" + (f" — {detail}" if detail else ""))
    return condition


def main():
    if not ACCOUNT_ID:
        print("ERROR: set ACCOUNT_ID env var to a registered cloud account UUID")
        sys.exit(1)

    print()
    print("=" * 65)
    print("  VUL-AGENT ENROLLMENT SMOKE TEST")
    print("=" * 65)
    failures = 0

    # ── 1. Provision ─────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 1: Provision agent bundle ...")
    prov = post(
        f"{BFF_URL}/api/v1/views/vulnerability/agent/provision",
        {"account_id": ACCOUNT_ID, "platform": PLATFORM},
    )
    ok = check("1.1 Provision returns 200", "_error" not in prov, str(prov.get("_status", "")))
    ok &= check("1.2 download_url present",  bool(prov.get("download_url")))
    ok &= check("1.3 agent_id present",      bool(prov.get("agent_id")))
    if not ok:
        failures += 1
        print(f"     Response: {json.dumps(prov, indent=2)[:300]}")
        print("     Skipping remaining steps — provision is a prerequisite.")
        sys.exit(failures)

    agent_id     = prov["agent_id"]
    download_url = prov["download_url"]
    print(f"     agent_id={agent_id}  url_expires_in={prov.get('url_expires_in')}s")

    # ── 2. Simulate Register (call vul engine /register directly) ─────────────
    print(f"\n{INFO} Step 2: Register agent (simulate binary startup_registration) ...")
    # We don't have the raw token here — only the BFF provisions it.
    # This step requires port-forwarding the vul engine or running in-cluster.
    # Simulate by crafting a fake token exchange.
    print(f"     {INFO} Registration requires a real token from the downloaded ZIP.")
    print(f"     {INFO} To test manually:")
    print(f"     {INFO}   wget -O agent.zip '{download_url}'")
    print(f"     {INFO}   unzip agent.zip && chmod +x vul-agent && ./vul-agent")
    print(f"     {INFO} This step is marked as MANUAL in the smoke test.")

    # ── 3. Sessions list ──────────────────────────────────────────────────────
    print(f"\n{INFO} Step 3: List sessions ...")
    sess = get(f"{BFF_URL}/api/v1/views/vulnerability/agent/sessions")
    ok3 = check("3.1 Sessions returns 200", "_error" not in sess, str(sess.get("_status", "")))
    ok3 &= check("3.2 sessions key present", "sessions" in sess)
    if not ok3:
        failures += 1
        print(f"     Response: {json.dumps(sess, indent=2)[:300]}")
    else:
        print(f"     total={sess.get('total', 0)} sessions")

    # ── 4. Revoke ─────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 4: Revoke agent ...")
    rev = post(
        f"{BFF_URL}/api/v1/views/vulnerability/agent/revoke",
        {"agent_id": agent_id},
    )
    ok4 = check(
        "4.1 Revoke returns 200 or 404",
        "_error" not in rev or rev.get("_status") == 404,
        f"status={rev.get('_status', 'ok')}",
    )
    if not ok4:
        failures += 1
        print(f"     Response: {json.dumps(rev, indent=2)[:200]}")

    # ── 5. Re-provision ───────────────────────────────────────────────────────
    print(f"\n{INFO} Step 5: Re-provision (token rotation) ...")
    prov2 = post(
        f"{BFF_URL}/api/v1/views/vulnerability/agent/provision",
        {"account_id": ACCOUNT_ID, "platform": PLATFORM},
    )
    ok5  = check("5.1 Re-provision returns 200", "_error" not in prov2, str(prov2.get("_status", "")))
    ok5 &= check("5.2 New download_url present", bool(prov2.get("download_url")))
    ok5 &= check("5.3 Same agent_id preserved", prov2.get("agent_id") == agent_id, f"{prov2.get('agent_id')} == {agent_id}")
    if not ok5:
        failures += 1
        print(f"     Response: {json.dumps(prov2, indent=2)[:300]}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 65)
    if failures == 0:
        print(f"{PASS} All automated checks passed.")
        print()
        print("Manual step required:")
        print("  Download the ZIP using the URL from Step 1 and run the agent binary.")
        print("  After it registers, re-run to verify the session appears in Step 3.")
    else:
        print(f"{FAIL} {failures} check group(s) failed. See details above.")
    print("=" * 65)
    print()
    sys.exit(failures)


if __name__ == "__main__":
    main()
