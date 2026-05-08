#!/usr/bin/env python3
"""
DeepSeek MITRE ATT&CK enrichment agent for rule_metadata.

Classifies ~10,001 config/posture rules that have mitre_tactics = '[]'
into MITRE tactics, techniques, and threat_category using DeepSeek API.

Run from engine-check pod:
    kubectl cp /path/mitre_enrichment_agent.py threat-engine-engines/<pod>:/tmp/mitre_enrichment.py
    kubectl exec -n threat-engine-engines <pod> -- python3 /tmp/mitre_enrichment.py
    kubectl exec -n threat-engine-engines <pod> -- python3 /tmp/mitre_enrichment.py --dry-run
    kubectl exec -n threat-engine-engines <pod> -- python3 /tmp/mitre_enrichment.py --verify
"""

import os
import json
import time
import sys
import argparse
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import Json

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "sk-3d7acb8511ad4da18e8b0c89733f472b")
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
BATCH_SIZE = 25
MAX_RETRIES = 3
RETRY_DELAY_SEC = 8

CANONICAL_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
    "Command and Control",
]

VALID_THREAT_CATEGORIES = {
    "identity_and_access",
    "data_exposure",
    "network_exposure",
    "configuration_drift",
    "logging_and_monitoring",
    "encryption",
    "privilege_escalation",
    "lateral_movement",
    "credential_theft",
    "resource_abuse",
}

SYSTEM_PROMPT = f"""You are a cloud security expert specializing in MITRE ATT&CK for Cloud (IaaS).
Given a list of cloud security misconfiguration/posture check rules, classify each one with:
1. mitre_tactics: 1-3 applicable MITRE ATT&CK tactic names (use ONLY the exact names from the list below)
2. mitre_techniques: 1-3 applicable MITRE ATT&CK technique IDs (e.g. T1078, T1552.001)
3. threat_category: exactly one category from the allowed list below

CANONICAL TACTICS (use ONLY these exact names):
{chr(10).join(f"- {t}" for t in CANONICAL_TACTICS)}

ALLOWED THREAT CATEGORIES:
identity_and_access | data_exposure | network_exposure | configuration_drift |
logging_and_monitoring | encryption | privilege_escalation | lateral_movement |
credential_theft | resource_abuse

CLASSIFICATION HINTS:
- MFA disabled / weak auth → Credential Access + Initial Access → credential_theft
- Excessive permissions / admin roles / privilege rules → Privilege Escalation + Initial Access → privilege_escalation
- Public S3 / public storage / open data → Collection + Exfiltration → data_exposure
- Logging disabled / audit trail missing → Defense Evasion → logging_and_monitoring
- Encryption at rest/transit disabled → Collection + Exfiltration → encryption
- Open ports / 0.0.0.0/0 security group rules → Initial Access + Lateral Movement → network_exposure
- Root account / high-privilege keys → Privilege Escalation + Credential Access → identity_and_access
- IAM policy / role / service account → Privilege Escalation + Defense Evasion → identity_and_access
- Resource not tagged / cost / naming → Defense Evasion → configuration_drift

Return ONLY a valid JSON array — no markdown, no explanation — one object per rule:
[
  {{
    "rule_id": "<rule_id>",
    "mitre_tactics": ["Tactic1"],
    "mitre_techniques": ["T1234"],
    "threat_category": "category_name"
  }}
]"""


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
def _check_conn():
    return psycopg2.connect(
        host=os.environ.get("CHECK_DB_HOST", os.environ.get("DB_HOST", "")),
        dbname=os.environ.get("CHECK_DB_NAME", "check"),
        user=os.environ.get("CHECK_DB_USER", "postgres"),
        password=os.environ.get("CHECK_DB_PASSWORD", ""),
        sslmode="require",
    )


def fetch_empty_rules(conn) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    cur.execute("""
        SELECT rule_id, title, description, domain, subcategory, severity, service, provider
        FROM rule_metadata
        WHERE mitre_tactics = '[]'::jsonb
        ORDER BY provider, service, rule_id
    """)
    rows = cur.fetchall()
    cur.close()
    return [
        {
            "rule_id": r[0],
            "title": r[1] or "",
            "description": (r[2] or "")[:300],
            "domain": r[3] or "",
            "subcategory": r[4] or "",
            "severity": r[5] or "",
            "service": r[6] or "",
            "provider": r[7] or "",
        }
        for r in rows
    ]


def apply_updates(conn, updates: List[Dict[str, Any]], dry_run: bool = False) -> int:
    if not updates:
        return 0
    if dry_run:
        for u in updates:
            print(f"  [DRY] {u['rule_id']} → tactics={u['mitre_tactics']} cat={u['threat_category']}")
        return len(updates)

    cur = conn.cursor()
    updated = 0
    for u in updates:
        cur.execute("""
            UPDATE rule_metadata
            SET mitre_tactics = %s::jsonb,
                mitre_techniques = %s::jsonb,
                threat_category = %s,
                updated_at = NOW()
            WHERE rule_id = %s
              AND mitre_tactics = '[]'::jsonb
        """, (
            json.dumps(u["mitre_tactics"]),
            json.dumps(u["mitre_techniques"]),
            u["threat_category"],
            u["rule_id"],
        ))
        updated += cur.rowcount
    conn.commit()
    cur.close()
    return updated


# ---------------------------------------------------------------------------
# DeepSeek API
# ---------------------------------------------------------------------------
def call_deepseek(rules_batch: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
    user_content = "Classify the following cloud security rules:\n\n" + json.dumps(
        [{"rule_id": r["rule_id"], "title": r["title"], "description": r["description"],
          "domain": r["domain"], "service": r["service"], "provider": r["provider"],
          "severity": r["severity"], "subcategory": r["subcategory"]}
         for r in rules_batch],
        indent=2,
    )

    payload = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.1,
        "max_tokens": 4096,
        "response_format": {"type": "json_object"},
    }).encode("utf-8")

    req = urllib.request.Request(
        DEEPSEEK_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        },
        method="POST",
    )

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
                content = raw["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                # DeepSeek may return {"results": [...]} or directly [...]
                if isinstance(parsed, dict):
                    for key in ("results", "classifications", "rules", "data"):
                        if key in parsed and isinstance(parsed[key], list):
                            parsed = parsed[key]
                            break
                    else:
                        # single object — wrap
                        parsed = [parsed]
                return parsed
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            print(f"    [WARN] HTTP {e.code} on attempt {attempt}: {body[:200]}")
            if e.code in (429, 502, 503) and attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY_SEC * attempt)
            else:
                return None
        except Exception as e:
            print(f"    [WARN] attempt {attempt} error: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY_SEC)
            else:
                return None
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_result(item: Any, valid_rule_ids: set) -> Optional[Dict[str, Any]]:
    if not isinstance(item, dict):
        return None
    rule_id = item.get("rule_id", "")
    if not rule_id or rule_id not in valid_rule_ids:
        return None

    raw_tactics = item.get("mitre_tactics", [])
    tactics = [t for t in (raw_tactics if isinstance(raw_tactics, list) else []) if t in CANONICAL_TACTICS]
    if not tactics:
        tactics = ["Defense Evasion"]  # safe fallback

    raw_tech = item.get("mitre_techniques", [])
    techniques = [t for t in (raw_tech if isinstance(raw_tech, list) else []) if isinstance(t, str) and t.startswith("T")]

    threat_cat = item.get("threat_category", "")
    if threat_cat not in VALID_THREAT_CATEGORIES:
        threat_cat = "configuration_drift"

    return {
        "rule_id": rule_id,
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "threat_category": threat_cat,
    }


# ---------------------------------------------------------------------------
# Main enrichment loop
# ---------------------------------------------------------------------------
def run_enrichment(dry_run: bool = False) -> None:
    conn = _check_conn()
    print("Connected to check DB.")

    rules = fetch_empty_rules(conn)
    total = len(rules)
    print(f"Rules with empty mitre_tactics: {total}")
    if not total:
        print("Nothing to enrich.")
        conn.close()
        return

    batches = [rules[i:i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]
    print(f"Processing {len(batches)} batches of up to {BATCH_SIZE} rules each.")
    if dry_run:
        print("[DRY RUN — no DB writes]")

    total_updated = 0
    failed_batches = 0

    for batch_num, batch in enumerate(batches, 1):
        valid_ids = {r["rule_id"] for r in batch}
        print(f"\n[{batch_num}/{len(batches)}] Calling DeepSeek for {len(batch)} rules ...", end=" ", flush=True)

        raw_results = call_deepseek(batch)
        if not raw_results:
            print(f"FAILED (skipping batch)")
            failed_batches += 1
            continue

        validated = []
        for item in raw_results:
            v = validate_result(item, valid_ids)
            if v:
                validated.append(v)

        # For any rule_ids not returned by DeepSeek, apply safe defaults
        returned_ids = {v["rule_id"] for v in validated}
        missing_ids = valid_ids - returned_ids
        for rid in missing_ids:
            validated.append({
                "rule_id": rid,
                "mitre_tactics": ["Defense Evasion"],
                "mitre_techniques": ["T1562"],
                "threat_category": "configuration_drift",
            })

        n = apply_updates(conn, validated, dry_run=dry_run)
        total_updated += n
        print(f"updated {n} rules (validated {len(validated)}, missing from response {len(missing_ids)})")

        # Rate limiting — be gentle with DeepSeek free tier
        if batch_num % 10 == 0:
            print(f"  [progress] {total_updated}/{total} rules enriched so far, {failed_batches} failed batches")
        time.sleep(0.5)

    conn.close()
    print(f"\n{'='*60}")
    print(f"Enrichment complete.")
    print(f"  Total rules processed: {total}")
    print(f"  Total rows updated: {total_updated}")
    print(f"  Failed batches: {failed_batches}")
    if dry_run:
        print("  [DRY RUN — no changes committed]")


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
def verify() -> None:
    conn = _check_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM rule_metadata")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM rule_metadata WHERE mitre_tactics != '[]'::jsonb AND mitre_tactics IS NOT NULL")
    with_mitre = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM rule_metadata WHERE mitre_tactics = '[]'::jsonb")
    empty = cur.fetchone()[0]
    cur.execute("""
        SELECT threat_category, COUNT(*) as n
        FROM rule_metadata
        WHERE threat_category IS NOT NULL AND threat_category != ''
        GROUP BY threat_category ORDER BY n DESC
    """)
    cats = cur.fetchall()
    cur.execute("""
        SELECT DISTINCT jsonb_array_elements_text(mitre_tactics) as tactic, COUNT(*) as n
        FROM rule_metadata WHERE mitre_tactics != '[]'::jsonb
        GROUP BY tactic ORDER BY n DESC LIMIT 10
    """)
    tactics = cur.fetchall()
    cur.close()
    conn.close()

    print(f"\nrule_metadata MITRE coverage:")
    print(f"  Total rules:      {total}")
    print(f"  With MITRE data:  {with_mitre} ({100*with_mitre//total if total else 0}%)")
    print(f"  Still empty:      {empty}")
    print(f"\nThreat category distribution:")
    for cat, n in cats:
        print(f"  {cat:<30} {n}")
    print(f"\nTop MITRE tactics:")
    for tactic, n in tactics:
        print(f"  {tactic:<30} {n}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepSeek MITRE enrichment agent for rule_metadata")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change, no DB writes")
    parser.add_argument("--verify", action="store_true", help="Show current MITRE coverage stats only")
    args = parser.parse_args()

    if args.verify:
        verify()
    else:
        run_enrichment(dry_run=args.dry_run)
        print("\n--- Post-run verification ---")
        verify()
