#!/usr/bin/env python3
"""
Unified MITRE ATT&CK Seeder — seeds all MITRE data in correct order.

This is the single entry point to populate the mitre_technique_reference table.
It orchestrates the modular seed scripts in dependency order:

    Step 1: seed_mitre_reference.py      — 102 base techniques (IDs, names, tactics, weights)
    Step 2: seed_mitre_guidance.py       — AWS detection/remediation guidance (30 techniques)
    Step 3: seed_mitre_gap_guidance.py   — Fill remaining 18 gaps (AWS + Azure + GCP)
    Step 4: seed_mitre_multicloud_guidance.py — Azure + GCP guidance (20 techniques)
    Step 5: seed_mitre_remaining_csp_guidance.py — OCI + IBM + Alicloud + K8s (10 each)

Each step is idempotent — re-running skips already-seeded data.

Usage:
    # Full pipeline (dry-run):
    python scripts/seed_mitre_all.py --dry-run

    # Full pipeline (real):
    python scripts/seed_mitre_all.py

    # Single step only:
    python scripts/seed_mitre_all.py --step 3

    # Verify coverage after seeding:
    python scripts/seed_mitre_all.py --verify-only

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │              mitre_technique_reference                    │
    │  ┌─────────────┐  ┌───────────────────────────────────┐ │
    │  │ technique_id │  │ detection_guidance (JSONB)         │ │
    │  │ technique_name│  │  ├── cloudtrail_events (AWS top)  │ │
    │  │ tactic       │  │  ├── guardduty_types (AWS top)     │ │
    │  │ severity_base│  │  ├── azure: {activity_logs, ...}   │ │
    │  │ ...          │  │  ├── gcp: {audit_logs, ...}        │ │
    │  └─────────────┘  │  ├── oci: {audit_logs, ...}        │ │
    │                    │  ├── ibm: {activity_tracker, ...}  │ │
    │                    │  ├── alicloud: {actiontrail, ...}  │ │
    │                    │  └── k8s: {audit_logs, ...}        │ │
    │                    └───────────────────────────────────┘ │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ remediation_guidance (JSONB)                       │   │
    │  │  ├── immediate (AWS top)                          │   │
    │  │  ├── preventive (AWS top)                         │   │
    │  │  ├── azure: {immediate, preventive, services}     │   │
    │  │  ├── gcp: {immediate, preventive, services}       │   │
    │  │  ├── oci: {immediate, preventive, services}       │   │
    │  │  ├── ibm: {immediate, preventive, services}       │   │
    │  │  ├── alicloud: {immediate, preventive, services}  │   │
    │  │  └── k8s: {immediate, preventive, services}       │   │
    │  └───────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────┘

    Consumer: threat_analyzer.build_recommendations(provider="gcp")
      → reads mitre_guidance[tech_id]["detection_guidance"]["gcp"]
      → reads mitre_guidance[tech_id]["remediation_guidance"]["gcp"]
"""

import argparse
import os
import subprocess
import sys

import psycopg2
from psycopg2.extras import RealDictCursor


SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

STEPS = [
    {
        "step": 1,
        "name": "Base techniques (102 techniques)",
        "script": "seed_mitre_reference.py",
        "args": [],
    },
    {
        "step": 2,
        "name": "AWS guidance (30 techniques)",
        "script": "seed_mitre_guidance.py",
        "args": [],
    },
    {
        "step": 3,
        "name": "Gap fill — AWS + Azure + GCP (18 techniques)",
        "script": "seed_mitre_gap_guidance.py",
        "args": [],
    },
    {
        "step": 4,
        "name": "Azure + GCP guidance (20 techniques)",
        "script": "seed_mitre_multicloud_guidance.py",
        "args": [],
    },
    {
        "step": 5,
        "name": "OCI + IBM + Alicloud + K8s guidance (40 technique-CSP pairs)",
        "script": "seed_mitre_remaining_csp_guidance.py",
        "args": [],
    },
]


def get_conn():
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", "localhost"),
        port=int(os.getenv("THREAT_DB_PORT", "5432")),
        database=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", "postgres"),
        password=os.getenv("THREAT_DB_PASSWORD", ""),
    )


def verify_coverage():
    """Show comprehensive coverage report."""
    conn = get_conn()

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Total techniques
        cur.execute("SELECT COUNT(*) as cnt FROM mitre_technique_reference")
        total = cur.fetchone()["cnt"]

        # With any guidance
        cur.execute("""
            SELECT COUNT(*) as cnt FROM mitre_technique_reference
            WHERE (detection_guidance IS NOT NULL AND detection_guidance::text NOT IN ('{}', 'null'))
               OR (remediation_guidance IS NOT NULL AND remediation_guidance::text NOT IN ('{}', 'null'))
        """)
        with_guidance = cur.fetchone()["cnt"]

        # Per-CSP coverage
        csps = {
            "aws":      "cloudtrail_events",
            "azure":    "azure",
            "gcp":      "gcp",
            "oci":      "oci",
            "ibm":      "ibm",
            "alicloud": "alicloud",
            "k8s":      "k8s",
        }

        csp_counts = {}
        for csp, key in csps.items():
            cur.execute("""
                SELECT COUNT(*) as cnt FROM mitre_technique_reference
                WHERE detection_guidance ? %s
            """, (key,))
            csp_counts[csp] = cur.fetchone()["cnt"]

        # Severity distribution
        cur.execute("""
            SELECT severity_base, COUNT(*) as cnt
            FROM mitre_technique_reference
            WHERE severity_base IS NOT NULL
            GROUP BY severity_base
            ORDER BY CASE severity_base
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 WHEN 'low' THEN 4 END
        """)
        by_severity = cur.fetchall()

    conn.close()

    print(f"\n{'='*60}")
    print(f"MITRE Technique Reference — Coverage Report")
    print(f"{'='*60}")
    print(f"\n  Total techniques:  {total}")
    print(f"  With guidance:     {with_guidance} ({round(with_guidance/total*100, 1)}%)")
    print(f"  Without guidance:  {total - with_guidance}")
    print(f"\n  Detection guidance by CSP:")
    for csp, count in csp_counts.items():
        bar = "█" * (count // 2) + "░" * ((50 - count) // 2)
        print(f"    {csp:10s} {count:3d} techniques  {bar}")
    print(f"\n  Severity distribution:")
    for row in by_severity:
        print(f"    {row['severity_base']:10s} {row['cnt']:3d}")
    print(f"{'='*60}\n")


def run_step(step_info: dict, dry_run: bool = False):
    """Execute a single seed step as a subprocess."""
    script_path = os.path.join(SCRIPTS_DIR, step_info["script"])

    if not os.path.exists(script_path):
        print(f"  ❌ Script not found: {script_path}")
        return False

    cmd = [sys.executable, script_path] + step_info["args"]
    if dry_run:
        cmd.append("--dry-run")

    print(f"\n  Step {step_info['step']}: {step_info['name']}")
    print(f"  Running: {' '.join(cmd)}")
    print(f"  {'─'*50}")

    result = subprocess.run(cmd, env=os.environ.copy())

    if result.returncode != 0:
        print(f"  ❌ Step {step_info['step']} failed (exit code {result.returncode})")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Unified MITRE ATT&CK seeder — runs all seed steps in order",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Steps:
  1  Base techniques (102 techniques)
  2  AWS guidance (30 techniques)
  3  Gap fill — AWS + Azure + GCP (18 techniques)
  4  Azure + GCP guidance (20 techniques)
  5  OCI + IBM + Alicloud + K8s guidance (40 technique-CSP pairs)
        """,
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview all steps without writing")
    parser.add_argument("--step", type=int, help="Run only this step (1-5)")
    parser.add_argument("--verify-only", action="store_true", help="Only show coverage report")
    args = parser.parse_args()

    if args.verify_only:
        verify_coverage()
        return

    steps_to_run = STEPS
    if args.step:
        steps_to_run = [s for s in STEPS if s["step"] == args.step]
        if not steps_to_run:
            print(f"Unknown step: {args.step}. Valid steps: 1-5")
            sys.exit(1)

    print(f"\n{'='*60}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}MITRE ATT&CK Unified Seeder")
    print(f"Steps: {len(steps_to_run)}")
    print(f"{'='*60}")

    failed = []
    for step in steps_to_run:
        ok = run_step(step, args.dry_run)
        if not ok:
            failed.append(step["step"])

    print(f"\n{'='*60}")
    if failed:
        print(f"FAILED steps: {failed}")
        sys.exit(1)
    else:
        print(f"All {len(steps_to_run)} steps completed successfully")
        if not args.dry_run:
            verify_coverage()
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
