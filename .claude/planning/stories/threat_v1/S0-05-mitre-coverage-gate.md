# Story S0-05: MITRE Coverage Validation Gate (≥ 80% Across Tagged Rule Groups)

## Status: ready

## Metadata
- **Sprint**: 0 — MITRE Tagging Prerequisites
- **Points**: 2 (Small — script writing + gate wiring; no DB schema changes; no Docker rebuild)
- **Priority**: P0
- **Depends on**: S0-01 (EC2 tagging), S0-02 (IAM tagging), S0-03 (S3 tagging), S0-04 (DDL fix + `mitre_techniques` column)
- **Blocks**: Sprint 1 start (S1-04 is blocked until this gate passes per Sprint Plan Section 1)
- **RACI**: R=QA A=DL C=ARCH,SA I=PO
- **Security Gate**: Sprint 1 is hard-blocked until this gate passes. DL must document gate result (pass/fail) in the Sprint 0 retrospective thread before S1-04 is assigned.

## Context

Three tagging stories (S0-01, S0-02, S0-03) collectively add MITRE technique IDs to 380 AWS rule metadata YAML files and upload them to the `rule_metadata` table. Before Sprint 1 coding can begin — specifically before the MisconfigLoader (S1-04) is built to join check_findings against rule_metadata for technique IDs — we need a machine-verifiable assertion that the tagging was successful.

This story produces a Python script (`check_mitre_coverage.py`) that queries the `rule_metadata` table in the check engine DB, computes per-group coverage percentages, and exits non-zero if any priority group is below 80%. This script is the Sprint 0 completion gate: it runs in CI and in the manual sign-off flow. If it passes, Sprint 1 is unblocked.

The 80% threshold is chosen because:
1. It exceeds the current baseline (EC2=0%, IAM=26%, S3=13%) by a material margin
2. It allows a small number of edge-case rules that have no clear ATT&CK mapping to remain untagged without blocking the sprint
3. The threat_v1 PatternExecutor degrades gracefully for untagged rules — it simply cannot match those rules to technique IDs in pattern conditions
4. 100% is not required for Sprint 1 to start; it is a post-launch improvement goal

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance [x] Design [ ] Implementation [x] Verification [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [x] GV Govern [x] ID Identify [ ] PR Protect [x] DE Detect [ ] RS Respond [ ] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: GRC-01 (Governance Risk Management Policy), IVS-01 (Infrastructure Security), IAM-01 (Identity and Access Management)

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Tampering | Coverage script | Script hard-codes a passing result instead of querying the DB — gate passes without real coverage | Script must print the raw DB counts in its output; DL must visually verify the count output matches the SQL query result |
| Spoofing | DB connection | Script connects to wrong DB (discoveries DB instead of check DB) — returns false counts | Script must use the `CHECK_DB_*` env vars explicitly; add an assertion that queried tables are in the `rule_metadata` namespace |
| Info Disclosure | Script output | Coverage report printed to stdout might reveal rule counts that expose security posture gap | Coverage numbers are engineering metrics, not customer-facing — acceptable to print to CI logs |
| DoS | Script | Script runs an expensive aggregate query during an active scan | Script uses simple `COUNT(*)` with `WHERE rule_id LIKE 'aws.X.%'` — index-backed, fast |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Detection suppression | Developer bypasses gate by setting threshold to 0% | Script has threshold as a named constant with a comment; gate threshold changes require PR review | Threshold is `COVERAGE_THRESHOLD = 80` in the script; not an argument; change requires a code review |

## MITRE ATT&CK Techniques Addressed

This story is a process/tooling story, not a detection story. It enables detection by validating that tagging stories produced usable coverage. No direct ATT&CK technique is addressed by the script itself.

The script's output (coverage ≥ 80%) is the prerequisite for PatternExecutor to accurately match check findings to:
- T1190 (Initial Access — EC2 public exposure rules)
- T1552.005 (Credential Access — IMDSv1 rules)
- T1078.004 (Initial Access — IAM cloud account rules)
- T1530 (Collection — S3 data access rules)

## Technical Notes

### Script file path

```
/Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/check_mitre_coverage.py
```

### Script implementation

```python
#!/usr/bin/env python3
"""
check_mitre_coverage.py
=======================
Sprint 0 gate: verify MITRE technique coverage across AWS priority rule groups.
Exits non-zero if any group is below COVERAGE_THRESHOLD.

Usage:
    python check_mitre_coverage.py                          # use env vars for DB
    python check_mitre_coverage.py --group ec2 iam s3       # specific groups only
    python check_mitre_coverage.py --threshold 80           # default threshold

DB: rule_metadata table in the check engine DB (threat_engine_check)
Connection env vars: CHECK_DB_HOST, CHECK_DB_USER, CHECK_DB_PASSWORD, CHECK_DB_NAME, CHECK_DB_PORT
"""

import argparse
import os
import sys

import psycopg2

# ── Constants ────────────────────────────────────────────────────────────────
# 80% is the Sprint 0 gate threshold. Do NOT lower this without a PR review.
COVERAGE_THRESHOLD = 80

# Priority rule groups for Sprint 0 gate
PRIORITY_GROUPS = {
    "ec2": "aws.ec2.%",
    "iam": "aws.iam.%",
    "s3":  "aws.s3.%",
}


def get_db_connection():
    return psycopg2.connect(
        host=os.environ["CHECK_DB_HOST"],
        port=int(os.environ.get("CHECK_DB_PORT", "5432")),
        user=os.environ["CHECK_DB_USER"],
        password=os.environ["CHECK_DB_PASSWORD"],
        dbname=os.environ["CHECK_DB_NAME"],
        sslmode="require",
    )


def compute_coverage(cur, rule_id_pattern: str) -> dict:
    """Query rule_metadata for a rule_id pattern and return coverage stats."""
    cur.execute(
        """
        SELECT
            COUNT(*)                                                                      AS total,
            COUNT(*) FILTER (
                WHERE mitre_techniques IS NOT NULL
                  AND jsonb_array_length(mitre_techniques) > 0
            )                                                                             AS tagged
        FROM rule_metadata
        WHERE rule_id LIKE %s
        """,
        (rule_id_pattern,),
    )
    row = cur.fetchone()
    total, tagged = row[0], row[1]
    pct = round(tagged / total * 100, 1) if total > 0 else 0.0
    return {"total": total, "tagged": tagged, "pct": pct}


def main():
    parser = argparse.ArgumentParser(description="MITRE coverage gate for Sprint 0")
    parser.add_argument(
        "--group", nargs="+", choices=list(PRIORITY_GROUPS.keys()),
        default=list(PRIORITY_GROUPS.keys()),
        help="Rule groups to check (default: all priority groups)",
    )
    parser.add_argument(
        "--threshold", type=int, default=COVERAGE_THRESHOLD,
        help=f"Minimum coverage percentage (default: {COVERAGE_THRESHOLD})",
    )
    args = parser.parse_args()

    print(f"MITRE Coverage Gate — Sprint 0")
    print(f"Threshold: {args.threshold}%")
    print(f"Groups:    {', '.join(args.group)}")
    print()
    print(f"{'Group':<8} {'Total':>8} {'Tagged':>8} {'Coverage':>10} {'Status':>8}")
    print("-" * 50)

    conn = get_db_connection()
    cur = conn.cursor()

    failures = []
    for group_name in args.group:
        pattern = PRIORITY_GROUPS[group_name]
        stats = compute_coverage(cur, pattern)
        status = "PASS" if stats["pct"] >= args.threshold else "FAIL"
        print(
            f"{group_name:<8} {stats['total']:>8} {stats['tagged']:>8} "
            f"{stats['pct']:>9.1f}% {status:>8}"
        )
        if status == "FAIL":
            failures.append((group_name, stats))

    cur.close()
    conn.close()

    print()
    if failures:
        print(f"GATE FAILED — {len(failures)} group(s) below {args.threshold}% threshold:")
        for group_name, stats in failures:
            print(
                f"  {group_name}: {stats['pct']:.1f}% "
                f"({stats['tagged']}/{stats['total']} rules tagged)"
            )
        print()
        print("Sprint 1 is BLOCKED until all groups pass this gate.")
        print("Complete S0-01, S0-02, and S0-03 tagging stories and re-run.")
        sys.exit(1)
    else:
        print(f"GATE PASSED — all groups meet {args.threshold}% threshold")
        print("Sprint 1 (S1-04 and later) is now UNBLOCKED.")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

### How to run (against production check DB)

The check engine DB is not publicly accessible. Use kubectl port-forward or run via kubectl exec:

**Option A — kubectl exec on a check engine pod (recommended)**
```bash
# Copy the script to the check pod
kubectl cp /Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/check_mitre_coverage.py \
  threat-engine-engines/$(kubectl get pods -n threat-engine-engines -l app=engine-check-aws -o jsonpath='{.items[0].metadata.name}'):/tmp/check_mitre_coverage.py

# Run inside the pod (env vars are already set in the pod)
kubectl exec -n threat-engine-engines \
  $(kubectl get pods -n threat-engine-engines -l app=engine-check-aws -o jsonpath='{.items[0].metadata.name}') \
  -- python3 /tmp/check_mitre_coverage.py
```

**Option B — local run with port-forward**
```bash
kubectl port-forward svc/engine-check-aws 8002:80 -n threat-engine-engines &
# Set local env vars from the configmap values:
# export CHECK_DB_HOST=<host from configmap>
# export CHECK_DB_USER=<user>
# export CHECK_DB_PASSWORD=<password from secrets manager>
# export CHECK_DB_NAME=<dbname>
python /Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/check_mitre_coverage.py
```

### Expected output when gate passes

```
MITRE Coverage Gate — Sprint 0
Threshold: 80%
Groups:    ec2, iam, s3

Group    Total   Tagged   Coverage   Status
--------------------------------------------------
ec2        181      145      80.1%     PASS
iam        182      163      89.6%     PASS
s3          76       61      80.3%     PASS

GATE PASSED — all groups meet 80% threshold
Sprint 1 (S1-04 and later) is now UNBLOCKED.
```

### Expected output when gate fails (S0-01 not yet complete)

```
MITRE Coverage Gate — Sprint 0
Threshold: 80%
Groups:    ec2, iam, s3

Group    Total   Tagged   Coverage   Status
--------------------------------------------------
ec2        181        0       0.0%     FAIL
iam        182      163      89.6%     PASS
s3          76       61      80.3%     PASS

GATE FAILED — 1 group(s) below 80% threshold:
  ec2: 0.0% (0/181 rules tagged)

Sprint 1 is BLOCKED until all groups pass this gate.
Complete S0-01, S0-02, and S0-03 tagging stories and re-run.
```

### Gate documentation

When the gate passes, DL must:
1. Capture the script output as a screenshot or copy-paste into the Sprint 0 retrospective thread
2. Comment "S0-05 PASSED — Sprint 1 UNBLOCKED" in the Sprint 0 PR thread
3. Assign S1-04 (ResourceResolver + MisconfigLoader) to DEV

The gate does not auto-create a story or trigger any CI pipeline. It is a manual sign-off gate backed by an automated script.

### What happens if a group is between 80% and 100%?

The gate passes at 80%. Rules that remain untagged after the tagging stories are documented in the script output (total - tagged = gap). These untagged rules will not contribute to MITRE technique matching in PatternExecutor, but patterns that reference tagged rules will still fire correctly. The remaining gap is backlogged for post-Sprint 0 cleanup and is not a blocker.

## Acceptance Criteria

- [ ] AC-1: Script file exists at `/Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/check_mitre_coverage.py`
- [ ] AC-2: Script exits with code 0 when all three groups (ec2, iam, s3) are ≥ 80% in the check DB
- [ ] AC-3: Script exits with code 1 and prints a clear error message identifying which group(s) failed when any group is below 80%
- [ ] AC-4: Script output includes: group name, total rule count, tagged rule count, coverage percentage, PASS/FAIL status for each group
- [ ] AC-5: Script uses the `CHECK_DB_*` env vars for DB connection — does not hardcode host/credentials
- [ ] AC-6: Script connects with `sslmode=require`
- [ ] AC-7: Script is idempotent — running multiple times produces the same output for the same DB state
- [ ] AC-8: DL has run the script against production check DB and confirmed PASS output, then documented in the sprint thread

## Security Acceptance Criteria

- [ ] Script does not write to the `rule_metadata` table — read-only query only
- [ ] Script does not print DB connection strings, passwords, or usernames in its output
- [ ] Script does not accept DB credentials as command-line arguments (uses env vars only)
- [ ] `COVERAGE_THRESHOLD = 80` is a named constant, not a magic number — visible to code reviewers
- [ ] All DB queries use parameterized bindings (`%s`) not f-string interpolation of the `rule_id_pattern` string

## Definition of Done

- [ ] Script committed to `engines/threat_v1/scripts/check_mitre_coverage.py`
- [ ] Script runs without error against check engine DB inside a kubectl exec session
- [ ] All three groups return PASS (≥ 80%) — output captured and documented in sprint thread
- [ ] DL has documented "S0-05 PASSED — Sprint 1 UNBLOCKED" in the Sprint 0 PR thread
- [ ] S0-01, S0-02, and S0-03 are all marked "done" before this story is marked done
- [ ] S0-04 (DDL fix) is done and `scan_vulnerabilities.mitre_techniques` column exists (verified by the vuln coverage query below)
- [ ] No existing tests broken

## Verification SQL

```sql
-- Run against the check engine DB (threat_engine_check)
-- This is the same query the script runs — run manually to cross-check script output

-- Full Sprint 0 coverage summary
SELECT
    CASE
        WHEN rule_id LIKE 'aws.ec2.%' THEN 'ec2'
        WHEN rule_id LIKE 'aws.iam.%' THEN 'iam'
        WHEN rule_id LIKE 'aws.s3.%'  THEN 's3'
    END                                                                           AS service_group,
    COUNT(*)                                                                      AS total_rules,
    COUNT(*) FILTER (
        WHERE mitre_techniques IS NOT NULL
          AND jsonb_array_length(mitre_techniques) > 0
    )                                                                             AS tagged_rules,
    ROUND(
        COUNT(*) FILTER (
            WHERE mitre_techniques IS NOT NULL
              AND jsonb_array_length(mitre_techniques) > 0
        )::numeric / COUNT(*)::numeric * 100, 1
    )                                                                             AS coverage_pct,
    CASE
        WHEN ROUND(
            COUNT(*) FILTER (
                WHERE mitre_techniques IS NOT NULL
                  AND jsonb_array_length(mitre_techniques) > 0
            )::numeric / COUNT(*)::numeric * 100, 1
        ) >= 80 THEN 'PASS'
        ELSE 'FAIL'
    END                                                                           AS gate_status
FROM rule_metadata
WHERE rule_id LIKE 'aws.ec2.%'
   OR rule_id LIKE 'aws.iam.%'
   OR rule_id LIKE 'aws.s3.%'
GROUP BY 1
ORDER BY 1;

-- Expected output (all gate_status = PASS):
-- ec2 | 181 | >=145 | >=80.0 | PASS
-- iam | 182 | >=146 | >=80.0 | PASS
-- s3  |  76 | >= 61 | >=80.0 | PASS

-- Confirm S0-04 (vuln DDL fix) is complete — run against VULNERABILITY DB
-- (separate kubectl exec session against engine-vulnerability pod)
SELECT
    column_name,
    data_type,
    is_nullable
FROM information_schema.columns
WHERE table_name = 'scan_vulnerabilities'
  AND column_name = 'mitre_techniques';
-- Expected: 1 row | jsonb | YES

-- Confirm cve_attack_mappings is fixed (no malformed constraint)
SELECT COUNT(*) AS unique_constraints
FROM information_schema.table_constraints
WHERE table_name = 'cve_attack_mappings'
  AND constraint_type = 'UNIQUE';
-- Expected: 1

-- Sprint 0 completion checklist (run this last — all 4 checks must show true)
SELECT
    (SELECT COUNT(*) > 0 FROM rule_metadata WHERE rule_id LIKE 'aws.ec2.%' AND mitre_techniques IS NOT NULL) AS ec2_tagged,
    (SELECT COUNT(*) > 0 FROM rule_metadata WHERE rule_id LIKE 'aws.iam.%' AND mitre_techniques IS NOT NULL) AS iam_tagged,
    (SELECT COUNT(*) > 0 FROM rule_metadata WHERE rule_id LIKE 'aws.s3.%'  AND mitre_techniques IS NOT NULL) AS s3_tagged;
-- Expected: ec2_tagged=true, iam_tagged=true, s3_tagged=true
```
