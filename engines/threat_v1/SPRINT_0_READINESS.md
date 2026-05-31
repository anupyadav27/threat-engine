# Sprint 0 Readiness Report

**Date:** 2026-05-10
**SM:** BMAD Scrum Master
**Sprint:** threat_v1 Sprint 0 — MITRE Tagging Prerequisites
**Stories reviewed:** S0-01, S0-02, S0-03, S0-04, S0-05

---

## Verdict: READY WITH NOTES

Sprint 0 can start immediately. S0-01, S0-02, S0-03, and S0-04 can be assigned to developers now. S0-05 must wait for its three tagging dependencies. Two WARNING-level issues and three MINOR issues require attention before the developer runs the verification steps — none are blockers for starting work, but all will cause failures at the verification/sign-off stage if not corrected.

---

## Per-Story Status Table

| Story | Ready? | Blocker? | Notes |
|-------|--------|----------|-------|
| S0-01 | YES | None | All 181 EC2 metadata files exist and have zero current tagging. Script path, upload path, DB target, and verification SQL are all correct. Minor: SPRINT_PLAN.md Sprint 0 DoD items 1-3 reference `aws_rule_check/` directories and `mitre_attack.technique` YAML field — neither matches what the stories actually target (`aws_rule_metadata/` and `mitre_techniques`). The stories are correct; the sprint plan DoD section has stale copy. |
| S0-02 | YES | None | 133 untagged IAM files confirmed (182 total - 49 already tagged). Copy-paste error in upload script comment at line 95: says "~182 total EC2 rows" — should say "~182 total IAM rows". Does not block dev; does confuse the `--dry-run` output interpretation. |
| S0-03 | YES | None | 66 untagged S3 files confirmed (76 total - 10 already tagged). File counts, paths, technique mapping table, and script path are all correct. |
| S0-04 | YES with WARNING | None (start), but WARNING on env var names | The DDL bug is confirmed at lines 292-293 of the schema file. Migration SQL, script path, and schema update target are all correct. WARNING: Story uses `VULNERABILITY_DB_HOST/USER/PASS/NAME` env vars in all kubectl exec commands, but the actual engine-vulnerability manifest exposes those values as bare `DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD` (from the `vulnerability-db-secret` Kubernetes secret, with no `VULNERABILITY_` prefix). Developer running the verification commands verbatim will get `psql: error: connection to server on socket... failed` on first attempt. |
| S0-05 | READY (blocked by deps) | Waiting on S0-01+S0-02+S0-03+S0-04 completing, as designed | WARNING: The coverage script uses `CHECK_DB_PASS` as the env var name, but the actual K8s secret key is `CHECK_DB_PASSWORD`. Running the script verbatim inside the check engine pod will raise `KeyError: 'CHECK_DB_PASS'`. The upload_rule_metadata_all_csps.py also uses `CHECK_DB_PASSWORD` (confirmed in its source). All three must align on the same name. |

---

## Gaps Found

| Story | Gap Description | Severity | Recommended Fix |
|-------|----------------|----------|-----------------|
| S0-04 | kubectl exec commands in Technical Notes use `$VULNERABILITY_DB_HOST`, `$VULNERABILITY_DB_USER`, `$VULNERABILITY_DB_PASS`, `$VULNERABILITY_DB_NAME` but the engine-vulnerability pod exposes these as `$DB_HOST`, `$DB_PORT`, `$DB_NAME`, `$DB_USER`, `$DB_PASSWORD` (sourced from the `vulnerability-db-secret` K8s secret, no `VULNERABILITY_` prefix). The verification Python snippet and the psql exec command will both fail as-is. | WARNING | Update all three kubectl exec command blocks in S0-04 Technical Notes to use `$DB_HOST`, `$DB_USER`, `$DB_PASSWORD`, `$DB_NAME`. Developer can verify: `kubectl exec -n threat-engine-engines deployment/engine-vulnerability -- env | grep DB_` to see actual names before running migration. |
| S0-05 | Coverage gate script (`check_mitre_coverage.py`) reads `os.environ["CHECK_DB_PASS"]` but the live K8s secret key (confirmed via `kubectl get secret threat-engine-db-passwords`) is `CHECK_DB_PASSWORD`. The check engine pod will not have `CHECK_DB_PASS` set. Script will raise `KeyError` on first run. `upload_rule_metadata_all_csps.py` also uses `CHECK_DB_PASSWORD` (not `CHECK_DB_PASS`) confirming the secret convention. | WARNING | Change `CHECK_DB_PASS` to `CHECK_DB_PASSWORD` in the `get_db_connection()` function of the S0-05 script implementation (line 114 of the script as written in the story), and update the docstring/usage comment at line 88 and the port-forward example at line 223. |
| SPRINT_PLAN.md (not a story) | Sprint 0 Definition of Done items 1-3 in SPRINT_PLAN.md (Section 4) reference `catalog/rule/aws_rule_check/ec2/`, `aws_rule_check/iam/`, `aws_rule_check/s3/` and the field `mitre_attack.technique`. The actual tagging target is `catalog/rule/aws_rule_metadata/ec2/iam/s3/` and the field is `mitre_techniques`. These are two entirely different directory trees. The check rule YAMLs (in `aws_rule_check/`) are not modified by this sprint. | WARNING | Update SPRINT_PLAN.md Section 4 Sprint 0 DoD items 1-3 to reference `catalog/rule/aws_rule_metadata/{ec2,iam,s3}/` and the `mitre_techniques` YAML field. This is a documentation-only fix and does not change any story. |
| S0-02 | Upload script comment at line 95 says `# Verify count: expect 49 unchanged + ~133 newly tagged = ~182 total EC2 rows`. "EC2 rows" should read "IAM rows". Minor copy-paste from S0-01. | MINOR | Change "EC2 rows" to "IAM rows" in the S0-02 Technical Notes upload script comment block. |
| S0-05 | S0-05 Technical Notes say to port-forward `svc/engine-check-aws` but the actual K8s Service name (confirmed in engine-check.yaml) is `engine-check`, not `engine-check-aws`. The `kubectl port-forward svc/engine-check-aws 8002:80` command will fail with "service not found". The pod selector label is also `app=engine-check-aws` in the script's kubectl exec command — same mismatch. | MINOR | Replace `engine-check-aws` with `engine-check` in both the port-forward command (Option B) and the kubectl exec commands (Option A) in the S0-05 Technical Notes. The correct label is `app=engine-check`. |
| S0-01 | SPRINT_PLAN.md S0-02 notes column references `T1098.003` as the IAM technique but S0-02 story uses `T1098.001`. The story is correct (T1098.001 = Additional Cloud Credentials). Sprint plan note is a minor documentation inconsistency. | MINOR | Update sprint plan S0-02 notes cell from `T1098.003` to `T1098.001`. |

---

## Path Verification Results

| Path | Exists? | Notes |
|------|---------|-------|
| `/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/ec2/` | YES | 181 YAML files confirmed. 0 currently have `mitre_techniques`. |
| `/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/iam/` | YES | 182 YAML files confirmed. 49 already have `mitre_techniques`. 133 untagged. |
| `/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/s3/` | YES | 76 YAML files confirmed. 10 already have `mitre_techniques`. 66 untagged. |
| `/Users/apple/Desktop/threat-engine/catalog/rule/upload_rule_metadata_all_csps.py` | YES | Supports `--csp aws`, `--type check`, `--dry-run` flags. Reads `mitre_techniques`, `mitre_tactics`, `threat_tags`, `threat_category` from YAML. Uses `CHECK_DB_PASSWORD` env var (not `CHECK_DB_PASS`). |
| `/Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/` | YES (empty) | Directory exists. `tag_ec2_rules.py`, `tag_iam_rules.py`, `tag_s3_rules.py`, `check_mitre_coverage.py` are all TO BE CREATED by this sprint — correct, not a blocker. |
| `/Users/apple/Desktop/threat-engine/engines/threat_v1/tests/` | YES | Contains only `__init__.py`. Test files created in this sprint are new — correct. |
| `/Users/apple/Desktop/threat-engine/engines/vulnerability/vul_engine/schemas_and_config/vulnerability_schema.sql` | YES | DDL bug confirmed at lines 292-293: `UNIQUE(cve_id,,` and duplicate UNIQUE constraint. `scan_vulnerabilities` table at line 648 has NO `mitre_techniques` column. Both issues described in S0-04 are real and match the story. |
| `/Users/apple/Desktop/threat-engine/shared/database/migrations/threat_v1_s0_04_vuln_ddl_fix.sql` | NO (to be created) | Migration file does not exist yet — correct, S0-04 creates it. |
| `/Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/check_mitre_coverage.py` | NO (to be created) | Correct — S0-05 creates it. |
| `/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_check/s3/aws.s3.bucket.cross.account.replication.disabled.check.yaml` | NOT VERIFIED | S0-03 mentions this path as a check-rule file that should NOT be modified. The metadata target is in `aws_rule_metadata/s3/` (confirmed). The check rule path is referenced only as a "do not touch" note. |

---

## Dependency Graph

```
S0-01 (EC2 tag — 181 files, no deps) ──┐
                                        │
S0-02 (IAM tag — 133 files, no deps) ──┼──► S0-05 (coverage gate) ──► Sprint 1 UNBLOCKED
                                        │    [depends on S0-01+02+03+04]
S0-03 (S3 tag — 66 files, no deps)  ──┘

S0-04 (vuln DDL fix — no deps) ─────────► S0-05 (confirms mitre_techniques column exists)
```

S0-01, S0-02, S0-03, S0-04 can all start immediately and run in parallel. S0-05 cannot start until all four are marked done.

---

## Sprint 0 Kickoff Recommendation

Sprint 0 can start today. All four foundational stories (S0-01, S0-02, S0-03, S0-04) are independent and should be assigned in parallel — S0-01 and S0-04 to a backend developer (S0-01 is higher LOE at 5 pts due to 181 files; S0-04 requires DB migration discipline), and S0-02 and S0-03 to a second developer or security analyst (both are smaller, 3 pts and 2 pts respectively, with well-established patterns from the already-tagged IAM files).

Before the developer on S0-04 runs any `kubectl exec` migration commands, they must resolve the env var name discrepancy (`VULNERABILITY_DB_*` vs `DB_*`) — the recommended fix is to run `kubectl exec -n threat-engine-engines deployment/engine-vulnerability -- env | grep DB_` first to confirm the actual names in the live pod. Before the developer on S0-05 writes and tests the coverage script, the `CHECK_DB_PASS` vs `CHECK_DB_PASSWORD` inconsistency must be resolved in the script source.

The three MINOR issues (S0-02 comment typo, engine-check-aws service name, T1098 technique ID in sprint plan notes) do not block any story from starting but should be fixed during implementation to avoid confusion.

---

## Definition of Sprint 0 Complete

The following must all be true before S1-04 (ResourceResolver + MisconfigLoader) is assigned to a developer:

1. S0-05 Python script (`engines/threat_v1/scripts/check_mitre_coverage.py`) exits with code 0 when run inside the check engine pod against the production `rule_metadata` table.
2. Script output shows all three groups at or above 80%: EC2 >= 80.0%, IAM >= 80.0%, S3 >= 80.0%.
3. DL has captured the script output and documented "S0-05 PASSED — Sprint 1 UNBLOCKED" in the Sprint 0 PR thread.
4. `cve_attack_mappings` table in the vulnerability DB has exactly one UNIQUE constraint (`cve_attack_mappings_cve_technique_uq`) — verified by S0-04 verification SQL query 4 returning count = 1.
5. `scan_vulnerabilities.mitre_techniques` JSONB column exists in the vulnerability DB — verified by S0-04 verification SQL query 2 returning one row with data_type = 'jsonb'.
6. Migration log for `threat_v1_s0_04_vuln_ddl_fix.sql` contains "MIGRATION COMPLETE: threat_v1_s0_04_vuln_ddl_fix" — visible in kubectl logs output.
7. `engines/threat_v1/scripts/tag_ec2_rules.py`, `tag_iam_rules.py`, `tag_s3_rules.py` are all committed and idempotent (second run produces no file changes).
8. All 181 EC2, 182 IAM, and 76 S3 YAML files in their respective `aws_rule_metadata/` directories have non-empty `mitre_techniques` lists.
9. `upload_rule_metadata_all_csps.py --csp aws --type check` ran without errors after all three tagging stories completed.
10. SA has signed off on technique mapping accuracy for the privilege escalation category (S0-02 AC-8) and T1537 vs T1530 distinction for cross-account replication (S0-03 AC-8) before their respective bulk-tagging runs executed.
