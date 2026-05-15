# Story S0-03: Tag 66 Untagged S3 Rules with MITRE Techniques

## Status: done

## Metadata
- **Sprint**: 0 — MITRE Tagging Prerequisites
- **Points**: 2 (Small — 76 total S3 metadata files, 10 already tagged; straightforward T1530/T1537 domain)
- **Priority**: P0
- **Depends on**: none (can run in parallel with S0-01 and S0-02)
- **Blocks**: S0-05 (coverage gate); Sprint 3 Tier 3 pattern PAT-AWS-001 (EC2 → IAMRole → S3 crown jewel chain)
- **RACI**: R=DEV A=PO C=SA I=DL,QA
- **Security Gate**: SA consulted for cross-account replication technique distinction (T1537 vs T1530).

## Context

The S3 rule group has 76 total metadata YAML files in `catalog/rule/aws_rule_metadata/s3/`, of which 10 are already tagged (13% coverage). The 66 remaining untagged rules cover public access blocking, bucket policy configuration, cross-account replication, and object versioning. S3 buckets are the terminal crown jewel in the Capital One pattern (PAT-AWS-001) and in most data exfiltration chains. Without MITRE tags on `block_public_access`, `cross_account_replication`, and `object_logging` rules, the threat_v1 PatternExecutor cannot verify that the S3 target node is actually reachable via a data collection path, which degrades Tier 3 pattern accuracy.

The technique family is narrow: T1530 (Data from Cloud Storage) covers almost all S3 data access risks, and T1537 (Transfer Data to Cloud Account) covers cross-account replication and replication-based exfiltration. This makes S3 the fastest of the three tagging stories.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance [x] Design [x] Implementation [ ] Verification [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern [x] ID Identify [x] PR Protect [x] DE Detect [ ] RS Respond [ ] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: DSP-01 (Data Security and Privacy Policy), DSP-07 (Sensitive Data Protection), IVS-04 (Remote Access)

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | rule_metadata DB | T1537 tagged on an S3 lifecycle policy rule that has no cross-account dimension — false positive in replication patterns | Restrict T1537 to rules with "cross_account", "replication", or "external" in rule_id; default to T1530 for all others |
| Tampering | YAML files | Incorrect technique tag causes S3 PatternExecutor to match a logging rule (T1562.008) as a data collection node — pollutes the evidence graph | Logging rules get T1562.007/T1562.008 (defense_evasion), not T1530 |
| DoS | PatternExecutor | All 76 S3 rules tagged T1530 causes every S3-touching Tier 1 pattern to fire (too broad) | Use specific sub-techniques and tactic combinations; Tier 1 patterns also check `is_crown_jewel` flag, not just technique |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Cross-tenant read | Attacker queries S3 rules from another tenant via public bucket | Rule tags are not tenant data — they are catalog-level shared config | No tenant isolation required for rule_metadata catalog; all tenants share the same rule definitions |

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1530 | Data from Cloud Storage | D3-DAM (Data Access Management) | Tags public access, ACL, and bucket policy rules that enable unauthorized S3 object access |
| T1537 | Transfer Data to Cloud Account | D3-ITF (Inbound Traffic Filtering) | Tags cross-account replication and external replication destination rules |
| T1619 | Cloud Storage Object Discovery | D3-ALT (Application Log Triage) | Tags object logging and access audit rules that reveal storage enumeration |
| T1562.008 | Impair Defenses: Disable Cloud Audit Logs | D3-PLM (Platform Monitoring) | Tags S3 server access logging disable rules |

## Technical Notes

### File locations

All 76 S3 metadata YAML files:
```
/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/s3/
```

Check which 10 are already tagged before running the script:
```bash
grep -l "mitre_techniques" /Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/s3/*.yaml
```

The tagging script must skip these 10 already-tagged files.

### File inventory

There is exactly 1 file in the check rule directory:
```
/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_check/s3/aws.s3.bucket.cross.account.replication.disabled.check.yaml
```

The metadata directory at `catalog/rule/aws_rule_metadata/s3/` has 76 files. These are the files to tag. The check rule file is separate and should not be modified by this story.

### MITRE field schema

Same schema as S0-01 and S0-02. Example for a public access block rule:
```yaml
mitre_tactics:
- collection
mitre_techniques:
- T1530
threat_tags:
- T1530
- collection
threat_category: collection
```

### Upload script invocation

```bash
cd /Users/apple/Desktop/threat-engine
python catalog/rule/upload_rule_metadata_all_csps.py --csp aws --type check --dry-run
python catalog/rule/upload_rule_metadata_all_csps.py --csp aws --type check
```

### Technique mapping table (authoritative)

| Rule keyword pattern | MITRE Technique(s) | Tactic(s) | Rationale |
|---------------------|-------------------|-----------|-----------|
| `block_public_access`, `public_access_block`, `bucket_public_configured`, `public_bucket_acl` | T1530 | collection | Disabling public access block makes bucket data directly accessible |
| `bucket_policy_public_access`, `bucket_acl_public_read`, `bucket_acl_public_write` | T1530 | collection | Permissive bucket policies enable unauthorized object access |
| `cross.account.replication`, `cross_account_replication`, `replication_external_destination` | T1537 | exfiltration | Cross-account replication is data transfer to an external cloud account |
| `bucket.versioning_enabled`, `versioning_configured` | T1530 | collection | Versioning-disabled buckets prevent recovery of deleted objects (data destruction enabler), but the access vector is still T1530 |
| `server_side_encryption`, `default_encryption`, `kms_encryption`, `encryption_at_rest` | T1530 | collection | Unencrypted buckets expose object contents if access is gained |
| `server_access_logging`, `access_logging_enabled` | T1562.008 | defense_evasion | Disabling S3 access logs impairs visibility into who accessed which objects |
| `object_lock_enabled`, `object_lock_configured` | T1485 | impact | Object lock prevents ransomware-style deletion; its absence enables T1485 |
| `lifecycle_policy`, `transition_glacier`, `retention_policy` | T1530 | collection | Lifecycle misconfigurations can expose data during transition periods |
| `bucket_policy.least_privilege`, `bucket_policy.deny_public_access`, `bucket_policy.no_wildcard_principal` | T1530 | collection | Overly permissive bucket policies enable data collection |
| `intelligent_tiering`, `static_website_hosting` | T1190 | initial_access | Static website hosting enabled with public content exposes application data |
| `cloudtrail_logs_bucket_access_restricted`, `cloudtrail_logs_not_publicly_accessible` | T1530 | collection | CloudTrail log buckets with public access expose audit trails |
| `mfa_delete_enabled`, `mfa_delete_configured` | T1485 | impact | MFA delete prevents versioned object destruction |

**Default for any remaining S3 rule:** Apply `T1530` with tactic `collection`. S3 rules without a specific exfiltration or integrity context default to the data collection technique.

### Script path

```
/Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/tag_s3_rules.py
```

Same approach as S0-01 and S0-02: keyword match loop, idempotent, skip existing tags, print summary.

### DB table for verification

`rule_metadata` in **check engine DB** (`threat_engine_check`), `rule_id LIKE 'aws.s3.%'`

## Acceptance Criteria

- [ ] AC-1: All 76 S3 rule YAML files in `catalog/rule/aws_rule_metadata/s3/` have a non-empty `mitre_techniques` list (10 previously tagged unchanged, 66 newly tagged)
- [ ] AC-2: The tagging script does not overwrite any file that already has `mitre_techniques` present
- [ ] AC-3: All `block_public_access` and `public_bucket_acl` rules are tagged with `T1530` and tactic `collection`
- [ ] AC-4: The cross-account replication rule (`aws.s3.bucket.cross.account.replication.disabled`) is tagged with `T1537` and tactic `exfiltration`
- [ ] AC-5: Server access logging rules are tagged with `T1562.008` and tactic `defense_evasion` (not `T1530`)
- [ ] AC-6: After upload, verification SQL shows S3 coverage ≥ 80% (≥ 61 of 76 rules tagged)
- [ ] AC-7: Upload script runs without errors against check DB
- [ ] AC-8: SA has confirmed T1537 is the correct technique for cross-account replication (not T1530) before tagging

## Security Acceptance Criteria

- [ ] No previously-tagged S3 rules have their `mitre_techniques` changed or removed
- [ ] All technique IDs pass format validation: `T\d{4}(\.\d{3})?`
- [ ] YAML syntax valid for all 76 files after edits

## Definition of Done

- [ ] Tagging script committed to `engines/threat_v1/scripts/tag_s3_rules.py`
- [ ] All 76 YAML files in `catalog/rule/aws_rule_metadata/s3/` have `mitre_techniques` present
- [ ] Upload script run successfully against check DB
- [ ] DL has reviewed PR — specifically the T1537 vs T1530 distinction for replication rules
- [ ] SA sign-off on T1537 assignment for cross-account replication rules
- [ ] Verification SQL passes (see below)
- [ ] No existing tests broken

## Verification SQL

```sql
-- Run against the check engine DB (threat_engine_check)

-- 1. Overall S3 coverage
SELECT
    's3' AS service,
    COUNT(*) AS total_rules,
    COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0) AS tagged_rules,
    ROUND(
        COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0)::numeric
        / COUNT(*)::numeric * 100, 1
    ) AS coverage_pct
FROM rule_metadata
WHERE rule_id LIKE 'aws.s3.%';

-- Expected: coverage_pct >= 80.0

-- 2. Spot-check cross-account replication rule
SELECT rule_id, mitre_techniques, mitre_tactics
FROM rule_metadata
WHERE rule_id = 'aws.s3.bucket.cross.account.replication.disabled';
-- Expected: mitre_techniques @> '["T1537"]', mitre_tactics @> '["exfiltration"]'

-- 3. Verify logging rules get defense_evasion (not collection)
SELECT rule_id, mitre_techniques, mitre_tactics
FROM rule_metadata
WHERE rule_id LIKE 'aws.s3.%logging%'
  AND mitre_techniques IS NOT NULL;
-- Expected: mitre_tactics contains 'defense_evasion' for logging rules

-- 4. Confirm previously-tagged files still tagged
SELECT COUNT(*) AS previously_tagged_still_tagged
FROM rule_metadata
WHERE rule_id LIKE 'aws.s3.%'
  AND mitre_techniques IS NOT NULL
  AND jsonb_array_length(mitre_techniques) > 0;
-- Expected: >= 61 (80% of 76)

-- 5. Combined Sprint 0 coverage summary (run after all three tagging stories complete)
SELECT
    CASE
        WHEN rule_id LIKE 'aws.ec2.%' THEN 'ec2'
        WHEN rule_id LIKE 'aws.iam.%' THEN 'iam'
        WHEN rule_id LIKE 'aws.s3.%'  THEN 's3'
    END AS service_group,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0) AS tagged,
    ROUND(
        COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0)::numeric
        / COUNT(*)::numeric * 100, 1
    ) AS pct
FROM rule_metadata
WHERE rule_id LIKE 'aws.ec2.%' OR rule_id LIKE 'aws.iam.%' OR rule_id LIKE 'aws.s3.%'
GROUP BY 1
ORDER BY 1;

-- Expected: all three rows show pct >= 80.0
-- This output is the input to S0-05 coverage gate
```