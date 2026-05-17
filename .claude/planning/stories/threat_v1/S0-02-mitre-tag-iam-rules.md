# Story S0-02: Tag 133 Untagged IAM Rules with MITRE Techniques

## Status: done

## Metadata
- **Sprint**: 0 — MITRE Tagging Prerequisites
- **Points**: 3 (Small-Medium — 133 remaining untagged files; 49 already tagged; pattern is well-established in existing tagged files)
- **Priority**: P0
- **Depends on**: none (can run in parallel with S0-01)
- **Blocks**: S0-05 (coverage gate), Sprint 1 pattern matching for IAM pivot rules
- **RACI**: R=DEV A=PO C=SA I=DL,QA
- **Security Gate**: SA consulted for technique mapping accuracy before bulk tagging. Specifically: `allows_privilege_escalation` rules require SA review to confirm T1548.002 vs T1098.

## Context

The IAM rule group has 182 total rules in `catalog/rule/aws_rule_metadata/iam/`, of which 49 are already MITRE-tagged (26% coverage). The remaining 133 are untagged. IAM rules are the pivot mechanism in virtually every cloud attack path — a compromised EC2 instance assumes an admin IAMRole, which then accesses S3, RDS, or Secrets Manager. Without MITRE tags on `allows_privilege_escalation`, `root_mfa_enabled`, `admin_policy_attached`, and password policy rules, the threat_v1 PatternExecutor cannot match IAM-pivoting check findings to techniques, making Tier 2 and Tier 3 patterns blind to the IAM signal.

The 49 already-tagged IAM rules cover activity_log (CDR) rules (T1078, T1078.004, T1098, T1550, etc.). The gap is the **posture/config rules** — password policy, MFA enforcement, root account usage, admin policy, and privilege escalation policies — which map to T1078.004, T1548, T1098.001, and T1136.003.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance [x] Design [x] Implementation [ ] Verification [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern [x] ID Identify [x] PR Protect [x] DE Detect [ ] RS Respond [ ] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: IAM-01 (Identity and Access Management Policy), IAM-02 (Least Privilege), IAM-08 (Multi-Factor Authentication), IAM-09 (Account Management)

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | YAML edit | Incorrect T1548 assigned to a read-only IAM role rule — rule fires on benign role, flooding incidents | SA review of the privilege escalation category mapping before bulk apply |
| Tampering | rule_metadata DB | Upload script overwrites existing 49 tagged IAM rules with incorrect data | Script must only write files where `mitre_techniques` is absent; use `--dry-run` first to verify count (should show ~133 new + 49 unchanged) |
| Info Disclosure | rule_metadata | No PII — technique IDs are public ATT&CK catalog entries | None |
| DoS | N/A | Overly broad T1078.004 tag on every IAM rule floods Tier 1 toxic combo matches | Use specific sub-techniques where available; Tier 1 patterns use rule_id checks, not just technique IDs |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Incorrect tagging | Detection suppression | T1548 tagged on MFA enforcement rule causes pattern to fire on all tenants without MFA — FP flood triggers per-tenant suppression | Manual review table in this story; use specific sub-techniques; SA consult |

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | D3-ANET (Authentication Event Thresholding) | Tags root account usage, inactive account, and failed login rules |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | D3-PCSV (Privilege Escalation Detection) | Tags `allows_privilege_escalation` and `admin_policy_attached` rules |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | D3-SCL (Service Control Limiting) | Tags rules detecting IAM key creation, access key rotation gaps |
| T1136.003 | Create Account: Cloud Account | D3-ANET (Authentication Event Thresholding) | Tags guest user creation and cross-account role creation rules |
| T1087.004 | Account Discovery: Cloud Account | D3-ALT (Application Log Triage) | Tags enumeration-enabling rules (overly permissive list/describe permissions) |
| T1531 | Account Access Removal | D3-ANET (Authentication Event Thresholding) | Tags rules detecting account lockout or deletion to prevent owner access |

## Technical Notes

### File locations

Files to tag (133 currently untagged):
```
/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/iam/
```

Already-tagged files (DO NOT overwrite):
```bash
# These 49 files already have mitre_techniques — script must skip them
grep -l "mitre_techniques" /Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/iam/*.yaml
```

The tagging script must check for `mitre_techniques` presence before writing. Running `yaml.safe_load()` on each file and checking for the key is the correct approach.

### MITRE field schema

Same schema as S0-01. Example for a root account rule:
```yaml
mitre_tactics:
- initial_access
mitre_techniques:
- T1078.004
threat_tags:
- T1078.004
- initial_access
threat_category: initial_access
```

### Upload script invocation

```bash
cd /Users/apple/Desktop/threat-engine
python catalog/rule/upload_rule_metadata_all_csps.py --csp aws --type check --dry-run
# Verify count: expect 49 unchanged + ~133 newly tagged = ~182 total EC2 rows
python catalog/rule/upload_rule_metadata_all_csps.py --csp aws --type check
```

The script path is: `/Users/apple/Desktop/threat-engine/catalog/rule/upload_rule_metadata_all_csps.py`

### Technique mapping table (authoritative — SA must review before bulk apply)

| Rule keyword pattern | MITRE Technique(s) | Tactic(s) | Rationale |
|---------------------|-------------------|-----------|-----------|
| `root_mfa_enabled`, `root_hardware_mfa`, `root_account_mfa`, `account.allow_root_mfa` | T1078.004 | initial_access | Root account without MFA is the highest-value cloud account compromise target |
| `root_account_credentials`, `root_access_key_exists`, `root.access_key_not_configured` | T1078.004 | initial_access | Root access keys enable full account takeover without MFA friction |
| `allows_privilege_escalation`, `admin_policy_attached`, `admin_access_granted`, `full_admin` | T1548 | privilege_escalation | Admin policy attachment is direct privilege escalation |
| `role.trust_policy_external_principals`, `cross_account_role_trust`, `wildcard_principal` | T1098.001 | persistence | External trust allows persistence via role assumption from foreign account |
| `password_policy.hard_expiry`, `password_minimum_length`, `password_reuse`, `password_complexity` | T1078.004 | initial_access | Weak password policy enables brute-force of cloud console accounts |
| `access_key_max_age`, `key_rotation`, `inactive_access_key`, `unused_credentials` | T1552 | credential_access | Long-lived access keys are standing credentials that can be exfiltrated |
| `user.mfa_not_enabled`, `mfa_disabled`, `hardware_mfa_not_enabled` | T1078.004 | initial_access | No MFA on console login enables credential stuffing |
| `user.inactive_user`, `inactive_credentials`, `unused_user_account` | T1078.004 | initial_access | Stale/dormant accounts provide low-visibility attack entry |
| `chain.guest_to_privileged`, `chain.role_assignment_evasion` | T1548.002 | privilege_escalation | Chained permission escalation is a specific PrivEsc technique |
| `iam.account.*` (general account posture rules) | T1078.004 | initial_access | Account-level IAM posture misconfigurations enable initial access |
| `activity_log.assume_role`, `activity_log.assume_role_high_privilege` | T1098.001 | persistence | CloudTrail events for role assumption activity |
| `activity_log.deactivate_mfa`, `activity_log.delete_policy_version` | T1548 | privilege_escalation | MFA removal and policy downgrade are active privilege escalation steps |
| `activity_log.failed_auth_attempts` | T1110 | credential_access | Brute-force authentication attempts |
| `activity_log.guest_user_creation` | T1136.003 | persistence | Guest/shadow account creation for persistence |
| `activity_log.role_assignment_modify` | T1098.001 | persistence | Direct role modification to add credentials or permissions |
| `audit.delete_malware_protection_role` | T1562.001 | defense_evasion | Deleting a protective IAM role disables a security control |
| `user.password_policy.*` | T1078.004 | initial_access | Weak or absent password policy weakens account security posture |

**Rules with no clear technique match:** Apply T1078.004 as the conservative default for any remaining IAM rule related to account access, credentials, or authorization. Document in PR if more than 5 rules fall into this category.

### Script path

```
/Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/tag_iam_rules.py
```

Same approach as S0-01 tagging script: keyword-match loop over files, write only if `mitre_techniques` absent, print per-file summary, exit non-zero on unmatched rules.

### DB table for verification

`rule_metadata` table in **check engine DB** (`threat_engine_check`):
- `rule_id` LIKE `'aws.iam.%'`
- `mitre_techniques` JSONB

## Acceptance Criteria

- [ ] AC-1: All 182 IAM rule YAML files in `catalog/rule/aws_rule_metadata/iam/` have a non-empty `mitre_techniques` list (49 previously tagged remain unchanged, 133 newly tagged)
- [ ] AC-2: The tagging script does not overwrite any file that already has `mitre_techniques` present
- [ ] AC-3: Root account rules (`allow_root_mfa`, `root_access_key_exists`) are tagged with `T1078.004` and tactic `initial_access`
- [ ] AC-4: Privilege escalation rules (`allows_privilege_escalation`, `chain.guest_to_privileged`) are tagged with `T1548` or `T1548.002` and tactic `privilege_escalation`
- [ ] AC-5: Access key rotation/age rules are tagged with `T1552` or `T1552.005` and tactic `credential_access`
- [ ] AC-6: After upload, verification SQL shows IAM coverage ≥ 80% (≥ 146 of 182 rules tagged)
- [ ] AC-7: Upload script runs without errors against check DB
- [ ] AC-8: SA has reviewed the privilege escalation category mapping (T1548 vs T1548.002 vs T1098) before bulk tagging runs

## Security Acceptance Criteria

- [ ] No existing 49 tagged IAM rules have their `mitre_techniques` changed or removed — verify by running `git diff catalog/rule/aws_rule_metadata/iam/` and confirming no previously-tagged file shows removal of `mitre_techniques`
- [ ] All technique IDs pass format validation: `T\d{4}(\.\d{3})?`
- [ ] YAML syntax valid for all 182 files after edits — run `python -c "import yaml; yaml.safe_load(open(f).read())" for f in iam/*.yaml`

## Definition of Done

- [ ] Tagging script committed to `engines/threat_v1/scripts/tag_iam_rules.py`
- [ ] All 182 YAML files in `catalog/rule/aws_rule_metadata/iam/` have `mitre_techniques` present
- [ ] Upload script run successfully against check DB
- [ ] DL has reviewed PR — specifically the privilege escalation mapping table
- [ ] SA sign-off on T1548 vs T1548.002 distinction for `allows_privilege_escalation` rules
- [ ] Verification SQL passes (see below)
- [ ] No existing tests broken

## Verification SQL

```sql
-- Run against the check engine DB (threat_engine_check)

-- 1. Overall IAM coverage
SELECT
    'iam' AS service,
    COUNT(*) AS total_rules,
    COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0) AS tagged_rules,
    ROUND(
        COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0)::numeric
        / COUNT(*)::numeric * 100, 1
    ) AS coverage_pct
FROM rule_metadata
WHERE rule_id LIKE 'aws.iam.%';

-- Expected: coverage_pct >= 80.0

-- 2. Spot-check root account rules
SELECT rule_id, mitre_techniques, mitre_tactics
FROM rule_metadata
WHERE rule_id IN (
    'aws.iam.account.allow_root_mfa',
    'aws.iam.user.password_policy.hard_expiry'
);
-- Expected: mitre_techniques @> '["T1078.004"]' for both

-- 3. Spot-check privilege escalation rules
SELECT rule_id, mitre_techniques, mitre_tactics
FROM rule_metadata
WHERE rule_id IN (
    'aws.iam.chain.guest_to_privileged',
    'aws.iam.chain.role_assignment_evasion',
    'aws.iam.role.trust_policy_external_principals'
);
-- Expected: mitre_techniques includes T1548 or T1098.001

-- 4. Confirm previously-tagged files still have their original techniques
SELECT rule_id, mitre_techniques
FROM rule_metadata
WHERE rule_id IN (
    'aws.iam.activity_log.assume_role',
    'aws.iam.activity_log.deactivate_mfa'
)
  AND mitre_techniques IS NOT NULL;
-- Expected: 2 rows (both still tagged)

-- 5. Confirm no previously-tagged file lost its technique
SELECT COUNT(*) AS previously_tagged_still_tagged
FROM rule_metadata
WHERE rule_id LIKE 'aws.iam.activity_log.%'
  AND mitre_techniques IS NOT NULL;
-- Expected: >= 10 (all activity_log rules still tagged)
```