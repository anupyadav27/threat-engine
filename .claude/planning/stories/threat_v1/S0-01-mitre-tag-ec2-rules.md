# Story S0-01: Tag 181 EC2 Rules with MITRE Techniques

## Status: ready

## Metadata
- **Sprint**: 0 — MITRE Tagging Prerequisites
- **Points**: 5 (Medium — 181 YAML files, no new DB schema, domain heuristic speeds bulk work)
- **Priority**: P0
- **Depends on**: none
- **Blocks**: S0-05 (coverage gate), Sprint 1 (S1-04 MisconfigLoader must read mitre_techniques from rule_metadata)
- **RACI**: R=DEV A=PO C=SA,ARCH I=DL,QA
- **Security Gate**: PO acceptance criteria must be written and reviewed before DEV starts. SA consulted for technique mapping accuracy before bulk tagging begins.

## Context

The EC2 rule group (181 rules in `catalog/rule/aws_rule_metadata/ec2/`) has **0% MITRE technique coverage** as of 2026-05-10. EC2 is the single highest-value attack entry point — IMDSv1-enabled instances, public security groups, and unencrypted EBS snapshots are the leading initial access and credential access vectors in cloud breach reports. Without MITRE tags on these rules, the threat_v1 PatternExecutor cannot match check_findings to techniques by ID, and all EC2-derived patterns will be blind to the check signal. This is the single highest-impact tagging gap and must be completed before Sprint 1's MisconfigLoader is tested.

The rule metadata YAML files are the authoritative source (not the check rule YAML files in `catalog/rule/aws_rule_check/ec2/`). MITRE tags added to the metadata YAMLs are picked up by `upload_rule_metadata_all_csps.py` and written to the `rule_metadata` table in the check engine DB via the `mitre_techniques` and `mitre_tactics` columns. The upload script already handles these fields — no code changes to the upload script are required.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance [x] Design [x] Implementation [ ] Verification [ ] Operations

**NIST CSF 2.0 Function(s) this story covers**
- [ ] GV Govern [x] ID Identify [ ] PR Protect [x] DE Detect [ ] RS Respond [ ] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: IVS-01 (Infrastructure and Virtualization Security — network exposure), IAM-01 (Identity and Access Management — metadata credential access), DSP-07 (Data Security and Privacy — storage encryption)

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | upload_rule_metadata_all_csps.py | Script run without `--csp aws` scope overwrites non-EC2 rules with incorrect technique IDs | Use `--csp aws --type check` flags; run with `--dry-run` first to inspect counts |
| Tampering | YAML files in git | Incorrect technique ID introduced via PR (e.g., T1552 assigned to a VPN rule with no metadata endpoint) | SA review of the technique-to-rule mapping table in this story before bulk tagging begins; DL PR review |
| Info Disclosure | rule_metadata DB table | No new PII risk — technique IDs are public ATT&CK catalog entries | None required |
| DoS | upload script | Bulk UPSERT of 181 rows causes lock contention on rule_metadata table during active scan | Run upload outside of scan window; script uses INSERT...ON CONFLICT DO UPDATE which is row-level |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Incorrect tagging | Pattern fires on wrong rule category | T1190 incorrectly tagged on a VPN tunnel rule that has no internet exposure context | Manual review table in this story; ARCH sign-off before bulk apply |

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1190 | Exploit Public-Facing Application | D3-NTA (Network Traffic Analysis) | Tags all public SG / public endpoint / NACL rules — enables PatternExecutor to match entry nodes |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | D3-OTF (Credential Hardening) | Tags all IMDSv1/IMDSv2 rules — enables Capital One pattern (PAT-AWS-001) |
| T1578 | Modify Cloud Compute Infrastructure | D3-DNSDL (DNS Denylisting) | Tags AMI public visibility, snapshot public access, and instance modification rules |
| T1530 | Data from Cloud Storage | D3-DAM (Data Access Management) | Tags EBS snapshot public access and encrypted volume rules |
| T1562.001 | Impair Defenses: Disable or Modify Tools | D3-AVS (Antivirus / Endpoint Detection) | Tags GuardDuty disable and antimalware disable activity log rules |
| T1021.004 | Remote Services: SSH | D3-NTF (Network Traffic Filtering) | Tags SSH port 22 and RDP port 3389 security group rules |

## Technical Notes

### File locations

All 181 metadata YAML files to be tagged:
```
/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/ec2/
```

Each file is named after its rule_id (e.g., `aws.ec2.instance.imdsv2_enabled.yaml`). The files do NOT currently contain `mitre_techniques` or `mitre_tactics` fields. These must be added.

The check rule YAML files (in `catalog/rule/aws_rule_check/ec2/`) are NOT the target — do not modify those. The metadata YAMLs are the source for `upload_rule_metadata_all_csps.py`.

### MITRE field schema (how to add to each metadata YAML)

Based on the existing tagged examples in `catalog/rule/aws_rule_metadata/iam/` (49 already-tagged files), the correct YAML format is:

```yaml
mitre_tactics:
- initial_access              # tactic name (snake_case, not tactic ID)
mitre_techniques:
- T1190                       # ATT&CK technique ID
- T1595.002                   # sub-technique where applicable
threat_tags:
- T1190
- initial_access
threat_category: initial_access   # single primary tactic (used for grouping)
```

Both `mitre_tactics` and `mitre_techniques` are lists. `threat_tags` is a duplicate of both technique IDs and tactic names — include it for consistency with already-tagged files.

### Upload script

After YAML edits:
```bash
cd /Users/apple/Desktop/threat-engine
python catalog/rule/upload_rule_metadata_all_csps.py --csp aws --type check --dry-run
# Review count output: expect ~181 EC2 records
python catalog/rule/upload_rule_metadata_all_csps.py --csp aws --type check
```

The script reads from `catalog/rule/aws_rule_metadata/ec2/*.yaml` and UPSERTs into the `rule_metadata` table in the **check engine DB** (not discoveries DB). Connection uses env var `CHECK_DB_*` from the pod running the script or from a local `.env` file.

### DB table for verification

`rule_metadata` table is in the **check engine DB** (`threat_engine_check`).

Key columns:
- `rule_id` (VARCHAR, primary key)
- `mitre_techniques` (JSONB, e.g., `["T1190", "T1552.005"]`)
- `mitre_tactics` (JSONB, e.g., `["initial_access", "credential_access"]`)

### Technique mapping table (authoritative — SA must review before bulk apply)

Apply the following heuristic mapping by rule_id keyword pattern:

| Rule keyword pattern | MITRE Technique(s) | Tactic(s) | Rationale |
|---------------------|-------------------|-----------|-----------|
| `imdsv1`, `imdsv2`, `imds_hardened` | T1552.005 | credential_access | Instance metadata API is the canonical credential theft vector |
| `instance.imdsv2_enabled`, `instance.imds_hardened_configured` | T1552.005 | credential_access | IMDSv2 enforcement prevents SSRF-based metadata theft |
| `port_ssh_exposed`, `ssh_access_restricted`, `security_group_ssh_restricted` | T1021.004 | lateral_movement | SSH unrestricted from internet is direct remote service access |
| `port_rdp_exposed`, `security_group_rdp_restricted`, `rdp_access_restricted` | T1021.001 | lateral_movement | RDP unrestricted from internet |
| `security_group.allow_ingress_from_internet`, `security_group_internet_ingress_all_ports`, `security_group_internet_ingress_high_risk_ports` | T1190 | initial_access | Unrestricted internet ingress = public-facing attack surface |
| `security_group.network_policies_configured`, `security_group.only_required_ports_allowed`, `security_group.zero_cidr_ingress_rules_blocked` | T1190 | initial_access | Network policy misconfiguration exposes services |
| `networkacl.network_no_unrestricted_ingress`, `networkacl.ssh_port_22_restricted`, `networkacl.rdp_port_3389_restricted` | T1190 | initial_access | NACL gaps allow bypass of security group restrictions |
| `instance.public_ip_configured`, `instance.no_public_ip`, `eip.shodan_exposure_detected` | T1595 | reconnaissance | Public IPs are active scanning targets |
| `instance.no_public_ip_configured`, `launchtemplate.no_public_ip`, `spotinstance.no_public_ip` | T1190 | initial_access | Preventing public IPs mitigates internet-facing exploitation |
| `instance.secrets_user_data`, `launchtemplate.user_data_no_secrets`, `launch_template_no_secrets` | T1552 | credential_access | Secrets in user data are plaintext credential exposure |
| `ebs.public_snapshot`, `ebs_public_snapshot`, `snapshot.not_public`, `snapshot.encryption_at_rest_enabled` | T1530 | collection | Public EBS snapshots expose stored data |
| `ami.not_publicly_shared`, `resource.ami_public_visibility`, `amipublic.ami_public_configured` | T1578 | defense_evasion | Public AMIs expose system state and may contain embedded secrets |
| `activity_log.disable_guardduty`, `activity_log.disable_antimalware` | T1562.001 | defense_evasion | Disabling security tools is active defense evasion |
| `activity_log.create_vpc_endpoint`, `activity_log.modify_network_interface`, `activity_log.security_group_modify` | T1578 | defense_evasion | Infrastructure modification to create exfiltration paths |
| `activity_log.run_instances` | T1578 | impact | Unauthorized compute provisioning (cryptomining, persistence) |
| `vpc.flow_logging_enabled`, `resource.vpc_flow_logging_reject_enabled` | T1562.008 | defense_evasion | Disabling flow logs impairs network visibility |
| `ebs.volume_encryption_configured`, `volume.encryption_at_rest_enabled`, `ebs.default_encryption_configured` | T1530 | collection | Unencrypted volumes expose data if snapshot is shared |
| `vpc.default_deny_between_tiers`, `subnet.default_deny_between_tiers`, `networkacl.network_no_allow_all_rules` | T1190 | initial_access | Network segmentation failures expand the reachable attack surface |
| `keypair.disable_unused_keys`, `keypair.key_max_age_days` | T1552 | credential_access | Stale SSH keys are long-lived credential exposure |
| `transitgateway.auto_cross_account_attachment_disabled` | T1190 | initial_access | Auto-accept transit gateway attachments expand network exposure |

**Rules without a clear MITRE mapping (assign T1190 as the conservative default):**

Any remaining EC2 rule covering network exposure, public access, or resource misconfiguration that does not fit the above patterns should receive `T1190` (Exploit Public-Facing Application) as the default technique with tactic `initial_access`. This is intentionally broad but accurate — every public-facing misconfiguration is a potential exploit entry point. Document any borderline decisions in the PR description.

### Rules requiring manual review (do NOT auto-apply heuristic)

The following rule categories need individual judgment — do not auto-tag these:
- `dedicatedhost.*` — hardware isolation rules, no clear ATT&CK mapping; use T1578 (Modify Cloud Compute)
- `reserved_instance.*billing_admins_mfa`, `reserved_instance.*purchase_permissions_restricted` — billing/governance; use T1078.004
- `resource.backup_enabled` — availability; use T1485 (Data Destruction, impact tactic)
- `vpnconnection.*` — network crypto; use T1040 (Network Sniffing) for weak cipher rules

### YAML edit approach (recommended workflow)

Given 181 files, the recommended approach is a Python script that reads each YAML, applies the keyword-match mapping table above, adds the `mitre_techniques` / `mitre_tactics` / `threat_tags` / `threat_category` fields, and writes the file back. This avoids manual edit errors.

Script path (create as part of this story):
```
/Users/apple/Desktop/threat-engine/engines/threat_v1/scripts/tag_ec2_rules.py
```

The script must:
1. Read each YAML file in `/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/ec2/`
2. Apply the keyword mapping table
3. Only write files where `mitre_techniques` is not already present (idempotent)
4. Print a per-file summary: `rule_id | techniques_applied | manual_review_needed`
5. Exit non-zero if any file had no mapping (forces manual review for unmatched rules)

## Acceptance Criteria

- [ ] AC-1: All 181 YAML files in `catalog/rule/aws_rule_metadata/ec2/` have a non-empty `mitre_techniques` list after tagging
- [ ] AC-2: All 181 files have a non-empty `mitre_tactics` list
- [ ] AC-3: No technique ID is malformed — all must match the pattern `T\d{4}(\.\d{3})?` (e.g., T1190, T1552.005)
- [ ] AC-4: The tagging script (`engines/threat_v1/scripts/tag_ec2_rules.py`) is idempotent — running twice produces no changes on the second run
- [ ] AC-5: `upload_rule_metadata_all_csps.py --csp aws --type check` runs without errors after YAML edits
- [ ] AC-6: After upload, at least 145 of 181 EC2 rule_ids in `rule_metadata` table have non-null `mitre_techniques` JSONB (≥ 80% threshold for S0-05)
- [ ] AC-7: IMDSv2 rules (`aws.ec2.instance.imdsv2_enabled`, `aws.ec2.instance.imds_hardened_configured`) are tagged with `T1552.005` and tactic `credential_access`
- [ ] AC-8: SSH SG rules (`aws.ec2.security_group_ssh_restricted.ssh_access_restricted`, `aws.ec2.instance.port_ssh_exposed_to_internet_configured`) are tagged with `T1021.004` and tactic `lateral_movement`
- [ ] AC-9: All public snapshot rules (`aws.ec2.ebs.public_snapshot_configured`, `aws.ec2.snapshot.not_public_configured`) are tagged with `T1530` and tactic `collection`
- [ ] AC-10: SA has reviewed the technique mapping table (listed in Technical Notes above) and confirmed accuracy before bulk tagging runs

## Security Acceptance Criteria

- [ ] No `mitre_techniques` value contains a free-text string instead of a valid ATT&CK ID (e.g., "initial access" is invalid; "T1190" is valid)
- [ ] The tagging script does not write credentials, tokens, or connection strings to YAML files
- [ ] YAML files pass `yaml.safe_load()` after edits — no YAML syntax errors introduced
- [ ] `upload_rule_metadata_all_csps.py` is run with `--csp aws --type check` scope only (not `--csp all`) to prevent accidental overwrite of other CSP metadata

## Definition of Done

- [ ] Tagging script committed to `engines/threat_v1/scripts/tag_ec2_rules.py`
- [ ] All 181 YAML files in `catalog/rule/aws_rule_metadata/ec2/` have `mitre_techniques` present
- [ ] Upload script run successfully against check DB
- [ ] DL has reviewed the PR — specifically the technique mapping table and any manually reviewed edge cases
- [ ] SA sign-off on technique mapping accuracy (CP-0 informal review, not a formal gate)
- [ ] Verification SQL passes (see below)
- [ ] No existing tests broken (run `pytest /Users/apple/Desktop/threat-engine/tests/ -k "rule_metadata" -v`)

## Verification SQL

```sql
-- Run against the check engine DB (threat_engine_check)
-- Port-forward first: kubectl port-forward svc/engine-check 8002:80 -n threat-engine-engines
-- Then exec psql inside the check pod or copy and run via kubectl exec

-- 1. Coverage count
SELECT
    'ec2' AS service,
    COUNT(*) AS total_rules,
    COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0) AS tagged_rules,
    ROUND(
        COUNT(*) FILTER (WHERE mitre_techniques IS NOT NULL AND jsonb_array_length(mitre_techniques) > 0)::numeric
        / COUNT(*)::numeric * 100, 1
    ) AS coverage_pct
FROM rule_metadata
WHERE rule_id LIKE 'aws.ec2.%';

-- Expected result: coverage_pct >= 80.0

-- 2. Spot-check IMDSv2 rules
SELECT rule_id, mitre_techniques, mitre_tactics
FROM rule_metadata
WHERE rule_id IN (
    'aws.ec2.instance.imdsv2_enabled',
    'aws.ec2.instance.imds_hardened_configured',
    'aws.ec2.launchtemplate.imds_hardened_configured'
);
-- Expected: mitre_techniques contains 'T1552.005', mitre_tactics contains 'credential_access'

-- 3. Spot-check SSH rules
SELECT rule_id, mitre_techniques, mitre_tactics
FROM rule_metadata
WHERE rule_id IN (
    'aws.ec2.security_group_ssh_restricted.ssh_access_restricted',
    'aws.ec2.instance.port_ssh_exposed_to_internet_configured'
);
-- Expected: mitre_techniques contains 'T1021.004', mitre_tactics contains 'lateral_movement'

-- 4. Confirm no NULL technique entries in the JSONB arrays
SELECT rule_id, mitre_techniques
FROM rule_metadata
WHERE rule_id LIKE 'aws.ec2.%'
  AND mitre_techniques IS NOT NULL
  AND mitre_techniques @> 'null'::jsonb;
-- Expected: 0 rows
```