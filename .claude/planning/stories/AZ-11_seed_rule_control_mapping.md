---
story_id: AZ-11
title: Seed rule_control_mapping + Update mitre_technique_reference.azure_checks
status: done
sprint: azure-track-wave-3
depends_on: [AZ-08, AZ-09]
blocks: [AZ-13]
sme: Compliance / Backend
estimate: 1 day
---

# Story: Seed Azure Rule → CIS Control Mapping + MITRE Reference

## Context
Two tables need populating after rules (AZ-09) and the CIS framework (AZ-08) are seeded:

1. `rule_control_mapping` — links each `rule_id` to its CIS Azure 1.5 `control_id`
   (enables compliance scoring: "X% of CIS 1.1 controls pass")

2. `mitre_technique_reference.azure_checks` — JSONB array of Azure rule_ids per MITRE technique
   (enables "Which MITRE technique T1530 is detected by which Azure rules?")

## Files to Create

- `consolidated_services/database/migrations/026_seed_azure_rule_control_mapping.sql`
  Maps each Azure rule_id → CIS Azure 1.5 control
- `consolidated_services/database/migrations/027_update_mitre_azure_checks.sql`
  Populates `azure_checks` column in `mitre_technique_reference`

## Implementation Notes

### rule_control_mapping

control_id format: `cis_azure_1_5_<section>_<num>` e.g., `cis_azure_1_5_3_5`

Key mappings:
```sql
-- Storage
('azure_storage_public_access_disabled', 'cis_azure_1_5_3_5', 'cis_azure_1_5'),
('azure_storage_https_only',              'cis_azure_1_5_3_1', 'cis_azure_1_5'),
('azure_storage_tls_version_12',          'cis_azure_1_5_3_2', 'cis_azure_1_5'),
('azure_storage_blob_soft_delete',        'cis_azure_1_5_3_9', 'cis_azure_1_5'),
-- IAM
('azure_iam_mfa_all_users',    'cis_azure_1_5_1_1',  'cis_azure_1_5'),
('azure_iam_no_legacy_auth',   'cis_azure_1_5_1_3',  'cis_azure_1_5'),
-- Networking
('azure_nsg_no_allow_all_inbound', 'cis_azure_1_5_6_1', 'cis_azure_1_5'),
('azure_nsg_rdp_restricted',       'cis_azure_1_5_6_2', 'cis_azure_1_5'),
-- ... all 500+ rules mapped to their controls
```

Also add NIST 800-53 mappings where compliance_frameworks JSONB already has them:
```sql
-- Rule azure_storage_public_access_disabled also maps to NIST AC-3
INSERT INTO rule_control_mapping (rule_id, control_id, framework_id)
VALUES ('azure_storage_public_access_disabled', 'nist_800_53_ac_3', 'nist_800_53')
ON CONFLICT (rule_id, control_id) DO NOTHING;
```

### mitre_technique_reference.azure_checks

```sql
UPDATE mitre_technique_reference
SET azure_checks = '["azure_storage_public_access_disabled", "azure_storage_blob_soft_delete"]'::jsonb
WHERE technique_id = 'T1530';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_mfa_all_users", "azure_iam_no_legacy_auth", "azure_iam_sp_credential_rotation"]'::jsonb
WHERE technique_id = 'T1078.004';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_sql_no_allow_all_firewall", "azure_appservice_https_only"]'::jsonb
WHERE technique_id = 'T1190';

UPDATE mitre_technique_reference
SET azure_checks = '["azure_iam_mfa_all_users", "azure_iam_no_permanent_admin"]'::jsonb
WHERE technique_id = 'T1098.001';
```

## Acceptance Criteria
- [ ] `SELECT count(*) FROM rule_control_mapping WHERE framework_id='cis_azure_1_5'` >= 200
- [ ] `SELECT count(*) FROM mitre_technique_reference WHERE azure_checks != '[]'` >= 8
- [ ] Compliance engine can generate a CIS Azure 1.5 score: `GET /compliance/score?framework=cis_azure_1_5`
- [ ] Migrations idempotent (ON CONFLICT DO NOTHING)

## Definition of Done
- [ ] Both migrations committed and applied
- [ ] Compliance scoring for Azure produces non-zero output