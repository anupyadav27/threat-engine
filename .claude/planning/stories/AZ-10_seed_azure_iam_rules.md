---
story_id: AZ-10
title: Seed Azure IAM Rules (EntraID / RBAC) + Tag for IAM Engine
status: done
sprint: azure-track-wave-3
depends_on: [AZ-09]
blocks: [AZ-13]
sme: IAM / Security engineer
estimate: 1 day
---

# Story: Seed Azure IAM Rules for EntraID/RBAC

## Context
The IAM engine reads `rule_metadata` rows that are tagged for IAM analysis (via `iam_security` JSONB
or `service='iam'`). AZ-09 seeds all Azure rules including some IAM-relevant ones. This story
ensures the IAM-engine-specific tagging is correct and adds any IAM-only rules not covered by AZ-09.

The IAM engine uses `iam_modules` (JSONB) per finding to group rules — for Azure this should
be `"azure_ad"`.

## Files to Modify/Create

- Adds `iam_security` JSONB tags to Azure IAM rules seeded by AZ-09
- Creates `consolidated_services/database/migrations/027_tag_azure_iam_rules.sql` (UPDATE, not INSERT)

## Implementation Notes

After AZ-09 seeds the IAM rules, this migration adds `iam_security` JSONB tagging:

```sql
UPDATE rule_metadata
SET iam_security = '{"module": "azure_ad", "iam_category": "identity"}'::jsonb
WHERE provider = 'azure'
  AND service IN ('iam', 'authorization')
  AND rule_id LIKE 'azure_iam_%';

UPDATE rule_metadata
SET iam_security = '{"module": "azure_ad", "iam_category": "rbac"}'::jsonb
WHERE provider = 'azure'
  AND rule_id LIKE 'azure_rbac_%';
```

### Additional IAM-only rules (not in AZ-09's 9 service categories):

```python
# rules to add in seed_azure_iam_rules.py (or append to seed_azure_check_rules.py)

"azure_iam_no_direct_user_role_assignments"  # Use groups, not direct user assignments
"azure_iam_no_stale_guest_accounts"          # Guest accounts inactive >90 days
"azure_iam_emergency_access_accounts_exist"  # Break-glass accounts configured
"azure_iam_custom_role_reviewed"             # No custom owner-equivalent roles
"azure_rbac_no_owner_at_subscription_scope_non_admin"
"azure_rbac_key_vault_uses_rbac_model"       # not legacy access policies
"azure_sp_cert_preferred_over_password"      # Service principals: use cert not secret
"azure_sp_no_expired_credentials"
"azure_app_registration_credential_expiry"
"azure_managed_identity_preferred"           # Prefer managed identity over SP with credentials
```

## Acceptance Criteria
- [ ] `SELECT count(*) FROM rule_metadata WHERE provider='azure' AND iam_security != '{}'` >= 30
- [ ] IAM engine can list Azure rules via `/api/v1/iam/rules?provider=azure`
- [ ] `iam_security->>'module' = 'azure_ad'` set on all Azure IAM rules

## Definition of Done
- [ ] Migration committed and applied
- [ ] IAM engine Azure run returns findings (not empty) after AZ-13 scan