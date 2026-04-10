---
story_id: AZ-17b
title: Azure SP Credential Resolution Path (Secrets Manager → ClientSecretCredential)
status: done
sprint: azure-track-wave-8
depends_on: [AZ-13]
blocks: [AZ-18]
sme: Backend engineer + Security analyst
estimate: 0.5 days
---

# Story: Azure SP Credential Resolution Path

## Context
AWS scanner resolves credentials via: `credential_ref` (e.g., `threat-engine/account/588989875114`) → `aws secretsmanager get-secret-value` → JSON dict with `access_key_id`, `secret_access_key`. Azure must follow the SAME pattern — no bare env vars in production.

The Azure SP credentials must be stored in Secrets Manager under a key like `threat-engine/azure/f6d24b5d` and the scanner resolves them at scan time, exactly like AWS.

## Files to Modify

- `engines/discoveries/providers/azure/scanner/service_scanner.py` — add credential resolution method
- `engines/onboarding/` — verify Azure credential type is stored/retrieved correctly
- `.claude/planning/multi-csp/10_CREDENTIALS_CONTEXT.md` — document the pattern

## Implementation Notes

**Resolution method (add to AzureDiscoveryScanner):**
```python
def _resolve_credentials(self, credential_ref: str) -> dict:
    """Resolve Azure SP credentials from AWS Secrets Manager.
    
    Args:
        credential_ref: e.g. 'threat-engine/azure/f6d24b5d-51ed-47b7-9f6a-0ad194156b5e'
        
    Returns:
        Dict with: tenant_id, client_id, client_secret, subscription_id
    """
    import boto3
    import json
    
    client = boto3.client("secretsmanager", region_name="ap-south-1")
    secret = client.get_secret_value(SecretId=credential_ref)
    creds = json.loads(secret["SecretString"])
    
    required_keys = {"tenant_id", "client_id", "client_secret", "subscription_id"}
    missing = required_keys - set(creds.keys())
    if missing:
        raise ValueError(
            f"Azure credentials at {credential_ref!r} missing keys: {missing}"
        )
    return creds
```

**Secret format in Secrets Manager:**
```json
{
  "tenant_id": "<entra-tenant-id>",
  "client_id": "<service-principal-app-id>",
  "client_secret": "<service-principal-secret>",
  "subscription_id": "f6d24b5d-51ed-47b7-9f6a-0ad194156b5e"
}
```

**Credential ref format:** `threat-engine/azure/{subscription_id}` (mirrors AWS: `threat-engine/account/{account_id}`)

## Acceptance Criteria
- [ ] `_resolve_credentials("threat-engine/azure/f6d24b5d-...")` returns dict with all 4 keys
- [ ] Missing key in secret → raises `ValueError` with helpful message listing missing keys
- [ ] Integration test: scanner starts with `credential_ref` from `scan_runs` table (not env var)
- [ ] Documentation updated in `10_CREDENTIALS_CONTEXT.md`

## Definition of Done
- [ ] Method implemented in scanner
- [ ] Integration tested against actual Secrets Manager secret on EKS
- [ ] No `AZURE_CLIENT_SECRET` env var reads in production code path