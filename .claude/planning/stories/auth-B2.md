---
id: auth-B2
title: "Google OAuth hd domain validation"
sprint: B
points: 1
depends_on: []
blocks: []
security_blocks: [BLOCK-03]
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: IAM-09
---

## Context

BLOCK-03 from the security architect review identified that the Google OAuth callback in Django does not validate the `hd` (hosted domain) claim in the Google ID token. Without this check, any Google account user (personal Gmail, other corporate domains) can log in to the platform as long as Google authentication succeeds. The platform is a B2B product — only users from invited domains or verified corporate accounts should authenticate. This story adds `hd` domain validation to the Google OAuth callback: if `GOOGLE_ALLOWED_DOMAINS` env var is set (comma-separated list), reject tokens whose `hd` claim is not in the list. If the env var is empty/unset, allow all (backward-compatible for dev). Also add logging for rejected OAuth attempts. The existing Google OAuth handler is in `platform/cspm-backend/user_auth/` — find the social auth callback view.

## Acceptance Criteria

- [ ] AC1 (BLOCK-03): Google OAuth callback validates the `hd` claim in the decoded Google ID token.
- [ ] AC2: If `GOOGLE_ALLOWED_DOMAINS` env var is set (e.g., `"acme.com,finvault.io"`), any OAuth token with `hd` not in that list returns HTTP 403 with `{"detail": "Domain not authorized for this platform"}`.
- [ ] AC3: If `GOOGLE_ALLOWED_DOMAINS` is empty string or not set, all `hd` values are accepted (backward-compatible).
- [ ] AC4: Personal Gmail accounts (`hd` field absent in token) are rejected when `GOOGLE_ALLOWED_DOMAINS` is set to any non-empty value.
- [ ] AC5: Rejected OAuth attempts are logged at WARNING level with the rejected email domain (not the full email).
- [ ] AC6: Valid domain OAuth attempts continue to work end-to-end (no regression on existing Google OAuth flow).
- [ ] AC7: The `GOOGLE_ALLOWED_DOMAINS` setting is documented in a comment next to where it is read from `os.environ`.
- [ ] AC8: Unit tests: valid hd passes; invalid hd returns 403; no hd (personal Gmail) returns 403 when domains configured; empty env allows all.

## Key Files

- `platform/cspm-backend/user_auth/views/` — Locate and modify the Google OAuth callback handler
- `platform/cspm-backend/user_auth/utils/oauth.py` (create if not exists) — `validate_google_hd(id_token: dict) -> bool`
- `deployment/aws/eks/engines/cspm-backend.yaml` — Add `GOOGLE_ALLOWED_DOMAINS` env var (empty string default)

## Technical Notes

**Locate Google OAuth handler:**
```bash
grep -r "google\|oauth\|social_auth\|hd" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py" -l
```

**Validation function:**
```python
# user_auth/utils/oauth.py
import os
import logging

logger = logging.getLogger(__name__)

def validate_google_hd(id_token_claims: dict) -> bool:
    """
    Validate that the Google OAuth token's hd (hosted domain) is in the allowed list.
    Returns True if valid, False if rejected.
    """
    allowed_raw = os.environ.get("GOOGLE_ALLOWED_DOMAINS", "").strip()
    if not allowed_raw:
        return True  # no restriction configured

    allowed_domains = {d.strip().lower() for d in allowed_raw.split(",")}
    hd = id_token_claims.get("hd", "").lower()

    if not hd or hd not in allowed_domains:
        logger.warning(
            "Google OAuth rejected: domain='%s' not in allowed_domains", hd or "(none)"
        )
        return False
    return True
```

**Integration point in OAuth callback view:**
```python
from user_auth.utils.oauth import validate_google_hd

# Inside the Google callback handler, after decoding id_token:
if not validate_google_hd(id_token_claims):
    return Response(
        {"detail": "Domain not authorized for this platform"}, status=403
    )
```

**K8s env var (add to cspm-backend Deployment):**
```yaml
- name: GOOGLE_ALLOWED_DOMAINS
  value: ""  # set to "acme.com,finvault.io" per customer deployment
```

**Note:** The `hd` claim is only present for Google Workspace accounts. Personal Gmail accounts will have no `hd` field — treat `hd=None` as rejected when allowed_domains is configured.

## Security Checklist

- [ ] `require_permission()` N/A — OAuth callback is pre-auth endpoint
- [ ] `tenant_id` N/A — pre-auth context
- [ ] No hardcoded domain lists — loaded from `GOOGLE_ALLOWED_DOMAINS` env var
- [ ] Rejected login attempts logged at WARNING (domain only, not full email)
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits in changed files
- [ ] Unit tests: 4 test cases (valid hd, invalid hd, no hd, empty env)
- [ ] bmad-security-reviewer: no BLOCKERs (BLOCK-03 resolved)
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: existing Google OAuth login still works for authorized domain
