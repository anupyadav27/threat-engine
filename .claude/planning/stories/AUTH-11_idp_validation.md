---
story_id: AUTH-11
title: IDP config validation — reachability check on save
status: ready
sprint: auth-redesign-2
depends_on: [AUTH-05]
blocks: []
sme: Python backend engineer
estimate: 1 day
---

# Story: IDP Config Validation (Reachability Check on Activate)

## Context

The `TenantIDPConfigActivateView` (AUTH-05) currently returns a placeholder. This story
implements the actual reachability checks so tenant admins get immediate feedback if their
IDP config is misconfigured before they lock themselves out.

## Files to Create/Modify

- `platform/cspm-backend/tenant_management/views.py` — implement `TenantIDPConfigActivateView` validation
- `platform/cspm-backend/user_auth/utils/idp_validation.py` — NEW: validation helpers

## Implementation Notes

### OIDC Validation

```python
def validate_oidc_config(config: dict) -> tuple[bool, str]:
    """Check OIDC discovery document is reachable and contains required fields."""
    issuer = config.get("issuer", "")
    if not issuer:
        return False, "issuer is required"
    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        resp = requests.get(discovery_url, timeout=10)
        resp.raise_for_status()
        doc = resp.json()
        required = ["authorization_endpoint", "token_endpoint", "jwks_uri"]
        missing = [k for k in required if k not in doc]
        if missing:
            return False, f"Discovery document missing: {missing}"
        return True, "ok"
    except requests.Timeout:
        return False, f"Discovery URL timed out: {discovery_url}"
    except Exception as e:
        return False, str(e)
```

### SAML Validation

```python
def validate_saml_config(config: dict) -> tuple[bool, str]:
    """Fetch and parse IDP SAML metadata."""
    metadata_url = config.get("metadata_url")
    metadata_xml = config.get("metadata_xml")
    if metadata_url:
        try:
            resp = requests.get(metadata_url, timeout=10)
            resp.raise_for_status()
            # Try parsing as XML
            from xml.etree import ElementTree as ET
            ET.fromstring(resp.text)
            return True, "ok"
        except requests.Timeout:
            return False, f"Metadata URL timed out: {metadata_url}"
        except ET.ParseError as e:
            return False, f"Metadata XML parse error: {e}"
        except Exception as e:
            return False, str(e)
    elif metadata_xml:
        try:
            ET.fromstring(metadata_xml)
            return True, "ok"
        except ET.ParseError as e:
            return False, f"Metadata XML parse error: {e}"
    return False, "metadata_url or metadata_xml is required"
```

### google_oauth Validation

No network check. Validate `client_id` format (ends in `.apps.googleusercontent.com` or is non-empty).

### Activate endpoint

```python
class TenantIDPConfigActivateView(APIView):
    def post(self, request, pk):
        user = require_auth(request)
        if not user:
            return JsonResponse({"message": "Authentication required"}, status=401)
        try:
            config_obj = TenantIDPConfig.objects.get(id=pk)
        except TenantIDPConfig.DoesNotExist:
            return JsonResponse({"message": "Not found"}, status=404)
        # Auth check
        if not TenantUsers.objects.filter(user=user, tenant=config_obj.tenant, is_active=True).exists():
            return JsonResponse({"message": "Not authorized"}, status=403)

        # Validate
        ok, reason = validate_idp_config(config_obj.idp_type, config_obj.config)
        if not ok:
            return JsonResponse({"status": "validation_failed", "reason": reason})

        # Deactivate others of same type for this tenant
        TenantIDPConfig.objects.filter(
            tenant=config_obj.tenant,
            idp_type=config_obj.idp_type,
            is_active=True
        ).exclude(id=pk).update(is_active=False)

        config_obj.is_active = True
        config_obj.save(update_fields=["is_active", "updated_at"])
        return JsonResponse({"status": "activated", "idp_name": config_obj.idp_name})
```

## Acceptance Criteria

- [ ] AC1: Activating OIDC config with unreachable `issuer` returns `validation_failed` with reason
- [ ] AC2: Activating OIDC config with reachable issuer returns `activated`
- [ ] AC3: Activating SAML config with valid metadata_url returns `activated`
- [ ] AC4: Activating SAML config with unparseable metadata_xml returns `validation_failed`
- [ ] AC5: Only one IDP config per type per tenant is active at a time
- [ ] AC6: Validation timeout is 10 seconds max (does not hang indefinitely)

## Definition of Done

- [ ] Code follows Python standards
- [ ] Tests with mocked HTTP responses for reachable and unreachable IDPs
- [ ] Story accepted by SM before merge
