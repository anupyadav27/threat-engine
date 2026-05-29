# DI-S2-02 — API Gateway Update (Route /api/v1/di → engine-di)
**Sprint**: DI-S2 | **Points**: 3 | **Status**: Ready for Dev

## Goal
Add engine-di routing to the central API gateway. Add `DI_ENGINE_URL` env var to the gateway
manifest and ConfigMap. After cutover (DI-S4-03), remove the discoveries and inventory routing
entries; this story only adds engine-di.

## Files to Modify
- `shared/api_gateway/main.py` — add `"di"` engine entry
- `deployment/aws/eks/engines/cspm-portal.yaml` — add `DI_ENGINE_URL` env var
- `deployment/aws/eks/configmaps/threat-engine-db-config.yaml` — add `DI_ENGINE_URL` key

## Changes to main.py

```python
# In the ENGINES dict (or equivalent routing configuration):
"di": {
    "url": os.getenv("DI_ENGINE_URL", "http://engine-di"),
    "prefixes": ["/api/v1/di"],
},
```

The existing `discoveries` and `inventory` entries remain unchanged until DI-S4-03 cutover.

## Changes to cspm-portal.yaml (api-gateway deployment)
```yaml
- name: DI_ENGINE_URL
  value: "http://engine-di.threat-engine-engines.svc.cluster.local"
```

## Acceptance Criteria

### Functional
- [ ] `GET /gateway/api/v1/di/assets` proxied to engine-di → 200 (auth-required)
- [ ] `POST /gateway/api/v1/di/scan` proxied to engine-di → 202
- [ ] `GET /gateway/api/v1/di/health/live` proxied → 200
- [ ] Existing `/api/v1/discoveries/` and `/api/v1/inventory/` routes unaffected
- [ ] `DI_ENGINE_URL` environment variable configurable (can point to port-forward for local test)

### Security
- [ ] `require_permission()` enforced by engine-di; gateway passes `X-Auth-Context` header
- [ ] No double-auth: gateway AuthMiddleware validates token; engine re-validates via `X-Auth-Context`

### Error Handling
- [ ] engine-di pod not running → gateway returns 502 (not 500)
- [ ] `DI_ENGINE_URL` not set → `KeyError` at startup → startup fails loudly (not silently None)

## Testing Requirements

**Integration**: `GET /gateway/api/v1/di/health/live` via ELB → 200

**Post-deploy smoke**:
```bash
kubectl logs -f -l app=cspm-portal -n threat-engine-engines --tail=50 | grep -i "di"
# Expected: DI_ENGINE_URL logged at startup
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `main.py` `"di"` entry added
- [ ] `cspm-portal.yaml` `DI_ENGINE_URL` env added; image tag updated
- [ ] `/gateway/api/v1/di/health/live` → 200 via ELB
- [ ] Existing routes unaffected
- [ ] MEMORY.md: gateway DI_ENGINE_URL added

## Dependencies
- DI-S1-06 (engine-di deployed)

## Rollback
Remove `"di"` entry from `main.py`; remove `DI_ENGINE_URL` from `cspm-portal.yaml`; redeploy gateway.