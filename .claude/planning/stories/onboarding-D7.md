---
id: onboarding-D7
title: "Frontend: tenant-type selector + org/tenant switcher"
sprint: D
points: 2
depends_on: [auth-A1]
blocks: [onboarding-D8]
security_blocks: []
nist_csf: DE.AE
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

Two frontend components needed before the onboarding wizard can work: (1) a tenant-type selector shown during tenant creation — the user picks `cloud`, `vulnerability`, or `secops` which determines what account types they can add in the wizard, (2) an org/tenant switcher in the top navigation bar that lets org_admins with multiple tenants switch context without logging out. The frontend uses Next.js 15 + React 19. The BFF pattern is `fetchView(page)` → `/gateway/api/v1/views/{page}`. API calls to Django go through the gateway. The `tenant_type` column exists after auth-A1. The switcher reads the list of accessible tenants from `GET /api/tenants/` (Django endpoint from B3) via the gateway.

## Acceptance Criteria

- [ ] AC1: Tenant creation form includes a `TenantTypeSelector` component with options: `Cloud` (value: `cloud`), `Vulnerability Scanning` (value: `vulnerability`), `SecOps / Code Security` (value: `secops`). Default is `cloud`.
- [ ] AC2: `TenantTypeSelector` displays a description for each option explaining what account types it enables.
- [ ] AC3: `POST /api/tenants/` call from the frontend includes `tenant_type` in the request body.
- [ ] AC4: `OrgTenantSwitcher` component appears in the top navigation bar, visible to `org_admin` and `platform_admin` roles only (hidden for `tenant_admin`, `analyst`, `viewer`).
- [ ] AC5: `OrgTenantSwitcher` fetches tenant list via `GET /gateway/api/v1/views/tenant_switcher` (BFF view to be added) and renders as a dropdown.
- [ ] AC6: Selecting a tenant from the switcher sets the active `tenant_id` in the session (via API call) and triggers a page reload to refresh all dashboard data.
- [ ] AC7: The active tenant name and type badge are visible in the switcher trigger button (e.g., "FinVault AWS [Cloud]").
- [ ] AC8: Components follow the existing design system — use `shadcn/ui` components if present, matching sidebar/nav styling.
- [ ] AC9: Loading skeleton shown while tenant list is fetching.
- [ ] AC10: If the user has only one tenant, the switcher renders as a static label (no dropdown affordance).

## Key Files

- `frontend/src/components/onboarding/TenantTypeSelector.tsx` — Create
- `frontend/src/components/nav/OrgTenantSwitcher.tsx` — Create
- `frontend/src/app/(portal)/onboarding/create-tenant/page.tsx` — Integrate TenantTypeSelector
- `frontend/src/components/nav/` — Integrate OrgTenantSwitcher into top nav
- `shared/api_gateway/bff/onboarding_cloud_accounts.py` — Add `view_tenant_switcher()` BFF view

## Technical Notes

**Check existing nav structure:**
```bash
ls /Users/apple/Desktop/threat-engine/frontend/src/components/nav/ 2>/dev/null
ls /Users/apple/Desktop/threat-engine/frontend/src/components/layout/ 2>/dev/null
```

**TenantTypeSelector component sketch:**
```tsx
// components/onboarding/TenantTypeSelector.tsx
'use client';

const TENANT_TYPES = [
  { value: 'cloud', label: 'Cloud', description: 'AWS, Azure, GCP, OCI, AliCloud accounts' },
  { value: 'vulnerability', label: 'Vulnerability Scanning', description: 'Agent-based vulnerability scanning' },
  { value: 'secops', label: 'SecOps / Code Security', description: 'Git repositories and IaC scanning' },
];

export function TenantTypeSelector({ value, onChange }) {
  return (
    <RadioGroup value={value} onValueChange={onChange}>
      {TENANT_TYPES.map(type => (
        <RadioGroupItem key={type.value} value={type.value}>
          <span className="font-medium">{type.label}</span>
          <span className="text-sm text-muted-foreground">{type.description}</span>
        </RadioGroupItem>
      ))}
    </RadioGroup>
  );
}
```

**BFF view for tenant switcher:**
```python
# onboarding_cloud_accounts.py
def view_tenant_switcher(auth_context: dict) -> dict:
    """Returns tenants accessible to the caller for the switcher dropdown."""
    # Call Django tenant list endpoint
    resp = requests.get(
        f"{DJANGO_URL}/api/tenants/",
        headers={"X-Auth-Context": json.dumps(auth_context)},
        timeout=5,
    )
    if resp.status_code != 200:
        return {"tenants": [], "active_tenant_id": auth_context.get("tenant_id")}
    tenants = resp.json()
    return {
        "tenants": [
            {"tenant_id": t["id"], "name": t["name"], "tenant_type": t.get("tenant_type", "cloud")}
            for t in tenants
        ],
        "active_tenant_id": auth_context.get("tenant_id"),
    }
```

**Tenant type badge color scheme (match severity colors):**
- `cloud` → blue badge
- `vulnerability` → orange badge
- `secops` → purple badge

**RBAC in frontend — hide switcher from non-org_admin:**
```tsx
// Check role from auth context
const { role } = useAuthContext();
if (!['org_admin', 'platform_admin'].includes(role)) return null;
```

**Existing auth context hook:**
```bash
grep -rn "useAuthContext\|useAuth\|AuthContext" \
  /Users/apple/Desktop/threat-engine/frontend/src/ --include="*.tsx" | head -10
```

**fetchView usage:**
```tsx
import { fetchView } from '@/lib/api';
const data = await fetchView('tenant_switcher');
```

## Security Checklist

- [ ] `OrgTenantSwitcher` rendered only for `org_admin` and `platform_admin` roles
- [ ] Tenant switching uses a server API call — not a client-side local state change
- [ ] No hardcoded tenant IDs or credentials in frontend
- [ ] `fetchView` is the only data-fetching method (no direct engine calls from frontend)
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `TenantTypeSelector` renders all 3 options with descriptions
- [ ] `OrgTenantSwitcher` hidden for `viewer` role
- [ ] Loading skeleton present during tenant list fetch
- [ ] BFF `view_tenant_switcher` registered and tested
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] Frontend build succeeds (`npm run build` no errors)
- [ ] Visual QA: switcher renders correctly in the top nav