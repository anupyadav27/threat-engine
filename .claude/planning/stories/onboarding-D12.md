---
id: onboarding-D12
title: "Frontend: user/group management pages"
sprint: D
points: 2
depends_on: [onboarding-D1, onboarding-D2, onboarding-D3]
blocks: []
security_blocks: []
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

The Django APIs for group management (D1, D3) and user invite (D2) are live. This story builds the frontend pages to expose these capabilities: (1) a Users page listing current org users with their roles, an "Invite User" button, and a user detail drilldown, (2) a Groups page listing groups with their members and access assignments (tenants/accounts), (3) an "Edit Group" drawer for adding/removing members and managing tenant/account assignments. These pages are under `(portal)/users/` and `(portal)/groups/`. They are visible only to `org_admin` and `platform_admin`. The pages use `fetchView()` for read operations and direct API calls via the gateway for mutations (invite, create group, assign).

## Acceptance Criteria

- [ ] AC1: `(portal)/users/` page renders a table of org users with columns: Name, Email, Role, Status (Active/Pending), Joined At.
- [ ] AC2: "Invite User" button opens an `InviteUserModal` with fields: Email (text), Role (select: org_admin|tenant_admin|analyst|viewer), Group (optional select).
- [ ] AC3: Submitting the invite modal calls `POST /gateway/api/v1/users/invite` and shows a success toast "Invite sent to {email}".
- [ ] AC4: Users page is accessible only to `org_admin` and `platform_admin` — `tenant_admin` redirected to 403 page.
- [ ] AC5: `(portal)/groups/` page renders a list of groups with: Group Name, Member Count, Tenants assigned, Accounts assigned.
- [ ] AC6: "New Group" button opens a `CreateGroupModal` with Name and Description fields. Calls `POST /gateway/api/v1/groups/`.
- [ ] AC7: Clicking a group name opens an `EditGroupDrawer` showing current members and a "Add Member" search/select.
- [ ] AC8: `EditGroupDrawer` has tabs: "Members", "Tenants", "Accounts". Each tab shows current assignments with a Remove button and an Add button.
- [ ] AC9: Remove member calls `DELETE /gateway/api/v1/groups/{id}/members/{user_id}/`.
- [ ] AC10: Groups page is accessible only to `org_admin` and `platform_admin`.
- [ ] AC11: Loading skeleton shown while user/group list is fetching.
- [ ] AC12: BFF views `view_users()` and `view_groups()` added to `shared/api_gateway/bff/` to back the read operations.

## Key Files

- `frontend/src/app/(portal)/users/page.tsx` — Users list page
- `frontend/src/app/(portal)/groups/page.tsx` — Groups list page
- `frontend/src/components/users/InviteUserModal.tsx` — Invite user form
- `frontend/src/components/groups/CreateGroupModal.tsx` — Create group form
- `frontend/src/components/groups/EditGroupDrawer.tsx` — Group member/access management
- `shared/api_gateway/bff/onboarding_cloud_accounts.py` — Add `view_users()` and `view_groups()` BFF views

## Technical Notes

**Check existing user pages:**
```bash
ls /Users/apple/Desktop/threat-engine/frontend/src/app/\(portal\)/ 2>/dev/null
grep -rn "users\|members\|groups" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/\(portal\)/ 2>/dev/null | head -10
```

**BFF `view_users` handler:**
```python
def view_users(auth_context: dict) -> dict:
    """List org users for the authenticated customer."""
    resp = requests.get(
        f"{DJANGO_URL}/api/users/",
        headers={"X-Auth-Context": json.dumps(auth_context)},
        timeout=5,
    )
    if resp.status_code != 200:
        raise ServiceUnavailableError("User service unavailable")
    users = resp.json()
    return {
        "users": [
            {
                "user_id": u["id"],
                "email": u["email"],
                "role": u.get("role", "viewer"),
                "is_active": u.get("is_active", False),
                "date_joined": u.get("date_joined"),
            }
            for u in users
        ],
        "total": len(users),
    }
```

**BFF `view_groups` handler:**
```python
def view_groups(auth_context: dict) -> dict:
    resp = requests.get(
        f"{DJANGO_URL}/api/groups/",
        headers={"X-Auth-Context": json.dumps(auth_context)},
        timeout=5,
    )
    resp.raise_for_status()
    groups = resp.json()
    return {
        "groups": [
            {
                "group_id": g["id"],
                "name": g["name"],
                "description": g.get("description", ""),
                "member_count": g.get("member_count", 0),
                "tenant_assignments": g.get("tenant_assignments", []),
                "account_assignments": g.get("account_assignments", []),
            }
            for g in groups
        ],
        "total": len(groups),
    }
```

**InviteUserModal:**
```tsx
// components/users/InviteUserModal.tsx
export function InviteUserModal({ onSuccess }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('analyst');
  const [groupId, setGroupId] = useState('');

  const handleInvite = async () => {
    await fetch('/gateway/api/v1/users/invite', {
      method: 'POST',
      body: JSON.stringify({ email, role, group_id: groupId || undefined }),
    });
    toast.success(`Invite sent to ${email}`);
    onSuccess();
  };
  ...
}
```

**Role guard for pages:**
```tsx
// users/page.tsx
const { role } = useAuthContext();
if (!['org_admin', 'platform_admin'].includes(role)) {
  redirect('/portal/403');
}
```

**EditGroupDrawer tabs:**
```tsx
<Tabs defaultValue="members">
  <TabsList>
    <TabsTrigger value="members">Members ({group.member_count})</TabsTrigger>
    <TabsTrigger value="tenants">Tenants</TabsTrigger>
    <TabsTrigger value="accounts">Accounts</TabsTrigger>
  </TabsList>
  <TabsContent value="members">
    {/* member list + add/remove */}
  </TabsContent>
  ...
</Tabs>
```

**Gateway routes needed (verify or add):**
- `POST /gateway/api/v1/users/invite` → Django `/api/users/invite`
- `GET /gateway/api/v1/groups/` → Django `/api/groups/`
- `POST /gateway/api/v1/groups/` → Django `/api/groups/`
- `POST /gateway/api/v1/groups/{id}/members/` → Django `/api/groups/{id}/members/`
- `DELETE /gateway/api/v1/groups/{id}/members/{user_id}/` → Django

Check gateway routing:
```bash
grep -rn "users/invite\|api/groups" \
  /Users/apple/Desktop/threat-engine/shared/api_gateway/ --include="*.py"
```

## Security Checklist

- [ ] Users and Groups pages accessible only to `org_admin` and `platform_admin`
- [ ] `customer_id` set server-side on invite — not user-editable
- [ ] No cross-org data visible (enforced by Django API + org boundary from B4)
- [ ] No hardcoded user IDs or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `tenant_admin` redirected to 403 on Users and Groups pages
- [ ] Invite modal sends email via Django → SES
- [ ] Group create, member add, member remove all work end-to-end
- [ ] BFF `view_users` and `view_groups` contract tests added
- [ ] Frontend build succeeds
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-frontend -n threat-engine-engines` shows AVAILABLE
