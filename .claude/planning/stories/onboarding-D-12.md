---
story_id: onboarding-D-12
title: Frontend — user/group management pages
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-D-1, onboarding-D-2, onboarding-D-3, onboarding-D-7]
blocks: []
sme: React/Next.js 15 engineer
estimate: 2 days
---

# Story: Frontend — user/group management pages

## User Story
As an `org_admin`, I want a Settings page where I can invite users, create groups, assign
groups to tenants, and see who has access to what, so that I can manage my team's
security permissions without using the API directly.

## Context
Stories D1-D3 add the backend APIs for groups, invites, and group access assignment.
This story builds the frontend UI for the Settings → Team section.

Pages:
1. `Settings → Users` — list org users, invite button, remove user
2. `Settings → Groups` — list groups, create/edit group, add/remove members
3. `Settings → Access` — for each tenant, show groups assigned to it, add/remove group access

**CORRECT DESIGN:** Users belong to an org via `customer_id`. The user list shows all
users where `user.customer_id = request.user.customer_id`. There is no "organization" concept
in the UI beyond what is stored as `customer_id`.

## Files to Create/Modify
- `frontend/src/app/settings/users/page.jsx` — user management page
- `frontend/src/app/settings/groups/page.jsx` — group management page
- `frontend/src/app/settings/access/page.jsx` — access assignment page
- `frontend/src/components/settings/InviteUserModal.jsx` — invite user modal
- `frontend/src/components/settings/GroupModal.jsx` — create/edit group modal
- `frontend/src/components/settings/GroupAccessModal.jsx` — assign group to tenant modal

## Implementation Notes

### Users page

```jsx
// frontend/src/app/settings/users/page.jsx
export default function UsersPage() {
  const { data: users } = useSWR('/gateway/api/v1/users/', fetcher);
  const [showInvite, setShowInvite] = useState(false);

  return (
    <div>
      <div className="flex justify-between">
        <h2>Team Members</h2>
        <Button onClick={() => setShowInvite(true)}>Invite User</Button>
      </div>
      <Table>
        <TableHeader>Name | Email | Role | Tenants | Joined</TableHeader>
        {users?.map(u => (
          <TableRow key={u.id}>
            <td>{u.email}</td>
            <td><RoleBadge role={u.role} /></td>
            <td>{u.tenant_count} tenants</td>
            <td><Button variant="ghost" size="sm">Remove</Button></td>
          </TableRow>
        ))}
      </Table>
      {showInvite && <InviteUserModal onClose={() => setShowInvite(false)} />}
    </div>
  );
}
```

### `InviteUserModal`

```jsx
export function InviteUserModal({ onClose }) {
  const { data: tenants } = useSWR('/gateway/api/v1/tenants/', fetcher);
  const [form, setForm] = useState({ email: '', tenant_id: '', role: 'viewer' });

  async function handleInvite() {
    await fetch('/gateway/api/v1/invites/', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(form),
    });
    toast.success(`Invite sent to ${form.email}`);
    onClose();
  }

  return (
    <Modal title="Invite User">
      <Input label="Email" type="email" onChange={e => setForm(f => ({...f, email: e.target.value}))} />
      <Select label="Tenant" options={tenants?.map(t => ({value: t.id, label: t.name}))}
              onChange={v => setForm(f => ({...f, tenant_id: v}))} />
      <Select label="Role" options={['viewer','analyst','tenant_admin'].map(r => ({value:r, label:r}))}
              onChange={v => setForm(f => ({...f, role: v}))} />
      <Button onClick={handleInvite}>Send Invite</Button>
    </Modal>
  );
}
```

### Groups page

- Lists all groups (from `GET /gateway/api/v1/groups/`)
- Create group → `POST /groups/`
- Edit group members → add/remove via `POST/DELETE /groups/{id}/members/`
- Delete group → `DELETE /groups/{id}/`

### Access page

- For each tenant: shows groups assigned + their role
- "Assign Group" → `GroupAccessModal` → `POST /tenants/{id}/group-access/`
- Remove → `DELETE /tenants/{id}/group-access/{access_id}/`

## Acceptance Criteria
- [ ] AC1: Users page lists all users in the org (scoped to `customer_id`)
- [ ] AC2: "Invite User" modal: email + tenant selector + role selector
- [ ] AC3: Invite submitted → `POST /gateway/api/v1/invites/` → success toast
- [ ] AC4: Groups page: create group, add members, delete group
- [ ] AC5: Access page: assign group to tenant with role, remove group access
- [ ] AC6: viewer role: Settings navigation hidden or shows read-only view
- [ ] AC7: No "organization" label in the UI — it shows tenant names only

## Definition of Done
- [ ] Users page with invite modal
- [ ] Groups page with create/edit/delete
- [ ] Access assignment page with group → tenant assignments
- [ ] All API calls use correct gateway URLs from D1-D3 stories
- [ ] Role badges consistent with existing RBAC.md role display
- [ ] Manual browser test: invite user, create group, assign group to tenant
- [ ] bmad-security-reviewer: no BLOCKERs
