# JNY-03 — Django + RBAC handoff (DESIGN phase)

**Authors:** cspm-django-engineer + cspm-rbac-guardian (R)
**Accountable:** bmad-security-architect
**Date:** 2026-05-04

---

## 1. Verdict on existing migration `0013_ciem_sensitive_permission.py`

**Verdict: ACCEPT with minor gaps.**

What it does correctly:
- Creates `Permissions` row `ciem:sensitive` (feature=`ciem`, action=`sensitive`, `tenant_scoped=False`), idempotent via `get_or_create`.
- Grants to `analyst`, `tenant_admin`, `org_admin`, `platform_admin` — exactly matches RBAC.md row 60 (viewer correctly excluded).
- Idempotent role lookup (skips silently if role missing).
- Forward uses `RunPython`; `noop_reverse` keeps the grant on rollback.
- Dependency `("user_auth", "0012_token_hint_index")` — correct.

Gaps vs story spec:
- **Reverse semantics:** story AC #1 expects "forward + reverse on a fresh DB". `noop_reverse` is technically reversible (no-op succeeds), but does not strip the grant. Recommend keeping noop (preserves audit history) and amending AC, OR add true delete logic. Decision needed from bmad-security-architect.
- **Seed file (`platform/cspm-backend/user_auth/seeds/roles.py`) does not exist** — story §What-to-build #3 references a missing path. The seed of record appears to be migration `0009_seed_roles_permissions`; migration 0013 effectively *is* the seed update.
- **Audit log on apply (story AC #5) missing** — see §6.

## 2. Renumbering needed?

**No.** Latest applied migration is `0012_token_hint_index.py`. `0013_ciem_sensitive_permission.py` is the correct next number, dependency chain is clean. File is currently untracked — needs `git add` before PR.

## 3. RBAC matrix diff (`.claude/documentation/RBAC.md`)

**Already updated.** Line 60 already shows:
```
| `ciem:sensitive` | — | Y | Y | Y | Y |
```
Line 264 already references migration 0013.

**Diff still needed** — add a rationale note after the §Permissions table (~line 84):

```
Note: `ciem:sensitive` gates identity entitlement detail (principal policies,
last-used keys, cross-account trust). Granted to analyst+ — viewer is
intentionally excluded for the same reason as `datasec:sensitive`. Enforced
at the BFF layer (`shared/api_gateway/bff/inventory.py`); engine endpoints
require only `ciem:read`. Both grants are needed for the Inventory CIEM tab.
```

## 4. Permission inheritance: `ciem:sensitive` ⇒ `ciem:read`?

**Decision: ORTHOGONAL — no inheritance.** `RolePermissions` is a flat M:N; no implicit inheritance graph. RBAC.md grants both to analyst+ explicitly, which is the project convention.

**Decorator behavior (verified):**
- `engines/ciem/ciem_engine/api_server.py` uses `require_permission("ciem:read")` exclusively (no engine endpoint requires `ciem:sensitive`).
- BFF enforces `ciem:sensitive` directly: `shared/api_gateway/bff/inventory.py:719` and `:1462` do `if "ciem:sensitive" not in ctx.permissions: 403`.
- Net effect: the CIEM tab needs **both** `ciem:read` (engine call downstream) AND `ciem:sensitive` (BFF gate). Viewer has `ciem:read` only — they hit the engine directly OK but 403 at BFF. Intended.

No code change needed. Document the dual-check in the §Permissions note (see §3).

## 5. Test fixture sketch

`platform/cspm-backend/user_auth/tests/conftest.py` does not exist (only `test_auth_b1.py`). Proposed:

```python
# platform/cspm-backend/user_auth/tests/conftest.py
import pytest
from user_auth.models import Roles

@pytest.fixture
def platform_admin_perms(db):
    role = Roles.objects.get(name="platform_admin")
    perms = list(role.role_permissions.values_list("permission__key", flat=True))
    assert "ciem:sensitive" in perms, "JNY-03 migration 0013 not applied"
    return perms
```

For BFF/engine tests that mock `AuthContext`: locate the canonical mock builder
(`shared/auth/fastapi/testing.py` if it exists, else project `tests/conftest.py`)
and add `"ciem:sensitive"` to the default `platform_admin` permission list.
Single point of change so future engine tests inherit it.

Regression test (per story §Files-touched): `engines/ciem/tests/test_auth.py` —
assert `admin@cspm.local` gets 200 on the BFF endpoint and that viewer gets 403.

## 6. Audit-log hook plan (W-1 ship-gate)

**Two distinct events; two hook sites.**

**(a) Permission grant event (one-time, at migration apply):**
Story AC #5 requires this. Append a second `RunPython` step or extend
`add_ciem_sensitive_permission` to write one `audit_logs` row:
```python
AuditLog.objects.create(
    actor="system:migration",
    action="rbac.permission.granted",
    target="role:platform_admin,org_admin,tenant_admin,analyst",
    details={"permission": "ciem:sensitive", "migration": "0013"},
)
```
Confirm `audit_logs` model exists in `user_auth`; if not, this becomes a JSON
log line via `logging.getLogger("audit")` until the schema lands.

**(b) Per-access event (every CIEM tab load):**
Hook in **BFF, not engine, not Django.** The BFF is the single chokepoint
where `ciem:sensitive` is checked. Add immediately after the permission gate
at `shared/api_gateway/bff/inventory.py:719` and `:1462`:
```python
if "ciem:sensitive" not in ctx.permissions:
    raise HTTPException(403, "...")
audit.emit(
    actor=ctx.user_id, tenant=ctx.tenant_id,
    action="ciem.sensitive.read",
    target=uid,                      # or principal arn
    permission="ciem:sensitive",
    request_id=ctx.request_id,
)
```
Sink: async producer to `audit_logs` table (preferred) or structured log
line consumed by the existing audit pipeline. Confirm canonical path with
bmad-security-architect.

## 7. Open questions for bmad-security-architect (A)

1. **Reverse migration policy** — accept `noop_reverse` (preserves grant history) or require true reverse (delete `RolePermissions` rows)? Story AC #1 is ambiguous.
2. **Seed module** — is `0009_seed_roles_permissions` the seed of record, or should we create `user_auth/seeds/roles.py` per story §What-to-build #3?
3. **`audit_logs` schema** — does it already accept `action="ciem.sensitive.read"` and `action="rbac.permission.granted"`, or do new enum values need to ship in this story?
4. **`tenant_scoped=False`** on the new permission — confirm correct. Entitlements are always viewed in tenant context; downstream scope check should still bite via `ctx.tenant_ids`.
5. **Stale import path** — `engines/ciem/ciem_engine/api_server.py:45` imports from `engine_auth.fastapi.dependencies` but shared module lives at `shared/auth/fastapi/`. Pre-existing, not in scope for JNY-03, but flagging — may indicate broken auth in fresh containers.

---

JNY-03: migration 0013 status = ACCEPT-with-minor-gaps. Roles granted = [analyst, tenant_admin, org_admin, platform_admin]. Audit-log hook = BFF inventory.py (post-permission-check, both endpoints). Open question: noop_reverse vs true reverse on AC #1?
