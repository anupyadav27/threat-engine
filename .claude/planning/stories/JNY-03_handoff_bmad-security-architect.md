# JNY-03 Handoff — bmad-security-architect (Accountable, CP-1 design gate)

**Frameworks applied:** STRIDE, NIST CSF 2.0 PR.AC/DE.AE, OWASP SAMM, CSA CCM IAM-09/LOG-08, ISO 27001 A.9.2/A.12.4, SOC2 CC6.1/CC7.2

## 1. Verdict: APPROVE WITH CHANGES

Design is sound: minimum-surface RBAC delta, sequential ownership-then-CIEM call already implemented in `shared/api_gateway/bff/inventory.py` (`view_asset_ciem` L705 and `view_inventory_ciem` L1450), audit logger wired for the latter. Three concrete gaps must close before merge.

**Key finding:** migration `0013_ciem_sensitive_permission.py` already grants `ciem:sensitive` to **four** roles (analyst, tenant_admin, org_admin, platform_admin) — broader than the JNY-03 story title ("platform_admin only") implies. Acceptable per least-privilege analysis below, but the story doc must be reconciled to the migration.

## 2. STRIDE table

| Threat | Vector | Mitigation | Residual | Action |
|---|---|---|---|---|
| **Spoofing** | Viewer forges cookie/`X-Auth-Context` to fake analyst role | Gateway AuthMiddleware validates session and emits `X-Auth-Context`; BFF reads from `request.state.auth_context`, not raw header; engines are ClusterIP behind NetworkPolicy | Low | SHIP-GATE: verify NetworkPolicy denies non-gateway pods → engine pods |
| **Tampering** | Mutate `X-Auth-Context` between gateway and engine | Gateway is the only injector; in-cluster transport only. **No HMAC** on the header today. | Medium — any compromised in-cluster pod can forge context | Add HMAC signature (shared secret) — separate hardening story, **not blocking JNY-03**. Document residual in RBAC.md. |
| **Repudiation** | Analyst views identity_arn, later denies | Audit log present in `view_inventory_ciem` (L1504-1511). **NOT** present in `view_asset_ciem` (L705) and **NOT** present in `/ciem_identity` (`bff/ciem_identity.py` — no permission gate AND no audit log) | **High gap** | **MUST-FIX PRE-MERGE** (see §4) |
| **Information disclosure** | `identity_arn`, `privilege_level`, `last_used_days`, `unused_permission_count` reach under-privileged user | `ciem:sensitive` gate blocks viewer/auditor/dev/security_engineer. ARN is not GDPR PII but is sensitive infra metadata (CSA CCM IAM-09); privilege_level + unused_permission_count are recon gold. | Medium — `/ciem_identity` is the leak point today | Same fix as Repudiation. Prefer 403 over silent field-stripping. |
| **DoS** | Authenticated analyst hammers `/inventory/{uid}/ciem` (`limit=500`) | No per-user rate limit at BFF; CIEM query indexed on `resource_uid+tenant_id` | Low-Medium | SHIP-GATE: 60 req/min per-user limit on `/inventory/*/ciem` and `/ciem_identity` |
| **EoP** | `ciem:sensitive` implicitly grants other ciem:* | Permission check is **exact string match** (`"ciem:sensitive" not in ctx.permissions`); no wildcard expansion. Migration 0013 adds only this one permission. | None | None |

## 3. Role-breadth recommendation

Story title says "platform_admin only"; migration 0013 grants to **analyst + tenant_admin + org_admin + platform_admin**. ADR §2.2 G-3 and BFF docstring (L712) say "analyst+". This is **the correct least-privilege call**:

- Analysts run investigations — denying breaks the journey unification goal and forces ticket-based escalation.
- Auditor/viewer/dev/security_engineer correctly excluded.
- The four granted roles already see other sensitive data (threat findings, IAM findings) — no new data class exposure.

**Action:** keep migration as-is; **update the story doc** to match (currently under-specifies vs. what's shipping → fails any future doc-vs-code audit).

## 4. Audit-log requirements

Mandatory fields (SOC2 CC7.2 + ISO27001 A.12.4 + CSA CCM LOG-08):

| Field | Status in `view_inventory_ciem` |
|---|---|
| `user_id` | Present |
| `tenant_id` | Present |
| `asset_id` / `resource_uid` | Present |
| `endpoint` | Present |
| `timestamp` (UTC ISO8601) | Present |
| `identity_arn`(s) accessed (top N) | **MISSING** |
| `result` (200/403/404) | **MISSING** |
| `request_id` correlation | **MISSING** |

**PRE-MERGE (blocking):**
1. Add audit log to `view_asset_ciem` (`bff/inventory.py` L705) — currently none.
2. Add `ciem:sensitive` gate **and** audit log to `view_ciem_identity` (`bff/ciem_identity.py` L36) — currently neither.
3. Log on 403/404 denials too; add `result` field.
4. Include top-5 `identity_arn`s in the audit payload — proves *what* was viewed.
5. Reconcile story doc with migration 0013 (4 roles, not 1).

**SHIP-GATE (post-merge, before sprint close):**
6. Add `request_id` correlation.
7. Ship audit log to durable store (DB `audit_log` table or CloudWatch group with retention) — `logging.getLogger("api-gateway.audit")` alone is not SOC2-durable.
8. Per-user rate limit (60 req/min) on CIEM BFF routes.
9. NetworkPolicy verification.
10. HMAC on `X-Auth-Context` (separate hardening story).

## 5. Sequential BFF call confirmation

**YES — confirmed for both inventory CIEM routes:**

- `view_asset_ciem` (`bff/inventory.py:705-756`) — Step 1 inventory fetch + tenant match (L733-741), then Step 2 CIEM fetch (L746-750).
- `view_inventory_ciem` (`bff/inventory.py:1450-1525`) — Step 1 ownership check (L1471-1480), Step 2 CIEM fetch (L1484-1489).

Both 403/404 before any CIEM data is fetched. **No MUST-FIX for security gate B-2 on the inventory routes.**

⚠ **`/ciem_identity` (`bff/ciem_identity.py`) has no ownership check** because identity is not asset-scoped — it scopes by `tenant_id` from AuthContext only. Acceptable IF:
- `principal` is a filter hint only (confirmed in docstring L41-43).
- Engine-side `/api/v1/ciem/findings` enforces `WHERE tenant_id = $X-Auth-Context.tenant_id`, not from query param.

**MUST-VERIFY (handoff to cspm-django-engineer track):** confirm `engines/ciem/api_server.py` `/findings` reads `tenant_id` from `X-Auth-Context`, not query param. If unscoped, it is IDOR-equivalent.

## 6. Required pre-merge controls (consolidated)

1. **MUST-FIX**: Add `ciem:sensitive` gate + audit log to `bff/ciem_identity.py:view_ciem_identity`.
2. **MUST-FIX**: Add audit log to `bff/inventory.py:view_asset_ciem` (L705).
3. **MUST-FIX**: Audit log on 403/404 denials; include `result` + top-5 `identity_arn`s.
4. **MUST-FIX**: Reconcile story doc with migration 0013 (4 roles granted, not "platform_admin only").
5. **MUST-VERIFY**: CIEM engine enforces tenant_id from `X-Auth-Context`, not query param.
6. **MUST-VERIFY**: `tests/bff/test_inventory_ciem.py` covers (a) viewer 403, (b) cross-tenant asset 403, (c) audit-log emission on 200 + 403.
