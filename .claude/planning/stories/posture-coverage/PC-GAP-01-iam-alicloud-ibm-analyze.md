# Story PC-GAP-01: IAM Engine — AliCloud + IBM analyze() Implementation

## Status: done

## Metadata
- **Phase**: CSP Coverage Track — Provider Gap Closure
- **Sprint**: Posture Coverage Enhancement
- **Points**: 6 (3 pts AliCloud + 3 pts IBM)
- **Priority**: P1 — Highest ROI (Pattern A stub → full analyze())
- **Depends on**: None (IAM engine already has Pattern A architecture; stubs exist)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-po + bmad-security-reviewer (IAM analysis touches credential/privilege logic)

## Gap Being Closed

`engines/iam/iam_engine/providers/__init__.py` dispatches to `AliCloudIAMProvider` and `IBMIAMProvider` — both return empty lists from `analyze()`. IAM findings for AliCloud and IBM tenants are zero.

**Confirmed stub locations:**
- `engines/iam/iam_engine/providers/alicloud.py` — `analyze()` returns `[]`
- `engines/iam/iam_engine/providers/ibm.py` — `analyze()` returns `[]`

## Pattern Reference

All Pattern A engines follow this contract (see PC-ARCH-01):

```python
class BaseIAMProvider(ABC):
    @abstractmethod
    def analyze(self, scan_run_id: str, tenant_id: int,
                account_id: str) -> List[IAMFinding]:
        ...
```

Findings write to `iam_findings` table. Posture signals are computed by `write_iam_posture_signals()` which aggregates from `iam_findings` — no changes needed there.

---

## AliCloud IAM Implementation

### Discovery Data Available

AliCloud RAM (Resource Access Management) resources are already discovered. Query check_findings for discovery IDs:

```
alicloud.ram.list_users
alicloud.ram.list_roles
alicloud.ram.list_policies
alicloud.ram.list_groups
alicloud.ram.get_account_alias
alicloud.ram.get_security_preference  ← MFA enforcement
```

### Analysis Modules to Implement

**Module 1 — RAM User over-permission**
- Users with `AdministratorAccess` policy attached directly (not via group/role)
- Users with `*` in policy Action + Resource
- Produces: `is_admin_role=True`, `role_has_wildcard_policy=True`

**Module 2 — AccessKey rotation**
- `alicloud.ram.list_access_keys` per user → `CreateDate` field
- AccessKey older than 90 days → HIGH finding
- AccessKey older than 180 days → CRITICAL finding
- Produces: `has_stale_credentials=True`

**Module 3 — MFA enforcement**
- `get_security_preference` → `LoginProfile.MFABindRequired`
- Users without MFA and console login enabled → finding
- Produces: `mfa_enforced=False` on user resources

**Module 4 — RAM Role trust boundary**
- Roles with `Principal: {"RAM": "acs:ram::*:root"}` — wildcard trust
- Cross-account role with `*` principal
- Produces: `cross_account_access=True`

**Module 5 — RAM Policy over-permission**
- Custom policies with `Effect: Allow, Action: *, Resource: *`
- System policies attached to groups with all users (implicit admin)

### AliCloud Discovery Field Mapping

```python
# alicloud.ram.list_users response structure
{
  "UserName": str,
  "UserId": str,
  "CreateDate": str,   # ISO 8601
  "UpdateDate": str,
  "LastLoginDate": str,
  "Comments": str
}

# alicloud.ram.list_policies → PolicyDocument (JSON string)
{
  "Statement": [
    {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}
  ]
}
```

---

## IBM IAM Implementation

### Discovery Data Available

IBM Cloud IAM resources discovered via:

```
ibm.iam.list_api_keys         ← Service IDs + User API keys
ibm.iam.list_service_ids
ibm.iam.list_access_groups
ibm.iam.list_access_group_members
ibm.iam.list_policies          ← IAM policies with roles
ibm.iam.list_trusted_profiles
ibm.accounts.get_account_settings  ← MFA, IP restrictions
```

### Analysis Modules to Implement

**Module 1 — API Key rotation**
- `ibm.iam.list_api_keys` → `created_at` field per key
- API key older than 90 days → HIGH finding
- API key with `locked=false` and no expiration → MEDIUM finding
- Produces: `has_stale_credentials=True`

**Module 2 — Service ID over-permission**
- Service IDs with `Administrator` or `Editor` on `*` resource
- Service IDs with platform `Administrator` on all account services
- Produces: `is_admin_role=True`, `role_has_wildcard_policy=True`

**Module 3 — MFA enforcement**
- `get_account_settings` → `mfa` field: `NONE` → CRITICAL
- `mfa=TOTP` acceptable, `mfa=TOTP4ALL` best practice
- Produces: `mfa_enforced=False`

**Module 4 — Trusted Profile over-scoping**
- `ibm.iam.list_trusted_profiles` → policies with `resourceType: *` and `Administrator`
- Trusted profiles are federated identities — wildcard admin is equivalent to root access

**Module 5 — Access Group wildcard policies**
- Groups with IAM policies granting `Administrator` on `serviceType: platform-services` (all services)
- Any user added to such a group gets implicit admin

### IBM Discovery Field Mapping

```python
# ibm.iam.list_api_keys
{
  "id": str,
  "name": str,
  "iam_id": str,       # user or service ID
  "created_at": str,   # "2024-01-15T10:30:00Z"
  "locked": bool,
  "account_id": str
}

# ibm.iam.list_policies
{
  "id": str,
  "type": "access",
  "subjects": [{"attributes": [{"name": "iam_id", "value": str}]}],
  "roles": [{"role_id": "crn:v1:bluemix:public:iam::::role:Administrator"}],
  "resources": [{"attributes": [{"name": "resourceType", "value": "*"}]}]
}
```

---

## Implementation Steps

1. **Open** `engines/iam/iam_engine/providers/alicloud.py` — replace stub `analyze()` with full implementation
2. **Open** `engines/iam/iam_engine/providers/ibm.py` — replace stub `analyze()` with full implementation
3. Each `analyze()` must call `get_discovery_findings(scan_run_id, provider)` to load raw data from discovery_findings table (same pattern as aws.py)
4. Return `List[IAMFinding]` — use existing IAMFinding dataclass (same fields as other CSPs)
5. **Do NOT** modify `posture_signals.py` — it's already CSP-agnostic

## IAMFinding fields to populate

```python
@dataclass
class IAMFinding:
    finding_id: str          # sha256(rule_id|resource_uid|scan_run_id)[:16]
    scan_run_id: str
    tenant_id: int
    account_id: str
    provider: str            # "alicloud" or "ibm"
    region: str
    resource_uid: str
    resource_type: str       # "ram_user" / "ram_role" / "service_id" / "api_key"
    rule_id: str
    severity: str
    status: str              # "FAIL"
    title: str
    description: str
    remediation: str
    raw_evidence: dict       # JSONB — the raw policy/key data
```

## Acceptance Criteria

- [ ] AC-1: `AliCloudIAMProvider.analyze()` returns non-empty list for a tenant with AliCloud account (test with mock discovery_findings)
- [ ] AC-2: `IBMIAMProvider.analyze()` returns non-empty list for IBM tenant
- [ ] AC-3: AccessKey rotation check fires for keys older than 90 days (AliCloud) and API keys older than 90 days (IBM)
- [ ] AC-4: Wildcard policy check fires: `AliCloud RAM policy with Action:* Resource:*` → CRITICAL finding
- [ ] AC-5: MFA check fires: AliCloud `MFABindRequired=false` → CRITICAL; IBM `mfa=NONE` → CRITICAL
- [ ] AC-6: After AliCloud scan, `iam_findings` table has rows with `provider='alicloud'`
- [ ] AC-7: After IBM scan, `iam_findings` table has rows with `provider='ibm'`
- [ ] AC-8: `write_iam_posture_signals()` correctly aggregates AliCloud/IBM findings into `resource_security_posture` (no code change needed — verify by checking posture table after scan)

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1078.004 | Valid Cloud Accounts — wildcard admin detection |
| T1098.001 | Account Manipulation: Additional Cloud Credentials — stale API key detection |
| T1552.004 | Unsecured Credentials: Private Keys — API key rotation |

## Definition of Done
- [ ] AliCloud and IBM `analyze()` methods fully implemented (no stub return)
- [ ] Unit tests in `tests/unit/iam/test_alicloud_provider.py` and `test_ibm_provider.py`
- [ ] IAM engine image rebuilt and deployed
- [ ] After scan with AliCloud/IBM account: `SELECT COUNT(*) FROM iam_findings WHERE provider IN ('alicloud','ibm')` > 0
