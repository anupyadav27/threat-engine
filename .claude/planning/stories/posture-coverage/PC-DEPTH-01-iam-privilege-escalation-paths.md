# Story PC-DEPTH-01: IAM — Privilege Escalation Path Detection

## Status: done

## Metadata
- **Phase**: Analysis Depth Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P1 — top MITRE T1078 vector; zero current coverage
- **Depends on**: PC-GAP-01 (AliCloud/IBM stubs closed first so this runs for all CSPs)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-architect (graph traversal logic) + bmad-security-reviewer

## Gap Being Closed

Current `policy_detector.py` detects **direct** admin access (`Action:* Resource:*`). It does NOT detect **chained** privilege escalation:

```
RoleA (no direct admin) 
  → has iam:PassRole on RoleB  
  → RoleB has AdministratorAccess
  = RoleA is effectively admin via one hop
```

Also undetected:
- Role chaining via `sts:AssumeRole` (A assumes B which assumes C with admin)
- Lambda/EC2 instance profile abuse (`iam:PassRole` to attach admin role to compute)
- `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` combo → create hidden admin version
- `iam:AttachRolePolicy` + `iam:AttachUserPolicy` → attach AdministratorAccess to self

---

## Data Required

### Source 1 — Discovery Engine (`discovery_findings` table)

**Discovery IDs needed (all already collected by discovery engine):**

| Discovery ID | What it provides | Field used |
|-------------|-----------------|-----------|
| `aws.iam.list_roles` | All roles with AssumeRolePolicyDocument | `raw_response.AssumeRolePolicyDocument.Statement[].Principal` |
| `aws.iam.list_role_policies` | Inline policies per role | `raw_response.PolicyDocument.Statement[].Action` |
| `aws.iam.list_attached_role_policies` | Managed policy ARNs attached to role | `raw_response.AttachedPolicies[].PolicyArn` |
| `aws.iam.get_policy_version` | Policy document for managed policy | `raw_response.PolicyVersion.Document.Statement[].Action` |
| `aws.iam.list_instance_profiles` | EC2 instance profiles → role mapping | `raw_response.InstanceProfiles[].Roles[].RoleName` |
| `aws.iam.list_users` | All IAM users | `raw_response.Users[].UserName` |
| `aws.iam.list_attached_user_policies` | Managed policies attached to users | `raw_response.AttachedPolicies[]` |
| `aws.iam.list_user_policies` | Inline policies per user | `raw_response.PolicyNames[]` |

**Query pattern** (same reader as existing `AWSIAMProvider.analyze()`):
```python
disc_data = reader.load_iam_resources(scan_run_id, tenant_id, account_id)
roles = reader.get_roles(disc_data)
managed_policies = extract_managed_policies(disc_data, account_id)
```

### Source 2 — CDR Engine (`cdr_findings` table) — for active-path enrichment

CDR tells us which escalation paths have been **actually used** (not just theoretically possible). High-value enrichment — a theoretical path that has never been triggered is lower risk than one triggered 10 times this week.

**Columns used from `cdr_findings`:**
```sql
SELECT actor_principal, service, operation, resource_uid, event_time
FROM cdr_findings
WHERE tenant_id = %s
  AND service = 'iam'
  AND operation IN ('AssumeRole', 'PassRole', 'CreatePolicyVersion',
                    'AttachRolePolicy', 'AttachUserPolicy',
                    'SetDefaultPolicyVersion', 'AddUserToGroup')
  AND event_time > NOW() - INTERVAL '30 days'
```

Joining CDR `actor_principal` to discovered roles gives: "this escalation path was traversed N times by principal X in the last 30 days."

### Source 3 — Vulnerability Engine — NOT needed for this story

---

## Privilege Escalation Detection Algorithm

### Step 1 — Build Permission Graph

For each IAM identity (user/role), collect effective permissions by merging:
- All attached managed policies (resolved documents)
- All inline policies

```python
identity_permissions: Dict[str, Set[str]] = {
    "arn:aws:iam::123:role/DevRole": {"iam:PassRole", "s3:GetObject", ...},
    "arn:aws:iam::123:role/AdminRole": {"*"},
}
```

### Step 2 — Detect Escalation Edges

For each identity, check for "escalation actions":

```python
_ESCALATION_ACTIONS = {
    "iam:PassRole":               "can attach any role to compute/lambda (classic PassRole abuse)",
    "iam:CreatePolicyVersion":    "can create new policy version with * permissions",
    "iam:SetDefaultPolicyVersion":"can promote a hidden admin policy version",
    "iam:AttachRolePolicy":       "can attach AdministratorAccess to any role",
    "iam:AttachUserPolicy":       "can attach AdministratorAccess to self",
    "iam:PutRolePolicy":          "can inject inline policy granting admin",
    "iam:AddUserToGroup":         "can add self to admin group",
    "sts:AssumeRole":             "can assume roles — check if target role is admin",
}
```

### Step 3 — Resolve Target Role Permissions

For `iam:PassRole` and `sts:AssumeRole`: resolve the **target role** and check if it has admin access.

```python
# Example: DevRole has iam:PassRole on Resource: *
# → can pass ANY role to Lambda, including AdminRole
# → if AdminRole has AdministratorAccess → escalation path detected
```

For `iam:CreatePolicyVersion`: check if identity also has `iam:SetDefaultPolicyVersion` on same policy → full escalation combo.

### Step 4 — Path Scoring

```python
escalation_path = {
    "source_identity": "arn:aws:iam::123:role/DevRole",
    "escalation_action": "iam:PassRole",
    "target_identity": "arn:aws:iam::123:role/LambdaAdminRole",
    "target_has_admin": True,
    "hop_count": 1,
    "severity": "critical",  # direct 1-hop = critical; 2-hop = high; 3-hop = medium
    "cdr_active": True,       # CDR shows this path was used in last 30 days
    "cdr_use_count": 7,
}
```

### Step 5 — Generate Findings

One finding per escalation path:

| Rule ID | Severity | When |
|---------|---------|------|
| `aws.iam.role.privilege_escalation_via_pass_role` | CRITICAL | Source has `iam:PassRole` on * and target has admin |
| `aws.iam.role.privilege_escalation_via_create_policy` | CRITICAL | Has `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` |
| `aws.iam.role.privilege_escalation_via_attach_policy` | HIGH | Has `iam:AttachRolePolicy` or `iam:AttachUserPolicy` on * |
| `aws.iam.role.privilege_escalation_via_assume_role_chain` | HIGH | Role chain A→B→C where C has admin (2-hop) |
| `aws.iam.role.privilege_escalation_cdr_confirmed` | CRITICAL | Any above + CDR confirms it was used |

---

## Implementation Location

**New file:** `engines/iam/iam_engine/detectors/escalation_detector.py`

```python
def detect_privilege_escalation_paths(
    roles: List[Dict],
    users: List[Dict],
    managed_policies: List[ParsedPolicy],
    inline_policies: List[ParsedPolicy],
    account_id: str,
    cdr_conn=None,   # optional — enrich with CDR if available
) -> List[Dict]:
    ...
```

**Called from** `engines/iam/iam_engine/providers/aws.py` — add call after `run_all_detectors()`.

**Also applicable to:** Azure (role assignments + managed identity), GCP (service account impersonation), K8s (RoleBinding chain) — separate implementations per CSP in later stories.

---

## Output

### `iam_findings` table
New rows with `rule_id` = `aws.iam.role.privilege_escalation_*`, `severity=critical/high`, `finding_data` containing the full escalation path chain.

### `resource_security_posture` table
New column needed (add to migration 024 or separate migration):

```sql
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS has_priv_escalation_path BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS priv_escalation_hop_count SMALLINT,
    ADD COLUMN IF NOT EXISTS priv_escalation_cdr_confirmed BOOLEAN DEFAULT FALSE;
```

Written by `write_iam_posture_signals()` — add aggregation:
```python
has_priv_escalation_path = any escalation finding for this resource_uid
priv_escalation_cdr_confirmed = any escalation finding where cdr_active=True
```

### Attack-Path Engine Boost
`has_priv_escalation_path=True` + `is_internet_exposed=True` → composite danger flag `exploitable_exposed_resource` boost +40 (already defined in PC-P1-07).

---

## Acceptance Criteria

- [ ] AC-1: `escalation_detector.py` created and called from `AWSIAMProvider.analyze()`
- [ ] AC-2: `aws.iam.role.privilege_escalation_via_pass_role` fires when DevRole has `iam:PassRole` on `*` and LambdaAdminRole has `AdministratorAccess` attached
- [ ] AC-3: `aws.iam.role.privilege_escalation_via_create_policy` fires when identity has both `iam:CreatePolicyVersion` AND `iam:SetDefaultPolicyVersion` on same policy ARN
- [ ] AC-4: CDR enrichment: if CDR has `operation=AssumeRole` by the source identity in last 30 days, finding is upgraded to `aws.iam.role.privilege_escalation_cdr_confirmed` and severity→CRITICAL
- [ ] AC-5: Hop count correct: direct PassRole→admin = 1 hop (CRITICAL); A→B→admin = 2 hops (HIGH)
- [ ] AC-6: `has_priv_escalation_path=TRUE` written to `resource_security_posture` for the source identity resource_uid
- [ ] AC-7: Tenant isolation: all CDR queries include `AND tenant_id = %s`

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1078.004 | Valid Cloud Accounts — escalation to admin identity |
| T1548.005 | Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access |
| T1098.001 | Account Manipulation: Additional Cloud Credentials — PassRole to new Lambda function |

## Definition of Done
- [ ] `escalation_detector.py` implemented with PassRole + CreatePolicy + AttachPolicy + AssumeRole chain detection
- [ ] CDR enrichment active (cdr_findings join on actor_principal + operation)
- [ ] Unit tests: `tests/unit/iam/test_escalation_detector.py`
- [ ] IAM engine rebuilt and deployed
- [ ] After AWS scan: `SELECT COUNT(*) FROM iam_findings WHERE rule_id LIKE '%privilege_escalation%'` > 0