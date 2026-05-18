# Story PC-DEPTH-04: DataSec — Cross-Account S3 Access + Lake Formation Analysis (AWS)

## Status: done

## Metadata
- **Phase**: Analysis Depth Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P2 — most common AWS data exposure vector; discovery data already collected
- **Depends on**: None (AWS DataSec provider already works; this adds new detection modules)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## Gap Being Closed

The current `AWSDataSecProvider.analyze()` checks per-bucket encryption, public access block, and tagging. It does NOT analyze:

1. **Cross-account bucket policies** — `Principal: {"AWS": "arn:aws:iam::999999:root"}` allows external account to read/write bucket. Current analysis only flags `Principal: *` (fully public). A bucket can be perfectly private from the internet but wide open to a different AWS account.

2. **Lake Formation fine-grained permissions** — Lake Formation can grant permissions that BYPASS S3 bucket policies and IAM. If LF grants `SELECT` on a database to `lakeformation:everyone`, it overrides IAM even if S3 bucket is locked down.

3. **S3 Object Ownership + ACL gap** — "Bucket owner preferred" + ACL enabled means uploaded objects from other accounts can retain the original uploader's ownership, breaking encryption enforcement.

---

## Data Required

### Source 1 — Discovery Engine (`discovery_findings`)

**For cross-account S3 analysis:**

| Discovery ID | What it provides | Field used |
|-------------|-----------------|-----------|
| `aws.s3.list_buckets` | All buckets | `raw_response.Buckets[].Name` |
| `aws.s3.get_bucket_policy` | Bucket resource policy JSON | `raw_response.Policy` (JSON string → parse as dict) |
| `aws.s3.get_bucket_acl` | Bucket + object ACL grants | `raw_response.Grants[].Grantee`, `raw_response.Grants[].Permission` |
| `aws.s3.get_bucket_ownership_controls` | Object ownership rule | `raw_response.OwnershipControls.Rules[].ObjectOwnership` |
| `aws.s3.get_bucket_replication` | Cross-region replication | `raw_response.ReplicationConfiguration.Rules[].Destination.Bucket` (cross-account dest) |

**For Lake Formation analysis:**

| Discovery ID | What it provides | Field used |
|-------------|-----------------|-----------|
| `aws.lakeformation.list_data_lakes_settings` | LF admins, data lake settings | `raw_response.DataLakeSettings.DataLakeAdmins`, `CreateDatabaseDefaultPermissions` |
| `aws.lakeformation.list_permissions` | All LF grant records | `raw_response.PrincipalResourcePermissions[].Principal.DataLakePrincipalIdentifier` |
| `aws.glue.list_databases` | Glue databases (LF-governed) | `raw_response.DatabaseList[].Name`, `CreateTableDefaultPermissions` |

### Source 2 — CDR Engine (`cdr_findings`) — enrichment only

Cross-account bucket access that has been **actively used** is higher risk than theoretical policy access. Enrich findings with CDR behavioral data:

```sql
SELECT actor_principal, operation, resource_uid, COUNT(*) AS call_count
FROM cdr_findings
WHERE tenant_id = %s
  AND service = 's3'
  AND operation IN ('GetObject', 'PutObject', 'DeleteObject', 'ListObjects', 'GetBucketPolicy')
  AND actor_principal NOT LIKE '%:' || %s || ':%%'   -- filter out same-account principals
  AND event_time > NOW() - INTERVAL '30 days'
GROUP BY actor_principal, operation, resource_uid
```

**Joining CDR `resource_uid` (bucket ARN)** with discovery bucket ARN gives: "this cross-account policy has been exercised N times by external account X in the last 30 days."

### Source 3 — Vulnerability Engine — NOT needed

---

## Cross-Account S3 Detection Logic

### Module: `_analyze_cross_account_access()`

```python
def _analyze_cross_account_access(self, buckets, account_id, scan_run_id, ...):
    findings = []
    for bucket in buckets:
        policy_doc = bucket.get("policy")   # already parsed dict from discovery
        if not policy_doc:
            continue

        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})
            # Normalize principal to list of ARNs
            arns = _flatten_principal(principal)

            for arn in arns:
                if arn == "*":
                    continue  # Already caught by existing public access check
                if not _is_same_account(arn, account_id):
                    # Cross-account principal in Allow statement
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str): actions = [actions]
                    severity = _cross_account_severity(actions)
                    findings.append({
                        "rule_id": "aws.s3.bucket.no_cross_account_write_access"
                        if any("Put" in a or "Delete" in a or "s3:*" in a for a in actions)
                        else "aws.s3.bucket.cross_account_read_access_reviewed",
                        "severity": severity,
                        ...
                    })
    return findings
```

**Severity logic:**
| Cross-account action | Severity |
|---------------------|---------|
| `s3:*` or `s3:PutObject` or `s3:DeleteObject` | CRITICAL |
| `s3:GetObject` or `s3:ListBucket` | HIGH |
| `s3:GetBucketPolicy` | MEDIUM |

### Module: `_analyze_bucket_acl_ownership()`

```python
# aws.s3.get_bucket_ownership_controls → ObjectOwnership
# "BucketOwnerPreferred" + ACL enabled → MEDIUM (uploaded objects from other accounts keep uploader ownership)
# "BucketOwnerEnforced" → PASS (ACL disabled, all objects owned by bucket owner)

# aws.s3.get_bucket_acl → check for FULL_CONTROL or WRITE grants to non-canonical owner
for grant in acl_grants:
    grantee_type = grant.get("Grantee", {}).get("Type")
    permission = grant.get("Permission")
    if grantee_type == "Group" and "AllUsers" in grant.get("Grantee", {}).get("URI", ""):
        # Public write ACL → CRITICAL (bucket-level public write)
```

### Module: `_analyze_lake_formation()`

```python
# aws.lakeformation.list_permissions → check for IAMAllowedPrincipals (LF bypass)
for permission in lf_permissions:
    principal = permission.get("Principal", {}).get("DataLakePrincipalIdentifier", "")
    if principal == "IAM_ALLOWED_PRINCIPALS":
        # IAMAllowedPrincipals = LF SuperGrant that lets IAM policies bypass LF governance
        # This is NOT secure — LF was designed to be the authority
        findings.append({
            "rule_id": "aws.lakeformation.database.no_iam_allowed_principals",
            "severity": "high",
            ...
        })
    if principal.endswith(":role/Admin") and permissions include "ALL":
        # Admin-level LF grant to broad role → HIGH
```

**Lake Formation `CreateDatabaseDefaultPermissions` check:**
```python
# Glue list_databases → CreateTableDefaultPermissions
default_perms = db.get("CreateTableDefaultPermissions", [])
for perm in default_perms:
    if perm.get("Principal", {}).get("DataLakePrincipalIdentifier") == "IAM_ALLOWED_PRINCIPALS":
        # New tables created in this DB automatically get LF bypass → HIGH
```

### Replication Cross-Account Check

```python
# aws.s3.get_bucket_replication → Destination.Bucket ARN
dest_arn = repl_rule.get("Destination", {}).get("Bucket", "")
dest_account = _extract_account_from_arn(dest_arn)
if dest_account and dest_account != account_id:
    # Cross-account replication destination — data leaving the account
    findings.append({
        "rule_id": "aws.s3.bucket.cross_account_replication_reviewed",
        "severity": "high",
        ...
    })
```

---

## Findings Produced

| Rule ID | Module | Severity | Notes |
|---------|--------|---------|-------|
| `aws.s3.bucket.no_cross_account_write_access` | Access | CRITICAL | External account has write/delete on bucket |
| `aws.s3.bucket.cross_account_read_access_reviewed` | Access | HIGH | External account has read on bucket |
| `aws.s3.bucket.bucket_owner_enforced` | Access | MEDIUM | ObjectOwnership not "BucketOwnerEnforced" + ACL active |
| `aws.s3.bucket.cross_account_replication_reviewed` | Residency | HIGH | Replication to external account |
| `aws.lakeformation.database.no_iam_allowed_principals` | Access | HIGH | LF bypass grant active |
| `aws.lakeformation.database.no_admin_wildcard_grant` | Access | HIGH | Admin-level LF grant to broad role |

---

## CDR Enrichment

For any cross-account policy finding, the CDR enrichment upgrades severity if the policy has been **actively exercised**:

```python
# After findings generated, join with CDR:
cdr_active_buckets = set(
    row["resource_uid"] for row in cdr_cross_account_s3_calls
    if row["call_count"] > 0
)
for finding in findings:
    if finding["resource_uid"] in cdr_active_buckets:
        finding["severity"] = "critical"
        finding["finding_data"]["cdr_confirmed"] = True
        finding["finding_data"]["cdr_last_use"] = cdr_data[finding["resource_uid"]]["last_event"]
```

---

## Posture Signals Written

Updated in `write_datasec_posture_signals()`:
- `has_exfil_path=True` when cross-account write access + CDR confirmed
- `data_classification` — unchanged (existing logic)
- `can_access_pii=True` — if cross-account read on PII-tagged bucket

---

## Acceptance Criteria

- [ ] AC-1: `aws.s3.bucket.no_cross_account_write_access` fires for buckets with `Principal: {"AWS": "arn:aws:iam::999999:root"}` with `s3:PutObject` in Allow statement
- [ ] AC-2: Same-account principals NOT flagged (cross-account filter correctly excludes own account_id)
- [ ] AC-3: `aws.lakeformation.database.no_iam_allowed_principals` fires for LF databases with `IAM_ALLOWED_PRINCIPALS` in permissions
- [ ] AC-4: Cross-account replication finding fires when `Destination.Bucket` ARN contains different account ID than `account_id` parameter
- [ ] AC-5: CDR enrichment: when `cdr_findings` has `GetObject` calls from external account principal on the same bucket, finding severity upgrades to CRITICAL
- [ ] AC-6: `has_exfil_path=True` written to `resource_security_posture` for buckets with cross-account write + CDR confirmed
- [ ] AC-7: All DB queries (discovery + CDR) include `AND tenant_id = %s`

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1530 | Data from Cloud Storage Object — cross-account read policy |
| T1020 | Automated Exfiltration — cross-account replication |
| T1083 | File and Directory Discovery — Lake Formation bypass enumeration |

## Definition of Done
- [ ] Three new analysis methods in `AWSDataSecProvider`: `_analyze_cross_account_access()`, `_analyze_bucket_acl_ownership()`, `_analyze_lake_formation()`
- [ ] CDR enrichment wired: upgrades confirmed active findings to CRITICAL
- [ ] Unit tests in `tests/unit/datasec/test_aws_cross_account.py`
- [ ] DataSec engine rebuilt and deployed
- [ ] After AWS scan: `SELECT rule_id, COUNT(*) FROM datasec_findings WHERE rule_id LIKE '%cross_account%' GROUP BY rule_id` shows new rules producing findings
