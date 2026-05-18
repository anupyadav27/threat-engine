# Story PC-GAP-04: DBSec Engine — Create IBM Cloud Provider (ibm.py)

## Status: done

## Metadata
- **Phase**: CSP Coverage Track — Provider Gap Closure
- **Sprint**: Posture Coverage Enhancement
- **Points**: 4
- **Priority**: P1 — Highest ROI (missing provider file → full 5-pillar analyze())
- **Depends on**: None (DBSec engine has Pattern A architecture; IBM is simply missing from dispatch map)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-po + bmad-security-reviewer

## Gap Being Closed

`engines/dbsec/dbsec_engine/providers/__init__.py` dispatches to AWS, Azure, GCP, OCI, K8s, AliCloud — **IBM is not in the dispatch map at all**. There is no `engines/dbsec/dbsec_engine/providers/ibm.py` file.

**Consequence:** IBM tenant database scans produce zero `dbsec_findings`. The DBSec engine logs a warning and returns no analysis.

## Files to Create/Modify

1. **CREATE** `engines/dbsec/dbsec_engine/providers/ibm.py` — full IBMDBSecProvider class
2. **MODIFY** `engines/dbsec/dbsec_engine/providers/__init__.py` — add IBM to dispatch

## Dispatch Map Change

```python
# Current state in providers/__init__.py
def get_provider(provider_name: str) -> BaseDBSecProvider:
    name = (provider_name or "aws").lower()
    if name == "aws":   return AWSDBSecProvider()
    if name == "azure": return AzureDBSecProvider()
    if name == "gcp":   return GCPDBSecProvider()
    if name == "oci":   return OCIDBSecProvider()
    if name == "k8s":   return K8sDBSecProvider()
    if name == "alicloud": return AliCloudDBSecProvider()
    # IBM is MISSING — falls through to stub
    logger.warning(f"Unknown provider '{provider_name}', returning stub")
    return _StubDBSecProvider()

# Change: add IBM before the stub fallback
    if name == "ibm":   return IBMDBSecProvider()
```

## DBSec 5-Pillar Framework

| Pillar | What it checks |
|--------|---------------|
| P1: Access Control | Authentication mechanisms, IP allowlists, public access |
| P2: Encryption | Encryption at rest, in transit, key management |
| P3: Authentication | Connection auth type, password policy, MFA |
| P4: Monitoring | Audit logging, activity tracking, query logging |
| P5: Backup/Recovery | Backup frequency, retention, encryption of backups |

---

## IBM Cloud Database Services

IBM Cloud has 3 categories of managed databases:

### IBM Cloud Databases (ICD) — Managed PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch, etcd

**Discovery IDs:**
- `ibm.databases.list_deployments` — all ICD deployments across all regions
- `ibm.databases.get_deployment` — instance config (plan, encryption, endpoint type)
- `ibm.databases.get_connection_strings` — connection details (endpoint type, TLS version)
- `ibm.databases.list_allowlisted_addresses` — IP allowlist

**Findings to generate (5-pillar):**

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `ibm.databases.deployment.ip_allowlist_configured` | P1 | `allowlist` not empty | critical |
| `ibm.databases.deployment.private_endpoint_only` | P1 | `endpoint_type = private` (not public) | critical |
| `ibm.databases.deployment.tls_version_12` | P2 | TLS version ≥ 1.2 on all connections | high |
| `ibm.databases.deployment.encryption_at_rest` | P2 | Default encryption enabled (IBM Key Protect) | high |
| `ibm.databases.deployment.customer_managed_key` | P2 | BYOK via Key Protect HPCS (vs IBM-managed key) | high |
| `ibm.databases.deployment.auto_scaling_enabled` | P5 | Auto-scaling configured (prevents DoS via OOM) | medium |
| `ibm.databases.deployment.backup_encryption_enabled` | P5 | Backups use customer-managed key | high |
| `ibm.databases.deployment.point_in_time_recovery` | P5 | PITR retention ≥ 7 days | medium |
| `ibm.databases.deployment.activity_tracker_connected` | P4 | Activity Tracker Hosted Event Search integration active | high |
| `ibm.databases.deployment.metrics_enabled` | P4 | IBM Cloud Monitoring integration enabled | medium |

### IBM Db2 on Cloud

**Discovery IDs (same as DataSec engine — different analysis):**
- `ibm.db2.list_instances`
- `ibm.db2.get_instance_details` — SSL, public access, IP restrictions, plan tier

**Findings to generate:**

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `ibm.db2.instance.ssl_enforced` | P2 | SSL-only connections | high |
| `ibm.db2.instance.public_connectivity_disabled` | P1 | No public endpoint | critical |
| `ibm.db2.instance.audit_policy_configured` | P4 | Audit policy active for DML/DDL | high |
| `ibm.db2.instance.row_level_security_enabled` | P3 | Row-level security (LBAC) configured | high |

### IBM Cloudant

**Discovery IDs (same as DataSec engine — different pillars checked):**
- `ibm.cloudant.list_instances`
- `ibm.cloudant.get_instance_config`

**Findings to generate:**

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `ibm.cloudant.instance.iam_only_auth` | P3 | IAM-only auth (not legacy API keys) | high |
| `ibm.cloudant.instance.https_only` | P2 | HTTP disabled | high |
| `ibm.cloudant.instance.cors_restricted` | P1 | CORS not `*` | medium |

---

## Discovery Field Mapping

```python
# ibm.databases.list_deployments (ICD)
{
  "id": str,          # CRN — use as resource_uid
  "name": str,
  "type": str,        # "postgresql" / "mysql" / "mongodb" / "redis"
  "plan": str,        # "standard" / "enterprise"
  "platform_options": {
    "disk_encryption_key_crn": str   # BYOK key CRN (empty = IBM-managed)
  },
  "service_endpoints": str,          # "public" / "private" / "public-and-private"
  "crn": str,
  "tags": list
}

# ibm.databases.list_allowlisted_addresses
{
  "ip_addresses": [
    {"address": "10.0.0.1/32", "description": "internal"}
  ]
}
```

---

## IBMDBSecProvider Class Skeleton

```python
# engines/dbsec/dbsec_engine/providers/ibm.py

from .base import BaseDBSecProvider
from ..models import DBSecFinding
from typing import List
import logging

logger = logging.getLogger(__name__)

class IBMDBSecProvider(BaseDBSecProvider):

    def analyze(self, scan_run_id: str, tenant_id: int,
                account_id: str) -> List[DBSecFinding]:
        findings = []
        disc_data = self.get_discovery_findings(scan_run_id, "ibm")

        findings.extend(self._analyze_icd(disc_data, scan_run_id, tenant_id, account_id))
        findings.extend(self._analyze_db2(disc_data, scan_run_id, tenant_id, account_id))
        findings.extend(self._analyze_cloudant(disc_data, scan_run_id, tenant_id, account_id))

        logger.info(f"IBM DBSec: {len(findings)} findings for scan {scan_run_id}")
        return findings

    def _analyze_icd(self, disc_data, scan_run_id, tenant_id, account_id):
        # Filter disc_data for ibm.databases.* discovery IDs
        # Apply 5-pillar checks
        ...

    def _analyze_db2(self, ...): ...
    def _analyze_cloudant(self, ...): ...
```

## Acceptance Criteria

- [ ] AC-1: `ibm.py` file created at `engines/dbsec/dbsec_engine/providers/ibm.py`
- [ ] AC-2: `providers/__init__.py` dispatch map includes `if name == "ibm": return IBMDBSecProvider()`
- [ ] AC-3: `IBMDBSecProvider.analyze()` returns findings for ICD, Db2, and Cloudant resource types
- [ ] AC-4: `ibm.databases.deployment.ip_allowlist_configured` fires for ICD instances with empty allowlist
- [ ] AC-5: `ibm.databases.deployment.private_endpoint_only` fires for ICD with `service_endpoints="public"`
- [ ] AC-6: After IBM scan: `SELECT resource_type, COUNT(*) FROM dbsec_findings WHERE provider='ibm' GROUP BY resource_type` shows icd_deployment, db2_instance, cloudant_instance rows
- [ ] AC-7: Coverage matrix shows IBM `dbsec.rule_count > 0` (closes PC-CSP-02 IBM gap from analysis side)
- [ ] AC-8: `resource_security_posture` updated with `connected_db_count` and `db_auth_type` for IBM resources

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1190 | Exploit Public-Facing Application — public ICD endpoint detection |
| T1078.004 | Valid Cloud Accounts — IAM-only auth enforcement (Cloudant) |
| T1530 | Data from Cloud Storage Object — public Db2 endpoint |
| T1048 | Exfiltration Over Alternative Protocol — ICD without TLS enforcement |

## Definition of Done
- [ ] `engines/dbsec/dbsec_engine/providers/ibm.py` created with full 5-pillar analyze()
- [ ] `providers/__init__.py` updated with IBM dispatch
- [ ] Unit test in `tests/unit/dbsec/test_ibm_provider.py`
- [ ] DBSec engine rebuilt and deployed
- [ ] After IBM scan: `SELECT COUNT(*) FROM dbsec_findings WHERE provider='ibm'` > 0
- [ ] PC-CSP-02 IBM DBSec check rules (catalog YAML) also uploaded so check_findings feed the writer