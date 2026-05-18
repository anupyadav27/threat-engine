# Story PC-CSP-02: DBSec Rules — IBM Cloud (0 rules) + K8s (0 rules)

## Status: done

## Metadata
- **Phase**: CSP Coverage Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P2
- **Depends on**: PC-CSP-00 (gap baseline)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-po + bmad-security-reviewer

## Gap Being Closed

**Coverage matrix shows:** IBM `dbsec=0`, K8s `dbsec=0`.

IBM Cloud and K8s have zero check rules tagged `database_security.applicable=true`. The DBSec engine can produce findings for AWS/Azure/GCP/OCI — but IBM Db2, IBM Cloud Databases (PostgreSQL, MySQL, MongoDB hosted), and K8s StatefulSets running databases are completely unchecked.

## IBM Cloud — Database Services

IBM databases discoverable:
- **IBM Cloud Databases (ICD):** PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, etcd (`ibm.databases.list_deployments`)
- **IBM Db2 on Cloud** (`ibm.db2.list_instances`)
- **IBM Cloudant** (NoSQL, CouchDB-based) (`ibm.cloudant.list_instances`)

Rules needed (5-pillar DBSec framework applied to IBM):

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `ibm.databases.deployment.ip_allowlist_configured` | Access Control | Allowlist not empty | critical |
| `ibm.databases.deployment.tls_enforced` | Encryption | TLS only connections | high |
| `ibm.databases.deployment.backup_encryption_enabled` | Backup/Recovery | Backups use customer key | high |
| `ibm.databases.deployment.service_endpoint_private` | Access Control | Private endpoint only | high |
| `ibm.databases.deployment.audit_logging_enabled` | Monitoring | Activity Tracker integration enabled | medium |
| `ibm.db2.instance.encryption_at_rest` | Encryption | Db2 data encrypted at rest | high |
| `ibm.cloudant.instance.cors_restricted` | Access Control | CORS not `*` | medium |
| `ibm.cloudant.instance.https_only` | Encryption | HTTP access disabled | high |

**Discovery IDs required:** `ibm.databases.list_deployments` (check if exists in `catalog/discovery_generator_data/ibm/databases/`), `ibm.db2.list_instances`, `ibm.cloudant.list_instances`.

## Kubernetes — Database Workloads

K8s doesn't host "databases" natively — databases run as StatefulSets or as operator-managed CRDs (PostgresSQL Operator, MySQL Operator, MongoDB Community Operator). The DBSec rules apply to:
- StatefulSets with well-known database image names (postgres, mysql, mongodb, redis, cassandra, elasticsearch)
- PersistentVolumeClaims attached to database StatefulSets — are they encrypted?
- Secrets containing DB credentials — are they using external secrets managers?
- NetworkPolicy restricting database pod access — is it present?

Rules needed:

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `k8s.statefulset.database.network_policy_present` | Access Control | Database StatefulSet namespace has NetworkPolicy restricting DB port | critical |
| `k8s.statefulset.database.secret_not_in_env` | Authentication | DB password not in pod env var (should use SecretStore/Vault) | high |
| `k8s.persistentvolumeclaim.database.encrypted` | Encryption | PVC StorageClass has encryption annotation | high |
| `k8s.statefulset.database.resource_limits_set` | Availability | CPU/memory limits set (prevent noisy neighbor) | medium |
| `k8s.statefulset.database.not_privileged` | Access Control | DB pod not running as privileged | critical |
| `k8s.statefulset.database.readonlyrootfilesystem` | Access Control | DB pod rootFileSystem = readOnly (except data dir) | medium |

**Discovery ID required:** `k8s.apps.list_stateful_sets_for_all_namespaces` ✅ (likely exists — StatefulSets are a core K8s resource). Filter by image name patterns: `postgres`, `mysql`, `mongodb`, `redis`, `cassandra`.

**Detection logic for K8s:** Check engine must detect database StatefulSets by image name pattern. Add a `service_detector` helper in check engine that reads StatefulSet `spec.containers[].image` and applies the database name patterns.

## rule_metadata Tag Structure

```yaml
rule_metadata:
  dbsec:
    applicable: true
    pillar: "access_control"  # authentication / encryption / access_control / monitoring / backup
  engine: "dbsec"
  check_type: "config"
```

## Acceptance Criteria

- [ ] AC-1: At least 8 IBM dbsec rules in `catalog/rule/ibm_rule_check/` tagged `dbsec.applicable=true`
- [ ] AC-2: At least 6 K8s dbsec rules in `catalog/rule/k8s_rule_check/`
- [ ] AC-3: IBM discovery IDs (`ibm.databases.list_deployments`, `ibm.cloudant.list_instances`) exist or stubs created
- [ ] AC-4: K8s StatefulSet discovery (`k8s.apps.list_stateful_sets_for_all_namespaces`) feeds the check engine — database pods detected by image name pattern
- [ ] AC-5: After scan, `dbsec_findings` has rows for IBM and K8s (verify with port-forward to dbsec engine)
- [ ] AC-6: Rules uploaded to DB without errors
- [ ] AC-7: Coverage matrix shows IBM `dbsec.rule_count > 0` and K8s `dbsec.rule_count > 0`

## Definition of Done
- [ ] All IBM dbsec YAML rule files committed
- [ ] All K8s dbsec YAML rule files committed
- [ ] Rules metadata uploaded to check DB
- [ ] After scan: `SELECT COUNT(*) FROM dbsec_findings WHERE provider IN ('ibm','k8s')` > 0