# Testing & Validation Strategy — All CSPs, All Engines

## Problem Statement

Full pipeline runs (discovery → check → inventory → threat → compliance → IAM → datasec) take 30-60 minutes.
Finding a bug at step 6 (threat engine) after 50 minutes wastes the entire cycle.
Need layered testing that catches bugs early, before committing to a full scan.

## Testing Pyramid

```
Layer 5 — Full scan (all services, all regions, all engines)      ← HOURS — run once before release
Layer 4 — Pipeline smoke (10 services, 2 regions, all engines)    ← 15-20 min — run before PR merge
Layer 3 — Engine smoke (10 services, 1 region, 1 engine)          ← 2-5 min — run during dev
Layer 2 — Service smoke (1 service, real API call, DB write)       ← 30 sec — run after any code change
Layer 1 — Unit tests (mocked, no cloud, no DB)                    ← seconds — run on every save
```

Each layer catches different bugs. Always start at Layer 1 and work up.
Never go straight to Layer 5 — it hides which component failed.

---

## Layer 1 — Unit Tests (No Cloud, No DB)

**What:** Test individual functions with mocked inputs/outputs.
**When:** On every code change. Fast — should run in < 30 seconds.
**Tools:** pytest + unittest.mock

### What to unit test per CSP scanner:

**Auth:**
```python
def test_azure_auth_builds_credential():
    """ClientSecretCredential is instantiated with correct env vars."""
    with mock.patch.dict(os.environ, {
        'AZURE_TENANT_ID': 'test-tenant',
        'AZURE_CLIENT_ID': 'test-client',
        'AZURE_CLIENT_SECRET': 'test-secret',
    }):
        cred = build_credential()
        assert isinstance(cred, ClientSecretCredential)

def test_gcp_auth_uses_adc_when_no_key_file():
    cred, _ = google.auth.default()
    assert cred is not None
```

**Pagination:**
```python
def test_azure_pagination_collects_all_pages():
    """ItemPaged iterator yields all items across pages."""
    mock_pager = [mock_vm(f"vm-{i}") for i in range(250)]
    result = azure_list_all(lambda: mock_pager)
    assert len(result) == 250

def test_alicloud_pagination_stops_at_total_count():
    """PageNumber stops when page_number * page_size >= total_count."""
    mock_client = build_mock_client(total_count=137, page_size=50)
    result = alicloud_paginate(mock_client.list_instances, page_size=50)
    assert len(result) == 137
    assert mock_client.list_instances.call_count == 3  # pages 1,2,3

def test_k8s_pagination_uses_continue_token():
    mock_api = MagicMock()
    mock_api.list_pod_for_all_namespaces.side_effect = [
        MockResponse(items=[pod1, pod2], metadata=MockMeta(_continue="tok1")),
        MockResponse(items=[pod3], metadata=MockMeta(_continue=None)),
    ]
    result = k8s_list_all(mock_api.list_pod_for_all_namespaces)
    assert len(result) == 3
```

**Resource type normalization:**
```python
def test_azure_resource_type_normalized():
    raw = "Microsoft.Compute/virtualMachines"
    assert normalize_azure_type(raw) == "VirtualMachine"

def test_gcp_resource_type_normalized():
    raw = "compute.googleapis.com/Instance"
    assert normalize_gcp_type(raw) == "GCEInstance"

def test_alicloud_resource_uid_format():
    uid = build_alicloud_uid("ecs", "ap-southeast-1", "12345", "instance", "i-abc123")
    assert uid == "acs:ecs:ap-southeast-1:12345:instance/i-abc123"
```

**Client factory:**
```python
def test_azure_client_factory_maps_compute():
    factory = AzureClientFactory(credential=mock_cred, subscription_id="sub-1")
    client = factory.get_client("compute")
    assert isinstance(client, ComputeManagementClient)

def test_gcp_client_factory_raises_on_unknown_service():
    factory = GCPClientFactory(credentials=mock_cred, project="proj")
    with pytest.raises(ValueError, match="Unknown service: foobar"):
        factory.get_client("foobar")
```

**Rule evaluation (check engine):**
```python
def test_azure_storage_public_access_rule_fails_when_public():
    resource = {"properties": {"allowBlobPublicAccess": True}}
    result = evaluate_rule("azure_storage_public_access_disabled", resource)
    assert result["status"] == "FAIL"

def test_k8s_privileged_pod_rule_fails():
    pod = {"spec": {"containers": [{"securityContext": {"privileged": True}}]}}
    result = evaluate_rule("k8s_pod_no_privileged_containers", pod)
    assert result["status"] == "FAIL"
```

**DB write mocking:**
```python
def test_discovery_finding_written_with_correct_provider():
    with mock.patch("psycopg2.connect") as mock_conn:
        writer = DiscoveryWriter(provider="azure")
        writer.write_finding(resource_uid="/sub/rg/vm1", resource_type="VirtualMachine", ...)
        call_args = mock_conn.return_value.cursor.return_value.execute.call_args
        assert "provider" in call_args[0][0]
        assert "azure" in call_args[0][1]
```

### Test file locations:
```
engines/discoveries/providers/azure/tests/
    test_auth.py
    test_client_factory.py
    test_pagination.py
    test_normalization.py
engines/check/engine_check_azure/tests/
    test_rule_evaluation.py
engines/discoveries/providers/gcp/tests/
    ...
```

### Run:
```bash
pytest engines/discoveries/providers/azure/tests/ -v --tb=short
pytest engines/check/engine_check_azure/tests/ -v --tb=short
```

---

## Layer 2 — Service Smoke Test (1 Service, Real API, Real DB Write)

**What:** Call one real cloud service, discover resources, write to DB.
**When:** After completing client factory + pagination for a new CSP.
**Duration:** 30 seconds per service.

### Test script pattern:

```bash
# Azure: test compute service only
python engines/discoveries/run_scan.py \
  --provider azure \
  --services compute \
  --regions eastus \
  --scan-run-id test-azure-smoke-001 \
  --tenant-id test-tenant \
  --account-id f6d24b5d-51ed-47b7-9f6a-0ad194156b5e \
  --dry-run     ← prints to stdout, no DB write

# Check output looks correct before writing
python engines/discoveries/run_scan.py \
  --provider azure \
  --services compute \
  --regions eastus \
  --scan-run-id test-azure-smoke-001 \
  --tenant-id test-tenant \
  --account-id f6d24b5d-51ed-47b7-9f6a-0ad194156b5e
```

### Validate DB after service smoke:
```sql
-- How many findings for this service?
SELECT service, resource_type, COUNT(*) 
FROM discovery_findings 
WHERE scan_run_id = 'test-azure-smoke-001' AND provider = 'azure'
GROUP BY service, resource_type;

-- Sample a finding — does it look right?
SELECT resource_uid, resource_type, emitted_fields
FROM discovery_findings
WHERE scan_run_id = 'test-azure-smoke-001'
LIMIT 3;
```

### Validation checklist per service:
- [ ] `provider` = 'azure' (or gcp/k8s/etc.)
- [ ] `resource_uid` is non-null and has correct format (ARM ID / GCP name / K8s UID)
- [ ] `resource_type` is normalized (VirtualMachine, not Microsoft.Compute/virtualMachines)
- [ ] `emitted_fields` JSONB is non-empty
- [ ] `region` is set correctly
- [ ] `account_id` matches the subscription/project/account
- [ ] No `ERROR` or `TIMEOUT` in logs

### Critical services to smoke-test first per CSP:

| CSP | Services for smoke test (in order) |
|-----|-------------------------------------|
| Azure | compute, network, storage, keyvault, authorization |
| GCP | compute, storage, container, iam, cloudkms |
| K8s | pods, services, serviceaccounts, clusterroles, clusterrolebindings |
| OCI | compute, network, identity, objectstorage |
| IBM | vpc, iam, resource_controller |
| AliCloud | ecs, vpc, ram, oss |

---

## Layer 3 — Engine Smoke Test (10 Services, 1 Region, 1 Engine)

**What:** Run one engine fully with a curated set of 10 most critical services.
**When:** After Layer 2 passes for all 5+ services. Test each engine independently.
**Duration:** 2-5 minutes per engine.

### Controlled service list per CSP (10 critical services only):

**Azure smoke services:**
```yaml
azure_smoke_services:
  - compute        # VMs
  - network        # NSGs, VNets
  - storage        # Storage accounts
  - keyvault       # Key vaults
  - sql            # SQL servers
  - authorization  # RBAC role assignments
  - containerservice # AKS
  - web            # App services
  - security       # Defender for Cloud settings
  - msi            # Managed identities
```

**GCP smoke services:**
```yaml
gcp_smoke_services:
  - compute        # GCE instances, firewalls
  - storage        # GCS buckets
  - container      # GKE clusters
  - iam            # Service accounts, IAM policies
  - cloudkms       # Key rings, crypto keys
  - sqladmin       # Cloud SQL
  - cloudfunctions # Functions
  - run            # Cloud Run
  - bigquery       # Datasets
  - cloudresourcemanager # Project IAM
```

### Engine-by-engine smoke test commands:

**Discovery smoke:**
```bash
python engines/discoveries/run_scan.py \
  --provider azure \
  --services compute,network,storage,keyvault,sql \
  --regions eastus \
  --scan-run-id smoke-azure-$(date +%s) \
  --tenant-id dev-tenant \
  --account-id f6d24b5d
```

**Check engine smoke (after discovery):**
```bash
# Run check engine against the smoke scan_run_id
python engines/check/run_scan.py \
  --scan-run-id smoke-azure-<id> \
  --provider azure \
  --limit-rules 50   ← run first 50 rules only for speed
```

Validate:
```sql
SELECT status, COUNT(*) FROM check_findings 
WHERE scan_run_id = 'smoke-azure-<id>' AND provider = 'azure'
GROUP BY status;
-- Expect: PASS + FAIL rows. Zero rows = bug.
```

**Inventory smoke:**
```bash
python engines/inventory/run_scan.py \
  --scan-run-id smoke-azure-<id> \
  --provider azure
```

Validate:
```sql
SELECT resource_type, COUNT(*) FROM inventory_findings
WHERE scan_run_id = 'smoke-azure-<id>'
GROUP BY resource_type;
-- Expect: VirtualMachine, StorageAccount, etc.
-- Check inventory_relationships table too.
```

**Threat engine smoke:**
```bash
python engines/threat/run_scan.py \
  --scan-run-id smoke-azure-<id> \
  --provider azure
```

Validate:
```sql
SELECT threat_category, severity, COUNT(*) FROM threat_findings
WHERE scan_run_id = 'smoke-azure-<id>'
GROUP BY threat_category, severity;
```

**IAM smoke:**
```bash
python engines/iam/run_scan.py \
  --scan-run-id smoke-azure-<id> \
  --provider azure
```

**Compliance smoke:**
```bash
python engines/compliance/run_scan.py \
  --scan-run-id smoke-azure-<id> \
  --provider azure \
  --framework cis_azure_1_5
```

Validate:
```sql
SELECT compliance_framework, controls_passed, controls_failed 
FROM compliance_report 
WHERE scan_run_id = 'smoke-azure-<id>';
```

### Engine smoke checklist:
- [ ] No unhandled exceptions in logs
- [ ] DB rows written for this scan_run_id
- [ ] `provider` column = correct value
- [ ] No null `resource_uid` in findings
- [ ] severity distribution looks reasonable (not all CRITICAL)
- [ ] `scan_runs.engine_statuses` updated for this engine

---

## Layer 4 — Pipeline Smoke (10 Services, All Engines)

**What:** Full Argo pipeline with limited services. Tests engine-to-engine data flow.
**When:** Before declaring a CSP "ready for full scan."
**Duration:** 15-20 minutes.

### How to run with limited services:

Option A — Disable unused services in DB before smoke:
```sql
-- Temporarily disable all Azure services except smoke set
UPDATE rule_discoveries 
SET is_active = false 
WHERE provider = 'azure' 
  AND service NOT IN ('compute','network','storage','keyvault','sql',
                      'authorization','containerservice','web','security','msi');

-- Run pipeline
-- After: re-enable all
UPDATE rule_discoveries SET is_active = true WHERE provider = 'azure';
```

Option B — Pass `--services` arg to Argo workflow (pipeline param):
```bash
argo submit deployment/aws/eks/argo/cspm-pipeline.yaml \
  -p scan-run-id=$(uuidgen) \
  -p tenant-id=dev-tenant \
  -p account-id=f6d24b5d \
  -p provider=azure \
  -p services=compute,network,storage,keyvault,sql \
  -n argo
```

### Pipeline smoke pass criteria:
- [ ] All engines complete (no `failed` status in scan_runs.engine_statuses)
- [ ] `scan_runs.overall_status` = 'completed'
- [ ] discovery_findings: > 0 rows
- [ ] check_findings: > 0 rows with PASS + FAIL
- [ ] inventory_findings: > 0 rows + inventory_relationships populated
- [ ] threat_findings: > 0 rows
- [ ] compliance_report: score computed (not null)
- [ ] iam_findings: > 0 rows
- [ ] datasec_findings: ≥ 0 rows (OK if 0 — datasec may not trigger on all services)
- [ ] Pipeline duration < 20 minutes

### Validate all engines at once:
```sql
SELECT 'discoveries' as engine, COUNT(*) FROM discovery_findings WHERE scan_run_id = '<id>'
UNION ALL
SELECT 'check', COUNT(*) FROM check_findings WHERE scan_run_id = '<id>'
UNION ALL
SELECT 'inventory', COUNT(*) FROM inventory_findings WHERE scan_run_id = '<id>'
UNION ALL
SELECT 'threat', COUNT(*) FROM threat_findings WHERE scan_run_id = '<id>'
UNION ALL
SELECT 'iam', COUNT(*) FROM iam_findings WHERE scan_run_id = '<id>'
UNION ALL
SELECT 'datasec', COUNT(*) FROM datasec_findings WHERE scan_run_id = '<id>'
ORDER BY engine;
```

---

## Layer 5 — Full Scan (All Services, All Regions, All Engines)

**What:** Production-equivalent scan with all services enabled.
**When:** Once Layer 4 passes. Run before tagging as production-ready.
**Duration:** 30-60 minutes per CSP.

### Gate criteria before running Layer 5:
- [ ] Layer 1: All unit tests pass
- [ ] Layer 2: All 5 critical services smoke-passed
- [ ] Layer 3: All 7 engines smoke-passed
- [ ] Layer 4: Full pipeline smoke-passed with 10 services

### Full scan trigger:
```bash
bash deployment/aws/eks/argo/trigger-scan.sh \
  $(uuidgen) \
  production-tenant \
  f6d24b5d-51ed-47b7-9f6a-0ad194156b5e \
  azure
```

### Full scan pass criteria:
- [ ] Duration < 60 minutes
- [ ] < 1% timeout rate in discovery logs
- [ ] compliance_score > 0 (real score, not null)
- [ ] risk_report populated
- [ ] No engine in `failed` status
- [ ] UI displays data correctly for this CSP

---

## CSP-Specific Test Fixtures

### Fixture data (mocked API responses for unit tests)

Each CSP scanner needs a `tests/fixtures/` directory:

```
engines/discoveries/providers/azure/tests/fixtures/
    compute_list_vms.json         ← sample Azure VM list response
    network_list_nsgs.json        ← sample NSG list response
    storage_list_accounts.json    ← sample storage account response

engines/discoveries/providers/gcp/tests/fixtures/
    compute_instances.json        ← sample GCE instance list
    storage_buckets.json
    container_clusters.json

engines/discoveries/providers/kubernetes/tests/fixtures/
    pods.json                     ← sample kubectl get pods -o json output
    clusterroles.json
    networkpolicies.json
```

Generate fixtures by running a real API call once and saving the response:
```python
# One-time fixture generation (run locally, commit the JSON)
response = compute_client.virtual_machines.list_all()
with open("tests/fixtures/compute_list_vms.json", "w") as f:
    json.dump([vm.as_dict() for vm in response], f, indent=2, default=str)
```

---

## Development Flow Per Engine Per CSP

```
Day 1: 
  → Write unit tests (Layer 1) FIRST (TDD approach)
  → Implement auth + client factory
  → Unit tests pass

Day 2:
  → Add pagination + normalization
  → Unit tests pass
  → Layer 2: service smoke for 2-3 services

Day 3:
  → All 10 smoke services passing Layer 2
  → Layer 3: discovery engine smoke

Day 4-5 (per engine):
  → Write check rules for 20-30 rules
  → Layer 3: check engine smoke
  → Repeat for inventory, threat, IAM, datasec, compliance

Day N:
  → Layer 4: pipeline smoke (10 services)
  → Fix issues
  → Layer 5: full scan
```

---

## Quick Validation Commands (reference card)

```bash
# Check discovery found anything
PGPASSWORD=<pw> psql -h <rds> -U postgres -d threat_engine_discoveries \
  -c "SELECT provider, COUNT(*) FROM discovery_findings WHERE scan_run_id='<id>' GROUP BY provider;"

# Check all engines wrote to DB
PGPASSWORD=<pw> psql -h <rds> -U postgres -d threat_engine_check \
  -c "SELECT status, COUNT(*) FROM check_findings WHERE scan_run_id='<id>' GROUP BY status;"

# Pipeline status
PGPASSWORD=<pw> psql -h <rds> -U postgres -d threat_engine_onboarding \
  -c "SELECT overall_status, engine_statuses FROM scan_runs WHERE scan_run_id='<id>';"

# Argo workflow status
argo get <workflow-name> -n argo

# Engine logs (last 100 lines)
kubectl logs -l app=engine-discoveries -n threat-engine-engines --tail=100
kubectl logs -l app=engine-check-aws -n threat-engine-engines --tail=100

# Run Layer 1 unit tests for Azure scanner
cd /Users/apple/Desktop/threat-engine
pytest engines/discoveries/providers/azure/tests/ -v --tb=short -x

# Run Layer 2 service smoke (Azure compute, dry-run)
python engines/discoveries/run_scan.py \
  --provider azure --services compute --regions eastus \
  --scan-run-id smoke-test-001 --dry-run
```

---

## Test Coverage Targets Per CSP Before Full Scan

| Coverage area | Minimum before Layer 5 |
|--------------|------------------------|
| Unit tests | 80% of scanner functions |
| Service smoke (Layer 2) | 5 critical services pass |
| Engine smoke (Layer 3) | All 7 engines pass |
| Pipeline smoke (Layer 4) | 10-service pipeline < 20 min |
| Rule count in rule_metadata | ≥ 50 rules for CSP |
| Compliance framework in DB | At least 1 framework seeded |
| Inventory relationships in DB | At least 5 relationship rules |

---

## Bug Triage by Layer

| Symptom | Start at |
|---------|---------|
| Scanner crashes on auth | Layer 1: test_auth.py |
| Scanner returns 0 findings | Layer 2: service smoke with debug logging |
| Wrong resource_type in DB | Layer 1: test_normalization.py |
| Pagination stops early | Layer 1: test_pagination.py |
| Check engine: 0 findings | Layer 3: check smoke — check rule_metadata has provider rows |
| Inventory: 0 relationships | Layer 3: check resource_security_relationship_rules is seeded |
| Threat: 0 findings | Layer 3: check mitre_technique_reference has CSP checks column |
| Pipeline: engine stuck | Layer 4: check Argo step logs + engine_statuses in scan_runs |
| Compliance: 0 score | Layer 3: verify compliance_frameworks + rule_control_mapping seeded |
| Timeout in full scan | Check `rule_discoveries.max_discovery_workers` for the service |