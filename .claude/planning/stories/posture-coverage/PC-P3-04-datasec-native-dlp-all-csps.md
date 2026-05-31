# Story PC-P3-04: DataSec Engine — Native DLP Integration Across All CSPs

## Status: ready

## Metadata
- **Phase**: P3 — Tier C (requires native DLP services enabled per cloud account; cost implications per CSP)
- **Sprint**: Posture Coverage Enhancement — Planning Track
- **Points**: 13
- **Priority**: P3
- **Depends on**: DataSec engine baseline (v-datasec-pydantic1), multi-cloud discovery (all CSPs)
- **RACI**: R=DEV A=DL C=SA I=PO
- **Security Gate**: bmad-security-architect + bmad-security-reviewer

## Gap Being Closed

**Current state:** DataSec classification is regex-based on resource names and tags only. An S3 bucket named `analytics-export-2026` that contains 10M SSNs gets classified as `unknown`. The same problem exists for Azure Blob containers, GCP Cloud Storage buckets, OCI Object Storage, and Alibaba OSS — all CSPs rely on name/tag heuristics, not actual content inspection.

**What's needed:** A unified DLP ingester that reads results from each CSP's native data classification service, normalises them into our `data_classification` taxonomy, and writes authoritative signals to `resource_security_posture`.

**Why Tier C:**
1. Each CSP's DLP service must be explicitly enabled per cloud account (cost + IAM setup)
2. Results are asynchronous — jobs take minutes to hours for large datasets
3. Requires tenant opt-in per CSP (separate `dlp_enabled` flag per provider in onboarding)

## Per-CSP DLP Service Map

| CSP | Native DLP Service | Data Coverage | Auth Required |
|-----|-------------------|---------------|---------------|
| **AWS** | Amazon Macie | S3 buckets | `macie2:GetFindings`, `macie2:ListFindings` |
| **Azure** | Microsoft Purview (formerly Azure Information Protection) | Blob Storage, ADLS Gen2, SQL | Purview Data Map Reader role |
| **GCP** | Cloud Data Loss Prevention (Cloud DLP) API | Cloud Storage, BigQuery, Datastore | `roles/dlp.reader` on project |
| **OCI** | OCI Data Safe (sensitive data discovery) | Object Storage, Autonomous DB, MySQL | `dataSafe-inspect-dataset` policy |
| **AliCloud** | Sensitive Data Discovery and Protection (SDDP) | OSS, RDS, MaxCompute | RAM policy for SDDP read |
| **IBM Cloud** | IBM OpenPages / Watson Knowledge Catalog | Cloud Object Storage | IAM `Reader` on catalog |

**Fallback for all CSPs:** When native DLP is not enabled, the existing regex heuristic (current behavior) is preserved unchanged.

## Classification Taxonomy Mapping

Normalise each CSP's classification labels to our taxonomy:

| Our Label | AWS Macie | Azure Purview | GCP DLP | OCI Data Safe | AliCloud SDDP |
|-----------|-----------|---------------|---------|---------------|---------------|
| `pii` | `PERSONAL_INFORMATION` | `Personal` | `PERSON_NAME`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SOCIAL_SECURITY_NUMBER` | `HCM_SENSITIVE` | `PERSONAL_INFO` |
| `phi` | `PERSONAL_HEALTH_INFORMATION` | `Medical/Health` | `US_DEA_NUMBER`, `MEDICAL_RECORD_NUMBER` | `HEALTH_SENSITIVE` | `HEALTH_INFO` |
| `pci` | `FINANCIAL` | `Financial` | `CREDIT_CARD_NUMBER`, `US_BANK_ROUTING_MICR` | `FINANCIAL_SENSITIVE` | `FINANCIAL_INFO` |
| `restricted` | `CREDENTIALS` | `Credentials/Keys` | `AUTH_TOKEN`, `AWS_CREDENTIALS`, `GCP_API_KEY` | `AUTH_SENSITIVE` | `SECRET_KEY` |
| `confidential` | `CUSTOM_IDENTIFIER` | `Custom sensitive` | `CUSTOM_DICTIONARY` | `USER_DEFINED` | `CUSTOM_SENSITIVE` |

## Implementation Architecture

### 1. DLP Ingester Base Class

**New file:** `engines/datasec/data_security_engine/dlp/base_dlp_ingester.py`

```python
class BaseDLPIngester(ABC):
    """Common interface all CSP-specific ingesters implement."""
    
    @abstractmethod
    def is_enabled(self, account_id: str, region: str) -> bool:
        """Check if DLP service is active for this account."""
    
    @abstractmethod
    def fetch_findings(self, account_id: str, scan_run_id: str, tenant_id: str) -> List[DLPFinding]:
        """Fetch and normalise DLP findings for this account."""
    
    def map_classification(self, native_type: str) -> str:
        """Normalise CSP label → our taxonomy. Must be implemented per CSP."""
```

### 2. Per-CSP Ingester Modules

**New files:**
- `engines/datasec/data_security_engine/dlp/aws_macie.py` — AWS implementation
- `engines/datasec/data_security_engine/dlp/azure_purview.py` — Azure implementation
- `engines/datasec/data_security_engine/dlp/gcp_dlp.py` — GCP implementation
- `engines/datasec/data_security_engine/dlp/oci_datasafe.py` — OCI implementation
- `engines/datasec/data_security_engine/dlp/alicloud_sddp.py` — AliCloud implementation

**Dispatcher in `run_scan.py`:**
```python
INGESTER_MAP = {
    "aws":      MacieDLPIngester,
    "azure":    PurviewDLPIngester,
    "gcp":      GCPDLPIngester,
    "oci":      OciDataSafeIngester,
    "alicloud": AlicloudSDDPIngester,
}

ingester = INGESTER_MAP.get(provider)
if ingester and ingester.is_enabled(account_id, region):
    dlp_findings = ingester.fetch_findings(account_id, scan_run_id, tenant_id)
    # Write to datasec_data_catalog with dlp_classified=TRUE
```

### 3. Database — New DLP Columns

**New migration (extend migration 024 or new 026):**
```sql
ALTER TABLE datasec_data_catalog
    ADD COLUMN IF NOT EXISTS dlp_classified     BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dlp_provider       VARCHAR(50),     -- 'macie'/'purview'/'gcp_dlp'/etc
    ADD COLUMN IF NOT EXISTS dlp_object_count   INTEGER  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS dlp_scanned_at     TIMESTAMPTZ;
```

### 4. Posture Signal Enhancement

When DLP classification exists, override the regex heuristic in `datasec/posture_signals.py`:
```python
# Prefer DLP-classified data_classification over regex heuristic
# dlp_classified=TRUE → authoritative; dlp_classified=FALSE → heuristic
```

**New posture columns:**
```sql
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS dlp_classified         BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dlp_sensitive_obj_count INTEGER  NOT NULL DEFAULT 0;
```

### 5. Opt-In Gate

DLP integration is controlled by a per-tenant, per-CSP setting:
```sql
-- In threat_engine_onboarding DB, cloud_accounts table:
ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS dlp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
```

Never enable DLP scanning without explicit `dlp_enabled=TRUE` set during account onboarding. Reason: GCP DLP charges per GB inspected (~$3/GB), Macie charges per resource monitored.

## AWS-Specific: Asynchronous Job Handling

AWS Macie classification jobs run asynchronously and may take hours. Handling:
1. **Check for existing results first:** Query Macie findings for findings created in last 24h
2. **Don't trigger new Macie jobs** — Macie continuous discovery mode creates findings automatically
3. **Watermark pattern:** Store `last_macie_ingested_at` per account; only fetch findings newer than watermark

## GCP-Specific: On-Demand Inspection Job

GCP DLP requires creating an `InspectJob` targeting a Cloud Storage path. The job runs and writes results to BigQuery. Steps:
1. Create `InspectJob` for each bucket → store job ID
2. On next scan run: check `InspectJob.state == DONE` → read results from BigQuery output table
3. Asynchronous — may span two scan cycles for large buckets

## Acceptance Criteria

### Shared (all CSPs)
- [ ] AC-1: `dlp_classified=TRUE` and authoritative `data_classification` set for resources scanned by native DLP
- [ ] AC-2: DLP integration is gated by `dlp_enabled=TRUE` on the cloud account — no DLP calls for accounts where opt-in is absent
- [ ] AC-3: DLP failure (service unreachable, quota exceeded) does NOT affect the DataSec scan — falls back to regex heuristic with WARNING log
- [ ] AC-4: `dlp_provider` column records which service produced the classification (`macie`/`purview`/`gcp_dlp`/`oci_datasafe`/`alicloud_sddp`)

### Per-CSP
- [ ] AC-5: **AWS:** `macie:GetFindings` ingests Macie findings and maps `PERSONAL_INFORMATION` → `pii`
- [ ] AC-6: **Azure:** Purview scan results fetched via `https://management.azure.com/...` — at least one resource gets `data_classification='pii'` from Azure Purview findings
- [ ] AC-7: **GCP:** Cloud DLP inspection job created; on subsequent scan, results read and `data_classification` updated
- [ ] AC-8: **OCI:** Data Safe sensitive data discovery results fetched and normalised
- [ ] AC-9: **AliCloud:** SDDP API results ingested (stub implementation acceptable if SDDP API not yet integrated in discovery)

### Posture Table
- [ ] AC-10: `dlp_classified=TRUE` in `resource_security_posture` for DLP-classified resources
- [ ] AC-11: `dlp_sensitive_obj_count > 0` for storage resources with DLP-detected sensitive objects

## MITRE ATT&CK
| Technique | How addressed |
|-----------|--------------|
| T1530 | Data from Cloud Storage Object — DLP confirms actual PII presence, making `internet_exposed_with_pii` composite flag accurate across all CSPs |
| T1567 | Exfiltration Over Web Service — DLP-classified `restricted` data + `is_internet_exposed` = high-confidence exfil risk |

## Definition of Done
- [ ] Base ingester class + all 5 CSP implementations written
- [ ] `dlp_enabled` opt-in gate wired in account settings
- [ ] New DB columns in datasec_data_catalog + resource_security_posture
- [ ] Integration test per CSP: at least AWS and GCP verified with real DLP results
- [ ] Cost documentation per CSP in engine README
- [ ] New image: `yadavanup84/engine-datasec:v-datasec-dlp1`