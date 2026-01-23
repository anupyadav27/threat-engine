# Threat Engine Implementation Summary

## Overview

Successfully implemented both the **configScan engine enhancement** and the **threat-engine** development as requested.

## 1. ConfigScan Engine Enhancement ✅

### Changes Made

**File**: `configScan_engines/aws-configScan-engine/engine/service_scanner.py`

1. **Added `extract_resource_identifier()` helper function**:
   - Extracts `resource_id`, `resource_type`, `resource_arn`, and `resource_uid` from item data
   - Supports service-specific extraction (S3, IAM, EC2, RDS, KMS, Lambda, etc.)
   - Generates ARN using existing `generate_arn()` utility
   - Creates fallback `resource_uid` if ARN is not available

2. **Enhanced `run_global_service()`**:
   - Extracts `account_id` from STS session
   - Calls `extract_resource_identifier()` for each check item
   - Adds `resource_uid`, `resource_arn`, `resource_id`, `resource_type` to check records

3. **Enhanced `run_regional_service()`**:
   - Same enhancements as global service
   - Uses region-specific account extraction

### Impact

- **Before**: NDJSON output had empty/incomplete resource identifiers
- **After**: Every check record includes:
  - `resource_uid`: Stable unique identifier (ARN preferred)
  - `resource_arn`: Full AWS ARN when available
  - `resource_id`: Resource-specific ID
  - `resource_type`: Normalized resource type

This enables **asset-level threat detection** instead of only account/region-level threats.

## 2. Threat Engine Development ✅

### Structure Created

```
threat-engine/
├── threat_engine/
│   ├── schemas/
│   │   ├── threat_report_schema.py      # cspm_threat_report.v1 schema
│   │   ├── misconfig_normalizer.py      # NDJSON → normalized findings
│   │   └── __init__.py
│   ├── detector/
│   │   ├── threat_detector.py          # Threat detection patterns
│   │   └── __init__.py
│   ├── reporter/
│   │   ├── threat_reporter.py          # Report generation
│   │   └── __init__.py
│   ├── api_server.py                    # FastAPI server
│   └── __init__.py
├── Dockerfile
├── requirements.txt
└── README.md
```

### Key Components

#### 1. Threat Report Schema (`cspm_threat_report.v1`)
- **Tenant & Scan Context**: Tenant info and scan metadata
- **Threat Summary**: Statistics (total, by severity, by category, by status)
- **Threats**: Individual threat detections with:
  - Threat type (exposure, identity, lateral_movement, etc.)
  - Severity and confidence
  - Correlations to misconfig findings
  - Affected assets
  - Evidence references
  - Remediation guidance
- **Misconfig Findings**: Normalized findings from scan
- **Asset Snapshots**: Unique assets referenced in threats

#### 2. Misconfig Normalizer
- Converts NDJSON lines to normalized `MisconfigFinding` objects
- Generates stable finding IDs using `rule_id|resource_uid|account|region`
- Handles missing resource identifiers with fallback logic
- Supports both S3 and local file sources

#### 3. Threat Detector
- **Pattern Matching**: Detects threats using regex patterns on rule IDs
- **Threat Categories**:
  - **Exposure**: Public access + internet reachable
  - **Identity**: Permissive IAM + privileged access + no MFA
  - **Lateral Movement**: Open inbound + reachable subnet + high privileges
  - **Data Exfiltration**: Public storage + sensitive data + weak logging
  - **Privilege Escalation**: IAM policies allowing escalation
  - **Data Breach**: Database/public resource misconfigurations
- **Correlation**: Links threats to root-cause misconfig findings
- **Grouping**: Groups related findings into single threats

#### 4. Threat Reporter
- Generates complete threat reports
- Calculates summary statistics
- Extracts unique asset snapshots
- Links threats to misconfig findings

#### 5. API Server
- **POST `/api/v1/threat/generate`**: Generate from scan results (S3/local)
- **POST `/api/v1/threat/generate/from-ndjson`**: Generate from NDJSON content
- Supports all CSPs (AWS, Azure, GCP, etc.)

### Deployment

#### Local (Docker Compose)
- **Port**: 8004 (host) → 8000 (container)
- **Volume**: Mounts `engines-output/` for scan results
- **Environment**: `USE_S3=false` for local development

#### AWS (EKS)
- **Port**: 80 (service) → 8000 (container)
- **S3**: Loads results from `s3://cspm-lgtech/{csp}-configScan-engine/output/{scan_id}/`
- **IRSA**: Uses IAM role for S3 access
- **LoadBalancer**: Optional external access

## Testing

### Local Testing

1. **Run configScan engine** to generate NDJSON with resource identifiers:
```bash
cd configScan_engines/aws-configScan-engine
python -m engine.main_scanner scan --stream_results
```

2. **Generate threat report**:
```bash
cd threat-engine
python -m uvicorn threat_engine.api_server:app --reload --port 8004
```

3. **Call API**:
```bash
curl -X POST http://localhost:8004/api/v1/threat/generate \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-123",
    "scan_run_id": "scan-456",
    "cloud": "aws",
    "trigger_type": "manual",
    "accounts": ["123456789012"],
    "regions": ["us-east-1"],
    "services": ["s3", "iam"],
    "started_at": "2024-01-01T00:00:00Z",
    "completed_at": "2024-01-01T01:00:00Z"
  }'
```

### Expected Output

The threat report will include:
- **Threat Summary**: Total threats, counts by severity/category
- **Threats**: List of detected threats with:
  - Threat type and severity
  - Correlated misconfig finding IDs
  - Affected assets
  - Remediation guidance
- **Misconfig Findings**: Normalized findings from scan
- **Asset Snapshots**: Unique assets

## Next Steps

1. **Test with real scan results**: Run a full AWS scan and generate threat report
2. **Enhance detection patterns**: Add more threat patterns based on real-world scenarios
3. **Add graph context**: Integrate asset relationship data for better correlation
4. **Export formats**: Add PDF/CSV export similar to compliance engine
5. **Database storage**: Store threat reports in PostgreSQL for historical tracking

## Files Modified/Created

### Modified
- `configScan_engines/aws-configScan-engine/engine/service_scanner.py` - Added resource identifier extraction

### Created
- `threat-engine/threat_engine/schemas/threat_report_schema.py`
- `threat-engine/threat_engine/schemas/misconfig_normalizer.py`
- `threat-engine/threat_engine/detector/threat_detector.py`
- `threat-engine/threat_engine/reporter/threat_reporter.py`
- `threat-engine/threat_engine/api_server.py`
- `threat-engine/Dockerfile`
- `threat-engine/requirements.txt`
- `threat-engine/README.md`
- `deployment/local/docker-compose/docker-compose.yml` (updated)
- `deployment/local/kubernetes/threat-engine-deployment.yaml`
- `deployment/aws/eks/threat-engine-deployment.yaml`

## Port Mapping

| Service | Local Port | Container Port | EKS Service Port |
|---------|-----------|----------------|------------------|
| AWS ConfigScan Engine | 8000 | 8000 | 80 |
| Compliance Engine | 8001 | 8000 | 80 |
| Rule Engine | 8002 | 8000 | 80 |
| Onboarding Engine | 8003 | 8000 | 80 |
| **Threat Engine** | **8004** | **8000** | **80** |

## Summary

✅ **ConfigScan Enhancement**: Resource identifiers now included in all check records  
✅ **Threat Engine**: Complete implementation with detection, correlation, and reporting  
✅ **Deployment**: Added to both local and AWS deployment configs  
✅ **Documentation**: README and implementation summary created

The threat engine is ready for testing and can now generate asset-level threats thanks to the configScan enhancement!

