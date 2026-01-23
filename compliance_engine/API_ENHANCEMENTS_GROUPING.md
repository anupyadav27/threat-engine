# Compliance Engine API Enhancements - Detailed Grouping

## New APIs Needed

### 1. Framework Report with Detailed Grouping
**Endpoint**: `GET /api/v1/compliance/framework/{framework}/detailed`
**Query Params**: `scan_id`, `csp`
**Response**: Framework report with `grouped_by_control` and `grouped_by_resource`

### 2. Controls Grouped by Control ID
**Endpoint**: `GET /api/v1/compliance/framework/{framework}/controls/grouped`
**Query Params**: `scan_id`, `csp`
**Response**: All controls with resources grouped by control ID

### 3. Resources Grouped by Resource
**Endpoint**: `GET /api/v1/compliance/framework/{framework}/resources/grouped`
**Query Params**: `scan_id`, `csp`
**Response**: All resources with compliance controls grouped by resource

### 4. List All Frameworks (from Consolidated CSV)
**Endpoint**: `GET /api/v1/compliance/frameworks/all`
**Query Params**: `csp`
**Response**: List of all available frameworks from consolidated CSV

### 5. Get Framework Structure
**Endpoint**: `GET /api/v1/compliance/framework/{framework}/structure`
**Query Params**: `csp`
**Response**: Framework structure (sections, categories, controls, services)

### 6. Generate Mock Data
**Endpoint**: `POST /api/v1/compliance/mock/generate`
**Body**: `{ "account_id": "...", "num_resources": 20, "pass_rate": 0.6 }`
**Response**: Mock scan results

### 7. Generate Reports with Separate Files
**Endpoint**: `POST /api/v1/compliance/generate/detailed`
**Body**: `{ "scan_id": "...", "csp": "aws", "save_separate_files": true }`
**Response**: Report IDs and file locations

## Mock Data Structure

```python
{
    "scan_id": "mock-scan-20260123-171400",
    "csp": "aws",
    "account_id": "123456789012",
    "scanned_at": "2026-01-23T17:14:00Z",
    "results": [
        {
            "account_id": "123456789012",
            "region": "us-east-1",
            "service": "s3",
            "checks": [
                {
                    "rule_id": "aws.s3.bucket.block_public_access_enabled",
                    "result": "FAIL",
                    "severity": "high",
                    "resource": {
                        "type": "s3_bucket",
                        "id": "test-bucket-1",
                        "arn": "arn:aws:s3:::test-bucket-1"
                    },
                    "evidence": {"public_access_blocked": False}
                }
            ]
        }
    ]
}
```

## Implementation Files

1. ✅ `compliance_engine/mock/compliance_mock_data.py` - Mock data generator
2. ✅ `compliance_engine/reporter/grouping_helper.py` - Grouping functions
3. ⏳ `compliance_engine/api_server.py` - New API endpoints (to be added)
