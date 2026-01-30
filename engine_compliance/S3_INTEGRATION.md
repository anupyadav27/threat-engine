# S3 Integration Guide

## S3 Structure for CSP Engines

The compliance engine loads scan results from S3 using the following structure:

```
s3://cspm-lgtech/
├── aws-configScan-engine/output/
│   └── {scan_id}/
│       ├── results.ndjson      # NDJSON format (one JSON object per line)
│       └── summary.json       # Scan summary metadata
├── azure-configScan-engine/output/
│   └── {scan_id}/
│       ├── results.ndjson
│       └── summary.json
├── gcp-configScan-engine/output/
│   └── {scan_id}/
│       ├── results.ndjson
│       └── summary.json
├── alicloud-configScan-engine/output/
│   └── {scan_id}/
│       ├── results.ndjson
│       └── summary.json
├── oci-configScan-engine/output/
│   └── {scan_id}/
│       ├── results.ndjson
│       └── summary.json
├── ibm-configScan-engine/output/
│   └── {scan_id}/
│       ├── results.ndjson
│       └── summary.json
└── k8s-configScan-engine/output/
    └── {scan_id}/
        ├── results.ndjson
        └── summary.json
```

## CSP to S3 Path Mapping

The compliance engine automatically maps CSP names to S3 paths:

| CSP Name | S3 Path |
|----------|---------|
| `aws` | `aws-configScan-engine/output` |
| `azure` | `azure-configScan-engine/output` |
| `gcp` | `gcp-configScan-engine/output` |
| `alicloud` | `alicloud-configScan-engine/output` |
| `oci` | `oci-configScan-engine/output` |
| `ibm` | `ibm-configScan-engine/output` |
| `k8s` | `k8s-configScan-engine/output` |

## Results.ndjson Format

Each line in `results.ndjson` is a separate JSON object representing a service/region scan result:

```json
{
  "account_id": "588989875114",
  "service": "accessanalyzer",
  "region": "us-east-1",
  "scope": "global",
  "checks": [
    {
      "rule_id": "aws.accessanalyzer.resource.access_analyzer_enabled",
      "result": "FAIL",
      "severity": "medium",
      "resource": {
        "arn": "arn:aws:access-analyzer:us-east-1:588989875114:analyzer/...",
        "type": "accessanalyzer",
        "id": "..."
      },
      "evidence": {
        "status": "INACTIVE",
        "checked_at": "2026-01-13T07:27:00Z"
      }
    }
  ]
}
```

## Summary.json Format

The `summary.json` file contains scan metadata:

```json
{
  "scan_id": "9c5ebb5b-5e68-4b9f-9851-6c5697f1d1f0",
  "total_checks": 150,
  "passed_checks": 120,
  "failed_checks": 30,
  "results_file": "results.ndjson",
  "report_folder": "/output/9c5ebb5b-5e68-4b9f-9851-6c5697f1d1f0"
}
```

## Loading Process

1. **S3 Primary**: Try to load from S3 first
   - Path: `s3://cspm-lgtech/{csp}-configScan-engine/output/{scan_id}/results.ndjson`
   - Falls back to `summary.json` if `results.ndjson` not found

2. **Local Fallback**: If S3 fails, try local filesystem
   - Path: `engines-output/{csp}-configScan-engine/output/{scan_id}/results.ndjson`
   - Or: `{OUTPUT_DIR}/{scan_id}/results.ndjson` (for container environments)
   - `OUTPUT_DIR` defaults to `/output`

3. **Error**: If both fail, return 404 error

## Environment Variables

- `S3_BUCKET`: S3 bucket name (default: `cspm-lgtech`)
- `OUTPUT_DIR`: Local output directory (default: `/output`)
- `AWS_REGION`: AWS region (default: `ap-south-1`)

## IAM Permissions Required

The compliance engine needs S3 read permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::cspm-lgtech",
        "arn:aws:s3:::cspm-lgtech/*"
      ]
    }
  ]
}
```

## Testing S3 Access

```bash
# Test S3 access from compliance engine pod
kubectl exec -n threat-engine-engines <compliance-engine-pod> -- \
  aws s3 ls s3://cspm-lgtech/aws-configScan-engine/output/

# List scan IDs
aws s3 ls s3://cspm-lgtech/aws-configScan-engine/output/ | grep PRE

# Check if results.ndjson exists for a scan
aws s3 ls s3://cspm-lgtech/aws-configScan-engine/output/{scan_id}/
```

