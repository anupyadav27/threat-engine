# Engines Output Directory

This directory contains scan results from all CSP ConfigScan engines, matching the S3 structure for easy local testing.

## Structure

```
engines-output/
├── aws-configScan-engine/output/
│   └── {scan_id}/
│       ├── results.ndjson
│       └── summary.json
├── azure-configScan-engine/output/
│   └── {scan_id}/
├── gcp-configScan-engine/output/
│   └── {scan_id}/
├── alicloud-configScan-engine/output/
│   └── {scan_id}/
├── oci-configScan-engine/output/
│   └── {scan_id}/
├── ibm-configScan-engine/output/
│   └── {scan_id}/
└── k8s-configScan-engine/output/
    └── {scan_id}/
```

## Usage

### For Engines
Set `OUTPUT_DIR` environment variable:
```bash
export OUTPUT_DIR="/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output"
```

### For Compliance Engine
The compliance engine automatically reads from this directory when running locally:
```bash
export WORKSPACE_ROOT="/Users/apple/Desktop/threat-engine"
```

## S3 Mapping

This structure matches the S3 bucket structure:
- Local: `engines-output/{csp}-configScan-engine/output/`
- S3: `s3://cspm-lgtech/{csp}-configScan-engine/output/`

This allows engines to work seamlessly in both local and cloud environments.

