# CSP ConfigScan Engines

This directory contains all CSP (Cloud Service Provider) configuration scanning engines.

## Structure

```
configScan_engines/
├── aws-configScan-engine/
├── azure-configScan-engine/
├── gcp-configScan-engine/
├── alicloud-configScan-engine/
├── oci-configScan-engine/
├── ibm-configScan-engine/
└── k8s-configScan-engine/
```

## Output Structure

All engines output scan results to a common location that matches the S3 structure:

```
../engines-output/
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

## Local Testing

Each engine can be run locally and will output to the `engines-output/` directory. The compliance-engine can then read from these directories to generate reports.

## Environment Variables

For local testing, set:
- `OUTPUT_DIR=/Users/apple/Desktop/threat-engine/engines-output/{csp}-configScan-engine`

This matches the S3 structure: `s3://cspm-lgtech/{csp}-configScan-engine/output/`

