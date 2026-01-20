# Full Compliance Test Guide

## Overview

This guide walks through running a complete end-to-end test:
1. **Full AWS Compliance Scan** (all accounts, regions, services)
2. **Compliance Report Generation** (from scan results)
3. **Multi-Format Export** (PDF, CSV, JSON)
4. **S3 Storage** (all reports saved to S3)

## S3 Structure

```
s3://cspm-lgtech/
├── aws-compliance-engine/output/{scan_id}/
│   ├── results.ndjson          # Scan results
│   └── summary.json            # Scan summary
└── compliance-engine/output/{csp}/{report_id}/
    ├── report.json             # Full compliance report (JSON)
    ├── executive_summary.pdf   # Executive dashboard (PDF)
    ├── executive_summary.csv   # Executive dashboard (CSV)
    ├── {framework}_report.pdf  # Framework-specific report (PDF)
    └── {framework}_report.csv  # Framework-specific report (CSV)
```

## Prerequisites

1. **AWS Compliance Engine** deployed and running
2. **Compliance Engine** deployed and running
3. **S3 Bucket** `cspm-lgtech` exists
4. **IAM Permissions** for S3 read/write

## Step-by-Step Test

### Option 1: Automated Script

```bash
cd /Users/apple/Desktop/threat-engine
./compliance-engine/trigger_full_scan_and_report.sh
```

This script will:
- Trigger full AWS scan
- Wait for completion
- Generate compliance reports
- Export to PDF/CSV
- Save everything to S3

### Option 2: Manual Steps

#### Step 1: Trigger Full AWS Scan

```bash
# Get AWS engine URL
AWS_ENGINE_URL=$(kubectl get svc aws-compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Trigger scan (all accounts, regions, services)
curl -X POST "http://${AWS_ENGINE_URL}/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "account": null,
    "include_accounts": null,
    "include_regions": null,
    "include_services": null,
    "stream_results": true
  }'

# Response: {"scan_id": "xxx", "status": "running", "message": "Scan started"}
```

#### Step 2: Monitor Scan Progress

```bash
SCAN_ID="your-scan-id-here"

# Check status
curl "http://${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/status"

# Monitor until status is "completed"
while true; do
  STATUS=$(curl -s "http://${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/status" | jq -r '.status')
  echo "Status: $STATUS"
  if [ "$STATUS" == "completed" ]; then
    break
  fi
  sleep 30
done
```

#### Step 3: Generate Compliance Report

```bash
# Get compliance engine URL
COMPLIANCE_ENGINE_URL=$(kubectl get svc compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Generate report
curl -X POST "http://${COMPLIANCE_ENGINE_URL}/api/v1/compliance/generate" \
  -H "Content-Type: application/json" \
  -d "{
    \"scan_id\": \"${SCAN_ID}\",
    \"csp\": \"aws\"
  }"

# Response: {"report_id": "xxx", "status": "completed", "compliance_report": {...}}
```

#### Step 4: Export Reports

```bash
REPORT_ID="your-report-id-here"

# Export PDF
curl "http://${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=pdf" \
  -o compliance_report.pdf

# Export CSV
curl "http://${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=csv" \
  -o compliance_report.csv

# Export JSON
curl "http://${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=json" \
  -o compliance_report.json
```

#### Step 5: Verify S3 Storage

```bash
REPORT_ID="your-report-id-here"

# List files in S3
aws s3 ls s3://cspm-lgtech/compliance-engine/output/aws/${REPORT_ID}/

# Download from S3
aws s3 sync s3://cspm-lgtech/compliance-engine/output/aws/${REPORT_ID}/ ./reports/
```

## API Endpoints

### Compliance Engine Endpoints

- `POST /api/v1/compliance/generate` - Generate compliance report
- `GET /api/v1/compliance/report/{report_id}` - Get report
- `GET /api/v1/compliance/report/{report_id}/export?format={pdf|csv|json}` - Export report
- `GET /api/v1/compliance/framework/{framework}/status` - Framework status
- `GET /api/v1/compliance/resource/drilldown` - Resource drill-down

### AWS Compliance Engine Endpoints

- `POST /api/v1/scan` - Start scan
- `GET /api/v1/scan/{scan_id}/status` - Check scan status
- `GET /api/v1/scan/{scan_id}/results` - Get scan results

## Report Formats

### JSON
- Full compliance report with all details
- Includes executive dashboard, framework reports, controls
- Best for programmatic access

### PDF
- Executive summary with compliance scores
- Framework summary tables
- Findings summary
- Best for executive presentations and audits

### CSV
- Framework compliance summary
- Control-by-control status
- Best for spreadsheet analysis

## Expected Output

After running the full test, you should have:

1. **Scan Results in S3**:
   - `s3://cspm-lgtech/aws-compliance-engine/output/{scan_id}/results.ndjson`
   - `s3://cspm-lgtech/aws-compliance-engine/output/{scan_id}/summary.json`

2. **Compliance Reports in S3**:
   - `s3://cspm-lgtech/compliance-engine/output/aws/{report_id}/report.json`
   - `s3://cspm-lgtech/compliance-engine/output/aws/{report_id}/executive_summary.pdf`
   - `s3://cspm-lgtech/compliance-engine/output/aws/{report_id}/executive_summary.csv`
   - `s3://cspm-lgtech/compliance-engine/output/aws/{report_id}/{framework}_report.pdf` (for each framework)
   - `s3://cspm-lgtech/compliance-engine/output/aws/{report_id}/{framework}_report.csv` (for each framework)

## Troubleshooting

### Scan Not Starting
- Check AWS engine pod logs: `kubectl logs -n threat-engine-engines -l app=aws-compliance-engine`
- Verify IAM permissions for AWS access
- Check service account configuration

### Report Generation Failing
- Check compliance engine pod logs: `kubectl logs -n threat-engine-engines -l app=compliance-engine`
- Verify scan results exist in S3
- Check S3 read permissions

### PDF Export Failing
- Verify `reportlab` is installed: `pip install reportlab`
- Check pod logs for import errors
- Ensure sufficient memory for PDF generation

### S3 Storage Not Working
- Verify IAM role has S3 write permissions
- Check service account annotation for IRSA
- Verify bucket exists: `aws s3 ls s3://cspm-lgtech/`

## Performance Notes

- **Full Scan**: May take 30-60 minutes depending on account size
- **Report Generation**: Typically 1-5 seconds
- **PDF Export**: Typically 1-3 seconds
- **S3 Sync**: Automatic, happens in background

## Next Steps

1. ✅ Full scan and report generation working
2. ⏳ Add database storage for historical trends
3. ⏳ Add scheduled report generation
4. ⏳ Add email notifications
5. ⏳ Add dashboard visualization

