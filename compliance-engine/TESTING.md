# Compliance Engine Testing Guide

## Deployment Status

✅ **Deployed and Running**
- **LoadBalancer URL**: `a8e79711ccb6f44d6b79080770de6499-921333edc30e8bb9.elb.ap-south-1.amazonaws.com`
- **Health Endpoint**: `http://<LB_URL>/api/v1/health`
- **Namespace**: `threat-engine-engines`

## Quick Test Commands

### 1. Health Check

```bash
LB_URL=$(kubectl get svc compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

curl http://${LB_URL}/api/v1/health
```

Expected response:
```json
{"status":"healthy","service":"compliance-engine","version":"1.0.0"}
```

### 2. Find Available Scan IDs

```bash
# List scan IDs in S3
aws s3 ls s3://cspm-lgtech/aws-compliance-engine/output/ | grep PRE

# Or from within pod
kubectl exec -n threat-engine-engines -l app=compliance-engine -- \
  aws s3 ls s3://cspm-lgtech/aws-compliance-engine/output/
```

### 3. Generate Compliance Report

```bash
LB_URL=$(kubectl get svc compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

SCAN_ID="56d4e1ae-2ba0-4232-bcf8-ebd89726856b"

curl -X POST http://${LB_URL}/api/v1/compliance/generate \
  -H "Content-Type: application/json" \
  -d "{
    \"scan_id\": \"${SCAN_ID}\",
    \"csp\": \"aws\"
  }"
```

### 4. Get Framework Status

```bash
LB_URL=$(kubectl get svc compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

SCAN_ID="56d4e1ae-2ba0-4232-bcf8-ebd89726856b"

# Get CIS AWS Foundations Benchmark status
curl "http://${LB_URL}/api/v1/compliance/framework/CIS%20AWS%20Foundations%20Benchmark/status?scan_id=${SCAN_ID}&csp=aws"
```

### 5. Get Resource Drill-down

```bash
LB_URL=$(kubectl get svc compliance-engine-lb -n threat-engine-engines \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

SCAN_ID="56d4e1ae-2ba0-4232-bcf8-ebd89726856b"

curl "http://${LB_URL}/api/v1/compliance/resource/drilldown?scan_id=${SCAN_ID}&csp=aws&service=s3"
```

## Available Scan IDs

From S3:
- `56d4e1ae-2ba0-4232-bcf8-ebd89726856b`
- `9382bcb6-c793-4b84-87e9-59cf0766288b`

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -n threat-engine-engines -l app=compliance-engine
kubectl describe pod -n threat-engine-engines -l app=compliance-engine
```

### Check Logs

```bash
kubectl logs -n threat-engine-engines -l app=compliance-engine --tail=50
kubectl logs -n threat-engine-engines -l app=compliance-engine -f
```

### Test S3 Access from Pod

```bash
kubectl exec -n threat-engine-engines -l app=compliance-engine -- \
  aws s3 ls s3://cspm-lgtech/aws-compliance-engine/output/

kubectl exec -n threat-engine-engines -l app=compliance-engine -- \
  aws s3 ls s3://cspm-lgtech/aws-compliance-engine/output/56d4e1ae-2ba0-4232-bcf8-ebd89726856b/
```

### Port Forward (Alternative Access)

```bash
kubectl port-forward -n threat-engine-engines \
  deployment/compliance-engine 8000:8000

# Then test locally
curl http://localhost:8000/api/v1/health
```

## Expected Response Format

### Compliance Report Response

```json
{
  "report_id": "uuid",
  "status": "completed",
  "compliance_report": {
    "report_id": "uuid",
    "scan_id": "56d4e1ae-2ba0-4232-bcf8-ebd89726856b",
    "csp": "aws",
    "generated_at": "2026-01-13T...",
    "executive_dashboard": {
      "summary": {
        "overall_compliance_score": 78.5,
        "total_frameworks": 3,
        "critical_findings": 12
      },
      "frameworks": [...]
    },
    "framework_reports": {...}
  }
}
```

## Next Steps

1. ✅ Deployment complete
2. ✅ Health check working
3. ⏳ Test with real scan results
4. ⏳ Verify compliance mappings are loaded
5. ⏳ Test framework reports
6. ⏳ Test resource drill-down

