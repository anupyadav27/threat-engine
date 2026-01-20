# AWS Compliance Engine - Real AWS Testing Guide

This guide explains how to test the compliance engine against real AWS accounts.

## Overview

The test script (`test_engine_against_aws.py`) tests services with high-quality metadata mappings (score >= 80) against your actual AWS account.

## Prerequisites

1. **AWS Credentials**: Configure AWS credentials (via `~/.aws/credentials`, environment variables, or IAM role)
2. **Python Dependencies**: Ensure all required packages are installed
3. **Quality Mappings**: Services must have quality score >= 80 in validation results

## Quick Start

```bash
cd aws_compliance_python_engine
python3 test_engine_against_aws.py
```

## What It Does

1. **Identifies Test Candidates**: Finds services with quality score >= 80
2. **Filters by Rules**: Only tests services that have rules YAML files
3. **Tests Against AWS**: Runs the compliance engine against your AWS account
4. **Reports Results**: Shows pass/fail/error counts for each service
5. **Saves Results**: Saves detailed results to `test_results_aws.json`

## Configuration

Edit the script to adjust:

- `MIN_QUALITY_SCORE`: Minimum quality score (default: 80)
- `MAX_TEST_SERVICES`: Limit number of services to test (default: 10)
- `TEST_REGION`: AWS region to test (default: 'us-east-1')
- `SKIP_DEPLOYMENT`: Skip deploying test resources (default: True)

## Test Modes

### Mode 1: Test Against Existing Resources (Default)

- Tests against resources already in your AWS account
- No deployment/cleanup needed
- Faster and safer
- May have limited coverage if account has few resources

### Mode 2: Deploy Test Resources

- Deploys test resources for services that need them
- More comprehensive testing
- Requires permissions to create/delete resources
- Costs money (for RDS, etc.)

To enable deployment mode, set `SKIP_DEPLOYMENT = False` in the script.

## Services Ready for Testing

Services with quality score >= 80 and rules YAML files:

- appstream (95.0)
- appsync (95.0)
- codeartifact (95.0)
- controltower (95.0)
- costexplorer (95.0)
- datasync (95.0)
- directoryservice (95.0)
- docdb (93.8)
- config (93.7)
- autoscaling (92.5)
- bedrock (92.5)
- budgets (92.5)
- detective (92.5)
- cloudtrail (91.9)
- apigatewayv2 (91.7)
- ... and more

## Understanding Results

### Status Codes

- **PASS**: Compliance check passed
- **FAIL**: Compliance check failed (non-compliant resource)
- **ERROR**: Error during check execution (may indicate mapping issue)

### Result File

Results are saved to `test_results_aws.json` with:

```json
{
  "timestamp": "2024-01-01T12:00:00",
  "account_id": "123456789012",
  "test_region": "us-east-1",
  "results": [
    {
      "service": "cloudfront",
      "status": "success",
      "total_checks": 10,
      "passed": 8,
      "failed": 1,
      "errors": 1,
      "elapsed_seconds": 5.23
    }
  ]
}
```

## Troubleshooting

### "No services found with rules YAML files"

**Solution**: Generate YAML files from metadata_mapping.json:
```bash
python3 generate_yaml_from_metadata_mapping.py
```

### "Failed to connect to AWS"

**Solution**: Configure AWS credentials:
```bash
aws configure
# OR
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

### "No resources found" (all checks skipped)

**Solution**: 
- Deploy test resources (set `SKIP_DEPLOYMENT = False`)
- Or test in an account with existing resources

### High error rate

**Possible causes**:
- Incorrect field paths in metadata_mapping.json
- Wrong boto3 method names
- Missing permissions
- API changes

**Solution**: Review validation results and fix mappings.

## Best Practices

1. **Start Small**: Test 3-5 services first
2. **Review Results**: Check for high error rates
3. **Fix Issues**: Address mapping issues before broader testing
4. **Test Incrementally**: Add more services as quality improves
5. **Monitor Costs**: Be aware of API costs for large accounts

## Next Steps

After successful testing:

1. Fix any mapping issues identified
2. Re-validate fixed services
3. Expand to more services
4. Integrate into CI/CD pipeline
5. Set up regular compliance scans

