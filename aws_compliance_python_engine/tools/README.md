# YAML Validator Tool

## Overview

The YAML Validator validates AWS compliance rule files against **real AWS API responses**. It catches issues before runtime by actually calling AWS services and verifying that:

- ✅ Field paths exist in API responses
- ✅ Template variables can be resolved
- ✅ API methods are valid
- ✅ Check conditions access correct data
- ✅ Operators match data types

## Quick Start

### Validate a Single File
```bash
python3 tools/validate_yaml.py services/accessanalyzer/rules/accessanalyzer.yaml
```

### Validate Multiple Files
```bash
python3 tools/validate_yaml.py \
  services/accessanalyzer/rules/accessanalyzer.yaml \
  services/account/rules/account.yaml
```

### Validate All YAMLs
```bash
python3 tools/validate_yaml.py services/*/rules/*.yaml
```

### Verbose Mode
```bash
python3 tools/validate_yaml.py services/account/rules/account.yaml --verbose
```

## What It Validates

### 1. Discovery Section

#### API Method Validation
```yaml
calls:
  - action: list_analyzers  # ✅ Validates this method exists on boto3 client
```

If invalid:
```
❌ Method 'list_analyzer' not found on client
   Did you mean one of: list_analyzers, list_findings, ...
```

#### Field Path Validation
```yaml
calls:
  - action: list_analyzers
    fields:
      - analyzers  # ✅ Validates this field exists in API response
```

The validator **actually calls** `client.list_analyzers()` and checks if `analyzers` field exists!

If invalid:
```
❌ Field path 'analyzer' not found in call 'list_analyzers' response
   Available fields: analyzers, nextToken
```

#### Template Variable Validation
```yaml
emit:
  item:
    id: '{{ resource.arn }}'  # ✅ Validates 'arn' exists in resource
```

If invalid:
```
❌ Template variable 'resource.arn' not found
   Available: resource.name, resource.status, resource.type
```

### 2. Checks Section

#### Discovery Reference Validation
```yaml
for_each:
  discovery: aws.accessanalyzer.resources  # ✅ Validates this discovery exists
```

If invalid:
```
❌ References unknown discovery 'aws.accessanalyzer.resource'
   Available discoveries: aws.accessanalyzer.resources, aws.accessanalyzer.findings
```

#### Condition Variable Validation
```yaml
conditions:
  var: resource.status  # ✅ Validates this path exists in discovery data
  op: equals
  value: 'ACTIVE'
```

If invalid:
```
❌ Variable path 'resource.state' not found in context
   Available: resource.status, resource.name, resource.arn
```

#### Operator Validation
```yaml
conditions:
  var: resource.count
  op: greater_than  # ❌ Invalid operator
```

```
❌ Unknown operator 'greater_than'
   Valid operators: exists, equals, gt, gte, lt, lte, contains, not_contains, length_gte
```

## How It Works

### Step 1: Load YAML
```python
rules = yaml.safe_load(open('accessanalyzer.yaml'))
```

### Step 2: Create AWS Client
```python
client = boto3.client(rules['service'])  # Creates actual AWS client
```

### Step 3: Execute Discovery Calls
```python
# For each call in discovery:
response = client.list_analyzers(**params)  # Real AWS API call!

# Validate fields exist
for field in call['fields']:
    if field not in response:
        print(f"❌ Field '{field}' not found")
```

### Step 4: Validate Templates
```python
# Check if template variables can be resolved
for template in emit['item'].values():
    variables = extract_template_variables(template)
    for var in variables:
        if not can_extract(saved_data, var):
            print(f"❌ Template variable '{var}' not found")
```

### Step 5: Validate Checks
```python
# Ensure checks can access discovery data
for check in checks:
    discovery_data = discovery_results[check['for_each']['discovery']]
    for condition in check['conditions']:
        if not can_extract(discovery_data, condition['var']):
            print(f"❌ Variable '{condition['var']}' not found")
```

## Example Output

### Successful Validation
```
================================================================================
Validating: services/s3/rules/s3.yaml
================================================================================

Service: s3

Validating discovery: aws.s3.buckets
  Call 1/1
  Testing API call: list_buckets({})
    Response keys: ['Buckets', 'Owner']
  Validating emit section
    Emitting 15 items

Validating 10 checks
  Validating check: aws.s3.bucket.encryption_enabled
  Validating check: aws.s3.bucket.versioning_enabled
  ...

================================================================================
VALIDATION SUMMARY
================================================================================

✅ All validations passed!

Total: 0 errors, 0 warnings
```

### Failed Validation
```
================================================================================
Validating: services/account/rules/account.yaml
================================================================================

Service: account

Validating discovery: aws.account.alternate_contacts
  Call 1/3
  Testing API call: get_alternate_contact({'AlternateContactType': 'SECURITY'})
  Validating emit section

================================================================================
VALIDATION SUMMARY
================================================================================

❌ Found 3 ERRORS:

  Discovery 'aws.account.alternate_contacts': 
    Template variable 'security_contact.AlternateContact' not found
    Available: security_contact.EmailAddress, security_contact.Name

  Check 'aws.account.security.contact_configured':
    Variable path 'contacts.security_contact' not found
    Available: item.security_contact, item.billing_contact

⚠️  Found 1 WARNINGS:

  Discovery 'aws.account.alternate_contacts':
    API call get_alternate_contact failed: ResourceNotFoundException (on_error=continue)

Total: 3 errors, 1 warnings
```

## AWS Credentials

The validator uses standard AWS credential resolution:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. IAM role (if running on EC2/ECS/Lambda)

Make sure you have AWS credentials configured before running the validator.

## Requirements

```bash
pip install boto3 pyyaml
```

## Common Issues Found

### Issue 1: Wrong Field Names
```yaml
# WRONG
fields:
  - analyzer  # Field doesn't exist

# CORRECT (validator shows you)
fields:
  - analyzers  # Actual field in AWS response
```

### Issue 2: Invalid Template Paths
```yaml
# WRONG
id: '{{ resource.identifier }}'

# CORRECT
id: '{{ resource.arn }}'  # Based on real AWS response
```

### Issue 3: Mismatched Check Variables
```yaml
# Discovery emits:
emit:
  item:
    bucket_name: '{{ bucket.Name }}'

# Check expects (WRONG):
conditions:
  var: item.name  # Doesn't match!

# Check should expect (CORRECT):
conditions:
  var: item.bucket_name  # Matches emit!
```

### Issue 4: Invalid for_each Syntax
```yaml
# WRONG
for_each: '{{ resource_list.items[] }}'  # Don't use {{ }} in for_each

# CORRECT
for_each: resource_list.items[]  # Raw path
```

## Best Practices

### 1. Validate Before Committing
```bash
# Add to pre-commit hook
python3 tools/validate_yaml.py $(git diff --name-only --cached | grep '\.yaml$')
```

### 2. Validate All YAMLs Regularly
```bash
# Weekly validation of all rules
python3 tools/validate_yaml.py services/*/rules/*.yaml > validation_report.txt
```

### 3. Use Verbose Mode for Debugging
```bash
python3 tools/validate_yaml.py services/account/rules/account.yaml --verbose
```

### 4. Test with Real AWS Account
Set up a test AWS account with resources configured to validate YAMLs properly.

## Troubleshooting

### Issue: "Cannot create client"
**Cause**: Invalid service name in YAML
**Fix**: Check the `service:` field matches boto3 service name

### Issue: "ResourceNotFoundException"
**Cause**: AWS account has no resources to test
**Fix**: This may be expected. Check if `on_error: continue` is set

### Issue: "AccessDeniedException"
**Cause**: AWS credentials lack permissions
**Fix**: Ensure IAM permissions for read-only access to the service

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Validate YAML Rules

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install boto3 pyyaml
      
      - name: Validate YAML files
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          python3 tools/validate_yaml.py services/*/rules/*.yaml
```

## Advanced Usage

### Custom Region
```bash
python3 tools/validate_yaml.py services/ec2/rules/ec2.yaml --region us-west-2
```

### Save Output to File
```bash
python3 tools/validate_yaml.py services/*/rules/*.yaml > validation_results.txt 2>&1
```

### Exit Code
The validator returns exit code 0 if all validations pass, 1 if any errors found.

```bash
if python3 tools/validate_yaml.py services/s3/rules/s3.yaml; then
    echo "✅ Validation passed"
else
    echo "❌ Validation failed"
fi
```

## Support

For issues or questions:
1. Check the validation report for specific error messages
2. Review the YAML syntax in engine documentation
3. Test with `--verbose` flag for detailed output

## Files Generated

After running validation, check:
- `tools/validation_report.md` - Detailed analysis
- `tools/VALIDATION_RESULTS_SUMMARY.md` - Executive summary
- `VALIDATION_QUICK_RESULTS.txt` - Quick reference

## Summary

The YAML Validator is **essential** for:
- ✅ Catching issues before deployment
- ✅ Understanding AWS API response structures
- ✅ Ensuring YAML correctness
- ✅ Saving debugging time

**Run it on every YAML before deploying!** 🚀
