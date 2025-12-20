# How to Test Generated YAML Files

## ✅ Files Copied

The generated YAML files have been copied to:
- `services/cognito/rules/cognito.yaml`
- `services/vpc/rules/vpc.yaml`
- `services/parameterstore/rules/parameterstore.yaml`
- ... and 84 more services

**Backups created:** Original files backed up as `*.yaml.backup`

---

## Testing Methods

### Method 1: Test Single Service (Recommended for Testing)

```bash
cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine
export PYTHONPATH=$PWD:$PYTHONPATH
python3 -m engine.main_scanner --service cognito --region us-east-1
```

**What this does:**
- Loads `services/cognito/rules/cognito.yaml`
- Executes all discoveries (calls boto3 APIs)
- Runs all compliance checks
- Saves results to `output/scan_*/account_*/`

### Method 2: Test Multiple Services

```bash
python3 -m engine.main_scanner --include-services cognito,vpc,parameterstore --region us-east-1
```

### Method 3: Test All Services

```bash
python3 -m engine.main_scanner
```

**Note:** This will scan all enabled services across all accounts/regions. Use with caution.

---

## Command Options

### Account Scope
```bash
--account 123456789012              # Single account
--include-accounts "123,456"        # Multiple accounts
--exclude-accounts "789"            # Exclude accounts
```

### Region Scope
```bash
--region us-east-1                   # Single region
--include-regions "us-east-1,us-west-2"  # Multiple regions
--exclude-regions "ap-southeast-1"  # Exclude regions
```

### Service Scope
```bash
--service cognito                    # Single service
--include-services "cognito,vpc"    # Multiple services
--exclude-services "cloudwatch"     # Exclude services
```

### Resource Scope
```bash
--resource "resource-id"            # Single resource (requires --service)
--resource-pattern "i-*-prod-*"    # Pattern matching (requires --service)
```

### Performance
```bash
--max-account-workers 3            # Parallel account scanning
--max-workers 10                    # Parallel service/region scanning
```

---

## Example: Test Cognito Service

```bash
cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine
export PYTHONPATH=$PWD:$PYTHONPATH

# Test cognito in current account, us-east-1
python3 -m engine.main_scanner --service cognito --region us-east-1
```

**Expected Output:**
- Scans cognito service
- Executes discoveries: `list_user_pools`, `get_group`, `describe_user_pool`, `list_users`
- Runs compliance checks
- Saves results to `output/scan_YYYYMMDD_HHMMSS/account_*/cognito_*.json`

---

## Verify Fixes Applied

After running, check the logs:

```bash
# Check scan log
tail -f output/latest/logs/scan.log

# Look for:
# ✅ list_user_pools (should work now)
# ❌ update_managed_login_branding (should NOT appear)
```

**Success indicators:**
- ✅ No errors about `update_managed_login_branding`
- ✅ `list_user_pools` executes successfully
- ✅ Compliance checks run without template errors
- ✅ Results saved to output folder

---

## Troubleshooting

### Issue: ModuleNotFoundError
```bash
# Fix: Set PYTHONPATH
export PYTHONPATH=/Users/apple/Desktop/threat-engine/aws_compliance_python_engine:$PYTHONPATH
```

### Issue: Service not found
```bash
# Check if YAML file exists
ls -la services/cognito/rules/cognito.yaml

# If missing, re-run copy:
cd Agent-rulesid-rule-yaml
python3 test_generated_yaml.py --copy-only
```

### Issue: Access Denied
- This is expected for some services
- The engine handles this gracefully with `on_error: continue`

---

## Quick Test Script

You can also use the test script:

```bash
cd Agent-rulesid-rule-yaml

# Copy files (already done)
python3 test_generated_yaml.py --copy-only

# Copy and test a service
python3 test_generated_yaml.py --test-service cognito --region us-east-1
```

---

## What Gets Tested

1. **Discovery Execution:**
   - Calls boto3 APIs (e.g., `list_user_pools()`)
   - Collects inventory
   - Handles errors gracefully

2. **Template Resolution:**
   - Resolves `{{ item.name }}` from parent discoveries
   - Matches parameters to parent fields

3. **Compliance Checks:**
   - Evaluates conditions
   - Reports PASS/FAIL

4. **Output Generation:**
   - Saves inventory JSON
   - Saves checks JSON
   - Creates scan reports

---

## Expected Results

After testing, you should see:
- ✅ Fewer template errors (48 → 0)
- ✅ No UPDATE/CREATE/DELETE function errors
- ✅ Better parameter matching
- ✅ Successful discovery execution
- ✅ Compliance check results

