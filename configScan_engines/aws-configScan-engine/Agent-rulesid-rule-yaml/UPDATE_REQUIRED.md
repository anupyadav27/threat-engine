# Update Required: Services YAML Files

## Current State

**❌ YAML files in `services/` folder are NOT automatically updated**

The current YAML files still have the **old wrong functions**:
- `services/cognito/rules/cognito.yaml` still uses `update_managed_login_branding` ❌
- Should use `list_user_pools` ✅

## Why Update is Needed

The Agent pipeline works like this:

```
Agent 1 → requirements_initial.json
    ↓
Agent 2 → requirements_with_functions.json (✅ JUST FIXED)
    ↓
Agent 3 → requirements_validated.json
    ↓
Agent 4 → output/{service}_generated.yaml
    ↓
Manual → Copy to services/{service}/rules/{service}.yaml
```

**Current Status:**
- ✅ Agent 2 code is fixed (filters UPDATE/CREATE/DELETE)
- ❌ `output/requirements_with_functions.json` still has old data
- ❌ `output/requirements_validated.json` still has old data
- ❌ `services/cognito/rules/cognito.yaml` still has wrong function

## What Needs to Be Done

### Step 1: Re-run Agent 2
```bash
cd Agent-rulesid-rule-yaml
python3 agent2_function_validator.py
```
**This will:**
- Read `output/requirements_initial.json`
- Apply the new filter (exclude UPDATE/CREATE/DELETE)
- Update `output/requirements_with_functions.json`
- Fix function selections (e.g., `update_managed_login_branding` → `list_user_pools`)

### Step 2: Re-run Agent 3
```bash
python3 agent3_field_validator.py
```
**This will:**
- Read updated `output/requirements_with_functions.json`
- Validate fields against correct functions
- Update `output/requirements_validated.json`

### Step 3: Re-run Agent 4
```bash
python3 agent4_yaml_generator.py
```
**This will:**
- Read updated `output/requirements_validated.json`
- Generate new YAML files in `output/{service}_generated.yaml`
- Use correct functions (e.g., `list_user_pools` instead of `update_managed_login_branding`)

### Step 4: Copy to Services Folder
Agent 4 currently generates files in `output/` folder. You need to:
```bash
# Copy generated YAMLs to services folder
cp output/cognito_generated.yaml ../services/cognito/rules/cognito.yaml
cp output/s3_generated.yaml ../services/s3/rules/s3.yaml
# ... etc for all services
```

**OR** update Agent 4 to write directly to services folder (better approach).

## Verification

After re-running all agents, verify:

1. **Check Agent 2 output:**
   ```bash
   # Should show list_user_pools, not update_managed_login_branding
   grep -A 5 "access_keys_rotated" output/requirements_with_functions.json
   ```

2. **Check generated YAML:**
   ```bash
   # Should show list_user_pools discovery
   grep "list_user_pools" output/cognito_generated.yaml
   ```

3. **Check services YAML:**
   ```bash
   # Should show list_user_pools discovery
   grep "list_user_pools" ../services/cognito/rules/cognito.yaml
   ```

## Summary

**Answer:** ❌ YAML files are NOT automatically updated  
**Action Required:** Re-run Agent 2 → Agent 3 → Agent 4 → Copy to services folder

The fix is in the code, but the data files and YAML outputs need regeneration.

