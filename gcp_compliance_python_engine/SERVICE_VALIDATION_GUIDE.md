# GCP Compliance Engine - Service Validation Guide

## 🎯 Purpose

This guide helps you systematically validate and fix all GCP service rule files to ensure the compliance engine runs correctly for every service.

---

## 📋 Quick Start (3 Steps)

### 1️⃣ Add Validation Prompts to All Service Files

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine
python add_validation_prompt_to_services.py
```

This adds a validation prompt header to each service's YAML file. The header contains:
- Step-by-step validation workflow
- Fix guidelines for discovery and checks
- Quick debugging tips
- Success criteria

### 2️⃣ Validate All Services Automatically

```bash
./validate_all_services.sh
```

This script:
- ✅ Runs the engine for each service
- ✅ Captures output and errors
- ✅ Analyzes inventories and checks
- ✅ Generates a summary report

**Output:** `output/validation_YYYYMMDD_HHMMSS/validation_results.txt`

### 3️⃣ Fix Services That Need Attention

Open the validation results and identify services that need fixes:

```bash
cat output/validation_*/validation_results.txt
```

For each service marked as "NEEDS REVIEW" or "FAILED":

1. Open the service YAML file
2. Read the validation prompt at the top
3. Follow the 8-step workflow
4. Fix issues in discovery and checks sections
5. Re-validate until clean

---

## 🔄 Validation Workflow (Detailed)

### Step 1: Understand the Service

Open the service rule file (e.g., `services/compute/compute_rules.yaml`)

**Read and note:**
- Service name (YAML root key)
- Total discoveries
- Total checks
- Scope (global/regional)
- API details

### Step 2: Run Engine for This Service

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine
source venv/bin/activate
export PYTHONPATH="$(pwd)/..:$PYTHONPATH"

# Replace <service> with actual service name
export GCP_ENGINE_FILTER_SERVICES="<service>"
python engine/gcp_engine.py > output/test_<service>_$(date +%Y%m%d_%H%M%S).json 2>&1
```

### Step 3: Analyze Output

```bash
# View the output
cat output/test_<service>_*.json | python -m json.tool | less
```

**Look for:**
- `inventories` array - Should contain discovered resources
- `main_checks` array - Should contain check results
- `skipped_checks` array - Note what was skipped
- Error messages or stack traces

### Step 4: Fix Discovery Issues

**Common Issues:**

| Problem | Cause | Fix |
|---------|-------|-----|
| Empty inventories | Wrong action name | Use `list_<resource>` or `aggregatedList_<resource>` |
| Missing fields | Field path incorrect | Check GCP API docs for correct paths |
| API errors | Method doesn't exist | Verify action matches GCP API method |

**Discovery Template:**
```yaml
discovery:
  - discovery_id: my_resources
    calls:
    - action: list_resources  # OR aggregatedList_resources
      fields:
      - path: name           # Exact field from GCP API response
        var: resource_name
      - path: status
        var: resource_status
```

### Step 5: Fix Check Issues

**Common Issues:**

| Problem | Cause | Fix |
|---------|-------|-----|
| All checks fail | Field paths wrong | Match paths to discovered data structure |
| Skipped checks | for_each invalid | Use exact discovery_id from discovery section |
| Wrong results | Operator mismatch | Use correct operator for field type |

**Check Template:**
```yaml
checks:
  - check_id: gcp.service.resource.check_name
    title: Human Readable Check Description
    severity: high|medium|low
    for_each: my_resources  # Must match discovery_id above
    logic: AND
    calls:
    - action: eval
      fields:
      - path: status        # Must exist in discovered data
        operator: equals    # exists|equals|contains|not_contains
        expected: ACTIVE
```

### Step 6: Validate Changes

Re-run the engine and compare:

```bash
export GCP_ENGINE_FILTER_SERVICES="<service>"
python engine/gcp_engine.py > output/validate_<service>_$(date +%Y%m%d_%H%M%S).json 2>&1

# Compare before and after
cat output/validate_<service>_*.json | python -m json.tool | head -100
```

**What to check:**
- ✅ More inventories populated?
- ✅ Fewer errors?
- ✅ More checks executing?
- ✅ Clean JSON output?

### Step 7: Iterate Until Clean

Repeat steps 4-6 until:
- ✅ No Python exceptions
- ✅ Inventories have data
- ✅ All checks execute
- ✅ No skipped checks (unless expected)
- ✅ Valid JSON output

### Step 8: Document and Move On

Add validation notes to the YAML file:

```yaml
# ============================================================================
# VALIDATION NOTES - 2025-12-05
# Issues Found:
#   - Discovery action was 'get_topics' (not supported)
#   - Field path 'encryption.kms' should be 'kmsKeyName'
#   - Missing for_each in 3 checks
# 
# Fixes Applied:
#   - Changed action to 'list_topics'
#   - Corrected all field paths to match GCP API
#   - Added for_each references
#
# Final Status:
#   ✅ 27 inventories discovered
#   ✅ 27 checks executed
#   ✅ 0 errors
# ============================================================================
```

---

## 🛠️ Common Fixes Reference

### Discovery Action Patterns

```yaml
# ✅ CORRECT - Supported patterns
- action: list_topics
- action: list_buckets  
- action: aggregatedList_instances
- action: list

# ❌ WRONG - Not supported
- action: get_topic_iam_policy
- action: fetch_buckets
- action: describe_instances
```

### Field Path Examples

```yaml
# ✅ CORRECT - Matches GCP API response
- path: kmsKeyName              # Simple field
- path: metadata.items          # Nested object
- path: networkInterfaces[].accessConfigs  # Array notation

# ❌ WRONG - Doesn't match API
- path: encryption.kms_key      # Wrong field name
- path: metadata->items         # Wrong syntax
- path: network_interfaces      # Underscore vs camelCase
```

### Operator Usage

```yaml
# exists - Check if field is present/true
- path: kmsKeyName
  operator: exists
  expected: true

# equals - Exact match
- path: status
  operator: equals
  expected: READY

# contains - String or list contains value
- path: sourceRanges
  operator: contains
  expected: "0.0.0.0/0"

# not_contains - Opposite of contains
- path: name
  operator: not_contains
  expected: default
```

---

## 📊 Validation Results Interpretation

### ✅ VALIDATED
```
✅ gcs - VALIDATED (inv:15, checks:79, skipped:0)
```
**Meaning:** Service is working perfectly
- Inventories populated
- All checks executed
- Ready for production

### ⚠️ NEEDS REVIEW
```
⚠️ compute - NEEDS REVIEW (inv:0, checks:0)
```
**Meaning:** Service needs attention
- Empty inventories = Discovery issue
- Zero checks = Discovery or for_each issue
- Review and fix according to workflow

### ❌ FAILED
```
❌ iam - ENGINE FAILED
```
**Meaning:** Python exception occurred
- Check error file for stack trace
- Usually YAML syntax error or invalid action
- Fix and re-run

---

## 🎯 Validation Checklist

Use this checklist for each service:

```
Service: _________________

Discovery Section:
[ ] All action names follow supported patterns
[ ] Field paths match GCP API response structure
[ ] Variables are descriptive and used in checks
[ ] Discovery IDs are unique

Checks Section:
[ ] check_id follows naming: gcp.<service>.<resource>.<check>
[ ] for_each references valid discovery_id
[ ] Field paths exist in discovered data
[ ] Operators correct for field types
[ ] Logic (AND/OR) makes sense
[ ] Titles are descriptive
[ ] Severity is appropriate

Validation:
[ ] Engine runs without errors
[ ] Inventories populated
[ ] Checks execute
[ ] JSON output valid
[ ] No unexpected skips

Documentation:
[ ] Added validation notes to YAML
[ ] Documented issues found
[ ] Documented fixes applied
[ ] Noted final status
```

---

## 📚 Reference Documentation

### Essential Files

1. **GCP_SERVICE_VALIDATION_PROMPT.md** - Detailed validation guide
2. **YAML_HEADER_PROMPT.txt** - Quick reference (added to each YAML)
3. **docs/YAML_ACTION_PATTERNS.md** - Action pattern reference
4. **README.md** - Engine overview

### Example Services (Validated)

- `services/gcs/gcs_rules.yaml` - 79 checks ✅
- `services/compute/compute_rules.yaml` - 106 checks ✅  
- `services/pubsub/pubsub_rules.yaml` - 27 checks ✅

### Tools

- `add_validation_prompt_to_services.py` - Add prompts to all YAMLs
- `validate_all_services.sh` - Automated validation
- `engine/gcp_engine.py` - The compliance engine

---

## 🚀 Automated Validation Workflow

For a completely automated approach:

```bash
# 1. Add prompts to all services
python add_validation_prompt_to_services.py

# 2. Run automated validation
./validate_all_services.sh

# 3. Review results
cat output/validation_*/validation_results.txt

# 4. Fix services marked as needing review
# (Follow manual workflow for each service)

# 5. Re-validate specific service
./validate_all_services.sh compute

# 6. Repeat until all services validated
./validate_all_services.sh
```

---

## ✅ Success Criteria

A service is **VALIDATED** when:

1. ✅ Engine runs without Python exceptions
2. ✅ Discovery populates inventories
3. ✅ All checks execute (pass/fail = actual compliance)
4. ✅ No structural errors in YAML
5. ✅ Field paths resolve correctly
6. ✅ Output JSON is clean and valid
7. ✅ Validation notes documented in YAML

---

## 🎊 Final Goal

**Target:** All 41+ services validated

**Current Status:** Check with:
```bash
./validate_all_services.sh
```

**When Complete:**
- Every service runs cleanly
- All discoveries work
- All checks execute
- Engine ready for production scans

---

## 💡 Tips

1. **Start with working services** - Learn from `gcs`, `compute`, `pubsub`
2. **Test frequently** - Run engine after each change
3. **Use GCP docs** - Verify field paths against actual API
4. **One service at a time** - Don't move on until validated
5. **Document everything** - Future you will thank you
6. **Ask for help** - Use Cursor AI with the validation prompt

---

## 🆘 Getting Help

**If stuck on a service:**

1. Read the validation prompt in the YAML file
2. Check example services (gcs, compute, pubsub)
3. Review GCP API documentation
4. Look at engine code: `engine/gcp_engine.py`
5. Check action patterns: `docs/YAML_ACTION_PATTERNS.md`

**Common solutions:**
- Empty inventories → Fix discovery action
- All checks fail → Fix field paths
- Engine crashes → Check YAML syntax
- Skipped checks → Fix for_each references

---

## 🎯 Next Steps

1. ✅ Run `python add_validation_prompt_to_services.py`
2. ✅ Run `./validate_all_services.sh`
3. ✅ Review results
4. ✅ Fix services one by one
5. ✅ Re-validate until all green
6. ✅ Celebrate! 🎉

