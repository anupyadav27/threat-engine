# 🚀 Quick Start - GCP Service Validation

## One-Time Setup (Run Once)

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine

# Add validation prompts to all service YAML files
python add_validation_prompt_to_services.py
```

---

## Option 1: Automated Validation (All Services)

```bash
# Run validation for all services
./validate_all_services.sh

# Check results
cat output/validation_*/validation_results.txt
```

**Interpret Results:**
- ✅ VALIDATED = Service working perfectly
- ⚠️ NEEDS REVIEW = Fix required (follow manual steps)
- ❌ FAILED = Python error (fix YAML syntax)

---

## Option 2: Manual Validation (One Service)

### 1. Run Engine for Specific Service

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine
source venv/bin/activate
export PYTHONPATH="$(pwd)/..:$PYTHONPATH"

# Example: Validate 'compute' service
export GCP_ENGINE_FILTER_SERVICES="compute"
python engine/gcp_engine.py > output/test_compute_$(date +%Y%m%d_%H%M%S).json 2>&1
```

### 2. Check Output

```bash
# View last output file
ls -lt output/test_compute_* | head -1
cat output/test_compute_*.json | python -m json.tool | head -100
```

### 3. Look For Issues

**Empty inventories?**
→ Fix discovery actions (use `list_*` or `aggregatedList_*`)

**Zero checks?**
→ Fix `for_each` to match discovery_id

**All checks fail?**
→ Fix field paths to match GCP API structure

### 4. Fix Issues

Open the service YAML file:
```bash
code services/compute/compute_rules.yaml
```

Read the validation prompt at the top and follow the fix guide.

### 5. Re-validate

```bash
export GCP_ENGINE_FILTER_SERVICES="compute"
python engine/gcp_engine.py > output/validate_compute_$(date +%Y%m%d_%H%M%S).json 2>&1
```

### 6. Repeat Until Clean

✅ Inventories populated
✅ Checks executing  
✅ Clean JSON output
✅ No errors

---

## Quick Fix Reference

### Discovery Actions (MUST use these patterns)

```yaml
# ✅ CORRECT
- action: list_topics
- action: aggregatedList_instances
- action: list

# ❌ WRONG (Engine won't understand)
- action: get_topic_iam_policy
- action: fetch_buckets
```

### Field Paths (MUST match GCP API)

```yaml
# ✅ CORRECT
- path: kmsKeyName
- path: metadata.items
- path: status

# ❌ WRONG
- path: encryption.kms_key  # Wrong field name
- path: metadata->items     # Wrong syntax
```

### Check Structure (MUST have all parts)

```yaml
checks:
  - check_id: gcp.service.resource.check_name  # ✅ Correct format
    title: Description
    severity: high|medium|low
    for_each: discovery_id  # ✅ Must match discovery above
    logic: AND|OR
    calls:
    - action: eval  # ✅ Primary check action
      fields:
      - path: fieldName
        operator: exists|equals|contains|not_contains
        expected: value
```

---

## Validation Checklist

```
[ ] Run engine for service
[ ] Check inventories populated
[ ] Check checks executed
[ ] Fix any issues
[ ] Re-run and verify
[ ] Add validation notes to YAML
[ ] Move to next service
```

---

## Example Commands

### Validate Single Service
```bash
./validate_all_services.sh compute
```

### Validate All Services
```bash
./validate_all_services.sh
```

### Test Specific Service Manually
```bash
export GCP_ENGINE_FILTER_SERVICES="gcs"
python engine/gcp_engine.py | python -m json.tool | less
```

### Check Validation Progress
```bash
grep "✅\|⚠️\|❌" output/validation_*/validation_results.txt
```

---

## What Success Looks Like

```json
{
  "inventories": [
    {
      "service": "compute",
      "discovery_id": "firewalls",
      "resources": [
        {
          "firewall_name": "default-allow-internal",
          "firewall_direction": "INGRESS",
          "source_ranges": ["10.128.0.0/9"]
        }
      ]
    }
  ],
  "main_checks": [
    {
      "check_id": "gcp.compute.firewall.no_allow_all",
      "status": "pass",
      "resource_name": "default-allow-internal"
    }
  ]
}
```

**Key indicators:**
✅ Inventories has resources
✅ main_checks has results
✅ No errors in JSON
✅ Checks show pass/fail (based on actual compliance)

---

## Need Help?

1. **Read the header** in the service YAML file
2. **Check examples**: `services/gcs/gcs_rules.yaml`
3. **Full guide**: `SERVICE_VALIDATION_GUIDE.md`
4. **Detailed prompt**: `GCP_SERVICE_VALIDATION_PROMPT.md`

---

## Progress Tracking

```bash
# See how many services are validated
./validate_all_services.sh | grep "Success Rate"

# List services that need work
grep "⚠️\|❌" output/validation_*/validation_results.txt
```

---

## 🎯 Your Next Steps

1. Run: `python add_validation_prompt_to_services.py`
2. Run: `./validate_all_services.sh`
3. Fix services marked as needing review
4. Re-validate until all green
5. Done! 🎉

