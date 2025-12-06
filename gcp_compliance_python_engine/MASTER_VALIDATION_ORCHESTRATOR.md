# 🎯 CURSOR AI: MASTER VALIDATION ORCHESTRATOR

## YOUR MISSION

Validate ALL 47 GCP services systematically. This is your primary instruction set.

**DO NOT STOP until SERVICE_TRACKER_VALIDATOR.md shows 47/47 ✅ VALIDATED**

---

## 📋 WORKFLOW OVERVIEW

```
┌─────────────────────────────────────────────────────┐
│ 1. SETUP (One Time)                                 │
│    ✅ Run update_inline_prompts.py                  │
│    ✅ Open SERVICE_TRACKER_VALIDATOR.md             │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│ 2. FOR EACH SERVICE (Repeat 47 times):             │
│                                                     │
│    a. Update tracker: Set status to 🔄              │
│    b. Open service YAML file                        │
│    c. Read inline validation prompt (top of file)   │
│    d. Run engine for this service                   │
│    e. Analyze output (inventories, checks)          │
│    f. Fix discovery section issues                  │
│    g. Fix checks section issues                     │
│    h. Re-run engine to verify                       │
│    i. Update validation status in YAML              │
│    j. Update tracker: Set status to ✅              │
│    k. Move to next service                          │
└─────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────┐
│ 3. COMPLETION                                       │
│    ✅ All 47 services marked validated              │
│    ✅ Run ./validate_all_services.sh                │
│    ✅ Verify 100% success rate                      │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 STEP-BY-STEP INSTRUCTIONS

### STEP 0: Initial Setup (Do Once)

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine

# Update all service YAMLs with inline prompts
python3 update_inline_prompts.py

# Open the tracker
code SERVICE_TRACKER_VALIDATOR.md
```

### STEP 1: Choose Next Service

Open `SERVICE_TRACKER_VALIDATOR.md` and find the first service with ⏳ status.

**Suggested Order:**
1. Start with **gcs** or **pubsub** (should already work - learn from them)
2. Then do **compute** (large, important)
3. Then work through the rest alphabetically

### STEP 2: Open Service YAML

```bash
# Example: accessapproval
code services/accessapproval/accessapproval_rules.yaml
```

### STEP 3: Read Inline Prompt

The file now has a comprehensive validation prompt at the top with:
- Mission statement
- Workflow steps
- Common issues and fixes
- Testing commands
- Success criteria
- Validation status template

**Read the entire prompt before proceeding!**

### STEP 4: Run Engine for Service

```bash
source venv/bin/activate
export PYTHONPATH="$(pwd)/..:$PYTHONPATH"

# Replace <service> with actual service name
export GCP_ENGINE_FILTER_SERVICES="<service>"
python engine/gcp_engine.py > output/test_<service>_$(date +%Y%m%d_%H%M%S).json 2>&1
```

### STEP 5: Analyze Output

```bash
# View output
cat output/test_<service>_*.json | python3 -m json.tool | less

# Quick stats
python3 -c "
import json
with open('output/test_<service>_TIMESTAMP.json') as f:
    data = json.load(f)
    print(f'Inventories: {len(data.get(\"inventories\", []))}')
    print(f'Checks: {len(data.get(\"main_checks\", []))}')
    print(f'Skipped: {len(data.get(\"skipped_checks\", []))}')
"
```

**What to look for:**
- ✅ `inventories` array has entries → Discovery working
- ✅ `main_checks` array has entries → Checks executing
- ❌ Empty arrays → Need to fix
- ❌ Python errors → Check YAML syntax

### STEP 6: Fix Discovery Section

**Common Issues:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty inventories | Wrong action name | Use `list_<resource>` or `aggregatedList_<resource>` |
| No resources found | Resources don't exist | Normal if no resources in GCP |
| Python error | Invalid action | Check action name matches engine parser |

**Fix Pattern:**
```yaml
# ❌ BEFORE
discovery:
  - discovery_id: topics
    calls:
    - action: get_topics  # Not supported!

# ✅ AFTER
discovery:
  - discovery_id: topics
    calls:
    - action: list_topics  # Supported pattern!
```

### STEP 7: Fix Checks Section

**Common Issues:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| Zero checks executed | Wrong for_each | Match discovery_id exactly |
| All checks fail | Wrong field paths | Update to match GCP API response |
| Checks skipped | Discovery didn't run | Fix discovery first |

**Fix Pattern:**
```yaml
# ❌ BEFORE
checks:
  - check_id: gcp.service.check
    for_each: wrong_id  # Doesn't exist!
    calls:
    - action: eval
      fields:
      - path: encryption.kms_key  # Wrong path!

# ✅ AFTER
checks:
  - check_id: gcp.service.check
    for_each: topics  # Matches discovery_id
    calls:
    - action: eval
      fields:
      - path: kmsKeyName  # Correct GCP API field!
```

### STEP 8: Re-Validate

```bash
# Run engine again
export GCP_ENGINE_FILTER_SERVICES="<service>"
python engine/gcp_engine.py > output/validate_<service>.json 2>&1

# Check improvement
cat output/validate_<service>.json | python3 -m json.tool | head -50
```

**Verify:**
- ✅ More inventories than before?
- ✅ More checks executing?
- ✅ Fewer errors?

**Repeat Steps 6-8 until all checks work!**

### STEP 9: Update Validation Status in YAML

At the bottom of the service YAML file, fill in the validation status section:

```yaml
# ============================================================================
# VALIDATION STATUS (UPDATE AFTER FIXING):
# ============================================================================
# Date: 2025-12-05
# 
# Issues Found:
# - Discovery action was 'get_topics' (not supported)
# - Field paths didn't match GCP API
# - 3 checks had wrong for_each
#
# Fixes Applied:
# - Changed action to 'list_topics'
# - Updated field paths: encryption.key → kmsKeyName
# - Fixed all for_each references to match discovery_id
#
# Test Results:
# - Engine Status: ✅ NO ERRORS
# - Inventories: 5 discoveries populated
# - Checks Executed: 12 checks ran successfully
# - Checks Skipped: 0
#
# Final Status: ✅ VALIDATED
# ============================================================================
```

### STEP 10: Update Tracker

Open `SERVICE_TRACKER_VALIDATOR.md` and update the service row:

```markdown
| ✅ | pubsub | 5 | 12 | 2025-12-05 | All working, 0 skipped |
```

Also update the progress counter at the top:

```markdown
Total Services: 47
✅ Validated: 1
⏳ In Progress: 46
❌ Failed: 0

Progress: [█                   ] 2%
```

### STEP 11: Move to Next Service

Go back to STEP 1 and repeat for the next ⏳ service!

---

## 🎯 VALIDATION CHECKLIST (Per Service)

Copy this for each service:

```
Service: _____________
Started: _____________

[ ] Updated tracker to 🔄 status
[ ] Opened YAML file
[ ] Read inline validation prompt
[ ] Ran engine: export GCP_ENGINE_FILTER_SERVICES="..."
[ ] Analyzed output JSON
[ ] Fixed discovery issues
[ ] Fixed checks issues
[ ] Re-ran engine to verify
[ ] Inventories populated: ___ count
[ ] Checks executed: ___ count
[ ] Updated validation status in YAML
[ ] Updated tracker to ✅ status
[ ] Moved to next service

Completed: _____________
```

---

## 📊 PROGRESS TRACKING

### Quick Progress Check

```bash
# Count services by status in tracker
grep -c "| ✅" SERVICE_TRACKER_VALIDATOR.md
grep -c "| ⏳" SERVICE_TRACKER_VALIDATOR.md
```

### Full Validation Run

```bash
# After all services fixed, run full validation
./validate_all_services.sh

# Check success rate
cat output/validation_*/validation_results.txt | grep "Success Rate"
```

---

## 🔧 DEBUGGING REFERENCE

### Issue: Empty Inventories

```bash
# Check what action is being used
grep -A 5 "discovery:" services/<service>/<service>_rules.yaml

# It should be list_<resource> or aggregatedList_<resource>
```

### Issue: Zero Checks

```bash
# Check for_each matches discovery_id
grep "for_each:" services/<service>/<service>_rules.yaml
grep "discovery_id:" services/<service>/<service>_rules.yaml

# They must match exactly!
```

### Issue: Python Errors

```bash
# Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('services/<service>/<service>_rules.yaml'))"

# If syntax OK, check action names match engine patterns
```

### Issue: All Checks Fail

```bash
# Look at actual resource structure in inventories
cat output/test_<service>.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
if data.get('inventories'):
    print(json.dumps(data['inventories'][0], indent=2))
"

# Update field paths in checks to match this structure
```

---

## 🎊 COMPLETION CRITERIA

**You are DONE when:**

1. ✅ SERVICE_TRACKER_VALIDATOR.md shows 47/47 services validated
2. ✅ Each service row has inventory and check counts
3. ✅ Each service YAML has completed validation status
4. ✅ Full validation passes: `./validate_all_services.sh`
5. ✅ Success rate = 100% (47/47)

**Final Verification:**

```bash
./validate_all_services.sh > FINAL_VALIDATION_REPORT.txt
cat FINAL_VALIDATION_REPORT.txt
```

---

## 📚 REFERENCE DOCUMENTS

**Essential Reading:**
1. `SERVICE_TRACKER_VALIDATOR.md` - Your main tracking document
2. `GCP_YAML_INLINE_PROMPT.yaml` - Template and examples
3. `QUICK_START_VALIDATION.md` - Quick commands

**In Each Service YAML:**
- Inline validation prompt at top
- Validation status template at bottom

**Tools:**
- `update_inline_prompts.py` - Update all YAMLs (already run)
- `validate_all_services.sh` - Full validation script

---

## 🚀 START NOW

**Your first command:**

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine

# If not already done:
python3 update_inline_prompts.py

# Open tracker
code SERVICE_TRACKER_VALIDATOR.md

# Start with first service
code services/accessapproval/accessapproval_rules.yaml
```

**Then follow STEP 1-11 above for each service!**

---

## 💡 TIPS FOR SUCCESS

1. **Start with working examples** - gcs, pubsub should already work
2. **One at a time** - Complete each service before moving on
3. **Test frequently** - Run engine after each change
4. **Update tracker** - Keep status current for motivation
5. **Document everything** - Future you will thank you
6. **Take breaks** - This is 47 services, pace yourself
7. **Batch similar fixes** - If you find a pattern, apply it consistently

---

## 🎯 FOCUS AREAS

### High Priority (Do First)
- compute, gcs, iam, cloudsql, container
- These are most commonly used

### Security Services (Important)
- cloudkms, secretmanager, securitycenter, accessapproval

### Can Be Last
- datastudio, elasticsearch, workspace, multi
- These are less critical

---

## ✅ FINAL STATUS

**When complete, update this:**

```
Validation Started: ___________
Validation Completed: ___________
Total Duration: ___________
Services Validated: 47/47 ✅
Success Rate: 100%

Notes:
- Common issues found: _______
- Most complex service: _______
- Easiest service: _______
- Total checks validated: ~1,636
```

---

## 🎊 YOU'VE GOT THIS!

This is systematic work. Follow the process for each service:

1. Open YAML
2. Read prompt
3. Run engine
4. Fix issues
5. Verify
6. Update tracker
7. Next service

**Start with service #1 NOW!** 🚀

