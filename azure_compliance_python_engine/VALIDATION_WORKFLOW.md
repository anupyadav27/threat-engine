# 🚀 Azure Service Validation - Complete Workflow

## ✅ Setup Complete!

All 58 Azure service YAML files now have **embedded validation instructions** at the top of each file.

---

## 🎯 How It Works

### 1. Each YAML File Has Instructions

Open any service YAML file (e.g., `services/network/network_rules.yaml`):

```yaml
# ============================================================================
# 🤖 CURSOR AI: SERVICE VALIDATION INSTRUCTIONS
# ============================================================================
# 
# SERVICE: network
# STATUS: ⏳ NOT_VALIDATED
#
# 🎯 YOUR TASK:
# 1. Run engine for this service
# 2. Analyze output
# 3. Fix issues in discovery/checks sections
# 4. Re-run until working
# 5. Mark complete at bottom
#
# ... (full instructions embedded) ...
# ============================================================================

network:
  version: '1.0'
  provider: azure
  service: network
  ...
  
  discovery:
  - discovery_id: azure.network.virtual_networks
    calls:
    - action: virtual_networks.list_all
      fields:
      - path: __self__
  
  checks:
  - check_id: azure.network.vnet.dns.logging.enabled
    ...

# ============================================================================
# VALIDATION TRACKING
# ============================================================================
# STATUS: ⏳ NOT_VALIDATED
# VALIDATED_BY: (your name)
# VALIDATED_DATE: (date)
# FIXES APPLIED: (list fixes here)
# TEST RESULTS: (resources, checks, pass/fail counts)
# ============================================================================
```

### 2. Sequential Validator Manages Progress

```bash
# See all services
python sequential_service_validator.py --list

# Start from first non-validated service
python sequential_service_validator.py --start

# Mark service as done
python sequential_service_validator.py --mark-done network

# Move to next service
python sequential_service_validator.py --next

# Check progress
python sequential_service_validator.py --status
```

---

## 🔥 Complete Workflow

### Method 1: Fully Automated with Cursor AI (Recommended)

```bash
# 1. Start validation
python sequential_service_validator.py --start

# Output shows:
📂 First Service: network
📄 File: /path/to/network_rules.yaml

# 2. Open in Cursor
cursor services/network/network_rules.yaml

# 3. Tell Cursor AI:
"Read the validation instructions at the top of this file.
 Run the engine, analyze output, fix issues, iterate until working.
 Update the validation tracking at the bottom when done."

# 4. Cursor AI will:
- Read embedded instructions
- Run: export AZURE_ENGINE_FILTER_SERVICES="network" && python engine/azure_generic_engine.py
- Analyze output
- Fix YAML issues (sdk_package, actions, field paths)
- Re-run and verify
- Update validation tracking
- Tell you when done

# 5. Mark as complete and move to next
python sequential_service_validator.py --mark-done network
python sequential_service_validator.py --next

# 6. Repeat for next service
cursor services/compute/compute_rules.yaml
# (Cursor AI repeats the process)
```

### Method 2: Manual Validation

```bash
# 1. Get next service
python sequential_service_validator.py --start
# Shows: Next service is "network"

# 2. Run engine
export AZURE_ENGINE_FILTER_SERVICES="network"
python engine/azure_generic_engine.py > /tmp/test_network.json 2>&1

# 3. Check output
tail -100 /tmp/test_network.json

# 4. If issues found, edit YAML
cursor services/network/network_rules.yaml
# Fix sdk_package, actions, field paths

# 5. Re-run
python engine/azure_generic_engine.py > /tmp/test_network.json 2>&1

# 6. Repeat until working (no errors)

# 7. Mark as done
python sequential_service_validator.py --mark-done network

# 8. Move to next
python sequential_service_validator.py --next
```

---

## 📊 Tracking Progress

### Check Overall Status

```bash
python sequential_service_validator.py --status

# Output:
================================================================================
AZURE SERVICE VALIDATION PROGRESS
================================================================================
Total Services: 58
✅ Validated: 4 (6.9%)
⏳ Remaining: 54 (93.1%)

Progress: [██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 4/58
================================================================================
```

### List All Services

```bash
python sequential_service_validator.py --list

# Shows all 58 services with status:
# ✅ = Validated & working
# ❌ = Has errors
# ⏳ = Not yet validated
```

### Check Current Service

```bash
python sequential_service_validator.py --current

# Shows which service you should be working on
```

---

## 🎯 Service Priority Order

The validator processes services in this order:

### ✅ Already Validated (4)
1. storage ✅
2. network ✅ (will re-validate)
3. keyvault ✅ (will re-validate)
4. iam ✅ (will re-validate)

### 🔴 High Priority (11)
5. aad (needs Graph API)
6. compute
7. sql
8. aks
9. webapp
10. function
11. cosmosdb
12. monitor
13. security
14. policy
15. dns

### 🟡 Medium Priority (22)
16-37. Infrastructure services

### 🟢 Lower Priority (21)
38-58. Specialized services

---

## 🔧 Quick Commands Reference

```bash
# Navigation
python sequential_service_validator.py --start      # Begin validation
python sequential_service_validator.py --next       # Next service
python sequential_service_validator.py --current    # Show current

# Status
python sequential_service_validator.py --status     # Show progress
python sequential_service_validator.py --list       # List all services

# Management
python sequential_service_validator.py --mark-done <service>  # Mark complete

# Testing
export AZURE_ENGINE_FILTER_SERVICES="<service>"
python engine/azure_generic_engine.py > /tmp/test_<service>.json 2>&1
tail -100 /tmp/test_<service>.json

# Auto-validation
python auto_validate_services.py --service <service>
python auto_validate_services.py --fix-report <service>
```

---

## 📝 What to Do for Each Service

### 1. Open Service YAML in Cursor
```bash
cursor services/network/network_rules.yaml
```

### 2. Read Embedded Instructions
The instructions are at the top of the file in comments.

### 3. Run Engine for This Service
```bash
export AZURE_ENGINE_FILTER_SERVICES="network"
python engine/azure_generic_engine.py > /tmp/test_network.json 2>&1
```

### 4. Analyze Output
```bash
tail -100 /tmp/test_network.json
```

Look for:
- ❌ Warnings (client creation, action not found)
- ❌ Empty inventory when resources should exist
- ❌ ERROR in check results
- ✅ Clean JSON output with PASS/FAIL

### 5. Fix Issues

**Common fixes:**
```yaml
# Fix 1: SDK package
sdk_package: azure.mgmt.network  # ✅ (dots not dashes)

# Fix 2: Action names
action: virtual_networks.list_all  # ✅ (correct method)

# Fix 3: Field paths
path: properties.enableDdosProtection  # ✅ (correct nested path)

# Fix 4: Parameters
params:
  resource_group_name: '{{resource_group}}'
```

### 6. Re-run and Verify
```bash
python engine/azure_generic_engine.py > /tmp/test_network_v2.json 2>&1
```

### 7. Update Validation Tracking

At the bottom of the YAML file:

```yaml
# ============================================================================
# VALIDATION TRACKING
# ============================================================================
# STATUS: ✅ VALIDATED
# VALIDATED_BY: Cursor AI
# VALIDATED_DATE: 2024-12-05
# 
# FIXES APPLIED:
# - Changed sdk_package from azure-mgmt-network to azure.mgmt.network
# - Changed action from 'list' to 'list_all'
# - Fixed field path from 'ddos' to 'properties.enableDdosProtection'
#
# TEST RESULTS:
# - Resources Discovered: 3
# - Checks Executed: 34
# - PASS: 5
# - FAIL: 29
# - ERROR: 0
# ============================================================================
```

### 8. Mark as Done
```bash
python sequential_service_validator.py --mark-done network
```

### 9. Move to Next Service
```bash
python sequential_service_validator.py --next
```

---

## 🤖 Using Cursor AI

### Prompt for Cursor AI:

```
I need you to validate this Azure service YAML file.

1. Read the validation instructions at the top of this file (in comments)
2. Run the engine for this service only
3. Analyze the output
4. Fix any issues in the discovery and checks sections
5. Re-run until all checks work (PASS/FAIL, not ERROR)
6. Update the validation tracking at the bottom
7. Let me know when this service is complete

Follow the embedded instructions exactly. Don't skip services - complete this one first.
```

### What Cursor Will Do:

1. **Read** embedded validation instructions
2. **Run** engine for this service
3. **Analyze** output for errors
4. **Fix** YAML issues:
   - SDK package names
   - Action names
   - Field paths
   - Parameters
5. **Test** by re-running engine
6. **Iterate** until working
7. **Document** fixes at bottom
8. **Confirm** service is ready

---

## 📈 Expected Timeline

### Per Service:
- **Simple services** (working already): 2-5 minutes
- **Medium complexity** (need fixes): 10-15 minutes
- **Complex services** (major fixes): 20-30 minutes

### Overall:
- **Optimistic**: 8-12 hours (all services mostly working)
- **Realistic**: 15-20 hours (moderate fixes needed)
- **Pessimistic**: 25-30 hours (many fixes needed)

### With Cursor AI Automation:
- **Process 4-5 services per hour**
- **Complete in 12-15 hours** with AI assistance

---

## 🎯 Success Metrics

### For Each Service:
- ✅ No warnings during engine run
- ✅ Client created successfully
- ✅ Inventory populated (if resources exist)
- ✅ All checks return PASS or FAIL (not ERROR)
- ✅ JSON output is clean
- ✅ Validation tracking updated

### For Overall Project:
- ✅ All 58 services validated
- ✅ Service validation tracker shows 100%
- ✅ Ready for production deployment

---

## 🚦 Getting Started NOW

### Step 1: Check Current Status
```bash
python sequential_service_validator.py --status
```

### Step 2: Start Validation
```bash
python sequential_service_validator.py --start
```

### Step 3: Open First Service in Cursor
```bash
# (Output will tell you which file to open)
cursor services/<service>/<service>_rules.yaml
```

### Step 4: Tell Cursor AI
```
"Validate this Azure service YAML using the embedded instructions.
 Fix all issues until the engine runs without errors.
 Update validation tracking when done."
```

### Step 5: Mark Done and Continue
```bash
python sequential_service_validator.py --mark-done <service>
python sequential_service_validator.py --next
```

### Step 6: Repeat Until All 58 Services Done

---

## 📋 Service Checklist

Copy this to track progress manually:

```
✅ = Validated & Working
⏳ = In Progress
❌ = Blocked/Error
⬜ = Not Started

High Priority:
[✅] storage
[⏳] network (current)
[⬜] keyvault
[⬜] iam
[⬜] aad (needs Graph API)
[⬜] compute
[⬜] sql
[⬜] aks
[⬜] webapp
[⬜] function
[⬜] cosmosdb
[⬜] monitor
[⬜] security
[⬜] policy
[⬜] dns

Medium Priority:
[⬜] containerregistry
[⬜] synapse
[⬜] databricks
... (continues)
```

---

## 🎉 Summary

### What's Ready:

✅ **Generic engine** - Working perfectly
✅ **58 service YAMLs** - All have embedded validation prompts
✅ **Sequential validator** - Tracks progress, manages workflow
✅ **Auto-validator** - Runs tests, analyzes output
✅ **Complete documentation** - Everything you need

### What to Do:

```bash
# 1. Start validation
python sequential_service_validator.py --start

# 2. Open service in Cursor
cursor services/network/network_rules.yaml

# 3. Tell Cursor: "Validate this service using embedded instructions"

# 4. Mark done when ready
python sequential_service_validator.py --mark-done network

# 5. Move to next
python sequential_service_validator.py --next

# 6. Repeat for all 58 services
```

### Estimated Time:
- **15-20 hours** total with Cursor AI assistance
- **Process 4-5 services per hour**
- **Complete all 58 services systematically**

---

## 🚀 START NOW!

```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

# See the list
python sequential_service_validator.py --list

# Start validation
python sequential_service_validator.py --start

# The validator will tell you exactly what to do next!
```

---

**Ready to validate all 58 Azure services! 🔥**

_Created: December 5, 2024_
