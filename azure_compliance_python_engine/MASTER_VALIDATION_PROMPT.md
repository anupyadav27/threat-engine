# 🤖 AZURE SERVICE VALIDATION - MASTER PROMPT FOR CURSOR AI

## 📋 CONTEXT

You are systematically validating **all 58 Azure service YAML files** for the Azure Generic Compliance Engine.

Each service YAML file has:
1. **Embedded inline validation instructions** at the top (in comments)
2. **Service configuration** (sdk_package, client_class, scope)
3. **Discovery section** (how to find resources)
4. **Checks section** (compliance rules to evaluate)
5. **Validation tracking** at the bottom (to update when done)

---

## 🎯 YOUR MISSION

Process **each service one by one** following this workflow:

```
FOR EACH SERVICE:
1. Read inline prompt at top of YAML file (MANDATORY)
2. Follow inline instructions exactly
3. Run engine for this service only
4. Analyze output
5. Fix issues in YAML
6. Re-run until working
7. Update validation tracking at bottom
8. Mark service as done
9. Move to next service

DO NOT SKIP TO NEXT SERVICE UNTIL CURRENT ONE IS ✅ VALIDATED
```

---

## 📂 ALL AZURE SERVICES TO VALIDATE (58 Total)

### PROCESSING ORDER:

Each service file path is: `services/<SERVICE>/<SERVICE>_rules.yaml`

**IMPORTANT:** Open the file and read the embedded instructions FIRST!

### ✅ ALREADY VALIDATED (4)

1. ✅ `storage` - services/storage/storage_rules.yaml
   - Scope: subscription
   - Discoveries: 1
   - Checks: 88
   - Status: WORKING

2. ✅ `network` - services/network/network_rules.yaml
   - Scope: subscription
   - Discoveries: 8
   - Checks: 34
   - Status: WORKING

3. ✅ `keyvault` - services/keyvault/keyvault_rules.yaml
   - Scope: subscription
   - Discoveries: 4
   - Checks: 7
   - Status: WORKING

4. ✅ `iam` - services/iam/iam_rules.yaml
   - Scope: subscription
   - Discoveries: 3
   - Checks: 7
   - Status: WORKING

---

### ⏳ TO BE VALIDATED (54)

**🔴 HIGH PRIORITY - Common Services (11)**

5. ⏳ `aad` - services/aad/aad_rules.yaml
   - Scope: tenant
   - Discoveries: 5
   - Checks: 72
   - **NOTE:** Needs Microsoft Graph API support
   - Sample checks:
     - azure.aad.identity_service_principal.access_service_account_no_user_long_lived_keys
     - azure.graph.api.365.group.creation.restriction.check
     - azure.aad.user.access_user_console_password_present_only_if_required

6. ⏳ `compute` - services/compute/compute_rules.yaml
   - Scope: subscription
   - Discoveries: 5
   - Checks: 81
   - Sample checks:
     - azure.compute.vm.disk.encryption.enabled
     - azure.compute.vm.managed.disk.encryption.enabled
     - azure.compute.vm.network.interface.public.ip.disabled

7. ⏳ `sql` - services/sql/sql_rules.yaml
   - Scope: subscription
   - Discoveries: 4
   - Checks: 65
   - Sample checks:
     - azure.sql.database.encryption.with.customer.managed.keys
     - azure.sql.server.auditing.enabled
     - azure.sql.database.transparent.data.encryption.enabled

8. ⏳ `aks` - services/aks/aks_rules.yaml
   - Scope: subscription
   - Discoveries: 1
   - Checks: 96
   - Sample checks:
     - azure.aks.cluster.rbac.enabled
     - azure.aks.cluster.network.policy.enabled
     - azure.aks.cluster.private.cluster.enabled

9. ⏳ `webapp` - services/webapp/webapp_rules.yaml
   - Scope: subscription
   - Discoveries: 2
   - Checks: 62
   - Sample checks:
     - azure.webapp.app.authentication.enabled
     - azure.webapp.app.https.only.enabled
     - azure.webapp.app.tls.version.minimum

10. ⏳ `function` - services/function/function_rules.yaml
    - Scope: subscription
    - Discoveries: 1
    - Checks: 41
    - Sample checks:
      - azure.function.app.authentication.enabled
      - azure.function.app.https.only.enabled
      - azure.function.app.managed.identity.enabled

11. ⏳ `cosmosdb` - services/cosmosdb/cosmosdb_rules.yaml
    - Scope: subscription
    - Discoveries: 1
    - Checks: 13
    - Sample checks:
      - azure.cosmosdb.account.automatic.failover.enabled
      - azure.cosmosdb.account.encryption.with.customer.managed.keys

12. ⏳ `monitor` - services/monitor/monitor_rules.yaml
    - Scope: subscription
    - Discoveries: 4
    - Checks: 101
    - Sample checks:
      - azure.monitor.alert.rule.enabled
      - azure.monitor.diagnostic.setting.enabled

13. ⏳ `security` - services/security/security_rules.yaml
    - Scope: subscription
    - Discoveries: 2
    - Checks: 84
    - Sample checks:
      - azure.security.center.auto.provisioning.enabled
      - azure.security.center.standard.pricing.tier

14. ⏳ `policy` - services/policy/policy_rules.yaml
    - Scope: management_group
    - Discoveries: 2
    - Checks: 51
    - Sample checks:
      - azure.policy.assignment.compliance.enabled
      - azure.policy.definition.parameters.configured

15. ⏳ `dns` - services/dns/dns_rules.yaml
    - Scope: subscription
    - Discoveries: 2
    - Checks: 12
    - Sample checks:
      - azure.dns.zone.dnssec.enabled
      - azure.dns.record.set.ttl.minimum

**🟡 MEDIUM PRIORITY - Infrastructure (22 services)**

16. ⏳ `containerregistry` - services/containerregistry/containerregistry_rules.yaml
    - Checks: 7

17. ⏳ `synapse` - services/synapse/synapse_rules.yaml
    - Checks: 41

18. ⏳ `databricks` - services/databricks/databricks_rules.yaml
    - Checks: 8

19. ⏳ `data` - services/data/data_rules.yaml (Data Factory)
    - Checks: 95

20. ⏳ `redis` - services/redis/redis_rules.yaml
    - Checks: 5

21. ⏳ `mysql` - services/mysql/mysql_rules.yaml
    - Checks: 8

22. ⏳ `postgresql` - services/postgresql/postgresql_rules.yaml
    - Checks: 7

23. ⏳ `backup` - services/backup/backup_rules.yaml
    - Checks: 51

24. ⏳ `automation` - services/automation/automation_rules.yaml
    - Checks: 9

25. ⏳ `log` - services/log/log_rules.yaml (Log Analytics)
    - Checks: 3

26-37. ... (additional medium priority services)

**🟢 LOWER PRIORITY - Specialized (21 services)**

38-58. Specialized services (batch, cdn, elastic, etc.)

---

## 🔄 VALIDATION WORKFLOW FOR EACH SERVICE

### MANDATORY STEP 1: Read Inline Prompt

**Before doing ANYTHING else**, you MUST:

```bash
# Open the service YAML file
cursor services/<SERVICE>/<SERVICE>_rules.yaml

# Read the validation instructions at the top (in comments starting with #)
# These instructions are SPECIFIC to this service
# They tell you exactly what to do
```

**The inline prompt contains:**
- Service name
- Current validation status
- Exact commands to run
- Common issues for this service
- Success criteria
- Where to update when done

**YOU MUST FOLLOW THE INLINE PROMPT FIRST!**

---

### STEP 2: Run Engine for This Service

```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine
source venv/bin/activate

export AZURE_ENGINE_FILTER_SERVICES="<SERVICE_NAME>"
export LOG_LEVEL=WARNING
python engine/azure_generic_engine.py > /tmp/test_<SERVICE>.json 2>&1

# View results
tail -100 /tmp/test_<SERVICE>.json
```

---

### STEP 3: Analyze Output

Check for:

**❌ Client Creation Errors:**
```
WARNING: Failed to create client for <service>: No module named 'azure.mgmt.<service>'
```
**FIX:**
- Install: `pip install azure-mgmt-<service>`
- Fix YAML: `sdk_package: azure.mgmt.<service>` (use DOTS)

**❌ Action Errors:**
```
WARNING: Action path not found: <resources>.<method>
WARNING: Method not found: <method> in action <resources>.<method>
```
**FIX:**
- Test in Python to find correct method
- Update YAML action name

**❌ Empty Inventory (when resources should exist):**
```json
{"inventory": {"azure.<service>.<resource>": []}}
```
**FIX:**
- Verify action name is correct
- Create test resource if needed
- Check required parameters

**❌ ERROR in Checks:**
```json
{"check_id": "azure.<service>.<check>", "result": "ERROR", "error": "..."}
```
**FIX:**
- Fix field paths
- Fix parameters
- Fix template substitution

**✅ Success:**
```json
{
  "inventory": {"azure.<service>.<resource>": [{...}]},
  "checks": [{"result": "PASS"}, {"result": "FAIL"}]
}
```

---

### STEP 4: Fix Issues in YAML

Edit the service YAML file to fix issues found in Step 3.

**Common fixes:**

```yaml
# 1. Fix SDK package (dots not dashes)
sdk_package: azure.mgmt.network  # ✅

# 2. Fix action names
action: virtual_machines.list_all  # ✅ (test in Python first)

# 3. Fix field paths
path: properties.enableDdosProtection  # ✅ (check resource structure)

# 4. Add parameters
params:
  resource_group_name: '{{resource_group}}'
```

---

### STEP 5: Re-run and Verify

```bash
# Re-run engine
python engine/azure_generic_engine.py > /tmp/test_<SERVICE>_v2.json 2>&1

# Verify:
# - No warnings
# - Inventory populated (if resources exist)
# - Checks = PASS/FAIL (not ERROR)
# - JSON is clean
```

---

### STEP 6: Update Validation Tracking

At the **bottom** of the YAML file, update the validation section:

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
# - Added resource_group_name parameter
#
# TEST RESULTS:
# - Resources Discovered: 3
# - Checks Executed: 34
# - PASS: 5
# - FAIL: 29
# - ERROR: 0
#
# NOTES:
# - All checks working correctly
# - Ready for production
# ============================================================================
```

---

### STEP 7: Mark Complete and Move to Next

```bash
# Mark this service as validated
python sequential_service_validator.py --mark-done <SERVICE>

# Move to next service
python sequential_service_validator.py --next

# This will show you the next service file to open
```

---

## 📊 SERVICE MANIFEST

Total Services: 58
Total Checks: ~1,700 across all services

### Service List with File Paths:

```
1.  storage          → services/storage/storage_rules.yaml (88 checks) ✅
2.  network          → services/network/network_rules.yaml (34 checks)
3.  keyvault         → services/keyvault/keyvault_rules.yaml (7 checks)
4.  iam              → services/iam/iam_rules.yaml (7 checks)
5.  aad              → services/aad/aad_rules.yaml (72 checks) [Graph API]
6.  compute          → services/compute/compute_rules.yaml (81 checks)
7.  sql              → services/sql/sql_rules.yaml (65 checks)
8.  aks              → services/aks/aks_rules.yaml (96 checks)
9.  webapp           → services/webapp/webapp_rules.yaml (62 checks)
10. function         → services/function/function_rules.yaml (41 checks)
11. cosmosdb         → services/cosmosdb/cosmosdb_rules.yaml (13 checks)
12. monitor          → services/monitor/monitor_rules.yaml (101 checks)
13. security         → services/security/security_rules.yaml (84 checks)
14. policy           → services/policy/policy_rules.yaml (51 checks)
15. dns              → services/dns/dns_rules.yaml (12 checks)
16. containerregistry → services/containerregistry/containerregistry_rules.yaml (7 checks)
17. synapse          → services/synapse/synapse_rules.yaml (41 checks)
18. databricks       → services/databricks/databricks_rules.yaml (8 checks)
19. data             → services/data/data_rules.yaml (95 checks)
20. redis            → services/redis/redis_rules.yaml (5 checks)
21. mysql            → services/mysql/mysql_rules.yaml (8 checks)
22. postgresql       → services/postgresql/postgresql_rules.yaml (7 checks)
23. backup           → services/backup/backup_rules.yaml (51 checks)
24. automation       → services/automation/automation_rules.yaml (9 checks)
25. log              → services/log/log_rules.yaml (3 checks)
26. rbac             → services/rbac/rbac_rules.yaml (10 checks)
27. resource         → services/resource/resource_rules.yaml (5 checks)
28. mariadb          → services/mariadb/mariadb_rules.yaml (1 check)
29. purview          → services/purview/purview_rules.yaml (143 checks)
30. search           → services/search/search_rules.yaml (5 checks)
31. hdinsight        → services/hdinsight/hdinsight_rules.yaml (6 checks)
32. batch            → services/batch/batch_rules.yaml (5 checks)
33. container        → services/container/container_rules.yaml (7 checks)
34. front            → services/front/front_rules.yaml (5 checks)
35. traffic          → services/traffic/traffic_rules.yaml (3 checks)
36. cdn              → services/cdn/cdn_rules.yaml (34 checks)
37. event            → services/event/event_rules.yaml (14 checks)
38. logic            → services/logic/logic_rules.yaml (3 checks)
39. api              → services/api/api_rules.yaml (31 checks)
40. notification     → services/notification/notification_rules.yaml (1 check)
41. iot              → services/iot/iot_rules.yaml (1 check)
42. machine          → services/machine/machine_rules.yaml (194 checks)
43. power            → services/power/power_rules.yaml (13 checks)
44. devops           → services/devops/devops_rules.yaml (1 check)
45. blob             → services/blob/blob_rules.yaml (2 checks)
46. files            → services/files/files_rules.yaml (2 checks)
47. key              → services/key/key_rules.yaml (9 checks)
48. certificates     → services/certificates/certificates_rules.yaml (2 checks)
49. netappfiles      → services/netappfiles/netappfiles_rules.yaml (1 check)
50. dataprotection   → services/dataprotection/dataprotection_rules.yaml (5 checks)
51. elastic          → services/elastic/elastic_rules.yaml (2 checks)
52. config           → services/config/config_rules.yaml (1 check)
53. intune           → services/intune/intune_rules.yaml (1 check)
54. subscription     → services/subscription/subscription_rules.yaml (1 check)
55. management       → services/management/management_rules.yaml (7 checks)
56. managementgroup  → services/managementgroup/managementgroup_rules.yaml (1 check)
57. billing          → services/billing/billing_rules.yaml (6 checks)
58. cost             → services/cost/cost_rules.yaml (14 checks)
```

**Total Checks Across All Services:** ~1,700 compliance checks

---

## 🎯 STEP-BY-STEP FOR EACH SERVICE

### Before Starting:
```bash
# Check which service is next
python sequential_service_validator.py --start

# Output tells you which service to open
```

### For Each Service:

#### 1️⃣ **OPEN SERVICE YAML**
```bash
cursor services/<SERVICE>/<SERVICE>_rules.yaml
```

#### 2️⃣ **READ INLINE PROMPT FIRST** (MANDATORY!)

The file starts with:
```yaml
# ============================================================================
# 🤖 CURSOR AI: SERVICE VALIDATION INSTRUCTIONS
# ============================================================================
# SERVICE: <service_name>
# ... (read ALL instructions) ...
```

**Read these instructions completely before proceeding!**

#### 3️⃣ **FOLLOW INLINE INSTRUCTIONS**

The inline prompt tells you:
- Exact command to run
- What to look for
- Common issues for this service
- How to fix them
- Success criteria

#### 4️⃣ **RUN ENGINE**
```bash
export AZURE_ENGINE_FILTER_SERVICES="<SERVICE>"
python engine/azure_generic_engine.py > /tmp/test_<SERVICE>.json 2>&1
```

#### 5️⃣ **ANALYZE OUTPUT**
```bash
tail -100 /tmp/test_<SERVICE>.json

# Look for:
# - Warnings (fix these)
# - Empty inventory (may be OK or need fixes)
# - ERROR in checks (must fix)
# - Clean JSON (should be)
```

#### 6️⃣ **FIX ISSUES**

Edit the YAML file to fix:
- sdk_package format
- action names
- field paths
- parameters
- template variables

#### 7️⃣ **RE-RUN AND VERIFY**
```bash
python engine/azure_generic_engine.py > /tmp/test_<SERVICE>_v2.json 2>&1

# Verify no ERROR results
```

#### 8️⃣ **UPDATE VALIDATION TRACKING**

At bottom of YAML file, update:
```yaml
# STATUS: ✅ VALIDATED
# VALIDATED_BY: Cursor AI
# VALIDATED_DATE: 2024-12-05
# FIXES APPLIED: (list what you fixed)
# TEST RESULTS: (resource counts, check results)
```

#### 9️⃣ **MARK COMPLETE**
```bash
python sequential_service_validator.py --mark-done <SERVICE>
```

#### 🔟 **MOVE TO NEXT**
```bash
python sequential_service_validator.py --next
```

---

## ⚠️ IMPORTANT RULES

### 1. **Always Read Inline Prompt First**
- Each service has specific instructions embedded
- Don't skip reading them
- They contain service-specific guidance

### 2. **One Service at a Time**
- Complete current service before moving to next
- Don't jump around
- Follow the sequential order

### 3. **Verify Complete Success**
- No warnings during run
- Inventory populated (or confirmed no resources)
- All checks = PASS/FAIL (not ERROR)
- JSON is clean
- Validation tracking updated

### 4. **Document Everything**
- Update validation tracking
- Note what you fixed
- Record test results
- Add any service-specific notes

---

## 📈 Progress Tracking

### Check Progress Anytime:
```bash
python sequential_service_validator.py --status

# Shows:
# - Total services
# - Validated count
# - Remaining count
# - Progress bar
# - Current service
```

### View Service List:
```bash
python sequential_service_validator.py --list

# Shows all 58 services with:
# - Status (✅ validated, ⏳ pending, ❌ error)
# - Check counts
# - Resource counts
```

---

## 🎯 What to Tell Cursor AI

### For Each Service:

```
I need you to validate the Azure service YAML file that's currently open.

IMPORTANT: Read the validation instructions at the TOP of this file first (in the comments).

Then:
1. Run the engine for this service only (command is in the inline prompt)
2. Analyze the output
3. Fix any issues in the discovery and checks sections
4. Re-run until all checks work (PASS/FAIL, not ERROR)
5. Update the validation tracking at the BOTTOM of the file
6. Tell me when this service is complete

Follow the embedded instructions exactly. Don't skip to another service until this one is ✅ VALIDATED.
```

---

## 📊 Expected Timeline

### Per Service Average:
- **5-10 minutes** if mostly working
- **10-20 minutes** if needs moderate fixes
- **20-30 minutes** if needs significant fixes

### Overall:
- **58 services** × **15 minutes average** = **~15 hours**
- With breaks and overhead = **18-20 hours total**
- Process **4-5 services per hour**

### Daily Target:
- **Day 1:** 20 services (storage → automation)
- **Day 2:** 20 services (log → api)
- **Day 3:** 18 services (notification → cost)

---

## ✅ Completion Criteria

### Service is DONE when:
- ✅ Engine runs without warnings
- ✅ Client created successfully
- ✅ Discovery actions execute
- ✅ Inventory populated (if resources exist, otherwise verified)
- ✅ All checks return PASS or FAIL (no ERROR)
- ✅ JSON output is clean objects
- ✅ Validation tracking updated
- ✅ Marked as validated in tracker

### All Services DONE when:
- ✅ 58/58 services validated
- ✅ Progress = 100%
- ✅ Ready for production deployment

---

## 🚀 START VALIDATION NOW

```bash
# 1. Start the workflow
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine
python sequential_service_validator.py --start

# 2. Follow the instructions it gives you

# 3. Process each service one by one

# 4. Track progress with:
python sequential_service_validator.py --status

# 5. Continue until all 58 services are validated!
```

---

**🎯 GOAL:** Validate all 58 Azure services systematically

**🔥 Let's complete them all!**

---

_Master Validation Prompt - Created: December 5, 2024_

