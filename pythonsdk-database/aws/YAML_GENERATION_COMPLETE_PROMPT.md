# Complete AWS Service YAML Generation Prompt

## Objective

Generate CSPM-compatible YAML files for AWS services using a systematic 5-step process that creates minimal, correct discovery entries and compliance rules.

## Quick Reference: YAML Field to CSV Mapping

**Complete mapping document:** See `YAML_FIELD_TO_CSV_MAPPING.md` for detailed field-by-field mapping.

**Key Flow:** `var` (from check) → `python_method` (from dependency chain CSV) → `action` & `discovery_id` → All YAML fields

**Critical Rule:** The `python_method` from `step2-required-params-to-methods-with-chains-{service}.csv` is the **source of truth** for:
- `action` field (direct use: `action: {python_method}`)
- `discovery_id` field (format: `aws.{service}.{python_method}`)

### Essential Mappings

| YAML Field | Source | CSV File/Column |
|-----------|--------|----------------|
| `discovery_id` | `python_method` | `step2-*-with-chains-*.csv` → `python_method` |
| `action` | `python_method` | `step2-*-with-chains-*.csv` → `python_method` |
| `for_each` (discovery) | Provider `python_method` | `step2-*-with-chains-*.csv` → chain provider |
| `for_each` (checks) | `python_method` emitting `var` field | `step2-*-with-chains-*.csv` → `python_method` |
| `params` | `required_params` + `full_path` | `step2-*-with-chains-*.csv` → `required_param`, `full_path` |
| `emit.items_for` | `full_path` (before `[]`) | `step2-*-with-chains-*.csv` → `full_path` |
| `emit.item.{field}` | **ALL** `item_fields` from metadata | Metadata `item_fields` (ALL fields from `main_output_field` array) |

### Critical Rules

1. **for_each in discovery:** If `python_method` has `required_params`, it **MUST** have `for_each` pointing to the provider method.
2. **emit.item.{field}:** Must emit **ALL** fields from `item_fields` in metadata JSON, not just a subset. The `item_fields` contains all fields from the `main_output_field` array (e.g., `Policies[]`).

## Prerequisites

- **Input JSON:** `/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/boto3_dependencies_with_python_names_fully_enriched.json`
- **Output Directory:** `/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/yaml_generation/`
- **Engine Path:** `/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/`

## Complete Process

### STEP 1: Generate Unique Functions Covering All Output Fields

**Objective:** Find minimal set of functions that can generate ALL unique output_fields for the service.

**Process:**
1. Load service data from enriched JSON
2. Identify independent vs dependent operations
3. Collect all `output_fields` (top-level) and `item_fields` (nested) from all operations
4. Build mappings:
   - `field_to_functions`: Which functions provide each field
   - `function_to_fields`: Which fields each function provides
   - `function_to_full_fields`: Full paths (e.g., `analyzers[].name`)
5. Use greedy algorithm:
   - Start with empty selected set
   - Iteratively add function that covers most uncovered fields
   - Stop when all fields are covered
6. Create CSV: `step1-unique-functions-all-output-fields-{SERVICE}.csv`
   - Columns: `python_method`, `is_independent`, `required_params`, `output_fields`, `output_fields_count`
   - Include all fields with full paths from `item_fields`

**Key Rules:**
- Include both `output_fields` and `item_fields`
- Build full paths: `{main_output_field}[].{field_name}` for nested fields
- Track independent methods (no required_params)

### STEP 2: Map Required Params to Python Methods

**Objective:** For each unique required_param, find the best python_method that provides it, following strict selection rules.

**Process:**
1. Collect all unique `required_params` from all operations
2. Build reverse mapping from operations:
   - Check `output_fields` (top-level)
   - Check `item_fields` (nested, with `main_output_field` paths)
3. For each required_param, apply selection rules in order:

   **Rule a:** Filter out methods that require the same param
   - Check if candidate method's `required_params` includes the param
   - Skip if circular dependency detected
   
   **Rule b-i:** Prefer independent over dependent methods
   - Check `independent` vs `dependent` arrays in JSON
   - If independent methods exist, use them
   
   **Rule b-ii:** If only dependent methods, prioritize by prefix:
   - `list_*` functions (priority 0) - best for discovery
   - `get_*` functions (priority 1)
   - `update_*` functions (priority 2)
   - `describe_*` functions (priority 3)
   - Others (priority 4)
   
   **Rule c:** Handle aliases with context awareness:
   - Param ending with `Arn` → try `arn` field
   - Param ending with `Name` → try `name` field
   - Param ending with `Id` → try `id` field
   - Context-specific: `accessPreviewId` → prefer methods with 'preview' in name
   - Context-specific: `findingId` → prefer methods with 'finding' in name
   
   **Rule d:** Build full path for param:
   - If `main_output_field` exists: `{main_output_field}[].{field_name}`
   - Example: `analyzerName` → `analyzers[].name`
   - Example: `accessPreviewId` → `accessPreviews[].id`

4. Create CSV: `step2-required-params-to-methods-{SERVICE}.csv`
   - Columns: `required_param`, `python_method`, `full_path`, `is_independent`, `selection_reason`
   - Mark as `NOT_FOUND` if no method provides the param

**Critical Fixes (Enhanced Rule a):**
- **Verify emission**: Method must actually EMIT the parameter in `item_fields` or `output_fields` (not just have it in output_fields structure)
- **Avoid circular**: Method must NOT require the same parameter it's supposed to provide
- **Read-only only**: Method must be read-only (`list_*`, `get_*`, `describe_*` only) - no `create_*`, `update_*`, `delete_*`
- **Handle aliases**: When exact match creates circular dependency, use aliases (e.g., `analyzerArn` → `arn` from `list_analyzers`)
- **Validate full path**: Ensure the `full_path` points to an actual emitted field

**Example of correct validation:**
```python
# For parameter "Bucket":
# ✅ CORRECT: list_buckets emits "Name" (which is Bucket name)
# ❌ WRONG: list_multipart_uploads requires "Bucket" (circular!)
# ❌ WRONG: create_bucket is write operation (not read-only)
```

### STEP 3: Build Dependency Chains

**Objective:** Trace dependency chains for each python_method back to independent methods.

**Process:**
1. Load step2 CSV to build param → method mappings
2. For each method in step2:
   - If `NOT_FOUND` → chain = `NOT_SUPPORTED`
   - If independent → chain = `method - INDEPENDENT`
   - If dependent → recursively trace:
     ```
     function build_dependency_chain(method, visited):
       if method in visited: return []  # Prevent loops
       if method == 'NOT_FOUND': return ['NOT_SUPPORTED']
       if method is independent: return [method]
       
       required_params = get_required_params(method)
       dependency_methods = []
       for param in required_params:
         provider = param_to_method[param]
         if provider != method and provider != 'NOT_FOUND':
           if provider is independent:
             dependency_methods.append(provider)
           else:
             # Check if provider doesn't require same param (avoid circular)
             if param not in get_required_params(provider):
               dependency_methods.append(provider)
       
       # Recursively get chains for dependencies
       all_chains = []
       for dep in dependency_methods:
         all_chains.extend(build_dependency_chain(dep, visited + [method]))
       
       return [method] + unique(all_chains)
     ```
3. Format chains with param paths:
   - `method (param1:path1, param2:path2) → dep_method (param:path) → independent_method (param:path) - INDEPENDENT`
4. Create CSV: `step2-required-params-to-methods-with-chains-{SERVICE}.csv`
   - Add columns: `dependency_chain`, `dependency_chain_formatted`

**Key Points:**
- Prevent infinite loops with visited set
- Handle circular dependencies gracefully
- Include param paths in formatted output
- Stop recursion at independent methods

### STEP 4: Add require_python_method_for_param to Step1

**Objective:** Map each function's required_params to the python_methods that provide them.

**Process:**
1. Load step2 CSV to get param → method mappings with priorities
2. Build priority mapping:
   - Independent methods: priority 0
   - `list_*` methods: priority 1
   - `get_*` methods: priority 2
   - Others: priority 3
3. For each function in step1:
   - Parse `required_params` column
   - For each param, find best method from step2 (sorted by priority)
   - Add method to `require_python_method_for_param` if not already present
   - Avoid duplicates (each method appears once per function)
4. Create CSV: `step1-unique-functions-all-output-fields-with-params-{SERVICE}.csv`
   - Add column: `require_python_method_for_param` (comma-separated methods)

**Key Points:**
- One method per param (best match)
- Multiple methods if multiple params needed
- Prioritize independent and list_ methods
- Avoid duplicate methods in the same function's mapping

### STEP 5: Generate Minimal YAML

**Objective:** Create YAML with only discovery entries needed for two compliance rules.

**Rules to Support:**
1. `aws.{SERVICE}.resource.{resource}_active` - checks `status == ACTIVE`
2. `aws.{SERVICE}.resource.{resource}_with_findings` - checks `id` exists

**Process:**
1. Identify required methods:
   - Method providing `status` field → for rule 1
   - Method providing `id` field → for rule 2
   - Trace dependencies (what provides params for these methods)

2. Build discovery entries in dependency order (independent first):

   **Independent Method:**
   ```yaml
   - discovery_id: aws.{service}.{method}
     calls:
     - action: {method}
       save_as: response
     emit:
       items_for: '{{ response.{main_output_field} }}'
       as: resource
       item:
         {field1}: '{{ resource.{field1} }}'
         {field2}: '{{ resource.{field2} }}'
         # ... all fields from item_fields
   ```

   **Dependent Method:**
   ```yaml
   - discovery_id: aws.{service}.{method}
     calls:
     - action: {method}
       save_as: response
       params:
         {param1}: '{{ item.{field1} }}'
         {param2}: '{{ item.{field2} }}'
       on_error: continue
       for_each: aws.{service}.{dependency_method}
     emit:
       items_for: '{{ response.{main_output_field} }}'  # if list_ method
       as: resource
       item:
         {field1}: '{{ resource.{field1} }}'
   ```

3. Handle parameter mapping with aliases:
   - If `for_each` is `list_analyzers` (or similar independent method):
     - `analyzerArn` → use `item.arn` (not `item.analyzerArn`)
     - `analyzerName` → use `item.name`
     - `analyzerId` → use `item.id`
   - Otherwise: use `full_path` from step2 CSV to extract field name

4. Handle emit structure:
   - **List methods** (`list_*`): Use `items_for` pattern
   - **Get methods** (`get_*`): Use `item` pattern with `response.{main_output_field}.{field}`

5. Build checks section:
   ```yaml
   checks:
   - rule_id: aws.{service}.resource.{resource}_active
     for_each: aws.{service}.{method_providing_status}
     conditions:
       var: item.status
       op: equals
       value: ACTIVE
   - rule_id: aws.{service}.resource.{resource}_with_findings
     for_each: aws.{service}.{method_providing_id}
     conditions:
       var: item.id
       op: exists
       value: null
   ```

6. Create YAML: `{SERVICE}_minimal_with_rules.yaml`

**Critical Fixes:**
- **Read-only only (Audit Mode)**: Only include `list_*`, `get_*`, `describe_*` methods in discovery. NEVER include `create_*`, `update_*`, `delete_*` methods.
- **Parameter emission validation**: Verify method actually EMITS the parameter (in `item_fields` or `output_fields`), not just has it in structure
- **Circular dependency prevention**: Method must NOT require the same parameter it's supposed to provide
- **for_each validation**: Ensure `for_each` discovery_id exists and emits all required parameters
- **Handle circular dependencies**: If method requires param that maps to itself, use alias from independent method
  - Example: `list_access_previews` requires `analyzerArn` → `analyzerArn` maps to `list_access_previews` → use `arn` from `list_analyzers`
- **Array/Object handling**: For `list_*` methods, use `items_for` pattern. For `get_*` methods, use `item` pattern with `response.{main_output_field}.{field}`
- **Include all fields**: Include all fields from `item_fields` in emit section

## Critical Quality Issues and Fixes (December 2024)

### Issue 1: Parameter Dependency Validation (Root Cause)

**Problem:** Methods were mapped to provide parameters they actually require (circular dependency).

**Example:** S3 `Bucket` parameter mapped to `list_multipart_uploads`, but `list_multipart_uploads` requires `Bucket` as input and doesn't emit it.

**Solution:** Enhanced Rule a in STEP 2:
1. **Verify emission**: Check method actually emits parameter in `item_fields` or `output_fields`
2. **Avoid circular**: Method must NOT require the same parameter
3. **Read-only only**: Method must be read-only (`list_*`, `get_*`, `describe_*` only)

**Implementation:**
```python
# Enhanced validation in STEP 2
for method in candidate_methods:
    op = method_to_op[method]
    
    # Check 1: Emits parameter
    emits_param = (param in item_fields or param in output_fields or 
                   any(alias in item_fields for alias in get_aliases(param)))
    
    # Check 2: Doesn't require parameter
    requires_param = param in op.get('required_params', [])
    
    # Check 3: Read-only
    is_read_only = method.startswith(('list_', 'get_', 'describe_'))
    
    if emits_param and not requires_param and is_read_only:
        filtered_candidates.append(method)
```

### Issue 2: Create/Update/Delete in Discovery

**Problem:** Discovery included `create_*`, `update_*`, `delete_*` methods which mutate AWS state.

**Solution:**
- Filter in STEP 1: Only consider read-only methods in greedy algorithm
- Filter in STEP 5: Only include read-only methods in discovery entries
- Add validation warnings if write operations detected

### Issue 3: Invalid for_each References

**Problem:** `for_each` referenced discovery IDs that don't exist or don't emit required fields.

**Example:** `get_access_key_last_used` uses `for_each: aws.iam.list_access_keys` but `list_access_keys` not in discovery.

**Solution:**
- Validate `for_each` discovery_id exists in discovery list
- Verify source discovery emits all required parameters
- Remove invalid `for_each` and params if source doesn't exist

### Issue 4: Template Resolution Failures

**Problem:** Literal strings like `"{{ item.Bucket }}"` passed to AWS API instead of resolved values.

**Solution:**
- Validate templates reference existing fields in source discovery
- Use proper field names from `full_path` in param mapping
- Ensure `for_each` source actually emits the field

### Issue 5: Array/Object Confusion

**Problem:** Templates like `response.UserDetailList.UserName` fail because `UserDetailList` is an array.

**Solution:**
- For `list_*` methods: Use `items_for: '{{ response.Users }}'` (array reference)
- For `get_*` methods: Use `item: { field: '{{ response.Object.field }}' }` (object reference)
- Validate `main_output_field` points to array when method is `list_*`

### Issue 6: Type Mismatches in Evaluators

**Problem:**
- Empty strings converted to float → `could not convert string to float: ''`
- `contains` used on lists → `'in <string>' requires string as left operand, not list`
- Date comparisons fail → relative dates like "90 days ago" not parsed

**Solution (Engine-level):**
- Normalize empty strings: `'' → None` before type operations
- List-aware contains: If left side is list, check `any(element contains value)`
- Date-aware operators: Parse relative dates properly

## Post-Generation Fixes

After generating YAML files, apply these fixes:

### Fix 1: Field Case Mapping
**Script:** `fix_field_case_mapping.py`

**Issue:** `var` fields in checks use snake_case (`is_encrypted`) but emit fields use PascalCase (`IsEncrypted`)

**Solution:**
- Convert snake_case to PascalCase/camelCase
- Use case-insensitive matching
- Handle field name variations (underscores, hyphens)
- Update all var references in checks

**Example:**
```yaml
# Before
var: item.is_encrypted

# After  
var: item.IsEncrypted
```

### Fix 2: for_each Reference Matching
**Script:** `fix_for_each_by_var_field.py`

**Issue:** Some checks reference wrong discovery_id in `for_each` - the var field doesn't exist in that discovery's emit

**Solution:**
- Match var field names with discovery emit fields
- Use case-insensitive and normalized field matching
- Handle nested fields (e.g., `item.security_contact.exists`)
- Update for_each to point to discovery that actually emits the field

**Process:**
1. Extract field name from var (e.g., `item.status` → `status`)
2. Check all discovery entries for field in emit
3. Use scoring system: exact match (100) > case-insensitive (90) > normalized (80) > partial (60)
4. Update for_each to best matching discovery_id

### Fix 3: Create Checks for Services Without Rules
**Script:** `create_checks_from_metadata.py`

**Issue:** Some services have no rules extracted from existing YAML

**Solution:**
- Read metadata files (`{service}_metadata.yaml`)
- Generate at least one discovery entry using independent methods as fallback
- Use AWS expertise to determine appropriate field checks:
  - Encryption checks → `IsEncrypted` or `EncryptionEnabled` fields
  - Status checks → `Status` or `State` fields
  - Risk checks → `RiskCounts` or `PrioritizedRiskCounts`
  - Failover checks → `FailoverEnabled` or `failback` fields
- Create checks based on metadata rule_ids

**Service-specific fallbacks:**
- `transfer`: Use `list_servers` for server encryption checks
- `wellarchitected`: Use `list_workloads` for risk checks
- `drs`: Use `describe_recovery_instances` for failover checks

### Fix 4: Copy YAMLs to Service Folders
**Script:** `copy_yamls_to_services.py`

**Process:**
1. Copy all `*_minimal_with_rules.yaml` files to:
   - `aws_compliance_python_engine/services/{service}/rules/{service}.yaml`
2. Remove old YAML files (keep `.backup` and `.test` files)
3. Handle service name mappings (e.g., `network-firewall` → `networkfirewall`)

## Output Files

All files saved to: `/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/yaml_generation/`

1. `step1-unique-functions-all-output-fields-{SERVICE}.csv` - Minimal function set
2. `step1-unique-functions-all-output-fields-with-params-{SERVICE}.csv` - With param mappings
3. `step2-required-params-to-methods-{SERVICE}.csv` - Param to method mappings
4. `step2-required-params-to-methods-with-chains-{SERVICE}.csv` - With dependency chains
5. `{SERVICE}_minimal_with_rules.yaml` - Final YAML file
6. `extracted_rules_by_service.json` - All rules extracted from existing YAMLs

**Final Location:** YAML files are copied to `aws_compliance_python_engine/services/{service}/rules/{service}.yaml`

## Testing

After generation, test the YAML:

```bash
cd /Users/apple/Desktop/threat-engine
python3 test_accessanalyzer_yaml.py
```

Expected output:
- Engine runs without errors
- Warnings about missing resources are OK (expected if no resources exist)
- YAML structure is validated
- Checks execute (may show 0 results if no resources exist)

## Common Issues and Solutions

### Issue 1: Circular Dependencies
**Symptom:** Method requires param that maps to itself
**Solution:** 
- Check if param ends with Arn/Name/Id
- Use alias from independent method (e.g., `arn` from `list_analyzers`)
- Update param mapping logic to handle this case

### Issue 2: Missing Params
**Symptom:** Param marked as `NOT_FOUND`
**Solution:**
- Check `item_fields` of all methods (not just `output_fields`)
- Try aliases (Arn→arn, Name→name, Id→id)
- Check if param exists in nested structures

### Issue 3: Wrong Emit Structure
**Symptom:** Engine fails to parse emit section
**Solution:**
- List methods: Use `items_for` with `as: resource`
- Get methods: Use `item` with `response.{main_output_field}.{field}`
- Include all fields from `item_fields`

### Issue 4: Invalid Parameter Reference
**Symptom:** `Invalid analyzerArn` error
**Solution:**
- Check if `for_each` method provides the param
- Use alias if param name doesn't match (e.g., `analyzerArn` → `arn`)
- Verify param path is correct from step2 CSV

## Script Usage

Use the consolidated script: `step1_generate_yaml_for_all_services.py`

```bash
# Process single service
python3 step1_generate_yaml_for_all_services.py accessanalyzer

# Process multiple services  
python3 step1_generate_yaml_for_all_services.py accessanalyzer ec2 s3

# Process all services (be careful - takes time!)
python3 step1_generate_yaml_for_all_services.py
```

## Example: accessanalyzer

**Step 1 Result:** 18 functions selected to cover 80 output_fields

**Step 2 Result:** 13/20 params mapped (7 marked NOT_FOUND - these are input params like `policyDocument`)

**Step 3 Result:** Dependency chains built, circular dependencies resolved

**Step 4 Result:** Each function has `require_python_method_for_param` column populated

**Step 5 Result:** Minimal YAML with:
- `list_analyzers` (independent) - provides `status`
- `list_access_previews` (dependent on `list_analyzers`) - provides `id`
- Two checks: `analyzer_active` and `analyzer_with_findings`

**Key Fix:** `list_access_previews` requires `analyzerArn` which mapped to itself → Fixed by using `arn` from `list_analyzers`

## Validation Checklist

Before finalizing, verify:
- [ ] All discovery entries have correct `for_each` references
- [ ] All params use correct field names (aliases applied where needed)
- [ ] Emit structures match method type (list vs get)
- [ ] All fields from `item_fields` included in emit
- [ ] Dependency chains resolve to independent methods
- [ ] No circular dependencies in final YAML
- [ ] Checks reference correct discovery_ids
- [ ] **var field names match emit field names (case-sensitive)**
- [ ] **for_each discovery_ids actually emit the fields referenced in var**
- [ ] **All services have at least one discovery entry**
- [ ] **All services have checks (or metadata-based checks created)**
- [ ] YAML syntax is valid (test with yaml.safe_load)

## Success Criteria

✅ YAML file generated successfully
✅ Field case mappings fixed (var matches emit)
✅ for_each references match var fields
✅ Checks created for all services (including from metadata)
✅ YAML files copied to service folders
✅ Old YAML files removed
✅ Engine runs without syntax errors
✅ Discovery entries execute (may show warnings if no resources)
✅ Checks execute (may show 0 results if no resources)
✅ Dependency chains are correct
✅ All required fields are accessible

## Key Learnings

1. **Field Case Mapping**: Always convert var field names to match emit field names using case-insensitive matching. Use `fix_field_case_mapping.py` to handle snake_case → PascalCase conversions.

2. **for_each Matching**: Verify that for_each discovery_id actually emits the field referenced in var. Use `fix_for_each_by_var_field.py` with scoring system (exact match > case-insensitive > normalized > partial).

3. **Services Without Rules**: Generate discovery entries using independent methods as fallback, then create checks from metadata files using AWS expertise. Use `create_checks_from_metadata.py` to handle services without extracted rules.

4. **Discovery ID Naming**: Match discovery_id names with original YAML when possible using fuzzy matching. Handle service-specific patterns (e.g., `alternate_contacts` → `get_alternate_contact`).

5. **Circular Dependencies**: Always check if method requires param that maps to itself, use aliases from independent methods (e.g., `analyzerArn` → `arn` from `list_analyzers`).

6. **Dependency Chains**: Ensure all transitive dependencies included, especially with parameter aliasing. Build complete chains: `method → dependent_method (param) → independent_method (param)`.

7. **Extract Rules First**: Always extract rules from existing YAMLs before generation to ensure correct for_each references and field mappings.

8. **Post-Generation Validation**: Always run all fix scripts in sequence: field case mapping → for_each matching → checks creation → copy to services.

## Final Deployment

After all fixes are applied:
1. All YAML files are in: `aws_compliance_python_engine/services/{service}/rules/{service}.yaml`
2. Old YAML files are removed (backup and test files preserved)
3. All services have discovery entries
4. All services have checks (either from extracted rules or metadata)
5. All var fields match emit fields
6. All for_each references point to correct discoveries

## YAML Field to CSV Mapping Reference

### Complete Mapping

Every YAML field maps to CSV/metadata sources. See `YAML_FIELD_TO_CSV_MAPPING.md` for complete reference.

### Key Mappings

| YAML Field | Source | CSV File/Column |
|-----------|--------|----------------|
| `discovery_id` | `python_method` | `step2-*-with-chains-*.csv` → `python_method` |
| `action` | `python_method` | `step2-*-with-chains-*.csv` → `python_method` |
| `for_each` (discovery) | Provider `python_method` | `step2-*-with-chains-*.csv` → chain provider |
| `for_each` (checks) | `python_method` emitting `var` field | `step2-*-with-chains-*.csv` → `python_method` |
| `params` | `required_params` + `full_path` | `step2-*-with-chains-*.csv` → `required_param`, `full_path` |
| `emit.items_for` | `full_path` (before `[]`) | `step2-*-with-chains-*.csv` → `full_path` |
| `emit.item.{field}` | `item_fields` + `full_path` | Metadata `item_fields` + CSV `full_path` |
| `rule_id`, `var`, `op`, `value` | Extracted rules | `extracted_rules_by_service.json` |

### Critical Rule

**The `python_method` from dependency chain CSV defines:**
- `action` field (direct: `action: {python_method}`)
- `discovery_id` field (format: `aws.{service}.{python_method}`)

**Flow:** `var` → field name → `python_method` (from chain) → `action` & `discovery_id`

## Implementation Status (December 2024)

### ✅ Fixes Implemented in `step1_generate_yaml_for_all_services.py`

1. **Enhanced Parameter Dependency Validation (STEP 2 - Rule a)**
   - ✅ Verifies method actually EMITS parameter (checks `item_fields` and `output_fields`)
   - ✅ Prevents circular dependencies (method must NOT require same parameter)
   - ✅ Enforces read-only only (only `list_*`, `get_*`, `describe_*` methods)
   - ✅ Location: Lines 235-280

2. **Read-Only Filter in STEP 1**
   - ✅ Only read-only methods considered in greedy algorithm
   - ✅ Location: Lines 100-120

3. **Read-Only Filter in STEP 5**
   - ✅ Filters out `create_*`, `update_*`, `delete_*` from discovery entries
   - ✅ Filters out write operations from `required_methods_for_rules` when matching from rules
   - ✅ Location: Lines 740-753, 625-650

4. **S3 Bucket Parameter Fix**
   - ✅ Automatically adds `list_buckets` when `Bucket` parameter is needed
   - ✅ Maps `Bucket` to `item.Name` from `list_buckets`
   - ✅ Location: Lines 726-736, 781-784, 820-840

5. **for_each Chain Validation**
   - ✅ Validates `for_each` discovery_id exists
   - ✅ Verifies source discovery emits all required parameters
   - ✅ Removes invalid `for_each` and params if source doesn't exist
   - ✅ Location: Lines 800-830

6. **Provider Method Validation**
   - ✅ Only read-only provider methods used for `for_each` chains
   - ✅ Location: Lines 809-812

### ✅ Verification Results

- **S3**: Bucket parameter correctly uses `list_buckets`, all `get_bucket_*` methods have proper `for_each`
- **IAM**: No write operations (`create_*`, `update_*`, `delete_*`) in discovery entries
- **Dependency Chains**: Circular dependencies prevented, `NOT_FOUND` correctly marked

### 📝 Next Steps

1. Regenerate all services with updated script
2. Test with engine for iam, s3, ec2
3. Fix any remaining issues found during testing
4. Update prompt document with any new learnings

