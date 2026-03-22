# GLUE YAML Rules Validation Prompt

## 🎯 PRIMARY INTENTION

**Validate that each YAML rule_id check correctly implements what its metadata file says it should check.**

For each rule_id:
1. Read metadata file → Understand **WHAT** it should check
2. Read YAML check → See **WHAT** it actually checks  
3. Compare → Do they match?
4. Fix if they don't match
5. Test against real AWS account
6. Update metadata review report

---

## Service Context

**Service**: `glue`  
**YAML**: `rules/glue.yaml`  
**Metadata**: `metadata/*.yaml`  
**Boto3 Reference**: `pythonsdk-database/aws/glue/`

---

## PHASE 1: Validate Intent Match

### For Each rule_id in YAML:

#### Step 1: Read Metadata Intention
```yaml
# metadata/{rule_id}.yaml
requirement: "What should be checked"
description: "Detailed intent"
rationale: "Why this check exists"
```

**Extract**: What fields should be checked? What values? What operators?

#### Step 2: Read YAML Implementation
```yaml
# rules/glue.yaml
- rule_id: {rule_id}
  for_each: {discovery_id}
  conditions:
    var: item.{field}
    op: {operator}
    value: {expected_value}
```

**Extract**: What fields are actually checked? What values? What operators?

#### Step 3: Compare - Do They Match?

**Check**:
- ✅ Field paths match emit structure?
- ✅ Operators match intent?
- ✅ Values match requirements?
- ✅ Discovery is correct?
- ✅ Logic (all/any) matches intent?

**Common Issues**:
- ❌ Wrong field path: `item.ContactInformation.field` vs `item.field`
- ❌ Wrong operator: `equals null` vs `not_exists`
- ❌ Missing fields: Metadata says check X+Y, YAML only checks X
- ❌ Wrong discovery: Using independent when needs parameters

#### Step 4: Fix Mismatches
Fix any issues found. Verify fix is correct.

---

## PHASE 2: Test Against Real AWS

### Run Test
```bash
cd /Users/apple/Desktop/threat-engine
PYTHONPATH=/Users/apple/Desktop/threat-engine python3 -m aws_compliance_python_engine.engine.main_scanner --service glue --region us-east-1
```

**Note**: If service is global, adjust region parameter as needed.

### Check Results
1. **Execution**: Any errors? Fix them.
2. **Warnings**: Expected or need fixing?
3. **Check Results**: Do PASS/FAIL make sense?
4. **Field Paths**: Match actual API data?

### Fix Runtime Issues
- Parameter errors → Fix discovery params
- Field path errors → Fix to match actual data
- Dependency errors → Fix for_each relationships

### Re-test
Run again. Verify all issues resolved.

---

## PHASE 3: Update Metadata Review

### Generate Report
Create/update `metadata_review_report.json`:

```json
{
  "service": "glue",
  "review_date": "YYYY-MM-DD",
  "review_summary": {
    "total_rules": N,
    "rules_reviewed": N,
    "consolidation_opportunities": N,
    "cross_service_suggestions": 0
  },
  "consolidation_suggestions": {
    "duplicates": [...]
  },
  "validation_summary": {
    "rules_validated": N,
    "rules_passing": N,
    "rules_fixed": N,
    "test_results": {
      "total_checks": N,
      "pass": N,
      "fail": N
    }
  }
}
```

---

## Critical Validation Rules

### Field Paths
- Match emit structure exactly
- Top-level: `item.field` if emit shows `field: '{{ item.field }}'`
- Nested: `item.Parent.field` if emit shows nested structure

### Operators
- `equals` for exact matches (ACTIVE, ENABLED)
- `exists` for presence checks
- `not_exists` for absence checks
- `gt/lt` for numbers

### Discoveries
- Independent: No parameters needed
- Dependent: Needs `for_each` + `params` if API requires parameters
- Use `on_error: continue` for optional resources

---

## Output Format

### Validation Summary
```markdown
## GLUE Validation Results

**Total Rules**: N
**Validated**: N  
**Passing**: N
**Fixed**: N
**Test Status**: PASS/FAIL
```

### Per-Rule Results
```markdown
### {rule_id}
**Metadata Intent**: [What it should check]
**YAML Checks**: [What it actually checks]
**Match**: ✅ YES | ❌ NO
**Issues**: [List if any]
**Fixed**: [Yes/No]
**Test**: [PASS/FAIL]
```

---

## Checklist

- [ ] All metadata files have YAML checks
- [ ] All YAML checks have metadata files
- [ ] Each check matches its metadata intention
- [ ] Field paths are correct
- [ ] Operators are correct
- [ ] Values are correct
- [ ] Discoveries are correct
- [ ] Test passes without errors
- [ ] Check results are logical
- [ ] Metadata review updated

---

**Start**: Phase 1, Step 1 - For each rule_id, read metadata intention and compare with YAML.
