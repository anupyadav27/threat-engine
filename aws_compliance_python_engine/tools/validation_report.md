# YAML Validation Report

Date: December 11, 2025

## Summary

Validated 2 YAML files against real AWS API responses:
- ❌ **accessanalyzer.yaml**: 1 error, 1 warning
- ❌ **account.yaml**: 15 errors, 3 warnings

---

## File 1: accessanalyzer.yaml

### Issues Found

#### ❌ ERROR 1: Invalid for_each pattern
**Location**: Discovery `aws.accessanalyzer.findings`

**Problem**:
```yaml
for_each: '{{ resource_list.analyzers[] }}'
```

The `for_each` is trying to use template syntax, but in the discovery section, `for_each` should reference saved data directly, not use template variables with `{{ }}`.

**Why it fails**:
- The `{{ analyzer.arn }}` in params is not being resolved
- AWS API receives literal string `"{{ analyzer.arn }}"` instead of actual ARN
- This causes validation error: "regex does not match input string"

**Fix**:
```yaml
# Option 1: Remove template syntax from for_each
for_each: resource_list.analyzers[]

# Option 2: Use the pattern from other services
# Don't use for_each at discovery level for this case
```

#### ⚠️ WARNING 1: API call validation error
The list_findings API call failed because the analyzer ARN parameter wasn't resolved.

---

## File 2: account.yaml

### Issues Found

#### Root Cause Analysis

The YAML has a **fundamental structural issue**: The `emit` section doesn't match the actual discovery calls.

**What the YAML does**:
1. Makes 3 API calls to `get_alternate_contact`
2. Saves each as `security_contact`, `billing_contact`, `operations_contact`
3. Tries to emit an item referencing `security_contact.AlternateContact`

**What happens in reality**:
- When API calls fail (ResourceNotFoundException), saved_data is empty
- When they succeed, the response structure doesn't match expectations
- The emit section tries to reference non-existent data

#### ❌ ERROR Group 1: Template variable not found (3 errors)

**Location**: Discovery `aws.account.alternate_contacts` emit section

**Problems**:
```yaml
emit:
  item:
    security_contact: '{{ security_contact.AlternateContact }}'
    billing_contact: '{{ billing_contact.AlternateContact }}'
    operations_contact: '{{ operations_contact.AlternateContact }}'
```

**Why it fails**:
- The API calls failed (ResourceNotFoundException) - no alternate contacts configured
- Even if successful, the saved_data structure doesn't match the template paths
- Available data after calls: empty (because all 3 calls failed)

**Fix**: Need to handle the case when contacts don't exist, and verify the response structure.

#### ❌ ERROR Group 2: Check variable paths not found (12 errors)

**Location**: All 5 checks

**Problems**:
All checks use `for_each` with:
```yaml
for_each:
  discovery: aws.account.alternate_contacts
  as: contacts
  item: contacts
```

Then reference variables like:
```yaml
conditions:
  var: contacts.security_contact
```

**Why it fails**:
- The discovery emitted empty results (because API calls failed)
- The context has `item.contact_info` but checks are looking for `contacts.security_contact`
- There's a mismatch between the emit structure and check expectations

**Available in context**: `item`, `item.contact_info`
**Expected by checks**: `contacts.security_contact`, etc.

#### ⚠️ WARNING Group: No resources configured (3 warnings)

**Location**: All 3 `get_alternate_contact` calls

**Message**: ResourceNotFoundException

**Meaning**: 
- This AWS account has no alternate contacts configured
- This is expected behavior, not necessarily an error
- The YAML has `on_error: continue` which is correct

---

## Detailed Issue Breakdown

### accessanalyzer.yaml Issues

| Issue | Severity | Discovery/Check | Description |
|-------|----------|----------------|-------------|
| Invalid for_each template syntax | ERROR | aws.accessanalyzer.findings | Using {{ }} in for_each when it should be raw path |
| API validation failure | WARNING | aws.accessanalyzer.findings | Parameters not resolved correctly |

### account.yaml Issues

| Issue | Severity | Discovery/Check | Description |
|-------|----------|----------------|-------------|
| Template path mismatch | ERROR | aws.account.alternate_contacts | security_contact.AlternateContact not found in saved_data |
| Template path mismatch | ERROR | aws.account.alternate_contacts | billing_contact.AlternateContact not found |
| Template path mismatch | ERROR | aws.account.alternate_contacts | operations_contact.AlternateContact not found |
| Context variable mismatch | ERROR | Check 1 | contacts.security_contact not in context |
| Context variable mismatch | ERROR | Check 1 | contacts.billing_contact not in context |
| Context variable mismatch | ERROR | Check 1 | contacts.operations_contact not in context |
| Context variable mismatch | ERROR | Check 2 | contacts.security_contact not in context |
| Context variable mismatch | ERROR | Check 3 | contact.contact_information not in context |
| Context variable mismatch | ERROR | Check 3 | contact.contact_information.FullName not in context |
| Context variable mismatch | ERROR | Check 3 | contact.contact_information.PhoneNumber not in context |
| Context variable mismatch | ERROR | Check 4 | contacts.security_contact not in context |
| Context variable mismatch | ERROR | Check 4 | contacts.security_contact.Name not in context |
| Context variable mismatch | ERROR | Check 4 | contacts.security_contact.EmailAddress not in context |
| Context variable mismatch | ERROR | Check 4 | contacts.security_contact.PhoneNumber not in context |
| Context variable mismatch | ERROR | Check 5 | contacts.security_contact not in context |
| No alternate contacts | WARNING | get_alternate_contact (SECURITY) | ResourceNotFoundException |
| No alternate contacts | WARNING | get_alternate_contact (BILLING) | ResourceNotFoundException |
| No alternate contacts | WARNING | get_alternate_contact (OPERATIONS) | ResourceNotFoundException |

---

## Recommendations

### For accessanalyzer.yaml

1. **Fix the for_each syntax**:
   ```yaml
   # Current (WRONG)
   for_each: '{{ resource_list.analyzers[] }}'
   
   # Fixed (CORRECT)
   # Remove the for_each from discovery level and handle in calls
   ```

2. **Alternative approach**: Reference the discovery results differently in the engine

### For account.yaml

1. **Test with actual AWS account that HAS alternate contacts configured**
   - The validation shows the YAML logic is flawed
   - Need real data to validate the structure

2. **Fix the emit/check mismatch**:
   - Either fix the emit section to match what checks expect
   - Or fix the checks to match what emit produces

3. **Verify API response structure**:
   - Check what `get_alternate_contact` actually returns
   - Update template paths accordingly

4. **Consider the no-data case**:
   - Current YAML fails when no contacts exist
   - Need to handle this gracefully

---

## Action Items

### Immediate
- [ ] Fix accessanalyzer.yaml for_each syntax
- [ ] Get actual AWS API response for get_alternate_contact (success case)
- [ ] Fix account.yaml emit section based on real response structure
- [ ] Update check variable paths to match emitted data

### Long-term
- [ ] Run validator on all YAML files in services/
- [ ] Create test AWS account with resources configured for validation
- [ ] Add validation step to CI/CD pipeline
- [ ] Document common YAML patterns and anti-patterns

---

## How the Validator Helped

This validator **saved significant debugging time** by:

1. ✅ **Finding issues before runtime** - No need to run full scans
2. ✅ **Showing actual API responses** - Know what fields exist
3. ✅ **Providing specific error messages** - Clear path to fix
4. ✅ **Suggesting available fields** - Easy to correct paths
5. ✅ **Testing against real AWS** - Not theoretical validation

**Without this validator**: Would need to:
- Run full scan
- Parse engine logs
- Guess at field names
- Trial and error fixes
- Repeat many times

**With this validator**: 
- Instant feedback
- See real AWS responses
- Know exact issues
- Fix once correctly
