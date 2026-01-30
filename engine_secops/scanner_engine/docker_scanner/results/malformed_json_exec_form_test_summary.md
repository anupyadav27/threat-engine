# Malformed JSON Exec Form Rule - Test Results

## Overview
This document summarizes the testing of the `malformed_json_exec_form` rule which detects malformed JSON syntax in Docker exec form commands (RUN, CMD, ENTRYPOINT).

## Rule Implementation

### Metadata File
- **Location**: `docker_docs/malformed_json_in_exec_form_leads_to_unexpected_be_metadata.json`
- **Rule ID**: `malformed_json_exec_form`
- **Severity**: Info
- **Category**: Reliability

### Logic
The rule uses generic regex checks to detect common malformed JSON patterns:
- **Checks**: RUN, CMD, ENTRYPOINT instructions
- **Patterns Detected**:
  1. `^\s*\['` - Single quotes instead of double quotes: `['cmd']`
  2. `^\s*\[[a-zA-Z]` - Missing quotes around elements: `[cmd, arg]`
  3. `^\s*\[.*,\s*\]` - Trailing commas: `["cmd",]`

### Implementation Details
```json
{
  "instruction_types": ["RUN", "CMD", "ENTRYPOINT"],
  "checks": [
    {
      "type": "regex_match",
      "property_path": ["value"],
      "patterns": [
        "^\\s*\\['",
        "^\\s*\\[[a-zA-Z]",
        "^\\s*\\[.*,\\s*\\]"
      ],
      "message": "Malformed JSON in exec form..."
    }
  ]
}
```

## Test File
**Location**: `docker_tests/Dockerfile.malformed_json`

### Test Cases Included

#### Noncompliant Examples (Should Trigger):
1. **Line 7**: `RUN ['apt-get', 'update']` - Single quotes
2. **Line 10**: `CMD [node, app.js]` - Missing quotes
3. **Line 13**: `ENTRYPOINT ['python', 'main.py']` - Single quotes
4. **Line 16**: `RUN ["apt-get", "install", "curl",]` - Trailing comma
5. **Line 19**: `CMD ['npm', "start"]` - Mixed quotes
6. **Line 22**: `RUN [echo, hello]` - No quotes
7. **Line 31**: `ENTRYPOINT ['sh', '-c', 'echo hello']` - Single quotes

#### Compliant Examples (Should Not Trigger):
- **Line 25**: `CMD ["python", "app.py"]` - Proper JSON format ✓
- **Line 28**: `RUN apt-get update && apt-get install -y curl` - Shell form ✓

## Test Results

### Scan Summary
- **File Scanned**: `docker_tests/Dockerfile.malformed_json`
- **Total Violations Found**: 17 (across all rules)
- **Malformed JSON Violations**: 7
- **Results File**: `results/Dockerfile_malformed_json_vulnerabilities.json`

### Violations Detected
All 7 malformed JSON patterns were successfully detected:

| Line | Instruction | Issue | Example | Status |
|------|-------------|-------|---------|--------|
| 7    | RUN         | Single quotes | `['apt-get', 'update']` | ✓ Detected |
| 10   | CMD         | Missing quotes | `[node, app.js]` | ✓ Detected |
| 13   | ENTRYPOINT  | Single quotes | `['python', 'main.py']` | ✓ Detected |
| 16   | RUN         | Trailing comma | `["curl",]` | ✓ Detected |
| 19   | CMD         | Mixed quotes | `['npm', "start"]` | ✓ Detected |
| 22   | RUN         | No quotes | `[echo, hello]` | ✓ Detected |
| 31   | ENTRYPOINT  | Single quotes | `['sh', '-c', 'echo']` | ✓ Detected |

### Compliant Cases (Correctly Not Flagged)
- Line 25: Valid JSON with double quotes - **No violation** ✓
- Line 28: Shell form (not exec form) - **No violation** ✓

## Why This Matters

When Docker encounters malformed JSON in exec form:
1. It **silently falls back to shell form** without warning
2. This changes the execution behavior (no shell → shell with `/bin/sh -c`)
3. Can lead to:
   - Unexpected signal handling
   - Different variable expansion
   - Security implications (shell injection risks)
   - Debugging confusion

### Example Impact:
```dockerfile
# Intended: Direct execution (no shell)
CMD ['node', 'app.js']

# Actual: Executed as shell form
CMD /bin/sh -c "['node', 'app.js']"  # Will fail!
```

## Running the Test

To test this rule yourself:

```bash
# Using the vulnerability scanner with filter
python docker_vulnerability_scanner.py Dockerfile.malformed_json --filter=malformed_json_exec_form

# Or scan directly
python docker_scanner.py docker_tests/Dockerfile.malformed_json json
```

## Common Mistakes Detected

### 1. Single Quotes (Most Common)
❌ **Wrong**: `CMD ['python', 'app.py']`  
✅ **Correct**: `CMD ["python", "app.py"]`

### 2. Missing Quotes
❌ **Wrong**: `CMD [node, app.js]`  
✅ **Correct**: `CMD ["node", "app.js"]`

### 3. Trailing Commas
❌ **Wrong**: `RUN ["apt-get", "install",]`  
✅ **Correct**: `RUN ["apt-get", "install"]`

### 4. Mixed Quotes
❌ **Wrong**: `CMD ['npm', "start"]`  
✅ **Correct**: `CMD ["npm", "start"]`

## Conclusion

✅ **Rule Successfully Implemented and Tested**

The `malformed_json_exec_form` rule is working correctly and detects the most common malformed JSON patterns in Docker exec form commands. The rule:
- Covers RUN, CMD, and ENTRYPOINT instructions
- Detects single quotes, missing quotes, and trailing commas
- Provides clear, actionable error messages
- Correctly ignores valid JSON and shell form commands
- Achieves 100% detection rate on test cases (7/7)

This rule helps prevent silent failures and unexpected behavior by catching JSON syntax errors that Docker would otherwise silently convert to shell form.
