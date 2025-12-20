# Root Cause Analysis: "Unknown" Errors

## Problem Statement

41 services showing "unknown" errors that should not occur since:
- Agent 1 generates requirements with boto3 equivalents
- Agent 4 generates YAML from validated boto3 SDK JSON
- YAML structure should be correct

## Actual Root Cause

**The issue is NOT YAML structure, boto3 mapping, or field names.**

### Real Problem: Python Module Import Error

All "unknown" errors are actually:
```
ModuleNotFoundError: No module named 'aws_compliance_python_engine'
```

This happens when Agent 5 tries to run the engine. The engine fails to start due to Python import path issues, not YAML problems.

### Evidence

1. **Error Pattern**: All failed services show only "Traceback (most recent call last):" with no details
2. **Actual Error**: When running engine manually, we see:
   ```
   ModuleNotFoundError: No module named 'aws_compliance_python_engine'
   ```
3. **YAML Validation**: YAML files are valid and properly structured
4. **Agent 5 Issue**: Only captures first line of traceback, missing actual error

## Technical Details

### Agent 5 Command
```python
cmd = f'PYTHONPATH=/Users/apple/Desktop/threat-engine python3 engine/main_scanner.py --service {service} ...'
cwd='/Users/apple/Desktop/threat-engine/aws_compliance_python_engine'
```

### Engine Import Issue
The engine code uses absolute imports:
```python
from aws_compliance_python_engine.utils.exception_manager import ...
```

But when running from `aws_compliance_python_engine/` directory with `PYTHONPATH=/Users/apple/Desktop/threat-engine`, Python can't resolve the module path correctly.

## Impact

- **41 services** incorrectly marked as "unknown" errors
- **Actual issue**: Python environment/module path, not YAML
- **Agent 6** can't categorize errors because it only sees "Traceback" line
- **Agent 7** can't fix because there's nothing wrong with YAML

## Solutions

### Option 1: Fix Python Import Path (Recommended)
Update Agent 5 to properly set PYTHONPATH and run from correct directory:
```python
# Run from threat-engine root, not aws_compliance_python_engine
cmd = f'cd /Users/apple/Desktop/threat-engine && PYTHONPATH=/Users/apple/Desktop/threat-engine python3 -m aws_compliance_python_engine.engine.main_scanner --service {service} ...'
```

### Option 2: Fix Engine Imports
Change engine code to use relative imports or fix module structure.

### Option 3: Improve Error Capture
Update Agent 5 to capture full traceback, not just first line:
```python
# Capture full traceback
if 'Traceback' in line:
    # Capture next 20 lines for full error
    traceback_lines = [line]
    # ... capture full stack trace
```

## Next Steps

1. **Fix Agent 5** to capture full error details
2. **Fix Python import path** in engine command
3. **Re-test** to get actual errors (likely will be different issues)
4. **Update Agent 6** to properly categorize Python import errors vs YAML errors

## Conclusion

The "unknown" errors are a **false positive** caused by:
1. Python module import failure (not YAML issues)
2. Incomplete error capture in Agent 5 (only first line)
3. Agent 6 can't categorize without full error details

**The YAML files are likely correct** - we just can't test them because the engine won't start due to Python environment issues.
