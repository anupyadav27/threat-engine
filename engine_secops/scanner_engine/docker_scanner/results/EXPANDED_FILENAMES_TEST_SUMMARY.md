# Expanded Filenames Should Not Become Options - Test Summary

## Rule Information
- **Rule ID**: `expanded_filenames_become_options`
- **Title**: Expanded filenames should not become options
- **Severity**: Info
- **Category**: General (Code Smell)
- **Status**: ✅ Implemented and Tested

## Rule Description
Filename and pathname should be prefixed to avoid missing filenames starting with a dash when globbing files as program option.

Within shell commands, arguments and filenames as options are passed as strings. Programs may misinterpret files as arguments if the file name starts with a single or double dash. When filenames are specified using glob patterns (like `*.txt`), files whose names begin with a dash (like `-file.txt`) may be misinterpreted as command options instead of filenames.

## Implementation

### Logic Configuration
The rule is implemented in [`expanded_filenames_should_not_become_options_metadata.json`](../docker_docs/expanded_filenames_should_not_become_options_metadata.json) with the following logic:

```json
{
  "instruction_types": ["RUN", "CMD", "ENTRYPOINT"],
  "checks": [{
    "type": "regex_match",
    "property_path": ["value"],
    "patterns": [
      "\\b(rm|cat|ls|cp|mv|grep|chmod|chown|find|xargs|sed|awk|tar|zip|unzip)\\s+[^-./][^\\s]*\\*",
      "\\b(rm|cat|ls|cp|mv|grep|chmod|chown|find|xargs|sed|awk|tar|zip|unzip)\\s+\\*",
      "\\b(for|while)\\s+\\w+\\s+in\\s+\\*[^/]"
    ]
  }]
}
```

The patterns detect:
1. Common file manipulation commands followed by glob patterns without `./` prefix
2. Loop constructs (for/while) that iterate over unprotected glob patterns

## Test Results

### Test File
- **Location**: [`docker_tests/Dockerfile.expanded_filenames`](../docker_tests/Dockerfile.expanded_filenames)
- **Purpose**: Comprehensive test with 33 examples (noncompliant, compliant, and edge cases)

### Scan Results
- **Total Issues Found**: 23 violations across all rules
- **Rule-Specific Violations**: **13 violations** of `expanded_filenames_become_options`
- **Results File**: [`results/expanded_filenames_test_results.json`](../results/expanded_filenames_test_results.json)

### Violations Detected

| Line | Instruction | Code | Status |
|------|-------------|------|--------|
| 12 | RUN | `rm *.tmp` | ❌ Noncompliant |
| 16 | RUN | `cat *.log` | ❌ Noncompliant |
| 19 | RUN | `ls *.txt` | ❌ Noncompliant |
| 22 | RUN | `cp *.conf /etc/` | ❌ Noncompliant |
| 25 | RUN | `mv *.bak /backup/` | ❌ Noncompliant |
| 43 | RUN | `for file in *.txt; do echo $file; done` | ❌ Noncompliant |
| 46 | RUN | `rm *.log *.tmp *.bak` | ❌ Noncompliant |
| 49 | RUN | `cp data/*.csv /output/` | ❌ Noncompliant |
| 55 | RUN | `zip archive.zip *.doc` | ❌ Noncompliant |
| 83 | RUN | `cp data/./*.csv /output/` | ❌ Noncompliant |
| 98 | CMD | `["sh", "-c", "rm *.tmp"]` | ❌ Noncompliant |
| 101 | ENTRYPOINT | `["sh", "-c", "cat *.log"]` | ❌ Noncompliant |
| 108 | RUN | `ls ./*.txt && rm *.tmp` | ❌ Noncompliant (mixed) |

### Compliant Examples (Not Flagged)
The following patterns were correctly **NOT** flagged as violations:

- ✅ `RUN rm ./*.tmp` - Glob with `./` prefix
- ✅ `RUN cat ./*.log` - Glob with `./` prefix
- ✅ `RUN ls ./*.txt` - Glob with `./` prefix
- ✅ `RUN rm /tmp/*.log` - Absolute path
- ✅ `RUN rm -- *.tmp` - Using `--` separator
- ✅ `RUN rm file1.tmp file2.tmp` - Specific files without glob

## Why This Matters

### The Problem
Consider a file named `-rf` in your directory:
```bash
$ touch -- -rf
$ rm *.txt  # May interpret -rf as a flag!
```

This could lead to:
- Files being ignored during operations
- Unintended command behavior
- Security vulnerabilities

### The Solution
Prefix glob patterns with `./`:
```bash
$ rm ./*.txt  # Safely processes all files including -rf.txt
```

## Recommendations

### ❌ Noncompliant Code
```dockerfile
RUN rm *.tmp
RUN cat *.log
RUN cp *.conf /etc/
RUN for file in *.txt; do process $file; done
```

### ✅ Compliant Code
```dockerfile
RUN rm ./*.tmp
RUN cat ./*.log
RUN cp ./*.conf /etc/
RUN for file in ./*.txt; do process "$file"; done

# Or use -- to separate options from arguments
RUN rm -- *.tmp

# Or use absolute paths
RUN rm /tmp/*.log
```

## Related Rules
- `double_quote_prevent_globbing` - Ensures variables are quoted to prevent globbing issues
- `prefer_exec_form` - Recommends exec form for CMD/ENTRYPOINT to avoid shell interpretation

## References
- [SonarSource Docker Rule RSPEC-6573](https://rules.sonarsource.com/docker/RSPEC-6573)
- [ShellCheck SC2035](https://www.shellcheck.net/wiki/SC2035) - Similar shell script check

## Test Execution

To run the test:
```bash
python test_expanded_filenames.py
```

To scan a specific Dockerfile:
```bash
python docker_scanner.py docker_tests/Dockerfile.expanded_filenames json
```

## Conclusion
✅ **Rule successfully implemented and tested**
- Logic correctly detects unprotected glob patterns
- Test file covers comprehensive scenarios
- Results saved to `results/expanded_filenames_test_results.json`
- 13 violations correctly identified
- Compliant patterns correctly excluded
