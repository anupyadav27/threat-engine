# Python Security Scanner v2

A comprehensive static analysis tool for Python code that detects security vulnerabilities, code quality issues, and best practice violations using Abstract Syntax Tree (AST) analysis.

## Overview

This Python scanner analyzes Python source code to identify:
- **Security vulnerabilities** (hardcoded secrets, weak cryptography, injection risks)
- **Code quality issues** (complexity, naming conventions, dead code)
- **Best practice violations** (exception handling, type hints, framework patterns)
- **Framework-specific issues** (Django, Flask, AWS, pandas, numpy, etc.)

## Features

- **300+ Rules**: Comprehensive rule set covering security, quality, and best practices
- **AST-based Analysis**: Deep understanding of Python code structure and semantics
- **Interactive Scanning**: Choose specific test files to analyze
- **Generic Rule Engine**: Rules defined in JSON metadata for easy customization
- **Detailed Reports**: JSON output with line numbers, descriptions, and remediation advice
- **Custom Logic Support**: Complex rule implementations for advanced pattern detection

## Quick Start

1. Navigate to the python_v2 directory:
   ```bash
   cd python_v2
   ```

2. Run the scanner:
   ```bash
   python python_scanner.py
   ```

3. Select a test file from the interactive menu

4. Review the generated JSON report

## Project Structure

```
python_v2/
├── python_scanner.py              # Main scanner entry point
├── python_generic_rule.py         # Generic rule engine for Python AST
├── python_generic_rule_enhanced.py # Enhanced rule engine features
├── logic_implementations.py       # Custom logic for complex rules
├── python_docs/                   # Rule metadata (300+ JSON files)
│   ├── *_metadata.json           # Individual rule definitions
├── test/                          # Test Python files with various patterns
│   ├── *.py                      # Test files to scan
│   └── *_report.json             # Generated scan reports
└── README.md                     # This file
```

## Core Components

### python_scanner.py
Main entry point that:
- Scans the test folder for Python files
- Provides interactive file selection
- Parses Python files into AST structures
- Loads and applies all rules
- Generates detailed JSON reports

### python_generic_rule.py
Generic rule engine that:
- Loads rule metadata from JSON files
- Traverses AST structures
- Applies rule logic and pattern matching
- Handles property path normalization
- Provides debug output

### logic_implementations.py
Custom implementations for complex rules including:
- AWS security patterns
- Django/Flask security checks
- Cryptography analysis
- Database security validation
- Network security patterns

### python_docs/
Contains 300+ rule metadata files covering:
- **Security**: Hardcoded credentials, weak crypto, injection risks
- **AWS**: Lambda, S3, IAM, CloudWatch best practices
- **Web Frameworks**: Django, Flask security patterns
- **Data Science**: pandas, numpy, scikit-learn best practices
- **Code Quality**: Complexity, naming, dead code detection
- **Testing**: unittest, pytest patterns and practices

## Rule Categories

### Security Rules (🔒)
- `credentials_should_not_be_hardcoded`
- `using_weak_hashing_algorithms_is_securitysensitive`
- `sql_injection_prevention_patterns`
- `aws_iam_policies_should_limit_scope`
- `server_certificates_should_be_verified`

### Code Quality Rules (📊)
- `functions_should_not_be_too_complex`
- `variables_should_follow_naming_conventions`
- `unused_imports_should_be_removed`
- `functions_should_not_have_too_many_parameters`
- `docstrings_should_be_defined`

### Framework Rules (🚀)
- `django_models_should_define_str_method`
- `flask_secret_keys_should_not_be_disclosed`
- `aws_lambda_handlers_should_clean_up_temp_files`
- `pandas_operations_should_be_optimized`
- `numpy_operations_should_be_vectorized`

## Usage Examples

### Basic Scanning
```bash
python python_scanner.py
# Select file interactively
# Review generated report
```

### Understanding Reports
The scanner generates JSON reports with this structure:
```json
{
  "scan_info": {
    "file": "test_file.py",
    "timestamp": "2025-10-08T10:30:00",
    "rules_applied": 156,
    "total_findings": 8
  },
  "findings": [
    {
      "rule_id": "hardcoded_secrets_are_securitysensitive",
      "title": "Hardcoded secrets are security-sensitive",
      "severity": "Critical",
      "line": 15,
      "column": 8,
      "message": "Make sure this hardcoded secret is not used in production.",
      "code_snippet": "password = 'admin123'",
      "remediation": "Use environment variables or secure secret management."
    }
  ]
}
```

## Rule Development

### Adding New Rules

1. Create a metadata JSON file in `python_docs/`:
```json
{
  "rule_id": "my_custom_rule",
  "title": "Custom Rule Title",
  "type": "CODE_SMELL",
  "defaultSeverity": "Major",
  "description": "Rule description",
  "message": "Issue message",
  "tags": ["security", "custom"],
  "logic": {
    "condition": "node_type == 'FunctionDef'",
    "check": "name.startswith('test_')"
  },
  "examples": {
    "compliant": ["def test_valid(): pass"],
    "noncompliant": ["def invalid_test(): pass"]
  }
}
```

2. For complex logic, add implementations to `logic_implementations.py`:
```python
def check_my_custom_rule(node):
    """Custom logic for my_custom_rule"""
    # Implementation here
    return violations
```

### Rule Metadata Structure

- **rule_id**: Unique identifier
- **title**: Human-readable name
- **type**: CODE_SMELL, BUG, VULNERABILITY, SECURITY_HOTSPOT
- **defaultSeverity**: Info, Minor, Major, Critical, Blocker
- **description**: Detailed explanation
- **message**: Issue message template
- **tags**: Categorization tags
- **logic**: Rule application logic
- **examples**: Compliant and non-compliant code examples

## Test Files

The `test/` directory contains various Python files demonstrating:
- Security vulnerabilities
- Code quality issues
- Framework-specific patterns
- Best practice violations

Each test file targets specific rules and generates corresponding reports.

## Performance

- **Processing Speed**: ~1000 lines/second
- **Memory Usage**: Scales with file size and AST complexity
- **Rule Evaluation**: Optimized pattern matching
- **Supported File Sizes**: Up to several MB per file

## Troubleshooting

### Common Issues

1. **Syntax Errors**: The scanner will report Python syntax errors before analysis
2. **Large Files**: May require more memory for very large Python files
3. **Complex AST**: Deeply nested code structures may slow processing

### Debug Output

Enable debug mode by modifying the scanner to see:
- AST structure details
- Rule application steps
- Pattern matching results
- Performance metrics

## Requirements

- **Python**: 3.8 or higher
- **Dependencies**: None (uses only standard library)
- **Memory**: 512MB+ recommended for large files
- **Storage**: ~50MB for rule metadata

## Contributing

1. Add test cases in the `test/` directory
2. Create rule metadata files in `python_docs/`
3. Implement custom logic in `logic_implementations.py`
4. Test with various Python code patterns
5. Update documentation

## Version History

- **v2.0**: Enhanced rule engine with improved AST analysis
- **v2.1**: Added framework-specific rules (Django, Flask, AWS)
- **v2.2**: Performance optimizations and custom logic support

---

*Python Security Scanner v2 - Professional static analysis for Python code*