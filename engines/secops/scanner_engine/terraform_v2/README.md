# Terraform Security Scanner

This project is a Python-based static analysis tool for scanning Terraform configurations for security and best-practice violations. It supports both per-file and merged project scanning, with robust rule logic and debug output.

## Project Structure

- **scanner_common.py**: Main entry point. Handles input (file/folder), shared helpers (parsing, rule loading, metadata), and delegates scanning to the appropriate mode (per-file or merged project). All common logic is here.
- **scanner_file.py**: Contains logic for per-file scanning. Imports shared helpers from `scanner_common.py`. Scans each `.tf` file independently and applies rules.
- **scanner_project.py**: Contains logic for merged/folder scanning. Imports shared helpers from `scanner_common.py`. Merges all `.tf` files into a single AST, builds symbol tables, resolves references, and applies rules across the project.
- **generic_rule.py**: Defines the `GenericRule` class, which implements rule logic, property path normalization, and debug output. All rule checks are performed through this class.
- **terraform_docs1/**: Contains rule metadata JSON files. Each file describes a rule, its logic, and examples.
- **test/**: Contains test Terraform configurations and expected scan reports. Each subfolder (e.g., `git1`, `git2`) is a separate test case.

## Code Flow

1. **Entry Point**: Run `scanner_common.py`. It prompts for scan mode (per-file or merged project) and input path (file or folder).
2. **Input Handling**: `scanner_common.py` collects all `.tf` files from the input path and loads rule metadata from `terraform_docs1/`.
3. **Delegation**:
   - **Per-file mode**: Calls `scanner_file.py` to scan each file independently.
   - **Merged project mode**: Calls `scanner_project.py` to merge all files, build symbol tables, resolve references, and scan as a whole.
4. **Rule Application**: For each resource/property, rules are applied using the `GenericRule` class. Debug output is printed for each check.
5. **Reporting**: Findings are collected and written to a report JSON file in the relevant test folder.

## Adding Rules
- Add a new metadata JSON file to `terraform_docs1/` describing the rule logic and examples.
- The engine will automatically load and apply all rules found in this folder.

## Testing
- Add a new subfolder to `test/` with `.tf` files to trigger specific rules.
- Run the scanner and review the generated report JSON for expected findings.

## Example Usage
```sh
python scanner_common.py
```
Follow the prompts to select scan mode and input path.

---

For more details, review the code and comments in each script. The project is designed for extensibility and easy debugging.
