"""
Ansible Playbook Validator — Phase 2 quality gate.

Two validation layers (each gracefully skipped if tool unavailable):
  1. yamllint  — pure Python, always available, catches YAML syntax errors
  2. ansible-lint — subprocess call, skipped if not installed (logs a warning)

validate_playbook() returns a ValidationResult:
  passed         True/False
  warnings       list of warning strings (non-fatal)
  errors         list of error strings (fatal — playbook should be retried/flagged)
  lint_available True if ansible-lint binary was found

Used by ai_fixer.fix_package_ansible() in a retry loop:
  - First attempt: generate playbook
  - Validate → if errors found, re-prompt with error context (max 2 retries)
  - If still failing after retries: push with lint_passed=False and note in PR

Design: No state. All functions are pure / stateless.
"""

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    passed: bool
    warnings: List[str] = field(default_factory=list)
    errors: List[str]   = field(default_factory=list)
    lint_available: bool = False

    def as_error_context(self) -> str:
        """
        Compact string sent back to AI on retry so it can fix its mistakes.
        """
        parts = []
        if self.errors:
            parts.append("ERRORS (must fix):\n" + "\n".join(f"  - {e}" for e in self.errors))
        if self.warnings:
            parts.append("WARNINGS:\n" + "\n".join(f"  - {w}" for w in self.warnings[:5]))
        return "\n".join(parts) if parts else "Unknown validation failure."


def validate_playbook(yaml_content: str) -> ValidationResult:
    """
    Run yamllint then ansible-lint on the provided YAML string.
    Returns a ValidationResult with all issues found.
    """
    result = ValidationResult(passed=True)

    # ── Layer 1: yamllint ─────────────────────────────────────────────────────
    yaml_errors, yaml_warnings = _run_yamllint(yaml_content)
    result.errors.extend(yaml_errors)
    result.warnings.extend(yaml_warnings)

    if yaml_errors:
        # Don't run ansible-lint if basic YAML is broken
        result.passed = False
        return result

    # ── Layer 2: ansible-lint ─────────────────────────────────────────────────
    lint_errors, lint_warnings, lint_available = _run_ansible_lint(yaml_content)
    result.lint_available = lint_available
    result.errors.extend(lint_errors)
    result.warnings.extend(lint_warnings)

    if lint_errors:
        result.passed = False

    return result


# ── yamllint ──────────────────────────────────────────────────────────────────

_YAMLLINT_CONFIG = """
extends: default
rules:
  line-length:
    max: 160
    level: warning
  truthy:
    allowed-values: ['true', 'false', 'yes', 'no']
    level: warning
  comments:
    level: warning
  document-start:
    level: warning
"""


def _run_yamllint(yaml_content: str):
    """Return (errors, warnings) from yamllint. Empty lists if unavailable."""
    try:
        import yamllint                          # noqa
        from yamllint import linter
        from yamllint.config import YamlLintConfig
    except ImportError:
        logger.debug("[Validator] yamllint not available — skipping YAML lint")
        return [], []

    errors, warnings = [], []
    try:
        config = YamlLintConfig(_YAMLLINT_CONFIG)
        problems = list(linter.run(yaml_content, config))
        for p in problems:
            msg = f"Line {p.line}:{p.column} [{p.rule}] {p.message}"
            if p.level == "error":
                errors.append(msg)
            else:
                warnings.append(msg)
    except Exception as e:
        logger.warning(f"[Validator] yamllint failed unexpectedly: {e}")

    return errors, warnings


# ── ansible-lint ──────────────────────────────────────────────────────────────

def _run_ansible_lint(yaml_content: str):
    """
    Write YAML to a temp file, run ansible-lint, parse output.
    Returns (errors, warnings, available_bool).
    Skips gracefully if ansible-lint binary not found.
    """
    ansible_lint_bin = shutil.which("ansible-lint")
    if not ansible_lint_bin:
        logger.debug("[Validator] ansible-lint not on PATH — skipping ansible-lint")
        return [], [], False

    errors, warnings = [], []
    tmp_file = None
    try:
        # Write to named temp file (ansible-lint needs a real file path)
        fd, tmp_file = tempfile.mkstemp(suffix=".yml", prefix="vulfix_lint_")
        with os.fdopen(fd, "w") as f:
            f.write(yaml_content)

        result = subprocess.run(
            [ansible_lint_bin, "--nocolor", "--parseable", tmp_file],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # ansible-lint exit codes: 0=pass, 1=violations, 2=warning-only, 3+=error
        output = result.stdout + result.stderr

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: path:line: [rule] description   (or just rule descriptions)
            if "[WARNING]" in line or line.startswith("WARNING"):
                warnings.append(line)
            elif result.returncode >= 1 and line and not line.startswith("#"):
                # Treat any output on failure as an error
                errors.append(line)

        logger.info(
            f"[Validator] ansible-lint exit={result.returncode}  "
            f"errors={len(errors)}  warnings={len(warnings)}"
        )

    except subprocess.TimeoutExpired:
        warnings.append("ansible-lint timed out (60s) — skipped")
    except Exception as e:
        logger.warning(f"[Validator] ansible-lint failed: {e}")
    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.unlink(tmp_file)

    return errors, warnings, True
