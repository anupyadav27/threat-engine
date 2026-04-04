"""
Fix Generator — produces a concrete fix suggestion for a finding + matched rule.

Strategy:
  1. Read the offending line from the cloned repo (if available).
  2. Use the rule's compliant example as the fix template.
  3. Attempt a smart substitution: replace the hardcoded value/pattern
     with the recommended safe pattern (e.g. env var reference).
  4. Set can_auto_patch=True when we are confident the line can be
     rewritten automatically; False when only guidance is provided.
"""

import os
import re
import logging
from typing import Optional

from ..models.finding import SecOpsFinding
from ..models.fix_result import FixResult

logger = logging.getLogger(__name__)

# Language → env-var accessor template
_ENV_TEMPLATES = {
    "python":        'os.getenv("{var_name}")',
    "javascript":    'process.env.{var_name}',
    "typescript":    'process.env.{var_name}',
    "java":          'System.getenv("{var_name}")',
    "go":            'os.Getenv("{var_name}")',
    "ruby":          'ENV["{var_name}"]',
    "csharp":        'Environment.GetEnvironmentVariable("{var_name}")',
    "terraform":     'var.{var_name}',
    "docker":        '${var_name}',
    "kubernetes":    'valueFrom:\n              secretKeyRef:\n                name: <secret-name>\n                key: {var_name}',
}

_DEFAULT_ENV_TEMPLATE = 'ENV["{var_name}"]'


def generate(
    finding: SecOpsFinding,
    rule: dict,
    match_layer: str,
    repo_local_path: Optional[str] = None,
) -> FixResult:
    """
    Generate a FixResult for a finding using the matched rule.

    Args:
        finding: The secops finding.
        rule: Matched rule dict from secrets_docs.
        match_layer: Which matching layer found this rule.
        repo_local_path: Local path of cloned repo (to read original line).
    """
    # Read the offending line if we have the repo locally
    original_code = _read_line(repo_local_path, finding.file_path, finding.line_number)

    # Extract compliant example from rule
    compliant_example = _pick_compliant_example(rule, finding.language)

    # Build suggested fix
    suggested_fix, can_auto_patch = _build_fix(
        original_code, rule, finding.language, finding.rule_id
    )

    # Build explanation
    fix_explanation = _build_explanation(rule, finding)

    return FixResult(
        finding_id=finding.id,
        secops_scan_id=finding.secops_scan_id,
        rule_id=finding.rule_id,
        matched_rule_id=rule.get("rule_id"),
        match_layer=match_layer,
        file_path=finding.file_path,
        line_number=finding.line_number,
        language=finding.language,
        severity=finding.severity,
        original_code=original_code,
        suggested_fix=suggested_fix,
        fix_explanation=fix_explanation,
        compliant_example=compliant_example,
        references=rule.get("references"),
        can_auto_patch=can_auto_patch,
    )


def generate_unmatched(finding: SecOpsFinding) -> FixResult:
    """Produce a minimal FixResult for a finding with no rule match."""
    return FixResult(
        finding_id=finding.id,
        secops_scan_id=finding.secops_scan_id,
        rule_id=finding.rule_id,
        matched_rule_id=None,
        match_layer="unmatched",
        file_path=finding.file_path,
        line_number=finding.line_number,
        language=finding.language,
        severity=finding.severity,
        original_code=None,
        suggested_fix=None,
        fix_explanation=(
            f"No fix rule matched for rule_id='{finding.rule_id}'. "
            "Review the finding manually and replace any hardcoded secret "
            "with an environment variable or secrets manager reference."
        ),
        compliant_example=None,
        references=None,
        can_auto_patch=False,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_line(
    repo_path: Optional[str],
    file_path: Optional[str],
    line_number: Optional[int],
) -> Optional[str]:
    if not all([repo_path, file_path, line_number]):
        return None
    full_path = os.path.join(repo_path, file_path.lstrip("/"))
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        idx = line_number - 1
        if 0 <= idx < len(lines):
            return lines[idx].rstrip("\n")
    except Exception as e:
        logger.debug(f"Could not read {full_path}: {e}")
    return None


def _pick_compliant_example(rule: dict, language: Optional[str]) -> Optional[str]:
    """Return the most relevant compliant example for the language."""
    examples = (rule.get("examples") or {}).get("compliant") or []
    if not examples:
        return None
    if not language:
        return examples[0]
    lang = language.lower()
    # Try to find an example that looks like the target language
    for ex in examples:
        ex_lower = ex.lower()
        if lang == "python" and ("os.getenv" in ex_lower or "os.environ" in ex_lower):
            return ex
        if lang in ("javascript", "typescript") and "process.env" in ex_lower:
            return ex
        if lang == "go" and "os.getenv" in ex_lower:
            return ex
        if lang == "java" and "system.getenv" in ex_lower:
            return ex
        if lang == "ruby" and "env[" in ex_lower:
            return ex
    return examples[0]


def _build_fix(
    original_code: Optional[str],
    rule: dict,
    language: Optional[str],
    rule_id: Optional[str],
) -> tuple:
    """
    Attempt to rewrite the offending line.

    Returns:
        (suggested_fix: str, can_auto_patch: bool)
    """
    if not original_code:
        # No source available — return guidance only
        compliant = _pick_compliant_example(rule, language)
        return compliant, False

    lang = (language or "").lower()
    env_template = _ENV_TEMPLATES.get(lang, _DEFAULT_ENV_TEMPLATE)

    # Derive a sensible env var name from the rule_id or the variable in the line
    var_name = _infer_var_name(original_code, rule_id)
    env_ref = env_template.format(var_name=var_name)

    # Find the assignment operator and replace the RHS value
    # Pattern: identifier = 'value'  OR  identifier: 'value'
    assignment_pattern = r"""(=\s*|:\s*)(['"][^'"]{8,}['"])"""
    match = re.search(assignment_pattern, original_code)
    if match:
        suggested = original_code[:match.start(2)] + env_ref + original_code[match.end(2):]
        return suggested, True

    # Could not auto-rewrite — return compliant example as guidance
    compliant = _pick_compliant_example(rule, language)
    return compliant or env_ref, False


def _infer_var_name(code_line: str, rule_id: Optional[str]) -> str:
    """
    Infer a sensible environment variable name from the code line or rule_id.
    """
    # Try to extract the variable name from the LHS of the assignment
    lhs_match = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]', code_line)
    if lhs_match:
        return lhs_match.group(1).upper()
    # Fall back to rule_id derived name
    if rule_id:
        parts = rule_id.split(".")
        base = parts[-1] if parts else rule_id
        return re.sub(r"[^A-Z0-9_]", "_", base.upper())
    return "SECRET_VALUE"


def _build_explanation(rule: dict, finding: SecOpsFinding) -> str:
    parts = []
    title = rule.get("title") or finding.rule_id or "Secret exposure"
    parts.append(f"Issue: {title}.")

    description = rule.get("description") or ""
    if description:
        # Take first two sentences max
        sentences = re.split(r'(?<=[.!?])\s+', description.strip())
        parts.append(" ".join(sentences[:2]))

    recommendation = rule.get("recommendation") or rule.get("remediation") or ""
    if recommendation:
        parts.append(f"Fix: {recommendation}")

    impact = rule.get("impact") or ""
    if impact:
        parts.append(f"Impact: {impact}")

    refs = rule.get("references") or []
    if refs:
        parts.append(f"Reference: {refs[0]}")

    return "\n".join(parts)
