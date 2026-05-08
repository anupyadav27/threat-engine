"""
rule_evaluator.py — Evaluates check rules against discovery results.

Reads the ``assertion`` block from each check rule YAML and evaluates it
against the corresponding discovery result dict.  Returns a list of finding
dicts with PASS/FAIL status and evidence.

Supported operators:
    eq, ne, in, not_in, contains, not_contains, exists, gt, gte, lt, lte
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _finding_id(rule_id: str, resource_uid: str, scan_run_id: str) -> str:
    """Generate a 16-char hex finding ID.

    Args:
        rule_id: The rule identifier string.
        resource_uid: Unique resource identifier.
        scan_run_id: The pipeline scan run UUID.

    Returns:
        First 16 hex chars of sha256(rule_id|resource_uid|scan_run_id).
    """
    raw = f"{rule_id}|{resource_uid}|{scan_run_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _evaluate_assertion(
    assertion: Dict[str, Any],
    result: Dict[str, Any],
) -> tuple[str, Dict[str, Any]]:
    """Apply one assertion dict against a discovery result dict.

    Args:
        assertion: Dict with keys ``operator``, ``expected``, and a field key.
            The assertion may use ``field``, ``key``, or ``expected_key`` to
            identify which key in *result* to check.
        result: The raw discovery result dict for this entry.

    Returns:
        Tuple of (status, evidence) where status is ``PASS``, ``FAIL``,
        or ``ERROR``.
    """
    operator = (
        assertion.get("operator")
        or assertion.get("op")
        or "eq"
    ).lower()

    # Support multiple field key names across rule YAML variants
    field_key = (
        assertion.get("field")
        or assertion.get("key")
        or assertion.get("expected_key")
        or ""
    )
    expected = assertion.get("expected")
    actual = result.get(field_key) if field_key else None

    evidence: Dict[str, Any] = {
        "field": field_key,
        "expected": expected,
        "actual": actual,
        "operator": operator,
    }

    status = _apply_operator(operator, actual, expected)
    return status, evidence


def _apply_operator(operator: str, actual: Any, expected: Any) -> str:
    """Apply a comparison operator and return PASS, FAIL, or ERROR.

    Args:
        operator: One of eq, ne, in, not_in, contains, not_contains,
            exists, gt, gte, lt, lte.
        actual: The actual value from discovery results.
        expected: The expected value from the rule assertion.

    Returns:
        ``PASS``, ``FAIL``, or ``ERROR``.
    """
    try:
        if operator in ("eq", "equals"):
            return "PASS" if str(actual) == str(expected) else "FAIL"
        if operator in ("ne", "not_equals"):
            return "PASS" if str(actual) != str(expected) else "FAIL"
        if operator == "in":
            return "PASS" if actual in (expected or []) else "FAIL"
        if operator == "not_in":
            return "PASS" if actual not in (expected or []) else "FAIL"
        if operator == "contains":
            return "PASS" if expected and str(expected) in str(actual or "") else "FAIL"
        if operator == "not_contains":
            return "PASS" if not (expected and str(expected) in str(actual or "")) else "FAIL"
        if operator == "exists":
            return "PASS" if actual is not None else "FAIL"
        if operator == "gt":
            return "PASS" if float(actual) > float(expected) else "FAIL"
        if operator == "gte":
            return "PASS" if float(actual) >= float(expected) else "FAIL"
        if operator == "lt":
            return "PASS" if float(actual) < float(expected) else "FAIL"
        if operator == "lte":
            return "PASS" if float(actual) <= float(expected) else "FAIL"
    except (TypeError, ValueError) as exc:
        logger.debug("Operator %s failed numeric comparison: %s", operator, exc)
        return "ERROR"

    logger.warning("Unknown operator: %s — defaulting to FAIL", operator)
    return "FAIL"


def _rule_id_to_discovery_id(rule_id: str) -> str:
    """Convert a check rule_id to its corresponding discovery_id.

    Rule IDs follow ``{tech}.cis.{section}.{slug}``.
    Discovery IDs follow ``{tech}.section_{section}.{slug}``.

    Args:
        rule_id: Check rule identifier string.

    Returns:
        Corresponding discovery_id string, or the original rule_id on mismatch.
    """
    parts = rule_id.split(".")
    # Expected: [tech, "cis", section, *slug_parts]
    if len(parts) >= 4 and parts[1] == "cis":
        tech    = parts[0]
        section = parts[2]
        slug    = ".".join(parts[3:])
        return f"{tech}.section_{section}.{slug}"
    return rule_id


class RuleEvaluator:
    """Evaluates check rules against a discovery result map.

    Args:
        scan_run_id: The pipeline scan run UUID (used in finding_id).
        account_id: Account/host identifier (used in resource_uid).
        tech_type: Technology type string, e.g. ``postgresql``.
    """

    def __init__(
        self,
        scan_run_id: str,
        account_id: str,
        tech_type: str,
    ) -> None:
        self._scan_run_id = scan_run_id
        self._account_id = account_id
        self._tech_type = tech_type

    def evaluate(
        self,
        check_rules: List[Dict[str, Any]],
        discovery_results: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Evaluate all check rules against discovery results.

        Each rule is matched to a discovery result by its ``scope`` field,
        which should correspond to a ``discovery_id`` key in *discovery_results*.
        When no matching result is found the rule is evaluated against an empty
        dict (will typically produce FAIL or ERROR).

        Args:
            check_rules: List of rule dicts from the catalog.
            discovery_results: Map of discovery_id -> result dict from
                LocalExecutor.run().

        Returns:
            List of finding dicts ready to push to the central server.
        """
        findings: List[Dict[str, Any]] = []

        for rule in check_rules:
            finding = self._evaluate_rule(rule, discovery_results)
            if finding:
                findings.append(finding)

        logger.info(
            "Evaluated %d rules → %d findings (%d PASS, %d FAIL, %d ERROR)",
            len(check_rules),
            len(findings),
            sum(1 for f in findings if f["status"] == "PASS"),
            sum(1 for f in findings if f["status"] == "FAIL"),
            sum(1 for f in findings if f["status"] == "ERROR"),
        )
        return findings

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        discovery_results: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Evaluate one rule and return a finding dict.

        Args:
            rule: Rule dict from the catalog.
            discovery_results: Full discovery results map.

        Returns:
            Finding dict or ``None`` when the rule has no rule_id.
        """
        rule_id = rule.get("rule_id", "")
        if not rule_id:
            return None

        # Derive discovery_id from rule_id: {tech}.cis.{section}.{slug}
        # → {tech}.section_{section}.{slug}
        scope = rule.get("scope", "") or _rule_id_to_discovery_id(rule_id)
        result = discovery_results.get(scope) or {}

        # Build resource_uid
        resource_uid = f"{self._account_id}.{self._tech_type}.{scope or rule_id}"

        assertion = rule.get("assertion") or {}
        if assertion:
            status, evidence = _evaluate_assertion(assertion, result)
        else:
            # No assertion configured — discovery-only rule, mark PASS
            status, evidence = "PASS", {"raw": result}

        fid = _finding_id(rule_id, resource_uid, self._scan_run_id)

        return {
            "finding_id": fid,
            "rule_id": rule_id,
            "rule_title": rule.get("title", ""),
            "status": status,
            "severity": rule.get("severity", "medium"),
            "evidence": evidence,
            "resource_uid": resource_uid,
            "resource_type": self._tech_type,
            "remediation": rule.get("remediation", ""),
            "cis_benchmark": rule.get("cis_benchmark", ""),
        }
