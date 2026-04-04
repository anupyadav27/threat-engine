"""
Rule Matcher — 3-layer enterprise matching strategy.

Layer 1 — Exact rule_id match       (O(1), highest confidence)
Layer 2 — CWE / category match      (semantic, medium confidence)
Layer 3 — Regex + keyword match     (pattern/text, lowest confidence fallback)

Returns the best matching rule dict and the layer that matched.
"""

import re
import logging
from typing import Optional, Tuple

from .rule_loader import rule_loader
from models.finding import SecOpsFinding

logger = logging.getLogger(__name__)

# ── Layer thresholds ─────────────────────────────────────────────────────────
_MIN_KEYWORD_SCORE = 2   # at least 2 keyword hits required for Layer 3 match


def match(finding: SecOpsFinding) -> Tuple[Optional[dict], str]:
    """
    Find the best matching rule for a finding.

    Returns:
        (rule_dict, layer)  where layer is one of:
            "exact"     — rule_id matched directly
            "cwe"       — CWE mapping matched
            "category"  — security category matched
            "regex"     — regex pattern in rule matched finding message
            "keyword"   — keyword similarity matched
            "unmatched" — no rule found
    """

    # ── Layer 1: Exact rule_id ───────────────────────────────────────���────────
    if finding.rule_id:
        rule = rule_loader.by_rule_id(finding.rule_id)
        if rule:
            logger.debug(f"[L1-exact] finding {finding.id} → {rule['rule_id']}")
            return rule, "exact"

        # Also try stripping common prefixes (e.g. "python.security.secrets.github_token" → "github_token")
        short_id = finding.rule_id.split(".")[-1].lower()
        rule = rule_loader.by_rule_id(short_id)
        if rule:
            logger.debug(f"[L1-exact-short] finding {finding.id} → {rule['rule_id']}")
            return rule, "exact"

    # ── Layer 2a: CWE match ───────────────────────────────────────────────────
    cwes = _extract_cwes(finding)
    for cwe in cwes:
        candidates = rule_loader.by_cwe(cwe)
        if candidates:
            rule = _best_by_severity(candidates, finding.severity)
            logger.debug(f"[L2-cwe] finding {finding.id} CWE={cwe} → {rule['rule_id']}")
            return rule, "cwe"

    # ── Layer 2b: Category match ──────────────────────────────────────────────
    category = _extract_category(finding)
    if category:
        candidates = rule_loader.by_category(category)
        if candidates:
            rule = _best_by_severity(candidates, finding.severity)
            logger.debug(f"[L2-cat] finding {finding.id} cat={category} → {rule['rule_id']}")
            return rule, "category"

    # ── Layer 3a: Regex pattern in rule matches finding message ───────────────
    search_text = f"{finding.message or ''} {finding.rule_id or ''}"
    rule = _regex_match(search_text)
    if rule:
        logger.debug(f"[L3-regex] finding {finding.id} → {rule['rule_id']}")
        return rule, "regex"

    # ── Layer 3b: Keyword similarity ──────────────────────────────────────────
    candidates = rule_loader.by_keywords(search_text, top_n=1)
    if candidates:
        logger.debug(f"[L3-keyword] finding {finding.id} → {candidates[0]['rule_id']}")
        return candidates[0], "keyword"

    logger.debug(f"[unmatched] finding {finding.id} rule_id={finding.rule_id}")
    return None, "unmatched"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_cwes(finding: SecOpsFinding):
    """Extract CWE IDs from finding metadata."""
    cwes = []
    meta = finding.metadata or {}
    for key in ("cwe", "cwes", "cwe_id"):
        val = meta.get(key)
        if val:
            if isinstance(val, list):
                cwes.extend([str(v) for v in val])
            else:
                cwes.append(str(val))
    return cwes


def _extract_category(finding: SecOpsFinding) -> Optional[str]:
    """Infer category from finding metadata or rule_id."""
    meta = finding.metadata or {}
    cat = meta.get("category") or meta.get("rule_type") or ""
    if cat:
        return cat.lower()
    # Infer from rule_id path (e.g. "python.security.hardcoded-secrets" ��� "security")
    if finding.rule_id and "secret" in finding.rule_id.lower():
        return "security"
    return None


def _best_by_severity(candidates: list, severity: str) -> dict:
    """From a list of candidate rules, prefer one whose defaultSeverity matches the finding."""
    for rule in candidates:
        rule_sev = (rule.get("defaultSeverity") or "").lower()
        if severity and rule_sev and rule_sev in severity:
            return rule
    return candidates[0]


def _regex_match(text: str) -> Optional[dict]:
    """
    Try each rule's regex patterns against the finding text.
    A match is accepted only when BOTH:
      1. The regex pattern matches somewhere in the text, AND
      2. At least one context_keyword from that check also appears in the text.
    This prevents broad regex patterns causing false positive matches.
    """
    if not text.strip():
        return None
    text_lower = text.lower()
    for rule in rule_loader._by_rule_id.values():
        logic = rule.get("logic") or {}
        checks = logic.get("checks") or []
        for check in checks:
            pattern = check.get("pattern")
            if not pattern:
                continue
            # Require at least one context keyword to be present in the text
            keywords = [k.lower() for k in (check.get("context_keywords") or [])]
            if keywords and not any(kw in text_lower for kw in keywords):
                continue
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return rule
            except re.error:
                continue
    return None
