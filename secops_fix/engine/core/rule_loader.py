"""
Rule Loader — loads and indexes all JSON rule metadata files at startup.

Indexes built:
  _by_rule_id   : rule_id  → rule dict          (Layer 1: exact match)
  _by_cwe       : cwe_id   → [rule, ...]         (Layer 2: CWE match)
  _by_category  : category → [rule, ...]         (Layer 2: category match)
  _by_keywords  : word     → [rule, ...]         (Layer 3: keyword match)
"""

import glob
import json
import logging
import os
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Path to secrets_docs relative to this file: ../../secrets_docs
_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "secrets_docs")


class RuleLoader:
    def __init__(self, rules_dir: str = _RULES_DIR):
        self.rules_dir = os.path.abspath(rules_dir)
        self._by_rule_id: Dict[str, dict] = {}
        self._by_cwe: Dict[str, List[dict]] = {}
        self._by_category: Dict[str, List[dict]] = {}
        self._by_keywords: Dict[str, List[dict]] = {}
        self._loaded = False

    def load(self) -> int:
        """Load all JSON rule files. Returns count of rules loaded."""
        pattern = os.path.join(self.rules_dir, "*.json")
        files = glob.glob(pattern)
        if not files:
            logger.warning(f"No rule files found in {self.rules_dir}")
            return 0

        count = 0
        for path in files:
            try:
                with open(path, "r", encoding="utf-8-sig") as f:
                    rule = json.load(f)
                self._index(rule)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to load rule file {path}: {e}")

        self._loaded = True
        logger.info(f"RuleLoader: loaded {count} rules from {self.rules_dir}")
        return count

    def _index(self, rule: dict) -> None:
        rule_id = rule.get("rule_id", "")
        if not rule_id:
            return

        # Layer 1 — exact rule_id
        self._by_rule_id[rule_id.lower()] = rule

        # Layer 2 — CWE
        security = rule.get("security_mappings", {}) or {}
        for cwe in security.get("cwe", []):
            cwe_key = str(cwe).upper().replace(" ", "")
            self._by_cwe.setdefault(cwe_key, []).append(rule)

        # Layer 2 — category
        category = (rule.get("category") or "").lower().strip()
        if category:
            self._by_category.setdefault(category, []).append(rule)

        # Layer 3 — keywords from title and description
        text = f"{rule.get('title', '')} {rule.get('description', '')}"
        for word in re.findall(r"[a-z]{4,}", text.lower()):
            self._by_keywords.setdefault(word, []).append(rule)

    # ── Lookup methods ────────────────────────────────────────────────────────

    def by_rule_id(self, rule_id: str) -> Optional[dict]:
        return self._by_rule_id.get((rule_id or "").lower())

    def by_cwe(self, cwe: str) -> List[dict]:
        key = str(cwe).upper().replace(" ", "")
        return self._by_cwe.get(key, [])

    def by_category(self, category: str) -> List[dict]:
        return self._by_category.get((category or "").lower(), [])

    def by_keywords(self, text: str, top_n: int = 3) -> List[dict]:
        """Return up to top_n rules with most keyword hits for given text."""
        words = set(re.findall(r"[a-z]{4,}", (text or "").lower()))
        scores: Dict[str, int] = {}
        candidates: Dict[str, dict] = {}
        for word in words:
            for rule in self._by_keywords.get(word, []):
                rid = rule.get("rule_id", "")
                scores[rid] = scores.get(rid, 0) + 1
                candidates[rid] = rule
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return [candidates[rid] for rid, _ in ranked[:top_n]]

    @property
    def total(self) -> int:
        return len(self._by_rule_id)


# Singleton — loaded once at process startup
rule_loader = RuleLoader()
