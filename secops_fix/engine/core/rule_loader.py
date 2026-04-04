"""
Rule Loader — loads and indexes all JSON rule metadata files at startup.

Auto-discovers every *_docs folder under secops_fix/ so new rule
categories are picked up without code changes.

Current categories (auto-loaded):
  secrets_docs        — 412  hardcoded credential / secret exposure rules
  python_docs         — 361  Python SAST rules
  java_docs           — 746  Java SAST rules
  javascript_docs     — 424  JavaScript / TypeScript SAST rules
  csharp_docs         — 487  C# SAST rules
  c_docs              — 317  C SAST rules
  cpp_docs            — 299  C++ SAST rules
  go_docs             —  70  Go SAST rules
  docker_docs         —  44  Docker SAST rules
  azure_docs          —  32  Azure IaC SAST rules
  cloudformation_docs —  29  CloudFormation SAST rules
  kubernetes_docs     —  26  Kubernetes SAST rules
  ansible_docs        —  17  Ansible SAST rules
  ruby_docs           —   5  Ruby SAST rules
  terraform_docs      —  52  Terraform SAST rules
  dast_docs           —  11  DAST / web security fix rules

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
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Root of secops_fix/ — one level above engine/
_SECOPS_FIX_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Minimum keyword hits required for a Layer-3 keyword match to be accepted
KEYWORD_CONFIDENCE_THRESHOLD = 3


class RuleLoader:
    def __init__(self, root_dir: str = _SECOPS_FIX_ROOT):
        self.root_dir = root_dir
        self._by_rule_id: Dict[str, dict] = {}
        self._by_cwe: Dict[str, List[dict]] = {}
        self._by_category: Dict[str, List[dict]] = {}
        self._by_keywords: Dict[str, List[dict]] = {}
        self._category_counts: Dict[str, int] = {}
        self._loaded = False

    def load(self) -> int:
        """
        Auto-discover all *_docs folders under root_dir and load their JSON files.
        Returns total count of rules loaded.
        """
        docs_dirs = sorted(glob.glob(os.path.join(self.root_dir, "*_docs")))
        if not docs_dirs:
            logger.warning(f"No *_docs folders found under {self.root_dir}")
            return 0

        total = 0
        for docs_dir in docs_dirs:
            category = os.path.basename(docs_dir)
            files = glob.glob(os.path.join(docs_dir, "*.json"))
            count = 0
            for path in files:
                try:
                    with open(path, "r", encoding="utf-8-sig") as f:
                        rule = json.load(f)
                    self._index(rule, category)
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to load {path}: {e}")
            self._category_counts[category] = count
            total += count

        self._loaded = True
        logger.info(
            f"RuleLoader: loaded {total} rules across {len(docs_dirs)} categories "
            f"from {self.root_dir}"
        )
        for cat, cnt in self._category_counts.items():
            logger.debug(f"  {cat}: {cnt} rules")
        return total

    def _index(self, rule: dict, category: str) -> None:
        rule_id = rule.get("rule_id", "")
        if not rule_id:
            return

        # Attach source category to rule for debugging
        rule["_category"] = category

        # Layer 1 — exact rule_id (normalised to lowercase)
        self._by_rule_id[rule_id.lower()] = rule
        # Also index without _metadata suffix if present
        clean_id = re.sub(r"_metadata$", "", rule_id.lower())
        if clean_id != rule_id.lower():
            self._by_rule_id[clean_id] = rule

        # Layer 2 — CWE
        security = rule.get("security_mappings", {}) or {}
        for cwe in security.get("cwe", []):
            cwe_key = str(cwe).upper().replace(" ", "")
            self._by_cwe.setdefault(cwe_key, []).append(rule)

        # Layer 2 — category from rule metadata
        rule_cat = (rule.get("category") or "").lower().strip()
        if rule_cat:
            self._by_category.setdefault(rule_cat, []).append(rule)
        # Also index by scanner category folder
        self._by_category.setdefault(category.replace("_docs", ""), []).append(rule)

        # Layer 3 — keywords from title and description
        text = f"{rule.get('title', '')} {rule.get('description', '')} {rule_id}"
        for word in re.findall(r"[a-z]{4,}", text.lower()):
            self._by_keywords.setdefault(word, []).append(rule)

    # ── Lookup methods ────────────────────────────────────────────────────────

    def by_rule_id(self, rule_id: str) -> Optional[dict]:
        return self._by_rule_id.get((rule_id or "").lower())

    def by_cwe(self, cwe: str) -> List[dict]:
        return self._by_cwe.get(str(cwe).upper().replace(" ", ""), [])

    def by_category(self, category: str) -> List[dict]:
        return self._by_category.get((category or "").lower(), [])

    def by_keywords(self, text: str, top_n: int = 3) -> List[Tuple[dict, int]]:
        """
        Return up to top_n rules with most keyword hits for given text.
        Returns list of (rule, score) tuples — caller checks score against threshold.
        """
        words = set(re.findall(r"[a-z]{4,}", (text or "").lower()))
        scores: Dict[str, int] = {}
        candidates: Dict[str, dict] = {}
        for word in words:
            for rule in self._by_keywords.get(word, []):
                rid = rule.get("rule_id", "")
                scores[rid] = scores.get(rid, 0) + 1
                candidates[rid] = rule
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return [(candidates[rid], score) for rid, score in ranked[:top_n]]

    @property
    def total(self) -> int:
        return len(self._by_rule_id)

    @property
    def category_counts(self) -> Dict[str, int]:
        return dict(self._category_counts)


# Singleton — loaded once at process startup
rule_loader = RuleLoader()
