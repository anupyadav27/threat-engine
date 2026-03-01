"""
Rule Metadata Loader — seed, sync, and read secops_rule_metadata from DB.

Patterns:
  - seed_all_rules(): Bulk load all rules from scanner docs folders into DB
  - sync_scanner_rules(scanner): Incremental upsert for one scanner
  - load_rules_from_db(scanner): Runtime read → returns dict[rule_id → metadata]
"""

import glob
import json
import logging
import os
from typing import Dict, List, Optional, Any

import psycopg2.extras

from .db_config import get_connection

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scanner → docs folder mapping
# ---------------------------------------------------------------------------
SCANNER_DOCS = {
    "python":         "python_v2/python_docs",
    "terraform":      "terraform_v2/terraform_rules1",
    "java":           "java_scanner/java_docs",
    "docker":         "docker_scanner/docker_docs",
    "kubernetes":     "kubernetes_scanner/kubernetes_docs",
    "ansible":        "ansible_scanner/ansible_docs",
    "javascript":     "javascript_scanner/javascript_docs",
    "csharp":         "csharp_scanner/csharp_docs",
    "azure":          "azure_scanner/azure_docs",
    "cloudformation": "cloudformation_scanner/cloudformation_docs",
    "go":             "go_scanner/go_docs",
    "cpp":            "cpp_scanner/cpp_docs",
    "c":              "C_scanner/c_docs",
    "ruby":           "ruby_scanner/ruby_docs",
}

# Severity normalization (raw → standard 5-tier)
_SEVERITY_MAP = {
    "blocker": "critical",
    "critical": "critical",
    "major": "high",
    "minor": "medium",
    "info": "low",
    "security hotspot": "medium",
}


def _normalize_severity(raw: Optional[str]) -> str:
    if not raw or not raw.strip():
        return "medium"
    return _SEVERITY_MAP.get(raw.strip().lower(), "medium")


def _extract_security_mappings(data: dict) -> Optional[dict]:
    """Extract CWE/OWASP/PCI mappings from various scanner formats."""
    mappings = {}

    # Python: security_mappings field
    if data.get("security_mappings"):
        mappings.update(data["security_mappings"])

    # Terraform: securityStandards field
    if data.get("securityStandards"):
        mappings.update(data["securityStandards"])

    # Java: enhanced_metadata.cwe / enhanced_metadata.owasp
    em = data.get("enhanced_metadata") or {}
    if em.get("cwe"):
        mappings["cwe"] = em["cwe"]
    if em.get("owasp"):
        mappings["owasp"] = em["owasp"]

    return mappings if mappings else None


def _extract_category(data: dict) -> Optional[str]:
    """Normalize category/type field."""
    return data.get("type") or data.get("category") or None


def _extract_rule_type(data: dict) -> Optional[str]:
    """Normalize to VULNERABILITY/CODE_SMELL/SECURITY_HOTSPOT/BUG."""
    raw = data.get("type") or data.get("category") or ""
    raw_upper = raw.upper().replace(" ", "_")
    if raw_upper in ("VULNERABILITY", "SECURITY_VULNERABILITY"):
        return "VULNERABILITY"
    if raw_upper in ("CODE_SMELL",):
        return "CODE_SMELL"
    if raw_upper in ("SECURITY_HOTSPOT",):
        return "SECURITY_HOTSPOT"
    if raw_upper in ("BUG",):
        return "BUG"
    if "security" in raw.lower():
        return "SECURITY_HOTSPOT"
    return None


# ---------------------------------------------------------------------------
# Load JSON files from a scanner's docs folder
# ---------------------------------------------------------------------------

def _load_json_files(scanner: str, base_dir: str) -> List[Dict[str, Any]]:
    """Load all JSON rule metadata files for a scanner."""
    rel_path = SCANNER_DOCS.get(scanner)
    if not rel_path:
        logger.warning(f"Unknown scanner: {scanner}")
        return []

    docs_dir = os.path.join(base_dir, rel_path)
    if not os.path.isdir(docs_dir):
        logger.warning(f"Docs folder not found: {docs_dir}")
        return []

    # Some scanners use *_metadata.json, others *.json
    files = glob.glob(os.path.join(docs_dir, "*_metadata.json"))
    if not files:
        files = glob.glob(os.path.join(docs_dir, "*.json"))

    rules = []
    for fpath in files:
        try:
            with open(fpath, "r") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and data.get("rule_id"):
                rules.append(data)
        except Exception as e:
            logger.debug(f"Skipping {fpath}: {e}")
    return rules


# ---------------------------------------------------------------------------
# Seed / Sync
# ---------------------------------------------------------------------------

def seed_all_rules(base_dir: str) -> Dict[str, int]:
    """
    Bulk load all rules from all scanner docs folders into secops_rule_metadata.
    Returns dict of scanner → count inserted/updated.
    """
    totals = {}
    for scanner in SCANNER_DOCS:
        count = sync_scanner_rules(scanner, base_dir)
        totals[scanner] = count
        logger.info(f"Seeded {scanner}: {count} rules")
    return totals


def sync_scanner_rules(scanner: str, base_dir: str) -> int:
    """
    Incremental upsert: load JSON files for one scanner, upsert into DB.
    Only updates rows where raw_metadata has changed.
    Returns count of rows upserted.
    """
    rules = _load_json_files(scanner, base_dir)
    if not rules:
        return 0

    conn = get_connection()
    count = 0
    BATCH_SIZE = 50
    try:
        with conn.cursor() as cur:
            for idx, data in enumerate(rules):
                rule_id = data.get("rule_id", "").strip()
                if not rule_id:
                    continue

                raw_sev = data.get("defaultSeverity") or data.get("default_severity") or ""

                def _clean(s):
                    """Strip \\u0000 null bytes — PostgreSQL JSONB can't store them."""
                    return s.replace("\x00", "").replace("\\u0000", "")

                def _jsonb(val):
                    """Wrap value for JSONB column — None stays None."""
                    if val is None:
                        return None
                    return psycopg2.extras.Json(
                        val,
                        dumps=lambda o: _clean(json.dumps(o, default=str)),
                    )

                def _text(val):
                    """Coerce to string for TEXT columns — dicts/nullbytes handled."""
                    if val is None:
                        return None
                    if isinstance(val, str):
                        return _clean(val)
                    return _clean(json.dumps(val, default=str))

                sec_map = _extract_security_mappings(data)

                cur.execute("""
                    INSERT INTO secops_rule_metadata
                        (rule_id, scanner, title, description, default_severity,
                         severity, status, category, rule_type,
                         impact, recommendation, remediation,
                         "references", tags, examples, security_mappings,
                         logic, raw_metadata, metadata_source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (rule_id) DO UPDATE SET
                        scanner = EXCLUDED.scanner,
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        default_severity = EXCLUDED.default_severity,
                        severity = EXCLUDED.severity,
                        status = EXCLUDED.status,
                        category = EXCLUDED.category,
                        rule_type = EXCLUDED.rule_type,
                        impact = EXCLUDED.impact,
                        recommendation = EXCLUDED.recommendation,
                        remediation = EXCLUDED.remediation,
                        "references" = EXCLUDED."references",
                        tags = EXCLUDED.tags,
                        examples = EXCLUDED.examples,
                        security_mappings = EXCLUDED.security_mappings,
                        logic = EXCLUDED.logic,
                        raw_metadata = EXCLUDED.raw_metadata,
                        updated_at = now()
                    WHERE secops_rule_metadata.raw_metadata::text != EXCLUDED.raw_metadata::text
                """, (
                    rule_id,
                    scanner,
                    _text(data.get("title")),
                    _text(data.get("description")),
                    raw_sev,
                    _normalize_severity(raw_sev),
                    _text(data.get("status", "ready")),
                    _text(_extract_category(data)),
                    _text(_extract_rule_type(data)),
                    _text(data.get("impact")),
                    _text(data.get("recommendation")),
                    _text(data.get("remediation")),
                    _jsonb(data.get("references")),
                    _jsonb(data.get("tags")),
                    _jsonb(data.get("examples")),
                    _jsonb(sec_map),
                    _jsonb(data.get("logic")),
                    _jsonb(data),  # raw_metadata = complete original
                    "seed",
                ))
                count += 1

                # Commit in batches to avoid timeout on remote DB
                if count % BATCH_SIZE == 0:
                    conn.commit()

        conn.commit()  # final batch
    finally:
        conn.close()
    return count


# ---------------------------------------------------------------------------
# Runtime read — load from DB into memory cache
# ---------------------------------------------------------------------------

def load_rules_from_db(scanner: str) -> Dict[str, Dict[str, Any]]:
    """
    Load rule metadata from DB for a specific scanner.
    Returns dict[rule_id → raw_metadata] — same format as load_rule_metadata()
    from each scanner, so it's a drop-in replacement.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rule_id, raw_metadata
                FROM secops_rule_metadata
                WHERE scanner = %s AND status NOT IN ('deprecated', 'disabled')
            """, (scanner,))
            rules = {}
            for row in cur.fetchall():
                rid = row[0]
                meta = row[1]
                if isinstance(meta, str):
                    meta = json.loads(meta)
                rules[rid] = meta
            return rules
    finally:
        conn.close()


def load_all_rules_from_db() -> Dict[str, Dict[str, Any]]:
    """Load ALL rule metadata from DB across all scanners."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rule_id, raw_metadata
                FROM secops_rule_metadata
                WHERE status NOT IN ('deprecated', 'disabled')
            """)
            rules = {}
            for row in cur.fetchall():
                rid = row[0]
                meta = row[1]
                if isinstance(meta, str):
                    meta = json.loads(meta)
                rules[rid] = meta
            return rules
    finally:
        conn.close()


def get_rule_stats() -> Dict[str, Any]:
    """Get statistics about rules in the DB."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM secops_rule_metadata")
            total = cur.fetchone()[0]

            cur.execute("""
                SELECT scanner, COUNT(*) as cnt
                FROM secops_rule_metadata
                GROUP BY scanner ORDER BY cnt DESC
            """)
            by_scanner = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM secops_rule_metadata
                GROUP BY severity ORDER BY cnt DESC
            """)
            by_severity = {r[0]: r[1] for r in cur.fetchall()}

            return {
                "total_rules": total,
                "by_scanner": by_scanner,
                "by_severity": by_severity,
            }
    finally:
        conn.close()
