"""
DB Fetcher — reads vulnerability scan data from vulnerability_db.

Tables used (read-only):
  scans              — scan metadata (agent_id, status, system_info, packages_scanned)
  scan_vulnerabilities — per-finding CVE data (cve_id, package_name, severity, score)
  cves               — CVE master data for enrichment (description, vectors, published_date)
  agents             — agent hostname/platform for AI context
"""

import json
import logging
from typing import Optional

from .db_config import get_dict_connection

logger = logging.getLogger(__name__)


def _parse_system_info(raw) -> dict:
    """Normalise system_info field to a plain dict."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            try:
                import ast
                return ast.literal_eval(raw)
            except Exception:
                pass
    return {}


def _parse_env_type(vul_agent_id: str) -> str:
    """
    Extract the environment type from the last segment of vul_agent_id.

    Format: {username}-{system_fingerprint}-{env_type}
    e.g.  ajay4141-035c62041ecf...-docker   → 'docker'
          user123-abc123...-aws-ec2          → 'aws-ec2'
          user-abc-bare-metal                → 'bare-metal'
    Returns 'unknown' if not parseable.
    """
    if not vul_agent_id:
        return "unknown"
    # Strip username prefix (first segment before '-')
    parts = vul_agent_id.split("-")
    if len(parts) < 3:
        return "unknown"
    # The fingerprint is a long hex string — find it, env is everything after
    for i, part in enumerate(parts):
        if len(part) >= 12 and all(c in "0123456789abcdef" for c in part.lower()):
            env = "-".join(parts[i + 1:]).strip("-")
            return env if env else "unknown"
    # Fallback: last segment
    return parts[-1] if parts[-1] else "unknown"


def get_scan_info(scan_id: str) -> Optional[dict]:
    """
    Return scan metadata including agent info, fully parsed system_info,
    and env_type parsed from vul_agent_id.

    Returned dict includes:
      scan_id, agent_id, vul_agent_id, env_type,
      status, packages_scanned, vulnerabilities_found, analysis_mode,
      system_info (dict), hostname, platform, architecture,
      os_id, os_name, os_version, os_family
    """
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    s.scan_id,
                    s.agent_id,
                    s.vul_agent_id,
                    s.scan_start,
                    s.scan_end,
                    s.status,
                    s.packages_scanned,
                    s.vulnerabilities_found,
                    s.analysis_mode,
                    s.system_info,
                    a.hostname,
                    a.platform,
                    a.architecture
                FROM scans s
                LEFT JOIN agents a ON a.agent_id = s.agent_id
                WHERE s.scan_id = %s
            """, (scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            result = dict(row)

            # Normalise system_info to dict
            result["system_info"] = _parse_system_info(result.get("system_info"))
            si = result["system_info"]

            # Surface OS detail fields directly (use system_info as primary source —
            # it has os_id/os_name/os_version which agents table does not)
            result["os_id"]      = si.get("os_id")      or si.get("os")       or ""
            result["os_name"]    = si.get("os_name")     or si.get("os_id")    or si.get("os") or ""
            result["os_version"] = si.get("os_version")  or si.get("version")  or ""
            result["os_family"]  = si.get("os_family")   or si.get("platform") or "linux"

            # Fill platform/hostname/arch from system_info if agents JOIN returned nothing
            if not result.get("platform"):
                result["platform"]     = si.get("platform")     or si.get("os") or ""
            if not result.get("hostname"):
                result["hostname"]     = si.get("hostname")     or ""
            if not result.get("architecture"):
                result["architecture"] = si.get("architecture") or si.get("machine") or "x86_64"

            # Parse environment type from vul_agent_id
            result["env_type"] = _parse_env_type(result.get("vul_agent_id") or "")

            return result
    finally:
        conn.close()


def get_scan_vulnerabilities(scan_id: str, severity_filter: Optional[list] = None) -> list:
    """
    Return all vulnerability findings for a scan, enriched with CVE master data.

    severity_filter: list of severities to include e.g. ['CRITICAL', 'HIGH'].
                     None = include all severities.
    """
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            base_query = """
                SELECT
                    sv.row_no              AS id,
                    sv.scan_id,
                    sv.cve_id,
                    sv.package_name,
                    sv.package_version,
                    sv.severity,
                    sv.score,
                    sv.vector,
                    sv.description         AS sv_description,
                    sv.remediation         AS basic_remediation,
                    sv.agent_id,
                    sv.vul_agent_id,
                    sv.system_info,
                    sv.scan_date,
                    -- CVE master data enrichment
                    c.description          AS cve_description,
                    c.cvss_v3_score,
                    c.cvss_v3_vector,
                    c.cvss_v2_score,
                    c.published_date,
                    c.modified_date
                FROM scan_vulnerabilities sv
                LEFT JOIN cves c ON c.cve_id = sv.cve_id
                WHERE sv.scan_id = %s
            """
            params = [scan_id]

            if severity_filter:
                upper = [s.upper() for s in severity_filter]
                base_query += " AND UPPER(sv.severity) = ANY(%s)"
                params.append(upper)

            base_query += " ORDER BY sv.score DESC NULLS LAST, sv.cve_id"
            cur.execute(base_query, params)
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()


def get_fixed_version(package_name: str) -> Optional[str]:
    """
    Look up the fixed/latest version for a package from pkg_database.
    Returns the fixed_version string if available, else None.
    """
    conn = get_dict_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT vt.full_version AS fixed_version
                FROM pkg_database pd
                JOIN version_table vt ON vt.id = pd.version
                WHERE LOWER(pd.pkg_name) = LOWER(%s)
                  AND pd.fixed_version IS NOT NULL
                  AND pd.status = 'active'
                ORDER BY pd.updated_at DESC
                LIMIT 1
            """, (package_name,))
            row = cur.fetchone()
            return row["fixed_version"] if row else None
    except Exception as e:
        # pkg_database schema may vary — non-fatal
        logger.debug(f"fixed_version lookup failed for {package_name}: {e}")
        return None
    finally:
        conn.close()
