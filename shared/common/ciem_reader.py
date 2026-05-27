"""
Shared CIEM Reader — reads log_events + ciem_findings for any engine.

Each engine imports this to enrich its analysis with actual usage data.
Lives in shared/common so all engines can access it.

Usage:
    from engine_common.ciem_reader import CIEMReader

    reader = CIEMReader(tenant_id, account_id)
    usage = reader.get_identity_usage(days=30)          # IAM engine
    data_access = reader.get_data_access_patterns()      # DataSec engine
    threats = reader.get_threat_events()                 # Threat engine
    audit_evidence = reader.get_audit_completeness()     # Compliance engine
"""

import os
import logging
from collections import defaultdict
from typing import Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def _get_check_conn():
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


def _get_log_conn():
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


def _get_ciem_conn():
    return psycopg2.connect(
        host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("CIEM_DB_NAME", "threat_engine_cdr"),
        user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CIEM_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD",
                 os.getenv("DB_PASSWORD", ""))),
    )


class CIEMReader:
    """Shared reader for log_events + ciem_findings data."""

    def __init__(self, tenant_id: str, account_id: str = "", days: int = 30):
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.days = days

    def close(self) -> None:
        """No-op — CIEMReader opens/closes connections per call."""
        pass

    def _resolve_latest_ciem_scan_run_id(self) -> Optional[str]:
        """Return the scan_run_id of the latest completed CIEM scan for this tenant.

        Falls back to None when no completed scan exists (caller then uses time window).
        """
        conn = _get_ciem_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scan_run_id FROM cdr_report
                    WHERE tenant_id = %s AND status = 'completed'
                    ORDER BY completed_at DESC NULLS LAST
                    LIMIT 1
                    """,
                    (self.tenant_id,),
                )
                row = cur.fetchone()
                return row[0] if row else None
        except Exception as exc:
            logger.warning(f"CIEMReader._resolve_latest_ciem_scan_run_id failed: {exc}")
            return None
        finally:
            conn.close()

    # ═══════════════════════════════════════════════════════════
    # IAM Engine: identity usage tracking
    # ═══════════════════════════════════════════════════════════

    def get_identity_usage(self) -> Dict[str, Dict]:
        """Get actual API usage per IAM principal from CloudTrail.

        Returns: {principal_arn: {total_calls, unique_ops, services, last_activity, ...}}
        """
        conn = _get_log_conn()
        usage = {}
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT actor_principal, actor_principal_type,
                           count(*) AS total_calls,
                           count(DISTINCT operation) AS unique_ops,
                           count(DISTINCT service) AS unique_services,
                           min(event_time) AS first_activity,
                           max(event_time) AS last_activity,
                           array_agg(DISTINCT actor_ip) FILTER (WHERE actor_ip != '') AS source_ips
                    FROM log_events
                    WHERE tenant_id = %s AND actor_principal != ''
                    AND event_time > NOW() - INTERVAL '%s days'
                    GROUP BY actor_principal, actor_principal_type
                """, (self.tenant_id, self.days))
                for row in cur.fetchall():
                    usage[row["actor_principal"]] = {
                        **dict(row),
                        "first_activity": row["first_activity"].isoformat() if row["first_activity"] else None,
                        "last_activity": row["last_activity"].isoformat() if row["last_activity"] else None,
                    }
        except Exception as exc:
            logger.warning(f"CIEMReader.get_identity_usage failed: {exc}")
        finally:
            conn.close()
        return usage

    def get_cross_account_access(self) -> List[Dict]:
        """Find cross-account AssumeRole events."""
        conn = _get_log_conn()
        results = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT actor_principal, actor_account_id, resource_uid,
                           count(*) AS assume_count,
                           max(event_time) AS last_seen
                    FROM log_events
                    WHERE tenant_id = %s AND operation = 'AssumeRole'
                    AND actor_account_id != %s AND actor_account_id != ''
                    AND event_time > NOW() - INTERVAL '%s days'
                    GROUP BY actor_principal, actor_account_id, resource_uid
                    ORDER BY assume_count DESC
                """, (self.tenant_id, self.account_id, self.days))
                results = [dict(r) for r in cur.fetchall()]
        except Exception as exc:
            logger.warning(f"CIEMReader.get_cross_account_access failed: {exc}")
        finally:
            conn.close()
        return results

    # ═══════════════════════════════════════════════════════════
    # Threat Engine: security-relevant events
    # ═══════════════════════════════════════════════════════════

    def get_threat_events(self, min_severity: str = "low") -> List[Dict]:
        """Get high/critical security events from log_events."""
        severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        min_level = severity_order.get(min_severity, 4)
        allowed = [s for s, l in severity_order.items() if l <= min_level]

        conn = _get_log_conn()
        results = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                placeholders = ",".join(["%s"] * len(allowed))
                cur.execute(f"""
                    SELECT event_id, event_time, service, operation, outcome,
                           actor_principal, actor_ip, resource_uid, resource_type,
                           severity, risk_indicators
                    FROM log_events
                    WHERE tenant_id = %s AND severity IN ({placeholders})
                    AND event_time > NOW() - INTERVAL '%s days'
                    ORDER BY event_time DESC LIMIT 5000
                """, [self.tenant_id] + allowed + [self.days])
                results = [dict(r) for r in cur.fetchall()]
        except Exception as exc:
            logger.warning(f"CIEMReader.get_threat_events failed: {exc}")
        finally:
            conn.close()
        return results

    # Maps caller engine_filter names → rule_metadata JSONB scope column
    _ENGINE_SCOPE_COL: Dict[str, str] = {
        "datasec":          "data_security",
        "data_security":    "data_security",
        "container":        "container_security",
        "container-security": "container_security",
        "container_security": "container_security",
        "database":         "database_security",
        "dbsec":            "database_security",
        "database_security": "database_security",
        "ai_security":      "ai_security",
        "ai-security":      "ai_security",
        "network":          "network_security",
        "network_security": "network_security",
        "iam":              "iam_security",
        "iam_security":     "iam_security",
    }

    def _get_applicable_rule_ids(self, scope_col: str) -> Optional[List[str]]:
        """Return rule_ids from rule_metadata where scope_col->>'applicable' = true.

        Returns None if the lookup fails (caller should skip the filter).
        """
        try:
            conn = _get_check_conn()
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT rule_id FROM rule_metadata "
                    f"WHERE ({scope_col}->>'applicable')::boolean = true "
                    f"AND customer_id IS NULL"
                )
                ids = [r[0] for r in cur.fetchall()]
            conn.close()
            logger.debug(f"engine_filter scope '{scope_col}': {len(ids)} applicable rule_ids")
            return ids
        except Exception as exc:
            logger.warning(f"CIEMReader._get_applicable_rule_ids({scope_col}) failed: {exc}")
            return None

    def get_ciem_findings(self, engine_filter: str = "", enrich: bool = True) -> List[Dict]:
        """Get CIEM findings, optionally filtered by engine scope.

        Args:
            engine_filter: Engine name (e.g. 'datasec', 'container', 'dbsec',
                'ai_security', 'network', 'iam'). Resolved to a rule_metadata
                JSONB scope column — only CIEM rule_ids that are applicable to
                that engine scope are returned.  Pass "" for all findings.
            enrich: If True, auto-enrich with rule_metadata from Check DB
                    (title, description, remediation, compliance_frameworks, MITRE).

        Returns:
            List of finding dicts, enriched with rule metadata when available.
        """
        # Resolve engine_filter → applicable rule_ids from rule_metadata
        applicable_rule_ids: Optional[List[str]] = None
        if engine_filter:
            scope_col = self._ENGINE_SCOPE_COL.get(engine_filter.lower())
            if scope_col:
                applicable_rule_ids = self._get_applicable_rule_ids(scope_col)
                if applicable_rule_ids is not None and len(applicable_rule_ids) == 0:
                    logger.info(f"No CIEM-applicable rules for engine '{engine_filter}' — returning empty")
                    return []
            # If scope_col not found, fall through without rule_id filter
            # (e.g. engine_filter='threat' or 'ciem' → return all findings)

        # Prefer findings scoped to the latest completed CIEM scan so we never
        # pull from in-progress or duplicate across multiple runs.  Fall back to
        # the rolling time-window when no completed scan exists yet.
        latest_scan_run_id = self._resolve_latest_ciem_scan_run_id()

        conn = _get_ciem_conn()
        results = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if latest_scan_run_id:
                    scope_clause = "AND scan_run_id = %s"
                    params: list = [self.tenant_id, latest_scan_run_id]
                else:
                    scope_clause = "AND event_time > NOW() - INTERVAL '%s days'"
                    params = [self.tenant_id, self.days]

                rule_id_clause = ""
                if applicable_rule_ids is not None:
                    rule_id_clause = "AND rule_id = ANY(%s)"
                    params.append(applicable_rule_ids)

                cur.execute(f"""
                    SELECT finding_id, rule_id, severity, operation,
                           actor_principal, resource_uid, resource_type,
                           event_time, title, action_category, primary_engine,
                           account_id, region
                    FROM cdr_findings
                    WHERE tenant_id = %s
                    {scope_clause}
                    {rule_id_clause}
                    ORDER BY event_time DESC LIMIT 5000
                """, params)
                results = [dict(r) for r in cur.fetchall()]
        except Exception as exc:
            logger.warning(f"CIEMReader.get_ciem_findings failed: {exc}")
        finally:
            conn.close()

        if enrich and results:
            results = self._enrich_with_rule_metadata(results)

        return results

    def _enrich_with_rule_metadata(self, findings: List[Dict]) -> List[Dict]:
        """Enrich CIEM findings with rule_metadata from Check DB.

        Looks up each finding's rule_id in rule_metadata (metadata_source='ciem')
        and merges: title, description, remediation, compliance_frameworks,
        mitre_tactics, mitre_techniques, risk_score, domain.

        Args:
            findings: List of CIEM finding dicts.

        Returns:
            Same list with enriched fields added.
        """
        rule_ids = list({f.get("rule_id") for f in findings if f.get("rule_id")})
        if not rule_ids:
            return findings

        rule_cache: Dict[str, Dict] = {}
        conn = None
        try:
            conn = _get_check_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                placeholders = ",".join(["%s"] * len(rule_ids))
                cur.execute(f"""
                    SELECT rule_id, title, description, remediation,
                           compliance_frameworks, mitre_tactics, mitre_techniques,
                           risk_score, domain, severity, threat_category
                    FROM rule_metadata
                    WHERE rule_id IN ({placeholders})
                """, rule_ids)
                for row in cur.fetchall():
                    rule_cache[row["rule_id"]] = dict(row)
        except Exception as exc:
            logger.warning(f"CIEMReader._enrich_with_rule_metadata failed: {exc}")
        finally:
            if conn:
                conn.close()

        if not rule_cache:
            return findings

        for f in findings:
            meta = rule_cache.get(f.get("rule_id", ""))
            if not meta:
                continue
            # Only fill in fields that are missing or empty
            if not f.get("title"):
                f["title"] = meta.get("title", "")
            if not f.get("description"):
                f["description"] = meta.get("description", "")
            if not f.get("remediation"):
                f["remediation"] = meta.get("remediation", "")
            if not f.get("compliance_frameworks"):
                cf = meta.get("compliance_frameworks")
                # JSONB auto-deserialized by psycopg2
                f["compliance_frameworks"] = cf if isinstance(cf, list) else []
            if not f.get("mitre_tactics"):
                mt = meta.get("mitre_tactics")
                f["mitre_tactics"] = mt if isinstance(mt, list) else []
            if not f.get("mitre_techniques"):
                mt = meta.get("mitre_techniques")
                f["mitre_techniques"] = mt if isinstance(mt, list) else []
            if not f.get("risk_score"):
                f["risk_score"] = meta.get("risk_score", 50)
            if not f.get("domain"):
                f["domain"] = meta.get("domain", "")

        logger.info(f"Enriched {len(rule_cache)} / {len(rule_ids)} CIEM rule_ids with rule_metadata")
        return findings

    # ═══════════════════════════════════════════════════════════
    # DataSec Engine: data access patterns
    # ═══════════════════════════════════════════════════════════

    def get_data_access_patterns(self) -> Dict[str, Dict]:
        """Get data access patterns per resource from CloudTrail.

        Returns: {resource_uid: {total_access, unique_accessors, operations, ...}}
        """
        conn = _get_log_conn()
        patterns = {}
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT resource_uid,
                           count(*) AS total_access,
                           count(DISTINCT actor_principal) AS unique_accessors,
                           count(DISTINCT operation) AS unique_operations,
                           max(event_time) AS last_access,
                           array_agg(DISTINCT operation) AS operations
                    FROM log_events
                    WHERE tenant_id = %s
                    AND service IN ('s3', 'rds', 'dynamodb', 'redshift', 'glue', 'kms')
                    AND resource_uid IS NOT NULL AND resource_uid != ''
                    AND event_time > NOW() - INTERVAL '%s days'
                    GROUP BY resource_uid
                    ORDER BY total_access DESC LIMIT 1000
                """, (self.tenant_id, self.days))
                for row in cur.fetchall():
                    patterns[row["resource_uid"]] = {
                        **dict(row),
                        "last_access": row["last_access"].isoformat() if row["last_access"] else None,
                    }
        except Exception as exc:
            logger.warning(f"CIEMReader.get_data_access_patterns failed: {exc}")
        finally:
            conn.close()
        return patterns

    # ═══════════════════════════════════════════════════════════
    # Compliance Engine: audit logging evidence
    # ═══════════════════════════════════════════════════════════

    def get_audit_completeness(self) -> Dict[str, Dict]:
        """Check audit logging completeness from log_events.

        Returns: {source_type: {total_events, days_covered, regions, ...}}
        """
        conn = _get_log_conn()
        completeness = {}
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT source_type,
                           count(*) AS total_events,
                           count(DISTINCT date(event_time)) AS days_covered,
                           count(DISTINCT resource_region) AS regions_covered,
                           min(event_time) AS earliest,
                           max(event_time) AS latest
                    FROM log_events
                    WHERE tenant_id = %s
                    AND event_time > NOW() - INTERVAL '%s days'
                    GROUP BY source_type
                """, (self.tenant_id, self.days))
                for row in cur.fetchall():
                    completeness[row["source_type"]] = {
                        **dict(row),
                        "earliest": row["earliest"].isoformat() if row["earliest"] else None,
                        "latest": row["latest"].isoformat() if row["latest"] else None,
                    }
        except Exception as exc:
            logger.warning(f"CIEMReader.get_audit_completeness failed: {exc}")
        finally:
            conn.close()
        return completeness

    # ═══════════════════════════════════════════════════════════
    # Network Engine: network flow summary
    # ═══════════════════════════════════════════════════════════

    def get_network_events(self) -> List[Dict]:
        """Get network-related events (VPC flow, SG changes)."""
        conn = _get_log_conn()
        results = []
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT event_id, event_time, source_type, service, operation,
                           actor_principal, resource_uid,
                           src_ip, dst_ip, src_port, dst_port, protocol,
                           bytes_in, flow_action, severity
                    FROM log_events
                    WHERE tenant_id = %s
                    AND (source_type = 'vpc_flow'
                         OR operation IN ('AuthorizeSecurityGroupIngress',
                             'RevokeSecurityGroupIngress', 'CreateNetworkAclEntry',
                             'CreateRoute', 'CreateVpcPeeringConnection'))
                    AND event_time > NOW() - INTERVAL '%s days'
                    ORDER BY event_time DESC LIMIT 5000
                """, (self.tenant_id, self.days))
                results = [dict(r) for r in cur.fetchall()]
        except Exception as exc:
            logger.warning(f"CIEMReader.get_network_events failed: {exc}")
        finally:
            conn.close()
        return results
