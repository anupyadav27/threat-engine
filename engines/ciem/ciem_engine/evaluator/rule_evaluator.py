"""
CIEM Rule Evaluator — evaluates log detection rules against log_events.

Reads:
  - rule_checks WHERE check_type = 'log' (conditions)
  - rule_metadata WHERE rule_source = 'log' (enrichment)
  - log_events (events to evaluate)

Writes:
  - ciem_findings (matched events)
  - ciem_report (scan summary)

Evaluation logic:
  For each log rule:
    1. Build SQL WHERE clause from rule conditions
    2. Query log_events matching the conditions
    3. For each matched event → create a ciem_finding
    4. Enrich with metadata (title, severity, MITRE, compliance)
"""

import hashlib
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

logger = logging.getLogger(__name__)


class CIEMRuleEvaluator:
    """Evaluate log rules against log_events and write findings."""

    def __init__(self, scan_run_id: str, tenant_id: str, provider: str = "aws"):
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.provider = provider

    def _get_check_conn(self):
        return psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )

    def _get_log_conn(self):
        return psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )

    def _get_ciem_conn(self):
        return psycopg2.connect(
            host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
            user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CIEM_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))),
        )

    def evaluate(self) -> Dict[str, Any]:
        """Run full evaluation: load rules → match events → write findings."""
        started = datetime.now(timezone.utc)

        # 1. Load rules
        rules = self._load_rules()
        logger.info(f"Loaded {len(rules)} log rules for {self.provider}")

        # 2. Load metadata for enrichment
        metadata = self._load_metadata(rules)
        logger.info(f"Loaded metadata for {len(metadata)} rules")

        # 3. Evaluate rules against log_events
        findings = self._evaluate_rules(rules, metadata)
        logger.info(f"Evaluation produced {len(findings)} findings")

        # 4. Write findings
        self._write_findings(findings)

        # 5. Write report
        completed = datetime.now(timezone.utc)
        stats = self._write_report(findings, started, completed)

        return stats

    def _load_rules(self) -> List[Dict]:
        """Load log rules from rule_checks."""
        conn = self._get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT rule_id, service, check_type, check_config
                    FROM rule_checks
                    WHERE check_type = 'log' AND is_active = true
                    AND (provider = %s OR provider IS NULL)
                """, (self.provider,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_metadata(self, rules: List[Dict]) -> Dict[str, Dict]:
        """Load rule_metadata for enrichment."""
        rule_ids = [r["rule_id"] for r in rules]
        if not rule_ids:
            return {}

        conn = self._get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Batch load in chunks
                metadata = {}
                for i in range(0, len(rule_ids), 500):
                    chunk = rule_ids[i:i + 500]
                    placeholders = ",".join(["%s"] * len(chunk))
                    cur.execute(f"""
                        SELECT rule_id, severity, title, description, remediation,
                               primary_engine, engines, action_category,
                               mitre_tactics, mitre_techniques,
                               compliance_frameworks, audit_log_event
                        FROM rule_metadata
                        WHERE rule_id IN ({placeholders})
                    """, chunk)
                    for row in cur.fetchall():
                        metadata[row["rule_id"]] = dict(row)
                return metadata
        finally:
            conn.close()

    def _evaluate_rules(self, rules: List[Dict], metadata: Dict) -> List[Dict]:
        """Evaluate rules against log_events using batch strategy.

        Performance: instead of 1 SQL per rule (17K queries), we:
          1. Pre-load all distinct (service, operation) pairs from log_events
          2. Match simple rules (service=X AND operation=Y) in Python
          3. Batch-query events for matched (service, operation) pairs
          4. Only run individual SQL for complex rules (contains, starts_with)
        """
        conn = self._get_log_conn()
        findings = []
        rules_matched = 0

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Step 1: Get all (service, operation) pairs in current events
                cur.execute("""
                    SELECT DISTINCT service, operation
                    FROM log_events WHERE tenant_id = %s
                """, (self.tenant_id,))
                event_pairs = {(r["service"], r["operation"]) for r in cur.fetchall()}
                logger.info(f"Found {len(event_pairs)} distinct (service, operation) pairs in log_events")

                # Step 2: Classify rules as simple or complex
                simple_rules = {}  # (service, operation) → [rules]
                complex_rules = []

                for rule in rules:
                    config = rule.get("check_config", {})
                    if isinstance(config, str):
                        config = json.loads(config)
                    conditions = config.get("conditions", {})
                    if not conditions:
                        continue

                    svc_op = self._extract_simple_match(conditions)
                    if svc_op:
                        svc, op = svc_op
                        if (svc, op) in event_pairs:
                            simple_rules.setdefault((svc, op), []).append(rule)
                    else:
                        complex_rules.append(rule)

                logger.info(
                    f"Rule classification: {sum(len(v) for v in simple_rules.values())} simple "
                    f"({len(simple_rules)} groups), {len(complex_rules)} complex"
                )

                # Step 3: Batch-query for simple rules grouped by (service, operation)
                event_cols = """event_id, event_time, service, operation, outcome,
                               actor_principal, actor_principal_type, actor_ip,
                               resource_uid, resource_type, resource_name,
                               account_id, resource_region AS region,
                               severity AS event_severity, risk_indicators"""

                for (svc, op), group_rules in simple_rules.items():
                    cur.execute(f"""
                        SELECT {event_cols} FROM log_events
                        WHERE tenant_id = %s AND service = %s AND operation = %s
                        LIMIT 1000
                    """, (self.tenant_id, svc, op))
                    rows = cur.fetchall()
                    if not rows:
                        continue

                    for rule in group_rules:
                        rules_matched += 1
                        meta = metadata.get(rule["rule_id"], {})
                        for row in rows:
                            findings.append(self._create_finding(rule, meta, dict(row)))

                # Step 4: Individual SQL for complex rules
                for rule in complex_rules:
                    config = rule.get("check_config", {})
                    if isinstance(config, str):
                        config = json.loads(config)
                    conditions = config.get("conditions", {})

                    where_clause, params = self._build_where(conditions)
                    if not where_clause:
                        continue

                    sql = f"""
                        SELECT {event_cols} FROM log_events
                        WHERE tenant_id = %s AND {where_clause}
                        LIMIT 1000
                    """
                    try:
                        cur.execute(sql, [self.tenant_id] + params)
                        rows = cur.fetchall()
                    except Exception as exc:
                        logger.debug(f"Rule {rule['rule_id']} query failed: {exc}")
                        continue

                    if not rows:
                        continue

                    rules_matched += 1
                    meta = metadata.get(rule["rule_id"], {})
                    for row in rows:
                        findings.append(self._create_finding(rule, meta, dict(row)))

            logger.info(f"Rules matched: {rules_matched}/{len(rules)}, findings: {len(findings)}")
        finally:
            conn.close()

        return findings

    def _extract_simple_match(self, conditions: Dict) -> Optional[tuple]:
        """Check if rule is a simple service+operation equals match.

        Returns (service, operation) tuple if simple, None if complex.
        """
        conds = conditions.get("all", [conditions] if "field" in conditions else [])
        svc = None
        op = None
        for c in conds:
            if c.get("op") != "equals":
                return None  # complex operator
            field = c.get("field", "")
            if field == "service":
                svc = c.get("value")
            elif field == "operation":
                op = c.get("value")
            else:
                return None  # extra field condition = complex
        if svc and op:
            return (svc, op)
        return None

    def _build_where(self, conditions: Dict) -> tuple:
        """Convert rule conditions to SQL WHERE clause.

        Supports: {all: [{field, op, value}]}, {field, op, value}
        """
        if "all" in conditions:
            parts = []
            params = []
            for cond in conditions["all"]:
                clause, p = self._single_condition(cond)
                if clause:
                    parts.append(clause)
                    params.extend(p)
            if parts:
                return " AND ".join(parts), params
            return "", []

        return self._single_condition(conditions)

    def _single_condition(self, cond: Dict) -> tuple:
        """Convert single {field, op, value} to SQL."""
        field = cond.get("field", "")
        op = cond.get("op", "")
        value = cond.get("value", "")

        # Map rule field names to DB column names
        col_map = {
            "service": "service",
            "operation": "operation",
            "outcome": "outcome",
            "error_code": "error_code",
            "source_type": "source_type",
            "actor.principal": "actor_principal",
            "actor.principal_type": "actor_principal_type",
            "actor.ip_address": "actor_ip",
            "actor.account_id": "actor_account_id",
            "resource.uid": "resource_uid",
            "resource.type": "resource_type",
            "resource.name": "resource_name",
            "resource.region": "resource_region",
            "severity": "severity",
            # Network fields (VPC Flow)
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "network.src_port": "src_port",
            "network.dst_port": "dst_port",
            "network.protocol": "protocol",
            "network.flow_action": "flow_action",
        }

        col = col_map.get(field, field)
        # Security: only allow known columns
        if col not in col_map.values():
            return "", []

        if op == "equals":
            return f"{col} = %s", [value]
        elif op == "not_equals":
            return f"{col} != %s", [value]
        elif op == "in":
            if isinstance(value, list):
                placeholders = ",".join(["%s"] * len(value))
                return f"{col} IN ({placeholders})", value
            return "", []
        elif op == "contains":
            return f"{col} LIKE %s", [f"%{value}%"]
        elif op == "starts_with":
            return f"{col} LIKE %s", [f"{value}%"]

        return "", []

    def _create_finding(self, rule: Dict, meta: Dict, event: Dict) -> Dict:
        """Create a ciem_finding from a matched rule + event."""
        rule_id = rule["rule_id"]
        event_id = event.get("event_id", "")

        finding_id = hashlib.sha256(
            f"{rule_id}|{event_id}|{self.scan_run_id}".encode()
        ).hexdigest()[:20]
        finding_id = f"ciem_{finding_id}"

        return {
            "finding_id": finding_id,
            "scan_run_id": self.scan_run_id,
            "tenant_id": self.tenant_id,
            "rule_id": rule_id,
            "rule_source": rule.get("check_type", "log"),
            "severity": meta.get("severity", event.get("event_severity", "medium")),
            "status": "OPEN",
            "primary_engine": meta.get("primary_engine", "threat_engine"),
            "engines": meta.get("engines", []),
            "action_category": meta.get("action_category", ""),
            "resource_uid": event.get("resource_uid", ""),
            "resource_type": event.get("resource_type", ""),
            "resource_name": event.get("resource_name", ""),
            "account_id": event.get("account_id", ""),
            "region": event.get("region", ""),
            "provider": self.provider,
            "actor_principal": event.get("actor_principal", ""),
            "actor_principal_type": event.get("actor_principal_type", ""),
            "actor_ip": event.get("actor_ip", ""),
            "event_id": event_id,
            "event_time": event.get("event_time"),
            "service": event.get("service", ""),
            "operation": event.get("operation", ""),
            "title": meta.get("title", f"Detection: {rule_id}"),
            "description": meta.get("description", ""),
            "remediation": meta.get("remediation", ""),
            "mitre_tactics": json.dumps(meta.get("mitre_tactics") or []),
            "mitre_techniques": json.dumps(meta.get("mitre_techniques") or []),
            "risk_indicators": event.get("risk_indicators", []),
            "compliance_frameworks": json.dumps(meta.get("compliance_frameworks") or {}),
            "finding_data": json.dumps({
                "event_operation": event.get("operation"),
                "event_outcome": event.get("outcome"),
                "event_severity": event.get("event_severity"),
                "matched_rule": rule_id,
            }),
        }

    def _write_findings(self, findings: List[Dict]):
        """Write findings to ciem_findings table."""
        if not findings:
            return

        conn = self._get_ciem_conn()
        try:
            # Ensure tenant
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (self.tenant_id, self.tenant_id),
                )

            values = []
            for f in findings:
                values.append((
                    f["finding_id"], f["scan_run_id"], f["tenant_id"],
                    f["rule_id"], f["rule_source"],
                    f["severity"], f["status"],
                    f["primary_engine"], f["engines"], f["action_category"],
                    f["resource_uid"], f["resource_type"], f["resource_name"],
                    f["account_id"], f["region"], f["provider"],
                    f["actor_principal"], f["actor_principal_type"], f["actor_ip"],
                    f["event_id"], f["event_time"], f["service"], f["operation"],
                    f["title"], f["description"], f["remediation"],
                    f["mitre_tactics"], f["mitre_techniques"],
                    f["risk_indicators"], f["compliance_frameworks"],
                    f["finding_data"],
                ))

            with conn.cursor() as cur:
                execute_values(cur, """
                    INSERT INTO ciem_findings (
                        finding_id, scan_run_id, tenant_id,
                        rule_id, rule_source,
                        severity, status,
                        primary_engine, engines, action_category,
                        resource_uid, resource_type, resource_name,
                        account_id, region, provider,
                        actor_principal, actor_principal_type, actor_ip,
                        event_id, event_time, service, operation,
                        title, description, remediation,
                        mitre_tactics, mitre_techniques,
                        risk_indicators, compliance_frameworks,
                        finding_data
                    ) VALUES %s
                    ON CONFLICT (finding_id) DO NOTHING
                """, values, page_size=500)
            conn.commit()
            logger.info(f"Wrote {len(findings)} findings to ciem_findings")
        finally:
            conn.close()

    def _write_report(self, findings: List[Dict], started: datetime, completed: datetime) -> Dict:
        """Write scan summary to ciem_report."""
        by_severity = defaultdict(int)
        by_engine = defaultdict(int)
        by_category = defaultdict(int)

        for f in findings:
            by_severity[f["severity"]] += 1
            by_engine[f["primary_engine"]] += 1
            by_category[f["action_category"]] += 1

        stats = {
            "scan_run_id": self.scan_run_id,
            "total_findings": len(findings),
            "by_severity": dict(by_severity),
            "by_engine": dict(by_engine),
            "by_category": dict(by_category),
            "duration_seconds": (completed - started).total_seconds(),
        }

        conn = self._get_ciem_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO ciem_report (
                        scan_run_id, tenant_id, provider, status,
                        started_at, completed_at,
                        total_findings, findings_by_severity,
                        findings_by_engine, findings_by_category
                    ) VALUES (%s, %s, %s, 'completed', %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_run_id) DO UPDATE SET
                        status = 'completed',
                        completed_at = EXCLUDED.completed_at,
                        total_findings = EXCLUDED.total_findings,
                        findings_by_severity = EXCLUDED.findings_by_severity,
                        findings_by_engine = EXCLUDED.findings_by_engine,
                        findings_by_category = EXCLUDED.findings_by_category
                """, (
                    self.scan_run_id, self.tenant_id, self.provider,
                    started, completed, len(findings),
                    json.dumps(dict(by_severity)),
                    json.dumps(dict(by_engine)),
                    json.dumps(dict(by_category)),
                ))
            conn.commit()
        finally:
            conn.close()

        return stats
