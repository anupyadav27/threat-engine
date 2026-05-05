"""
CIEM L1 Rule Evaluator — in-memory evaluation against NormalizedEvent stream.

No log_events table. Rules are loaded once at startup, then evaluated
against each NormalizedEvent as it comes off the parser — zero DB roundtrips
per event.

Reads:
  - rule_checks WHERE check_type = 'log'   (conditions)
  - rule_metadata WHERE rule_source = 'log' (enrichment)

Writes:
  - ciem_findings  (matched events)
  - ciem_report    (scan summary)
"""

import hashlib
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

from ..normalizer.schema import NormalizedEvent

logger = logging.getLogger(__name__)

# ── Field accessor map ────────────────────────────────────────────────────────
# Maps rule condition field names → callables that extract a string value
# from a NormalizedEvent. Returns None if the field is absent.

def _str(v) -> Optional[str]:
    return str(v) if v is not None else None

_FIELD_ACCESSORS: Dict[str, Callable[[NormalizedEvent], Optional[str]]] = {
    "service":                lambda e: _str(e.service),
    "operation":              lambda e: _str(e.operation),
    "outcome":                lambda e: _str(e.outcome.value if hasattr(e.outcome, "value") else e.outcome),
    "error_code":             lambda e: _str(e.error_code),
    "source_type":            lambda e: _str(e.source_type),
    "severity":               lambda e: _str(e.severity.value if hasattr(e.severity, "value") else e.severity),
    "actor.principal":        lambda e: _str(e.actor.principal) if e.actor else None,
    "actor.principal_type":   lambda e: _str(e.actor.principal_type) if e.actor else None,
    "actor.ip_address":       lambda e: _str(e.actor.ip_address) if e.actor else None,
    "actor.account_id":       lambda e: _str(e.actor.account_id) if e.actor else None,
    "resource.uid":           lambda e: _str(e.resource.uid) if e.resource else None,
    "resource.type":          lambda e: _str(e.resource.resource_type) if e.resource else None,
    "resource.name":          lambda e: _str(e.resource.name) if e.resource else None,
    "resource.region":        lambda e: _str(e.resource.region) if e.resource else None,
    "network.src_ip":         lambda e: _str(e.network.src_ip) if e.network else None,
    "network.dst_ip":         lambda e: _str(e.network.dst_ip) if e.network else None,
    "network.src_port":       lambda e: _str(e.network.src_port) if e.network else None,
    "network.dst_port":       lambda e: _str(e.network.dst_port) if e.network else None,
    "network.protocol":       lambda e: _str(e.network.protocol) if e.network else None,
    "network.flow_action":    lambda e: _str(e.network.flow_action) if e.network else None,
}


def _match(field_val: Optional[str], op: str, value: Any) -> bool:
    """Apply a single operator against a field value extracted from a NormalizedEvent."""
    if field_val is None:
        return op in ("is_null",)

    v = field_val  # already a str
    if op == "equals":
        return v == str(value)
    if op == "not_equals":
        return v != str(value)
    if op == "in":
        return isinstance(value, list) and v in [str(x) for x in value]
    if op == "not_in":
        return isinstance(value, list) and v not in [str(x) for x in value]
    if op == "contains":
        return str(value) in v
    if op == "not_contains":
        return str(value) not in v
    if op == "starts_with":
        return v.startswith(str(value))
    if op == "starts_with_any":
        return isinstance(value, list) and any(v.startswith(str(x)) for x in value)
    if op == "is_not_null":
        return True
    if op == "is_null":
        return False
    return False


def _compile_conditions(conditions: Dict) -> Optional[Callable[[NormalizedEvent], bool]]:
    """Compile a rule's condition tree into a single callable matcher.

    Returns None if the conditions are empty or unrecognised.
    """
    if not conditions:
        return None

    if "all" in conditions:
        sub = [_compile_single(c) for c in conditions["all"] if "field" in c]
        sub = [s for s in sub if s]
        if not sub:
            return None
        return lambda e, _sub=sub: all(fn(e) for fn in _sub)

    if "any" in conditions:
        sub = [_compile_single(c) for c in conditions["any"] if "field" in c]
        sub = [s for s in sub if s]
        if not sub:
            return None
        return lambda e, _sub=sub: any(fn(e) for fn in _sub)

    if "field" in conditions:
        return _compile_single(conditions)

    return None


def _compile_single(cond: Dict) -> Optional[Callable[[NormalizedEvent], bool]]:
    field = cond.get("field", "")
    op = cond.get("op", "")
    value = cond.get("value", "")
    accessor = _FIELD_ACCESSORS.get(field)
    if accessor is None:
        # Fall back to raw_event for provider-specific fields (e.g. K8s: verb, resource, namespace)
        accessor = lambda e, _f=field: _str(e.raw_event.get(_f)) if e.raw_event else None
    return lambda e, _acc=accessor, _op=op, _val=value: _match(_acc(e), _op, _val)


# ── Main evaluator ────────────────────────────────────────────────────────────

class CIEMRuleEvaluator:
    """In-memory L1 rule evaluator.

    Usage (from run_scan.py):
        evaluator = CIEMRuleEvaluator(scan_run_id, tenant_id, provider)
        evaluator.load()          # one DB round-trip at start of scan
        for event in stream:
            findings += evaluator.evaluate_event(event)
        evaluator.flush(findings)  # one batch write at end
    """

    def __init__(self, scan_run_id: str, tenant_id: str, provider: str = "aws"):
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.provider = provider
        self._matchers: List[Tuple[Dict, Dict, Callable]] = []  # (rule, meta, matcher_fn)

    # ── DB helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _pw(*keys: str) -> str:
        for k in keys:
            v = os.getenv(k)
            if v:
                return v
        return os.getenv("DISCOVERIES_DB_PASSWORD", "")

    def _get_check_conn(self):
        return psycopg2.connect(
            host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
            password=self._pw("CHECK_DB_PASSWORD", "DB_PASSWORD"),
        )

    def _get_ciem_conn(self):
        return psycopg2.connect(
            host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
            user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
            password=self._pw("CIEM_DB_PASSWORD", "INVENTORY_DB_PASSWORD", "DB_PASSWORD"),
        )

    # ── Load rules (once per scan) ────────────────────────────────────────────

    def load(self) -> int:
        """Load + compile all log rules from DB. Returns number of rules compiled."""
        conn = self._get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT rc.rule_id, rc.service, rc.check_type, rc.check_config,
                           rm.severity, rm.title, rm.description, rm.remediation,
                           rm.subcategory, rm.threat_category,
                           rm.mitre_tactics, rm.mitre_techniques,
                           rm.compliance_frameworks,
                           rm.remediation_effort
                    FROM rule_checks rc
                    LEFT JOIN rule_metadata rm USING (rule_id)
                    WHERE rc.check_type = 'log' AND rc.is_active = true
                      AND (rc.provider = %s OR rc.provider IS NULL)
                """, (self.provider,))
                rows = cur.fetchall()
        finally:
            conn.close()

        compiled = 0
        for row in rows:
            config = row["check_config"] or {}
            if isinstance(config, str):
                config = json.loads(config)
            conditions = config.get("conditions", {})
            matcher = _compile_conditions(conditions)
            if matcher is None:
                continue
            self._matchers.append((dict(row), matcher))
            compiled += 1

        logger.info(f"L1: compiled {compiled}/{len(rows)} log rules for provider={self.provider}")
        return compiled

    # ── Per-event evaluation ──────────────────────────────────────────────────

    def evaluate_event(self, event: NormalizedEvent) -> List[Dict]:
        """Evaluate all compiled rules against one event. Returns list of findings."""
        results = []
        for rule, matcher in self._matchers:
            try:
                if matcher(event):
                    results.append(self._make_finding(rule, event))
            except Exception:
                pass  # never let a bad rule crash the stream
        return results

    def _make_finding(self, rule: Dict, event: NormalizedEvent) -> Dict:
        rule_id = rule["rule_id"]
        event_id = event.event_id or ""

        finding_id = hashlib.sha256(
            f"{rule_id}|{event_id}".encode()
        ).hexdigest()[:20]

        actor = event.actor
        resource = event.resource
        outcome_val = event.outcome.value if hasattr(event.outcome, "value") else str(event.outcome or "")

        return {
            "finding_id":          f"ciem_{finding_id}",
            "scan_run_id":         self.scan_run_id,
            "tenant_id":           self.tenant_id,
            "rule_id":             rule_id,
            "rule_source":         "log",
            "severity":            rule.get("severity") or "medium",
            "status":              "OPEN",
            "primary_engine":      "ciem",
            "engines":             ["ciem"],
            "action_category":     rule.get("subcategory") or rule.get("threat_category") or "",
            "resource_uid":        (resource.uid if resource else "") or "",
            "resource_type":       (resource.resource_type if resource else "") or "",
            "resource_name":       (resource.name if resource else "") or "",
            "account_id":          (actor.account_id if actor else "") or "",
            "region":              (resource.region if resource else "") or "",
            "provider":            self.provider,
            "actor_principal":     (actor.principal if actor else "") or "",
            "actor_principal_type":(actor.principal_type if actor else "") or "",
            "actor_ip":            (actor.ip_address if actor else "") or "",
            "event_id":            event_id,
            "event_time":          event.event_time,
            "service":             event.service or "",
            "operation":           event.operation or "",
            "title":               rule.get("title") or f"Detection: {rule_id}",
            "description":         rule.get("description") or "",
            "remediation":         rule.get("remediation") or "",
            "mitre_tactics":       json.dumps(rule.get("mitre_tactics") or []),
            "mitre_techniques":    json.dumps(rule.get("mitre_techniques") or []),
            "risk_indicators":     [],
            "compliance_frameworks": json.dumps(rule.get("compliance_frameworks") or {}),
            "finding_data":        json.dumps({
                "event_operation":   event.operation,
                "event_outcome":     outcome_val,
                "matched_rule":      rule_id,
                "remediation_effort": rule.get("remediation_effort", "medium"),
            }),
        }

    # ── Batch write (once per scan) ───────────────────────────────────────────

    def flush(self, findings: List[Dict], started: datetime, completed: datetime) -> Dict:
        """Write all findings + report to DB. Called once at end of scan."""
        self._write_findings(findings)
        return self._write_report(findings, started, completed)

    def _write_findings(self, findings: List[Dict]):
        if not findings:
            return
        conn = self._get_ciem_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (self.tenant_id, self.tenant_id),
                )
            values = [
                (
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
                )
                for f in findings
            ]
            with conn.cursor() as cur:
                execute_values(cur, """
                    INSERT INTO ciem_findings (
                        finding_id, scan_run_id, tenant_id,
                        rule_id, rule_source, severity, status,
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
            logger.info(f"L1: wrote {len(findings)} findings to ciem_findings")
        finally:
            conn.close()

    def _write_report(self, findings: List[Dict], started: datetime, completed: datetime) -> Dict:
        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        for f in findings:
            by_severity[f["severity"]] += 1
            by_category[f["action_category"]] += 1

        stats = {
            "scan_run_id":    self.scan_run_id,
            "total_findings": len(findings),
            "by_severity":    dict(by_severity),
            "by_category":    dict(by_category),
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
                    json.dumps({"ciem": len(findings)}),
                    json.dumps(dict(by_category)),
                ))
            conn.commit()
        finally:
            conn.close()

        return stats
