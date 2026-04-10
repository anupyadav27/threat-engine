"""
L2 Correlation Evaluator — detects multi-event attack patterns.

Reads L1 findings from ciem_findings + raw events from log_events,
groups by actor/resource, checks time-windowed sequences, and writes
new high-severity correlation findings.

Each scenario defines:
  - sequence: ordered list of L1 rule_ids (any_of / rule_id)
  - match_by: field to group events (actor.principal, actor.ip_address, resource.uid)
  - time_window_minutes: max time between first and last event
  - min_events: minimum events needed to trigger

Performance: runs AFTER L1 evaluation, uses SQL aggregation not per-event loops.
"""

import hashlib
import json
import logging
import os
import yaml
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

logger = logging.getLogger(__name__)

# Map YAML match_by → DB column names
_MATCH_FIELD_MAP = {
    "actor.principal": "actor_principal",
    "actor.ip_address": "actor_ip",
    "resource.uid": "resource_uid",
    "account_id": "account_id",
}


class CorrelationEvaluator:
    """Evaluate L2 correlation scenarios against L1 findings."""

    def __init__(self, scan_run_id: str, tenant_id: str, provider: str = "aws"):
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.provider = provider

    def _get_ciem_conn(self):
        return psycopg2.connect(
            host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
            user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CIEM_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD",
                     os.getenv("DB_PASSWORD", ""))),
        )

    def _get_log_conn(self):
        return psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )

    def load_scenarios(self) -> List[Dict]:
        """Load L2 scenarios from YAML + DB."""
        scenarios = []
        # Load from YAML files in rules/ directory
        rules_dir = Path(__file__).parent.parent.parent / "rules"
        for f in rules_dir.glob("l2_*.yaml"):
            try:
                data = yaml.safe_load(f.read_text()) or []
                if isinstance(data, dict):
                    data = data.get("scenarios", data.get("rules", []))
                for s in data:
                    if s.get("scenario_id"):
                        scenarios.append(s)
            except Exception as exc:
                logger.warning(f"Failed to load {f}: {exc}")

        logger.info(f"Loaded {len(scenarios)} L2 correlation scenarios")
        return scenarios

    def evaluate(self) -> Dict[str, Any]:
        """Run L2 correlation on L1 findings. Returns stats."""
        started = datetime.now(timezone.utc)
        scenarios = self.load_scenarios()
        if not scenarios:
            return {"total_findings": 0, "scenarios_matched": 0}

        # Load L1 findings for this scan
        findings_by_rule = self._load_l1_findings()
        if not findings_by_rule:
            logger.info("No L1 findings to correlate")
            return {"total_findings": 0, "scenarios_matched": 0}

        logger.info(
            f"Correlating: {sum(len(v) for v in findings_by_rule.values())} L1 findings "
            f"across {len(findings_by_rule)} rules"
        )

        # Evaluate each scenario
        corr_findings = []
        scenarios_matched = 0

        for scenario in scenarios:
            matched = self._evaluate_scenario(scenario, findings_by_rule)
            if matched:
                corr_findings.extend(matched)
                scenarios_matched += 1

        # Write correlation findings
        if corr_findings:
            self._write_findings(corr_findings)

        completed = datetime.now(timezone.utc)
        stats = {
            "total_findings": len(corr_findings),
            "scenarios_evaluated": len(scenarios),
            "scenarios_matched": scenarios_matched,
            "duration_seconds": (completed - started).total_seconds(),
        }
        logger.info(
            f"L2 correlation: {len(corr_findings)} findings from "
            f"{scenarios_matched}/{len(scenarios)} scenarios in "
            f"{stats['duration_seconds']:.1f}s"
        )
        return stats

    def _load_l1_findings(self) -> Dict[str, List[Dict]]:
        """Load L1 findings grouped by rule_id."""
        conn = self._get_ciem_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT finding_id, rule_id, event_time,
                           actor_principal, actor_ip,
                           resource_uid, resource_type, resource_name,
                           account_id, region, service, operation,
                           severity, title
                    FROM ciem_findings
                    WHERE scan_run_id = %s AND tenant_id = %s
                    AND rule_source != 'correlation'
                    ORDER BY event_time
                """, (self.scan_run_id, self.tenant_id))
                rows = cur.fetchall()

            by_rule = defaultdict(list)
            for row in rows:
                by_rule[row["rule_id"]].append(dict(row))
            return dict(by_rule)
        finally:
            conn.close()

    def _evaluate_scenario(
        self, scenario: Dict, findings_by_rule: Dict[str, List[Dict]]
    ) -> List[Dict]:
        """Check if a scenario's sequence is satisfied in the findings."""
        scenario_id = scenario.get("scenario_id", "")
        sequence = scenario.get("sequence", [])
        match_by = scenario.get("match_by", "actor.principal")
        window_min = scenario.get("time_window_minutes", 60)
        min_events = scenario.get("min_events", 2)

        match_col = _MATCH_FIELD_MAP.get(match_by, match_by)

        # Collect all findings that match any step in the sequence
        relevant_findings = []
        step_rule_map = {}  # rule_id → step_index

        for step_idx, step in enumerate(sequence):
            is_optional = False
            rule_ids = []

            if isinstance(step, dict):
                if "optional" in step:
                    is_optional = True
                    rule_ids = step["optional"]
                elif "any_of" in step:
                    rule_ids = step["any_of"]
                elif "rule_id" in step:
                    rule_ids = [step["rule_id"]]
            elif isinstance(step, str):
                rule_ids = [step]

            for rid in rule_ids:
                if rid in findings_by_rule:
                    for f in findings_by_rule[rid]:
                        f["_step_idx"] = step_idx
                        f["_step_optional"] = is_optional
                        f["_step_min_count"] = step.get("min_count", 1) if isinstance(step, dict) else 1
                        relevant_findings.append(f)
                    step_rule_map[rid] = step_idx

        if not relevant_findings:
            return []

        # Group by match field
        groups = defaultdict(list)
        for f in relevant_findings:
            key = f.get(match_col, "") or ""
            if key:
                groups[key].append(f)

        # Check each group for sequence satisfaction
        corr_findings = []
        window = timedelta(minutes=window_min)

        for group_key, group_findings in groups.items():
            if not group_key:
                continue

            # Sort by time
            group_findings.sort(key=lambda f: f.get("event_time") or datetime.min)

            # Check which steps are satisfied
            steps_satisfied = defaultdict(int)
            for f in group_findings:
                steps_satisfied[f["_step_idx"]] += 1

            # Count required (non-optional) steps
            required_steps = set()
            for step_idx, step in enumerate(sequence):
                if isinstance(step, dict) and "optional" in step:
                    continue
                required_steps.add(step_idx)

            satisfied_required = sum(1 for s in required_steps if steps_satisfied.get(s, 0) > 0)

            # Check min_count for counted steps
            count_ok = True
            for f in group_findings:
                mc = f.get("_step_min_count", 1)
                if mc > 1 and steps_satisfied.get(f["_step_idx"], 0) < mc:
                    count_ok = False

            # Need all required steps + min total events + within time window
            total_events = len(group_findings)
            if satisfied_required < len(required_steps):
                continue
            if total_events < min_events:
                continue
            if not count_ok:
                continue

            # Check time window
            times = [f["event_time"] for f in group_findings if f.get("event_time")]
            if len(times) >= 2:
                time_span = max(times) - min(times)
                if time_span > window:
                    continue

            # Scenario matched — create correlation finding
            corr_finding = self._create_correlation_finding(
                scenario, group_key, match_by, group_findings
            )
            corr_findings.append(corr_finding)

        return corr_findings

    def _create_correlation_finding(
        self, scenario: Dict, group_key: str, match_by: str,
        contributing_findings: List[Dict],
    ) -> Dict:
        """Create a correlation finding from a matched scenario."""
        scenario_id = scenario["scenario_id"]
        finding_id = hashlib.sha256(
            f"corr|{scenario_id}|{group_key}|{self.scan_run_id}".encode()
        ).hexdigest()[:20]
        finding_id = f"corr_{finding_id}"

        # Use the earliest and latest event times
        times = [f["event_time"] for f in contributing_findings if f.get("event_time")]
        first_time = min(times) if times else None
        last_time = max(times) if times else None

        # Collect unique contributing rule_ids
        contributing_rules = list({f["rule_id"] for f in contributing_findings})

        # Collect unique contributing finding_ids
        contributing_ids = [f["finding_id"] for f in contributing_findings]

        # Get representative fields from first finding
        first = contributing_findings[0]

        return {
            "finding_id": finding_id,
            "scan_run_id": self.scan_run_id,
            "tenant_id": self.tenant_id,
            "rule_id": scenario_id,
            "rule_source": "correlation",
            "severity": scenario.get("severity", "high"),
            "status": "OPEN",
            "primary_engine": scenario.get("engine", "threat_engine"),
            "engines": [scenario.get("engine", "threat_engine")],
            "action_category": "correlation",
            "resource_uid": first.get("resource_uid", ""),
            "resource_type": first.get("resource_type", ""),
            "resource_name": first.get("resource_name", ""),
            "account_id": first.get("account_id", ""),
            "region": first.get("region", ""),
            "provider": self.provider,
            "actor_principal": first.get("actor_principal", ""),
            "actor_principal_type": "",
            "actor_ip": first.get("actor_ip", ""),
            "event_id": "",
            "event_time": first_time,
            "service": "",
            "operation": "",
            "title": scenario.get("title", f"Correlation: {scenario_id}"),
            "description": scenario.get("description", ""),
            "remediation": "",
            "mitre_tactics": json.dumps(scenario.get("mitre_tactics", [])),
            "mitre_techniques": json.dumps(scenario.get("mitre_techniques", [])),
            "risk_indicators": [],
            "compliance_frameworks": "{}",
            "finding_data": json.dumps({
                "scenario_id": scenario_id,
                "match_by": match_by,
                "match_key": group_key,
                "contributing_findings": contributing_ids[:50],
                "contributing_rules": contributing_rules,
                "event_count": len(contributing_findings),
                "time_window_minutes": scenario.get("time_window_minutes", 60),
                "first_event": first_time.isoformat() if first_time else None,
                "last_event": last_time.isoformat() if last_time else None,
            }, default=str),
        }

    def _write_findings(self, findings: List[Dict]):
        """Write correlation findings to ciem_findings."""
        if not findings:
            return

        conn = self._get_ciem_conn()
        try:
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
                """, values, page_size=100)
            conn.commit()
            logger.info(f"Wrote {len(findings)} correlation findings")
        finally:
            conn.close()
