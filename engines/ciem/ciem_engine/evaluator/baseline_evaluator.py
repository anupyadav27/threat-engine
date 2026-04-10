"""
L3 Baseline Evaluator — behavioral anomaly detection.

Two phases:
  1. COMPUTE: Aggregate historical metrics per entity per day → compute mean/stddev
  2. DETECT:  Compare today's metrics against baseline → flag anomalies

Baselines are stored in ciem_baselines table and recomputed periodically.
Anomalies become ciem_findings with rule_source='baseline'.

Each baseline profile defines:
  - entity_type: what to group by (actor.principal, resource.uid, account_id)
  - metrics: what to measure (counts, distinct counts, ratios)
  - window_days: how many days of history to use
  - anomaly_threshold: how many stddev = anomaly (2 or 3)
"""

import hashlib
import json
import logging
import math
import os
import yaml
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor, execute_values

logger = logging.getLogger(__name__)

# Map entity_type → DB column
_ENTITY_COL = {
    "actor.principal": "actor_principal",
    "actor.ip_address": "actor_ip",
    "resource.uid": "resource_uid",
    "account_id": "account_id",
}


class BaselineEvaluator:
    """Compute behavioral baselines and detect anomalies."""

    def __init__(self, scan_run_id: str, tenant_id: str, provider: str = "aws"):
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.provider = provider

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
            password=os.getenv("CIEM_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD",
                     os.getenv("DB_PASSWORD", ""))),
        )

    def load_profiles(self) -> List[Dict]:
        """Load L3 baseline profiles from YAML."""
        profiles = []
        rules_dir = Path(__file__).parent.parent.parent / "rules"
        for f in rules_dir.glob("l3_*.yaml"):
            try:
                data = yaml.safe_load(f.read_text()) or []
                if isinstance(data, dict):
                    data = data.get("baselines", data.get("profiles", []))
                for p in data:
                    if p.get("baseline_id"):
                        profiles.append(p)
            except Exception as exc:
                logger.warning(f"Failed to load {f}: {exc}")
        logger.info(f"Loaded {len(profiles)} L3 baseline profiles")
        return profiles

    def ensure_table(self):
        """Create ciem_baselines table if not exists."""
        conn = self._get_ciem_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS ciem_baselines (
                        baseline_id VARCHAR(100),
                        entity_key VARCHAR(500),
                        metric_name VARCHAR(100),
                        tenant_id VARCHAR(100),
                        mean DOUBLE PRECISION,
                        stddev DOUBLE PRECISION,
                        data_points INTEGER,
                        min_val DOUBLE PRECISION,
                        max_val DOUBLE PRECISION,
                        last_computed TIMESTAMPTZ DEFAULT NOW(),
                        PRIMARY KEY (baseline_id, entity_key, metric_name, tenant_id)
                    )
                """)
            conn.commit()
        finally:
            conn.close()

    def evaluate(self) -> Dict[str, Any]:
        """Full L3 pipeline: compute baselines → detect anomalies."""
        started = datetime.now(timezone.utc)
        self.ensure_table()

        profiles = self.load_profiles()
        if not profiles:
            return {"total_findings": 0, "baselines_computed": 0}

        total_baselines = 0
        total_anomalies = 0
        all_findings = []

        for profile in profiles:
            baseline_id = profile["baseline_id"]
            entity_type = profile["entity_type"]
            entity_col = _ENTITY_COL.get(entity_type, entity_type)
            window_days = profile.get("window_days", 14)
            min_data_points = profile.get("min_data_points", 5)
            metrics = profile.get("metrics", [])

            if not metrics:
                continue

            # Phase 1: Compute baselines from historical data
            source_filter = None
            for m in metrics:
                q = m.get("query", "")
                if "vpc_flow" in q:
                    source_filter = "vpc_flow"
                    break

            historical = self._compute_historical_metrics(
                entity_col, metrics, window_days, source_filter
            )

            if not historical:
                logger.debug(f"No historical data for {baseline_id}")
                continue

            # Store baselines
            baselines_stored = self._store_baselines(
                baseline_id, historical, min_data_points
            )
            total_baselines += baselines_stored

            # Phase 2: Compute today's metrics
            today_metrics = self._compute_today_metrics(
                entity_col, metrics, source_filter
            )

            if not today_metrics:
                continue

            # Phase 3: Detect anomalies
            findings = self._detect_anomalies(
                profile, historical, today_metrics
            )
            all_findings.extend(findings)
            total_anomalies += len(findings)

        # Write anomaly findings
        if all_findings:
            self._write_findings(all_findings)

        duration = (datetime.now(timezone.utc) - started).total_seconds()
        stats = {
            "total_findings": total_anomalies,
            "baselines_computed": total_baselines,
            "profiles_evaluated": len(profiles),
            "duration_seconds": duration,
        }
        logger.info(
            f"L3 baselines: {total_baselines} baselines, {total_anomalies} anomalies "
            f"from {len(profiles)} profiles in {duration:.1f}s"
        )
        return stats

    def _compute_historical_metrics(
        self, entity_col: str, metrics: List[Dict],
        window_days: int, source_filter: str = None,
    ) -> Dict[str, Dict[str, List[float]]]:
        """Compute daily metric values per entity over the historical window.

        Returns: {entity_key: {metric_name: [day1_val, day2_val, ...]}}
        """
        conn = self._get_log_conn()
        result = defaultdict(lambda: defaultdict(list))

        try:
            with conn.cursor() as cur:
                for metric in metrics:
                    name = metric["name"]
                    sql, params = self._build_metric_query(
                        entity_col, metric, window_days, source_filter, is_today=False
                    )
                    if not sql:
                        continue

                    try:
                        cur.execute(sql, params)
                        for row in cur.fetchall():
                            entity_key = row[0] or ""
                            day_val = float(row[1]) if row[1] is not None else 0.0
                            if entity_key:
                                result[entity_key][name].append(day_val)
                    except Exception as exc:
                        logger.debug(f"Historical metric {name} failed: {exc}")
        finally:
            conn.close()

        return dict(result)

    def _compute_today_metrics(
        self, entity_col: str, metrics: List[Dict],
        source_filter: str = None,
    ) -> Dict[str, Dict[str, float]]:
        """Compute today's metric values per entity.

        Returns: {entity_key: {metric_name: value}}
        """
        conn = self._get_log_conn()
        result = defaultdict(dict)

        try:
            with conn.cursor() as cur:
                for metric in metrics:
                    name = metric["name"]
                    sql, params = self._build_metric_query(
                        entity_col, metric, window_days=1,
                        source_filter=source_filter, is_today=True,
                    )
                    if not sql:
                        continue

                    try:
                        cur.execute(sql, params)
                        for row in cur.fetchall():
                            entity_key = row[0] or ""
                            val = float(row[1]) if row[1] is not None else 0.0
                            if entity_key:
                                result[entity_key][name] = val
                    except Exception as exc:
                        logger.debug(f"Today metric {name} failed: {exc}")
        finally:
            conn.close()

        return dict(result)

    def _build_metric_query(
        self, entity_col: str, metric: Dict,
        window_days: int, source_filter: str = None,
        is_today: bool = False,
    ) -> Tuple[str, list]:
        """Build SQL for a metric aggregation."""
        name = metric["name"]
        params = [self.tenant_id]

        source_clause = ""
        if source_filter:
            source_clause = " AND source_type = %s"
            params.append(source_filter)

        if is_today:
            time_clause = " AND event_time >= NOW() - INTERVAL '1 day'"
            group_by = entity_col
        else:
            time_clause = f" AND event_time >= NOW() - INTERVAL '{window_days} days' AND event_time < NOW() - INTERVAL '1 day'"
            group_by = f"{entity_col}, DATE(event_time)"

        where = f"tenant_id = %s{source_clause}{time_clause} AND {entity_col} IS NOT NULL AND {entity_col} != ''"

        # Build aggregation based on metric name patterns
        if name == "daily_api_count" or name == "daily_flow_count" or name == "daily_access_count" or name == "api_call_volume":
            agg = "COUNT(*)"
        elif name == "unique_operations" or name == "unique_services_used":
            agg = "COUNT(DISTINCT operation)" if "operation" in name else "COUNT(DISTINCT service)"
        elif name == "unique_source_ips" or name == "unique_accessors":
            agg = "COUNT(DISTINCT actor_ip)" if "ip" in name else "COUNT(DISTINCT actor_principal)"
        elif name == "unique_regions":
            agg = "COUNT(DISTINCT resource_region)"
        elif name == "unique_destination_ips":
            agg = "COUNT(DISTINCT dst_ip)"
        elif name == "unique_destination_ports":
            agg = "COUNT(DISTINCT dst_port)"
        elif name == "error_rate":
            agg = "COALESCE(SUM(CASE WHEN outcome = 'Failure' THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*), 0), 0)"
        elif name == "rejected_flow_ratio":
            agg = "COALESCE(SUM(CASE WHEN flow_action = 'REJECT' THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*), 0), 0)"
        elif name == "off_hours_access_ratio":
            agg = "COALESCE(SUM(CASE WHEN EXTRACT(HOUR FROM event_time) NOT BETWEEN 8 AND 18 THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*), 0), 0)"
        elif name == "bytes_transferred":
            agg = "COALESCE(SUM(COALESCE(bytes_in, 0) + COALESCE(bytes_out, 0)), 0)"
        elif name == "new_service_first_use":
            # Special: handled separately
            return "", []
        else:
            agg = "COUNT(*)"

        if is_today:
            sql = f"SELECT {entity_col}, {agg} FROM log_events WHERE {where} GROUP BY {entity_col}"
        else:
            sql = f"SELECT {entity_col}, {agg} FROM log_events WHERE {where} GROUP BY {group_by}"

        return sql, params

    def _store_baselines(
        self, baseline_id: str, historical: Dict[str, Dict[str, List[float]]],
        min_data_points: int,
    ) -> int:
        """Compute and store mean/stddev for each entity+metric."""
        conn = self._get_ciem_conn()
        rows = []

        for entity_key, metrics in historical.items():
            for metric_name, values in metrics.items():
                if len(values) < min_data_points:
                    continue
                mean = sum(values) / len(values)
                variance = sum((v - mean) ** 2 for v in values) / len(values)
                stddev = math.sqrt(variance) if variance > 0 else 0.0
                rows.append((
                    baseline_id, entity_key, metric_name, self.tenant_id,
                    mean, stddev, len(values),
                    min(values), max(values),
                ))

        if not rows:
            return 0

        try:
            with conn.cursor() as cur:
                execute_values(cur, """
                    INSERT INTO ciem_baselines
                    (baseline_id, entity_key, metric_name, tenant_id,
                     mean, stddev, data_points, min_val, max_val, last_computed)
                    VALUES %s
                    ON CONFLICT (baseline_id, entity_key, metric_name, tenant_id)
                    DO UPDATE SET
                        mean = EXCLUDED.mean,
                        stddev = EXCLUDED.stddev,
                        data_points = EXCLUDED.data_points,
                        min_val = EXCLUDED.min_val,
                        max_val = EXCLUDED.max_val,
                        last_computed = NOW()
                """, rows, page_size=500)
            conn.commit()
            logger.info(f"Stored {len(rows)} baselines for {baseline_id}")
        finally:
            conn.close()

        return len(rows)

    def _detect_anomalies(
        self, profile: Dict,
        historical: Dict[str, Dict[str, List[float]]],
        today_metrics: Dict[str, Dict[str, float]],
    ) -> List[Dict]:
        """Compare today's metrics against baselines, generate findings for anomalies."""
        findings = []
        baseline_id = profile["baseline_id"]
        min_data_points = profile.get("min_data_points", 5)

        for entity_key, today in today_metrics.items():
            hist = historical.get(entity_key, {})
            anomalies = []

            for metric in profile.get("metrics", []):
                name = metric["name"]
                threshold_str = metric.get("anomaly_threshold", "2_stddev")

                if name == "new_service_first_use":
                    continue  # Handled separately

                today_val = today.get(name)
                hist_vals = hist.get(name, [])

                if today_val is None or len(hist_vals) < min_data_points:
                    continue

                mean = sum(hist_vals) / len(hist_vals)
                variance = sum((v - mean) ** 2 for v in hist_vals) / len(hist_vals)
                stddev = math.sqrt(variance) if variance > 0 else 0.0

                # Parse threshold
                if threshold_str == "any_new":
                    if today_val > 0:
                        anomalies.append({
                            "metric": name, "today": today_val,
                            "mean": mean, "stddev": stddev,
                            "deviation": "new_activity",
                        })
                    continue

                n_stddev = 2
                if "3" in str(threshold_str):
                    n_stddev = 3

                if stddev == 0:
                    # No variance — any change from mean is anomalous
                    if today_val != mean and today_val > mean * 1.5:
                        anomalies.append({
                            "metric": name, "today": today_val,
                            "mean": mean, "stddev": 0,
                            "deviation": round(today_val - mean, 2),
                        })
                elif today_val > mean + n_stddev * stddev:
                    deviation = (today_val - mean) / stddev
                    anomalies.append({
                        "metric": name, "today": round(today_val, 2),
                        "mean": round(mean, 2), "stddev": round(stddev, 2),
                        "deviation": round(deviation, 1),
                        "threshold": f"{n_stddev}σ",
                    })

            if anomalies:
                finding = self._create_anomaly_finding(
                    profile, entity_key, anomalies
                )
                findings.append(finding)

        return findings

    def _create_anomaly_finding(
        self, profile: Dict, entity_key: str, anomalies: List[Dict],
    ) -> Dict:
        """Create a baseline anomaly finding."""
        baseline_id = profile["baseline_id"]
        finding_id = hashlib.sha256(
            f"bl|{baseline_id}|{entity_key}|{self.scan_run_id}".encode()
        ).hexdigest()[:20]
        finding_id = f"bl_{finding_id}"

        # Severity based on deviation magnitude
        max_dev = max(
            (a.get("deviation", 0) if isinstance(a.get("deviation"), (int, float)) else 5)
            for a in anomalies
        )
        if max_dev >= 5:
            severity = "high"
        elif max_dev >= 3:
            severity = "medium"
        else:
            severity = "low"

        entity_type = profile.get("entity_type", "")
        title_entity = entity_type.split(".")[-1] if "." in entity_type else entity_type
        anomaly_names = [a["metric"] for a in anomalies]

        return {
            "finding_id": finding_id,
            "scan_run_id": self.scan_run_id,
            "tenant_id": self.tenant_id,
            "rule_id": baseline_id,
            "rule_source": "baseline",
            "severity": severity,
            "status": "OPEN",
            "primary_engine": "ciem_engine",
            "engines": ["ciem_engine"],
            "action_category": "anomaly",
            "resource_uid": entity_key if "resource" in entity_type else "",
            "resource_type": "",
            "resource_name": "",
            "account_id": entity_key if entity_type == "account_id" else "",
            "region": "",
            "provider": self.provider,
            "actor_principal": entity_key if "actor" in entity_type else "",
            "actor_principal_type": "",
            "actor_ip": entity_key if "ip" in entity_type else "",
            "event_id": "",
            "event_time": datetime.now(timezone.utc),
            "service": "",
            "operation": "",
            "title": f"Anomalous {title_entity} behavior: {entity_key} ({', '.join(anomaly_names)})",
            "description": profile.get("description", ""),
            "remediation": "Investigate the anomalous activity — compare with expected behavior.",
            "mitre_tactics": "[]",
            "mitre_techniques": "[]",
            "risk_indicators": [],
            "compliance_frameworks": "{}",
            "finding_data": json.dumps({
                "baseline_id": baseline_id,
                "entity_type": entity_type,
                "entity_key": entity_key,
                "anomalies": anomalies,
                "anomaly_count": len(anomalies),
            }, default=str),
        }

    def _write_findings(self, findings: List[Dict]):
        """Write anomaly findings to ciem_findings."""
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
            logger.info(f"Wrote {len(findings)} baseline anomaly findings")
        finally:
            conn.close()
