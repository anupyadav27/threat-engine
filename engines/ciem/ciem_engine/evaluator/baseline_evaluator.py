"""
L3 Baseline Evaluator — behavioral anomaly detection (no log_events dependency).

Two phases:
  1. STORE:  Accept in-memory actor stats from the current scan (aggregated during
             the read loop in run_scan.py) and persist to ciem_actor_daily_stats.
             This tiny table (1 row per actor per day) replaces reading log_events.
  2. DETECT: Compare today's in-memory stats against the historical window stored
             in ciem_actor_daily_stats → flag anomalies → write to ciem_findings.

ciem_actor_daily_stats schema:
  (tenant_id, account_id, entity_type, entity_key, metric_name, stat_date, value)

Called from run_scan.py as:
    baseline_eval = BaselineEvaluator(scan_run_id, tenant_id, provider)
    baseline_eval.ensure_tables()
    baseline_eval.store_daily_stats(today_actor_stats)  # persists in-memory aggregates
    l3_stats = baseline_eval.evaluate(today_actor_stats) # detect anomalies
"""

import hashlib
import json
import logging
import math
import os
import yaml
from collections import defaultdict
from datetime import datetime, date, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import execute_values

logger = logging.getLogger(__name__)

CREATE_DAILY_STATS_DDL = """
CREATE TABLE IF NOT EXISTS ciem_actor_daily_stats (
    tenant_id   VARCHAR(64)  NOT NULL,
    account_id  VARCHAR(64)  NOT NULL DEFAULT '',
    entity_type VARCHAR(50)  NOT NULL,   -- actor.principal | actor.ip_address | resource.uid | account_id
    entity_key  VARCHAR(500) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    stat_date   DATE         NOT NULL,
    value       DOUBLE PRECISION NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, account_id, entity_type, entity_key, metric_name, stat_date)
);
CREATE INDEX IF NOT EXISTS idx_cads_tenant_date
    ON ciem_actor_daily_stats (tenant_id, stat_date);
CREATE INDEX IF NOT EXISTS idx_cads_entity
    ON ciem_actor_daily_stats (tenant_id, entity_type, entity_key);
"""

CREATE_BASELINES_DDL = """
CREATE TABLE IF NOT EXISTS ciem_baselines (
    baseline_id  VARCHAR(100),
    entity_key   VARCHAR(500),
    metric_name  VARCHAR(100),
    tenant_id    VARCHAR(100),
    mean         DOUBLE PRECISION,
    stddev       DOUBLE PRECISION,
    data_points  INTEGER,
    min_val      DOUBLE PRECISION,
    max_val      DOUBLE PRECISION,
    last_computed TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (baseline_id, entity_key, metric_name, tenant_id)
);
"""


class BaselineEvaluator:
    """Compute behavioral baselines from daily stats, detect anomalies."""

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

    def ensure_tables(self):
        conn = self._get_ciem_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(CREATE_DAILY_STATS_DDL)
                cur.execute(CREATE_BASELINES_DDL)
            conn.commit()
        finally:
            conn.close()

    def load_profiles(self) -> List[Dict]:
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

    # ── Phase 1: Persist in-memory stats to daily stats table ────────────────

    def store_daily_stats(
        self,
        actor_stats: Dict[str, Dict[str, Any]],
        account_id: str = "",
    ) -> int:
        """Persist today's in-memory aggregated stats to ciem_actor_daily_stats.

        actor_stats format (built in run_scan.py read loop):
          {
            "actor.principal": {
              "arn:aws:iam::123:user/admin": {
                "daily_api_count": 142,
                "unique_operations": 23,
                "unique_source_ips": 2,
                "error_rate": 0.04,
                "off_hours_access_ratio": 0.12,
                "bytes_transferred": 0,
              }
            },
            "actor.ip_address": { ... },
            "resource.uid": { ... },
          }
        """
        today = date.today().isoformat()
        rows = []
        for entity_type, entities in actor_stats.items():
            for entity_key, metrics in entities.items():
                if not entity_key:
                    continue
                for metric_name, value in metrics.items():
                    if not isinstance(value, (int, float)):
                        continue
                    rows.append((
                        self.tenant_id, account_id, entity_type,
                        entity_key, metric_name, today, float(value),
                    ))

        if not rows:
            return 0

        conn = self._get_ciem_conn()
        try:
            with conn.cursor() as cur:
                execute_values(cur, """
                    INSERT INTO ciem_actor_daily_stats
                        (tenant_id, account_id, entity_type, entity_key, metric_name, stat_date, value)
                    VALUES %s
                    ON CONFLICT (tenant_id, account_id, entity_type, entity_key, metric_name, stat_date)
                    DO UPDATE SET value = EXCLUDED.value
                """, rows, page_size=1000)
            conn.commit()
            logger.info(f"L3: stored {len(rows)} daily stat rows for today={today}")
        finally:
            conn.close()

        return len(rows)

    # ── Phase 2: Evaluate anomalies ───────────────────────────────────────────

    def evaluate(self, today_actor_stats: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Detect anomalies by comparing today's in-memory stats against history.

        today_actor_stats: same format as store_daily_stats() argument.
        """
        started = datetime.now(timezone.utc)
        self.ensure_tables()

        profiles = self.load_profiles()
        if not profiles:
            return {"total_findings": 0, "baselines_computed": 0}

        all_findings = []
        total_baselines = 0

        for profile in profiles:
            baseline_id = profile["baseline_id"]
            entity_type = profile.get("entity_type", "actor.principal")
            window_days = profile.get("window_days", 14)
            min_data_points = profile.get("min_data_points", 5)
            metrics_cfg = profile.get("metrics", [])

            if not metrics_cfg:
                continue

            metric_names = [m["name"] for m in metrics_cfg]

            # Load historical daily stats from DB
            historical = self._load_historical(
                entity_type, metric_names, window_days
            )
            if not historical:
                logger.debug(f"No historical data yet for {baseline_id}")
                continue

            # Compute + store baselines (mean/stddev per entity+metric)
            stored = self._store_baselines(baseline_id, historical, min_data_points)
            total_baselines += stored

            # Get today's values from in-memory stats
            today_entities = today_actor_stats.get(entity_type, {})

            # Detect anomalies
            for entity_key, hist_metrics in historical.items():
                today = today_entities.get(entity_key, {})
                if not today:
                    continue

                anomalies = []
                for metric_cfg in metrics_cfg:
                    name = metric_cfg["name"]
                    hist_vals = hist_metrics.get(name, [])
                    today_val = today.get(name)

                    if today_val is None or len(hist_vals) < min_data_points:
                        continue

                    threshold_str = metric_cfg.get("anomaly_threshold", "2_stddev")
                    anomaly = self._check_anomaly(name, today_val, hist_vals, threshold_str)
                    if anomaly:
                        anomalies.append(anomaly)

                if anomalies:
                    all_findings.append(
                        self._make_finding(profile, entity_key, anomalies)
                    )

        if all_findings:
            self._write_findings(all_findings)

        duration = (datetime.now(timezone.utc) - started).total_seconds()
        stats = {
            "total_findings": len(all_findings),
            "baselines_computed": total_baselines,
            "profiles_evaluated": len(profiles),
            "duration_seconds": duration,
        }
        logger.info(
            f"L3: {total_baselines} baselines, {len(all_findings)} anomalies "
            f"from {len(profiles)} profiles in {duration:.1f}s"
        )
        return stats

    def _load_historical(
        self,
        entity_type: str,
        metric_names: List[str],
        window_days: int,
    ) -> Dict[str, Dict[str, List[float]]]:
        """Load daily stat rows from ciem_actor_daily_stats for the historical window.

        Returns: {entity_key: {metric_name: [day1_val, day2_val, ...]}}
        """
        cutoff = (date.today() - timedelta(days=window_days)).isoformat()
        today = date.today().isoformat()

        conn = self._get_ciem_conn()
        result: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        try:
            with conn.cursor() as cur:
                placeholders = ",".join(["%s"] * len(metric_names))
                cur.execute(f"""
                    SELECT entity_key, metric_name, value
                    FROM ciem_actor_daily_stats
                    WHERE tenant_id = %s
                      AND entity_type = %s
                      AND metric_name IN ({placeholders})
                      AND stat_date >= %s AND stat_date < %s
                    ORDER BY entity_key, metric_name, stat_date
                """, [self.tenant_id, entity_type] + metric_names + [cutoff, today])
                for row in cur.fetchall():
                    entity_key, metric_name, value = row
                    if entity_key:
                        result[entity_key][metric_name].append(float(value))
        finally:
            conn.close()

        return dict(result)

    def _check_anomaly(
        self,
        name: str,
        today_val: float,
        hist_vals: List[float],
        threshold_str: str,
    ) -> Optional[Dict]:
        mean = sum(hist_vals) / len(hist_vals)
        variance = sum((v - mean) ** 2 for v in hist_vals) / len(hist_vals)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        if threshold_str == "any_new":
            if today_val > 0:
                return {"metric": name, "today": today_val, "mean": mean, "stddev": stddev, "deviation": "new_activity"}
            return None

        n_stddev = 3 if "3" in str(threshold_str) else 2

        if stddev == 0:
            if today_val != mean and today_val > mean * 1.5:
                return {"metric": name, "today": today_val, "mean": mean, "stddev": 0, "deviation": round(today_val - mean, 2)}
        elif today_val > mean + n_stddev * stddev:
            deviation = (today_val - mean) / stddev
            return {
                "metric": name, "today": round(today_val, 2),
                "mean": round(mean, 2), "stddev": round(stddev, 2),
                "deviation": round(deviation, 1), "threshold": f"{n_stddev}σ",
            }
        return None

    def _store_baselines(
        self, baseline_id: str, historical: Dict, min_data_points: int
    ) -> int:
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
                    mean, stddev, len(values), min(values), max(values),
                ))
        if not rows:
            return 0
        conn = self._get_ciem_conn()
        try:
            with conn.cursor() as cur:
                execute_values(cur, """
                    INSERT INTO ciem_baselines
                    (baseline_id, entity_key, metric_name, tenant_id,
                     mean, stddev, data_points, min_val, max_val, last_computed)
                    VALUES %s
                    ON CONFLICT (baseline_id, entity_key, metric_name, tenant_id)
                    DO UPDATE SET
                        mean = EXCLUDED.mean, stddev = EXCLUDED.stddev,
                        data_points = EXCLUDED.data_points,
                        min_val = EXCLUDED.min_val, max_val = EXCLUDED.max_val,
                        last_computed = NOW()
                """, rows, page_size=500)
            conn.commit()
        finally:
            conn.close()
        return len(rows)

    def _make_finding(self, profile: Dict, entity_key: str, anomalies: List[Dict]) -> Dict:
        baseline_id = profile["baseline_id"]
        finding_id = f"bl_{hashlib.sha256(f'bl|{baseline_id}|{entity_key}'.encode()).hexdigest()[:20]}"
        entity_type = profile.get("entity_type", "")
        title_entity = entity_type.split(".")[-1] if "." in entity_type else entity_type
        anomaly_names = [a["metric"] for a in anomalies]

        max_dev = max(
            (a.get("deviation", 0) if isinstance(a.get("deviation"), (int, float)) else 5)
            for a in anomalies
        )
        severity = "high" if max_dev >= 5 else "medium" if max_dev >= 3 else "low"

        return {
            "finding_id":          finding_id,
            "scan_run_id":         self.scan_run_id,
            "tenant_id":           self.tenant_id,
            "rule_id":             baseline_id,
            "rule_source":         "baseline",
            "severity":            severity,
            "status":              "OPEN",
            "primary_engine":      "ciem_engine",
            "engines":             ["ciem_engine"],
            "action_category":     "anomaly",
            "resource_uid":        entity_key if "resource" in entity_type else "",
            "resource_type":       "",
            "resource_name":       "",
            "account_id":          entity_key if entity_type == "account_id" else "",
            "region":              "",
            "provider":            self.provider,
            "actor_principal":     entity_key if "actor" in entity_type and "ip" not in entity_type else "",
            "actor_principal_type": "",
            "actor_ip":            entity_key if "ip" in entity_type else "",
            "event_id":            "",
            "event_time":          datetime.now(timezone.utc),
            "service":             "",
            "operation":           "",
            "title":               f"Anomalous {title_entity} behavior: {entity_key} ({', '.join(anomaly_names)})",
            "description":         profile.get("description", ""),
            "remediation":         "Investigate the anomalous activity — compare with expected behavior.",
            "mitre_tactics":       "[]",
            "mitre_techniques":    "[]",
            "risk_indicators":     [],
            "compliance_frameworks": "{}",
            "finding_data":        json.dumps({
                "baseline_id": baseline_id, "entity_type": entity_type,
                "entity_key": entity_key, "anomalies": anomalies,
            }, default=str),
        }

    def _write_findings(self, findings: List[Dict]):
        conn = self._get_ciem_conn()
        try:
            values = [
                (
                    f["finding_id"], f["scan_run_id"], f["tenant_id"],
                    f["rule_id"], f["rule_source"], f["severity"], f["status"],
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
                """, values, page_size=100)
            conn.commit()
            logger.info(f"L3: wrote {len(findings)} baseline anomaly findings")
        finally:
            conn.close()
