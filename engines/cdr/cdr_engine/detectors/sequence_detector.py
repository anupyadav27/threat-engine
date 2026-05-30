"""
CDR Sequence Detector — multi-event attack pattern detection (PC-DEPTH-06).

Detects ordered behavioral sequences that are individually benign but collectively
indicate an exfiltration campaign, identity pivot, secrets staging, or compute hijack.

4 templates:
  1. aws.cdr.sequence.s3_exfil_pattern       — S3 recon → bulk read spike → cross-account write
  2. aws.cdr.sequence.identity_pivot         — AssumeRole → CreateUser → admin policy attachment
  3. aws.cdr.sequence.secrets_staging        — ≥10 secret reads + PutObject to external/public bucket
  4. aws.cdr.sequence.compute_hijack         — RunInstances (unknown AMI) → disable termination → SSM

Called from run_scan.py after CorrelationEvaluator.evaluate().
Writes to cdr_findings (same table, new rule_ids with rule_source='sequence').
Also writes has_exfil_path=True to resource_security_posture when S3 exfil confirmed.

Multi-tenant: all queries scope by tenant_id.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras
from psycopg2.extras import Json, RealDictCursor, execute_values

logger = logging.getLogger(__name__)

# ── Rule IDs produced by this detector ───────────────────────────────────────
RULE_S3_EXFIL       = "aws.cdr.sequence.s3_exfil_pattern"
RULE_IDENTITY_PIVOT = "aws.cdr.sequence.identity_pivot"
RULE_SECRETS_STAGE  = "aws.cdr.sequence.secrets_staging"
RULE_COMPUTE_HIJACK = "aws.cdr.sequence.compute_hijack"

# ── Stage definitions ─────────────────────────────────────────────────────────

def _make_stage(
    service: str,
    operations: List[str],
    min_count: int = 1,
    window_seconds: int = 300,
    distinct_resources: bool = False,
    cross_account_only: bool = False,
    spike_multiplier: float = 0.0,
) -> Dict[str, Any]:
    return {
        "service": service,
        "operations": operations,
        "min_count": min_count,
        "window_seconds": window_seconds,
        "distinct_resources": distinct_resources,
        "cross_account_only": cross_account_only,
        "spike_multiplier": spike_multiplier,
    }


_SEQUENCE_TEMPLATES: List[Dict[str, Any]] = [
    {
        "rule_id":  RULE_S3_EXFIL,
        "severity": "critical",
        "title":    "S3 Data Exfiltration Sequence: Recon → Bulk Read → Cross-Account Write",
        "max_total_window_seconds": 7200,
        "mitre_techniques": ["T1530", "T1020"],
        "mitre_tactics":    ["collection", "exfiltration"],
        "stages": [
            _make_stage("s3", ["ListBuckets", "GetBucketPolicy", "GetBucketAcl", "ListObjects",
                               "GetBucketLocation", "GetBucketTagging"],
                        min_count=2, window_seconds=300),
            _make_stage("s3", ["GetObject"],
                        min_count=5, window_seconds=600, spike_multiplier=3.0),
            _make_stage("s3", ["CreateJob", "PutObject", "CopyObject"],
                        min_count=1, window_seconds=3600, cross_account_only=True),
        ],
    },
    {
        "rule_id":  RULE_IDENTITY_PIVOT,
        "severity": "critical",
        "title":    "Identity Pivot Sequence: AssumeRole → CreateUser → Admin Policy",
        "max_total_window_seconds": 1800,
        "mitre_techniques": ["T1078.004", "T1136.003"],
        "mitre_tactics":    ["persistence", "privilege_escalation"],
        "stages": [
            _make_stage("sts", ["AssumeRole", "AssumeRoleWithWebIdentity"],
                        min_count=1, window_seconds=120),
            _make_stage("iam", ["CreateUser", "CreateAccessKey"],
                        min_count=1, window_seconds=300),
            _make_stage("iam", ["AttachUserPolicy", "PutUserPolicy", "AddUserToGroup"],
                        min_count=1, window_seconds=300),
        ],
    },
    {
        "rule_id":  RULE_SECRETS_STAGE,
        "severity": "critical",
        "title":    "Secrets Staging Sequence: Bulk Secret Read → Exfil to External Bucket",
        "max_total_window_seconds": 3600,
        "mitre_techniques": ["T1555.006", "T1530"],
        "mitre_tactics":    ["credential_access", "exfiltration"],
        "stages": [
            _make_stage("secretsmanager", ["GetSecretValue"],
                        min_count=10, window_seconds=900, distinct_resources=True),
            _make_stage("s3", ["PutObject", "CopyObject", "CreateJob"],
                        min_count=1, window_seconds=1800, cross_account_only=True),
        ],
    },
    {
        "rule_id":  RULE_COMPUTE_HIJACK,
        "severity": "high",
        "title":    "Compute Hijack Sequence: RunInstances → Disable Termination → SSM Shell",
        "max_total_window_seconds": 3600,
        "mitre_techniques": ["T1496", "T1021.006"],
        "mitre_tactics":    ["execution", "persistence"],
        "stages": [
            _make_stage("ec2", ["RunInstances"],
                        min_count=1, window_seconds=300),
            _make_stage("ec2", ["ModifyInstanceAttribute", "ModifyInstanceTerminationProtection"],
                        min_count=1, window_seconds=600),
            _make_stage("ssm", ["SendCommand", "StartSession", "CreateDocument"],
                        min_count=1, window_seconds=1800),
        ],
    },
]


class SequenceDetector:
    """Detect multi-event attack sequences from ordered CDR event streams."""

    def __init__(self, scan_run_id: str, tenant_id: str, provider: str = "aws"):
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.provider = provider

    def _get_cdr_conn(self) -> psycopg2.extensions.connection:
        return psycopg2.connect(
            host=os.getenv("CDR_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CDR_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("CDR_DB_NAME", "threat_engine_cdr"),
            user=os.getenv("CDR_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CDR_DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD",
                     os.getenv("DB_PASSWORD", ""))),
        )

    def _get_inventory_conn(self) -> psycopg2.extensions.connection:
        return psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )

    def _load_actor_events(
        self, cdr_conn: psycopg2.extensions.connection, account_id: str
    ) -> Dict[str, List[Dict]]:
        """Load CDR findings from last 24h, grouped by actor_principal."""
        with cdr_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT finding_id, rule_id, event_time,
                       actor_principal, actor_principal_type, actor_ip,
                       resource_uid, resource_type, resource_name,
                       account_id, region, service, operation,
                       severity, title, finding_data
                FROM cdr_findings
                WHERE tenant_id = %s
                  AND account_id = %s
                  AND event_time > NOW() - INTERVAL '24 hours'
                  AND rule_source != 'sequence'
                ORDER BY actor_principal, event_time ASC
                """,
                (self.tenant_id, account_id),
            )
            rows = cur.fetchall()

        events_by_actor: Dict[str, List[Dict]] = defaultdict(list)
        for row in rows:
            actor = row.get("actor_principal") or ""
            if actor:
                events_by_actor[actor].append(dict(row))
        return dict(events_by_actor)

    def _load_baselines(
        self, cdr_conn: psycopg2.extensions.connection, account_id: str
    ) -> Dict[str, Dict]:
        """Load per-actor behavioral baselines from cdr_actor_daily_stats."""
        try:
            with cdr_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT actor_principal,
                           AVG(get_object_count)        AS avg_get_object,
                           PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY get_object_count)
                                                         AS p95_get_object
                    FROM cdr_actor_daily_stats
                    WHERE tenant_id = %s
                      AND account_id = %s
                      AND stats_date >= CURRENT_DATE - INTERVAL '30 days'
                    GROUP BY actor_principal
                    """,
                    (self.tenant_id, account_id),
                )
                rows = cur.fetchall()
            return {r["actor_principal"]: dict(r) for r in rows if r.get("actor_principal")}
        except Exception as exc:
            logger.warning("Could not load baselines: %s", exc)
            return {}

    def _match_stage(
        self,
        events: List[Dict],
        stage: Dict,
        after_time: datetime,
        account_id: str,
        baseline: Optional[Dict] = None,
    ) -> Tuple[bool, datetime, List[Dict]]:
        """Find events matching stage criteria in [after_time, after_time + window_seconds]."""
        window_end = after_time + timedelta(seconds=stage["window_seconds"])
        service = stage["service"]
        operations = {op.lower() for op in stage["operations"]}

        candidates = [
            e for e in events
            if e.get("event_time")
            and after_time <= e["event_time"] <= window_end
            and str(e.get("service") or "").lower() == service.lower()
            and str(e.get("operation") or "").lower() in operations
        ]

        # Cross-account filter: resource_uid in a different account
        if stage.get("cross_account_only") and candidates:
            candidates = [
                e for e in candidates
                if e.get("account_id") and e["account_id"] != account_id
            ]

        if not candidates:
            return False, after_time, []

        # Distinct resources (e.g. distinct secrets)
        if stage.get("distinct_resources"):
            distinct_count = len({e.get("resource_uid") or e.get("resource_name") for e in candidates})
            matched = distinct_count >= stage["min_count"]
        elif stage.get("spike_multiplier", 0) > 0 and baseline:
            p95 = float(baseline.get("p95_get_object") or 0)
            threshold = max(stage["min_count"], int(p95 * stage["spike_multiplier"]))
            matched = len(candidates) >= threshold
        else:
            matched = len(candidates) >= stage["min_count"]

        last_time = max((e["event_time"] for e in candidates), default=after_time)
        return matched, last_time, candidates if matched else []

    def _evaluate_template(
        self,
        template: Dict,
        actor: str,
        events: List[Dict],
        account_id: str,
        baseline: Optional[Dict],
    ) -> Optional[Dict]:
        """Check if a template's stage sequence is satisfied for this actor."""
        stages = template["stages"]
        max_window = timedelta(seconds=template["max_total_window_seconds"])
        all_stage_events: List[List[Dict]] = []

        # Find the earliest event matching stage 0
        stage0 = stages[0]
        ops0 = {op.lower() for op in stage0["operations"]}
        trigger_events = [
            e for e in events
            if str(e.get("service") or "").lower() == stage0["service"].lower()
            and str(e.get("operation") or "").lower() in ops0
            and e.get("event_time")
        ]

        for trigger in trigger_events:
            t0 = trigger["event_time"]
            stage_start = t0
            stage_events_acc: List[List[Dict]] = []

            for stage in stages:
                matched, stage_end, matched_events = self._match_stage(
                    events, stage, stage_start, account_id, baseline
                )
                if not matched:
                    break
                stage_events_acc.append(matched_events)
                stage_start = stage_end
            else:
                # All stages matched
                total_duration = (stage_start - t0).total_seconds()
                if total_duration <= template["max_total_window_seconds"]:
                    all_stage_events = stage_events_acc
                    break

        if not all_stage_events:
            return None

        # Build finding
        all_contributing = [e for stage_e in all_stage_events for e in stage_e]
        t_first = min((e["event_time"] for e in all_contributing), default=datetime.now(timezone.utc))
        t_last  = max((e["event_time"] for e in all_contributing), default=t_first)

        finding_id = hashlib.sha256(
            f"seq|{template['rule_id']}|{actor}|{t_first.isoformat()}".encode()
        ).hexdigest()[:20]

        stage_data = {
            f"stage_{i+1}_events": [
                {"operation": e.get("operation"), "resource_uid": e.get("resource_uid"),
                 "event_time": e["event_time"].isoformat() if e.get("event_time") else None}
                for e in stage_evts
            ]
            for i, stage_evts in enumerate(all_stage_events)
        }

        baseline_note: Dict = {}
        if baseline and template["rule_id"] == RULE_S3_EXFIL:
            s3_events = all_stage_events[1] if len(all_stage_events) > 1 else []
            baseline_note = {
                "actor_p95_get_object": float(baseline.get("p95_get_object") or 0),
                "observed_get_object": len(s3_events),
            }

        return {
            "finding_id":      finding_id,
            "rule_id":         template["rule_id"],
            "rule_source":     "sequence",
            "severity":        template["severity"],
            "title":           template["title"],
            "actor_principal": actor,
            "event_time":      t_first,
            "first_seen_at":   t_first,
            "last_seen_at":    t_last,
            "finding_data": {
                "sequence_matched": template["rule_id"].split(".")[-1],
                **stage_data,
                "total_duration_seconds": int((t_last - t_first).total_seconds()),
                "cdr_event_ids": [str(e.get("finding_id", "")) for e in all_contributing[:50]],
                "baseline_comparison": baseline_note,
            },
            "mitre_techniques": template.get("mitre_techniques", []),
            "mitre_tactics":    template.get("mitre_tactics", []),
        }

    def _write_findings(
        self,
        cdr_conn: psycopg2.extensions.connection,
        findings: List[Dict],
        account_id: str,
        provider: str,
        region: str,
    ) -> int:
        """Upsert sequence findings into cdr_findings."""
        if not findings:
            return 0

        now = datetime.now(timezone.utc)
        rows = [
            (
                f["finding_id"],
                self.scan_run_id,
                self.tenant_id,
                f.get("rule_id", ""),
                f.get("rule_source", "sequence"),
                f.get("severity", "high"),
                "open",
                account_id,
                region,
                provider,
                f.get("actor_principal", ""),
                None,   # actor_principal_type
                None,   # actor_ip
                None,   # resource_uid
                None,   # resource_type
                None,   # resource_name
                None,   # service
                None,   # operation
                f.get("event_time") or now,
                f.get("title", f.get("rule_id", "")),
                None,   # description
                Json(f.get("finding_data", {})),
                Json(f.get("mitre_techniques", [])),
                Json(f.get("mitre_tactics", [])),
                f.get("first_seen_at") or now,
            )
            for f in findings
        ]

        sql = """
            INSERT INTO cdr_findings (
                finding_id, scan_run_id, tenant_id,
                rule_id, rule_source, severity, status,
                account_id, region, provider,
                actor_principal, actor_principal_type, actor_ip,
                resource_uid, resource_type, resource_name,
                service, operation, event_time,
                title, description,
                finding_data, mitre_techniques, mitre_tactics,
                first_seen_at
            ) VALUES %s
            ON CONFLICT (finding_id) DO UPDATE SET
                last_seen_at = NOW(),
                severity = EXCLUDED.severity
        """
        with cdr_conn.cursor() as cur:
            execute_values(cur, sql, rows)
        cdr_conn.commit()
        return len(rows)

    def _write_exfil_posture_signal(self, actors_with_exfil: List[str], account_id: str) -> None:
        """Set has_exfil_path=True on resource_security_posture rows for exfil actors."""
        if not actors_with_exfil:
            return
        try:
            inv_conn = self._get_inventory_conn()
            try:
                with inv_conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE resource_security_posture
                        SET has_exfil_path = TRUE,
                            updated_at = NOW()
                        WHERE tenant_id = %s
                          AND account_id = %s
                          AND resource_uid = ANY(%s::text[])
                        """,
                        (self.tenant_id, account_id, actors_with_exfil),
                    )
                inv_conn.commit()
                logger.info(
                    "exfil posture signal: set has_exfil_path=True for %d actors",
                    len(actors_with_exfil),
                )
            finally:
                inv_conn.close()
        except Exception as exc:
            logger.warning("Could not write exfil posture signal: %s", exc)

    def _write_pivot_posture_signal(self, pivot_actors: List[str], account_id: str) -> None:
        """Set is_on_attack_path=True + attack_entry_point_category='identity_pivot' for pivot actors."""
        if not pivot_actors:
            return
        try:
            inv_conn = self._get_inventory_conn()
            try:
                with inv_conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE resource_security_posture
                        SET is_on_attack_path = TRUE,
                            is_attack_entry_point = TRUE,
                            attack_entry_point_category = 'identity_pivot',
                            updated_at = NOW()
                        WHERE tenant_id = %s
                          AND account_id = %s
                          AND resource_uid = ANY(%s::text[])
                        """,
                        (self.tenant_id, account_id, pivot_actors),
                    )
                inv_conn.commit()
                logger.info(
                    "pivot posture signal: set identity_pivot on %d actors (updated=%d rows)",
                    len(pivot_actors), inv_conn.cursor().rowcount if hasattr(inv_conn.cursor(), "rowcount") else -1,
                )
            finally:
                inv_conn.close()
        except Exception as exc:
            logger.warning("Could not write identity_pivot posture signal: %s", exc)

    def _write_secrets_posture_signal(self, secrets_actors: List[str], account_id: str) -> None:
        """Set secrets_in_env_vars=True for actors that staged secrets from Secrets Manager."""
        if not secrets_actors:
            return
        try:
            inv_conn = self._get_inventory_conn()
            try:
                with inv_conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE resource_security_posture
                        SET secrets_in_env_vars = TRUE,
                            updated_at = NOW()
                        WHERE tenant_id = %s
                          AND account_id = %s
                          AND resource_uid = ANY(%s::text[])
                        """,
                        (self.tenant_id, account_id, secrets_actors),
                    )
                inv_conn.commit()
                logger.info(
                    "secrets posture signal: set secrets_in_env_vars=True for %d actors",
                    len(secrets_actors),
                )
            finally:
                inv_conn.close()
        except Exception as exc:
            logger.warning("Could not write secrets_staging posture signal: %s", exc)

    def _write_hijack_posture_signal(self, hijack_actors: List[str], account_id: str) -> None:
        """Set is_on_attack_path=True + attack_entry_point_category='compute_hijack' for hijack actors."""
        if not hijack_actors:
            return
        try:
            inv_conn = self._get_inventory_conn()
            try:
                with inv_conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE resource_security_posture
                        SET is_on_attack_path = TRUE,
                            attack_entry_point_category = 'compute_hijack',
                            updated_at = NOW()
                        WHERE tenant_id = %s
                          AND account_id = %s
                          AND resource_uid = ANY(%s::text[])
                        """,
                        (self.tenant_id, account_id, hijack_actors),
                    )
                inv_conn.commit()
                logger.info(
                    "hijack posture signal: set compute_hijack on %d actors",
                    len(hijack_actors),
                )
            finally:
                inv_conn.close()
        except Exception as exc:
            logger.warning("Could not write compute_hijack posture signal: %s", exc)

    def detect(self, account_id: str, region: str) -> Dict[str, Any]:
        """Run sequence detection against 24h CDR event window. Returns stats."""
        cdr_conn = self._get_cdr_conn()
        try:
            events_by_actor = self._load_actor_events(cdr_conn, account_id)
            if not events_by_actor:
                logger.info("Sequence detector: no actor events in last 24h")
                return {"total_findings": 0, "sequences_matched": 0}

            baselines = self._load_baselines(cdr_conn, account_id)
            logger.info(
                "Sequence detector: %d actors, %d with baselines",
                len(events_by_actor), len(baselines),
            )

            all_findings: List[Dict] = []
            exfil_actors: List[str] = []
            pivot_actors: List[str] = []
            secrets_actors: List[str] = []
            hijack_actors: List[str] = []

            for actor, events in events_by_actor.items():
                for template in _SEQUENCE_TEMPLATES:
                    finding = self._evaluate_template(
                        template, actor, events, account_id, baselines.get(actor)
                    )
                    if finding:
                        all_findings.append(finding)
                        rule = template["rule_id"]
                        if rule == RULE_S3_EXFIL:
                            exfil_actors.append(actor)
                        elif rule == RULE_IDENTITY_PIVOT:
                            pivot_actors.append(actor)
                        elif rule == RULE_SECRETS_STAGE:
                            secrets_actors.append(actor)
                        elif rule == RULE_COMPUTE_HIJACK:
                            hijack_actors.append(actor)
                        logger.info(
                            "Sequence matched: %s for actor %s",
                            template["rule_id"], actor[:32]
                        )

            written = self._write_findings(cdr_conn, all_findings, account_id, self.provider, region)
        finally:
            cdr_conn.close()

        self._write_exfil_posture_signal(exfil_actors, account_id)
        self._write_pivot_posture_signal(pivot_actors, account_id)
        self._write_secrets_posture_signal(secrets_actors, account_id)
        self._write_hijack_posture_signal(hijack_actors, account_id)

        stats = {
            "total_findings": written,
            "sequences_matched": len(all_findings),
            "exfil_actors_flagged": len(exfil_actors),
            "pivot_actors_flagged": len(pivot_actors),
            "secrets_actors_flagged": len(secrets_actors),
            "hijack_actors_flagged": len(hijack_actors),
        }
        logger.info("Sequence detector: %s", stats)
        return stats
