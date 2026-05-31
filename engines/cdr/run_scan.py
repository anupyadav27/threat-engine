"""
CDR Scanner — Job entry point.

Runs as a K8s Job on on-demand nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Flow:
  1. Get orchestration metadata (tenant, account, provider)
  2. Find log sources from inventory/discovery data
  3. Load + compile L1 rules (one DB round-trip)
  4. For each source: read → parse → normalize → evaluate L1 in-memory + accumulate L3 stats
  5. Flush L1 findings batch to DB
  6. Store L3 daily actor stats, run L2 correlation + L3 baseline evaluation
  7. Write scan report

No raw events are written to RDS — only findings and aggregated daily stats.
"""

import argparse
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine_common.logger import setup_logger
from engine_common.orchestration import get_orchestration_metadata


def _resolve_cdr_credentials(account_id: str, credential_ref: str, credential_type: str, provider: str) -> dict:
    """Fetch credentials from Secrets Manager (mirrors discovery engine pattern).

    Falls back to empty dict so providers can use instance-profile / env-var defaults.
    """
    import boto3
    import json as _json

    cred_type = (credential_type or "").lower()

    # Role / managed-identity: no Secrets Manager fetch needed
    if cred_type in ("aws_iam_role", "iam_role", "role", "managed_identity"):
        return {"credential_type": cred_type, "role_arn": credential_ref}

    # CLI / ADC: no Secrets Manager fetch needed
    if cred_type in ("cli", "in_cluster", "k8s_in_cluster"):
        return {"credential_type": cred_type, "account_id": account_id}

    # Key-based: pull from Secrets Manager using the standard secret path
    try:
        region = os.getenv("AWS_REGION", "ap-south-1")
        prefix = os.getenv("SECRETS_MANAGER_PREFIX", "threat-engine")
        secret_name = f"{prefix}/account/{account_id}"
        sm = boto3.client("secretsmanager", region_name=region)
        response = sm.get_secret_value(SecretId=secret_name)
        secret_data = _json.loads(response["SecretString"])

        credentials = secret_data.get("credentials", {})
        credentials["credential_type"] = secret_data.get("credential_type", credential_type)

        # Provider-specific normalisations (same as discovery engine)
        raw_type = (credentials.get("credential_type") or "").lower()
        if provider == "aws" and raw_type in ("aws_access_key", "access_key_id"):
            credentials["credential_type"] = "access_key"
        elif provider == "gcp" and raw_type in ("service_account", "gcp_service_account"):
            credentials["credential_type"] = "service_account"
            if not credentials.get("credentials") and not credentials.get("service_account_json"):
                if credentials.get("type") == "service_account":
                    credentials["credentials"] = {
                        k: v for k, v in credentials.items()
                        if k not in ("credential_type", "account_id", "created_at", "expires_at")
                    }
        elif provider == "azure" and raw_type in ("service_principal", "client_secret"):
            credentials["credential_type"] = "service_principal"
        elif provider == "oci" and raw_type in ("api_key", "oci_api_key"):
            credentials["credential_type"] = "api_key"
        elif provider == "ibm" and raw_type in ("api_key", "ibm_api_key"):
            credentials["credential_type"] = "api_key"

        logger.info(f"Resolved credentials from Secrets Manager for account={account_id} provider={provider}")
        return credentials

    except Exception as exc:
        logger.warning(f"Could not fetch credentials from Secrets Manager: {exc} — using env/instance-profile fallback")
        return {}


# Configure root logger so all modules output logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")

from cdr_engine.source_discovery.log_source_finder import LogSourceFinder
from cdr_engine.normalizer.event_normalizer import EventNormalizer
from cdr_engine.storage.event_writer import EventWriter

logger = setup_logger(__name__, engine_name="cdr-scanner")


def _load_identifier_index(csp: str = "aws") -> dict:
    """Load identifier patterns from di_resource_catalog table.

    Returns: {service.canonical_type → {identifier_pattern, primary_param, canonical_type}}
    """
    import psycopg2
    from psycopg2.extras import RealDictCursor
    try:
        conn = psycopg2.connect(
            host=os.getenv("DI_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("DI_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("DI_DB_NAME", "threat_engine_di"),
            user=os.getenv("DI_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("DI_DB_PASSWORD") or os.getenv("DB_PASSWORD") or os.getenv("DISCOVERIES_DB_PASSWORD", ""),
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT service, canonical_type, identifier_pattern, primary_param
            FROM di_resource_catalog
            WHERE csp = %s AND identifier_pattern IS NOT NULL AND identifier_pattern != ''
            AND identifier_pattern LIKE 'arn:%%'
        """, (csp,))
        index = {}
        for row in cur.fetchall():
            key = f"{row['service']}.{row['canonical_type']}"
            index[key] = {
                "identifier_pattern": row["identifier_pattern"],
                "primary_param": row["primary_param"] or "",
                "canonical_type": row["canonical_type"],
            }
        conn.close()
        logger.info(f"Loaded {len(index)} identifier patterns for {csp}")
        return index
    except Exception as exc:
        logger.warning(f"Failed to load identifier index: {exc}")
        return {}


def _write_failed_report(scan_run_id: str, tenant_id: str, provider: str, error: str) -> None:
    """Best-effort: write a failed row to cdr_report so Argo doesn't poll 404 forever.
    Retries up to 5 times with 10s delay (spot node DB connectivity may lag on startup).
    """
    import time as _time
    import psycopg2

    for _attempt in range(5):
        try:
            conn = psycopg2.connect(
                host=os.getenv("CDR_DB_HOST", os.getenv("DB_HOST", "localhost")),
                port=int(os.getenv("CDR_DB_PORT", os.getenv("DB_PORT", "5432"))),
                database=os.getenv("CDR_DB_NAME", "threat_engine_cdr"),
                user=os.getenv("CDR_DB_USER", os.getenv("DB_USER", "postgres")),
                password=os.getenv("CDR_DB_PASSWORD", os.getenv(
                    "INVENTORY_DB_PASSWORD", os.getenv(
                        "DB_PASSWORD", os.getenv("DISCOVERIES_DB_PASSWORD", "")))),
                connect_timeout=10,
            )
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (tenant_id, tenant_id),
                )
                cur.execute("""
                    INSERT INTO cdr_report
                        (scan_run_id, tenant_id, provider, status, started_at, completed_at,
                         total_findings, findings_by_severity, findings_by_engine, findings_by_category)
                    VALUES (%s, %s, %s, 'failed', NOW(), NOW(), 0, '{}', '{}', '{}')
                    ON CONFLICT (scan_run_id) DO NOTHING
                """, (scan_run_id, tenant_id, provider))
            conn.commit()
            conn.close()
            logger.info(f"Wrote failed cdr_report row for scan_run_id={scan_run_id}")
            return
        except Exception as e:
            logger.warning(f"Could not write failed cdr_report row (attempt {_attempt+1}/5): {e}")
            if _attempt < 4:
                _time.sleep(10)


def _update_actor_stats(event, actor_raw: dict) -> None:
    """Accumulate per-actor behavioral metrics from a NormalizedEvent.

    Mutates actor_raw in-place:
      {entity_type: {entity_key: {metric: int|set}}}
    """
    if not event.actor or not event.actor.principal:
        return

    entity_type = (event.actor.principal_type or "unknown").lower()
    entity_key = event.actor.principal

    if entity_type not in actor_raw:
        actor_raw[entity_type] = {}
    if entity_key not in actor_raw[entity_type]:
        actor_raw[entity_type][entity_key] = {
            "action_count": 0,
            "failed_action_count": 0,
            "_services": set(),
            "_operations": set(),
            "_ips": set(),
        }

    m = actor_raw[entity_type][entity_key]
    m["action_count"] += 1

    outcome = event.outcome.value if hasattr(event.outcome, "value") else str(event.outcome or "")
    if outcome.lower() in ("failure", "error", "denied", "unauthorized"):
        m["failed_action_count"] += 1

    if event.service:
        m["_services"].add(event.service)
    if event.operation:
        m["_operations"].add(event.operation)
    if event.actor.ip_address:
        m["_ips"].add(event.actor.ip_address)


def _serialize_actor_stats(actor_raw: dict) -> dict:
    """Convert in-memory actor_raw (with sets) to serializable actor_stats dict."""
    actor_stats = {}
    for entity_type, entities in actor_raw.items():
        actor_stats[entity_type] = {}
        for entity_key, m in entities.items():
            actor_stats[entity_type][entity_key] = {
                "action_count": m["action_count"],
                "failed_action_count": m["failed_action_count"],
                "unique_services": len(m["_services"]),
                "unique_operations": len(m["_operations"]),
                "unique_source_ips": len(m["_ips"]),
            }
    return actor_stats


def main():
    parser_arg = argparse.ArgumentParser(description="CDR Scanner")
    parser_arg.add_argument("--scan-run-id", required=True)
    args = parser_arg.parse_args()

    scan_run_id = args.scan_run_id
    logger.info(f"CDR scan starting scan_run_id={scan_run_id}")

    start = datetime.now(timezone.utc)
    # Initialize so _write_failed_report can reference them even if exception fires early
    tenant_id = "unknown"
    provider = "aws"

    try:
        # 1. Get metadata — retry up to 6 times with 10s delay (on-demand nodes need
        #    30-60s to establish network/DNS connectivity to RDS after cold start)
        import time as _time
        meta = None
        for _attempt in range(6):
            try:
                meta = get_orchestration_metadata(scan_run_id)
                if meta:
                    break
            except Exception as _meta_err:
                logger.warning(f"get_orchestration_metadata attempt {_attempt+1}/6 failed: {_meta_err}")
            if _attempt < 5:
                _time.sleep(10)

        if not meta:
            raise RuntimeError(f"scan_run_id={scan_run_id} not found in scan_runs after 6 attempts")

        tenant_id = meta.get("tenant_id", "default-tenant")
        account_id = meta.get("account_id", "")
        provider = (meta.get("provider") or "aws").lower()
        region = meta.get("region", os.getenv("AWS_REGION", "ap-south-1"))
        credential_ref = meta.get("credential_ref", "")
        credential_type = meta.get("credential_type", "access_key")
        lookback_hours = int(os.getenv("LOG_LOOKBACK_HOURS", "1"))
        max_events = int(os.getenv("LOG_MAX_EVENTS", "500000"))

        logger.info(f"Tenant={tenant_id} account={account_id} provider={provider} lookback={lookback_hours}h")

        # Load CSP-specific parsers, readers, and session via provider factory
        from cdr_engine.providers import get_provider as get_cdr_provider
        cdr_provider_impl = get_cdr_provider(provider)
        PARSERS = cdr_provider_impl.get_parsers()
        READERS = cdr_provider_impl.get_readers()

        # Early exit for providers with no log collection support (e.g. AliCloud stub)
        if not PARSERS and not READERS:
            logger.warning(
                f"Provider '{provider}' has no CIEM log parsers/readers — "
                "writing skipped report and exiting"
            )
            _write_failed_report(scan_run_id, tenant_id, provider, f"CIEM not implemented for provider={provider}")
            return

        # 2. Resolve credentials, find log sources
        credentials = _resolve_cdr_credentials(account_id, credential_ref, credential_type, provider)

        finder = LogSourceFinder(tenant_id=tenant_id, account_id=account_id, provider=provider)
        sources = finder.find_all_sources(scan_run_id, region)
        logger.info(f"Found {len(sources)} log sources")

        if not sources:
            logger.warning("No log sources found — skipping collection, proceeding to rule evaluation")

        # 3. Create cloud session
        try:
            session = cdr_provider_impl.create_session(region, account_id, credentials)
        except Exception as sess_exc:
            logger.warning(
                f"CSP session creation failed for provider={provider}: {sess_exc} — "
                "log collection will be skipped; proceeding to rule evaluation"
            )
            session = None

        # 4. Ensure watermark table; load identifier index; compile L1 rules
        writer = EventWriter()
        writer.ensure_table()

        identifier_index = _load_identifier_index(provider)

        from cdr_engine.evaluator.rule_evaluator import CIEMRuleEvaluator
        evaluator = CIEMRuleEvaluator(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            provider=provider,
        )
        num_rules = evaluator.load()
        logger.info(f"L1: {num_rules} rules compiled and ready")

        # 5. Collect from each source — evaluate L1 in-memory, accumulate L3 stats
        all_findings = []   # L1 findings accumulated across all sources
        actor_raw = {}      # per-actor behavioral metrics (sets + ints) for L3
        source_stats = {}
        per_source_limit = max_events
        end_time = datetime.now(timezone.utc)
        fallback_lookback = __import__("datetime").timedelta(hours=lookback_hours)

        for source in sources:
            source_type = source.source_type
            storage_type = source.storage_type

            reader_cls = READERS.get(storage_type)
            parser_cls = PARSERS.get(source_type)

            if not reader_cls:
                logger.warning(f"No reader for storage_type={storage_type}")
                continue
            if not parser_cls:
                logger.warning(f"No parser for source_type={source_type}")
                continue

            # Per-source watermark: resume from last successful collection
            watermark = writer.get_watermark(tenant_id, account_id, source_type)
            if watermark:
                start_time = watermark
                logger.info(f"[{source_type}] Resuming from watermark {watermark.isoformat()}")
            else:
                start_time = end_time - fallback_lookback
                logger.info(f"[{source_type}] No watermark — using {lookback_hours}h lookback")

            reader = reader_cls()
            parser_inst = parser_cls()

            normalizer = EventNormalizer(
                source_type=source_type,
                field_mapping=parser_inst.get_field_mapping(),
                category=parser_inst.get_event_category(),
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                source_bucket=source.location,
                source_region=source.region,
                identifier_index=identifier_index,
            )

            source_count = 0
            source_max_event_time = None

            try:
                for raw_bytes in reader.read(session, source, start_time, end_time):
                    for raw_event in parser_inst.parse(raw_bytes):
                        event = normalizer.normalize(raw_event, source.prefix)
                        if event:
                            # L1: evaluate all rules against this event in pure Python
                            findings = evaluator.evaluate_event(event)
                            if findings:
                                all_findings.extend(findings)

                            # L3: accumulate behavioral metrics per actor
                            _update_actor_stats(event, actor_raw)

                            source_count += 1
                            if event.event_time and (
                                source_max_event_time is None
                                or event.event_time > source_max_event_time
                            ):
                                source_max_event_time = event.event_time

                            if source_count >= per_source_limit:
                                break
                    if source_count >= per_source_limit:
                        logger.info(f"[{source_type}] Hit per-source limit ({per_source_limit})")
                        break
            except Exception as src_exc:
                logger.error(f"[{source_type}] Collection error: {src_exc}", exc_info=True)

            source_stats[source_type] = source_count
            logger.info(
                f"[{source_type}] {source.location}: {source_count} events, "
                f"{sum(1 for f in all_findings if True)} L1 findings so far"
            )

            # Advance watermark
            new_watermark = source_max_event_time or end_time
            writer.update_watermark(tenant_id, account_id, source_type, new_watermark)

        # 6. Flush L1 findings to DB (one batch write)
        completed_at = datetime.now(timezone.utc)
        eval_stats = evaluator.flush(all_findings, start, completed_at)
        logger.info(f"L1: {eval_stats}")

        # Convert actor_raw (with sets) to serializable dict for L3
        actor_stats = _serialize_actor_stats(actor_raw)

        # 7. L2 Correlation evaluation (multi-event patterns, queries cdr_findings)
        l2_stats = {"total_findings": 0}
        try:
            from cdr_engine.evaluator.correlation_evaluator import CorrelationEvaluator
            correlator = CorrelationEvaluator(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
            )
            l2_stats = correlator.evaluate()
            logger.info(f"L2 correlation: {l2_stats}")
        except Exception as l2_exc:
            logger.warning(f"L2 correlation failed (non-fatal): {l2_exc}", exc_info=True)

        # 7b. Sequence detection (multi-event attack patterns — PC-DEPTH-06)
        seq_stats = {"total_findings": 0}
        try:
            from cdr_engine.detectors.sequence_detector import SequenceDetector
            seq_detector = SequenceDetector(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
            )
            seq_stats = seq_detector.detect(account_id=account_id, region=region)
            logger.info(f"Sequence detection: {seq_stats}")
        except Exception as seq_exc:
            logger.warning(f"Sequence detection failed (non-fatal): {seq_exc}", exc_info=True)

        # 8. L3 Baseline evaluation (behavioral anomaly detection)
        l3_stats = {"total_findings": 0}
        try:
            from cdr_engine.evaluator.baseline_evaluator import BaselineEvaluator
            baseline_eval = BaselineEvaluator(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
            )
            baseline_eval.ensure_tables()
            # Persist today's aggregated actor stats (feeds future L3 windows)
            baseline_eval.store_daily_stats(actor_stats, account_id)
            # Detect anomalies against historical baseline
            l3_stats = baseline_eval.evaluate(actor_stats)
            logger.info(f"L3 baselines: {l3_stats}")
        except Exception as l3_exc:
            logger.warning(f"L3 baselines failed (non-fatal): {l3_exc}", exc_info=True)

        total_findings = (
            eval_stats.get("total_findings", 0)
            + l2_stats.get("total_findings", 0)
            + seq_stats.get("total_findings", 0)
            + l3_stats.get("total_findings", 0)
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        logger.info(
            f"CDR scan completed: {scan_run_id} — "
            f"{total_findings} findings "
            f"(L1={eval_stats.get('total_findings', 0)}, "
            f"L2={l2_stats.get('total_findings', 0)}, "
            f"SEQ={seq_stats.get('total_findings', 0)}, "
            f"L3={l3_stats.get('total_findings', 0)}) "
            f"in {duration:.1f}s. Sources: {source_stats}"
        )

        # Retention: archive old scans to S3, keep last 5 in DB
        try:
            from engine_common.retention import run_retention
            run_retention("cdr", scan_run_id)
        except Exception as _ret_err:
            logger.warning("Retention cleanup skipped: %s", _ret_err)

        # Write CDR posture signals to resource_security_posture (non-fatal)
        try:
            from cdr_engine.posture_signals import (
                write_cdr_posture_signals,
                write_cdr_iam_cross_signal,
            )
            write_cdr_posture_signals(
                cdr_scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id or "",
                provider=provider,
            )
            # Link actor_principal ARNs → IAM role posture rows (PC-P2-02)
            write_cdr_iam_cross_signal(
                cdr_scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id or "",
                provider=provider,
            )
        except Exception as _ps_err:
            logger.warning("CDR posture signal write skipped: %s", _ps_err)

        # Write OBSERVED_ACCESS behavioral edges to asset_relationships (non-fatal)
        try:
            from cdr_engine.behavioral_edges import write_behavioral_edges
            write_behavioral_edges(
                cdr_scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id or "",
                provider=provider,
            )
        except Exception as _be_err:
            logger.warning("CDR behavioral edges write skipped: %s", _be_err)

        # Write CDR OPEN findings to shared security_findings table (non-fatal)
        # actor_principal is PII — store only actor_hash = sha256(actor_principal)[:32]
        try:
            import hashlib
            import psycopg2.extras
            from engine_common.security_findings_writer import upsert_findings
            from engine_common.db_connections import get_di_conn, get_cdr_conn

            cdr_conn = get_cdr_conn()
            inv_conn = get_di_conn()
            rows: list = []
            with cdr_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT finding_id, rule_id, resource_uid, resource_type,
                           account_id, provider, region, severity, status,
                           actor_principal, title, description,
                           mitre_tactics, mitre_techniques,
                           action_category, operation, first_seen_at
                    FROM cdr_findings
                    WHERE scan_run_id = %s AND tenant_id = %s AND LOWER(status) = 'open'
                    LIMIT 2000
                    """,
                    (scan_run_id, tenant_id),
                )
                for r in cur.fetchall():
                    actor = r.get("actor_principal") or ""
                    actor_hash = hashlib.sha256(actor.encode()).hexdigest()[:32] if actor else None
                    techs = r.get("mitre_techniques") or []
                    tacts = r.get("mitre_tactics") or []
                    rows.append({
                        "source_finding_id": str(r["finding_id"]),
                        "resource_uid": r.get("resource_uid") or "",
                        "account_id": r.get("account_id", ""),
                        "provider": r.get("provider", ""),
                        "resource_type": r.get("resource_type", ""),
                        "finding_type": "threat_detection",
                        "severity": (r.get("severity") or "medium").lower(),
                        "rule_id": r.get("rule_id", ""),
                        "title": r.get("title", ""),
                        "description": r.get("description", ""),
                        "mitre_technique_id": techs[0] if techs else None,
                        "mitre_tactic": tacts[0] if tacts else None,
                        "detail": {
                            "actor_hash": actor_hash,
                            "operation": r.get("operation"),
                            "action_category": r.get("action_category"),
                            "all_mitre_techniques": techs,
                            "all_mitre_tactics": tacts,
                        },
                        "status": "open",
                        "first_seen_at": r.get("first_seen_at"),
                    })
            try:
                if rows:
                    written = upsert_findings(
                        conn=inv_conn,
                        findings=rows,
                        source_engine="cdr",
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                    )
                    logger.info("security_findings: wrote %d CDR rows", written)
            finally:
                inv_conn.close()
                cdr_conn.close()
        except Exception as _sf_err:
            logger.warning("CDR security_findings write skipped: %s", _sf_err)

    except Exception as exc:
        logger.error(f"CIEM scan FAILED: {exc}", exc_info=True)
        _write_failed_report(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            provider=provider,
            error=str(exc)[:500],
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
