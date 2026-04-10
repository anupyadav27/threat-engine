"""
Log Collection Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Flow:
  1. Get orchestration metadata (tenant, account, provider)
  2. Find log sources from inventory/discovery data
  3. For each source: read → parse → normalize → store
  4. Write summary to log_collection_report
"""

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine_common.logger import setup_logger
from engine_common.orchestration import get_orchestration_metadata

# Configure root logger so all modules (source_discovery, reader, parser) output logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")

from ciem_engine.source_discovery.log_source_finder import LogSourceFinder
from ciem_engine.normalizer.event_normalizer import EventNormalizer
from ciem_engine.storage.event_writer import EventWriter
from ciem_engine.tenant_storage.log_store import TenantLogStore

# AWS readers
from ciem_engine.reader.aws_s3_reader import AWSS3Reader
from ciem_engine.reader.aws_cloudwatch_reader import AWSCloudWatchReader

# AWS parsers
from ciem_engine.parser.cloudtrail_parser import CloudTrailParser
from ciem_engine.parser.vpc_flow_parser import VPCFlowParser
from ciem_engine.parser.alb_parser import ALBParser
from ciem_engine.parser.waf_parser import WAFParser
from ciem_engine.parser.cloudfront_parser import CloudFrontParser
from ciem_engine.parser.s3_access_parser import S3AccessParser
from ciem_engine.parser.dns_parser import DNSParser
from ciem_engine.parser.rds_audit_parser import RDSAuditParser
from ciem_engine.parser.eks_audit_parser import EKSAuditParser
from ciem_engine.parser.lambda_parser import LambdaParser
from ciem_engine.parser.guardduty_parser import GuardDutyParser

# Multi-CSP parsers (lazy import to avoid SDK deps when not needed)
def _import_csp_parsers():
    """Import CSP-specific parsers. Returns dict of source_type → parser class."""
    extra = {}
    try:
        from ciem_engine.parser.azure_activity_parser import AzureActivityParser
        from ciem_engine.parser.azure_nsg_flow_parser import AzureNSGFlowParser
        extra["azure_activity"] = AzureActivityParser
        extra["azure_nsg_flow"] = AzureNSGFlowParser
    except ImportError:
        pass
    try:
        from ciem_engine.parser.gcp_audit_parser import GCPAuditParser
        from ciem_engine.parser.gcp_flow_parser import GCPFlowParser
        extra["gcp_audit"] = GCPAuditParser
        extra["gcp_vpc_flow"] = GCPFlowParser
    except ImportError:
        pass
    try:
        from ciem_engine.parser.oci_audit_parser import OCIAuditParser
        extra["oci_audit"] = OCIAuditParser
    except ImportError:
        pass
    try:
        from ciem_engine.parser.ibm_activity_parser import IBMActivityParser
        extra["ibm_activity"] = IBMActivityParser
    except ImportError:
        pass
    return extra

def _import_csp_readers():
    """Import CSP-specific readers. Returns dict of storage_type → reader class."""
    extra = {}
    try:
        from ciem_engine.reader.azure_blob_reader import AzureBlobReader
        extra["azure_blob"] = AzureBlobReader
    except ImportError:
        pass
    try:
        from ciem_engine.reader.gcp_gcs_reader import GCSReader
        extra["gcs"] = GCSReader
    except ImportError:
        pass
    try:
        from ciem_engine.reader.oci_os_reader import OCIObjectStorageReader
        extra["oci_os"] = OCIObjectStorageReader
    except ImportError:
        pass
    try:
        from ciem_engine.reader.ibm_cos_reader import IBMCOSReader
        extra["ibm_cos"] = IBMCOSReader
    except ImportError:
        pass
    return extra

logger = setup_logger(__name__, engine_name="ciem-scanner")


def _load_identifier_index(csp: str = "aws") -> dict:
    """Load identifier patterns from resource_inventory_identifier table.

    Returns: {service.canonical_type → {identifier_pattern, primary_param, canonical_type}}
    """
    import psycopg2
    from psycopg2.extras import RealDictCursor
    try:
        conn = psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT service, canonical_type, identifier_pattern, primary_param
            FROM resource_inventory_identifier
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

# Parser registry: source_type → parser class
PARSERS = {
    # AWS
    "cloudtrail": CloudTrailParser,
    "vpc_flow": VPCFlowParser,
    "alb": ALBParser,
    "waf": WAFParser,
    "cloudfront": CloudFrontParser,
    "s3_access": S3AccessParser,
    "dns": DNSParser,
    "rds_audit": RDSAuditParser,
    "eks_audit": EKSAuditParser,
    "eks_authenticator": EKSAuditParser,
    "lambda": LambdaParser,
    "guardduty": GuardDutyParser,
}
# Add multi-CSP parsers (Azure, GCP, OCI, IBM)
PARSERS.update(_import_csp_parsers())

# Reader registry: storage_type → reader class
READERS = {
    "s3": AWSS3Reader,
    "cloudwatch": AWSCloudWatchReader,
}
# Add multi-CSP readers
READERS.update(_import_csp_readers())


def _create_cloud_session(provider: str, region: str, account_id: str):
    """Create CSP-specific session for reading logs from storage.

    AWS: boto3 session (credentials from environment/IAM role)
    Azure: DefaultAzureCredential or connection string
    GCP: google.auth.default() or service account
    OCI: OCI config from environment
    IBM: IBM API key from environment
    """
    provider = provider.lower()

    if provider == "aws":
        import boto3
        return boto3.Session(region_name=region)

    elif provider == "azure":
        try:
            from azure.identity import DefaultAzureCredential
            return DefaultAzureCredential()
        except ImportError:
            logger.warning("azure-identity not installed — Azure log collection unavailable")
            return None

    elif provider == "gcp":
        try:
            from google.cloud import storage as gcs_storage
            return gcs_storage.Client()
        except ImportError:
            logger.warning("google-cloud-storage not installed — GCP log collection unavailable")
            return None

    elif provider == "oci":
        try:
            import oci
            config = oci.config.from_file() if os.path.exists(os.path.expanduser("~/.oci/config")) else {
                "tenancy": os.getenv("OCI_TENANCY", ""),
                "user": os.getenv("OCI_USER", ""),
                "fingerprint": os.getenv("OCI_FINGERPRINT", ""),
                "key_file": os.getenv("OCI_KEY_FILE", ""),
                "region": region or os.getenv("OCI_REGION", ""),
            }
            return config
        except ImportError:
            logger.warning("oci SDK not installed — OCI log collection unavailable")
            return None

    elif provider == "ibm":
        return {
            "api_key": os.getenv("IBM_API_KEY", ""),
            "service_instance_id": os.getenv("IBM_COS_INSTANCE_ID", ""),
            "endpoint": os.getenv("IBM_COS_ENDPOINT", "https://s3.us-south.cloud-object-storage.appdomain.cloud"),
        }

    else:
        logger.warning(f"Unknown provider: {provider}")
        return None


def main():
    parser_arg = argparse.ArgumentParser(description="Log Collection Scanner")
    parser_arg.add_argument("--scan-run-id", required=True)
    args = parser_arg.parse_args()

    scan_run_id = args.scan_run_id
    logger.info(f"Log collection starting scan_run_id={scan_run_id}")

    start = datetime.now(timezone.utc)

    try:
        # 1. Get metadata
        meta = get_orchestration_metadata(scan_run_id)
        tenant_id = meta.get("tenant_id", "default-tenant")
        account_id = meta.get("account_id", "")
        provider = (meta.get("provider") or "aws").lower()
        region = meta.get("region", os.getenv("AWS_REGION", "ap-south-1"))
        lookback_hours = int(os.getenv("LOG_LOOKBACK_HOURS", "24"))
        max_events = int(os.getenv("LOG_MAX_EVENTS", "100000"))

        logger.info(f"Tenant={tenant_id} account={account_id} provider={provider} lookback={lookback_hours}h")

        # 2. Find log sources
        finder = LogSourceFinder(tenant_id=tenant_id, account_id=account_id, provider=provider)
        sources = finder.find_all_sources(scan_run_id, region)
        logger.info(f"Found {len(sources)} log sources")

        if not sources:
            logger.warning("No log sources found — nothing to collect")
            return

        # 3. Create cloud session for reading logs (CSP-specific)
        session = _create_cloud_session(provider, region, account_id)

        # 4. Ensure log_events table
        writer = EventWriter()
        writer.ensure_table()

        # 4b. Load identifier index for ARN construction
        identifier_index = _load_identifier_index(provider)

        # 5. Collect from each source (per-source limit, not global)
        total_events = 0
        source_stats = {}
        per_source_limit = max_events  # each source gets the full allocation
        start_time = datetime.now(timezone.utc) - __import__("datetime").timedelta(hours=lookback_hours)
        end_time = datetime.now(timezone.utc)

        for source in sources:
            source_type = source.source_type
            storage_type = source.storage_type

            # Get reader and parser
            reader_cls = READERS.get(storage_type)
            parser_cls = PARSERS.get(source_type)

            if not reader_cls:
                logger.warning(f"No reader for storage_type={storage_type}")
                continue
            if not parser_cls:
                logger.warning(f"No parser for source_type={source_type}")
                continue

            reader = reader_cls()
            parser_inst = parser_cls()

            # Create normalizer
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

            # Read → Parse → Normalize
            events = []
            source_count = 0

            try:
                for raw_bytes in reader.read(session, source, start_time, end_time):
                    for raw_event in parser_inst.parse(raw_bytes):
                        event = normalizer.normalize(raw_event, source.prefix)
                        if event:
                            events.append(event)
                            source_count += 1
                            # Flush in batches of 5000 to control memory
                            if len(events) >= 5000:
                                written = writer.write_events(events)
                                total_events += written
                                events = []
                            if source_count >= per_source_limit:
                                break
                    if source_count >= per_source_limit:
                        logger.info(f"[{source_type}] Hit per-source limit ({per_source_limit})")
                        break
            except Exception as src_exc:
                logger.error(f"[{source_type}] Collection error: {src_exc}", exc_info=True)

            # Write remaining events
            if events:
                written = writer.write_events(events)
                total_events += written

            source_stats[source_type] = source_count
            logger.info(f"[{source_type}] {source.location}: {source_count} events collected")

        # 6. Evaluate rules against collected events
        logger.info("Starting rule evaluation...")
        from ciem_engine.evaluator.rule_evaluator import CIEMRuleEvaluator
        evaluator = CIEMRuleEvaluator(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            provider=provider,
        )
        eval_stats = evaluator.evaluate()
        logger.info(f"Rule evaluation: {eval_stats}")

        # 7. L2 Correlation evaluation (multi-event patterns)
        l2_stats = {"total_findings": 0}
        try:
            from ciem_engine.evaluator.correlation_evaluator import CorrelationEvaluator
            correlator = CorrelationEvaluator(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
            )
            l2_stats = correlator.evaluate()
            logger.info(f"L2 correlation: {l2_stats}")
        except Exception as l2_exc:
            logger.warning(f"L2 correlation failed (non-fatal): {l2_exc}", exc_info=True)

        # 8. L3 Baseline evaluation (behavioral anomaly detection)
        l3_stats = {"total_findings": 0}
        try:
            from ciem_engine.evaluator.baseline_evaluator import BaselineEvaluator
            baseline_eval = BaselineEvaluator(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
            )
            l3_stats = baseline_eval.evaluate()
            logger.info(f"L3 baselines: {l3_stats}")
        except Exception as l3_exc:
            logger.warning(f"L3 baselines failed (non-fatal): {l3_exc}", exc_info=True)

        # 9. Cleanup old events
        writer.cleanup_old_events(tenant_id, keep_days=30)

        total_findings = (
            eval_stats.get('total_findings', 0)
            + l2_stats.get('total_findings', 0)
            + l3_stats.get('total_findings', 0)
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        logger.info(
            f"CIEM scan completed: {scan_run_id} — "
            f"{total_events} events, {total_findings} findings "
            f"(L1={eval_stats.get('total_findings', 0)}, "
            f"L2={l2_stats.get('total_findings', 0)}, "
            f"L3={l3_stats.get('total_findings', 0)}) "
            f"in {duration:.1f}s. Sources: {source_stats}"
        )

    except Exception as exc:
        logger.error(f"Log collection FAILED: {exc}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
