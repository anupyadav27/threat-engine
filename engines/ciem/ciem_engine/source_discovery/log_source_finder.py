"""
Log Source Finder — discovers where logs are stored by reading discovery/inventory data.

NO direct API calls — all data comes from discovery_findings or inventory_findings.
For multi-account SaaS: each account's discovery scan populates these tables.

Sources:
  - CloudTrail → S3 bucket (from aws.cloudtrail.describe_trails)
  - VPC Flow Logs → S3 bucket (from aws.ec2.describe_flow_logs)
  - ALB Access Logs → S3 bucket (from inventory_findings ELB attributes)
  - S3 Access Logs → S3 bucket (from inventory_findings bucket logging)
  - WAF Logs → S3 (from aws.wafv2.get_logging_configuration)
  - CloudFront Logs → S3 (from aws.cloudfront.list_distributions)
  - Route53 DNS → CloudWatch (from aws.route53.list_query_logging_configs)
  - RDS Audit → CloudWatch (from aws.rds.describe_db_instances)
  - EKS Audit → CloudWatch (from aws.eks.describe_cluster)
  - Lambda → CloudWatch (from aws.lambda.list_functions)
  - GuardDuty → S3 (from aws.guardduty.list_publishing_destinations)

Priority: user-configured (cloud_accounts.log_sources) → discovery data.
"""

import json
import logging
import os
from typing import Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

from ..reader.base_reader import LogSource

logger = logging.getLogger(__name__)


class LogSourceFinder:
    """Find log storage locations from discovery/inventory data + user config.

    Priority:
      1. User-configured log_sources (cloud_accounts.log_sources)
      2. Discovery data (discovery_findings / inventory_findings)

    NO direct API calls. For non-AWS CSPs, customer provides bucket details
    during onboarding. Discovery data enriches with auto-discovered sources.
    """

    def __init__(self, tenant_id: str, account_id: str = "", provider: str = "aws"):
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.provider = provider.lower()

    def _get_inventory_conn(self):
        return psycopg2.connect(
            host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )

    def _get_discovery_conn(self):
        return psycopg2.connect(
            host=os.getenv("DISCOVERIES_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("DISCOVERIES_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
            user=os.getenv("DISCOVERIES_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("DISCOVERIES_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )

    def _get_onboarding_conn(self):
        return psycopg2.connect(
            host=os.getenv("ONBOARDING_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("ONBOARDING_DB_PORT", os.getenv("DB_PORT", "5432"))),
            database=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
            user=os.getenv("ONBOARDING_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("ONBOARDING_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        )

    def _load_user_configured_sources(self) -> Dict[str, List[LogSource]]:
        """Load user-configured log sources from cloud_accounts.log_sources.

        Expected JSON format:
        {
          "cloudtrail": [{"bucket": "my-trail-bucket", "prefix": "AWSLogs/", "region": "us-east-1"}],
          "vpc_flow":   [{"bucket": "my-flow-bucket", "prefix": "", "region": "ap-south-1"}],
          "alb":        [{"bucket": "my-alb-logs", "prefix": "alb/", "region": "ap-south-1"}],
          "waf":        [{"bucket": "my-waf-logs"}],
          "s3_access":  [{"bucket": "my-s3-access-logs"}]
        }
        """
        result: Dict[str, List[LogSource]] = {}
        try:
            conn = self._get_onboarding_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT log_sources FROM cloud_accounts
                    WHERE account_number = %s AND tenant_id = %s
                    AND log_sources IS NOT NULL
                    LIMIT 1
                """, (self.account_id, self.tenant_id))
                row = cur.fetchone()
            conn.close()

            if not row or not row["log_sources"]:
                return result

            cfg = row["log_sources"]
            if isinstance(cfg, str):
                cfg = json.loads(cfg)

            for source_type, entries in cfg.items():
                if not isinstance(entries, list):
                    continue
                sources = []
                for entry in entries:
                    bucket = entry.get("bucket", "")
                    if not bucket:
                        continue
                    sources.append(LogSource(
                        source_type=source_type,
                        storage_type="s3",
                        location=bucket,
                        prefix=entry.get("prefix", ""),
                        region=entry.get("region", ""),
                        account_id=self.account_id,
                        format=entry.get("format", ""),
                    ))
                if sources:
                    result[source_type] = sources
                    logger.info(f"User-configured: {len(sources)} {source_type} source(s)")

        except Exception as exc:
            logger.debug(f"No user-configured log sources: {exc}")

        return result

    def find_all_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find all log sources for this tenant/account.

        Priority: user config → discovery data (no direct API calls).
        CSP-aware: only runs finders relevant to the account's cloud provider.
        """
        # Load user-configured sources first (highest priority)
        user_sources = self._load_user_configured_sources()

        sources = []

        # CSP-specific discovery finders
        finders_by_csp = {
            "aws": {
                "cloudtrail": self.find_cloudtrail_sources,
                "vpc_flow": self.find_vpc_flow_sources,
                "alb": self.find_alb_log_sources,
                "s3_access": self.find_s3_access_log_sources,
                "waf": self.find_waf_log_sources,
                "cloudfront": self.find_cloudfront_log_sources,
                "dns": self.find_dns_log_sources,
                "rds_audit": self.find_rds_audit_log_sources,
                "eks_audit": self.find_eks_audit_log_sources,
                "lambda": self.find_lambda_log_sources,
                "guardduty": self.find_guardduty_sources,
            },
            "azure": {
                "azure_activity": self._find_azure_activity_sources,
                "azure_nsg_flow": self._find_azure_nsg_flow_sources,
                "azure_aks_audit": self._find_azure_aks_sources,
                "azure_keyvault": self._find_azure_keyvault_sources,
                "azure_sql_audit": self._find_azure_sql_sources,
            },
            "gcp": {
                "gcp_audit": self._find_gcp_audit_sources,
                "gcp_vpc_flow": self._find_gcp_flow_sources,
                "gcp_gke_audit": self._find_gcp_gke_sources,
            },
            "oci": {
                "oci_audit": self._find_oci_audit_sources,
                "oci_vcn_flow": self._find_oci_flow_sources,
                "oci_oke_audit": self._find_oci_oke_sources,
            },
            "ibm": {
                "ibm_activity": self._find_ibm_activity_sources,
                "ibm_k8s_audit": self._find_ibm_k8s_sources,
            },
        }

        finders = finders_by_csp.get(self.provider, {})

        # For each type: use user config if available, otherwise auto-discover
        for stype, finder in finders.items():
            if stype in user_sources:
                sources.extend(user_sources[stype])
            else:
                sources.extend(finder(scan_run_id, region))

        # Include any extra user-configured types not in our finder list
        for stype, srcs in user_sources.items():
            if stype not in finders:
                sources.extend(srcs)

        logger.info(f"Found {len(sources)} total log sources for tenant={self.tenant_id} provider={self.provider}")
        return sources

    # ═══════════════════════════════════════════════════════════════
    # Azure Source Finders (discovery_findings based)
    # ═══════════════════════════════════════════════════════════════

    def _find_azure_activity_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find Azure Activity Log export to storage account from discovery data."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id FROM discovery_findings
                    WHERE discovery_id LIKE 'azure.monitor.%%diagnostic%%'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str): ef = json.loads(ef)
                    storage_id = ef.get("storageAccountId", "")
                    if storage_id:
                        # Extract storage account name from resource ID
                        parts = storage_id.split("/")
                        sa_name = parts[-1] if parts else ""
                        sources.append(LogSource(
                            source_type="azure_activity",
                            storage_type="azure_blob",
                            location=sa_name,
                            prefix="insights-activity-logs/",
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                            metadata={"storage_account_id": storage_id},
                        ))
            conn.close()
        except Exception as exc:
            logger.debug(f"Azure Activity source discovery failed: {exc}")
        logger.info(f"Azure Activity: {len(sources)} sources found")
        return sources

    def _find_azure_nsg_flow_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find Azure NSG Flow Log storage from discovery data."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id FROM discovery_findings
                    WHERE discovery_id LIKE 'azure.network.%%flow_log%%'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str): ef = json.loads(ef)
                    storage_id = ef.get("storageId", ef.get("storageAccountId", ""))
                    if storage_id:
                        sa_name = storage_id.split("/")[-1] if "/" in storage_id else storage_id
                        sources.append(LogSource(
                            source_type="azure_nsg_flow",
                            storage_type="azure_blob",
                            location=sa_name,
                            prefix="insights-logs-networksecuritygroupflowevent/",
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                        ))
            conn.close()
        except Exception as exc:
            logger.debug(f"Azure NSG Flow source discovery failed: {exc}")
        logger.info(f"Azure NSG Flow: {len(sources)} sources found")
        return sources

    def _find_azure_aks_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find AKS audit log sources — customer configures diagnostic settings to storage."""
        # AKS audit logs go to storage account via diagnostic settings
        # Discovered via azure.containerservice.managed_clusters
        return []  # User-configured via cloud_accounts.log_sources

    def _find_azure_keyvault_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        return []  # User-configured

    def _find_azure_sql_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        return []  # User-configured

    # ═══════════════════════════════════════════════════════════════
    # GCP Source Finders
    # ═══════════════════════════════════════════════════════════════

    def _find_gcp_audit_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find GCP Audit Log export to GCS from discovery data."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # GCP log sinks export to GCS buckets
                cur.execute("""
                    SELECT emitted_fields, region, account_id FROM discovery_findings
                    WHERE discovery_id LIKE 'gcp.logging.%%sink%%'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str): ef = json.loads(ef)
                    dest = ef.get("destination", "")
                    if dest.startswith("storage.googleapis.com/"):
                        bucket = dest.replace("storage.googleapis.com/", "")
                        sources.append(LogSource(
                            source_type="gcp_audit",
                            storage_type="gcs",
                            location=bucket,
                            prefix="cloudaudit.googleapis.com/",
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                        ))
            conn.close()
        except Exception as exc:
            logger.debug(f"GCP Audit source discovery failed: {exc}")
        logger.info(f"GCP Audit: {len(sources)} sources found")
        return sources

    def _find_gcp_flow_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        return []  # User-configured — VPC Flow Logs export to GCS via log sink

    def _find_gcp_gke_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        return []  # User-configured — GKE audit via log sink to GCS

    # ═══════════════════════════════════════════════════════════════
    # OCI Source Finders
    # ═══════════════════════════════════════════════════════════════

    def _find_oci_audit_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find OCI Audit Log export to Object Storage from discovery data."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id FROM discovery_findings
                    WHERE discovery_id LIKE 'oci.audit.%%configuration%%'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str): ef = json.loads(ef)
                    # OCI Service Connector Hub exports to Object Storage
                    bucket = ef.get("targetBucket", "")
                    namespace = ef.get("targetNamespace", "")
                    if bucket:
                        sources.append(LogSource(
                            source_type="oci_audit",
                            storage_type="oci_os",
                            location=f"{namespace}/{bucket}" if namespace else bucket,
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                        ))
            conn.close()
        except Exception as exc:
            logger.debug(f"OCI Audit source discovery failed: {exc}")
        logger.info(f"OCI Audit: {len(sources)} sources found")
        return sources

    def _find_oci_flow_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        return []  # User-configured

    def _find_oci_oke_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        return []  # User-configured

    # ═══════════════════════════════════════════════════════════════
    # IBM Source Finders
    # ═══════════════════════════════════════════════════════════════

    def _find_ibm_activity_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find IBM Activity Tracker export to COS from discovery data."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id FROM discovery_findings
                    WHERE discovery_id LIKE 'ibm.atracker.%%route%%'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str): ef = json.loads(ef)
                    targets = ef.get("targets", [])
                    for t in targets:
                        if t.get("target_type") == "cloud_object_storage":
                            bucket = t.get("cos_endpoint", {}).get("bucket", "")
                            endpoint = t.get("cos_endpoint", {}).get("endpoint", "")
                            if bucket:
                                sources.append(LogSource(
                                    source_type="ibm_activity",
                                    storage_type="ibm_cos",
                                    location=bucket,
                                    region=row.get("region", region),
                                    account_id=row.get("account_id", self.account_id),
                                    metadata={"endpoint": endpoint},
                                ))
            conn.close()
        except Exception as exc:
            logger.debug(f"IBM Activity source discovery failed: {exc}")
        logger.info(f"IBM Activity: {len(sources)} sources found")
        return sources

    def _find_ibm_k8s_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        return []  # User-configured

    def find_cloudtrail_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find CloudTrail S3 buckets from discovery data.

        Checks multiple discovery_ids: describe_trails (has S3BucketName)
        and list_trails (has TrailARN only). Also falls back to direct
        CloudTrail API if no S3 bucket found in discovery data.
        """
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Try describe_trails first (has S3BucketName)
                cur.execute("""
                    SELECT emitted_fields, region, account_id
                    FROM discovery_findings
                    WHERE discovery_id IN ('aws.cloudtrail.describe_trails', 'aws.cloudtrail.list_trails')
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))

                trail_arns = []
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    bucket = ef.get("S3BucketName", "")
                    prefix = ef.get("S3KeyPrefix", "")
                    if bucket:
                        if prefix and not prefix.endswith("/"):
                            prefix += "/"
                        sources.append(LogSource(
                            source_type="cloudtrail",
                            storage_type="s3",
                            location=bucket,
                            prefix=prefix,
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                        ))
                    else:
                        # list_trails doesn't have S3BucketName — save ARN for API lookup
                        arn = ef.get("TrailARN", "")
                        if arn:
                            trail_arns.append((arn, row.get("region", region)))
            conn.close()

            logger.info(f"CloudTrail discovery: {len(sources)} from DB, {len(trail_arns)} trail ARNs")

        except Exception as exc:
            logger.error(f"Failed to find CloudTrail sources: {exc}", exc_info=True)

        logger.info(f"CloudTrail: {len(sources)} trail buckets found")
        return sources

    def find_vpc_flow_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find VPC Flow Log S3 buckets from discovery data."""
        sources = []
        seen_buckets = set()
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.ec2.describe_flow_logs'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))

                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    # Discovery may store FlowLogs as nested array or flat
                    flow_logs = ef.get("FlowLogs", [ef]) if isinstance(ef, dict) else [ef]
                    for fl in flow_logs:
                        if not isinstance(fl, dict):
                            continue
                        src = self._parse_flow_log_entry(
                            fl, row.get("region", region),
                            row.get("account_id", self.account_id),
                        )
                        if src and src.location not in seen_buckets:
                            sources.append(src)
                            seen_buckets.add(src.location)
            conn.close()
        except Exception as exc:
            logger.warning(f"Failed to find VPC Flow sources from DB: {exc}")

        logger.info(f"VPC Flow: {len(sources)} sources found")
        return sources

    def _parse_flow_log_entry(self, fl: dict, region: str, account_id: str) -> Optional[LogSource]:
        """Parse a single flow log entry dict into a LogSource (S3 only)."""
        dest_type = fl.get("LogDestinationType", "")
        dest = fl.get("LogDestination", "")
        if dest_type == "s3" and dest:
            # dest is arn:aws:s3:::bucket-name/prefix
            bucket = dest.split(":::")[-1].split("/")[0] if ":::" in dest else dest
            prefix = "/".join(dest.split(":::")[-1].split("/")[1:]) if "/" in dest.split(":::")[-1] else ""
            return LogSource(
                source_type="vpc_flow",
                storage_type="s3",
                location=bucket,
                prefix=prefix,
                region=region,
                account_id=account_id,
                format="text",
            )
        return None

    def find_alb_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find ALB access log S3 buckets."""
        sources = []
        try:
            conn = self._get_inventory_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # ALB access logs are in the ELB's attributes
                cur.execute("""
                    SELECT resource_uid, properties, region, account_id
                    FROM inventory_findings
                    WHERE resource_type IN ('elbv2.load-balancer', 'elb.load-balancer')
                    AND tenant_id = %s
                    AND scan_run_id = %s
                """, (self.tenant_id, scan_run_id))

                for row in cur.fetchall():
                    props = row["properties"]
                    if isinstance(props, str):
                        props = json.loads(props)
                    ef = props.get("emitted_fields", props)
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    # Check AccessLogs attribute
                    access_logs = ef.get("AccessLogs", ef.get("access_logs", {}))
                    if isinstance(access_logs, dict) and access_logs.get("S3Enabled"):
                        bucket = access_logs.get("S3BucketName", "")
                        prefix = access_logs.get("S3BucketPrefix", "")
                        if bucket:
                            sources.append(LogSource(
                                source_type="alb",
                                storage_type="s3",
                                location=bucket,
                                prefix=prefix,
                                region=row.get("region", region),
                                account_id=row.get("account_id", self.account_id),
                                format="text",
                            ))
            conn.close()
        except Exception as exc:
            logger.warning(f"Failed to find ALB log sources: {exc}")

        logger.info(f"ALB: {len(sources)} sources found")
        return sources

    def find_s3_access_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find S3 server access log targets."""
        sources = []
        try:
            conn = self._get_inventory_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT resource_uid, configuration, region, account_id
                    FROM inventory_findings
                    WHERE resource_type = 's3.bucket'
                    AND tenant_id = %s AND scan_run_id = %s
                """, (self.tenant_id, scan_run_id))

                for row in cur.fetchall():
                    config = row["configuration"]
                    if isinstance(config, str):
                        config = json.loads(config)
                    if not isinstance(config, dict):
                        continue
                    # Check get_bucket_logging enrichment
                    logging_config = config.get("get_bucket_logging", {})
                    target_bucket = logging_config.get("TargetBucket", "")
                    target_prefix = logging_config.get("TargetPrefix", "")
                    if target_bucket:
                        sources.append(LogSource(
                            source_type="s3_access",
                            storage_type="s3",
                            location=target_bucket,
                            prefix=target_prefix,
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                            format="text",
                            metadata={"source_bucket": row["resource_uid"]},
                        ))
            conn.close()
        except Exception as exc:
            logger.warning(f"Failed to find S3 access log sources: {exc}")

        logger.info(f"S3 Access: {len(sources)} sources found")
        return sources

    # ── WAF Logs ──

    def find_waf_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find WAF logging destinations (S3 or Firehose→S3)."""
        sources = []
        seen = set()
        try:
            # Try discovery data first
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'aws.wafv2.list_web_acls',
                        'aws.wafv2.get_logging_configuration'
                    )
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    # get_logging_configuration has LoggingConfiguration.LogDestinationConfigs
                    log_config = ef.get("LoggingConfiguration", ef)
                    for dest in log_config.get("LogDestinationConfigs", []):
                        if "s3" in dest.lower() and ":::" in dest:
                            bucket = dest.split(":::")[-1].split("/")[0]
                            if bucket not in seen:
                                sources.append(LogSource(
                                    source_type="waf", storage_type="s3",
                                    location=bucket, prefix="",
                                    region=row.get("region", region),
                                    account_id=row.get("account_id", self.account_id),
                                ))
                                seen.add(bucket)
            conn.close()
        except Exception as exc:
            logger.debug(f"WAF discovery query failed: {exc}")

        logger.info(f"WAF: {len(sources)} sources found")
        return sources

    # ── CloudFront Logs ──

    def find_cloudfront_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find CloudFront access log S3 buckets."""
        sources = []
        seen = set()
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, account_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'aws.cloudfront.list_distributions',
                        'aws.cloudfront.get_distribution'
                    )
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    # Distribution config has Logging.Bucket and Logging.Prefix
                    dist_config = ef.get("DistributionConfig", ef)
                    logging_cfg = dist_config.get("Logging", {})
                    if logging_cfg.get("Enabled") and logging_cfg.get("Bucket"):
                        bucket = logging_cfg["Bucket"].replace(".s3.amazonaws.com", "")
                        prefix = logging_cfg.get("Prefix", "")
                        if bucket not in seen:
                            sources.append(LogSource(
                                source_type="cloudfront", storage_type="s3",
                                location=bucket, prefix=prefix,
                                region="us-east-1",  # CF logs are always global
                                account_id=row.get("account_id", self.account_id),
                                format="tsv_gz",
                            ))
                            seen.add(bucket)
            conn.close()
        except Exception as exc:
            logger.debug(f"CloudFront discovery query failed: {exc}")

        logger.info(f"CloudFront: {len(sources)} sources found")
        return sources

    # ── Route53 DNS Query Logs ──

    def find_dns_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find Route53 DNS query log destinations from discovery data.

        Uses: aws.route53.list_query_logging_configs (already discovered)
        Each row has {Id, CloudWatchLogsLogGroupArn}
        """
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, account_id
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.route53.list_query_logging_configs'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    log_group_arn = ef.get("CloudWatchLogsLogGroupArn", "")
                    if log_group_arn:
                        group_name = log_group_arn.split("log-group:")[-1].rstrip(":*")
                        sources.append(LogSource(
                            source_type="dns",
                            storage_type="cloudwatch",
                            location=group_name,
                            region="us-east-1",  # DNS logging is always us-east-1
                            account_id=row.get("account_id", self.account_id),
                            format="json",
                            metadata={"config_id": ef.get("Id", "")},
                        ))
            conn.close()
        except Exception as exc:
            logger.debug(f"DNS query log discovery failed: {exc}")

        logger.info(f"DNS: {len(sources)} sources found")
        return sources

    # ── RDS Audit Logs ──

    def find_rds_audit_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find RDS audit log CloudWatch log groups."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.rds.describe_db_instances'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    db_id = ef.get("DBInstanceIdentifier", "")
                    engine = ef.get("Engine", "")
                    enabled_logs = ef.get("EnabledCloudwatchLogsExports", [])
                    r = row.get("region", region)
                    for log_type in enabled_logs:
                        if log_type in ("audit", "general", "slowquery", "error", "postgresql"):
                            group_name = f"/aws/rds/instance/{db_id}/{log_type}"
                            sources.append(LogSource(
                                source_type="rds_audit",
                                storage_type="cloudwatch",
                                location=group_name,
                                region=r,
                                account_id=row.get("account_id", self.account_id),
                                format="csv" if engine.startswith("mysql") else "json",
                                metadata={"db_instance": db_id, "engine": engine, "log_type": log_type},
                            ))
            conn.close()
        except Exception as exc:
            logger.debug(f"RDS audit log discovery failed: {exc}")

        logger.info(f"RDS Audit: {len(sources)} sources found")
        return sources

    # ── EKS Audit Logs ──

    def find_eks_audit_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find EKS cluster audit log CloudWatch log groups."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id
                    FROM discovery_findings
                    WHERE discovery_id IN ('aws.eks.list_clusters', 'aws.eks.describe_cluster')
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                seen_clusters = set()
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    cluster_name = ef.get("name", ef.get("Name", ""))
                    r = row.get("region", region)
                    if not cluster_name or cluster_name in seen_clusters:
                        continue
                    seen_clusters.add(cluster_name)
                    # EKS logs go to /aws/eks/<cluster-name>/cluster
                    # Check if audit logging is enabled
                    logging_cfg = ef.get("logging", {})
                    log_types = []
                    for lc in logging_cfg.get("clusterLogging", []):
                        if lc.get("enabled"):
                            log_types.extend(lc.get("types", []))
                    if "audit" in log_types or "api" in log_types:
                        for lt in ["audit", "authenticator"]:
                            if lt in log_types or lt == "audit":
                                sources.append(LogSource(
                                    source_type=f"eks_{lt}",
                                    storage_type="cloudwatch",
                                    location=f"/aws/eks/{cluster_name}/cluster",
                                    prefix=lt,  # stream prefix filter
                                    region=r,
                                    account_id=row.get("account_id", self.account_id),
                                    format="json",
                                    metadata={"cluster_name": cluster_name, "log_type": lt},
                                ))
            conn.close()
        except Exception as exc:
            logger.debug(f"EKS audit log discovery failed: {exc}")

        logger.info(f"EKS Audit: {len(sources)} sources found")
        return sources

    # ── Lambda Logs ──

    def find_lambda_log_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find Lambda function CloudWatch log groups."""
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT emitted_fields, region, account_id
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.lambda.list_functions'
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    fn_name = ef.get("FunctionName", "")
                    if fn_name:
                        sources.append(LogSource(
                            source_type="lambda",
                            storage_type="cloudwatch",
                            location=f"/aws/lambda/{fn_name}",
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                            format="text",
                            metadata={"function_name": fn_name},
                        ))
            conn.close()
        except Exception as exc:
            logger.debug(f"Lambda log discovery failed: {exc}")

        logger.info(f"Lambda: {len(sources)} sources found")
        return sources

    # ── GuardDuty Findings ──

    def find_guardduty_sources(self, scan_run_id: str, region: str = "") -> List[LogSource]:
        """Find GuardDuty finding export S3 buckets from discovery data.

        Uses: aws.guardduty.list_detectors + aws.guardduty.list_publishing_destinations
        """
        sources = []
        try:
            conn = self._get_discovery_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # GuardDuty publishing destinations have the S3 bucket info
                cur.execute("""
                    SELECT emitted_fields, region, account_id
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'aws.guardduty.list_publishing_destinations',
                        'aws.guardduty.describe_publishing_destination'
                    )
                    AND scan_run_id = %s AND tenant_id = %s
                """, (scan_run_id, self.tenant_id))
                for row in cur.fetchall():
                    ef = row["emitted_fields"]
                    if isinstance(ef, str):
                        ef = json.loads(ef)
                    dest_type = ef.get("DestinationType", "")
                    dest_arn = ef.get("DestinationArn", "")
                    if dest_type == "S3" and ":::" in dest_arn:
                        bucket = dest_arn.split(":::")[-1]
                        sources.append(LogSource(
                            source_type="guardduty",
                            storage_type="s3",
                            location=bucket,
                            region=row.get("region", region),
                            account_id=row.get("account_id", self.account_id),
                            format="json_gz",
                        ))
            conn.close()
        except Exception as exc:
            logger.debug(f"GuardDuty discovery failed: {exc}")

        logger.info(f"GuardDuty: {len(sources)} sources found")
        return sources
