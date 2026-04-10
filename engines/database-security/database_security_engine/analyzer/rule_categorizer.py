"""
Rule Categorizer — Maps check rule_ids to database security domains.

Security domains:
  - access_control      — public access, IAM auth, RBAC, sharing restrictions
  - encryption          — at-rest, in-transit, KMS/CMK, snapshot encryption
  - audit_logging       — audit logs, CloudWatch, monitoring, alerting
  - backup_recovery     — backups, PITR, snapshots, deletion protection, retention
  - network_security    — VPC, subnets, TLS/SSL, security groups, ports, endpoints
  - configuration       — version upgrades, maintenance, parameter groups, misc config
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── DB services recognized by this engine ────────────────────────────────────
DB_SERVICES = frozenset({
    "rds", "dynamodb", "redshift", "elasticache", "neptune",
    "documentdb", "opensearch", "timestream", "keyspaces", "dax",
})

SECURITY_DOMAINS = frozenset({
    "access_control", "encryption", "audit_logging",
    "backup_recovery", "network_security", "configuration",
})

# ── Exhaustive rule → domain mapping ────────────────────────────────────────
RULE_DOMAIN_MAP: Dict[str, str] = {
    # ─── RDS ─────────────────────────────────────────────────────────────────
    # access_control
    "aws.rds.instance.public_access_disabled": "access_control",
    "aws.rds.instance.iam_authentication_enabled": "access_control",
    "aws.rds.instance.no_public_access_configured": "access_control",
    "aws.rds.instance.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    "aws.rds.snapshot.not_publicly_shared_configured": "access_control",
    "aws.rds.snapshot.not_public_configured": "access_control",
    "aws.rds.snapshot.cross_account_sharing_restricted": "access_control",
    "aws.rds.snapshots.public_access_configured": "access_control",
    "aws.rds.snapshots_public_access.snapshots_public_access_configured": "access_control",
    "aws.rds.cluster.public_access_disabled": "access_control",
    "aws.rds.cluster.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    "aws.rds.clustersnapshot.not_publicly_shared_configured": "access_control",
    "aws.rds.clustersnapshot.snapshot_cross_account_sharing_restricted": "access_control",
    "aws.rds.dbuser.approved_list_of_superusers_only_configured": "access_control",
    "aws.rds.dbuser.no_unused_or_default_superusers_configured": "access_control",
    "aws.rds.dbuser.iam_auth_preferred_configured": "access_control",
    "aws.rds.reserved_instance.billing_admins_mfa_required": "access_control",
    "aws.rds.reserved_instance.purchase_permissions_restricted": "access_control",
    "aws.rds.reserved_instance.instance_approval_workflow_required": "access_control",
    # encryption
    "aws.rds.instance.storage_encrypted": "encryption",
    "aws.rds.instance.encryption_at_rest_enabled": "encryption",
    "aws.rds.instance.backup_encrypted": "encryption",
    "aws.rds.instance.transport_encrypted": "encryption",
    "aws.rds.instance.require_tls_in_transit_configured": "encryption",
    "aws.rds.cluster.encryption_at_rest_enabled": "encryption",
    "aws.rds.cluster.encryption_at_rest_cmek_configured": "encryption",
    "aws.rds.cluster.storage_encrypted": "encryption",
    "aws.rds.cluster.require_tls_in_transit_configured": "encryption",
    "aws.rds.snapshot.encryption_at_rest_enabled": "encryption",
    "aws.rds.snapshot.storage_encrypted": "encryption",
    "aws.rds.snapshot.cross_region_copy_encrypted": "encryption",
    "aws.rds.clustersnapshot.encryption_at_rest_enabled": "encryption",
    "aws.rds.clustersnapshot.snapshot_cross_region_copy_encrypted": "encryption",
    "aws.rds.resource.snapshots_encrypted": "encryption",
    "aws.rds.resource.dynamodb_table_encryption_enabled": "encryption",
    "aws.rds.parametergroup.require_ssl_configured": "encryption",
    # audit_logging
    "aws.rds.instance.enhanced_monitoring_enabled": "audit_logging",
    "aws.rds.instance.integration_cloudwatch_logs_configured": "audit_logging",
    "aws.rds.instance.performance_insights_enabled": "audit_logging",
    "aws.rds.cluster.audit_logging_enabled": "audit_logging",
    "aws.rds.cluster.integration_cloudwatch_logs_configured": "audit_logging",
    "aws.rds.parametergroup.audit_logging_enabled": "audit_logging",
    "aws.rds.parametergroup.logging_enabled": "audit_logging",
    # backup_recovery
    "aws.rds.instance.deletion_protection_enabled": "backup_recovery",
    "aws.rds.instance.deletion_protection_configured": "backup_recovery",
    "aws.rds.instance.backup_enabled": "backup_recovery",
    "aws.rds.instance.copy_tags_to_snapshots_configured": "backup_recovery",
    "aws.rds.instance.multi_az_configured": "backup_recovery",
    "aws.rds.cluster.deletion_protection_enabled": "backup_recovery",
    "aws.rds.cluster.multi_az_configured": "backup_recovery",
    "aws.rds.cluster.copy_tags_to_snapshots_configured": "backup_recovery",
    "aws.rds.backup_retention_period.backup_retention_period_configured": "backup_recovery",
    # network_security
    "aws.rds.instance.inside_vpc_configured": "network_security",
    "aws.rds.cluster.private_networking_enforced": "network_security",
    "aws.rds.subnetgroup.private_subnets_only_configured": "network_security",
    "aws.rds.securitygroup.security_egress_restricted": "network_security",
    "aws.rds.securitygroup.security_only_required_ports_open_restricted": "network_security",
    "aws.rds.securitygroup.security_no_0_ingress_on_db_ports_configured": "network_security",
    # configuration
    "aws.rds.instance.auto_minor_version_upgrade_configured": "configuration",
    "aws.rds.instance.security_configuration_review_configured": "configuration",
    "aws.rds.optiongroup.insecure_extensions_not_enabled": "configuration",
    "aws.rds.optiongroup.only_approved_extensions_enabled": "configuration",
    "aws.rds.parametergroup.insecure_features_disabled_if_applicable_configured": "configuration",

    # ─── DynamoDB ────────────────────────────────────────────────────────────
    # access_control
    "aws.dynamodb.table.rbac_least_privilege": "access_control",
    "aws.dynamodb.stream.consumer_auth_required": "access_control",
    # encryption
    "aws.dynamodb.accelerator.cluster_encryption_enabled": "encryption",
    "aws.dynamodb.cluster.encryption_enabled": "encryption",
    "aws.dynamodb.cluster.in_transit_encryption_enabled": "encryption",
    "aws.dynamodb.resource.encryption_enabled": "encryption",
    "aws.dynamodb.table.encryption_at_rest_enabled": "encryption",
    "aws.dynamodb.stream.encryption_at_rest_enabled": "encryption",
    "aws.dynamodb.tables.kms_cmk_encryption_enabled": "encryption",
    "aws.dynamodb.resource.tables_kms_cmk_encryption_enabled": "encryption",
    "aws.dynamodb.globaltable.cross_region_replication_encrypted": "encryption",
    "aws.dynamodb.globaltable.encryption_at_rest_all_regions_configured": "encryption",
    # audit_logging (none in metadata — handled by keyword fallback)
    # backup_recovery
    "aws.dynamodb.resource.backup_enabled": "backup_recovery",
    "aws.dynamodb.resource.dynamodb_pitr_enabled": "backup_recovery",
    "aws.dynamodb.tables.table_pitr_enabled": "backup_recovery",
    "aws.dynamodb.globaltable.table_pitr_enabled_if_supported": "backup_recovery",
    "aws.dynamodb.table_protected_by_backup_plan.table_protected_by_backup_plan_configured": "backup_recovery",
    "aws.dynamodb.resource.global_tables_enabled": "backup_recovery",
    "aws.dynamodb.cluster.dynamodb_multi_az_configured": "backup_recovery",
    # network_security
    "aws.dynamodb.table.private_network_only_if_supported": "network_security",
    "aws.dynamodb.stream.private_network_only_if_supported": "network_security",
    # configuration
    "aws.dynamodb.resource.dynamodb_autoscaling_enabled": "configuration",

    # ─── Redshift ────────────────────────────────────────────────────────────
    # access_control
    "aws.redshift.cluster.public_access_configured": "access_control",
    "aws.redshift.cluster.admin_access_least_privilege": "access_control",
    "aws.redshift.snapshot.not_publicly_shared_configured": "access_control",
    "aws.redshift.snapshot.redshift_cross_account_sharing_restricted": "access_control",
    "aws.redshift.endpoint_authorization.no_anonymous_access_configured": "access_control",
    "aws.redshift.endpoint_authorization.rbac_least_privilege": "access_control",
    "aws.redshift.user.redshift_approved_list_of_supers_only_configured": "access_control",
    "aws.redshift.user.redshift_no_unused_or_default_supers_configured": "access_control",
    "aws.redshift.user.iam_auth_preferred_configured": "access_control",
    "aws.redshift.event_subscription.redshift_cross_account_sharing_restricted": "access_control",
    "aws.redshift.event_subscription.redshift_destination_least_privilege": "access_control",
    # encryption
    "aws.redshift.cluster.encryption_at_rest_enabled": "encryption",
    "aws.redshift.cluster.encryption_at_rest_cmek_configured": "encryption",
    "aws.redshift.cluster.in_transit_encryption_enabled": "encryption",
    "aws.redshift.cluster.tls_min_1_2_enforced": "encryption",
    "aws.redshift.snapshot.encryption_at_rest_enabled": "encryption",
    "aws.redshift.snapshot.redshift_cross_region_copy_encrypted": "encryption",
    "aws.redshift.snapshot.kms_key_policy_least_privilege": "encryption",
    "aws.redshift.event_subscription.redshift_destination_encrypted": "encryption",
    "aws.redshift.parametergroup.require_ssl_configured": "encryption",
    "aws.redshift.parametergroup.tls_required": "encryption",
    "aws.redshift.endpointaccess.tls_required": "encryption",
    "aws.redshift.hsm_configuration.redshift_configuration_present": "encryption",
    "aws.redshift.hsm_configuration.keys_in_hsm_only_configured": "encryption",
    "aws.redshift.hsm_configuration.only_approved_hsm_endpoints_configured": "encryption",
    "aws.redshift.hsm_client_certificate.key_length_minimum": "encryption",
    "aws.redshift.hsm_client_certificate.certificate_trusted_issuer_verified": "encryption",
    "aws.redshift.hsm_client_certificate.certificate_valid": "encryption",
    # audit_logging
    "aws.redshift.cluster.audit_logging_enabled": "audit_logging",
    "aws.redshift.cluster.audit_logging_configured": "audit_logging",
    "aws.redshift.parametergroup.audit_logging_enabled": "audit_logging",
    "aws.redshift.parametergroup.logging_enabled": "audit_logging",
    # backup_recovery
    "aws.redshift.resource.backup_enabled": "backup_recovery",
    "aws.redshift.cluster.automated_snapshot_configured": "backup_recovery",
    "aws.redshift.cluster.deletion_protection_enabled": "backup_recovery",
    "aws.redshift.cluster.multi_az_enabled": "backup_recovery",
    # network_security
    "aws.redshift.cluster.private_networking_enforced": "network_security",
    "aws.redshift.cluster.enhanced_vpc_routing_configured": "network_security",
    "aws.redshift.subnetgroup.redshift_private_subnets_only_configured": "network_security",
    "aws.redshift.securitygroup.security_egress_restricted": "network_security",
    "aws.redshift.securitygroup.security_no_0_configured": "network_security",
    "aws.redshift.securitygroup.security_no_0_ingress_configured": "network_security",
    "aws.redshift.securitygroup.security_no_0_ingress_on_db_ports_configured": "network_security",
    "aws.redshift.securitygroup.security_only_required_ports_open_restricted": "network_security",
    "aws.redshift.securitygroup.security_only_required_ports": "network_security",
    "aws.redshift.endpointaccess.access_allowed_cidrs_minimized_configured": "network_security",
    "aws.redshift.endpointaccess.access_private_only_configured": "network_security",
    # configuration
    "aws.redshift.cluster.minor_version_auto_upgrade_enabled": "configuration",
    "aws.redshift.cluster.automatic_upgrades_configured": "configuration",
    "aws.redshift.cluster.maintenance_settings_configured": "configuration",
    "aws.redshift.parametergroup.redshift_insecure_features_disabled_if_applicable_configured": "configuration",

    # ─── ElastiCache ─────────────────────────────────────────────────────────
    # access_control
    "aws.elasticache.cluster.public_access_disabled": "access_control",
    "aws.elasticache.node.public_access_disabled": "access_control",
    "aws.elasticache.cluster.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    "aws.elasticache.node.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    # encryption
    "aws.elasticache.cluster.encryption_at_rest_enabled": "encryption",
    "aws.elasticache.cluster.encryption_at_rest_cmek_configured": "encryption",
    "aws.elasticache.cluster.rest_encryption_enabled": "encryption",
    "aws.elasticache.cluster.in_transit_encryption_enabled": "encryption",
    "aws.elasticache.cluster.require_tls_in_transit_configured": "encryption",
    "aws.elasticache.node.encryption_at_rest_enabled": "encryption",
    "aws.elasticache.node.require_tls_in_transit_configured": "encryption",
    # audit_logging
    "aws.elasticache.cluster.audit_logging_enabled": "audit_logging",
    # backup_recovery
    "aws.elasticache.cluster.deletion_protection_enabled": "backup_recovery",
    "aws.elasticache.node.deletion_protection_enabled": "backup_recovery",
    "aws.elasticache.cluster.elasticache_automatic_failover_enabled": "backup_recovery",
    "aws.elasticache.cluster.elasticache_multi_az_enabled": "backup_recovery",
    "aws.elasticache.backupretention.backup_retention_configured": "backup_recovery",
    # network_security
    "aws.elasticache.cluster.private_networking_enforced": "network_security",
    # configuration
    "aws.elasticache.cluster.elasticache_minor_version_auto_upgrade_enabled": "configuration",

    # ─── Neptune ─────────────────────────────────────────────────────────────
    # access_control
    "aws.neptune.instance.public_access_disabled": "access_control",
    "aws.neptune.cluster.public_access_disabled": "access_control",
    "aws.neptune.cluster.iam_db_authentication_enabled": "access_control",
    "aws.neptune.cluster.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    "aws.neptune.instance.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    # encryption
    "aws.neptune.cluster.encryption_at_rest_enabled": "encryption",
    "aws.neptune.cluster.encryption_at_rest_cmek_configured": "encryption",
    "aws.neptune.cluster.neptune_storage_encrypted": "encryption",
    "aws.neptune.cluster.snapshot_encrypted": "encryption",
    "aws.neptune.cluster.encryption_in_transit_enforced": "encryption",
    "aws.neptune.cluster.require_tls_in_transit_configured": "encryption",
    "aws.neptune.instance.encryption_at_rest_enabled": "encryption",
    "aws.neptune.instance.require_tls_in_transit_configured": "encryption",
    # audit_logging
    "aws.neptune.cluster.audit_logging_enabled": "audit_logging",
    "aws.neptune.cluster.neptune_integration_cloudwatch_logs_configured": "audit_logging",
    "aws.neptune.cluster.cloudwatch_monitoring_alerting_enabled": "audit_logging",
    "aws.neptune.cluster.network_security_audit_configured": "audit_logging",
    # backup_recovery
    "aws.neptune.cluster.deletion_protection_enabled": "backup_recovery",
    "aws.neptune.instance.deletion_protection_enabled": "backup_recovery",
    "aws.neptune.cluster.neptune_multi_az_configured": "backup_recovery",
    "aws.neptune.cluster.copy_tags_to_snapshots_configured": "backup_recovery",
    # network_security
    "aws.neptune.cluster.private_networking_enforced": "network_security",
    # configuration
    "aws.neptune.cluster.neptune_minor_version_auto_upgrade_enabled": "configuration",
    "aws.neptune.security_configuration_review.security_configuration_review_configured": "configuration",

    # ─── OpenSearch ──────────────────────────────────────────────────────────
    # access_control
    "aws.opensearch.service.domains_not_publicly_accessible_configured": "access_control",
    "aws.opensearch.service.domains_access_control_enabled": "access_control",
    "aws.opensearch.service.domains_internal_user_database_enabled": "access_control",
    # encryption
    "aws.opensearch.service.domains_encryption_at_rest_enabled": "encryption",
    "aws.opensearch.service.domains_node_to_node_encryption_enabled": "encryption",
    "aws.opensearch.service.opensearch_domains_https_communications_enforced": "encryption",
    # audit_logging
    "aws.opensearch.service.domains_audit_logging_enabled": "audit_logging",
    "aws.opensearch.service.domains_cloudwatch_logging_enabled": "audit_logging",
    # backup_recovery
    "aws.opensearch.service.domains_fault_tolerant_data_nodes_configured": "backup_recovery",
    "aws.opensearch.service.domains_fault_tolerant_master_nodes_configured": "backup_recovery",

    # ─── Timestream ──────────────────────────────────────────────────────────
    # access_control
    "aws.timestream.database.public_access_disabled": "access_control",
    "aws.timestream.table.public_access_disabled": "access_control",
    "aws.timestream.database.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    "aws.timestream.table.iam_or_managed_identity_auth_enabled_if_supported": "access_control",
    "aws.timestream.resource.iam_fine_grained_access_control_enabled": "access_control",
    "aws.timestream.table.rbac_least_privilege": "access_control",
    # encryption
    "aws.timestream.database.encryption_at_rest_enabled": "encryption",
    "aws.timestream.database.check_encryption_at_rest_enabled": "encryption",
    "aws.timestream.table.encryption_at_rest_enabled": "encryption",
    "aws.timestream.database.require_tls_in_transit_configured": "encryption",
    "aws.timestream.table.require_tls_in_transit_configured": "encryption",
    "aws.timestream.resource.timestream_ingestion_secure_protocol_configured": "encryption",
    # audit_logging
    "aws.timestream.resource.cloudwatch_monitoring_and_alerting_enabled": "audit_logging",
    "aws.timestream.resource.cloudtrail_management_and_data_logging_enabled": "audit_logging",
    # backup_recovery
    "aws.timestream.database.deletion_protection_enabled": "backup_recovery",
    "aws.timestream.table.deletion_protection_enabled": "backup_recovery",
    # network_security
    "aws.timestream.table.private_network_only_if_supported": "network_security",
    # configuration
    "aws.timestream.resource.security_configuration_compliance_configured": "configuration",

    # ─── Keyspaces ───────────────────────────────────────────────────────────
    # encryption
    "aws.keyspaces.resource.keyspace_encryption_at_rest_and_in_transit_configured": "encryption",
    # configuration
    "aws.keyspaces.resource.keyspace_security_configuration_configured": "configuration",
}

# ── Keyword patterns for fallback classification ────────────────────────────
_KEYWORD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"encrypt|cmek|kms|tls|ssl|transport_encrypt|storage_encrypt", re.I), "encryption"),
    (re.compile(r"public|iam_auth|iam_or_managed|rbac|superuser|least_privilege|sharing_restricted|anonymous", re.I), "access_control"),
    (re.compile(r"audit|log|monitor|cloudwatch|performance_insights|cloudtrail", re.I), "audit_logging"),
    (re.compile(r"backup|retention|deletion_protection|pitr|snapshot|failover|multi_az|replication", re.I), "backup_recovery"),
    (re.compile(r"vpc|subnet|private_network|ingress|egress|port|security_group|endpoint.*access|cidr", re.I), "network_security"),
]


def categorize_finding(rule_id: str, finding: Optional[Dict[str, Any]] = None) -> str:
    """Classify a check finding into a database security domain.

    Args:
        rule_id: The check rule identifier (e.g. 'aws.rds.instance.public_access_disabled').
        finding: Optional finding dict — currently unused but reserved for
                 future content-based classification.

    Returns:
        One of the six security domain strings. Falls back to 'configuration'
        if no pattern matches.
    """
    # 1. Exact match
    domain = RULE_DOMAIN_MAP.get(rule_id)
    if domain:
        return domain

    # 2. Keyword-based fallback on the rule_id string
    for pattern, domain_name in _KEYWORD_PATTERNS:
        if pattern.search(rule_id):
            return domain_name

    # 3. Default
    return "configuration"


def get_service_from_rule(rule_id: str) -> Optional[str]:
    """Extract the DB service name from a rule_id prefix.

    Rule IDs follow the pattern ``aws.<service>.<resource>.<check_name>``.
    Returns the service portion if it is a recognized DB service, else None.

    Args:
        rule_id: The check rule identifier.

    Returns:
        Service name (e.g. 'rds', 'dynamodb') or None if not a DB service.
    """
    parts = rule_id.split(".")
    if len(parts) >= 2:
        service = parts[1]
        if service in DB_SERVICES:
            return service
    return None


def is_db_rule(rule_id: str) -> bool:
    """Return True if the rule_id belongs to a known database service."""
    return get_service_from_rule(rule_id) is not None
