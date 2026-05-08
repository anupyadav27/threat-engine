#!/usr/bin/env python3
"""
Expert review and fix of all AliCloud check rule var/op/value conditions.

Each rule reviewed based on actual security intent, not generic keyword matching.
Two passes:
  1. Explicit overrides — rules where the correct field was determined by
     reading the rule name and understanding what property is being evaluated.
  2. Enhanced keyword classification — for remaining rules.

Also fixes wrong multi-condition patterns:
  - (encrypted + logging_enabled) for KMS rules → (encrypted + kms_key_id)
  - (logging_enabled + permissions) for configured/enabled rules → single status
"""

import yaml
from pathlib import Path
from collections import defaultdict, Counter

CATALOG = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def single(var, op, value=None):
    d = {"var": var, "op": op}
    if value is not None:
        d["value"] = str(value)
    return d


def multi_all(*conds):
    return {"all": list(conds)}


# ─── Explicit rule overrides ──────────────────────────────────────────────────
# Maps rule_id suffix (everything after "alicloud.") → correct condition dict.
# Overrides take priority over keyword classification.

EXPLICIT = {

    # ── AccessAnalyzer ────────────────────────────────────────────────────────
    "accessanalyzer.enabled.configured":
        single("item.status", "equals", "Active"),
    "accessanalyzer.enabled.without_findings":
        single("item.status", "equals", "Active"),

    # ── ACK (Kubernetes) ─ item.id rules ────────────────────────────────────
    "ack.admission_webhook.admission_host_namespace_usage_denied":
        single("item.permissions", "not_contains", "*"),
    "ack.admission_webhook.admission_image_registry_allowlist_enforced":
        single("item.permissions", "not_contains", "*"),
    "ack.admission_webhook.admission_image_signature_verification_enabled":
        single("item.status", "equals", "Active"),
    "ack.admission_webhook.admission_privilege_escalation_denied":
        single("item.permissions", "not_contains", "*"),
    "ack.certificates.expiration_check":
        single("item.status", "equals", "Active"),
    "ack.certificates.not_expired_and_valid":
        single("item.status", "equals", "Active"),
    "ack.cluster.approved_container_registries_enforced":
        single("item.permissions", "not_contains", "*"),
    "ack.cluster.basic_auth_disabled_enforced":
        single("item.permissions", "not_contains", "*"),
    "ack.cluster.cloud_monitoring_enabled":
        single("item.status", "equals", "Active"),
    "ack.cluster.control_plane_private_access_ip_allowlist_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "ack.cluster.endpoint_private_access_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "ack.cluster.network_plugin_terway_compliance_enforced":
        single("item.status", "equals", "Active"),
    "ack.cluster.network_policy_enforced":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.cluster.nodes_private_ip_required":
        single("item.public_ip_address", "not_exists"),
    "ack.cluster.pod_security_policy_compliance_enforced":
        single("item.permissions", "not_contains", "*"),
    "ack.cluster.private_access_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "ack.cluster.private_nodes_only":
        single("item.internet_facing", "not_equals", "true"),
    "ack.cluster.rbac_authorization_enforced":
        single("item.permissions", "not_contains", "*"),
    "ack.cluster.uses_latest_supported_version":
        single("item.status", "equals", "Active"),
    "ack.cluster.weekly_health_checks_enabled":
        single("item.status", "equals", "Active"),
    "ack.control_plane.admission_psa_enforce_mode":
        single("item.permissions", "not_contains", "*"),
    "ack.control_plane.anonymous_auth_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.control_plane.apiserver_anonymous_auth_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.control_plane.apiserver_authorization_mode_rbac":
        single("item.permissions", "not_contains", "*"),
    "ack.control_plane.apiserver_insecure_port_disabled":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.control_plane.root_ca_file_configured":
        single("item.status", "equals", "Active"),
    "ack.control_plane.token_signing_enabled":
        single("item.status", "equals", "Active"),
    "ack.control_plane.use_service_account_credentials_enabled":
        single("item.status", "equals", "Active"),
    "ack.enabled.for_ec2":
        single("item.status", "equals", "Active"),
    "ack.endpoints.private_access_only":
        single("item.internet_facing", "not_equals", "true"),
    "ack.etcd.auth_enabled":
        single("item.permissions", "not_contains", "*"),
    "ack.etcd.cert_auth_enabled":
        single("item.ssl_enabled", "equals", "true"),
    "ack.instance.access_policy_network_restriction_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "ack.kube.apiserver_client_ca_file_check":
        single("item.status", "equals", "Active"),
    "ack.kube_apiserver.client_ca_file_properly_configured":
        single("item.status", "equals", "Active"),
    "ack.log.service_integration_check":
        single("item.logging_enabled", "equals", "true"),
    "ack.namespace.namespace_default_service_account_automount_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.namespace.namespace_network_policies_present":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.network_policy.networkpolicy_default_deny_egress_per_namespace":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.network_policy.networkpolicy_default_deny_ingress_per_namespace":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.network_policy.policy_enabled":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.node.auth_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.node.kubelet_anonymous_auth_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.node.kubelet_authz_webhook_or_rbac_enabled":
        single("item.permissions", "not_contains", "*"),
    "ack.node.kubelet_read_only_port_disabled":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.node.only_port_disabled":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ack.node.security_patches_current":
        single("item.status", "equals", "Active"),
    "ack.plan.configured":
        single("item.backup_enabled", "equals", "true"),
    "ack.plans.exist":
        single("item.backup_enabled", "equals", "true"),
    "ack.pod.security_context_configured":
        single("item.permissions", "not_contains", "*"),
    "ack.pod.service_account_token_mounting_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.pod_security_policy.net_raw_capability_dropped":
        single("item.permissions", "not_contains", "*"),
    "ack.psp.net_raw_capability_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.registry.image_scan_on_push_enabled":
        single("item.status", "equals", "Active"),
    "ack.repository.vulnerability_scanning_continuous":
        single("item.status", "equals", "Active"),
    "ack.scheduler.authentication_kubeconfig_configured":
        single("item.status", "equals", "Active"),
    "ack.scheduler.authorization_kubeconfig_configured":
        single("item.status", "equals", "Active"),
    "ack.serverless.fargate_profile_private_subnets_only":
        single("item.internet_facing", "not_equals", "true"),
    "ack.service_account.cluster_default_service_account_automount_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.service_account.cluster_private_control_plane_endpoint_enabled":
        single("item.internet_facing", "not_equals", "true"),
    "ack.service_account.default_no_token_no_roles_enforced":
        single("item.permissions", "not_contains", "*"),
    "ack.service_account.external_ips_not_used":
        single("item.internet_facing", "not_equals", "true"),
    "ack.service_account.keys_not_used_or_rotated_90_days_or_less":
        single("item.status", "equals", "Active"),
    "ack.service_account.no_user_managed_long_lived_keys":
        single("item.permissions", "not_contains", "*"),
    "ack.service_account.token_auto_mount_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.service_account.type_loadbalancer_internal_only_where_required":
        single("item.internet_facing", "not_equals", "true"),
    "ack.workload.env_no_plaintext_secrets":
        single("item.permissions", "not_contains", "*"),
    "ack.workload.host_network_pid_ipc_disabled":
        single("item.permissions", "not_contains", "*"),
    "ack.workload.no_hostpath_mounts":
        single("item.permissions", "not_contains", "*"),

    # ── ActionTrail ───────────────────────────────────────────────────────────
    "actiontrail.failed_console_signin_alerts.configured":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.logging_all_regions_properly_configured.configured":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.logservice.failed_console_signin_alerts":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.threat.detection_enumeration":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.threat.detection_privilege_escalation":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.threat.llm_jacking":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.threat_detection.enumeration_detected":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.threat_detection.llm_jacking_detected":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.threat_detection.privilege_escalation_detected":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.vpc.change_monitoring":
        single("item.logging_enabled", "equals", "true"),
    "actiontrail.vpc_change_alerts.configured":
        single("item.logging_enabled", "equals", "true"),
    # KMS encryption of ActionTrail → encrypted + kms_key_id
    "actiontrail.configuration.config_delivery_kms_encryption_enabled":
        multi_all(single("item.encrypted", "equals", "true"),
                  single("item.kms_key_id", "exists")),
    "actiontrail.delivery.channel_kms_encryption_enabled":
        multi_all(single("item.encrypted", "equals", "true"),
                  single("item.kms_key_id", "exists")),
    "actiontrail.kms.encryption_enabled":
        multi_all(single("item.encrypted", "equals", "true"),
                  single("item.kms_key_id", "exists")),
    "actiontrail.kms_encryption_active.configured":
        multi_all(single("item.encrypted", "equals", "true"),
                  single("item.kms_key_id", "exists")),

    # ── ALB ───────────────────────────────────────────────────────────────────
    "alb.deletion.protection":
        single("item.status", "equals", "Active"),
    "alb.hologres_access_control.endpoint_authz_no_anonymous_access":
        single("item.permissions", "not_contains", "*"),
    "alb.hologres_endpoint.endpoint_access_private_only":
        single("item.internet_facing", "not_equals", "true"),
    "alb.internet.facing":
        single("item.internet_facing", "not_equals", "true"),
    "alb.is.in_multiple_az":
        single("item.status", "equals", "Active"),
    "alb.listener.facing":
        single("item.internet_facing", "not_equals", "true"),
    "alb.target.group_health_check_enabled":
        single("item.status", "equals", "Active"),
    "alb.target_group.tg_targets_in_private_subnets":
        single("item.internet_facing", "not_equals", "true"),
    "alb.waf.acl_attached":
        single("item.status", "equals", "Active"),

    # ── AliDNS ────────────────────────────────────────────────────────────────
    "dns.dnssec.disabled":
        single("item.status", "equals", "Active"),
    "dns.health_check.no_plaintext_credentials_in_url":
        single("item.permissions", "not_contains", "*"),
    "dns.key.in_dnssec":
        single("item.status", "equals", "Active"),
    "dns.record.set_caa_records_present_for_root_and_wildcard":
        single("item.status", "equals", "Active"),
    "dns.record.set_dmarc_record_present_when_mx_present":
        single("item.status", "equals", "Active"),
    "dns.record.set_no_overly_broad_wildcard_records_in_sensitive_zones":
        single("item.permissions", "not_contains", "*"),
    "dns.rsasha1.in_use_to_key_sign_in_dnssec":
        single("item.status", "equals", "Active"),
    "dns.rsasha1.in_use_to_zone_sign_in_dnssec":
        single("item.status", "equals", "Active"),
    "dns.service.dnssec_enabled_for_security":
        single("item.status", "equals", "Active"),
    "dns.service.rsasha1_deprecated_for_key_signing_in_dnssec":
        single("item.status", "equals", "Active"),
    "dns.service.rsasha1_deprecated_for_zone_signing_in_dnssec":
        single("item.status", "equals", "Active"),
    "dns.zone.dnssec_enabled_where_supported":
        single("item.status", "equals", "Active"),

    # ── AnalyticDB ───────────────────────────────────────────────────────────
    "analyticdb.cluster.enhanced_vpc_routing_enabled":
        single("item.vpc_id", "exists"),
    "analyticdb.cluster.maintenance_window_configured":
        single("item.status", "equals", "Active"),
    "analyticdb.cluster.private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "analyticdb.cluster.public_access":
        single("item.internet_facing", "not_equals", "true"),
    "analyticdb.cluster.security_configuration_baseline_enforced":
        single("item.status", "equals", "Active"),

    # ── API Gateway ───────────────────────────────────────────────────────────
    "api.api.endpoint_authn_required":
        single("item.permissions", "not_contains", "*"),
    "api.api.endpoint_authz_policies_enforced":
        single("item.permissions", "not_contains", "*"),
    "api.api.endpoint_waf_attached":
        single("item.status", "equals", "Active"),
    "api.function.access_keys_configured":
        single("item.status", "equals", "Active"),
    "api.gateway.client_certificate_enabled":
        single("item.ssl_enabled", "equals", "true"),
    "api.gateway.restapi_client_certificate_enabled":
        single("item.ssl_enabled", "equals", "true"),
    "api.gateway.restapi_waf_acl_attached":
        single("item.status", "equals", "Active"),
    "api.gateway.validation_api_parameters_validation_enabled":
        single("item.status", "equals", "Active"),
    "api.gateway.validation_api_request_schema_validation_enabled":
        single("item.status", "equals", "Active"),
    "api.gateway.validation_api_required_security_headers_enforced":
        single("item.status", "equals", "Active"),
    "api.hosting.managed_updates_enabled":
        single("item.status", "equals", "Active"),
    "api.stage.throttling_enabled":
        single("item.status", "equals", "Active"),
    "api.usage_plan.rate_limits_configured":
        single("item.status", "equals", "Active"),
    "apikeys.key.rotated_in_90_days":
        single("item.status", "equals", "Active"),

    # ── ARMS ─────────────────────────────────────────────────────────────────
    "arms.api.monitoring_api_access_log_fields_identity_present":
        single("item.logging_enabled", "equals", "true"),
    "arms.api.monitoring_api_access_log_sink_configured":
        single("item.logging_enabled", "equals", "true"),
    "arms.ml.monitoring_private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),

    # ── BSS ──────────────────────────────────────────────────────────────────
    "bss.document.secrets":
        single("item.permissions", "not_contains", "*"),
    "bss.documents.set_as_public":
        single("item.internet_facing", "not_equals", "true"),
    "bss.managed.compliant_patching":
        single("item.status", "equals", "Active"),
    "bss.plans.properly_configured":
        single("item.backup_enabled", "equals", "true"),
    "bss.plans.retention_90_days_minimum":
        single("item.backup_enabled", "equals", "true"),
    "bss.plans_configured_and_active.configured":
        single("item.backup_enabled", "equals", "true"),
    "bss.recovery_point.retention_90_days_minimum":
        single("item.backup_enabled", "equals", "true"),
    "bss.reportplans_configured_and_active.configured":
        single("item.backup_enabled", "equals", "true"),

    # ── CAS ──────────────────────────────────────────────────────────────────
    "cas.cas.certificate_trusted_issuer":
        single("item.status", "equals", "Active"),
    "cas.cas_private_ca.private_ca_ca_key_in_hsm_where_supported":
        single("item.status", "equals", "Active"),
    "cas.cas_private_ca.private_ca_crl_or_ocsp_configured":
        single("item.status", "equals", "Active"),
    "cas.certificate.expiration":
        single("item.status", "equals", "Active"),
    "cas.kubernetes.cluster_confidential_computing_enabled":
        single("item.status", "equals", "Active"),
    "cas.kubernetes_cluster.confidential_computing_enforced":
        single("item.status", "equals", "Active"),

    # ── CDN ──────────────────────────────────────────────────────────────────
    "cdn.cache_policy.no_sensitive_headers_cached":
        single("item.permissions", "not_contains", "*"),
    "cdn.dcdn.cdn_cache_key_excludes_sensitive_headers":
        single("item.permissions", "not_contains", "*"),
    "cdn.dcdn.cdn_signed_urls_or_headers_required_for_private_content":
        single("item.permissions", "not_contains", "*"),
    "cdn.dcdn.cdn_waf_web_acl_attached":
        single("item.status", "equals", "Active"),
    "cdn.distribution.custom_ssl_certificate_valid":
        single("item.ssl_enabled", "equals", "true"),
    "cdn.domain.custom_ssl_certificate":
        single("item.ssl_enabled", "equals", "true"),
    "cdn.domain.multiple_origin_failover_configured":
        single("item.status", "equals", "Active"),
    "cdn.edge.cache_policy_no_sensitive_headers_cached":
        single("item.permissions", "not_contains", "*"),
    "cdn.edge.cache_policy_respects_cache_control_no_store_private":
        single("item.permissions", "not_contains", "*"),
    "cdn.origin.origin_request_policy_no_secret_headers_forwarded":
        single("item.permissions", "not_contains", "*"),

    # ── CloudFW ──────────────────────────────────────────────────────────────
    "cfw.ipset.ip_set_cidrs_valid_and_minimized":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "cfw.microsegmentation.microseg_endpoint_policies_applied":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "cfw.microsegmentation.microseg_identity_aware_policies_enabled":
        single("item.permissions", "not_contains", "*"),
    "cfw.network.firewall_no_permit_any_any":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "cfw.policy.access_control_no_permit_all":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "cfw.policy.access_control_policies_present":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "cfw.traffic_analysis.alert_destinations_configured":
        single("item.logging_enabled", "equals", "true"),
    "cfw.waf_ip_sets.ip_set_sources_trusted":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "cloudfw.deployed_across_all_vpcs.configured":
        single("item.vpc_id", "exists"),
    "cloudfw.in.all_vpc":
        single("item.vpc_id", "exists"),
    "cloudfw.instance.postgres_log_error_verbosity_flag":
        single("item.logging_enabled", "equals", "true"),
    "cloudfw.instance.postgres_log_min_duration_statement_flag":
        single("item.logging_enabled", "equals", "true"),
    "cloudfw.instance.postgres_log_min_error_statement_flag":
        single("item.logging_enabled", "equals", "true"),
    "cloudfw.instance.postgres_log_min_messages_flag":
        single("item.logging_enabled", "equals", "true"),
    "cloudfw.instance.postgres_log_statement_flag":
        single("item.logging_enabled", "equals", "true"),
    "cloudfw.instance.public_ip":
        single("item.internet_facing", "not_equals", "true"),
    "cloudfw.multi.az":
        single("item.status", "equals", "Active"),
    "cloudfw.multi_az_with_auto_scaling.configured":
        single("item.status", "equals", "Active"),

    # ── CMS / CloudMonitor edge cases ─────────────────────────────────────────
    # These rules MONITOR SG/ACL changes — they are logging checks, not SG checks
    "cloudmonitor.alert.rds_sqlserver_firewall_rule_change_logged":
        single("item.logging_enabled", "equals", "true"),
    "cloudmonitor.alert.rds_sqlserver_firewall_rule_deletion_logged":
        single("item.logging_enabled", "equals", "true"),
    "cloudmonitor.log_metric_filter_for_security_group_changes.configured":
        single("item.logging_enabled", "equals", "true"),
    "cloudmonitor.network_acls_change_alarm_configured.configured":
        single("item.logging_enabled", "equals", "true"),
    "cms.changes.to_network_acls_alarm_configured":
        single("item.logging_enabled", "equals", "true"),
    "cms.log.metric_filter_security_group_changes":
        single("item.logging_enabled", "equals", "true"),
    "cms.metric.metric_filter_network_acl_or_sg_change_detected_filter_present":
        single("item.logging_enabled", "equals", "true"),
    "cms.network_acls.change_detection_alarm_configured":
        single("item.logging_enabled", "equals", "true"),
    # Dashboard public embeds = internet exposure check
    "cms.dashboard.public_embeds_disabled":
        single("item.internet_facing", "not_equals", "true"),
    # Activity logs storage should be private
    "cms.storage.account_with_activity_logs_is_private":
        single("item.internet_facing", "not_equals", "true"),

    # ── Config ────────────────────────────────────────────────────────────────
    "config.drift_detection.config_drift_alerts_configured":
        single("item.logging_enabled", "equals", "true"),
    "config.recorder.config_recorder_global_resource_types_tracked":
        single("item.logging_enabled", "equals", "true"),
    "config.recorder.delivery_channel_secure_destination_configured":
        single("item.logging_enabled", "equals", "true"),
    "config.remediation.config_remediation_auto_remediation_enabled_for_high":
        single("item.status", "equals", "Active"),
    "config.rule.config_rule_remediation_targets_bound":
        single("item.status", "equals", "Active"),
    "config.rule.config_rule_required_rules_present":
        single("item.status", "equals", "Active"),
    "config.workload.no_high_or_medium_risks":
        single("item.status", "equals", "Active"),

    # ── CR (Container Registry) ───────────────────────────────────────────────
    "artifacts.container.analysis_enabled":
        single("item.status", "equals", "Active"),
    "cr.container.vulnerability_scanning_enabled":
        single("item.status", "equals", "Active"),
    "cr.image.critical_vulnerabilities_blocked":
        single("item.status", "equals", "Active"),
    "cr.image.vulnerability_scan_on_push":
        single("item.status", "equals", "Active"),
    "cr.instance.access_policy_and_network_restriction_audit":
        single("item.permissions", "not_contains", "*"),
    "cr.packages.external_public_publishing_disabled":
        single("item.internet_facing", "not_equals", "true"),
    "cr.repository.registry_image_scanning_enabled":
        single("item.status", "equals", "Active"),
    "cr.repository.scanning_enabled":
        single("item.status", "equals", "Active"),
    "cr.uses.private_link":
        single("item.internet_facing", "not_equals", "true"),

    # ── DDOS ─────────────────────────────────────────────────────────────────
    "ddos.advanced.protection_in_internet_facing_load_balancers":
        single("item.status", "equals", "Active"),

    # ── DMS / DataWorks / DLF ─────────────────────────────────────────────────
    "dataworks.ai.data_pipeline_private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "dataworks.connection.credentials_in_secrets_manager":
        single("item.permissions", "not_contains", "*"),
    "dataworks.connection.private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "dataworks.connections.connection_private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "dataworks.data_classification.classifier_source_trusted":
        single("item.permissions", "not_contains", "*"),
    "dataworks.data_integration.crawler_network_private_only":
        single("item.internet_facing", "not_equals", "true"),
    "dataworks.database.pii_detection_enabled":
        single("item.status", "equals", "Active"),
    "dataworks.datamap_data.catalog_cross_account_sharing_review_required":
        single("item.permissions", "not_contains", "*"),
    "dataworks.dqc_expression.rule_parameters_no_plaintext_secrets":
        single("item.permissions", "not_contains", "*"),
    "dataworks.dqc_expression.rule_source_trusted":
        single("item.permissions", "not_contains", "*"),
    "dataworks.dqc_rule.rule_source_trusted":
        single("item.permissions", "not_contains", "*"),
    "dataworks.incident.workflow_approval_steps_required_for_destructive_actions":
        single("item.permissions", "not_contains", "*"),
    "dataworks.param_attribute.parameter_metadata_sensitive_keys_require_secret_type":
        single("item.permissions", "not_contains", "*"),
    "dataworks.param_attribute.parameter_metadata_values_not_plaintext_secret":
        single("item.permissions", "not_contains", "*"),
    "dataworks.parameter.attributes_no_plaintext_secrets":
        single("item.permissions", "not_contains", "*"),
    "dataworks.parameter.value_from_secrets_manager_when_sensitive":
        single("item.permissions", "not_contains", "*"),
    "dataworks.parameter_object.parameter_binding_secret_refs_resolved_at_runtime":
        single("item.permissions", "not_contains", "*"),
    "dataworks.parameter_object.parameter_binding_sensitive_params_not_logged":
        single("item.permissions", "not_contains", "*"),
    "dataworks.pipeline_workflow.pipeline_private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "dataworks.resource.object_environment_no_plaintext_secrets":
        single("item.permissions", "not_contains", "*"),
    "dataworks.resource.object_network_private_only":
        single("item.internet_facing", "not_equals", "true"),
    "dataworks.stream.data_retention_period":
        single("item.logging_enabled", "equals", "true"),
    "dataworks.tasks_jobs.job_network_private_only":
        single("item.internet_facing", "not_equals", "true"),
    "dataworks.workflow_definition.definition_storage_private":
        single("item.internet_facing", "not_equals", "true"),
    "dlf.classifiers.classifier_source_trusted":
        single("item.permissions", "not_contains", "*"),
    "dlf.connections.connection_private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "dlf.crawlers.crawler_network_private_only":
        single("item.internet_facing", "not_equals", "true"),
    "dlf.dataworks_crawlers.crawler_network_private_only":
        single("item.internet_facing", "not_equals", "true"),
    "dlf.table.column_level_access_controls_enabled":
        single("item.permissions", "not_contains", "*"),
    "dlf.table.public_sharing_disabled":
        single("item.internet_facing", "not_equals", "true"),
    "dms.classification.auto_discovery_enabled":
        single("item.status", "equals", "Active"),
    "dms.classification.classifier_source_trusted":
        single("item.permissions", "not_contains", "*"),
    "dms.classification.sensitive_data_alerts_configured":
        single("item.logging_enabled", "equals", "true"),
    "dms.classification_data.classification_policy_blocks_public_for_sensitive":
        single("item.permissions", "not_contains", "*"),
    "dms.compliance_pack_data.compliance_export_destinations_private":
        single("item.internet_facing", "not_equals", "true"),
    "dms.data_masking.masking_policies_present_for_sensitive_fields":
        single("item.permissions", "not_contains", "*"),
    "dms.desensitization.anonymization_jobs_private_networking":
        single("item.internet_facing", "not_equals", "true"),
    "dms.instance.multi_az_deployment":
        single("item.status", "equals", "Active"),

    # ── DTS ──────────────────────────────────────────────────────────────────
    "dts.autoscaling_properly_configured.configured":
        single("item.status", "equals", "Active"),
    "dts.instance.private_access_only":
        single("item.internet_facing", "not_equals", "true"),
    "dts.pitr_properly_configured.configured":
        single("item.backup_enabled", "equals", "true"),
    "dts.tables_point_in_time_recovery_enabled.configured":
        single("item.backup_enabled", "equals", "true"),

    # ── ECS ──────────────────────────────────────────────────────────────────
    "ecs.ami.public":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.compute_service.vm_imds_hardened":
        single("item.status", "equals", "Active"),
    "ecs.compute_service.vm_secure_boot_enabled":
        single("item.status", "equals", "Active"),
    "ecs.compute_service.vm_ssh_key_based_auth_required":
        single("item.permissions", "not_contains", "*"),
    "ecs.compute_service.vm_ssh_password_auth_disabled":
        single("item.permissions", "not_contains", "*"),
    "ecs.custom_image.image_approved_image_allowlist_enforced":
        single("item.permissions", "not_contains", "*"),
    "ecs.custom_image.image_image_signed_and_verified":
        single("item.status", "equals", "Active"),
    "ecs.custom_image.image_vuln_scanned_no_critical":
        single("item.status", "equals", "Active"),
    "ecs.e_hpc.training_pipeline_private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.e_hpc.training_pipeline_secrets_from_vault_only":
        single("item.permissions", "not_contains", "*"),
    "ecs.e_hpc_ai.network_isolation_enabled":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.ebs.volume_snapshots_exists":
        single("item.backup_enabled", "equals", "true"),
    "ecs.eip_exposure_to_shodan.configured":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.eip_unassigned_cleanup_required.configured":
        single("item.status", "equals", "Active"),
    "ecs.elastic.ip_shodan":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.elastic.ip_unassigned":
        single("item.status", "equals", "Active"),
    "ecs.image.vulnerability_scan_passed":
        single("item.status", "equals", "Active"),
    "ecs.instance.age_check_older_than_90_days":
        single("item.status", "equals", "Active"),
    "ecs.instance.confidential_computing_enforced":
        single("item.status", "equals", "Active"),
    "ecs.instance.configured":
        single("item.status", "equals", "Active"),
    "ecs.instance.critical_cve_remediated":
        single("item.status", "equals", "Active"),
    "ecs.instance.env_no_plaintext_secrets":
        single("item.permissions", "not_contains", "*"),
    "ecs.instance.imdsv2_mandatory":
        single("item.status", "equals", "Active"),
    "ecs.instance.ip_forwarding_disabled_for_security":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.instance.managed":
        single("item.status", "equals", "Active"),
    "ecs.instance.managed_by_ssm":
        single("item.status", "equals", "Active"),
    "ecs.instance.network_type_verified":
        single("item.vpc_id", "exists"),
    "ecs.instance.os_version_supported":
        single("item.status", "equals", "Active"),
    "ecs.instance.paravirtual_type_deprecated":
        single("item.status", "equals", "Active"),
    "ecs.instance.password_auth_disabled":
        single("item.permissions", "not_contains", "*"),
    "ecs.instance.port_ftp_exposed_to_internet":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ecs.instance.port_rdp_exposed_to_internet":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ecs.instance.public_ip_disabled":
        single("item.public_ip_address", "not_exists"),
    "ecs.instance.public_ip_disabled_unless_explicitly_approved":
        single("item.public_ip_address", "not_exists"),
    "ecs.instance.secrets_user_data":
        single("item.permissions", "not_contains", "*"),
    "ecs.instance.security_center_agent_installed_and_active":
        single("item.status", "equals", "Active"),
    "ecs.instance.security_hardening_applied":
        single("item.status", "equals", "Active"),
    "ecs.instance.security_patches_applied":
        single("item.status", "equals", "Active"),
    "ecs.instance.serial_ports_disabled_for_security":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ecs.instance.shielded_vm_security_features_enabled":
        single("item.status", "equals", "Active"),
    "ecs.instance.single_eni_usage_verified":
        single("item.status", "equals", "Active"),
    "ecs.instance.ssh_key_authentication_mandatory":
        single("item.permissions", "not_contains", "*"),
    "ecs.instance.user_data_secrets_exposure_prevented":
        single("item.permissions", "not_contains", "*"),
    "ecs.instance.uses_single_eni":
        single("item.status", "equals", "Active"),
    "ecs.instance_managed_by_ssm_agent_installed.configured":
        single("item.status", "equals", "Active"),
    "ecs.key_pair.inactive_keys_disabled_after_90_days":
        single("item.status", "equals", "Active"),
    "ecs.launch.template_imdsv2_required":
        single("item.status", "equals", "Active"),
    "ecs.launch.template_no_secrets":
        single("item.permissions", "not_contains", "*"),
    "ecs.launch_template.imdsv2_enforcement":
        single("item.status", "equals", "Active"),
    "ecs.launch_template.public_ip_assignment_disabled":
        single("item.public_ip_address", "not_exists"),
    "ecs.launch_template.security_groups_restrictive":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ecs.management.compliance":
        single("item.status", "equals", "Active"),
    "ecs.management_compliance_standards_met.configured":
        single("item.status", "equals", "Active"),
    "ecs.network_custom_vpc_required.configured":
        single("item.vpc_id", "exists"),
    "ecs.networkacl.not_legacy":
        single("item.status", "equals", "Active"),
    "ecs.networkacl.unused":
        single("item.status", "equals", "Active"),
    "ecs.networkacl.unused_resources_identified":
        single("item.status", "equals", "Active"),
    "ecs.patch.compliance":
        single("item.status", "equals", "Active"),
    "ecs.patch_management_compliance_standards_met.configured":
        single("item.status", "equals", "Active"),
    "ecs.public.address_shodan":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.security_group.allow_ingress_from_internet_to_high_risk_tcp_ports":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ecs.security_group.allow_ingress_from_internet_to_tcp_port_memcached_11211":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ecs.security_group.default_deny_all":
        single("item.security_group_rules", "not_contains", "0.0.0.0/0"),
    "ecs.security_group.not_used":
        single("item.status", "equals", "Active"),
    "ecs.security_group.unused_security_groups_identified":
        single("item.status", "equals", "Active"),
    "ecs.task.definitions_logging_block_mode":
        single("item.logging_enabled", "equals", "true"),
    "ecs.training_job.network_isolation_enabled":
        single("item.internet_facing", "not_equals", "true"),
    "ecs.transitgateway.auto_accept_vpc_attachments":
        single("item.permissions", "not_contains", "*"),
    "ecs.transitgateway.vpc_attachment_auto_accept_disabled":
        single("item.permissions", "not_contains", "*"),
    "ecs.trusted.launch_secure_boot_enabled":
        single("item.status", "equals", "Active"),
    "ecs.volume.in_use":
        single("item.status", "equals", "Active"),
    "ecs.volume_attached_to_instance.configured":
        single("item.status", "equals", "Active"),
    "ecs.vulnerability.automated_scanning_scheduled_weekly":
        single("item.status", "equals", "Active"),
    "ecs.vulnerability.scan_enabled":
        single("item.status", "equals", "Active"),
    "ecs.vulnerability_scan_scheduled.configured":
        single("item.status", "equals", "Active"),

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    "elasticsearch.redis.cluster_automatic_failover_enabled":
        single("item.status", "equals", "Active"),
    "elasticsearch.redis.cluster_multi_az_enabled":
        single("item.status", "equals", "Active"),
    "elasticsearch.service.domains_access_control_enabled":
        single("item.permissions", "not_contains", "*"),
    "elasticsearch.service.domains_fault_tolerant_data_nodes":
        single("item.status", "equals", "Active"),
    "elasticsearch.service.domains_fault_tolerant_master_nodes":
        single("item.status", "equals", "Active"),
    "elasticsearch.service.domains_internal_user_database_enabled":
        single("item.permissions", "not_contains", "*"),

    # ── EMR ──────────────────────────────────────────────────────────────────
    "emr.cluster.master_nodes_public_ip_disabled":
        single("item.public_ip_address", "not_exists"),
    "emr.cluster.private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),

    # ── ESS ──────────────────────────────────────────────────────────────────
    "ess.group.capacity_rebalance_enforced":
        single("item.status", "equals", "Active"),
    "ess.group.health_check_configured":
        single("item.status", "equals", "Active"),
    "ess.group.multi_az_deployment":
        single("item.status", "equals", "Active"),
    "ess.group.properly_configured":
        single("item.status", "equals", "Active"),

    # ── FC (Function Compute) ─────────────────────────────────────────────────
    "fc.compute.function_restrict_public_access":
        single("item.internet_facing", "not_equals", "true"),
    "fc.compute.function_url_authentication":
        single("item.permissions", "not_contains", "*"),
    "fc.compute.function_url_public":
        single("item.internet_facing", "not_equals", "true"),
    "fc.function.dependency_scan_passed":
        single("item.status", "equals", "Active"),
    "fc.function.inside_vpc":
        single("item.vpc_id", "exists"),
    "fc.function.reserved_concurrency_set":
        single("item.status", "equals", "Active"),
    "fc.function.url_cors_policy_enforced":
        single("item.permissions", "not_contains", "*"),
    "fc.function.vpc_isolation_enabled":
        single("item.vpc_id", "exists"),
    "fc.trigger.event_source_source_authenticated":
        single("item.permissions", "not_contains", "*"),

    # ── General ──────────────────────────────────────────────────────────────
    "general.access_keys_rotated_90_days.configured":
        single("item.status", "equals", "Active"),
    "general.account.part_of_organization_structure":
        single("item.status", "equals", "Active"),
    "general.account.private_endpoints_mandatory":
        single("item.internet_facing", "not_equals", "true"),
    "general.advanced_protection_enabled_for_internet_facing_load_balancers.configured":
        single("item.status", "equals", "Active"),
    "general.api.access_restrictions_configured":
        single("item.permissions", "not_contains", "*"),
    "general.asset_fingerprint_refresh_30_days.configured":
        single("item.status", "equals", "Active"),
    "general.associated_with_instance.configured":
        single("item.status", "equals", "Active"),
    "general.authorization_oauth2_enabled.configured":
        single("item.permissions", "not_contains", "*"),
    "general.automatic_security_updates_enabled.configured":
        single("item.status", "equals", "Active"),
    "general.broker.active_active_deployment_mode":
        single("item.status", "equals", "Active"),
    "general.broker.cluster_deployment_mode_with_redundancy":
        single("item.status", "equals", "Active"),
    "general.bucket.log_retention_policy_locked_90_days":
        single("item.logging_enabled", "equals", "true"),
    "general.certificates_expiration_30_days_alert.configured":
        single("item.status", "equals", "Active"),
    "general.client_certificate_mandatory.configured":
        single("item.ssl_enabled", "equals", "true"),
    "general.cluster.multi_az_deployment":
        single("item.status", "equals", "Active"),
    "general.cluster_tags_copied_to_snapshots.configured":
        single("item.backup_enabled", "equals", "true"),
    "general.compliant_patching_enforced.configured":
        single("item.status", "equals", "Active"),
    "general.container.image_vulnerability_scanning_enabled":
        single("item.status", "equals", "Active"),
    "general.deletion_protection_enabled.configured":
        single("item.status", "equals", "Active"),
    "general.distributions.origin_failover_configured_with_redundancy":
        single("item.status", "equals", "Active"),
    "general.domains.internal_user_database_access_control_enabled":
        single("item.permissions", "not_contains", "*"),
    "general.domains.private_access_only":
        single("item.internet_facing", "not_equals", "true"),
    "general.file_system_tags_copied_to_volumes.configured":
        single("item.tags", "exists"),
    "general.function.url_authentication_mandatory":
        single("item.permissions", "not_contains", "*"),
    "general.global_endpoint.event_replication_enforced":
        single("item.status", "equals", "Active"),
    "general.global_tables_cross_region_enabled.configured":
        single("item.backup_enabled", "equals", "true"),
    "general.image_scan_on_push_enabled_for_vulnerabilities.configured":
        single("item.status", "equals", "Active"),
    "general.least_privilege_assessment_enabled.configured":
        single("item.status", "equals", "Active"),
    "general.managed_instance_compliant_patching_enabled.configured":
        single("item.status", "equals", "Active"),
    "general.models.vpc_settings_properly_configured":
        single("item.vpc_id", "exists"),
    "general.multi_az_deployment.configured":
        single("item.status", "equals", "Active"),
    "general.no_critical_findings.configured":
        single("item.status", "equals", "Active"),
    "general.notebook_instance.vpc_settings_properly_configured":
        single("item.vpc_id", "exists"),
    "general.project.buildspec_source_controlled":
        single("item.status", "equals", "Active"),
    "general.project.envvar_no_hardcoded_credentials":
        single("item.permissions", "not_contains", "*"),
    "general.project.no_secrets_in_environment_variables":
        single("item.permissions", "not_contains", "*"),
    "general.project.reviewed_90_days":
        single("item.status", "equals", "Active"),
    "general.project.source_repo_url_no_sensitive_credentials_exposed":
        single("item.permissions", "not_contains", "*"),
    "general.redis_cluster.automatic_failover_enforced":
        single("item.status", "equals", "Active"),
    "general.redis_cluster.multi_az_deployment":
        single("item.status", "equals", "Active"),
    "general.resource.account_contact_details_current_maintenance_enforced":
        single("item.status", "equals", "Active"),
    "general.resource.account_contact_details_differentiation_enforced":
        single("item.status", "equals", "Active"),
    "general.resource.account_security_contact_information_registration_verified":
        single("item.status", "equals", "Active"),
    "general.resource.security_center_central_management_enforced":
        single("item.status", "equals", "Active"),
    "general.resource.security_center_no_high_severity_findings_present":
        single("item.status", "equals", "Active"),
    "general.restapi.client_certificate_required":
        single("item.ssl_enabled", "equals", "true"),
    "general.restapi.waf_acl_enforced":
        single("item.status", "equals", "Active"),
    "general.root_login_alerts.configured":
        single("item.logging_enabled", "equals", "true"),
    "general.secret_automatic_rotation_enabled.configured":
        single("item.status", "equals", "Active"),
    "general.service.active":
        single("item.status", "equals", "Active"),
    "general.service.private_endpoints_required_for_access":
        single("item.internet_facing", "not_equals", "true"),
    "general.service.private_link_enforced_for_all_traffic":
        single("item.internet_facing", "not_equals", "true"),
    "general.tables.point_in_time_recovery_enabled":
        single("item.backup_enabled", "equals", "true"),
    "general.tag_policies_enabled_and_attached.configured":
        single("item.tags", "exists"),
    "general.target_group.health_check_properly_configured":
        single("item.status", "equals", "Active"),
    "general.training_jobs.vpc_settings_properly_configured":
        single("item.vpc_id", "exists"),
    "general.virtual_interface_redundancy_enforced.configured":
        single("item.status", "equals", "Active"),
    "general.vpc.subnet_configuration_with_nat_gateway":
        single("item.vpc_id", "exists"),
    "general.vulnerability_scan_configured.configured":
        single("item.status", "equals", "Active"),
    "general.waf_acl_enforced.configured":
        single("item.status", "equals", "Active"),
    "general.windows_file_system.multi_az_deployment":
        single("item.status", "equals", "Active"),
    "general.workload_risks_mitigated.configured":
        single("item.status", "equals", "Active"),

    # ── IMS ──────────────────────────────────────────────────────────────────
    "ims.account.access_approval_enabled":
        single("item.permissions", "not_contains", "*"),
    "ims.organization.essential_contacts_configured":
        single("item.status", "equals", "Active"),

    # ── RDS ──────────────────────────────────────────────────────────────────
    "apsaradb.instance.public_access_disabled":
        single("item.internet_facing", "not_equals", "true"),
    "apsaradb.mongodb_cluster.cluster_private_networking_enforced":
        single("item.internet_facing", "not_equals", "true"),
    "apsaradb.rds_instance.instance_iam_or_managed_identity_auth_enabled_where_supported":
        single("item.permissions", "not_contains", "*"),
    "apsaradb.rds_instance.instance_public_access_disabled":
        single("item.internet_facing", "not_equals", "true"),
    "apsaradb.redis_mongodb_instance.instance_iam_or_managed_identity_auth_enabled_where_supported":
        single("item.permissions", "not_contains", "*"),
    "apsaradb.redis_mongodb_instance.instance_public_access_disabled":
        single("item.internet_facing", "not_equals", "true"),

    # ── VPC ──────────────────────────────────────────────────────────────────
    "eip.attached.configured":
        single("item.status", "equals", "Active"),
    "expressconnect.connect.vpn_pre_shared_keys_rotation_policy_defined":
        single("item.status", "equals", "Active"),
    "expressconnect.connection.redundancy":
        single("item.status", "equals", "Active"),
    "expressconnect.virtual.interface_redundancy":
        single("item.status", "equals", "Active"),
}


# ─── Multi-condition pattern fixes ───────────────────────────────────────────

def fix_multi_condition(rule_id: str, cond: dict) -> tuple[dict, bool]:
    """
    Fix known-wrong multi-condition patterns.
    Returns (new_cond, was_changed).
    """
    r = rule_id.lower()

    if "all" not in cond and "any" not in cond:
        return cond, False

    key = "all" if "all" in cond else "any"
    subs = cond[key]
    vars_used = set(s.get("var", "") for s in subs if isinstance(s, dict))

    # Pattern: (encrypted + logging_enabled) for KMS encryption rules
    # These should be (encrypted + kms_key_id)
    if vars_used == {"item.encrypted", "item.logging_enabled"}:
        if any(x in r for x in ["kms", "cmek", "cmk"]):
            return multi_all(
                single("item.encrypted", "equals", "true"),
                single("item.kms_key_id", "exists"),
            ), True

    # Pattern: (logging_enabled + permissions) → single status check
    if vars_used == {"item.logging_enabled", "item.permissions"}:
        return single("item.status", "equals", "Active"), True

    # Pattern: (encrypted + logging_enabled + ssl_enabled) → check rule intent
    if vars_used == {"item.encrypted", "item.logging_enabled", "item.ssl_enabled"}:
        # These are weird combined rule IDs; classify by name
        if any(x in r for x in ["tls", "ssl", "https"]):
            return multi_all(
                single("item.ssl_enabled", "equals", "true"),
                single("item.min_tls_version", "gte", "1.2"),
            ), True
        # Otherwise treat as status
        return single("item.status", "equals", "Active"), True

    return cond, False


# ─── Keyword classification (fallback for rules not in EXPLICIT) ──────────────

def classify_by_keyword(rule_id: str) -> dict:
    """Keyword-based classification as fallback. Returns correct condition."""
    r = rule_id.lower()

    # TLS minimum version
    if any(x in r for x in ["tls_1_2", "tls_1_3", "tls_min_1_2", "tls_min_1_3",
                              "min_tls", "minimum_tls", "1_2_enforced", "tls_12", "tls_13"]):
        return multi_all(
            single("item.ssl_enabled", "equals", "true"),
            single("item.min_tls_version", "gte", "1.2"),
        )

    # SSL / HTTPS / in-transit
    if any(x in r for x in ["ssl_enabled", "tls_enabled", "https_only", "https_enforce",
                              "in_transit_tls", "transit_tls", "transit_encryption",
                              "in_transit_encrypt", "encryption_in_transit",
                              "node_to_node_encryption", "ssl_listener",
                              "https_communication", "client_certificate"]):
        return single("item.ssl_enabled", "equals", "true")

    # CMEK
    if any(x in r for x in ["cmek", "kms_cmk", "customer_managed_key", "cmk_encryption",
                              "kms_encrypted", "kms_key_configured"]):
        return multi_all(
            single("item.encrypted", "equals", "true"),
            single("item.kms_key_id", "exists"),
        )

    # Encryption at rest
    if any(x in r for x in ["encrypt", "at_rest", "disk_encrypt", "volume_encrypt",
                              "data_encrypt", "storage_encrypt", "encryption_enabled",
                              "encryption_at_rest"]):
        return single("item.encrypted", "equals", "true")

    # No public IP
    if any(x in r for x in ["no_public_ip", "public_ip_blocked", "public_ip_assigned",
                              "public_ip_disabled", "public_ip_restricted",
                              "master_nodes_public_ip"]):
        return single("item.public_ip_address", "not_exists")

    # Internet-facing / private access
    if any(x in r for x in ["internet_facing", "internet_access_blocked",
                              "internet_exposure", "publicly_exposed",
                              "no_internet", "public_facing", "restrict_public",
                              "block_public", "private_access_enforced",
                              "private_access_only", "private_nodes_only",
                              "private_subnets_only", "private_endpoint",
                              "endpoint_private_access", "private_control_plane",
                              "internal_only", "external_ips_not_used",
                              "not_publicly_accessible", "public_access_blocked",
                              "private_networking_enforced", "network_private_only",
                              "private_network", "private_only", "public_access"]):
        return single("item.internet_facing", "not_equals", "true")

    # Security groups / firewall
    if any(x in r for x in ["security_group", "securitygroup", "ingress_tcp",
                              "ingress_udp", "egress", "port_22", "port_3389",
                              "port_80", "port_443", "tcp_22", "tcp_3389",
                              "unrestricted_ingress", "firewall_rule",
                              "network_acl", "networkacl", "deny_all_traffic",
                              "default_deny", "permit_any", "no_permit_all"]):
        return single("item.security_group_rules", "not_contains", "0.0.0.0/0")

    # Permissions / IAM
    if any(x in r for x in ["least_privilege", "overpermissive", "permission",
                              "policy_restrict", "policy_blocked", "rbac",
                              "wildcard", "star_policy", "admin_privilege",
                              "privilege_escalation", "authorization",
                              "auth_required", "authn_required", "authz",
                              "anonymous_auth_disabled", "no_anonymous",
                              "access_control_enabled", "allowlist_enforced",
                              "no_plaintext_credentials", "no_secrets",
                              "no_hardcoded", "automount_disabled",
                              "token_mounting_disabled", "no_token",
                              "host_namespace", "host_network", "hostpath",
                              "privilege_denied", "psp.", "seccomp",
                              "cross_account", "sso_required", "oauth2",
                              "trusted_issuer", "signed_url", "cors_policy",
                              "identity_aware", "access_approval"]):
        return single("item.permissions", "not_contains", "*")

    # Logging / monitoring / alerting
    if any(x in r for x in ["logging_enabled", "log_enabled", "logs_enabled",
                              "access_log", "audit_log", "audit_trail",
                              "log_metric", "metric_filter", "flow_log",
                              "activity_log", "field_level_log",
                              "alert_configured", "alarm_configured",
                              "retention_90", "90_day_retention",
                              "log_archive", "log_collection",
                              "cloudwatch", "cloudmonitor", "monitoring_alert",
                              "monitoring_enabled", "log_group",
                              "log_retention", "log_sink", "log_stream",
                              "diagnostic_setting", "delivery_channel",
                              "config_recorder", "config_delivery",
                              "vpc_change_alerts", "threat_detection",
                              "change_monitoring", "alert_destination",
                              "alarm_threshold"]):
        return single("item.logging_enabled", "equals", "true")

    # Backup / recovery
    if any(x in r for x in ["backup_enabled", "backup_configured", "automated_backup",
                              "point_in_time", "pitr", "cross_region_backup",
                              "backup_retention", "snapshot_enabled",
                              "regular_backup", "recovery_point",
                              "reportplans", "backup_plan", "plans.exist",
                              "plans.configured", "global_tables_cross_region"]):
        return single("item.backup_enabled", "equals", "true")

    # MFA
    if "mfa" in r:
        return single("item.mfa_enabled", "equals", "true")

    # Versioning
    if "versioning" in r:
        return single("item.versioning_enabled", "equals", "true")

    # VPC / private network
    if any(x in r for x in ["in_vpc", "custom_vpc", "private_subnet",
                              "vpc_required", "vpc_isolation",
                              "inside_vpc", "vpc_settings", "vpc_routing",
                              "nat_gateway", "enhanced_vpc"]):
        return single("item.vpc_id", "exists")

    # Tags
    if any(x in r for x in ["tagged", "tag_policy", "tags_copied", "resource_tag",
                              "tag_policies"]):
        return single("item.tags", "exists")

    # Status / enabled / configured (feature active)
    return single("item.status", "equals", "Active")


# ─── Main processor ──────────────────────────────────────────────────────────

def get_correct_condition(rule_id: str, current_cond: dict) -> tuple[dict, bool]:
    """
    Returns (correct_condition, was_changed).
    Priority: EXPLICIT override → multi-condition pattern fix → keyword fallback.
    """
    # Strip "alicloud." prefix for lookup
    key = rule_id.removeprefix("alicloud.")

    # 1. Explicit override
    if key in EXPLICIT:
        new = EXPLICIT[key]
        changed = (new != current_cond)
        return new, changed

    # 2. Multi-condition pattern fix (only for multi-condition rules)
    if isinstance(current_cond, dict) and ("all" in current_cond or "any" in current_cond):
        fixed, changed = fix_multi_condition(rule_id, current_cond)
        if changed:
            return fixed, True
        # If no pattern matched, preserve multi-condition rules as-is
        return current_cond, False

    # 3. For single-condition rules with wrong var: use keyword classification
    if isinstance(current_cond, dict) and "var" in current_cond:
        current_var = current_cond.get("var", "")
        # Always reclassify item.id (tautology — resource was already discovered)
        if current_var == "item.id":
            new = classify_by_keyword(rule_id)
            changed = (new != current_cond)
            return new, changed
        # Reclassify logging_enabled when rule has no logging context
        if current_var == "item.logging_enabled":
            log_words = ["log", "monitor", "audit", "alert", "alarm", "metric",
                         "trail", "diagnos", "flow_log", "retention", "delivery",
                         "recorder", "sink", "cloudwatch", "cloudmonitor"]
            if not any(w in rule_id.lower() for w in log_words):
                new = classify_by_keyword(rule_id)
                changed = (new != current_cond)
                return new, changed

    return current_cond, False


def process_all() -> None:
    step7_files = sorted(CATALOG.glob("*/step7_*.checks.yaml"))

    total_rules = 0
    total_fixed = 0
    fix_log = defaultdict(list)

    for step7 in step7_files:
        svc = step7.parent.name
        data = yaml.safe_load(step7.read_text())
        if not data:
            continue
        checks = data.get("checks", []) or []
        file_changed = False

        for rule in checks:
            total_rules += 1
            rule_id = rule.get("rule_id", "")
            old_cond = rule.get("conditions", {})

            new_cond, changed = get_correct_condition(rule_id, old_cond)

            if changed:
                rule["conditions"] = new_cond
                file_changed = True
                total_fixed += 1

                # Summarize old → new for report
                def summarize(c):
                    if isinstance(c, dict):
                        if "all" in c or "any" in c:
                            k = "all" if "all" in c else "any"
                            return f"{k}:[" + ", ".join(
                                f"{s.get('var','')} {s.get('op','')}" for s in c[k]
                            ) + "]"
                        return f"{c.get('var','')} {c.get('op','')} {c.get('value','')}"
                    return str(c)

                fix_log[svc].append(
                    f"  {rule_id}\n"
                    f"    OLD: {summarize(old_cond)}\n"
                    f"    NEW: {summarize(new_cond)}"
                )

        if file_changed:
            data["checks"] = checks
            step7.write_text(
                yaml.dump(data, default_flow_style=False, allow_unicode=True,
                          sort_keys=False, width=120)
            )

    # ── Report ────────────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("AliCloud Check Rule Expert Fix — Results")
    print(f"{'='*70}")
    print(f"\n  Total rules processed : {total_rules}")
    print(f"  Rules corrected       : {total_fixed}")
    print(f"  Rules unchanged       : {total_rules - total_fixed}\n")

    for svc in sorted(fix_log):
        print(f"\n[{svc}]  {len(fix_log[svc])} rules fixed:")
        for line in fix_log[svc]:
            print(line)

    # Final var distribution
    var_counter = Counter()
    for step7 in step7_files:
        data = yaml.safe_load(step7.read_text())
        for rule in (data.get("checks") or []):
            def collect(c):
                if isinstance(c, dict):
                    if "var" in c:
                        var_counter[c["var"]] += 1
                    for k in ("all", "any"):
                        if k in c:
                            for s in c[k]:
                                collect(s)
                elif isinstance(c, list):
                    for s in c:
                        collect(s)
            collect(rule.get("conditions", {}))

    print(f"\n{'='*70}")
    print("Final var distribution across all 1,400 rules:")
    print(f"{'='*70}")
    for var, cnt in var_counter.most_common():
        print(f"  {cnt:4d}  {var}")


if __name__ == "__main__":
    process_all()
