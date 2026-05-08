#!/usr/bin/env python3
"""
Apply maximum field specificity to collision groups.
Each override was chosen by semantic intent of the rule_id.
"""
import csv
from pathlib import Path

# ── Override map: rule_id → new final_var ──────────────────────────────────
# Only rules where we can do BETTER than the current final_var.
OVERRIDES = {

    # ═══════════════════════════════════════════════════════════════════════
    # ecs.security_group — ALL ingress/port rules → security_group_rules
    # (source had them as permissions, wrong for network ACL rules)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_all_ports":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_any_port":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_kafka_9092":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_oracle_1521_2483":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.default_restricted":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.excessive_ingress_egress_rules_reviewed":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.fine_grained_rules_enforced":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.from_launch_wizard":
        "status equals Active",
    "alicloud.ecs.security_group.launch_wizard_security_group_audit":
        "status equals Active",
    # perm+sg multi → sg only
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_22":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_3389":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_ftp_20_21":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_mysql_3306":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_postgres_5432":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.allow_ingress_from_internet_to_tcp_port_redis_6379":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.inbound_3389_restricted_to_trusted_ips":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.ingress_port_22_restricted_to_trusted_ips":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.rdp_access_restricted_to_vpn":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.ssh_access_restricted_to_whitelist":
        "security_group_rules not_contains 0.0.0.0/0",
    # public+internet+perm multi → sg only
    "alicloud.ecs.security_group.all_ports_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.any_port_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.cassandra_ports_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.elasticsearch_kibana_ports_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.kafka_port_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.memcached_port_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.oracle_ports_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.sql_server_ports_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    # 4-condition multi → sg only
    "alicloud.ecs.security_group.ftp_ports_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.mongodb_ports_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.mysql_port_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.postgres_port_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.redis_port_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.security_group.telnet_port_public_ingress_blocked":
        "security_group_rules not_contains 0.0.0.0/0",

    # ═══════════════════════════════════════════════════════════════════════
    # ecs.networkacl — port rules stay security_group_rules; unused → status
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ecs.networkacl.allow_ingress_tcp_port_22":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.networkacl.allow_ingress_tcp_port_3389":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.networkacl.rdp_port_3389_ingress_restricted":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.networkacl.ssh_port_22_ingress_restricted":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.networkacl.default_in_use":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # ecs.instance — port-blocked rules → security_group_rules (from public_ip+internet_facing)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ecs.instance.cassandra_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.cifs_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.kafka_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.kerberos_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.ldap_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.memcached_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.oracle_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.rds_sqlserver_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.no_public_ip_assigned":
        "public_ip_address not_exists",
    # port-blocked (3-condition → sg)
    "alicloud.ecs.instance.mongodb_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.mysql_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.postgresql_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.rdp_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.redis_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.ssh_port_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.telnet_port_public_access_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    # instance status — security-specific overrides
    "alicloud.ecs.instance.confidential_computing_enforced":
        "encrypted equals true",
    "alicloud.ecs.instance.shielded_vm_security_features_enabled":
        "encrypted equals true",
    "alicloud.ecs.instance.single_eni_usage_verified":
        "internet_facing not_equals true",
    "alicloud.ecs.instance.uses_single_eni":
        "internet_facing not_equals true",
    # instance permissions — auth config → status
    "alicloud.ecs.instance.iam_profile_attached":
        "status equals Active",
    "alicloud.ecs.instance.password_auth_disabled":
        "status equals Active",
    "alicloud.ecs.instance.ssh_key_authentication_mandatory":
        "status equals Active",
    # serial port is a config, not SG rule
    "alicloud.ecs.instance.serial_ports_disabled_for_security":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # ecs.ebs — public snapshot rules → internet_facing (not backup)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ecs.ebs.public_snapshot":
        "internet_facing not_equals true",
    "alicloud.ecs.ebs.snapshot_account_block_public_access":
        "internet_facing not_equals true",
    # compound public_snapshot rules → internet_facing
    "alicloud.ecs.ebs.public_snapshot_alicloud_rds_instance_no_public_access_alicloud_ack_endpoints_not_publicly_accessible_alicloud_oss_account_level_public_access_blocks_alicloud_awslambda_function_not_publicly_accessible_alicloud_emr_cluster_master_nodes_no":
        "internet_facing not_equals true",
    "alicloud.ecs.ebs.public_snapshot_alicloud_rds_instance_no_public_access_alicloud_ack_endpoints_not_publicly_accessible_alicloud_vpc_endpoint_for_ec2_enabled_alicloud_oss_account_level_public_access_blocks_alicloud_awslambda_function_not_publicly_accessibl":
        "internet_facing not_equals true",
    "alicloud.ecs.ebs.public_snapshot_alicloud_rds_instance_no_public_access_alicloud_awslambda_function_not_publicly_accessible_alicloud_rds_snapshots_public_access_alicloud_elasticsearch_service_domains_not_publicly_accessible_alicloud_analyticdb_cluster_pub":
        "internet_facing not_equals true",
    "alicloud.ecs.ebs.public_snapshot_alicloud_rds_instance_no_public_access_alicloud_ecs_securitygroup_default_restrict_traffic_alicloud_ecs_securitygroup_allow_ingress_from_internet_to_all_ports_alicloud_ecs_networkacl_allow_ingress_tcp_port_22_alicloud_awsl":
        "internet_facing not_equals true",

    # ecs.disk — public snapshot → internet_facing
    "alicloud.ecs.disk.snapshot_public_access_block_enforced":
        "internet_facing not_equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # ecs.compute_service
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ecs.compute_service.vm_secure_boot_enabled":
        "encrypted equals true",
    "alicloud.ecs.compute_service.vm_serial_console_access_restricted":
        "status equals Active",
    "alicloud.ecs.compute_service.vm_ssh_key_based_auth_required":
        "ssl_enabled equals true",
    "alicloud.ecs.compute_service.vm_ssh_password_auth_disabled":
        "status equals Active",

    # ecs.launch_template
    "alicloud.ecs.launch_template.secrets_management_enforced":
        "permissions not_contains *",

    # ═══════════════════════════════════════════════════════════════════════
    # ack cluster — differentiate within collision groups
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ack.cluster.private_nodes_only":
        "vpc_id exists",
    "alicloud.ack.cluster.weekly_health_checks_enabled":
        "status equals Active",
    "alicloud.ack.cluster.basic_auth_disabled_enforced":
        "status equals Active",
    "alicloud.ack.cluster.dashboard_access_restricted":
        "internet_facing not_equals true",

    # ack control_plane
    "alicloud.ack.control_plane.anonymous_auth_disabled":
        "status equals Active",
    "alicloud.ack.control_plane.apiserver_anonymous_auth_disabled":
        "status equals Active",
    "alicloud.ack.control_plane.token_signing_enabled":
        "ssl_enabled equals true",
    "alicloud.ack.plan.configured":
        "status equals Active",

    # ack service_account
    "alicloud.general.account.private_endpoints_mandatory":
        "vpc_id exists",
    "alicloud.ack.service_account.keys_not_used_or_rotated_90_days_or_less":
        "status equals Active",
    "alicloud.ack.service_account.no_user_managed_long_lived_keys":
        "status equals Active",
    "alicloud.general.account.firewall_restrict_to_selected_networks":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ims.account.access_approval_enabled":
        "status equals Active",

    # ack nodes
    "alicloud.ack.node.auth_disabled":
        "status equals Active",
    "alicloud.ack.node.kubelet_anonymous_auth_disabled":
        "status equals Active",

    # ack network_policy
    "alicloud.ack.network_policy.policy_enabled":
        "status equals Active",

    # ack workload
    "alicloud.ack.workload.host_network_pid_ipc_disabled":
        "internet_facing not_equals true",

    # ack pod
    "alicloud.ack.pod.security_context_configured":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # cloudmonitor alarm rules → status (not logging)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.cloudmonitor.actiontrail_config_changes_log_metric_filter_and_alarm_enabled.configured":
        "status equals Active",
    "alicloud.cloudmonitor.alarm.cpu_utilization_threshold_set":
        "status equals Active",
    "alicloud.cloudmonitor.alarm.memory_utilization_threshold_set":
        "status equals Active",
    "alicloud.cloudmonitor.alarm.thresholds_configured":
        "status equals Active",
    "alicloud.cms.alarm.alert_alarm_actions_configured":
        "status equals Active",
    "alicloud.cms.alarm.alert_critical_alarms_enabled":
        "status equals Active",
    "alicloud.cms.alarm.alert_destinations_authenticated":
        "status equals Active",
    "alicloud.cms.alarm.configured":
        "status equals Active",
    "alicloud.cms.alarm.memory_utilization_configured":
        "status equals Active",
    # cms.alerts notification config → status
    "alicloud.cms.alerts.notification_destinations_configured":
        "status equals Active",
    "alicloud.cms.alerts.notification_endpoints_authenticated":
        "status equals Active",
    # cms.changes alarm rules → status
    "alicloud.cms.changes.to_network_acls_alarm_configured":
        "status equals Active",
    "alicloud.cms.changes.to_network_gateways_alarm_configured":
        "status equals Active",
    "alicloud.cms.changes.to_network_route_tables_alarm_configured":
        "status equals Active",
    "alicloud.cms.changes.to_vpcs_alarm_configured":
        "status equals Active",
    "alicloud.cms.changes.vpcs_alarm_configured":
        "status equals Active",
    # cms.network_acls alarm → status; flow logs → logging
    "alicloud.cms.network.monitoring_alerts_for_anomalies_configured":
        "status equals Active",
    "alicloud.cms.network_acls.change_detection_alarm_configured":
        "status equals Active",
    # actiontrail DR monitoring alerts → backup-related
    "alicloud.cms.dr.monitoring_alert_destinations_configured":
        "status equals Active",
    "alicloud.cms.dr.monitoring_alerts_for_backup_failures_configured":
        "backup_enabled equals true",
    "alicloud.cms.dr.monitoring_alerts_for_replication_lag_configured":
        "backup_enabled equals true",
    "alicloud.cms.dr.monitoring_alerts_for_rpo_rto_breach_configured":
        "backup_enabled equals true",
    # hbr backup job alerts → status
    "alicloud.hbr.backup_recovery_job.monitoring_alert_rules_for_job_failures_configured":
        "status equals Active",
    "alicloud.hbr.backup_recovery_job.monitoring_alert_rules_for_sla_breach_configured":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # .configured / .enabled generic rules → status equals Active
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.analyticdb.cluster_audit_logging_enabled.configured":
        "status equals Active",
    "alicloud.actiontrail.oss_bucket_access_logging_enabled.configured":
        "status equals Active",
    "alicloud.actiontrail.vpc_change_alerts.configured":
        "status equals Active",
    "alicloud.actiontrail.kms_encryption_active.configured":
        "status equals Active",
    "alicloud.bss.plans_configured_and_active.configured":
        "status equals Active",
    "alicloud.bss.plans.properly_configured":
        "status equals Active",
    "alicloud.general.backup_enabled.configured":
        "status equals Active",
    "alicloud.general.global_tables_cross_region_enabled.configured":
        "status equals Active",
    "alicloud.fc.function_public_access_blocked.configured":
        "status equals Active",
    "alicloud.ecs.patch_management_compliance_standards_met.configured":
        "status equals Active",
    "alicloud.general.guardduty_service_enabled.configured":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # logging rules that are really about status
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.actiontrail.logservice.failed_console_signin_alerts":
        "status equals Active",
    "alicloud.config.recorder.delivery_channel_secure_destination_configured":
        "status equals Active",
    "alicloud.apigateway.api.access_logging_enabled":
        "logging_enabled equals true",
    "alicloud.api.gateway.restapi_tracing_enabled":
        "logging_enabled equals true",
    "alicloud.general.restapi.xray_tracing_enabled":
        "logging_enabled equals true",
    "alicloud.cfw.policy.access_control_policies_present":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # asr.GetProjectList — status exists → correct fields
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.devops.project.envvar_awscred_check":
        "permissions not_contains *",
    "alicloud.devops.project.no_secrets_in_variables":
        "permissions not_contains *",
    "alicloud.devops.project.older_90_days":
        "status equals Active",
    "alicloud.devops.project.source_repo_url_check":
        "ssl_enabled equals true",
    "alicloud.devops.project.source_repo_url_no_sensitive_credentials":
        "permissions not_contains *",
    "alicloud.devops.project.source_repo_url_no_sensitive_credentials_alicloud_devops_project_no_secrets_in_variables":
        "permissions not_contains *",
    "alicloud.devops.project.user_controlled_buildspec":
        "status equals Active",
    "alicloud.general.project.source_repo_url_secure":
        "ssl_enabled equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # apsaravideo / datahub stream — status exists → correct fields
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.datahub.stream.consumer_auth_required":
        "permissions not_contains *",
    "alicloud.datahub.stream.data_retention_30_days_minimum":
        "backup_enabled equals true",
    "alicloud.apsaramq.broker.active_deployment_mode":
        "status equals Active",
    "alicloud.apsaramq.broker.cluster_deployment_mode":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # cas certificates — encrypted → status (cert validity is not encryption)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.cas.certificates.expiration_check":
        "status equals Active",
    "alicloud.cas.certificates.not_expired_and_valid":
        "status equals Active",
    # cas private CA — HSM → encrypted
    "alicloud.cas.cas_private_ca.private_ca_ca_key_in_hsm_where_supported":
        "encrypted equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # TLS version differentiation — min_tls_version gte 1.2 vs ssl_enabled
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.analyticdb.cluster.tls_min_1_2_enforced":
        "min_tls_version gte 1.2",
    "alicloud.cdn.distribution.origin_traffic_encrypted_tls1_2_or_higher":
        "min_tls_version gte 1.2",
    "alicloud.dns.rsasha1.in_use_to_key_sign_in_dnssec":
        "ssl_enabled equals true",
    "alicloud.dns.rsasha1.in_use_to_zone_sign_in_dnssec":
        "ssl_enabled equals true",
    "alicloud.expressconnect.connect.vpn_pre_shared_keys_rotation_policy_defined":
        "ssl_enabled equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # backup_enabled → internet_facing (public backup destination)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.hbr.dr.backup_destination_private_only":
        "internet_facing not_equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # hbr.vault multi-condition — split encrypted vs backup
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.hbr.vault.encryption_backup_storage_immutability_enabled":
        "backup_enabled equals true",
    "alicloud.hbr.vault.encryption_encryption_at_rest_enabled":
        "encrypted equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # dataworks.ai_services multi — encrypted+logging → encrypted
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.dataworks.data.catalogs_connection_passwords_encryption_enabled":
        "encrypted equals true",
    "alicloud.dataworks.data.catalogs_metadata_encryption_enabled":
        "encrypted equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # permissions → internet_facing where rule is about public/network access
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.cdn.dcdn.cdn_origin_access_restricted":
        "internet_facing not_equals true",
    "alicloud.hologres.database.public_sharing_disabled":
        "internet_facing not_equals true",
    "alicloud.dms.classification_data.classification_policy_blocks_public_for_sensitive":
        "internet_facing not_equals true",
    "alicloud.cr.instance.access_policy_and_network_restriction_audit":
        "internet_facing not_equals true",
    "alicloud.ack.workload.host_network_pid_ipc_disabled":
        "internet_facing not_equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # permissions → ssl_enabled where rule is about cryptographic auth
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.alb.DescribeZones":
        "ssl_enabled equals true",  # DNS zone transfer TSIG
    "alicloud.dns.zone.zone_transfer_restricted_or_tsig_required":
        "ssl_enabled equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # vpc_id for VPC placement rules
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.general.service.private_endpoints_required_for_access":
        "vpc_id exists",
    "alicloud.general.service.private_link_enforced_for_all_traffic":
        "internet_facing not_equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # internet_facing simplification (multi → single)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.cr.not.publicly_accessible":
        "internet_facing not_equals true",
    "alicloud.efs.not.publicly_accessible":
        "internet_facing not_equals true",
    "alicloud.actiontrail.logs.oss_bucket_is_not_publicly_accessible":
        "internet_facing not_equals true",
    "alicloud.actiontrail.logs.s3_bucket_is_not_publicly_accessible":
        "internet_facing not_equals true",
    # fc.compute
    "alicloud.fc.function.url_cors_policy_enforced":
        "internet_facing not_equals true",
    "alicloud.fc.function.url_public":
        "internet_facing not_equals true",

    # ═══════════════════════════════════════════════════════════════════════
    # fc.ListTriggers — auth source → status
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.fc.trigger.event_source_source_authenticated":
        "status equals Active",

    # ═══════════════════════════════════════════════════════════════════════
    # eck.DescribeAutoProvisioningGroupInstances security group
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ecs.instance.port_ftp_exposed_to_internet":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.instance.port_rdp_exposed_to_internet":
        "security_group_rules not_contains 0.0.0.0/0",

    # ═══════════════════════════════════════════════════════════════════════
    # cfw firewall rules → security_group_rules
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.ecs.firewall.rdp_access_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",
    "alicloud.ecs.firewall.ssh_access_internet_blocked":
        "security_group_rules not_contains 0.0.0.0/0",

    # ═══════════════════════════════════════════════════════════════════════
    # dlf.ListDatabases permissions — cross-account sharing → internet_facing
    # ═══════════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════════
    # credentials_in_secrets_manager → status (using SM = config status)
    # ═══════════════════════════════════════════════════════════════════════
    "alicloud.dataworks.connections.connection_credentials_in_secrets_manager":
        "status equals Active",
    "alicloud.dlf.connections.connection_credentials_in_secrets_manager":
        "status equals Active",
}


def apply_overrides() -> None:
    csv_path = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud/check_rules_final.csv")
    rows = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            rows.append(row)

    changed = 0
    for row in rows:
        rid = row["rule_id"]
        if rid in OVERRIDES:
            old = row["final_var"]
            new = OVERRIDES[rid]
            if old != new:
                row["final_var"] = new
                # append to change_reason
                note = f"specificity: {old} → {new}"
                row["change_reason"] = (row["change_reason"] + " | " + note).strip(" | ")
                changed += 1

    out_path = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud/check_rules_specific.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Applied {changed} overrides → {out_path}")

    # Report new collision count
    from collections import defaultdict
    groups = defaultdict(list)
    for row in rows:
        key = (row["for_each"], row["final_var"])
        groups[key].append(row["rule_id"])
    collisions = {k: v for k, v in groups.items() if len(v) > 1}
    collision_rules = sum(len(v) for v in collisions.values())
    print(f"Remaining collision groups : {len(collisions)}")
    print(f"Remaining rules in collision: {collision_rules}")

    # Field distribution
    from collections import Counter
    dist = Counter(row["final_var"] for row in rows)
    print("\nField distribution:")
    for var, cnt in dist.most_common():
        print(f"  {cnt:4d}  {var}")


if __name__ == "__main__":
    apply_overrides()
