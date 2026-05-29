"""
DI UID Template Seeder — di_seed_uid_templates.py

Injects uid_template into root op entries in rule_discoveries.discoveries_data
(threat_engine_check DB). Also updates the YAML files in catalog/ so the two
stay in sync.

Template resolution priority (highest → lowest):
  1. _DISCOVERY_ID_TEMPLATES  — explicit per-op override (covers all edge cases)
  2. Emit-field ARN scan       — any emit field ending in Arn/ARN
  3. Emit-field ID scan        — Id/ID/id + Name fields → synthetic ARN
  4. Service-level pattern     — _AWS_ARN_PATTERNS fallback
  5. None → uid_source='heuristic' (runtime scan of well-known field candidates)

Usage:
    # Dry-run (shows what would change, no writes):
    python3 di_seed_uid_templates.py

    # Apply YAML edits + DB update:
    python3 di_seed_uid_templates.py --apply
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import yaml

_REPO    = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
_CATALOG = os.path.join(_REPO, "catalog/discovery_generator_data")

# =============================================================================
# Priority-1: Explicit per-discovery-id templates
# Covers every root op that cannot be resolved by generic field detection.
# Key   = discovery_id (exact match)
# Value = uid_template string, OR "singleton" → generates account-scoped UID
# =============================================================================
_DISCOVERY_ID_TEMPLATES: Dict[str, str] = {

    # ── AccessAnalyzer ────────────────────────────────────────────────────────
    "aws.accessanalyzer.list_analyzers":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.name}",
    "aws.accessanalyzer.list_archive_rules":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.analyzerName}/archive-rule/{item.ruleName}",
    "aws.accessanalyzer.list_findings":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.analyzerArn}/finding/{item.id}",
    "aws.accessanalyzer.list_findings_v2":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.analyzerArn}/finding/{item.id}",
    "aws.accessanalyzer.list_access_previews":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.analyzerArn}/access-preview/{item.id}",
    "aws.accessanalyzer.list_analyzed_resources":
        "{item.resourceArn}",
    "aws.accessanalyzer.list_policy_generations":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:policy-generation/{item.jobId}",
    "aws.accessanalyzer.get_access_preview":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.analyzerArn}/access-preview/{item.id}",
    "aws.accessanalyzer.get_analyzed_resource":
        "{item.resourceArn}",
    "aws.accessanalyzer.get_analyzer":
        "{item.arn}",
    "aws.accessanalyzer.get_archive_rule":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.analyzerName}/archive-rule/{item.ruleName}",
    "aws.accessanalyzer.get_finding":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:finding/{item.id}",
    "aws.accessanalyzer.get_finding_v2":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:finding/{item.id}",
    "aws.accessanalyzer.get_finding_recommendation":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:finding/{item.findingId}/recommendation",
    "aws.accessanalyzer.get_findings_statistics":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:findings-statistics",
    "aws.accessanalyzer.list_access_preview_findings":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:access-preview-finding/{item.id}",
    "aws.accessanalyzer.list_tags_for_resource":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.resourceArn}",

    # ── Account ───────────────────────────────────────────────────────────────
    "aws.account.get_alternate_contact":
        "arn:aws:account::{context.account_id}:alternate-contact/{item.AlternateContactType}",
    "aws.account.get_contact_information":
        "arn:aws:account::{context.account_id}:contact-information",

    # ── ACM ───────────────────────────────────────────────────────────────────
    "aws.acm.get_account_configuration":
        "arn:aws:acm:{context.region}:{context.account_id}:account-configuration",

    # ── ACM PCA ───────────────────────────────────────────────────────────────
    "aws.acm-pca.list_certificate_authorities":
        "{item.CertificateAuthorityArn}",

    # ── API Gateway v1 ────────────────────────────────────────────────────────
    "aws.apigateway.get_rest_apis":
        "arn:aws:apigateway:{context.region}::/restapis/{item.id}",
    "aws.apigateway.get_api_keys":
        "arn:aws:apigateway:{context.region}::/apikeys/{item.id}",
    "aws.apigateway.get_usage_plans":
        "arn:aws:apigateway:{context.region}::/usageplans/{item.id}",
    "aws.apigateway.get_authorizers":
        "arn:aws:apigateway:{context.region}::/restapis/{item.restApiId}/authorizers/{item.id}",
    "aws.apigateway.get_method":
        "arn:aws:apigateway:{context.region}::/restapis/{item.restApiId}/resources/{item.resourceId}/methods/{item.httpMethod}",
    "aws.apigateway.get_request_validators":
        "arn:aws:apigateway:{context.region}::/restapis/{item.restApiId}/requestvalidators/{item.id}",
    "aws.apigateway.get_resources":
        "arn:aws:apigateway:{context.region}::/restapis/{item.restApiId}/resources/{item.id}",
    "aws.apigateway.get_vpc_links":
        "arn:aws:apigateway:{context.region}::/vpclinks/{item.id}",

    # ── API Gateway v2 ────────────────────────────────────────────────────────
    "aws.apigatewayv2.get_apis":
        "arn:aws:apigateway:{context.region}::/apis/{item.ApiId}",
    "aws.apigatewayv2.get_integration":
        "arn:aws:apigateway:{context.region}::/apis/{item.ApiId}/integrations/{item.IntegrationId}",

    # ── AppSync ───────────────────────────────────────────────────────────────
    "aws.appsync.get_graphql_api":
        "{item.apiId}",
    "aws.appsync.get_api_cache":
        "arn:aws:appsync:{context.region}:{context.account_id}:apis/{item.apiId}/ApiCaches",

    # ── Bedrock ───────────────────────────────────────────────────────────────
    "aws.bedrock.list_guardrails":
        "{item.guardrailArn}",
    "aws.bedrock.get_model_invocation_logging_configuration":
        "arn:aws:bedrock:{context.region}:{context.account_id}:logging-configuration",

    # ── Budgets ───────────────────────────────────────────────────────────────
    "aws.budgets.describe_notifications_for_budget":
        "arn:aws:budgets::{context.account_id}:budget/{item.BudgetName}/notification/{item.NotificationType}",

    # ── CloudFormation ────────────────────────────────────────────────────────
    "aws.cloudformation.describe_stack_resources":
        "arn:aws:cloudformation:{context.region}:{context.account_id}:stack/{item.StackName}/resource/{item.LogicalResourceId}",
    "aws.cloudformation.get_hook_result":
        "arn:aws:cloudformation:{context.region}:{context.account_id}:hook-result/{item.TypeName}/{item.HookStatusCode}",
    "aws.cloudformation.list_stacks_for_events":
        "arn:aws:cloudformation:{context.region}:{context.account_id}:stack-event/{item.StackId}",

    # ── CodeBuild ─────────────────────────────────────────────────────────────
    "aws.codebuild.list_projects":
        "arn:aws:codebuild:{context.region}:{context.account_id}:project/{item.name}",
    "aws.codebuild.batch_get_projects":
        "{item.arn}",

    # ── Cognito ───────────────────────────────────────────────────────────────
    "aws.cognito.list_user_pools":
        "arn:aws:cognito-idp:{context.region}:{context.account_id}:userpool/{item.Id}",
    "aws.cognito.list_identity_pools":
        "arn:aws:cognito-identity:{context.region}:{context.account_id}:identitypool/{item.IdentityPoolId}",

    # ── Control Tower ─────────────────────────────────────────────────────────
    "aws.controltower.list_control_operations":
        "arn:aws:controltower:{context.region}:{context.account_id}:control-operation/{item.operationIdentifier}",

    # ── Cost Explorer ─────────────────────────────────────────────────────────
    "aws.ce.list_cost_allocation_tags":
        "arn:aws:ce::{context.account_id}:cost-allocation-tag/{item.TagKey}",

    # ── Direct Connect ────────────────────────────────────────────────────────
    "aws.directconnect.describe_connections":
        "arn:aws:directconnect:{context.region}:{context.account_id}:dxcon/{item.connectionId}",
    "aws.directconnect.describe_virtual_interfaces":
        "arn:aws:directconnect:{context.region}:{context.account_id}:dxvif/{item.virtualInterfaceId}",
    "aws.directconnect.list_virtual_interface_test_history":
        "arn:aws:directconnect:{context.region}:{context.account_id}:dxvif-test/{item.testId}",

    # ── Directory Service ─────────────────────────────────────────────────────
    "aws.ds.list_log_subscriptions":
        "arn:aws:ds:{context.region}:{context.account_id}:directory/{item.DirectoryId}/log-subscription",

    # ── EBS (EC2 service) ─────────────────────────────────────────────────────
    "aws.ec2.describe_fast_snapshot_restores":
        "arn:aws:ec2:{context.region}:{context.account_id}:snapshot/{item.SnapshotId}/fast-restore/{item.AvailabilityZone}",

    # ── EFS ───────────────────────────────────────────────────────────────────
    "aws.efs.describe_account_preferences":
        "arn:aws:elasticfilesystem:{context.region}:{context.account_id}:account-preferences",
    "aws.efs.describe_mount_targets":
        "arn:aws:elasticfilesystem:{context.region}:{context.account_id}:file-system/{item.FileSystemId}/mount-target/{item.MountTargetId}",
    "aws.efs.list_tags_for_resource":
        "arn:aws:elasticfilesystem:{context.region}:{context.account_id}:file-system/{item.ResourceId}",

    # ── EIP (EC2 service) ─────────────────────────────────────────────────────
    "aws.eip.describe_addresses":
        "arn:aws:ec2:{context.region}:{context.account_id}:elastic-ip/{item.AllocationId}",

    # ── EMR ───────────────────────────────────────────────────────────────────
    "aws.emr.list_clusters":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.Id}",
    "aws.emr.describe_cluster":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.Id}",
    "aws.emr.list_studios":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:studio/{item.StudioId}",
    "aws.emr.list_studio_session_mappings":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:studio/{item.StudioId}/session/{item.SessionPolicyArn}",
    "aws.emr.get_block_public_access_configuration":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:block-public-access-configuration",
    "aws.emr.list_security_configurations":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:security-configuration/{item.Name}",
    "aws.emr.describe_job_flows":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.JobFlowId}",
    "aws.emr.list_notebook_executions":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:notebook-execution/{item.NotebookExecutionId}",
    "aws.emr.list_release_labels":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:release/{item.ReleaseLabel}",
    "aws.emr.describe_release_label":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:release/{item.ReleaseLabel}",
    "aws.emr.describe_persistent_app_ui":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:persistent-app-ui/{item.Id}",
    "aws.emr.describe_step":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/step/{item.Id}",
    "aws.emr.get_auto_termination_policy":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/auto-termination-policy",
    "aws.emr.get_cluster_session_credentials":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/session-credentials",
    "aws.emr.get_managed_scaling_policy":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/managed-scaling-policy",
    "aws.emr.get_on_cluster_app_ui_presigned_url":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/app-ui",
    "aws.emr.get_persistent_app_ui_presigned_url":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:persistent-app-ui/{item.Id}/presigned-url",
    "aws.emr.list_bootstrap_actions":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/bootstrap-action/{item.Name}",
    "aws.emr.list_instance_fleets":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/instance-fleet/{item.Id}",
    "aws.emr.list_instance_groups":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/instance-group/{item.Id}",
    "aws.emr.list_instances":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/instance/{item.Ec2InstanceId}",
    "aws.emr.list_steps":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.ClusterId}/step/{item.Id}",

    # ── Fargate (ECS service) ─────────────────────────────────────────────────
    "aws.ecs.list_task_definitions":
        "arn:aws:ecs:{context.region}:{context.account_id}:task-definition/{item.taskDefinitionArn}",

    # ── Glacier ───────────────────────────────────────────────────────────────
    "aws.glacier.get_data_retrieval_policy":
        "arn:aws:glacier:{context.region}:{context.account_id}:vaults/data-retrieval-policy",
    "aws.glacier.get_vault_access_policy":
        "arn:aws:glacier:{context.region}:{context.account_id}:vaults/{item.vaultName}/access-policy",
    "aws.glacier.get_vault_lock":
        "arn:aws:glacier:{context.region}:{context.account_id}:vaults/{item.vaultName}/lock-policy",

    # ── Glue ──────────────────────────────────────────────────────────────────
    "aws.glue.get_jobs":
        "arn:aws:glue:{context.region}:{context.account_id}:job/{item.Name}",
    "aws.glue.get_databases":
        "arn:aws:glue:{context.region}:{context.account_id}:database/{item.Name}",
    "aws.glue.get_tables":
        "arn:aws:glue:{context.region}:{context.account_id}:table/{item.DatabaseName}/{item.Name}",
    "aws.glue.get_connections":
        "arn:aws:glue:{context.region}:{context.account_id}:connection/{item.Name}",
    "aws.glue.get_classifiers":
        "arn:aws:glue:{context.region}:{context.account_id}:classifier/{item.Name}",
    "aws.glue.get_column_statistics_task_run":
        "arn:aws:glue:{context.region}:{context.account_id}:column-statistics-task-run/{item.ColumnStatisticsTaskRunId}",
    # Missing ops from check rules — add YAML entries + templates
    "aws.glue.get_ml_transforms":
        "arn:aws:glue:{context.region}:{context.account_id}:mlTransform/{item.TransformId}",
    "aws.glue.get_triggers":
        "arn:aws:glue:{context.region}:{context.account_id}:trigger/{item.Name}",
    "aws.glue.list_data_quality_rulesets":
        "arn:aws:glue:{context.region}:{context.account_id}:dataQualityRuleset/{item.Name}",

    # ── GuardDuty ─────────────────────────────────────────────────────────────
    "aws.guardduty.list_detectors":
        "arn:aws:guardduty:{context.region}:{context.account_id}:detector/{item.DetectorId}",
    "aws.guardduty.get_detector":
        "arn:aws:guardduty:{context.region}:{context.account_id}:detector/{item.DetectorId}",
    "aws.guardduty.get_member_detectors":
        "arn:aws:guardduty:{context.region}:{context.account_id}:detector/{item.DetectorId}",
    "aws.guardduty.describe_malware_scans":
        "arn:aws:guardduty:{context.region}:{context.account_id}:detector/{item.DetectorId}/scan/{item.ScanId}",
    "aws.guardduty.describe_organization_configuration":
        "arn:aws:guardduty:{context.region}:{context.account_id}:detector/{item.DetectorId}/organization-configuration",

    # ── Identity Center (SSO Admin) ───────────────────────────────────────────
    "aws.identitystore.list_users":
        "arn:aws:identitystore::{context.account_id}:identitystore/{item.IdentityStoreId}/user/{item.UserId}",
    "aws.identitystore.list_groups":
        "arn:aws:identitystore::{context.account_id}:identitystore/{item.IdentityStoreId}/group/{item.GroupId}",
    "aws.sso-admin.get_inline_policy_for_permission_set":
        "arn:aws:sso:::permissionSet/{item.InstanceArn}/{item.PermissionSetArn}/inline-policy",

    # ── Import/Export ─────────────────────────────────────────────────────────
    "aws.importexport.list_jobs":
        "arn:aws:importexport::{context.account_id}:job/{item.JobId}",
    "aws.importexport.get_shipping_label":
        "arn:aws:importexport::{context.account_id}:shipping-label/{item.JobId}",

    # ── Inspector (v1) ────────────────────────────────────────────────────────
    "aws.inspector.list_findings":
        "{item.findingArn}",
    "aws.inspector.list_rules_packages":
        "{item.rulesPackageArn}",

    # ── Inspector2 ────────────────────────────────────────────────────────────
    "aws.inspector2.describe_organization_configuration":
        "arn:aws:inspector2:{context.region}:{context.account_id}:organization-configuration",
    "aws.inspector2.list_coverage":
        "arn:aws:inspector2:{context.region}:{context.account_id}:coverage/{item.resourceId}",

    # ── Kafka (MSK) ───────────────────────────────────────────────────────────
    "aws.kafka.list_kafka_versions":
        "arn:aws:kafka:{context.region}:{context.account_id}:kafka-version/{item.Version}",
    "aws.kafka.get_compatible_kafka_versions":
        "arn:aws:kafka:{context.region}:{context.account_id}:compatible-kafka-versions/{item.SourceVersion}",
    "aws.kafka.list_tags_for_resource":
        "{item.ResourceArn}",

    # ── Keyspaces ─────────────────────────────────────────────────────────────
    "aws.keyspaces.list_keyspaces":
        "arn:aws:cassandra:{context.region}:{context.account_id}:/keyspace/{item.keyspaceName}",

    # ── Macie ─────────────────────────────────────────────────────────────────
    "aws.macie.list_findings":
        "arn:aws:macie2:{context.region}:{context.account_id}:finding/{item.id}",

    # ── Network Firewall ──────────────────────────────────────────────────────
    "aws.networkfirewall.list_firewall_policies":
        "{item.FirewallPolicyArn}",
    "aws.networkfirewall.describe_rule_group":
        "{item.RuleGroupArn}",
    "aws.networkfirewall.describe_logging_configuration":
        "arn:aws:network-firewall:{context.region}:{context.account_id}:firewall/{item.FirewallName}/logging-configuration",

    # ── OpenSearch ────────────────────────────────────────────────────────────
    "aws.opensearch.list_domain_names":
        "arn:aws:es:{context.region}:{context.account_id}:domain/{item.DomainName}",

    # ── Organizations ─────────────────────────────────────────────────────────
    "aws.organizations.describe_effective_policy":
        "arn:aws:organizations::{context.account_id}:policy/effective/{item.PolicyType}/{item.TargetId}",

    # ── QLDB ──────────────────────────────────────────────────────────────────
    "aws.qldb.list_qldbs":
        "arn:aws:qldb:{context.region}:{context.account_id}:ledger/{item.name}",

    # ── QuickSight ────────────────────────────────────────────────────────────
    "aws.quicksight.list_dashboards":
        "arn:aws:quicksight:{context.region}:{context.account_id}:dashboard/{item.DashboardId}",
    "aws.quicksight.list_users":
        "arn:aws:quicksight:{context.region}:{context.account_id}:user/{item.UserName}",
    "aws.quicksight.list_groups":
        "arn:aws:quicksight:{context.region}:{context.account_id}:group/{item.GroupName}",
    "aws.quicksight.describe_account_settings":
        "arn:aws:quicksight:{context.region}:{context.account_id}:account-settings",
    "aws.quicksight.describe_data_set_permissions":
        "arn:aws:quicksight:{context.region}:{context.account_id}:dataset/{item.DataSetId}/permissions",
    "aws.quicksight.describe_action_connector_permissions":
        "arn:aws:quicksight:{context.region}:{context.account_id}:connector/{item.ConnectorId}/permissions",

    # ── RDS (missing op) ──────────────────────────────────────────────────────
    "aws.rds.describe_db_option_groups":
        "arn:aws:rds:{context.region}:{context.account_id}:og:{item.OptionGroupName}",

    # ── Redshift ──────────────────────────────────────────────────────────────
    "aws.redshift.describe_cluster_db_revisions":
        "arn:aws:redshift:{context.region}:{context.account_id}:cluster-db-revision:{item.ClusterIdentifier}",
    "aws.redshift.describe_cluster_parameter_groups":
        "arn:aws:redshift:{context.region}:{context.account_id}:parametergroup:{item.ParameterGroupName}",
    "aws.redshift.describe_cluster_security_groups":
        "arn:aws:redshift:{context.region}:{context.account_id}:securitygroup:{item.ClusterSecurityGroupName}",
    "aws.redshift.describe_cluster_subnet_groups":
        "arn:aws:redshift:{context.region}:{context.account_id}:subnetgroup:{item.ClusterSubnetGroupName}",
    "aws.redshift.describe_endpoint_access":
        "arn:aws:redshift:{context.region}:{context.account_id}:endpoint:{item.EndpointName}",
    "aws.redshift.describe_endpoint_authorization":
        "arn:aws:redshift:{context.region}:{context.account_id}:endpoint-authorization:{item.ClusterIdentifier}",
    "aws.redshift.describe_hsm_client_certificates":
        "arn:aws:redshift:{context.region}:{context.account_id}:hsmclientcertificate:{item.HsmClientCertificateIdentifier}",
    "aws.redshift.describe_hsm_configurations":
        "arn:aws:redshift:{context.region}:{context.account_id}:hsmconfiguration:{item.HsmConfigurationIdentifier}",

    # ── SageMaker ─────────────────────────────────────────────────────────────
    "aws.sagemaker.list_apps":
        "arn:aws:sagemaker:{context.region}:{context.account_id}:app/{item.DomainId}/{item.UserProfileName}/{item.AppType}/{item.AppName}",
    "aws.sagemaker.describe_domain":
        "arn:aws:sagemaker:{context.region}:{context.account_id}:domain/{item.DomainId}",
    "aws.sagemaker.describe_inference_experiment":
        "arn:aws:sagemaker:{context.region}:{context.account_id}:inference-experiment/{item.Name}",

    # ── Security Hub ──────────────────────────────────────────────────────────
    "aws.securityhub.get_master_account":
        "arn:aws:securityhub:{context.region}:{context.account_id}:master-account/{item.AccountId}",

    # ── SES ───────────────────────────────────────────────────────────────────
    "aws.ses.describe_active_receipt_rule_set":
        "arn:aws:ses:{context.region}:{context.account_id}:receipt-rule-set/{item.Name}",
    "aws.ses.list_configuration_sets":
        "arn:aws:ses:{context.region}:{context.account_id}:configuration-set/{item.Name}",
    "aws.ses.list_verified_email_addresses":
        "arn:aws:ses:{context.region}:{context.account_id}:identity/{item.VerifiedEmailAddress}",
    "aws.ses.list_identity_policies":
        "arn:aws:ses:{context.region}:{context.account_id}:identity/{item.Identity}/policy/{item.PolicyName}",

    # ── SSM ───────────────────────────────────────────────────────────────────
    "aws.ssm.list_documents":
        "arn:aws:ssm:{context.region}:{context.account_id}:document/{item.Name}",
    "aws.ssm.describe_association":
        "arn:aws:ssm:{context.region}:{context.account_id}:association/{item.AssociationId}",
    "aws.ssm.describe_maintenance_windows":
        "arn:aws:ssm:{context.region}:{context.account_id}:maintenancewindow/{item.WindowId}",
    "aws.ssm.describe_maintenance_window_schedule":
        "arn:aws:ssm:{context.region}:{context.account_id}:maintenancewindow/{item.WindowId}/schedule",
    "aws.ssm.describe_patch_baselines":
        "arn:aws:ssm:{context.region}:{context.account_id}:patchbaseline/{item.BaselineId}",
    "aws.ssm.describe_patch_groups":
        "arn:aws:ssm:{context.region}:{context.account_id}:patchbaseline/{item.BaselineIdentity.BaselineId}/patchgroup/{item.PatchGroup}",
    "aws.ssm.describe_automation_executions":
        "arn:aws:ssm:{context.region}:{context.account_id}:automation-execution/{item.AutomationExecutionId}",
    "aws.ssm.list_nodes":
        "arn:aws:ssm:{context.region}:{context.account_id}:managed-instance/{item.Id}",
    "aws.ssm.list_resource_compliance_summaries":
        "arn:aws:ssm:{context.region}:{context.account_id}:resource/{item.ResourceType}/{item.ResourceId}/compliance/{item.ComplianceType}",
    # Missing op from check rules
    "aws.ssm.describe_parameters":
        "arn:aws:ssm:{context.region}:{context.account_id}:parameter/{item.Name}",

    # ── SSO Admin ─────────────────────────────────────────────────────────────
    "aws.sso-admin.get_inline_policy_for_permission_set":
        "arn:aws:sso:::permissionSet/{item.InstanceArn}/{item.PermissionSetArn}/inline-policy",

    # ── Step Functions ────────────────────────────────────────────────────────
    "aws.stepfunctions.list_state_machines":
        "{item.stateMachineArn}",
    "aws.stepfunctions.list_activities":
        "{item.activityArn}",
    "aws.stepfunctions.list_executions":
        "{item.executionArn}",
    "aws.stepfunctions.list_tags_for_resource":
        "{item.resourceArn}",

    # ── Timestream ────────────────────────────────────────────────────────────
    "aws.timestream-query.describe_account_settings":
        "arn:aws:timestream:{context.region}:{context.account_id}:account-settings",
    "aws.timestream-query.describe_endpoints":
        "arn:aws:timestream:{context.region}:{context.account_id}:endpoint/{item.Address}",
    "aws.timestream-query.list_tags_for_resource":
        "{item.ResourceARN}",

    # ── Transfer Family ───────────────────────────────────────────────────────
    "aws.transfer.list_connectors":
        "arn:aws:transfer:{context.region}:{context.account_id}:connector/{item.ConnectorId}",
    "aws.transfer.list_agreements":
        "arn:aws:transfer:{context.region}:{context.account_id}:agreement/{item.AgreementId}",
    "aws.transfer.list_certificates":
        "arn:aws:transfer:{context.region}:{context.account_id}:certificate/{item.CertificateId}",
    "aws.transfer.list_profiles":
        "arn:aws:transfer:{context.region}:{context.account_id}:profile/{item.ProfileId}",
    "aws.transfer.list_workflows":
        "arn:aws:transfer:{context.region}:{context.account_id}:workflow/{item.WorkflowId}",

    # ── VPC (missing op) ──────────────────────────────────────────────────────
    "aws.vpc.describe_customer_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:customer-gateway/{item.CustomerGatewayId}",
    "aws.ec2.describe_vpn_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpn-gateway/{item.VpnGatewayId}",

    # ── VPN ───────────────────────────────────────────────────────────────────
    "aws.vpn.list_vpns":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpn-connection/{item.id}",

    # ── WAF (Classic) ─────────────────────────────────────────────────────────
    "aws.waf.list_web_ac_ls":
        "arn:aws:waf::{context.account_id}:webacl/{item.WebACLId}",
    "aws.waf.list_ip_sets":
        "arn:aws:waf::{context.account_id}:ipset/{item.IPSetId}",
    "aws.waf.list_rule_groups":
        "arn:aws:waf::{context.account_id}:rulegroup/{item.RuleGroupId}",
    "aws.waf.list_regex_pattern_sets":
        "arn:aws:waf::{context.account_id}:regexpatternset/{item.RegexPatternSetId}",
    "aws.waf.list_activated_rules_in_rule_group":
        "arn:aws:waf::{context.account_id}:rulegroup/{item.RuleGroupId}/rule/{item.RuleId}",

    # ── WAFv2 ─────────────────────────────────────────────────────────────────
    "aws.wafv2.list_available_managed_rule_groups":
        "arn:aws:wafv2:{context.region}:{context.account_id}:managed-rule-group/{item.VendorName}/{item.Name}",
    "aws.wafv2.list_resources_for_web_acl":
        "{item.ResourceArn}",

    # ── WorkSpaces ────────────────────────────────────────────────────────────
    "aws.workspaces.describe_workspace_directories":
        "arn:aws:workspaces:{context.region}:{context.account_id}:directory/{item.DirectoryId}",

    # ── X-Ray ─────────────────────────────────────────────────────────────────
    "aws.xray.get_encryption_config":
        "arn:aws:xray:{context.region}:{context.account_id}:encryption-config",
    "aws.xray.get_sampling_statistic_summaries":
        "arn:aws:xray:{context.region}:{context.account_id}:sampling-rule/{item.RuleName}",

    # ── CORRECTIONS: override wrong-field-name templates ──────────────────────
    # These entries override Priority-3 (_AWS_ARN_PATTERNS) assignments where the
    # service-level fallback referenced a field name not present in the op's emit
    # mapping.  Python dict last-value-wins ensures these take priority.

    # AccessAnalyzer — emit wraps result in a nested key; use dot-path access
    "aws.accessanalyzer.get_access_preview":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.accessPreview.analyzerArn}/access-preview/{item.accessPreview.id}",
    "aws.accessanalyzer.get_analyzed_resource":
        "{item.resource.resourceArn}",
    "aws.accessanalyzer.get_analyzer":
        "{item.analyzer.arn}",
    "aws.accessanalyzer.get_archive_rule":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:analyzer/{item.archiveRule.analyzerName}/archive-rule/{item.archiveRule.ruleName}",
    "aws.accessanalyzer.get_finding":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:finding/{item.finding.id}",
    "aws.accessanalyzer.list_tags_for_resource":
        "arn:aws:access-analyzer:{context.region}:{context.account_id}:tags-resource",

    # ACM PCA — Arn field IS at top level of the raw object
    "aws.acm-pca.list_certificate_authorities":
        "{item.Arn}",

    # API Gateway — use the `id` field that IS in emit
    "aws.apigateway.get_authorizers":
        "arn:aws:apigateway:{context.region}::/authorizers/{item.id}",
    "aws.apigateway.get_method":
        "arn:aws:apigateway:{context.region}::/methods/{item.httpMethod}",
    "aws.apigateway.get_request_validators":
        "arn:aws:apigateway:{context.region}::/requestvalidators/{item.id}",
    "aws.apigateway.get_resources":
        "arn:aws:apigateway:{context.region}::/resources/{item.id}",
    "aws.apigatewayv2.get_integration":
        "arn:aws:apigateway:{context.region}::{context.account_id}:integration",

    # AppSync — singletons (no unique ID in emit)
    "aws.appsync.get_api_cache":
        "arn:aws:appsync:{context.region}:{context.account_id}:apis/cache",
    "aws.appsync.get_graphql_api":
        "arn:aws:appsync:{context.region}:{context.account_id}:graphql-api",

    # Bedrock — `name` IS in emit
    "aws.bedrock.list_guardrails":
        "arn:aws:bedrock:{context.region}:{context.account_id}:guardrail/{item.name}",

    # Budgets — NotificationType IS in emit
    "aws.budgets.describe_notifications_for_budget":
        "arn:aws:budgets::{context.account_id}:budget/notification/{item.NotificationType}",

    # CloudFormation
    "aws.cloudformation.get_hook_result":
        "arn:aws:cloudformation:{context.region}:{context.account_id}:hook-result/{item.AnnotationName}",
    "aws.cloudformation.list_stacks_for_events":
        "{item.item.StackId}",

    # CloudFront — emit=['item'], value is nested OriginRequestPolicy object
    "aws.cloudfront.list_origin_request_policies":
        "arn:aws:cloudfront::{context.account_id}:origin-request-policy/{item.item.OriginRequestPolicy.Id}",

    # CloudTrail — singleton (no trail identifier in emit for this op)
    "aws.cloudtrail.get_event_selectors":
        "arn:aws:cloudtrail:{context.region}:{context.account_id}:trail/event-selectors",

    # CloudWatch — use available identifier fields
    "aws.cloudwatch.describe_anomaly_detectors":
        "arn:aws:cloudwatch:{context.region}:{context.account_id}:anomaly-detector/{item.Namespace}/{item.MetricName}",
    "aws.cloudwatch.describe_insight_rules":
        "arn:aws:cloudwatch:{context.region}:{context.account_id}:insight-rule/{item.Name}",
    "aws.cloudwatch.list_tags_for_resource":
        "arn:aws:cloudwatch:{context.region}:{context.account_id}:resource-tags",

    # CodeBuild — list_projects emit=['nextToken'] where value is project name string
    "aws.codebuild.list_projects":
        "arn:aws:codebuild:{context.region}:{context.account_id}:project/{item.nextToken}",
    "aws.codebuild.batch_get_projects":
        "arn:aws:codebuild:{context.region}:{context.account_id}:project/batch-get",

    # Cognito — list_user_pools emit=['item'] where item is pool object with Id
    "aws.cognito.list_identity_pools":
        "arn:aws:cognito-identity:{context.region}:{context.account_id}:identitypool/unknown",
    "aws.cognito.list_user_pools":
        "arn:aws:cognito-idp:{context.region}:{context.account_id}:userpool/{item.item.Id}",

    # DynamoDB — GlobalTableName IS in emit; list_tables emit=['item'] = table name string
    "aws.dynamodb.list_global_tables":
        "arn:aws:dynamodb::{context.account_id}:global-table/{item.GlobalTableName}",
    "aws.dynamodb.list_tables":
        "arn:aws:dynamodb:{context.region}:{context.account_id}:table/{item.item}",

    # EC2 — override wrong InstanceId service-level fallback with resource-specific IDs
    "aws.ec2.describe_account_attributes":
        "arn:aws:ec2:{context.region}:{context.account_id}:account-attribute/{item.AttributeName}",
    "aws.ec2.describe_address_transfers":
        "arn:aws:ec2:{context.region}:{context.account_id}:elastic-ip/{item.AllocationId}",
    "aws.ec2.describe_carrier_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:carrier-gateway/{item.CarrierGatewayId}",
    "aws.ec2.describe_dhcp_options":
        "arn:aws:ec2:{context.region}:{context.account_id}:dhcp-options",
    "aws.ec2.describe_egress_only_internet_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:egress-only-internet-gateway/{item.EgressOnlyInternetGatewayId}",
    "aws.ec2.describe_fleets":
        "arn:aws:ec2:{context.region}:{context.account_id}:fleet/unknown",
    "aws.ec2.describe_images":
        "arn:aws:ec2:{context.region}:{context.account_id}:image/{item.ImageId}",
    "aws.ec2.describe_import_image_tasks":
        "arn:aws:ec2:{context.region}:{context.account_id}:import-image-task/{item.ImportTaskId}",
    "aws.ec2.describe_internet_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:internet-gateway/{item.item.InternetGatewayId}",
    "aws.ec2.describe_ipv6_pools":
        "arn:aws:ec2:{context.region}:{context.account_id}:ipv6pool-ec2/{item.PoolId}",
    "aws.ec2.describe_key_pairs":
        "arn:aws:ec2:{context.region}:{context.account_id}:key-pair/{item.KeyPairId}",
    "aws.ec2.describe_launch_template_versions":
        "arn:aws:ec2:{context.region}:{context.account_id}:launch-template/{item.LaunchTemplateId}/version/{item.VersionNumber}",
    "aws.ec2.describe_launch_templates":
        "arn:aws:ec2:{context.region}:{context.account_id}:launch-template/{item.LaunchTemplateId}",
    "aws.ec2.describe_local_gateway_route_table_vpc_associations":
        "arn:aws:ec2:{context.region}:{context.account_id}:local-gateway-route-table-vpc-association/{item.LocalGatewayRouteTableVpcAssociationId}",
    "aws.ec2.describe_nat_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:natgateway/{item.NatGatewayId}",
    "aws.ec2.describe_network_acls":
        "arn:aws:ec2:{context.region}:{context.account_id}:network-acl/{item.NetworkAclId}",
    "aws.ec2.describe_prefix_lists":
        "arn:aws:ec2:{context.region}:{context.account_id}:prefix-list/{item.PrefixListName}",
    "aws.ec2.describe_public_ipv4_pools":
        "arn:aws:ec2:{context.region}:{context.account_id}:ipv4pool-ec2/{item.PoolId}",
    "aws.ec2.describe_reserved_instances":
        "arn:aws:ec2:{context.region}:{context.account_id}:reserved-instances/{item.ReservedInstancesId}",
    "aws.ec2.describe_route_tables":
        "arn:aws:ec2:{context.region}:{context.account_id}:route-table/{item.RouteTableId}",
    "aws.ec2.describe_security_group_vpc_associations":
        "arn:aws:ec2:{context.region}:{context.account_id}:security-group-vpc-association/{item.GroupId}",
    "aws.ec2.describe_traffic_mirror_filter_rules":
        "arn:aws:ec2:{context.region}:{context.account_id}:traffic-mirror-filter/{item.TrafficMirrorFilterId}",
    "aws.ec2.describe_transit_gateway_attachments":
        "arn:aws:ec2:{context.region}:{context.account_id}:transit-gateway/{item.TransitGatewayId}/attachment",
    "aws.ec2.describe_transit_gateway_route_tables":
        "arn:aws:ec2:{context.region}:{context.account_id}:transit-gateway-route-table/{item.TransitGatewayRouteTableId}",
    "aws.ec2.describe_transit_gateway_vpc_attachments":
        "arn:aws:ec2:{context.region}:{context.account_id}:transit-gateway/{item.TransitGatewayId}/vpc-attachment/{item.VpcId}",
    "aws.ec2.describe_verified_access_instances":
        "arn:aws:ec2:{context.region}:{context.account_id}:verified-access-instance/{item.VerifiedAccessInstanceId}",
    "aws.ec2.describe_vpc_block_public_access_options":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc-block-public-access",
    "aws.ec2.describe_vpc_endpoint_connections":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc-endpoint-connection/{item.VpcEndpointConnectionId}",
    "aws.ec2.describe_vpc_endpoint_service_configurations":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc-endpoint-service/{item.ServiceId}",
    "aws.ec2.describe_vpc_endpoint_service_permissions":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc-endpoint-service-permissions",
    "aws.ec2.describe_vpc_peering_connections":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc-peering-connection/{item.VpcPeeringConnectionId}",
    "aws.ec2.describe_vpcs":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc/{item.VpcId}",
    "aws.ec2.get_ebs_encryption_by_default":
        "arn:aws:ec2:{context.region}:{context.account_id}:ebs-encryption-by-default",
    "aws.ec2.get_enabled_ipam_policy":
        "arn:aws:ec2:{context.region}:{context.account_id}:ipam-policy",
    "aws.ec2.get_serial_console_access_status":
        "arn:aws:ec2:{context.region}:{context.account_id}:serial-console-access",
    "aws.ec2.list_images_in_recycle_bin":
        "arn:aws:ec2:{context.region}:{context.account_id}:image/{item.ImageId}",
    "aws.ec2.list_snapshots_in_recycle_bin":
        "arn:aws:ec2:{context.region}:{context.account_id}:snapshot/{item.SnapshotId}",

    # ECR — registry-level singleton settings
    "aws.ecr.describe_registry":
        "arn:aws:ecr:{context.region}:{context.account_id}:registry",
    "aws.ecr.get_registry_scanning_configuration":
        "arn:aws:ecr:{context.region}:{context.account_id}:registry-scanning-config",

    # ECS — emit=['item'], value is service/task-def ARN string
    "aws.ecs.list_services":
        "{item.item}",
    "aws.ecs.list_task_definitions":
        "{item.item}",

    # EFS — singleton (no resource ID in emit for tag list op)
    "aws.efs.list_tags_for_resource":
        "arn:aws:elasticfilesystem:{context.region}:{context.account_id}:resource-tags",

    # EKS — emit=['nextToken'] where value is cluster name string
    "aws.eks.list_clusters":
        "arn:aws:eks:{context.region}:{context.account_id}:cluster/{item.nextToken}",

    # ELBv2 — Name IS in emit for SSL policies
    "aws.elbv2.describe_ssl_policies":
        "arn:aws:elasticloadbalancing:{context.region}:{context.account_id}:ssl-policy/{item.Name}",

    # EMR — nested-object emit patterns
    "aws.emr.describe_cluster":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:cluster/{item.Cluster.Id}",
    "aws.emr.describe_persistent_app_ui":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:persistent-app-ui",
    "aws.emr.describe_step":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:step/{item.Step.Id}",
    "aws.emr.get_auto_termination_policy":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:auto-termination-policy",
    "aws.emr.get_cluster_session_credentials":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:session-credentials",
    "aws.emr.get_managed_scaling_policy":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:managed-scaling-policy",
    "aws.emr.get_on_cluster_app_ui_presigned_url":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:on-cluster-app-ui",
    "aws.emr.get_persistent_app_ui_presigned_url":
        "arn:aws:elasticmapreduce:{context.region}:{context.account_id}:persistent-app-ui-presigned",

    # Glacier — singletons (no vault name in emit for these ops)
    "aws.glacier.get_vault_access_policy":
        "arn:aws:glacier:{context.region}:{context.account_id}:vaults/access-policy",
    "aws.glacier.get_vault_lock":
        "arn:aws:glacier:{context.region}:{context.account_id}:vaults/lock-policy",

    # GuardDuty
    "aws.guardduty.list_detectors":
        "arn:aws:guardduty:{context.region}:{context.account_id}:detector/{item.item}",
    "aws.guardduty.get_detector":
        "arn:aws:guardduty:{context.region}:{context.account_id}:detector/config",
    "aws.guardduty.get_member_detectors":
        "arn:aws:guardduty:{context.region}:{context.account_id}:member-detector/{item.AccountId}",
    "aws.guardduty.describe_organization_configuration":
        "arn:aws:guardduty:{context.region}:{context.account_id}:organization-config",

    # IAM — singletons and composite keys
    "aws.iam.get_account_password_policy":
        "arn:aws:iam::{context.account_id}:account-password-policy",
    "aws.iam.get_account_summary":
        "arn:aws:iam::{context.account_id}:account-summary",
    "aws.iam.get_saml_provider":
        "arn:aws:iam::{context.account_id}:saml-provider",
    "aws.iam.list_access_keys":
        "arn:aws:iam::{context.account_id}:user/{item.UserName}/access-key/{item.AccessKeyId}",
    "aws.iam.list_delegation_requests":
        "arn:aws:iam::{context.account_id}:delegation-request/{item.DelegationRequestId}",
    "aws.iam.list_mfa_devices":
        "arn:aws:iam::{context.account_id}:mfa-device/{item.SerialNumber}",
    "aws.iam.list_policy_versions":
        "arn:aws:iam::{context.account_id}:policy-version/{item.VersionId}",
    "aws.iam.list_signing_certificates":
        "arn:aws:iam::{context.account_id}:user/{item.UserName}/signing-certificate/{item.CertificateId}",
    "aws.iam.list_virtual_mfa_devices":
        "arn:aws:iam::{context.account_id}:mfa/{item.SerialNumber}",

    # Identity Store — IdentityStoreId IS in emit
    "aws.identitystore.list_groups":
        "arn:aws:identitystore::{context.account_id}:identitystore/{item.IdentityStoreId}/group",
    "aws.identitystore.list_users":
        "arn:aws:identitystore::{context.account_id}:identitystore/{item.IdentityStoreId}/user/{item.DisplayName}",

    # ImportExport — singleton
    "aws.importexport.get_shipping_label":
        "arn:aws:importexport::{context.account_id}:shipping-label",

    # Inspector Classic — emit=['item'] = finding/package ARN string
    "aws.inspector.list_findings":
        "{item.item}",
    "aws.inspector.list_rules_packages":
        "{item.rulesPackages}",

    # Kafka — singleton (no cluster name in emit for tag op)
    "aws.kafka.list_tags_for_resource":
        "arn:aws:kafka:{context.region}:{context.account_id}:cluster/tags",

    # KMS — singleton (no KeyId in emit for rotation status op)
    "aws.kms.get_key_rotation_status":
        "arn:aws:kms:{context.region}:{context.account_id}:key-rotation-status",

    # Macie — title IS in emit
    "aws.macie.list_findings":
        "arn:aws:macie2:{context.region}:{context.account_id}:finding/{item.title}",

    # Network Firewall — nested Arn field in RuleGroupResponse
    "aws.networkfirewall.describe_logging_configuration":
        "arn:aws:network-firewall:{context.region}:{context.account_id}:firewall/logging-config",
    "aws.networkfirewall.describe_rule_group":
        "{item.RuleGroupResponse.RuleGroupArn}",
    "aws.networkfirewall.list_firewall_policies":
        "{item.item.Arn}",

    # QuickSight — singletons
    "aws.quicksight.describe_action_connector_permissions":
        "arn:aws:quicksight:{context.region}:{context.account_id}:connector/permissions",
    "aws.quicksight.describe_data_set_permissions":
        "arn:aws:quicksight:{context.region}:{context.account_id}:dataset/permissions",

    # RDS — BlueGreenDeploymentIdentifier IS in emit
    "aws.rds.describe_blue_green_deployments":
        "arn:aws:rds:{context.region}:{context.account_id}:blue-green-deployment:{item.BlueGreenDeploymentIdentifier}",

    # Route53 Recovery Readiness — singletons (no ID in emit)
    "aws.route53.list_cells":
        "arn:aws:route53-recovery-readiness::{context.account_id}:cell",
    "aws.route53.list_clusters":
        "arn:aws:route53-recovery-readiness::{context.account_id}:cluster",

    # SageMaker — singletons (only Tags in emit for these ops)
    "aws.sagemaker.describe_domain":
        "arn:aws:sagemaker:{context.region}:{context.account_id}:domain",
    "aws.sagemaker.describe_inference_experiment":
        "arn:aws:sagemaker:{context.region}:{context.account_id}:inference-experiment",

    # SES — singleton
    "aws.ses.list_identity_policies":
        "arn:aws:ses:{context.region}:{context.account_id}:identity/policies",
    "aws.ses.list_verified_email_addresses":
        "arn:aws:ses:{context.region}:{context.account_id}:identity/verified-emails",

    # SSO Admin — get_inline_policy emits only Version/Statement, no permission set identifier
    "aws.sso-admin.get_inline_policy_for_permission_set":
        "arn:aws:sso:::permission-set/inline-policy",

    # Timestream Query — list_tags emits only Key/Value, no resource ARN
    "aws.timestream-query.list_tags_for_resource":
        "arn:aws:timestream:{context.region}:{context.account_id}:database/resource-tags",

    # Transfer — singletons for list ops; connector uses nested item
    "aws.transfer.list_agreements":
        "arn:aws:transfer:{context.region}:{context.account_id}:agreement",
    "aws.transfer.list_certificates":
        "arn:aws:transfer:{context.region}:{context.account_id}:certificate",
    "aws.transfer.list_connectors":
        "arn:aws:transfer:{context.region}:{context.account_id}:connector/{item.item.ConnectorId}",
    "aws.transfer.list_profiles":
        "arn:aws:transfer:{context.region}:{context.account_id}:profile",
    "aws.transfer.list_workflows":
        "arn:aws:transfer:{context.region}:{context.account_id}:workflow",

    # VPC — proper ID fields ARE in emit (unlike ec2.describe_* ops above)
    "aws.vpc.describe_dhcp_options":
        "arn:aws:ec2:{context.region}:{context.account_id}:dhcp-options/{item.DhcpOptionsId}",
    "aws.vpc.describe_egress_only_internet_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:egress-only-internet-gateway/{item.EgressOnlyInternetGatewayId}",
    "aws.vpc.describe_internet_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:internet-gateway/{item.InternetGatewayId}",
    "aws.vpc.describe_vpc_endpoint_service_configurations":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc-endpoint-service/{item.ServiceId}",
    "aws.vpc.describe_vpc_peering_connections":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpc-peering-connection/{item.VpcPeeringConnectionId}",
    "aws.vpc.describe_vpn_gateways":
        "arn:aws:ec2:{context.region}:{context.account_id}:vpn-gateway/{item.VpnGatewayId}",

    # WAF Classic — RuleId IS in emit
    "aws.waf.list_activated_rules_in_rule_group":
        "arn:aws:waf::{context.account_id}:rule/{item.RuleId}",
}

# =============================================================================
# Priority-2: Service-level ARN patterns (used when no ARN field in emit)
# =============================================================================
_AWS_ARN_PATTERNS: Dict[str, str] = {
    "s3":              "arn:aws:s3:::{item.Name}",
    "iam":             "arn:aws:iam::{context.account_id}:{item.Path}{item.UserName}",
    "ec2":             "arn:aws:ec2:{context.region}:{context.account_id}:instance/{item.InstanceId}",
    "lambda":          "arn:aws:lambda:{context.region}:{context.account_id}:function:{item.FunctionName}",
    "rds":             "arn:aws:rds:{context.region}:{context.account_id}:db:{item.DBInstanceIdentifier}",
    "eks":             "arn:aws:eks:{context.region}:{context.account_id}:cluster/{item.name}",
    "elasticache":     "arn:aws:elasticache:{context.region}:{context.account_id}:cluster:{item.CacheClusterId}",
    "dynamodb":        "arn:aws:dynamodb:{context.region}:{context.account_id}:table/{item.TableName}",
    "kms":             "arn:aws:kms:{context.region}:{context.account_id}:key/{item.KeyId}",
    "cloudtrail":      "arn:aws:cloudtrail:{context.region}:{context.account_id}:trail/{item.Name}",
    "cloudwatch":      "arn:aws:cloudwatch:{context.region}:{context.account_id}:alarm/{item.AlarmName}",
    "sns":             "{item.TopicArn}",
    "sqs":             "arn:aws:sqs:{context.region}:{context.account_id}:{item.QueueUrl}",
    "secretsmanager":  "arn:aws:secretsmanager:{context.region}:{context.account_id}:secret:{item.Name}",
    "vpc":             "arn:aws:ec2:{context.region}:{context.account_id}:vpc/{item.VpcId}",
    "elb":             "{item.LoadBalancerArn}",
    "elbv2":           "{item.LoadBalancerArn}",
    "cloudfront":      "arn:aws:cloudfront::{context.account_id}:distribution/{item.Id}",
    "route53":         "arn:aws:route53:::hostedzone/{item.Id}",
    "ecr":             "{item.repositoryArn}",
    "ecs":             "{item.clusterArn}",
    "backup":          "{item.BackupPlanArn}",
    "codebuild":       "{item.arn}",
    "appsync":         "{item.apiId}",
    "kafka":           "{item.ClusterArn}",
    "kinesis":         "{item.StreamARN}",
    "sagemaker":       "{item.DomainArn}",
    "bedrock":         "{item.guardrailArn}",
    "wafv2":           "{item.ARN}",
    "athena":          "{item.WorkGroupArn}",
    "neptune":         "arn:aws:rds:{context.region}:{context.account_id}:cluster:{item.DBClusterIdentifier}",
    "docdb":           "arn:aws:rds:{context.region}:{context.account_id}:cluster:{item.DBClusterIdentifier}",
    "redshift":        "arn:aws:redshift:{context.region}:{context.account_id}:cluster:{item.ClusterIdentifier}",
    "stepfunctions":   "{item.stateMachineArn}",
    "glue":            "arn:aws:glue:{context.region}:{context.account_id}:job/{item.Name}",
    "opensearch":      "arn:aws:es:{context.region}:{context.account_id}:domain/{item.DomainName}",
}

# =============================================================================
# Emit field detection helpers
# =============================================================================
_ARN_SUFFIXES   = ("Arn", "ARN", "arn")
_ID_FIELDS      = ("id", "Id", "ID", "identifier", "Identifier")
_NAME_FIELDS    = ("name", "Name")

_ID_FIELDS_BY_CSP: Dict[str, Tuple[str, ...]] = {
    "azure":    ("id", "resourceId"),
    "gcp":      ("selfLink", "name"),
    "oci":      ("id", "identifier"),
    "ibm":      ("crn", "id"),
    "alicloud": ("Arn", "ARN", "ResourceId", "InstanceId"),
    "k8s":      ("uid", "name"),
}


def _find_arn_field(emit_fields: List[str]) -> Optional[str]:
    return next((f for f in emit_fields if any(f.endswith(s) for s in _ARN_SUFFIXES)), None)


def _find_id_field(emit_fields: List[str]) -> Optional[str]:
    """Find the first field that looks like a unique identifier."""
    # Prefer fields that end with common ID suffixes
    for f in emit_fields:
        if f.endswith("Id") and f not in ("EventId", "LogId"):
            return f
    for f in emit_fields:
        if f in ("id", "ID", "identifier", "Identifier"):
            return f
    return None


def _build_uid_template(
    discovery_id: str,
    service: str,
    csp: str,
    action: str,
    emit_fields: List[str],
) -> Optional[str]:
    """Resolve uid_template for one root op using the priority chain."""

    # Priority 1: explicit per-op override
    if discovery_id in _DISCOVERY_ID_TEMPLATES:
        return _DISCOVERY_ID_TEMPLATES[discovery_id]

    if csp == "aws":
        # Priority 2: emit field contains an ARN
        arn_field = _find_arn_field(emit_fields)
        if arn_field:
            return f"{{item.{arn_field}}}"

        # Priority 3: service-level pattern
        pattern = _AWS_ARN_PATTERNS.get(service)
        if pattern:
            return pattern

        return None

    # Non-AWS CSPs
    candidates = _ID_FIELDS_BY_CSP.get(csp, ())
    for c in candidates:
        if c in emit_fields:
            return f"{{item.{c}}}"

    return None


# =============================================================================
# YAML processing
# =============================================================================

def process_yaml(path: str, csp: str, dry_run: bool = True) -> List[Tuple[str, str]]:
    """Inject uid_template into root op entries in one YAML file.

    Returns list of (discovery_id, uid_template) for ops that were updated.
    """
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        print(f"  WARN: {path}: {e}", file=sys.stderr)
        return []

    if not isinstance(data, dict):
        return []

    service = data.get("service", "")
    ops: List[Dict[str, Any]] = data.get("discovery", []) or []

    updated: List[Tuple[str, str]] = []
    changed = False

    for op in ops:
        if op.get("for_each"):
            continue  # enrichment — skip

        did = op.get("discovery_id", "")
        if not did:
            continue

        if op.get("uid_template"):
            updated.append((did, op["uid_template"]))
            continue

        emit = op.get("emit") or {}
        emit_fields = list((emit.get("item") or {}).keys())
        calls = op.get("calls") or []
        action = calls[0].get("action", "") if calls else ""

        template = _build_uid_template(did, service, csp, action, emit_fields)

        if template:
            op["uid_template"] = template
            op["uid_source"] = "template"
            updated.append((did, template))
            changed = True
        else:
            updated.append((did, ""))  # heuristic

    if changed and not dry_run:
        with open(path, "w") as fh:
            yaml.dump(data, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return updated


def load_all_csp_yamls(dry_run: bool = True) -> Dict[str, List[Tuple[str, str, str]]]:
    """Walk all CSP catalog dirs and process discovery YAMLs."""
    results: Dict[str, List[Tuple[str, str, str]]] = {}

    for csp_dir in sorted(glob.glob(os.path.join(_CATALOG, "*"))):
        csp = os.path.basename(csp_dir)
        if not os.path.isdir(csp_dir):
            continue

        csp_entries: List[Tuple[str, str, str]] = []
        seen_dids: set = set()

        for yaml_path in sorted(glob.glob(os.path.join(csp_dir, "**/*.yaml"), recursive=True)):
            pairs = process_yaml(yaml_path, csp, dry_run=dry_run)
            svc_rel = os.path.relpath(yaml_path, csp_dir)
            service = svc_rel.split(os.sep)[0]
            for (did, tmpl) in pairs:
                if did not in seen_dids:
                    seen_dids.add(did)
                    csp_entries.append((service, did, tmpl))

        if csp_entries:
            results[csp] = csp_entries

    return results


def update_rule_discoveries(entries_by_csp: Dict[str, List[Tuple[str, str, str]]]) -> None:
    """Inject uid_template into rule_discoveries.discoveries_data in the check DB."""
    import psycopg2

    conn = psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "postgres"),
        password=os.getenv("CHECK_DB_PASSWORD", ""),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )

    total = 0
    try:
        with conn.cursor() as cur:
            for csp, entries in entries_by_csp.items():
                by_service: Dict[str, List[Tuple[str, str]]] = {}
                for (svc, did, tmpl) in entries:
                    by_service.setdefault(svc, []).append((did, tmpl))

                for service, pairs in by_service.items():
                    cur.execute(
                        "SELECT id, discoveries_data FROM rule_discoveries "
                        "WHERE service = %s AND provider = %s LIMIT 1",
                        (service, csp),
                    )
                    row = cur.fetchone()
                    if not row:
                        continue

                    row_id, data = row
                    ops = (data or {}).get("discovery", [])
                    did_to_tmpl = {did: tmpl for (did, tmpl) in pairs if tmpl}

                    changed = False
                    for op in ops:
                        did = op.get("discovery_id", "")
                        if did in did_to_tmpl and not op.get("uid_template"):
                            op["uid_template"] = did_to_tmpl[did]
                            op["uid_source"] = "template"
                            changed = True

                    if changed:
                        data["discovery"] = ops
                        cur.execute(
                            "UPDATE rule_discoveries SET discoveries_data = %s WHERE id = %s",
                            (json.dumps(data), row_id),
                        )
                        total += 1

        conn.commit()
        print(f"Updated {total} rule_discoveries rows with uid_template")
    finally:
        conn.close()


def print_coverage_report(entries_by_csp: Dict[str, List[Tuple[str, str, str]]]) -> None:
    for csp in sorted(entries_by_csp):
        entries = entries_by_csp[csp]
        with_tmpl  = [(s, d, t) for s, d, t in entries if t]
        no_tmpl    = [(s, d, t) for s, d, t in entries if not t]
        pct = 100 * len(with_tmpl) // len(entries) if entries else 0
        print(f"\n  [{csp}] {len(with_tmpl)}/{len(entries)} ({pct}%) have uid_template")
        if no_tmpl:
            print(f"    Still heuristic ({len(no_tmpl)}):")
            for (s, d, _) in no_tmpl[:10]:
                print(f"      {d}")
            if len(no_tmpl) > 10:
                print(f"      ... and {len(no_tmpl)-10} more")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true",
                        help="Write YAML changes and update rule_discoveries DB")
    parser.add_argument("--csp", default=None,
                        help="Limit to one CSP (e.g. --csp aws)")
    args = parser.parse_args()

    dry_run = not args.apply
    print(f"=== DI UID Template Seeder [{'DRY-RUN' if dry_run else 'APPLY'}] ===")

    entries_by_csp = load_all_csp_yamls(dry_run=dry_run)

    if args.csp:
        entries_by_csp = {k: v for k, v in entries_by_csp.items() if k == args.csp}

    print_coverage_report(entries_by_csp)

    total_with = sum(1 for e in entries_by_csp.values() for (_, _, t) in e if t)
    total_all  = sum(len(e) for e in entries_by_csp.values())
    print(f"\nGrand total: {total_with}/{total_all} root ops have uid_template "
          f"({100*total_with//total_all if total_all else 0}%)")

    if args.apply:
        print("\nUpdating rule_discoveries DB...")
        update_rule_discoveries(entries_by_csp)
        print("Done.")
    else:
        print("\nRun with --apply to write YAMLs and update DB.")


if __name__ == "__main__":
    main()
