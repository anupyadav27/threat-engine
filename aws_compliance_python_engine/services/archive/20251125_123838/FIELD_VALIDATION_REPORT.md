# Rule Field Validation Report

## Summary

- **Total Services**: 102
- **Total Checks**: 1932
- **Total Issues**: 1346
- **Clean Services**: 6 (5.9%)
- **Issues Rate**: 69.7% of checks

## Services with Issues

### ec2

- Checks: 175
- Issues: 115
- Issue rate: 65.7%

**Issue**: missing_fields
- Rule: `aws.ec2.group.cifs_access_restriction_tcp_port_445_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.ec2.resource.ebs_encryption_by_default_enabled`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.ec2.security_group.default_deny_between_network_tiers_enforced`
- Missing fields: in_vpc

... and 112 more issues

### iam

- Checks: 105
- Issues: 105
- Issue rate: 100.0%

**Issue**: missing_fields
- Rule: `aws.iam.password.policy_lowercase_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.iam.instanceprofile.no_instance_profile_with_admin_star_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.iam.policy.security_check_full_admin_privileges_configured`
- Missing fields: is_public

... and 102 more issues

### cloudwatch

- Checks: 86
- Issues: 85
- Issue rate: 98.8%

**Issue**: missing_fields
- Rule: `aws.cloudwatch.log_metric_filter_sign_in_without_mfa.log_metric_filter_sign_in_without_mfa_configured`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.cloudwatch.group.cloudwatch_log_edr_log_delivery_configured`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.cloudwatch.metricfilter.metric_log_console_root_login_detected_filter_present`
- Missing fields: logging_enabled

... and 82 more issues

### glue

- Checks: 97
- Issues: 84
- Issue rate: 86.6%

**Issue**: missing_fields
- Rule: `aws.glue.registry.metadata_encryption_enabled`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.glue.table.access_logging_enabled`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.glue.devendpoint.no_public_access_configured`
- Missing fields: is_public

... and 81 more issues

### sagemaker

- Checks: 83
- Issues: 73
- Issue rate: 88.0%

**Issue**: missing_fields
- Rule: `aws.sagemaker.flowdefinition.workteam_access_rbac_least_privilege`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.sagemaker.volume.and_output_encryption_enabled`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.sagemaker.modelpackage.encryption_at_rest_enabled`
- Missing fields: encryption_enabled

... and 70 more issues

### backup

- Checks: 66
- Issues: 61
- Issue rate: 92.4%

**Issue**: missing_fields
- Rule: `aws.backup.reportplan.backup_plans_configured`
- Missing fields: versioning_enabled

**Issue**: missing_fields
- Rule: `aws.backup.backupplan.failed_jobs_alerting_enabled`
- Missing fields: versioning_enabled

**Issue**: missing_fields
- Rule: `aws.backup.restorejob.role_least_privilege`
- Missing fields: is_public

... and 58 more issues

### vpc

- Checks: 53
- Issues: 53
- Issue rate: 100.0%

**Issue**: missing_fields
- Rule: `aws.vpc.subnet.dns_hostnames_and_support_configured`
- Missing fields: in_vpc

**Issue**: missing_fields
- Rule: `aws.vpc.customergateway.flow_logging_enabled`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.vpc.internetgateway.flow_logging_enabled`
- Missing fields: logging_enabled

... and 50 more issues

### rds

- Checks: 62
- Issues: 48
- Issue rate: 77.4%

**Issue**: missing_fields
- Rule: `aws.rds.securitygroup.security_egress_restricted`
- Missing fields: compliant

**Issue**: missing_fields
- Rule: `aws.rds.instance.storage_encrypted`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.rds.instance.public_access_disabled`
- Missing fields: is_public

... and 45 more issues

### cloudtrail

- Checks: 42
- Issues: 41
- Issue rate: 97.6%

**Issue**: missing_fields
- Rule: `aws.cloudtrail.trail.alerts_for_anomalies_configured`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.cloudtrail.nacl_event_selectors_monitoring.nacl_event_selectors_monitoring_configured`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.cloudtrail.group.trail_cloudtrail_configuration_changes_monitored`
- Missing fields: logging_enabled

... and 38 more issues

### redshift

- Checks: 51
- Issues: 37
- Issue rate: 72.5%

**Issue**: missing_fields
- Rule: `aws.redshift.securitygroup.security_only_required_ports_open_restricted`
- Missing fields: compliant

**Issue**: missing_fields
- Rule: `aws.redshift.parametergroup.audit_logging_enabled`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.redshift.cluster.admin_access_least_privilege`
- Missing fields: is_public

... and 34 more issues

### stepfunctions

- Checks: 37
- Issues: 29
- Issue rate: 78.4%

**Issue**: missing_fields
- Rule: `aws.stepfunctions.statemachine.stepfunctions_allowlist_defined_when_applicable_configured`
- Missing fields: compliant

**Issue**: missing_fields
- Rule: `aws.stepfunctions.statemachine.stepfunctions_max_length_defined_if_applicable_configured`
- Missing fields: compliant

**Issue**: missing_fields
- Rule: `aws.stepfunctions.statemachine.stepfunctions_min_length_defined_when_applicable_configured`
- Missing fields: compliant

... and 26 more issues

### s3

- Checks: 64
- Issues: 27
- Issue rate: 42.2%

**Issue**: missing_fields
- Rule: `aws.s3.bucket.destination_private_only_configured`
- Missing fields: compliant

**Issue**: missing_fields
- Rule: `aws.s3.bucket.encryption_in_transit_tls_min_1_2_configured`
- Missing fields: has_tls_requirement

**Issue**: missing_fields
- Rule: `aws.s3.bucket.key_policy_least_privilege`
- Missing fields: has_least_privilege

... and 24 more issues

### lambda

- Checks: 36
- Issues: 25
- Issue rate: 69.4%

**Issue**: missing_fields
- Rule: `aws.lambda.function.vpc_private_networking_enabled`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.lambda.function.restrict_public_access_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.lambda.function.execution_roles_least_privilege`
- Missing fields: is_public

... and 22 more issues

### eks

- Checks: 78
- Issues: 24
- Issue rate: 30.8%

**Issue**: missing_fields
- Rule: `aws.eks.cluster.encryption_at_rest_enabled`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.eks.nodegroup.nodes_no_public_ip_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.eks.resource.control_plane_logging_all_types_enabled`
- Missing fields: logging_enabled

... and 21 more issues

### kms

- Checks: 24
- Issues: 24
- Issue rate: 100.0%

**Issue**: missing_fields
- Rule: `aws.kms.alias.points_to_active_key_configured`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.kms.alias.logging_enabled`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.kms.key.state_change_monitoring_enabled`
- Missing fields: encryption_enabled

... and 21 more issues

### cloudfront

- Checks: 26
- Issues: 22
- Issue rate: 84.6%

**Issue**: missing_fields
- Rule: `aws.cloudfront.resource.distributions_logging_enabled`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.cloudfront.origin_request_policy.cloudfront_forward_querystrings_minimal_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.cloudfront.cachepolicy.cache_allowlists_minimal_query_headers_cookies_configured`
- Missing fields: is_public

... and 19 more issues

### docdb

- Checks: 25
- Issues: 22
- Issue rate: 88.0%

**Issue**: missing_fields
- Rule: `aws.docdb.cluster.monitoring_and_alerting_configured`
- Missing fields: monitoring_enabled

**Issue**: missing_fields
- Rule: `aws.docdb.cluster.iam_or_managed_identity_auth_enabled_if_supported`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.docdb.instance.require_tls_in_transit_configured`
- Missing fields: in_vpc

... and 19 more issues

### neptune

- Checks: 24
- Issues: 20
- Issue rate: 83.3%

**Issue**: missing_fields
- Rule: `aws.neptune.cluster.iam_or_managed_identity_auth_enabled_if_supported`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.neptune.cluster.public_access_disabled`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.neptune.instance.require_tls_in_transit_configured`
- Missing fields: in_vpc

... and 17 more issues

### apigateway

- Checks: 49
- Issues: 18
- Issue rate: 36.7%

**Issue**: missing_fields
- Rule: `aws.apigateway.apikey.key_rotation_policy_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.apigateway.stage.logging_enabled`
- Missing fields: logging_enabled

**Issue**: missing_fields
- Rule: `aws.apigateway.resource.restapi_cache_encrypted`
- Missing fields: encryption_enabled

... and 15 more issues

### sns

- Checks: 24
- Issues: 16
- Issue rate: 66.7%

**Issue**: missing_fields
- Rule: `aws.sns.resource.topics_kms_encryption_at_rest_enabled`
- Missing fields: encryption_enabled

**Issue**: missing_fields
- Rule: `aws.sns.topics_not_publicly_accessible.topics_not_publicly_accessible_configured`
- Missing fields: is_public

**Issue**: missing_fields
- Rule: `aws.sns.topic.no_public_webhooks_without_auth_configured`
- Missing fields: is_public

... and 13 more issues

## Recommendations

1. **Fix Missing Fields**: Update discovery steps to emit required fields
2. **Validate API Calls**: Ensure AWS Boto3 methods match actual service APIs
3. **Test with AWS**: Run checks against real AWS accounts to validate
4. **Refine Conditions**: Update check conditions to use available fields

