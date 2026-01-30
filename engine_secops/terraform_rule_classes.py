import json

class TerraformRule:
    def __init__(self, rule_id, title, description, severity):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
    # print(f"Loaded rule: {self.rule_id}")  # Debugging

    def check(self, ast, filename):
        """Override this method in subclasses to implement rule logic."""
        # Default: do nothing, return no findings
        return []




class track_uses_of_todo_tags(TerraformRule):
    rule_id = "track_uses_of_todo_tags"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="track_uses_of_todo_tags",
            title='Track uses of "TODO" tags',
            description='Track uses of "TODO" tags',
            severity="Info"
        )

    def check(self, ast_tree, filename):
        findings = []
        # Example: Flag any resource with a 'TODO' in its name (dummy logic)
        for resource in ast_tree.get("resource", []):
            for res_type, res_dict in resource.items():
                for res_name in res_dict:
                    if "TODO" in res_name.upper():
                        findings.append({
                            "ruleId": self.rule_id,
                            "message": self.title,
                            "severity": self.severity,
                            "file": filename
                        })
        return findings



class terraform_parsing_failure(TerraformRule):
    rule_id = "terraform_parsing_failure"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="terraform_parsing_failure",
            title="Terraform parsing failure",
            description="Terraform parsing failure",
            severity="Major"
        )

    def check(self, ast_tree, filename):
        findings = []
        # Example: Flag if parsing failed (dummy logic)
         # Real logic would require error handling in the parser
        return findings



class weak_ssltls_protocols_should_not_be_used(TerraformRule):
    rule_id = "weak_ssltls_protocols_should_not_be_used"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="weak_ssltls_protocols_should_not_be_used",
            title="Weak SSL/TLS protocols should not be used",
            description="Weak SSL/TLS protocols should not be used",
            severity="Critical"
        )

    def check(self, ast_tree, filename):
        findings = []
        # Example: Flag any resource with 'ssl' or 'tls' in its name (dummy logic)
        for resource in ast_tree.get("resource", []):
            for res_type, res_dict in resource.items():
                if "ssl" in res_type.lower() or "tls" in res_type.lower():
                    findings.append({
                        "ruleId": self.rule_id,
                        "message": self.title,
                        "severity": self.severity,
                        "file": filename
                    })
        return findings


class using_clear_text_protocols_is_security_sensitive(TerraformRule):
    rule_id = "using_clear_text_protocols_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_clear_text_protocols_is_security_sensitive",
            title="Using clear-text protocols is security-sensitive",
            description="Using clear-text protocols is security-sensitive",
            severity="Critical"
        )

    def check(self, ast_tree, filename):
        findings = []
        # Example: Flag any resource with 'http' in its name (dummy logic)
        for resource in ast_tree.get("resource", []):
            for res_type, res_dict in resource.items():
                if "http" in res_type.lower():
                    findings.append({
                        "ruleId": self.rule_id,
                        "message": self.title,
                        "severity": self.severity,
                        "file": filename
                    })
        return findings


class disabling_server_side_encryption_of_s3_buckets_is_security_sensitive(TerraformRule):
    rule_id = "disabling_server_side_encryption_of_s3_buckets_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="disabling_server_side_encryption_of_s3_buckets_is_security_sensitive",
            title="Disabling server-side encryption of S3 buckets is security-sensitive",
            description="Disabling server-side encryption of S3 buckets is security-sensitive",
            severity="Minor"
        )

    def check(self, ast_tree, filename):
        findings = []
        # Example: Flag S3 buckets with 'encryption' set to false (dummy logic)
        for resource in ast_tree.get("resource", []):
            if "aws_s3_bucket" in resource:
                bucket = resource["aws_s3_bucket"]
                for _, config in bucket.items():
                    encryption = config.get("server_side_encryption_configuration", [])
                    if encryption and encryption[0].get("rule", {}).get("apply_server_side_encryption_by_default", {}).get("sse_algorithm") == "NONE":
                        findings.append({
                            "ruleId": self.rule_id,
                            "message": self.title,
                            "severity": self.severity,
                            "file": filename
                        })
        return findings


class authorizing_http_communications_with_s3_buckets_is_security_sensitive(TerraformRule):
    rule_id = "authorizing_http_communications_with_s3_buckets_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="authorizing_http_communications_with_s3_buckets_is_security_sensitive",
            title="Authorizing HTTP communications with S3 buckets is security-sensitive",
            description="Authorizing HTTP communications with S3 buckets is security-sensitive",
            severity="Critical"
        )

    def check(self, ast_tree, filename):
        findings = []
        # Example: Flag S3 buckets with 'http' in bucket policy (dummy logic)
        for resource in ast_tree.get("resource", []):
            if "aws_s3_bucket_policy" in resource:
                policy = resource["aws_s3_bucket_policy"]
                for _, config in policy.items():
                    if "http" in json.dumps(config).lower():
                        findings.append({
                            "ruleId": self.rule_id,
                            "message": self.title,
                            "severity": self.severity,
                            "file": filename
                        })
        return findings


class disabling_versioning_of_s3_buckets_is_security_sensitive(TerraformRule):
    rule_id = "disabling_versioning_of_s3_buckets_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="disabling_versioning_of_s3_buckets_is_security_sensitive",
            title="Disabling versioning of S3 buckets is security-sensitive",
            description="Disabling versioning of S3 buckets is security-sensitive",
            severity="Minor"
        )

    def check(self, ast_tree, filename):
        findings = []
        # Example: Flag S3 buckets with versioning disabled (dummy logic)
        for resource in ast_tree.get("resource", []):
            if "aws_s3_bucket" in resource:
                bucket = resource["aws_s3_bucket"]
                for _, config in bucket.items():
                    versioning = config.get("versioning", [])
                    if versioning and not versioning[0].get("enabled", True):
                        findings.append({
                            "ruleId": self.rule_id,
                            "message": self.title,
                            "severity": self.severity,
                            "file": filename
                        })
        return findings


class disabling_s3_bucket_mfa_delete_is_security_sensitive(TerraformRule):
    rule_id = "disabling_s3_bucket_mfa_delete_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="disabling_s3_bucket_mfa_delete_is_security_sensitive",
            title="Disabling S3 bucket MFA delete is security-sensitive",
            description="Disabling S3 bucket MFA delete is security-sensitive",
            severity="Minor"
        )
    def check(self, ast, filename):
        findings = []
        for resource in ast.get("resource", []):
            if "aws_s3_bucket" in resource:
                bucket = resource["aws_s3_bucket"]
                for _, config in bucket.items():
                    versioning = config.get("versioning", [])
                    if versioning and versioning[0].get("mfa_delete") == False:
                        findings.append({
                            "ruleId": self.rule_id,
                            "message": self.title,
                            "severity": self.severity,
                            "file": filename
                        })
        return findings


class disabling_logging_is_security_sensitive(TerraformRule):
    rule_id = "disabling_logging_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="disabling_logging_is_security_sensitive",
            title="Disabling logging is security-sensitive",
            description="Disabling logging is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        findings = []
        for resource in ast.get("resource", []):
            if "aws_s3_bucket" in resource:
                bucket = resource["aws_s3_bucket"]
                for name, config in bucket.items():
                    logging_block = config.get("logging", [])
                    if not logging_block or not logging_block[0].get("target_bucket"):
                        findings.append({
                            "ruleId": self.rule_id,
                            "message": f"{self.title}: {name} has logging disabled or not configured.",
                            "severity": self.severity,
                            "file": filename
                        })
        return findings


class granting_access_to_s3_buckets_to_all_or_authenticated_users_is_security_sensitive(TerraformRule):
    rule_id = "granting_access_to_s3_buckets_to_all_or_authenticated_users_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="granting_access_to_s3_buckets_to_all_or_authenticated_users_is_security_sensitive",
            title="Granting access to S3 buckets to all or authenticated users is security-sensitive",
            description="Granting access to S3 buckets to all or authenticated users is security-sensitive",
            severity="Blocker"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class policies_authorizing_public_access_to_resources_are_security_sensitive(TerraformRule):
    rule_id = "policies_authorizing_public_access_to_resources_are_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="policies_authorizing_public_access_to_resources_are_security_sensitive",
            title="Policies authorizing public access to resources are security-sensitive",
            description="Policies authorizing public access to resources are security-sensitive",
            severity="Blocker"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class aws_tag_keys_should_comply_with_a_naming_convention(TerraformRule):
    rule_id = "aws_tag_keys_should_comply_with_a_naming_convention"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="aws_tag_keys_should_comply_with_a_naming_convention",
            title="AWS tag keys should comply with a naming convention",
            description="AWS tag keys should comply with a naming convention",
            severity="Minor"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_ebs_volumes_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_ebs_volumes_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_ebs_volumes_is_security_sensitive",
            title="Using unencrypted EBS volumes is security-sensitive",
            description="Using unencrypted EBS volumes is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class allowing_public_acls_or_policies_on_a_s3_bucket_is_security_sensitive(TerraformRule):
    rule_id = "allowing_public_acls_or_policies_on_a_s3_bucket_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="allowing_public_acls_or_policies_on_a_s3_bucket_is_security_sensitive",
            title="Allowing public ACLs or policies on a S3 bucket is security-sensitive",
            description="Allowing public ACLs or policies on a S3 bucket is security-sensitive",
            severity="Critical"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class policies_granting_all_privileges_are_security_sensitive(TerraformRule):
    rule_id = "policies_granting_all_privileges_are_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="policies_granting_all_privileges_are_security_sensitive",
            title="Policies granting all privileges are security-sensitive",
            description="Policies granting all privileges are security-sensitive",
            severity="Blocker"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_rds_db_resources_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_rds_db_resources_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_rds_db_resources_is_security_sensitive",
            title="Using unencrypted RDS DB resources is security-sensitive",
            description="Using unencrypted RDS DB resources is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class policies_granting_access_to_all_resources_of_an_account_are_security_sensitive(TerraformRule):
    rule_id = "policies_granting_access_to_all_resources_of_an_account_are_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="policies_granting_access_to_all_resources_of_an_account_are_security_sensitive",
            title="Policies granting access to all resources of an account are security-sensitive",
            description="Policies granting access to all resources of an account are security-sensitive",
            severity="Blocker"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_elasticsearch_domains_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_elasticsearch_domains_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_elasticsearch_domains_is_security_sensitive",
            title="Using unencrypted Elasticsearch domains is security-sensitive",
            description="Using unencrypted Elasticsearch domains is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class aws_iam_policies_should_limit_the_scope_of_permissions_given(TerraformRule):
    rule_id = "aws_iam_policies_should_limit_the_scope_of_permissions_given"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="aws_iam_policies_should_limit_the_scope_of_permissions_given",
            title="AWS IAM policies should limit the scope of permissions given",
            description="AWS IAM policies should limit the scope of permissions given",
            severity="Critical"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_sagemaker_notebook_instances_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_sagemaker_notebook_instances_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_sagemaker_notebook_instances_is_security_sensitive",
            title="Using unencrypted SageMaker notebook instances is security-sensitive",
            description="Using unencrypted SageMaker notebook instances is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class administration_services_access_should_be_restricted_to_specific_ip_addresses(TerraformRule):
    rule_id = "administration_services_access_should_be_restricted_to_specific_ip_addresses"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="administration_services_access_should_be_restricted_to_specific_ip_addresses",
            title="Administration services access should be restricted to specific IP addresses",
            description="Administration services access should be restricted to specific IP addresses",
            severity="Minor"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_sns_topics_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_sns_topics_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_sns_topics_is_security_sensitive",
            title="Using unencrypted SNS topics is security-sensitive",
            description="Using unencrypted SNS topics is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class allowing_public_network_access_to_cloud_resources_is_security_sensitive(TerraformRule):
    rule_id = "allowing_public_network_access_to_cloud_resources_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="allowing_public_network_access_to_cloud_resources_is_security_sensitive",
            title="Allowing public network access to cloud resources is security-sensitive",
            description="Allowing public network access to cloud resources is security-sensitive",
            severity="Blocker"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_sqs_queues_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_sqs_queues_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_sqs_queues_is_security_sensitive",
            title="Using unencrypted SQS queues is security-sensitive",
            description="Using unencrypted SQS queues is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_efs_file_systems_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_efs_file_systems_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_efs_file_systems_is_security_sensitive",
            title="Using unencrypted EFS file systems is security-sensitive",
            description="Using unencrypted EFS file systems is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class creating_public_apis_is_security_sensitive(TerraformRule):
    rule_id = "creating_public_apis_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="creating_public_apis_is_security_sensitive",
            title="Creating public APIs is security-sensitive",
            description="Creating public APIs is security-sensitive",
            severity="Blocker"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class defining_a_short_backup_retention_duration_is_security_sensitive(TerraformRule):
    rule_id = "defining_a_short_backup_retention_duration_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="defining_a_short_backup_retention_duration_is_security_sensitive",
            title="Defining a short backup retention duration is security-sensitive",
            description="Defining a short backup retention duration is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class assigning_high_privileges_azure_active_directory_built_in_roles_is_security_sensitive(TerraformRule):
    rule_id = "assigning_high_privileges_azure_active_directory_built_in_roles_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="assigning_high_privileges_azure_active_directory_built_in_roles_is_security_sensitive",
            title="Assigning high privileges Azure Active Directory built-in roles is security-sensitive",
            description="Assigning high privileges Azure Active Directory built-in roles is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class disabling_managed_identities_for_azure_resources_is_security_sensitive(TerraformRule):
    rule_id = "disabling_managed_identities_for_azure_resources_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="disabling_managed_identities_for_azure_resources_is_security_sensitive",
            title="Disabling Managed Identities for Azure resources is security-sensitive",
            description="Disabling Managed Identities for Azure resources is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class enabling_azure_resource_specific_admin_accounts_is_security_sensitive(TerraformRule):
    rule_id = "enabling_azure_resource_specific_admin_accounts_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="enabling_azure_resource_specific_admin_accounts_is_security_sensitive",
            title="Enabling Azure resource-specific admin accounts is security-sensitive",
            description="Enabling Azure resource-specific admin accounts is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class authorizing_anonymous_access_to_azure_resources_is_security_sensitive(TerraformRule):
    rule_id = "authorizing_anonymous_access_to_azure_resources_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="authorizing_anonymous_access_to_azure_resources_is_security_sensitive",
            title="Authorizing anonymous access to Azure resources is security-sensitive",
            description="Authorizing anonymous access to Azure resources is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class assigning_high_privileges_azure_resource_manager_built_in_roles_is_security_sensitive(TerraformRule):
    rule_id = "assigning_high_privileges_azure_resource_manager_built_in_roles_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="assigning_high_privileges_azure_resource_manager_built_in_roles_is_security_sensitive",
            title="Assigning high privileges Azure Resource Manager built-in roles is security-sensitive",
            description="Assigning high privileges Azure Resource Manager built-in roles is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class disabling_certificate_based_authentication_is_security_sensitive(TerraformRule):
    rule_id = "disabling_certificate_based_authentication_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="disabling_certificate_based_authentication_is_security_sensitive",
            title="Disabling certificate-based authentication is security-sensitive",
            description="Disabling certificate-based authentication is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class disabling_role_based_access_control_on_azure_resources_is_security_sensitive(TerraformRule):
    rule_id = "disabling_role_based_access_control_on_azure_resources_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="disabling_role_based_access_control_on_azure_resources_is_security_sensitive",
            title="Disabling Role-Based Access Control on Azure resources is security-sensitive",
            description="Disabling Role-Based Access Control on Azure resources is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class azure_custom_roles_should_not_grant_subscription_owner_capabilities(TerraformRule):
    rule_id = "azure_custom_roles_should_not_grant_subscription_owner_capabilities"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="azure_custom_roles_should_not_grant_subscription_owner_capabilities",
            title="Azure custom roles should not grant subscription Owner capabilities",
            description="Azure custom roles should not grant subscription Owner capabilities",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class azure_role_assignments_that_grant_access_to_all_resources_of_a_subscription_are_security_sensitive(TerraformRule):
    rule_id = "azure_role_assignments_that_grant_access_to_all_resources_of_a_subscription_are_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="azure_role_assignments_that_grant_access_to_all_resources_of_a_subscription_are_security_sensitive",
            title="Azure role assignments that grant access to all resources of a subscription are security-sensitive",
            description="Azure role assignments that grant access to all resources of a subscription are security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class using_unencrypted_cloud_storages_is_security_sensitive(TerraformRule):
    rule_id = "using_unencrypted_cloud_storages_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="using_unencrypted_cloud_storages_is_security_sensitive",
            title="Using unencrypted cloud storages is security-sensitive",
            description="Using unencrypted cloud storages is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class granting_highly_privileged_gcp_resource_rights_is_security_sensitive(TerraformRule):
    rule_id = "granting_highly_privileged_gcp_resource_rights_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="granting_highly_privileged_gcp_resource_rights_is_security_sensitive",
            title="Granting highly privileged GCP resource rights is security-sensitive",
            description="Granting highly privileged GCP resource rights is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class creating_keys_without_a_rotation_period_is_security_sensitive(TerraformRule):
    rule_id = "creating_keys_without_a_rotation_period_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="creating_keys_without_a_rotation_period_is_security_sensitive",
            title="Creating keys without a rotation period is security-sensitive",
            description="Creating keys without a rotation period is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class creating_dns_zones_without_dnssec_enabled_is_security_sensitive(TerraformRule):
    rule_id = "creating_dns_zones_without_dnssec_enabled_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="creating_dns_zones_without_dnssec_enabled_is_security_sensitive",
            title="Creating DNS zones without DNSSEC enabled is security-sensitive",
            description="Creating DNS zones without DNSSEC enabled is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class creating_gcp_sql_instances_without_requiring_tls_is_security_sensitive(TerraformRule):
    rule_id = "creating_gcp_sql_instances_without_requiring_tls_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="creating_gcp_sql_instances_without_requiring_tls_is_security_sensitive",
            title="Creating GCP SQL instances without requiring TLS is security-sensitive",
            description="Creating GCP SQL instances without requiring TLS is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class granting_public_access_to_gcp_resources_is_security_sensitive(TerraformRule):
    rule_id = "granting_public_access_to_gcp_resources_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="granting_public_access_to_gcp_resources_is_security_sensitive",
            title="Granting public access to GCP resources is security-sensitive",
            description="Granting public access to GCP resources is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class enabling_project_wide_ssh_keys_to_access_vm_instances_is_security_sensitive(TerraformRule):
    rule_id = "enabling_project_wide_ssh_keys_to_access_vm_instances_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="enabling_project_wide_ssh_keys_to_access_vm_instances_is_security_sensitive",
            title="Enabling project-wide SSH keys to access VM instances is security-sensitive",
            description="Enabling project-wide SSH keys to access VM instances is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class excessive_granting_of_gcp_iam_permissions_is_security_sensitive(TerraformRule):
    rule_id = "excessive_granting_of_gcp_iam_permissions_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="excessive_granting_of_gcp_iam_permissions_is_security_sensitive",
            title="Excessive granting of GCP IAM permissions is security-sensitive",
            description="Excessive granting of GCP IAM permissions is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class creating_app_engine_handlers_without_requiring_tls_is_security_sensitive(TerraformRule):
    rule_id = "creating_app_engine_handlers_without_requiring_tls_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="creating_app_engine_handlers_without_requiring_tls_is_security_sensitive",
            title="Creating App Engine handlers without requiring TLS is security-sensitive",
            description="Creating App Engine handlers without requiring TLS is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class creating_custom_roles_allowing_privilege_escalation_is_security_sensitive(TerraformRule):
    rule_id = "creating_custom_roles_allowing_privilege_escalation_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="creating_custom_roles_allowing_privilege_escalation_is_security_sensitive",
            title="Creating custom roles allowing privilege escalation is security-sensitive",
            description="Creating custom roles allowing privilege escalation is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class enabling_attribute_based_access_control_for_kubernetes_is_security_sensitive(TerraformRule):
    rule_id = "enabling_attribute_based_access_control_for_kubernetes_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="enabling_attribute_based_access_control_for_kubernetes_is_security_sensitive",
            title="Enabling Attribute-Based Access Control for Kubernetes is security-sensitive",
            description="Enabling Attribute-Based Access Control for Kubernetes is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class google_cloud_load_balancers_ssl_policies_should_not_offer_weak_cipher_suites(TerraformRule):
    rule_id = "google_cloud_load_balancers_ssl_policies_should_not_offer_weak_cipher_suites"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="google_cloud_load_balancers_ssl_policies_should_not_offer_weak_cipher_suites",
            title="Google Cloud load balancers SSL policies should not offer weak cipher suites",
            description="Google Cloud load balancers SSL policies should not offer weak cipher suites",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class unversioned_google_cloud_storage_buckets_are_security_sensitive(TerraformRule):
    rule_id = "unversioned_google_cloud_storage_buckets_are_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="unversioned_google_cloud_storage_buckets_are_security_sensitive",
            title="Unversioned Google Cloud Storage buckets are security-sensitive",
            description="Unversioned Google Cloud Storage buckets are security-sensitive",
            severity="Minor"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class defining_a_short_log_retention_duration_is_security_sensitive(TerraformRule):
    rule_id = "defining_a_short_log_retention_duration_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="defining_a_short_log_retention_duration_is_security_sensitive",
            title="Defining a short log retention duration is security-sensitive",
            description="Defining a short log retention duration is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class excluding_users_or_groups_activities_from_audit_logs_is_security_sensitive(TerraformRule):
    rule_id = "excluding_users_or_groups_activities_from_audit_logs_is_security_sensitive"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="excluding_users_or_groups_activities_from_audit_logs_is_security_sensitive",
            title="Excluding users or groups activities from audit logs is security-sensitive",
            description="Excluding users or groups activities from audit logs is security-sensitive",
            severity="Major"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []


class aws_resource_tags_should_have_valid_format(TerraformRule):
    rule_id = "aws_resource_tags_should_have_valid_format"
    def __init__(self, *args, **kwargs):
        super().__init__(
            rule_id="aws_resource_tags_should_have_valid_format",
            title="AWS resource tags should have valid format",
            description="AWS resource tags should have valid format",
            severity="Minor"
        )
    def check(self, ast, filename):
        # TODO: Implement rule logic
        return []
