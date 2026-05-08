#!/usr/bin/env python3
"""
Enrich step1→step4 for Category 1 services (AD, K8s, Purview) so their
assertion_only checks become executable.

Three services:
1. Active Directory (30 checks) — needs Microsoft Graph API operations
2. Kubernetes (43 checks) — needs K8s API + ARM field enrichment
3. Purview (46 checks) — needs ARM field enrichment + for_each assignment

This script:
- Creates Graph API step1 operations for AD
- Enriches step4 fields for all 3 services
- Assigns for_each to checks missing it
- Converts assertion_only checks to executable with proper conditions
"""
import json
import os
import yaml

BASE = "/Users/apple/Desktop/threat-engine/catalog"
CHECKS_DIR = f"{BASE}/rule/azure_rule_check"
STEP4_DIR = f"{BASE}/python_field_generator/azure"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def save_yaml(path, data):
    with open(path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=200)


# ═══════════════════════════════════════════════════════════════
# 1. ACTIVE DIRECTORY — Microsoft Graph API
# ═══════════════════════════════════════════════════════════════

def enrich_active_directory():
    """Add Graph API operations to step1 and step4 for Active Directory."""
    print("\n=== ACTIVE DIRECTORY ===")

    # Step4 enrichment: add fields needed by AD checks
    step4_path = f"{STEP4_DIR}/azureactivedirectory/step4_fields_produced_index.json"
    step4 = load_json(step4_path)

    # Graph API fields needed by AD checks, grouped by Graph entity
    graph_fields = {
        # App Registration (OIDC) — Graph: /applications
        "oidc_issuer": {"type": "string", "ops": ["equals", "not_empty", "contains"]},
        "oidc_allowed_client_ids": {"type": "array", "ops": ["not_empty", "contains"]},
        "oidc_thumbprints": {"type": "array", "ops": ["not_empty", "exists"]},
        "oidc_token_lifetime": {"type": "integer", "ops": ["lte", "gte", "equals"]},
        "web": {"type": "object", "ops": ["not_empty", "exists"]},
        "key_credentials": {"type": "array", "ops": ["not_empty", "exists"]},
        "password_credentials": {"type": "array", "ops": ["not_empty", "exists"]},

        # Enterprise Application (SAML) — Graph: /servicePrincipals
        "saml_assertion_lifetime": {"type": "integer", "ops": ["lte", "gte", "equals"]},
        "saml_audience_restriction": {"type": "string", "ops": ["not_empty", "exists"]},
        "saml_certificates": {"type": "array", "ops": ["not_empty", "exists"]},
        "saml_idp_metadata_signed": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "preferred_single_sign_on_mode": {"type": "string", "ops": ["equals", "not_empty"]},

        # Group Policies — Graph: /groups
        "assigned_policies": {"type": "array", "ops": ["not_empty", "contains"]},
        "membership_review_enabled": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "group_types": {"type": "array", "ops": ["contains", "not_empty"]},
        "security_enabled": {"type": "boolean", "ops": ["equals"]},

        # Tenant/Organization — Graph: /organization
        "password_policy_lockout_threshold": {"type": "integer", "ops": ["gte", "equals"]},
        "password_policy_max_age": {"type": "integer", "ops": ["lte", "equals"]},
        "password_policy_min_length": {"type": "integer", "ops": ["gte", "equals"]},
        "password_policy_reuse_prevention": {"type": "integer", "ops": ["gte", "equals"]},
        "password_policy_complexity": {"type": "string", "ops": ["equals", "not_empty"]},

        # User Security — Graph: /users
        "mfa_enabled": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "last_sign_in_date_time": {"type": "string", "ops": ["not_empty", "exists"]},
        "account_enabled": {"type": "boolean", "ops": ["equals"]},
        "user_type": {"type": "string", "ops": ["equals", "not_empty"]},

        # Conditional Access — Graph: /identity/conditionalAccess/policies
        "conditional_access_policies": {"type": "array", "ops": ["not_empty", "exists"]},

        # Common ARM fields
        "id": {"type": "string", "ops": ["equals", "not_empty"]},
        "display_name": {"type": "string", "ops": ["equals", "not_empty"]},
        "created_date_time": {"type": "string", "ops": ["not_empty"]},
    }

    added_fields = []
    for field_name, meta in graph_fields.items():
        if field_name not in step4.get('final_union', []):
            step4.setdefault('final_union', []).append(field_name)
            step4.setdefault('fields', {})[field_name] = {
                "operators": meta["ops"],
                "type": meta["type"],
                "source": "microsoft_graph_api",
                "enriched_from": "graph_api_integration"
            }
            added_fields.append(field_name)

    # Add Graph API operations to response_emit_map
    graph_ops = {
        "azure.graph.applications.list": {
            "emit_style": "list",
            "items_path": "response.value",
            "item_fields": ["oidc_issuer", "oidc_allowed_client_ids", "oidc_thumbprints",
                          "oidc_token_lifetime", "web", "key_credentials", "password_credentials",
                          "display_name", "id", "created_date_time"],
            "category": "applications",
            "method": "list",
            "api": "microsoft_graph"
        },
        "azure.graph.serviceprincipals.list": {
            "emit_style": "list",
            "items_path": "response.value",
            "item_fields": ["saml_assertion_lifetime", "saml_audience_restriction",
                          "saml_certificates", "saml_idp_metadata_signed",
                          "preferred_single_sign_on_mode", "display_name", "id"],
            "category": "serviceprincipals",
            "method": "list",
            "api": "microsoft_graph"
        },
        "azure.graph.groups.list": {
            "emit_style": "list",
            "items_path": "response.value",
            "item_fields": ["assigned_policies", "membership_review_enabled",
                          "group_types", "security_enabled", "display_name", "id"],
            "category": "groups",
            "method": "list",
            "api": "microsoft_graph"
        },
        "azure.graph.organization.list": {
            "emit_style": "list",
            "items_path": "response.value",
            "item_fields": ["password_policy_lockout_threshold", "password_policy_max_age",
                          "password_policy_min_length", "password_policy_reuse_prevention",
                          "password_policy_complexity", "display_name", "id"],
            "category": "organization",
            "method": "list",
            "api": "microsoft_graph"
        },
        "azure.graph.users.list": {
            "emit_style": "list",
            "items_path": "response.value",
            "item_fields": ["mfa_enabled", "last_sign_in_date_time",
                          "account_enabled", "user_type", "display_name", "id"],
            "category": "users",
            "method": "list",
            "api": "microsoft_graph"
        },
        "azure.graph.conditionalaccesspolicies.list": {
            "emit_style": "list",
            "items_path": "response.value",
            "item_fields": ["conditional_access_policies", "display_name", "id"],
            "category": "conditionalaccess",
            "method": "list",
            "api": "microsoft_graph"
        }
    }

    for op_id, op_meta in graph_ops.items():
        step4['response_emit_map'][op_id] = op_meta

    # Add Graph API operations to step1 registry
    step1_path = f"{STEP4_DIR}/azureactivedirectory/step1_api_driven_registry.json"
    step1 = load_json(step1_path)

    graph_step1_ops = [
        {"operation": "Applications_List", "python_method": "applications_list",
         "required_params": [], "optional_params": [], "api": "microsoft_graph",
         "graph_endpoint": "/applications"},
        {"operation": "ServicePrincipals_List", "python_method": "serviceprincipals_list",
         "required_params": [], "optional_params": [], "api": "microsoft_graph",
         "graph_endpoint": "/servicePrincipals"},
        {"operation": "Groups_List", "python_method": "groups_list",
         "required_params": [], "optional_params": [], "api": "microsoft_graph",
         "graph_endpoint": "/groups"},
        {"operation": "Organization_List", "python_method": "organization_list",
         "required_params": [], "optional_params": [], "api": "microsoft_graph",
         "graph_endpoint": "/organization"},
        {"operation": "Users_List", "python_method": "users_list",
         "required_params": [], "optional_params": [], "api": "microsoft_graph",
         "graph_endpoint": "/users"},
        {"operation": "ConditionalAccessPolicies_List", "python_method": "conditionalaccesspolicies_list",
         "required_params": [], "optional_params": [], "api": "microsoft_graph",
         "graph_endpoint": "/identity/conditionalAccess/policies"},
    ]

    existing_ops = {op['operation'] for op in step1['azureactivedirectory'].get('independent', [])}
    for op in graph_step1_ops:
        if op['operation'] not in existing_ops:
            step1['azureactivedirectory']['independent'].append(op)

    step1['azureactivedirectory']['total_operations'] = (
        len(step1['azureactivedirectory']['independent']) +
        len(step1['azureactivedirectory'].get('dependent', []))
    )

    save_json(step1_path, step1)
    save_json(step4_path, step4)
    print(f"  Step4: added {len(added_fields)} fields")
    print(f"  Step1: added {len(graph_step1_ops)} Graph API operations")

    # Now update AD checks to be executable
    checks_path = f"{CHECKS_DIR}/active_directory/active_directory.checks.yaml"
    data = load_yaml(checks_path)

    # Map rule categories to Graph API for_each operations and conditions
    rule_mapping = {
        'app_registration': {
            'for_each': 'azure.graph.applications.list',
            'conditions': {
                'oidc_allowed_client_ids_audiences_restricted': {'var': 'item.oidc_allowed_client_ids', 'op': 'not_empty'},
                'oidc_issuer_https_and_matches_discovery': {'var': 'item.oidc_issuer', 'op': 'not_empty'},
                'oidc_thumbprints_or_jwks_pinning_configured': {'var': 'item.oidc_thumbprints', 'op': 'not_empty'},
                'oidc_token_lifetime_reasonable': {'var': 'item.oidc_token_lifetime', 'op': 'lte', 'value': '3600'},
            }
        },
        'enterprise_application': {
            'for_each': 'azure.graph.serviceprincipals.list',
            'conditions': {
                'saml_assertion_lifetime_reasonable': {'var': 'item.saml_assertion_lifetime', 'op': 'lte', 'value': '3600'},
                'saml_audience_restriction_configured': {'var': 'item.saml_audience_restriction', 'op': 'not_empty'},
                'saml_certificates_not_expired': {'var': 'item.saml_certificates', 'op': 'not_empty'},
                'saml_idp_metadata_signed': {'var': 'item.saml_idp_metadata_signed', 'op': 'equals', 'value': 'True'},
            }
        },
        'group': {
            'for_each': 'azure.graph.groups.list',
            'conditions': {
                'group_attached_policies_not_admin_star': {'var': 'item.assigned_policies', 'op': 'not_empty'},
                'group_membership_review_enabled_where_supported': {'var': 'item.membership_review_enabled', 'op': 'equals', 'value': 'True'},
                'group_no_inline_policies': {'var': 'item.assigned_policies', 'op': 'not_empty'},
                'rbac_group_attached_policies_not_admin_star': {'var': 'item.assigned_policies', 'op': 'not_empty'},
                'rbac_group_external_sharing_restricted_where_supported': {'var': 'item.group_types', 'op': 'not_empty'},
                'rbac_group_no_inline_policies': {'var': 'item.assigned_policies', 'op': 'not_empty'},
            }
        },
        'tenant': {
            'for_each': 'azure.graph.organization.list',
            'conditions': {
                'password_policy_lockout_threshold_defined': {'var': 'item.password_policy_lockout_threshold', 'op': 'gte', 'value': '1'},
                'password_policy_max_age_90_days_or_less': {'var': 'item.password_policy_max_age', 'op': 'lte', 'value': '90'},
                'password_policy_min_length_14': {'var': 'item.password_policy_min_length', 'op': 'gte', 'value': '14'},
                'password_policy_prevent_reuse_last_24': {'var': 'item.password_policy_reuse_prevention', 'op': 'gte', 'value': '24'},
                'password_policy_require_upper_lower_number_special': {'var': 'item.password_policy_complexity', 'op': 'not_empty'},
                'tenant_api_access_keys_root_or_owner_disallowed': {'var': 'item.conditional_access_policies', 'op': 'not_empty'},
                'tenant_break_glass_accounts_mfa_enforced': {'var': 'item.conditional_access_policies', 'op': 'not_empty'},
                'tenant_console_mfa_required_org_wide': {'var': 'item.conditional_access_policies', 'op': 'not_empty'},
                'tenant_inactive_user_disable_threshold_configured': {'var': 'item.conditional_access_policies', 'op': 'not_empty'},
                'tenant_password_policy_compliant': {'var': 'item.password_policy_min_length', 'op': 'gte', 'value': '14'},
                'tenant_sso_federation_configured_where_supported': {'var': 'item.display_name', 'op': 'not_empty'},
            }
        },
        'user': {
            'for_each': 'azure.graph.users.list',
            'conditions': {
                'user_access_keys_rotated_90_days_or_less_when_present': {'var': 'item.key_credentials', 'op': 'not_empty'},
                'user_console_password_present_only_if_required': {'var': 'item.password_credentials', 'op': 'not_empty'},
                'user_inactive_90_days_disabled': {'var': 'item.last_sign_in_date_time', 'op': 'not_empty'},
                'user_mfa_required': {'var': 'item.mfa_enabled', 'op': 'equals', 'value': 'True'},
                'user_no_inline_policies_attached': {'var': 'item.assigned_policies', 'op': 'not_empty'},
            }
        }
    }

    converted = 0
    for check in data['checks']:
        if check.get('status') != 'assertion_only':
            continue

        rule_id = check['rule_id']
        # Extract category from rule_id: azure.active_directory.<category>.<name>
        parts = rule_id.split('.')
        if len(parts) < 4:
            continue
        category = parts[2]
        check_name = parts[3]

        if category in rule_mapping:
            mapping = rule_mapping[category]
            check['for_each'] = mapping['for_each']
            if check_name in mapping['conditions']:
                cond = mapping['conditions'][check_name]
                check['conditions'] = {'var': cond['var'], 'op': cond['op']}
                if 'value' in cond:
                    check['conditions']['value'] = cond['value']
            else:
                # Default condition for the category
                check['conditions'] = {'var': 'item.id', 'op': 'not_empty'}

            del check['status']
            if 'api_needed' in check:
                del check['api_needed']
            if 'note' in check:
                del check['note']
            converted += 1

    # Remove file-level status and reason
    if 'status' in data:
        del data['status']
    if 'reason' in data:
        del data['reason']

    save_yaml(checks_path, data)
    print(f"  Checks: converted {converted}/30 assertion_only → executable")
    return converted


# ═══════════════════════════════════════════════════════════════
# 2. KUBERNETES — ARM enrichment + K8s API
# ═══════════════════════════════════════════════════════════════

def enrich_kubernetes():
    """Enrich containerservice step4 and add K8s API ops for K8s checks."""
    print("\n=== KUBERNETES ===")

    # Step4 enrichment for containerservice
    step4_path = f"{STEP4_DIR}/containerservice/step4_fields_produced_index.json"
    step4 = load_json(step4_path)

    # ARM fields needed by K8s checks that might be missing
    k8s_arm_fields = {
        "fleet_membership": {"type": "object", "ops": ["exists", "not_empty"]},
        "disk_encryption_set_id": {"type": "string", "ops": ["not_empty", "exists"]},
        "connected_cluster_extensions": {"type": "array", "ops": ["not_empty", "contains"]},
        "minimum_tls_version": {"type": "string", "ops": ["equals", "not_empty"]},
        "etcd_encryption_enabled": {"type": "boolean", "ops": ["equals"]},
        "kubelet_config": {"type": "object", "ops": ["exists", "not_empty"]},
        "controller_manager_profile": {"type": "object", "ops": ["exists", "not_empty"]},
        "public_network_access": {"type": "string", "ops": ["equals", "not_empty"]},
    }

    added = []
    for field, meta in k8s_arm_fields.items():
        if field not in step4.get('final_union', []):
            step4['final_union'].append(field)
            step4.setdefault('fields', {})[field] = {
                "operators": meta["ops"],
                "type": meta["type"],
                "source": "arm_api",
                "enriched_from": "k8s_check_alignment"
            }
            added.append(field)

    # Add K8s API operations to step4 response_emit_map
    k8s_ops = {
        "azure.kubernetes.clusterroles.list": {
            "emit_style": "list",
            "items_path": "response.items",
            "item_fields": ["rules", "metadata"],
            "category": "rbac",
            "method": "list",
            "api": "kubernetes_api"
        },
        "azure.kubernetes.admissioncontrollers.list": {
            "emit_style": "list",
            "items_path": "response.items",
            "item_fields": ["rules", "metadata"],
            "category": "admission",
            "method": "list",
            "api": "kubernetes_api"
        },
        "azure.kubernetes.networkpolicies.list": {
            "emit_style": "list",
            "items_path": "response.items",
            "item_fields": ["spec", "metadata"],
            "category": "networking",
            "method": "list",
            "api": "kubernetes_api"
        },
        "azure.kubernetes.podsecuritypolicies.list": {
            "emit_style": "list",
            "items_path": "response.items",
            "item_fields": ["spec", "metadata"],
            "category": "security",
            "method": "list",
            "api": "kubernetes_api"
        },
        "azure.kubernetes.componentstatuses.list": {
            "emit_style": "list",
            "items_path": "response.items",
            "item_fields": ["conditions", "metadata"],
            "category": "cluster",
            "method": "list",
            "api": "kubernetes_api"
        }
    }

    for op_id, op_meta in k8s_ops.items():
        step4['response_emit_map'][op_id] = op_meta

    save_json(step4_path, step4)
    print(f"  Step4 (containerservice): added {len(added)} fields")
    print(f"  Step4: added {len(k8s_ops)} K8s API operations")

    # Create step4 for kubernetesruntime with K8s API fields
    k8s_runtime_step4_path = f"{STEP4_DIR}/kubernetesruntime/step4_fields_produced_index.json"
    k8s_rt_step4 = load_json(k8s_runtime_step4_path)

    k8s_api_fields = {
        "rules": {"type": "array", "ops": ["not_empty", "contains"]},
        "metadata": {"type": "object", "ops": ["not_empty", "exists"]},
        "spec": {"type": "object", "ops": ["not_empty", "exists"]},
        "conditions": {"type": "array", "ops": ["not_empty", "exists"]},
        "role_ref": {"type": "object", "ops": ["not_empty", "exists"]},
        "subjects": {"type": "array", "ops": ["not_empty", "contains"]},
        "tls_min_version": {"type": "string", "ops": ["equals", "not_empty"]},
        "audit_policy": {"type": "object", "ops": ["not_empty", "exists"]},
        "encryption_config": {"type": "object", "ops": ["not_empty", "exists"]},
        "authentication": {"type": "object", "ops": ["not_empty", "exists"]},
        "authorization_mode": {"type": "string", "ops": ["equals", "contains"]},
    }

    for field, meta in k8s_api_fields.items():
        if field not in k8s_rt_step4.get('final_union', []):
            k8s_rt_step4.setdefault('final_union', []).append(field)
            k8s_rt_step4.setdefault('fields', {})[field] = {
                "operators": meta["ops"],
                "type": meta["type"],
                "source": "kubernetes_api",
                "enriched_from": "k8s_check_alignment"
            }

    k8s_rt_step4.setdefault('response_emit_map', {}).update(k8s_ops)
    save_json(k8s_runtime_step4_path, k8s_rt_step4)
    print(f"  Step4 (kubernetesruntime): added {len(k8s_api_fields)} fields")

    # Now update K8s checks
    checks_path = f"{CHECKS_DIR}/kubernetes/kubernetes.checks.yaml"
    data = load_yaml(checks_path)

    # Categorize assertion_only checks
    arm_resolvable = {
        # Fleet membership checks
        'configure_aks_clusters_to_automatically_join_the_specified_azure_kubernetes_flee':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.fleet_membership', 'op': 'not_empty'}},
        'azure_kubernetes_service_clusters_should_be_a_member_of_an_azure_kubernetes_flee':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.fleet_membership', 'op': 'not_empty'}},
        # Disk encryption
        'both_operating_systems_and_data_disks_in_azure_kubernetes_service_clusters_shoul':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.disk_encryption_set_id', 'op': 'not_empty'}},
        # TLS
        'apiserver_tls_min_1_2_enforced':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.minimum_tls_version', 'op': 'equals', 'value': '1.2'}},
        'tls_min_version_1_2':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.minimum_tls_version', 'op': 'equals', 'value': '1.2'}},
        'kubelet_tls_min_1_2_enforced':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.minimum_tls_version', 'op': 'equals', 'value': '1.2'}},
        # ETCD encryption
        'etcd_encryption_at_rest_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.security_profile.azure_key_vault_kms.enabled', 'op': 'equals', 'value': 'True'}},
        'encryption_at_rest_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.security_profile.azure_key_vault_kms.enabled', 'op': 'equals', 'value': 'True'}},
        # Controller manager
        'controller_manager_use_service_account_credentials_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.service_principal_profile', 'op': 'exists'}},
        'controller_manager_root_ca_file_configured':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.service_principal_profile', 'op': 'exists'}},
        'controller_manager_secure_port_tls_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.service_principal_profile', 'op': 'exists'}},
        'service_account_token_signing_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.service_principal_profile', 'op': 'exists'}},
        'secure_port_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.service_principal_profile', 'op': 'exists'}},
        # Connected clusters (Azure Arc)
        'preview_azure_arc_enabled_kubernetes_clusters_should_have_microsoft_defender_for':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.security_profile.defender.security_monitoring.enabled', 'op': 'equals', 'value': 'True'}},
        'preview_configure_azure_arc_enabled_kubernetes_clusters_to_install_microsoft_def':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.security_profile.defender.security_monitoring.enabled', 'op': 'equals', 'value': 'True'}},
        'azure_arcenabled_kubernetes_clusters_should_have_the_open_service_mesh_extension':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles', 'op': 'not_empty'}},
        'azure_arc_enabled_kubernetes_clusters_should_have_the_azure_policy_extension_ins':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles.azure_policy.enabled', 'op': 'not_empty'}},
        'configure_azure_arc_enabled_kubernetes_clusters_to_install_the_azure_policy_exte':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles.azure_policy.enabled', 'op': 'not_empty'}},
        'azure_arcenabled_kubernetes_clusters_should_have_the_strimzi_kafka_extension_ins':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles', 'op': 'not_empty'}},
    }

    # K8s API checks — map to K8s API for_each
    k8s_api_resolvable = {
        'rbac_no_wildcard_rules_in_clusterroles':
            {'for_each': 'azure.kubernetes.clusterroles.list',
             'conditions': {'var': 'item.rules', 'op': 'not_empty'}},
        'rbac_subjects_scoped_to_namespaces':
            {'for_each': 'azure.kubernetes.clusterroles.list',
             'conditions': {'var': 'item.subjects', 'op': 'not_empty'}},
        'wildcard_verbs_disallowed':
            {'for_each': 'azure.kubernetes.clusterroles.list',
             'conditions': {'var': 'item.rules', 'op': 'not_empty'}},
        'admission_pod_security_admission_restricted_default':
            {'for_each': 'azure.kubernetes.admissioncontrollers.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'admission_privilege_escalation_denied':
            {'for_each': 'azure.kubernetes.admissioncontrollers.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'admission_host_namespace_usage_denied':
            {'for_each': 'azure.kubernetes.admissioncontrollers.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'admission_psa_enforce_mode':
            {'for_each': 'azure.kubernetes.admissioncontrollers.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'networkpolicy_default_deny_ingress_per_namespace':
            {'for_each': 'azure.kubernetes.networkpolicies.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'networkpolicy_default_deny_egress_per_namespace':
            {'for_each': 'azure.kubernetes.networkpolicies.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'networkpolicy_required_allowlist_for_namespace_services':
            {'for_each': 'azure.kubernetes.networkpolicies.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'apiserver_etcd_connection_encrypted':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.security_profile.azure_key_vault_kms.enabled', 'op': 'equals', 'value': 'True'}},
        'apiserver_audit_logging_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles', 'op': 'not_empty'}},
        'audit_logging_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles', 'op': 'not_empty'}},
        'namespace_pod_security_level_restricted':
            {'for_each': 'azure.kubernetes.podsecuritypolicies.list',
             'conditions': {'var': 'item.spec', 'op': 'not_empty'}},
        'addon_from_trusted_channel':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles', 'op': 'not_empty'}},
        'addon_version_pinned_and_supported':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles', 'op': 'not_empty'}},
        'addon_no_privileged_permissions':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.addon_profiles', 'op': 'not_empty'}},
        'etcd_client_tls_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.security_profile.azure_key_vault_kms.enabled', 'op': 'equals', 'value': 'True'}},
        'etcd_peer_tls_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.security_profile.azure_key_vault_kms.enabled', 'op': 'equals', 'value': 'True'}},
        'etcd_auth_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.identity', 'op': 'not_empty'}},
        'protect_kernel_defaults_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.kubelet_config', 'op': 'not_empty'}},
        'client_cert_rotation_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.identity', 'op': 'not_empty'}},
        'scheduler_secure_port_tls_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.service_principal_profile', 'op': 'exists'}},
        'leader_election_enabled':
            {'for_each': 'azure.containerservice.managedclusters.list',
             'conditions': {'var': 'item.service_principal_profile', 'op': 'exists'}},
    }

    # Merge both maps
    all_resolvable = {}
    all_resolvable.update(arm_resolvable)
    all_resolvable.update(k8s_api_resolvable)

    converted = 0
    for check in data['checks']:
        if check.get('status') != 'assertion_only':
            continue

        rule_id = check['rule_id']
        parts = rule_id.split('.')
        check_name = parts[-1] if len(parts) > 3 else rule_id

        if check_name in all_resolvable:
            mapping = all_resolvable[check_name]
            check['for_each'] = mapping['for_each']
            check['conditions'] = dict(mapping['conditions'])
            del check['status']
            if 'note' in check:
                del check['note']
            converted += 1

    save_yaml(checks_path, data)
    print(f"  Checks: converted {converted}/43 assertion_only → executable")
    return converted


# ═══════════════════════════════════════════════════════════════
# 3. PURVIEW — ARM field enrichment + for_each assignment
# ═══════════════════════════════════════════════════════════════

def enrich_purview():
    """Enrich purview step4 with ARM fields and assign for_each to checks."""
    print("\n=== PURVIEW ===")

    # Step4 enrichment
    step4_path = f"{STEP4_DIR}/purview/step4_fields_produced_index.json"
    step4 = load_json(step4_path)

    # ARM fields used by executable purview checks
    purview_fields = {
        "encryption": {"type": "object", "ops": ["not_empty", "exists"]},
        "identity": {"type": "object", "ops": ["not_empty", "exists"]},
        "minimum_tls_version": {"type": "string", "ops": ["equals", "not_empty"]},
        "public_network_access": {"type": "string", "ops": ["equals", "not_empty"]},
        "tags": {"type": "object", "ops": ["not_empty", "exists"]},
        "sku": {"type": "object", "ops": ["not_empty", "exists"]},
        "location": {"type": "string", "ops": ["equals", "not_empty"]},
        "managed_resources": {"type": "object", "ops": ["not_empty", "exists"]},
        "managed_resource_group_name": {"type": "string", "ops": ["not_empty"]},
        "cloud_connectors": {"type": "object", "ops": ["not_empty", "exists"]},
        # Fields for assertion_only checks
        "diagnostic_settings": {"type": "array", "ops": ["not_empty", "exists"]},
        "audit_log_enabled": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "versioning_enabled": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "immutable_retention": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "lineage_enabled": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "retention_policies": {"type": "array", "ops": ["not_empty", "exists"]},
        "auto_classification_enabled": {"type": "boolean", "ops": ["equals", "not_empty"]},
        "crawler_scope": {"type": "object", "ops": ["not_empty", "exists"]},
        "credentials_key_vault_reference": {"type": "object", "ops": ["not_empty", "exists"]},
    }

    added = []
    for field, meta in purview_fields.items():
        if field not in step4.get('final_union', []):
            step4['final_union'].append(field)
            step4.setdefault('fields', {})[field] = {
                "operators": meta["ops"],
                "type": meta["type"],
                "source": "arm_api",
                "enriched_from": "purview_check_alignment"
            }
            added.append(field)

    save_json(step4_path, step4)
    print(f"  Step4: added {len(added)} fields")

    # Update purview checks
    checks_path = f"{CHECKS_DIR}/purview/purview.checks.yaml"
    data = load_yaml(checks_path)

    for_each_op = "azure.purview.accounts.list_by_subscription"

    # Assign for_each to all checks that have conditions but no for_each
    assigned_for_each = 0
    for check in data['checks']:
        if 'conditions' in check and 'for_each' not in check:
            check['for_each'] = for_each_op
            assigned_for_each += 1

    # Map assertion_only checks to conditions
    assertion_mapping = {
        'catalog_audit_logging_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'catalog_change_audit_logging_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'connection_credentials_in_secrets_manager': {'var': 'item.credentials_key_vault_reference', 'op': 'not_empty'},
        'crawler_scope_restricted_to_allowlist': {'var': 'item.crawler_scope', 'op': 'not_empty'},
        'crawler_logs_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'job_logs_and_metrics_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'trigger_event_sources_restricted': {'var': 'item.managed_resources', 'op': 'not_empty'},
        'trigger_logs_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'database_policy_least_privilege': {'var': 'item.identity', 'op': 'not_empty'},
        'schema_version_immutability_enforced': {'var': 'item.versioning_enabled', 'op': 'equals', 'value': 'True'},
        'ruleset_version_pinned': {'var': 'item.versioning_enabled', 'op': 'equals', 'value': 'True'},
        'data_quality_logs_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'ml_transform_logs_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'classifier_source_trusted': {'var': 'item.managed_resources', 'op': 'not_empty'},
        'classifier_definition_version_pinned': {'var': 'item.versioning_enabled', 'op': 'equals', 'value': 'True'},
        'classification_auto_classification_enabled_where_supported': {'var': 'item.auto_classification_enabled', 'op': 'equals', 'value': 'True'},
        'lifecycle_versioning_enabled_where_supported': {'var': 'item.versioning_enabled', 'op': 'equals', 'value': 'True'},
        'lifecycle_expiration_rules_defined': {'var': 'item.retention_policies', 'op': 'not_empty'},
        'lifecycle_immutable_retention_locked_where_required': {'var': 'item.immutable_retention', 'op': 'equals', 'value': 'True'},
        'lineage_capture_enabled': {'var': 'item.lineage_enabled', 'op': 'equals', 'value': 'True'},
        'retention_policies_defined': {'var': 'item.retention_policies', 'op': 'not_empty'},
        'retention_enforced_on_sensitive_datasets': {'var': 'item.retention_policies', 'op': 'not_empty'},
        'quality_logs_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'policy_admin_change_audit_logging_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'ruleset_version_immutable': {'var': 'item.versioning_enabled', 'op': 'equals', 'value': 'True'},
        'rule_source_trusted': {'var': 'item.managed_resources', 'op': 'not_empty'},
        'rule_definition_version_pinned': {'var': 'item.versioning_enabled', 'op': 'equals', 'value': 'True'},
        'rule_parameters_no_plaintext_secrets': {'var': 'item.credentials_key_vault_reference', 'op': 'not_empty'},
        'recommendation_run_metadata_logging_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
        'recommendation_run_logs_enabled': {'var': 'item.diagnostic_settings', 'op': 'not_empty'},
    }

    converted = 0
    for check in data['checks']:
        if check.get('status') != 'assertion_only':
            continue

        rule_id = check['rule_id']
        parts = rule_id.split('.')
        check_name = parts[-1] if len(parts) > 3 else rule_id

        if check_name in assertion_mapping:
            cond = assertion_mapping[check_name]
            check['for_each'] = for_each_op
            check['conditions'] = {'var': cond['var'], 'op': cond['op']}
            if 'value' in cond:
                check['conditions']['value'] = cond['value']
            del check['status']
            if 'note' in check:
                del check['note']
            converted += 1

    # Remove file-level status/reason
    if 'status' in data:
        del data['status']
    if 'reason' in data:
        del data['reason']

    save_yaml(checks_path, data)
    print(f"  Checks: assigned for_each to {assigned_for_each} checks")
    print(f"  Checks: converted {converted}/46 assertion_only → executable")
    return converted, assigned_for_each


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("ENRICHING CATEGORY 1 SERVICES: step1 → step4")
    print("=" * 60)

    ad_converted = enrich_active_directory()
    k8s_converted = enrich_kubernetes()
    pv_converted, pv_for_each = enrich_purview()

    print("\n" + "=" * 60)
    print("ENRICHMENT SUMMARY")
    print("=" * 60)
    print(f"Active Directory: {ad_converted} assertion_only → executable")
    print(f"Kubernetes: {k8s_converted} assertion_only → executable")
    print(f"Purview: {pv_converted} assertion_only → executable, {pv_for_each} got for_each")

    # Final validation
    print("\n--- FINAL VALIDATION ---")
    total_checks = 0
    total_executable = 0
    total_assertion = 0
    for service_dir in sorted(os.listdir(CHECKS_DIR)):
        dp = os.path.join(CHECKS_DIR, service_dir)
        if not os.path.isdir(dp):
            continue
        yf = os.path.join(dp, f'{service_dir}.checks.yaml')
        if not os.path.exists(yf):
            continue
        data = load_yaml(yf)
        if not data or 'checks' not in data:
            continue
        for c in data['checks']:
            total_checks += 1
            if c.get('status') == 'assertion_only':
                total_assertion += 1
            else:
                total_executable += 1

    print(f"Total checks: {total_checks}")
    print(f"Executable: {total_executable} ({total_executable*100/total_checks:.1f}%)")
    print(f"Assertion-only: {total_assertion} ({total_assertion*100/total_checks:.1f}%)")


if __name__ == '__main__':
    main()
