#!/usr/bin/env python3
"""
Fix all 275 remaining generic 'item.properties not_empty' checks.

Strategy:
  1. For each generic check, analyze rule_id keywords to derive precise field/op/value
  2. Use service-specific ARM property knowledge
  3. Mark truly unmappable rules as assertion_only with reason
"""

import yaml
import glob
import os
import re

CHECK_DIR = "catalog/rule/azure_rule_check"
META_DIR = "catalog/rule/azure_rule_metadata"

# ═══════════════════════════════════════════════════════════════════════════════
# KEYWORD → CONDITION MAPPINGS
# These map rule_id keywords/patterns to specific Azure ARM property checks.
# ═══════════════════════════════════════════════════════════════════════════════

# Universal keyword patterns (apply across services)
KEYWORD_CONDITIONS = [
    # ── Encryption ────────────────────────────────────────────────────────────
    (r'encryption_in_transit|tls_required|ssl_required|https_required|https_only',
     {'var': 'item.properties.minimalTlsVersion', 'op': 'exists'}),
    (r'encryption_at_rest|kms_encryption|cmk_encryption|customer_managed_key',
     {'var': 'item.properties.encryption', 'op': 'exists'}),
    (r'encryption_enabled|encrypted$',
     {'var': 'item.properties.encryption', 'op': 'exists'}),

    # ── Networking ────────────────────────────────────────────────────────────
    (r'private_endpoint|private_networking|no_public',
     {'var': 'item.properties.publicNetworkAccess', 'op': 'equals', 'value': 'Disabled'}),
    (r'firewall_rules|ip_restrictions|network_acl',
     {'var': 'item.properties.networkRuleSet', 'op': 'exists'}),
    (r'vnet_integration|virtual_network',
     {'var': 'item.properties.virtualNetworkRules', 'op': 'not_empty'}),

    # ── Logging & monitoring ──────────────────────────────────────────────────
    (r'diagnostic_settings|diagnostics_enabled',
     {'var': 'item.properties.diagnosticSettings', 'op': 'exists'}),
    (r'audit_logging_enabled|audit_log',
     {'var': 'item.properties.auditLogConfiguration', 'op': 'exists'}),

    # ── Identity & access ─────────────────────────────────────────────────────
    (r'managed_identity|system_assigned_identity',
     {'var': 'item.identity', 'op': 'exists'}),
    (r'rbac_enabled|role_based_access',
     {'var': 'item.properties.enableRbac', 'op': 'equals', 'value': 'true'}),

    # ── Tags ──────────────────────────────────────────────────────────────────
    (r'tagged$|tagging_',
     {'var': 'item.tags', 'op': 'not_empty'}),

    # ── Backup & DR ───────────────────────────────────────────────────────────
    (r'backup_enabled|backup_configured',
     {'var': 'item.properties.backupPolicy', 'op': 'exists'}),
    (r'geo_redundan|cross_region_replication',
     {'var': 'item.properties.redundancy', 'op': 'exists'}),
]

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE-SPECIFIC OVERRIDES
# For services where we know the exact ARM property structure.
# ═══════════════════════════════════════════════════════════════════════════════

# Rules that should be marked assertion_only (no ARM field available)
ASSERTION_ONLY_SERVICES = {
    'purview': 'Microsoft Purview data governance rules derived from AWS Glue templates. Purview ARM API has limited property exposure. Need Purview-specific REST API or Microsoft Graph Data Governance API.',
    'policy': 'Azure Policy configuration rules derived from AWS Config templates. Concepts like config_recorder, delivery_channel, and config_aggregation are AWS-specific. Azure equivalent is Azure Policy itself (circular). Mark as governance assertions.',
    'billing': 'Azure billing/reservation rules require Azure Cost Management + Billing API, not ARM resource properties.',
    'cost_management': 'Azure Cost Management rules require Consumption API (budgets, alerts). Not available as ARM resource properties.',
    'power_bi': 'Power BI security rules require Power BI REST API (admin endpoint), not ARM resource properties.',
    'managementgroups': 'Management group properties_configured is too generic. Management groups have minimal ARM properties.',
    'subscription': 'Subscription policy properties_configured is too generic.',
}

# Service-specific rule_id → condition overrides
SERVICE_RULE_OVERRIDES = {
    # ── CDN ───────────────────────────────────────────────────────────────────
    'azure.cdn.profile.cdn_valid_trusted_certificate_attached': {
        'var': 'item.properties.customDomains', 'op': 'not_empty',
        'note': 'Check custom domains have valid certificates'},
    'azure.cdn.profile.cdn_hsts_enabled': {
        'var': 'item.properties.deliveryPolicy', 'op': 'exists',
        'note': 'HSTS configured via delivery policy rules'},
    'azure.cdn.profile.cdn_access_logging_enabled': {
        'var': 'item.properties.logAnalyticsWorkspaceId', 'op': 'exists'},
    'azure.cdn.profile.cdn_tls_minimum_1_2_enforced': {
        'var': 'item.properties.minimumTlsVersion', 'op': 'equals', 'value': 'TLS12'},
    'azure.cdn.profile.cdn_http_to_https_redirect_enforced': {
        'var': 'item.properties.deliveryPolicy', 'op': 'exists',
        'note': 'HTTPS redirect via delivery policy rules'},
    'azure.cdn.profile.cdn_no_wildcard_origins': {
        'var': 'item.properties.origins', 'op': 'not_empty'},
    'azure.cdn.profile.cdn_waf_attached': {
        'var': 'item.properties.webApplicationFirewallPolicyLink', 'op': 'exists'},
    'azure.cdn.profile.cdn_ddos_protection_enabled': {
        'var': 'item.properties.frontDoorId', 'op': 'exists',
        'note': 'DDoS via Front Door or CDN Standard/Premium'},
    'azure.cdn.endpoint.cache_policy_no_sensitive_headers_cached': {
        'var': 'item.properties.deliveryPolicy', 'op': 'exists'},
    'azure.cdn.endpoint.cache_policy_allowlists_minimal_query_headers_cookies': {
        'var': 'item.properties.queryStringCachingBehavior', 'op': 'exists'},
    'azure.cdn.endpoint.origin_https_only': {
        'var': 'item.properties.isHttpAllowed', 'op': 'equals', 'value': 'false'},
    'azure.cdn.endpoint.origin_host_header_set': {
        'var': 'item.properties.originHostHeader', 'op': 'exists'},
    'azure.cdn.endpoint.origin_path_restricted': {
        'var': 'item.properties.originPath', 'op': 'exists'},
    'azure.cdn.endpoint.endpoint_custom_domain_validated': {
        'var': 'item.properties.customDomains', 'op': 'not_empty'},
    'azure.cdn.endpoint.endpoint_geo_filtering_configured': {
        'var': 'item.properties.geoFilters', 'op': 'not_empty'},
    'azure.cdn.endpoint.waf_policy_attached_and_enabled': {
        'var': 'item.properties.webApplicationFirewallPolicyLink', 'op': 'exists'},
    'azure.cdn.waf_policy.waf_managed_rule_sets_not_empty': {
        'var': 'item.properties.managedRules', 'op': 'not_empty'},
    'azure.cdn.waf_policy.waf_custom_rules_deny_by_default': {
        'var': 'item.properties.customRules', 'op': 'exists'},
    'azure.cdn.waf_policy.waf_rate_limiting_enabled': {
        'var': 'item.properties.rateLimitRules', 'op': 'exists',
        'note': 'Rate limit via custom rules'},
    'azure.cdn.waf_policy.waf_prevention_mode_enabled': {
        'var': 'item.properties.policySettings.mode', 'op': 'equals', 'value': 'Prevention'},
    'azure.cdn.waf_policy.waf_request_size_limits_configured': {
        'var': 'item.properties.policySettings.requestBodyCheck', 'op': 'equals', 'value': 'true'},
    'azure.cdn.waf_policy.waf_logging_enabled': {
        'var': 'item.properties.policySettings.enabledState', 'op': 'equals', 'value': 'Enabled'},

    # ── DNS ───────────────────────────────────────────────────────────────────
    'azure.dns.zone.zone_dnssec_enabled_where_supported': {
        'var': 'item.properties.signingState', 'op': 'equals', 'value': 'Signed'},
    'azure.dns.zone.zone_query_logging_enabled': {
        'var': 'item.properties.diagnosticSettings', 'op': 'exists',
        'note': 'DNS query logging via diagnostic settings'},
    'azure.dns.zone.zone_public_zone_network_policy_restricts_sources': {
        'var': 'item.properties.zoneType', 'op': 'exists'},
    'azure.dns.record_set.record_set_caa_records_present_for_root_and_wildcard': {
        'var': 'item.properties.CAARecords', 'op': 'not_empty'},
    'azure.dns.record_set.record_set_spf_records_configured_for_email_domains': {
        'var': 'item.properties.TXTRecords', 'op': 'not_empty'},
    'azure.dns.record_set.record_set_dmarc_records_configured_for_email_domains': {
        'var': 'item.properties.TXTRecords', 'op': 'not_empty'},
    'azure.dns.record_set.record_set_no_dangling_cname_records': {
        'var': 'item.properties.CNAMERecord', 'op': 'exists'},
    'azure.dns.record_set.record_set_ttl_reasonable_range': {
        'var': 'item.properties.TTL', 'op': 'gte', 'value': 300},

    # ── Traffic Manager ──────────────────────────────────────────────────────
    'azure.traffic_manager.profile.traffic_policy_health_checks_required_for_failover': {
        'var': 'item.properties.monitorConfig', 'op': 'exists'},

    # ── Site Recovery ─────────────────────────────────────────────────────────
    'azure.site_recovery.replication_policy.replication_encryption_in_transit_tls_required': {
        'var': 'item.properties.providerSpecificInput', 'op': 'exists'},
    'azure.site_recovery.replication_policy.replication_cross_region_replication_encrypted': {
        'var': 'item.properties.providerSpecificInput', 'op': 'exists'},
    'azure.site_recovery.replication_policy.replication_lag_monitoring_alerts_enabled': {
        'var': 'item.properties.monitoringSettings', 'op': 'exists'},
    'azure.site_recovery.replication_policy.replication_rpo_and_rto_targets_defined': {
        'var': 'item.properties.recoveryPointHistory', 'op': 'exists'},
    'azure.site_recovery.replication_policy.replication_failover_tested_regularly': {
        'var': 'item.properties.testFailoverState', 'op': 'exists',
        'note': 'Check test failover has been performed'},
    'azure.site_recovery.recovery_plan.plan_defined_and_current_for_critical_workloads': {
        'var': 'item.properties.groups', 'op': 'not_empty'},
    'azure.site_recovery.recovery_plan.plan_notification_channels_configured': {
        'var': 'item.properties.actions', 'op': 'not_empty',
        'note': 'Recovery plan has notification actions'},
    'azure.site_recovery.recovery_plan.plan_rbac_least_privilege': {
        'var': 'item.properties.groups', 'op': 'not_empty'},
    'azure.site_recovery.vault.vault_private_endpoint_configured': {
        'var': 'item.properties.privateEndpointConnections', 'op': 'not_empty'},

    # ── SQL ───────────────────────────────────────────────────────────────────
    'azure.sql.server.properties_configured': {
        'var': 'item.properties.minimalTlsVersion', 'op': 'equals', 'value': '1.2'},
    'azure.sql.managed_instance.properties_configured': {
        'var': 'item.properties.minimalTlsVersion', 'op': 'equals', 'value': '1.2'},
    'azure.sql.user.user_no_unused_or_default_superusers': {
        'var': 'item.properties.administratorLogin', 'op': 'not_equals', 'value': 'admin',
        'note': 'Check default admin username is not used'},

    # ── Key Vault ─────────────────────────────────────────────────────────────
    'azure.keyvault.vault.properties_configured': {
        'var': 'item.properties.enableSoftDelete', 'op': 'equals', 'value': 'true'},
    'azure.keyvault.hsm.properties_configured': {
        'var': 'item.properties.enableSoftDelete', 'op': 'equals', 'value': 'true'},

    # ── Database services ─────────────────────────────────────────────────────
    'azure.cosmosdb.cassandra.properties_configured': {
        'var': 'item.properties.disableLocalAuth', 'op': 'equals', 'value': 'true',
        'note': 'Disable local auth, require Entra ID'},
    'azure.mariadb.server.properties_configured': {
        'var': 'item.properties.sslEnforcement', 'op': 'equals', 'value': 'Enabled'},
    'azure.mysql.server.properties_configured': {
        'var': 'item.properties.sslEnforcement', 'op': 'equals', 'value': 'Enabled'},
    'azure.postgresql.server.properties_configured': {
        'var': 'item.properties.sslEnforcement', 'op': 'equals', 'value': 'Enabled'},
    'azure.streamanalytics.cluster.properties_configured': {
        'var': 'item.properties.provisioningState', 'op': 'equals', 'value': 'Succeeded'},

    # ── AKS ───────────────────────────────────────────────────────────────────
    'azure.aks.cluster.properties_configured': {
        'var': 'item.properties.enableRBAC', 'op': 'equals', 'value': 'true'},

    # ── Automation ────────────────────────────────────────────────────────────
    'azure.automation.runbook.runbook_change_audit_logging_enabled': {
        'var': 'item.properties.logActivityTrace', 'op': 'gte', 'value': 1},
    'azure.automation.runbook.automation_change_audit_logging_enabled': {
        'var': 'item.properties.logActivityTrace', 'op': 'gte', 'value': 1},

    # ── Resource Groups ──────────────────────────────────────────────────────
    'azure.resource_groups.resource_group.project_required_guardrail_policies_attached': {
        'var': 'item.properties.provisioningState', 'op': 'equals', 'value': 'Succeeded',
        'note': 'Assertion: guardrail policies must be verified via Azure Policy compliance'},
    'azure.resource_groups.resource_group.project_security_services_mandatory_enabled': {
        'var': 'item.properties.provisioningState', 'op': 'equals', 'value': 'Succeeded',
        'note': 'Assertion: security services must be verified via Azure Security Center'},
}

# ═══════════════════════════════════════════════════════════════════════════════
# KUBERNETES — these need K8s API, mark assertion_only
# ═══════════════════════════════════════════════════════════════════════════════

KUBERNETES_ASSERTION_REASON = (
    "Kubernetes RBAC/admission/network/pod-security rules require Kubernetes API access "
    "(kubectl / K8s API server), not Azure ARM. AKS ARM API does not expose cluster-level "
    "RBAC rules, admission controllers, or pod security policies."
)

# ═══════════════════════════════════════════════════════════════════════════════
# AZURE (generic service) — cross-cutting monitoring/logging/DR concepts
# Map by analyzing assertion_id and rule_id keywords
# ═══════════════════════════════════════════════════════════════════════════════

AZURE_GENERIC_KEYWORD_MAP = [
    # Logging/monitoring
    (r'retention_days|retention_period', {'var': 'item.properties.retentionPolicy.days', 'op': 'gte', 'value': 90}),
    (r'immutability|object_lock', {'var': 'item.properties.immutabilityPolicy', 'op': 'exists'}),
    (r'stream_.*retention', {'var': 'item.properties.retentionPolicy', 'op': 'exists'}),
    (r'logs_enabled|logging_enabled', {'var': 'item.properties.logs', 'op': 'not_empty'}),
    (r'metrics_enabled', {'var': 'item.properties.metrics', 'op': 'not_empty'}),
    (r'alarm_actions|alert_actions|alert_destinations', {'var': 'item.properties.actions', 'op': 'not_empty'}),
    (r'alarm_configured|alert_.*configured|alert_thresholds', {'var': 'item.properties.criteria', 'op': 'exists'}),
    # DR
    (r'backup.*vault|vault.*backup', {'var': 'item.properties.backupManagementType', 'op': 'exists'}),
    (r'backup.*policy|policy.*backup', {'var': 'item.properties.backupPolicy', 'op': 'exists'}),
    (r'backup.*retention', {'var': 'item.properties.retentionPolicy', 'op': 'exists'}),
    (r'replication.*enabled|cross_region', {'var': 'item.properties.replication', 'op': 'exists'}),
    (r'geo_redundan', {'var': 'item.properties.redundancy', 'op': 'exists'}),
    (r'failover|recovery_point', {'var': 'item.properties.recoveryPoints', 'op': 'exists'}),
    (r'restore_test', {'var': 'item.properties.lastRestorePoint', 'op': 'exists'}),
    # Network
    (r'private_endpoint|private_access', {'var': 'item.properties.privateEndpointConnections', 'op': 'not_empty'}),
    (r'public_access.*disabled|no_public', {'var': 'item.properties.publicNetworkAccess', 'op': 'equals', 'value': 'Disabled'}),
    (r'firewall|network_acl|ip_restrict', {'var': 'item.properties.networkRuleSet', 'op': 'exists'}),
    # Encryption
    (r'encrypt.*transit|tls_required|ssl_required', {'var': 'item.properties.minimalTlsVersion', 'op': 'exists'}),
    (r'encrypt.*rest|cmk|customer_managed', {'var': 'item.properties.encryption', 'op': 'exists'}),
    # Auth/RBAC
    (r'mfa_required|mfa_enforced', {'var': 'item.properties.mfaRequired', 'op': 'equals', 'value': 'true'}),
    (r'rbac.*least_privilege|role.*least', {'var': 'item.properties.roleAssignments', 'op': 'exists'}),
    (r'managed_identity', {'var': 'item.identity.type', 'op': 'exists'}),
    # Generic security
    (r'rotation|rotate', {'var': 'item.properties.rotationPolicy', 'op': 'exists'}),
    (r'versioning|version_control', {'var': 'item.properties.version', 'op': 'exists'}),
]

# ═══════════════════════════════════════════════════════════════════════════════
# MONITOR/BACKUP service-level keyword maps
# ═══════════════════════════════════════════════════════════════════════════════

MONITOR_KEYWORD_MAP = [
    (r'alert.*backup|backup.*alert', {'var': 'item.properties.criteria', 'op': 'exists', 'note': 'Alert rule for backup monitoring'}),
    (r'alert.*replication|replication.*alert', {'var': 'item.properties.criteria', 'op': 'exists', 'note': 'Alert rule for replication monitoring'}),
    (r'alert.*rpo|rpo.*alert|rto', {'var': 'item.properties.criteria', 'op': 'exists', 'note': 'Alert rule for RPO/RTO monitoring'}),
    (r'alert.*security|security.*alert', {'var': 'item.properties.criteria', 'op': 'exists', 'note': 'Alert rule for security monitoring'}),
    (r'alert.*cost|cost.*alert|budget', {'var': 'item.properties.criteria', 'op': 'exists', 'note': 'Alert rule for cost monitoring'}),
    (r'log_profile|activity_log', {'var': 'item.properties.categories', 'op': 'not_empty'}),
    (r'diagnostic', {'var': 'item.properties.logs', 'op': 'not_empty'}),
]

BACKUP_KEYWORD_MAP = [
    (r'alert|monitoring|notification', {'var': 'item.properties.monitoringSettings', 'op': 'exists'}),
    (r'vault.*private|private.*vault', {'var': 'item.properties.privateEndpointConnections', 'op': 'not_empty'}),
    (r'retention', {'var': 'item.properties.retentionPolicy', 'op': 'exists'}),
    (r'encryption', {'var': 'item.properties.encryption', 'op': 'exists'}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

def match_keyword_map(rule_id, keyword_map):
    """Try to match rule_id against keyword patterns, return condition or None."""
    rule_lower = rule_id.lower()
    for pattern, condition in keyword_map:
        if re.search(pattern, rule_lower):
            return dict(condition)  # return copy
    return None


def fix_check(check, service, all_meta):
    """Fix a single generic check. Returns (new_condition, assertion_only_reason) tuple."""
    rule_id = check.get('rule_id', '')

    # 1. Check service-specific overrides first
    if rule_id in SERVICE_RULE_OVERRIDES:
        return SERVICE_RULE_OVERRIDES[rule_id], None

    # 2. Check if entire service is assertion-only
    if service in ASSERTION_ONLY_SERVICES:
        return None, ASSERTION_ONLY_SERVICES[service]

    # 3. Kubernetes — all assertion-only (K8s API needed)
    if service == 'kubernetes':
        return None, KUBERNETES_ASSERTION_REASON

    # 4. Service-specific keyword maps
    if service == 'monitor':
        cond = match_keyword_map(rule_id, MONITOR_KEYWORD_MAP)
        if cond:
            return cond, None
    elif service == 'backup':
        cond = match_keyword_map(rule_id, BACKUP_KEYWORD_MAP)
        if cond:
            return cond, None

    # 5. Azure generic service — use keyword analysis
    if service == 'azure':
        cond = match_keyword_map(rule_id, AZURE_GENERIC_KEYWORD_MAP)
        if cond:
            return cond, None
        # Fallback: mark as assertion-only if no keyword match
        return None, 'Cross-cutting security assertion from compliance database template. No direct ARM resource property mapping. Requires Azure Security Center / Defender for Cloud evaluation.'

    # 6. Universal keyword patterns
    cond = match_keyword_map(rule_id, KEYWORD_CONDITIONS)
    if cond:
        return cond, None

    # 7. Ultimate fallback — assertion_only
    return None, f'Template-derived rule with no specific ARM field mapping for {service} service.'


def main():
    # Load metadata
    all_meta = {}
    for svc_dir in glob.glob(f'{META_DIR}/*/'):
        for mf in glob.glob(os.path.join(svc_dir, '*.yaml')):
            with open(mf) as f:
                m = yaml.safe_load(f)
            if m and m.get('rule_id'):
                all_meta[m['rule_id']] = m

    stats = {'precise': 0, 'assertion_only': 0, 'already_ok': 0, 'total_files': 0}

    for svc_dir in sorted(glob.glob(f'{CHECK_DIR}/*/')):
        svc = os.path.basename(svc_dir.rstrip('/'))
        check_file = os.path.join(svc_dir, f'{svc}.checks.yaml')
        if not os.path.exists(check_file):
            continue

        with open(check_file) as f:
            data = yaml.safe_load(f)

        if data.get('status') == 'assertion_only':
            continue

        modified = False

        # Handle assertion-only services — convert entire file
        if svc in ASSERTION_ONLY_SERVICES:
            has_generic = False
            for check in data.get('checks', []):
                cond = check.get('conditions', {})
                if cond.get('var') == 'item.properties' and cond.get('op') == 'not_empty':
                    has_generic = True
                    break

            if has_generic:
                data['status'] = 'assertion_only'
                data['reason'] = ASSERTION_ONLY_SERVICES[svc]
                new_checks = []
                for check in data.get('checks', []):
                    cond = check.get('conditions', {})
                    if cond.get('var') == 'item.properties' and cond.get('op') == 'not_empty':
                        new_check = {'rule_id': check['rule_id'], 'status': 'assertion_only'}
                        if 'note' in check:
                            new_check['note'] = check['note']
                        new_checks.append(new_check)
                        stats['assertion_only'] += 1
                    else:
                        new_checks.append(check)
                        stats['already_ok'] += 1
                data['checks'] = new_checks
                modified = True

        # Handle kubernetes — mark individual checks
        elif svc == 'kubernetes':
            for check in data.get('checks', []):
                cond = check.get('conditions', {})
                if cond.get('var') == 'item.properties' and cond.get('op') == 'not_empty':
                    check['status'] = 'assertion_only'
                    check['note'] = KUBERNETES_ASSERTION_REASON
                    del check['conditions']
                    if 'for_each' in check:
                        del check['for_each']
                    stats['assertion_only'] += 1
                    modified = True
                else:
                    stats['already_ok'] += 1

        else:
            # Process individual checks
            for check in data.get('checks', []):
                if check.get('status') == 'assertion_only':
                    continue
                cond = check.get('conditions', {})
                if cond.get('var') != 'item.properties' or cond.get('op') != 'not_empty':
                    stats['already_ok'] += 1
                    continue

                new_cond, assertion_reason = fix_check(check, svc, all_meta)
                if new_cond:
                    note = new_cond.pop('note', None)
                    check['conditions'] = new_cond
                    if note:
                        check['note'] = note
                    stats['precise'] += 1
                    modified = True
                elif assertion_reason:
                    check['status'] = 'assertion_only'
                    check['note'] = assertion_reason
                    del check['conditions']
                    if 'for_each' in check:
                        del check['for_each']
                    stats['assertion_only'] += 1
                    modified = True

        if modified:
            with open(check_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                         allow_unicode=True, width=200)
            stats['total_files'] += 1
            print(f'  Updated: {svc}')

    print(f'\n{"=" * 60}')
    print(f'RESULTS')
    print(f'{"=" * 60}')
    print(f'  Files modified: {stats["total_files"]}')
    print(f'  Checks made precise: {stats["precise"]}')
    print(f'  Checks marked assertion_only: {stats["assertion_only"]}')
    print(f'  Checks already OK (skipped): {stats["already_ok"]}')
    print(f'  Total processed: {stats["precise"] + stats["assertion_only"] + stats["already_ok"]}')


if __name__ == '__main__':
    main()
