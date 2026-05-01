#!/usr/bin/env python3
"""
Generate template metadata for CIEM/log-detection rules missing rationale.

These rules (e.g. aws.eks.audit_log.audit.clusterrolebinding_create) are audit/
event correlation rules — they detect events in logs, not config drift. Their
metadata needs to be generated programmatically since there are no YAML files.

Usage:
  python3 scripts/generate_log_rule_metadata.py [--dry-run] [--csp aws]
"""

import re, json, psycopg2, argparse

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# Log/event service patterns → domain/context
LOG_PATTERNS = [
    # pattern in rule_id → (domain, subcategory, rule_type)
    (r'\.audit_log\.', 'identity_and_access_management', 'audit_activity', 'audit_log'),
    (r'\.cloudtrail\.', 'security_monitoring', 'audit_activity', 'cloudtrail'),
    (r'\.activity_tracker\.', 'security_monitoring', 'audit_activity', 'activity_log'),
    (r'\.gke_audit\.', 'identity_and_access_management', 'audit_activity', 'audit_log'),
    (r'\.nsg_flow\.', 'network_security', 'network_monitoring', 'network_flow'),
    (r'\.vpc_flow\.', 'network_security', 'network_monitoring', 'network_flow'),
    (r'\.flowlog\.', 'network_security', 'network_monitoring', 'network_flow'),
    (r'\.guardduty\.', 'threat_detection', 'threat_detection', 'threat_finding'),
    (r'\.securityhub\.', 'threat_detection', 'threat_detection', 'security_finding'),
    (r'\.datasec\.', 'data_security', 'data_classification', 'data_security'),
    (r'\.storage\.cloudtrail\.', 'data_security', 'audit_activity', 'cloudtrail'),
    (r'\.alb\.alb_log\.', 'network_security', 'access_logging', 'access_log'),
    (r'\.paas\.cloudtrail\.', 'security_monitoring', 'audit_activity', 'cloudtrail'),
    (r'\.organizations\.', 'identity_and_access_management', 'account_governance', 'config'),
]

# Action templates for different event types
ACTION_TEMPLATES = {
    'create':  ('created', 'Creation', 'creation'),
    'delete':  ('deleted', 'Deletion', 'deletion'),
    'update':  ('updated', 'Modification', 'modification'),
    'modify':  ('modified', 'Modification', 'modification'),
    'attach':  ('attached', 'Association', 'attachment'),
    'detach':  ('detached', 'Dissociation', 'detachment'),
    'enable':  ('enabled', 'Enablement', 'enablement'),
    'disable': ('disabled', 'Disabling', 'disabling'),
    'invoke':  ('invoked', 'Invocation', 'invocation'),
    'assume':  ('assumed', 'Assumption', 'assumption'),
    'subscribe': ('subscribed', 'Subscription', 'subscription'),
    'publish': ('published', 'Publication', 'publication'),
}

# MITRE ATT&CK mapping by rule type
MITRE_BY_TYPE = {
    'audit_log': ['TA0003:Persistence', 'TA0004:Privilege Escalation', 'TA0007:Discovery'],
    'cloudtrail': ['TA0005:Defense Evasion', 'TA0007:Discovery', 'TA0040:Impact'],
    'network_flow': ['TA0007:Discovery', 'TA0011:Command and Control', 'TA0010:Exfiltration'],
    'threat_finding': ['TA0001:Initial Access', 'TA0002:Execution', 'TA0040:Impact'],
    'security_finding': ['TA0001:Initial Access', 'TA0040:Impact'],
    'activity_log': ['TA0007:Discovery', 'TA0003:Persistence'],
    'data_security': ['TA0009:Collection', 'TA0010:Exfiltration'],
    'config': ['TA0003:Persistence', 'TA0005:Defense Evasion'],
    'access_log': ['TA0007:Discovery', 'TA0011:Command and Control'],
}

REFERENCES_BY_TYPE = {
    'audit_log':    ['https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html'],
    'cloudtrail':   ['https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html'],
    'network_flow': ['https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'],
    'threat_finding': ['https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html'],
    'security_finding': ['https://docs.aws.amazon.com/securityhub/latest/userguide/findings-understanding.html'],
    'activity_log': ['https://cloud.ibm.com/docs/activity-tracker'],
    'data_security': ['https://aws.amazon.com/macie/'],
    'config':       ['https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security.html'],
    'access_log':   ['https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html'],
}


def humanize(s: str) -> str:
    """Convert snake_case to Title Case."""
    return ' '.join(w.capitalize() for w in s.replace('-', '_').replace('.', '_').split('_'))


def get_rule_type(rule_id: str) -> tuple:
    """Returns (domain, subcategory, log_type) from rule_id."""
    for pattern, domain, subcategory, log_type in LOG_PATTERNS:
        if re.search(pattern, rule_id, re.IGNORECASE):
            return domain, subcategory, log_type
    return 'security_monitoring', 'event_detection', 'audit_log'


def detect_action(rule_id: str) -> tuple:
    """Extract action verb from rule_id. Returns (past_tense, noun, gerund)."""
    parts = rule_id.split('.')
    last = parts[-1].lower() if parts else ''
    for verb, forms in ACTION_TEMPLATES.items():
        if last.endswith(f'_{verb}') or last.endswith(f'-{verb}') or last == verb:
            return forms
        if last.startswith(f'{verb}_') or f'_{verb}_' in last:
            return forms
    return ('detected', 'Detection', 'detection')


def get_resource_name(rule_id: str) -> str:
    """Extract meaningful resource name from rule_id."""
    parts = rule_id.split('.')
    # Usually: provider.service.subsvc.event_action
    if len(parts) >= 4:
        return humanize(parts[-2])
    elif len(parts) >= 3:
        return humanize(parts[-2])
    return humanize(parts[-1] if parts else rule_id)


def get_service_name(rule_id: str) -> str:
    """Extract service name."""
    parts = rule_id.split('.')
    for i, p in enumerate(parts):
        if p in ('audit_log', 'gke_audit', 'cloudtrail', 'guardduty', 'nsg_flow',
                 'vpc_flow', 'alb_log', 'activity_tracker', 'securityhub'):
            # The service is the part before this
            if i > 0:
                return humanize(parts[i-1])
    if len(parts) >= 2:
        svc = parts[1]
        if svc in ('paas', 'saas', 'eks', 'alb', 'storage') and len(parts) >= 3:
            return humanize(f'{parts[1]}_{parts[2]}')
        return humanize(svc)
    return 'Cloud Resource'


def generate_metadata(rule_id: str, existing_title: str) -> dict:
    """Generate template metadata for a log/event rule."""
    domain, subcategory, log_type = get_rule_type(rule_id)
    past_tense, noun, gerund = detect_action(rule_id)
    resource = get_resource_name(rule_id)
    service = get_service_name(rule_id)

    # Use existing title if available
    if existing_title and len(existing_title) > 10:
        title = existing_title
    else:
        parts = rule_id.split('.')
        action = humanize(parts[-1]) if parts else ''
        title = f'{service}: {action}'

    # Build rationale
    if log_type == 'threat_finding':
        rationale = (
            f"Monitoring {service} security findings ensures that active threats are detected "
            f"and responded to promptly. Unaddressed findings can lead to data breaches, "
            f"unauthorized access, and compliance violations."
        )
    elif log_type in ('audit_log', 'cloudtrail', 'activity_log'):
        rationale = (
            f"Detecting {resource} {gerund} events in audit logs is critical for "
            f"security monitoring. Unauthorized or unexpected {resource.lower()} "
            f"{gerund} may indicate insider threats, compromised credentials, "
            f"or privilege escalation attempts."
        )
    elif log_type == 'network_flow':
        rationale = (
            f"Monitoring network flow logs for {resource.lower()} patterns enables "
            f"detection of anomalous traffic, potential data exfiltration, "
            f"and unauthorized network communication. Early detection reduces "
            f"the blast radius of network-based attacks."
        )
    elif log_type == 'data_security':
        rationale = (
            f"Detecting {resource.lower()} {gerund} events in data security logs "
            f"helps identify potential data exfiltration, unauthorized data access, "
            f"or compliance violations. Timely detection enables incident response "
            f"before data is compromised."
        )
    else:
        rationale = (
            f"Monitoring {resource.lower()} {gerund} events helps detect security "
            f"anomalies and policy violations. Real-time detection of these events "
            f"enables rapid response to potential security incidents."
        )

    # Build remediation
    remediation = (
        f"1. Review the detected {resource.lower()} {gerund} event in context\n"
        f"2. Validate if the action was authorized and expected\n"
        f"3. If unauthorized, revoke credentials and investigate the source\n"
        f"4. Update IAM policies to restrict unauthorized {resource.lower()} {gerund}\n"
        f"5. Enable alerts for this event type in your SIEM\n"
        f"6. Review CloudTrail/audit logs for correlated suspicious activity\n"
        f"7. Consider implementing automated response via AWS Security Hub or similar"
    )

    description = (
        f"Detects when {resource.lower()} {gerund} events occur in {service} logs. "
        f"This rule correlates log events to identify potential security threats "
        f"requiring investigation."
    )

    refs = REFERENCES_BY_TYPE.get(log_type, [
        'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html'
    ])

    mitre = MITRE_BY_TYPE.get(log_type, ['TA0007:Discovery'])

    return {
        'title': title,
        'description': description,
        'rationale': rationale,
        'remediation': remediation,
        'domain': domain,
        'subcategory': subcategory,
        'references': json.dumps(refs),
        'mitre_tactics': json.dumps(mitre),
    }


UPDATE_SQL = """
    UPDATE rule_metadata SET
        description   = COALESCE(NULLIF(description, ''), %(description)s),
        rationale     = COALESCE(NULLIF(rationale, ''), %(rationale)s),
        remediation   = COALESCE(NULLIF(remediation, ''), %(remediation)s),
        domain        = COALESCE(NULLIF(domain, ''), %(domain)s),
        subcategory   = COALESCE(NULLIF(subcategory, ''), %(subcategory)s),
        "references"  = CASE
            WHEN "references" IS NULL OR "references"::text IN ('null', '[]')
            THEN %(references)s::jsonb
            ELSE "references"
        END,
        mitre_tactics = CASE
            WHEN mitre_tactics IS NULL OR mitre_tactics::text IN ('null', '[]')
            THEN %(mitre_tactics)s::jsonb
            ELSE mitre_tactics
        END,
        updated_at    = NOW()
    WHERE rule_id = %(rule_id)s AND customer_id IS NULL
"""


def run(csps: list, dry_run: bool):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    total_updated = 0

    for csp in csps:
        cur.execute("""
            SELECT rule_id, title FROM rule_metadata
            WHERE provider = %s
              AND customer_id IS NULL
              AND (rationale IS NULL OR rationale = '')
        """, (csp,))
        rows = cur.fetchall()
        print(f"\n{csp.upper()}: {len(rows)} rules need metadata")

        updated = 0
        for rule_id, title in rows:
            meta = generate_metadata(rule_id, title or '')
            meta['rule_id'] = rule_id

            if dry_run:
                if updated < 3:
                    print(f"  [DRY] {rule_id}")
                    print(f"        domain: {meta['domain']}")
                    print(f"        rationale: {meta['rationale'][:80]}...")
            else:
                cur.execute(UPDATE_SQL, meta)
                if cur.rowcount:
                    updated += 1

        if not dry_run:
            conn.commit()
            print(f"  Updated: {updated}")
            total_updated += updated

    cur.close()
    conn.close()

    if not dry_run:
        print(f"\nTotal rules updated: {total_updated}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--csp', default=None)
    args = parser.parse_args()

    all_csps = ['aws', 'azure', 'gcp', 'alicloud', 'ibm', 'k8s', 'oci']
    csps = [args.csp] if args.csp else all_csps
    run(csps, args.dry_run)
