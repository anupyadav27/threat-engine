#!/usr/bin/env python3
"""
Generate MITRE ATT&CK tactics and compliance framework tags for rules missing them.

Strategy:
  MITRE   → mapped by domain + check_type (CIEM log rules get attack-chain tactics,
             config rules get configuration-specific tactics)
  Compliance → mapped by domain + severity + provider
               using standard multi-cloud framework IDs from the existing DB pattern

Usage:
  python3 scripts/generate_mitre_compliance.py [--dry-run] [--csp aws]
"""

import json, psycopg2, argparse, re
from collections import defaultdict

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

# Log/CIEM rules get attack-phase tactics
MITRE_CIEM_LOG = {
    'audit_log':        ['TA0003:Persistence', 'TA0004:Privilege Escalation', 'TA0007:Discovery'],
    'cloudtrail':       ['TA0005:Defense Evasion', 'TA0007:Discovery', 'TA0040:Impact'],
    'activity_log':     ['TA0007:Discovery', 'TA0003:Persistence'],
    'network_flow':     ['TA0007:Discovery', 'TA0011:Command and Control', 'TA0010:Exfiltration'],
    'threat_finding':   ['TA0001:Initial Access', 'TA0002:Execution', 'TA0040:Impact'],
    'security_finding': ['TA0001:Initial Access', 'TA0040:Impact'],
    'data_security':    ['TA0009:Collection', 'TA0010:Exfiltration'],
    'access_log':       ['TA0007:Discovery', 'TA0011:Command and Control'],
    'container':        ['TA0002:Execution', 'TA0004:Privilege Escalation', 'TA0008:Lateral Movement'],
}

# Config rules get domain-specific tactics
MITRE_BY_DOMAIN = {
    'identity_and_access_management':   ['TA0001:Initial Access', 'TA0003:Persistence', 'TA0004:Privilege Escalation'],
    'network_security':                  ['TA0001:Initial Access', 'TA0007:Discovery', 'TA0011:Command and Control'],
    'network_security_and_connectivity': ['TA0001:Initial Access', 'TA0007:Discovery', 'TA0011:Command and Control'],
    'data_security':                     ['TA0009:Collection', 'TA0010:Exfiltration', 'TA0040:Impact'],
    'data_protection_and_privacy':       ['TA0009:Collection', 'TA0010:Exfiltration'],
    'compute_and_workload_security':     ['TA0002:Execution', 'TA0005:Defense Evasion', 'TA0040:Impact'],
    'storage_security':                  ['TA0009:Collection', 'TA0010:Exfiltration'],
    'logging_monitoring_and_alerting':   ['TA0005:Defense Evasion', 'TA0007:Discovery'],
    'security_monitoring':               ['TA0005:Defense Evasion', 'TA0007:Discovery'],
    'container_security':                ['TA0002:Execution', 'TA0004:Privilege Escalation', 'TA0008:Lateral Movement'],
    'vulnerability_management':          ['TA0002:Execution', 'TA0040:Impact'],
    'compliance_and_governance':         ['TA0005:Defense Evasion', 'TA0003:Persistence'],
    'resilience_and_disaster_recovery':  ['TA0040:Impact'],
    'cryptography_and_key_management':   ['TA0006:Credential Access', 'TA0009:Collection'],
    'application_security':              ['TA0001:Initial Access', 'TA0002:Execution'],
    'cloud_security':                    ['TA0001:Initial Access', 'TA0007:Discovery'],
    'iam':                               ['TA0001:Initial Access', 'TA0003:Persistence', 'TA0004:Privilege Escalation'],
}

MITRE_DEFAULT = ['TA0007:Discovery', 'TA0005:Defense Evasion']


# ── Compliance Framework Mapping ─────────────────────────────────────────────

# Common multi-cloud compliance frameworks used in the DB (based on existing data patterns)
COMPLIANCE_BY_DOMAIN = {
    'identity_and_access_management': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'iso27001_2022_multi_cloud_A.9',
        'nist_800_53_rev5_multi_cloud_AC',
        'soc2_multi_cloud_cc_6',
    ],
    'network_security': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'nist_800_53_rev5_multi_cloud_SC',
        'iso27001_2022_multi_cloud_A.13',
        'pci_dss_v4_multi_cloud_1',
    ],
    'network_security_and_connectivity': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'nist_800_53_rev5_multi_cloud_SC',
        'iso27001_2022_multi_cloud_A.13',
    ],
    'data_security': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'iso27001_2022_multi_cloud_A.10',
        'nist_800_53_rev5_multi_cloud_SC',
        'pci_dss_v4_multi_cloud_3',
        'hipaa_multi_cloud_164.312',
    ],
    'data_protection_and_privacy': [
        'iso27001_2022_multi_cloud_A.8',
        'gdpr_multi_cloud_art_32',
        'nist_800_53_rev5_multi_cloud_SC',
        'hipaa_multi_cloud_164.312',
    ],
    'compute_and_workload_security': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'nist_800_53_rev5_multi_cloud_CM',
        'iso27001_2022_multi_cloud_A.12',
    ],
    'storage_security': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'iso27001_2022_multi_cloud_A.10',
        'nist_800_53_rev5_multi_cloud_SC',
        'pci_dss_v4_multi_cloud_3',
    ],
    'logging_monitoring_and_alerting': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'iso27001_2022_multi_cloud_A.12.4',
        'nist_800_53_rev5_multi_cloud_AU',
        'soc2_multi_cloud_cc_7',
    ],
    'security_monitoring': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'nist_800_53_rev5_multi_cloud_AU',
        'soc2_multi_cloud_cc_7',
    ],
    'container_security': [
        'cis_kubernetes_kubernetes_1.6',
        'nist_800_53_rev5_multi_cloud_CM',
        'iso27001_2022_multi_cloud_A.12',
    ],
    'vulnerability_management': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'nist_800_53_rev5_multi_cloud_RA',
        'iso27001_2022_multi_cloud_A.12.6',
        'pci_dss_v4_multi_cloud_6',
    ],
    'cryptography_and_key_management': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'iso27001_2022_multi_cloud_A.10',
        'nist_800_53_rev5_multi_cloud_SC',
        'pci_dss_v4_multi_cloud_3.5',
    ],
    'compliance_and_governance': [
        'iso27001_2022_multi_cloud_A.18',
        'soc2_multi_cloud_cc_a_1',
        'nist_800_53_rev5_multi_cloud_CA',
    ],
    'resilience_and_disaster_recovery': [
        'iso27001_2022_multi_cloud_A.17',
        'nist_800_53_rev5_multi_cloud_CP',
        'soc2_multi_cloud_a_1',
    ],
    'application_security': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'nist_800_53_rev5_multi_cloud_SI',
        'owasp_top10_multi_cloud',
    ],
    'cloud_security': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'nist_800_53_rev5_multi_cloud_CM',
        'iso27001_2022_multi_cloud_A.12',
    ],
    'iam': [
        'cis_foundations_benchmark_1.4_multi_cloud',
        'iso27001_2022_multi_cloud_A.9',
        'nist_800_53_rev5_multi_cloud_AC',
        'soc2_multi_cloud_cc_6',
    ],
}

COMPLIANCE_DEFAULT = [
    'cis_foundations_benchmark_1.4_multi_cloud',
    'iso27001_2022_multi_cloud_A.12',
    'nist_800_53_rev5_multi_cloud_CM',
]

# For CIEM log rules
COMPLIANCE_CIEM = [
    'cis_foundations_benchmark_1.4_multi_cloud',
    'iso27001_2022_multi_cloud_A.12.4',
    'nist_800_53_rev5_multi_cloud_AU',
    'soc2_multi_cloud_cc_7',
    'pci_dss_v4_multi_cloud_10',
]


def detect_log_type(rule_id: str) -> str | None:
    """Detect if a rule is a log/event rule and return its type."""
    patterns = [
        (r'\.audit_log\.', 'audit_log'),
        (r'\.cloudtrail\.', 'cloudtrail'),
        (r'\.activity_tracker\.', 'activity_log'),
        (r'\.gke_audit\.', 'audit_log'),
        (r'\.nsg_flow\.', 'network_flow'),
        (r'\.vpc_flow\.', 'network_flow'),
        (r'\.guardduty\.', 'threat_finding'),
        (r'\.securityhub\.', 'security_finding'),
        (r'\.datasec\.', 'data_security'),
        (r'container\.(k8s|ct)\.', 'container'),
    ]
    for pat, log_type in patterns:
        if re.search(pat, rule_id, re.IGNORECASE):
            return log_type
    return None


def get_mitre(rule_id: str, domain: str, check_type: str) -> list:
    log_type = detect_log_type(rule_id)
    if check_type == 'log' or log_type:
        return MITRE_CIEM_LOG.get(log_type or 'audit_log', MITRE_DEFAULT)
    return MITRE_BY_DOMAIN.get(domain or '', MITRE_DEFAULT)


def get_compliance(rule_id: str, domain: str, check_type: str, severity: str) -> list:
    log_type = detect_log_type(rule_id)
    if check_type == 'log' or log_type:
        return COMPLIANCE_CIEM

    base = COMPLIANCE_BY_DOMAIN.get(domain or '', COMPLIANCE_DEFAULT)

    # Add severity-specific frameworks
    if severity in ('critical', 'high'):
        extra = ['pci_dss_v4_multi_cloud_12', 'hipaa_multi_cloud_164.308']
        return list(dict.fromkeys(base + extra))  # dedup preserving order
    return base


def run(csps: list, dry_run: bool):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    grand_mitre = grand_compliance = 0

    for csp in csps:
        # Get rules missing mitre OR compliance
        cur.execute("""
            SELECT rm.rule_id, rm.domain, rm.severity, rc.check_type
            FROM rule_metadata rm
            LEFT JOIN rule_checks rc ON rc.rule_id = rm.rule_id
            WHERE rm.provider = %s AND rm.customer_id IS NULL
              AND (
                  rm.mitre_tactics IS NULL OR rm.mitre_tactics::text IN ('null','[]')
                  OR rm.compliance_frameworks IS NULL OR rm.compliance_frameworks::text IN ('null','[]','{}')
              )
        """, (csp,))
        rows = cur.fetchall()

        mitre_updated = compliance_updated = 0

        for rule_id, domain, severity, check_type in rows:
            mitre = get_mitre(rule_id, domain or '', check_type or 'config')
            compliance = get_compliance(rule_id, domain or '', check_type or 'config', severity or 'medium')

            if dry_run:
                if mitre_updated + compliance_updated < 2:
                    print(f"  [DRY] {rule_id}")
                    print(f"        mitre:      {mitre}")
                    print(f"        compliance: {compliance[:3]}...")
            else:
                cur.execute("""
                    UPDATE rule_metadata SET
                        mitre_tactics = CASE
                            WHEN mitre_tactics IS NULL OR mitre_tactics::text IN ('null','[]')
                            THEN %s::jsonb ELSE mitre_tactics END,
                        compliance_frameworks = CASE
                            WHEN compliance_frameworks IS NULL OR compliance_frameworks::text IN ('null','[]','{}')
                            THEN %s::jsonb ELSE compliance_frameworks END,
                        updated_at = NOW()
                    WHERE rule_id = %s AND customer_id IS NULL
                """, (json.dumps(mitre), json.dumps(compliance), rule_id))

            mitre_updated += 1
            compliance_updated += 1

        if not dry_run:
            conn.commit()

        print(f"{csp:10s}: {len(rows):5d} rules processed | mitre_tags={mitre_updated} | compliance_tags={compliance_updated}")
        grand_mitre += mitre_updated
        grand_compliance += compliance_updated

    prefix = "[DRY] " if dry_run else ""
    print(f"\n{prefix}Total: {grand_mitre} MITRE tags, {grand_compliance} compliance tags generated")
    cur.close()
    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--csp', default=None)
    args = parser.parse_args()

    all_csps = ['aws', 'azure', 'gcp', 'ibm', 'alicloud', 'k8s', 'oci']
    csps = [c.strip() for c in args.csp.split(',')] if args.csp else all_csps
    run(csps, args.dry_run)
