#!/usr/bin/env python3
"""
generate_rule_metadata.py
=========================
Generate standardized rule metadata YAML files for all CSPs.

Covers:
 - Check rules from *_rule_check/{svc}/{svc}.checks.yaml
 - CIEM  rules from *_rule_ciem/**/*.yaml
 - Skips entries that already exist (unless --overwrite)

Output: catalog/rule/{csp}_rule_metadata/{svc}/{rule_id}.yaml

Usage:
    python generate_rule_metadata.py --csp gcp               # dry-run GCP
    python generate_rule_metadata.py --csp ibm --apply       # write IBM
    python generate_rule_metadata.py --apply                  # write all
    python generate_rule_metadata.py --apply --overwrite      # regenerate all
"""

from __future__ import annotations
import re, sys
from collections import defaultdict
from pathlib import Path
from typing import Optional
import yaml

ROOT     = Path('/Users/apple/Desktop/threat-engine')
RULE_DIR = ROOT / 'catalog/rule'

APPLY     = '--apply'     in sys.argv
OVERWRITE = '--overwrite' in sys.argv
TARGET_CSP: Optional[str] = None
if '--csp' in sys.argv:
    idx = sys.argv.index('--csp')
    if idx + 1 < len(sys.argv):
        TARGET_CSP = sys.argv[idx + 1].lower()

if not APPLY:
    print('*** DRY RUN — pass --apply to write files ***')
print()

# ──────────────────────────────────────────────────────────────────────────────
# Domain inference from rule_id / service / requirement keywords
# ──────────────────────────────────────────────────────────────────────────────

DOMAIN_KEYWORDS = {
    'identity_and_access_management': [
        'iam', 'role', 'policy', 'permission', 'access', 'user', 'group',
        'account', 'mfa', 'auth', 'principal', 'privilege', 'rbac', 'identity',
        'credential', 'service_account', 'trusted_profile', 'access_group',
        'password', 'apikey', 'serviceids',
    ],
    'network_security_and_connectivity': [
        'firewall', 'network', 'vpc', 'subnet', 'security_group', 'nacl',
        'acl', 'ingress', 'egress', 'port', 'flow_log', 'dns', 'routing',
        'load_balancer', 'alb', 'nlb', 'cdn', 'waf', 'vpn', 'gateway',
        'endpoint', 'peer', 'transit', 'cen', 'expressconnect',
    ],
    'data_protection_and_privacy': [
        'encrypt', 'kms', 'key', 'tls', 'ssl', 'cipher', 'secret', 'certificate',
        'rotation', 'cmk', 'byok', 'hpcs', 'key_protect', 'vault',
        'bucket', 'object_storage', 'cos', 'oss', 's3', 'blob', 'storage',
        'database', 'db', 'rds', 'sql', 'backup', 'snapshot', 'volume',
    ],
    'logging_monitoring_and_alerting': [
        'log', 'audit', 'monitor', 'alert', 'trail', 'event', 'activity',
        'metric', 'notification', 'alarm', 'insight', 'detective', 'scc',
        'cloudwatch', 'flowlog', 'logging', 'actiontrail',
    ],
    'compliance_and_governance': [
        'tag', 'tagging', 'governance', 'compliance', 'config', 'policy_attest',
        'retention', 'lifecycle', 'resource_group', 'label', 'standard',
    ],
    'infrastructure_security': [
        'compute', 'instance', 'vm', 'server', 'vsi', 'ec2', 'patch',
        'image', 'ami', 'launch_template', 'metadata', 'imds', 'ssm',
        'host', 'dedicated', 'bare_metal', 'node', 'hypervisor',
    ],
    'container_and_kubernetes_security': [
        'container', 'k8s', 'kubernetes', 'pod', 'cluster', 'namespace',
        'daemonset', 'deployment', 'replicaset', 'statefulset', 'cronjob',
        'ingress_controller', 'serviceaccount', 'rbac', 'iks', 'gke', 'aks',
        'ack', 'admission', 'networkpolicy',
    ],
    'resilience_and_disaster_recovery': [
        'backup', 'recovery', 'replication', 'multi_az', 'multi_region',
        'failover', 'snapshot', 'restore', 'availability', 'hdr',
    ],
    'secrets_and_key_management': [
        'secret', 'key_management', 'kms', 'hsm', 'hpcs', 'key_protect',
        'certificate_manager', 'vault', 'rotation', 'apikey',
    ],
    'application_and_api_security': [
        'api', 'apigw', 'apigateway', 'lambda', 'function', 'app',
        'web', 'code_engine', 'schematics', 'serverless', 'fc', 'faas',
        'event_streams', 'messaging', 'queue', 'topic',
    ],
    'compute_and_workload_security': [
        'workload', 'runtime', 'process', 'privilege', 'capability',
        'seccomp', 'apparmor', 'selinux',
    ],
    'storage_and_database_security': [
        'database', 'db', 'rds', 'nosql', 'redis', 'memcached',
        'elasticsearch', 'opensearch', 'cassandra', 'mongo', 'postgres',
        'mysql', 'cloud_databases', 'cloudant', 'analyticdb',
    ],
    'threat_detection_and_incident_response': [
        'threat', 'detection', 'incident', 'guard', 'inspector', 'macie',
        'securityhub', 'siem', 'soc', 'investigation',
    ],
}


def infer_domain(rule_id: str, service: str, requirement: str) -> str:
    text = f'{rule_id} {service} {requirement}'.lower().replace('.', ' ').replace('_', ' ')
    scores: dict[str, int] = defaultdict(int)
    for domain, kws in DOMAIN_KEYWORDS.items():
        for kw in kws:
            if kw.replace('_', ' ') in text:
                scores[domain] += 1
    if scores:
        return max(scores, key=lambda k: scores[k])
    return 'configuration_and_change_management'


SUBCATEGORY_MAP = {
    'identity_and_access_management': 'access_control',
    'network_security_and_connectivity': 'network_controls',
    'data_protection_and_privacy': 'encryption',
    'logging_monitoring_and_alerting': 'audit_logging',
    'compliance_and_governance': 'governance',
    'infrastructure_security': 'system_hardening',
    'container_and_kubernetes_security': 'container_security',
    'resilience_and_disaster_recovery': 'backup_recovery',
    'secrets_and_key_management': 'key_management',
    'application_and_api_security': 'api_security',
    'compute_and_workload_security': 'workload_security',
    'storage_and_database_security': 'data_security',
    'threat_detection_and_incident_response': 'threat_detection',
}

# CIEM threat category inference
THREAT_KEYWORDS = {
    'initial_access':       ['login', 'signin', 'authenticate', 'access_key', 'token'],
    'persistence':          ['create', 'add', 'register', 'attach', 'enable', 'update_role'],
    'privilege_escalation': ['assume_role', 'pass_role', 'escalat', 'admin', 'root', 'privilege'],
    'defense_evasion':      ['delete_log', 'disable_log', 'stop_trail', 'disable_trail',
                             'destroy', 'evasion', 'modify_policy'],
    'credential_access':    ['credential', 'password', 'key_pair', 'secret', 'apikey'],
    'discovery':            ['list_', 'describe_', 'get_', 'enumerate', 'scan'],
    'lateral_movement':     ['assume', 'federate', 'switch', 'trust'],
    'exfiltration':         ['copy', 'export', 'download', 'put_object', 'share', 'public'],
    'impact':               ['delete', 'terminate', 'destroy', 'wipe', 'format'],
}

MITRE_MAP = {
    'initial_access':       ('TA0001', ['T1078', 'T1566']),
    'persistence':          ('TA0003', ['T1098', 'T1136']),
    'privilege_escalation': ('TA0004', ['T1548', 'T1068']),
    'defense_evasion':      ('TA0005', ['T1562', 'T1070']),
    'credential_access':    ('TA0006', ['T1552', 'T1528']),
    'discovery':            ('TA0007', ['T1087', 'T1526']),
    'lateral_movement':     ('TA0008', ['T1550', 'T1534']),
    'exfiltration':         ('TA0010', ['T1537', 'T1530']),
    'impact':               ('TA0040', ['T1485', 'T1489']),
}

RISK_SCORE_MAP = {
    'critical': 90, 'high': 70, 'medium': 50, 'low': 30,
}

CSP_DOC_URLS = {
    'aws':      'https://docs.aws.amazon.com/',
    'azure':    'https://docs.microsoft.com/azure/',
    'gcp':      'https://cloud.google.com/docs/',
    'oci':      'https://docs.oracle.com/iaas/',
    'alicloud': 'https://www.alibabacloud.com/help/',
    'ibm':      'https://cloud.ibm.com/docs/',
    'k8s':      'https://kubernetes.io/docs/',
}


def infer_threat_category(rule_id: str) -> str:
    rid_lower = rule_id.lower()
    for cat, kws in THREAT_KEYWORDS.items():
        for kw in kws:
            if kw in rid_lower:
                return cat
    return 'discovery'


def req_from_rule_id(rule_id: str) -> str:
    """Extract human-readable requirement from rule_id last segment."""
    last = rule_id.split('.')[-1]
    return last.replace('_', ' ').title()


def title_from_rule_id(csp: str, svc: str, resource: str, req: str) -> str:
    return f'{csp.upper()} {svc.upper()} {resource.replace("_", " ").title()}: {req}'


def description_for_check(rule_id: str, svc: str, resource: str, req: str, csp: str) -> str:
    return (
        f'Validates that {csp.upper()} {svc} {resource.replace("_", " ")} has '
        f'{req.lower()} configured according to security best practices. '
        f'Proper configuration reduces security risks, prevents unauthorized '
        f'access, and ensures compliance with industry standards and regulations.'
    )


def rationale_for_check(svc: str, resource: str, req: str, csp: str) -> str:
    return (
        f'Ensures {csp.upper()} {svc} {resource.replace("_", " ")} has '
        f'{req.lower()} properly configured for security compliance. '
        f'This control is essential for maintaining a strong security posture '
        f'and meeting regulatory requirements.'
    )


def remediation_for_check(req: str, csp: str) -> str:
    return (
        f'Review and remediate the {req} configuration according to '
        f'{csp.upper()} security best practices and organisational policy. '
        f'Refer to the {csp.upper()} documentation for step-by-step remediation guidance.'
    )


# ──────────────────────────────────────────────────────────────────────────────
# Build metadata dict
# ──────────────────────────────────────────────────────────────────────────────

def build_check_metadata(rule_id: str, severity: str, csp: str) -> dict:
    parts = rule_id.split('.')            # e.g. aws.ec2.instance.encrypted
    svc      = parts[1] if len(parts) > 1 else csp
    resource = parts[2] if len(parts) > 2 else svc
    req      = req_from_rule_id(rule_id)

    domain    = infer_domain(rule_id, svc, req)
    subcat    = SUBCATEGORY_MAP.get(domain, 'configuration')
    doc_url   = CSP_DOC_URLS.get(csp, 'https://docs.example.com/') + svc

    return {
        'rule_id':         rule_id,
        'title':           title_from_rule_id(csp, svc, resource, req),
        'scope':           f'{svc}.{resource}',
        'domain':          domain,
        'subcategory':     subcat,
        'severity':        severity.lower(),
        'service':         svc,
        'resource':        resource,
        'requirement':     req,
        'description':     description_for_check(rule_id, svc, resource, req, csp),
        'rationale':       rationale_for_check(svc, resource, req, csp),
        'remediation':     remediation_for_check(req, csp),
        'references':      [doc_url],
        'compliance':      [],
        'source':          'auto_generated',
        'metadata_source': 'auto_generated',
        'generated_by':    f'{csp}_rule_generator',
    }


def build_ciem_metadata(rule: dict, csp: str) -> dict:
    rule_id  = rule.get('rule_id', '')
    severity = rule.get('severity', 'medium')
    parts    = rule_id.split('.')
    svc      = parts[1] if len(parts) > 1 else csp
    resource = parts[2] if len(parts) > 2 else svc
    req      = req_from_rule_id(rule_id)

    threat_cat = rule.get('threat_category') or infer_threat_category(rule_id)
    mitre_ta, mitre_te = MITRE_MAP.get(threat_cat, ('TA0007', ['T1526']))
    risk_score = RISK_SCORE_MAP.get(severity.lower(), 50)
    domain = infer_domain(rule_id, svc, req)
    subcat = SUBCATEGORY_MAP.get(domain, 'threat_detection')
    doc_url = CSP_DOC_URLS.get(csp, 'https://docs.example.com/') + svc

    d: dict = {
        'rule_id':         rule_id,
        'rule_type':       'ciem',
        'title':           rule.get('title') or title_from_rule_id(csp, svc, resource, req),
        'scope':           f'{svc}.{resource}',
        'domain':          domain,
        'subcategory':     subcat,
        'severity':        severity.lower(),
        'service':         svc,
        'resource':        resource,
        'requirement':     req,
        'description':     rule.get('description') or description_for_check(rule_id, svc, resource, req, csp),
        'rationale':       rule.get('rationale') or rationale_for_check(svc, resource, req, csp),
        'remediation':     rule.get('remediation') or remediation_for_check(req, csp),
        'references':      rule.get('references') or [doc_url],
        'compliance':      rule.get('compliance_frameworks') or [],
        'threat_category': threat_cat,
        'mitre_tactics':   rule.get('mitre_tactics') or [mitre_ta],
        'mitre_techniques':rule.get('mitre_techniques') or mitre_te,
        'risk_score':      rule.get('risk_score') or risk_score,
        'action_category': rule.get('action_category') or 'write',
        'source':          rule.get('source') or 'auto_generated',
        'metadata_source': 'auto_generated',
        'generated_by':    f'{csp}_ciem_generator',
    }
    return d


# ──────────────────────────────────────────────────────────────────────────────
# Per-CSP loader
# ──────────────────────────────────────────────────────────────────────────────

def load_existing_meta_ids(meta_dir: Path) -> set:
    ids = set()
    if meta_dir.exists():
        for f in meta_dir.rglob('*.yaml'):
            try:
                d = yaml.safe_load(f.read_text()) or {}
                rid = d.get('rule_id', '')
                if rid:
                    ids.add(rid)
            except Exception:
                pass
    return ids


def collect_check_rules(check_dir: Path) -> list[dict]:
    rules = []
    if not check_dir.exists():
        return rules
    for f in sorted(check_dir.rglob('*.checks.yaml')):
        try:
            d = yaml.safe_load(f.read_text()) or {}
        except Exception:
            continue
        for c in d.get('checks', []):
            if c.get('rule_id'):
                rules.append(c)
    return rules


def collect_ciem_rules(ciem_dir: Path) -> list[dict]:
    rules = []
    if not ciem_dir.exists():
        return rules
    for f in sorted(ciem_dir.rglob('*.yaml')):
        try:
            d = yaml.safe_load(f.read_text()) or {}
        except Exception:
            continue
        if d.get('rule_id'):
            rules.append(d)
    return rules


def svc_from_rule_id(rule_id: str) -> str:
    parts = rule_id.split('.')
    return parts[1] if len(parts) > 1 else 'general'


def write_metadata(meta_dir: Path, rule_id: str, meta: dict) -> Path:
    import hashlib
    svc = svc_from_rule_id(rule_id)
    svc_dir = meta_dir / svc
    svc_dir.mkdir(parents=True, exist_ok=True)
    fname = f'{rule_id}.yaml'
    # macOS/Linux max filename = 255 bytes; truncate with hash suffix if needed
    if len(fname.encode()) > 240:
        h = hashlib.sha1(rule_id.encode()).hexdigest()[:8]
        fname = f'{rule_id[:200]}__{h}.yaml'
    out = svc_dir / fname
    with out.open('w') as f:
        yaml.dump(meta, f,
                  default_flow_style=False,
                  allow_unicode=True,
                  indent=2,
                  sort_keys=False)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────────────────────

ALL_CSPS = ['aws', 'azure', 'gcp', 'oci', 'alicloud', 'ibm', 'k8s']
csps = [TARGET_CSP] if TARGET_CSP else ALL_CSPS

for csp in csps:
    check_dir = RULE_DIR / f'{csp}_rule_check'
    ciem_dir  = RULE_DIR / f'{csp}_rule_ciem'
    meta_dir  = RULE_DIR / f'{csp}_rule_metadata'

    existing = load_existing_meta_ids(meta_dir)

    check_rules = collect_check_rules(check_dir)
    ciem_rules  = collect_ciem_rules(ciem_dir)

    # Determine what needs to be written
    check_needed = [r for r in check_rules
                    if r.get('rule_id') and (OVERWRITE or r['rule_id'] not in existing)]
    ciem_needed  = [r for r in ciem_rules
                    if r.get('rule_id') and (OVERWRITE or r['rule_id'] not in existing)]

    total_needed = len(check_needed) + len(ciem_needed)
    print(f'[{csp.upper():<10}] checks={len(check_rules):>5} ciem={len(ciem_rules):>4} | '
          f'existing meta={len(existing):>5} | to write={total_needed:>5}')

    if not APPLY or total_needed == 0:
        continue

    written_check = written_ciem = 0

    for rule in check_needed:
        rid = rule['rule_id']
        sev = rule.get('severity', 'medium')
        meta = build_check_metadata(rid, sev, csp)
        write_metadata(meta_dir, rid, meta)
        written_check += 1

    for rule in ciem_needed:
        rid = rule['rule_id']
        meta = build_ciem_metadata(rule, csp)
        write_metadata(meta_dir, rid, meta)
        written_ciem += 1

    print(f'  → wrote {written_check} check + {written_ciem} ciem metadata files')

print()
print('Done.')
