#!/usr/bin/env python3
"""
Generate template remediation text for config-check rules that have rationale
but no remediation. These are the non-AWS rules loaded from the Feb backup
whose metadata YAMLs didn't have remediation content.

Usage:
  python3 scripts/generate_config_rule_remediation.py [--dry-run]
"""

import re, json, psycopg2, argparse

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# Provider-specific console names
CONSOLE_NAMES = {
    'aws':      'AWS Management Console',
    'azure':    'Azure Portal',
    'gcp':      'Google Cloud Console',
    'oci':      'Oracle Cloud Infrastructure Console',
    'ibm':      'IBM Cloud Console',
    'alicloud': 'Alibaba Cloud Console',
    'k8s':      'Kubernetes Dashboard / kubectl',
}

# Compliance references per provider
COMPLIANCE_REFS = {
    'aws':      ['https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html'],
    'azure':    ['https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns'],
    'gcp':      ['https://cloud.google.com/security/best-practices'],
    'oci':      ['https://docs.oracle.com/en-us/iaas/Content/Security/Concepts/security_guide.htm'],
    'ibm':      ['https://cloud.ibm.com/docs/framework-financial-services'],
    'alicloud': ['https://www.alibabacloud.com/trust-center/compliance'],
    'k8s':      ['https://kubernetes.io/docs/concepts/security/'],
}

def humanize(s: str) -> str:
    return ' '.join(w.capitalize() for w in re.split(r'[._\-]', s))


def extract_requirement(rule_id: str, title: str) -> str:
    """Extract the security requirement from rule_id or title."""
    if title and len(title) > 15 and title != rule_id:
        # Clean up auto-generated titles like "AZURE STORAGE File: Share Soft Delete Enabled"
        # → "share soft delete enabled"
        cleaned = re.sub(r'^[A-Z]+ [A-Z]+ [A-Za-z_]+: ', '', title)
        return cleaned if cleaned else title
    parts = rule_id.split('.')
    return humanize(parts[-1]) if parts else rule_id


def extract_service_resource(rule_id: str) -> tuple:
    """Returns (service, resource_type) from rule_id."""
    parts = rule_id.split('.')
    service = humanize(parts[1]) if len(parts) > 1 else 'Cloud Resource'
    resource = humanize(parts[2]) if len(parts) > 2 else service
    return service, resource


def build_remediation(rule_id: str, title: str, provider: str) -> str:
    console = CONSOLE_NAMES.get(provider, 'Cloud Console')
    requirement = extract_requirement(rule_id, title or '')
    service, resource = extract_service_resource(rule_id)

    return (
        f"Configure {resource} for compliance with '{requirement}':\n\n"
        f"Steps:\n"
        f"1. Open the {console}\n"
        f"2. Navigate to the {service} service\n"
        f"3. Select the affected {resource.lower()} resource(s)\n"
        f"4. Review the current configuration\n"
        f"5. Apply the required setting: {requirement}\n"
        f"6. Verify the change is reflected in the configuration\n"
        f"7. Save and confirm the update\n\n"
        f"Security Recommendations:\n"
        f"• Follow {console.split()[0]} Security Best Practices\n"
        f"• Implement defense in depth\n"
        f"• Enable logging and monitoring for configuration changes\n"
        f"• Use automation (IaC/Policy-as-Code) to enforce this setting at scale\n"
        f"• Regular security audits to verify compliance"
    )


def build_references(rule_id: str, provider: str) -> list:
    refs = list(COMPLIANCE_REFS.get(provider, []))
    # Add service-specific docs where we can infer the service
    parts = rule_id.split('.')
    service = parts[1] if len(parts) > 1 else ''

    service_doc_patterns = {
        'aws': {
            's3': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html',
            'iam': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
            'ec2': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html',
            'rds': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html',
            'kms': 'https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html',
        },
        'azure': {
            'storage': 'https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations',
            'keyvault': 'https://docs.microsoft.com/en-us/azure/key-vault/general/best-practices',
            'network': 'https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices',
            'iam': 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-deployment-checklist-p2',
        },
        'gcp': {
            'iam': 'https://cloud.google.com/iam/docs/using-iam-securely',
            'compute': 'https://cloud.google.com/compute/docs/security',
            'storage': 'https://cloud.google.com/storage/docs/best-practices',
        },
        'k8s': {
            'rbac': 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/',
            'network': 'https://kubernetes.io/docs/concepts/services-networking/network-policies/',
            'pod': 'https://kubernetes.io/docs/concepts/security/pod-security-standards/',
        },
    }

    if provider in service_doc_patterns and service in service_doc_patterns[provider]:
        refs.append(service_doc_patterns[provider][service])

    return refs


def run(dry_run: bool):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        SELECT rule_id, title, provider
        FROM rule_metadata
        WHERE customer_id IS NULL
          AND (remediation IS NULL OR remediation = '')
          AND (rationale IS NOT NULL AND rationale != '')
        ORDER BY provider, rule_id
    """)
    rows = cur.fetchall()
    print(f"Rules needing remediation: {len(rows)}")

    # Count by provider
    from collections import Counter
    by_prov = Counter(r[2] for r in rows)
    for prov, count in sorted(by_prov.items()):
        print(f"  {prov}: {count}")
    print()

    updated = 0
    for rule_id, title, provider in rows:
        remediation = build_remediation(rule_id, title or '', provider)
        refs = build_references(rule_id, provider)

        if dry_run:
            if updated < 3:
                print(f"[DRY] {rule_id}")
                print(f"      {remediation[:100]}...")
            updated += 1
            continue

        cur.execute("""
            UPDATE rule_metadata SET
                remediation  = %(remediation)s,
                "references" = CASE
                    WHEN "references" IS NULL OR "references"::text IN ('null', '[]')
                    THEN %(references)s::jsonb
                    ELSE "references"
                END,
                updated_at   = NOW()
            WHERE rule_id = %(rule_id)s AND customer_id IS NULL
        """, {
            'rule_id':     rule_id,
            'remediation': remediation,
            'references':  json.dumps(refs),
        })
        if cur.rowcount:
            updated += 1

    if not dry_run:
        conn.commit()
        print(f"Updated {updated} rules with remediation")

    cur.close()
    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    run(args.dry_run)
