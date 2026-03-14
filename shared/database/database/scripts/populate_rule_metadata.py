#!/usr/bin/env python3
"""
Populate rule_metadata table from metadata YAML files.
Reads from: engine_input/engine_configscan_aws/input/rule_db/default/services/*/metadata/*.yaml
Inserts into: threat_engine_check.rule_metadata table
"""
import os
import sys
import yaml
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import psycopg2
from psycopg2.extras import Json

DEFAULT_METADATA_DIR = os.path.join(
    ROOT, "engine_input", "engine_configscan_aws", "input", "rule_db", "default", "services"
)


def get_check_db_config():
    """Read config from env (CHECK_DB_*)"""
    return {
        "host": os.getenv("CHECK_DB_HOST", "localhost"),
        "port": int(os.getenv("CHECK_DB_PORT", "5432")),
        "database": os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        "user": os.getenv("CHECK_DB_USER", "check_user"),
        "password": os.getenv("CHECK_DB_PASSWORD", "check_password"),
    }


def parse_metadata_yaml(yaml_path: Path) -> dict:
    """Parse metadata YAML and extract fields for rule_metadata table"""
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or not isinstance(data, dict):
            return None
        
        rule_id = data.get('rule_id') or data.get('assertion_id')
        if not rule_id:
            return None
        
        return {
            'rule_id': rule_id,
            'service': data.get('service', ''),
            'provider': data.get('provider', 'aws'),
            'resource': data.get('resource', ''),
            'severity': data.get('severity', 'medium'),
            'title': data.get('title', ''),
            'description': data.get('description', ''),
            'remediation': data.get('remediation', ''),
            'rationale': data.get('rationale', ''),
            'domain': data.get('domain', ''),
            'subcategory': data.get('subcategory', ''),
            'requirement': data.get('requirement', ''),
            'assertion_id': data.get('assertion_id', ''),
            'compliance_frameworks': data.get('compliance_frameworks', []),
            'data_security': data.get('data_security', {}),
            'references': data.get('references', []),
            'resource_service': data.get('resource_service', data.get('service', '')),
        }
    except Exception as e:
        print(f"  Error parsing {yaml_path}: {e}")
        return None


def populate_metadata(services_dir: str = None, upsert: bool = True):
    services_dir = services_dir or DEFAULT_METADATA_DIR
    services_path = Path(services_dir)
    if not services_path.is_dir():
        raise FileNotFoundError(f"Services dir not found: {services_dir}")
    
    config = get_check_db_config()
    conn = psycopg2.connect(**config)
    cur = conn.cursor()
    
    sql = """
    INSERT INTO rule_metadata (
        rule_id, service, provider, resource, resource_service, severity, title,
        description, remediation, rationale, domain, subcategory, requirement,
        assertion_id, compliance_frameworks, data_security, "references"
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    )
    ON CONFLICT (rule_id) DO UPDATE SET
        service = EXCLUDED.service,
        provider = EXCLUDED.provider,
        resource = EXCLUDED.resource,
        resource_service = EXCLUDED.resource_service,
        severity = EXCLUDED.severity,
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        remediation = EXCLUDED.remediation,
        rationale = EXCLUDED.rationale,
        domain = EXCLUDED.domain,
        subcategory = EXCLUDED.subcategory,
        requirement = EXCLUDED.requirement,
        assertion_id = EXCLUDED.assertion_id,
        compliance_frameworks = EXCLUDED.compliance_frameworks,
        data_security = EXCLUDED.data_security,
        "references" = EXCLUDED."references",
        updated_at = NOW();
    """ if upsert else """
    INSERT INTO rule_metadata (
        rule_id, service, provider, resource, resource_service, severity, title,
        description, remediation, rationale, domain, subcategory, requirement,
        assertion_id, compliance_frameworks, data_security, "references"
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    );
    """
    
    count = 0
    for service_dir in sorted(services_path.iterdir()):
        if not service_dir.is_dir():
            continue
        
        metadata_dir = service_dir / "metadata"
        if not metadata_dir.exists():
            continue
        
        for yaml_path in metadata_dir.glob("*.yaml"):
            metadata = parse_metadata_yaml(yaml_path)
            if not metadata:
                continue
            
            try:
                cur.execute(sql, (
                    metadata['rule_id'],
                    metadata['service'],
                    metadata['provider'],
                    metadata['resource'],
                    metadata['resource_service'],
                    metadata['severity'],
                    metadata['title'],
                    metadata['description'],
                    metadata['remediation'],
                    metadata['rationale'],
                    metadata['domain'],
                    metadata['subcategory'],
                    metadata['requirement'],
                    metadata['assertion_id'],
                    Json(metadata['compliance_frameworks']),
                    Json(metadata['data_security']),
                    Json(metadata['references']),
                ))
                count += 1
                if count % 100 == 0:
                    print(f"  uploaded {count} metadata entries...")
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Insert failed {metadata['rule_id']}: {e}") from e
    
    conn.commit()
    cur.close()
    conn.close()
    return count


def main():
    import argparse
    p = argparse.ArgumentParser(description="Populate rule_metadata from metadata YAMLs")
    p.add_argument("--services-dir", default=DEFAULT_METADATA_DIR, help="Path to services folder")
    p.add_argument("--no-upsert", action="store_true", help="Fail on duplicate instead of update")
    args = p.parse_args()
    n = populate_metadata(services_dir=args.services_dir, upsert=not args.no_upsert)
    print(f"Done. Populated {n} rule_metadata row(s).")


if __name__ == "__main__":
    main()
