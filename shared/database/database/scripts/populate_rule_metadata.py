#!/usr/bin/env python3
"""
Populate rule_metadata table from metadata YAML files.
Reads from: engine_input/engine_configscan_aws/input/rule_db/default/services/*/metadata/*.yaml
Inserts into: threat_engine_check.rule_metadata table

Engine scope JSONB columns (data_security, encryption_security, container_security,
database_security, ai_security) are computed from service + domain — no hard-coded
lists in engine Python code and no need to update individual YAML files.
The mappings below are the single source of truth for engine routing.
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

# ── Engine scope mappings ─────────────────────────────────────────────────────
# These are the SINGLE SOURCE OF TRUTH for which services/domains belong to
# each domain engine. Edit here when adding new services — never in engine code.

_DATA_SECURITY_DOMAINS = frozenset({
    "data_protection_and_privacy",
    "storage_and_database_security",
    "secrets_and_key_management",
    "cryptography_and_key_management",
})
_DATA_SECURITY_MODULE_MAP = {
    "data_protection_and_privacy":    ["data_protection_encryption", "data_access_governance", "data_classification"],
    "storage_and_database_security":  ["data_protection_encryption", "data_access_governance"],
    "secrets_and_key_management":     ["data_protection_encryption"],
    "cryptography_and_key_management":["data_protection_encryption"],
}
_DATA_SECURITY_CATEGORY_MAP = {
    "data_protection_and_privacy":    ["data_protection", "privacy", "sensitive_data_protection"],
    "storage_and_database_security":  ["storage_security", "database_security"],
    "secrets_and_key_management":     ["encryption", "key_management", "secrets"],
    "cryptography_and_key_management":["encryption", "cryptography"],
}
_DATA_SECURITY_PRIORITY_MAP = {
    "secrets_and_key_management": "critical",
}

_ENCRYPTION_SERVICES = frozenset({
    # AWS
    "kms", "acm", "acm-pca", "secretsmanager",
    # Azure
    "keyvault", "certificates",
    # GCP
    "cloudkms",
    # OCI
    "vault", "key_management",
    # AliCloud
    "kms_openapi",
})
_ENCRYPTION_DOMAINS = frozenset({
    "secrets_and_key_management",
    "cryptography_and_key_management",
})

_CONTAINER_SERVICES = frozenset({
    # AWS
    "eks", "ecs", "ecr", "fargate", "lambda", "container", "compute",
    # Azure
    "aks", "containerregistry", "containerinstance", "containerapp",
    # GCP
    "container", "artifactregistry", "run",
    # OCI
    "containerengine", "artifacts",
    # K8s
    "pod", "deployment", "namespace", "networkpolicy", "serviceaccount",
    "rbac", "clusterrole", "clusterrolebinding",
})
_CONTAINER_DOMAINS = frozenset({"container_and_kubernetes_security"})

_DATABASE_SERVICES = frozenset({
    # AWS
    "rds", "dynamodb", "redshift", "elasticache", "neptune", "docdb",
    "documentdb", "opensearch", "timestream", "keyspaces", "dax",
    # Azure
    "sql", "sqlserver", "cosmosdb", "redis", "postgresql", "mysql",
    "mariadb", "synapse",
    # GCP
    "sqladmin", "spanner", "bigtable", "datastore", "firestore",
    "memorystore", "alloydb",
    # OCI
    "database", "nosql", "autonomousdatabase",
    # AliCloud
    "polardb", "mongodb", "kvstore", "gpdb",
})
_DATABASE_DOMAINS = frozenset({"storage_and_database_security"})

_AI_SERVICES = frozenset({
    # AWS
    "sagemaker", "sagemaker-runtime", "sagemaker-edge", "sagemaker-featurestore-runtime",
    "bedrock", "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime",
    "comprehend", "comprehendmedical", "textract", "translate", "transcribe",
    "rekognition", "polly", "personalize", "forecast", "frauddetector",
    "machinelearning", "lookoutmetrics", "lookoutequipment", "lookoutvision", "kendra",
    # Azure
    "cognitiveservices", "machinelearningservices", "openai",
    # GCP
    "aiplatform", "automl", "videointelligence", "vision", "naturallanguage",
    # OCI
    "generative_ai", "ai_language", "ai_vision",
})


def _compute_engine_scope(service: str, domain: str) -> dict:
    """Compute all 5 engine scope JSONB values from service + domain.

    Returns dict with keys: data_security, encryption_security,
    container_security, database_security, ai_security.
    """
    svc = (service or "").lower()
    dom = (domain or "").lower()

    # data_security
    if dom in _DATA_SECURITY_DOMAINS:
        data_sec = {
            "applicable": True,
            "modules": _DATA_SECURITY_MODULE_MAP.get(dom, ["data_protection_encryption"]),
            "categories": _DATA_SECURITY_CATEGORY_MAP.get(dom, ["data_protection"]),
            "priority": _DATA_SECURITY_PRIORITY_MAP.get(dom, "high"),
        }
    else:
        data_sec = {}

    enc_sec = {"applicable": True} if (svc in _ENCRYPTION_SERVICES or dom in _ENCRYPTION_DOMAINS) else {}
    ctr_sec = {"applicable": True} if (svc in _CONTAINER_SERVICES or dom in _CONTAINER_DOMAINS) else {}
    db_sec  = {"applicable": True} if (svc in _DATABASE_SERVICES  or dom in _DATABASE_DOMAINS)  else {}
    ai_sec  = {"applicable": True} if svc in _AI_SERVICES else {}

    return {
        "data_security":       data_sec,
        "encryption_security": enc_sec,
        "container_security":  ctr_sec,
        "database_security":   db_sec,
        "ai_security":         ai_sec,
    }


def get_check_db_config():
    """Read config from env (CHECK_DB_*)"""
    return {
        "host":     os.getenv("CHECK_DB_HOST", "localhost"),
        "port":     int(os.getenv("CHECK_DB_PORT", "5432")),
        "database": os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        "user":     os.getenv("CHECK_DB_USER", "check_user"),
        "password": os.getenv("CHECK_DB_PASSWORD", "check_password"),
    }


def parse_metadata_yaml(yaml_path: Path) -> dict:
    """Parse metadata YAML and extract fields for rule_metadata table."""
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return None

        rule_id = data.get('rule_id') or data.get('assertion_id')
        if not rule_id:
            return None

        service = data.get('service', '')
        domain  = data.get('domain', '')
        scope   = _compute_engine_scope(service, domain)

        return {
            'rule_id':              rule_id,
            'service':              service,
            'provider':             data.get('provider', 'aws'),
            'resource':             data.get('resource', ''),
            'resource_service':     data.get('resource_service', service),
            'severity':             data.get('severity', 'medium'),
            'title':                data.get('title', ''),
            'description':          data.get('description', ''),
            'remediation':          data.get('remediation', ''),
            'rationale':            data.get('rationale', ''),
            'domain':               domain,
            'subcategory':          data.get('subcategory', ''),
            'requirement':          data.get('requirement', ''),
            'assertion_id':         data.get('assertion_id', ''),
            'compliance_frameworks':data.get('compliance_frameworks', []),
            'references':           data.get('references', []),
            # Engine scope — computed from service + domain, not from YAML field
            'data_security':       scope['data_security'],
            'encryption_security': scope['encryption_security'],
            'container_security':  scope['container_security'],
            'database_security':   scope['database_security'],
            'ai_security':         scope['ai_security'],
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
        assertion_id, compliance_frameworks,
        data_security, encryption_security, container_security, database_security, ai_security,
        "references"
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s
    )
    ON CONFLICT (rule_id) DO UPDATE SET
        service              = EXCLUDED.service,
        provider             = EXCLUDED.provider,
        resource             = EXCLUDED.resource,
        resource_service     = EXCLUDED.resource_service,
        severity             = EXCLUDED.severity,
        title                = EXCLUDED.title,
        description          = EXCLUDED.description,
        remediation          = EXCLUDED.remediation,
        rationale            = EXCLUDED.rationale,
        domain               = EXCLUDED.domain,
        subcategory          = EXCLUDED.subcategory,
        requirement          = EXCLUDED.requirement,
        assertion_id         = EXCLUDED.assertion_id,
        compliance_frameworks= EXCLUDED.compliance_frameworks,
        data_security        = EXCLUDED.data_security,
        encryption_security  = EXCLUDED.encryption_security,
        container_security   = EXCLUDED.container_security,
        database_security    = EXCLUDED.database_security,
        ai_security          = EXCLUDED.ai_security,
        "references"         = EXCLUDED."references",
        updated_at           = NOW();
    """ if upsert else """
    INSERT INTO rule_metadata (
        rule_id, service, provider, resource, resource_service, severity, title,
        description, remediation, rationale, domain, subcategory, requirement,
        assertion_id, compliance_frameworks,
        data_security, encryption_security, container_security, database_security, ai_security,
        "references"
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s
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
                    Json(metadata['encryption_security']),
                    Json(metadata['container_security']),
                    Json(metadata['database_security']),
                    Json(metadata['ai_security']),
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
