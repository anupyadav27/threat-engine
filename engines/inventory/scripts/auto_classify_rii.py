#!/usr/bin/env python3
"""
Auto-classify ALL resource_inventory_identifier entries into service_classification.

Reads all rows from resource_inventory_identifier (6,600+ across all CSPs),
maps each to a category/subcategory using service-name pattern matching,
and upserts into the service_classification table.

IMPORTANT: Existing manually-curated entries (from YAML) are preserved via
ON CONFLICT DO UPDATE — but manual entries have higher priority so they
are loaded AFTER this script.

Usage:
    python auto_classify_rii.py \
        --db-url postgresql://user:pass@host:5432/threat_engine_inventory

    # Or with env vars:
    INVENTORY_DB_HOST=... python auto_classify_rii.py

    # Dry run:
    python auto_classify_rii.py --dry-run

    # Single CSP:
    python auto_classify_rii.py --csp aws
"""

import argparse
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("psycopg2 not found. Install: pip install psycopg2-binary")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── Service → Category Mapping ───────────────────────────────────────────────
# Pattern: (regex_on_service_name, category, subcategory, default_service_model)
# Order matters — first match wins.

SERVICE_CATEGORY_MAP: List[Tuple[str, str, str, str]] = [
    # ── Compute ──
    (r"^ec2$",                  "compute",     "vm",                    "IaaS"),
    (r"^lambda$",               "compute",     "function",              "FaaS"),
    (r"^lightsail$",            "compute",     "vm",                    "PaaS"),
    (r"^apprunner$",            "compute",     "app_runner",            "PaaS"),
    (r"^batch$",                "compute",     "batch",                 "PaaS"),
    (r"^autoscaling$",          "compute",     "autoscaling",           "PaaS"),
    (r"^imagebuilder$",         "compute",     "image",                 "PaaS"),
    (r"^outposts$",             "compute",     "hybrid",                "IaaS"),
    (r"^braket$",               "compute",     "quantum",               "PaaS"),
    (r"^appstream$",            "compute",     "desktop",               "PaaS"),
    (r"^workspaces",            "compute",     "desktop",               "PaaS"),
    (r"^gamelift$",             "compute",     "game_server",           "PaaS"),
    (r"^simspaceweaver$",       "compute",     "simulation",            "PaaS"),
    (r"^compute-optimizer$",    "compute",     "optimizer",             "SaaS"),
    (r"^elastic-inference$",    "compute",     "accelerator",           "PaaS"),
    (r"^dlm$",                  "compute",     "lifecycle",             "PaaS"),

    # ── Containers ──
    (r"^eks",                   "container",   "cluster",               "PaaS"),
    (r"^ecs$",                  "container",   "cluster",               "PaaS"),
    (r"^ecr",                   "container",   "registry",              "PaaS"),
    (r"^proton$",               "container",   "provisioning",          "PaaS"),
    (r"^appconfig$",            "container",   "config",                "PaaS"),

    # ── Database ──
    (r"^rds$",                  "database",    "relational",            "PaaS"),
    (r"^dynamodb$",             "database",    "nosql",                 "PaaS"),
    (r"^elasticache$",          "database",    "cache",                 "PaaS"),
    (r"^redshift",              "database",    "warehouse",             "PaaS"),
    (r"^neptune$",              "database",    "graph",                 "PaaS"),
    (r"^docdb",                 "database",    "document",              "PaaS"),
    (r"^memorydb$",             "database",    "cache",                 "PaaS"),
    (r"^timestream$",           "database",    "timeseries",            "PaaS"),
    (r"^qldb$",                 "database",    "ledger",                "PaaS"),
    (r"^keyspaces$",            "database",    "nosql",                 "PaaS"),
    (r"^dax$",                  "database",    "cache",                 "PaaS"),
    (r"^dms$",                  "database",    "migration",             "PaaS"),
    (r"^simpledb$",             "database",    "nosql",                 "PaaS"),
    (r"^cloudsearch$",          "database",    "search",                "PaaS"),
    (r"^opensearch",            "database",    "search",                "PaaS"),
    (r"^elasticsearch$",        "database",    "search",                "PaaS"),

    # ── Storage ──
    (r"^s3",                    "storage",     "object",                "PaaS"),
    (r"^efs$",                  "storage",     "file",                  "PaaS"),
    (r"^fsx$",                  "storage",     "file",                  "PaaS"),
    (r"^glacier$",              "storage",     "archive",               "PaaS"),
    (r"^backup",                "storage",     "backup",                "PaaS"),
    (r"^storagegateway$",       "storage",     "gateway",               "PaaS"),
    (r"^datasync$",             "storage",     "transfer",              "PaaS"),
    (r"^transfer$",             "storage",     "transfer",              "PaaS"),
    (r"^snowball$",             "storage",     "edge",                  "PaaS"),
    (r"^snow",                  "storage",     "edge",                  "PaaS"),
    (r"^ebs$",                  "storage",     "block",                 "IaaS"),

    # ── Network ──
    (r"^vpc$",                  "network",     "vpc",                   "IaaS"),
    (r"^elb",                   "network",     "load_balancer",         "PaaS"),
    (r"^route53",               "network",     "dns",                   "PaaS"),
    (r"^cloudfront$",           "edge",        "cdn",                   "PaaS"),
    (r"^apigateway",            "edge",        "api_gateway",           "PaaS"),
    (r"^globalaccelerator$",    "edge",        "accelerator",           "PaaS"),
    (r"^directconnect$",        "network",     "dedicated_connection",  "IaaS"),
    (r"^transitgateway$",       "network",     "gateway",               "IaaS"),
    (r"^networkmanager$",       "network",     "management",            "PaaS"),
    (r"^network-firewall$",     "security",    "firewall",              "PaaS"),
    (r"^networkmonitor$",       "network",     "monitoring",            "PaaS"),
    (r"^app-mesh$",             "network",     "service_mesh",          "PaaS"),
    (r"^appmesh$",              "network",     "service_mesh",          "PaaS"),
    (r"^cloud-map$",            "network",     "service_discovery",     "PaaS"),
    (r"^servicediscovery$",     "network",     "service_discovery",     "PaaS"),
    (r"^privatelink$",          "network",     "endpoint",              "PaaS"),
    (r"^vpn$",                  "network",     "vpn",                   "IaaS"),

    # ── Security ──
    (r"^waf",                   "security",    "waf",                   "PaaS"),
    (r"^shield$",               "security",    "ddos",                  "PaaS"),
    (r"^guardduty$",            "security",    "threat_detection",      "PaaS"),
    (r"^securityhub$",          "security",    "posture",               "PaaS"),
    (r"^inspector",             "security",    "vulnerability",         "PaaS"),
    (r"^macie$",                "security",    "data_discovery",        "PaaS"),
    (r"^detective$",            "security",    "investigation",         "PaaS"),
    (r"^firewall",              "security",    "firewall",              "PaaS"),
    (r"^cloudfirewall$",        "security",    "firewall",              "PaaS"),
    (r"^fms$",                  "security",    "firewall_manager",      "PaaS"),
    (r"^auditmanager$",         "security",    "audit",                 "PaaS"),
    (r"^config$",               "security",    "compliance",            "PaaS"),
    (r"^accessanalyzer$",       "security",    "access_analysis",       "PaaS"),
    (r"^securitylake$",         "security",    "data_lake",             "PaaS"),
    (r"^artifact$",             "security",    "compliance",            "PaaS"),
    (r"^wellarchitected$",      "security",    "review",               "PaaS"),
    (r"^resiliencehub$",        "security",    "resilience",            "PaaS"),
    (r"^trustedadvisor$",       "security",    "advisor",               "SaaS"),
    (r"^controlcatalog$",       "security",    "controls",              "PaaS"),
    (r"^controltower$",         "security",    "governance",            "PaaS"),

    # ── Identity / IAM ──
    (r"^iam$",                  "identity",    "iam",                   "SaaS"),
    (r"^sts$",                  "identity",    "token",                 "SaaS"),
    (r"^sso",                   "identity",    "sso",                   "SaaS"),
    (r"^cognito",               "identity",    "user_pool",             "PaaS"),
    (r"^ram$",                  "identity",    "resource_sharing",      "SaaS"),
    (r"^organizations$",        "identity",    "organizations",         "SaaS"),
    (r"^directory",             "identity",    "directory",             "PaaS"),

    # ── Encryption / KMS ──
    (r"^kms$",                  "encryption",  "key",                   "PaaS"),
    (r"^acm",                   "encryption",  "certificate",           "PaaS"),
    (r"^cloudhsm",              "encryption",  "hsm",                   "PaaS"),
    (r"^secretsmanager$",       "encryption",  "secrets",               "PaaS"),
    (r"^ssm$",                  "encryption",  "parameter_store",       "PaaS"),

    # ── Monitoring / Logging ──
    (r"^cloudwatch$",           "monitoring",  "metrics",               "PaaS"),
    (r"^logs$",                 "monitoring",  "logs",                  "PaaS"),
    (r"^cloudtrail$",           "monitoring",  "audit",                 "PaaS"),
    (r"^xray$",                 "monitoring",  "tracing",               "PaaS"),
    (r"^application-insights$", "monitoring",  "apm",                   "PaaS"),
    (r"^application-signals$",  "monitoring",  "apm",                   "PaaS"),
    (r"^internetmonitor$",      "monitoring",  "internet",              "PaaS"),
    (r"^devops-guru$",          "monitoring",  "ml_insights",           "PaaS"),
    (r"^health$",               "monitoring",  "health",                "SaaS"),
    (r"^synthetics$",           "monitoring",  "canary",                "PaaS"),
    (r"^evidently$",            "monitoring",  "experimentation",       "PaaS"),
    (r"^rum$",                  "monitoring",  "real_user",             "PaaS"),

    # ── Management / Governance ──
    (r"^cloudformation$",       "management",  "iac",                   "PaaS"),
    (r"^servicecatalog$",       "management",  "catalog",               "PaaS"),
    (r"^systems-manager$",      "management",  "operations",            "PaaS"),
    (r"^ssm-",                  "management",  "operations",            "PaaS"),
    (r"^organizations$",        "management",  "organizations",         "SaaS"),
    (r"^resource-groups$",      "management",  "tagging",               "SaaS"),
    (r"^resource-explorer",     "management",  "explorer",              "SaaS"),
    (r"^tag$",                  "management",  "tagging",               "SaaS"),
    (r"^license-manager$",      "management",  "licensing",             "PaaS"),
    (r"^ce$",                   "management",  "cost",                  "SaaS"),
    (r"^budgets$",              "management",  "cost",                  "SaaS"),
    (r"^billing",               "management",  "billing",               "SaaS"),
    (r"^bcm",                   "management",  "cost",                  "SaaS"),
    (r"^freetier$",             "management",  "billing",               "SaaS"),
    (r"^cur$",                  "management",  "cost",                  "SaaS"),
    (r"^support$",              "management",  "support",               "SaaS"),
    (r"^chatbot$",              "management",  "chatops",               "PaaS"),
    (r"^ros$",                  "management",  "iac",                   "PaaS"),
    (r"^schematics$",           "management",  "iac",                   "PaaS"),
    (r"^opsworks$",             "management",  "configuration",         "PaaS"),
    (r"^launch-wizard$",        "management",  "wizard",                "PaaS"),

    # ── Messaging / Events ──
    (r"^sqs$",                  "messaging",   "queue",                 "PaaS"),
    (r"^sns$",                  "messaging",   "notification",          "PaaS"),
    (r"^eventbridge$",          "messaging",   "event_bus",             "PaaS"),
    (r"^events$",               "messaging",   "event_bus",             "PaaS"),
    (r"^mq$",                   "messaging",   "broker",                "PaaS"),
    (r"^kafka$",                "messaging",   "streaming",             "PaaS"),
    (r"^msk$",                  "messaging",   "streaming",             "PaaS"),
    (r"^kinesis",               "messaging",   "streaming",             "PaaS"),
    (r"^ses$",                  "messaging",   "email",                 "PaaS"),
    (r"^pinpoint$",             "messaging",   "engagement",            "PaaS"),
    (r"^connect$",              "messaging",   "contact_center",        "PaaS"),
    (r"^chime",                 "messaging",   "communications",        "PaaS"),
    (r"^ivs",                   "messaging",   "video",                 "PaaS"),

    # ── Analytics ──
    (r"^athena$",               "analytics",   "query",                 "PaaS"),
    (r"^glue$",                 "analytics",   "etl",                   "PaaS"),
    (r"^emr",                   "analytics",   "hadoop",                "PaaS"),
    (r"^quicksight$",           "analytics",   "bi",                    "SaaS"),
    (r"^databrew$",             "analytics",   "data_prep",             "PaaS"),
    (r"^lakeformation$",        "analytics",   "data_lake",             "PaaS"),
    (r"^firehose$",             "analytics",   "delivery",              "PaaS"),
    (r"^datapipeline$",         "analytics",   "pipeline",              "PaaS"),
    (r"^datazone$",             "analytics",   "catalog",               "PaaS"),
    (r"^cleanrooms",            "analytics",   "collaboration",         "PaaS"),

    # ── AI/ML ──
    (r"^sagemaker$",            "ai_ml",       "ml_platform",           "PaaS"),
    (r"^bedrock",               "ai_ml",       "foundation_model",      "PaaS"),
    (r"^comprehend$",           "ai_ml",       "nlp",                   "PaaS"),
    (r"^rekognition$",          "ai_ml",       "vision",                "PaaS"),
    (r"^textract$",             "ai_ml",       "ocr",                   "PaaS"),
    (r"^polly$",                "ai_ml",       "speech",                "PaaS"),
    (r"^transcribe$",           "ai_ml",       "speech",                "PaaS"),
    (r"^translate$",            "ai_ml",       "translation",           "PaaS"),
    (r"^lex$",                  "ai_ml",       "chatbot",               "PaaS"),
    (r"^personalize$",          "ai_ml",       "recommendation",        "PaaS"),
    (r"^forecast$",             "ai_ml",       "forecasting",           "PaaS"),
    (r"^kendra$",               "ai_ml",       "search",                "PaaS"),
    (r"^lookout",               "ai_ml",       "anomaly",               "PaaS"),
    (r"^aiops$",                "ai_ml",       "operations",            "PaaS"),
    (r"^codewhisperer$",        "ai_ml",       "code_assist",           "SaaS"),
    (r"^q$",                    "ai_ml",       "assistant",             "SaaS"),

    # ── IoT ──
    (r"^iot",                   "iot",         "platform",              "PaaS"),
    (r"^greengrass$",           "iot",         "edge",                  "PaaS"),

    # ── Media ──
    (r"^media",                 "messaging",   "media",                 "PaaS"),
    (r"^elastic-transcoder$",   "messaging",   "media",                 "PaaS"),

    # ── Developer Tools ──
    (r"^codecommit$",           "management",  "source_control",        "PaaS"),
    (r"^codebuild$",            "management",  "ci",                    "PaaS"),
    (r"^codepipeline$",         "management",  "ci_cd",                 "PaaS"),
    (r"^codedeploy$",           "management",  "deployment",            "PaaS"),
    (r"^codeartifact$",         "management",  "artifact",              "PaaS"),
    (r"^codeguru$",             "management",  "code_review",           "PaaS"),
    (r"^codestar",              "management",  "project",               "PaaS"),
    (r"^cloud9$",               "management",  "ide",                   "PaaS"),
    (r"^cloudcontrol$",         "management",  "api",                   "PaaS"),
    (r"^schemas$",              "management",  "schema_registry",       "PaaS"),
    (r"^appflow$",              "management",  "integration",           "PaaS"),
    (r"^appintegrations$",      "management",  "integration",           "PaaS"),
    (r"^amplify$",              "management",  "frontend",              "PaaS"),
    (r"^elasticbeanstalk$",     "compute",     "app_platform",          "PaaS"),
]

# ── Scope by service (override defaults) ──
GLOBAL_SERVICES = {
    "iam", "sts", "organizations", "route53", "cloudfront", "s3",
    "waf", "wafv2", "shield", "globalaccelerator", "budgets",
    "billing", "billingconductor", "ce", "cur", "support",
    "trustedadvisor", "health", "artifact", "freetier",
    "ram", "sso", "sso-admin",
}

# ── Priority by classification type ──
PRIORITY_BY_CLASS = {
    "PRIMARY_RESOURCE": 3,
    "SUB_RESOURCE": 4,
    "ACTION_ENDPOINT": 5,
    "CONFIG_ONLY": 5,
    "CONFIGURATION": 5,
    "GENERIC": 5,
}

# ── Container resources ──
CONTAINER_RESOURCES = {
    ("ec2", "vpc"), ("ec2", "subnet"), ("vpc", "vpc"), ("vpc", "subnet"),
    ("eks", "cluster"), ("ecs", "cluster"),
}


# ── Auto-classify ────────────────────────────────────────────────────────────

def classify_service(service: str) -> Tuple[str, str, str]:
    """Return (category, subcategory, service_model) for a service name."""
    for pattern, cat, subcat, model in SERVICE_CATEGORY_MAP:
        if re.match(pattern, service, re.IGNORECASE):
            return cat, subcat, model
    return "management", "other", "PaaS"  # fallback


def make_display_name(service: str, canonical_type: str) -> str:
    """Generate a human-friendly display name."""
    svc = service.replace("-", " ").replace("_", " ").title()
    rt = canonical_type.replace("-", " ").replace("_", " ").title()
    return f"{svc} {rt}"


# ── DB Connection ────────────────────────────────────────────────────────────

def get_db_connection(db_url: Optional[str] = None):
    if db_url:
        return psycopg2.connect(db_url)
    host = os.environ.get("INVENTORY_DB_HOST", os.environ.get("DB_HOST", "localhost"))
    port = os.environ.get("INVENTORY_DB_PORT", os.environ.get("DB_PORT", "5432"))
    name = os.environ.get("INVENTORY_DB_NAME", os.environ.get("DB_NAME", "threat_engine_inventory"))
    user = os.environ.get("INVENTORY_DB_USER", os.environ.get("DB_USER", "postgres"))
    password = os.environ.get("INVENTORY_DB_PASSWORD", os.environ.get("DB_PASSWORD", ""))
    return psycopg2.connect(host=host, port=int(port), dbname=name, user=user, password=password)


# ── Main ─────────────────────────────────────────────────────────────────────

def auto_classify(
    db_url: Optional[str] = None,
    dry_run: bool = False,
    csp_filter: Optional[str] = None,
) -> Dict[str, int]:
    """Read all RII entries, classify, and upsert into service_classification."""

    stats = {"total_rii": 0, "upserted": 0, "skipped": 0, "errors": 0}

    conn = get_db_connection(db_url)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # ── Read all RII entries ──
            csp_clause = ""
            params: list = []
            if csp_filter:
                csp_clause = "WHERE csp = %s"
                params.append(csp_filter)

            cur.execute(f"""
                SELECT csp, service, resource_type, canonical_type, classification
                FROM resource_inventory_identifier
                {csp_clause}
                ORDER BY csp, service, canonical_type
            """, params)

            rii_rows = cur.fetchall()
            stats["total_rii"] = len(rii_rows)
            logger.info("Read %d RII entries", len(rii_rows))

            if dry_run:
                # Just show stats
                categories = {}
                for row in rii_rows:
                    cat, _, _ = classify_service(row["service"])
                    categories[cat] = categories.get(cat, 0) + 1
                logger.info("DRY RUN — category distribution:")
                for cat, cnt in sorted(categories.items()):
                    logger.info("  %s: %d", cat, cnt)
                return stats

            # ── Build and upsert ──
            sql = """
                INSERT INTO service_classification (
                    csp, resource_type, service, resource_name, display_name,
                    scope, category, subcategory, service_model, managed_by,
                    access_pattern, is_container, container_parent,
                    diagram_priority, csp_category
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s
                )
                ON CONFLICT (csp, resource_type) DO UPDATE SET
                    service = EXCLUDED.service,
                    resource_name = EXCLUDED.resource_name,
                    display_name = COALESCE(service_classification.display_name, EXCLUDED.display_name),
                    scope = COALESCE(service_classification.scope, EXCLUDED.scope),
                    category = COALESCE(service_classification.category, EXCLUDED.category),
                    subcategory = COALESCE(service_classification.subcategory, EXCLUDED.subcategory),
                    service_model = COALESCE(service_classification.service_model, EXCLUDED.service_model),
                    managed_by = COALESCE(service_classification.managed_by, EXCLUDED.managed_by),
                    access_pattern = COALESCE(service_classification.access_pattern, EXCLUDED.access_pattern),
                    is_container = service_classification.is_container,
                    container_parent = COALESCE(service_classification.container_parent, EXCLUDED.container_parent),
                    diagram_priority = LEAST(service_classification.diagram_priority, EXCLUDED.diagram_priority),
                    csp_category = COALESCE(service_classification.csp_category, EXCLUDED.csp_category),
                    updated_at = NOW()
            """

            batch_values = []
            for row in rii_rows:
                csp = row["csp"]
                service = row["service"]
                ct = row.get("canonical_type") or row["resource_type"]
                classification = row.get("classification", "PRIMARY_RESOURCE")

                # Skip deprecated
                if csp == "deprecated":
                    stats["skipped"] += 1
                    continue

                # Build dotted resource_type
                resource_type_dotted = f"{service}.{ct}"

                # Classify
                cat, subcat, svc_model = classify_service(service)

                # Scope
                scope = "global" if service.lower() in GLOBAL_SERVICES else "regional"

                # Priority
                priority = PRIORITY_BY_CLASS.get(classification, 4)

                # Container check
                is_container = (service, ct) in CONTAINER_RESOURCES

                # Container parent
                if scope == "global":
                    container_parent = "account"
                elif service == "ec2" and ct in ("vpc", "subnet", "security-group", "network-interface"):
                    container_parent = "vpc" if ct != "vpc" else "region"
                elif service in ("eks", "ecs") and ct not in ("cluster",):
                    container_parent = "cluster"
                else:
                    container_parent = "region"

                # Managed by
                managed_by = csp if csp in ("aws", "azure", "gcp", "oci", "alicloud", "ibm") else "shared"
                # customer-managed for IaaS
                if svc_model == "IaaS":
                    managed_by = "customer"

                display_name = make_display_name(service, ct)

                batch_values.append((
                    csp, resource_type_dotted, service, ct, display_name,
                    scope, cat, subcat, svc_model, managed_by,
                    "private", is_container, container_parent,
                    priority, None,
                ))

            # Execute with per-row savepoints to handle errors gracefully
            for idx, values in enumerate(batch_values):
                try:
                    cur.execute("SAVEPOINT sp")
                    cur.execute(sql, values)
                    cur.execute("RELEASE SAVEPOINT sp")
                    stats["upserted"] += 1
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT sp")
                    logger.warning("Skip %s/%s: %s", values[0], values[1], str(e)[:80])
                    stats["errors"] += 1

                if (idx + 1) % 1000 == 0:
                    conn.commit()
                    logger.info("Progress: %d/%d upserted (%d errors)",
                                stats["upserted"], len(batch_values), stats["errors"])

            conn.commit()

            logger.info("Done. upserted=%d, skipped=%d, errors=%d",
                        stats["upserted"], stats["skipped"], stats["errors"])

    finally:
        conn.close()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Auto-classify all RII entries into service_classification"
    )
    parser.add_argument("--db-url", default=None, help="PostgreSQL connection URL")
    parser.add_argument("--dry-run", action="store_true", help="Print stats without executing")
    parser.add_argument("--csp", default=None, help="Filter to single CSP (e.g., aws)")

    args = parser.parse_args()
    stats = auto_classify(db_url=args.db_url, dry_run=args.dry_run, csp_filter=args.csp)
    sys.exit(0 if stats["errors"] == 0 else 1)


if __name__ == "__main__":
    main()
