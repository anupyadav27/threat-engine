#!/usr/bin/env python3
"""
Fix orphaned services in rule_discoveries.

For each CSP, inserts alias rows in rule_discoveries so that
rule_metadata.service names match rule_discoveries.service names.

Two strategies:
  1. ALIAS  — copy discoveries_data from existing service, rename service field
  2. EMPTY  — insert a row with empty discovery list + is_active=false
              so check engine knows it exists but isn't discoverable

Run:
  python3 scripts/fix_orphaned_services.py [--dry-run]
"""

import os, sys, json, psycopg2, psycopg2.extras, argparse

DB_CONFIG = {
    "host":     "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "port":     5432,
    "dbname":   "threat_engine_check",
    "user":     "postgres",
    "password": "jtv2BkJF8qoFtAKP",
}

# ── Alias maps: orphan_service → existing rule_discoveries.service ─────────────
ALIAS_MAP = {
    "azure": {
        "machine":              "machinelearningservices",
        "kubernetes":           "containerservice",
        "aks":                  "containerservice",
        "vm":                   "compute",
        "virtualmachines":      "compute",
        "disk":                 "compute",
        "functionapp":          "web",
        "function":             "web",
        "site":                 "web",
        "webapp":               "web",
        "appservice":           "web",
        "blob":                 "storage",
        "storageaccount":       "storage",
        "files":                "storage",
        "key":                  "keyvault",
        "certificates":         "keyvault",
        "cosmos":               "cosmosdb",
        "cache":                "redis",
        "load":                 "network",
        "loadbalancer":         "network",
        "networksecuritygroup": "network",
        "vpn":                  "network",
        "rbac":                 "authorization",
        "iam":                  "authorization",
        "managedidentity":      "msi",
        "aad":                  "security",
        "ad":                   "security",
        "entra":                "security",
        "entrad":               "security",
        "defender":             "security",
        "securitycenter":       "security",
        "log":                  "loganalytics",
        "sqlserver":            "sql",
        "event":                "eventgrid",
        "iot":                  "iothub",
        "notification":         "notificationhubs",
        "traffic":              "trafficmanager",
        "front":                "frontdoor",
        "container":            "containerservice",
        "managementgroup":      "managementgroups",
        "management":           "managementgroups",
        "cost":                 "costmanagement",
        "policyinsights":       "policyinsights",
        "config":               "resource",
        "backup":               "dataprotection",
        "policy":               "policyinsights",
        # These already exist in rule_discoveries but need check:
        "data":                 "datafactory",
        "purview":              "purview",
        "power":                "powerbidedicated",
        "application":         "applicationinsights",
        "monitor":              "monitor",
        "web":                  "web",
    },
    "k8s": {
        "rbac":       "clusterrole",
        "network":    "networkpolicy",
        "storage":    "persistentvolumeclaim",
        "autoscaling":"deployment",
    },
    "alicloud": {
        "cfw":        "cloudfw",
        "cloudmonitor":"cms",
        "dns":        "dns",
    },
    "gcp": {
        "dataproc":   "dataproc",
        "bigtable":   "bigtable",
        "resourcemanager": "resourcemanager",
        "aiplatform": "aiplatform",
        "backupdr":   "backupdr",
        "billing":    "billing",
        "osconfig":   "osconfig",
        "asset":      "asset",
        "endpoints":  "endpoints",
        "trace":      "trace",
        "filestore":  "filestore",
        "apikeys":    "apikeys",
        "cloudsql":   "cloudsql",
    },
    "oci": {
        "edge_services":           "virtual_network",
        "ai_anomaly_detection":    "ai_vision",
    },
}

# ── Not-discoverable: insert inactive stub so engine knows they exist ──────────
NOT_DISCOVERABLE = {
    "k8s":  ["apiserver","audit","etcd","controlplane","kubelet","admission",
              "monitoring","cluster","node","certificate","policy","federation",
              "general","horizontalpodautoscaler","image","inventory","pod_security",
              "resource","scheduler","software","workload","disaster_recovery","event"],
    "gcp":  ["datastudio","workspace","elasticsearch","multi","services","essentialcontacts"],
    "aws":  ["personalize-events","sso-oidc","cloudtrail-data","ec2-instance-connect",
             "geo-routes","eks-auth","meteringmarketplace","payment-cryptography-data","signin"],
    "alicloud": ["general"],
    "oci":  ["announcements_service","compute_instance_agent","usage"],
}

UPSERT_SQL = """
    INSERT INTO rule_discoveries
        (service, provider, version, discoveries_data, boto3_client_name,
         source, generated_by, is_active, customer_id, tenant_id, created_at, updated_at)
    VALUES
        (%(service)s, %(provider)s, '1.0', %(discoveries_data)s::jsonb,
         %(boto3_client_name)s, 'alias_fix', 'fix_orphaned_services', %(is_active)s,
         NULL, NULL, NOW(), NOW())
    ON CONFLICT (service, provider, customer_id, tenant_id) DO NOTHING
"""


def run(dry_run: bool):
    conn = None if dry_run else psycopg2.connect(**DB_CONFIG)
    total_alias = 0
    total_stub  = 0

    for provider, alias_map in ALIAS_MAP.items():
        print(f"\n── {provider.upper()} aliases ──")
        for orphan_svc, source_svc in alias_map.items():
            # Check if orphan already exists
            if not dry_run:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM rule_discoveries WHERE service=%s AND provider=%s AND customer_id IS NULL",
                        (orphan_svc, provider)
                    )
                    if cur.fetchone():
                        print(f"  SKIP  {orphan_svc} (already exists)")
                        continue

                    # Fetch source row
                    cur.execute(
                        "SELECT discoveries_data, boto3_client_name FROM rule_discoveries "
                        "WHERE service=%s AND provider=%s AND customer_id IS NULL AND is_active=true LIMIT 1",
                        (source_svc, provider)
                    )
                    row = cur.fetchone()
                    if not row:
                        print(f"  WARN  {orphan_svc} → {source_svc} (source not found, inserting empty)")
                        discoveries_data = json.dumps({"service": orphan_svc, "provider": provider,
                                                        "version": "1.0", "services": {}, "discovery": []})
                        boto3_name = ""
                        is_active = False
                    else:
                        src_data = row[0]
                        boto3_name = row[1] or ""
                        # Copy discovery data but rename service field
                        if isinstance(src_data, dict):
                            src_data["service"] = orphan_svc
                            discoveries_data = json.dumps(src_data)
                        else:
                            discoveries_data = src_data
                        is_active = True

                    cur.execute(UPSERT_SQL, {
                        "service": orphan_svc, "provider": provider,
                        "discoveries_data": discoveries_data,
                        "boto3_client_name": boto3_name,
                        "is_active": is_active,
                    })
                conn.commit()
                print(f"  ALIAS {orphan_svc} → {source_svc}")
                total_alias += 1
            else:
                print(f"  [DRY] ALIAS {orphan_svc} → {source_svc}")
                total_alias += 1

    for provider, services in NOT_DISCOVERABLE.items():
        print(f"\n── {provider.upper()} stubs (not discoverable) ──")
        for svc in services:
            if not dry_run:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM rule_discoveries WHERE service=%s AND provider=%s AND customer_id IS NULL",
                        (svc, provider)
                    )
                    if cur.fetchone():
                        print(f"  SKIP  {svc} (already exists)")
                        continue
                    cur.execute(UPSERT_SQL, {
                        "service": svc, "provider": provider,
                        "discoveries_data": json.dumps({
                            "service": svc, "provider": provider,
                            "version": "1.0", "services": {},
                            "discovery": [],
                            "_note": "not-discoverable: config/audit check, no list API"
                        }),
                        "boto3_client_name": "",
                        "is_active": False,
                    })
                conn.commit()
                print(f"  STUB  {svc} (is_active=false)")
                total_stub += 1
            else:
                print(f"  [DRY] STUB {svc} (is_active=false)")
                total_stub += 1

    if conn:
        conn.close()

    print(f"\n── TOTAL ──")
    print(f"  Alias rows: {total_alias}")
    print(f"  Stub rows:  {total_stub}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    run(args.dry_run)
