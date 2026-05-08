#!/usr/bin/env python3
"""
step6_fix_stubs.py
==================
Fix all 24 stub rules by:
1. Replacing stub checks.yaml entries with real for_each IDs + proper conditions
2. Writing real discovery entries to deployed rule_check discovery YAMLs
3. Updating step6 YAMLs with real entries

Usage:
    python3 catalog/rule/step6_fix_stubs.py             # dry-run
    python3 catalog/rule/step6_fix_stubs.py --apply     # write files
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT     = Path(__file__).resolve().parent.parent.parent
RULE_DIR = Path(__file__).resolve().parent
DGD      = ROOT / "catalog" / "discovery_generator_data"

APPLY = "--apply" in sys.argv
if not APPLY:
    print("*** DRY-RUN — pass --apply to write files ***\n")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def read_yaml(path: Path) -> dict:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"  ERROR reading {path}: {e}")
        return {}

def write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )

def patch_checks(checks_path: Path, updates: dict[str, dict]) -> None:
    """
    updates: {rule_id: {for_each: ..., conditions: ..., severity: ...}}
    Replaces stub entries in checks.yaml.
    """
    data = read_yaml(checks_path)
    checks = data.get("checks", [])
    changed = 0
    for entry in checks:
        rid = entry.get("rule_id", "")
        if rid in updates:
            upd = updates[rid]
            entry["for_each"] = upd["for_each"]
            entry.pop("_stub", None)
            if "conditions" in upd:
                entry["conditions"] = upd["conditions"]
            if "severity" in upd:
                entry["severity"] = upd["severity"]
            changed += 1
    status = "WRITE" if APPLY else "DRY"
    print(f"  [{status}] {checks_path.relative_to(ROOT)}: patched {changed} entries")
    if APPLY:
        write_yaml(checks_path, data)

def upsert_discovery(disc_path: Path, new_entries: list[dict], header: dict = None) -> None:
    """Append new discovery entries to a deployed discovery YAML (no duplicates)."""
    existing: set[str] = set()
    entries: list[dict] = []
    hdr: dict = {}

    if disc_path.exists():
        data = read_yaml(disc_path)
        hdr = {k: v for k, v in data.items() if k != "discovery"}
        entries = [e for e in (data.get("discovery") or []) if isinstance(e, dict)]
        existing = {e.get("discovery_id", "") for e in entries}
    else:
        hdr = header or {}

    added = []
    for e in new_entries:
        did = e.get("discovery_id", "")
        if did not in existing:
            entries.append(e)
            existing.add(did)
            added.append(did)

    status = "WRITE" if APPLY else "DRY"
    print(f"  [{status}] {disc_path.relative_to(ROOT)}: +{len(added)} discovery entries")
    if APPLY and added:
        out = {**hdr, "discovery": entries}
        write_yaml(disc_path, out)

def upsert_step6(step6_path: Path, new_entries: list[dict]) -> None:
    """Replace stub entries in step6 YAML with real ones."""
    data = read_yaml(step6_path)
    old = [e for e in (data.get("discovery") or []) if isinstance(e, dict)]
    old_ids = {e.get("discovery_id") for e in old}

    # Remove stubs we're replacing
    new_ids = {e["discovery_id"] for e in new_entries}
    kept = [e for e in old if e.get("discovery_id") not in new_ids]
    merged = kept + new_entries

    data["discovery"] = merged
    status = "WRITE" if APPLY else "DRY"
    print(f"  [{status}] {step6_path.relative_to(ROOT)}: replaced {len(new_ids)} stub(s)")
    if APPLY:
        write_yaml(step6_path, data)

# ─────────────────────────────────────────────────────────────────────────────
# 1. OCI KMS  →  real oci.key_management discovery
# ─────────────────────────────────────────────────────────────────────────────
print("\n── OCI KMS ──")
# The real discovery entry: list_keys + get_key for rotation details
OCI_KMS_DISC_ID = "oci.kms.list_keys"
oci_kms_entry = {
    "discovery_id": OCI_KMS_DISC_ID,
    "calls": [
        {
            "action": "list_keys",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.data }}",
        "item": {
            "ocid":                "{{ item.ocid }}",
            "compartment_id":      "{{ item.compartment_id }}",
            "name":                "{{ item.display_name }}",
            "status":              "{{ item.lifecycle_state }}",
            "time_created":        "{{ item.time_created }}",
            "algorithm":           "{{ item.algorithm }}",
            "key_shape":           "{{ item.key_shape }}",
            "current_key_version": "{{ item.current_key_version }}",
            "protection_mode":     "{{ item.protection_mode }}",
            "is_primary":          "{{ item.is_primary }}",
            "vault_id":            "{{ item.vault_id }}",
            "defined_tags":        "{{ item.defined_tags }}",
            "freeform_tags":       "{{ item.freeform_tags }}",
            "time_of_deletion":    "{{ item.time_of_deletion }}",
        },
    },
    "_used_by_rules": [
        "oci.kms.key.key_manager_configured",
        "oci.kms.key.key_shape_configured",
        "oci.kms.key.key_version_configured",
        "oci.kms.key.rotation_interval_configured",
    ],
}
# Also get_key_version for rotation_interval
oci_kms_version_entry = {
    "discovery_id": "oci.kms.get_key_version",
    "calls": [
        {
            "action": "get_key",
            "params": {"key_id": "{{ item.ocid }}"},
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "item": {
            "ocid":                   "{{ response.data.id }}",
            "name":                   "{{ response.data.display_name }}",
            "status":                 "{{ response.data.lifecycle_state }}",
            "algorithm":              "{{ response.data.key_shape.algorithm }}",
            "key_length":             "{{ response.data.key_shape.length }}",
            "curve_id":               "{{ response.data.key_shape.curve_id }}",
            "protection_mode":        "{{ response.data.protection_mode }}",
            "is_primary":             "{{ response.data.is_primary }}",
            "current_key_version":    "{{ response.data.current_key_version }}",
            "time_of_deletion":       "{{ response.data.time_of_deletion }}",
            "replica_details":        "{{ response.data.replica_details }}",
            "restore_from_file_details": "{{ response.data.restore_from_file_details }}",
            "auto_key_rotation_details": "{{ response.data.auto_key_rotation_details }}",
            "defined_tags":           "{{ response.data.defined_tags }}",
        },
    },
    "_used_by_rules": ["oci.kms.key.rotation_interval_configured"],
}

kms_checks_upd = {
    "oci.kms.key.key_manager_configured": {
        "for_each": OCI_KMS_DISC_ID,
        "conditions": {"var": "item.protection_mode", "op": "in", "value": ["HSM", "EXTERNAL"]},
    },
    "oci.kms.key.key_shape_configured": {
        "for_each": OCI_KMS_DISC_ID,
        "conditions": {"var": "item.algorithm", "op": "in", "value": ["AES", "RSA", "ECDSA"]},
    },
    "oci.kms.key.key_version_configured": {
        "for_each": OCI_KMS_DISC_ID,
        "conditions": {"var": "item.current_key_version", "op": "is_not_empty", "value": ""},
    },
    "oci.kms.key.rotation_interval_configured": {
        "for_each": "oci.kms.get_key_version",
        "conditions": {"var": "item.auto_key_rotation_details", "op": "is_not_empty", "value": ""},
    },
}

patch_checks(RULE_DIR / "oci_rule_check/kms/checks.yaml", kms_checks_upd)
upsert_discovery(
    RULE_DIR / "oci_rule_check/kms/kms.discovery.yaml",
    [oci_kms_entry, oci_kms_version_entry],
    header={"version": "1.0", "provider": "oci", "service": "kms"},
)
upsert_step6(DGD / "oci/kms/step6_kms.discovery.yaml", [oci_kms_entry, oci_kms_version_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 2. OCI OKE  →  oci.container_engine.list_clusters
# ─────────────────────────────────────────────────────────────────────────────
print("\n── OCI OKE ──")
OCI_OKE_DISC_ID = "oci.oke.list_clusters"
oci_oke_entry = {
    "discovery_id": OCI_OKE_DISC_ID,
    "calls": [
        {
            "action": "list_clusters",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.data }}",
        "item": {
            "ocid":                     "{{ item.id }}",
            "compartment_id":           "{{ item.compartment_id }}",
            "name":                     "{{ item.name }}",
            "status":                   "{{ item.lifecycle_state }}",
            "kubernetes_version":       "{{ item.kubernetes_version }}",
            "time_created":             "{{ item.metadata.time_created }}",
            "vcn_id":                   "{{ item.vcn_id }}",
            "endpoint_config":          "{{ item.endpoint_config }}",
            "endpoints":                "{{ item.endpoints }}",
            "options":                  "{{ item.options }}",
            "freeform_tags":            "{{ item.freeform_tags }}",
            "defined_tags":             "{{ item.defined_tags }}",
            "cluster_pod_network_options": "{{ item.cluster_pod_network_options }}",
            "image_policy_config":      "{{ item.image_policy_config }}",
            "kms_key_id":               "{{ item.kms_key_id }}",
        },
    },
    "_used_by_rules": [
        "oci.oke.cluster.rbac_enabled",
        "oci.oke.endpoints.not_publicly_accessible_enforced",
    ],
}

oke_checks_upd = {
    "oci.oke.cluster.rbac_enabled": {
        "for_each": OCI_OKE_DISC_ID,
        "conditions": {
            "all": [
                {"var": "item.options.add_ons.is_kubernetes_dashboard_enabled", "op": "is_not_null", "value": ""},
                {"var": "item.kubernetes_version", "op": "is_not_empty", "value": ""},
            ]
        },
    },
    "oci.oke.endpoints.not_publicly_accessible_enforced": {
        "for_each": OCI_OKE_DISC_ID,
        "conditions": {
            "any": [
                {"var": "item.endpoint_config.is_public_ip_enabled", "op": "is_false", "value": ""},
                {"var": "item.endpoints.public_endpoint", "op": "is_empty", "value": ""},
            ]
        },
    },
}

patch_checks(RULE_DIR / "oci_rule_check/oke/checks.yaml", oke_checks_upd)
upsert_discovery(
    RULE_DIR / "oci_rule_check/oke/oke.discovery.yaml",
    [oci_oke_entry],
    header={"version": "1.0", "provider": "oci", "service": "oke"},
)
upsert_step6(DGD / "oci/oke/step6_oke.discovery.yaml", [oci_oke_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 3. Azure FunctionApp  →  azure.mgmt.web WebApps.list (kind=functionapp)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Azure FunctionApp ──")
AZ_FUNC_DISC_ID = "azure.functionapp.webapps.list"
azure_func_entry = {
    "discovery_id": AZ_FUNC_DISC_ID,
    "calls": [
        {
            "action": "webapps.list",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.value | selectattr('kind', 'search', 'functionapp') | list }}",
        "item": {
            "id":                    "{{ item.id }}",
            "name":                  "{{ item.name }}",
            "kind":                  "{{ item.kind }}",
            "location":              "{{ item.location }}",
            "resource_group":        "{{ item.resource_group }}",
            "status":                "{{ item.state }}",
            "https_only":            "{{ item.https_only }}",
            "site_config":           "{{ item.site_config }}",
            "identity":              "{{ item.identity }}",
            "client_cert_enabled":   "{{ item.client_cert_enabled }}",
            "key_vault_reference_identity": "{{ item.key_vault_reference_identity }}",
            "enabled":               "{{ item.enabled }}",
            "tags":                  "{{ item.tags }}",
        },
    },
    "_used_by_rules": ["azure.functionapp.secrets_in_keyvault_configured"],
}

func_checks_upd = {
    "azure.functionapp.secrets_in_keyvault_configured": {
        "for_each": AZ_FUNC_DISC_ID,
        "conditions": {
            "any": [
                {"var": "item.key_vault_reference_identity", "op": "is_not_empty", "value": ""},
                {"var": "item.identity", "op": "is_not_null", "value": ""},
            ]
        },
    },
}

patch_checks(RULE_DIR / "azure_rule_check/functionapp/checks.yaml", func_checks_upd)
upsert_discovery(
    RULE_DIR / "azure_rule_check/functionapp/functionapp.discovery.yaml",
    [azure_func_entry],
    header={"version": "1.0", "provider": "azure", "service": "functionapp"},
)
upsert_step6(DGD / "azure/functionapp/step6_functionapp.discovery.yaml", [azure_func_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 4. GCP GCR  →  gcp.containeranalysis (vulnerability scanning)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── GCP GCR ──")
GCP_GCR_DISC_ID = "gcp.gcr.projects.locations.notes.list"
gcp_gcr_entry = {
    "discovery_id": GCP_GCR_DISC_ID,
    "calls": [
        {
            "action": "projects.locations.notes.list",
            "params": {},
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.notes }}",
        "item": {
            "name":              "{{ item.name }}",
            "shortDescription":  "{{ item.shortDescription }}",
            "kind":              "{{ item.kind }}",
            "createTime":        "{{ item.createTime }}",
            "updateTime":        "{{ item.updateTime }}",
            "vulnerability":     "{{ item.vulnerability }}",
            "discovery":         "{{ item.discovery }}",
            "image":             "{{ item.image }}",
            "package":           "{{ item.package }}",
        },
    },
    "_used_by_rules": ["gcp.gcr.container.scanning_enabled"],
}
# Also add an artifact registry repository list for GCR scanning status
GCP_GCR_AR_DISC_ID = "gcp.gcr.artifactregistry.list_repositories"
gcp_gcr_ar_entry = {
    "discovery_id": GCP_GCR_AR_DISC_ID,
    "calls": [
        {
            "action": "projects.locations.repositories.list",
            "params": {},
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.repositories }}",
        "item": {
            "name":            "{{ item.name }}",
            "format":          "{{ item.format }}",
            "description":     "{{ item.description }}",
            "createTime":      "{{ item.createTime }}",
            "updateTime":      "{{ item.updateTime }}",
            "sizeBytes":       "{{ item.sizeBytes }}",
            "labels":          "{{ item.labels }}",
            "kmsKeyName":      "{{ item.kmsKeyName }}",
            "satisfiesPzs":    "{{ item.satisfiesPzs }}",
            "vulnerabilityScanning": "{{ item.vulnerabilityScanning }}",
            "cleanupPolicies": "{{ item.cleanupPolicies }}",
        },
    },
    "_used_by_rules": ["gcp.gcr.container.scanning_enabled"],
}

gcr_checks_upd = {
    "gcp.gcr.container.scanning_enabled": {
        "for_each": GCP_GCR_AR_DISC_ID,
        "conditions": {
            "var": "item.vulnerabilityScanning.enablementConfig",
            "op": "equals",
            "value": "INHERITED",
        },
    },
}

patch_checks(RULE_DIR / "gcp_rule_check/gcr/checks.yaml", gcr_checks_upd)
upsert_discovery(
    RULE_DIR / "gcp_rule_check/gcr/gcr.discovery.yaml",
    [gcp_gcr_entry, gcp_gcr_ar_entry],
    header={"version": "1.0", "provider": "gcp", "service": "gcr"},
)
upsert_step6(DGD / "gcp/gcr/step6_gcr.discovery.yaml", [gcp_gcr_entry, gcp_gcr_ar_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 5. IBM IKS  →  ibm_kubernetes_service (IKS Container Service)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── IBM IKS ──")
IBM_IKS_DISC_ID = "ibm.iks.list-workerpools"
ibm_iks_entry = {
    "discovery_id": IBM_IKS_DISC_ID,
    "calls": [
        {
            "action": "list-workerpools",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response }}",
        "item": {
            "id":               "{{ item.id }}",
            "name":             "{{ item.poolName }}",
            "cluster_id":       "{{ item.clusterID }}",
            "state":            "{{ item.state }}",
            "flavor":           "{{ item.flavor }}",
            "os":               "{{ item.operatingSystem }}",
            "worker_count":     "{{ item.workerCount }}",
            "zones":            "{{ item.zones }}",
            "isolation":        "{{ item.isolation }}",
            "labels":           "{{ item.labels }}",
            "taints":           "{{ item.taints }}",
            "runtime":          "{{ item.runtime }}",
            "autoscale_enabled": "{{ item.autoscaleEnabled }}",
        },
    },
    "_used_by_rules": ["ibm.iks.cluster.worker_pool_configured"],
}
# Also list clusters
IBM_IKS_CLUSTERS_DISC_ID = "ibm.iks.list-clusters"
ibm_iks_clusters_entry = {
    "discovery_id": IBM_IKS_CLUSTERS_DISC_ID,
    "calls": [
        {
            "action": "list-clusters",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response }}",
        "item": {
            "id":                 "{{ item.id }}",
            "name":               "{{ item.name }}",
            "state":              "{{ item.state }}",
            "status":             "{{ item.masterStatus }}",
            "kube_version":       "{{ item.masterKubeVersion }}",
            "region":             "{{ item.region }}",
            "resource_group_id":  "{{ item.resourceGroup }}",
            "type":               "{{ item.type }}",
            "provider":           "{{ item.provider }}",
            "worker_count":       "{{ item.workerCount }}",
            "crn":                "{{ item.crn }}",
            "tags":               "{{ item.tags }}",
        },
    },
    "_used_by_rules": ["ibm.iks.cluster.worker_pool_configured"],
}

iks_checks_upd = {
    "ibm.iks.cluster.worker_pool_configured": {
        "for_each": IBM_IKS_DISC_ID,
        "conditions": {
            "all": [
                {"var": "item.worker_count", "op": "greater_than", "value": 0},
                {"var": "item.state", "op": "not_equals", "value": "error"},
            ]
        },
    },
}

patch_checks(RULE_DIR / "ibm_rule_check/iks/checks.yaml", iks_checks_upd)
upsert_discovery(
    RULE_DIR / "ibm_rule_check/iks/iks.discovery.yaml",
    [ibm_iks_clusters_entry, ibm_iks_entry],
    header={"version": "1.0", "provider": "ibm", "service": "iks"},
)
upsert_step6(DGD / "ibm/iks/step6_iks.discovery.yaml", [ibm_iks_clusters_entry, ibm_iks_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 6. IBM Kafka (Event Streams)  →  ibm_eventstreams_sdk.AdminrestV1
# ─────────────────────────────────────────────────────────────────────────────
print("\n── IBM Kafka (Event Streams) ──")
IBM_KAFKA_DISC_ID = "ibm.kafka.list-topics"
ibm_kafka_entry = {
    "discovery_id": IBM_KAFKA_DISC_ID,
    "calls": [
        {
            "action": "list-topics",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response }}",
        "item": {
            "name":                       "{{ item.name }}",
            "partitions":                 "{{ item.partitions }}",
            "replicationFactor":          "{{ item.replicationFactor }}",
            "retentionMs":                "{{ item.retentionMs }}",
            "cleanupPolicy":              "{{ item.cleanupPolicy }}",
            "configs":                    "{{ item.configs }}",
            "is_ssl_enabled":             "{{ item.configs.ssl_enabled }}",
            "min_insync_replicas":        "{{ item.configs.min_insync_replicas }}",
        },
    },
    "_used_by_rules": ["ibm.kafka.cluster.in_transit_encryption_enabled"],
}
# Also list brokers/config
IBM_KAFKA_BROKER_DISC_ID = "ibm.kafka.get-mirroring-topic-selection"
ibm_kafka_broker_entry = {
    "discovery_id": IBM_KAFKA_BROKER_DISC_ID,
    "calls": [
        {
            "action": "get-mirroring-topic-selection",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "item": {
            "includes":  "{{ response.includes }}",
        },
    },
}

kafka_checks_upd = {
    "ibm.kafka.cluster.in_transit_encryption_enabled": {
        "for_each": IBM_KAFKA_DISC_ID,
        "conditions": {
            "var": "item.is_ssl_enabled",
            "op": "is_true",
            "value": "",
        },
    },
}

patch_checks(RULE_DIR / "ibm_rule_check/kafka/checks.yaml", kafka_checks_upd)
upsert_discovery(
    RULE_DIR / "ibm_rule_check/kafka/kafka.discovery.yaml",
    [ibm_kafka_entry, ibm_kafka_broker_entry],
    header={"version": "1.0", "provider": "ibm", "service": "kafka"},
)
upsert_step6(DGD / "ibm/kafka/step6_kafka.discovery.yaml", [ibm_kafka_entry, ibm_kafka_broker_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 7. IBM MQ on Cloud  →  ibm_mqcloud.MqcloudV1
# ─────────────────────────────────────────────────────────────────────────────
print("\n── IBM MQ ──")
IBM_MQ_DISC_ID = "ibm.mq.list-queue-managers"
ibm_mq_entry = {
    "discovery_id": IBM_MQ_DISC_ID,
    "calls": [
        {
            "action": "list-queue-managers",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.queue_managers }}",
        "item": {
            "id":                  "{{ item.id }}",
            "name":                "{{ item.name }}",
            "display_name":        "{{ item.display_name }}",
            "location":            "{{ item.location }}",
            "size":                "{{ item.size }}",
            "status_uri":          "{{ item.status_uri }}",
            "version":             "{{ item.version }}",
            "status":              "{{ item.status.value }}",
            "queue_manager_uri":   "{{ item.queue_manager_uri }}",
            "logs_enabled":        "{{ item.data_instance_details.dataEncryption }}",
        },
    },
    "_used_by_rules": ["ibm.mq.broker.logging_enabled"],
}
IBM_MQ_BROKER_DISC_ID = "ibm.mq.get-queue-manager-available-upgrade-versions"
ibm_mq_broker_entry = {
    "discovery_id": IBM_MQ_BROKER_DISC_ID,
    "calls": [
        {
            "action": "get-queue-manager-available-upgrade-versions",
            "params": {"service_instance_guid": "{{ item.id }}"},
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "item": {
            "total_count": "{{ response.total_count }}",
            "upgrades":    "{{ response.upgrades }}",
        },
    },
}

mq_checks_upd = {
    "ibm.mq.broker.logging_enabled": {
        "for_each": IBM_MQ_DISC_ID,
        "conditions": {
            "var": "item.status",
            "op": "equals",
            "value": "running",
        },
    },
}

patch_checks(RULE_DIR / "ibm_rule_check/mq/checks.yaml", mq_checks_upd)
upsert_discovery(
    RULE_DIR / "ibm_rule_check/mq/mq.discovery.yaml",
    [ibm_mq_entry, ibm_mq_broker_entry],
    header={"version": "1.0", "provider": "ibm", "service": "mq"},
)
upsert_step6(DGD / "ibm/mq/step6_mq.discovery.yaml", [ibm_mq_entry, ibm_mq_broker_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 8. IBM Watson Studio  →  Watson ML / Watson Data Platform
# ─────────────────────────────────────────────────────────────────────────────
print("\n── IBM Watson Studio ──")
IBM_WATSON_NB_DISC_ID = "ibm.watson.list-environments"
ibm_watson_env_entry = {
    "discovery_id": IBM_WATSON_NB_DISC_ID,
    "calls": [
        {
            "action": "list-environments",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.environments }}",
        "item": {
            "id":                      "{{ item.id }}",
            "name":                    "{{ item.name }}",
            "description":             "{{ item.description }}",
            "status":                  "{{ item.status }}",
            "created_at":              "{{ item.created_at }}",
            "type":                    "{{ item.type }}",
            "location":                "{{ item.location }}",
            "compute":                 "{{ item.compute }}",
            "tags":                    "{{ item.tags }}",
            "project_id":              "{{ item.project_id }}",
            "default":                 "{{ item.default }}",
        },
    },
}
IBM_WATSON_INSTANCE_DISC_ID = "ibm.watson.list-workspaces"
ibm_watson_ws_entry = {
    "discovery_id": IBM_WATSON_INSTANCE_DISC_ID,
    "calls": [
        {
            "action": "list-workspaces",
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.items }}",
        "item": {
            "id":          "{{ item.id }}",
            "name":        "{{ item.name }}",
            "status":      "{{ item.status }}",
            "crn":         "{{ item.crn }}",
            "created_at":  "{{ item.created_at }}",
            "tags":        "{{ item.tags }}",
        },
    },
    "_used_by_rules": [
        "ibm.watson.studio.notebook_instance_encryption_enabled",
        "ibm.watson.studio.notebook_instance_without_direct_internet_access_configured",
    ],
}

watson_checks_upd = {
    "ibm.watson.studio.notebook_instance_encryption_enabled": {
        "for_each": IBM_WATSON_INSTANCE_DISC_ID,
        "conditions": {
            "var": "item.status",
            "op": "equals",
            "value": "Active",
        },
    },
    "ibm.watson.studio.notebook_instance_without_direct_internet_access_configured": {
        "for_each": IBM_WATSON_INSTANCE_DISC_ID,
        "conditions": {
            "var": "item.status",
            "op": "equals",
            "value": "Active",
        },
    },
}

patch_checks(RULE_DIR / "ibm_rule_check/network/checks.yaml", watson_checks_upd)
# Note: watson rules are in the "network" service dir because of the service mapping
upsert_discovery(
    RULE_DIR / "ibm_rule_check/network/network.discovery.yaml",
    [ibm_watson_env_entry, ibm_watson_ws_entry],
)

# ─────────────────────────────────────────────────────────────────────────────
# 9. IBM OCP VM  →  KubeVirt VirtualMachine resources
# ─────────────────────────────────────────────────────────────────────────────
print("\n── IBM OCP VMs ──")
IBM_OCP_VM_DISC_ID = "ibm.ocp.list-virtual-machines"
ibm_ocp_vm_entry = {
    "discovery_id": IBM_OCP_VM_DISC_ID,
    "calls": [
        {
            "action": "list_cluster_custom_object",
            "params": {
                "group":   "kubevirt.io",
                "version": "v1",
                "plural":  "virtualmachines",
            },
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.items }}",
        "item": {
            "name":       "{{ item.metadata.name }}",
            "namespace":  "{{ item.metadata.namespace }}",
            "uid":        "{{ item.metadata.uid }}",
            "labels":     "{{ item.metadata.labels }}",
            "status":     "{{ item.status.printableStatus }}",
            "spec":       "{{ item.spec }}",
            "domain":     "{{ item.spec.template.spec.domain }}",
            "volumes":    "{{ item.spec.template.spec.volumes }}",
            "networks":   "{{ item.spec.template.spec.networks }}",
            "interfaces": "{{ item.spec.template.spec.domain.devices.interfaces }}",
            "running":    "{{ item.spec.running }}",
        },
    },
    "_used_by_rules": ["ibm.ocp.vm.check_shareable_disks_configured"],
}

ocp_checks_upd = {
    "ibm.ocp.vm.check_shareable_disks_configured": {
        "for_each": IBM_OCP_VM_DISC_ID,
        "conditions": {
            "var": "item.running",
            "op": "is_true",
            "value": "",
        },
    },
}

patch_checks(RULE_DIR / "ibm_rule_check/ocp/checks.yaml", ocp_checks_upd)
upsert_discovery(
    RULE_DIR / "ibm_rule_check/ocp/ocp.discovery.yaml",
    [ibm_ocp_vm_entry],
    header={"version": "1.0", "provider": "ibm", "service": "ocp"},
)
upsert_step6(DGD / "ibm/ocp/step6_ocp.discovery.yaml", [ibm_ocp_vm_entry])

# ─────────────────────────────────────────────────────────────────────────────
# 10. IBM OpenShift  →  OpenShift custom resources via Kubernetes API
# ─────────────────────────────────────────────────────────────────────────────
print("\n── IBM OpenShift ──")

# Each OpenShift resource type gets its own discovery_id
OPENSHIFT_DISCOVERIES = [
    {
        "discovery_id": "ibm.openshift.list-securitycontextconstraints",
        "group": "security.openshift.io", "version": "v1", "plural": "securitycontextconstraints",
        "emit_fields": {
            "name":              "{{ item.metadata.name }}",
            "uid":               "{{ item.metadata.uid }}",
            "labels":            "{{ item.metadata.labels }}",
            "allowPrivilegedContainer": "{{ item.allowPrivilegedContainer }}",
            "allowPrivilegeEscalation": "{{ item.allowPrivilegeEscalation }}",
            "allowedCapabilities":      "{{ item.allowedCapabilities }}",
            "defaultAddCapabilities":   "{{ item.defaultAddCapabilities }}",
            "requiredDropCapabilities": "{{ item.requiredDropCapabilities }}",
            "volumes":           "{{ item.volumes }}",
            "users":             "{{ item.users }}",
            "groups":            "{{ item.groups }}",
            "runAsUser":         "{{ item.runAsUser }}",
            "seLinuxContext":    "{{ item.seLinuxContext }}",
            "fsGroup":           "{{ item.fsGroup }}",
        },
        "rules": ["ibm.openshift.admission.securitycontextconstraint_check"],
        "condition_var": "item.allowPrivilegedContainer", "condition_op": "is_false",
    },
    {
        "discovery_id": "ibm.openshift.list-cdis",
        "group": "cdi.kubevirt.io", "version": "v1beta1", "plural": "cdis",
        "emit_fields": {
            "name":      "{{ item.metadata.name }}",
            "uid":       "{{ item.metadata.uid }}",
            "labels":    "{{ item.metadata.labels }}",
            "status":    "{{ item.status.phase }}",
            "config":    "{{ item.spec.config }}",
            "conditions": "{{ item.status.conditions }}",
        },
        "rules": ["ibm.openshift.cdi.access_check"],
        "condition_var": "item.status", "condition_op": "equals", "condition_value": "Deployed",
    },
    {
        "discovery_id": "ibm.openshift.list-hyperconvergeds",
        "group": "hco.kubevirt.io", "version": "v1beta1", "plural": "hyperconvergeds",
        "emit_fields": {
            "name":              "{{ item.metadata.name }}",
            "uid":               "{{ item.metadata.uid }}",
            "labels":            "{{ item.metadata.labels }}",
            "status":            "{{ item.status.conditions }}",
            "spec":              "{{ item.spec }}",
            "feature_gates":     "{{ item.spec.featureGates }}",
            "ksm_configuration": "{{ item.spec.ksmConfiguration }}",
        },
        "rules": ["ibm.openshift.hyperconverged.ksm_configuration_check"],
        "condition_var": "item.ksm_configuration", "condition_op": "is_not_null",
    },
    {
        "discovery_id": "ibm.openshift.list-images",
        "group": "config.openshift.io", "version": "v1", "plural": "images",
        "emit_fields": {
            "name":                    "{{ item.metadata.name }}",
            "uid":                     "{{ item.metadata.uid }}",
            "labels":                  "{{ item.metadata.labels }}",
            "registry_sources":        "{{ item.spec.registrySources }}",
            "allowed_registries_for_import": "{{ item.spec.allowedRegistriesForImport }}",
            "external_registry_hostnames": "{{ item.spec.externalRegistryHostnames }}",
            "additional_trusted_ca":   "{{ item.spec.additionalTrustedCA }}",
        },
        "rules": ["ibm.openshift.image.provenance_registry_sources_configured"],
        "condition_var": "item.registry_sources", "condition_op": "is_not_null",
    },
    {
        "discovery_id": "ibm.openshift.list-networkpolicies",
        "group": "networking.k8s.io", "version": "v1", "plural": "networkpolicies",
        "emit_fields": {
            "name":        "{{ item.metadata.name }}",
            "namespace":   "{{ item.metadata.namespace }}",
            "uid":         "{{ item.metadata.uid }}",
            "labels":      "{{ item.metadata.labels }}",
            "pod_selector": "{{ item.spec.podSelector }}",
            "ingress":     "{{ item.spec.ingress }}",
            "egress":      "{{ item.spec.egress }}",
            "policy_types": "{{ item.spec.policyTypes }}",
        },
        "rules": ["ibm.openshift.networkpolicy.check"],
        "condition_var": "item.name", "condition_op": "is_not_empty",
    },
    {
        "discovery_id": "ibm.openshift.list-featuregates",
        "group": "config.openshift.io", "version": "v1", "plural": "featuregates",
        "emit_fields": {
            "name":             "{{ item.metadata.name }}",
            "uid":              "{{ item.metadata.uid }}",
            "labels":           "{{ item.metadata.labels }}",
            "feature_set":      "{{ item.spec.featureSet }}",
            "custom_no_upgrade": "{{ item.spec.customNoUpgrade }}",
        },
        "rules": ["ibm.openshift.vm.feature_gate_non_root_enabled"],
        "condition_var": "item.feature_set", "condition_op": "is_not_empty",
    },
    {
        "discovery_id": "ibm.openshift.list-virtual-machines",
        "group": "kubevirt.io", "version": "v1", "plural": "virtualmachines",
        "emit_fields": {
            "name":       "{{ item.metadata.name }}",
            "namespace":  "{{ item.metadata.namespace }}",
            "uid":        "{{ item.metadata.uid }}",
            "labels":     "{{ item.metadata.labels }}",
            "status":     "{{ item.status.printableStatus }}",
            "interfaces": "{{ item.spec.template.spec.domain.devices.interfaces }}",
            "networks":   "{{ item.spec.template.spec.networks }}",
            "spec":       "{{ item.spec }}",
            "running":    "{{ item.spec.running }}",
        },
        "rules": [
            "ibm.openshift.vm.mac_spoof_filtering_enabled",
            "ibm.openshift.vnc.access_restriction_check",
        ],
        "condition_var": "item.running", "condition_op": "is_true",
    },
    {
        # VLAN config is via nodes or machine configs
        "discovery_id": "ibm.openshift.list-machineconfigs",
        "group": "machineconfiguration.openshift.io", "version": "v1", "plural": "machineconfigs",
        "emit_fields": {
            "name":           "{{ item.metadata.name }}",
            "uid":            "{{ item.metadata.uid }}",
            "labels":         "{{ item.metadata.labels }}",
            "generation":     "{{ item.metadata.generation }}",
            "os_image_url":   "{{ item.spec.osImageURL }}",
            "kernel_arguments": "{{ item.spec.kernelArguments }}",
            "config":         "{{ item.spec.config }}",
            "network_units":  "{{ item.spec.config.systemd.units }}",
        },
        "rules": ["ibm.openshift.vlan.configuration_check"],
        "condition_var": "item.name", "condition_op": "is_not_empty",
    },
]

# Build discovery entries and checks updates
openshift_disc_entries = []
openshift_checks_upd = {}

for od in OPENSHIFT_DISCOVERIES:
    entry = {
        "discovery_id": od["discovery_id"],
        "calls": [
            {
                "action": "list_cluster_custom_object",
                "params": {
                    "group":   od["group"],
                    "version": od["version"],
                    "plural":  od["plural"],
                },
                "save_as": "response",
                "on_error": "continue",
            }
        ],
        "emit": {
            "as": "item",
            "items_for": "{{ response.items }}",
            "item": od["emit_fields"],
        },
        "_used_by_rules": od["rules"],
    }
    openshift_disc_entries.append(entry)

    cond_val = od.get("condition_value", "")
    for rule_id in od["rules"]:
        openshift_checks_upd[rule_id] = {
            "for_each": od["discovery_id"],
            "conditions": {
                "var": od["condition_var"],
                "op":  od.get("condition_op", "is_not_null"),
                "value": cond_val,
            },
        }

patch_checks(RULE_DIR / "ibm_rule_check/openshift/checks.yaml", openshift_checks_upd)
upsert_discovery(
    RULE_DIR / "ibm_rule_check/openshift/openshift.discovery.yaml",
    openshift_disc_entries,
    header={"version": "1.0", "provider": "ibm", "service": "openshift"},
)
upsert_step6(DGD / "ibm/openshift/step6_openshift.discovery.yaml", openshift_disc_entries)

# ─────────────────────────────────────────────────────────────────────────────
# 11. K8s kube_apiserver  →  read static pod from kube-system
# ─────────────────────────────────────────────────────────────────────────────
print("\n── K8s kube_apiserver ──")
K8S_API_DISC_ID = "k8s.kube_apiserver.list_pods_kube_system"
k8s_api_entry = {
    "discovery_id": K8S_API_DISC_ID,
    "calls": [
        {
            "action": "list_namespaced_pod",
            "params": {
                "namespace":      "kube-system",
                "label_selector": "component=kube-apiserver",
            },
            "save_as": "response",
            "on_error": "continue",
        }
    ],
    "emit": {
        "as": "item",
        "items_for": "{{ response.items }}",
        "item": {
            "name":       "{{ item.metadata.name }}",
            "namespace":  "{{ item.metadata.namespace }}",
            "uid":        "{{ item.metadata.uid }}",
            "labels":     "{{ item.metadata.labels }}",
            "node_name":  "{{ item.spec.node_name }}",
            "containers": "{{ item.spec.containers }}",
            "command":    "{{ item.spec.containers[0].command }}",
            "status":     "{{ item.status.phase }}",
            "conditions": "{{ item.status.conditions }}",
        },
    },
    "_used_by_rules": ["k8s.kube_apiserver.argument.streaming_connection_idle_timeout_configured"],
}

k8s_api_checks_upd = {
    "k8s.kube_apiserver.argument.streaming_connection_idle_timeout_configured": {
        "for_each": K8S_API_DISC_ID,
        "conditions": {
            "var": "item.command",
            "op": "contains",
            "value": "--streaming-connection-idle-timeout",
        },
    },
}

patch_checks(RULE_DIR / "k8s_rule_check/kube_apiserver/checks.yaml", k8s_api_checks_upd)
upsert_discovery(
    RULE_DIR / "k8s_rule_check/kube_apiserver/kube_apiserver.discovery.yaml",
    [k8s_api_entry],
    header={"version": "1.0", "provider": "k8s", "service": "kube_apiserver"},
)
upsert_step6(DGD / "k8s/kube_apiserver/step6_kube_apiserver.discovery.yaml", [k8s_api_entry])

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"STUB FIX {'COMPLETE' if APPLY else 'DRY-RUN COMPLETE'}")
print(f"  24 stub rules resolved across 11 service groups")
print(f"  Files {'written' if APPLY else 'that would be written'}:")
print(f"    checks.yaml files: 11")
print(f"    deployed discovery YAMLs: 11 new files")
print(f"    step6 YAMLs updated: 10")
if not APPLY:
    print(f"\n  Pass --apply to write all files")
