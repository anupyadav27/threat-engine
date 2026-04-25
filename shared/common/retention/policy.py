"""
Retention policy: which tables to archive/clean per engine.

Layout:
  DB  → keep last KEEP_IN_DB scan_run_ids  (hot, fast queries)
  S3  → keep next KEEP_IN_S3 scan_run_ids  (cold archive, recoverable)
  Old → delete from both                   (scans beyond KEEP_IN_DB + KEEP_IN_S3)

Total retention = KEEP_IN_DB + KEEP_IN_S3 = 10 scans per provider by default.

Tables with a `provider` column use partition_by="provider" so each CSP
(aws, azure, gcp, k8s, …) maintains its own independent 5-scan window.
Without partitioning, a burst of Azure/GCP scans would evict AWS findings
before inventory or check get a chance to read them.

Tables without a provider column (risk_*, log_events) retain the global limit.
"""

KEEP_IN_DB: int = 5
KEEP_IN_S3: int = 5

# S3 destination — override via env ARCHIVE_S3_BUCKET / ARCHIVE_S3_PREFIX
DEFAULT_S3_BUCKET: str = "anup-backup"
DEFAULT_S3_PREFIX: str = "threat-engine-archives"

# Each entry: conn_factory matches a function in engine_common.db_connections
# partition_by: column to partition retention by (keeps KEEP_IN_DB per partition value)
ENGINE_POLICY: dict = {
    "discoveries": {
        "conn_factory": "get_discoveries_conn",
        "tables": [
            {"name": "discovery_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
            {"name": "discovery_history",  "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "check": {
        "conn_factory": "get_check_conn",
        "tables": [
            {"name": "check_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "inventory": {
        "conn_factory": "get_inventory_conn",
        "tables": [
            {"name": "inventory_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
            {"name": "log_events",         "timestamp_col": "ingestion_time"},  # no provider column
        ],
    },
    "threat": {
        "conn_factory": "get_threat_conn",
        "tables": [
            {"name": "threat_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "compliance": {
        "conn_factory": "get_compliance_conn",
        "tables": [
            {"name": "compliance_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "iam": {
        "conn_factory": "get_iam_conn",
        "tables": [
            {"name": "iam_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "network": {
        "conn_factory": "get_network_conn",
        "tables": [
            {"name": "network_findings",          "timestamp_col": "first_seen_at", "partition_by": "provider"},
            {"name": "network_topology_snapshot", "timestamp_col": "created_at",    "partition_by": "provider"},
        ],
    },
    "datasec": {
        "conn_factory": "get_datasec_conn",
        "tables": [
            {"name": "datasec_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "ciem": {
        "conn_factory": "get_ciem_conn",
        "tables": [
            {"name": "ciem_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "risk": {
        "conn_factory": "get_risk_conn",
        "tables": [
            # risk tables have no provider column — global retention only
            {"name": "risk_scenarios",         "timestamp_col": "created_at"},
            {"name": "risk_input_transformed", "timestamp_col": "scanned_at"},
            {"name": "risk_summary",           "timestamp_col": "created_at"},
        ],
    },
    "encryption": {
        "conn_factory": "get_encryption_conn",
        "tables": [
            {"name": "encryption_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "container": {
        "conn_factory": "get_container_sec_conn",
        "tables": [
            {"name": "container_sec_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "dbsec": {
        "conn_factory": "get_dbsec_conn",
        "tables": [
            {"name": "dbsec_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
    "ai_security": {
        "conn_factory": "get_ai_security_conn",
        "tables": [
            {"name": "ai_security_findings", "timestamp_col": "first_seen_at", "partition_by": "provider"},
        ],
    },
}
