# RDS Config and EKS Usage

## consolidated_services/database – where config comes from

### 1. Code: `config/database_config.py`

All engines read from **environment variables** (pydantic-settings):

| Engine     | Host              | Port  | Database                 | User              | Password (env)           |
|-----------|-------------------|-------|---------------------------|-------------------|---------------------------|
| configscan| CONFIGSCAN_DB_HOST| CONFIGSCAN_DB_PORT | CONFIGSCAN_DB_NAME | CONFIGSCAN_DB_USER | CONFIGSCAN_DB_PASSWORD |
| compliance| COMPLIANCE_DB_*   | same  | threat_engine_compliance   | same              | COMPLIANCE_DB_PASSWORD    |
| inventory | INVENTORY_DB_*    | same  | threat_engine_inventory    | same              | INVENTORY_DB_PASSWORD     |
| threat    | THREAT_DB_*       | same  | threat_engine_threat       | same              | THREAT_DB_PASSWORD        |
| shared    | SHARED_DB_*       | same  | threat_engine_shared        | same              | SHARED_DB_PASSWORD        |

So EKS (or any deployer) must set these env vars; typically **host/port/name/user** from a ConfigMap and **passwords** from a Secret.

### 2. Init script: `scripts/init_rds_for_eks.sh`

Used to **create DBs and apply schemas** on RDS. It uses:

| Env var (preferred in EKS) | Fallback   | Purpose        |
|----------------------------|------------|----------------|
| RDS_HOST                   | PGHOST     | RDS endpoint   |
| RDS_PORT                   | PGPORT     | 5432           |
| RDS_SUPERUSER              | PGUSER     | e.g. postgres  |
| RDS_SUPERUSER_PASSWORD     | PGPASSWORD | Master password|
| PGSSLMODE                  | (optional) | e.g. require   |

The init Job in EKS gets these from the K8s secret **threat-engine-rds-credentials** (see `deployment/aws/eks/jobs/init-threat-engine-databases-job.yaml`).

---

## EKS – current sources of RDS config

| What                | Type     | File / source | Used for |
|---------------------|----------|---------------|----------|
| Host, port, DB, user| ConfigMap| `threat-engine-db-config` | All engines (envFrom) |
| Passwords           | Secret   | `threat-engine-db-passwords` | All engines (envFrom) |
| Init job creds      | Secret   | `threat-engine-rds-credentials` (kubectl create) | DB init job only |
| Legacy DB URL       | ConfigMap| `platform-config` → database-url | Onboarding / scheduler |

So today:

- **Engines**: get host/port/db/user from ConfigMap + passwords from Secret.
- **Init job**: gets RDS superuser from a **separate** secret (`threat-engine-rds-credentials`), which is not synced from anywhere by default.

To use **AWS Secrets Manager** for RDS in EKS, you sync one or two secrets from Secrets Manager into these K8s secrets. See **deployment/aws/eks/EKS_SECRETS_MANAGER.md** and the External Secrets example there.
