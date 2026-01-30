# EKS Mumbai (ap-south-1) – S3, RDS & DB Init Runbook

Use this runbook to ensure **S3 is ready**, **RDS is clean** (vulnerability DB untouched), and **all threat-engine databases, tables, and views** are created on a **dedicated** RDS instance.

---

## 1. S3 readiness

- **Bucket:** `cspm-lgtech`
- **Region:** `ap-south-1` (Mumbai)

**Check:**

```bash
aws s3 ls s3://cspm-lgtech/ --region ap-south-1
```

**Config in cluster:** `s3-mount-config` ConfigMap already sets `s3-bucket: cspm-lgtech`, `s3-region: ap-south-1`. Ensure the EKS node/service role has the S3 permissions in `deployment/aws/eks/iam/s3-access-policy.json`.

---

## 2. RDS – do not touch vulnerability DB

- **Do not use:** `postgres-vulnerability-db.*.rds.amazonaws.com` or database `vulnerability_db`.
- **Use a separate RDS** instance in `ap-south-1` for threat engine only.

**On the new RDS instance:**

- Create one PostgreSQL 14+ instance (e.g. `threat-engine-rds`).
- Note: **Host**, **Port**, **Superuser**, **Password** (you will put these in a K8s secret).

---

## 3. Databases to create on the new RDS

All on the **same** RDS instance, **different** databases:

| Database name               | Purpose                          |
|----------------------------|----------------------------------|
| `threat_engine_shared`     | Tenants, customers, orchestration, audit |
| `threat_engine_configscan` | Scans, discoveries, check_results, rule_metadata |
| `threat_engine_compliance` | Compliance outputs, control mappings, views |
| `threat_engine_inventory`  | Inventory assets, relationships |
| `threat_engine_threat`     | Threat/incident data, normalized tables |

---

## 4. Create K8s secret for the new RDS

Create a secret **only** for this new RDS (not for the vulnerability DB):

```bash
kubectl create secret generic threat-engine-rds-credentials \
  --namespace threat-engine-engines \
  --from-literal=RDS_HOST=<new-rds-endpoint> \
  --from-literal=RDS_PORT=5432 \
  --from-literal=RDS_SUPERUSER=postgres \
  --from-literal=RDS_SUPERUSER_PASSWORD='<password>'
```

Optional: set `PGSSLMODE=require` in the init job if your RDS requires SSL.

---

## 5. Run DB init (create DBs, tables, views)

**Option A – From repo (machine that can reach RDS):**

```bash
cd /path/to/threat-engine
export PGHOST=<new-rds-endpoint>
export PGPORT=5432
export PGUSER=postgres
export PGPASSWORD='<password>'
export TE_DB_ROOT=./consolidated_services/database
chmod +x consolidated_services/database/scripts/init_rds_for_eks.sh
./consolidated_services/database/scripts/init_rds_for_eks.sh
```

**Option B – From EKS (init Job):**

1. Build and push the DB init image (see `deployment/aws/eks/jobs/README_DB_INIT.md`).
2. Apply the job:

   ```bash
   kubectl apply -f deployment/aws/eks/jobs/init-threat-engine-databases-job.yaml -n threat-engine-engines
   kubectl wait --for=condition=complete job/init-threat-engine-databases -n threat-engine-engines --timeout=600s
   ```

3. Check logs:

   ```bash
   kubectl logs job/init-threat-engine-databases -n threat-engine-engines
   ```

---

## 6. What the init does (summary)

1. Connects to the **new** RDS (using the secret above).
2. Creates the 5 databases listed in section 3.
3. Applies base schemas in order: **shared → configscan → compliance → inventory → threat**.
4. Runs migrations:
   - **configscan:** `002_add_rule_metadata.sql`, `004_add_threat_metadata.sql`, `008_iam_datasec_views.sql`
   - **threat:** `003_normalize_threat_schema.sql`
   - **compliance:** `005_compliance_output_tables.sql`, `006_compliance_control_mappings.sql`, `007_compliance_analysis_views.sql`

After this, all tables and views needed for threat engine are ready on the new RDS; the vulnerability DB is never used.

---

## 7. Point engines at the new RDS

Set engine env (or ConfigMaps) so all `*_DB_HOST` (and port/user/password) point to the **new** RDS endpoint and the DB names above. Example (same host, different DB names):

- `CONFIGSCAN_DB_HOST=<new-rds-endpoint>`, `CONFIGSCAN_DB_NAME=threat_engine_configscan`
- `COMPLIANCE_DB_HOST=<new-rds-endpoint>`, `COMPLIANCE_DB_NAME=threat_engine_compliance`
- … and similarly for inventory, threat, shared.

`database_config.py` reads these env vars; no code change needed if env is set.

---

## 8. Old onboarding init job (vul DB)

The existing job `init-db-schema` in `deployment/aws/eks/jobs/init-db-schema-job.yaml` targets the **vulnerability** RDS and **onboarding** schema. To avoid touching the vul DB:

- Do **not** apply that job for threat-engine DB setup, or
- Remove/comment the job in your deployment pipeline for EKS Mumbai threat-engine init.

Use **only** the new job/script above for threat-engine databases.
