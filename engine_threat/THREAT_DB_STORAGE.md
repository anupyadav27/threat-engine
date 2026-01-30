# Threat Engine – Database Storage

Threat reports can be stored in **PostgreSQL** instead of local JSON files. Use this for SaaS, multi-node, and DB-backed workflows.

## Enable DB storage

```bash
export THREAT_USE_DB=true
```

With this set, `ThreatStorage` writes to and reads from the **Threat DB** (`threat_reports` table). File storage is not used.

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `THREAT_USE_DB` | Use PostgreSQL for report storage | `false` |
| `THREAT_DB_HOST` | Threat DB host | `localhost` |
| `THREAT_DB_PORT` | Threat DB port | `5432` |
| `THREAT_DB_NAME` | Threat DB name | `threat_engine_threat` |
| `THREAT_DB_USER` | Threat DB user | `threat_user` |
| `THREAT_DB_PASSWORD` | Threat DB password | `threat_password` |
| `DB_SCHEMA` | `search_path` (e.g. `engine_threat,engine_shared`) | `engine_threat,engine_shared` |

## Schema

The writer creates `threat_reports` if it does not exist:

- **`threat_reports`**: `report_id`, `scan_run_id`, `tenant_id`, `cloud`, `trigger_type`, `report_data` (JSONB), `generated_at`, `created_at`, `UNIQUE(tenant_id, scan_run_id)`.

Full report JSON (`cspm_threat_report.v1`) is stored in `report_data`. Upsert is by `(tenant_id, scan_run_id)`.

Schema SQL: `threat_engine/database/threat_reports_schema.sql`.

## Behaviour

- **Save**: `save_report(report)` → inserts/upserts into `threat_reports`.
- **Get**: `get_report(scan_run_id, tenant_id)` → reads from `threat_reports`.
- **List**: `list_reports(tenant_id)` → lists metadata from `threat_reports`.
- **Get threat**: `get_threat(threat_id, tenant_id)` → scans stored reports (best-effort).
- **Update status**: `update_threat_status(...)` → updates report in DB and cache.

When `THREAT_USE_DB=false`, behaviour is unchanged: reports are stored under `THREAT_REPORTS_DIR` (default `./threat_reports`).

## Flow

1. Discovery → Check → Threat → Compliance (all DB-backed).
2. Threat reads check results from **Check DB** (`threat_engine_check`).
3. Threat writes reports to **Threat DB** (`threat_reports`).
4. Compliance can use **Check DB** (`from-check-db`) or, later, **Threat** outputs if stored in DB.

## Setup

1. Create DB and user, e.g.:

   ```sql
   CREATE DATABASE threat_engine_threat;
   CREATE USER threat_user WITH PASSWORD 'threat_password';
   GRANT ALL ON DATABASE threat_engine_threat TO threat_user;
   ```

2. Set `THREAT_USE_DB=true` and `THREAT_DB_*` (and `DB_SCHEMA` if needed).
3. Run the Threat engine; it will create `threat_reports` (and `engine_threat` schema if used) on first use.
