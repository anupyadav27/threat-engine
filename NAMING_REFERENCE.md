# CSPM Naming Reference

**Convention**: `engine_*` prefix for all engines, `data_*` for data/config folders. Ensures engines (rule, threat, compliance, etc.) are discoverable and consistent.

## Top-Level Folders

| Current | New | Purpose |
|--------|-----|---------|
| `engine_threats` | `engine_threat` | Threat detection engine |
| `engine_compliance` | *(no change)* | Compliance engine |
| `engine_inventory` | *(no change)* | Inventory engine |
| `engine_onboarding` | *(no change)* | Onboarding & orchestration |
| `engine_rule` | *(no change)* | Rule engine |
| `engine_userportal` | *(no change)* | User-facing portal |
| `engine_adminportal` | *(no change)* | Admin portal |
| `engine_secops` | *(no change)* | SecOps vulnerability scanner |
| `datasec_engine` | `engine_datasec` | Data security engine |
| `engines_configScan` | `engine_configscan` | ConfigScan engines parent |
| `engines_configScan/aws-configScan-engine` | `engine_configscan/engine_configscan_aws` | AWS ConfigScan |
| `engines_configScan/azure-configScan-engine` | `engine_configscan/engine_configscan_azure` | Azure ConfigScan |
| `engines_configScan/gcp-configScan-engine` | `engine_configscan/engine_configscan_gcp` | GCP ConfigScan |
| `engines_configScan/alicloud-configScan-engine` | `engine_configscan/engine_configscan_alicloud` | AliCloud ConfigScan |
| `engines_configScan/oci-configScan-engine` | `engine_configscan/engine_configscan_oci` | OCI ConfigScan |
| `engines_configScan/ibm-configScan-engine` | `engine_configscan/engine_configscan_ibm` | IBM ConfigScan |
| `engines_configScan/k8s-configScan-engine` | `engine_configscan/engine_configscan_k8s` | K8s ConfigScan |
| `engines_input` | `engine_input` | ConfigScan rule_db input |
| `engines_output` | `engine_output` | Scan output (NDJSON, etc.) |
| `common` | `engine_common` | Shared libs (logger, storage_paths, etc.) |
| `data_compliance` | *(no change)* | Compliance rules data |
| `data_pythonsdk` | *(no change)* | Python SDK / rule data |

## Path Conventions (storage_paths, env defaults)

- Output base: `engine_output` (project-root relative).
- ConfigScan output: `engine_output/engine_configscan_aws/output/{scan_run_id}/`.
- Inventory output: `engine_output/engine_inventory/output/`.
- Input: `engine_input/engine_configscan_aws/...`. Use `get_project_root()` from `engine_common.storage_paths`; no absolute paths.

## Service / K8s / Docker Names

- Use consistent service names: `engine-threat`, `engine-compliance`, `engine-inventory`, `engine-datasec`, `engine-rule`, `engine-secops`, `engine-configscan-aws`, etc.
- Container names and URLs can use same kebab-case.

## Database (consolidated)

- Single PostgreSQL; schemas use **engine_*** prefix: `engine_shared`, `engine_onboarding`, `engine_configscan`, `engine_compliance`, `engine_inventory`, `engine_userportal`, `engine_adminportal`, `engine_secops`.
- Init script: `scripts/init-databases.sql`. All services use `DATABASE_URL` + `DB_SCHEMA`.

## Inner Python Packages

- Keep inner packages as-is (`threat_engine`, `compliance_engine`, `inventory_engine`) to minimize import churn. Imports remain `from threat_engine.x import ...`; only parent folder is `engine_threat`.
- `engine_onboarding` uses package name `engine_onboarding` (internal imports updated from `onboarding`).

---

## Architecture Review & Improvements

### Naming & discoverability
- **engine_*** prefix makes all engines visible in one place (engine_threat, engine_rule, engine_compliance, etc.), reducing “missing” engines in docs or scripts.
- **engine_input** / **engine_output** / **engine_common**: input, output, and shared code. **data_*** (`data_compliance`, `data_pythonsdk`) for static assets.

### Performance
- **No runtime impact**: Renames are folder/module names and path strings only. Import resolution and I/O are unchanged.
- **Path length**: `engine_configscan_aws` vs `aws-configScan-engine` is similar; no meaningful perf difference.

### Suggested improvements
1. **Single source of CSP → folder mapping**: `common/storage_paths` and each engine’s `get_csp_s3_path`-style logic should share one map (e.g. `CSP_TO_CONFIGSCAN_FOLDER`) to avoid drift.
2. **Unified engine URL config**: Replace per-engine env vars with one `ENGINE_BASE_URL` + engine name (e.g. `http://engine-threat:8000`) or a small config file used by onboarding, admin portal, and tests.
3. **Consistent Docker build context**: All engine Dockerfiles use repo root as context; ensure `COPY` paths and `common/` usage are uniform.
4. **K8s/Docker align with engine_* names**: Update remaining K8s manifests (e.g. `kubernetes/admin-backend`) to use `engine-threat`, `engine-compliance`, etc., and match docker-compose service names.
5. **engine_output layout**: Standardize subdirs (`engine_configscan_*`, `engine_inventory`, `engine_compliance`, `engine_rule`) and document in `engine_output/README.md`.
6. **Database**: Consolidated single PostgreSQL with `engine_*` schemas; see `DATABASE_DOCUMENTATION.md` and `scripts/init-databases.sql`.
