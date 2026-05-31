# Sprint: API Security Engine (APISEC)

## Goal
Standalone API Security engine — OWASP API Top 10 posture checks across 6 CSPs, CDR behavioral enrichment, attack-path integration, and two differentiators no competitor covers (API key rotation + API quota misconfig).

## Competitive Position (2025)

| Feature | Orca | Wiz | Prisma | Our Engine | Sprint |
|---------|------|-----|--------|------------|--------|
| OWASP API Top 10 mapping | yes | yes | yes | yes | S1 |
| Unauthenticated endpoint detection | yes | yes | yes | yes | S1 |
| API GW WAF coverage gap | partial | yes | yes | yes | S1 |
| API key exposed in cloud config | yes | yes | partial | yes | S1 |
| API quota/rate-limit misconfig | no | no | no | **yes — DIFFERENTIATOR** | S1 |
| mTLS enforcement gap | no | yes | partial | yes | S2 |
| GraphQL introspection check | no | partial | yes | yes | S2 |
| API key rotation/expiry | no | no | no | **yes — DIFFERENTIATOR** | S2 |
| BOLA behavioral (CDR-based) | no | partial | no | yes | S3 |
| Shadow API / spec drift | no | yes | partial | deferred | — |

## Engine Facts
- **Port**: 8035 | **DB**: `threat_engine_api_security` | **Pipeline**: Step 5 parallel
- **New posture columns**: `api_auth_type`, `api_has_waf`, `api_has_rate_limit`, `api_publicly_accessible`, `api_deprecated_version_active`, `api_security_score`, `api_detail`
- **Attack-path composite flags added in S3**: `api_public_no_waf`, `api_public_no_auth`
- **security_findings**: `source_engine='api_security'`; S1 → `misconfig`; S2 → `api_exposure`
- **New Django permissions**: `api_security:read`, `api_security:write` (migration 0019)

---

## Sprint 1 — Foundation + AWS (61 pts)

| Story | Title | Points |
|-------|-------|--------|
| [APISEC-S1-01](APISEC-S1-01-db-schema.md) | DB: apisec_001 initial schema + apisec_002 posture columns | 3 |
| [APISEC-S1-02](APISEC-S1-02-shared-module-updates.md) | Shared: db_connections + security_findings_writer + RBAC 0019 | 3 |
| [APISEC-S1-03](APISEC-S1-03-engine-scaffold.md) | FastAPI pod: health + scan trigger endpoint + require_permission | 5 |
| [APISEC-S1-04](APISEC-S1-04-k8s-dockerfile.md) | K8s Deployment/Service (port 8035) + Dockerfile + requirements.txt | 3 |
| [APISEC-S1-05](APISEC-S1-05-run-scan-entrypoint.md) | run_scan.py: SIGTERM + scan_run_id tenant validation + report pre-create | 4 |
| [APISEC-S1-06](APISEC-S1-06-layer1-check-reader.md) | Layer 1 reader: check_findings WHERE rule_id LIKE '%apigateway%' | 3 |
| [APISEC-S1-07](APISEC-S1-07-layer2-discovery-reader.md) | Layer 2 reader: discovery_findings for all AWS API gateway types | 5 |
| [APISEC-S1-08](APISEC-S1-08-aws-provider.md) | AWS provider: AWSAPISecProvider.analyze() + provider factory | 8 |
| [APISEC-S1-09](APISEC-S1-09-aws-analysis-modules.md) | AWS modules: auth_scheme + throttle + waf + versioning + api_key_exposure | 10 |
| [APISEC-S1-10](APISEC-S1-10-db-writer.md) | DB writer: INSERT api_security_findings + ON CONFLICT dedup | 4 |
| [APISEC-S1-11](APISEC-S1-11-posture-signals.md) | Posture signals: UPSERT api_* columns to resource_security_posture | 4 |
| [APISEC-S1-12](APISEC-S1-12-security-findings-wire.md) | Wire findings to security_findings (source_engine=api_security) | 3 |
| [APISEC-S1-13](APISEC-S1-13-argo-pipeline.md) | Argo: add api-security step to cspm-pipeline.yaml + primitives | 3 |
| [APISEC-S1-14](APISEC-S1-14-unit-tests.md) | Tests: 5 module checks + DB conflict + 5-role RBAC matrix | 5 |

## Sprint 2 — Multi-CSP + CDR + Differentiators (50 pts)

| Story | Title | Points |
|-------|-------|--------|
| APISEC-S2-01 | Azure provider: APIM auth/rate/WAF/version | 8 |
| APISEC-S2-02 | GCP provider: Apigee proxy/environment/quota | 8 |
| APISEC-S2-03 | OCI + AliCloud providers | 6 |
| APISEC-S2-04 | K8s provider: Ingress TLS + auth annotations | 6 |
| APISEC-S2-05 | CDR enricher: execute-api/apigw events 24h window | 8 |
| APISEC-S2-06 | backend_ssrf.py: RFC1918 + metadata IP in backend URL | 5 |
| APISEC-S2-07 | DIFFERENTIATOR: api_key_lifecycle.py — rotation age + expiry | 5 |
| APISEC-S2-08 | mTLS gap + GraphQL introspection modules | 5 |
| APISEC-S2-09 | BFF /views/api_security + contract tests | 5 |
| APISEC-S2-10 | finding_type: misconfig → api_exposure upgrade | 4 |

## Sprint 3 — Depth + Attack Path + UI (44 pts)

| Story | Title | Points |
|-------|-------|--------|
| APISEC-S3-01 | spec_validation.py: OWASP API3 per CSP | 6 |
| APISEC-S3-02 | BOLA CDR pattern: same actor, spread resource IDs | 8 |
| APISEC-S3-03 | Attack-path: api_public_no_waf + api_public_no_auth in posture_updater.py | 6 |
| APISEC-S3-04 | PostureTabs: API Security tab | 8 |
| APISEC-S3-05 | Frontend /api-security page: OWASP heatmap + at-risk table | 8 |
| APISEC-S3-06 | Nav + RS-API-01 stub + regression baseline | 4 |
| APISEC-S3-07 | E2E smoke test: pipeline → findings → posture → security_findings | 6 |
| APISEC-S3-08 | Migration apisec_003: api_public_no_waf + api_public_no_auth columns | 2 |
