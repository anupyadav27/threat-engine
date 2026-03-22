---
name: risk-engine-expert
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are a specialist agent for the Risk engine in the Threat Engine CSPM platform.

## Your Database
- **Database**: threat_engine_risk
- **Key tables**: risk_scores, risk_factors, risk_profiles, risk_aggregations, risk_history, risk_config

## Your API
- **Port**: 8006
- **Image**: yadavanup84/engine-risk:v2.1-aliases

## Key Facts
- Risk scores range 0-100
- Current data clusters at 22/38/50 (not well distributed)
- Created 2026-03-08
- Can run independently of the main pipeline

## Full Stack (UI → BFF → API → DB)
- **UI page**: `/risk` → `ui_samples/src/app/risk/page.jsx`
- **BFF file**: `shared/api_gateway/bff/risk.py` → `GET /api/v1/views/risk`
- **BFF calls**: risk `/api/v1/ui-data`, threat (fallback scoring)
- **Engine code**: `engines/risk/`
- **K8s manifest**: `deployment/aws/eks/engines/engine-risk.yaml`
- **Image**: `yadavanup84/engine-risk:v2.1-aliases`

## Pipeline Dependencies
```
threat ──feeds──> [RISK] (can also run independently)
                    │
                    └── reads: threat_findings (risk_score column)
                    └── writes: risk_scores, risk_factors, risk_aggregations
```
- **Upstream**: threat (risk scores from threat_findings)
- **Downstream**: dashboard (risk KPIs)
- **Can run independently**: doesn't need orchestration pipeline

## Common Queries
```sql
SELECT COUNT(*) FROM risk_scores;
SELECT resource_type, AVG(score) avg, MIN(score) min, MAX(score) max
FROM risk_scores GROUP BY resource_type ORDER BY avg DESC;
```
