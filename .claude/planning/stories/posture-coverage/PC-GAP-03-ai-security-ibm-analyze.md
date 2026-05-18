# Story PC-GAP-03: AI Security Engine — IBM Cloud analyze() Implementation

## Status: done

## Metadata
- **Phase**: CSP Coverage Track — Provider Gap Closure
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P1 — Highest ROI (Pattern A partial → full analyze())
- **Depends on**: None (AI Security engine has Pattern A architecture; IBM provider exists but has no analyze())
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-po + bmad-security-reviewer

## Gap Being Closed

`engines/ai-security/ai_security_engine/providers/ibm.py` has **service definitions only** — no `analyze()` method. IBM Watson Studio and Watson Machine Learning workloads are completely unassessed.

Current state (confirmed):
- AWS AI Security: ✅ 5-pillar MITRE ATLAS on SageMaker, Bedrock, Comprehend
- Azure AI Security: ✅ 5-pillar ATLAS on ML Workspaces, CognitiveServices, OpenAI
- GCP AI Security: ✅ 5-pillar ATLAS on Vertex AI, AI Platform, AutoML, Notebooks
- OCI AI Security: ✅ 5-pillar ATLAS on DataScience Models/Projects, AnomalyDetection
- K8s AI Security: ✅ 5-pillar ATLAS on MLflow, Kubeflow, Jupyter, Ray, KServe
- AliCloud AI Security: ✅ 5-pillar ATLAS on PAI Workspace, ML Jobs, NLP/Vision Models
- IBM AI Security: ⚠️ **Service definitions only — no analyze()**

## MITRE ATLAS 5-Pillar Framework (same for all CSPs)

| Pillar | ATLAS Tactic | What it checks |
|--------|-------------|----------------|
| P1: Data Security | AML.T0031 | Training data encryption, residency, access control |
| P2: Model Security | AML.T0035 | Model artifact protection, signing, access |
| P3: Access Control | AML.T0012 | Overpermissive IAM to ML services, API key exposure |
| P4: Network Isolation | AML.T0010 | Public endpoints, VPC isolation, egress controls |
| P5: Monitoring | AML.T0048 | Inference logging, activity tracking, anomaly detection |

---

## IBM AI/ML Services

### Watson Studio

Watson Studio is IBM's collaborative data science and ML platform.

**Discovery IDs:**
- `ibm.watson_studio.list_projects` — all Watson Studio projects (incl. collaboration settings)
- `ibm.watson_studio.list_project_members` — member roles within each project
- `ibm.watson_studio.list_notebooks` — Jupyter notebooks in project
- `ibm.watson_studio.get_project_settings` — public access, token expiry, compute config

**Findings to generate:**

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `ibm.watson_studio.project.private_access_only` | P3/P4 | Project visibility not `public` | critical |
| `ibm.watson_studio.project.no_public_members` | P3 | No members with `public` or `viewer` access from outside org | high |
| `ibm.watson_studio.notebook.kernel_idle_timeout` | P5 | Notebook auto-shutdown configured (< 60 min idle) | medium |
| `ibm.watson_studio.project.activity_tracking_enabled` | P5 | Activity Tracker events enabled for project | high |
| `ibm.watson_studio.project.resource_group_scoped` | P3 | Project scoped to specific resource group (not default) | medium |

### Watson Machine Learning (WML)

WML provides model deployment, serving, and batch scoring infrastructure.

**Discovery IDs:**
- `ibm.machine_learning.list_instances` — all WML service instances
- `ibm.machine_learning.list_deployments` — deployed models (online/batch/streaming)
- `ibm.machine_learning.list_model_definitions` — model artifacts + framework
- `ibm.machine_learning.get_deployment_details` — endpoint URL, autoscaling, resources

**Findings to generate:**

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `ibm.machine_learning.deployment.private_endpoint` | P4 | Deployment uses private endpoint (not public inference URL) | critical |
| `ibm.machine_learning.deployment.iam_api_key_rotation` | P3 | API key used for WML < 90 days old | high |
| `ibm.machine_learning.deployment.input_data_validation` | P1 | Input data schema validation configured | medium |
| `ibm.machine_learning.model.no_public_download` | P2 | Model artifacts not publicly downloadable | critical |
| `ibm.machine_learning.instance.activity_logging_enabled` | P5 | WML instance has Activity Tracker integration | high |

### IBM OpenScale / Watson OpenScale (AI Fairness 360)

IBM Watson OpenScale (now IBM OpenPages) monitors model bias and drift.

**Discovery IDs:**
- `ibm.openscale.list_subscriptions` — monitored model subscriptions
- `ibm.openscale.get_monitor_instances` — active monitors (fairness, quality, drift)

**Findings to generate:**

| Rule ID | Pillar | Check | Severity |
|---------|--------|-------|---------|
| `ibm.openscale.subscription.drift_monitor_active` | P5 | Drift detection monitor enabled for production models | high |
| `ibm.openscale.subscription.fairness_monitor_active` | P5 | Fairness monitor active (bias detection) | medium |

---

## Discovery Field Mapping

```python
# ibm.watson_studio.list_projects
{
  "metadata": {
    "guid": str,         # project ID
    "url": str,
    "created_at": str
  },
  "entity": {
    "name": str,
    "description": str,
    "public": bool,      # M1: P1 check — should be False
    "settings": {
      "access_list": {"groups": list}
    },
    "compute": [{"name": str, "type": str}]
  }
}

# ibm.machine_learning.list_deployments
{
  "metadata": {
    "id": str,
    "name": str,
    "created_at": str
  },
  "entity": {
    "online": {
      "parameters": {
        "serving_name": str   # public serving name → public endpoint
      }
    },
    "deployed_asset": {"id": str, "type": "model"},
    "status": {"state": "ready"}
  }
}
```

---

## Implementation Steps

1. **Open** `engines/ai-security/ai_security_engine/providers/ibm.py`
2. Add `analyze(self, scan_run_id, tenant_id, account_id) -> List[AISecurityFinding]`
3. Call `get_discovery_findings(scan_run_id, 'ibm')` filtered by service prefixes
4. Implement 3 service analyzers: Watson Studio, Watson ML, OpenScale
5. Map findings to ATLAS pillars in `atlas_pillar` field of AISecurityFinding

**Pattern to follow:** `engines/ai-security/ai_security_engine/providers/alicloud.py` — PAI Workspace analysis (similar scope: workspace + deployment + monitoring)

## Posture Signals Produced

After PC-P2-04 (AI Security posture writer) is implemented, these signals will flow:
- `has_shadow_ai_service` — public Watson Studio projects
- `ai_model_publicly_accessible` — WML deployments with public endpoints
- `ai_training_data_has_pii` — projects with PII-tagged datasets

## Acceptance Criteria

- [ ] AC-1: `IBMAISecurityProvider.analyze()` returns findings for Watson Studio, WML, OpenScale
- [ ] AC-2: `ibm.watson_studio.project.private_access_only` fires for projects with `entity.public=true`
- [ ] AC-3: `ibm.machine_learning.deployment.private_endpoint` fires for deployments using public serving URLs
- [ ] AC-4: ATLAS pillar correctly tagged in each finding (`atlas_pillar: "P4"` for network isolation findings)
- [ ] AC-5: After IBM AI scan: `SELECT COUNT(*), atlas_pillar FROM ai_security_findings WHERE provider='ibm' GROUP BY atlas_pillar` shows findings across multiple pillars
- [ ] AC-6: Coverage matrix shows `ai_security.rule_count > 0` for IBM after upload

## MITRE ATLAS
| Technique | Addressed by |
|-----------|-------------|
| AML.T0012.000 | Obtain Capabilities: ML Model — public WML endpoint detection |
| AML.T0031 | Erode ML Model Integrity — missing drift monitoring |
| AML.T0035 | Craft Adversarial Data — no input validation detection |

## Definition of Done
- [ ] IBM `analyze()` implemented (Watson Studio + WML + OpenScale)
- [ ] Unit test in `tests/unit/ai_security/test_ibm_provider.py`
- [ ] AI Security engine rebuilt and deployed
- [ ] After IBM scan: `SELECT COUNT(*) FROM ai_security_findings WHERE provider='ibm'` > 0
