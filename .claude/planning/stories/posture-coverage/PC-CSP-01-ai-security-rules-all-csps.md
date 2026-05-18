# Story PC-CSP-01: AI Security — Check Rules for All CSPs (Currently Zero Everywhere)

## Status: done

## Metadata
- **Phase**: CSP Coverage Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 8
- **Priority**: P2
- **Depends on**: PC-CSP-00 (gap baseline confirms: 0 AI rules for all 7 CSPs)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-po (new check rules) + bmad-security-reviewer

## Gap Being Closed

**Confirmed by coverage matrix:** `ai_security` tagged rule count = **0 for every CSP** (AWS, Azure, GCP, OCI, AliCloud, IBM, K8s). The AI security engine runs but produces findings only from `threat_findings` (general threat detection) — it has no dedicated check rules tagged with `rule_metadata.ai_security.applicable=true`.

**Why critical:** AI/ML workloads are the fastest-growing attack surface. SageMaker notebooks with public access, Bedrock models without VPC endpoints, GCP Vertex AI training jobs with overpermissive IAM — none of these are checked by the rule engine today.

## Scope: Rules Needed per CSP

### AWS (SageMaker, Bedrock, Comprehend, Rekognition, Forecast)

| Rule ID | Check | Severity |
|---------|-------|---------|
| `aws.sagemaker.notebook_instance.direct_internet_access_disabled` | Notebook DirectInternetAccess != Disabled | critical |
| `aws.sagemaker.notebook_instance.vpc_configured` | NotebookInstance in VPC | high |
| `aws.sagemaker.domain.vpc_only_mode` | Domain AppNetworkAccessType = VpcOnly | high |
| `aws.sagemaker.model.network_isolation_enabled` | Model NetworkIsolation = true | medium |
| `aws.bedrock.model.invocation_logging_enabled` | Bedrock invocation logs configured | high |
| `aws.bedrock.model.vpc_endpoint_present` | Bedrock accessed via VPC endpoint not public | high |
| `aws.sagemaker.training_job.inter_container_encryption` | InterContainerTrafficEncryption = true | medium |
| `aws.comprehend.pii_entities_detection.enabled` | Comprehend PII detection configured for data stores | medium |

### Azure (Azure OpenAI, Azure ML, Cognitive Services)

| Rule ID | Check | Severity |
|---------|-------|---------|
| `azure.cognitive_services.account.public_network_access_disabled` | PublicNetworkAccess = Disabled | critical |
| `azure.cognitive_services.account.managed_identity_configured` | SystemAssignedManagedIdentity present | high |
| `azure.machine_learning.workspace.public_access_disabled` | Workspace PublicNetworkAccess = Disabled | high |
| `azure.machine_learning.workspace.customer_managed_key` | CMK encryption configured | high |
| `azure.openai.deployment.content_filter_enabled` | Content filtering policy active | medium |

### GCP (Vertex AI, AutoML, Vision AI)

| Rule ID | Check | Severity |
|---------|-------|---------|
| `gcp.aiplatform.dataset.encryption_spec_configured` | Dataset KMS key configured | high |
| `gcp.aiplatform.endpoint.private_service_connect` | Endpoint uses PSC not public IP | critical |
| `gcp.aiplatform.training_pipeline.service_account_not_default` | Custom service account (not compute-default) | high |
| `gcp.notebooks.instance.no_public_ip` | Notebook instance has no external IP | critical |
| `gcp.notebooks.instance.service_account_scopes_restricted` | OAuth scopes minimal | medium |

### OCI (OCI AI Services, OCI Data Science)

| Rule ID | Check | Severity |
|---------|-------|---------|
| `oci.datascience.notebook_session.private_endpoint` | Notebook uses private endpoint | high |
| `oci.datascience.model.artifact_signed` | Model artifact integrity check | medium |
| `oci.ai_services.model.vcn_security_list_restricted` | AI service VCN has restrictive security list | high |

### IBM (Watson Studio, Watson Machine Learning)

| Rule ID | Check | Severity |
|---------|-------|---------|
| `ibm.watson_studio.project.private_catalog` | Watson Studio project not publicly accessible | high |
| `ibm.machine_learning.service.iam_api_key_rotation` | API key rotation < 90 days | medium |

### K8s (AI workload patterns — operator-deployed models)

| Rule ID | Check | Severity |
|---------|-------|---------|
| `k8s.inference_service.network_policy_present` | KServe/Seldon InferenceService has NetworkPolicy | high |
| `k8s.inference_service.resource_limits_set` | AI pod has CPU/memory limits (prevent resource exhaustion) | medium |

### AliCloud (PAI — Platform for AI)

| Rule ID | Check | Severity |
|---------|-------|---------|
| `alicloud.pai.workspace.private_link_configured` | PAI workspace uses PrivateLink | high |
| `alicloud.pai.eas.service.vpc_configured` | EAS (Elastic Algorithm Service) in VPC | critical |

## rule_metadata Tag Structure

All new rules must have:
```yaml
rule_metadata:
  ai_security:
    applicable: true
    category: "model_access"  # or: data_security / access_control / monitoring / governance
    risk_level: "high"
  engine: "ai-security"
  check_type: "config"
```

## Discovery Dependencies

The following discovery IDs must exist (or be created) for these rules to produce findings:

| CSP | Discovery ID needed |
|-----|-------------------|
| AWS | `aws.sagemaker.list_notebook_instances` ✅ (likely exists) |
| AWS | `aws.bedrock.list_foundation_models` — **check if exists** |
| Azure | `azure.cognitiveservices.accounts.list` ✅ |
| GCP | `gcp.aiplatform.list_endpoints` — **check if exists** |
| OCI | `oci.datascience.list_notebook_sessions` ✅ |
| IBM | `ibm.watson_studio.list_projects` — **stub likely** |
| K8s | `k8s.serving.list_inference_services_for_all_namespaces` — **may not exist** |

**If discovery ID doesn't exist:** create stub discovery YAML in `catalog/discovery_generator_data/{csp}/` before adding the check rule. Check engine requires matching discovery ID.

## Acceptance Criteria

- [ ] AC-1: At least 5 AWS AI security check rules exist in `catalog/rule/aws_rule_check/` tagged with `ai_security.applicable=true`
- [ ] AC-2: At least 3 Azure AI security check rules exist
- [ ] AC-3: At least 3 GCP AI security check rules exist
- [ ] AC-4: OCI, IBM, K8s, AliCloud have at least 2 rules each
- [ ] AC-5: Rules upload to DB via `upload_rule_metadata_all_csps.py` without errors
- [ ] AC-6: After a scan, `ai_security_findings` table has rows for at least one CSP
- [ ] AC-7: `rule_metadata.ai_security.applicable=true` means the AI security engine reads these findings via `check_findings` — verify the engine's `rule_reader.py` is tagged to pick them up
- [ ] AC-8: Coverage matrix re-run after this story shows `ai_security.rule_count > 0` for all 7 CSPs

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1567.002 | Exfiltration to Cloud Storage — Bedrock/SageMaker model artifacts exfil path |
| T1499.004 | Endpoint Denial of Service — AI inference endpoint resource exhaustion |
| T1613 | Container and Resource Discovery — Shadow AI detection via CDR |

## Definition of Done
- [ ] All rule YAML files committed to `catalog/rule/{csp}_rule_check/`
- [ ] All rule metadata YAML files in `catalog/rule/{csp}_rule_metadata/`
- [ ] Rules uploaded to check DB via `upload_rule_metadata_all_csps.py`
- [ ] Scan produces at least one `ai_security_findings` row for AWS (SageMaker check)
- [ ] Coverage matrix shows `ai_security` no longer zero for AWS/Azure/GCP