# Story PC-P2-04: AI Security Engine — Write Posture Signals to resource_security_posture

## Status: done

## Metadata
- **Phase**: P2 — Tier B (shadow AI detection needs CDR cross-reference; not pure check findings)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 4
- **Priority**: P2
- **Depends on**: PC-P0-01 (ai-security columns in posture table), AP-P0-02 (posture_writer)
- **Blocks**: Crown jewel classifier for AI endpoints
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## Gap Being Closed

**Current state:** AI security engine produces `ai_security_findings` but has no posture writer. AI/ML endpoints, SageMaker notebooks, and Bedrock model access are invisible to the attack-path engine. A publicly accessible SageMaker inference endpoint cannot be flagged as a crown jewel.

**Why Tier B:** Two of the three signals need cross-engine data:
- `ai_model_publicly_accessible` — straightforward from check findings (Tier A)
- `ai_training_data_has_pii` — needs DataSec posture row for the S3 bucket used as training data (cross-engine join)
- `has_shadow_ai_service` — needs CDR actor calls to AI service APIs not in inventory (cross-engine with CDR)

## Data Sources

```
threat_engine_ai_security DB → ai_security_findings
  rule_id patterns: public_access, encryption, iam_access, shadow_ai

threat_engine_inventory DB → resource_security_posture (DataSec rows)
  Used to check if S3 bucket linked as training data has data_classification IN ('pii','phi')

threat_engine_cdr DB → cdr_findings
  WHERE resource_type = 'sagemaker_endpoint' OR resource_type = 'bedrock_model'
  AND resource_uid NOT IN (SELECT resource_uid FROM ai_security_findings WHERE scan_run_id=...)
  → resources called but not in inventory = shadow AI
```

## Signals to Write (PC-P0-01 columns)

| Column | Source | Logic |
|--------|--------|-------|
| `ai_model_publicly_accessible` | ai_security_findings | `status=FAIL` for rules matching `public_access\|public_endpoint\|no_vpc` |
| `ai_training_data_has_pii` | Cross-engine join | Check posture row for S3 bucket ARN in `finding_data->>'training_data_bucket'`; is `data_classification` in PII set? |
| `has_shadow_ai_service` | CDR cross-reference | CDR `resource_uid` of AI service type not present in `ai_security_findings` for same scan |

## Crown Jewel Classifier Extension

Add `ai_endpoint` to crown jewel types in the attack-path engine's `crown_jewel_classifier.py`:
```python
# A SageMaker endpoint or Bedrock model is a crown jewel if:
# - publicly accessible, OR
# - training data contains PII
resource_type in ("sagemaker_endpoint", "bedrock_model", "sagemaker_notebook") 
AND (ai_model_publicly_accessible OR ai_training_data_has_pii)
```

## Acceptance Criteria

- [ ] AC-1: SageMaker endpoints without VPC configuration have `ai_model_publicly_accessible=TRUE`
- [ ] AC-2: `ai_training_data_has_pii=TRUE` for SageMaker training jobs whose S3 training bucket has `data_classification='pii'` in posture table (cross-engine join works)
- [ ] AC-3: `has_shadow_ai_service=TRUE` for CDR-observed AI API calls where the resource is not in the AI security findings inventory
- [ ] AC-4: Crown jewel classifier marks AI endpoints with `ai_model_publicly_accessible=TRUE` as `crown_jewel_type='ai_endpoint'`
- [ ] AC-5: Non-fatal — AI security scan completes even if CDR DB is unreachable (shadow AI detection skipped with INFO log)
- [ ] AC-6: New image: `yadavanup84/engine-ai-security:v-ai-posture1`

## Definition of Done
- [ ] PC-P0-01 migration applied
- [ ] `posture_signals.py` implemented for ai-security engine
- [ ] Crown jewel classifier updated
- [ ] Post-deploy: AI resources appear in `resource_security_posture` with at least one non-default column value