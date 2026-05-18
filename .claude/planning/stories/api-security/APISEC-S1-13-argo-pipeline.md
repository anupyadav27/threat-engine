# Story APISEC-S1-13: Argo Pipeline Integration

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 3
- **Depends on**: APISEC-S1-04 (K8s service must be live before Argo step can call it)
- **Blocks**: nothing in Sprint 1 (Argo is last wiring step)
- **Security Gate**: bmad-security-reviewer (Argo template must not log credential_ref)

## Files to Modify

### 1. `deployment/aws/eks/argo/cspm-templates-primitives.yaml`

Add after the existing `call-engine-network-security` template block:

```yaml
# =============================================================================
# API Security Engine — parallel step 5
# =============================================================================
- name: call-engine-api-security
  inputs:
    parameters:
      - name: scan-run-id
      - name: tenant-id
      - name: account-id
      - name: provider
      - name: credential-ref
      - name: credential-type
      - name: region
        default: ""
  script:
    image: python:3.11.9-slim
    command: [python3]
    source: |
      import urllib.request, json, os, sys

      url = "http://engine-api-security.threat-engine-engines.svc.cluster.local/api/v1/apisec/scan"
      token = os.environ.get("ARGO_INTERNAL_TOKEN", "")
      payload = json.dumps({
          "scan_run_id":     "{{inputs.parameters.scan-run-id}}",
          "tenant_id":       "{{inputs.parameters.tenant-id}}",
          "account_id":      "{{inputs.parameters.account-id}}",
          "provider":        "{{inputs.parameters.provider}}",
          "credential_ref":  "{{inputs.parameters.credential-ref}}",
          "credential_type": "{{inputs.parameters.credential-type}}",
          "region":          "{{inputs.parameters.region}}",
      }).encode()

      req = urllib.request.Request(url, data=payload,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"}, method="POST")
      try:
          with urllib.request.urlopen(req, timeout=30) as resp:
              body = json.loads(resp.read())
              print(f"API security scan dispatched: {body}")
              sys.exit(0)
      except urllib.error.HTTPError as e:
          print(f"HTTP {e.code}: {e.read()}")
          sys.exit(1)
    env:
      - name: ARGO_INTERNAL_TOKEN
        valueFrom:
          secretKeyRef:
            name: threat-engine-db-passwords
            key: ARGO_INTERNAL_TOKEN
            optional: true
```

### 2. `deployment/aws/eks/argo/cspm-pipeline.yaml`

Add `call-engine-api-security` to the parallel step 5 group (alongside IAM, DataSec, Network, etc.):

```yaml
# In the DAG steps section, find the parallel step-5 group and add:
- name: api-security-scan
  template: call-engine-api-security
  dependencies: [check-scan, threat-scan]
  arguments:
    parameters:
      - name: scan-run-id
        value: "{{inputs.parameters.scan-run-id}}"
      - name: tenant-id
        value: "{{inputs.parameters.tenant-id}}"
      - name: account-id
        value: "{{inputs.parameters.account-id}}"
      - name: provider
        value: "{{inputs.parameters.provider}}"
      - name: credential-ref
        value: "{{inputs.parameters.credential-ref}}"
      - name: credential-type
        value: "{{inputs.parameters.credential-type}}"
      - name: region
        value: "{{inputs.parameters.region}}"
```

## Pipeline Position

```
Discovery → Inventory → Check → Threat
                                  ↓
               ┌──────────────────┼──────────────────────┐
          IAM-scan        api-security-scan          Network-scan
          CDR-scan          DataSec-scan           Container-scan
          Vuln-scan         Encryption-scan
                                  ↓
                            graph-build
                                  ↓
                           Risk → Narrative
```

API Security runs in the same parallel fan-out as IAM, CDR, Network — all after Threat scan completes.

## Acceptance Criteria

- [ ] AC-1: `kubectl apply -f deployment/aws/eks/argo/cspm-templates-primitives.yaml` applies without YAML parse errors
- [ ] AC-2: `kubectl apply -f deployment/aws/eks/argo/cspm-pipeline.yaml` applies without error
- [ ] AC-3: `argo submit` with a real scan_run_id shows `api-security-scan` step in the DAG (Argo UI)
- [ ] AC-4: `api-security-scan` step resolves dependency on `check-scan` and `threat-scan` before executing
- [ ] AC-5: Argo step logs show `"API security scan dispatched"` — no credential_ref logged
- [ ] AC-6: On engine HTTP 404 (scan_run_id not found for tenant) → Argo step exits 1, scan marked failed for that step

## Definition of Done
- [ ] Both Argo YAML files committed
- [ ] `argo submit --watch` shows api-security-scan step completing Succeeded
- [ ] `kubectl logs` of the api-security engine pod shows scan started and completed
