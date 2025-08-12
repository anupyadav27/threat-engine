# YAML-driven Kubernetes Compliance Engine

This directory contains a parallel, non-invasive YAML-based evaluation engine for Kubernetes checks. It discovers cluster data/actions, evaluates conditions from YAML rules, and emits results using the same `CheckResult`/`CheckStatus`/`CheckSeverity` types as the existing engine.

## Structure
- `engine.py`: Orchestrates discovery and checks, loads YAML from `rules/`.
- `registry.py`: Action registry; add discovery and getter actions here.
- `operators.py`: Common operators for condition evaluation.
- `rules/`: YAML files per component (e.g., `apiserver.yaml`).

## Example run (Python)
```python
from compliance_engine.kubernetes.yaml_engine import run_yaml_engine

results = run_yaml_engine(
  yaml_root="/path/to/backend/services/compliance-service/src/compliance_engine/kubernetes/yaml_engine/rules",
  kubeconfig=None,
  context=None,
  target_components=["apiserver"],
  verbose=True,
)
for r in results:
    print(r.check_id, r.status.value, r.status_extended)
```

YAML sample is in `rules/apiserver.yaml` and mirrors the discovery/checks pattern requested. 