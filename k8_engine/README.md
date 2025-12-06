# Kubernetes CSPM Engine

Production-ready YAML-driven Kubernetes compliance and security posture management engine. Discovers cluster resources, evaluates 649 security checks across 34 components, and generates comprehensive compliance reports.

## Features
- **649 Security Checks** across control plane, workloads, network, storage, RBAC
- **34 Service Components** (apiserver, etcd, pods, rbac, network, etc.)
- **Non-invasive** read-only discovery using Kubernetes Python SDK
- **Mock Support** for testing without live clusters
- **Compliance Mapping** CIS, PCI-DSS, NIST, SOC2, and more
- **Flexible Operators** 15+ condition operators including list iteration

## Structure
- `engine.py`: Orchestrates discovery and checks, loads YAML from `services/`.
- `registry.py`: Action registry; add discovery and getter actions here.
- `operators.py`: Common operators for condition evaluation.
- `services/`: YAML files per component (e.g., `apiserver.yaml`).

## Example run (Python)
```python
from compliance_engine.kubernetes.yaml_engine import run_yaml_engine

results = run_yaml_engine(
  yaml_root="/path/to/backend/services/compliance-service/src/compliance_engine/kubernetes/yaml_engine/services",
  kubeconfig=None,
  context=None,
  target_components=["apiserver"],
  verbose=True,
)
for r in results:
    print(r.check_id, r.status.value, r.status_extended)
```

YAML samples are in `services/{component}/{component}_rules.yaml` and mirror the discovery/checks pattern.

## Installation

```bash
cd k8_engine
pip install -r requirements.txt
```

## Quick Start

```bash
# Scan all components
python3 run_yaml_scan.py

# Scan specific components
python3 run_yaml_scan.py --components apiserver etcd rbac

# Use mock data for testing
python3 run_yaml_scan.py --mock-dir mocks/ --components apiserver

# Specify kubeconfig
python3 run_yaml_scan.py --kubeconfig ~/.kube/config --context my-cluster
```

## Regenerating Rules

```bash
# Regenerate all 649 rules from rule IDs YAML
python3 utils/k8s_rule_generator.py
```

## Architecture

See `K8S_ENGINE_IMPROVEMENTS.md` for detailed improvements and capabilities. 