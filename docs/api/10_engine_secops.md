# engine_secops — Security Operations Scanner (IaC/Code)

> Port: **8000** | Docker: `yadavanup84/secops-engine:latest`
> Storage: S3 (cspm-lgtech/secops/input/, cspm-lgtech/secops/output/)

---

## Folder Structure

```
engine_secops/scanner_engine/
├── api_server.py                       # FastAPI (7 endpoints)
├── Dockerfile                          # Container definition
├── scanner/
│   ├── ansible_scanner.py              # Ansible playbook scanning
│   ├── arm_scanner.py                  # Azure ARM template scanning
│   ├── cloudformation_scanner.py       # CF template scanning
│   ├── csharp_scanner.py               # C# code scanning
│   ├── docker_scanner.py               # Dockerfile scanning
│   ├── java_scanner.py                 # Java code scanning
│   ├── javascript_scanner.py           # JS/Node code scanning
│   ├── kubernetes_scanner.py           # K8s manifest scanning
│   ├── python_scanner.py               # Python code scanning
│   └── terraform_scanner.py            # Terraform scanning (planned)
├── rules/                              # Scanner rules
└── k8s/                                # K8s deployment manifests
    ├── configmap.yaml
    ├── deployment.yaml
    ├── service.yaml
    ├── serviceaccount.yaml
    ├── ingress.yaml
    └── README.md
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Scan Project** | `POST /scan` | Upload and scan IaC/code |
| **Scan Local** | `POST /scan-local` | Scan local files |
| **Scan List** | `GET /api/v1/secops/scans` | List past scans |
| **Scan Detail** | `GET /api/v1/secops/scans/{id}` | Scan result summary |
| **Scan Findings** | `GET /api/v1/secops/scans/{id}/findings` | Detailed findings |
| **Latest Results** | `GET /results/{project_name}` | Latest scan for project |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |
| POST | `/scan` | Scan uploaded project |
| POST | `/scan-local` | Scan local files |
| GET | `/results/{project_name}` | Get latest results |
| GET | `/api/v1/secops/scans` | List all scans |
| GET | `/api/v1/secops/scans/{scan_id}` | Get scan detail |
| GET | `/api/v1/secops/scans/{scan_id}/findings` | Get scan findings |

### Supported Scanners

| Scanner | Languages/Formats | Checks |
|---------|------------------|--------|
| Ansible | .yaml/.yml playbooks | Hardcoded secrets, insecure modules |
| CloudFormation | .yaml/.json templates | Insecure resource configs |
| Docker | Dockerfile | Base image risks, USER directive |
| Kubernetes | .yaml manifests | Privileged containers, host paths |
| ARM | .json ARM templates | Azure resource misconfigs |
| Python | .py files | Hardcoded secrets, unsafe imports |
| Java | .java files | SQL injection, path traversal |
| JavaScript | .js/.ts files | XSS, prototype pollution |
| C# | .cs files | Security-sensitive APIs |
