# Engine SecOps (Security Operations / Vulnerability Scanner)

> Multi-language static analysis engine supporting 10 languages and IaC formats for vulnerability detection in source code and configuration files.

---

## Overview

The SecOps Engine performs static security analysis on source code and Infrastructure-as-Code (IaC) templates. It supports 10 languages/formats with custom rule engines, AST-based analysis, and CI/CD integration (Jenkins pipeline support).

**Port:** `8000` (scanner_engine)
**Database:** `threat_engine_secops`
**Docker Image:** `yadavanup84/engine-secops:latest`

---

## Architecture

```
Source Code / IaC Files
        |
        v
  +----------------------------+
  |   SecOps Engine             |
  |                              |
  |  1. Detect language/format   |
  |  2. Parse AST                |
  |  3. Apply security rules     |
  |  4. Generate findings        |
  +----------------------------+
        |
        v
  PostgreSQL (secops_findings)
  + JSON files (scan_output/)
```

---

## Supported Languages & Formats

| Scanner | Language/Format | Rules | Analysis Method |
|---------|----------------|-------|-----------------|
| `python_v2` | Python | 200+ | AST-based parsing |
| `terraform_v2` | Terraform (HCL) | 40+ | HCL2 parser |
| `docker_scanner` | Dockerfile | Custom | AST parser |
| `kubernetes_scanner` | Kubernetes YAML | Custom | YAML structure analysis |
| `ansible_scanner` | Ansible Playbooks | Custom | YAML/task analysis |
| `java_scanner` | Java | Custom | Source analysis |
| `javascript_scanner` | JavaScript | Custom | Esprima AST |
| `csharp_scanner` | C# | Custom | Roslyn integration |
| `azure_scanner` | Azure ARM Templates | Custom | JSON template analysis |
| `cloudformation_scanner` | AWS CloudFormation | Custom | Template validation |

---

## Directory Structure

```
engine_secops/
├── terraform_rule_classes.py  # Terraform rule definitions
├── k8s/                       # Kubernetes deployment
│   ├── deployment.yaml
│   ├── service-external.yaml
│   ├── ingress.yaml
│   ├── configmap.yaml
│   ├── namespace.yaml
│   ├── serviceaccount.yaml
│   ├── deploy.sh              # Deployment script
│   ├── setup-iam.sh           # IAM role setup
│   ├── build-and-push-dockerhub.sh
│   └── QUICKSTART.md
└── scanner_engine/
    ├── api_server.py           # FastAPI application
    ├── Dockerfile              # Container definition
    ├── Dockerfile-Jenkins      # Jenkins-specific build
    ├── requirements.txt        # Python dependencies
    ├── docker-compose.yml      # Local Docker Compose
    ├── scan_local.py           # Local file/folder scanning
    ├── scanner_plugin.py       # Language detection & scanner registry
    ├── language_detector.py    # Multi-language file detector
    ├── secops_db.py            # Database persistence
    ├── database/
    │   └── connection/
    │       └── database_config.py
    ├── python_v2/              # Python vulnerability scanner
    │   ├── python_scanner.py
    │   ├── python_generic_rule.py
    │   ├── logic_implementations.py
    │   ├── python_rules/       # YAML security rules
    │   └── test/               # 200+ test files
    ├── terraform_v2/           # Terraform scanner
    │   ├── scanner_project.py
    │   ├── scanner_file.py
    │   ├── generic_rule.py
    │   ├── scanner_common.py
    │   ├── terraform_rules1/   # 40+ rule JSON files
    │   └── test_rules/
    ├── docker_scanner/         # Dockerfile scanner
    │   ├── docker_scanner.py
    │   ├── docker_ast_parser.py
    │   ├── docker_generic_rule.py
    │   └── logic_implementations.py
    ├── kubernetes_scanner/     # Kubernetes YAML scanner
    │   ├── kubernetes_scanner.py
    │   ├── kubernetes_ast_builder.py
    │   ├── kubernetes_generic_rule.py
    │   └── logic_implementations.py
    ├── ansible_scanner/        # Ansible playbook scanner
    │   ├── ansible_scanner_engine.py
    │   ├── ansible_ast_builder.py
    │   ├── ansible_generic_rule.py
    │   └── logic_implementations.py
    ├── java_scanner/           # Java code scanner
    │   ├── scanner.py
    │   ├── generic_rule_engine.py
    │   └── logic_implementations.py
    ├── javascript_scanner/     # JavaScript scanner
    │   ├── javascript_scanner.py
    │   ├── generic_rule_engine.py
    │   └── logic_implementations.py
    ├── csharp_scanner/         # C# code scanner
    │   ├── csharp_scanner.py
    │   ├── csharp_generic_rule_engine.py
    │   └── logic_implementations.py
    ├── azure_scanner/          # Azure ARM template scanner
    │   ├── arm_scanner.py
    │   ├── arm_vulnerability_scanner.py
    │   ├── arm_generic_rule_engine.py
    │   └── arm_logic_implementations.py
    └── cloudformation_scanner/ # CloudFormation scanner
        ├── cloudformation_scanner.py
        ├── cloudformation_generic_rule_engine.py
        └── cloudformation_logic_implementations.py
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Scan a project from input folder |
| `GET` | `/results/{project_name}` | Get latest scan results |
| `GET` | `/api/v1/secops/scans` | List SecOps scans (DB-backed) |
| `GET` | `/api/v1/secops/scans/{scan_id}` | Get scan details |
| `GET` | `/api/v1/secops/scans/{scan_id}/findings` | Get scan findings |
| `GET` | `/health` | Health check |

### Scan a Project

```bash
# Place files in scan_input/{project_name}/ then:
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "my-app",
    "tenant_id": "your-tenant",
    "languages": ["python", "terraform"]
  }'
```

### Get Results

```bash
curl http://localhost:8000/results/my-app
```

---

## Database Schema

**Database:** `threat_engine_secops`

| Table | Description |
|-------|-------------|
| `secops_scans` | Scan metadata (project, status, timestamps) |
| `secops_findings` | Security findings (rule, severity, location, code snippet) |

---

## CI/CD Integration (Jenkins)

The SecOps engine supports a Jenkins pipeline workflow:

```
1. Jenkins clones repo → scan_input/{project_name}/
2. Jenkins calls POST /scan with project_name
3. Scanner analyzes scan_input/{project_name}/
4. Results written to scan_output/{project_name}/scan_results.json
5. Jenkins reads results from scan_output/
```

### Jenkins Dockerfile

Use `Dockerfile-Jenkins` for Jenkins integration with pre-configured scan directories.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8000` | Server port |
| `SECOPS_DB_HOST` | `localhost` | PostgreSQL host |
| `SECOPS_DB_PORT` | `5432` | PostgreSQL port |
| `SECOPS_DB_NAME` | `threat_engine_secops` | Database name |
| `SECOPS_DB_USER` | `postgres` | Database user |
| `SECOPS_DB_PASSWORD` | - | Database password |
| `SCAN_INPUT_DIR` | `/app/scan_input` | Input directory for code |
| `SCAN_OUTPUT_DIR` | `/app/scan_output` | Output directory for results |
| `SCAN_TIMEOUT` | `30` | Per-file scan timeout (seconds) |

---

## Running Locally

```bash
cd engine_secops/scanner_engine

# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn api_server:app --host 0.0.0.0 --port 8000 --workers 2 --reload

# Scan a local folder directly
python scan_local.py /path/to/project
```

---

## Docker

```bash
# Build
docker build -t engine-secops -f engine_secops/scanner_engine/Dockerfile engine_secops/scanner_engine/

# Run
docker run -p 8000:8000 \
  -v ./scan_input:/app/scan_input \
  -v ./scan_output:/app/scan_output \
  engine-secops
```

---

## Rule System

### Rule Structure (Python example)

Rules are defined in YAML with Python logic implementations:

```yaml
rule_id: PY-SEC-001
title: Hardcoded Password Detection
severity: high
description: Detects hardcoded passwords in Python source code
cwe: CWE-798
owasp: A07:2021
```

### Adding Custom Rules

1. Create rule YAML in `{scanner}/rules/`
2. Implement logic in `logic_implementations.py`
3. Register rule in scanner's rule loader
4. Add test cases in `test/` directory

---

## Testing

```bash
cd engine_secops/scanner_engine

# Run Python scanner tests
python -m pytest python_v2/test/ -v

# Run Terraform scanner tests
python -m pytest terraform_v2/test_rules/ -v
```
