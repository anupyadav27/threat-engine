# Threat Engine Development Guide

## Project Overview
Comprehensive Cloud Security Posture Management (CSPM) platform for multi-cloud environments supporting AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud with:
- **Discovery scanning**: Enumerate 40+ cloud services and resources
- **Compliance evaluation**: Map findings to 13+ frameworks (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2)
- **Threat detection**: MITRE ATT&CK technique mapping, risk scoring (0-100)
- **Security analysis**: IAM posture (57 rules), Data security (62 rules)
- **Vulnerability scanning**: Multi-language IaC scanning (14 languages)

## Repository Structure

### Core Engines (`engines/`)
- `engines/onboarding/`: Multi-cloud account onboarding and credential management (Port 8010)
- `engines/discoveries/`: Cloud resource discovery and enumeration (Port 8001)
- `engines/check/`: Compliance rule evaluation - PASS/FAIL assessment (Port 8002)
- `engines/inventory/`: Asset normalization, relationships, drift detection (Port 8022)
- `engines/threat/`: Threat detection, MITRE mapping, attack chains (Port 8020)
- `engines/compliance/`: Framework reporting and compliance scoring (Port 8000)
- `engines/iam/`: IAM security posture analysis (Port 8001)
- `engines/datasec/`: Data security and classification (Port 8003)
- `engines/secops/`: IaC scanning (14 languages) (Port 8005)
- `engines/rule/`: YAML rule management (Port 8011)
- `vulnerability/`: CVE and vulnerability database subsystem

### Shared Services (`shared/`)
- `shared/database/`: PostgreSQL schemas, migrations, database config (was `consolidated_services/`)
- `shared/common/`: Shared Python utilities across all engines (was `engine_common/`)
- `shared/api_gateway/`: Central API routing and service discovery (was `api_gateway/`)
- `shared/auth/`: Authentication utilities (was `engine_auth/`)

### Data Catalog
- `catalog/`: CSP service catalog for inventory (was `data_pythonsdk/`)

### Infrastructure
- `deployment/`: Kubernetes manifests, Docker Compose, AWS configurations

## Important Paths (Always Use Absolute Paths)

**CRITICAL:** Agent threads reset working directory between bash calls.
Always use absolute paths: `/Users/apple/Desktop/threat-engine/...`

Key locations:
- **Database schemas**: `/Users/apple/Desktop/threat-engine/shared/database/schemas/`
- **Database config**: `/Users/apple/Desktop/threat-engine/shared/database/config/`
- **Engine implementations**: `/Users/apple/Desktop/threat-engine/engines/*/`
- **Shared utilities**: `/Users/apple/Desktop/threat-engine/shared/common/`
- **Kubernetes manifests**: `/Users/apple/Desktop/threat-engine/deployment/aws/eks/`
- **Docker configs**: `/Users/apple/Desktop/threat-engine/deployment/docker/`
- **CSP catalog**: `/Users/apple/Desktop/threat-engine/catalog/`

## Development Commands

### Build & Test
```bash
# Build Docker images (build context is repo root)
docker build -t threat-engine -f engines/discoveries/Dockerfile .

# Run tests
pytest /Users/apple/Desktop/threat-engine/tests/ -v

# Type checking
mypy /Users/apple/Desktop/threat-engine/src/

# Linting
pylint /Users/apple/Desktop/threat-engine/engines/*/
```

### Kubernetes Operations
```bash
# Apply all manifests
kubectl apply -f /Users/apple/Desktop/threat-engine/deployment/aws/eks/

# Check deployment status
kubectl get deployments -n threat-engine-engines

# View logs
kubectl logs -f -l app=engine-discoveries -n threat-engine-engines
kubectl logs -f -l app=engine-compliance -n threat-engine-engines

# Port forward for local testing
kubectl port-forward svc/engine-discoveries 8001:8001 -n threat-engine-engines

# Rollout status
kubectl rollout status deployment/engine-discoveries -n threat-engine-engines
```

### Database Operations
```bash
# View schemas
ls -la /Users/apple/Desktop/threat-engine/consolidated_services/database/schemas/

# Connect to RDS (via port-forward)
kubectl port-forward svc/postgres 5432:5432
psql -h localhost -U postgres -d threat_engine_discoveries

# Run migrations
python /Users/apple/Desktop/threat-engine/consolidated_services/database/migrate.py
```

### Git Workflow
```bash
# Always check status first
git status

# Create feature branch
git checkout -b feature/description

# View changes
git diff

# Commit with meaningful messages
git commit -m "feat(engine-threat): Add MITRE technique T1234 mapping"
```

## Code Standards

### Python
- **Type hints required**: All function arguments and return types (PEP 484)
- **Docstrings**: Google-style for all public functions and classes
- **Indentation**: 4 spaces (enforced by Black)
- **Imports**: stdlib → third-party → local (grouped and sorted alphabetically)
- **Async**: Use FastAPI async endpoints for I/O operations
- **Error handling**: Specific exceptions, never bare `except:`

Example:
```python
from typing import List, Optional
import asyncio

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

async def get_resources(
    provider: str,
    service: str,
    region: Optional[str] = None
) -> List[dict]:
    """Retrieve cloud resources from provider.

    Args:
        provider: Cloud provider ('aws', 'azure', 'gcp')
        service: Service name (e.g., 'ec2', 'rds')
        region: Optional region filter

    Returns:
        List of resource dictionaries

    Raises:
        HTTPException: If provider authentication fails
    """
    pass
```

### YAML (Kubernetes/Rules)
- **Indentation**: 2 spaces (NEVER tabs)
- **Validation**: Run `yamllint <file>` before committing
- **Comments**: Explain non-obvious configurations
- **Naming**: Use kebab-case for keys

### SQL
- **Parameterized queries only**: Never string concatenation
- **ORM preferred**: Use SQLAlchemy when possible
- **Migrations**: Atomic, reversible, tested
- **Indexing**: Add indexes for frequently queried columns

### Docker
- **Multi-stage builds**: Separate build and runtime stages
- **Non-root user**: Always run as non-root in production
- **Layer optimization**: Group related commands to minimize layers
- **Security scanning**: Use `docker scan` before pushing

## Architecture Patterns

### Data Flow
```
Onboarding → Discovery → Check → Inventory → Threat/Compliance
  (8010)      (8001)     (8002)    (8022)      (8020/8000)
                                              ↓
                                        IAM + DataSec
                                       (8001 + 8003)
```

### Database Design
- **scan_orchestration**: Central coordination hub (all engines read this)
- **Engine-specific tables**: Each engine writes to its own schema
- **Cross-engine linking**: Via scan_id fields in orchestration table
- **Versioning**: `config_hash` for drift detection

### API Patterns
- **FastAPI**: All engines use FastAPI with OpenAPI docs
- **Health checks**: `/api/v1/health/live` and `/api/v1/health/ready`
- **Metrics**: `/api/v1/metrics` (Prometheus format)
- **Versioning**: `/api/v1/` prefix for all endpoints

## Security & Access Control

### Protected Files (Cannot Edit/Read)
- `.env*` files (contains secrets)
- `/secrets/` directory
- Kubernetes secrets
- AWS credentials (`~/.aws/`)
- SSH keys (`~/.ssh/`)

### Safety Guardrails
- **Cannot run**: `rm -rf`, `curl`, `wget`, `sudo`
- **Requires confirmation**: `kubectl delete`, `docker push`
- **Read-only AWS commands**: Only `describe-*` and `ls` allowed

### Before Deployment Checklist
1. Run security review: Review all changes for secrets, hardcoded credentials
2. Test locally: `docker run -it <image> /bin/bash`
3. Validate YAML: `yamllint deployment/aws/eks/`
4. Check git diff: `git diff deployment/`
5. Get approval: Create PR for review

## Common Workflows

### Adding a New Engine
1. Create directory: `/Users/apple/Desktop/threat-engine/engines/newtype/`
2. Copy template: Use `engines/compliance/` as reference
3. Implement API server: Follow FastAPI pattern from `api_server.py`
4. Create database schema: Add to `shared/database/schemas/`
5. Create K8s manifest: `deployment/aws/eks/engines/engine-newtype.yaml`
6. Update orchestration: Add `newtype_scan_id` to `scan_orchestration` table
7. Test locally: Build Docker image and run
8. Deploy: `kubectl apply -f` the manifest

### Database Schema Changes
1. Create migration: `/Users/apple/Desktop/threat-engine/shared/database/migrations/`
2. Update schema SQL: `shared/database/schemas/<engine>_schema.sql`
3. Test migration: `python migrate.py --dry-run`
4. Apply locally: `python migrate.py`
5. Review in PR: Database changes require thorough review
6. Deploy to RDS: Run migration script on production

### Deployment to EKS
1. Update manifests: `deployment/aws/eks/engines/<engine>.yaml`
2. Review changes: `git diff deployment/`
3. Build Docker image: `docker build -t yadavanup84/<engine>:v1.x .`
4. Push to registry: `docker push yadavanup84/<engine>:v1.x` (requires confirmation)
5. Apply to cluster: `kubectl apply -f deployment/aws/eks/engines/<engine>.yaml`
6. Monitor rollout: `kubectl rollout status deployment/<engine> -n threat-engine-engines`
7. Check logs: `kubectl logs -f -l app=<engine> -n threat-engine-engines`

## Debugging & Troubleshooting

### Check Database Connection
```bash
kubectl get configmap threat-engine-db-config -o yaml -n threat-engine-engines
kubectl describe secret external-secret-db-passwords -n threat-engine-engines
```

### View Service Logs
```bash
kubectl logs -f -l app=engine-discoveries -n threat-engine-engines
kubectl logs -f -l app=engine-threat -n threat-engine-engines --tail=100
```

### Port Forward for Local Testing
```bash
# Database
kubectl port-forward svc/postgres 5432:5432 -n threat-engine-engines

# Engine APIs
kubectl port-forward svc/engine-discoveries 8001:8001 -n threat-engine-engines
kubectl port-forward svc/engine-compliance 8000:8000 -n threat-engine-engines
```

### Common Issues

**Discovery scan fails:**
1. Check credentials: Verify AWS Secrets Manager contains valid credentials
2. Check IAM permissions: Ensure role has required read permissions
3. Review logs: `kubectl logs -f -l app=engine-discoveries`

**Check scan returns no results:**
1. Verify discovery_scan_id exists in orchestration table
2. Check discovery_findings table for resources
3. Validate rule definitions in rule_metadata table

**Compliance report empty:**
1. Ensure check_findings exist for check_scan_id
2. Verify rule_control_mapping has mappings for framework
3. Check compliance_frameworks table for framework definition

## Important Notes

- **Absolute paths**: Each agent session resets working directory
- **Git status**: Always run before operations to see pending changes
- **PR reviews**: Complex changes must go through review process
- **Security reviews**: Changes to auth, secrets, or deployment require security audit
- **Documentation**: Update this file when architectural decisions change

## External Documentation

### Infrastructure & Deployment
See AWS infrastructure details: @.claude/documentation/INFRASTRUCTURE.md
See architectural decisions (ADRs): @.claude/documentation/ARCHITECTURE-DECISIONS.md
See secrets & credentials management: @.claude/documentation/SECRETS-CREDENTIALS.md

### Development Resources
See database schemas: @.claude/documentation/DATABASE-SCHEMA.md (to be created)
See deployment guide: @.claude/documentation/DEPLOYMENT.md (to be created)
See API reference: @.claude/documentation/API-REFERENCE.md (to be created)

### MCP & Setup
See MCP server setup guide: @.claude/.mcp-setup-guide.md

## Code Examples

See onboarding examples: @.claude/examples/ONBOARDING.md
See discovery examples: @.claude/examples/DISCOVERY.md
See threat detection examples: @.claude/examples/THREAT-DETECTION.md
