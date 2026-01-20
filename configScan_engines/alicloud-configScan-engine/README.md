# AliCloud Compliance Python Engine

Enterprise-grade compliance scanning engine for Alibaba Cloud (AliCloud) infrastructure.

## Overview

This engine performs automated compliance checks against AliCloud resources to ensure they meet security, compliance, and best practice standards.

## Features

- ✅ **53 AliCloud Services** supported
- ✅ **1,400+ Compliance Rules** across all services
- ✅ **Multi-Region Support** - Scan resources across all AliCloud regions
- ✅ **Flexible Authentication** - AccessKey, STS tokens, RAM roles
- ✅ **Detailed Reporting** - JSON reports with pass/fail status
- ✅ **Extensible** - Easy to add new services and checks

## Prerequisites

- Python 3.8+
- AliCloud account with appropriate permissions
- Access Key ID and Access Key Secret

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure credentials:
```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
export ALIBABA_CLOUD_REGION="cn-hangzhou"  # Optional, defaults to cn-hangzhou
```

## Usage

### Run Full Compliance Scan

```bash
python run_engine.py
```

### Configuration

Edit `config/service_list.json` to enable/disable services:

```json
{
  "services": [
    {
      "name": "ecs",
      "enabled": true,
      "scope": "regional"
    }
  ]
}
```

## Project Structure

```
alicloud_compliance_python_engine/
├── auth/                   # Authentication modules
│   └── alicloud_auth.py
├── config/                 # Configuration files
│   └── service_list.json
├── engine/                 # Core engine logic
│   └── alicloud_sdk_engine.py
├── services/               # Service-specific rules
│   └── {service}/
│       ├── metadata/       # Rule metadata
│       └── rules/          # Discovery & check definitions
├── utils/                  # Utility modules
│   ├── alicloud_helpers.py
│   ├── exception_manager.py
│   ├── inventory_reporter.py
│   └── reporting_manager.py
├── logs/                   # Log files
├── reporting/              # Scan results (JSON)
└── run_engine.py           # Entry point
```

## Supported Services

### Compute
- **ECS** (Elastic Compute Service) - 230 rules
- **ACK** (Container Service for Kubernetes) - 134 rules

### Storage
- **OSS** (Object Storage Service)
- **NAS** (Network Attached Storage)

### Database
- **RDS** (Relational Database Service)
- **Redis** (ApsaraDB for Redis)
- **MongoDB** (ApsaraDB for MongoDB)

### Network
- **VPC** (Virtual Private Cloud)
- **SLB** (Server Load Balancer)
- **ALB** (Application Load Balancer)
- **CDN** (Content Delivery Network)

### Security
- **RAM** (Resource Access Management)
- **KMS** (Key Management Service)
- **ActionTrail** (Audit Logging)
- **CloudFirewall**

### Monitoring & Management
- **CMS** (Cloud Monitor Service)
- **Config** (Cloud Config)

*...and 40+ more services*

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | AliCloud Access Key ID | Required |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | AliCloud Access Key Secret | Required |
| `ALIBABA_CLOUD_REGION` | Default region | `cn-hangzhou` |
| `ALIBABA_CLOUD_SECURITY_TOKEN` | STS token (optional) | None |
| `ALIBABA_CLOUD_ROLE_ARN` | RAM role ARN (optional) | None |
| `LOG_LEVEL` | Logging level | `INFO` |
| `COMPLIANCE_MAX_RETRIES` | API retry attempts | `5` |

## Output

Scan results are saved to `reporting/` directory:

```
reporting/
├── {timestamp}_compliance_report.json
├── {timestamp}_summary.json
└── {timestamp}_failed_checks.json
```

## Example Report

```json
{
  "rule_id": "alicloud.ecs.instance.encryption_enabled",
  "title": "ECS instance encryption enabled",
  "severity": "high",
  "result": "PASS",
  "resource_id": "i-bp1234567890abcde",
  "region": "cn-hangzhou"
}
```

## Adding New Services

1. Create service directory:
```bash
mkdir -p services/{service_name}/{metadata,rules}
```

2. Create rule definition: `services/{service_name}/rules/{service_name}.yaml`

3. Add metadata files: `services/{service_name}/metadata/{rule_id}.yaml`

4. Enable in `config/service_list.json`

## Compliance Frameworks Supported

- CIS Benchmarks
- ISO 27001
- GDPR
- HIPAA
- PCI-DSS
- SOC 2
- And more...

## Troubleshooting

### Authentication Errors
```bash
# Test connection
python -c "from alicloud_compliance_python_engine.auth.alicloud_auth import AliCloudAuth; auth = AliCloudAuth(); print('✅ Connection successful' if auth.test_connection() else '❌ Connection failed')"
```

### Enable Debug Logging
```bash
export LOG_LEVEL=DEBUG
python run_engine.py
```

## License

Proprietary - Internal Use Only

## Support

For questions or issues, contact the Compliance Team.

---

**Version**: 1.0.0  
**Last Updated**: 2025-11-30

