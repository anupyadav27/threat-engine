# Threat Rules Database - Comprehensive Coverage

## Overview

This threat rules database combines:
- **All AWS services** from `service_list.json` (100+ services)
- **MITRE ATT&CK for Cloud** techniques
- **Relationship-based threat detection** using inventory engine relationships
- **Misconfiguration patterns** from config scan engine

## Quick Start

### 1. Generate Threat Rules

```bash
cd /Users/apple/Desktop/threat-engine/threat_engine
python3 scripts/generate_comprehensive_threat_rules.py \
    --service-list /Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/config/service_list.json \
    --relation-types /Users/apple/Desktop/threat-engine/inventory-engine/inventory_engine/config/relation_types.json \
    --output threat_engine/config/threat_rules.yaml
```

### 2. Analyze Coverage

```bash
python3 scripts/analyze_threat_rule_coverage.py threat_engine/config/threat_rules.yaml
```

### 3. Use in Threat Detector

The relationship-aware threat detector will automatically load rules from:
```
threat_engine/config/threat_rules.yaml
```

## Architecture

### Threat Rule Structure

```yaml
threat_rules:
  - rule_id: "exposure_s3_public_uses_ec2"
    threat_type: "exposure"
    mitre_techniques: ["T1078.004", "T1190"]
    service: "s3"
    service_category: "storage"
    title: "Exposure in s3 via uses"
    description: "Detects exposure threat in s3 when misconfig pattern '.*public.*' is combined with 'uses' relationship to 'ec2.*'"
    severity: "high"
    confidence: "high"
    misconfig_patterns:
      - ".*public.*"
    relationship_conditions:
      required_relations:
        - relation_type: "uses"
          target_resource_type: "ec2.*"
    remediation:
      summary: "Review and remediate exposure threat in s3"
      steps:
        - "Review misconfig: .*public.*"
        - "Analyze relationship: uses → ec2.*"
        - "Apply security best practices for s3"
        - "Re-scan to verify threat is resolved"
```

## MITRE ATT&CK Coverage

### Techniques Mapped

| Technique ID | Name | Threat Types |
|-------------|------|--------------|
| T1078 | Valid Accounts | identity, privilege_escalation |
| T1078.004 | Cloud Accounts | identity, exposure |
| T1134 | Access Token Manipulation | privilege_escalation |
| T1021 | Remote Services | lateral_movement |
| T1071 | Application Layer Protocol | lateral_movement, exposure |
| T1048 | Exfiltration Over Alternative Protocol | data_exfiltration, data_breach |
| T1190 | Exploit Public-Facing Application | exposure |
| T1485 | Data Destruction | data_breach |
| T1486 | Data Encrypted for Impact | data_breach |

## Service Coverage

### Categories Covered

- **Compute**: EC2, Lambda, ECS, EKS, Fargate, Batch, Lightsail
- **Storage**: S3, EBS, EFS, Glacier, Storage Gateway, FSx
- **Database**: RDS, DynamoDB, Redshift, DocumentDB, Neptune, OpenSearch
- **Network**: VPC, ELB, NLB, CloudFront, Route53, Transit Gateway
- **Identity**: IAM, Cognito, Identity Center, Organizations
- **Secrets**: Secrets Manager, SSM, KMS
- **Messaging**: SNS, SQS, EventBridge, Kinesis
- **Monitoring**: CloudWatch, CloudTrail, Config, GuardDuty, Security Hub
- **API**: API Gateway, AppSync
- **Container**: ECR, ECS, EKS
- **ML/AI**: SageMaker, Bedrock
- **Security**: WAF, Shield, GuardDuty, Macie, Inspector

## Relationship Types Used

- `uses` - Resource uses another resource
- `assumes` - Principal assumes IAM role
- `connected_to` - Network connectivity
- `internet_connected` - Internet exposure
- `encrypted_by` - Encryption relationship
- `grants_access_to` - Access grants
- `routes_to` - Traffic routing
- `attached_to` - Security attachments
- `stores_data_in` - Data storage
- `triggers` - Event triggering
- `invokes` - Service invocation
- `serves_traffic_for` - Load balancing
- `exposed_through` - External exposure
- `publishes_to` / `subscribes_to` - Messaging
- `logging_enabled_to` - Logging destinations
- `monitored_by` - Monitoring relationships

## Threat Types

1. **exposure** - Resources exposed to internet/public access
2. **identity** - IAM/identity misconfigurations
3. **lateral_movement** - Network paths enabling lateral movement
4. **data_exfiltration** - Paths for unauthorized data access
5. **privilege_escalation** - IAM policies enabling privilege escalation
6. **data_breach** - Configurations leading to data breaches

## Rule Generation Strategy

### Phase 1: Service-Based Rules
For each service:
- Identify service category
- Get relevant misconfig patterns
- Generate rules for each threat type
- Map to MITRE techniques

### Phase 2: Relationship-Based Rules
For each misconfig + relationship combination:
- Identify target resource types
- Create relationship conditions
- Determine severity and confidence

### Phase 3: Coverage Optimization
- Deduplicate rules
- Prioritize high-confidence rules
- Fill coverage gaps

## Usage in Threat Detector

```python
from threat_engine.detector.relationship_threat_detector import RelationshipThreatDetector

detector = RelationshipThreatDetector(
    threat_rules_path="threat_engine/config/threat_rules.yaml",
    inventory_output_dir="/path/to/inventory/output"
)

threats = detector.detect_threats(
    findings=misconfig_findings,
    tenant_id="tenant-123",
    scan_run_id="scan-456"
)
```

## Coverage Metrics

After generation, check coverage:

```bash
python3 scripts/analyze_threat_rule_coverage.py threat_engine/config/threat_rules.yaml
```

Metrics tracked:
- Total rules
- Services covered
- Threat types covered
- MITRE techniques covered
- Relationship types used
- Coverage gaps

## Customization

### Add New Rules

Edit `threat_rules.yaml` or extend the generator:

```python
# Add custom rule
custom_rule = {
    "rule_id": "custom_threat_rule",
    "threat_type": "exposure",
    "mitre_techniques": ["T1190"],
    "service": "custom_service",
    "misconfig_patterns": [".*custom.*pattern.*"],
    "relationship_conditions": {
        "required_relations": [
            {"relation_type": "uses", "target_resource_type": "target.*"}
        ]
    }
}
```

### Modify Service Categories

Update `service_categories` in generator to add new categories.

### Add MITRE Techniques

Extend `_load_mitre_techniques()` to add new techniques.

## Best Practices

1. **Start with high-confidence rules** - Focus on clear attack paths
2. **Test with real data** - Validate against actual scan results
3. **Iterate based on feedback** - Adjust based on false positives/negatives
4. **Maintain coverage** - Regularly check for gaps
5. **Document custom rules** - Keep track of manual additions

## Next Steps

1. Generate initial rules: `python3 scripts/generate_comprehensive_threat_rules.py`
2. Analyze coverage: `python3 scripts/analyze_threat_rule_coverage.py`
3. Test with real scans
4. Refine based on results
5. Expand coverage iteratively
