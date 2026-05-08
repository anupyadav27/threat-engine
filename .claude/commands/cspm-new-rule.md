# /cspm-new-rule

Create a new CSPM check rule for any CSP. Handles YAML authoring, DB seeding, and verification.

## Usage
```
/cspm-new-rule <rule-id> <csp>
```

Example:
```
/cspm-new-rule AWS-S3-042 aws
/cspm-new-rule AZURE-STORAGE-015 azure
```

## Steps

1. **Create YAML** — Add to `catalog/rule/<csp>_rule_check/<rule-id>.yaml`
   Required fields: `rule_id`, `title`, `severity`, `description`, `remediation`, `rationale`, `domain`, `service`, `resource_type`, `compliance_frameworks`, `mitre_tactics`, `mitre_techniques`, `risk_score`
   If network rule: include `network_security: {applicable: true}`

2. **Seed to DB** — Run `python catalog/rule/upload_rule_metadata_all_csps.py`

3. **Verify** — `SELECT * FROM rule_metadata WHERE rule_id = '<rule-id>'` in check DB

4. **Ensure service is active** — `SELECT is_active FROM rule_discoveries WHERE service = '<service>' AND provider = '<csp>'` in check DB

## Rule YAML template
```yaml
rule_id: AWS-S3-042
title: "S3 bucket should have versioning enabled"
severity: medium
description: "..."
remediation: "..."
rationale: "..."
domain: data_security
service: s3
resource_type: AWS::S3::Bucket
compliance_frameworks:
  cis: "2.1.1"
  nist: "CM-8"
mitre_tactics: [Defense Evasion]
mitre_techniques: [T1485]
risk_score: 38
```