"""
Misconfig Normalizer

Converts NDJSON scan output to normalized misconfig findings with stable IDs.
"""

import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from .threat_report_schema import MisconfigFinding, Severity, Cloud


def generate_stable_finding_id(rule_id: str, resource_uid: str, account: str, region: str) -> str:
    """
    Generate stable finding ID from composite key.
    Uses deterministic hash for consistency across scans.
    """
    key = f"{rule_id}|{resource_uid}|{account}|{region}"
    hash_obj = hashlib.sha256(key.encode())
    return f"fnd_{hash_obj.hexdigest()[:16]}"


def normalize_ndjson_to_findings(
    ndjson_lines: List[str],
    cloud: Cloud = Cloud.AWS
) -> List[MisconfigFinding]:
    """
    Normalize NDJSON scan output to misconfig findings.
    
    Expected NDJSON format (per line):
    {
      "inventory": {...},
      "checks": [
        {
          "rule_id": "...",
          "result": "FAIL",
          "severity": "high",
          "region": "us-east-1",
          "resource_uid": "...",  # Should be present after configScan enhancement
          "resource_arn": "...",  # Should be present after configScan enhancement
          "resource_id": "...",
          "resource_type": "...",
          ...
        }
      ],
      "service": "s3",
      "scope": "regional",
      "region": "us-east-1",
      "account": "123456789012"
    }
    """
    findings = []
    finding_keys_seen = set()
    
    for line in ndjson_lines:
        if not line.strip():
            continue
        
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            continue
        
        service = record.get("service", "unknown")
        scope = record.get("scope", "regional")
        region = record.get("region") or record.get("location") or "global"
        account = record.get("account") or record.get("subscription") or record.get("project_id") or "unknown"
        
        checks = record.get("checks", [])
        
        for check in checks:
            # Skip passing checks (focus on failures/warnings)
            result = check.get("result", "PASS")
            if result not in ["FAIL", "WARN"]:
                continue
            
            # Extract resource identifiers (should be present after configScan enhancement)
            resource_uid = (
                check.get("resource_uid") or
                check.get("resource_arn") or
                check.get("arn") or
                check.get("Arn")
            )
            
            resource_arn = (
                check.get("resource_arn") or
                check.get("arn") or
                check.get("Arn")
            )
            
            resource_id = (
                check.get("resource_id") or
                check.get("resource_name") or
                check.get("id") or
                check.get("name") or
                check.get("Name")
            )
            
            resource_type = check.get("resource_type", "resource")
            
            # If resource_uid is missing, try to construct it
            if not resource_uid:
                if resource_arn:
                    resource_uid = resource_arn
                elif resource_id:
                    # Construct best-effort UID
                    resource_uid = f"{service}:{region}:{account}:{resource_id}"
                else:
                    # Last resort: use service-level identifier
                    resource_uid = f"{service}:{region}:{account}:unknown"
            
            rule_id = check.get("rule_id", "unknown")
            
            # Generate stable finding key and ID
            finding_key = f"{rule_id}|{resource_uid}|{account}|{region}"
            
            # Skip duplicates (same finding key)
            if finding_key in finding_keys_seen:
                continue
            
            finding_keys_seen.add(finding_key)
            
            misconfig_finding_id = generate_stable_finding_id(rule_id, resource_uid, account, region)
            
            # Extract severity
            severity_str = check.get("severity", "medium").lower()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.MEDIUM
            
            # Extract checked fields
            checked_fields = check.get("_checked_fields", [])
            if not checked_fields and isinstance(checked_fields, list):
                checked_fields = []
            
            # Build resource dict
            resource = {
                "resource_uid": resource_uid,
                "resource_arn": resource_arn,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "tags": check.get("tags", {}) or {}
            }
            
            # Extract evidence refs if present
            evidence_refs = check.get("evidence_refs", [])
            if not evidence_refs:
                evidence_refs = []
            
            finding = MisconfigFinding(
                misconfig_finding_id=misconfig_finding_id,
                finding_key=finding_key,
                rule_id=rule_id,
                severity=severity,
                result=result,
                account=account,
                region=region,
                service=service,
                resource=resource,
                evidence_refs=evidence_refs,
                checked_fields=checked_fields,
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc)
            )
            
            findings.append(finding)
    
    return findings


def load_ndjson_from_file(file_path: str) -> List[str]:
    """Load NDJSON lines from file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def load_ndjson_from_s3(s3_path: str) -> List[str]:
    """Load NDJSON lines from S3"""
    import boto3
    from urllib.parse import urlparse
    
    parsed = urlparse(s3_path)
    bucket = parsed.netloc
    key = parsed.path.lstrip('/')
    
    s3_client = boto3.client('s3')
    response = s3_client.get_object(Bucket=bucket, Key=key)
    content = response['Body'].read().decode('utf-8')
    
    return [line.strip() for line in content.split('\n') if line.strip()]


def normalize_db_check_results_to_findings(
    check_results: List[Dict[str, Any]],
    cloud: Cloud = Cloud.AWS,
    include_metadata: bool = True
) -> List[MisconfigFinding]:
    """
    Normalize check results from database to misconfig findings with MITRE ATT&CK enrichment.

    Args:
        check_results: List of check result dicts from database (enriched via JOIN with rule_metadata).
                      Expected fields from check_findings: id, check_scan_id, customer_id, tenant_id,
                      provider, hierarchy_id, rule_id, resource_arn, resource_uid, resource_id,
                      resource_type, status, checked_fields, finding_data, created_at.
                      Expected fields from rule_metadata JOIN: severity, title, description,
                      remediation, domain, subcategory, threat_category, threat_tags, risk_score,
                      risk_indicators, mitre_techniques, mitre_tactics.
        cloud: Cloud provider (auto-detected from check data when possible)
        include_metadata: If True, expects metadata fields in check_results (from JOIN)

    Returns:
        List of normalized MisconfigFinding objects with MITRE ATT&CK data
    """
    findings = []
    finding_keys_seen = set()

    for check in check_results:
        # Skip passing checks (focus on failures/warnings)
        status = check.get("status", "PASS")
        if status not in ["FAIL", "WARN"]:
            continue

        # Auto-detect cloud provider from check data
        provider = check.get("provider", cloud.value).lower()
        try:
            detected_cloud = Cloud(provider)
        except ValueError:
            detected_cloud = cloud

        # Extract resource identifiers
        resource_uid = check.get("resource_uid") or check.get("resource_arn")
        resource_arn = check.get("resource_arn")
        resource_id = check.get("resource_id")
        resource_type = check.get("resource_type", "resource")

        # Extract account and region from resource_arn (preferred) or hierarchy_id (fallback)
        hierarchy_id = check.get("hierarchy_id", "unknown")
        account = hierarchy_id  # default: internal UUID

        # Extract region AND real cloud account number from resource_arn if available
        # AWS ARN format: arn:aws:service:region:account-id:resource
        region = "global"
        if resource_arn:
            parts = resource_arn.split(":")
            if len(parts) >= 4:
                region = parts[3] if parts[3] else "global"
            if len(parts) >= 5 and parts[4]:
                account = parts[4]  # real AWS/Azure/GCP account number from ARN
        elif resource_uid and ":" in resource_uid:
            parts = resource_uid.split(":")
            if len(parts) >= 3:
                region = parts[2] if parts[2] else "global"

        # Extract service from rule_metadata (preferred) or resource_type
        service = check.get("rule_service") or "unknown"
        if service == "unknown" and resource_type:
            service = resource_type.replace(f"{detected_cloud.value}_", "").split("_")[0]

        # If resource_uid is missing, try to construct it
        if not resource_uid:
            if resource_arn:
                resource_uid = resource_arn
            elif resource_id:
                resource_uid = f"{service}:{region}:{account}:{resource_id}"
            else:
                resource_uid = f"{service}:{region}:{account}:unknown"

        rule_id = check.get("rule_id", "unknown")

        # Generate stable finding key and ID
        finding_key = f"{rule_id}|{resource_uid}|{account}|{region}"

        # Skip duplicates
        if finding_key in finding_keys_seen:
            continue

        finding_keys_seen.add(finding_key)

        misconfig_finding_id = generate_stable_finding_id(rule_id, resource_uid, account, region)

        # Extract finding_data (always needed for tags/evidence refs)
        finding_data = check.get("finding_data", {}) or {}

        # Extract severity from database metadata (enriched via JOIN) or fallback to defaults
        if include_metadata and check.get("severity"):
            severity_str = check.get("severity", "medium").lower()
        else:
            severity_str = finding_data.get("severity", "medium").lower()

        try:
            severity = Severity(severity_str)
        except ValueError:
            if status == "FAIL":
                severity = Severity.HIGH
            elif status == "WARN":
                severity = Severity.MEDIUM
            else:
                severity = Severity.MEDIUM

        # Extract checked fields
        checked_fields = check.get("checked_fields", []) or []
        if not isinstance(checked_fields, list):
            checked_fields = []

        # Extract tags from finding_data if available
        tags = finding_data.get("tags", {}) or {}
        if not isinstance(tags, dict):
            tags = {}

        # Build resource dict
        resource = {
            "resource_uid": resource_uid,
            "resource_arn": resource_arn,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "tags": tags
        }

        # Extract evidence refs from finding_data if available
        evidence_refs = finding_data.get("evidence_refs", []) or []
        if not isinstance(evidence_refs, list):
            evidence_refs = []

        # Use scan_timestamp (aliased from created_at) or created_at as timestamps
        created_at = check.get("scan_timestamp") or check.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            except Exception:
                created_at = datetime.now(timezone.utc)
        elif created_at is None:
            created_at = datetime.now(timezone.utc)

        # Extract MITRE ATT&CK enrichment from rule_metadata JOIN
        threat_category = check.get("threat_category")
        threat_tags = check.get("threat_tags") or []
        risk_score = check.get("risk_score")

        # mitre_techniques/mitre_tactics come as JSONB from DB — could be:
        # - List of strings: ["T1485", "T1530"]
        # - List of dicts: [{"technique_id": "T1485", "technique_name": "Data Destruction", "confidence": 1.0}]
        raw_techniques = check.get("mitre_techniques") or []
        raw_tactics = check.get("mitre_tactics") or []

        mitre_techniques = []
        for t in raw_techniques:
            if isinstance(t, str):
                mitre_techniques.append(t)
            elif isinstance(t, dict):
                mitre_techniques.append(t.get("technique_id", str(t)))

        mitre_tactics = []
        for t in raw_tactics:
            if isinstance(t, str):
                mitre_tactics.append(t)
            elif isinstance(t, dict):
                mitre_tactics.append(t.get("tactic_name") or t.get("tactic_id", str(t)))

        # Extract rule metadata fields
        rule_title = check.get("title")
        rule_description = check.get("description")
        rule_remediation = check.get("remediation")
        rule_domain = check.get("domain")

        finding = MisconfigFinding(
            misconfig_finding_id=misconfig_finding_id,
            finding_key=finding_key,
            rule_id=rule_id,
            severity=severity,
            result=status,
            account=account,
            region=region,
            service=service,
            resource=resource,
            evidence_refs=evidence_refs,
            checked_fields=checked_fields,
            first_seen_at=created_at,
            last_seen_at=created_at,
            # MITRE ATT&CK enrichment
            threat_category=threat_category,
            threat_tags=threat_tags,
            risk_score=risk_score,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            # Rule metadata
            title=rule_title,
            description=rule_description,
            remediation=rule_remediation,
            domain=rule_domain,
        )

        findings.append(finding)

    return findings

