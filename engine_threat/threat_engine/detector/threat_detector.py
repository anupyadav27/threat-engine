"""
Threat Detector

Detects threats from normalized misconfig findings using pattern matching and correlation.
"""

import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
from ..schemas.threat_report_schema import (
    Threat,
    ThreatType,
    Severity,
    Confidence,
    ThreatStatus,
    ThreatCorrelation,
    MisconfigFinding
)


def generate_stable_threat_id(threat_type: ThreatType, resource_uid: str, account: str, region: str) -> str:
    """Generate stable threat ID from composite key"""
    key = f"{threat_type.value}|{resource_uid}|{account}|{region}"
    hash_obj = hashlib.sha256(key.encode())
    return f"thr_{hash_obj.hexdigest()[:16]}"


class ThreatDetector:
    """Detects threats from misconfig findings"""
    
    def __init__(self):
        self.detection_patterns = self._load_detection_patterns()
    
    def _load_detection_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load threat detection patterns"""
        return {
            "exposure": {
                "description": "Resource is internet-reachable and has public access misconfigurations",
                "rule_patterns": [
                    ".*public.*access.*",
                    ".*internet.*reachable.*",
                    ".*public.*read.*",
                    ".*public.*write.*",
                    ".*bucket.*public.*",
                    ".*security.*group.*0\.0\.0\.0.*",
                    ".*all.*traffic.*allowed.*"
                ],
                "severity_mapping": {
                    "critical": ["public.*write", "all.*traffic"],
                    "high": ["public.*read", "public.*access"],
                    "medium": [".*public.*"]
                },
                "confidence": Confidence.HIGH
            },
            "identity": {
                "description": "Permissive IAM policies combined with privileged access or missing MFA",
                "rule_patterns": [
                    ".*iam.*policy.*permissive.*",
                    ".*iam.*policy.*wildcard.*",
                    ".*iam.*role.*trust.*",
                    ".*mfa.*not.*enabled.*",
                    ".*root.*access.*",
                    ".*admin.*access.*",
                    ".*privilege.*escalation.*"
                ],
                "severity_mapping": {
                    "critical": ["root.*access", "admin.*access", "privilege.*escalation"],
                    "high": ["iam.*policy.*wildcard", "iam.*role.*trust"],
                    "medium": ["mfa.*not.*enabled", "iam.*policy.*permissive"]
                },
                "confidence": Confidence.MEDIUM
            },
            "lateral_movement": {
                "description": "Open inbound rules combined with reachable subnets and high privileges",
                "rule_patterns": [
                    ".*security.*group.*inbound.*open.*",
                    ".*network.*acl.*allow.*all.*",
                    ".*vpc.*peering.*",
                    ".*transit.*gateway.*",
                    ".*vpn.*connection.*"
                ],
                "severity_mapping": {
                    "high": [".*security.*group.*inbound.*open.*", ".*network.*acl.*allow.*all.*"],
                    "medium": [".*vpc.*peering.*", ".*transit.*gateway.*"]
                },
                "confidence": Confidence.MEDIUM
            },
            "data_exfiltration": {
                "description": "Public storage with sensitive data tags and weak logging",
                "rule_patterns": [
                    ".*s3.*bucket.*public.*",
                    ".*storage.*public.*",
                    ".*logging.*not.*enabled.*",
                    ".*encryption.*not.*enabled.*",
                    ".*sensitive.*data.*",
                    ".*pii.*data.*"
                ],
                "severity_mapping": {
                    "critical": [".*s3.*bucket.*public.*sensitive.*", ".*pii.*data.*public.*"],
                    "high": [".*s3.*bucket.*public.*", ".*storage.*public.*"],
                    "medium": [".*logging.*not.*enabled.*", ".*encryption.*not.*enabled.*"]
                },
                "confidence": Confidence.HIGH
            },
            "privilege_escalation": {
                "description": "IAM policies or roles that allow privilege escalation",
                "rule_patterns": [
                    ".*iam.*policy.*escalate.*",
                    ".*iam.*role.*assume.*",
                    ".*passrole.*",
                    ".*create.*role.*",
                    ".*attach.*policy.*"
                ],
                "severity_mapping": {
                    "critical": [".*iam.*policy.*escalate.*", ".*passrole.*"],
                    "high": [".*iam.*role.*assume.*", ".*create.*role.*"]
                },
                "confidence": Confidence.HIGH
            },
            "data_breach": {
                "description": "Misconfigurations that could lead to data breach",
                "rule_patterns": [
                    ".*database.*public.*",
                    ".*rds.*public.*",
                    ".*encryption.*disabled.*",
                    ".*backup.*not.*enabled.*",
                    ".*snapshot.*public.*"
                ],
                "severity_mapping": {
                    "critical": [".*database.*public.*", ".*rds.*public.*"],
                    "high": [".*encryption.*disabled.*", ".*backup.*not.*enabled.*"]
                },
                "confidence": Confidence.HIGH
            }
        }
    
    def detect_threats(
        self,
        findings: List[MisconfigFinding],
        graph_context: Optional[Dict[str, Any]] = None
    ) -> List[Threat]:
        """
        Detect threats from misconfig findings using metadata-driven categorization.
        
        Uses threat_category from rule_metadata (enriched via JOIN) instead of pattern matching.
        
        Args:
            findings: Normalized misconfig findings (with rule metadata)
            graph_context: Optional graph context (asset relationships, reachability)
        
        Returns:
            List of detected threats
        """
        threats = []
        threat_groups = {}  # Group threats by type and resource
        
        for finding in findings:
            if finding.result != "FAIL":
                continue
            
            # Get threat category from rule metadata (enriched via database JOIN)
            threat_category = None
            risk_score = 50
            threat_tags = []
            
            # Check if finding has metadata fields (from check_results JOIN rule_metadata)
            if hasattr(finding, 'threat_category'):
                threat_category = finding.threat_category
                risk_score = getattr(finding, 'risk_score', 50) or 50
                threat_tags = getattr(finding, 'threat_tags', []) or []
            elif isinstance(finding, dict):
                threat_category = finding.get('threat_category')
                risk_score = finding.get('risk_score', 50) or 50
                threat_tags = finding.get('threat_tags', []) or []
            
            # Skip if no threat category in metadata
            if not threat_category:
                # Fallback to pattern matching for rules without metadata
                threat_category = self._infer_category_from_rule_id(finding.rule_id)
            
            # Convert category string to ThreatType enum
            try:
                threat_type = ThreatType(threat_category)
            except (ValueError, TypeError):
                # Default to misconfiguration if category doesn't map to enum
                threat_type = ThreatType.MISCONFIGURATION
            
            # Determine confidence from metadata or default
            confidence = Confidence.MEDIUM  # Default
            if risk_score >= 85:
                confidence = Confidence.HIGH
            elif risk_score <= 60:
                confidence = Confidence.LOW
            
            # Create threat key for grouping (group by threat type + resource)
            resource_uid = finding.resource.get("resource_uid", "")
            threat_key = f"{threat_type.value}:{resource_uid}:{finding.account}:{finding.region}"
            
            if threat_key not in threat_groups:
                threat_groups[threat_key] = {
                    "threat_type": threat_type,
                    "findings": [],
                    "resource_uid": resource_uid,
                    "account": finding.account,
                    "region": finding.region,
                    "severity": finding.severity,  # Use rule's severity
                    "confidence": confidence,
                    "risk_score": risk_score,
                    "threat_tags": threat_tags
                }
            
            threat_groups[threat_key]["findings"].append(finding)
        
        # Generate threats from groups
        for threat_key, group in threat_groups.items():
            threat = self._create_threat_from_group(group)
            if threat:
                threats.append(threat)
        
        return threats
    
    def _infer_category_from_rule_id(self, rule_id: str) -> str:
        """Fallback: infer category from rule_id for rules without metadata"""
        rule_lower = rule_id.lower()
        if 'iam' in rule_lower or 'auth' in rule_lower or 'mfa' in rule_lower:
            return 'identity'
        elif 'public' in rule_lower or 'internet' in rule_lower or '0.0.0.0' in rule_lower:
            return 'exposure'
        elif 's3' in rule_lower and ('logging' in rule_lower or 'encryption' in rule_lower):
            return 'data_exfiltration'
        elif 'rds' in rule_lower and 'public' in rule_lower:
            return 'data_breach'
        else:
            return 'misconfiguration'
    
    def _matches_pattern(self, rule_id: str, patterns: List[str]) -> bool:
        """Check if rule_id matches any pattern"""
        import re
        rule_id_lower = rule_id.lower()
        for pattern in patterns:
            if re.search(pattern, rule_id_lower):
                return True
        return False
    
    def _determine_severity(
        self,
        rule_id: str,
        finding_severity: Severity,
        pattern_config: Dict[str, Any]
    ) -> Severity:
        """Determine threat severity based on pattern matching"""
        import re
        
        rule_id_lower = rule_id.lower()
        severity_mapping = pattern_config.get("severity_mapping", {})
        
        # Check critical patterns first
        for severity_str, patterns in severity_mapping.items():
            for pattern in patterns:
                if re.search(pattern, rule_id_lower):
                    try:
                        return Severity(severity_str)
                    except ValueError:
                        pass
        
        # Fall back to finding severity
        return finding_severity
    
    def _create_threat_from_group(self, group: Dict[str, Any]) -> Optional[Threat]:
        """Create threat object from grouped findings"""
        findings = group["findings"]
        if not findings:
            return None
        
        # Use first finding for base information
        first_finding = findings[0]
        
        # Generate threat ID
        threat_id = generate_stable_threat_id(
            group["threat_type"],
            group["resource_uid"],
            group["account"],
            group["region"]
        )
        
        # Collect misconfig finding refs
        misconfig_finding_refs = [f.misconfig_finding_id for f in findings]
        
        # Build title and description from rule metadata (use first finding's metadata)
        threat_type = group["threat_type"]
        
        # Try to get title from rule metadata (findings should have this from enrichment)
        rule_title = None
        for finding in findings:
            # Check if finding has metadata fields (from database JOIN)
            if hasattr(finding, 'title') or (isinstance(finding, dict) and 'title' in finding):
                rule_title = finding.title if hasattr(finding, 'title') else finding.get('title')
                break
        
        if rule_title:
            # Use rule metadata title with resource context
            title = f"{rule_title} - {threat_type.value.replace('_', ' ').title()}"
            description = (
                f"Detected {len(findings)} violations of '{rule_title}' "
                f"indicating {threat_type.value.replace('_', ' ')} risk. "
                f"Affected resource: {group['resource_uid']}"
            )
        else:
            # Fallback to generic title
            title = f"{threat_type.value.replace('_', ' ').title()} Threat Detected"
            description = (
                f"Detected {len(findings)} misconfiguration(s) that indicate a "
                f"{threat_type.value.replace('_', ' ')} threat. "
                f"Resource: {group['resource_uid']}"
            )
        
        # Extract affected assets
        affected_assets = []
        for finding in findings:
            asset = {
                "resource_uid": finding.resource.get("resource_uid"),
                "resource_arn": finding.resource.get("resource_arn"),
                "resource_id": finding.resource.get("resource_id"),
                "resource_type": finding.resource.get("resource_type"),
                "region": finding.region,
                "account": finding.account
            }
            if asset not in affected_assets:
                affected_assets.append(asset)
        
        # Collect evidence refs
        evidence_refs = []
        for finding in findings:
            evidence_refs.extend(finding.evidence_refs)
        evidence_refs = list(set(evidence_refs))  # Deduplicate
        
        # Build correlations
        correlations = ThreatCorrelation(
            misconfig_finding_refs=misconfig_finding_refs,
            affected_assets=affected_assets
        )
        
        # Determine highest severity from findings
        severities = [f.severity for f in findings]
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        highest_severity = group["severity"]
        for sev in severity_order:
            if sev in severities:
                highest_severity = sev
                break
        
        threat = Threat(
            threat_id=threat_id,
            threat_type=threat_type,
            title=title,
            description=description,
            severity=highest_severity,
            confidence=group["confidence"],
            status=ThreatStatus.OPEN,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
            correlations=correlations,
            affected_assets=affected_assets,
            evidence_refs=evidence_refs,
            remediation={
                "summary": f"Review and remediate {len(findings)} misconfiguration(s) to mitigate this threat",
                "steps": [
                    f"Review misconfig findings: {', '.join(misconfig_finding_refs[:3])}",
                    "Apply recommended remediation for each finding",
                    "Re-scan to verify threat is resolved"
                ]
            }
        )
        
        return threat

