"""
Threat Detector

Detects threats from normalized misconfig findings using pattern matching and correlation.
"""

import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
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
        pass  # Detection patterns now come from rule_metadata via DB
    
    def detect_threats(
        self,
        findings: List[MisconfigFinding],
        graph_context: Optional[Dict[str, Any]] = None
    ) -> List[Threat]:
        """
        Detect threats from misconfig findings using MITRE ATT&CK enriched metadata.

        Uses threat_category and mitre_techniques/mitre_tactics from rule_metadata
        (enriched via database JOIN in check_findings → rule_metadata).

        Args:
            findings: Normalized misconfig findings (with MITRE ATT&CK data)
            graph_context: Optional graph context from inventory_relationships
                          (asset relationships, reachability, network topology)

        Returns:
            List of detected threats with MITRE ATT&CK enrichment
        """
        threats = []
        threat_groups = {}  # Group threats by type and resource

        # Build reachability map from graph_context if available
        reachable_resources = set()
        if graph_context:
            for rel in graph_context.get("relationships", []):
                if rel.get("relationship_type") in ("exposes", "routes_to", "allows_traffic"):
                    reachable_resources.add(rel.get("target_resource_uid"))

        for finding in findings:
            if finding.result != "FAIL":
                continue

            # Get MITRE data directly from finding (populated by normalizer)
            threat_category = finding.threat_category
            risk_score = finding.risk_score or 50
            threat_tags = finding.threat_tags or []
            mitre_techniques = finding.mitre_techniques or []
            mitre_tactics = finding.mitre_tactics or []

            # Fallback to pattern matching for rules without metadata
            if not threat_category:
                threat_category = self._infer_category_from_rule_id(finding.rule_id)

            # Boost risk score if resource is internet-reachable (from graph context)
            resource_uid = finding.resource.get("resource_uid", "")
            if resource_uid in reachable_resources:
                risk_score = min(100, risk_score + 15)

            # Convert category string to ThreatType enum
            try:
                threat_type = ThreatType(threat_category)
            except (ValueError, TypeError):
                threat_type = ThreatType.MISCONFIGURATION

            # Determine confidence from risk_score
            confidence = Confidence.MEDIUM
            if risk_score >= 85:
                confidence = Confidence.HIGH
            elif risk_score <= 60:
                confidence = Confidence.LOW

            # Group by threat_type + resource_uid so multiple rules on the
            # same resource cluster into ONE threat with many contributing findings.
            threat_key = f"{threat_type.value}:{resource_uid}:{finding.account}:{finding.region}"

            if threat_key not in threat_groups:
                threat_groups[threat_key] = {
                    "threat_type": threat_type,
                    "findings": [],
                    "rule_ids": [],
                    "resource_uid": resource_uid,
                    "resource_type": finding.resource.get("resource_type", ""),
                    "account": finding.account,
                    "region": finding.region,
                    "severity": finding.severity,
                    "confidence": confidence,
                    "risk_score": risk_score,
                    "threat_tags": threat_tags,
                    "mitre_techniques": [],
                    "mitre_tactics": [],
                }

            threat_groups[threat_key]["findings"].append(finding)
            threat_groups[threat_key]["rule_ids"].append(finding.rule_id)
            # Keep highest risk_score and severity across all findings in group
            if risk_score > threat_groups[threat_key]["risk_score"]:
                threat_groups[threat_key]["risk_score"] = risk_score
            # Aggregate MITRE techniques and tactics across findings in group
            if mitre_techniques:
                threat_groups[threat_key]["mitre_techniques"].extend(mitre_techniques)
            if mitre_tactics:
                threat_groups[threat_key]["mitre_tactics"].extend(mitre_tactics)

        # Generate threats from groups
        for threat_key, group in threat_groups.items():
            # Deduplicate MITRE data
            group["mitre_techniques"] = list(set(group["mitre_techniques"]))
            group["mitre_tactics"] = list(set(group["mitre_tactics"]))
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
    
    def _create_threat_from_group(self, group: Dict[str, Any]) -> Optional[Threat]:
        """Create threat object from grouped findings with MITRE ATT&CK enrichment"""
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

        # Collect misconfig finding refs and unique rule_ids
        misconfig_finding_refs = [f.misconfig_finding_id for f in findings]
        unique_rule_ids = list(dict.fromkeys(group.get("rule_ids", [])))

        # Build title and description
        threat_type = group["threat_type"]
        resource_uid = group["resource_uid"]
        resource_type = group.get("resource_type", "")
        threat_label = threat_type.value.replace("_", " ").title()

        # Extract resource short name (last segment of ARN or uid)
        resource_short = resource_uid.rsplit("/", 1)[-1].rsplit(":", 1)[-1] if resource_uid else "unknown"
        service_label = (resource_type.split(".")[0] if resource_type else "resource").upper()

        # Collect all remediations from findings
        all_remediations = []
        for f in findings:
            if f.remediation and f.remediation not in all_remediations:
                all_remediations.append(f.remediation)

        if len(unique_rule_ids) == 1:
            # Single rule — use rule title directly
            rule_title = first_finding.title or unique_rule_ids[0]
            title = f"{rule_title} — {threat_label}"
            description = (
                f"{threat_label} risk detected on {service_label} '{resource_short}'. "
                f"Rule: {unique_rule_ids[0]}"
            )
        else:
            # Multiple rules — summarize as compound threat
            title = f"{service_label} {threat_label} — {len(unique_rule_ids)} violations on {resource_short}"
            # Collect distinct rule titles
            rule_titles = []
            for f in findings:
                t = f.title or f.rule_id
                if t and t not in rule_titles:
                    rule_titles.append(t)
            description = (
                f"Detected {len(findings)} misconfiguration(s) across {len(unique_rule_ids)} rules "
                f"indicating {threat_label.lower()} risk on {service_label} '{resource_short}'. "
                f"Rules: {', '.join(unique_rule_ids[:5])}"
                + (f" (+{len(unique_rule_ids) - 5} more)" if len(unique_rule_ids) > 5 else "")
            )

        # Add MITRE context to description if available
        mitre_techniques = group.get("mitre_techniques", [])
        mitre_tactics = group.get("mitre_tactics", [])
        if mitre_techniques:
            description += f" MITRE ATT&CK: {', '.join(mitre_techniques[:3])}"

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
        evidence_refs = list(set(evidence_refs))

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

        # Build remediation from ALL contributing findings
        remediation_steps = []
        for rem in all_remediations[:5]:
            remediation_steps.append(rem)
        if not remediation_steps:
            remediation_steps.append(f"Review and remediate {len(unique_rule_ids)} failing rule(s)")
        remediation_steps.append("Re-scan to verify threat is resolved")

        # Detect source (ciem or check)
        sources = set()
        for f in findings:
            fd = f.resource if isinstance(f.resource, dict) else {}
            sources.add(fd.get("source", "check"))
        source = "ciem" if "ciem" in sources else "check"

        threat = Threat(
            threat_id=threat_id,
            threat_type=threat_type,
            title=title,
            description=description,
            severity=highest_severity,
            confidence=group["confidence"],
            status=ThreatStatus.OPEN,
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            correlations=correlations,
            affected_assets=affected_assets,
            evidence_refs=evidence_refs,
            remediation={
                "summary": f"Remediate {len(unique_rule_ids)} rule violation(s) to mitigate this {threat_label.lower()} threat",
                "steps": remediation_steps,
            },
            # MITRE ATT&CK enrichment
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            risk_score=group.get("risk_score"),
            # Multi-rule grouping fields
            rule_id=unique_rule_ids[0] if unique_rule_ids else None,
            contributing_rules=unique_rule_ids,
            finding_count=len(findings),
            resource_type=resource_type,
            account_id=group.get("account", ""),
            region=group.get("region", ""),
            source=source,
        )

        return threat

