"""
Enriches AI security findings with MITRE ATT&CK / ATLAS techniques,
compliance frameworks, and remediation context.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AIFindingEnricher:
    """Enriches AI security findings with MITRE, frameworks, and remediation."""

    # MITRE ATT&CK + ATLAS technique mapping
    RULE_TO_MITRE: Dict[str, List[str]] = {
        "AI-MOD-001": ["T1530"],                        # Data from Cloud Storage
        "AI-MOD-002": ["T1565.002"],                    # Stored Data Manipulation
        "AI-MOD-003": [],                               # Governance — no direct technique
        "AI-MOD-004": ["AML.T0020"],                    # Poison Training Data (ATLAS)
        "AI-MOD-005": ["T1190"],                        # Exploit Public-Facing Application
        "AI-EP-001": ["T1190", "AML.T0024"],            # Exploit Public App + Infer Training Data
        "AI-EP-002": ["T1190"],                         # Exploit Public-Facing Application
        "AI-EP-003": ["T1557"],                         # Adversary-in-the-Middle
        "AI-EP-004": [],                                # Monitoring gap — no direct technique
        "AI-EP-005": ["T1499"],                         # Endpoint Denial of Service
        "AI-PS-001": ["AML.T0051", "AML.T0043"],       # LLM Prompt Injection + Craft Adversarial Data
        "AI-PS-002": ["AML.T0051"],                     # LLM Prompt Injection
        "AI-PS-003": ["T1048", "AML.T0024"],            # Exfiltration + Infer Training Data
        "AI-PS-004": [],                                # Content filter gap
        "AI-PS-005": ["T1530"],                         # Data from Cloud Storage (cost/exfil)
        "AI-DP-001": ["T1557"],                         # Adversary-in-the-Middle
        "AI-DP-002": ["T1190"],                         # Exploit Public-Facing Application
        "AI-DP-003": [],                                # Logging gap
        "AI-DP-004": ["T1078"],                         # Valid Accounts
        "AI-DP-005": ["T1048"],                         # Exfiltration Over Alternative Protocol
        "AI-GOV-001": [],                               # Monitoring gap
        "AI-GOV-002": ["T1078"],                        # Valid Accounts (Shadow AI)
        "AI-GOV-003": [],                               # Tagging gap
        "AI-GOV-004": [],                               # Reliability
        "AI-GOV-005": ["T1059", "T1565"],               # Command Execution + Data Manipulation
        "AI-AC-001": ["T1078"],                         # Valid Accounts
        "AI-AC-002": ["T1078"],                         # Valid Accounts
        "AI-AC-003": ["T1078.003"],                     # Local Accounts
        "AI-AC-004": ["T1078.004"],                     # Cloud Accounts
        "AI-AC-005": ["T1530"],                         # Data from Cloud Storage
    }

    # Compliance framework mapping
    RULE_TO_FRAMEWORKS: Dict[str, List[str]] = {
        "AI-MOD-001": ["NIST_AI_RMF-MAP-1.5", "ISO_42001-A.7.3"],
        "AI-MOD-002": ["NIST_AI_RMF-GOV-1.3"],
        "AI-MOD-003": ["AI_ACT-Art.11", "NIST_AI_RMF-GOV-1.3", "ISO_42001-A.5.4"],
        "AI-MOD-004": ["AI_ACT-Art.10", "NIST_AI_RMF-MAP-2.3"],
        "AI-MOD-005": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.1"],
        "AI-EP-001": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.1", "AI_ACT-Art.15"],
        "AI-EP-002": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.1"],
        "AI-EP-003": ["NIST_AI_RMF-GOV-1.7", "GDPR-Art.32"],
        "AI-EP-004": ["NIST_AI_RMF-MAN-2.2", "AI_ACT-Art.12"],
        "AI-EP-005": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.1"],
        "AI-PS-001": ["AI_ACT-Art.15", "NIST_AI_RMF-MAN-4.1"],
        "AI-PS-002": ["AI_ACT-Art.15", "NIST_AI_RMF-MAN-4.2"],
        "AI-PS-003": ["AI_ACT-Art.15", "GDPR-Art.32"],
        "AI-PS-004": ["AI_ACT-Art.15"],
        "AI-PS-005": ["NIST_AI_RMF-GOV-1.7"],
        "AI-DP-001": ["NIST_AI_RMF-GOV-1.7", "GDPR-Art.32"],
        "AI-DP-002": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.1"],
        "AI-DP-003": ["AI_ACT-Art.12", "NIST_AI_RMF-MAN-2.2"],
        "AI-DP-004": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.3"],
        "AI-DP-005": ["NIST_AI_RMF-GOV-1.7"],
        "AI-GOV-001": ["AI_ACT-Art.9", "NIST_AI_RMF-MAN-2.2", "ISO_42001-A.8.4"],
        "AI-GOV-002": ["AI_ACT-Art.16", "ISO_42001-A.6.2"],
        "AI-GOV-003": ["ISO_42001-A.5.4"],
        "AI-GOV-004": ["NIST_AI_RMF-MAN-2.2"],
        "AI-GOV-005": ["NIST_AI_RMF-MAN-4.1", "AI_ACT-Art.15"],
        "AI-AC-001": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.3"],
        "AI-AC-002": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.3"],
        "AI-AC-003": ["NIST_AI_RMF-GOV-1.7", "SOC2-CC6.1"],
        "AI-AC-004": ["NIST_AI_RMF-GOV-1.7"],
        "AI-AC-005": ["NIST_AI_RMF-GOV-1.7", "GDPR-Art.32", "SOC2-CC6.1"],
    }

    # Blast radius estimates by resource type
    BLAST_RADIUS: Dict[str, str] = {
        "sagemaker_endpoint": "high",       # Public inference, data exfil risk
        "sagemaker_model": "medium",        # Model poisoning scope
        "sagemaker_notebook": "high",       # Credential access, lateral movement
        "sagemaker_training_job": "medium",
        "sagemaker_processing_job": "low",
        "bedrock_model": "high",            # Shared model, prompt injection scope
        "bedrock_endpoint": "high",
        "bedrock_guardrail": "low",
        "lambda_ml": "medium",
        "s3_ml_artifact": "medium",
    }

    # ------------------------------------------------------------------ public

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add MITRE techniques, compliance frameworks, and remediation to findings.

        For each finding:
        1. Add mitre_techniques from RULE_TO_MITRE
        2. Add compliance_frameworks from RULE_TO_FRAMEWORKS
        3. Preserve remediation text from rule (or generate stub)
        4. Add risk_context with blast_radius estimate based on resource type

        Args:
            findings: List of finding dicts, each containing at minimum
                      rule_id, resource_type, and optionally remediation.

        Returns:
            Enriched findings list (modified in place and returned).
        """
        for finding in findings:
            rule_id = finding.get("rule_id", "")
            resource_type = (finding.get("resource_type") or "").lower()

            # 1. MITRE techniques
            finding["mitre_techniques"] = self._get_mitre_techniques(
                rule_id, finding.get("mitre_techniques"),
            )

            # 2. Compliance frameworks
            finding["compliance_frameworks"] = self._get_frameworks(
                rule_id, finding.get("frameworks"),
            )

            # 3. Remediation
            if not finding.get("remediation"):
                finding["remediation"] = self._generate_remediation_stub(rule_id)

            # 4. Risk context
            finding["risk_context"] = {
                "blast_radius": self.BLAST_RADIUS.get(resource_type, "unknown"),
                "resource_type": resource_type,
                "is_public": finding.get("evidence", {}).get("actual") if "public" in (finding.get("evidence", {}).get("field") or "") else None,
            }

        logger.info("Enriched %d findings with MITRE/framework/remediation data", len(findings))
        return findings

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single finding.

        Args:
            finding: Finding dict.

        Returns:
            Enriched finding dict.
        """
        return self.enrich_findings([finding])[0]

    def get_enrichment_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from enriched findings.

        Args:
            findings: List of enriched finding dicts.

        Returns:
            Dict with technique and framework coverage statistics.
        """
        total = len(findings)
        with_mitre = sum(1 for f in findings if f.get("mitre_techniques"))
        with_frameworks = sum(1 for f in findings if f.get("compliance_frameworks"))

        # Unique techniques and frameworks
        all_techniques: set = set()
        all_frameworks: set = set()
        for f in findings:
            all_techniques.update(f.get("mitre_techniques") or [])
            all_frameworks.update(f.get("compliance_frameworks") or [])

        return {
            "total_findings": total,
            "findings_with_mitre": with_mitre,
            "findings_with_frameworks": with_frameworks,
            "mitre_coverage_pct": round(with_mitre / max(total, 1) * 100, 2),
            "framework_coverage_pct": round(with_frameworks / max(total, 1) * 100, 2),
            "unique_techniques": sorted(all_techniques),
            "unique_frameworks": sorted(all_frameworks),
        }

    # ------------------------------------------------------------ helpers

    def _get_mitre_techniques(
        self,
        rule_id: str,
        existing: Optional[List[str]] = None,
    ) -> List[str]:
        """Get MITRE techniques for a rule, merging with any existing values.

        Args:
            rule_id: Rule identifier.
            existing: Pre-existing techniques from the rule definition.

        Returns:
            Deduplicated list of MITRE technique IDs.
        """
        mapped = self.RULE_TO_MITRE.get(rule_id, [])
        if existing:
            merged = set(mapped) | set(existing)
            return sorted(merged)
        return list(mapped)

    def _get_frameworks(
        self,
        rule_id: str,
        existing: Optional[List[str]] = None,
    ) -> List[str]:
        """Get compliance frameworks for a rule, merging with any existing values.

        Args:
            rule_id: Rule identifier.
            existing: Pre-existing framework mappings from the rule definition.

        Returns:
            Deduplicated list of framework control IDs.
        """
        mapped = self.RULE_TO_FRAMEWORKS.get(rule_id, [])
        if existing:
            merged = set(mapped) | set(existing)
            return sorted(merged)
        return list(mapped)

    @staticmethod
    def _generate_remediation_stub(rule_id: str) -> str:
        """Generate a generic remediation stub when none is provided.

        Args:
            rule_id: Rule identifier.

        Returns:
            Generic remediation text.
        """
        prefix = rule_id.split("-")[1] if "-" in rule_id else ""
        category_hints = {
            "MOD": "Review model security configuration and apply encryption, versioning, and access controls.",
            "EP": "Review endpoint security settings including authentication, VPC isolation, and TLS.",
            "PS": "Implement prompt security controls including guardrails, input validation, and output filtering.",
            "DP": "Secure the data pipeline with encryption, VPC isolation, and audit logging.",
            "GOV": "Address AI governance gaps including monitoring, tagging, and model registry.",
            "AC": "Apply least-privilege access controls and review IAM policies for ML resources.",
        }
        return category_hints.get(prefix, f"Review and remediate finding for rule {rule_id}.")
