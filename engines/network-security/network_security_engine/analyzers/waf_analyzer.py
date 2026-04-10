"""
Layer 6 — WAF / Shield Analyzer

Analyzes WAFv2 Web ACL coverage, rule configuration, and protection gaps.

Findings:
  - Internet-facing ALB/CloudFront with no WAF
  - WAF in COUNT mode (not BLOCK)
  - WAF with no rules / empty rule groups
  - No rate limiting rule (DDoS gap)
  - Missing managed OWASP core rule set
  - WAF logging disabled
  - WAF default action is ALLOW (should be BLOCK for strict mode)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List

from ..models import (
    NetworkFinding, NetworkLayer, NetworkTopology, WAFRuleGroup, WAFWebACL,
)

logger = logging.getLogger(__name__)

# AWS managed rule group names that should be present
EXPECTED_MANAGED_RULE_GROUPS = {
    "AWSManagedRulesCommonRuleSet",       # OWASP core
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet",
}


def build_waf_acls(
    discovery_data: Dict[str, List[Dict[str, Any]]],
    topology: NetworkTopology,
) -> None:
    """Parse WAFv2 discovery data and populate topology.waf_acls."""
    # WAF Web ACL details
    for row in discovery_data.get("wafv2_web_acl_detail", []):
        raw = row.get("raw_response") or {}
        web_acl = raw.get("WebACL", raw)
        acl_arn = web_acl.get("ARN", row.get("resource_uid", ""))
        if not acl_arn:
            continue

        rule_groups = []
        has_rate_limit = False
        has_managed_core = False

        for rule in web_acl.get("Rules", []):
            name = rule.get("Name", "")
            action = ""
            if rule.get("Action"):
                action = list(rule["Action"].keys())[0] if rule["Action"] else ""
            elif rule.get("OverrideAction"):
                action = list(rule["OverrideAction"].keys())[0] if rule["OverrideAction"] else ""

            # Check for rate-based rule
            stmt = rule.get("Statement", {})
            if "RateBasedStatement" in stmt:
                has_rate_limit = True

            # Check for managed rule groups
            managed = stmt.get("ManagedRuleGroupStatement", {})
            vendor = managed.get("VendorName", "")
            mg_name = managed.get("Name", "")
            if mg_name in EXPECTED_MANAGED_RULE_GROUPS:
                has_managed_core = True

            rule_groups.append(WAFRuleGroup(
                name=name,
                vendor=vendor or "custom",
                priority=rule.get("Priority", 0),
                action=action,
                rules_count=1,
            ))

        default_action = ""
        da = web_acl.get("DefaultAction", {})
        if da:
            default_action = list(da.keys())[0] if da else "allow"

        waf = WAFWebACL(
            acl_arn=acl_arn,
            acl_name=web_acl.get("Name", ""),
            default_action=default_action.lower(),
            rule_groups=rule_groups,
            has_rate_limiting=has_rate_limit,
            has_managed_core_ruleset=has_managed_core,
            capacity_used=web_acl.get("Capacity", 0),
        )
        topology.waf_acls[acl_arn] = waf

    # WAF logging
    for row in discovery_data.get("wafv2_logging", []):
        raw = row.get("raw_response") or {}
        configs = raw.get("LoggingConfigurations", [raw]) if isinstance(raw, dict) else []
        for cfg in configs:
            acl_arn = cfg.get("ResourceArn", "")
            if acl_arn in topology.waf_acls:
                topology.waf_acls[acl_arn].logging_enabled = True

    # WAF → resource associations
    for row in discovery_data.get("wafv2_resources", []):
        raw = row.get("raw_response") or {}
        resource_arns = raw.get("ResourceArns", [])
        # The parent resource UID is the WAF ACL
        acl_arn = row.get("resource_uid", "")
        if acl_arn in topology.waf_acls:
            topology.waf_acls[acl_arn].associated_resources.extend(resource_arns)

    # Also check LBs for WAF association
    for lb_arn, lb in topology.load_balancers.items():
        for acl_arn, waf in topology.waf_acls.items():
            if lb_arn in waf.associated_resources:
                lb.waf_acl_arn = acl_arn

    logger.info("Built %d WAF Web ACLs", len(topology.waf_acls))


def analyze_waf(topology: NetworkTopology) -> List[NetworkFinding]:
    """Analyze WAF configuration (Layer 6)."""
    findings: List[NetworkFinding] = []

    # 1. Internet-facing LBs without WAF
    for lb_arn, lb in topology.load_balancers.items():
        if lb.is_internet_facing and lb.lb_type == "application" and not lb.waf_acl_arn:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l6.no_waf", lb_arn),
                rule_id="net.l6.internet_facing_alb_no_waf",
                title="Internet-facing ALB has no WAF",
                description=(
                    f"Application Load Balancer {lb.lb_name} is internet-facing but has "
                    "no WAFv2 Web ACL associated. No Layer 7 protection against "
                    "SQLi, XSS, or other OWASP attacks."
                ),
                severity="high",
                network_layer=NetworkLayer.L6_WAF,
                network_modules=["waf_protection", "internet_exposure"],
                resource_uid=lb_arn,
                resource_type="load_balancer",
                remediation="Associate a WAFv2 Web ACL with AWSManagedRulesCommonRuleSet.",
                finding_data={
                    "waf_posture": {
                        "lb_name": lb.lb_name,
                        "has_waf": False,
                        "is_internet_facing": True,
                    },
                    "mitre_techniques": ["T1190"],
                },
            ))

    # 2-7. Analyze each WAF ACL
    for acl_arn, waf in topology.waf_acls.items():
        # 2. WAF with no rules
        if len(waf.rule_groups) == 0:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l6.empty_waf", acl_arn),
                rule_id="net.l6.waf_no_rules",
                title="WAF Web ACL has no rules",
                description=(
                    f"WAF Web ACL {waf.acl_name} exists but has no rules. "
                    "It provides no protection."
                ),
                severity="critical",
                network_layer=NetworkLayer.L6_WAF,
                network_modules=["waf_protection"],
                resource_uid=acl_arn,
                resource_type="web_acl",
                remediation="Add managed rule groups (AWSManagedRulesCommonRuleSet at minimum).",
            ))

        # 3. Rules in COUNT mode (monitoring only)
        count_rules = [rg for rg in waf.rule_groups if rg.action in ("count", "none")]
        if count_rules and len(count_rules) == len(waf.rule_groups):
            findings.append(NetworkFinding(
                finding_id=_fid("net.l6.count_only", acl_arn),
                rule_id="net.l6.waf_all_rules_count_mode",
                title="WAF has all rules in COUNT mode (not blocking)",
                description=(
                    f"WAF {waf.acl_name} has {len(count_rules)} rules ALL in COUNT mode. "
                    "No traffic is being blocked — WAF is monitoring only."
                ),
                severity="high",
                network_layer=NetworkLayer.L6_WAF,
                network_modules=["waf_protection"],
                resource_uid=acl_arn,
                resource_type="web_acl",
                remediation="Switch critical rules from COUNT to BLOCK after validation.",
            ))

        # 4. No rate limiting
        if not waf.has_rate_limiting and waf.associated_resources:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l6.no_rate_limit", acl_arn),
                rule_id="net.l6.waf_no_rate_limiting",
                title="WAF has no rate-limiting rule",
                description=(
                    f"WAF {waf.acl_name} has no rate-based rule. "
                    "No protection against DDoS, credential stuffing, or brute-force."
                ),
                severity="medium",
                network_layer=NetworkLayer.L6_WAF,
                network_modules=["waf_protection"],
                resource_uid=acl_arn,
                resource_type="web_acl",
                remediation="Add a rate-based rule (e.g., 2000 requests/5 min per IP).",
                finding_data={"mitre_techniques": ["T1499"]},
            ))

        # 5. Missing OWASP core rule set
        if not waf.has_managed_core_ruleset and waf.rule_groups:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l6.no_owasp", acl_arn),
                rule_id="net.l6.waf_missing_owasp_ruleset",
                title="WAF missing AWS Managed OWASP core rule set",
                description=(
                    f"WAF {waf.acl_name} does not include AWSManagedRulesCommonRuleSet. "
                    "This provides baseline protection against XSS, SQLi, path traversal."
                ),
                severity="medium",
                network_layer=NetworkLayer.L6_WAF,
                network_modules=["waf_protection"],
                resource_uid=acl_arn,
                resource_type="web_acl",
                remediation="Add AWSManagedRulesCommonRuleSet and AWSManagedRulesSQLiRuleSet.",
            ))

        # 6. WAF logging disabled
        if not waf.logging_enabled:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l6.no_waf_logging", acl_arn),
                rule_id="net.l6.waf_logging_disabled",
                title="WAF logging is disabled",
                description=(
                    f"WAF {waf.acl_name} does not have logging enabled. "
                    "Cannot analyze blocked requests or detect attack patterns."
                ),
                severity="medium",
                network_layer=NetworkLayer.L6_WAF,
                network_modules=["waf_protection", "network_monitoring"],
                resource_uid=acl_arn,
                resource_type="web_acl",
                remediation="Enable WAF logging to S3, CloudWatch, or Kinesis Firehose.",
                finding_data={"mitre_techniques": ["T1562.008"]},
            ))

        # 7. Default action is ALLOW
        if waf.default_action == "allow" and waf.associated_resources:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l6.default_allow", acl_arn),
                rule_id="net.l6.waf_default_action_allow",
                title="WAF default action is ALLOW",
                description=(
                    f"WAF {waf.acl_name} default action is ALLOW. Any request not matching "
                    "a rule is permitted. Consider BLOCK as default for strict posture."
                ),
                severity="low",
                status="WARN",
                network_layer=NetworkLayer.L6_WAF,
                network_modules=["waf_protection"],
                resource_uid=acl_arn,
                resource_type="web_acl",
                remediation="Consider switching default action to BLOCK with explicit ALLOW rules.",
            ))

    return findings


def _fid(rule_id: str, resource_key: str) -> str:
    raw = f"{rule_id}|{resource_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
