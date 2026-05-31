"""Tag EC2 rule metadata YAML files with MITRE ATT&CK techniques.

Story: S0-01 — Tag 181 EC2 Rules with MITRE Techniques
Sprint: 0 — MITRE Tagging Prerequisites

Reads each YAML file in catalog/rule/aws_rule_metadata/ec2/, applies a
keyword-based MITRE technique mapping, and adds mitre_techniques,
mitre_tactics, threat_tags, and threat_category fields in-place.

Idempotent: skips files that already have mitre_techniques set.
"""

import re
import sys
from pathlib import Path
from typing import Optional

import yaml

EC2_METADATA_DIR = Path(
    "/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/ec2"
)

# ---------------------------------------------------------------------------
# Mapping rules — evaluated in priority order.
# Each entry is (match_fn, techniques, tactics, threat_tags, threat_category).
# The first matching rule wins.
# ---------------------------------------------------------------------------

TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def _any(*keywords: str):
    """Return a function that checks if any keyword appears in a rule_id / title."""

    def _check(rule_id: str, title: str) -> bool:
        combined = (rule_id + " " + title).lower()
        return any(kw in combined for kw in keywords)

    return _check


# Priority-ordered mapping table.
# (match_fn, techniques_list, tactics_list, extra_threat_tags, threat_category)
MAPPING_RULES = [
    # 1. SSH exposed
    (
        _any("port_ssh", "ssh_access_restricted", "ssh_port_22", "ssh_key", "ssh_password"),
        ["T1021.004"],
        ["lateral_movement"],
        ["ssh-exposed"],
        "lateral_movement",
    ),
    # 2. RDP exposed
    (
        _any("port_rdp", "rdp_access_restricted", "rdp_port_3389"),
        ["T1021.001"],
        ["lateral_movement"],
        ["rdp-exposed"],
        "lateral_movement",
    ),
    # 3. IMDS / metadata — credential theft via SSRF
    (
        _any("imds", "imdsv1", "imdsv2", "metadata"),
        ["T1552.005"],
        ["credential_access"],
        ["cloud-metadata-abuse"],
        "credential_access",
    ),
    # 4. Secrets in user-data / launch templates
    (
        _any("secrets_user_data", "user_data_no_secrets", "launch_template_no_secrets"),
        ["T1552"],
        ["credential_access"],
        ["secrets-in-userdata"],
        "credential_access",
    ),
    # 5. Stale keypairs
    (
        _any("keypair"),
        ["T1552"],
        ["credential_access"],
        ["stale-credentials"],
        "credential_access",
    ),
    # 6. Public EBS snapshots / snapshot encryption — data exposure
    (
        _any("public_snapshot", "snapshot.not_public", "ebs_public_snapshot", "ebs_snapshots_encrypted", "snapshot.encryption", "snapshot.cross_region"),
        ["T1530"],
        ["collection"],
        ["public-snapshot"],
        "collection",
    ),
    # 7. EBS / volume encryption — data at rest
    (
        _any("ebs.volume_encryption", "ebs.default_encryption", "volume.encryption", "ebs_encryption_by_default", "volume.cmk", "instance.data_volumes_encrypted", "instance.root_volume_encrypted", "launchtemplate.root_volume_encrypted", "launchtemplate.volumes_encrypted", "autoscalinggroup.volumes_encrypted", "volume.snapshots_encrypted", "ami.encryption_at_rest"),
        ["T1530"],
        ["collection"],
        ["unencrypted-volume"],
        "collection",
    ),
    # 8. AMI public visibility — infrastructure modification
    (
        _any("ami.not_publicly_shared", "ami_public_visibility", "amipublic.ami_public"),
        ["T1578"],
        ["defense_evasion"],
        ["public-ami"],
        "defense_evasion",
    ),
    # 9. Disable GuardDuty / antimalware — defense evasion
    (
        _any("disable_guardduty", "disable_antimalware"),
        ["T1562.001"],
        ["defense_evasion"],
        ["disable-security-tooling"],
        "defense_evasion",
    ),
    # 10. Activity log — infrastructure modification events
    (
        _any("activity_log.create_vpc_endpoint", "activity_log.modify_network_interface", "activity_log.security_group_modify"),
        ["T1578"],
        ["defense_evasion"],
        ["infra-modification"],
        "defense_evasion",
    ),
    # 11. Run instances — unauthorized compute (cryptomining / persistence)
    (
        _any("activity_log.run_instances"),
        ["T1578"],
        ["impact"],
        ["unauthorized-compute"],
        "impact",
    ),
    # 12. VPC flow logging / logging config — disable cloud logs
    (
        _any("vpc.flow_logging", "vpc_flow_logging", "flow_log", "log_config_change", "client_vpn_endpoint_connection_logging"),
        ["T1562.008"],
        ["defense_evasion"],
        ["disable-flow-logs"],
        "defense_evasion",
    ),
    # 13. Public IP / internet-facing instance
    (
        _any("public_ip", "no_public_ip", "internet_facing"),
        ["T1190"],
        ["initial_access"],
        ["public-ip-exposure"],
        "initial_access",
    ),
    # 14. Shodan / EIP exposure
    (
        _any("shodan_exposure", "eip.shodan"),
        ["T1595"],
        ["reconnaissance"],
        ["shodan-exposed"],
        "initial_access",
    ),
    # 15. EIP not in use — attack surface
    (
        _any("eip.not_in_use"),
        ["T1190"],
        ["initial_access"],
        ["unused-eip"],
        "initial_access",
    ),
    # 16. Security group — internet ingress / open ports
    (
        _any(
            "security_group.allow_ingress_from_internet",
            "security_group_internet_ingress",
            "security_group.network_policies",
            "security_group.only_required_ports",
            "security_group.zero_cidr_ingress",
            "security_group.default_deny_between_network_tiers",
            "security_group.permit_all_egress",
            "security_group.egress_access_restricted",
            "security_group.exception_approvals",
            "security_group.identity_aware",
            "security_group.tier_to_tier",
            "security_group.vpc_endpoint",
            "security_group.policy_store",
            "security_group_default_restrict",
            "security_group_common_ports_restricted",
            "security_group_from_launch_wizard",
            "security_group_with_many_ingress",
            "group.cifs_access_restriction",
            "group.cifs_unrestricted",
            "group.ingress_ipv6_restriction",
            "network_interface.security_groups",
        ),
        ["T1190"],
        ["initial_access"],
        ["open-security-group"],
        "initial_access",
    ),
    # 17. NACL / network ACL
    (
        _any(
            "networkacl.network_no_unrestricted_ingress",
            "networkacl.ssh_port_22",
            "networkacl.rdp_port_3389",
            "networkacl.network_no_allow_all",
            "networkacl.network_allow_ingress_any_port",
            "networkacl.network_egress_restricted",
            "networkacl.ingress_restrict_all",
            "networkacl.endpoint_policies",
            "networkacl.unused_network_acl",
            "networkacl.unrestricted_ingress_blocked",
            "networkacl.network_identity_aware",
        ),
        ["T1190"],
        ["initial_access"],
        ["network-acl-gap"],
        "initial_access",
    ),
    # 18. Subnet isolation / segmentation
    (
        _any("subnet.default_deny_between_tiers", "subnet.automated_isolation", "subnet.quarantine_network", "subnet.private_s_no_igw", "subnet.public_s_use_nacl", "subnet.exception_approvals", "subnet.route_table_association", "subnet.tier_to_tier"),
        ["T1190"],
        ["initial_access"],
        ["subnet-segmentation-gap"],
        "initial_access",
    ),
    # 19. VPC isolation / segmentation
    (
        _any("vpc.default_deny_between_tiers", "vpc.automated_isolation", "vpc.quarantine_network", "vpc.exception_approvals", "vpc.tier_to_tier", "vpc.route_tables_no_unintended", "vpc.dns_hostnames"),
        ["T1190"],
        ["initial_access"],
        ["vpc-segmentation-gap"],
        "initial_access",
    ),
    # 20. Transit gateway — network exposure expansion
    (
        _any("transitgateway.auto_cross_account"),
        ["T1190"],
        ["initial_access"],
        ["transit-gateway-exposure"],
        "initial_access",
    ),
    # 21. VPC endpoint policies
    (
        _any("vpcendpoint.policy_least_privilege", "vpcendpoint.private_dns"),
        ["T1190"],
        ["initial_access"],
        ["vpc-endpoint-policy"],
        "initial_access",
    ),
    # 22. Route table — accidental internet path
    (
        _any("routetable.no_0_from_private", "routetable.vpc_endpoints_used"),
        ["T1190"],
        ["initial_access"],
        ["route-table-internet-path"],
        "initial_access",
    ),
    # 23. IAM role / instance profile
    (
        _any("iam_role", "profile_enabled", "instance.profile_enabled", "internet_facing_with_instance_profile"),
        ["T1078.004"],
        ["defense_evasion"],
        ["iam-role-misconfiguration"],
        "defense_evasion",
    ),
    # 24. Dedicated host — compute isolation
    (
        _any("dedicatedhost"),
        ["T1578"],
        ["defense_evasion"],
        ["dedicated-host"],
        "defense_evasion",
    ),
    # 25. Reserved instance billing/governance
    (
        _any("reserved_instance"),
        ["T1078.004"],
        ["defense_evasion"],
        ["billing-governance"],
        "defense_evasion",
    ),
    # 26. Backup / snapshot existence — availability / data destruction defense
    (
        _any("resource.backup_enabled", "volume.protected_by_backup_plan", "volume.snapshots_exists"),
        ["T1485"],
        ["impact"],
        ["backup-availability"],
        "impact",
    ),
    # 27. VPN connection — weak cipher / key rotation
    (
        _any("vpnconnection"),
        ["T1040"],
        ["credential_access"],
        ["weak-vpn-cipher"],
        "credential_access",
    ),
    # 28. AMI — signed/verified / approved allowlist / vuln scanned
    (
        _any("ami.approved_image", "ami.image_signed", "ami.vuln_scanned"),
        ["T1578"],
        ["defense_evasion"],
        ["unapproved-ami"],
        "defense_evasion",
    ),
    # 29. Launch template — approved / uses_approved
    (
        _any("launchtemplate.uses_approved", "autoscalinggroup.uses_approved_launch_template", "spotinstance.instance_uses_approved_launch_template"),
        ["T1578"],
        ["defense_evasion"],
        ["unapproved-launch-template"],
        "defense_evasion",
    ),
    # 30. Launch template no public IP
    (
        _any("launch_template_no_public_ip", "launchtemplate.no_public_ip", "autoscalinggroup.no_public_ip", "spotinstance.no_public_ip"),
        ["T1190"],
        ["initial_access"],
        ["launch-template-public-ip"],
        "initial_access",
    ),
    # 31. Launch template security groups restrictive
    (
        _any("launchtemplate.security_groups_restrictive"),
        ["T1190"],
        ["initial_access"],
        ["launch-template-sg"],
        "initial_access",
    ),
    # 32. SSM managed / patch compliance / association
    (
        _any("managed_by_ssm", "ssm_association_compliant", "patch_compliance_status"),
        ["T1190"],
        ["initial_access"],
        ["patch-compliance"],
        "initial_access",
    ),
    # 33. Audit log / config change (non-VPC flow)
    (
        _any("audit.log_config_change", "audit.modify_instance_capabilities", "audit.nested_virtualization", "audit.patch_override"),
        ["T1578"],
        ["defense_evasion"],
        ["audit-log-gap"],
        "defense_evasion",
    ),
    # 34. Customer gateway
    (
        _any("customergateway"),
        ["T1190"],
        ["initial_access"],
        ["customer-gateway"],
        "initial_access",
    ),
    # 35. Port exposures (non-SSH/RDP — database/service ports)
    (
        _any("port_cassandra", "port_cifs", "port_elasticsearch", "port_ftp", "port_kafka", "port_kerberos", "port_ldap", "port_memcached", "port_mongodb", "port_mysql", "port_oracle", "port_postgresql", "port_redis", "port_sqlserver", "port_telnet"),
        ["T1190"],
        ["initial_access"],
        ["exposed-service-port"],
        "initial_access",
    ),
    # 36. Instance features — serial console, secure boot, vtpm, paravirtual, ENI
    (
        _any("serial_console_access_restricted", "secure_boot_enabled", "vtpm_enabled", "paravirtual_type", "uses_single_eni"),
        ["T1578"],
        ["defense_evasion"],
        ["instance-hardening"],
        "defense_evasion",
    ),
    # 37. Monitoring / detailed monitoring
    (
        _any("detailed_monitoring"),
        ["T1562.008"],
        ["defense_evasion"],
        ["monitoring-gap"],
        "defense_evasion",
    ),
    # 38. Account block public access
    (
        _any("account.block_public_access"),
        ["T1190"],
        ["initial_access"],
        ["account-public-access-block"],
        "initial_access",
    ),
    # 39. Instance age (older_than_specific_days)
    (
        _any("older_than_specific_days"),
        ["T1578"],
        ["defense_evasion"],
        ["stale-instance"],
        "defense_evasion",
    ),
    # 40. Instance SSH auth method (key-based required)
    (
        _any("ssh_key_authentication", "ssh_key_based_auth_required"),
        ["T1021.004"],
        ["lateral_movement"],
        ["ssh-auth-method"],
        "lateral_movement",
    ),
    # 41. Security group — instance level least functionality
    (
        _any("instance.security_group.least_functionality", "instance.security_group_inbound_restricted"),
        ["T1190"],
        ["initial_access"],
        ["instance-sg-least-functionality"],
        "initial_access",
    ),
    # 42. Volume in-use check
    (
        _any("volume.in_use"),
        ["T1578"],
        ["defense_evasion"],
        ["unattached-volume"],
        "defense_evasion",
    ),
    # 43. VPC peering route table
    (
        _any("vpc_peering_route_table"),
        ["T1190"],
        ["initial_access"],
        ["vpc-peering-exposure"],
        "initial_access",
    ),
]

# Default fallback
DEFAULT_TECHNIQUES = ["T1190"]
DEFAULT_TACTICS = ["initial_access"]
DEFAULT_THREAT_TAGS = ["misconfiguration"]
DEFAULT_THREAT_CATEGORY = "initial_access"


def resolve_mitre(rule_id: str, title: str) -> tuple[list[str], list[str], list[str], str]:
    """Return (techniques, tactics, threat_tags, threat_category) for a rule.

    Args:
        rule_id: The rule identifier string.
        title: The rule title string.

    Returns:
        A 4-tuple of (mitre_techniques, mitre_tactics, threat_tags, threat_category).
    """
    for match_fn, techniques, tactics, extra_tags, category in MAPPING_RULES:
        if match_fn(rule_id, title):
            threat_tags = techniques + tactics + extra_tags
            return techniques, tactics, threat_tags, category

    # Default fallback
    threat_tags = DEFAULT_TECHNIQUES + DEFAULT_TACTICS + DEFAULT_THREAT_TAGS
    return DEFAULT_TECHNIQUES, DEFAULT_TACTICS, threat_tags, DEFAULT_THREAT_CATEGORY


def validate_technique_ids(techniques: list[str]) -> bool:
    """Validate that all technique IDs match ATT&CK pattern T\\d{4}(\\.\\d{3})?.

    Args:
        techniques: List of technique ID strings.

    Returns:
        True if all IDs are valid; False otherwise.
    """
    return all(TECHNIQUE_PATTERN.match(t) for t in techniques)


def tag_file(yaml_path: Path) -> str:
    """Apply MITRE tags to a single YAML file.

    Args:
        yaml_path: Absolute path to the rule metadata YAML file.

    Returns:
        One of: "tagged", "skipped", "error".
    """
    try:
        raw = yaml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except Exception as exc:
        print(f"  ERROR parsing {yaml_path.name}: {exc}")
        return "error"

    if not isinstance(data, dict):
        print(f"  ERROR not a dict: {yaml_path.name}")
        return "error"

    # Idempotency guard
    if data.get("mitre_techniques"):
        return "skipped"

    rule_id = data.get("rule_id", yaml_path.stem)
    title = data.get("title", "")

    techniques, tactics, threat_tags, category = resolve_mitre(rule_id, title)

    # Validate technique IDs before writing
    if not validate_technique_ids(techniques):
        print(f"  ERROR invalid technique IDs for {rule_id}: {techniques}")
        return "error"

    # Append MITRE fields at the end of the file to minimise diff noise
    mitre_block = (
        f"mitre_techniques:\n"
        + "".join(f"- {t}\n" for t in techniques)
        + f"mitre_tactics:\n"
        + "".join(f"- {tac}\n" for tac in tactics)
        + f"threat_tags:\n"
        + "".join(f"- {tag}\n" for tag in threat_tags)
        + f"threat_category: {category}\n"
    )

    # Ensure file ends with a newline before appending
    if not raw.endswith("\n"):
        raw += "\n"

    yaml_path.write_text(raw + mitre_block, encoding="utf-8")

    # Verify the written file parses correctly
    try:
        verification = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert isinstance(verification, dict)
        assert "mitre_techniques" in verification
    except Exception as exc:
        print(f"  ERROR verification failed for {yaml_path.name}: {exc}")
        return "error"

    return "tagged"


def main() -> None:
    """Entry point: tag all EC2 rule metadata YAML files."""
    if not EC2_METADATA_DIR.is_dir():
        print(f"ERROR: directory not found: {EC2_METADATA_DIR}", file=sys.stderr)
        sys.exit(1)

    yaml_files = sorted(EC2_METADATA_DIR.glob("*.yaml"))
    total = len(yaml_files)
    tagged = 0
    skipped = 0
    errors = 0

    print(f"Processing {total} EC2 rule metadata YAMLs in {EC2_METADATA_DIR}")
    print("-" * 70)

    for yaml_path in yaml_files:
        result = tag_file(yaml_path)
        if result == "tagged":
            tagged += 1
        elif result == "skipped":
            skipped += 1
        else:
            errors += 1

    print("-" * 70)
    print(f"Tagged: {tagged}, Skipped (already tagged): {skipped}, Errors: {errors}")
    print(f"Total: {total} files processed.")

    if errors > 0:
        sys.exit(1)

    # AC-1/AC-2 gate: at least 150 of 181 files should be tagged
    min_tagged = 150
    if tagged < min_tagged and skipped == 0:
        print(
            f"WARNING: only {tagged} files tagged — below the {min_tagged} threshold.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
