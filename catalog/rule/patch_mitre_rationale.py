#!/usr/bin/env python3
"""
patch_mitre_rationale.py

Updates rationale text for 15 key techniques with authoritative MITRE ATT&CK
content sourced from attack.mitre.org (web-researched). Also adds specific
detection_events field to inform the threat engine.

Runs against both aws_rule_ciem/ and azure_rule_ciem/.

Usage:
    python3 patch_mitre_rationale.py
    python3 patch_mitre_rationale.py --dry-run
"""

import argparse
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
DIRS = [
    ROOT / "catalog" / "rule" / "azure_rule_ciem",
    ROOT / "catalog" / "rule" / "aws_rule_ciem",
    ROOT / "catalog" / "rule" / "gcp_rule_ciem",
    ROOT / "catalog" / "rule" / "k8s_rule_ciem",
]

# ─────────────────────────────────────────────────────────────────────────────
# Authoritative MITRE ATT&CK content from attack.mitre.org
# ─────────────────────────────────────────────────────────────────────────────

MITRE_PATCHES: dict[str, dict] = {
    "T1098.003": {
        "rationale": (
            "Adversaries add additional roles or permissions to adversary-controlled cloud accounts "
            "to maintain persistent access to a tenant. Attackers target Global Administrator, Owner, "
            "and Contributor roles — granting full control over subscription resources without "
            "deploying remote access tools. Detected via: IAM role attachment events, privilege grant "
            "events in Entra ID/Okta, and admin role assignment in Microsoft 365."
        ),
        "detection_events": [
            "Microsoft.Authorization/roleAssignments/write",
            "iam:AttachUserPolicy",
            "iam:PutRolePolicy",
            "Add member to role (Entra ID audit)",
        ],
    },
    "T1098.006": {
        "rationale": (
            "Adversaries add roles or permissions to service accounts or workload identities to "
            "maintain persistent access to container orchestration systems. Creating Kubernetes "
            "RoleBindings or ClusterRoleBindings for attacker-controlled identities enables "
            "cluster-wide command execution. Detected via: high-privilege role assignments outside "
            "CI/CD automation, bindings from unfamiliar IP addresses, and unexpected ServiceAccount token creation."
        ),
        "detection_events": [
            "rolebindings/create",
            "clusterrolebindings/create",
            "serviceaccounts/create",
        ],
    },
    "T1548": {
        "rationale": (
            "Adversaries circumvent elevation control mechanisms to gain higher-level permissions. "
            "In cloud environments this includes SAML assertion manipulation, IAM role privilege "
            "boundary modifications, and STS:AssumeRole chaining to escalate from limited to "
            "administrative access. Detected via: privilege boundary removal events, "
            "STS role chaining with unusually broad permissions, and unexpected policy attachments."
        ),
        "detection_events": [
            "iam:CreateRole with permissive trust",
            "sts:AssumeRole with cross-account escalation",
            "Microsoft.Authorization/elevateAccess/action",
        ],
    },
    # K8s provider override for T1548 — container-specific escalation
    "T1548_k8s": {
        "rationale": (
            "Adversaries abuse Linux privilege escalation mechanisms within Kubernetes containers — "
            "including setuid/setgid binaries, Linux capabilities, and missing allowPrivilegeEscalation "
            "controls. Without explicit securityContext restrictions, a process inside a container can "
            "call execve() on a setuid binary to gain root (UID 0), directly enabling container escape "
            "chains (T1611). CIS Kubernetes Benchmark 5.2.5/5.2.6 require these controls to be "
            "explicitly set. Detected via: pods created without runAsNonRoot=true, "
            "pods created with allowPrivilegeEscalation unset or true, and setuid binary execution."
        ),
        "detection_events": [
            "pods/create without securityContext.runAsNonRoot=true",
            "pods/create with allowPrivilegeEscalation unset or true",
            "pods/create with runAsUser=0",
            "setuid binary execution inside container namespace",
        ],
    },
    "T1556.007": {
        "rationale": (
            "Adversaries patch, modify, or backdoor cloud authentication processes tied to on-premises "
            "identities (Golden SAML / hybrid identity attack). Organizations using Password Hash Sync, "
            "Pass-Through Authentication, or AD FS are at risk. A rogue identity provider can issue "
            "valid tokens for any user in the tenant without their credentials. Detected via: "
            "AD FS token-signing certificate changes, federation trust modifications, "
            "and conditional access MFA bypass modifications."
        ),
        "detection_events": [
            "microsoft.directory/domains/federation/update",
            "Set domain authentication (Entra ID audit)",
            "AD FS token-signing certificate modification",
            "ExternalIdP creation event",
        ],
    },
    "T1562.008": {
        "rationale": (
            "Adversaries disable or modify cloud logging capabilities to limit visibility into their "
            "activities. With sufficient permissions they can disable CloudTrail, delete Azure diagnostic "
            "settings, delete log sinks, or modify audit configurations — blinding defenders to all "
            "subsequent actions. Detected via: StopLogging, DeleteTrail, UpdateSink, "
            "Delete-DiagnosticSetting, license downgrade events, and SaaS audit log disable events."
        ),
        "detection_events": [
            "cloudtrail:StopLogging",
            "cloudtrail:DeleteTrail",
            "Microsoft.Insights/diagnosticSettings/delete",
            "microsoft.aadiam/diagnosticSettings/delete",
            "logging.sinks.delete",
        ],
    },
    "T1562.001": {
        "rationale": (
            "Adversaries modify or disable security tools to avoid detection of their activities — "
            "including killing security software processes, disabling GuardDuty detectors, deleting "
            "Microsoft Defender plans, or tampering with cloud monitoring agents. Once defenses are "
            "disabled, subsequent attack phases proceed without generating alerts. Detected via: "
            "security process/service termination, cloud monitoring agent disable API calls, "
            "and container admission controller tampering."
        ),
        "detection_events": [
            "guardduty:DeleteDetector",
            "securityhub:DisableSecurityHub",
            "Microsoft.Security/pricings/write (Standard → Free)",
            "Set-MpPreference -DisableRealtimeMonitoring",
        ],
    },
    "T1552.001": {
        "rationale": (
            "Adversaries search local file systems, remote file shares, and cloud storage for files "
            "containing insecurely stored credentials — including config files, source code, .env files, "
            "and shell history. Cloud-specific targets include ~/.aws/credentials, terraform.tfstate "
            "(containing plaintext secrets), and container environment variable dumps. Detected via: "
            "file read access to .env/.xml/.ps1/config files, grep commands targeting credential "
            "patterns, and container process access to mounted secret paths."
        ),
        "detection_events": [
            "s3:GetObject on .env / credentials files",
            "EC2 metadata API call from unexpected source",
            "Container exec with grep/find credential patterns",
        ],
    },
    "T1136.003": {
        "rationale": (
            "Adversaries create cloud accounts (IAM users, Entra ID users, service principals) to "
            "maintain access to victim systems without deploying persistent remote access tools. "
            "Such accounts establish secondary credentialed access that survives password resets of "
            "the initially compromised account. Detected via: IAM CreateUser + AttachUserPolicy from "
            "non-standard sources, Add User events from unusual IPs, and SaaS account provisioning "
            "outside business hours."
        ),
        "detection_events": [
            "iam:CreateUser",
            "microsoft.directory/users/create",
            "organizations:CreateAccount",
            "New-MsolUser (PowerShell)",
        ],
    },
    "T1578.001": {
        "rationale": (
            "Adversaries create snapshots or data backups within cloud accounts to evade defenses and "
            "stage data for exfiltration. Snapshots can be shared with attacker-controlled accounts, "
            "mounted to attacker instances to bypass access restrictions on the original volume. "
            "Detected via: snapshot creation by unexpected or newly provisioned IAM users, "
            "rapid snapshot-create → cross-account share sequences, and snapshots from sensitive "
            "volumes without change-control approval."
        ),
        "detection_events": [
            "ec2:CreateSnapshot",
            "ec2:ModifySnapshotAttribute (cross-account share)",
            "Microsoft.Compute/snapshots/write",
            "Microsoft.Compute/disks/beginGetAccess/action",
        ],
    },
    "T1578.002": {
        "rationale": (
            "Adversaries create new instances or VMs within cloud accounts to execute from a clean "
            "environment that bypasses existing firewall rules and permissions tied to existing "
            "resources. Fresh compute resources are also used for cryptomining, C2 hosting, or as "
            "pivot points. Detected via: VM launch by rarely-used or newly-created accounts, "
            "instance creation from unexpected geographic locations, and large instance type selection."
        ),
        "detection_events": [
            "ec2:RunInstances",
            "Microsoft.Compute/virtualMachines/write",
            "containers:create with privileged=true",
        ],
    },
    "T1651": {
        "rationale": (
            "Adversaries abuse cloud management services such as AWS Systems Manager (Run Command), "
            "Azure VM RunCommand, or Automation Runbooks to execute commands within virtual machines "
            "via installed agents — achieving remote code execution through the cloud control plane "
            "without requiring network access to the instance. Detected via: SSM RunCommand / Azure "
            "RunCommand API calls by unexpected users, command execution outside maintenance windows, "
            "and service account-initiated script execution atypical for admin tasks."
        ),
        "detection_events": [
            "ssm:SendCommand",
            "Microsoft.Compute/virtualMachines/runCommand/action",
            "Microsoft.Automation/automationAccounts/runbooks/publish/action",
            "ec2:GetConsoleOutput (post-execution evidence gathering)",
        ],
    },
    "T1611": {
        "rationale": (
            "Adversaries escape container or virtualized environment isolation to gain access to the "
            "underlying host, circumventing container security boundaries to access other containerized "
            "resources or the node's credentials. Requires privileged container, hostPath mounts, or "
            "kernel exploit. Detected via: hostPath mounts to /proc or /sys, privileged container "
            "launches, unshare/keyctl/mount syscalls from container processes, and process execution "
            "outside container namespaces."
        ),
        "detection_events": [
            "pods/create with securityContext.privileged=true",
            "pods/create with hostPath mount to /",
            "seccomp profile disabled or unconfined",
            "Container process fork outside namespace",
        ],
    },
    "T1610": {
        "rationale": (
            "Adversaries deploy containers into environments using Docker APIs or Kubernetes control "
            "planes to facilitate execution or evade defenses by running malicious images outside "
            "standard deployment processes. Deployed containers can host C2 infrastructure, "
            "cryptomining workloads, or data exfiltration tools. Detected via: container create + "
            "start by non-admin principals, images not on an allowlist or using 'latest' tag, "
            "privileged mode or host namespace mount at runtime, and unauthenticated Docker API access."
        ),
        "detection_events": [
            "pods/create (Kubernetes audit)",
            "containers:create via Docker API",
            "aks:CreatePod by non-CI/CD principal",
            "Admission controller deny events (missing context = bypass attempt)",
        ],
    },
    "T1485": {
        "rationale": (
            "Adversaries destroy data and files on cloud storage or databases at scale to interrupt "
            "availability, render services inoperable, or destroy evidence. Cloud data destruction "
            "is often irreversible without backups. Detected via: bulk S3 object deletion via elevated "
            "IAM credentials, EC2/EBS/snapshot mass deletion events, storage account deletion with "
            "soft-delete disabled, and database cluster deletion without final snapshot."
        ),
        "detection_events": [
            "s3:DeleteObject (bulk)",
            "s3:DeleteBucket",
            "ec2:TerminateInstances (mass)",
            "Microsoft.Storage/storageAccounts/delete",
            "rds:DeleteDBCluster without SkipFinalSnapshot=false",
        ],
    },
    "T1530": {
        "rationale": (
            "Adversaries access data from cloud object storage (S3, Azure Blob, GCS) which may be "
            "misconfigured with overly permissive policies exposing PII, medical records, financial "
            "data, or credentials. Bulk download followed by external transfer indicates active data "
            "theft. Detected via: unusual object access patterns from new IAM users or roles, "
            "OAuth token grants to external apps preceding high-volume downloads, "
            "and GetObject events from anomalous IPs or user agents."
        ),
        "detection_events": [
            "s3:GetObject (high volume from single principal)",
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "ListObjects followed by bulk GetObject",
            "Storage access from external/anonymous IP",
        ],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# YAML writer  (same field order as main enrichment)
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_str(value: str) -> str:
    if "\n" in value:
        lines = value.rstrip("\n").split("\n")
        return "|\n" + "\n".join("  " + ln for ln in lines)
    if any(c in value for c in (':', '#', '[', ']', '{', '}', '&', '*', '!', '|', '>', '"', "'")):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def _dump_rule(data: dict) -> str:
    lines = []

    SCALAR_FIELDS = ["rule_id", "service", "provider", "check_type", "severity", "title", "description"]
    for field in SCALAR_FIELDS:
        if field in data:
            lines.append(f"{field}: {_yaml_str(str(data[field]))}")

    if "rationale" in data:
        lines.append(f"rationale: {_yaml_str(data['rationale'])}")

    if "threat_category" in data:
        lines.append(f"threat_category: {data['threat_category']}")

    if "mitre_tactics" in data:
        lines.append("mitre_tactics:")
        for t in data["mitre_tactics"]:
            lines.append(f"- {t}")

    if "mitre_techniques" in data:
        lines.append("mitre_techniques:")
        for t in data["mitre_techniques"]:
            lines.append(f"- {t}")

    if "risk_score" in data:
        lines.append(f"risk_score: {data['risk_score']}")

    for field in ("resource", "source", "is_active"):
        if field in data:
            val = data[field]
            if isinstance(val, bool):
                lines.append(f"{field}: {'true' if val else 'false'}")
            else:
                lines.append(f"{field}: {_yaml_str(str(val))}")

    # Engine tags (from enrich_ciem_tags.py)
    for field in ("domain", "action_category", "log_source_type", "posture_category"):
        if field in data and data[field]:
            lines.append(f"{field}: {_yaml_str(str(data[field]))}")

    if "threat_tags" in data:
        tags = data["threat_tags"] or []
        if tags:
            lines.append("threat_tags:")
            for t in tags:
                lines.append(f"- {t}")
        else:
            lines.append("threat_tags: []")

    if "risk_indicators" in data:
        ri = data.get("risk_indicators") or {}
        if ri:
            lines.append("risk_indicators:")
            for k, v in ri.items():
                lines.append(f"  {k}: {v}")

    if "iam_security" in data:
        iam = data["iam_security"] or {}
        lines.append("iam_security:")
        lines.append(f"  applicable: {'true' if iam.get('applicable') else 'false'}")
        mods = iam.get("modules", [])
        if mods:
            lines.append("  modules:")
            for m in mods:
                lines.append(f"  - {m}")
        else:
            lines.append("  modules: []")

    if "data_security" in data:
        ds = data["data_security"] or {}
        lines.append("data_security:")
        lines.append(f"  applicable: {'true' if ds.get('applicable') else 'false'}")
        if ds.get("applicable"):
            mods = ds.get("modules", [])
            if mods:
                lines.append("  modules:")
                for m in mods:
                    lines.append(f"  - {m}")
            cats = ds.get("categories", [])
            if cats:
                lines.append("  categories:")
                for c in cats:
                    lines.append(f"  - {c}")
            if "priority" in ds:
                lines.append(f"  priority: {ds['priority']}")
            impact = ds.get("impact", {})
            if impact:
                lines.append("  impact:")
                for k, v in impact.items():
                    lines.append(f"    {k}: {_yaml_str(v)}")
            sc = ds.get("sensitive_data_context", "")
            if sc:
                lines.append(f"  sensitive_data_context: {_yaml_str(sc)}")

    # compliance_frameworks
    cf = data.get("compliance_frameworks") or {}
    if cf:
        lines.append("compliance_frameworks:")
        for fw, controls in cf.items():
            lines.append(f"  {fw}:")
            for c in (controls or []):
                lines.append(f"  - {c}")
    else:
        lines.append("compliance_frameworks: {}")

    # detection_events
    if "detection_events" in data:
        lines.append("detection_events:")
        for de in data["detection_events"]:
            lines.append(f"- {_yaml_str(de)}")

    if "remediation" in data:
        lines.append(f"remediation: {_yaml_str(data['remediation'])}")

    if "references" in data:
        lines.append("references:")
        for ref in data["references"]:
            lines.append(f"- {ref}")

    if "check_config" in data:
        cc_yaml = yaml.dump(
            {"check_config": data["check_config"]},
            default_flow_style=False,
            allow_unicode=True,
        ).rstrip()
        lines.append(cc_yaml)

    if "version" in data:
        lines.append(f"version: '{data['version']}'")

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Patch rationale with authoritative MITRE content")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    updated = skipped = 0
    for d in DIRS:
        for path in sorted(d.rglob("*.yaml")):
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                if not isinstance(rule, dict):
                    continue

                techniques = rule.get("mitre_techniques") or []
                provider  = rule.get("provider", "")
                patch = None
                for tech in techniques:
                    # Check provider-specific override first (e.g. T1548_k8s)
                    provider_key = f"{tech}_{provider}"
                    if provider_key in MITRE_PATCHES:
                        patch = MITRE_PATCHES[provider_key]
                        break
                    if tech in MITRE_PATCHES:
                        patch = MITRE_PATCHES[tech]
                        break
                    parent = tech.split(".")[0]
                    parent_key = f"{parent}_{provider}"
                    if parent_key in MITRE_PATCHES:
                        patch = MITRE_PATCHES[parent_key]
                        break
                    if parent in MITRE_PATCHES:
                        patch = MITRE_PATCHES[parent]
                        break

                if not patch:
                    skipped += 1
                    continue

                rule["rationale"] = patch["rationale"]
                if patch.get("detection_events"):
                    rule["detection_events"] = patch["detection_events"]

                if args.dry_run:
                    print(f"  DRY  {path.name}")
                    updated += 1
                    continue

                path.write_text(_dump_rule(rule), encoding="utf-8")
                updated += 1

            except Exception as exc:
                print(f"  ERROR  {path.name}: {exc}")

    print(f"\nPatched  : {updated}")
    print(f"Unchanged: {skipped}")
    if args.dry_run:
        print("(dry-run)")


if __name__ == "__main__":
    main()
