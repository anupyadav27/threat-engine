"""Tag S3 rule YAML files with MITRE ATT&CK techniques.

Story S0-03: Tag 66 untagged S3 rules with MITRE techniques. The 10 files
that already have ``mitre_techniques`` are skipped without modification.

Run:
    python catalog/rule/tag_mitre_s3.py

Prints:
    Tagged: X, Skipped (already tagged): Y, Errors: Z
"""

import os
import re
import sys
from pathlib import Path
from typing import Optional

import yaml

S3_METADATA_DIR = Path(
    "/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/s3"
)

# ---------------------------------------------------------------------------
# Technique definitions
# ---------------------------------------------------------------------------

TECHNIQUE_T1562_008 = {
    "mitre_techniques": ["T1562.008"],
    "mitre_tactics": ["defense-evasion"],
    "threat_tags": ["disable-cloud-audit-logs"],
    "threat_category": "defense_evasion",
}

TECHNIQUE_T1537 = {
    "mitre_techniques": ["T1537"],
    "mitre_tactics": ["exfiltration"],
    "threat_tags": ["cloud-account-transfer"],
    "threat_category": "exfiltration",
}

TECHNIQUE_T1530 = {
    "mitre_techniques": ["T1530"],
    "mitre_tactics": ["collection"],
    "threat_tags": ["cloud-storage-exposure"],
    "threat_category": "collection",
}

TECHNIQUE_T1486 = {
    "mitre_techniques": ["T1486"],
    "mitre_tactics": ["impact"],
    "threat_tags": ["data-encrypted-for-impact"],
    "threat_category": "impact",
}

TECHNIQUE_T1485 = {
    "mitre_techniques": ["T1485"],
    "mitre_tactics": ["impact"],
    "threat_tags": ["data-destruction"],
    "threat_category": "impact",
}

TECHNIQUE_T1071 = {
    "mitre_techniques": ["T1071"],
    "mitre_tactics": ["command-and-control"],
    "threat_tags": ["application-layer-protocol"],
    "threat_category": "command_and_control",
}

TECHNIQUE_DEFAULT = TECHNIQUE_T1530


# ---------------------------------------------------------------------------
# Keyword → technique mapping (evaluated in priority order)
# ---------------------------------------------------------------------------

def _rule_key(rule_id: str, title: str) -> str:
    """Return a single lowercase string from rule_id and title for keyword matching."""
    return (rule_id + " " + title).lower()


def select_technique(rule_id: str, title: str) -> dict:
    """Return the MITRE technique dict for a given rule.

    Priority order:
        1. Log / logging / access_log → T1562.008 (defense-evasion)
        2. Replication / cross-account / cross_account → T1537 (exfiltration)
        3. Public / acl / policy + public → T1530 (collection)
        4. Encrypt → T1486 (impact)
        5. Versioning / lifecycle / mfa_delete → T1485 (impact)
        6. Notification / event → T1071 (command-and-control)
        7. Default → T1530 (collection)

    Special override: ``server_access_logging`` rules get T1562.008, not T1530.
    The keyword "log" / "logging" / "access_log" at rule level already captures
    these — this note documents intent, not a separate code path.
    """
    key = _rule_key(rule_id, title)

    # Priority 1: logging / access_log rules → disable cloud audit logs
    if any(kw in key for kw in ("log", "logging", "access_log")):
        return TECHNIQUE_T1562_008

    # Priority 2: cross-account / replication rules → data transfer
    if any(kw in key for kw in ("replication", "cross-account", "cross_account")):
        return TECHNIQUE_T1537

    # Priority 3: public access / acl / policy public → data collection
    if any(kw in key for kw in ("public", "acl")):
        return TECHNIQUE_T1530

    # Priority 4: encryption rules → data encrypted for impact (absence of encryption)
    if "encrypt" in key:
        return TECHNIQUE_T1486

    # Priority 5: versioning / lifecycle / mfa_delete → data destruction
    if any(kw in key for kw in ("versioning", "lifecycle", "mfa_delete", "immutab", "object_lock", "lock")):
        return TECHNIQUE_T1485

    # Priority 6: notification / event rules → application layer protocol
    if any(kw in key for kw in ("notification", "event")):
        return TECHNIQUE_T1071

    # Default fallback
    return TECHNIQUE_DEFAULT


# ---------------------------------------------------------------------------
# YAML load / dump helpers
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> Optional[dict]:
    """Load YAML file, returning None on parse error."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        print(f"  ERROR: YAML parse error in {path.name}: {exc}", file=sys.stderr)
        return None
    except OSError as exc:
        print(f"  ERROR: Cannot read {path.name}: {exc}", file=sys.stderr)
        return None


def _dump_yaml(data: dict, path: Path) -> bool:
    """Write YAML to file, returning False on write error."""
    try:
        with path.open("w", encoding="utf-8") as fh:
            yaml.dump(
                data,
                fh,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
        return True
    except OSError as exc:
        print(f"  ERROR: Cannot write {path.name}: {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def _validate_techniques(techniques: list) -> bool:
    """Return True if all technique IDs match T####[.###] format."""
    return all(_TECHNIQUE_PATTERN.match(t) for t in techniques)


# ---------------------------------------------------------------------------
# Main tagging loop
# ---------------------------------------------------------------------------

def tag_s3_rules() -> None:
    """Iterate over all S3 metadata YAML files and apply MITRE tags."""
    yaml_files = sorted(S3_METADATA_DIR.glob("*.yaml"))
    if not yaml_files:
        print(f"No YAML files found in {S3_METADATA_DIR}", file=sys.stderr)
        sys.exit(1)

    tagged = 0
    skipped = 0
    errors = 0

    for path in yaml_files:
        data = _load_yaml(path)
        if data is None:
            errors += 1
            continue

        # Skip files that already have mitre_techniques
        if data.get("mitre_techniques"):
            skipped += 1
            continue

        rule_id: str = data.get("rule_id", path.stem)
        title: str = data.get("title", "")

        technique = select_technique(rule_id, title)

        # Validate before writing
        if not _validate_techniques(technique["mitre_techniques"]):
            print(
                f"  ERROR: Invalid technique format for {rule_id}: "
                f"{technique['mitre_techniques']}",
                file=sys.stderr,
            )
            errors += 1
            continue

        # Apply MITRE fields (append at end of document, preserving all existing keys)
        data["mitre_techniques"] = technique["mitre_techniques"]
        data["mitre_tactics"] = technique["mitre_tactics"]
        data["threat_tags"] = technique["threat_tags"]
        data["threat_category"] = technique["threat_category"]

        if not _dump_yaml(data, path):
            errors += 1
            continue

        tagged += 1

    print(f"Tagged: {tagged}, Skipped (already tagged): {skipped}, Errors: {errors}")


if __name__ == "__main__":
    tag_s3_rules()
