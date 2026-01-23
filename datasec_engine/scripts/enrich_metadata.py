#!/usr/bin/env python3
"""
Script to identify data-security-relevant rules and add data_security sections
to metadata files in the rule database.

Usage:
    python enrich_metadata.py --service s3 --dry-run
    python enrich_metadata.py --service s3 --enrich
    python enrich_metadata.py --all-services --dry-run
"""

import os
import sys
import yaml
import json
import argparse
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Rule patterns that map to data security modules
DATA_SECURITY_PATTERNS = {
    "data_protection_encryption": [
        "encryption",
        "encrypted",
        "kms",
        "cmk",
        "cmek",
        "sse",
        "tls",
        "ssl",
    ],
    "data_access_governance": [
        "public_access",
        "rbac",
        "least_privilege",
        "no_public",
        "block_public",
        "policy",
        "iam",
    ],
    "data_activity_monitoring": [
        "logging",
        "audit",
        "access_log",
        "server_log",
        "cloudtrail",
        "monitoring",
    ],
    "data_residency": [
        "replication",
        "region",
        "cross_region",
        "geographic",
    ],
    "data_compliance": [
        "retention",
        "lifecycle",
        "immutable",
        "worm",
        "lock",
        "backup",
    ],
}

# Compliance mappings for common rules
COMPLIANCE_MAPPINGS = {
    "encryption": {
        "gdpr": "Article 32 - Encryption requirement for personal data",
        "pci": "Requirement 3.4 - Render PAN unreadable via encryption",
        "hipaa": "§164.312(a)(2)(iv) - Encryption of ePHI at rest",
    },
    "public_access": {
        "gdpr": "Article 25 - Data protection by design and by default",
        "pci": "Requirement 7 - Restrict access to cardholder data",
        "hipaa": "§164.312(a)(1) - Access control",
    },
    "logging": {
        "gdpr": "Article 30 - Records of processing activities",
        "pci": "Requirement 10 - Track and monitor all access",
        "hipaa": "§164.312(b) - Audit controls",
    },
}


def identify_data_security_modules(rule_id: str, metadata: Dict) -> List[str]:
    """Identify which data security modules a rule belongs to based on rule_id and metadata."""
    modules = set()
    rule_lower = rule_id.lower()
    description = (metadata.get("description", "") or "").lower()
    requirement = (metadata.get("requirement", "") or "").lower()
    combined_text = f"{rule_lower} {description} {requirement}"
    
    for module, patterns in DATA_SECURITY_PATTERNS.items():
        for pattern in patterns:
            if pattern in combined_text:
                modules.add(module)
                break
    
    return sorted(list(modules))


def get_compliance_impact(rule_id: str, modules: List[str]) -> Dict[str, str]:
    """Get compliance impact statements based on rule modules."""
    impact = {}
    
    # Map modules to compliance keywords
    if "data_protection_encryption" in modules:
        impact.update(COMPLIANCE_MAPPINGS.get("encryption", {}))
    if "data_access_governance" in modules:
        impact.update(COMPLIANCE_MAPPINGS.get("public_access", {}))
    if "data_activity_monitoring" in modules:
        impact.update(COMPLIANCE_MAPPINGS.get("logging", {}))
    
    return impact


def generate_data_security_section(rule_id: str, metadata: Dict, modules: List[str]) -> Dict:
    """Generate data_security section for a metadata file."""
    if not modules:
        return None
    
    # Determine priority based on severity
    severity = metadata.get("severity", "medium").lower()
    priority_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    priority = priority_map.get(severity, "medium")
    
    # Get compliance impact
    impact = get_compliance_impact(rule_id, modules)
    
    # Generate categories based on modules
    categories = []
    if "data_protection_encryption" in modules:
        if "encryption" in rule_id.lower() or "encrypted" in rule_id.lower():
            categories.append("encryption_at_rest" if "rest" in rule_id.lower() or "s3" in rule_id.lower() else "encryption")
        categories.append("sensitive_data_protection")
    if "data_access_governance" in modules:
        categories.append("access_control")
        if "public" in rule_id.lower():
            categories.append("public_access_prevention")
    if "data_activity_monitoring" in modules:
        categories.append("audit_logging")
    
    # Generate sensitive data context
    sensitive_data_context = ""
    if "encryption" in rule_id.lower() or "data_protection_encryption" in modules:
        sensitive_data_context = """Encryption is mandatory for all resources containing:
    - PII (personally identifiable information)
    - PCI data (credit card information)
    - PHI (protected health information)
    - Financial records"""
    elif "public_access" in rule_id.lower() or "data_access_governance" in modules:
        sensitive_data_context = """Public access to data storage resources must be restricted to prevent:
    - Unauthorized data access
    - Data breaches
    - Compliance violations (GDPR, PCI, HIPAA)"""
    
    return {
        "applicable": True,
        "modules": modules,
        "categories": categories,
        "priority": priority,
        "impact": impact if impact else None,
        "sensitive_data_context": sensitive_data_context if sensitive_data_context else None,
    }


def find_metadata_files(rule_db_path: Path, service: Optional[str] = None) -> List[Path]:
    """Find all metadata files for a service or all services."""
    metadata_files = []
    
    if service:
        service_dir = rule_db_path / "default" / "services" / service
        if service_dir.exists():
            metadata_dir = service_dir / "metadata"
            if metadata_dir.exists():
                metadata_files.extend(metadata_dir.glob("*.yaml"))
    else:
        services_dir = rule_db_path / "default" / "services"
        if services_dir.exists():
            for service_dir in services_dir.iterdir():
                if service_dir.is_dir():
                    metadata_dir = service_dir / "metadata"
                    if metadata_dir.exists():
                        metadata_files.extend(metadata_dir.glob("*.yaml"))
    
    return sorted(metadata_files)


def enrich_metadata_file(metadata_path: Path, dry_run: bool = True) -> Dict:
    """Enrich a single metadata file with data_security section."""
    try:
        with open(metadata_path, 'r') as f:
            metadata = yaml.safe_load(f) or {}
        
        rule_id = metadata.get("rule_id", "")
        if not rule_id:
            return {"status": "skipped", "reason": "No rule_id found"}
        
        # Identify modules
        modules = identify_data_security_modules(rule_id, metadata)
        if not modules:
            return {"status": "skipped", "reason": "Not applicable to data security modules"}
        
        # Generate data_security section
        data_security = generate_data_security_section(rule_id, metadata, modules)
        
        if not dry_run and data_security:
            # Add data_security section to metadata (before description field)
            if "data_security" not in metadata:
                # Insert before description to maintain structure
                new_metadata = {}
                for key, value in metadata.items():
                    if key == "compliance" and data_security:
                        new_metadata[key] = value
                        new_metadata["data_security"] = data_security
                    else:
                        new_metadata[key] = value
                
                # If compliance doesn't exist, add data_security after it
                if "compliance" not in metadata:
                    # Insert after rationale or severity
                    insert_after = None
                    for key in ["rationale", "severity", "assertion_id"]:
                        if key in metadata:
                            insert_after = key
                            break
                    
                    if insert_after:
                        new_metadata = {}
                        for key, value in metadata.items():
                            new_metadata[key] = value
                            if key == insert_after:
                                new_metadata["data_security"] = data_security
                    else:
                        new_metadata["data_security"] = data_security
                
                metadata = new_metadata
                
                # Write back to file
                with open(metadata_path, 'w') as f:
                    yaml.dump(metadata, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
                
                return {
                    "status": "enriched",
                    "rule_id": rule_id,
                    "modules": modules,
                }
        
        return {
            "status": "would_enrich" if dry_run else "already_has_data_security",
            "rule_id": rule_id,
            "modules": modules,
        }
    
    except Exception as e:
        return {
            "status": "error",
            "rule_id": metadata.get("rule_id", "unknown"),
            "error": str(e),
        }


def main():
    parser = argparse.ArgumentParser(description="Enrich metadata files with data_security sections")
    parser.add_argument(
        "--rule-db-path",
        type=str,
        default="/Users/apple/Desktop/threat-engine/engines-input/aws-configScan-engine/input/rule_db",
        help="Path to rule database"
    )
    parser.add_argument(
        "--service",
        type=str,
        help="Service to process (e.g., s3, rds, dynamodb). If not specified, processes all services"
    )
    parser.add_argument(
        "--all-services",
        action="store_true",
        help="Process all services"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Dry run mode (don't modify files)"
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Actually enrich files (overrides --dry-run)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output JSON file for enrichment report"
    )
    
    args = parser.parse_args()
    
    if args.enrich:
        args.dry_run = False
    
    rule_db_path = Path(args.rule_db_path)
    if not rule_db_path.exists():
        print(f"Error: Rule database path does not exist: {rule_db_path}")
        return 1
    
    # Find metadata files
    if args.all_services or not args.service:
        metadata_files = find_metadata_files(rule_db_path)
        print(f"Found {len(metadata_files)} metadata files across all services")
    else:
        metadata_files = find_metadata_files(rule_db_path, args.service)
        print(f"Found {len(metadata_files)} metadata files for service: {args.service}")
    
    # Process files
    results = {
        "enriched": [],
        "would_enrich": [],
        "skipped": [],
        "errors": [],
        "module_counts": defaultdict(int),
    }
    
    for metadata_path in metadata_files:
        result = enrich_metadata_file(metadata_path, dry_run=args.dry_run)
        
        status = result.get("status")
        if status == "enriched":
            results["enriched"].append(result)
            for module in result.get("modules", []):
                results["module_counts"][module] += 1
        elif status == "would_enrich":
            results["would_enrich"].append(result)
            for module in result.get("modules", []):
                results["module_counts"][module] += 1
        elif status == "skipped":
            results["skipped"].append(result)
        elif status == "error":
            results["errors"].append(result)
    
    # Print summary
    print("\n" + "="*60)
    print("Enrichment Summary")
    print("="*60)
    print(f"Total files processed: {len(metadata_files)}")
    print(f"Enriched: {len(results['enriched'])}")
    print(f"Would enrich (dry-run): {len(results['would_enrich'])}")
    print(f"Skipped: {len(results['skipped'])}")
    print(f"Errors: {len(results['errors'])}")
    print("\nModule distribution:")
    for module, count in sorted(results["module_counts"].items()):
        print(f"  {module}: {count}")
    
    if args.dry_run:
        print("\nNOTE: This was a dry run. Use --enrich to actually modify files.")
    
    # Save report
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nReport saved to: {args.output}")
    
    # Print errors if any
    if results["errors"]:
        print("\nErrors encountered:")
        for error in results["errors"][:10]:  # Show first 10
            print(f"  {error.get('rule_id')}: {error.get('error')}")
    
    return 0 if not results["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())

