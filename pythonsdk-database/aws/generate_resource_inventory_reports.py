"""
Generate comprehensive resource inventory report for each service.
Shows which resources can be produced from primary vs dependent functions.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum
from datetime import datetime

class ResourceCategory(Enum):
    PRIMARY_RESOURCE = "PRIMARY_RESOURCE"
    CONFIGURATION = "CONFIGURATION"
    EPHEMERAL = "EPHEMERAL"
    SUB_RESOURCE = "SUB_RESOURCE"

def classify_resource(resource_type: str, resource_info: Dict, service: str) -> Dict:
    """Classify a resource into one of the four categories."""
    
    resource_lower = resource_type.lower()
    
    # EPHEMERAL PATTERNS
    EPHEMERAL_PATTERNS = [
        r'.*_job$', r'.*_jobs?$', r'.*_task$', r'.*_tasks?$', r'.*_workflow$',
        r'.*_preview$', r'.*_preview_.*', r'.*_finding$', r'.*_findings?$',
        r'.*_upload$', r'.*_uploads?$', r'.*_version$', r'.*_versions?$',
        r'.*_request$', r'.*_approval$', r'.*_delegation$'
    ]
    
    for pattern in EPHEMERAL_PATTERNS:
        if re.match(pattern, resource_lower):
            return {
                "category": ResourceCategory.EPHEMERAL.value,
                "should_inventory": False,
                "use_for_enrichment": False
            }
    
    # CONFIGURATION PATTERNS
    CONFIGURATION_PATTERNS = [
        r'.*_configuration$', r'.*_config$', r'.*_rule$', r'.*_rules?$',
        r'.*_setting$', r'.*_settings?$', r'.*_topic$', r'.*_queue$',
        r'.*_lifecycle$', r'.*_versioning$', r'.*_encryption$', r'.*_replication$',
        r'.*_acl$', r'.*_permission$', r'.*_permissions?$'
    ]
    
    CONFIGURATION_EXCEPTIONS = {
        "iam": {"policy", "role", "user", "group"},
        "s3": {"bucket"},
    }
    
    if service in CONFIGURATION_EXCEPTIONS:
        if resource_type not in CONFIGURATION_EXCEPTIONS[service]:
            for pattern in CONFIGURATION_PATTERNS:
                if re.match(pattern, resource_lower):
                    return {
                        "category": ResourceCategory.CONFIGURATION.value,
                        "should_inventory": False,
                        "use_for_enrichment": True
                    }
    else:
        for pattern in CONFIGURATION_PATTERNS:
            if re.match(pattern, resource_lower):
                return {
                    "category": ResourceCategory.CONFIGURATION.value,
                    "should_inventory": False,
                    "use_for_enrichment": True
                }
    
    # SUB_RESOURCE PATTERNS
    parts = resource_type.split('_')
    if len(parts) >= 3:
        if len(parts) >= 2 and parts[0] == parts[1]:
            return {
                "category": ResourceCategory.SUB_RESOURCE.value,
                "should_inventory": False,
                "use_for_enrichment": True
            }
    
    SUB_RESOURCE_PATTERNS = [
        r'.*_metadata$', r'.*_detail$', r'.*_details?$', r'.*_principal$',
        r'.*_owner$', r'.*_approver$', r'.*_requestor$'
    ]
    
    for pattern in SUB_RESOURCE_PATTERNS:
        if re.match(pattern, resource_lower):
            if resource_info.get("requires_dependent_ops") and not resource_info.get("arn_entity"):
                return {
                    "category": ResourceCategory.SUB_RESOURCE.value,
                    "should_inventory": False,
                    "use_for_enrichment": True
                }
    
    # PRIMARY RESOURCE
    SERVICE_PRIMARY_RESOURCES = {
        "accessanalyzer": {"analyzer", "resource"},
        "s3": {"bucket"},
        "ec2": {
            "instance", "volume", "snapshot", "vpc", "subnet", "security-group",
            "image", "launch-template", "network-interface", "nat-gateway"
        },
        "iam": {"user", "role", "group", "policy", "instance-profile"},
    }
    
    if service in SERVICE_PRIMARY_RESOURCES:
        if resource_type in SERVICE_PRIMARY_RESOURCES[service]:
            return {
                "category": ResourceCategory.PRIMARY_RESOURCE.value,
                "should_inventory": True,
                "use_for_enrichment": False
            }
    
    # Default: Has ARN = PRIMARY, else SUB_RESOURCE
    if resource_info.get("arn_entity"):
        return {
            "category": ResourceCategory.PRIMARY_RESOURCE.value,
            "should_inventory": True,
            "use_for_enrichment": False
        }
    else:
        return {
            "category": ResourceCategory.SUB_RESOURCE.value,
            "should_inventory": False,
            "use_for_enrichment": True
        }

def get_root_operations(resource_info: Dict, root_operations: List[str]) -> List[str]:
    """Get root operations that produce this resource."""
    all_ops = resource_info.get("arn_producing_operations", []) + resource_info.get("id_producing_operations", [])
    return [op for op in all_ops if op in root_operations]

def get_dependent_operations(resource_info: Dict, root_operations: List[str]) -> List[str]:
    """Get dependent operations that produce this resource."""
    all_ops = resource_info.get("arn_producing_operations", []) + resource_info.get("id_producing_operations", [])
    return [op for op in all_ops if op not in root_operations]

def generate_resource_report(service_name: str, mapping_file: Path) -> Optional[Dict]:
    """Generate comprehensive resource report for a service."""
    
    if not mapping_file.exists():
        return None
    
    try:
        with open(mapping_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return {"error": str(e)}
    
    analysis = data.get("analysis", {})
    resources = analysis.get("resources", {})
    root_operations = analysis.get("root_operations", [])
    
    report = {
        "service": service_name,
        "generated_at": datetime.now().isoformat(),
        "root_operations": root_operations,
        "resources": []
    }
    
    for resource_type, resource_info in sorted(resources.items()):
        classification = classify_resource(resource_type, resource_info, service_name)
        
        root_ops = get_root_operations(resource_info, root_operations)
        dependent_ops = get_dependent_operations(resource_info, root_operations)
        
        resource_report = {
            "resource_type": resource_type,
            "classification": classification["category"],
            "should_inventory": classification["should_inventory"],
            "use_for_enrichment": classification["use_for_enrichment"],
            "has_arn": resource_info.get("arn_entity") is not None,
            "arn_entity": resource_info.get("arn_entity"),
            "can_get_from_root_ops": resource_info.get("can_get_arn_from_roots", False),
            "requires_dependent_ops": resource_info.get("requires_dependent_ops", False),
            "root_operations": sorted(root_ops),
            "dependent_operations": sorted(dependent_ops),
            "all_operations": sorted(
                resource_info.get("arn_producing_operations", []) + 
                resource_info.get("id_producing_operations", [])
            )
        }
        
        report["resources"].append(resource_report)
    
    return report

def generate_markdown_report(report: Dict) -> str:
    """Generate markdown formatted report."""
    
    lines = []
    lines.append(f"# {report['service'].upper()} - Resource Inventory Report")
    lines.append("")
    lines.append(f"**Generated:** {report['generated_at']}")
    lines.append("")
    lines.append(f"**Root Operations:** {', '.join(report['root_operations'])}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Group by classification
    by_category = {}
    for resource in report["resources"]:
        category = resource["classification"]
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(resource)
    
    for category in [ResourceCategory.PRIMARY_RESOURCE.value, 
                     ResourceCategory.CONFIGURATION.value,
                     ResourceCategory.EPHEMERAL.value,
                     ResourceCategory.SUB_RESOURCE.value]:
        if category not in by_category:
            continue
        
        lines.append(f"## {category.replace('_', ' ').title()}")
        lines.append("")
        
        for resource in by_category[category]:
            lines.append(f"### {resource['resource_type']}")
            lines.append("")
            
            # Status indicators
            inventory_status = "✅ **INVENTORY**" if resource["should_inventory"] else "❌ Not in inventory"
            enrichment_status = "📊 Use for enrichment" if resource["use_for_enrichment"] else ""
            
            lines.append(f"- **Status:** {inventory_status} {enrichment_status}")
            lines.append(f"- **Classification:** {resource['classification']}")
            lines.append(f"- **Has ARN:** {'Yes' if resource['has_arn'] else 'No'}")
            if resource['arn_entity']:
                lines.append(f"- **ARN Entity:** `{resource['arn_entity']}`")
            lines.append("")
            
            # Root operations
            if resource["can_get_from_root_ops"]:
                lines.append(f"#### ✅ Can be produced from ROOT operations:")
                lines.append("")
                for op in resource["root_operations"]:
                    lines.append(f"- `{op}`")
                lines.append("")
            else:
                lines.append(f"#### ❌ Cannot be produced from root operations")
                lines.append("")
            
            # Dependent operations
            if resource["requires_dependent_ops"]:
                lines.append(f"#### ⚠️  Requires DEPENDENT operations:")
                lines.append("")
                for op in resource["dependent_operations"]:
                    lines.append(f"- `{op}`")
                lines.append("")
            
            lines.append("---")
            lines.append("")
    
    return "\n".join(lines)

def generate_csv_report(report: Dict) -> str:
    """Generate CSV formatted report."""
    
    lines = []
    # Header
    lines.append("Resource Type,Classification,Should Inventory,Use for Enrichment,Has ARN,Can Get from Root,Requires Dependent,Root Operations,Dependent Operations")
    
    for resource in report["resources"]:
        row = [
            resource["resource_type"],
            resource["classification"],
            "Yes" if resource["should_inventory"] else "No",
            "Yes" if resource["use_for_enrichment"] else "No",
            "Yes" if resource["has_arn"] else "No",
            "Yes" if resource["can_get_from_root_ops"] else "No",
            "Yes" if resource["requires_dependent_ops"] else "No",
            "; ".join(resource["root_operations"]) if resource["root_operations"] else "None",
            "; ".join(resource["dependent_operations"]) if resource["dependent_operations"] else "None"
        ]
        lines.append(",".join(f'"{str(cell)}"' for cell in row))
    
    return "\n".join(lines)

def generate_all_reports(aws_dir: str, services: List[str]):
    """Generate reports for all specified services."""
    
    aws_path = Path(aws_dir)
    all_reports = {}
    
    print("=" * 80)
    print("GENERATING RESOURCE INVENTORY REPORTS")
    print("=" * 80)
    
    for service_name in services:
        print(f"\n{'='*80}")
        print(f"Processing: {service_name.upper()}")
        print(f"{'='*80}")
        
        service_dir = aws_path / service_name
        mapping_file = service_dir / "resource_arn_mapping.json"
        
        if not mapping_file.exists():
            print(f"  ⚠️  Mapping file not found: {mapping_file}")
            continue
        
        report = generate_resource_report(service_name, mapping_file)
        
        if not report:
            print(f"  ❌ Could not generate report")
            continue
        
        if "error" in report:
            print(f"  ❌ Error: {report['error']}")
            continue
        
        # Save JSON report
        json_file = service_dir / "resource_inventory_report.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"  ✅ JSON report saved: {json_file}")
        
        # Save Markdown report
        md_content = generate_markdown_report(report)
        md_file = service_dir / "resource_inventory_report.md"
        with open(md_file, 'w') as f:
            f.write(md_content)
        print(f"  ✅ Markdown report saved: {md_file}")
        
        # Save CSV report
        csv_content = generate_csv_report(report)
        csv_file = service_dir / "resource_inventory_report.csv"
        with open(csv_file, 'w') as f:
            f.write(csv_content)
        print(f"  ✅ CSV report saved: {csv_file}")
        
        # Print summary
        primary_count = sum(1 for r in report["resources"] if r["classification"] == ResourceCategory.PRIMARY_RESOURCE.value)
        inventory_count = sum(1 for r in report["resources"] if r["should_inventory"])
        root_available = sum(1 for r in report["resources"] if r["can_get_from_root_ops"])
        
        print(f"\n  Summary:")
        print(f"    Total Resources: {len(report['resources'])}")
        print(f"    Primary Resources: {primary_count}")
        print(f"    Should Inventory: {inventory_count}")
        print(f"    Available from Root Ops: {root_available}")
        
        all_reports[service_name] = report
    
    return all_reports

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_to_report = ["accessanalyzer", "ec2", "s3", "iam"]
    
    reports = generate_all_reports(aws_dir, services_to_report)
    
    print(f"\n\n{'='*80}")
    print("REPORT GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"\nGenerated reports for {len(reports)} services:")
    for service_name in reports.keys():
        print(f"  - {service_name}")
        print(f"    - resource_inventory_report.json")
        print(f"    - resource_inventory_report.md")
        print(f"    - resource_inventory_report.csv")

