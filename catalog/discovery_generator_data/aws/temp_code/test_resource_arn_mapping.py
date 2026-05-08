import json
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Optional
from datetime import datetime

def extract_resource_arn_entities(dependency_index: Dict) -> Dict[str, Dict]:
    """Extract all entities that represent ARNs and their producing operations"""
    arn_entities = {}
    entity_paths = dependency_index.get("entity_paths", {})
    
    for entity_name, paths in entity_paths.items():
        # Check if entity represents an ARN
        if "_arn" in entity_name.lower() or entity_name.lower().endswith("arn"):
            operations = set()
            
            for path_data in paths:
                ops = path_data.get("operations", [])
                operations.update(ops)
            
            if operations:
                # Extract resource type from entity name
                parts = entity_name.split(".")
                if len(parts) >= 2:
                    entity_part = parts[-1]  # e.g., "analyzer_arn", "resource_resource_arn"
                    # Remove _arn suffix and clean up
                    resource_type = entity_part.replace("_arn", "").replace("resource_", "")
                    if resource_type:
                        arn_entities[entity_name] = {
                            "operations": sorted(operations),
                            "resource_type": resource_type,
                            "entity_name": entity_name
                        }
    
    return arn_entities

def extract_resource_ids(dependency_index: Dict) -> Dict[str, Dict]:
    """Extract entities that represent resource IDs/names"""
    id_entities = {}
    entity_paths = dependency_index.get("entity_paths", {})
    
    for entity_name, paths in entity_paths.items():
        # Skip ARNs (already handled)
        if "_arn" in entity_name.lower():
            continue
            
        # Check if entity represents an ID/identifier
        if (entity_name.lower().endswith("_id") or 
            entity_name.lower().endswith("_name") or
            "identifier" in entity_name.lower()):
            
            operations = set()
            for path_data in paths:
                ops = path_data.get("operations", [])
                operations.update(ops)
            
            if operations:
                parts = entity_name.split(".")
                if len(parts) >= 2:
                    entity_part = parts[-1]
                    resource_type = entity_part.replace("_id", "").replace("_name", "").replace("_identifier", "")
                    if resource_type:
                        id_entities[entity_name] = {
                            "operations": sorted(operations),
                            "resource_type": resource_type,
                            "entity_name": entity_name,
                            "id_type": "id" if "_id" in entity_part else "name" if "_name" in entity_part else "identifier"
                        }
    
    return id_entities

def analyze_service(service_dir: Path) -> Optional[Dict]:
    """Analyze a single service to extract resource ARN mappings"""
    di_path = service_dir / "dependency_index.json"
    
    if not di_path.exists():
        return None
    
    try:
        with open(di_path, 'r') as f:
            dependency_index = json.load(f)
    except Exception as e:
        return {"error": str(e)}
    
    service_name = dependency_index.get("service", service_dir.name)
    
    # Extract ARN entities
    arn_entities = extract_resource_arn_entities(dependency_index)
    
    # Extract ID entities
    id_entities = extract_resource_ids(dependency_index)
    
    # Get root operations
    roots = dependency_index.get("roots", [])
    root_ops = [r.get("op") for r in roots]
    
    # Build resource mapping
    resources = {}
    
    # Process ARN entities
    for entity_name, data in arn_entities.items():
        resource_type = data["resource_type"]
        if resource_type not in resources:
            resources[resource_type] = {
                "resource_type": resource_type,
                "arn_entity": entity_name,
                "arn_producing_operations": [],
                "id_entities": [],
                "id_producing_operations": [],
                "can_get_arn_from_roots": False,
                "requires_dependent_ops": False
            }
        
        resources[resource_type]["arn_producing_operations"] = data["operations"]
        
        # Check if any operation is a root
        if any(op in root_ops for op in data["operations"]):
            resources[resource_type]["can_get_arn_from_roots"] = True
        else:
            resources[resource_type]["requires_dependent_ops"] = True
    
    # Process ID entities and link to resources
    for entity_name, data in id_entities.items():
        resource_type = data["resource_type"]
        
        # Try to match with existing resource
        if resource_type in resources:
            if entity_name not in resources[resource_type]["id_entities"]:
                resources[resource_type]["id_entities"].append(entity_name)
            resources[resource_type]["id_producing_operations"].extend(data["operations"])
            # Remove duplicates
            resources[resource_type]["id_producing_operations"] = list(set(resources[resource_type]["id_producing_operations"]))
        else:
            # Create new resource entry for ID-only resources
            resources[resource_type] = {
                "resource_type": resource_type,
                "arn_entity": None,
                "arn_producing_operations": [],
                "id_entities": [entity_name],
                "id_producing_operations": data["operations"],
                "can_get_arn_from_roots": any(op in root_ops for op in data["operations"]),
                "requires_dependent_ops": not any(op in root_ops for op in data["operations"])
            }
    
    # Build dependency chain analysis
    dependency_chains = {}
    for resource_type, resource_info in resources.items():
        if resource_info["requires_dependent_ops"]:
            # Find what inputs are needed
            required_inputs = set()
            for op in resource_info["arn_producing_operations"] + resource_info["id_producing_operations"]:
                # Find what this op consumes
                entity_paths = dependency_index.get("entity_paths", {})
                for entity, paths in entity_paths.items():
                    for path_data in paths:
                        if op in path_data.get("operations", []):
                            consumes = path_data.get("consumes", {})
                            if op in consumes:
                                required_inputs.update(consumes[op])
            
            dependency_chains[resource_type] = {
                "required_inputs": sorted(required_inputs),
                "operations": resource_info["arn_producing_operations"] + resource_info["id_producing_operations"]
            }
    
    return {
        "service": service_name,
        "resources": resources,
        "root_operations": root_ops,
        "dependency_chains": dependency_chains,
        "summary": {
            "total_resources": len(resources),
            "resources_with_arn_from_roots": sum(1 for r in resources.values() if r["can_get_arn_from_roots"]),
            "resources_requiring_dependent_ops": sum(1 for r in resources.values() if r["requires_dependent_ops"]),
            "total_arn_entities": len(arn_entities),
            "total_id_entities": len(id_entities)
        }
    }

def expert_analysis(analysis_result: Dict) -> Dict:
    """AWS Expert analysis of the resource mapping"""
    service = analysis_result["service"]
    resources = analysis_result["resources"]
    root_ops = analysis_result["root_operations"]
    
    analysis = {
        "service": service,
        "expert_assessment": {
            "coverage": "good" if analysis_result["summary"]["total_resources"] > 0 else "poor",
            "root_coverage": "good" if analysis_result["summary"]["resources_with_arn_from_roots"] > 0 else "needs_improvement",
            "issues": [],
            "recommendations": []
        },
        "resource_analysis": {}
    }
    
    # Analyze each resource
    for resource_type, resource_info in resources.items():
        resource_analysis = {
            "has_arn": resource_info["arn_entity"] is not None,
            "has_id": len(resource_info["id_entities"]) > 0,
            "arn_from_roots": resource_info["can_get_arn_from_roots"],
            "requires_dependent_ops": resource_info["requires_dependent_ops"],
            "assessment": "complete" if resource_info["arn_entity"] else "incomplete"
        }
        
        # Service-specific validations
        if service == "accessanalyzer":
            if resource_type == "analyzer" and not resource_info["can_get_arn_from_roots"]:
                analysis["expert_assessment"]["issues"].append(
                    f"analyzer ARN should be available from root operations"
                )
        
        elif service == "ec2":
            # EC2 typically has instances, volumes, snapshots, etc.
            if resource_type in ["instance", "volume", "snapshot"] and not resource_info["arn_entity"]:
                analysis["expert_assessment"]["issues"].append(
                    f"{resource_type} should have ARN entity"
                )
        
        elif service == "s3":
            # S3 buckets are key resources
            if resource_type == "bucket" and not resource_info["arn_entity"]:
                analysis["expert_assessment"]["issues"].append(
                    "S3 bucket should have ARN entity"
                )
        
        elif service == "iam":
            # IAM has users, roles, groups, policies
            if resource_type in ["user", "role", "group", "policy"] and not resource_info["arn_entity"]:
                analysis["expert_assessment"]["issues"].append(
                    f"IAM {resource_type} should have ARN entity"
                )
        
        analysis["resource_analysis"][resource_type] = resource_analysis
    
    # Overall recommendations
    if analysis_result["summary"]["resources_requiring_dependent_ops"] > 0:
        analysis["expert_assessment"]["recommendations"].append(
            f"{analysis_result['summary']['resources_requiring_dependent_ops']} resources require dependent operations - ensure dependency chain is complete"
        )
    
    if len(root_ops) == 0:
        analysis["expert_assessment"]["issues"].append("No root operations defined - all operations are dependent")
    
    return analysis

def test_services(aws_dir: str, services: List[str]):
    """Test specific services and save outputs"""
    aws_path = Path(aws_dir)
    results = {}
    
    print("=" * 80)
    print("RESOURCE ARN MAPPING TEST - AWS EXPERT ANALYSIS")
    print("=" * 80)
    
    for service_name in services:
        service_dir = aws_path / service_name
        print(f"\n{'='*80}")
        print(f"Testing: {service_name.upper()}")
        print(f"{'='*80}")
        
        if not service_dir.exists():
            print(f"  ❌ Service directory not found: {service_dir}")
            continue
        
        result = analyze_service(service_dir)
        
        if not result:
            print(f"  ❌ Could not analyze service")
            continue
        
        if "error" in result:
            print(f"  ❌ Error: {result['error']}")
            continue
        
        # Expert analysis
        expert = expert_analysis(result)
        
        # Print summary
        print(f"\n  Summary:")
        print(f"    Total Resources: {result['summary']['total_resources']}")
        print(f"    Resources with ARN from roots: {result['summary']['resources_with_arn_from_roots']}")
        print(f"    Resources requiring dependent ops: {result['summary']['resources_requiring_dependent_ops']}")
        print(f"    Root Operations: {len(result['root_operations'])}")
        
        print(f"\n  Resources Found:")
        for resource_type, resource_info in sorted(result["resources"].items()):
            arn_status = "✓" if resource_info["arn_entity"] else "✗"
            root_status = "✓" if resource_info["can_get_arn_from_roots"] else "✗"
            ops_count = len(resource_info['arn_producing_operations']) + len(resource_info['id_producing_operations'])
            print(f"    {arn_status} {resource_type:25s} | ARN from roots: {root_status} | Ops: {ops_count}")
            if resource_info["arn_entity"]:
                print(f"      ARN Entity: {resource_info['arn_entity']}")
                print(f"      ARN Ops: {', '.join(resource_info['arn_producing_operations'][:3])}{'...' if len(resource_info['arn_producing_operations']) > 3 else ''}")
        
        if expert["expert_assessment"]["issues"]:
            print(f"\n  ⚠️  Issues Found:")
            for issue in expert["expert_assessment"]["issues"]:
                print(f"    - {issue}")
        
        if expert["expert_assessment"]["recommendations"]:
            print(f"\n  💡 Recommendations:")
            for rec in expert["expert_assessment"]["recommendations"]:
                print(f"    - {rec}")
        
        # Save to service folder
        output_file = service_dir / "resource_arn_mapping.json"
        output_data = {
            "analysis": result,
            "expert_analysis": expert,
            "generated_at": datetime.now().isoformat()
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n  ✅ Results saved to: {output_file}")
        
        results[service_name] = {
            "analysis": result,
            "expert": expert
        }
    
    return results

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_to_test = ["accessanalyzer", "ec2", "s3", "iam"]
    
    results = test_services(aws_dir, services_to_test)
    
    print(f"\n\n{'='*80}")
    print("TEST COMPLETE")
    print(f"{'='*80}")
    print(f"\nTested {len(results)} services")
    print("Output files saved in respective service folders as: resource_arn_mapping.json")

