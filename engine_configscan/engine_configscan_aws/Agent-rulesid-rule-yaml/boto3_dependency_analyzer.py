"""
Boto3 Dependency Analyzer for ALL AWS Services

Analyzes boto3 service models to identify:
- Independent operations (no required params) → Root discoveries
- Dependent operations (has required params) → for_each discoveries
- Parameter dependencies and chains

Usage:
    # Analyze single service
    python boto3_dependency_analyzer.py apigateway
    
    # Analyze all services
    python boto3_dependency_analyzer.py --all
    
    # Export to JSON
    python boto3_dependency_analyzer.py --all --export dependencies.json
"""

import boto3
import json
import sys
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict


def get_all_aws_services() -> List[str]:
    """
    Get list of all available AWS services in boto3.
    
    Returns:
        List of service names
    """
    session = boto3.Session()
    return session.get_available_services()


def analyze_service_operations(service_name: str) -> Dict[str, Any]:
    """
    Analyze all operations for a service.
    
    Args:
        service_name: AWS service name (e.g., 'apigateway', 'acm')
    
    Returns:
        Dict with independent and dependent operations, including output fields
    """
    try:
        client = boto3.client(service_name, region_name='us-east-1')
        service_model = client._service_model
        
        independent_ops = []
        dependent_ops = []
        
        for op_name in service_model.operation_names:
            op_model = service_model.operation_model(op_name)
            
            # INPUT PARAMETERS
            required_params = []
            optional_params = []
            
            if op_model.input_shape:
                required_params = list(op_model.input_shape.required_members)
                all_params = list(op_model.input_shape.members.keys())
                optional_params = [p for p in all_params if p not in required_params]
            
            # OUTPUT FIELDS (NEW!)
            output_fields = []
            output_structure = None
            item_fields = []  # NEW: Fields within list items
            
            if op_model.output_shape:
                output_fields = list(op_model.output_shape.members.keys())
                
                # Try to identify the main list/collection field
                for field in output_fields:
                    field_shape = op_model.output_shape.members[field]
                    
                    # Check if it's a list
                    if field_shape.type_name == 'list':
                        # Common list field patterns (or just take first list)
                        if (any(keyword in field.lower() for keyword in ['list', 'items', 'resources', 'summary', 'analyzers', 'buckets', 'keys', 'apis', 'functions']) 
                            or not output_structure):  # Take first list if no pattern match
                            output_structure = field
                            
                            # Extract fields from list items
                            if field_shape.member.type_name == 'structure':
                                item_fields = list(field_shape.member.members.keys())
                            
                            # If we found a pattern match, break; otherwise continue looking
                            if any(keyword in field.lower() for keyword in ['list', 'items', 'resources', 'summary']):
                                break
                
                # If no list found, check for structure fields
                if not output_structure and output_fields:
                    for field in output_fields:
                        field_shape = op_model.output_shape.members[field]
                        if field_shape.type_name == 'structure':
                            output_structure = field
                            # Get structure fields
                            item_fields = list(field_shape.members.keys())
                            break
                    
                    # Last resort: use first field
                    if not output_structure:
                        output_structure = output_fields[0]
            
            # Convert PascalCase to snake_case for Python/YAML
            python_method = _to_snake_case(op_name)
            
            op_info = {
                'operation': op_name,  # Boto3 PascalCase name
                'python_method': python_method,  # Python snake_case name
                'yaml_action': python_method,  # YAML action name (same as Python)
                'required_params': required_params,
                'optional_params': optional_params[:5],  # Limit for brevity
                'total_optional': len(optional_params),
                'output_fields': output_fields,  # All top-level output fields
                'main_output_field': output_structure,  # Primary list/collection
                'item_fields': item_fields  # Fields within list items or structure
            }
            
            if len(required_params) == 0:
                independent_ops.append(op_info)
            else:
                dependent_ops.append(op_info)
        
        return {
            'service': service_name,
            'total_operations': len(service_model.operation_names),
            'independent': independent_ops,
            'dependent': dependent_ops,
            'independent_count': len(independent_ops),
            'dependent_count': len(dependent_ops)
        }
        
    except Exception as e:
        return {
            'service': service_name,
            'error': str(e),
            'total_operations': 0,
            'independent': [],
            'dependent': [],
            'independent_count': 0,
            'dependent_count': 0
        }


def find_potential_dependency_sources(service_name: str, operation_name: str, required_param: str) -> List[str]:
    """
    Find which operations could provide a required parameter.
    
    Args:
        service_name: AWS service
        operation_name: The dependent operation
        required_param: The parameter name to find sources for
    
    Returns:
        List of potential source operations
    """
    # Extract resource type from parameter name
    # Common patterns: restApiId, CertificateArn, analyzerArn, bucketName
    
    potential_sources = []
    
    # Pattern matching
    if required_param.endswith('Id'):
        resource = required_param[:-2]  # Remove 'Id'
        potential_sources.extend([
            f"Get{resource}s",
            f"List{resource}s",
            f"Get{resource}",
        ])
    
    elif required_param.endswith('Arn'):
        resource = required_param[:-3]  # Remove 'Arn'
        potential_sources.extend([
            f"List{resource}s",
            f"Get{resource}s",
            f"Describe{resource}",
        ])
    
    elif required_param.endswith('Name'):
        resource = required_param[:-4]  # Remove 'Name'
        potential_sources.extend([
            f"List{resource}s",
            f"Get{resource}s",
        ])
    
    # Add common list/get patterns
    potential_sources.extend([
        'GetRestApis',
        'ListApis',
        'GetApis',
    ])
    
    # Filter to only existing operations
    try:
        client = boto3.client(service_name, region_name='us-east-1')
        service_model = client._service_model
        existing = [op for op in potential_sources if op in service_model.operation_names]
        return existing
    except:
        return []


def build_dependency_map(service_analysis: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Build a dependency map showing which operations depend on which.
    
    Returns:
        Dict mapping operation_name -> list of potential source operations
    """
    service_name = service_analysis['service']
    dependency_map = {}
    
    for op_info in service_analysis['dependent']:
        op_name = op_info['operation']
        required_params = op_info['required_params']
        
        sources = []
        for param in required_params:
            param_sources = find_potential_dependency_sources(service_name, op_name, param)
            sources.extend(param_sources)
        
        if sources:
            dependency_map[op_name] = {
                'requires': required_params,
                'potential_sources': list(set(sources))
            }
    
    return dependency_map


def suggest_yaml_discovery_order(service_analysis: Dict[str, Any]) -> str:
    """
    Suggest YAML discovery structure with correct ordering.
    
    Returns:
        YAML structure suggestion as string
    """
    service = service_analysis['service']
    
    yaml_parts = []
    yaml_parts.append(f"# Suggested YAML discovery for {service}")
    yaml_parts.append(f"# Based on boto3 dependency analysis")
    yaml_parts.append(f"")
    yaml_parts.append(f"version: '1.0'")
    yaml_parts.append(f"provider: aws")
    yaml_parts.append(f"service: {service}")
    yaml_parts.append(f"")
    yaml_parts.append(f"discovery:")
    yaml_parts.append(f"")
    
    # Add independent operations first
    yaml_parts.append(f"# INDEPENDENT Operations (call these first - no dependencies)")
    for op_info in service_analysis['independent'][:5]:  # Limit to first 5
        op_name = op_info['operation']
        snake_case = _to_snake_case(op_name)
        
        yaml_parts.append(f"- discovery_id: aws.{service}.{snake_case}")
        yaml_parts.append(f"  calls:")
        yaml_parts.append(f"  - action: {snake_case}")
        yaml_parts.append(f"    save_as: {snake_case}_response")
        yaml_parts.append(f"  # TODO: Add emit section based on response structure")
        yaml_parts.append(f"")
    
    # Add dependent operations
    yaml_parts.append(f"# DEPENDENT Operations (call these after - need for_each)")
    dep_map = build_dependency_map(service_analysis)
    
    for op_name, dep_info in list(dep_map.items())[:3]:  # Limit to first 3
        snake_case = _to_snake_case(op_name)
        required = dep_info['requires']
        sources = dep_info['potential_sources']
        
        yaml_parts.append(f"- discovery_id: aws.{service}.{snake_case}")
        if sources:
            source_op = _to_snake_case(sources[0])
            yaml_parts.append(f"  for_each: aws.{service}.{source_op}  # Get {required[0]} from here")
        yaml_parts.append(f"  calls:")
        yaml_parts.append(f"  - action: {snake_case}")
        yaml_parts.append(f"    params:")
        for param in required:
            yaml_parts.append(f"      {param}: '{{{{ item.FIELD_NAME }}}}'  # TODO: Map correct field")
        yaml_parts.append(f"    save_as: {snake_case}_response")
        yaml_parts.append(f"  # TODO: Add emit section")
        yaml_parts.append(f"")
    
    return '\n'.join(yaml_parts)


def _to_snake_case(name: str) -> str:
    """Convert PascalCase to snake_case"""
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def print_service_summary(analysis: Dict[str, Any], show_output_fields: bool = True):
    """Print human-readable summary with output fields"""
    print("=" * 80)
    print(f"SERVICE: {analysis['service']}")
    print("=" * 80)
    print(f"Total operations: {analysis['total_operations']}")
    print(f"  ✅ Independent: {analysis['independent_count']} ({analysis['independent_count']/analysis['total_operations']*100:.1f}%)")
    print(f"  ❌ Dependent: {analysis['dependent_count']} ({analysis['dependent_count']/analysis['total_operations']*100:.1f}%)")
    print()
    
    print("INDEPENDENT Operations (can call first):")
    for op in analysis['independent'][:10]:
        print(f"  - {op['operation']}() → Python: {op.get('python_method', 'N/A')}()")
        if show_output_fields and op.get('output_fields'):
            print(f"      Returns: {op.get('main_output_field', 'N/A')}")
            if op.get('item_fields'):
                print(f"      Item fields: {', '.join(op['item_fields'][:8])}")
                if len(op['item_fields']) > 8:
                    print(f"         ... and {len(op['item_fields']) - 8} more")
            else:
                print(f"      Top-level fields: {', '.join(op['output_fields'][:5])}")
    if len(analysis['independent']) > 10:
        print(f"  ... and {len(analysis['independent']) - 10} more")
    print()
    
    print("DEPENDENT Operations (need parameters):")
    for op in analysis['dependent'][:10]:
        params = ', '.join(op['required_params'])
        print(f"  - {op['operation']}({params}) → Python: {op.get('python_method', 'N/A')}()")
        if show_output_fields and op.get('output_fields'):
            print(f"      Returns: {op.get('main_output_field', 'N/A')}")
            if op.get('item_fields'):
                print(f"      Item fields: {', '.join(op['item_fields'][:8])}")
                if len(op['item_fields']) > 8:
                    print(f"         ... and {len(op['item_fields']) - 8} more")
            else:
                print(f"      Top-level fields: {', '.join(op['output_fields'][:5])}")
    if len(analysis['dependent']) > 10:
        print(f"  ... and {len(analysis['dependent']) - 10} more")
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python boto3_dependency_analyzer.py <service_name>")
        print("  python boto3_dependency_analyzer.py --all")
        print("  python boto3_dependency_analyzer.py --all --export output.json")
        print()
        print("Examples:")
        print("  python boto3_dependency_analyzer.py apigateway")
        print("  python boto3_dependency_analyzer.py acm")
        print("  python boto3_dependency_analyzer.py --all --export all_services_deps.json")
        sys.exit(1)
    
    export_file = None
    if '--export' in sys.argv:
        export_idx = sys.argv.index('--export')
        if len(sys.argv) > export_idx + 1:
            export_file = sys.argv[export_idx + 1]
    
    if '--all' in sys.argv:
        # Analyze all services
        print("Analyzing ALL AWS services...")
        print("This may take a few minutes...")
        print()
        
        all_services = get_all_aws_services()
        all_analysis = {}
        
        for idx, service in enumerate(sorted(all_services), 1):
            print(f"[{idx}/{len(all_services)}] Analyzing {service}...", end='\r')
            analysis = analyze_service_operations(service)
            all_analysis[service] = analysis
        
        print()  # New line after progress
        
        # Print summary
        print("\n" + "=" * 80)
        print("SUMMARY - ALL AWS SERVICES")
        print("=" * 80)
        
        total_services = len(all_analysis)
        services_with_data = sum(1 for a in all_analysis.values() if a['total_operations'] > 0)
        total_independent = sum(a['independent_count'] for a in all_analysis.values())
        total_dependent = sum(a['dependent_count'] for a in all_analysis.values())
        
        print(f"\nAnalyzed: {total_services} services")
        print(f"Services with operations: {services_with_data}")
        print(f"Total operations across all services: {total_independent + total_dependent}")
        print(f"  ✅ Independent: {total_independent}")
        print(f"  ❌ Dependent: {total_dependent}")
        
        # Show top services by operation count
        print("\nTop 10 services by operation count:")
        sorted_services = sorted(
            all_analysis.items(),
            key=lambda x: x[1]['total_operations'],
            reverse=True
        )
        for service, analysis in sorted_services[:10]:
            print(f"  {service}: {analysis['total_operations']} ops ({analysis['independent_count']} independent)")
        
        # Export if requested
        if export_file:
            with open(export_file, 'w') as f:
                json.dump(all_analysis, f, indent=2)
            print(f"\n✅ Exported to: {export_file}")
    
    else:
        # Analyze single service
        service_name = sys.argv[1]
        
        print(f"Analyzing {service_name}...")
        analysis = analyze_service_operations(service_name)
        
        if 'error' in analysis:
            print(f"❌ Error: {analysis['error']}")
            sys.exit(1)
        
        # Print summary
        print_service_summary(analysis)
        
        # Print dependency map
        dep_map = build_dependency_map(analysis)
        if dep_map:
            print("=" * 80)
            print("DEPENDENCY MAP")
            print("=" * 80)
            for op, info in list(dep_map.items())[:10]:
                print(f"\n{op}:")
                print(f"  Requires: {info['requires']}")
                print(f"  Can get from: {info['potential_sources']}")
        
        # Suggest YAML
        print("\n" + "=" * 80)
        print("SUGGESTED YAML DISCOVERY STRUCTURE")
        print("=" * 80)
        yaml_suggestion = suggest_yaml_discovery_order(analysis)
        print(yaml_suggestion)


if __name__ == '__main__':
    main()
