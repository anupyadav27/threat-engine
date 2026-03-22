import sys
import re
import os
import json
import yaml
from . import cloudformation_generic_rule_engine
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass

# Create a custom YAML loader for CloudFormation intrinsic functions
class CloudFormationYamlLoader(yaml.SafeLoader):
    pass

def cloudformation_constructor(loader, tag_suffix, node):
    """
    Constructor for CloudFormation intrinsic functions.
    Handles tags like !Ref, !Sub, !GetAtt, etc.
    """
    if tag_suffix == 'Ref':
        return {'Ref': loader.construct_scalar(node)}
    elif tag_suffix == 'Sub':
        if isinstance(node, yaml.ScalarNode):
            return {'Fn::Sub': loader.construct_scalar(node)}
        else:
            return {'Fn::Sub': loader.construct_sequence(node)}
    elif tag_suffix == 'GetAtt':
        if isinstance(node, yaml.ScalarNode):
            # Handle "Resource.Property" format
            value = loader.construct_scalar(node)
            parts = value.split('.', 1)
            return {'Fn::GetAtt': parts}
        else:
            return {'Fn::GetAtt': loader.construct_sequence(node)}
    elif tag_suffix == 'Join':
        return {'Fn::Join': loader.construct_sequence(node)}
    elif tag_suffix == 'Split':
        return {'Fn::Split': loader.construct_sequence(node)}
    elif tag_suffix == 'Select':
        return {'Fn::Select': loader.construct_sequence(node)}
    elif tag_suffix == 'Base64':
        return {'Fn::Base64': loader.construct_scalar(node)}
    elif tag_suffix == 'GetAZs':
        return {'Fn::GetAZs': loader.construct_scalar(node)}
    elif tag_suffix == 'ImportValue':
        return {'Fn::ImportValue': loader.construct_scalar(node)}
    elif tag_suffix == 'FindInMap':
        return {'Fn::FindInMap': loader.construct_sequence(node)}
    elif tag_suffix == 'Equals':
        return {'Fn::Equals': loader.construct_sequence(node)}
    elif tag_suffix == 'If':
        return {'Fn::If': loader.construct_sequence(node)}
    elif tag_suffix == 'Not':
        return {'Fn::Not': loader.construct_sequence(node)}
    elif tag_suffix == 'And':
        return {'Fn::And': loader.construct_sequence(node)}
    elif tag_suffix == 'Or':
        return {'Fn::Or': loader.construct_sequence(node)}
    else:
        # For unknown tags, try to preserve them
        # Handle both old and new PyYAML API
        try:
            # Try newer PyYAML API first (without 'deep' parameter)
            return {f'!{tag_suffix}': loader.construct_yaml_object(node)}
        except TypeError:
            try:
                # Fallback for older PyYAML versions that accept 'deep' parameter
                return {f'!{tag_suffix}': loader.construct_yaml_object(node, deep=True)}
            except Exception:
                # Last resort: just preserve the tag name
                return {f'!{tag_suffix}': str(node.value) if hasattr(node, 'value') else None}

# Register the constructor for all CloudFormation intrinsic function tags
CloudFormationYamlLoader.add_multi_constructor('!', cloudformation_constructor)

@dataclass
class Finding:
    """Represents a single rule violation finding."""
    rule_id: str
    message: str
    file: str
    line: Optional[int]
    severity: str
    property_path: List[str]

    def __hash__(self) -> int:
        """Enable finding deduplication based on core attributes."""
        return hash((self.rule_id, self.file, self.line, self.message))

def load_rule_metadata(folder="cloudformation_docs"):
    """Load CloudFormation rule metadata from JSON files."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Metadata folder '{folder}' not found in {script_dir}.")
    
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith("_metadata.json"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "rule_id" in data:
                        rules_meta[data["rule_id"]] = data
            except Exception as e:
                print(f"Warning: Failed to load metadata from {filename}: {e}", file=sys.stderr)
                continue
    return rules_meta

def get_all_cloudformation_files(scan_path):
    """Get all CloudFormation template files (.json, .yaml, .yml)."""
    cf_files = []
    cf_extensions = [".json", ".yaml", ".yml", ".template"]
    
    if os.path.isfile(scan_path) and any(scan_path.endswith(ext) for ext in cf_extensions):
        cf_files.append(scan_path)
    else:
        for root, _, files in os.walk(scan_path):
            for file in files:
                if any(file.endswith(ext) for ext in cf_extensions):
                    file_path = os.path.join(root, file)
                    # Check if it's actually a CloudFormation template
                    if is_cloudformation_file(file_path):
                        cf_files.append(file_path)
    return cf_files

def is_cloudformation_file(file_path):
    """Check if a file is a CloudFormation template."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try parsing as YAML first
        try:
            data = yaml.load(content, Loader=CloudFormationYamlLoader)
        except yaml.YAMLError:
            # Try parsing as JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return False
        
        if not isinstance(data, dict):
            return False
        
        # Check for CloudFormation indicators
        cf_indicators = [
            "AWSTemplateFormatVersion",
            "Resources",
            "Parameters", 
            "Outputs",
            "Mappings",
            "Conditions"
        ]
        
        return any(indicator in data for indicator in cf_indicators)
    
    except Exception:
        return False

def safe_parse_cloudformation_file(cf_file):
    """
    Safely parse CloudFormation file with enhanced error handling.
    Returns (nodes, None) on success or ([], error_message) on failure.
    """
    try:
        return parse_cloudformation_file(cf_file), None
    except Exception as e:
        error_msg = str(e)
        # Provide more specific error messages for common issues
        if "construct_yaml_object" in error_msg and "deep" in error_msg:
            error_msg = "YAML parsing error - incompatible PyYAML version"
        elif "'list' object has no attribute 'get'" in error_msg:
            error_msg = "CloudFormation template uses advanced features (e.g., Fn::ForEach) that require AWS Language Extensions"
        elif "Failed to parse as YAML" in error_msg and "Failed to parse as JSON" in error_msg:
            error_msg = "File format not recognized as valid YAML or JSON"
        return [], error_msg

def parse_cloudformation_file(file_path):
    """
    Parse CloudFormation template file (JSON/YAML) to extract resources and properties.
    Returns a structured AST-like representation for rule processing.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.splitlines()
    
    try:
        # Try parsing as YAML first (more common for CloudFormation)
        yaml_error = None
        json_error = None
        
        try:
            template = yaml.load(content, Loader=CloudFormationYamlLoader)
            file_format = "yaml"
        except yaml.YAMLError as ye:
            yaml_error = ye
            # Fall back to JSON
            try:
                template = json.loads(content)
                file_format = "json"
            except json.JSONDecodeError as je:
                json_error = je
                # Both parsers failed
                raise ValueError(f"Failed to parse as YAML: {yaml_error}. Failed to parse as JSON: {json_error}")
        
        if not isinstance(template, dict):
            raise ValueError("CloudFormation template must be a dictionary/object")
        
        nodes = []
        
        # Extract template-level information
        template_version = template.get("AWSTemplateFormatVersion")
        if template_version:
            nodes.append({
                'node_type': 'TemplateVersion',
                'type': 'AWSTemplateFormatVersion',
                'value': template_version,
                'lineno': find_line_number(content, "AWSTemplateFormatVersion"),
                'source': content,
                'parent_source': content
            })
        
        # Extract Parameters
        parameters = template.get("Parameters", {})
        if not isinstance(parameters, dict):
            print(f"Warning: Parameters section is not a dict. Skipping parameter analysis for {cf_file}", file=sys.stderr)
            parameters = {}
            
        for param_name, param_config in parameters.items():
            if not isinstance(param_config, dict):
                print(f"Warning: Parameter '{param_name}' has non-standard structure. Skipping.", file=sys.stderr)
                continue
            nodes.append({
                'node_type': 'Parameter',
                'type': 'Parameter',
                'name': param_name,
                'properties': param_config,
                'lineno': find_line_number(content, param_name),
                'source': json.dumps({param_name: param_config}, indent=2),
                'parent_source': content
            })
        
        # Extract Resources (main focus for security rules)
        resources = template.get("Resources", {})
        
        # Handle CloudFormation Language Extensions (Fn::ForEach)
        if not isinstance(resources, dict):
            # If Resources is not a dict, it might be using Fn::ForEach or other language extensions
            print(f"Warning: Resources section uses CloudFormation Language Extensions (not a dict). Skipping resource analysis for {cf_file}", file=sys.stderr)
            resources = {}
        
        for resource_name, resource_config in resources.items():
            # Handle cases where resource_config might not be a dict
            if not isinstance(resource_config, dict):
                print(f"Warning: Resource '{resource_name}' has non-standard structure. Skipping.", file=sys.stderr)
                continue
            
            resource_type = resource_config.get("Type", "")
            resource_properties = resource_config.get("Properties", {})
            
            # Create main resource node
            resource_node = {
                'node_type': 'Resource',
                'type': 'Resource',
                'name': resource_name,
                'resource_type': resource_type,
                'properties': resource_properties,
                'lineno': find_line_number(content, resource_name),
                'source': json.dumps({resource_name: resource_config}, indent=2),
                'parent_source': content,
                'full_config': resource_config
            }
            nodes.append(resource_node)
            
            # Extract individual properties as separate nodes for granular analysis
            for prop_name, prop_value in resource_properties.items():
                prop_node = {
                    'node_type': 'Property',
                    'type': 'Property',
                    'name': prop_name,
                    'value': prop_value,
                    'parent_resource': resource_name,
                    'parent_resource_type': resource_type,
                    'lineno': find_line_number(content, prop_name),
                    'source': json.dumps({prop_name: prop_value}, indent=2),
                    'parent_source': content,
                    'property_path': [resource_name, "Properties", prop_name]
                }
                nodes.append(prop_node)
                
                # For complex properties (objects/arrays), create nested nodes
                if isinstance(prop_value, dict):
                    extract_nested_properties(prop_value, nodes, content, 
                                            [resource_name, "Properties", prop_name], 
                                            resource_name, resource_type)
                elif isinstance(prop_value, list):
                    for i, item in enumerate(prop_value):
                        if isinstance(item, dict):
                            extract_nested_properties(item, nodes, content,
                                                    [resource_name, "Properties", prop_name, str(i)],
                                                    resource_name, resource_type)
        
        # Extract Outputs
        outputs = template.get("Outputs", {})
        for output_name, output_config in outputs.items():
            nodes.append({
                'node_type': 'Output',
                'type': 'Output',
                'name': output_name,
                'properties': output_config,
                'lineno': find_line_number(content, output_name),
                'source': json.dumps({output_name: output_config}, indent=2),
                'parent_source': content
            })
        
        # Extract Conditions
        conditions = template.get("Conditions", {})
        for condition_name, condition_logic in conditions.items():
            nodes.append({
                'node_type': 'Condition',
                'type': 'Condition',
                'name': condition_name,
                'logic': condition_logic,
                'lineno': find_line_number(content, condition_name),
                'source': json.dumps({condition_name: condition_logic}, indent=2),
                'parent_source': content
            })
        
        return {
            'node_type': 'CloudFormationTemplate',
            'filename': file_path,
            'source': content,
            'template': template,
            'format': file_format,
            'children': nodes
        }
    
    except (yaml.YAMLError, json.JSONDecodeError, ValueError) as e:
        print(f"Warning: Failed to parse CloudFormation template {file_path}: {str(e)}", file=sys.stderr)
        
        # Create a parsing failure AST with error information
        error_type = "unknown"
        error_message = str(e)
        
        # Determine error type more accurately
        if "Failed to parse as YAML" in error_message and "Failed to parse as JSON" in error_message:
            error_type = "both_formats"
        elif isinstance(e, yaml.YAMLError):
            error_type = "yaml"
        elif isinstance(e, json.JSONDecodeError):
            error_type = "json"
        elif isinstance(e, ValueError):
            if "YAML" in error_message:
                error_type = "yaml"
            elif "JSON" in error_message:
                error_type = "json"
            else:
                error_type = "structure"
        
        return {
            'node_type': 'CloudFormationTemplate',
            'filename': file_path,
            'source': content,
            'template': {},
            'format': 'unknown',
            'children': [],
            'parsing_error': {
                'type': error_type,
                'message': error_message,
                'exception': type(e).__name__
            }
        }

def extract_nested_properties(obj, nodes, content, property_path, parent_resource, parent_resource_type):
    """Recursively extract nested properties from CloudFormation resources."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            nested_path = property_path + [key]
            
            node = {
                'node_type': 'NestedProperty',
                'type': 'NestedProperty',
                'name': key,
                'value': value,
                'parent_resource': parent_resource,
                'parent_resource_type': parent_resource_type,
                'lineno': find_line_number(content, key),
                'source': json.dumps({key: value}, indent=2),
                'parent_source': content,
                'property_path': nested_path
            }
            nodes.append(node)
            
            # Continue recursion for nested objects/arrays
            if isinstance(value, (dict, list)):
                extract_nested_properties(value, nodes, content, nested_path, parent_resource, parent_resource_type)
    
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                extract_nested_properties(item, nodes, content, property_path + [str(i)], parent_resource, parent_resource_type)

def find_line_number(content, search_term):
    """Find the line number where a term appears in the content."""
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if search_term in line:
            return i
    return 1  # Default to line 1 if not found

def parse_cloudformation_file_fallback(file_path, content):
    """
    Fallback parser for when YAML/JSON parsing fails.
    Uses regex-based approach to extract basic information.
    """
    lines = content.splitlines()
    nodes = []
    
    # Try to extract resource names using regex patterns
    for idx, line in enumerate(lines, 1):
        line_strip = line.strip()
        
        # Look for resource definitions (common patterns)
        # YAML: ResourceName:
        # JSON: "ResourceName": {
        if re.match(r'^[A-Za-z][A-Za-z0-9]*:\s*$', line_strip) or \
           re.match(r'^"[A-Za-z][A-Za-z0-9]*":\s*\{', line_strip):
            resource_name = line_strip.rstrip(':').strip('"')
            nodes.append({
                'node_type': 'Resource',
                'type': 'Resource',
                'name': resource_name,
                'lineno': idx,
                'source': line_strip,
                'parent_source': content,
                'properties': {}
            })
        
        # Look for AWS resource types
        elif 'AWS::' in line_strip:
            nodes.append({
                'node_type': 'ResourceType',
                'type': 'ResourceType',
                'value': line_strip.strip(),
                'lineno': idx,
                'source': line_strip,
                'parent_source': content
            })
    
    return {
        'node_type': 'CloudFormationTemplate',
        'filename': file_path,
        'source': content,
        'template': {},
        'format': 'unknown',
        'children': nodes
    }

def run_cloudformation_scanner(scan_path):
    """
    Main scanner function for CloudFormation templates.
    """
    try:
        from database.rule_cache import rule_cache
        rules_meta = rule_cache.get_rules("cloudformation")
    except Exception:
        rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())

    # Filter out disabled rules
    rules = [rule for rule in rules if rule.get('status') != 'disabled']
    
    cf_files = get_all_cloudformation_files(scan_path)
    all_findings = []
    
    print(f"Found {len(cf_files)} CloudFormation files to scan", file=sys.stderr)
    
    for cf_file in cf_files:
        print(f"Scanning: {cf_file}", file=sys.stderr)
        ast_tree, error_msg = safe_parse_cloudformation_file(cf_file)
        
        if error_msg:
            print(f"Warning: Failed to parse {cf_file}: {error_msg}", file=sys.stderr)
            continue
        
        for rule in rules:
            try:
                findings = cloudformation_generic_rule_engine.run_rule(rule, ast_tree, cf_file)
                if findings:
                    for finding in findings:
                        finding['file'] = cf_file
                        all_findings.append(finding)
            except Exception as e:
                print(f"Warning: Rule {rule.get('rule_id', 'unknown')} failed on {cf_file}: {e}", file=sys.stderr)
                continue
    
    # Deduplicate findings
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get('rule_id'), f.get('file'), f.get('line'), f.get('message'))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    return deduped

def clean_for_json(obj, depth=0, max_depth=10):
    """Clean objects for JSON serialization."""
    if depth > max_depth:
        return f"<Max depth {max_depth} reached>"
    if isinstance(obj, dict):
        obj = {k: v for k, v in obj.items() if k != '__parent__'}
        return {key: clean_for_json(value, depth+1, max_depth) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [clean_for_json(item, depth+1, max_depth) for item in obj]
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return str(obj)
    else:
        return obj

def load_rules(language: str) -> Dict[str, Dict]:
    """Load all rule JSON files for CloudFormation."""
    rules_path = os.path.join("rules", language)
    rules = {}
    
    if not os.path.exists(rules_path):
        return rules
        
    for filename in os.listdir(rules_path):
        if filename.endswith('.json'):
            rule_id = filename.replace('.json', '')
            with open(os.path.join(rules_path, filename), 'r') as f:
                rules[rule_id] = json.load(f)
                
    return rules

def load_metadata(language: str) -> Dict[str, Dict]:
    """Load all metadata JSON files for CloudFormation."""
    metadata_path = os.path.join("metadata", language)
    metadata = {}
    
    if not os.path.exists(metadata_path):
        return metadata
        
    for filename in os.listdir(metadata_path):
        if filename.endswith('_metadata.json'):
            rule_id = filename.replace('_metadata.json', '')
            with open(os.path.join(metadata_path, filename), 'r') as f:
                metadata[rule_id] = json.load(f)
                
    return metadata

def merge_rule_and_metadata(rule_json: Dict, metadata_json: Dict) -> Dict:
    """Combine rule and metadata into a unified rule object."""
    merged = {
        "rule_id": rule_json.get("rule_id", ""),
        "title": rule_json.get("title", ""),
        "description": rule_json.get("description", ""),
        "node_types": rule_json.get("node_types", []),
        "logic": metadata_json.get("logic", {}),
        "severity": rule_json.get("severity", "INFO"),
        "examples": metadata_json.get("examples", []),
        "recommendation": metadata_json.get("recommendation", ""),
        "impact": metadata_json.get("impact", "")
    }
    return merged

def get_language_extensions(language: str) -> List[str]:
    """Map CloudFormation to its file extensions."""
    extensions = {
        "cloudformation": [".json", ".yaml", ".yml", ".template"],
        "cfn": [".json", ".yaml", ".yml", ".template"],
        "cf": [".json", ".yaml", ".yml", ".template"]
    }
    return extensions.get(language, [".json", ".yaml", ".yml"])

def get_all_files(path: str, language: str) -> List[str]:
    """Recursively collect all CloudFormation template files."""
    if language.lower() in ["cloudformation", "cfn", "cf"]:
        return get_all_cloudformation_files(path)
    else:
        return []

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on core attributes."""
    return list(set(findings))

def run_scan(scan_path):
    """
    Main scanner function for CloudFormation templates.
    This function provides compatibility with the scanner plugin system.
    """
    return run_cloudformation_scanner(scan_path)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: cloudformation_scanner.py <input_path> [language]")
        print("Language should be 'cloudformation', 'cfn', or 'cf'")
        sys.exit(1)
        
    input_path = sys.argv[1]
    language = sys.argv[2].lower() if len(sys.argv) > 2 else "cloudformation"
    
    if language not in ["cloudformation", "cfn", "cf"]:
        print("Error: Language must be 'cloudformation', 'cfn', or 'cf'", file=sys.stderr)
        sys.exit(1)
    
    try:
        findings = run_cloudformation_scanner(input_path)
        
        # Count actual files scanned
        files_scanned = len(get_all_cloudformation_files(input_path))
        
        result = {
            "language": "cloudformation",
            "files_scanned": files_scanned,
            "findings": findings
        }
        
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)