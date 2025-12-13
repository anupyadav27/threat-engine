"""
YAML Validator Tool - Tests YAML rules against real AWS API responses

This tool:
1. Loads YAML rule files
2. Makes actual AWS API calls
3. Validates all field paths exist in real responses
4. Tests template variable paths
5. Validates operator compatibility with data types
6. Reports all issues with suggestions

Usage:
    python validate_yaml.py services/accessanalyzer/rules/accessanalyzer.yaml
    python validate_yaml.py services/*/rules/*.yaml  # Validate all
"""

import boto3
import yaml
import json
import re
import sys
from typing import Any, Dict, List, Tuple, Optional
from pathlib import Path
from botocore.exceptions import ClientError
import argparse
from collections import defaultdict


class YAMLValidator:
    """Validates YAML rule files against real AWS API responses"""
    
    def __init__(self, region='us-east-1', verbose=False):
        self.region = region
        self.verbose = verbose
        self.session = boto3.Session()
        self.clients = {}
        self.issues = []
        self.warnings = []
        self.api_cache = {}  # Cache API responses to avoid duplicate calls
        
    def get_client(self, service_name: str):
        """Get or create boto3 client for service"""
        if service_name not in self.clients:
            try:
                self.clients[service_name] = self.session.client(
                    service_name, 
                    region_name=self.region
                )
            except Exception as e:
                self.add_issue(f"Cannot create client for '{service_name}': {e}")
                return None
        return self.clients[service_name]
    
    def add_issue(self, message: str, severity='ERROR'):
        """Add a validation issue"""
        self.issues.append({'severity': severity, 'message': message})
        if self.verbose:
            print(f"[{severity}] {message}")
    
    def add_warning(self, message: str):
        """Add a validation warning"""
        self.warnings.append(message)
        if self.verbose:
            print(f"[WARNING] {message}")
    
    def extract_value(self, obj: Any, path: str) -> Tuple[Any, bool]:
        """
        Extract value from nested object using dot notation.
        Returns: (value, success)
        """
        if obj is None:
            return None, False
        
        parts = path.split('.')
        current = obj
        
        for idx, part in enumerate(parts):
            # Handle array notation like 'analyzers[]'
            if part.endswith('[]'):
                key = part[:-2]
                if isinstance(current, dict) and key in current:
                    current = current[key]
                    if not isinstance(current, list):
                        return None, False
                    return current, True
                return None, False
            
            # Handle dict access
            if isinstance(current, dict):
                if part in current:
                    current = current[part]
                else:
                    return None, False
            elif isinstance(current, list):
                # If current is a list, we need to check items
                if part.isdigit():
                    idx_num = int(part)
                    if 0 <= idx_num < len(current):
                        current = current[idx_num]
                    else:
                        return None, False
                else:
                    # Check if any item in list has this field
                    for item in current:
                        if isinstance(item, dict) and part in item:
                            return item[part], True
                    return None, False
            else:
                return None, False
        
        return current, True
    
    def get_template_variables(self, template: str) -> List[str]:
        """Extract all variable paths from template string"""
        if not isinstance(template, str):
            return []
        
        matches = re.findall(r'\{\{\s*([^}]+)\s*\}\}', template)
        return [m.strip() for m in matches]
    
    def make_api_call(self, client, action: str, params: Dict) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Make API call and return response or error
        Returns: (response, error)
        """
        cache_key = f"{client._service_model.service_name}.{action}.{json.dumps(params, sort_keys=True)}"
        
        if cache_key in self.api_cache:
            return self.api_cache[cache_key], None
        
        try:
            method = getattr(client, action)
            response = method(**params)
            self.api_cache[cache_key] = response
            return response, None
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            
            # Some errors are expected (e.g., no resources exist)
            if error_code in ['ResourceNotFoundException', 'NoSuchEntity', 'NotFound', 'NotFoundException']:
                return None, f"No resources found ({error_code})"
            else:
                return None, f"{error_code}: {error_msg}"
        except Exception as e:
            return None, str(e)
    
    def validate_field_path(self, response: Dict, field_path: str, context: str) -> bool:
        """Validate that a field path exists in the response"""
        value, success = self.extract_value(response, field_path)
        
        if not success:
            available_fields = self.get_available_fields(response)
            self.add_issue(
                f"Field path '{field_path}' not found in {context}\n"
                f"    Available fields: {', '.join(available_fields[:15])}"
            )
            return False
        
        return True
    
    def get_available_fields(self, obj: Any, prefix: str = '', max_depth: int = 2) -> List[str]:
        """Get list of available field paths in an object"""
        if max_depth == 0:
            return []
        
        fields = []
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{prefix}.{key}" if prefix else key
                fields.append(current_path)
                
                if isinstance(value, (dict, list)) and max_depth > 1:
                    if isinstance(value, list) and value:
                        fields.append(f"{current_path}[]")
                        sub_fields = self.get_available_fields(value[0], current_path, max_depth - 1)
                        fields.extend(sub_fields)
                    elif isinstance(value, dict):
                        sub_fields = self.get_available_fields(value, current_path, max_depth - 1)
                        fields.extend(sub_fields)
        
        return fields
    
    def validate_discovery_call(self, call: Dict, discovery_id: str, client, saved_data: Dict) -> Optional[Dict]:
        """Validate a single discovery call"""
        action = call.get('action')
        params = call.get('params', {})
        save_as = call.get('save_as')
        fields = call.get('fields', [])
        on_error = call.get('on_error', 'fail')
        
        if not action:
            self.add_issue(f"Discovery '{discovery_id}': Missing 'action' field")
            return None
        
        # Validate action exists on client
        if not hasattr(client, action):
            available_methods = [m for m in dir(client) if not m.startswith('_') and callable(getattr(client, m))]
            self.add_issue(
                f"Discovery '{discovery_id}': Method '{action}' not found on client\n"
                f"    Did you mean one of: {', '.join(available_methods[:10])}"
            )
            return None
        
        # Make actual API call
        print(f"  Testing API call: {action}({params})")
        response, error = self.make_api_call(client, action, params)
        
        if error:
            if on_error == 'continue':
                self.add_warning(f"Discovery '{discovery_id}': API call {action} failed: {error} (on_error=continue)")
                return None
            else:
                self.add_issue(f"Discovery '{discovery_id}': API call {action} failed: {error}")
                return None
        
        if response is None:
            self.add_warning(f"Discovery '{discovery_id}': API call {action} returned None")
            return None
        
        # Remove ResponseMetadata
        response_copy = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
        
        print(f"    Response keys: {list(response_copy.keys())}")
        
        # Validate fields extraction
        if fields:
            for field in fields:
                if not self.validate_field_path(response_copy, field, f"call '{action}' response"):
                    # Show the actual response structure
                    if self.verbose:
                        print(f"    Response structure:\n{json.dumps(response_copy, indent=4, default=str)[:500]}")
        
        # Save to saved_data for next calls
        if save_as:
            if fields:
                # Extract only specified fields
                extracted_data = {}
                for field in fields:
                    value, success = self.extract_value(response_copy, field)
                    if success:
                        # Store with the field name as key
                        field_name = field.rstrip('[]').split('.')[-1]
                        extracted_data[field_name] = value
                saved_data[save_as] = extracted_data
            else:
                saved_data[save_as] = response_copy
        
        return response_copy
    
    def validate_emit_section(self, emit: Dict, discovery_id: str, saved_data: Dict) -> List[Dict]:
        """Validate emit section and return emitted items"""
        emitted_items = []
        
        if 'items_for' in emit:
            # items_for pattern
            items_path = emit['items_for'].replace('{{ ', '').replace(' }}', '').strip()
            as_var = emit.get('as', 'resource')
            item_template = emit.get('item', {})
            
            # Extract items from saved_data
            items, success = self.extract_value(saved_data, items_path)
            
            if not success:
                available = self.get_available_fields(saved_data)
                self.add_issue(
                    f"Discovery '{discovery_id}': Cannot extract items from path '{items_path}'\n"
                    f"    Available paths in saved_data: {', '.join(available[:15])}"
                )
                return []
            
            if not isinstance(items, list):
                self.add_issue(
                    f"Discovery '{discovery_id}': items_for path '{items_path}' does not point to a list"
                )
                return []
            
            print(f"    Emitting {len(items)} items")
            
            if items:
                # Validate templates using first item
                sample_item = items[0]
                context = {as_var: sample_item}
                context.update(saved_data)
                
                for field_name, template in item_template.items():
                    var_paths = self.get_template_variables(str(template))
                    
                    for var_path in var_paths:
                        value, success = self.extract_value(context, var_path)
                        if not success:
                            available = self.get_available_fields(context)
                            self.add_issue(
                                f"Discovery '{discovery_id}': Template variable '{var_path}' in field '{field_name}' not found\n"
                                f"    Available: {', '.join(available[:20])}"
                            )
                
                # Process all items for emission
                for item in items:
                    context = {as_var: item}
                    emitted_items.append(context)
        
        elif 'item' in emit:
            # Single item pattern
            item_template = emit['item']
            
            for field_name, template in item_template.items():
                var_paths = self.get_template_variables(str(template))
                
                for var_path in var_paths:
                    value, success = self.extract_value(saved_data, var_path)
                    if not success:
                        available = self.get_available_fields(saved_data)
                        self.add_issue(
                            f"Discovery '{discovery_id}': Template variable '{var_path}' in field '{field_name}' not found\n"
                            f"    Available: {', '.join(available[:15])}"
                        )
            
            emitted_items.append({'item': saved_data})
        
        return emitted_items
    
    def validate_condition(self, condition: Dict, context: Dict, check_id: str):
        """Validate a single condition"""
        if 'all' in condition:
            for sub_cond in condition['all']:
                self.validate_condition(sub_cond, context, check_id)
            return
        
        if 'any' in condition:
            for sub_cond in condition['any']:
                self.validate_condition(sub_cond, context, check_id)
            return
        
        var = condition.get('var')
        op = condition.get('op')
        value = condition.get('value')
        
        if not var:
            self.add_issue(f"Check '{check_id}': Condition missing 'var' field")
            return
        
        if not op:
            self.add_issue(f"Check '{check_id}': Condition missing 'op' field")
            return
        
        # Validate var path exists in context
        actual_value, success = self.extract_value(context, var)
        
        if not success:
            available = self.get_available_fields(context)
            self.add_issue(
                f"Check '{check_id}': Variable path '{var}' not found in context\n"
                f"    Available: {', '.join(available[:20])}"
            )
            return
        
        # Validate operator
        valid_operators = ['exists', 'equals', 'gt', 'gte', 'lt', 'lte', 'contains', 'not_contains', 'length_gte']
        if op not in valid_operators:
            self.add_issue(
                f"Check '{check_id}': Unknown operator '{op}'\n"
                f"    Valid operators: {', '.join(valid_operators)}"
            )
        
        # Validate operator is compatible with value type
        if op in ['gt', 'gte', 'lt', 'lte']:
            if not isinstance(actual_value, (int, float, str)):
                self.add_warning(
                    f"Check '{check_id}': Operator '{op}' used on {type(actual_value).__name__}, "
                    f"expected numeric type"
                )
        
        if op in ['contains', 'not_contains']:
            if not isinstance(actual_value, (list, str)):
                self.add_warning(
                    f"Check '{check_id}': Operator '{op}' used on {type(actual_value).__name__}, "
                    f"expected list or string"
                )
    
    def validate_yaml_file(self, yaml_path: str) -> Dict:
        """Validate a YAML rule file"""
        print(f"\n{'='*80}")
        print(f"Validating: {yaml_path}")
        print(f"{'='*80}\n")
        
        # Load YAML
        try:
            with open(yaml_path, 'r') as f:
                rules = yaml.safe_load(f)
        except Exception as e:
            self.add_issue(f"Failed to load YAML: {e}")
            return self.get_summary()
        
        # Validate metadata
        service_name = rules.get('service')
        if not service_name:
            self.add_issue("Missing 'service' field in YAML")
            return self.get_summary()
        
        print(f"Service: {service_name}\n")
        
        # Create client
        client = self.get_client(service_name)
        if client is None:
            return self.get_summary()
        
        # Validate discoveries
        discoveries = rules.get('discovery', [])
        saved_data = {}
        discovery_results = {}
        
        for discovery in discoveries:
            discovery_id = discovery.get('discovery_id')
            print(f"Validating discovery: {discovery_id}")
            
            if not discovery_id:
                self.add_issue("Discovery block missing 'discovery_id'")
                continue
            
            # Process calls
            calls = discovery.get('calls', [])
            for call_idx, call in enumerate(calls, 1):
                print(f"  Call {call_idx}/{len(calls)}")
                response = self.validate_discovery_call(call, discovery_id, client, saved_data)
            
            # Validate emit
            emit = discovery.get('emit')
            if emit:
                print(f"  Validating emit section")
                emitted_items = self.validate_emit_section(emit, discovery_id, saved_data)
                discovery_results[discovery_id] = emitted_items
        
        # Validate checks
        checks = rules.get('checks', [])
        print(f"\nValidating {len(checks)} checks")
        
        for check in checks:
            check_id = check.get('rule_id', 'unknown')
            print(f"  Validating check: {check_id}")
            
            for_each = check.get('for_each')
            
            if for_each and isinstance(for_each, dict):
                # for_each with discovery reference
                discovery_ref = for_each.get('discovery')
                as_var = for_each.get('as', 'item')
                
                if discovery_ref not in discovery_results:
                    self.add_issue(
                        f"Check '{check_id}': References unknown discovery '{discovery_ref}'\n"
                        f"    Available discoveries: {', '.join(discovery_results.keys())}"
                    )
                    continue
                
                items = discovery_results[discovery_ref]
                if items:
                    # Validate conditions using first item
                    sample_context = items[0]
                    conditions = check.get('conditions')
                    if conditions:
                        self.validate_condition(conditions, sample_context, check_id)
        
        return self.get_summary()
    
    def get_summary(self) -> Dict:
        """Get validation summary"""
        return {
            'issues': self.issues,
            'warnings': self.warnings,
            'issue_count': len(self.issues),
            'warning_count': len(self.warnings),
            'success': len(self.issues) == 0
        }
    
    def print_summary(self):
        """Print validation summary"""
        print(f"\n{'='*80}")
        print("VALIDATION SUMMARY")
        print(f"{'='*80}\n")
        
        if self.issues:
            print(f"❌ Found {len(self.issues)} ERRORS:\n")
            for issue in self.issues:
                print(f"  {issue['message']}\n")
        
        if self.warnings:
            print(f"⚠️  Found {len(self.warnings)} WARNINGS:\n")
            for warning in self.warnings:
                print(f"  {warning}\n")
        
        if not self.issues and not self.warnings:
            print("✅ All validations passed!\n")
        
        print(f"Total: {len(self.issues)} errors, {len(self.warnings)} warnings\n")


def main():
    parser = argparse.ArgumentParser(description='Validate YAML rule files against real AWS API responses')
    parser.add_argument('yaml_files', nargs='+', help='YAML file(s) to validate')
    parser.add_argument('--region', default='us-east-1', help='AWS region to use')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    validator = YAMLValidator(region=args.region, verbose=args.verbose)
    
    all_results = []
    
    for yaml_file in args.yaml_files:
        result = validator.validate_yaml_file(yaml_file)
        all_results.append({
            'file': yaml_file,
            'result': result
        })
        
        # Print summary for this file
        validator.print_summary()
        
        # Reset for next file
        validator.issues = []
        validator.warnings = []
    
    # Exit code
    total_errors = sum(r['result']['issue_count'] for r in all_results)
    sys.exit(1 if total_errors > 0 else 0)


if __name__ == '__main__':
    main()
