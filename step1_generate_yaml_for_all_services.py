#!/usr/bin/env python3
"""
Complete YAML generation pipeline for AWS services:
1. Generate unique functions covering all output_fields
2. Map required_params to python_methods with selection rules
3. Build dependency chains
4. Add require_python_method_for_param to step1
5. Generate minimal YAML with required discovery entries and rules
"""

import json
import csv
import yaml
import os
import re
from collections import defaultdict, OrderedDict

def get_aliases(param):
    """Generate aliases for a parameter"""
    aliases = [param]
    
    if param.endswith('Arn'):
        aliases.append('arn')
    elif param.endswith('Name'):
        aliases.append('name')
    elif param.endswith('Id'):
        aliases.append('id')
    
    return aliases

def process_service(service_name, input_json, output_dir, extracted_rules=None):
    """Process a single service through the complete pipeline"""
    
    print(f"\n{'='*70}")
    print(f"PROCESSING SERVICE: {service_name.upper()}")
    print(f"{'='*70}")
    
    # Load service data
    print("\n1. Loading service data...")
    with open(input_json, 'r') as f:
        all_services_data = json.load(f)
    
    service_data = all_services_data.get(service_name, {})
    if not service_data:
        print(f"   ❌ Service {service_name} not found!")
        return False
    
    independent_ops = service_data.get('independent', [])
    dependent_ops = service_data.get('dependent', [])
    all_ops = independent_ops + dependent_ops
    
    independent_methods = {op.get('python_method') for op in independent_ops if op.get('python_method')}
    
    method_to_op = {}
    for op in all_ops:
        method = op.get('python_method')
        if method:
            method_to_op[method] = op
    
    print(f"   ✓ Loaded {len(method_to_op)} methods ({len(independent_methods)} independent)")
    
    # ============================================================================
    # STEP 1: Find unique functions that can generate ALL output_fields
    # ============================================================================
    print("\n2. STEP 1: Finding unique functions for all output_fields...")
    
    field_to_functions = defaultdict(set)
    function_to_fields = defaultdict(set)
    function_to_full_fields = defaultdict(list)
    
    for op in all_ops:
        method = op.get('python_method')
        if not method:
            continue
        
        output_fields = op.get('output_fields', {})
        item_fields = op.get('item_fields', {})
        main_output_field = op.get('main_output_field', '')
        
        # Process output_fields (top-level)
        if isinstance(output_fields, dict):
            for field_name in output_fields.keys():
                field_to_functions[field_name].add(method)
                function_to_fields[method].add(field_name)
                function_to_full_fields[method].append(field_name)
        
        # Process item_fields (nested fields)
        if isinstance(item_fields, dict):
            for field_name in item_fields.keys():
                if main_output_field:
                    full_path = f"{main_output_field}[].{field_name}"
                else:
                    full_path = field_name
                
                field_to_functions[field_name].add(method)
                function_to_fields[method].add(field_name)
                function_to_full_fields[method].append(full_path)
    
    # Greedy algorithm to find minimal set
    # FIX 1: Only consider read-only methods (audit mode)
    read_only_prefixes = ('list_', 'get_', 'describe_')
    read_only_functions = {f for f in function_to_fields.keys() 
                          if any(f.startswith(prefix) for prefix in read_only_prefixes)}
    
    all_fields_set = set(field_to_functions.keys())
    selected_functions = []
    covered_fields = set()
    
    while covered_fields < all_fields_set:
        best_function = None
        best_coverage = 0
        uncovered_fields = all_fields_set - covered_fields
        
        # Only consider read-only functions
        for func in read_only_functions:
            func_fields = function_to_fields[func]
            new_coverage = len(func_fields & uncovered_fields)
            if new_coverage > best_coverage:
                best_coverage = new_coverage
                best_function = func
        
        if best_function:
            selected_functions.append(best_function)
            covered_fields.update(function_to_fields[best_function])
        else:
            break
    
    print(f"   ✓ Selected {len(selected_functions)} functions to cover {len(all_fields_set)} fields")
    
    # Write Step 1 CSV with actual field names and absolute paths
    step1_csv = os.path.join(output_dir, f'step1-unique-functions-all-output-fields-{service_name}.csv')
    with open(step1_csv, 'w', newline='') as f:
        fieldnames = ['python_method', 'is_independent', 'required_params', 'field_name', 'absolute_path']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for method in sorted(selected_functions):
            required_params = []
            field_data = []  # List of dicts with field_name and absolute_path
            
            if method in method_to_op:
                op = method_to_op[method]
                required_params = op.get('required_params', [])
                output_fields = op.get('output_fields', {})
                item_fields = op.get('item_fields', {})
                main_output_field = op.get('main_output_field', '')
                
                # Process output_fields (top-level fields)
                if isinstance(output_fields, dict):
                    for field_name in output_fields.keys():
                        field_data.append({
                            'field_name': field_name,
                            'absolute_path': field_name  # Top-level fields use field name as path
                        })
                
                # Process item_fields (nested fields)
                if isinstance(item_fields, dict):
                    for field_name in item_fields.keys():
                        if main_output_field:
                            absolute_path = f"{main_output_field}[].{field_name}"
                        else:
                            absolute_path = field_name
                        field_data.append({
                            'field_name': field_name,
                            'absolute_path': absolute_path
                        })
            
            # Write one row per field
            if field_data:
                for field_info in field_data:
                    writer.writerow({
                        'python_method': method,
                        'is_independent': 'YES' if method in independent_methods else 'NO',
                        'required_params': ', '.join(required_params) if required_params else '',
                        'field_name': field_info['field_name'],
                        'absolute_path': field_info['absolute_path']
                    })
            else:
                # Fallback: use old format if no field data
                output_fields_list = function_to_full_fields.get(method, [])
                for path in output_fields_list:
                    # Try to extract field name from path
                    if '[]' in path:
                        field_name = path.split('[]')[-1].lstrip('.')
                    else:
                        field_name = path
                    writer.writerow({
                        'python_method': method,
                        'is_independent': 'YES' if method in independent_methods else 'NO',
                        'required_params': ', '.join(required_params) if required_params else '',
                        'field_name': field_name,
                        'absolute_path': path
                    })
    
    print(f"   ✓ Created: {os.path.basename(step1_csv)}")
    
    # ============================================================================
    # STEP 2: Map required_params to python_methods
    # ============================================================================
    print("\n3. STEP 2: Mapping required_params to python_methods...")
    
    # Collect all unique required_params
    all_required_params = set()
    for op in all_ops:
        required_params = op.get('required_params', [])
        all_required_params.update(required_params)
    
    # Build param to methods mapping
    param_to_methods = defaultdict(set)
    param_to_methods_with_paths = defaultdict(list)
    
    for op in all_ops:
        method = op.get('python_method')
        if not method:
            continue
        
        output_fields = op.get('output_fields', {})
        item_fields = op.get('item_fields', {})
        main_output_field = op.get('main_output_field', '')
        
        # Check output_fields
        if isinstance(output_fields, dict):
            for field_name in output_fields.keys():
                param_to_methods[field_name].add(method)
                param_to_methods_with_paths[field_name].append({
                    'method': method,
                    'path': field_name,
                    'is_independent': method in independent_methods
                })
        
        # Check item_fields
        if isinstance(item_fields, dict):
            for field_name in item_fields.keys():
                if main_output_field:
                    path = f"{main_output_field}[].{field_name}"
                else:
                    path = field_name
                
                param_to_methods[field_name].add(method)
                param_to_methods_with_paths[field_name].append({
                    'method': method,
                    'path': path,
                    'is_independent': method in independent_methods
                })
    
    # Map each required_param to best method
    param_mappings = []
    
    for param in sorted(all_required_params):
        # Try exact match first
        candidate_methods = list(param_to_methods.get(param, []))
        
        # If not found, try aliases with context matching
        if not candidate_methods:
            if param.endswith('Id') and 'preview' in param.lower():
                for alias in get_aliases(param):
                    for method in param_to_methods.get(alias, []):
                        if 'preview' in method.lower() and method not in candidate_methods:
                            candidate_methods.append(method)
            elif param.endswith('Id') and 'finding' in param.lower():
                for alias in get_aliases(param):
                    for method in param_to_methods.get(alias, []):
                        if 'finding' in method.lower() and method not in candidate_methods:
                            candidate_methods.append(method)
            else:
                for alias in get_aliases(param):
                    if alias in param_to_methods:
                        candidate_methods.extend(param_to_methods[alias])
                        break
        
        if not candidate_methods:
            param_mappings.append({
                'required_param': param,
                'python_method': 'NOT_FOUND',
                'full_path': '',
                'is_independent': '',
                'selection_reason': 'No method found'
            })
            continue
        
        candidate_methods = list(set(candidate_methods))
        
        # Rule a: Enhanced validation - method must:
        #  1. Actually EMIT the parameter (in item_fields or output_fields)
        #  2. NOT require the same parameter (avoid circular)
        #  3. Be read-only (list_*, get_*, describe_* only)
        filtered_candidates = []
        for method in candidate_methods:
            if method not in method_to_op:
                continue
                
            op = method_to_op[method]
            
            # Check 1: Method must emit the parameter
            emits_param = False
            item_fields = op.get('item_fields', {})
            output_fields = op.get('output_fields', {})
            
            # Check in item_fields (with aliases)
            if isinstance(item_fields, dict):
                if param in item_fields:
                    emits_param = True
                else:
                    # Check aliases
                    for alias in get_aliases(param):
                        if alias in item_fields:
                            emits_param = True
                            break
            
            # Check in output_fields
            if not emits_param and isinstance(output_fields, dict):
                if param in output_fields:
                    emits_param = True
                else:
                    # Check aliases
                    for alias in get_aliases(param):
                        if alias in output_fields:
                            emits_param = True
                            break
            
            # Check 2: Method must NOT require the same parameter
            method_req_params = op.get('required_params', [])
            requires_param = param in method_req_params
            
            # Check 3: Method must be read-only (audit mode)
            is_read_only = any(method.startswith(prefix) for prefix in ('list_', 'get_', 'describe_'))
            
            if emits_param and not requires_param and is_read_only:
                filtered_candidates.append(method)
        
        if not filtered_candidates:
            # If no valid candidates, mark as NOT_FOUND
            param_mappings.append({
                'required_param': param,
                'python_method': 'NOT_FOUND',
                'full_path': '',
                'is_independent': '',
                'selection_reason': 'No read-only method emits this parameter'
            })
            continue
        
        candidate_methods = filtered_candidates
        
        # Rule b-i: Prefer independent over dependent
        independent_candidates = [m for m in candidate_methods if m in independent_methods]
        dependent_candidates = [m for m in candidate_methods if m not in independent_methods]
        
        if independent_candidates:
            candidates = independent_candidates
            selection_reason = 'Independent method'
        else:
            candidates = dependent_candidates
            selection_reason = 'Dependent method'
        
        # Rule b-ii: Prefer list_ > get_ > update_ > describe_
        def method_priority(method):
            if method.startswith('list_'):
                return 0
            elif method.startswith('get_'):
                return 1
            elif method.startswith('update_'):
                return 2
            elif method.startswith('describe_'):
                return 3
            else:
                return 4
        
        candidates.sort(key=method_priority)
        selected_method = candidates[0]
        
        # Get full path
        full_path = ''
        for entry in param_to_methods_with_paths.get(param, []):
            if entry['method'] == selected_method:
                full_path = entry['path']
                break
        
        if not full_path:
            for alias in get_aliases(param):
                for entry in param_to_methods_with_paths.get(alias, []):
                    if entry['method'] == selected_method:
                        full_path = entry['path']
                        break
                if full_path:
                    break
        
        param_mappings.append({
            'required_param': param,
            'python_method': selected_method,
            'full_path': full_path,
            'is_independent': 'YES' if selected_method in independent_methods else 'NO',
            'selection_reason': selection_reason
        })
    
    # Write Step 2 CSV
    step2_csv = os.path.join(output_dir, f'step2-required-params-to-methods-{service_name}.csv')
    with open(step2_csv, 'w', newline='') as f:
        fieldnames = ['required_param', 'python_method', 'full_path', 'is_independent', 'selection_reason']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(param_mappings)
    
    print(f"   ✓ Created: {os.path.basename(step2_csv)}")
    print(f"   ✓ Mapped {sum(1 for p in param_mappings if p['python_method'] != 'NOT_FOUND')}/{len(all_required_params)} params")
    
    # ============================================================================
    # STEP 3: Build dependency chains
    # ============================================================================
    print("\n4. STEP 3: Building dependency chains...")
    
    # Build param mappings dict
    param_to_method_dict = {p['required_param']: p['python_method'] for p in param_mappings}
    param_to_path_dict = {p['required_param']: p['full_path'] for p in param_mappings}
    param_to_is_independent_dict = {p['required_param']: p['is_independent'] == 'YES' for p in param_mappings}
    
    # Build method to required_params mapping for dependent methods
    # The metadata required_params is the source of truth for what a method needs
    # The dependency chain CSV (param_to_method_dict) shows which method provides each param
    method_to_required_params_from_chain = {}
    for op in all_ops:
        method = op.get('python_method', '')
        if method and method not in independent_methods:
            # This method is dependent, so it needs params
            # Use metadata required_params as the source of truth
            req_params = op.get('required_params', [])
            if req_params:
                method_to_required_params_from_chain[method] = req_params
    
    # Build method to required_params mapping
    method_to_required_params_dict = {}
    for op in all_ops:
        method = op.get('python_method')
        if method:
            method_to_required_params_dict[method] = op.get('required_params', [])
    
    def build_dependency_chain(method, visited=None, depth=0):
        """Recursively build dependency chain"""
        if visited is None:
            visited = set()
        
        if method in visited or depth > 10:
            return []
        
        visited.add(method)
        
        if method == 'NOT_FOUND':
            return ['NOT_SUPPORTED']
        
        if method in independent_methods:
            return [method]
        
        required_params = method_to_required_params_dict.get(method, [])
        if not required_params:
            return [method]
        
        dependency_methods = set()
        for param in required_params:
            providing_method = param_to_method_dict.get(param, 'NOT_FOUND')
            if providing_method != 'NOT_FOUND' and providing_method != method:
                if providing_method in independent_methods:
                    dependency_methods.add(providing_method)
                else:
                    providing_req_params = method_to_required_params_dict.get(providing_method, [])
                    if param not in providing_req_params:
                        dependency_methods.add(providing_method)
        
        if not dependency_methods:
            return [method]
        
        all_dependencies = []
        for dep_method in dependency_methods:
            if dep_method not in visited:
                dep_chain = build_dependency_chain(dep_method, visited.copy(), depth + 1)
                if dep_chain:
                    all_dependencies.extend(dep_chain)
        
        seen = set()
        unique_deps = []
        for dep in all_dependencies:
            if dep not in seen and dep != method:
                seen.add(dep)
                unique_deps.append(dep)
        
        chain = [method]
        chain.extend(unique_deps)
        return chain
    
    # Add dependency chains to step2
    step2_with_chains_csv = os.path.join(output_dir, f'step2-required-params-to-methods-with-chains-{service_name}.csv')
    with open(step2_csv, 'r') as f_in, open(step2_with_chains_csv, 'w', newline='') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = reader.fieldnames + ['dependency_chain', 'dependency_chain_formatted']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            method = row['python_method']
            param = row['required_param']
            full_path = row['full_path']
            
            if method == 'NOT_FOUND':
                chain = ['NOT_SUPPORTED']
                chain_formatted = 'NOT_SUPPORTED'
            else:
                chain = build_dependency_chain(method)
                
                chain_parts = []
                for i, chain_method in enumerate(chain):
                    if chain_method == 'NOT_SUPPORTED':
                        chain_parts.append('NOT_SUPPORTED')
                    elif chain_method in independent_methods:
                        param_path = param_to_path_dict.get(param, '')
                        if param_path:
                            chain_parts.append(f"{chain_method} ({param_path}) - INDEPENDENT")
                        else:
                            chain_parts.append(f"{chain_method} - INDEPENDENT")
                    else:
                        req_params = method_to_required_params_dict.get(chain_method, [])
                        if req_params:
                            param_paths = []
                            for req_param in req_params[:2]:
                                if req_param in param_to_path_dict:
                                    param_paths.append(f"{req_param}:{param_to_path_dict[req_param]}")
                            if param_paths:
                                chain_parts.append(f"{chain_method} ({', '.join(param_paths)})")
                            else:
                                chain_parts.append(chain_method)
                        else:
                            chain_parts.append(chain_method)
                
                chain_formatted = ' → '.join(chain_parts)
            
            row['dependency_chain'] = ' → '.join(chain)
            row['dependency_chain_formatted'] = chain_formatted
            writer.writerow(row)
    
    print(f"   ✓ Created: {os.path.basename(step2_with_chains_csv)}")
    
    # ============================================================================
    # STEP 4: Add require_python_method_for_param to step1
    # ============================================================================
    print("\n5. STEP 4: Adding require_python_method_for_param to step1...")
    
    # Build param to methods with priority
    param_to_methods_priority = defaultdict(list)
    for p in param_mappings:
        if p['python_method'] != 'NOT_FOUND':
            method = p['python_method']
            if method.startswith('list_'):
                priority = 0
            elif method.startswith('get_'):
                priority = 1
            else:
                priority = 2
            
            param_to_methods_priority[p['required_param']].append({
                'method': method,
                'priority': priority,
                'is_independent': p['is_independent'] == 'YES'
            })
    
    for param in param_to_methods_priority:
        param_to_methods_priority[param].sort(key=lambda x: (not x['is_independent'], x['priority']))
    
    # Update step1 CSV
    step1_with_params_csv = os.path.join(output_dir, f'step1-unique-functions-all-output-fields-with-params-{service_name}.csv')
    with open(step1_csv, 'r') as f_in, open(step1_with_params_csv, 'w', newline='') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = list(reader.fieldnames) + ['require_python_method_for_param']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        
        # Track methods we've seen to avoid duplicates
        method_to_params = {}
        
        for row in reader:
            method = row.get('python_method', '')
            required_params_str = row.get('required_params', '')
            required_params = [p.strip() for p in required_params_str.split(',')] if required_params_str else []
            
            # Group by method to collect all params
            if method not in method_to_params:
                method_to_params[method] = {
                    'row_template': row.copy(),
                    'params': set(required_params)
                }
            else:
                method_to_params[method]['params'].update(required_params)
        
        # Write rows with require_python_method_for_param
        for method, data in method_to_params.items():
            row = data['row_template'].copy()
            required_params = list(data['params'])
            
            mapped_methods = []
            seen_methods = set()
            
            for param in required_params:
                if param in param_to_methods_priority:
                    for method_info in param_to_methods_priority[param]:
                        method_name = method_info['method']
                        if method_name not in seen_methods and method_name != method:
                            mapped_methods.append(method_name)
                            seen_methods.add(method_name)
                            break
            
            row['require_python_method_for_param'] = ', '.join(mapped_methods) if mapped_methods else ''
            # Update required_params to show all params for this method
            row['required_params'] = ', '.join(sorted(required_params)) if required_params else ''
            writer.writerow(row)
    
    print(f"   ✓ Created: {os.path.basename(step1_with_params_csv)}")
    
    # ============================================================================
    # STEP 5: Generate minimal YAML
    # ============================================================================
    print("\n6. STEP 5: Generating minimal YAML...")
    
    # Extract rules for this service
    service_rules = []
    if extracted_rules and service_name in extracted_rules:
        service_rules = extracted_rules[service_name].get('rules', [])
        print(f"   Found {len(service_rules)} rules from existing YAML")
    
    # Extract required fields from rules (from var field like "item.status" -> "status")
    required_fields = set()
    rule_to_discovery = {}  # Map rule_id to discovery_id (for_each)
    
    for rule in service_rules:
        var = rule.get('var', '')
        if var.startswith('item.'):
            field = var.replace('item.', '').split('.')[0]  # Get first part after item.
            required_fields.add(field)
        
        # Track which discovery each rule needs
        for_each = rule.get('for_each', '')
        if for_each:
            rule_to_discovery[rule.get('rule_id', '')] = for_each
    
    print(f"   Required fields from rules: {sorted(required_fields)}")
    
    # Find methods that provide these fields
    field_to_methods = defaultdict(list)
    
    for method in method_to_op.keys():
        op = method_to_op[method]
        item_fields = op.get('item_fields', {})
        if isinstance(item_fields, dict):
            for field in item_fields.keys():
                if field in required_fields:
                    field_to_methods[field].append(method)
    
    # Also check output_fields for nested fields (e.g., "item.security_contact.exists" -> "security_contact")
    for method in method_to_op.keys():
        op = method_to_op[method]
        output_fields = op.get('output_fields', {})
        if isinstance(output_fields, dict):
            for field_path in output_fields.keys():
                # Handle nested fields like "security_contact.exists"
                parts = field_path.split('.')
                for i in range(len(parts)):
                    nested_field = '.'.join(parts[:i+1])
                    if nested_field in required_fields or any(nested_field.startswith(f) for f in required_fields):
                        if method not in field_to_methods.get(nested_field, []):
                            field_to_methods[nested_field].append(method)
    
    # Build list of required methods (prefer independent, prefer list_ methods)
    required_methods_for_rules = set()
    
    for field, methods in field_to_methods.items():
        if not methods:
            continue
        
        # Prefer independent methods
        independent_for_field = [m for m in methods if m in independent_methods]
        if independent_for_field:
            # Prefer list_ methods
            list_methods = [m for m in independent_for_field if m.startswith('list_')]
            if list_methods:
                required_methods_for_rules.add(list_methods[0])
            else:
                required_methods_for_rules.add(independent_for_field[0])
        else:
            # Use dependent methods, prefer list_
            list_methods = [m for m in methods if m.startswith('list_')]
            if list_methods:
                required_methods_for_rules.add(list_methods[0])
            elif methods:
                required_methods_for_rules.add(methods[0])
    
    # Also check for_each from rules to include those discovery methods
    # This is the primary way to determine which methods are needed
    # The for_each contains discovery_id like "aws.account.alternate_contacts"
    # We need to find which method(s) provide the fields needed by the rules
    # FIX: Only add read-only methods (filter out create/update/delete)
    read_only_prefixes = ('list_', 'get_', 'describe_')
    
    for rule in service_rules:
        for_each = rule.get('for_each', '')
        if for_each:
            # Extract discovery_id name (e.g., "aws.account.alternate_contacts" -> "alternate_contacts")
            parts = for_each.split('.')
            if len(parts) >= 2:
                discovery_id_name = parts[-1]
                discovery_base = discovery_id_name.rstrip('s').replace('_', '')  # Remove plural, remove underscores
                
                # Try to find method that matches discovery pattern
                # Patterns: alternate_contacts -> get_alternate_contact, list_certificates -> list_certificates
                best_match = None
                best_score = 0
                
                for method in method_to_op.keys():
                    # FIX: Skip non-read-only methods
                    if not any(method.startswith(prefix) for prefix in read_only_prefixes):
                        continue
                    
                    method_base = method.replace('_', '').replace('get_', '').replace('list_', '').replace('describe_', '')
                    
                    # Score based on similarity
                    score = 0
                    if discovery_base in method_base or method_base in discovery_base:
                        score += 10
                    if discovery_id_name.lower() in method.lower() or method.lower() in discovery_id_name.lower():
                        score += 5
                    
                    # Also check output_fields for keywords
                    op = method_to_op[method]
                    output_fields = op.get('output_fields', {})
                    if isinstance(output_fields, dict):
                        output_str = ' '.join(output_fields.keys()).lower()
                        if discovery_base in output_str or any(part in output_str for part in discovery_id_name.split('_')):
                            score += 3
                    
                    if score > best_score:
                        best_score = score
                        best_match = method
                
                if best_match and best_score > 0:
                    required_methods_for_rules.add(best_match)
                    print(f"   Added method from rule for_each ({discovery_id_name} -> {best_match}, score: {best_score})")
    
    # If no methods found from for_each, try to find methods that provide the fields
    if not required_methods_for_rules:
        print("   No methods from for_each, trying field-based matching...")
        for field, methods in field_to_methods.items():
            if not methods:
                continue
            
            # Prefer independent methods
            independent_for_field = [m for m in methods if m in independent_methods]
            if independent_for_field:
                # Prefer list_ methods
                list_methods = [m for m in independent_for_field if m.startswith('list_')]
                if list_methods:
                    required_methods_for_rules.add(list_methods[0])
                else:
                    required_methods_for_rules.add(independent_for_field[0])
            else:
                # Use dependent methods, prefer list_
                list_methods = [m for m in methods if m.startswith('list_')]
                if list_methods:
                    required_methods_for_rules.add(list_methods[0])
                elif methods:
                    required_methods_for_rules.add(methods[0])
        
        # Service-specific fallbacks based on AWS best practices
        if not required_methods_for_rules:
            if service_name == 'transfer':
                # For transfer, prefer list_servers for server-related checks
                if 'list_servers' in method_to_op:
                    required_methods_for_rules.add('list_servers')
            elif service_name == 'wellarchitected':
                # For wellarchitected, prefer list_workloads for workload checks
                if 'list_workloads' in method_to_op:
                    required_methods_for_rules.add('list_workloads')
            elif service_name == 'drs':
                # For DRS, prefer describe_recovery_instances for failover checks
                if 'describe_recovery_instances' in method_to_op:
                    required_methods_for_rules.add('describe_recovery_instances')
                elif 'describe_replication_configuration_templates' in method_to_op:
                    required_methods_for_rules.add('describe_replication_configuration_templates')
    
    # Add dependencies for all required methods
    # Load step1 data if available
    step1_csv_path = os.path.join(output_dir, f'step1-unique-functions-all-output-fields-with-params-{service_name}.csv')
    step1_data = {}
    if os.path.exists(step1_csv_path):
        with open(step1_csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                method_name = row.get('python_method', '')
                if method_name:
                    step1_data[method_name] = row
    
    all_required_methods = set(required_methods_for_rules)
    for method in list(required_methods_for_rules):
        if method in step1_data:
            req_methods_str = step1_data[method].get('require_python_method_for_param', '')
            if req_methods_str:
                req_methods = [m.strip() for m in req_methods_str.split(',')]
                all_required_methods.update(req_methods)
    
    # Sort: independent first, then by name
    required_methods_for_rules = sorted(all_required_methods, key=lambda m: (m not in independent_methods, m))
    
    # FIX: Add list_buckets for S3 if any method needs Bucket parameter
    if service_name == 's3' and 'list_buckets' in method_to_op and 'list_buckets' not in required_methods_for_rules:
        # Check if any required method needs Bucket
        needs_bucket = False
        for method in required_methods_for_rules:
            if method in method_to_op:
                req_params = method_to_op[method].get('required_params', [])
                if 'Bucket' in req_params:
                    needs_bucket = True
                    break
        if needs_bucket:
            required_methods_for_rules.insert(0, 'list_buckets')  # Add at beginning (independent)
            print(f"   Added list_buckets (required for Bucket parameter)")
    
    # If no methods found for rules, use first independent method as fallback
    if not required_methods_for_rules and independent_methods:
        # Prefer list_ methods
        list_methods = [m for m in independent_methods if m.startswith('list_')]
        if list_methods:
            required_methods_for_rules = [list_methods[0]]
        else:
            required_methods_for_rules = [sorted(independent_methods)[0]]
        print(f"   No rules found, using fallback method: {required_methods_for_rules}")
    else:
        print(f"   Required methods for rules: {required_methods_for_rules}")
    
    discovery_entries = []
    
    # FIX 2: Filter out create/update/delete methods (read-only only)
    read_only_prefixes = ('list_', 'get_', 'describe_')
    read_only_methods = [m for m in required_methods_for_rules 
                        if any(m.startswith(prefix) for prefix in read_only_prefixes)]
    
    if not read_only_methods and required_methods_for_rules:
        print(f"   ⚠ Warning: No read-only methods found, using first independent method as fallback")
        if independent_methods:
            list_methods = [m for m in independent_methods if m.startswith('list_')]
            if list_methods:
                read_only_methods = [list_methods[0]]
            else:
                read_only_methods = [sorted(independent_methods)[0]]
    
    for method in read_only_methods:
        if method not in method_to_op:
            continue
        
        op = method_to_op[method]
        discovery_id = f"aws.{service_name}.{method}"
        
        calls = [{'action': method, 'save_as': 'response'}]
        
        # Add params if dependent
        if method not in independent_methods:
            # Check both metadata and dependency chain CSV for required params
            required_params_metadata = op.get('required_params', [])
            required_params_chain = method_to_required_params_from_chain.get(method, [])
            # Use params from chain if available, otherwise use metadata
            required_params = required_params_chain if required_params_chain else required_params_metadata
            
            if required_params:
                params_dict = {}
                for_each_id = None
                
                # Find what provides the params
                for param in required_params:
                    provider_method = None
                    
                    # Check direct mapping first
                    if param in param_to_method_dict:
                        provider_method = param_to_method_dict[param]
                    
                    # Handle NOT_FOUND and circular dependencies - use service-specific fallbacks
                    if provider_method == method or provider_method == 'NOT_FOUND' or not provider_method:
                        # Service-specific fallbacks for common parameters
                        if param == 'Bucket' and service_name == 's3':
                            # S3 Bucket parameter - use list_buckets which emits Name
                            if 'list_buckets' in method_to_op:
                                provider_method = 'list_buckets'
                        elif param.endswith('Arn'):
                            # Try to find list_* method that provides 'arn'
                            for m in method_to_op.keys():
                                if m.startswith('list_') and m in independent_methods:
                                    op_check = method_to_op[m]
                                    item_fields = op_check.get('item_fields', {})
                                    if isinstance(item_fields, dict) and 'arn' in item_fields:
                                        provider_method = m
                                        break
                        elif param.endswith('Name'):
                            # Try to find list_* method that provides 'name'
                            for m in method_to_op.keys():
                                if m.startswith('list_') and m in independent_methods:
                                    op_check = method_to_op[m]
                                    item_fields = op_check.get('item_fields', {})
                                    if isinstance(item_fields, dict) and 'name' in item_fields:
                                        provider_method = m
                                        break
                        elif param.endswith('Id'):
                            # Try to find a method that provides 'id' (not the current method)
                            for p, m in param_to_method_dict.items():
                                if p == 'id' and m != method and m != 'NOT_FOUND':
                                    provider_method = m
                                    break
                    
                    # FIX 3: Validate provider_method is read-only and exists in discovery
                    if provider_method and provider_method != method and provider_method != 'NOT_FOUND':
                        # Verify provider is read-only
                        if not any(provider_method.startswith(prefix) for prefix in ('list_', 'get_', 'describe_')):
                            continue  # Skip non-read-only providers
                        
                        if not for_each_id:
                            for_each_id = f"aws.{service_name}.{provider_method}"
                        
                        # Determine field name - handle aliases and service-specific mappings
                        if for_each_id and 'list_buckets' in for_each_id and param == 'Bucket':
                            # S3: Bucket parameter maps to Name field from list_buckets
                            field_name = 'Name'
                        elif for_each_id and 'list_analyzers' in for_each_id:
                            if param.endswith('Arn'):
                                field_name = 'arn'
                            elif param.endswith('Name'):
                                field_name = 'name'
                            elif param.endswith('Id'):
                                field_name = 'id'
                            else:
                                field_name = param
                        elif provider_method and provider_method.startswith('list_'):
                            # For list_ methods, check what field they emit for this param
                            if provider_method in method_to_op:
                                op = method_to_op[provider_method]
                                item_fields = op.get('item_fields', {})
                                if isinstance(item_fields, dict):
                                    # Check exact match first
                                    if param in item_fields:
                                        field_name = param
                                    # Check aliases
                                    elif param.endswith('Arn') and 'arn' in item_fields:
                                        field_name = 'arn'
                                    elif param.endswith('Name') and 'name' in item_fields:
                                        field_name = 'name'
                                    elif param.endswith('Id') and 'id' in item_fields:
                                        field_name = 'id'
                                    else:
                                        field_name = param
                                else:
                                    field_name = param
                            else:
                                field_name = param
                        else:
                            # Use path from param mapping
                            path = param_to_path_dict.get(param, '')
                            if '[]' in path:
                                field_name = path.split('[]')[1].lstrip('.')
                            else:
                                field_name = path
                            
                            if not field_name:
                                field_name = param
                        
                        params_dict[param] = f"{{{{ item.{field_name} }}}}"
                
                if params_dict:
                    calls[0]['params'] = params_dict
                
                if for_each_id:
                    discovery_entry = {
                        'discovery_id': discovery_id,
                        'calls': calls,
                        'on_error': 'continue',
                        'for_each': for_each_id
                    }
                else:
                    discovery_entry = {'discovery_id': discovery_id, 'calls': calls}
            else:
                discovery_entry = {'discovery_id': discovery_id, 'calls': calls}
        else:
            discovery_entry = {'discovery_id': discovery_id, 'calls': calls}
        
        # Build emit
        main_output_field = op.get('main_output_field', '')
        item_fields = op.get('item_fields', {})
        
        if isinstance(item_fields, dict) and item_fields:
            if main_output_field:
                is_list_method = method.startswith('list_')
                if is_list_method:
                    emit = {
                        'items_for': f"{{{{ response.{main_output_field} }}}}",
                        'as': 'resource',
                        'item': {}
                    }
                    for field_name in item_fields.keys():
                        emit['item'][field_name] = f"{{{{ resource.{field_name} }}}}"
                else:
                    emit = {'item': {}}
                    for field_name in item_fields.keys():
                        emit['item'][field_name] = f"{{{{ response.{main_output_field}.{field_name} }}}}"
                discovery_entry['emit'] = emit
        
        discovery_entries.append(discovery_entry)
    
    # FIX 4: Validate for_each chains - ensure source discovery exists and emits required fields
    discovery_id_to_entry = {entry['discovery_id']: entry for entry in discovery_entries}
    discovery_id_to_emitted_fields = {}
    
    for entry in discovery_entries:
        disc_id = entry['discovery_id']
        method_name = disc_id.split('.')[-1]
        emitted_fields = set()
        
        if method_name in method_to_op:
            op = method_to_op[method_name]
            item_fields = op.get('item_fields', {})
            if isinstance(item_fields, dict):
                emitted_fields.update(item_fields.keys())
        
        discovery_id_to_emitted_fields[disc_id] = emitted_fields
    
    # Validate and fix for_each references
    for entry in discovery_entries:
        for_each_id = entry.get('for_each')
        if for_each_id:
            # Check if source exists
            if for_each_id not in discovery_id_to_entry:
                print(f"   ⚠ Warning: {entry['discovery_id']} references non-existent for_each: {for_each_id}")
                # Try to find alternative or remove for_each
                entry.pop('for_each', None)
                if 'params' in entry.get('calls', [{}])[0]:
                    # If params exist but no valid for_each, this is an error
                    print(f"   ❌ Error: {entry['discovery_id']} has params but no valid for_each source")
                    # Remove params that can't be resolved
                    entry['calls'][0].pop('params', None)
            else:
                # Check if source emits required params
                required_params = []
                if 'params' in entry.get('calls', [{}])[0]:
                    params = entry['calls'][0]['params']
                    # Extract field names from templates like "{{ item.Bucket }}"
                    for param_value in params.values():
                        matches = re.findall(r'item\.([A-Za-z][A-Za-z0-9_]*)', str(param_value))
                        required_params.extend(matches)
                
                source_emitted = discovery_id_to_emitted_fields.get(for_each_id, set())
                missing = [p for p in required_params if p not in source_emitted]
                if missing:
                    print(f"   ⚠ Warning: {entry['discovery_id']} requires fields not emitted by {for_each_id}: {missing}")
    
    # Build checks from extracted rules
    checks = []
    
    # FIX: Build field_name -> discovery_id mapping from actual emit structures
    # This maps the field names (like "status", "is_public") to the discovery_id that emits them
    field_to_discovery = defaultdict(list)
    
    for entry in discovery_entries:
        discovery_id = entry['discovery_id']
        emit = entry.get('emit', {})
        item = emit.get('item', {})
        
        # Get all field names from the emit item (these are what checks reference)
        if item:
            for field_name in item.keys():
                field_to_discovery[field_name].append(discovery_id)
    
    # Create discovery_id to method mapping
    discovery_id_to_method = {}
    for entry in discovery_entries:
        discovery_id = entry['discovery_id']
        method_name = discovery_id.split('.')[-1]
        discovery_id_to_method[discovery_id] = method_name
    
    # Build checks from extracted rules
    for rule in service_rules:
        rule_id = rule.get('rule_id', '')
        var = rule.get('var', '')
        op = rule.get('op', '')
        value = rule.get('value')
        for_each_from_rule = rule.get('for_each', '')
        
        if not rule_id or not var:
            continue
        
        # Find the discovery_id for this rule
        discovery_id_for_rule = None
        
        # First, try to use for_each from the rule if it exists
        if for_each_from_rule:
            # Check if this discovery_id exists in our discovery_entries
            if for_each_from_rule in discovery_id_to_method:
                discovery_id_for_rule = for_each_from_rule
            else:
                # Try to find a matching discovery entry
                # Extract method name from for_each (e.g., "aws.acm.list_certificates" -> "list_certificates")
                parts = for_each_from_rule.split('.')
                if len(parts) >= 2:
                    method_name = parts[-1]
                    # Find discovery entry with this method
                    for entry in discovery_entries:
                        if entry['discovery_id'].endswith(f'.{method_name}'):
                            discovery_id_for_rule = entry['discovery_id']
                            break
        
        # FIX: If still not found, match based on field name from var using actual emit mapping
        if not discovery_id_for_rule:
            # Extract field from var (e.g., "item.status" -> "status")
            field = var.replace('item.', '').split('.')[0]
            
            # Use the field_to_discovery mapping we built from actual emits
            if field in field_to_discovery:
                # Prefer the first one, or prioritize based on method type (list_ > get_ > describe_)
                candidates = field_to_discovery[field]
                if len(candidates) == 1:
                    discovery_id_for_rule = candidates[0]
                else:
                    # Prioritize: list_ methods first, then get_, then describe_
                    for prefix in ('list_', 'get_', 'describe_'):
                        for disc_id in candidates:
                            method_name = disc_id.split('.')[-1]
                            if method_name.startswith(prefix):
                                discovery_id_for_rule = disc_id
                                break
                        if discovery_id_for_rule:
                            break
                    # If still not found, use first candidate
                    if not discovery_id_for_rule:
                        discovery_id_for_rule = candidates[0]
        
        # If still not found, try metadata-based matching (fallback)
        if not discovery_id_for_rule:
            field = var.replace('item.', '').split('.')[0]
            # Find discovery entry that provides this field from metadata
            for entry in discovery_entries:
                entry_method = discovery_id_to_method.get(entry['discovery_id'], '')
                if entry_method in method_to_op:
                    op_data = method_to_op[entry_method]
                    item_fields = op_data.get('item_fields', {})
                    if isinstance(item_fields, dict) and field in item_fields:
                        discovery_id_for_rule = entry['discovery_id']
                        break
        
        # If still not found, use first discovery entry
        if not discovery_id_for_rule and discovery_entries:
            discovery_id_for_rule = discovery_entries[0]['discovery_id']
        
        if discovery_id_for_rule:
            check = {
                'rule_id': rule_id,
                'conditions': {
                    'var': var,
                    'op': op
                }
            }
            
            if value is not None:
                check['conditions']['value'] = value
            
            if discovery_id_for_rule:
                check['for_each'] = discovery_id_for_rule
            
            checks.append(check)
    
    print(f"   Created {len(checks)} checks from {len(service_rules)} extracted rules")
    
    # Build YAML
    yaml_data = OrderedDict([
        ('version', '1.0'),
        ('provider', 'aws'),
        ('service', service_name),
        ('services', OrderedDict([
            ('client', service_name),
            ('module', 'boto3.client')
        ])),
        ('discovery', discovery_entries),
        ('checks', checks)
    ])
    
    def convert_to_dict(obj):
        if isinstance(obj, OrderedDict):
            return {k: convert_to_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_to_dict(item) for item in obj]
        else:
            return obj
    
    yaml_data_dict = convert_to_dict(yaml_data)
    
    # Write YAML
    output_yaml = os.path.join(output_dir, f'{service_name}_minimal_with_rules.yaml')
    with open(output_yaml, 'w') as f:
        yaml.dump(yaml_data_dict, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)
    
    print(f"   ✓ Created: {os.path.basename(output_yaml)}")
    print(f"   ✓ Discovery entries: {len(discovery_entries)}, Checks: {len(checks)}")
    
    return True

# Main execution
if __name__ == '__main__':
    input_json = '/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/boto3_dependencies_with_python_names_fully_enriched.json'
    output_dir = '/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/yaml_generation'
    extracted_rules_json = '/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/yaml_generation/extracted_rules_by_service.json'
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Load all services
    print("="*70)
    print("YAML GENERATION PIPELINE FOR AWS SERVICES")
    print("="*70)
    
    with open(input_json, 'r') as f:
        all_services_data = json.load(f)
    
    # Load extracted rules
    extracted_rules = {}
    if os.path.exists(extracted_rules_json):
        with open(extracted_rules_json, 'r') as f:
            extracted_rules = json.load(f)
        print(f"✓ Loaded rules for {len(extracted_rules)} services")
    else:
        print(f"⚠ Warning: {extracted_rules_json} not found. Run extract_rules_from_existing_yaml.py first")
    
    # Get list of services from services folder
    services_folder = '/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services'
    service_folders = []
    if os.path.exists(services_folder):
        for item in os.listdir(services_folder):
            item_path = os.path.join(services_folder, item)
            if os.path.isdir(item_path) and not item.startswith('.') and item not in ['metadata', 'test_results']:
                service_folders.append(item)
    
    # Map folder names to JSON service names (handle naming differences)
    folder_to_json_name = {}
    json_service_names = set(all_services_data.keys())
    
    for folder_name in service_folders:
        # Try exact match first
        folder_lower = folder_name.lower()
        if folder_lower in json_service_names:
            folder_to_json_name[folder_name] = folder_lower
        else:
            # Try variations
            folder_norm = folder_name.replace('-', '').replace('_', '').lower()
            for json_name in json_service_names:
                json_norm = json_name.replace('-', '').replace('_', '').lower()
                if folder_norm == json_norm:
                    folder_to_json_name[folder_name] = json_name
                    break
    
    # Process services
    import sys
    
    if len(sys.argv) > 1:
        # Process specific service(s) from command line
        requested_services = sys.argv[1:]
        service_names = []
        for req in requested_services:
            if req in folder_to_json_name:
                service_names.append(folder_to_json_name[req])
            elif req in json_service_names:
                service_names.append(req)
            else:
                print(f"⚠ Warning: Service '{req}' not found, skipping...")
    else:
        # Process all services from folder
        service_names = sorted(set(folder_to_json_name.values()))
        print(f"\nFound {len(service_folders)} service folders")
        print(f"Mapped to {len(service_names)} services in JSON")
    
    # Mark accessanalyzer as done (skip if already processed)
    completed_services = set()
    if 'accessanalyzer' in service_names:
        completed_services.add('accessanalyzer')
        print(f"\n✓ accessanalyzer marked as completed (already processed)")
    
    print(f"\nProcessing {len(service_names)} service(s)...")
    
    successful = []
    failed = []
    skipped = []
    
    for service_name in service_names:
        if service_name in completed_services:
            skipped.append(service_name)
            continue
            
        try:
            print(f"\n{'='*70}")
            success = process_service(service_name, input_json, output_dir, extracted_rules)
            if success:
                successful.append(service_name)
            else:
                failed.append(service_name)
        except KeyboardInterrupt:
            print(f"\n\n⚠ Interrupted by user")
            break
        except Exception as e:
            print(f"\n❌ Error processing {service_name}: {e}")
            import traceback
            traceback.print_exc()
            failed.append(service_name)
    
    # Summary
    print(f"\n{'='*70}")
    print("PROCESSING SUMMARY")
    print(f"{'='*70}")
    print(f"\n✓ Successfully processed: {len(successful)}")
    print(f"⏭ Skipped (already done): {len(skipped)}")
    print(f"❌ Failed: {len(failed)}")
    print(f"📊 Total: {len(service_names)}")
    
    if successful:
        print(f"\n✓ Successful services ({len(successful)}):")
        for svc in successful[:20]:
            print(f"   - {svc}")
        if len(successful) > 20:
            print(f"   ... and {len(successful) - 20} more")
    
    if skipped:
        print(f"\n⏭ Skipped services ({len(skipped)}):")
        for svc in skipped:
            print(f"   - {svc}")
    
    if failed:
        print(f"\n❌ Failed services ({len(failed)}):")
        for svc in failed[:20]:
            print(f"   - {svc}")
        if len(failed) > 20:
            print(f"   ... and {len(failed) - 20} more")
    
    print(f"\n📁 Output files in: {output_dir}")
    print(f"   - step1-unique-functions-all-output-fields-{{service}}.csv")
    print(f"   - step1-unique-functions-all-output-fields-with-params-{{service}}.csv")
    print(f"   - step2-required-params-to-methods-{{service}}.csv")
    print(f"   - step2-required-params-to-methods-with-chains-{{service}}.csv")
    print(f"   - {{service}}_minimal_with_rules.yaml")

