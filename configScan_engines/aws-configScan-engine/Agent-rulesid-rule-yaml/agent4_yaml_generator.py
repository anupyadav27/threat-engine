"""
Agent 4: YAML Generator

Takes validated requirements and generates complete YAML files.

Flow:
1. Read requirements_validated.json
2. For each rule, traverse: field → function → dependencies → emit
3. Generate complete discovery + checks YAML
4. Save to service/rules/*.yaml

Uses: boto3_dependencies_with_python_names.json for field mappings
"""

import json
import os
import sys
import re
from typing import Dict, List, Any, Set, Optional


def load_boto3_catalog():
    """Load boto3 catalog"""
    with open('boto3_dependencies_with_python_names.json') as f:
        return json.load(f)


def load_validated_requirements():
    """Load validated requirements from Agent 3"""
    with open('output/requirements_validated.json') as f:
        return json.load(f)


def validate_parameter_format(param_name: str, param_value_template: str) -> bool:
    """
    Validate parameter format based on known patterns.
    
    Returns: True if format seems valid, False if likely invalid
    """
    # Common validation patterns
    # Trail names must start with letter/number
    if 'trail' in param_name.lower() and 'name' in param_name.lower():
        # Will be validated at runtime, but we can add on_error: continue
        return True
    
    # ARN format validation (basic check)
    if 'arn' in param_name.lower():
        # ARNs have specific format, but template will be resolved at runtime
        return True
    
    # IDs often have format constraints
    if 'id' in param_name.lower() and 'arn' not in param_name.lower():
        # Most IDs are alphanumeric, but format varies
        return True
    
    return True  # Default to valid, runtime will catch issues


def generate_discovery_for_function(service: str, function_data: Dict, discovery_id: str, 
                                   parent_discovery_id: Optional[str] = None,
                                   parent_field_name: Optional[str] = None) -> Dict:
    """
    Generate discovery YAML section with CORRECT emit structure.
    
    KEY LEARNING FROM S3:
    - Independent discoveries: Need items_for + as + item (defines iteration)
    - Dependent discoveries: Simple item emit (inherits 'item' from parent)
    
    Args:
        service: Service name
        function_data: Function info from validated requirements
        discovery_id: ID for this discovery
        parent_discovery_id: Parent discovery ID (if dependent)
        parent_field_name: Field name from parent (if dependent)
    
    Returns:
        Discovery dict ready for YAML
    """
    python_method = function_data['python_method']
    main_output = function_data['main_output_field']
    is_independent = function_data['is_independent']
    required_params = function_data.get('required_params', [])
    available_fields = function_data.get('available_fields', [])
    
    discovery = {
        'discovery_id': discovery_id,
        'calls': [
            {
                'action': python_method,
                'save_as': f'{python_method}_response'
            }
        ]
    }
    
    # Add for_each if dependent (use actual parent if provided)
    if not is_independent:
        if parent_discovery_id:
            discovery['for_each'] = parent_discovery_id
        else:
            # Will be resolved in second pass
            discovery['for_each'] = f'aws.{service}.PARENT_DISCOVERY'
    
    # Add params if dependent (use actual field name if provided)
    if required_params:
        discovery['calls'][0]['params'] = {}
        for param in required_params:
            if parent_field_name:
                # Use actual field name from parent
                discovery['calls'][0]['params'][param] = f'{{{{ item.{parent_field_name} }}}}'
            else:
                # Will be resolved in second pass
                discovery['calls'][0]['params'][param] = '{{ item.FIELD_NAME }}'
        discovery['calls'][0]['on_error'] = 'continue'
    
    # Generate emit section - CRITICAL DIFFERENCE
    emit = {}
    
    if is_independent:
        # INDEPENDENT: Full emit with items_for
        if main_output:
            emit['items_for'] = f'{{{{ {python_method}_response.{main_output} }}}}'
            emit['as'] = 'resource'  # Use generic name
            
            # Map fields from response
            emit['item'] = {}
            for field in available_fields[:10]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ resource.{field} }}}}'
        else:
            # Fallback for operations without clear list output
            emit['item'] = {}
            for field in available_fields[:5]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ {python_method}_response.{field} }}}}'
    else:
        # DEPENDENT: Simple emit - inherit 'item' from parent
        emit['item'] = {}
        
        # Pass through parent id/name (always useful)
        emit['item']['resource_id'] = '{{ item.resource_id }}'
        
        # Add NEW fields from THIS discovery's response
        if main_output and available_fields:
            # If response has a main structure, access it
            for field in available_fields[:5]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ {python_method}_response.{main_output}.{field} }}}}'
        elif available_fields:
            # Direct fields from response
            for field in available_fields[:5]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ {python_method}_response.{field} }}}}'
    
    discovery['emit'] = emit
    
    return discovery


def generate_check(rule: Dict, discovery_id: str) -> Dict:
    """
    Generate check YAML section.
    
    Args:
        rule: Validated rule data
        discovery_id: Which discovery to use
    
    Returns:
        Check dict ready for YAML
    """
    rule_id = rule['rule_id']
    fields = rule['ai_generated_requirements']['fields']
    condition_logic = rule['ai_generated_requirements'].get('condition_logic', 'single')
    
    check = {
        'rule_id': rule_id,
        'for_each': discovery_id
    }
    
    # Build conditions
    if condition_logic == 'single' and len(fields) == 1:
        field = fields[0]
        field_name = _to_snake_case(field['boto3_python_field'])
        
        check['conditions'] = {
            'var': f'item.{field_name}',
            'op': field['operator']
        }
        
        # ALWAYS add value (even for exists operator, for clarity)
        value = field.get('boto3_python_field_expected_values')
        if value is not None:
            check['conditions']['value'] = value
    
    elif condition_logic in ['all', 'any']:
        # Multiple conditions
        check['conditions'] = {condition_logic: []}
        
        for field in fields:
            field_name = _to_snake_case(field['boto3_python_field'])
            cond = {
                'var': f'item.{field_name}',
                'op': field['operator']
            }
            
            # ALWAYS add value if provided
            value = field.get('boto3_python_field_expected_values')
            if value is not None:
                cond['value'] = value
            elif field['operator'] == 'exists':
                # For exists operator, value can be omitted
                pass
            else:
                # Default value based on operator
                if field['operator'] == 'equals':
                    cond['value'] = None  # Will need manual review
            
            check['conditions'][condition_logic].append(cond)
    
    return check


def infer_parameter_type(param_name: str) -> str:
    """
    Infer parameter type from parameter name.
    
    Returns: 'list', 'string', 'dict', or 'unknown'
    """
    param_lower = param_name.lower()
    
    # List/array indicators (check first, as they're more specific)
    list_indicators = ['ids', 'arns', 'names', 'keys', 'values', 'items', 'list', 'array', 
                      'executions', 'queries', 'statements', 'resources', 'results']
    if any(indicator in param_lower for indicator in list_indicators):
        return 'list'
    
    # Dict/object indicators
    dict_indicators = ['config', 'settings', 'attributes', 'details', 'tags', 'metadata', 
                      'policy', 'parameters', 'options', 'specification']
    if any(indicator in param_lower for indicator in dict_indicators):
        return 'dict'
    
    # String indicators (most common - default)
    # Most parameters are strings unless explicitly list/dict
    return 'string'


def infer_field_type(field_name: str) -> str:
    """
    Infer field type from field name.
    
    Returns: 'list', 'string', 'dict', 'datetime', or 'unknown'
    """
    field_lower = field_name.lower()
    
    # List/array indicators (check first, as they're more specific)
    list_indicators = ['ids', 'arns', 'names', 'list', 'array', 'items', 'groups', 'tags', 
                      'executions', 'queries', 'statements', 'resources', 'results']
    if any(indicator in field_lower for indicator in list_indicators):
        return 'list'
    
    # Dict/object indicators
    dict_indicators = ['config', 'settings', 'attributes', 'details', 'metadata', 'policy', 
                      'parameters', 'options', 'specification', 'configuration']
    if any(indicator in field_lower for indicator in dict_indicators):
        return 'dict'
    
    # Datetime indicators
    datetime_indicators = ['date', 'time', 'timestamp', 'created', 'modified', 'updated', 
                          'lastmodified', 'creation', 'expiration']
    if any(indicator in field_lower for indicator in datetime_indicators):
        return 'datetime'
    
    # String (default - most fields are strings)
    return 'string'


def find_parent_discovery(service: str, required_params: List[str], all_discoveries: Dict, boto3_service_data: Dict, current_function: str = '') -> str:
    """
    Find which discovery can provide the required parameters.
    
    SYSTEMATIC APPROACH:
    1. Identify primary LIST/DESCRIBE/GET functions (independent) for each service
    2. For required fields, look at both dependent and independent functions
    3. If independent, use directly
    4. If dependent, prioritize those derived from primary LIST/DESCRIBE/GET functions
    
    Args:
        service: Service name
        required_params: List of parameter names needed
        all_discoveries: Already created discoveries
        boto3_service_data: Boto3 data for this service
        current_function: Current function name for context
    
    Returns:
        Parent discovery_id or None
    """
    # STEP 1: Identify primary LIST/DESCRIBE/GET functions (independent)
    # These are the root discovery functions that don't depend on others
    primary_independent_discoveries = []
    dependent_discoveries_list = []
    
    for discovery_id, discovery_data in all_discoveries.items():
        func_data = discovery_data.get('_function_data', {})
        required_params = func_data.get('required_params', [])
        python_method = func_data.get('python_method', '').lower()
        
        # Check if already linked (has for_each) - means it's dependent
        if discovery_data.get('for_each'):
            dependent_discoveries_list.append(discovery_id)
        # Check if has required params (will be dependent)
        elif required_params:
            # Check if all required params are optional (effectively independent)
            optional_only_params = ['maxresults', 'nexttoken', 'paginationtoken', 'maxitems', 'limit']
            required_lower = [p.lower() for p in required_params]
            is_effectively_independent = all(any(opt in p for opt in optional_only_params) for p in required_lower)
            
            if not is_effectively_independent:
                dependent_discoveries_list.append(discovery_id)
            elif python_method.startswith(('list_', 'describe_', 'get_')):
                # Effectively independent LIST/DESCRIBE/GET = primary
                primary_independent_discoveries.append(discovery_id)
        # No required params = independent
        elif python_method.startswith(('list_', 'describe_', 'get_')):
            # Primary functions are LIST/DESCRIBE/GET that are independent
            primary_independent_discoveries.append(discovery_id)
    
    # STEP 2: Build field-to-discovery mapping
    # Map each field to which discovery(ies) can provide it
    field_to_discoveries = {}  # field_name -> [(discovery_id, is_primary, depth), ...]
    
    def get_all_fields(discovery_data):
        """Get all fields emitted by a discovery"""
        func_data = discovery_data.get('_function_data', {})
        item_fields = func_data.get('item_fields', [])
        available_fields = func_data.get('available_fields', [])
        return list(set(item_fields + available_fields))
    
    # First, map fields from primary independent discoveries (depth 0)
    for discovery_id in primary_independent_discoveries:
        discovery_data = all_discoveries[discovery_id]
        fields = get_all_fields(discovery_data)
        for field in fields:
            field_lower = field.lower()
            if field_lower not in field_to_discoveries:
                field_to_discoveries[field_lower] = []
            field_to_discoveries[field_lower].append((discovery_id, True, 0))
    
    # Then, map fields from dependent discoveries (depth 1+)
    # These depend on primary discoveries, so they're secondary sources
    # Note: At this point, dependent discoveries may not have for_each set yet
    # So we'll treat them as depth 1 (they will depend on a primary)
    for discovery_id in dependent_discoveries_list:
        discovery_data = all_discoveries[discovery_id]
        fields = get_all_fields(discovery_data)
        
        # Check if already has parent (for_each set)
        parent_id = discovery_data.get('for_each')
        if parent_id and parent_id in all_discoveries:
            parent_data = all_discoveries[parent_id]
            # If parent is also dependent, this is depth 2
            if parent_data.get('for_each'):
                depth = 2  # Grandchild of primary
            else:
                depth = 1  # Child of primary
        else:
            depth = 1  # Will be child of primary (not linked yet)
        
        for field in fields:
            field_lower = field.lower()
            if field_lower not in field_to_discoveries:
                field_to_discoveries[field_lower] = []
            field_to_discoveries[field_lower].append((discovery_id, False, depth))
    
    # STEP 3: For each required parameter, find best matching discovery
    # Priority: 1) Primary independent, 2) Dependent from primary, 3) Others
    best_matches = []  # [(discovery_id, score, match_type), ...]
    
    # Direct parameter → function name mapping (most reliable)
    # restApiId → get_rest_apis, bucketName → list_buckets, etc.
    param_to_function_hints = {
        'restApiId': ['rest_api', 'restapis', 'get_rest'],
        'restApi': ['rest_api', 'restapis', 'get_rest'],
        'bucketName': ['bucket', 'list_bucket', 'get_bucket'],
        'bucket': ['bucket', 'list_bucket', 'get_bucket'],
        'analyzerArn': ['analyzer', 'list_analyzer', 'get_analyzer'],
        'analyzerId': ['analyzer', 'list_analyzer', 'get_analyzer'],
        'tableName': ['table', 'list_table', 'get_table'],
        'queueName': ['queue', 'list_queue', 'get_queue'],
        'streamName': ['stream', 'list_stream', 'get_stream'],
        'workGroupName': ['work_group', 'workgroup', 'list_work'],
        'workGroup': ['work_group', 'workgroup', 'list_work'],
    }
    
    for param in required_params:
        param_lower = param.lower()
        param_original = param  # Keep original for camelCase splitting
        matches = []
        
        # Strategy 0: Direct parameter → function name mapping (highest priority)
        if param in param_to_function_hints or param_lower in param_to_function_hints:
            hints = param_to_function_hints.get(param, param_to_function_hints.get(param_lower, []))
            for hint in hints:
                for discovery_id, discovery_data in all_discoveries.items():
                    if discovery_data.get('for_each'):
                        continue
                    func_data = discovery_data.get('_function_data', {})
                    python_method = func_data.get('python_method', '').lower()
                    if hint.lower() in python_method:
                        # Verify it has the required field
                        fields = get_all_fields(discovery_data)
                        field_lower = param_lower.replace('api', '').replace('arn', '').replace('name', '').replace('id', '').strip('_')
                        if 'id' in [f.lower() for f in fields] or any(f.lower() in param_lower for f in fields):
                            is_primary = discovery_id in primary_independent_discoveries
                            score = 120 if is_primary else 70  # Highest priority score
                            matches.append((discovery_id, score, 'direct_mapping'))
                            break  # Found match, move to next hint
                if matches:
                    break  # Found match for this param, move to next param
        
        # Try exact field match first
        if param_lower in field_to_discoveries:
            for discovery_id, is_primary, depth in field_to_discoveries[param_lower]:
                score = 100 if is_primary else (50 - depth * 10)  # Primary gets highest score
                matches.append((discovery_id, score, 'exact'))
        
        # Try parameter ends with field name (e.g., restApiId → id)
        # BUT: Use semantic context to prefer better matches
        if not matches:
            for field_lower, discovery_list in field_to_discoveries.items():
                if param_lower.endswith(field_lower) or field_lower in param_lower:
                    # Extract semantic context from parameter name
                    # restApiId → remove 'id' → 'restapi' → split camelCase → ['rest', 'api']
                    import re
                    # Use ORIGINAL param to preserve camelCase: restApiId → restApi (not restapi)
                    # Remove field from original (try both capitalized and lowercase)
                    field_variants = [field_lower, field_lower.capitalize(), field_lower.upper()]
                    param_without_field = param_original
                    for variant in field_variants:
                        param_without_field = param_without_field.replace(variant, '')
                    param_without_field = param_without_field.strip('_').strip('-')
                    
                    # Split camelCase: restApiId → ['rest', 'api', 'id'] → remove 'id' → ['rest', 'api']
                    # Split snake_case: rest_api_id → ['rest', 'api', 'id'] → remove 'id' → ['rest', 'api']
                    if '_' in param_without_field:
                        param_words = set([w for w in param_without_field.split('_') if w and w != field_lower])
                    else:
                        # Split camelCase properly: restApi → ['rest', 'Api'] → ['rest', 'api']
                        # Insert space before each capital letter
                        camel_split = re.sub('([a-z])([A-Z])', r'\1 \2', param_without_field)
                        # Also handle capitals at start
                        camel_split = re.sub('([A-Z][a-z]+)', r' \1', camel_split)
                        # Split and filter
                        camel_parts = camel_split.split()
                        param_words = set([w.lower() for w in camel_parts if w.lower() != field_lower and len(w) > 2])
                        
                        # Fallback: if no words extracted, try splitting on any capital
                        if not param_words and param_without_field:
                            # Try simple split: find where lowercase meets uppercase
                            import string
                            words = []
                            current_word = ''
                            for char in param_without_field:
                                if char.isupper() and current_word:
                                    words.append(current_word.lower())
                                    current_word = char
                                else:
                                    current_word += char
                            if current_word:
                                words.append(current_word.lower())
                            param_words = set([w for w in words if w != field_lower and len(w) > 2])
                    
                    for discovery_id, is_primary, depth in discovery_list:
                        discovery_data = all_discoveries[discovery_id]
                        func_data = discovery_data.get('_function_data', {})
                        python_method = func_data.get('python_method', '').lower()
                        method_words = set(python_method.split('_'))
                        
                        # Base score
                        base_score = 80 if is_primary else (40 - depth * 10)
                        
                        # Boost score if semantic context matches
                        # restApiId → ['rest', 'api'] → should match get_rest_apis (has 'rest' and 'api')
                        if param_words and method_words:
                            # Normalize plurals: 'apis' → 'api', 'buckets' → 'bucket'
                            normalized_method_words = set()
                            for w in method_words:
                                if w.endswith('s') and len(w) > 3:
                                    normalized_method_words.add(w[:-1])  # Remove 's'
                                normalized_method_words.add(w)
                            
                            overlap = param_words & normalized_method_words
                            # Also check substring matches (api in apis, bucket in buckets)
                            for param_word in param_words:
                                for method_word in method_words:
                                    if param_word in method_word or method_word in param_word:
                                        overlap.add(param_word)
                            
                            if len(overlap) >= 2:  # At least 2 words match (e.g., 'rest' and 'api')
                                base_score += 20  # Boost for semantic match
                        
                        matches.append((discovery_id, base_score, 'partial'))
        
        # Try semantic matching: parameter name → function name
        # restApiId → look for functions with 'rest' and 'api' in name
        if not matches:
            param_words = set(param_lower.replace('id', '').replace('arn', '').replace('name', '').split('_'))
            param_words.discard('')
            
            for discovery_id, discovery_data in all_discoveries.items():
                if discovery_data.get('for_each'):
                    continue
                
                func_data = discovery_data.get('_function_data', {})
                python_method = func_data.get('python_method', '').lower()
                method_words = set(python_method.split('_'))
                
                # Check if method words overlap with param words (semantic match)
                overlap = param_words & method_words
                if len(overlap) >= 2:  # At least 2 words match
                    fields = get_all_fields(discovery_data)
                    # Check if it has a matching field (id, name, arn)
                    if any(f.lower() in ['id', 'name', 'arn'] for f in fields):
                        is_primary = discovery_id in primary_independent_discoveries
                        score = 60 if is_primary else 30
                        matches.append((discovery_id, score, 'semantic'))
        
        if matches:
            # Sort by score (highest first)
            matches.sort(key=lambda x: x[1], reverse=True)
            # If multiple matches have same highest score, prefer semantic match
            if len(matches) > 1 and matches[0][1] == matches[1][1]:
                # Check if any have semantic boost (higher score indicates semantic match)
                semantic_matches = [m for m in matches if m[1] > 80]  # Semantic boost adds 20
                if semantic_matches:
                    best_matches.extend(semantic_matches[:1])
                else:
                    best_matches.extend(matches[:1])
            else:
                best_matches.extend(matches[:1])  # Take best match for this param
    
    # STEP 4: Select best overall match
    if best_matches:
        # Group by discovery_id and sum scores
        discovery_scores = {}
        for discovery_id, score, match_type in best_matches:
            if discovery_id not in discovery_scores:
                discovery_scores[discovery_id] = {'score': 0, 'types': []}
            discovery_scores[discovery_id]['score'] += score
            discovery_scores[discovery_id]['types'].append(match_type)
        
        # Return discovery with highest score
        best_discovery = max(discovery_scores.items(), key=lambda x: x[1]['score'])
        return best_discovery[0]
    
    # STEP 5: Fallback to first primary independent discovery
    if primary_independent_discoveries:
        return primary_independent_discoveries[0]
    
    # STEP 6: Last resort: any independent discovery
    for discovery_id, discovery_data in all_discoveries.items():
        if not discovery_data.get('for_each'):
            return discovery_id
    
    return None


def generate_yaml_for_service(service: str, rules: List[Dict], boto3_data: Dict) -> Dict:
    """
    Generate complete YAML structure for a service.
    
    Args:
        service: Service name
        rules: List of validated rules for this service
        boto3_data: Boto3 catalog
    
    Returns:
        Complete YAML structure
    """
    yaml_structure = {
        'version': '1.0',
        'provider': 'aws',
        'service': service,
        'discovery': [],
        'checks': []
    }
    
    # Track discoveries
    discoveries = {}  # discovery_id -> discovery_dict
    independent_discoveries = []
    dependent_discoveries = []
    
    # Helper: Check if function is effectively independent (optional params only)
    def is_effectively_independent_func(func):
        """Check if function should be treated as independent despite having params"""
        required = func.get('required_params', [])
        if not required:
            return True
        # Check if all required params are actually optional (MaxResults, NextToken, etc.)
        optional_only_params = ['maxresults', 'nexttoken', 'paginationtoken', 'maxitems', 'limit']
        required_lower = [p.lower() for p in required]
        return all(any(opt in p for opt in optional_only_params) for p in required_lower)
    
    # First pass: Create all discoveries
    for rule in rules:
        if not rule.get('validated_function'):
            continue
        
        func = rule['validated_function']
        python_method = func['python_method']
        discovery_id = f'aws.{service}.{python_method}'
        
        if discovery_id not in discoveries:
            discovery = generate_discovery_for_function(service, func, discovery_id)
            discovery['_function_data'] = func  # Store for parent lookup
            discoveries[discovery_id] = discovery
            
            # Use effective independence check
            if func['is_independent'] or is_effectively_independent_func(func):
                independent_discoveries.append(discovery_id)
                # Remove for_each if it was set (should be independent)
                if 'for_each' in discovery:
                    del discovery['for_each']
                # Remove params if only optional params (MaxResults, etc.)
                if 'params' in discovery.get('calls', [{}])[0]:
                    params = discovery['calls'][0]['params']
                    # Remove optional-only params
                    optional_params = ['MaxResults', 'NextToken', 'PaginationToken', 'MaxItems', 'Limit']
                    if all(p in optional_params for p in params.keys()):
                        del discovery['calls'][0]['params']
            else:
                dependent_discoveries.append(discovery_id)
    
    # Second pass: Link dependent discoveries to parents
    for disc_id in dependent_discoveries:
        discovery = discoveries[disc_id]
        func_data = discovery['_function_data']
        required_params = func_data.get('required_params', [])
        current_function = func_data.get('python_method', '')
        
        # Find parent (pass current function for semantic matching)
        parent_id = find_parent_discovery(service, required_params, discoveries, boto3_data.get(service, {}), current_function)
        
        if parent_id:
            # Update for_each
            discovery['for_each'] = parent_id
            
            # Update params to reference parent fields
            if 'params' in discovery['calls'][0]:
                parent_func = discoveries[parent_id]['_function_data']
                parent_fields = parent_func.get('available_fields', [])
                
                for param in required_params:
                    # Infer parameter type
                    param_type = infer_parameter_type(param)
                    
                    # Smart matching patterns
                    matched_field = None
                    matched_field_type = None
                    
                    # Pattern 1: Exact match (case-insensitive)
                    for field in parent_fields:
                        if field.lower() == param.lower():
                            matched_field = field
                            matched_field_type = infer_field_type(field)
                            break
                    
                    # Pattern 2: Parameter ends with field name
                    # analyzerArn → arn, bucketName → name, Bucket → name
                    if not matched_field:
                        for field in parent_fields:
                            if param.lower().endswith(field.lower()):
                                matched_field = field
                                matched_field_type = infer_field_type(field)
                                break
                    
                    # Pattern 3: Field name in parameter
                    if not matched_field:
                        for field in parent_fields:
                            if field.lower() in param.lower():
                                matched_field = field
                                matched_field_type = infer_field_type(field)
                                break
                    
                    # Pattern 4: Special cases
                    if not matched_field:
                        # Bucket parameter usually maps to Name field in list_buckets
                        if param.lower() == 'bucket' and 'Name' in parent_fields:
                            matched_field = 'Name'
                            matched_field_type = 'string'
                        elif param.lower() == 'bucket' and 'name' in parent_fields:
                            matched_field = 'name'
                            matched_field_type = 'string'
                    
                    # Pattern 5: Resource type parameter → Name field
                    # Common pattern: WorkGroup, Table, Queue, Stream → Name field
                    if not matched_field:
                        resource_types = ['group', 'bucket', 'table', 'queue', 'stream', 
                                         'vault', 'detector', 'domain', 'cluster', 'server']
                        if any(rt in param.lower() for rt in resource_types) and 'Name' in parent_fields:
                            matched_field = 'Name'
                            matched_field_type = 'string'
                    
                    # Pattern 6: Parameter ends with resource type → Name field
                    # WorkGroupName, TableName, BucketName → Name
                    if not matched_field:
                        if 'Name' in parent_fields and (
                            param.lower().endswith('name') or 
                            param.lower().endswith('group') or
                            param.lower() in ['bucket', 'table', 'queue', 'workgroup']
                        ):
                            matched_field = 'Name'
                            matched_field_type = 'string'
                    
                    # Pattern 7: Type-aware matching for list parameters
                    # If parameter expects list, look for array/list fields
                    if not matched_field and param_type == 'list':
                        # Look for fields that might be arrays
                        for field in parent_fields:
                            field_type = infer_field_type(field)
                            if field_type == 'list' or any(indicator in field.lower() for indicator in ['ids', 'arns', 'names', 'list']):
                                # Check if field name matches parameter concept
                                if any(indicator in field.lower() for indicator in [p.replace('ids', '').replace('arns', '').replace('names', '') for p in [param.lower()]]):
                                    matched_field = field
                                    matched_field_type = 'list'
                                    break
                    
                    # Type validation: Check if types match
                    if matched_field and param_type != 'unknown' and matched_field_type != 'unknown':
                        if param_type == 'list' and matched_field_type != 'list':
                            # Parameter expects list but field is not a list
                            # Try to find array field or use single value in list format
                            print(f"   ⚠️  Type mismatch: parameter '{param}' expects {param_type}, but field '{matched_field}' is {matched_field_type}")
                            # For now, still use the field but note the issue
                            # In future, could wrap in list: [{{ item.field }}]
                    
                    if matched_field:
                        field_snake = _to_snake_case(matched_field)
                        
                        # Handle list parameters - if param expects list but field is string
                        if param_type == 'list' and matched_field_type == 'string':
                            # Some APIs accept single string in list format, but better to find array field
                            # For now, use the field as-is (boto3 may handle conversion)
                            discovery['calls'][0]['params'][param] = f'{{{{ item.{field_snake} }}}}'
                            print(f"   ⚠️  Parameter '{param}' expects list, using string field '{matched_field}'")
                        else:
                            discovery['calls'][0]['params'][param] = f'{{{{ item.{field_snake} }}}}'
                    else:
                        # Last resort: try common identifier fields
                        common_id_fields = ['name', 'id', 'Name', 'Id', 'resource_id']
                        fallback_field = None
                        for field in common_id_fields:
                            if field in parent_fields:
                                fallback_field = field
                                break
                        
                        if fallback_field:
                            field_snake = _to_snake_case(fallback_field)
                            param_value = f'{{{{ item.{field_snake} }}}}'
                            
                            # Validate and add error handling for potentially problematic parameters
                            if not validate_parameter_format(param, param_value):
                                if 'on_error' not in discovery['calls'][0]:
                                    discovery['calls'][0]['on_error'] = 'continue'
                            
                            discovery['calls'][0]['params'][param] = param_value
                            print(f"   ⚠️  Used fallback field '{fallback_field}' for parameter '{param}'")
                        else:
                            # Couldn't match - use 'name' as last resort (most common)
                            param_value = '{{ item.name }}'
                            
                            # Add error handling for unmatched parameters
                            if 'on_error' not in discovery['calls'][0]:
                                discovery['calls'][0]['on_error'] = 'continue'
                            
                            discovery['calls'][0]['params'][param] = param_value
                            print(f"   ⚠️  Could not match parameter '{param}', using 'name' as fallback")
        
        # Remove helper data
        del discovery['_function_data']
    
    # Remove helper data from independent
    for disc_id in independent_discoveries:
        if '_function_data' in discoveries[disc_id]:
            del discoveries[disc_id]['_function_data']
    
    # Generate checks
    for rule in rules:
        if not rule.get('validated_function'):
            continue
        
        func = rule['validated_function']
        discovery_id = f'aws.{service}.{func['python_method']}'
        check = generate_check(rule, discovery_id)
        yaml_structure['checks'].append(check)
    
    # Add discoveries (independent first, then dependent)
    for disc_id in independent_discoveries:
        yaml_structure['discovery'].append(discoveries[disc_id])
    for disc_id in dependent_discoveries:
        yaml_structure['discovery'].append(discoveries[disc_id])
    
    return yaml_structure


def _to_snake_case(name: str) -> str:
    """Convert PascalCase/camelCase to snake_case"""
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def main():
    print("=" * 80)
    print("AGENT 4: YAML Generator")
    print("=" * 80)
    print("Generating YAML from validated requirements")
    print()
    
    # Load data
    print("Loading data...")
    boto3_data = load_boto3_catalog()
    requirements = load_validated_requirements()
    print("✅ Loaded")
    
    # Generate YAML for each service
    for service, rules in requirements.items():
        print(f"\n📦 {service}")
        
        # Count valid rules
        valid_rules = [r for r in rules if r.get('all_fields_valid')]
        print(f"   Valid rules: {len(valid_rules)}/{len(rules)}")
        
        if not valid_rules:
            print(f"   ⚠️  No valid rules, skipping")
            continue
        
        # Generate YAML
        yaml_structure = generate_yaml_for_service(service, valid_rules, boto3_data)
        
        print(f"   Discoveries: {len(yaml_structure['discovery'])}")
        print(f"   Checks: {len(yaml_structure['checks'])}")
        
        # Save YAML
        output_file = f'output/{service}_generated.yaml'
        
        # Convert to YAML format
        import yaml
        with open(output_file, 'w') as f:
            yaml.dump(yaml_structure, f, default_flow_style=False, sort_keys=False)
        
        print(f"   ✅ Saved: {output_file}")
    
    print("\n" + "=" * 80)
    print("✅ YAML GENERATION COMPLETE")
    print("=" * 80)
    print("\nGenerated YAML files:")
    print("  output/*_generated.yaml")
    print("\nNext: Review and copy to services/*/rules/*.yaml")


if __name__ == '__main__':
    main()
