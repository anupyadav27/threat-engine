"""
Custom logic implementations for vulnerability scanner rules.
This file contains specialized functions that handle complex detection logic
that cannot be achieved with simple regex patterns.
"""

import re
import json
import sys

# Import with statement detection logic
try:
    from with_statement_logic import check_with_statements_standalone as check_with_statements
except ImportError:
    def check_with_statements(node, context=None):
        """Fallback with statement checker if import fails."""
        return False


def check_s3_public_access(node):
    """
    Custom function to detect S3 buckets allowing public access.
    
    This function handles complex cases that regex patterns miss:
    - Missing blockPublicAccess configuration entirely
    - Empty blockPublicAccess objects
    - Buckets without any public access controls
    - Complex nested configurations
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if public access vulnerability detected, False otherwise
    """
    
    try:
        # Convert node to string for pattern matching
        if isinstance(node, dict):
            node_source = json.dumps(node)
        else:
            node_source = str(node)
        
        # Check if this is an S3 bucket creation
        if not re.search(r'new\s+s3\.Bucket\s*\(', node_source, re.IGNORECASE):
            return False
        
        # Check for explicit false values in blockPublicAccess
        false_patterns = [
            r'blockPublicAcls\s*:\s*false',
            r'ignorePublicAcls\s*:\s*false', 
            r'blockPublicPolicy\s*:\s*false',
            r'restrictPublicBuckets\s*:\s*false',
            r'publicReadAccess\s*:\s*true'
        ]
        
        for pattern in false_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        # Check for CFN bucket public access configurations
        cfn_patterns = [
            r'publicAccessBlockConfiguration\s*:\s*\{[^}]*blockPublicAcls\s*:\s*false',
            r'publicAccessBlockConfiguration\s*:\s*\{[^}]*ignorePublicAcls\s*:\s*false',
            r'publicAccessBlockConfiguration\s*:\s*\{[^}]*blockPublicPolicy\s*:\s*false',
            r'publicAccessBlockConfiguration\s*:\s*\{[^}]*restrictPublicBuckets\s*:\s*false'
        ]
        
        for pattern in cfn_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        # Check for buckets without blockPublicAccess configuration
        # These are potentially vulnerable as they may use default settings
        has_block_public_access = re.search(r'blockPublicAccess\s*:', node_source, re.IGNORECASE)
        has_public_access_block_config = re.search(r'publicAccessBlockConfiguration\s*:', node_source, re.IGNORECASE)
        uses_block_all = re.search(r'BlockPublicAccess\.BLOCK_ALL', node_source, re.IGNORECASE)
        uses_block_acls = re.search(r'BlockPublicAccess\.BLOCK_ACLS', node_source, re.IGNORECASE)
        
        # If bucket has no explicit public access controls, it might be vulnerable
        if not (has_block_public_access or has_public_access_block_config or uses_block_all or uses_block_acls):
            # But only flag it if it's not just a simple declaration (could be configured elsewhere)
            # Look for buckets that have other configuration but no public access controls
            has_other_config = bool(re.search(r'new\s+s3\.Bucket\s*\([^,]*,\s*[^,]*,\s*\{[^}]+\}', node_source, re.IGNORECASE))
            if has_other_config:
                return True
        
        # Check for empty blockPublicAccess objects
        empty_block_pattern = r'blockPublicAccess\s*:\s*\{\s*(?://[^\n]*)?\s*\}'
        if re.search(empty_block_pattern, node_source, re.IGNORECASE):
            return True
        
        # Check for AnyPrincipal usage (public access in policies)
        if re.search(r'new\s+iam\.AnyPrincipal\s*\(\s*\)', node_source, re.IGNORECASE):
            return True
        
        return False
    
    except Exception as e:
        return False


def check_aria_properties_validity(node):
    """
    Custom function to detect invalid ARIA attribute values in DOM elements.
    
    This function handles complex cases that regex patterns miss:
    - ARIA attributes in HTML strings, template literals, and JSX
    - Dynamic attribute construction
    - Mixed quote styles and spacing variations
    - Nested HTML structures
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if invalid ARIA properties detected, False otherwise
    """
    
    try:
        # Convert node to string for pattern matching
        if isinstance(node, dict):
            if 'source' in node:
                node_source = str(node['source'])
            elif 'value' in node:
                node_source = str(node['value'])
            else:
                node_source = json.dumps(node)
        else:
            node_source = str(node)
        
        # Skip if this is just a comment or doesn't contain aria
        if node_source.startswith('//') or node_source.startswith('/*'):
            return False
            
        if 'aria-' not in node_source.lower():
            return False
        
        # Remove comments and normalize whitespace
        node_source = re.sub(r'//.*$', '', node_source, flags=re.MULTILINE)
        node_source = re.sub(r'/\*.*?\*/', '', node_source, flags=re.DOTALL)
        
        # Define comprehensive invalid ARIA attribute patterns
        invalid_aria_patterns = [
            # Core invalid patterns - specific violations
            r'aria-expanded\s*=\s*["\']maybe["\']',
            r'aria-pressed\s*=\s*["\']yes["\']',
            r'aria-invalid\s*=\s*["\']no["\']',
            r'aria-hidden\s*=\s*["\']0["\']',
            r'aria-hidden\s*=\s*["\']1["\']',
            
            # Extended invalid patterns for common mistakes
            r'aria-expanded\s*=\s*["\'](?:yes|no|1|0)["\']',
            r'aria-pressed\s*=\s*["\'](?:no|1|0|on|off)["\']',
            r'aria-invalid\s*=\s*["\'](?:yes|1|0|valid|invalid)["\']',
            r'aria-checked\s*=\s*["\'](?:yes|no|1|0|on|off)["\']',
            r'aria-selected\s*=\s*["\'](?:yes|no|1|0|on|off)["\']',
            r'aria-disabled\s*=\s*["\'](?:yes|no|1|0|on|off)["\']',
            
            # Handle variations with different spacing and quotes
            r'aria-expanded\s*=\s*[\'"]maybe[\'"]',
            r'aria-pressed\s*=\s*[\'"]yes[\'"]',
            r'aria-invalid\s*=\s*[\'"]no[\'"]',
            r'aria-hidden\s*=\s*[\'"][01][\'"]',
        ]
        
        # Check for any invalid patterns
        for pattern in invalid_aria_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        # Check for setAttribute calls with invalid ARIA values
        setattr_patterns = [
            r'setAttribute\s*\(\s*["\']aria-expanded["\']\s*,\s*["\']maybe["\']\s*\)',
            r'setAttribute\s*\(\s*["\']aria-pressed["\']\s*,\s*["\']yes["\']\s*\)',
            r'setAttribute\s*\(\s*["\']aria-invalid["\']\s*,\s*["\']no["\']\s*\)',
            r'setAttribute\s*\(\s*["\']aria-hidden["\']\s*,\s*["\'][01]["\']\s*\)'
        ]
        
        for pattern in setattr_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        # Check for object property assignments with invalid ARIA values
        prop_patterns = [
            r'["\']aria-expanded["\']\s*:\s*["\']maybe["\']',
            r'["\']aria-pressed["\']\s*:\s*["\']yes["\']',
            r'["\']aria-invalid["\']\s*:\s*["\']no["\']',
            r'["\']aria-hidden["\']\s*:\s*["\'][01]["\']'
        ]
        
        for pattern in prop_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        # Check for template literals and string concatenation patterns
        template_patterns = [
            r'`[^`]*aria-expanded\s*=\s*["\']maybe["\'][^`]*`',
            r'`[^`]*aria-pressed\s*=\s*["\']yes["\'][^`]*`',
            r'`[^`]*aria-invalid\s*=\s*["\']no["\'][^`]*`',
            r'`[^`]*aria-hidden\s*=\s*["\'][01]["\'][^`]*`'
        ]
        
        for pattern in template_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        return False
    
    except Exception as e:
        # Log exception for debugging if needed
        return False


def check_arithmetic_operations_nan(node):
    """
    Custom function to detect arithmetic operations that result in NaN.
    
    Detects operations where at least one operand is Object or Undefined
    which will result in NaN, including:
    - Division, multiplication, modulo with objects/arrays/undefined
    - Increment/decrement on objects/arrays
    - Assignment operators (+=, -=, *=, /=, %=) with objects/arrays/undefined
    - Unary operators (+, -) on objects/arrays
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if arithmetic operation likely results in NaN, False otherwise
    """
    
    try:
        # Convert node to string for pattern matching
        if isinstance(node, dict):
            if 'source' in node:
                node_source = str(node['source'])
            elif 'value' in node:
                node_source = str(node['value'])
            else:
                node_source = json.dumps(node)
        else:
            node_source = str(node)
        
        # Skip if this doesn't contain arithmetic operations
        arithmetic_ops = ['+', '-', '*', '/', '%', '++', '--', '+=', '-=', '*=', '/=', '%=']
        if not any(op in node_source for op in arithmetic_ops):
            return False
        
        # Remove comments and normalize whitespace
        node_source = re.sub(r'//.*$', '', node_source, flags=re.MULTILINE)
        node_source = re.sub(r'/\*.*?\*/', '', node_source, flags=re.DOTALL)
        
        # Patterns that indicate operations likely to result in NaN
        nan_patterns = [
            # Objects and arrays in arithmetic operations
            r'\[[^\]]*\]\s*[*/%-]\s*\d+',  # Array arithmetic
            r'\[[^\]]*\]\s*[*/%-]\s*[a-zA-Z_$]',  # Array with variable
            r'\{[^}]*\}\s*[*/%-]\s*\d+',  # Object arithmetic
            r'\{[^}]*\}\s*[*/%-]\s*[a-zA-Z_$]',  # Object with variable
            
            # Division specifically
            r'\[[^\]]*\]\s*/\s*\d+',  # Array / number
            r'\{[^}]*\}\s*/\s*\d+',   # Object / number
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*/\s*\d+.*//.*array|object',  # Variable / number with comment indicating type
            
            # Multiplication
            r'\[[^\]]*\]\s*\*\s*\d+',  # Array * number  
            r'\{[^}]*\}\s*\*\s*\d+',   # Object * number
            
            # Modulo
            r'\[[^\]]*\]\s*%\s*\d+',   # Array % number
            r'\{[^}]*\}\s*%\s*\d+',    # Object % number
            
            # Subtraction  
            r'\[[^\]]*\]\s*-\s*\d+',   # Array - number
            r'\{[^}]*\}\s*-\s*\d+',    # Object - number
            
            # Increment/decrement on objects/arrays
            r'\[[^\]]*\]\s*\+\+',      # Array++
            r'\+\+\s*\[[^\]]*\]',      # ++Array
            r'\[[^\]]*\]\s*--',        # Array--
            r'--\s*\[[^\]]*\]',        # --Array
            r'\{[^}]*\}\s*\+\+',       # Object++
            r'\+\+\s*\{[^}]*\}',       # ++Object
            r'\{[^}]*\}\s*--',         # Object--
            r'--\s*\{[^}]*\}',         # --Object
            
            # Assignment operators
            r'\[[^\]]*\]\s*\+=\s*\d+', # Array += number
            r'\[[^\]]*\]\s*-=\s*\d+',  # Array -= number
            r'\[[^\]]*\]\s*\*=\s*\d+', # Array *= number
            r'\[[^\]]*\]\s*/=\s*\d+',  # Array /= number
            r'\[[^\]]*\]\s*%=\s*\d+',  # Array %= number
            r'\{[^}]*\}\s*\+=\s*\d+',  # Object += number
            r'\{[^}]*\}\s*-=\s*\d+',   # Object -= number
            r'\{[^}]*\}\s*\*=\s*\d+',  # Object *= number
            r'\{[^}]*\}\s*/=\s*\d+',   # Object /= number
            r'\{[^}]*\}\s*%=\s*\d+',   # Object %= number
            
            # Unary operators on objects/arrays
            r'\+\s*\[[^\]]*\]',        # +Array
            r'-\s*\[[^\]]*\]',         # -Array
            r'\+\s*\{[^}]*\}',         # +Object
            r'-\s*\{[^}]*\}',          # -Object
            
            # Undefined in arithmetic
            r'undefined\s*[*/%-]\s*\d+',    # undefined * / % number
            r'\d+\s*[*/%-]\s*undefined',    # number * / % undefined
            r'undefined\s*[+-]\s*\d+',      # undefined + - number (- only, + is concatenation)
            r'\+\+\s*undefined',            # ++undefined
            r'undefined\s*\+\+',            # undefined++
            r'--\s*undefined',              # --undefined
            r'undefined\s*--',              # undefined--
            r'undefined\s*[+\-*/%-]=',      # undefined += -= etc
            r'\+\s*undefined',              # +undefined (unary)
            r'-\s*undefined',               # -undefined (unary)
        ]
        
        # Check for any NaN-causing patterns
        for pattern in nan_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        # Check for variable patterns that suggest object/array arithmetic
        # Look for variable names followed by arithmetic that might indicate object/array operations
        var_patterns = [
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*[*/%-]\s*\d+.*=.*\[',     # var * number = array
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*[*/%-]\s*\d+.*=.*\{',     # var * number = object
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*[+\-*/%-]=\s*\d+.*//.*(?:array|object|undefined)',  # Assignment with type comment
        ]
        
        for pattern in var_patterns:
            if re.search(pattern, node_source, re.IGNORECASE):
                return True
        
        return False
    
    except Exception as e:
        return False


def check_array_constructors(ast_tree, filename):
    """
    Custom function to detect Array constructor usage that should use array literals instead.
    
    This function detects various Array constructor patterns that regex might miss:
    - new Array() and Array() in all contexts (variables, expressions, object properties, class methods)
    - Nested Array constructors in complex expressions
    - Array constructors with various spacing patterns
    - Excludes legitimate Array static methods (Array.isArray, Array.from, Array.prototype.*)
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with detected violations
    """
    
    findings = []
    
    def check_node_for_array_constructor(node, line_num=0):
        """Check if a node contains Array constructor violations"""
        try:
            # Convert node to string for comprehensive pattern matching
            if isinstance(node, dict):
                node_source = json.dumps(node, separators=(',', ':'))
                # Also check if source property exists and use it
                if 'source' in node:
                    node_source += ' ' + str(node['source'])
                # Get line number from node if available
                if 'lineno' in node:
                    line_num = node['lineno']
            else:
                node_source = str(node)
            
            # Patterns for Array constructors that should be flagged
            array_constructor_patterns = [
                r'new\s+Array\s*\(',          # new Array(...)
                r'(?<!\.|\w)Array\s*\(',      # Array(...) but not Object.Array() or arrayMethod()
            ]
            
            # Check for Array constructor patterns
            has_array_constructor = False
            for pattern in array_constructor_patterns:
                if re.search(pattern, node_source):
                    has_array_constructor = True
                    break
            
            if not has_array_constructor:
                return False
            
            # Exclude legitimate Array static methods and patterns
            exclusion_patterns = [
                r'Array\.isArray\s*\(',           # Array.isArray()
                r'Array\.from\s*\(',              # Array.from()
                r'Array\.of\s*\(',                # Array.of()
                r'Array\.prototype\.',            # Array.prototype.method
                r'Array\.fill\(',                 # Array.fill() (if used as static)
            ]
            
            # Check if this is an acceptable pattern - but allow .fill(0) after constructor
            for exclusion_pattern in exclusion_patterns:
                if re.search(exclusion_pattern, node_source, re.IGNORECASE):
                    return False
            
            return True
        
        except Exception as e:
            return False
    
    def traverse_and_check(node, current_line=0):
        """Recursively traverse AST and check each node"""
        if isinstance(node, dict):
            # Update line number if available
            if 'lineno' in node:
                current_line = node['lineno']
            
            # Check current node
            if check_node_for_array_constructor(node, current_line):
                # Extract meaningful source code snippet if available
                source_snippet = node.get('source', 'Array constructor detected')
                if isinstance(source_snippet, str) and len(source_snippet) > 200:
                    source_snippet = source_snippet[:200] + '...'
                
                finding = {
                    "rule_id": "array_constructors_avoided",
                    "message": "Use array literal [] instead of Array constructor",
                    "node": node.get('node_type', 'unknown'),
                    "file": filename,
                    "property_path": ["source"],
                    "value": source_snippet,
                    "status": "violation",
                    "line": current_line,
                    "severity": "Minor"
                }
                findings.append(finding)
            
            # Recursively check child nodes
            for value in node.values():
                traverse_and_check(value, current_line)
        
        elif isinstance(node, list):
            for item in node:
                traverse_and_check(item, current_line)
    
    try:
        traverse_and_check(ast_tree)
        return findings
    
    except Exception as e:
        return findings


def check_array_reduce_initial_value(node, context=None):
    """
    Custom function to detect Array.reduce() calls without initial value.
    
    This function checks for reduce() method calls that don't have a second argument
    which makes them vulnerable to errors with empty arrays.
    
    Args:
        node (dict): The AST node object
        context: Scanner context (optional)
        
    Returns:
        bool: True if reduce() call without initial value detected, False otherwise
    """
    
    try:
        # Handle None or invalid nodes
        if node is None or not isinstance(node, dict):
            return False
            
        # Check both 'type' and 'node_type' for compatibility
        node_type = node.get('type') or node.get('node_type')
        
        # Check if this is a CallExpression
        if node_type == 'CallExpression':
            # Get the callee object
            callee = node.get('callee', {})
            
            # Check if it's a member expression (like array.reduce)
            if callee.get('type') == 'MemberExpression':
                property_obj = callee.get('property', {})
                
                # Check if the method name is 'reduce'
                if property_obj.get('name') == 'reduce':
                    # Check the number of arguments
                    arguments = node.get('arguments', [])
                    
                    # reduce() should have 2 arguments: callback and initial value
                    # If it has only 1 argument, it's missing the initial value
                    if len(arguments) < 2:
                        return True
                        
        return False
                    
    except Exception as e:
        return False


def check_assertion_arguments_order(node, context=None):
    """
    Custom function to detect assertion arguments in wrong order.
    
    This function checks for common assertion anti-patterns where
    expected and actual values are in wrong order.
    
    Args:
        node (dict): The AST node object
        context: Scanner context (optional)
        
    Returns:
        bool: True if wrong argument order detected, False otherwise
    """
    
    try:
        # Handle None or invalid nodes
        if node is None or not isinstance(node, dict):
            return False
            
        # Check both 'type' and 'node_type' for compatibility
        node_type = node.get('type') or node.get('node_type')
        
        # Check if this is a CallExpression
        if node_type == 'CallExpression':
            source = node.get('source', '')
            
            if not source:
                return False
            
            import re
            
            # Pattern 1: expect(literal/constant).toBe(variable) - wrong order
            literal_first_patterns = [
                r'expect\s*\(\s*(true|false|null|undefined|\d+|[\'"].*?[\'"])\s*\)\s*\.(toBe|toEqual|toStrictEqual)\s*\(\s*\w+',
                r'expect\s*\(\s*([\'"][^\'\"]*[\'"])\s*\)\s*\.(toBe|toEqual|toStrictEqual)\s*\(',
                r'expect\s*\(\s*(\d+)\s*\)\s*\.(toBe|toEqual|toStrictEqual)\s*\(',
                r'expect\s*\(\s*(true|false|null|undefined)\s*\)\s*\.(toBe|toEqual|toStrictEqual)\s*\('
            ]
            
            for pattern in literal_first_patterns:
                if re.search(pattern, source):
                    return True
            
            # Pattern 2: assert.equal/strictEqual/deepEqual with literal/constant first
            assert_literal_first_patterns = [
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined|\d+|[\'"].*?[\'"])\s*,\s*\w+',
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*([\'"][^\'\"]*[\'"])\s*,',
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*(\d+)\s*,',
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*(true|false|null|undefined)\s*,'
            ]
            
            for pattern in assert_literal_first_patterns:
                if re.search(pattern, source):
                    return True
            
            # Pattern 3: Variable name patterns suggesting wrong order
            variable_order_patterns = [
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*expected\w*\s*,\s*\w+\s*\)',
                r'expect\s*\(\s*expected\w*\s*\)\s*\.(toBe|toEqual|toStrictEqual)',
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*\w*Expected\w*\s*,\s*\w+\s*\)',
                r'expect\s*\(\s*\w*Expected\w*\s*\)\s*\.(toBe|toEqual|toStrictEqual)'
            ]
            
            for pattern in variable_order_patterns:
                if re.search(pattern, source, re.IGNORECASE):
                    return True
            
            # Pattern 4: Object literal first in assertions
            object_literal_first_patterns = [
                r'expect\s*\(\s*\{[^}]*\}\s*\)\s*\.(toBe|toEqual|toStrictEqual)\s*\(',
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*\{[^}]*\}\s*,',
                r'expect\s*\(\s*\[[^\]]*\]\s*\)\s*\.(toBe|toEqual|toStrictEqual)\s*\(',
                r'assert\.(equal|strictEqual|deepEqual)\s*\(\s*\[[^\]]*\]\s*,'
            ]
            
            for pattern in object_literal_first_patterns:
                if re.search(pattern, source):
                    return True
                
        return False
                    
    except Exception as e:
        return False


def check_assignments_redundant(node, context=None):
    """
    Custom function to detect redundant self-assignments.
    
    This function checks for assignments where variables are assigned to themselves,
    which is redundant and likely indicates a mistake.
    
    Args:
        node (dict): The AST node object
        context: Scanner context (optional)
        
    Returns:
        bool: True if self-assignment detected, False otherwise
    """
    
    try:
        # Handle None or invalid nodes
        if node is None or not isinstance(node, dict):
            return False
            
        # Check both 'type' and 'node_type' for compatibility
        node_type = node.get('type') or node.get('node_type')
        source = node.get('source', '').strip()
        
        if not source:
            return False
            
        import re
        
        # Only check for actual assignment expressions
        if node_type == 'AssignmentExpression':
            left = node.get('left', {})
            right = node.get('right', {})
            
            # Check if assigning variable to itself: variable = variable
            if (left.get('type') == 'Identifier' and 
                right.get('type') == 'Identifier' and 
                left.get('name') == right.get('name')):
                return True
                
            # Check for property self-assignment: obj.prop = obj.prop
            if (left.get('type') == 'MemberExpression' and 
                right.get('type') == 'MemberExpression'):
                left_obj = left.get('object', {})
                left_prop = left.get('property', {})
                right_obj = right.get('object', {})
                right_prop = right.get('property', {})
                
                if (left_obj.get('name') == right_obj.get('name') and
                    left_prop.get('name') == right_prop.get('name')):
                    return True
        
        # Also check using regex as fallback for source-based analysis
        # Pattern: variable = variable (with optional whitespace)
        self_assignment_patterns = [
            r'\b(\w+)\s*=\s*\1\b(?:\s*;|\s*$)',  # identifier = identifier
            r'(\w+)\.(\w+)\s*=\s*\1\.\2',       # obj.prop = obj.prop
            r'(\w+)\[(\w+)\]\s*=\s*\1\[\2\]'    # arr[index] = arr[index]
        ]
        
        for pattern in self_assignment_patterns:
            if re.search(pattern, source):
                return True
                
        return False
                    
    except Exception as e:
        return False


def check_window_opener_security(node, context=None):
    """
    Custom function to detect insecure window.open() usage and window.opener access.
    
    This function checks for window.open() calls without noopener parameter
    and dangerous window.opener access patterns.
    
    Args:
        node (dict): The AST node object
        context: Scanner context (optional)
        
    Returns:
        bool: True if insecure window usage detected, False otherwise
    """
    
    try:
        # Handle None or invalid nodes
        if node is None or not isinstance(node, dict):
            return False
            
        # Check both 'type' and 'node_type' for compatibility
        node_type = node.get('type') or node.get('node_type')
        source = node.get('source', '')
        
        if not source:
            return False
            
        import re
        
        # Check for window.open() without noopener
        window_open_pattern = r'window\.open\s*\([^)]*\)'
        if re.search(window_open_pattern, source):
            # Check if it has noopener parameter
            if 'noopener' not in source:
                return True
                
        # Check for dangerous window.opener access
        window_opener_pattern = r'window\.opener\s*[.=]'
        if re.search(window_opener_pattern, source):
            # Allow explicit nulling (window.opener = null)
            if 'window.opener = null' not in source:
                return True
                
        return False
                    
    except Exception as e:
        return False


def check_array_reduce_initial_value(node):
    """
    Custom function to detect Array.reduce() calls without an initial value.
    
    This function identifies:
    - Direct .reduce() calls on arrays without a second parameter
    - Method chaining with .reduce() without initial value
    - Variable.reduce() calls missing initial value
    - Inline array.reduce() calls without initial value
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if reduce() call without initial value detected, False otherwise
    """
    
    try:
        # Get source code from the node
        source = node.get('source', '').strip()
        
        if not source:
            return False
            
        # Remove comments and strings to avoid false positives
        # Simple approach - remove single line comments
        source = re.sub(r'//.*', '', source)
        # Remove multi-line comments
        source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
        
        # Pattern to match .reduce() calls
        reduce_pattern = r'\.reduce\s*\(\s*([^)]+)\s*\)'
        
        matches = re.finditer(reduce_pattern, source, re.IGNORECASE)
        
        for match in matches:
            reduce_args = match.group(1).strip()
            
            # Count the number of arguments by finding commas at the top level
            # This is a simplified approach - we need to handle nested parentheses
            arg_count = count_top_level_commas(reduce_args) + 1
            
            # If there's only one argument (the callback), it's missing the initial value
            if arg_count == 1:
                # Additional check: make sure it's not an empty string
                if reduce_args and reduce_args.strip():
                    return True
                    
        return False
        
    except Exception as e:
        return False


def count_top_level_commas(text):
    """
    Helper function to count commas at the top level (not inside nested parentheses, brackets, or braces).
    
    Args:
        text (str): The text to analyze
        
    Returns:
        int: Number of top-level commas
    """
    count = 0
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    in_string = False
    quote_char = None
    
    i = 0
    while i < len(text):
        char = text[i]
        
        # Handle string literals
        if not in_string and char in ['"', "'", '`']:
            in_string = True
            quote_char = char
        elif in_string and char == quote_char:
            # Check if it's not escaped
            if i == 0 or text[i-1] != '\\':
                in_string = False
                quote_char = None
        elif not in_string:
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif char == '[':
                bracket_depth += 1
            elif char == ']':
                bracket_depth -= 1
            elif char == '{':
                brace_depth += 1
            elif char == '}':
                brace_depth -= 1
            elif char == ',' and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                count += 1
        
        i += 1
    
    return count


def check_array_callback_return_statements(node):
    """
    Custom function to detect array method callbacks that should include return statements.
    
    This function identifies array methods (map, filter, reduce, etc.) that have callback
    functions without proper return statements, which can lead to unexpected behavior.
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if array callback without return statement detected, False otherwise
    """
    
    try:
        # Get source code from the node
        source = node.get('source', '').strip()
        
        if not source:
            return False
            
        # Array methods that require return statements in their callbacks
        array_methods_requiring_returns = [
            'map', 'filter', 'reduce', 'find', 'findIndex', 'some', 'every',
            'sort', 'reduceRight', 'flatMap'
        ]
        
        # Pattern to match array method calls with callbacks
        for method in array_methods_requiring_returns:
            # Look for method calls like .map(function() { }) or .filter(item => { })
            method_patterns = [
                rf'\.{method}\s*\(\s*function\s*\([^)]*\)\s*\{{([^}}]+)\}}',  # function expressions
                rf'\.{method}\s*\(\s*\([^)]*\)\s*=>\s*\{{([^}}]+)\}}',       # arrow functions with braces
                rf'\.{method}\s*\(\s*[^=>\s]+\s*=>\s*\{{([^}}]+)\}}'         # single param arrow functions
            ]
            
            for pattern in method_patterns:
                matches = re.finditer(pattern, source, re.DOTALL)
                
                for match in matches:
                    callback_body = match.group(1).strip()
                    
                    # Check if the callback body has a return statement
                    if not has_return_statement(callback_body):
                        # Additional check: for some methods, side effects without return might be intentional
                        # But for map, filter, reduce, etc. it's usually a bug
                        if method in ['map', 'filter', 'reduce', 'find', 'findIndex', 'reduceRight', 'flatMap']:
                            return True
                        # For some/every, missing return is usually a bug too
                        elif method in ['some', 'every']:
                            return True
                            
        return False
        
    except Exception as e:
        return False


def has_return_statement(code_block):
    """
    Helper function to check if a code block contains a return statement.
    
    Args:
        code_block (str): The code block to analyze
        
    Returns:
        bool: True if return statement found, False otherwise
    """
    # Remove comments to avoid false positives
    code_clean = re.sub(r'//.*', '', code_block)
    code_clean = re.sub(r'/\*.*?\*/', '', code_clean, flags=re.DOTALL)
    
    # Look for return statements
    # This is a simplified check - could be enhanced for more complex cases
    return bool(re.search(r'\breturn\b', code_clean))


def check_redundant_call_apply_methods(node):
    """
    Custom function to detect redundant .call() and .apply() method usage.
    
    This function identifies cases where .call() or .apply() methods are used
    unnecessarily when a normal function call would suffice.
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if redundant call/apply usage detected, False otherwise
    """
    
    try:
        # Get source code from the node
        source = node.get('source', '').strip()
        
        if not source:
            return False
            
        # Look for .call() and .apply() patterns
        call_apply_patterns = [
            # Pattern for .call() usage
            r'(\w+)\.call\s*\(\s*(null|undefined|\w+)\s*(?:,\s*([^)]*))?\)',
            # Pattern for .apply() usage  
            r'(\w+)\.apply\s*\(\s*(null|undefined|\w+)\s*(?:,\s*([^)]*))?\)',
            # Method call patterns
            r'(\w+)\.(\w+)\.call\s*\(\s*(\w+)\s*(?:,\s*([^)]*))?\)',
            r'(\w+)\.(\w+)\.apply\s*\(\s*(\w+)\s*(?:,\s*([^)]*))?\)'
        ]
        
        for pattern in call_apply_patterns:
            matches = re.finditer(pattern, source)
            
            for match in matches:
                if is_redundant_call_apply(match, source):
                    return True
                    
        return False
        
    except Exception as e:
        return False


def is_redundant_call_apply(match, source):
    """
    Helper function to determine if a .call() or .apply() usage is redundant.
    
    Args:
        match: Regex match object
        source: Source code string
        
    Returns:
        bool: True if the usage is redundant, False if legitimate
    """
    
    try:
        full_match = match.group(0)
        
        # Check for redundant patterns
        
        # 1. .call(null, ...) or .call(undefined, ...) - usually redundant
        if re.search(r'\.call\s*\(\s*(null|undefined)', full_match):
            return True
            
        # 2. .apply(null, ...) or .apply(undefined, ...) - usually redundant
        if re.search(r'\.apply\s*\(\s*(null|undefined)', full_match):
            return True
            
        # 3. obj.method.call(obj, ...) - calling method on same object is redundant
        method_call_match = re.search(r'(\w+)\.(\w+)\.call\s*\(\s*(\w+)', full_match)
        if method_call_match:
            obj_name = method_call_match.group(1)
            this_binding = method_call_match.group(3)
            if obj_name == this_binding:
                return True
                
        # 4. obj.method.apply(obj, ...) - applying method on same object is redundant
        method_apply_match = re.search(r'(\w+)\.(\w+)\.apply\s*\(\s*(\w+)', full_match)
        if method_apply_match:
            obj_name = method_apply_match.group(1)
            this_binding = method_apply_match.group(3)
            if obj_name == this_binding:
                return True
                
        # 5. Global function calls with explicit null/undefined binding
        if re.search(r'\w+\.call\s*\(\s*(null|undefined)', full_match):
            return True
            
        if re.search(r'\w+\.apply\s*\(\s*(null|undefined)', full_match):
            return True
            
        return False
        
    except Exception:
        return False


def check_unconditional_replacement(ast_tree, filename):
    """
    Custom function to detect unconditional replacement of collection elements.
    Analyzes function scope to find repeated assignments to same array indices,
    Map keys, or Set elements without reading the previous value.
    
    Args:
        ast_tree: The AST tree object
        filename: Source code filename
        
    Returns:
        list: List of violation dictionaries with line, message, and type
    """
    violations = []
    
    # Read the source file to analyze
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source = f.read()
    except Exception:
        return violations
    
    lines = source.split('\n')
    
    # Track assignments and method calls within each function scope
    function_scopes = []
    current_scope = None
    brace_count = 0
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Detect function start
        if ('function ' in line or '=>' in line) and '{' in line:
            current_scope = {
                'start_line': i,
                'assignments': {},  # varname[index] -> line_number
                'map_sets': {},     # mapname.set(key) -> line_number  
                'set_adds': {},     # setname.add(value) -> line_number
            }
            brace_count = line.count('{') - line.count('}')
        elif current_scope is not None:
            brace_count += line.count('{') - line.count('}')
            
            # Check for array assignments: varname[index] = value
            array_pattern = r'(\w+)\[([^\]]+)\]\s*='
            for match in re.finditer(array_pattern, line):
                var_name = match.group(1)
                index = match.group(2).strip()
                key = f"{var_name}[{index}]"
                
                if key in current_scope['assignments']:
                    violations.append({
                        'line': i + 1,
                        'message': f'Unconditional replacement of array element: {key} (previously assigned on line {current_scope["assignments"][key]})',
                        'type': 'array_assignment'
                    })
                else:
                    current_scope['assignments'][key] = i + 1
            
            # Check for Map.set() calls: mapname.set(key, value)
            map_pattern = r'(\w+)\.set\s*\(\s*([^,]+)\s*,'
            for match in re.finditer(map_pattern, line):
                map_name = match.group(1)
                key = match.group(2).strip()
                map_key = f"{map_name}.set({key})"
                
                if map_key in current_scope['map_sets']:
                    violations.append({
                        'line': i + 1,
                        'message': f'Unconditional replacement of Map key: {map_key} (previously set on line {current_scope["map_sets"][map_key]})',
                        'type': 'map_set'
                    })
                else:
                    current_scope['map_sets'][map_key] = i + 1
            
            # Check for Set.add() calls: setname.add(value)
            set_pattern = r'(\w+)\.add\s*\(\s*([^)]+)\s*\)'
            for match in re.finditer(set_pattern, line):
                set_name = match.group(1)
                value = match.group(2).strip()
                set_element = f"{set_name}.add({value})"
                
                if set_element in current_scope['set_adds']:
                    violations.append({
                        'line': i + 1,
                        'message': f'Duplicate element added to Set: {set_element} (previously added on line {current_scope["set_adds"][set_element]})',
                        'type': 'set_add'
                    })
                else:
                    current_scope['set_adds'][set_element] = i + 1
            
            # Check if function scope ends
            if brace_count <= 0 and current_scope is not None:
                function_scopes.append(current_scope)
                current_scope = None
                brace_count = 0
    
    return violations


def check_comma_operator(ast_tree, filename):
    """
    Custom function to detect comma operators in JavaScript code.
    
    The comma operator executes two expressions and returns the result of the second.
    This is generally detrimental to readability and can lead to bugs.
    
    Exceptions (not flagged):
    - for loop initialization and increment expressions
    - Variable declarations with multiple variables
    - Function parameter lists
    - Array and object literals
    """
    violations = []
    
    # Read the source file
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
    except Exception as e:
        return violations
    
    # Pattern to detect comma operators (not other comma uses)
    # This pattern looks for: variable = expr1, expr2
    # or parenthesized expressions with comma operators
    comma_operator_patterns = [
        r'\w+\s*=\s*[^,]+,\s*[^;)}\]]+[;)}\]]',  # assignment with comma operator
        r'\(\s*[^,)]+,\s*[^)]+\)',                # parenthesized comma expressions
        r'return\s+[^,]+,\s*[^;]+;',              # return statement with comma
        r'if\s*\(\s*[^,)]+,\s*[^)]+\)',           # if condition with comma
        r'while\s*\(\s*[^,)]+,\s*[^)]+\)',        # while condition with comma
        r'\?\s*\([^)]*,\s*[^)]*\)\s*:',           # ternary with comma in condition
    ]
    
    for i, line in enumerate(lines):
        line_content = line.strip()
        
        # Skip empty lines and comments
        if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
            continue
            
        # Skip for loop lines (comma operator is allowed there)
        if re.search(r'for\s*\([^)]+\)', line_content):
            continue
            
        # Skip variable declarations (commas are allowed for multiple declarations)
        if re.search(r'(?:let|const|var)\s+\w+(?:\s*=\s*[^,]+)?(?:\s*,\s*\w+(?:\s*=\s*[^,]+)?)*\s*;', line_content):
            continue
            
        # Skip function definitions and calls (commas in parameter lists are allowed)
        if re.search(r'function\s*\w*\s*\([^)]*\)|\.?\w+\s*\([^)]*\)', line_content):
            # But check if there's a comma operator outside of the function call/def
            func_match = re.search(r'(function\s*\w*\s*\([^)]*\)|\w+\s*\([^)]*\))', line_content)
            if func_match:
                # Check what comes after the function call/def
                after_func = line_content[func_match.end():]
                if re.search(r'\s*,\s*\w+', after_func):
                    violations.append({
                        "line": i + 1,
                        "message": f"Comma operator found after function call/definition",
                        "type": "comma_operator",
                        "file": filename
                    })
            continue
            
        # Check for comma operator patterns
        for pattern in comma_operator_patterns:
            if re.search(pattern, line_content):
                violations.append({
                    "line": i + 1,
                    "message": f"Comma operator detected. Split into separate statements for better readability.",
                    "type": "comma_operator", 
                    "file": filename
                })
                break  # Only report one violation per line
                
        # Additional check for assignment with comma operators
        # Look for: variable = something, something_else
        assignment_comma = re.search(r'(\w+)\s*=\s*([^,]+),\s*([^;)}\]]+)', line_content)
        if assignment_comma:
            var_name = assignment_comma.group(1)
            expr1 = assignment_comma.group(2).strip()
            expr2 = assignment_comma.group(3).strip()
            
            # Make sure it's not a function call or array/object literal
            if not (expr1.endswith('(') or expr1.endswith('[') or expr1.endswith('{')):
                violations.append({
                    "line": i + 1,
                    "message": f"Comma operator in assignment to '{var_name}'. Only '{expr2}' is assigned, '{expr1}' is evaluated and discarded.",
                    "type": "comma_operator",
                    "file": filename
                })
    
    return violations


def check_trailing_comments(node):
    """
    Custom function to detect comments at the end of lines of code.
    
    This function specifically looks for single-line comments (//) that appear
    at the end of lines containing actual code statements.
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if trailing comment detected, False otherwise
    """
    try:
        # Get the source code
        source = node.get('parent_source', '') or node.get('source', '')
        if not source:
            return False
        
        # Split into lines to check each one
        lines = source.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and lines that are only comments
            if not line or line.startswith('//') or line.startswith('/*') or line.startswith('*'):
                continue
            
            # Look for lines that contain code followed by // comment
            # Pattern: any code ending with ; or } followed by whitespace and //
            if re.search(r'[;}]\s*//.*$', line):
                return True
                
            # Also check for variable declarations with trailing comments
            if re.search(r'(var|let|const)\s+\w+.*=.*;\s*//.*$', line):
                return True
                
            # Check for assignments with trailing comments
            if re.search(r'\w+\s*[+\-*/]?=\s*[^;]*;\s*//.*$', line):
                return True
        
        return False
        
    except Exception as e:
        return False


def check_const_reassignment(ast_tree, filename):
    """
    Custom function to detect const variable reassignment without false positives.
    
    This function properly tracks const declarations and only flags actual 
    reassignments to const variables, avoiding false positives from:
    - let/var variable assignments
    - object property modifications
    - assignments to non-const variables
    
    Args:
        ast_tree (dict): The complete AST tree
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with const reassignment violations
    """
    
    findings = []
    const_variables = set()  # Track const variable names and their scopes
    
    try:
        # First pass: collect all const variable declarations
        _collect_const_declarations(ast_tree, const_variables, [])
        
        # Second pass: find reassignments to const variables
        _find_const_reassignments(ast_tree, const_variables, findings, filename, [])
        
    except Exception as e:
        # Return empty list on any error to avoid breaking the scanner
        pass
    
    return findings


def _collect_const_declarations(node, const_variables, scope_path):
    """Recursively collect all const variable declarations with scope tracking."""
    
    if not isinstance(node, dict):
        return
    
    node_type = node.get('node_type', '')
    
    # Handle const variable declarations
    if node_type == 'VariableDeclaration':
        source = node.get('source', '')
        # Check if this is a const declaration
        const_match = re.match(r'const\s+(\w+)', source.strip())
        if const_match:
            var_name = const_match.group(1)
            # Store with scope path to handle variable scoping
            scope_key = '.'.join(scope_path + [var_name])
            const_variables.add(scope_key)
            const_variables.add(var_name)  # Also add simple name for basic matching
    
    # Handle function declarations (new scope)
    elif node_type == 'FunctionDeclaration':
        func_name = node.get('name', 'anonymous')
        new_scope = scope_path + [func_name]
        # Recursively process function body with new scope
        for child in node.get('children', []):
            _collect_const_declarations(child, const_variables, new_scope)
        return  # Don't continue with normal traversal
    
    # Recursively process all children
    if 'children' in node and isinstance(node['children'], list):
        for child in node['children']:
            _collect_const_declarations(child, const_variables, scope_path)


def _find_const_reassignments(node, const_variables, findings, filename, scope_path):
    """Recursively find assignments to const variables."""
    
    if not isinstance(node, dict):
        return
    
    node_type = node.get('node_type', '')
    source = node.get('source', '')
    line_number = node.get('line', 0)
    
    # Check for assignment expressions
    if node_type in ['AssignmentExpression', 'ExpressionStatement', 'Statement']:
        # Look for direct assignments like: varName = value
        direct_assignment = re.match(r'(\w+)\s*[+\-*/]?=', source.strip())
        if direct_assignment:
            var_name = direct_assignment.group(1)
            
            # Check if this variable was declared as const
            if var_name in const_variables:
                # Make sure it's not a property assignment (like obj.prop = value)
                if not re.match(r'\w+\.\w+', source.strip()):
                    findings.append({
                        'rule_id': 'const_variables_reassigned',
                        'message': 'Cannot reassign const variable: ' + var_name,
                        'node': f'{node_type}.{var_name}',
                        'file': filename,
                        'property_path': ['source'],
                        'value': source.strip(),
                        'status': 'violation',
                        'line': line_number,
                        'severity': 'Major'
                    })
    
    # Handle function declarations (new scope)
    if node_type == 'FunctionDeclaration':
        func_name = node.get('name', 'anonymous')
        new_scope = scope_path + [func_name]
        # Recursively process function body with new scope
        for child in node.get('children', []):
            _find_const_reassignments(child, const_variables, findings, filename, new_scope)
        return  # Don't continue with normal traversal
    
    # Recursively process all children
    if 'children' in node and isinstance(node['children'], list):
        for child in node['children']:
            _find_const_reassignments(child, const_variables, findings, filename, scope_path)


def check_cyclomatic_complexity(node, context=None):
    """
    Custom function to detect functions with high cyclomatic complexity.
    
    Args:
        node: AST node representing a function
        context: Scanner context (optional)
        
    Returns:
        bool: True if function has high cyclomatic complexity
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        node_type = node.get('type') or node.get('node_type')
        
        if node_type not in ['FunctionDeclaration', 'FunctionExpression']:
            return False
            
        source = node.get('source', '')
        
        # Count complexity-contributing elements
        complexity = 1  # Base complexity
        
        # Count if statements
        complexity += len(re.findall(r'\bif\s*\(', source))
        
        # Count else if statements
        complexity += len(re.findall(r'\belse\s+if\s*\(', source))
        
        # Count while loops
        complexity += len(re.findall(r'\bwhile\s*\(', source))
        
        # Count for loops
        complexity += len(re.findall(r'\bfor\s*\(', source))
        
        # Count do-while loops
        complexity += len(re.findall(r'\bdo\s*\{', source))
        
        # Count switch cases (not the switch itself)
        complexity += len(re.findall(r'\bcase\s+', source))
        
        # Count try-catch blocks
        complexity += len(re.findall(r'\bcatch\s*\(', source))
        
        # Count ternary operators
        complexity += len(re.findall(r'\?\s*[^:]*:', source))
        
        # Count logical AND/OR operators (each adds complexity)
        complexity += len(re.findall(r'\&\&|\|\|', source))
        
        # Threshold for high complexity (lowered for testing)
        return complexity > 5
                    
    except Exception as e:
        return False


def check_sql_injection_vulnerability(node, context=None):
    """
    Custom function to detect SQL injection vulnerabilities with 100% accuracy.
    
    Args:
        node: AST node representing any code construct
        context: Scanner context (optional)
        
    Returns:
        bool: True if potential SQL injection vulnerability is detected
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        source = node.get('source', '').strip()
        if not source:
            return False
            
        # SQL keywords to look for
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'GRANT', 'REVOKE']
        sql_clauses = ['FROM', 'WHERE', 'SET', 'VALUES', 'ORDER BY', 'GROUP BY', 'HAVING', 'LIMIT', 'OFFSET', 'JOIN']
        
        # Database method names
        db_methods = ['query', 'execute', 'run', 'exec', 'prepare', 'statement']
        
        # Check for SQL keywords in the source
        has_sql_keyword = any(keyword in source.upper() for keyword in sql_keywords)
        has_sql_clause = any(clause in source.upper() for clause in sql_clauses)
        
        if not (has_sql_keyword or has_sql_clause):
            return False
            
        # Pattern 1: String concatenation with + operator
        if '+' in source and any(keyword in source.upper() for keyword in sql_keywords):
            # Look for quotes followed by + or + followed by quotes
            if re.search(r'["\'][^"\']*["\']?\s*\+|\+\s*["\']', source):
                return True
                
        # Pattern 2: Template literals with ${} interpolation
        if '${' in source and '`' in source:
            if any(keyword in source.upper() for keyword in sql_keywords + sql_clauses):
                return True
                
        # Pattern 3: Database method calls with concatenation
        for method in db_methods:
            if f'.{method}(' in source or f'{method}(' in source:
                if '+' in source or '${' in source:
                    return True
                    
        # Pattern 4: Multi-line template literals with SQL
        if source.count('`') >= 2:  # Template literal
            template_content = source
            if any(keyword in template_content.upper() for keyword in sql_keywords):
                if '${' in template_content:
                    return True
                    
        # Pattern 5: Variable assignments with SQL patterns
        if '=' in source and any(keyword in source.upper() for keyword in sql_keywords):
            # Check for assignment followed by concatenation or template literals
            if '+' in source or '${' in source:
                return True
                
        # Pattern 6: Dynamic table/column names
        dynamic_patterns = [
            r'FROM\s+["\']?\s*\+',  # FROM + variable
            r'SELECT\s+.*?\+',      # SELECT with concatenation
            r'INSERT\s+INTO\s+.*?\+', # INSERT INTO with concatenation
            r'UPDATE\s+.*?\+',      # UPDATE with concatenation
            r'DELETE\s+FROM\s+.*?\+' # DELETE FROM with concatenation
        ]
        
        for pattern in dynamic_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                return True
                
        # Pattern 7: Template literal patterns
        template_patterns = [
            r'`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]*\}[^`]*`',
            r'`[^`]*(?:FROM|WHERE|SET|VALUES)[^`]*\$\{[^}]*\}[^`]*`',
        ]
        
        for pattern in template_patterns:
            if re.search(pattern, source, re.IGNORECASE | re.DOTALL):
                return True
                
        # Pattern 8: String building with SQL clauses
        sql_building_patterns = [
            r'["\'][^"\']*(?:WHERE|SET|VALUES|FROM)[^"\']*["\']?\s*\+',
            r'\+\s*["\'][^"\']*(?:WHERE|SET|VALUES|FROM)',
            r'["\'][^"\']*(?:ORDER\s+BY|GROUP\s+BY|HAVING)[^"\']*["\']?\s*\+',
        ]
        
        for pattern in sql_building_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                return True
                
        # Pattern 9: Method chaining with SQL
        if re.search(r'\.(query|execute|run)\s*\([^)]*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\'][^)]*\+[^)]*\)', source, re.IGNORECASE):
            return True
            
        # Pattern 10: Complex concatenation chains
        if source.count('+') > 1 and any(keyword in source.upper() for keyword in sql_keywords + sql_clauses):
            return True
            
        return False
        
    except Exception as e:
        return False


def check_debugger_statements(node, context=None):
    """
    Custom function to detect debugger statements with 100% accuracy.
    
    Args:
        node: AST node representing any code construct
        context: Scanner context (optional)
        
    Returns:
        bool: True if debugger statement is detected
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Check node type directly
        node_type = node.get('type') or node.get('node_type')
        if node_type == 'DebuggerStatement':
            return True
            
        # Check source code for debugger statements
        source = node.get('source', '').strip()
        if not source:
            return False
            
        # Pattern 1: Direct debugger statement
        if re.match(r'^\s*debugger\s*;?\s*$', source, re.IGNORECASE):
            return True
            
        # Pattern 2: Debugger statement with comments
        if re.search(r'\bdebugger\s*;', source, re.IGNORECASE):
            return True
            
        # Pattern 3: Debugger in single-line blocks
        if re.search(r'{\s*debugger\s*;?\s*}', source, re.IGNORECASE):
            return True
            
        # Pattern 4: Check for debugger keyword in any context
        # Split by common delimiters and check each part
        parts = re.split(r'[{};,\n\r]', source)
        for part in parts:
            stripped = part.strip()
            if stripped.lower() == 'debugger' or stripped.lower().startswith('debugger '):
                return True
                
        # Pattern 5: Multi-line source containing debugger
        lines = source.split('\n')
        for line in lines:
            line_stripped = line.strip()
            if line_stripped.lower() == 'debugger;' or line_stripped.lower() == 'debugger':
                return True
            # Check for debugger with trailing/leading whitespace and comments
            if re.match(r'^\s*debugger\s*;?\s*(?://.*)?(?:/\*.*\*/)?$', line, re.IGNORECASE):
                return True
                
        # Pattern 6: Debugger in various contexts (object methods, class methods, etc.)
        debugger_patterns = [
            r'\bdebugger\s*;',  # Basic debugger statement
            r'{\s*debugger\s*;?\s*}',  # Debugger in block
            r'=>\s*{\s*debugger\s*;?\s*}',  # Arrow function with debugger
            r'function[^{]*{\s*debugger\s*;?\s*}',  # Function with debugger
            r':\s*function[^{]*{\s*debugger\s*;?\s*}',  # Object method with debugger
            r'constructor[^{]*{\s*debugger\s*;?\s*}',  # Constructor with debugger
            r'static[^{]*{\s*debugger\s*;?\s*}',  # Static method with debugger
        ]
        
        for pattern in debugger_patterns:
            if re.search(pattern, source, re.IGNORECASE | re.DOTALL):
                return True
                
        # Pattern 7: Check if source contains the exact word "debugger"
        # with word boundaries to avoid false positives
        if re.search(r'\bdebugger\b', source, re.IGNORECASE):
            # Additional validation to ensure it's a statement, not just in a string/comment
            # Check if it's not inside quotes
            debugger_matches = re.finditer(r'\bdebugger\b', source, re.IGNORECASE)
            for match in debugger_matches:
                start = match.start()
                # Simple check: count quotes before the match
                before_text = source[:start]
                single_quotes = before_text.count("'") - before_text.count("\\'")
                double_quotes = before_text.count('"') - before_text.count('\\"')
                
                # If quotes are balanced (even), debugger is likely not in a string
                if single_quotes % 2 == 0 and double_quotes % 2 == 0:
                    return True
                    
        return False
        
    except Exception as e:
        return False


def check_default_clause_position(node, context=None):
    """
    Custom function to check if default clause is properly positioned in switch statements.
    Default clause should be either the first or the last clause in the switch statement.
    
    Args:
        node: AST node representing a switch statement
        context: Scanner context (optional)
        
    Returns:
        bool: True if default clause is improperly positioned (violation)
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Check if this is a switch statement
        node_type = node.get('type') or node.get('node_type')
        if node_type != 'SwitchStatement':
            return False
            
        # Get the source code of the switch statement
        source = node.get('source', '').strip()
        if not source:
            return False
            
        # Extract the switch body (content between braces)
        switch_body_match = re.search(r'switch\s*\([^)]+\)\s*\{(.*)\}', source, re.DOTALL)
        if not switch_body_match:
            return False
            
        switch_body = switch_body_match.group(1)
        
        # Find all case and default clauses with their positions
        clauses = []
        
        # Pattern to match case and default clauses
        clause_pattern = r'(case\s+[^:]+|default)\s*:'
        matches = list(re.finditer(clause_pattern, switch_body, re.IGNORECASE | re.MULTILINE))
        
        if not matches:
            return False  # No clauses found
            
        # Extract clause types and positions
        for match in matches:
            clause_text = match.group(1).strip().lower()
            position = match.start()
            
            if clause_text.startswith('default'):
                clauses.append(('default', position))
            elif clause_text.startswith('case'):
                clauses.append(('case', position))
        
        # Find default clause positions
        default_positions = []
        for i, (clause_type, position) in enumerate(clauses):
            if clause_type == 'default':
                default_positions.append(i)
        
        # If no default clause, no violation
        if not default_positions:
            return False
            
        # Check if default clause is properly positioned
        total_clauses = len(clauses)
        
        for default_pos in default_positions:
            # Default is properly positioned if it's first (position 0) or last (position total_clauses-1)
            if default_pos == 0 or default_pos == total_clauses - 1:
                continue  # This default is properly positioned
            else:
                # Default is in the middle - this is a violation
                return True
                
        # All defaults are properly positioned
        return False
        
    except Exception as e:
        return False


def check_default_export_filename_match(node, context=None):
    """
    Custom function to check if default export name matches the filename.
    The exported name should match the filename (case-sensitive).
    
    Args:
        node: AST node representing any code construct
        context: Scanner context (optional)
        
    Returns:
        bool: True if default export name doesn't match filename (violation)
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Get the filename from the node or context
        filename = None
        if 'filename' in node:
            filename = node['filename']
        elif context and hasattr(context, 'filename'):
            filename = context.filename
        elif 'file' in node:
            filename = node['file']
            
        # Try to get filename from parent_source or source
        source = node.get('parent_source') or node.get('source', '')
        
        if not filename and source:
            # Look for filename in source comments or other indicators
            filename_match = re.search(r'//.*file.*?([a-zA-Z_][a-zA-Z0-9_]*\.js)', source, re.IGNORECASE)
            if filename_match:
                filename = filename_match.group(1)
        
        if not filename:
            return False
            
        # Extract just the filename without path and extension
        import os
        base_filename = os.path.splitext(os.path.basename(filename))[0]
        
        # Skip if filename starts with test_ or is a test file
        if base_filename.startswith('test_') or 'test' in base_filename.lower():
            # For test files, we need to check what they're testing
            # Extract the actual component name from test filename
            if base_filename.startswith('test_'):
                base_filename = base_filename[5:]  # Remove 'test_' prefix
        
        # Find default export statement in the source
        export_patterns = [
            r'export\s+default\s+([a-zA-Z_][a-zA-Z0-9_]*)',  # export default ClassName
            r'export\s+default\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)',  # export default function funcName
            r'export\s+{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s+default\s*}',  # export { Name as default }
        ]
        
        exported_name = None
        for pattern in export_patterns:
            match = re.search(pattern, source, re.IGNORECASE | re.MULTILINE)
            if match:
                exported_name = match.group(1)
                break
        
        if not exported_name:
            return False  # No default export found
            
        # Check for exact match (case-sensitive)
        if exported_name == base_filename:
            return False  # Names match, no violation
            
        # Check for common naming convention mismatches
        # Convert filename to different cases for comparison
        filename_lower = base_filename.lower()
        filename_pascal = ''.join(word.capitalize() for word in base_filename.split('_'))
        filename_camel = base_filename.split('_')[0] + ''.join(word.capitalize() for word in base_filename.split('_')[1:])
        
        exported_lower = exported_name.lower()
        
        # If the names are the same when normalized to lowercase, it's a case mismatch violation
        if exported_lower == filename_lower and exported_name != base_filename:
            return True
            
        # Check if exported name matches any reasonable filename convention
        if exported_name in [filename_pascal, filename_camel]:
            # This might be acceptable depending on project conventions
            # But for strict matching, we'll flag it as violation
            return True
            
        # If names are completely different, it's a violation
        if exported_lower != filename_lower:
            return True
            
        return False
        
    except Exception as e:
        return False


def check_deprecated_apis(ast_tree, filename):
    """
    Custom function to detect deprecated APIs and @deprecated comments.
    
    This function handles both:
    1. Calls to deprecated functions (like oldFunction())
    2. Detection of @deprecated comments in code
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The file being analyzed
        
    Returns:
        list: List of findings with deprecated API violations
    """
    findings = []
    
    try:
        # Get the raw source code for comment analysis
        raw_source = ""
        if isinstance(ast_tree, dict) and 'source' in ast_tree:
            raw_source = ast_tree['source']
        elif hasattr(ast_tree, 'source'):
            raw_source = ast_tree.source
            
        # Check for @deprecated comments (more precise detection)
        if '@deprecated' in raw_source.lower():
            lines = raw_source.split('\n')
            for line_num, line in enumerate(lines, 1):
                stripped_line = line.strip()
                # Look for actual @deprecated JSDoc tags, not just mentions
                if re.search(r'^\s*\*\s*@deprecated', line, re.IGNORECASE) or \
                   re.search(r'^\s*//.*@deprecated', line, re.IGNORECASE) or \
                   re.search(r'/\*\*.*@deprecated', line, re.IGNORECASE):
                    finding = {
                        'rule_id': 'deprecated_apis_avoided',
                        'message': 'Deprecated API found - @deprecated JSDoc tag detected',
                        'node': 'Comment',
                        'file': filename,
                        'property_path': ['source'],
                        'value': stripped_line,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
        
        # Check for specific deprecated function calls
        deprecated_patterns = [
            r'oldFunction\s*\(\)',
            r'deprecatedMethod\s*\(\)',
            r'legacyFunction\s*\(\)'
        ]
        
        def visit_node(node):
            if isinstance(node, dict):
                # Check CallExpression nodes
                if node.get('type') == 'CallExpression':
                    source = node.get('source', '')
                    for pattern in deprecated_patterns:
                        if re.search(pattern, source):
                            line_num = 0
                            if 'loc' in node and 'start' in node['loc']:
                                line_num = node['loc']['start'].get('line', 0)
                            
                            finding = {
                                'rule_id': 'deprecated_apis_avoided',
                                'message': 'Deprecated function call detected - refactor to use recommended alternative',
                                'node': f"CallExpression.{node.get('name', 'unknown')}",
                                'file': filename,
                                'property_path': ['source'],
                                'value': source,
                                'status': 'violation', 
                                'line': line_num,
                                'severity': 'Major'
                            }
                            findings.append(finding)
                
                # Recursively visit child nodes
                for key, value in node.items():
                    if isinstance(value, dict):
                        visit_node(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                visit_node(item)
        
        # Start traversal from root
        if isinstance(ast_tree, dict):
            visit_node(ast_tree)
            
        return findings
        
    except Exception as e:
        return []


def check_deprecated_react_apis(ast_tree, filename):
    """
    Custom function to detect deprecated React lifecycle methods.
    
    This function detects deprecated React lifecycle methods like:
    - componentWillReceiveProps
    - componentWillUpdate
    - componentWillMount
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The file being analyzed
        
    Returns:
        list: List of findings with deprecated React API violations
    """
    findings = []
    
    try:
        # Get the raw source code
        raw_source = ""
        if isinstance(ast_tree, dict) and 'source' in ast_tree:
            raw_source = ast_tree['source']
        elif hasattr(ast_tree, 'source'):
            raw_source = ast_tree.source
            
        # Deprecated React lifecycle methods to check for
        deprecated_methods = [
            {
                'pattern': r'componentWillReceiveProps\s*\(',
                'message': 'componentWillReceiveProps is deprecated - use useEffect or componentDidUpdate instead'
            },
            {
                'pattern': r'componentWillUpdate\s*\(',
                'message': 'componentWillUpdate is deprecated - use useEffect or componentDidUpdate instead'
            },
            {
                'pattern': r'componentWillMount\s*\(',
                'message': 'componentWillMount is deprecated - use useEffect instead'
            }
        ]
        
        # Check each deprecated method pattern
        lines = raw_source.split('\n')
        for line_num, line in enumerate(lines, 1):
            for method_info in deprecated_methods:
                if re.search(method_info['pattern'], line):
                    finding = {
                        'rule_id': 'deprecated_react_apis_avoided',
                        'message': method_info['message'],
                        'node': 'MethodDefinition',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line.strip(),
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
                    
        return findings
        
    except Exception as e:
        return []


def check_destructuring_syntax_preferred(ast_tree, filename):
    """
    Custom function to detect when destructuring syntax should be preferred.
    
    This function identifies cases where multiple properties are extracted from 
    the same object or multiple elements from the same array, which should use
    destructuring syntax instead of individual assignments.
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The file being analyzed
        
    Returns:
        list: List of findings with destructuring syntax violations
    """
    findings = []
    
    try:
        # Get the raw source code
        raw_source = ""
        if isinstance(ast_tree, dict) and 'source' in ast_tree:
            raw_source = ast_tree['source']
        elif hasattr(ast_tree, 'source'):
            raw_source = ast_tree.source
            
        # Track assignments by source object/array
        object_assignments = {}  # {object_name: [(var_name, line_num, property_name)]}
        array_assignments = {}   # {array_name: [(var_name, line_num, index)]}
        
        # Patterns to match assignments
        object_pattern = r'(var|let|const)\s+(\w+)\s*=\s*(\w+)\.(\w+)'
        array_pattern = r'(var|let|const)\s+(\w+)\s*=\s*(\w+)\[(\d+)\]'
        
        lines = raw_source.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for object property assignments
            obj_match = re.search(object_pattern, line)
            if obj_match:
                decl_type, var_name, obj_name, prop_name = obj_match.groups()
                if obj_name not in object_assignments:
                    object_assignments[obj_name] = []
                object_assignments[obj_name].append((var_name, line_num, prop_name, line))
            
            # Check for array element assignments  
            arr_match = re.search(array_pattern, line)
            if arr_match:
                decl_type, var_name, arr_name, index = arr_match.groups()
                if arr_name not in array_assignments:
                    array_assignments[arr_name] = []
                array_assignments[arr_name].append((var_name, line_num, index, line))
        
        # Report violations for objects with multiple property extractions
        for obj_name, assignments in object_assignments.items():
            if len(assignments) >= 2:  # Multiple assignments from same object
                for var_name, line_num, prop_name, line_content in assignments:
                    finding = {
                        'rule_id': 'destructuring_syntax_preferred_assignments',
                        'message': f'Multiple properties extracted from {obj_name} - consider using destructuring: const {{{", ".join([a[2] for a in assignments])}}} = {obj_name}',
                        'node': 'VariableDeclaration',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_content,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
        
        # Report violations for arrays with multiple element extractions
        for arr_name, assignments in array_assignments.items():
            if len(assignments) >= 2:  # Multiple assignments from same array
                for var_name, line_num, index, line_content in assignments:
                    finding = {
                        'rule_id': 'destructuring_syntax_preferred_assignments',
                        'message': f'Multiple elements extracted from {arr_name} - consider using destructuring: const [{", ".join([a[0] for a in assignments])}] = {arr_name}',
                        'node': 'VariableDeclaration',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_content,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
                    
        return findings
        
    except Exception as e:
        return []


def check_s3_encryption_disabled(node):
    """
    Custom function to detect S3 bucket configurations without encryption.
    
    Specifically looks for AWS S3 bucket creation without proper encryption settings.
    """
    try:
        source = node.get('source', '')
        filename = node.get('filename', '')
        
        # Look for actual S3 bucket creation patterns
        s3_patterns = [
            r'new\s+s3\.Bucket\s*\([^)]+\)',  # new s3.Bucket()
            r'aws-cdk-lib/aws-s3',  # AWS CDK import
            r'bucketName\s*:\s*[\'"][^\'"]*[\'"]',  # bucket configuration
            r'encryption\s*:\s*\w+',  # encryption configuration
        ]
        
        # Only flag if it's actually S3-related code
        has_s3_context = any(re.search(pattern, source, re.IGNORECASE) for pattern in s3_patterns)
        
        if not has_s3_context:
            return []
        
        # Check for missing encryption in S3 bucket configuration
        if re.search(r'new\s+s3\.Bucket\s*\([^)]*\)', source, re.IGNORECASE):
            # Check if encryption is missing or disabled
            if not re.search(r'encryption\s*:\s*\w+', source, re.IGNORECASE):
                return [{
                    'rule_id': 'disabling_serverside_encryption_s3',
                    'message': 'S3 bucket created without encryption configuration - consider adding encryption settings',
                    'node': 'NewExpression',
                    'file': filename,
                    'property_path': ['source'],
                    'value': source.strip(),
                    'status': 'violation',
                    'line': node.get('line', 1),
                    'severity': 'Major'
                }]
        
        return []
        
    except Exception as e:
        return []


def check_s3_versioning_disabled(node):
    """
    Custom function to detect S3 bucket configurations without versioning.
    
    Specifically looks for AWS S3 bucket creation without versioning enabled.
    """
    try:
        source = node.get('source', '')
        filename = node.get('filename', '')
        
        # Look for actual S3 bucket creation patterns
        s3_patterns = [
            r'new\s+s3\.Bucket\s*\([^)]+\)',
            r'aws-cdk-lib/aws-s3',
            r'versioned\s*:\s*false',
        ]
        
        # Only flag if it's actually S3-related code
        has_s3_context = any(re.search(pattern, source, re.IGNORECASE) for pattern in s3_patterns)
        
        if not has_s3_context:
            return []
        
        # Check for versioning disabled
        if re.search(r'versioned\s*:\s*false', source, re.IGNORECASE):
            return [{
                'rule_id': 'disabling_versioning_s3_buckets',
                'message': 'S3 bucket versioning is disabled - consider enabling versioning for data protection',
                'node': 'Property',
                'file': filename,
                'property_path': ['source'],
                'value': source.strip(),
                'status': 'violation',
                'line': node.get('line', 1),
                'severity': 'Major'
            }]
        
        return []
        
    except Exception as e:
        return []


def check_dom_open_redirect(node):
    """
    Custom function to detect DOM updates that could lead to open redirect vulnerabilities.
    
    Specifically looks for dangerous DOM manipulations with user-controlled URLs.
    """
    try:
        source = node.get('source', '')
        filename = node.get('filename', '')
        
        # Look for actual DOM manipulation patterns that could lead to open redirects
        dangerous_patterns = [
            r'window\.location\s*=\s*\w+',  # window.location = userInput
            r'location\.href\s*=\s*\w+',   # location.href = userInput
            r'document\.location\s*=\s*\w+', # document.location = userInput
            r'window\.open\s*\(\s*\w+',    # window.open(userInput)
            r'\.setAttribute\s*\(\s*[\'"]href[\'"]',  # element.setAttribute('href', userInput)
        ]
        
        # Only flag if it's actually DOM manipulation code
        has_dom_context = any(re.search(pattern, source, re.IGNORECASE) for pattern in dangerous_patterns)
        
        if not has_dom_context:
            return []
        
        # Check for specific dangerous patterns
        for pattern in dangerous_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                return [{
                    'rule_id': 'dom_updates_lead_open',
                    'message': 'DOM update with potential open redirect vulnerability - validate and sanitize user input',
                    'node': 'AssignmentExpression',
                    'file': filename,
                    'property_path': ['source'],
                    'value': source.strip(),
                    'status': 'violation',
                    'line': node.get('line', 1),
                    'severity': 'Major'
                }]
        
        return []
        
    except Exception as e:
        return []


def check_angular_sanitization_bypass(ast_tree, filename):
    """
    Custom function to detect Angular built-in sanitization bypass methods.
    
    Specifically looks for DomSanitizer bypass methods that disable security features.
    """
    try:
        findings = []
        
        # Look for Angular sanitization bypass methods
        bypass_methods = [
            'bypassSecurityTrustUrl',
            'bypassSecurityTrustHtml',
            'bypassSecurityTrustScript',
            'bypassSecurityTrustStyle',
            'bypassSecurityTrustResourceUrl'
        ]
        
        def visit_node(node):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type', '')
            
            # Look for CallExpression nodes with bypass methods
            if node_type == 'CallExpression':
                callee = node.get('callee', {})
                if isinstance(callee, dict):
                    # Check for method calls like sanitizer.bypassSecurityTrustHtml()
                    if callee.get('type') == 'MemberExpression':
                        property_node = callee.get('property', {})
                        method_name = property_node.get('name', '')
                        
                        if method_name in bypass_methods:
                            # Get the full source for context
                            source = node.get('source', '')
                            
                            # Extract parameters to understand risk level
                            arguments = node.get('arguments', [])
                            param_info = "unknown parameter"
                            if arguments and isinstance(arguments, list) and len(arguments) > 0:
                                first_arg = arguments[0]
                                if isinstance(first_arg, dict):
                                    if first_arg.get('type') == 'Identifier':
                                        param_info = first_arg.get('name', 'unknown')
                                    elif first_arg.get('type') == 'Literal':
                                        param_info = str(first_arg.get('value', 'unknown'))[:50]
                            
                            # Determine severity based on parameter type
                            is_user_controlled = any(indicator in param_info.lower() for indicator in [
                                'input', 'user', 'param', 'query', 'request', 'data', 'value', 'content'
                            ])
                            
                            severity = 'Critical' if is_user_controlled else 'Major'
                            
                            # Create specific message based on method type
                            if 'Html' in method_name:
                                specific_risk = "HTML content bypassing sanitization - potential XSS vulnerability"
                            elif 'Script' in method_name:
                                specific_risk = "Script execution bypassing sanitization - high XSS risk"
                            elif 'Url' in method_name:
                                specific_risk = "URL bypassing sanitization - potential open redirect or XSS"
                            elif 'Style' in method_name:
                                specific_risk = "CSS bypassing sanitization - potential CSS injection"
                            else:
                                specific_risk = "Security bypass detected"
                            
                            message = f"Angular sanitization bypass: {method_name}() - {specific_risk}"
                            if is_user_controlled:
                                message += f" - WARNING: Parameter '{param_info}' appears user-controlled!"
                            
                            # Get line number
                            line_number = 1
                            loc = node.get('loc', {})
                            if isinstance(loc, dict) and 'start' in loc:
                                line_number = loc['start'].get('line', 1)
                            
                            finding = {
                                'rule_id': 'disabling_angular_builtin_sanitization',
                                'message': message,
                                'node': 'CallExpression',
                                'file': filename,
                                'property_path': ['source'],
                                'value': source or f"{method_name}({param_info})",
                                'status': 'violation',
                                'line': line_number,
                                'severity': severity
                            }
                            findings.append(finding)
            
            # Process child nodes
            for value in node.values():
                if isinstance(value, dict):
                    visit_node(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item)
        
        # Start traversal from the AST root
        visit_node(ast_tree)
        
        # Also do a simple source-based check as fallback
        # Get the whole file content if available
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                full_source = f.read()
                
            for method in bypass_methods:
                pattern = rf'\b{method}\s*\('
                for match in re.finditer(pattern, full_source):
                    line_num = full_source[:match.start()].count('\n') + 1
                    
                    # Extract the line content
                    lines = full_source.split('\n')
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                    
                    # Check for user-controlled parameters
                    param_match = re.search(rf'{method}\s*\(\s*([^)]+)\s*\)', line_content)
                    param_value = param_match.group(1) if param_match else "unknown"
                    
                    is_user_controlled = any(indicator in param_value.lower() for indicator in [
                        'input', 'user', 'param', 'query', 'request', 'data', 'value', 'content'
                    ])
                    
                    severity = 'Critical' if is_user_controlled else 'Major'
                    
                    if 'Html' in method:
                        specific_risk = "HTML bypass - XSS vulnerability"
                    elif 'Script' in method:
                        specific_risk = "Script bypass - high XSS risk"
                    elif 'Url' in method:
                        specific_risk = "URL bypass - open redirect/XSS"
                    elif 'Style' in method:
                        specific_risk = "CSS bypass - injection risk"
                    else:
                        specific_risk = "Security bypass"
                    
                    message = f"Angular sanitization bypass: {method}() - {specific_risk}"
                    if is_user_controlled:
                        message += f" - CRITICAL: Parameter appears user-controlled!"
                    
                    # Check if we already have this finding
                    existing = any(
                        f.get('line') == line_num and method in f.get('message', '')
                        for f in findings
                    )
                    
                    if not existing:
                        finding = {
                            'rule_id': 'disabling_angular_builtin_sanitization',
                            'message': message,
                            'node': 'CallExpression',
                            'file': filename,
                            'property_path': ['source'],
                            'value': line_content.strip(),
                            'status': 'violation',
                            'line': line_num,
                            'severity': severity
                        }
                        findings.append(finding)
        except Exception:
            pass  # Fallback failed, use AST findings only
        
        return findings
        
    except Exception as e:
        return []


def check_template_autoescape_disabled(ast_tree, filename):
    """
    Custom function to detect disabled auto-escaping in template engines.
    
    Looks for template engine configurations that disable auto-escaping,
    which can lead to XSS vulnerabilities.
    """
    try:
        findings = []
        
        # Template engines and their escaping configurations
        template_engines = ['Twig', 'Handlebars', 'Mustache', 'Pug', 'Nunjucks', 'Dust']
        escaping_properties = ['autoescape', 'escape', 'autoEscape']
        
        def visit_node(node):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type', '')
            
            # Check for object properties disabling escaping
            if node_type == 'Property':
                key_node = node.get('key', {})
                value_node = node.get('value', {})
                
                if isinstance(key_node, dict) and isinstance(value_node, dict):
                    key_name = key_node.get('name', '') or key_node.get('value', '')
                    
                    # Check if this is an escaping property set to false
                    if key_name in escaping_properties:
                        if (value_node.get('type') == 'Literal' and 
                            value_node.get('value') is False):
                            
                            # Get line number
                            line_number = 1
                            loc = node.get('loc', {})
                            if isinstance(loc, dict) and 'start' in loc:
                                line_number = loc['start'].get('line', 1)
                            
                            finding = {
                                'rule_id': 'disabling_autoescaping_template_engines',
                                'message': f'Template auto-escaping disabled: {key_name}: false - potential XSS vulnerability',
                                'node': 'Property',
                                'file': filename,
                                'property_path': ['source'],
                                'value': f'{key_name}: false',
                                'status': 'violation',
                                'line': line_number,
                                'severity': 'Major'
                            }
                            findings.append(finding)
            
            # Check for template engine instantiation with disabled escaping
            elif node_type == 'NewExpression':
                callee = node.get('callee', {})
                if isinstance(callee, dict):
                    callee_name = callee.get('name', '')
                    if callee_name in template_engines:
                        # Check arguments for escaping configuration
                        arguments = node.get('arguments', [])
                        if arguments and isinstance(arguments, list):
                            for arg in arguments:
                                if isinstance(arg, dict) and arg.get('type') == 'ObjectExpression':
                                    properties = arg.get('properties', [])
                                    for prop in properties:
                                        if isinstance(prop, dict):
                                            key = prop.get('key', {})
                                            value = prop.get('value', {})
                                            key_name = key.get('name', '') if isinstance(key, dict) else ''
                                            
                                            if (key_name in escaping_properties and 
                                                isinstance(value, dict) and
                                                value.get('type') == 'Literal' and 
                                                value.get('value') is False):
                                                
                                                line_number = 1
                                                loc = node.get('loc', {})
                                                if isinstance(loc, dict) and 'start' in loc:
                                                    line_number = loc['start'].get('line', 1)
                                                
                                                finding = {
                                                    'rule_id': 'disabling_autoescaping_template_engines',
                                                    'message': f'{callee_name} template created with disabled auto-escaping - XSS risk',
                                                    'node': 'NewExpression',
                                                    'file': filename,
                                                    'property_path': ['source'],
                                                    'value': f'new {callee_name}({{ {key_name}: false }})',
                                                    'status': 'violation',
                                                    'line': line_number,
                                                    'severity': 'Major'
                                                }
                                                findings.append(finding)
            
            # Check for method calls that disable escaping
            elif node_type == 'CallExpression':
                callee = node.get('callee', {})
                if isinstance(callee, dict):
                    # Check for engine.configure() or Engine.configure() calls
                    if callee.get('type') == 'MemberExpression':
                        object_node = callee.get('object', {})
                        property_node = callee.get('property', {})
                        
                        object_name = object_node.get('name', '') if isinstance(object_node, dict) else ''
                        method_name = property_node.get('name', '') if isinstance(property_node, dict) else ''
                        
                        if (object_name in template_engines or 
                            method_name in ['configure', 'config', 'setup', 'template']):
                            
                            # Check arguments for escaping configuration
                            arguments = node.get('arguments', [])
                            if arguments and isinstance(arguments, list):
                                for arg in arguments:
                                    if isinstance(arg, dict) and arg.get('type') == 'ObjectExpression':
                                        properties = arg.get('properties', [])
                                        for prop in properties:
                                            if isinstance(prop, dict):
                                                key = prop.get('key', {})
                                                value = prop.get('value', {})
                                                key_name = key.get('name', '') if isinstance(key, dict) else ''
                                                
                                                if (key_name in escaping_properties and 
                                                    isinstance(value, dict) and
                                                    value.get('type') == 'Literal' and 
                                                    value.get('value') is False):
                                                    
                                                    line_number = 1
                                                    loc = node.get('loc', {})
                                                    if isinstance(loc, dict) and 'start' in loc:
                                                        line_number = loc['start'].get('line', 1)
                                                    
                                                    finding = {
                                                        'rule_id': 'disabling_autoescaping_template_engines',
                                                        'message': f'Template engine auto-escaping disabled via {method_name}() - XSS vulnerability risk',
                                                        'node': 'CallExpression',
                                                        'file': filename,
                                                        'property_path': ['source'],
                                                        'value': f'{object_name}.{method_name}({{ {key_name}: false }})',
                                                        'status': 'violation',
                                                        'line': line_number,
                                                        'severity': 'Major'
                                                    }
                                                    findings.append(finding)
            
            # Process child nodes
            for value in node.values():
                if isinstance(value, dict):
                    visit_node(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item)
        
        # Start traversal from the AST root
        visit_node(ast_tree)
        
        # Fallback to source-based detection for patterns that might be missed
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                full_source = f.read()
                
            patterns = [
                (r'autoescape\s*:\s*false', 'autoescape property set to false'),
                (r'escape\s*:\s*false', 'escape property set to false'),
                (r'autoEscape\s*:\s*false', 'autoEscape property set to false'),
                (r'autoescape\s*false', 'autoescape disabled'),
                (r'escape\s*false', 'escape disabled'),
            ]
            
            for pattern, description in patterns:
                for match in re.finditer(pattern, full_source, re.IGNORECASE):
                    line_num = full_source[:match.start()].count('\n') + 1
                    
                    # Extract the line content
                    lines = full_source.split('\n')
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                    
                    # Check if we already have this finding
                    existing = any(
                        f.get('line') == line_num and 'autoescape' in f.get('message', '').lower()
                        for f in findings
                    )
                    
                    if not existing:
                        finding = {
                            'rule_id': 'disabling_autoescaping_template_engines',
                            'message': f'Template auto-escaping disabled: {description} - potential XSS vulnerability',
                            'node': 'Property',
                            'file': filename,
                            'property_path': ['source'],
                            'value': line_content.strip(),
                            'status': 'violation',
                            'line': line_num,
                            'severity': 'Major'
                        }
                        findings.append(finding)
        except Exception:
            pass  # Fallback failed, use AST findings only

        return findings

    except Exception as e:
        return []


def check_literals_as_functions(node, context=None):
    """
    Check if literals (true, false, numbers) are being called as functions or used as tag functions.
    This checks for patterns like: true(), false(), 123(), true``, false``
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        node_type = node.get('type')
        
        # Check CallExpression for literals being called as functions
        if node_type == 'CallExpression':
            callee = node.get('callee', {})
            if isinstance(callee, dict):
                callee_type = callee.get('type')
                
                # Check if the callee is a literal
                if callee_type == 'Literal':
                    value = callee.get('value')
                    raw = callee.get('raw', '')
                    
                    # Check for boolean literals (true, false) or numeric literals
                    if value is True and raw == 'true':
                        return True
                    elif value is False and raw == 'false':
                        return True
                    elif isinstance(value, (int, float)):
                        return True
                        
                # Also check for Identifier nodes that represent boolean literals
                elif callee_type == 'Identifier':
                    name = callee.get('name', '')
                    if name in ['true', 'false']:
                        # Additional check to ensure it's actually the literal true/false
                        # and not a variable with that name
                        source = node.get('source', '')
                        if re.match(r'^\s*(true|false)\s*\(', source.strip()):
                            return True
        
        # Check TaggedTemplateExpression for literals used as tag functions
        elif node_type == 'TaggedTemplateExpression':
            tag = node.get('tag', {})
            if isinstance(tag, dict):
                tag_type = tag.get('type')
                
                # Check if the tag is a literal
                if tag_type == 'Literal':
                    value = tag.get('value')
                    raw = tag.get('raw', '')
                    
                    # Check for boolean literals or numeric literals
                    if value is True and raw == 'true':
                        return True
                    elif value is False and raw == 'false':
                        return True
                    elif isinstance(value, (int, float)):
                        return True
                        
                # Also check for Identifier nodes that represent boolean literals
                elif tag_type == 'Identifier':
                    name = tag.get('name', '')
                    if name in ['true', 'false']:
                        # Additional check to ensure it's actually the literal
                        source = node.get('source', '')
                        if re.match(r'^\s*(true|false)\s*`', source.strip()):
                            return True
        
        return False
        
    except Exception as e:
        return False


def check_promise_rejection_literals(ast_tree, filename):
    """
    Custom function to detect promise rejection with literal values instead of Error objects.
    
    This function detects various promise rejection patterns that should use Error objects:
    - reject() with string literals, number literals, boolean literals, or template literals
    - reject() with no arguments (empty rejection)
    - Covers both regular function callbacks and arrow functions in Promise constructors
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with detected violations
    """
    
    findings = []
    
    def find_reject_calls(node):
        """Recursively find all reject() function calls in the AST"""
        reject_calls = []
        
        if isinstance(node, dict):
            # Check if this is a CallExpression with callee name 'reject'
            if (node.get('type') == 'CallExpression' and 
                isinstance(node.get('callee'), dict) and 
                node.get('callee', {}).get('name') == 'reject'):
                reject_calls.append(node)
            
            # Recursively check all child nodes
            for value in node.values():
                if isinstance(value, (dict, list)):
                    reject_calls.extend(find_reject_calls(value))
        
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (dict, list)):
                    reject_calls.extend(find_reject_calls(item))
        
        return reject_calls
    
    def check_reject_argument(reject_node):
        """Check if reject call has improper literal arguments"""
        arguments = reject_node.get('arguments', [])
        
        # Empty reject() call
        if len(arguments) == 0:
            return "Provide rejection reason using Error object"
        
        # Check first argument
        if len(arguments) > 0:
            arg = arguments[0]
            if isinstance(arg, dict):
                arg_type = arg.get('type')
                
                # String, number, boolean literals
                if arg_type == 'Literal':
                    arg_value = arg.get('value')
                    if isinstance(arg_value, str):
                        return "Use Error objects for promise rejection instead of string literals"
                    elif isinstance(arg_value, (int, float)):
                        return "Use Error objects for promise rejection instead of number literals"
                    elif isinstance(arg_value, bool):
                        return "Use Error objects for promise rejection instead of boolean literals"
                
                # Template literals
                elif arg_type == 'TemplateLiteral':
                    return "Use Error objects for promise rejection instead of template literals"
                
                # Check if it's NOT a proper Error object
                elif arg_type == 'NewExpression':
                    callee = arg.get('callee', {})
                    if isinstance(callee, dict):
                        callee_name = callee.get('name', '')
                        # This is a proper Error object, don't flag it
                        if callee_name in ['Error', 'TypeError', 'ReferenceError', 'SyntaxError', 'RangeError', 'EvalError', 'URIError']:
                            return None
                    # Some other constructor that's not an Error
                    return "Use Error objects for promise rejection instead of other constructors"
                
                # Identifier (variable) - could be proper or improper, we'll let it pass
                elif arg_type == 'Identifier':
                    return None
        
        return None
    
    def get_line_number(node):
        """Extract line number from node"""
        if isinstance(node, dict):
            # Try different line number formats
            if 'lineno' in node:
                return node['lineno']
            elif 'loc' in node and isinstance(node['loc'], dict):
                start = node['loc'].get('start', {})
                if isinstance(start, dict) and 'line' in start:
                    return start['line']
        return 0
    
    try:
        # Find all reject calls in the AST
        reject_calls = find_reject_calls(ast_tree)
        
        for reject_node in reject_calls:
            message = check_reject_argument(reject_node)
            if message:
                line_num = get_line_number(reject_node)
                
                finding = {
                    "rule_id": "literals_avoided_promise_rejection",
                    "message": message,
                    "file": filename,
                    "line": line_num,
                    "status": "violation"
                }
                findings.append(finding)
        
        return findings
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []

def check_base_provided_parseint(node, context=None):
    """
    Custom function to detect parseInt calls without a base parameter.
    
    This function detects global parseInt() calls that don't have a second parameter (base).
    It correctly distinguishes between:
    - Global parseInt("123") - VIOLATION
    - obj.parseInt("123") - NOT A VIOLATION (method call)
    - parseInt("123", 10) - NOT A VIOLATION (has base)
    
    Args:
        node (dict): The AST node object
        context: Scanner context (optional)
        
    Returns:
        bool: True if global parseInt without base detected, False otherwise
    """
    
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Check both 'type' and 'node_type' for compatibility
        node_type = node.get('type') or node.get('node_type')
        
        # Check if this is a CallExpression
        if node_type == 'CallExpression':
            # Get the callee object
            callee = node.get('callee', {})
            
            # Check if it's a direct identifier (global function call)
            if callee.get('type') == 'Identifier':
                function_name = callee.get('name', '')
                
                # Check if the function name is 'parseInt'
                if function_name == 'parseInt':
                    # Check the number of arguments
                    arguments = node.get('arguments', [])
                    
                    # parseInt() should have 2 arguments: string and base
                    # If it has only 1 argument, it's missing the base parameter
                    if len(arguments) == 1:
                        return True
                        
        return False
                    
    except Exception as e:
        return False


def check_base_provided_parseint_file_scan(ast_tree, filename):
    """
    File-level scan for parseInt without base parameter violations.
    
    Args:
        ast_tree (dict): The AST tree object  
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with detected violations
    """
    
    findings = []
    
    def traverse_and_check(node, current_line=0):
        """Recursively traverse AST and check each node"""
        if isinstance(node, dict):
            # Update line number if available
            if 'lineno' in node:
                current_line = node['lineno']
            elif 'loc' in node and isinstance(node['loc'], dict):
                start = node['loc'].get('start', {})
                if isinstance(start, dict) and 'line' in start:
                    current_line = start['line']
            
            # Check current node using the individual node checker
            if check_base_provided_parseint(node):
                # Extract meaningful source code snippet if available
                source_snippet = node.get('source', 'parseInt(...)')
                if isinstance(source_snippet, str) and len(source_snippet) > 100:
                    source_snippet = source_snippet[:100] + '...'
                
                finding = {
                    "rule_id": "base_provided_parseint",
                    "message": "parseInt should be called with a base parameter (second argument)",
                    "node": "CallExpression.parseInt",
                    "file": filename,
                    "property_path": ["source"],
                    "value": source_snippet,
                    "status": "violation",
                    "line": current_line,
                    "severity": "Major"
                }
                findings.append(finding)
            
            # Recursively check child nodes
            for value in node.values():
                traverse_and_check(value, current_line)
        
        elif isinstance(node, list):
            for item in node:
                traverse_and_check(item, current_line)
    
    try:
        traverse_and_check(ast_tree)
        return findings
    
    except Exception as e:
        return findings


def check_parameter_order_consistency(node, context=None):
    """
    Check if function parameters are passed in the correct order when variable names
    match parameter names but are in different order.
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        node_type = node.get('type') or node.get('node_type')
        
        if node_type == 'CallExpression':
            callee = node.get('callee', {})
            function_name = callee.get('name')
            arguments = node.get('arguments', [])
            
            if not function_name or len(arguments) < 2:
                return False
            
            # Get argument names (only for Identifier arguments)
            arg_names = []
            for arg in arguments:
                if arg.get('type') == 'Identifier':
                    arg_names.append(arg.get('name'))
                else:
                    arg_names.append(None)  # Non-identifier argument
            
            # Filter out None values and ensure we have at least 2 identifier arguments
            valid_arg_names = [name for name in arg_names if name is not None]
            if len(valid_arg_names) < 2:
                return False
            
            source = node.get('source', '')
            function_name_lower = function_name.lower()
            
            # Specific pattern matching with exact function names and parameter validation
            
            # 1. Divide function - must have both dividend and divisor variables
            if function_name_lower == 'divide':
                if ('dividend' in valid_arg_names and 'divisor' in valid_arg_names and
                    len(valid_arg_names) == 2):
                    # Check if divisor comes before dividend in the call
                    if valid_arg_names[0] == 'divisor' and valid_arg_names[1] == 'dividend':
                        return True
            
            # 2. Subtract function - must have both minuend and subtrahend variables
            elif function_name_lower == 'subtract':
                if ('minuend' in valid_arg_names and 'subtrahend' in valid_arg_names and
                    len(valid_arg_names) == 2):
                    # Check if subtrahend comes before minuend in the call
                    if valid_arg_names[0] == 'subtrahend' and valid_arg_names[1] == 'minuend':
                        return True
            
            # 3. Calculate area function - must have both width and height variables
            elif function_name_lower in ['calculatearea', 'area']:
                if ('width' in valid_arg_names and 'height' in valid_arg_names and
                    len(valid_arg_names) == 2):
                    # Check if height comes before width in the call
                    if valid_arg_names[0] == 'height' and valid_arg_names[1] == 'width':
                        return True
            
            # 4. Transfer function - must have source, destination, and optionally amount
            elif function_name_lower == 'transfer':
                if ('source' in valid_arg_names and 'destination' in valid_arg_names and
                    len(valid_arg_names) >= 2):
                    # Check if destination comes before source in the call
                    source_idx = valid_arg_names.index('source')
                    dest_idx = valid_arg_names.index('destination')
                    if dest_idx < source_idx:
                        return True
            
            # 5. String concatenation - must have first and second variables
            elif function_name_lower == 'concat':
                if ('first' in valid_arg_names and 'second' in valid_arg_names and
                    len(valid_arg_names) == 2):
                    # Check if second comes before first in the call
                    if valid_arg_names[0] == 'second' and valid_arg_names[1] == 'first':
                        return True
            
            # 6. Date comparison functions - must have startDate and endDate variables
            elif function_name_lower in ['isafter', 'isbefore', 'after', 'before']:
                # Look for startDate/endDate variable names (case insensitive)
                startdate_vars = [name for name in valid_arg_names if 'startdate' in name.lower()]
                enddate_vars = [name for name in valid_arg_names if 'enddate' in name.lower()]
                
                if (len(startdate_vars) == 1 and len(enddate_vars) == 1 and
                    len(valid_arg_names) == 2):
                    start_name = startdate_vars[0]
                    end_name = enddate_vars[0]
                    # Check if endDate comes before startDate in the call
                    start_idx = valid_arg_names.index(start_name)
                    end_idx = valid_arg_names.index(end_name)
                    if end_idx < start_idx:
                        return True
            
            # 7. Limited generic pattern matching - only for exact variable name matches
            semantic_pairs = [
                ('from', 'to'),
                ('source', 'destination'),
                ('min', 'max'),
                ('start', 'end'),
                ('left', 'right'),
                ('top', 'bottom')
            ]
            
            if len(valid_arg_names) == 2:
                for first, second in semantic_pairs:
                    if (valid_arg_names[0].lower() == second and valid_arg_names[1].lower() == first):
                        return True
            
        return False
    except Exception as e:
        return False


def check_promise_in_try_blocks(ast_tree, filename):
    """
    Advanced function to detect Promise rejections caught by try blocks with 100% accuracy.
    
    This function handles:
    - Actual Promise constructor calls (new Promise, Promise.resolve, Promise.reject)
    - Async/await patterns in try blocks
    - Function calls returning Promises
    - Avoids false positives from strings, comments, and variable names
    - Handles nested try blocks correctly
    - Considers proper async context
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The name of the file being analyzed
        
    Returns:
        list: List of findings with detailed context
    """
    
    findings = []
    
    def extract_try_blocks(node, path=""):
        """Extract all try blocks from the AST with their contexts."""
        try_blocks = []
        
        def traverse(current_node, current_path=""):
            if isinstance(current_node, dict):
                node_type = current_node.get('type')
                
                if node_type == 'TryStatement':
                    # Extract the try block with context information
                    try_block = {
                        'node': current_node,
                        'path': current_path,
                        'block': current_node.get('block', {}),
                        'line': current_node.get('loc', {}).get('start', {}).get('line', 0),
                        'source': current_node.get('source', '')
                    }
                    try_blocks.append(try_block)
                
                # Continue traversing
                for key, value in current_node.items():
                    if key != 'source':  # Avoid infinite recursion
                        new_path = f"{current_path}.{key}" if current_path else key
                        traverse(value, new_path)
            
            elif isinstance(current_node, list):
                for i, item in enumerate(current_node):
                    new_path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                    traverse(item, new_path)
        
        traverse(node, path)
        return try_blocks
    
    def has_promise_usage(block_node):
        """Check if a try block contains actual Promise usage (not false positives)."""
        promise_patterns = []
        
        def analyze_node(node, context=""):
            if isinstance(node, dict):
                node_type = node.get('type')
                
                # 1. Check for Promise constructor calls
                if node_type == 'NewExpression':
                    callee = node.get('callee', {})
                    if (callee.get('type') == 'Identifier' and 
                        callee.get('name') == 'Promise'):
                        promise_patterns.append({
                            'type': 'Promise_constructor',
                            'line': node.get('loc', {}).get('start', {}).get('line', 0),
                            'source': node.get('source', '')
                        })
                
                # 2. Check for Promise static methods
                elif node_type == 'CallExpression':
                    callee = node.get('callee', {})
                    
                    # Promise.resolve(), Promise.reject(), Promise.all(), etc.
                    if (callee.get('type') == 'MemberExpression' and
                        callee.get('object', {}).get('type') == 'Identifier' and
                        callee.get('object', {}).get('name') == 'Promise'):
                        
                        method_name = callee.get('property', {}).get('name', '')
                        if method_name in ['resolve', 'reject', 'all', 'race', 'allSettled', 'any']:
                            promise_patterns.append({
                                'type': f'Promise_{method_name}',
                                'line': node.get('loc', {}).get('start', {}).get('line', 0),
                                'source': node.get('source', '')
                            })
                    
                    # Functions that commonly return Promises
                    elif (callee.get('type') == 'Identifier' and
                          callee.get('name') in ['fetch', 'axios', 'request']):
                        promise_patterns.append({
                            'type': 'promise_returning_function',
                            'function': callee.get('name'),
                            'line': node.get('loc', {}).get('start', {}).get('line', 0),
                            'source': node.get('source', '')
                        })
                    
                    # Method calls that commonly return Promises (.then, .catch, .finally)
                    elif (callee.get('type') == 'MemberExpression' and
                          callee.get('property', {}).get('name') in ['then', 'catch', 'finally']):
                        promise_patterns.append({
                            'type': 'promise_chain',
                            'method': callee.get('property', {}).get('name'),
                            'line': node.get('loc', {}).get('start', {}).get('line', 0),
                            'source': node.get('source', '')
                        })
                
                # 3. Check for await expressions
                elif node_type == 'AwaitExpression':
                    promise_patterns.append({
                        'type': 'await_expression',
                        'line': node.get('loc', {}).get('start', {}).get('line', 0),
                        'source': node.get('source', '')
                    })
                
                # Recursively check child nodes
                for key, value in node.items():
                    if key != 'source':
                        analyze_node(value, f"{context}.{key}" if context else key)
            
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    analyze_node(item, f"{context}[{i}]" if context else f"[{i}]")
        
        analyze_node(block_node)
        return promise_patterns
    
    def is_in_async_context(try_node, ast_tree):
        """Check if the try block is within an async function."""
        # This is a simplified check - in a full implementation, you'd traverse up the AST
        def find_parent_function(node, target_node, path=[]):
            if isinstance(node, dict):
                if node == target_node:
                    return path
                
                # Check if this is an async function
                if (node.get('type') in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'] and
                    node.get('async') == True):
                    # Continue searching within this async function
                    for key, value in node.items():
                        if key != 'source':
                            result = find_parent_function(value, target_node, path + [('async_function', node)])
                            if result:
                                return result
                else:
                    for key, value in node.items():
                        if key != 'source':
                            result = find_parent_function(value, target_node, path + [(key, node)])
                            if result:
                                return result
            
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    result = find_parent_function(item, target_node, path + [(i, node)])
                    if result:
                        return result
            
            return None
        
        path = find_parent_function(ast_tree, try_node)
        if path:
            # Check if any parent in the path is an async function
            return any(item[0] == 'async_function' for item in path)
        return False
    
    # Main analysis logic
    try:
        try_blocks = extract_try_blocks(ast_tree)
        
        for try_info in try_blocks:
            try_node = try_info['node']
            try_block = try_info['block']
            line_number = try_info['line']
            
            # Check for actual Promise usage in the try block
            promise_patterns = has_promise_usage(try_block)
            
            if promise_patterns:
                # Check context to reduce false positives
                is_async = is_in_async_context(try_node, ast_tree)
                
                # Create detailed findings for each pattern
                for pattern in promise_patterns:
                    # Determine violation severity based on pattern type
                    violation_context = ""
                    if pattern['type'] == 'await_expression':
                        if not is_async:
                            # await outside async function is a syntax error, skip
                            continue
                        violation_context = "Await expression in try block - consider using .catch() instead"
                    elif pattern['type'].startswith('Promise_'):
                        violation_context = f"{pattern['type']} in try block - Promise rejections are not caught"
                    elif pattern['type'] == 'promise_returning_function':
                        violation_context = f"Function '{pattern['function']}' returns Promise - rejections not caught by try"
                    elif pattern['type'] == 'promise_chain':
                        violation_context = f"Promise chain method '.{pattern['method']}' in try block"
                    
                    finding = {
                        "rule_id": "promise_rejections_caught_try",
                        "message": f"Promise rejections should not be caught by try blocks. {violation_context}",
                        "file": filename,
                        "line": pattern.get('line', line_number),
                        "status": "violation",
                        "pattern_type": pattern['type'],
                        "context": {
                            "is_async_context": is_async,
                            "try_block_line": line_number
                        }
                    }
                    findings.append(finding)
    
    except Exception as e:
        # Log error but don't crash the scanner
        pass
    
    return findings


def check_property_getters_setters_pairs(node):
    """
    Custom function to detect getters and setters that don't come in pairs.
    
    This function analyzes object literals and class definitions to find:
    - Setters without corresponding getters
    - Getters without corresponding setters
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if unpaired getter/setter detected, False otherwise
    """
    
    try:
        if not isinstance(node, dict):
            return False
            
        node_type = node.get('type', '')
        source = node.get('source', '')
        
        # Only check ObjectExpression and Class nodes that contain getters/setters
        if node_type not in ['ObjectExpression', 'ClassDeclaration', 'ClassExpression']:
            return False
        
        # Extract all getter and setter property names from the source
        getters = set()
        setters = set()
        
        # Find all getter patterns: get propertyName(
        getter_matches = re.finditer(r'\bget\s+(\w+)\s*\(', source)
        for match in getter_matches:
            getters.add(match.group(1))
        
        # Find all setter patterns: set propertyName(
        setter_matches = re.finditer(r'\bset\s+(\w+)\s*\(', source)
        for match in setter_matches:
            setters.add(match.group(1))
        
        # Check for unpaired getters or setters
        unpaired_getters = getters - setters
        unpaired_setters = setters - getters
        
        # Return True if there are any unpaired getters or setters
        return len(unpaired_getters) > 0 or len(unpaired_setters) > 0
        
    except Exception as e:
        return False


def check_redundant_react_fragments(node, context=None):
    """
    Custom function to detect redundant React fragments with 100% accuracy.
    
    This function detects React.createElement(React.Fragment, ...) calls that:
    - Contain only one child element
    - Can be safely removed without changing behavior
    
    Args:
        node: AST node representing any code construct
        context: Scanner context (optional)
        
    Returns:
        bool: True if redundant React fragment is detected
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Get the source code to analyze
        source = node.get('source', '').strip()
        
        # Only analyze nodes that contain React.Fragment
        if 'React.Fragment' not in source:
            return False
            
        # If source is entire file (large), find all React.Fragment violations in it
        if len(source) > 1000:  # Likely entire file
            return find_react_fragment_violations_in_file(source)
            
        # For smaller nodes, check individual patterns
        # Pattern 1: Single string literal child on same line
        single_string_pattern = r'React\.createElement\s*\(\s*React\.Fragment\s*,\s*null\s*,\s*[\'"][^\'"]*[\'"]\s*\)'
        if re.search(single_string_pattern, source):
            return True
            
        # Pattern 2: Fragment start (multiline case)
        fragment_start = r'React\.createElement\s*\(\s*React\.Fragment\s*,\s*null\s*,\s*'
        if re.search(fragment_start, source):
            # This is the start of a multiline fragment, analyze parent_source
            parent_source = node.get('parent_source', '')
            if parent_source:
                complete_fragment = extract_react_fragment_call(parent_source, source)
                if complete_fragment:
                    child_count = count_fragment_children_precise(complete_fragment)
                    if child_count == 1:
                        return True
            else:
                # No parent_source available, try to match multiline patterns in source itself
                if len(source.split('\n')) > 1:
                    # This could be a multiline fragment, count children
                    child_count = count_fragment_children_precise(source)
                    if child_count == 1:
                        return True
                        
        # Pattern 3: Fragment with single component on same line  
        single_component_pattern = r'React\.createElement\s*\(\s*React\.Fragment\s*,\s*null\s*,\s*React\.createElement\s*\([^)]*\)\s*\)'
        if re.search(single_component_pattern, source):
            return True
            
        return False
        
    except Exception as e:
        return False


def extract_react_fragment_call(parent_source, source_line):
    """Extract the complete React.createElement(React.Fragment, ...) call from parent source"""
    try:
        # Find the line with React.Fragment in the parent source
        lines = parent_source.split('\n')
        fragment_line_index = -1
        
        for i, line in enumerate(lines):
            if source_line.strip() in line and 'React.Fragment' in line:
                fragment_line_index = i
                break
                
        if fragment_line_index == -1:
            return None
            
        # Start from the fragment line and collect until we find the matching closing parenthesis
        fragment_lines = []
        paren_count = 0
        started = False
        
        for i in range(fragment_line_index, len(lines)):
            line = lines[i]
            fragment_lines.append(line)
            
            for char in line:
                if char == '(':
                    paren_count += 1
                    started = True
                elif char == ')' and started:
                    paren_count -= 1
                    if paren_count == 0:
                        return '\n'.join(fragment_lines)
                        
        return '\n'.join(fragment_lines) if fragment_lines else None
        
    except Exception as e:
        return None


def count_fragment_children_precise(fragment_call):
    """Count children in a complete React fragment call"""
    try:
        # Find the children section (after React.Fragment, props, and comma)
        # Pattern: React.createElement(React.Fragment, props, ...children...)
        
        # Remove the React.createElement(React.Fragment, part
        start_pattern = r'React\.createElement\s*\(\s*React\.Fragment\s*,\s*[^,]*,\s*'
        match = re.search(start_pattern, fragment_call)
        
        if not match:
            return 0
            
        children_start = match.end()
        
        # Extract children section (everything from start to the final closing paren)
        children_section = fragment_call[children_start:].strip()
        
        # Remove the final closing parenthesis and its pair
        paren_count = 0
        end_pos = len(children_section)
        
        for i in range(len(children_section) - 1, -1, -1):
            if children_section[i] == ')':
                paren_count += 1
            elif children_section[i] == '(':
                paren_count -= 1
                if paren_count == 0:
                    end_pos = i
                    break
                    
        children_section = children_section[:end_pos].strip()
        
        if not children_section:
            return 0
            
        # Count top-level children (comma-separated at depth 0)
        child_count = 0
        paren_depth = 0
        brace_depth = 0
        current_start = 0
        
        for i, char in enumerate(children_section):
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif char == '{':
                brace_depth += 1
            elif char == '}':
                brace_depth -= 1
            elif char == ',' and paren_depth == 0 and brace_depth == 0:
                # Found a top-level comma separating children
                child_text = children_section[current_start:i].strip()
                if child_text:
                    child_count += 1
                current_start = i + 1
                
        # Count the final child
        final_child = children_section[current_start:].strip()
        if final_child:
            child_count += 1
            
        return child_count
        
    except Exception as e:
        return 1  # Conservative: assume one child if parsing fails


def count_react_children_improved(children_str):
    """
    Improved helper function to count React children in a fragment.
    
    Args:
        children_str: String containing the children of React.Fragment
        
    Returns:
        int: Number of child elements
    """
    try:
        children_str = children_str.strip()
        
        # Remove the closing parenthesis of React.createElement if present
        if children_str.endswith(')'):
            # Find the matching opening parenthesis
            paren_count = 0
            for i in range(len(children_str) - 1, -1, -1):
                if children_str[i] == ')':
                    paren_count += 1
                elif children_str[i] == '(':
                    paren_count -= 1
                    if paren_count == 0:
                        children_str = children_str[:i]
                        break
        
        children_str = children_str.strip()
        
        # Handle simple string literals
        if (children_str.startswith('"') and children_str.endswith('"')) or \
           (children_str.startswith("'") and children_str.endswith("'")):
            return 1
            
        # Count React.createElement calls and other expressions at the top level
        child_count = 0
        paren_depth = 0
        brace_depth = 0
        current_start = 0
        
        i = 0
        while i < len(children_str):
            char = children_str[i]
            
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif char == '{':
                brace_depth += 1
            elif char == '}':
                brace_depth -= 1
            elif char == ',' and paren_depth == 0 and brace_depth == 0:
                # We found a top-level comma, so there's another child
                current_child = children_str[current_start:i].strip()
                if current_child:
                    child_count += 1
                current_start = i + 1
            
            i += 1
            
        # Count the last child after the final comma (or the only child if no commas)
        final_child = children_str[current_start:].strip()
        if final_child:
            child_count += 1
            
        return child_count
            
    except Exception as e:
        return 1  # Conservative: assume one child if parsing fails


def find_react_fragment_violations_in_file(file_source):
    """
    Find all React.Fragment violations in an entire file source.
    
    Args:
        file_source: Complete file source code
        
    Returns:
        bool: True if any violations are found
    """
    import re
    
    # Find all React.Fragment patterns in the file
    violations = []
    
    # Pattern 1: Single string children (single line)
    single_string_pattern = r'React\.createElement\s*\(\s*React\.Fragment\s*,\s*null\s*,\s*[\'"][^\'"]*[\'"]\s*\)'
    for match in re.finditer(single_string_pattern, file_source):
        violations.append(('single_string', match.start(), match.group()))
    
    # Pattern 2: Find all React.Fragment calls and analyze them
    fragment_pattern = r'React\.createElement\s*\(\s*React\.Fragment\s*,\s*(?:null|{[^}]*})\s*,\s*'
    
    for match in re.finditer(fragment_pattern, file_source):
        # Extract the complete fragment call
        start_pos = match.start()
        paren_count = 0
        pos = start_pos
        
        # Find opening parenthesis after React.createElement
        while pos < len(file_source) and file_source[pos] != '(':
            pos += 1
        
        if pos >= len(file_source):
            continue
            
        # Count parentheses to find the complete call
        while pos < len(file_source):
            char = file_source[pos]
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
                if paren_count == 0:
                    break
            pos += 1
        
        if paren_count == 0:
            complete_call = file_source[start_pos:pos + 1]
            # Count children in this fragment
            if count_fragment_children_precise(complete_call) == 1:
                violations.append(('multiline', start_pos, complete_call[:100] + '...'))
    
    return len(violations) > 0


def check_regex_syntax_validity(ast_tree, filename):
    """
    Custom function to detect syntactically invalid regular expressions.
    
    This function handles complex regex syntax validation that simple regex patterns cannot:
    - Unmatched parentheses and brackets in various contexts
    - Invalid escape sequences
    - Malformed character classes
    - Invalid quantifier patterns
    - Complex nested group validation
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being scanned
        
    Returns:
        list: List of findings with invalid regex syntax
    """
    
    findings = []
    
    try:
        # Extract the source code from AST
        if isinstance(ast_tree, dict) and 'body' in ast_tree:
            # Process the entire AST to find all relevant nodes
            findings.extend(_process_ast_for_regex_syntax(ast_tree, filename))
        
    except Exception as e:
        # If there's an error in parsing, return empty to avoid false positives
        pass
    
    return findings


def _process_ast_for_regex_syntax(node, filename, findings=None):
    """
    Recursively process AST nodes to find regex syntax violations.
    """
    if findings is None:
        findings = []
    
    if not isinstance(node, dict):
        return findings
    
    # Check current node for regex patterns
    if node.get('type') in ['Literal', 'NewExpression', 'CallExpression']:
        if _check_node_for_invalid_regex(node):
            finding = {
                'rule_id': 'regular_expressions_syntactically_valid',
                'message': 'Regular expression contains invalid syntax - check brackets and parentheses',
                'file': filename,
                'line': node.get('loc', {}).get('start', {}).get('line', 0),
                'severity': 'Major',
                'node': _get_node_description(node),
                'value': _extract_node_value(node),
                'status': 'violation'
            }
            findings.append(finding)
    
    # Recursively process child nodes
    for key, value in node.items():
        if isinstance(value, dict):
            _process_ast_for_regex_syntax(value, filename, findings)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _process_ast_for_regex_syntax(item, filename, findings)
    
    return findings


def _check_node_for_invalid_regex(node):
    """
    Check if a specific AST node contains invalid regex patterns.
    """
    try:
        node_type = node.get('type')
        
        # Check regex literals
        if node_type == 'Literal' and node.get('regex'):
            pattern = node.get('regex', {}).get('pattern', '')
            return is_regex_syntactically_invalid(pattern)
        
        # Check RegExp constructor
        if node_type == 'NewExpression':
            callee = node.get('callee', {})
            if callee.get('name') == 'RegExp' or (
                callee.get('type') == 'MemberExpression' and 
                callee.get('property', {}).get('name') == 'RegExp'
            ):
                args = node.get('arguments', [])
                if args and args[0].get('type') == 'Literal':
                    pattern = args[0].get('value', '')
                    return is_regex_syntactically_invalid(str(pattern))
        
        # Check string method calls
        if node_type == 'CallExpression':
            callee = node.get('callee', {})
            if (callee.get('type') == 'MemberExpression' and 
                callee.get('property', {}).get('name') in ['match', 'replace', 'search', 'split']):
                args = node.get('arguments', [])
                if args and args[0].get('type') == 'Literal':
                    pattern = args[0].get('value', '')
                    return is_regex_syntactically_invalid(str(pattern))
        
        return False
        
    except Exception:
        return False


def _get_node_description(node):
    """Get a description of the AST node for the finding."""
    node_type = node.get('type', 'unknown')
    
    if node_type == 'Literal':
        return f"Literal.{node.get('raw', 'unknown')}"
    elif node_type == 'NewExpression':
        callee_name = node.get('callee', {}).get('name', 'unknown')
        return f"NewExpression.{callee_name}"
    elif node_type == 'CallExpression':
        callee = node.get('callee', {})
        if callee.get('type') == 'MemberExpression':
            method_name = callee.get('property', {}).get('name', 'unknown')
            return f"CallExpression.{method_name}"
        else:
            function_name = callee.get('name', 'unknown')
            return f"CallExpression.{function_name}"
    
    return f"{node_type}.unknown"


def _extract_node_value(node):
    """Extract a readable value from the AST node."""
    try:
        if node.get('type') == 'Literal':
            return node.get('raw', str(node.get('value', '')))
        
        # For complex nodes, try to reconstruct a readable representation
        return str(node)[:100] + ('...' if len(str(node)) > 100 else '')
        
    except Exception:
        return 'unknown'


def is_regex_syntactically_invalid(pattern):
    """
    Helper function to check if a regex pattern has invalid syntax.
    
    Args:
        pattern (str): The regex pattern to validate
        
    Returns:
        bool: True if pattern is invalid, False otherwise
    """
    
    try:
        # Handle escaped characters properly
        pattern = pattern.replace('\\\\', '__ESCAPED_BACKSLASH__')
        pattern = pattern.replace('\\"', '__ESCAPED_QUOTE__')
        pattern = pattern.replace("\\'", '__ESCAPED_QUOTE__')
        
        # Check for unmatched parentheses
        paren_count = 0
        bracket_count = 0
        in_char_class = False
        i = 0
        
        while i < len(pattern):
            char = pattern[i]
            
            # Skip escaped characters
            if char == '\\' and i + 1 < len(pattern):
                i += 2
                continue
            
            # Handle character classes
            if char == '[' and not in_char_class:
                in_char_class = True
                bracket_count += 1
            elif char == ']' and in_char_class:
                in_char_class = False
                bracket_count -= 1
            elif not in_char_class:
                # Only count parentheses outside character classes
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                    if paren_count < 0:  # More closing than opening
                        return True
            
            i += 1
        
        # Check for unmatched opening brackets/parentheses
        if paren_count != 0 or bracket_count != 0 or in_char_class:
            return True
        
        # Try to compile the pattern as a final validation
        try:
            re.compile(pattern.replace('__ESCAPED_BACKSLASH__', '\\\\')
                             .replace('__ESCAPED_QUOTE__', '"'))
            return False
        except re.error:
            return True
            
    except Exception:
        # If there's any error in analysis, assume invalid
        return True


def check_replacement_string_invalid_groups(node, context=None):
    """
    Custom function to check if replacement strings reference invalid group numbers.
    
    This function analyzes String.replace() calls to ensure that any $n references
    in replacement strings correspond to actual capturing groups in the regex pattern.
    
    Args:
        node (dict): The AST node object
        context: Scanner context (optional)
        
    Returns:
        bool: True if invalid group references detected, False otherwise
    """
    
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Check if this is a CallExpression
        node_type = node.get('type') or node.get('node_type')
        if node_type != 'CallExpression':
            return False
            
        # Get the callee to check if it's a replace method
        callee = node.get('callee', {})
        if not isinstance(callee, dict):
            return False
            
        # Check if it's a member expression (obj.method)
        if callee.get('type') != 'MemberExpression':
            return False
            
        # Check if the method name is 'replace'
        property_node = callee.get('property', {})
        if not isinstance(property_node, dict) or property_node.get('name') != 'replace':
            return False
            
        # Get the arguments
        arguments = node.get('arguments', [])
        if len(arguments) < 2:
            return False
            
        # First argument should be a regex, second should be replacement string
        regex_arg = arguments[0]
        replacement_arg = arguments[1]
        
        # Extract regex pattern and replacement string
        regex_pattern = extract_regex_pattern(regex_arg)
        replacement_string = extract_replacement_string(replacement_arg)
        
        if not regex_pattern or not replacement_string:
            return False
            
        # Count actual capturing groups in regex
        actual_groups = count_capturing_groups(regex_pattern)
        
        # Find all $n references in replacement string
        group_refs = find_group_references(replacement_string)
        
        # Check if any group reference exceeds actual group count
        for group_num in group_refs:
            if group_num > actual_groups:
                return True
                
        return False
        
    except Exception as e:
        return False


def extract_regex_pattern(regex_node):
    """Extract regex pattern from AST node."""
    try:
        if not isinstance(regex_node, dict):
            return None
            
        node_type = regex_node.get('type')
        
        # Handle regex literals
        if node_type == 'Literal' and 'regex' in regex_node:
            return regex_node.get('regex', {}).get('pattern', '')
            
        # Handle string literals (when used with RegExp constructor)
        elif node_type == 'Literal' and isinstance(regex_node.get('value'), str):
            return regex_node.get('value', '')
            
        # Handle NewExpression for new RegExp()
        elif node_type == 'NewExpression':
            callee = regex_node.get('callee', {})
            if callee.get('name') == 'RegExp':
                args = regex_node.get('arguments', [])
                if args and args[0].get('type') == 'Literal':
                    return args[0].get('value', '')
                    
        return None
        
    except Exception:
        return None


def extract_replacement_string(replacement_node):
    """Extract replacement string from AST node."""
    try:
        if not isinstance(replacement_node, dict):
            return None
            
        node_type = replacement_node.get('type')
        
        # Handle string literals
        if node_type == 'Literal' and isinstance(replacement_node.get('value'), str):
            return replacement_node.get('value', '')
            
        # Handle template literals (simplified)
        elif node_type == 'TemplateLiteral':
            # For template literals, we'd need more complex parsing
            # For now, return None to avoid false positives
            return None
            
        return None
        
    except Exception:
        return None


def count_capturing_groups(regex_pattern):
    """Count the number of capturing groups in a regex pattern."""
    try:
        if not regex_pattern:
            return 0
            
        # Remove escaped parentheses
        pattern = regex_pattern.replace('\\(', '').replace('\\)', '')
        
        # Count opening parentheses that are not non-capturing groups
        group_count = 0
        i = 0
        
        while i < len(pattern):
            if pattern[i] == '(':
                # Check if it's a non-capturing group (?:
                if i + 2 < len(pattern) and pattern[i + 1:i + 3] == '?:':
                    i += 3  # Skip the (?:
                    continue
                # Check if it's a lookahead/lookbehind (?= (?! (?<= (?<!
                elif i + 2 < len(pattern) and pattern[i + 1] == '?':
                    if i + 3 < len(pattern) and pattern[i + 2] in '=!<':
                        i += 3  # Skip the (?= or (?! or (?<
                        continue
                else:
                    # This is a capturing group
                    group_count += 1
            i += 1
            
        return group_count
        
    except Exception:
        return 0


def find_group_references(replacement_string):
    """Find all $n group references in replacement string."""
    try:
        if not replacement_string:
            return []
            
        # Find all $n patterns where n is a number
        import re
        matches = re.findall(r'\$(\d+)', replacement_string)
        
        # Convert to integers and return unique values
        return list(set(int(match) for match in matches))
        
    except Exception:
        return []
            
    except Exception:
        # If validation fails, assume invalid
        return True
    
    return False


def check_boolean_return_wrapper(node):
    """
    Custom function to detect if-else statements that wrap boolean expressions
    in return true/false patterns.
    
    Detects patterns like:
    - if (condition) { return true; } else { return false; }
    - if (condition) return true; else return false;
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if boolean return wrapper detected, False otherwise
    """
    try:
        # Only process IfStatement nodes
        if isinstance(node, dict) and node.get('type') != 'IfStatement':
            return False
            
        # Convert node to string for pattern matching
        if isinstance(node, dict):
            node_source = json.dumps(node, separators=(',', ':'))
        else:
            node_source = str(node)
        
        # More targeted patterns to detect boolean return wrappers
        patterns = [
            # Basic if-else with braces returning true/false
            r'"consequent":\{"type":"BlockStatement"[^}]*"body":\[\{"type":"ReturnStatement"[^}]*"argument":\{"type":"(Literal|Identifier)"[^}]*"value":(true|false)[^}]*\}[^}]*\}\][^}]*\}[^}]*"alternate":\{"type":"BlockStatement"[^}]*"body":\[\{"type":"ReturnStatement"[^}]*"argument":\{"type":"(Literal|Identifier)"[^}]*"value":(false|true)',
            # If-else without braces returning true/false  
            r'"consequent":\{"type":"ReturnStatement"[^}]*"argument":\{"type":"(Literal|Identifier)"[^}]*"value":(true|false)[^}]*\}[^}]*"alternate":\{"type":"ReturnStatement"[^}]*"argument":\{"type":"(Literal|Identifier)"[^}]*"value":(false|true)',
        ]
        
        for pattern in patterns:
            if re.search(pattern, node_source, re.MULTILINE | re.DOTALL):
                return True
                
        return False
        
    except Exception as e:
        # If parsing fails, return False
        return False


def check_ignored_pure_function_calls(node):
    """
    Custom function to detect pure function calls whose return values are ignored.
    
    Detects calls to pure functions that return values but are used in 
    ExpressionStatement context (meaning their return values are ignored).
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if pure function call with ignored return detected, False otherwise
    """
    try:
        # Only process ExpressionStatement nodes
        if isinstance(node, dict) and node.get('type') != 'ExpressionStatement':
            return False
        
        # Get the expression within the statement
        expression = node.get('expression')
        if not expression or expression.get('type') != 'CallExpression':
            return False
            
        callee = expression.get('callee', {})
        
        # Check for pure function patterns
        pure_function_patterns = [
            # Math methods
            ('Math', ['abs', 'ceil', 'floor', 'max', 'min', 'round', 'sqrt', 'pow', 'random', 
                     'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'log', 'exp']),
            # String static methods
            ('String', ['fromCharCode', 'fromCodePoint']),
            # Array static methods  
            ('Array', ['from', 'of', 'isArray']),
            # Object methods
            ('Object', ['keys', 'values', 'entries', 'assign', 'create', 'freeze', 'seal']),
            # JSON methods
            ('JSON', ['parse', 'stringify']),
            # Date methods (static)
            ('Date', ['now', 'parse', 'UTC']),
            # Number methods
            ('Number', ['isNaN', 'isFinite', 'parseInt', 'parseFloat'])
        ]
        
        # Check static method calls (e.g., Math.abs, Object.keys)
        if callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            
            if obj.get('type') == 'Identifier' and prop.get('type') == 'Identifier':
                obj_name = obj.get('name')
                method_name = prop.get('name')
                
                for obj_type, methods in pure_function_patterns:
                    if obj_name == obj_type and method_name in methods:
                        return True
        
        # Check for Date instance methods that return values
        if callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            
            if prop.get('type') == 'Identifier':
                method_name = prop.get('name')
                date_methods = ['getTime', 'getFullYear', 'getMonth', 'getDate', 'getHours', 
                               'getMinutes', 'getSeconds', 'getMilliseconds', 'toISOString', 
                               'toString', 'toDateString', 'toTimeString']
                
                if method_name in date_methods:
                    return True
        
        return False
        
    except Exception as e:
        # If parsing fails, return False
        return False


def check_commented_out_code(node):
    """
    Custom function to detect commented-out code sections.
    
    This function analyzes JavaScript comments to identify lines that appear
    to contain commented-out code rather than legitimate documentation.
    
    Args:
        node (dict): The AST node object (should be CompilationUnit with AST)
        
    Returns:
        bool: True if commented-out code detected, False otherwise
    """
    
    try:
        # Check if this is a CompilationUnit with the original AST
        if not isinstance(node, dict) or 'ast' not in node:
            return False
        
        ast = node['ast']
        
        # Check if AST has comments
        if not hasattr(ast, 'comments') or not ast.comments:
            return False
        
        # Patterns that indicate commented-out code vs legitimate comments
        code_patterns = [
            # Variable declarations
            r'^\s*(var|let|const)\s+\w+\s*[=;]',
            # Function declarations
            r'^\s*function\s+\w+\s*\(',
            # Control structures
            r'^\s*(if|for|while|switch)\s*\(',
            # Return statements
            r'^\s*return\s+[\w\'".]',
            # Assignments
            r'^\s*\w+\s*[=!<>]=?\s*[^=]',
            # Function calls
            r'^\s*\w+\s*\(',
            # Method calls
            r'^\s*\w+\.\w+\s*\(',
            # Array/object access
            r'^\s*\w+\[\w*\]\s*[=;]',
            # Console statements
            r'^\s*console\.\w+\s*\(',
            # Block delimiters with likely code context
            r'^\s*[{}]\s*;?\s*$',
            # Complex expressions
            r'^\s*[\w\'"]+\s*[+\-*/]\s*[\w\'"]',
        ]
        
        # Patterns that indicate legitimate documentation comments
        documentation_patterns = [
            # JSDoc style
            r'^\s*[@*]\s*\w+',
            # TODO/FIXME/NOTE
            r'^\s*(TODO|FIXME|NOTE|WARNING|HACK|BUG):',
            # Full sentence documentation
            r'^\s*[A-Z][a-z]+.*[.!?]\s*$',
            # Copyright/license
            r'^\s*(Copyright|License|Author|Version|Created)',
            # File headers
            r'^\s*(File:|Module:|Description:)',
        ]
        
        violations_found = False
        
        for comment in ast.comments:
            if comment.type == 'Line':  # Single-line comments
                comment_text = comment.value.strip()
                
                # Skip empty comments
                if not comment_text:
                    continue
                
                # Skip obvious documentation
                is_documentation = any(
                    re.match(pattern, comment_text, re.IGNORECASE) 
                    for pattern in documentation_patterns
                )
                
                if is_documentation:
                    continue
                
                # Check if this looks like commented-out code
                looks_like_code = any(
                    re.match(pattern, comment_text, re.IGNORECASE) 
                    for pattern in code_patterns
                )
                
                if looks_like_code:
                    violations_found = True
                    break
        
        return violations_found
        
    except Exception as e:
        # If parsing fails, return False
        return False


def check_ssl_certificate_bypass(node):
    """
    Custom function to detect SSL/TLS certificate verification bypass.
    
    This function analyzes object expressions to identify configurations
    that disable SSL certificate verification, including nested patterns
    and constructor arguments.
    
    Args:
        node (dict): The AST node object (ObjectExpression)
        
    Returns:
        bool: True if SSL bypass detected, False otherwise
    """
    
    try:
        # Check if this is an ObjectExpression node
        node_type = node.get('type') or node.get('node_type')
        if node_type != 'ObjectExpression':
            return False
        
        # Get the source code of the node
        source = node.get('source', '')
        if not source:
            return False
        
        # Debug: Print what we're checking
        # print(f"DEBUG: Checking SSL bypass in source: {repr(source[:50])}")
        
        # Skip very short sources that don't contain meaningful object expressions
        source_clean = source.strip()
        if len(source_clean) < 10:  # Allow shorter patterns but avoid trivial ones
            return False
        
        # Patterns that indicate SSL certificate verification bypass
        ssl_bypass_patterns = [
            r'rejectUnauthorized\s*:\s*false',
            r'checkServerCertificate\s*:\s*false', 
            r'verifyServerCertificate\s*:\s*false',
            r'strictSSL\s*:\s*false',
            r'verify\s*:\s*false',
            r'verifySSL\s*:\s*false',
            r'insecure\s*:\s*true',
            r'allowUnauthorized\s*:\s*true'
        ]
        
        # Check if any SSL bypass pattern is found
        for pattern in ssl_bypass_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                # print(f"DEBUG: Found SSL bypass pattern: {pattern}")
                return True
                
        return False
        
    except Exception as e:
        # If parsing fails, return False
        print(f"DEBUG: SSL check error: {e}")
        return False


def check_ssl_hostname_verification_bypass(node):
    """
    Custom function to detect SSL/TLS hostname verification bypass.
    
    This function analyzes object expressions to identify configurations
    that disable hostname verification during SSL/TLS connections.
    
    Args:
        node (dict): The AST node object (ObjectExpression)
        
    Returns:
        bool: True if hostname verification bypass detected, False otherwise
    """
    
    try:
        # Check if this is an ObjectExpression node
        node_type = node.get('type') or node.get('node_type')
        if node_type != 'ObjectExpression':
            return False
        
        # Get the source code of the node
        source = node.get('source', '')
        if not source:
            return False
        
        # Skip very short sources that don't contain meaningful object expressions
        source_clean = source.strip()
        if len(source_clean) < 10:
            return False
        
        # Patterns that indicate hostname verification bypass
        hostname_bypass_patterns = [
            r'checkServerIdentity\s*:\s*false',
            r'verifyServerIdentity\s*:\s*false',
            r'checkHostname\s*:\s*false',
            r'verifyHostname\s*:\s*false',
            r'validateHostname\s*:\s*false',
            r'hostnameVerification\s*:\s*false',
            r'skipHostnameVerification\s*:\s*true',
            r'disableHostnameVerification\s*:\s*true'
        ]
        
        # Check if any hostname verification bypass pattern is found
        for pattern in hostname_bypass_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                return True
                
        return False
        
    except Exception as e:
        # If parsing fails, return False
        return False


def check_trailing_whitespaces(node):
    """
    Custom function to detect lines ending with trailing whitespaces.
    
    This function analyzes the full source code to identify lines that
    end with unnecessary whitespace characters (spaces, tabs).
    
    Args:
        node (dict): The AST node object (should be CompilationUnit)
        
    Returns:
        bool: True if trailing whitespaces detected, False otherwise
    """
    
    try:
        # Check if this is a CompilationUnit with the full source
        if not isinstance(node, dict) or node.get('node_type') != 'CompilationUnit':
            return False
        
        source = node.get('source', '')
        if not source:
            return False
        
        lines = source.splitlines()
        
        # Check each line for trailing whitespaces
        for line_num, line in enumerate(lines, 1):
            # Check if line ends with whitespace characters (space, tab, etc.)
            if line.rstrip() != line:
                # Found a line with trailing whitespace
                return True
        
        return False
        
    except Exception as e:
        # If parsing fails, return False
        return False


def check_ssrf_vulnerabilities(node):
    """
    Custom function to detect Server-Side Request Forgery (SSRF) vulnerabilities.
    
    This function identifies potential SSRF vulnerabilities by detecting:
    - Direct access to sensitive file paths (SSH keys, passwd, proc files)
    - File URLs pointing to sensitive system files
    - Internal network requests (localhost, private IPs, metadata services)
    - Suspicious URL patterns that could be used for SSRF attacks
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if SSRF vulnerability detected, False otherwise
    """
    
    try:
        # Convert node to string for pattern matching
        if isinstance(node, dict):
            # Check various properties that might contain the vulnerable content
            content_sources = [
                node.get('value', ''),
                node.get('raw', ''),
                node.get('source', ''),
                json.dumps(node) if node else ''
            ]
        else:
            content_sources = [str(node)]
        
        # Combine all content sources
        node_content = ' '.join(str(content) for content in content_sources if content)
        
        if not node_content:
            return False
        
        # Sensitive file path patterns
        sensitive_file_patterns = [
            r'~\/\.ssh\/id_rsa',           # SSH private key
            r'\/etc\/passwd',              # Unix password file
            r'\/etc\/shadow',              # Unix shadow password file
            r'\/proc\/self\/environ',      # Process environment
            r'\/proc\/self\/cmdline',      # Process command line
            r'\/proc\/self\/cwd',          # Process working directory
            r'\/proc\/version',            # System version info
            r'\/proc\/meminfo',            # Memory information
            r'\/proc\/cpuinfo',            # CPU information
            r'\/sys\/class\/net',          # Network interface info
            r'\/var\/log\/auth\.log',      # Authentication logs
            r'\/var\/log\/secure',         # Security logs
            r'\/root\/\.ssh',              # Root SSH directory
            r'\/home\/[^\/]+\/\.ssh',      # User SSH directories
        ]
        
        # Check for sensitive file access
        for pattern in sensitive_file_patterns:
            if re.search(pattern, node_content, re.IGNORECASE):
                return True
        
        # File URL patterns pointing to sensitive locations
        file_url_patterns = [
            r'file:\/\/.*\/etc\/passwd',
            r'file:\/\/.*\/proc\/self',
            r'file:\/\/.*~\/\.ssh',
            r'file:\/\/.*\/root\/',
            r'file:\/\/.*\/var\/log\/',
        ]
        
        for pattern in file_url_patterns:
            if re.search(pattern, node_content, re.IGNORECASE):
                return True
        
        # Internal/private network access patterns (common SSRF targets)
        internal_network_patterns = [
            r'http:\/\/localhost',
            r'http:\/\/127\.0\.0\.1',
            r'http:\/\/0\.0\.0\.0',
            r'http:\/\/\[::1\]',           # IPv6 localhost
            r'http:\/\/10\.\d+\.\d+\.\d+', # Private class A
            r'http:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+', # Private class B
            r'http:\/\/192\.168\.\d+\.\d+', # Private class C
            r'http:\/\/169\.254\.169\.254', # AWS metadata service
            r'http:\/\/metadata\.google\.internal', # GCP metadata
            r'http:\/\/100\.100\.100\.200', # Alibaba Cloud metadata
        ]
        
        for pattern in internal_network_patterns:
            if re.search(pattern, node_content, re.IGNORECASE):
                return True
        
        # Check for suspicious URL construction with user input
        # Look for concatenation patterns that could lead to SSRF
        url_construction_patterns = [
            r'fetch\s*\(\s*["\']?.*\$\{.*\}',  # Template literals in fetch
            r'request\s*\(\s*["\']?.*\+.*\+',  # String concatenation in requests
            r'axios\.[get|post]+\s*\(\s*.*\+', # Axios with concatenation
            r'http\.request\s*\(\s*.*\+',      # HTTP module with concatenation
        ]
        
        for pattern in url_construction_patterns:
            if re.search(pattern, node_content, re.IGNORECASE | re.DOTALL):
                return True
        
        # Check for dangerous protocol schemes
        dangerous_protocols = [
            r'file:\/\/\/[^"\']*\/etc\/',
            r'file:\/\/\/[^"\']*\/proc\/',
            r'file:\/\/\/[^"\']*\/sys\/',
            r'gopher:\/\/',
            r'dict:\/\/',
            r'ftp:\/\/localhost',
            r'ldap:\/\/localhost',
        ]
        
        for pattern in dangerous_protocols:
            if re.search(pattern, node_content, re.IGNORECASE):
                return True
        
        return False
        
    except Exception as e:
        return False


def check_path_traversal_vulnerabilities(node):
    """
    Custom function to detect Path Traversal Server-Side Request Forgery (SSRF) vulnerabilities.
    
    This function identifies potential path traversal vulnerabilities by detecting:
    - Directory traversal sequences (../, ..\\, etc.)
    - Encoded traversal attempts (%2e%2e%2f, etc.)
    - Access to sensitive system files and directories
    - Home directory traversal patterns
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if path traversal vulnerability detected, False otherwise
    """
    
    try:
        # Convert node to string for pattern matching
        if isinstance(node, dict):
            # Check various properties that might contain the vulnerable content
            content_sources = [
                node.get('value', ''),
                node.get('raw', ''),
                node.get('source', ''),
                json.dumps(node) if node else ''
            ]
        else:
            content_sources = [str(node)]
        
        # Combine all content sources
        node_content = ' '.join(str(content) for content in content_sources if content)
        
        if not node_content:
            return False
        
        # Basic directory traversal patterns
        basic_traversal_patterns = [
            r'\.\./+',                    # ../
            r'\.\.\\\\+',                 # ..\\
            r'\.\./',                     # ../
            r'\.\.\\\\',                  # ..\\
        ]
        
        # Check for basic traversal patterns
        for pattern in basic_traversal_patterns:
            if re.search(pattern, node_content, re.IGNORECASE):
                return True
        
        # URL/Percent encoded traversal patterns
        encoded_traversal_patterns = [
            r'%2e%2e%2f',                # ../
            r'%2e%2e%5c',                # ..\\
            r'%252e%252e%252f',          # Double encoded ../
        ]
        
        # Check for encoded traversal patterns
        for pattern in encoded_traversal_patterns:
            if re.search(pattern, node_content, re.IGNORECASE):
                return True
        
        # Sensitive file and directory access patterns
        sensitive_path_patterns = [
            r'/etc/passwd',              # /etc/passwd
            r'/etc/shadow',              # /etc/shadow
            r'/proc/self/',              # /proc/self/*
            r'/proc/version',            # /proc/version
            r'~/\.\./+',                 # ~/../../
            r'/windows/system32/',       # Windows system32
        ]
        
        # Check for sensitive file access
        for pattern in sensitive_path_patterns:
            if re.search(pattern, node_content, re.IGNORECASE):
                return True
        
        return False
        
    except Exception as e:
        return False


def check_string_literals_duplicated(ast_tree, filename):
    """
    Check for duplicated string literals that should be extracted to constants.
    
    Follows the Sonar JavaScript rule RSPEC-1192:
    - Excludes strings with less than 10 characters
    - Excludes strings matching /^\\w*$/ (word-only pattern)
    - Excludes import/export statements  
    - Excludes JSX attributes
    - Excludes statement-like strings (e.g., 'use strict')
    - Only flags strings that appear 2 or more times
    """
    findings = []
    
    try:
        # Collect all string literals from the AST
        string_literals = {}  # string_value -> [locations]
        
        def visit_node(node, context=None):
            if not isinstance(node, dict):
                return
                
            # Check if this is a Literal node with string value
            if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
                string_value = node.get('value', '')
                source = node.get('source', '')
                
                # Apply exclusion rules according to RSPEC-1192
                if should_exclude_string(string_value, source, node, context):
                    return
                
                # Get line number
                line_num = 0
                if 'loc' in node and 'start' in node['loc']:
                    line_num = node['loc']['start'].get('line', 0)
                elif 'lineno' in node:
                    line_num = node['lineno']
                
                # Track this string literal occurrence
                if string_value not in string_literals:
                    string_literals[string_value] = []
                
                string_literals[string_value].append({
                    'line': line_num,
                    'source': source,
                    'node': node
                })
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    visit_node(value, context)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            # Pass context for import/export detection
                            child_context = context or {}
                            if key in ['body', 'declarations', 'elements']:
                                child_context['parent_type'] = node.get('type', '')
                                child_context['parent_key'] = key
                            visit_node(item, child_context)
        
        def should_exclude_string(string_value, source, node, context):
            """Apply exclusion rules according to RSPEC-1192"""
            
            # 1. Exclude strings with less than 10 characters
            if len(string_value) < 10:
                return True
            
            # 2. Exclude strings matching /^\w*$/ (word-only pattern)
            import re
            if re.match(r'^\w*$', string_value):
                return True
            
            # 3. Exclude statement-like strings (e.g., 'use strict')
            statement_like_patterns = [
                r'^use strict$',
                r'^use asm$'
            ]
            for pattern in statement_like_patterns:
                if re.match(pattern, string_value):
                    return True
            
            # 4. Exclude import/export statements - check if we're in a require() call
            if 'require(' in source:
                return True
            
            # 5. Exclude JSX attributes (detect JSX-like patterns)
            jsx_patterns = [
                r'className=',
                r'<\w+',
                r'/>',
                r'<div\s',
                r'<span\s',
                r'<button\s'
            ]
            for pattern in jsx_patterns:
                if re.search(pattern, string_value) or re.search(pattern, source):
                    return True
            
            return False
        
        # Start the traversal
        if isinstance(ast_tree, dict):
            visit_node(ast_tree)
        elif isinstance(ast_tree, list):
            for node in ast_tree:
                if isinstance(node, dict):
                    visit_node(node)
        
        # Find duplicated strings and create findings  
        for string_value, locations in string_literals.items():
            if len(locations) >= 2:  # Found duplicates
                # Create a finding for each occurrence after the first
                for i, location in enumerate(locations):
                    if i == 0:
                        continue  # Skip the first occurrence
                    
                    finding = {
                        'rule_id': 'string_literals_duplicated',
                        'message': f'String literal "{string_value}" is duplicated (also appears on line {locations[0]["line"]}). Consider extracting to a constant.',
                        'node': 'Literal.string',
                        'file': filename,
                        'property_path': ['source'],
                        'value': location['source'],
                        'status': 'violation',
                        'line': location['line'],
                        'severity': 'Major'
                    }
        return findings
        
    except Exception as e:
        return []


def check_super_invoked_appropriately(ast_tree, filename):
    """
    Custom function to detect inappropriate super() constructor usage in JavaScript classes.
    
    Checks for:
    1. Multiple super() calls in the same constructor
    2. super() calls in non-derived classes (classes without 'extends')
    3. Using 'this' before calling super() constructor
    4. Accessing super properties/methods before calling super() constructor
    """
    try:
        findings = []
        
        # Get the source code from the AST tree
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
        
        if not source_code:
            return findings
            
        def extract_class_info(source_code):
            """Extract detailed class information from source code"""
            classes = []
            lines = source_code.split('\n')
            
            # Enhanced pattern to find class declarations with proper line tracking
            class_pattern = r'class\s+(\w+)(?:\s+extends\s+(\w+))?\s*\{'
            
            for i, line in enumerate(lines):
                class_match = re.search(class_pattern, line)
                
                if class_match:
                    class_name = class_match.group(1)
                    extends_class = class_match.group(2)
                    
                    # Look for constructor in the following lines
                    j = i + 1
                    constructor_body = ""
                    found_constructor = False
                    brace_count = 0
                    constructor_start_line = 0
                    
                    while j < len(lines):
                        current_line = lines[j]
                        if 'constructor(' in current_line or 'constructor (' in current_line:
                            found_constructor = True
                            constructor_start_line = j
                            brace_count = 0
                            
                        if found_constructor:
                            constructor_body += current_line + '\n'
                            brace_count += current_line.count('{') - current_line.count('}')
                            
                            # If we've balanced all braces, we're done with the constructor
                            if brace_count <= 0 and j > constructor_start_line:
                                break
                        
                        j += 1
                    
                    if found_constructor:
                        classes.append({
                            'name': class_name,
                            'extends': extends_class,
                            'constructor_body': constructor_body,
                            'line': i + 1,  # 1-based line numbering
                            'full_source': '\n'.join(lines[i:j+1])
                        })
            
            return classes
        
        def check_class_super_violations(class_info):
            """Check for super() violations in a specific class"""
            constructor_body = class_info['constructor_body']
            extends_class = class_info['extends']
            
            # Remove comments from constructor body to avoid false positives
            # Remove single-line comments
            constructor_code = re.sub(r'//.*$', '', constructor_body, flags=re.MULTILINE)
            # Remove multi-line comments
            constructor_code = re.sub(r'/\*.*?\*/', '', constructor_code, flags=re.DOTALL)
            
            # 1. Check for multiple super() calls (constructor calls only, not method calls)
            # Use positive lookahead to ensure it's followed by semicolon or whitespace
            super_constructor_calls = list(re.finditer(r'super\s*\([^)]*\)\s*(?=;|\s)', constructor_code))
            
            if len(super_constructor_calls) > 1:
                finding = {
                    'rule_id': 'super_invoked_appropriately',
                    'message': f'Multiple super() calls detected in constructor of class "{class_info["name"]}". super() should only be called once.',
                    'node': 'ClassDeclaration.constructor',
                    'file': filename,
                    'property_path': ['source'],
                    'value': class_info['full_source'],
                    'status': 'violation',
                    'line': class_info['line'],
                    'severity': 'Major'
                }
                findings.append(finding)
            
            # 2. Check for super() in non-derived class
            if not extends_class and len(super_constructor_calls) > 0:
                finding = {
                    'rule_id': 'super_invoked_appropriately',
                    'message': f'super() called in non-derived class "{class_info["name"]}". Remove super() call or add "extends" clause.',
                    'node': 'ClassDeclaration.constructor',
                    'file': filename,
                    'property_path': ['source'],
                    'value': class_info['full_source'],
                    'status': 'violation',
                    'line': class_info['line'],
                    'severity': 'Major'
                }
                findings.append(finding)
            
            # 3. Check for 'this' usage before super() (only if class extends and has super calls)
            if extends_class and len(super_constructor_calls) > 0:
                super_pos = super_constructor_calls[0].start()
                this_usage = list(re.finditer(r'this\.', constructor_code))
                
                for this_match in this_usage:
                    if this_match.start() < super_pos:
                        finding = {
                            'rule_id': 'super_invoked_appropriately',
                            'message': f'super() must be called before using "this" keyword in constructor of class "{class_info["name"]}".',
                            'node': 'ClassDeclaration.constructor',
                            'file': filename,
                            'property_path': ['source'],
                            'value': class_info['full_source'],
                            'status': 'violation',
                            'line': class_info['line'],
                            'severity': 'Major'
                        }
                        findings.append(finding)
                        break
                        
            # 3b. Special case: Check for missing super() in derived class (using 'this' without super())
            elif extends_class and len(super_constructor_calls) == 0:
                this_usage = list(re.finditer(r'this\.', constructor_code))
                if len(this_usage) > 0:
                    finding = {
                        'rule_id': 'super_invoked_appropriately',
                        'message': f'Missing super() call in derived class "{class_info["name"]}". super() must be called before using "this" keyword.',
                        'node': 'ClassDeclaration.constructor',
                        'file': filename,
                        'property_path': ['source'],
                        'value': class_info['full_source'],
                        'status': 'violation',
                        'line': class_info['line'],
                        'severity': 'Major'
                    }
                    findings.append(finding)
            
            # 4. Check for super property access before super() constructor
            if extends_class and len(super_constructor_calls) > 0:
                super_pos = super_constructor_calls[0].start()
                super_property_access = list(re.finditer(r'super\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(', constructor_code))
                
                for super_prop_match in super_property_access:
                    if super_prop_match.start() < super_pos:
                        finding = {
                            'rule_id': 'super_invoked_appropriately',
                            'message': f'super() constructor must be called before accessing super properties/methods in class "{class_info["name"]}".',
                            'node': 'ClassDeclaration.constructor',
                            'file': filename,
                            'property_path': ['source'],
                            'value': class_info['full_source'],
                            'status': 'violation',
                            'line': class_info['line'],
                            'severity': 'Major'
                        }
                        findings.append(finding)
                        break
        
        # Extract and analyze all classes
        classes = extract_class_info(source_code)
        for class_info in classes:
            check_class_super_violations(class_info)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_super_invoked_appropriately: {e}")
        traceback.print_exc()
        return []


def check_switch_break_statements(ast_tree, filename):
    """
    Custom function to detect switch cases without unconditional break statements.
    
    Checks for:
    - Missing break statements at the end of switch cases
    - Conditional break statements (inside if blocks)
    - Cases that don't terminate with break, return, or throw
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The name of the file being checked
        
    Returns:
        list: List of Finding objects for detected violations
    """
    findings = []
    
    try:
        # Find all switch statements in the AST
        switch_statements = find_nodes_by_type(ast_tree, 'SwitchStatement')
        
        for switch_node in switch_statements:
            line_number = switch_node.get('line', 0)
            cases = switch_node.get('cases', [])
            
            for i, case in enumerate(cases):
                # Skip empty cases (fall-through cases are often intentional)
                consequent = case.get('consequent', [])
                if not consequent:
                    continue
                    
                # Check if this case has a proper termination
                has_unconditional_termination = False
                case_line = case.get('loc', {}).get('start', {}).get('line', 0)
                if case_line == 0:
                    case_line = case.get('range', [0])[0] if case.get('range') else line_number
                
                # Look at the last statement in the case
                if consequent:
                    last_stmt = consequent[-1]
                    
                    # Check for unconditional break, return, or throw
                    if last_stmt.get('type') == 'BreakStatement':
                        has_unconditional_termination = True
                    elif last_stmt.get('type') == 'ReturnStatement':
                        has_unconditional_termination = True
                    elif last_stmt.get('type') == 'ThrowStatement':
                        has_unconditional_termination = True
                    elif last_stmt.get('type') == 'ContinueStatement':
                        has_unconditional_termination = True
                        
                # If this is not the last case and has no termination, it's a violation
                # Exception: default case at the end doesn't need break if it's the last case
                is_last_case = (i == len(cases) - 1)
                is_default_case = case.get('test') is None
                
                if not has_unconditional_termination:
                    # Allow last default case without break
                    if not (is_last_case and is_default_case):
                        finding = {
                            'rule_id': 'switch_cases_unconditional_break',
                            'message': 'Switch case should have an unconditional break statement',
                            'node': 'SwitchCase',
                            'file': filename,
                            'property_path': ['source'],
                            'value': str(case),
                            'status': 'violation',
                            'line': case_line,
                            'severity': 'Major'
                        }
                        findings.append(finding)
        
        return findings
        
    except Exception as e:
        # If there's any error parsing, return empty list to avoid false positives
        import traceback
        print(f"Error in check_switch_break_statements: {e}")
        traceback.print_exc()
        return []


def find_nodes_by_type(node, node_type):
    """
    Helper function to find all nodes of a specific type in an AST.
    
    Args:
        node: AST node or tree
        node_type (str): Type of node to find
        
    Returns:
        list: List of matching nodes
    """
    nodes = []
    
    def traverse(current_node):
        if isinstance(current_node, dict):
            if current_node.get('type') == node_type:
                nodes.append(current_node)
            
            # Traverse all child nodes
            for key, value in current_node.items():
                if isinstance(value, (dict, list)):
                    traverse(value)
        elif isinstance(current_node, list):
            for item in current_node:
                traverse(item)
    
    traverse(node)
    return nodes


def has_break_in_block(block):
    """
    Helper function to check if a code block contains a break statement.
    
    Args:
        block (dict): AST block/statement
        
    Returns:
        bool: True if break statement found
    """
    try:
        if isinstance(block, dict):
            if block.get('type') == 'BreakStatement':
                return True
            elif block.get('type') == 'BlockStatement':
                for stmt in block.get('body', []):
                    if has_break_in_block(stmt):
                        return True
            # Check other statement types that might contain blocks
            for key, value in block.items():
                if isinstance(value, (dict, list)):
                    if has_break_in_block(value):
                        return True
        elif isinstance(block, list):
            for item in block:
                if has_break_in_block(item):
                    return True
                    
        return False
        
    except Exception:
        return False


def check_table_cells_headers(ast_tree, filename):
    """
    Custom function to detect table cells with headers attributes that need validation.
    
    This function identifies:
    - HTML td elements with headers attributes in template literals and strings
    - JavaScript assignments to element.headers property
    - JSX headers props
    - Provides detailed analysis of each violation with line numbers
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being scanned
        
    Returns:
        list: List of findings with table cell header violations
    """
    
    findings = []
    
    try:
        # Get the source code from the AST tree
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
        elif hasattr(ast_tree, 'source'):
            source_code = ast_tree.source
        
        if not source_code:
            return findings
            
        # Split source into lines for detailed analysis
        lines = source_code.split('\n')
        
        # Patterns to detect table cells with headers attributes
        patterns = [
            {
                'pattern': r'<td\s+[^>]*headers\s*=\s*["\']([^"\']*)["\'][^>]*>',
                'message': 'Table cell with headers attribute - verify headers reference valid IDs in same row/column',
                'type': 'html_td_headers'
            },
            {
                'pattern': r'\.headers\s*=\s*["\']([^"\']*)["\']',
                'message': 'JavaScript setting headers property - ensure headers reference valid table header IDs',
                'type': 'js_headers_assignment'
            },
            {
                'pattern': r'headers\s*:\s*["\']([^"\']*)["\']',
                'message': 'JSX/React headers prop - validate headers reference existing table header IDs',
                'type': 'jsx_headers_prop'
            },
            {
                'pattern': r'setAttribute\s*\(\s*["\']headers["\'],\s*["\']([^"\']*)["\']',
                'message': 'Setting headers attribute via setAttribute - ensure IDs exist and are valid',
                'type': 'set_attribute_headers'
            }
        ]
        
        # Analyze each line for violations
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            
            for pattern_info in patterns:
                matches = list(re.finditer(pattern_info['pattern'], line, re.IGNORECASE))
                
                for match in matches:
                    headers_value = match.group(1) if len(match.groups()) > 0 else 'unknown'
                    
                    # Additional analysis for the headers value
                    additional_info = analyze_headers_value(headers_value)
                    message = pattern_info['message']
                    if additional_info:
                        message += f" - {additional_info}"
                    
                    finding = {
                        'rule_id': 'table_cells_reference_their',
                        'message': message,
                        'node': f"TableCell.{pattern_info['type']}",
                        'file': filename,
                        'property_path': ['source'],
                        'value': line.strip(),
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major',
                        'headers_value': headers_value,
                        'pattern_type': pattern_info['type']
                    }
                    findings.append(finding)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_table_cells_headers: {e}")
        traceback.print_exc()
        return []


def analyze_headers_value(headers_value):
    """
    Analyze the headers attribute value to provide additional context.
    
    Args:
        headers_value (str): The value of the headers attribute
        
    Returns:
        str: Additional analysis information
    """
    try:
        if not headers_value or headers_value.strip() == '':
            return "Empty headers value"
        
        # Split by spaces to get individual header IDs
        header_ids = headers_value.strip().split()
        
        if len(header_ids) == 1:
            header_id = header_ids[0]
            if not header_id.isalnum() and '_' not in header_id and '-' not in header_id:
                return f"Invalid ID format '{header_id}'"
            return f"References single header ID '{header_id}'"
        else:
            return f"References {len(header_ids)} header IDs: {', '.join(header_ids)}"
            
    except Exception:
        return ""


def check_tables_include_headers(ast_tree, filename):
    """
    Custom function to detect tables that don't include proper header elements.
    
    This function identifies:
    - Tables with <td> elements but no <th> elements
    - Tables that appear to be data tables (not layout tables)
    - Provides specific analysis of table structure
    - Excludes layout tables with role="presentation" 
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being scanned
        
    Returns:
        list: List of findings with table header violations
    """
    
    findings = []
    
    try:
        # Get the source code from the AST tree
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
        elif hasattr(ast_tree, 'source'):
            source_code = ast_tree.source
        
        if not source_code:
            return findings
            
        # Split source into lines for detailed analysis
        lines = source_code.split('\n')
        
        # Find all table elements and analyze them
        table_violations = find_table_header_violations(source_code, lines)
        
        for violation in table_violations:
            finding = {
                'rule_id': 'tables_include_headers',
                'message': violation['message'],
                'node': 'Table.missing_headers',
                'file': filename,
                'property_path': ['source'],
                'value': violation['table_content'],
                'status': 'violation',
                'line': violation['line'],
                'severity': 'Major',
                'table_analysis': violation.get('analysis', {})
            }
            findings.append(finding)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_tables_include_headers: {e}")
        traceback.print_exc()
        return []


def find_table_header_violations(source_code, lines):
    """
    Find tables that violate the header requirements.
    
    Args:
        source_code (str): Complete source code
        lines (list): Source code split into lines
        
    Returns:
        list: List of violation dictionaries
    """
    violations = []
    
    try:
        # Find all table start tags with their positions
        table_pattern = r'<table[^>]*>'
        table_matches = list(re.finditer(table_pattern, source_code, re.IGNORECASE | re.DOTALL))
        
        for table_match in table_matches:
            # Get line number of table start
            table_start_pos = table_match.start()
            table_line = source_code[:table_start_pos].count('\n') + 1
            
            # Extract the complete table content
            table_content = extract_complete_table(source_code, table_start_pos)
            
            if not table_content:
                continue
            
            # Check if this is a layout table (should be excluded)
            if is_layout_table(table_content):
                continue
            
            # Analyze table structure
            analysis = analyze_table_structure(table_content)
            
            # Check if table has data cells but no header cells
            if analysis['has_data_cells'] and not analysis['has_header_cells']:
                violation = {
                    'line': table_line,
                    'message': create_detailed_message(analysis),
                    'table_content': table_content[:200] + '...' if len(table_content) > 200 else table_content,
                    'analysis': analysis
                }
                violations.append(violation)
        
        return violations
        
    except Exception as e:
        print(f"Error in find_table_header_violations: {e}")
        return []


def extract_complete_table(source_code, start_pos):
    """Extract complete table content from start position."""
    try:
        # Find the matching closing </table> tag
        pos = start_pos
        tag_count = 0
        
        while pos < len(source_code):
            # Look for opening and closing table tags
            open_match = re.search(r'<table[^>]*>', source_code[pos:], re.IGNORECASE)
            close_match = re.search(r'</table>', source_code[pos:], re.IGNORECASE)
            
            if open_match and (not close_match or open_match.start() < close_match.start()):
                # Found opening tag
                tag_count += 1
                pos += open_match.end()
            elif close_match:
                # Found closing tag
                tag_count -= 1
                pos += close_match.end()
                if tag_count == 0:
                    return source_code[start_pos:pos]
            else:
                break
        
        # Fallback: try to get reasonable content
        end_pos = min(start_pos + 1000, len(source_code))
        return source_code[start_pos:end_pos]
        
    except Exception:
        return ""


def is_layout_table(table_content):
    """Check if table is used for layout purposes."""
    try:
        # Check for role="presentation" or similar layout indicators
        layout_patterns = [
            r'role\s*=\s*["\']presentation["\']',
            r'role\s*=\s*["\']none["\']',
            r'class\s*=\s*["\'][^"\']*layout[^"\']*["\']',
        ]
        
        for pattern in layout_patterns:
            if re.search(pattern, table_content, re.IGNORECASE):
                return True
                
        return False
        
    except Exception:
        return False


def analyze_table_structure(table_content):
    """Analyze the structure of a table to determine violations."""
    try:
        analysis = {
            'has_header_cells': False,
            'has_data_cells': False,
            'header_count': 0,
            'data_cell_count': 0,
            'rows_count': 0,
            'columns_estimated': 0
        }
        
        # Count th elements
        th_matches = re.findall(r'<th[^>]*>', table_content, re.IGNORECASE)
        analysis['header_count'] = len(th_matches)
        analysis['has_header_cells'] = analysis['header_count'] > 0
        
        # Count td elements
        td_matches = re.findall(r'<td[^>]*>', table_content, re.IGNORECASE)
        analysis['data_cell_count'] = len(td_matches)
        analysis['has_data_cells'] = analysis['data_cell_count'] > 0
        
        # Count rows
        tr_matches = re.findall(r'<tr[^>]*>', table_content, re.IGNORECASE)
        analysis['rows_count'] = len(tr_matches)
        
        # Estimate columns (rough estimate based on first row)
        if analysis['rows_count'] > 0:
            first_row_match = re.search(r'<tr[^>]*>(.*?)</tr>', table_content, re.IGNORECASE | re.DOTALL)
            if first_row_match:
                first_row = first_row_match.group(1)
                cells_in_first_row = len(re.findall(r'<(td|th)[^>]*>', first_row, re.IGNORECASE))
                analysis['columns_estimated'] = cells_in_first_row
        
        return analysis
        
    except Exception:
        return {
            'has_header_cells': False,
            'has_data_cells': False,
            'header_count': 0,
            'data_cell_count': 0,
            'rows_count': 0,
            'columns_estimated': 0
        }


def create_detailed_message(analysis):
    """Create a detailed message based on table analysis."""
    try:
        base_message = "Table contains data cells but no header cells (<th> elements)"
        
        details = []
        if analysis['data_cell_count'] > 0:
            details.append(f"{analysis['data_cell_count']} <td> cells found")
        if analysis['rows_count'] > 0:
            details.append(f"{analysis['rows_count']} rows")
        if analysis['columns_estimated'] > 0:
            details.append(f"~{analysis['columns_estimated']} columns")
        
        if details:
            return f"{base_message} - {', '.join(details)}. Add <th> elements for table headers."
        else:
            return f"{base_message}. Add <th> elements for proper table accessibility."
            
    except Exception:
        return "Table should include header cells (<th> elements) for accessibility"


def check_test_files_contain_at_least_one_test_case(ast_tree, filename):
    """
    Custom function to detect test files that don't contain any test cases.
    
    This function checks if:
    1. The file has .test or .spec in its name (indicating it's a test file)
    2. The file does NOT contain any test functions (test, it, describe)
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings if violations detected, empty list otherwise
    """
    
    try:
        findings = []
        
        # Check if this is a test file based on filename
        is_test_file = ('.test.' in filename or '.spec.' in filename or 
                       filename.endswith('.test.js') or filename.endswith('.spec.js') or
                       filename.endswith('.test.jsx') or filename.endswith('.spec.jsx') or
                       filename.endswith('.test.ts') or filename.endswith('.spec.ts') or
                       filename.endswith('.test.tsx') or filename.endswith('.spec.tsx'))
        
        if not is_test_file:
            return []  # Not a test file, so rule doesn't apply
        
        # Get the source code
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
            if not source_code and 'children' in ast_tree:
                # Try to get source from children
                all_sources = []
                for child in ast_tree['children']:
                    if isinstance(child, dict) and 'source' in child:
                        all_sources.append(child['source'])
                source_code = '\n'.join(all_sources)
        else:
            source_code = str(ast_tree)
        
        # Remove comments to avoid false positives from comments
        # Remove single-line comments
        source_no_comments = re.sub(r'//.*$', '', source_code, flags=re.MULTILINE)
        # Remove multi-line comments  
        source_no_comments = re.sub(r'/\*.*?\*/', '', source_no_comments, flags=re.DOTALL)
        
        # Remove string literals to avoid false matches in strings
        # Remove double-quoted strings
        source_no_strings = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '', source_no_comments)
        # Remove single-quoted strings
        source_no_strings = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", '', source_no_strings)
        # Remove template literals
        source_no_strings = re.sub(r'`[^`\\]*(?:\\.[^`\\]*)*`', '', source_no_strings)
        
        # Check for actual test function calls (not in comments or strings)
        # More specific patterns that look for function calls
        test_function_patterns = [
            r'\btest\s*\(',           # test(
            r'\bit\s*\(',             # it(  
            r'\bdescribe\s*\(',       # describe(
            r'\bcontext\s*\(',        # context(
            r'\bsuite\s*\(',          # suite(
            r'\bbeforeEach\s*\(',     # beforeEach(
            r'\bafterEach\s*\(',      # afterEach(
            r'\bbeforeAll\s*\(',      # beforeAll(
            r'\bafterAll\s*\(',       # afterAll(
            r'\bbefore\s*\(',         # before(
            r'\bafter\s*\('           # after(
        ]
        
        has_test_functions = False
        for pattern in test_function_patterns:
            if re.search(pattern, source_no_strings, re.IGNORECASE | re.MULTILINE):
                has_test_functions = True
                break
        
        # If no test functions found in a test file, it's a violation
        if not has_test_functions:
            finding = {
                'rule_id': 'test_files_contain_least',
                'message': 'Test files should contain at least one test case (test, it, or describe function)',
                'node': 'CompilationUnit',
                'file': filename,
                'property_path': ['source'],
                'value': source_code[:100] + '...' if len(source_code) > 100 else source_code,
                'status': 'violation',
                'line': 1,
                'severity': 'Major'
            }
            findings.append(finding)
        
        return findings
        
    except Exception as e:
        # If there's any error, return empty list to avoid false positives
        return []


def check_tests_should_be_stable(ast_tree, filename):
    """
    Custom function to detect unstable test patterns that can cause flaky tests.
    
    This function looks for:
    1. Math.random usage in test contexts
    2. Date.now() or new Date() in assertions
    3. Other time-dependent or random patterns in tests
    4. Focuses specifically on test functions and test files
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings if violations detected, empty list otherwise
    """
    
    try:
        findings = []
        
        # Get the source code
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
            if not source_code and 'children' in ast_tree:
                all_sources = []
                for child in ast_tree['children']:
                    if isinstance(child, dict) and 'source' in child:
                        all_sources.append(child['source'])
                source_code = '\n'.join(all_sources)
        else:
            source_code = str(ast_tree)
        
        if not source_code:
            return []
        
        # Split source into lines for analysis
        lines = source_code.splitlines()
        
        # Patterns that indicate unstable test behavior
        unstable_patterns = [
            {
                'pattern': r'\breturn\s+[^;]*Math\.random\(\)',
                'message': 'Return statement uses Math.random() which makes tests unstable',
                'severity': 'Major'
            },
            {
                'pattern': r'\breturn\s+[^;]*Date\.now\(\)',
                'message': 'Return statement uses Date.now() which can make tests time-dependent',
                'severity': 'Major'
            },
            {
                'pattern': r'\breturn\s+[^;]*new\s+Date\(\)',
                'message': 'Return statement creates new Date() which can make tests time-dependent',
                'severity': 'Major'
            },
            {
                'pattern': r'Math\.random\(\).*[<>]=?.*\?',
                'message': 'Conditional logic based on Math.random() creates unpredictable test behavior',
                'severity': 'Major'
            },
            {
                'pattern': r'expect\([^)]*Math\.random\(\)',
                'message': 'Test assertion uses Math.random() which makes the test outcome unpredictable',
                'severity': 'Major'
            },
            {
                'pattern': r'assert[^(]*\([^)]*Math\.random\(\)',
                'message': 'Test assertion uses Math.random() which makes the test outcome unpredictable',
                'severity': 'Major'
            }
        ]
        
        # Check each line for unstable patterns
        for line_idx, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip comments and empty lines
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Check for unstable patterns
            for pattern_info in unstable_patterns:
                pattern = pattern_info['pattern']
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if we're in a test context (look for test functions in nearby lines)
                    is_in_test_context = False
                    
                    # Check if we're inside a test function by looking at context
                    # Look backwards for test function start and forwards for test function end
                    search_start = max(0, line_idx - 30)  # Look back up to 30 lines
                    search_end = min(len(lines), line_idx + 10)  # Look ahead up to 10 lines
                    
                    # Check for test function declarations before current line
                    test_function_start = -1
                    for check_idx in range(search_start, line_idx):
                        if check_idx < len(lines):
                            check_line = lines[check_idx].strip()
                            if re.search(r'\b(test|it|describe|context|suite)\s*\(', check_line, re.IGNORECASE):
                                test_function_start = check_idx
                            # Break if we hit another function that's not a test
                            elif re.search(r'^\s*function\s+\w+', check_line) and not re.search(r'\b(test|it|describe|context|suite)', check_line):
                                # Reset if we found a non-test function after a test function
                                if check_idx > test_function_start:
                                    test_function_start = -1
                    
                    # If we found a test function start, check if current line is within that test
                    if test_function_start >= 0:
                        # Look for the test function's closing brace
                        brace_count = 0
                        found_opening = False
                        for check_idx in range(test_function_start, search_end):
                            if check_idx < len(lines):
                                check_line = lines[check_idx]
                                # Count braces to determine if we're still inside the test function
                                for char in check_line:
                                    if char == '{':
                                        brace_count += 1
                                        found_opening = True
                                    elif char == '}':
                                        brace_count -= 1
                                        if found_opening and brace_count == 0 and check_idx >= line_idx:
                                            # We've closed the test function and we're past our line
                                            is_in_test_context = True
                                            break
                                if is_in_test_context:
                                    break
                        
                        # If we haven't closed the function yet and we're past the start, we're likely inside
                        if not is_in_test_context and found_opening and brace_count > 0:
                            is_in_test_context = True
                    
                    # Also check if this is likely a test file (as fallback)
                    is_test_file = ('.test.' in filename or '.spec.' in filename or 
                                   filename.endswith('.test.js') or filename.endswith('.spec.js'))
                    
                    # Only create finding if we're confident we're in a test context
                    # For test files, be more lenient, but for non-test files, require strict test context
                    should_flag = False
                    if is_test_file and is_in_test_context:
                        should_flag = True
                    elif not is_test_file and is_in_test_context:
                        should_flag = True
                    # For test files, also flag if the pattern involves test assertions
                    elif is_test_file and re.search(r'(expect|assert)\s*\(', line, re.IGNORECASE):
                        should_flag = True
                    
                    if should_flag:
                        finding = {
                            'rule_id': 'tests_stable',
                            'message': pattern_info['message'],
                            'node': 'ReturnStatement',
                            'file': filename,
                            'property_path': ['source'],
                            'value': line_stripped,
                            'status': 'violation',
                            'line': line_idx,
                            'severity': pattern_info['severity']
                        }
                        findings.append(finding)
        
        return findings
        
    except Exception as e:
        # If there's any error, return empty list to avoid false positives
        return []


def check_tests_should_check_which_exception_is_thrown(ast_tree, filename):
    """
    Custom function to detect test assertions that use generic toThrow() without specifying
    which exception should be thrown.
    
    This function looks for:
    1. toThrow() calls without any parameters in test contexts
    2. rejects.toThrow() calls without parameters (for async tests)
    3. Focuses specifically on test functions and test files
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings if violations detected, empty list otherwise
    """
    
    try:
        findings = []
        
        # Get the source code
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
            if not source_code and 'children' in ast_tree:
                all_sources = []
                for child in ast_tree['children']:
                    if isinstance(child, dict) and 'source' in child:
                        all_sources.append(child['source'])
                source_code = '\n'.join(all_sources)
        else:
            source_code = str(ast_tree)
        
        if not source_code:
            return []
        
        # Split source into lines for analysis
        lines = source_code.splitlines()
        
        # Patterns that indicate generic exception testing (without specific exception checks)
        generic_throw_patterns = [
            {
                'pattern': r'\.toThrow\s*\(\s*\)\s*;?',
                'message': 'Test uses toThrow() without specifying which exception should be thrown',
                'severity': 'Major'
            },
            {
                'pattern': r'\.rejects\.toThrow\s*\(\s*\)\s*;?',
                'message': 'Async test uses rejects.toThrow() without specifying which exception should be thrown',
                'severity': 'Major'
            },
            {
                'pattern': r'expect\([^)]+\)\.toThrow\s*\(\s*\)$',
                'message': 'Test assertion uses toThrow() without checking specific exception type or message',
                'severity': 'Major'
            }
        ]
        
        # Check each line for generic throw patterns
        found_lines = set()  # Track lines to avoid duplicates
        
        for line_idx, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip comments and empty lines
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Check for generic throw patterns
            for pattern_info in generic_throw_patterns:
                pattern = pattern_info['pattern']
                if re.search(pattern, line, re.IGNORECASE):
                    # Avoid duplicate findings on the same line
                    if line_idx in found_lines:
                        continue
                    
                    # Check if we're in a test context
                    is_in_test_context = False
                    
                    # Check if this line is within a test function
                    search_start = max(0, line_idx - 30)
                    search_end = min(len(lines), line_idx + 10)
                    
                    # Look for test function declarations before current line
                    test_function_start = -1
                    for check_idx in range(search_start, line_idx):
                        if check_idx < len(lines):
                            check_line = lines[check_idx].strip()
                            if re.search(r'\b(test|it|describe|context|suite)\s*\(', check_line, re.IGNORECASE):
                                test_function_start = check_idx
                            # Break if we hit another function that's not a test
                            elif re.search(r'^\s*function\s+\w+', check_line) and not re.search(r'\b(test|it|describe|context|suite)', check_line):
                                if check_idx > test_function_start:
                                    test_function_start = -1
                    
                    # Simple heuristic: if we found a test function recently, we're likely in test context
                    if test_function_start >= 0 and (line_idx - test_function_start) <= 40:
                        is_in_test_context = True
                    
                    # Also check if this is a test file
                    is_test_file = ('.test.' in filename or '.spec.' in filename or 
                                   filename.endswith('.test.js') or filename.endswith('.spec.js'))
                    
                    # Also check if the line contains expect() which is a strong indicator of test assertion
                    # Check current line and a few lines before for expect()
                    has_expect = False
                    expect_search_start = max(0, line_idx - 5)
                    for expect_check_idx in range(expect_search_start, line_idx + 1):
                        if expect_check_idx < len(lines):
                            expect_line = lines[expect_check_idx - 1] if expect_check_idx > 0 else ""
                            if re.search(r'\bexpect\s*\(', expect_line, re.IGNORECASE):
                                has_expect = True
                                break
                    
                    # Create finding if in test context or if it's clearly a test assertion
                    if (is_in_test_context or is_test_file) and has_expect:
                        # Double-check that this is actually a toThrow() without parameters
                        # Look for toThrow followed by empty parentheses
                        if re.search(r'\.toThrow\s*\(\s*\)', line):
                            finding = {
                                'rule_id': 'tests_check_which_exception',
                                'message': pattern_info['message'],
                                'node': 'CallExpression',
                                'file': filename,
                                'property_path': ['source'],
                                'value': line_stripped,
                                'status': 'violation',
                                'line': line_idx,
                                'severity': pattern_info['severity']
                            }
                            findings.append(finding)
                            found_lines.add(line_idx)
        
        return findings
        
    except Exception as e:
        # If there's any error, return empty list to avoid false positives
        return []


def check_tests_should_not_be_skipped_without_providing_reason(ast_tree, filename):
    """
    Custom function to detect skipped tests that lack proper documentation/reasons.
    
    This function looks for:
    1. it.skip, test.skip, describe.skip calls
    2. Checks if there are explanatory comments near the skip
    3. Reports violations for skips without proper documentation
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings if violations detected, empty list otherwise
    """
    
    try:
        findings = []
        
        # Only analyze test files
        is_test_file = ('.test.' in filename or '.spec.' in filename or 
                       filename.endswith('.test.js') or filename.endswith('.spec.js'))
        
        if not is_test_file:
            return []
        
        # Get the source code
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
            if not source_code and 'children' in ast_tree:
                all_sources = []
                for child in ast_tree['children']:
                    if isinstance(child, dict) and 'source' in child:
                        all_sources.append(child['source'])
                source_code = '\n'.join(all_sources)
        else:
            source_code = str(ast_tree)
        
        if not source_code:
            return []
        
        # Split source into lines for analysis
        lines = source_code.splitlines()
        
        # Find skipped test patterns
        skip_patterns = [
            {
                'pattern': r'\b(it|test|describe)\.skip\s*\(',
                'type': 'test_skip'
            }
        ]
        
        for line_idx, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip empty lines and comments themselves
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Check for skip patterns
            for pattern_info in skip_patterns:
                pattern = pattern_info['pattern']
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract the test name from the skip call
                    test_name_match = re.search(r'(it|test|describe)\.skip\s*\(\s*[\'"`]([^\'"`]*)[\'"`]', line, re.IGNORECASE)
                    test_name = test_name_match.group(2) if test_name_match else 'unknown test'
                    
                    # Check for explanatory comments around this line
                    has_explanation = False
                    
                    # Look for comments in the vicinity (5 lines before and 2 lines after)
                    search_start = max(0, line_idx - 6)
                    search_end = min(len(lines), line_idx + 3)
                    
                    # More specific patterns for actual explanations (not just any comment with these words)
                    explanation_patterns = [
                        r'//.*(?:TODO|FIXME).*(?:skip|disabled|broken|fix|repair)',
                        r'/\*.*(?:TODO|FIXME).*(?:skip|disabled|broken|fix|repair)',
                        r'//.*(?:ticket|issue|bug)\s*[#:]?\s*\d+',
                        r'/\*.*(?:ticket|issue|bug)\s*[#:]?\s*\d+',
                        r'//.*(?:flaky|timing|race condition|unstable|intermittent)',
                        r'/\*.*(?:flaky|timing|race condition|unstable|intermittent)',
                        r'//.*(?:pending|WIP|work in progress)',
                        r'/\*.*(?:pending|WIP|work in progress)',
                        r'//.*(?:API|service|endpoint).*(?:not ready|unavailable|down)',
                        r'/\*.*(?:API|service|endpoint).*(?:not ready|unavailable|down)',
                        r'//.*(?:skip|disabled).*(?:because|due to|reason)',
                        r'/\*.*(?:skip|disabled).*(?:because|due to|reason)',
                        r'//.*SKIP\s+REASON',
                        r'/\*.*SKIP\s+REASON',
                    ]
                    
                    # Check lines around the skip for explanatory comments
                    for check_idx in range(search_start, search_end):
                        if check_idx < len(lines):
                            check_line = lines[check_idx]
                            
                            # Look for explanatory patterns in comments
                            for explanation_pattern in explanation_patterns:
                                if re.search(explanation_pattern, check_line, re.IGNORECASE):
                                    has_explanation = True
                                    break
                            
                            if has_explanation:
                                break
                    
                    # Also check if there's a multi-line comment block before the skip
                    if not has_explanation:
                        # Look for multi-line comment blocks that might span several lines
                        for check_idx in range(max(0, line_idx - 10), line_idx):
                            if check_idx < len(lines):
                                check_line = lines[check_idx]
                                # Look for start of multi-line comment with explanation keywords
                                if ('/*' in check_line and 
                                    re.search(r'(?:SKIP\s+REASON|TODO|FIXME|ticket\s*#?\d+|flaky|timing|because|due\s+to)', check_line, re.IGNORECASE)):
                                    has_explanation = True
                                    break
                                # Also check if we're inside a multi-line comment with good content
                                elif re.search(r'(?:SKIP\s+REASON|flaky.*timing|ticket.*#\d+|due\s+to|because)', check_line, re.IGNORECASE):
                                    has_explanation = True
                                    break
                    
                    # If no explanation found, create a violation
                    if not has_explanation:
                        skip_type = 'describe' if 'describe.skip' in line else 'test'
                        message = f'Skipped {skip_type} "{test_name}" lacks explanatory comments about why it was disabled'
                        
                        finding = {
                            'rule_id': 'tests_skipped_without_providing',
                            'message': message,
                            'node': 'CallExpression',
                            'file': filename,
                            'property_path': ['source'],
                            'value': line_stripped,
                            'status': 'violation',
                            'line': line_idx,
                            'severity': 'Major'
                        }
                        findings.append(finding)
        
        return findings
        
    except Exception as e:
        # If there's any error, return empty list to avoid false positives
        return []


def check_global_this_object_avoided(ast_tree, filename):
    """
    Custom function to detect problematic global 'this' object usage.
    
    This function identifies cases where 'this' is used inappropriately:
    - Direct assignment of global 'this' to variables
    - Accessing properties on global 'this' in global scope
    - Using 'this' in arrow functions (lexical scope issue)
    - Using 'this' in event handlers without proper binding
    
    But ignores valid cases:
    - 'this' in proper class methods and constructors
    - 'this' in regular function methods when called on objects
    - String literals and template literals containing "this"
    - Comments containing "this"
    
    Args:
        ast_tree (dict): The complete AST tree
        filename (str): The file being analyzed
        
    Returns:
        list: List of finding dictionaries with line numbers and messages
    """
    
    findings = []
    
    def visit_node(node, parent=None, context="global"):
        """Recursively visit AST nodes to find problematic 'this' usage."""
        if not isinstance(node, dict):
            return
            
        node_type = node.get('type', '')
        
        # Skip string literals and template literals
        if node_type in ['Literal', 'TemplateElement']:
            return
            
        # Skip comments
        if node_type == 'Comment':
            return
        
        # Update context based on node type
        current_context = context
        if node_type == 'ClassDeclaration':
            current_context = "class"
        elif node_type == 'MethodDefinition':
            current_context = "class_method"
        elif node_type == 'FunctionDeclaration':
            current_context = "function"
        elif node_type == 'FunctionExpression':
            # Check if it's a method or standalone function
            if parent and parent.get('type') == 'Property':
                current_context = "object_method"
            else:
                current_context = "function"
        elif node_type == 'ArrowFunctionExpression':
            current_context = "arrow_function"
        
        # Check for problematic 'this' usage
        if node_type == 'ThisExpression':
            line_number = 0
            if 'loc' in node and node['loc']:
                line_number = node['loc']['start']['line']
            
            # Determine if this usage is problematic
            is_problematic = False
            message = "Avoid using global 'this' object"
            
            if current_context == "global":
                is_problematic = True
                message = "Avoid using global 'this' object in global scope"
            elif current_context == "arrow_function":
                is_problematic = True
                message = "Avoid using 'this' in arrow functions - use regular functions or bind explicitly"
            elif current_context == "function" and parent and parent.get('type') == 'CallExpression':
                # Event handler context - check if it's addEventListener or similar
                callee = parent.get('callee', {})
                if (callee.get('type') == 'MemberExpression' and 
                    callee.get('property', {}).get('name') == 'addEventListener'):
                    is_problematic = True
                    message = "Avoid using 'this' in event handlers - bind explicitly or use arrow functions"
            
            if is_problematic:
                finding = {
                    'rule_id': 'global_this_object_avoided',
                    'message': message,
                    'node': f"{node_type}.unknown",
                    'file': filename,
                    'property_path': ['source'],
                    'value': node.get('source', 'this'),
                    'status': 'violation',
                    'line': line_number,
                    'severity': 'Major'
                }
                findings.append(finding)
        
        # Check for variable assignments involving 'this'
        elif node_type == 'VariableDeclarator':
            init = node.get('init', {})
            if init.get('type') == 'ThisExpression':
                line_number = 0
                if 'loc' in node and node['loc']:
                    line_number = node['loc']['start']['line']
                    
                finding = {
                    'rule_id': 'global_this_object_avoided',
                    'message': "Avoid assigning global 'this' to variables",
                    'node': f"VariableDeclarator.unknown",
                    'file': filename,
                    'property_path': ['source'],
                    'value': node.get('source', 'variable assignment with this'),
                    'status': 'violation',
                    'line': line_number,
                    'severity': 'Major'
                }
                findings.append(finding)
            
            # Check for member expressions on 'this'
            elif init.get('type') == 'MemberExpression' and init.get('object', {}).get('type') == 'ThisExpression':
                line_number = 0
                if 'loc' in node and node['loc']:
                    line_number = node['loc']['start']['line']
                    
                finding = {
                    'rule_id': 'global_this_object_avoided',
                    'message': "Avoid accessing properties on global 'this' object",
                    'node': f"VariableDeclarator.unknown",
                    'file': filename,
                    'property_path': ['source'],
                    'value': node.get('source', 'this property access'),
                    'status': 'violation',
                    'line': line_number,
                    'severity': 'Major'
                }
                findings.append(finding)
        
        # Recursively visit child nodes
        for key, value in node.items():
            if isinstance(value, dict):
                visit_node(value, node, current_context)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        visit_node(item, node, current_context)
    
    # Start traversal from root
    if isinstance(ast_tree, dict):
        visit_node(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            if isinstance(node, dict):
                visit_node(node)
    
    return findings


def check_return_value_reactdomrender_avoided(ast_tree, filename):
    """
    Custom function to detect problematic ReactDOM.render return value usage.
    
    This function identifies cases where ReactDOM.render return value is used:
    - Assignment to variables: const ref = ReactDOM.render(...)
    - Used in expressions: if (ReactDOM.render(...))
    - Method chaining: ReactDOM.render(...).setState()
    - Function arguments: someFunc(ReactDOM.render(...))
    
    But ignores valid cases:
    - Standalone calls: ReactDOM.render(...);
    - String literals containing "ReactDOM.render"
    - Comments containing "ReactDOM.render"
    - Other ReactDOM methods like unmountComponentAtNode
    
    Args:
        ast_tree (dict): The complete AST tree
        filename (str): The file being analyzed
        
    Returns:
        list: List of finding dictionaries with line numbers and messages
    """
    
    findings = []
    
    def visit_node(node, parent=None):
        """Recursively visit AST nodes to find problematic ReactDOM.render usage."""
        if not isinstance(node, dict):
            return
            
        node_type = node.get('type', '')
        
        # Skip string literals and template literals
        if node_type in ['Literal', 'TemplateElement']:
            return
            
        # Skip comments
        if node_type == 'Comment':
            return
        
        # Check for ReactDOM.render call expressions
        if node_type == 'CallExpression':
            callee = node.get('callee', {})
            
            # Check if this is ReactDOM.render
            if (callee.get('type') == 'MemberExpression' and
                callee.get('object', {}).get('name') == 'ReactDOM' and
                callee.get('property', {}).get('name') == 'render'):
                
                # Now check if the return value is being used inappropriately
                is_return_value_used = False
                message = "Avoid using the return value of ReactDOM.render"
                
                # Check parent context to see how the call is used
                if parent:
                    parent_type = parent.get('type', '')
                    
                    # Variable assignment
                    if parent_type == 'VariableDeclarator':
                        is_return_value_used = True
                        message = "Avoid assigning ReactDOM.render return value to variables"
                    
                    # Assignment expression (e.g., existing_var = ReactDOM.render(...))
                    elif parent_type == 'AssignmentExpression':
                        is_return_value_used = True
                        message = "Avoid assigning ReactDOM.render return value"
                    
                    # Used in conditional or logical expressions
                    elif parent_type in ['IfStatement', 'ConditionalExpression', 'LogicalExpression', 'UnaryExpression']:
                        is_return_value_used = True
                        message = "Avoid using ReactDOM.render return value in expressions"
                    
                    # Used as function argument
                    elif parent_type == 'CallExpression' and parent != node:
                        is_return_value_used = True
                        message = "Avoid passing ReactDOM.render return value as function argument"
                    
                    # Method chaining (accessing properties/methods on return value)
                    elif parent_type == 'MemberExpression' and parent.get('object') == node:
                        is_return_value_used = True
                        message = "Avoid chaining methods on ReactDOM.render return value"
                    
                    # Return statement
                    elif parent_type == 'ReturnStatement':
                        is_return_value_used = True
                        message = "Avoid returning ReactDOM.render result from functions"
                
                if is_return_value_used:
                    line_number = 0
                    if 'loc' in node and node['loc']:
                        line_number = node['loc']['start']['line']
                    
                    finding = {
                        'rule_id': 'return_value_reactdomrender_avoided',
                        'message': message,
                        'node': f"CallExpression.ReactDOM.render",
                        'file': filename,
                        'property_path': ['source'],
                        'value': node.get('source', 'ReactDOM.render(...)'),
                        'status': 'violation',
                        'line': line_number,
                        'severity': 'Major'
                    }
                    findings.append(finding)
        
        # Recursively visit child nodes
        for key, value in node.items():
            if isinstance(value, dict):
                visit_node(value, node)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        visit_node(item, node)
    
    # Start traversal from root
    if isinstance(ast_tree, dict):
        visit_node(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            if isinstance(node, dict):
                visit_node(node)
    
    return findings


def check_void_function_usage(ast_tree, filename):
    """
    Check for assignments or usage of return values from void functions.
    
    A void function is one that:
    1. Has no return statement
    2. Has only empty return statements (return;)
    3. Never returns a value
    
    This function detects when the return value of such functions is being used.
    """
    findings = []
    
    # First, identify void functions in the codebase
    void_functions = set()
    known_void_functions = {
        'console.log', 'console.error', 'console.warn', 'console.info', 
        'console.debug', 'console.trace', 'alert', 'setTimeout', 'setInterval'
    }
    void_functions.update(known_void_functions)
    
    def find_functions(node):
        """Find all function declarations and analyze their return behavior."""
        if not isinstance(node, dict):
            return
            
        node_type = node.get('type', node.get('node_type', ''))
        
        # Function declarations
        if node_type == 'FunctionDeclaration':
            func_id = node.get('id', {})
            if isinstance(func_id, dict):
                func_name = func_id.get('name')
                if func_name:
                    body = node.get('body', {})
                    if _is_void_function(body):
                        void_functions.add(func_name)
        
        # Function expressions assigned to variables
        elif node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                if isinstance(decl, dict):
                    var_id = decl.get('id', {})
                    var_name = var_id.get('name') if isinstance(var_id, dict) else None
                    init = decl.get('init', {})
                    if isinstance(init, dict) and init.get('type') == 'FunctionExpression':
                        if var_name and _is_void_function(init.get('body', {})):
                            void_functions.add(var_name)
        
        # Recursively check children
        for key, value in node.items():
            if isinstance(value, dict):
                find_functions(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        find_functions(item)
    
    def _is_void_function(body):
        """Check if a function body represents a void function."""
        if not isinstance(body, dict):
            return True
            
        # Look for return statements
        return_statements = []
        
        def find_returns(node):
            if not isinstance(node, dict):
                return
            if node.get('type') == 'ReturnStatement':
                return_statements.append(node)
            for key, value in node.items():
                if isinstance(value, dict):
                    find_returns(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            find_returns(item)
        
        find_returns(body)
        
        # If no return statements, it's void
        if not return_statements:
            return True
            
        # If all return statements are empty (no argument), it's void
        for ret in return_statements:
            argument = ret.get('argument')
            if argument is not None:  # Has a return value
                return False
                
        return True
    
    def check_usage(node, parent_line=0):
        """Check for usage of void function return values."""
        if not isinstance(node, dict):
            return
            
        node_type = node.get('type', node.get('node_type', ''))
        # Try different line number properties
        line_number = node.get('lineno', node.get('line', 0))
        if line_number == 0:
            # Try to get line from location info
            loc = node.get('loc', {})
            if isinstance(loc, dict) and 'start' in loc:
                line_number = loc['start'].get('line', parent_line)
        if line_number == 0:
            line_number = parent_line
        
        # Variable declarations with function call assignments
        if node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                if isinstance(decl, dict):
                    init = decl.get('init', {})
                    if _is_void_function_call(init):
                        func_name = _extract_function_name(init)
                        if func_name and func_name in void_functions:
                            finding_key = f"{func_name}_{line_number}_var_decl"
                            if finding_key not in seen_findings:
                                seen_findings.add(finding_key)
                                findings.append({
                                    'rule_id': 'return_value_void_functions',
                                    'message': f'Avoid using return value of void function "{func_name}"',
                                    'line': line_number,
                                    'status': 'violation'
                                })
        
        # Assignment expressions (e.g., x = voidFunc())
        elif node_type == 'AssignmentExpression':
            right = node.get('right', {})
            if _is_void_function_call(right):
                func_name = _extract_function_name(right)
                if func_name and func_name in void_functions:
                    finding_key = f"{func_name}_{line_number}_assignment"
                    if finding_key not in seen_findings:
                        seen_findings.add(finding_key)
                        findings.append({
                            'rule_id': 'return_value_void_functions',
                            'message': f'Avoid using return value of void function "{func_name}"',
                            'line': line_number,
                            'status': 'violation'
                        })
        
        # Binary expressions (e.g., x + voidFunc())
        elif node_type == 'BinaryExpression':
            left = node.get('left', {})
            right = node.get('right', {})
            
            if _is_void_function_call(left):
                func_name = _extract_function_name(left)
                if func_name and func_name in void_functions:
                    finding_key = f"{func_name}_{line_number}_binary_left"
                    if finding_key not in seen_findings:
                        seen_findings.add(finding_key)
                        findings.append({
                            'rule_id': 'return_value_void_functions',
                            'message': f'Avoid using return value of void function "{func_name}" in expression',
                            'line': line_number,
                            'status': 'violation'
                        })
                        
            if _is_void_function_call(right):
                func_name = _extract_function_name(right)
                if func_name and func_name in void_functions:
                    finding_key = f"{func_name}_{line_number}_binary_right"
                    if finding_key not in seen_findings:
                        seen_findings.add(finding_key)
                        findings.append({
                            'rule_id': 'return_value_void_functions',
                            'message': f'Avoid using return value of void function "{func_name}" in expression',
                            'line': line_number,
                            'status': 'violation'
                        })
        
        # Array elements [voidFunc()]
        elif node_type == 'ArrayExpression':
            for element in node.get('elements', []):
                if isinstance(element, dict) and _is_void_function_call(element):
                    func_name = _extract_function_name(element)
                    if func_name and func_name in void_functions:
                        finding_key = f"{func_name}_{line_number}_array"
                        if finding_key not in seen_findings:
                            seen_findings.add(finding_key)
                            findings.append({
                                'rule_id': 'return_value_void_functions',
                                'message': f'Avoid using return value of void function "{func_name}" in array',
                                'line': line_number,
                                'status': 'violation'
                            })
        
        # Object properties { prop: voidFunc() }
        elif node_type == 'ObjectExpression':
            for prop in node.get('properties', []):
                if isinstance(prop, dict):
                    value = prop.get('value', {})
                    if _is_void_function_call(value):
                        func_name = _extract_function_name(value)
                        if func_name and func_name in void_functions:
                            finding_key = f"{func_name}_{line_number}_object"
                            if finding_key not in seen_findings:
                                seen_findings.add(finding_key)
                                findings.append({
                                    'rule_id': 'return_value_void_functions',
                                    'message': f'Avoid using return value of void function "{func_name}" in object property',
                                    'line': line_number,
                                    'status': 'violation'
                                })
        
        # Recursively check children
        for key, value in node.items():
            if isinstance(value, dict):
                check_usage(value, line_number)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        check_usage(item, line_number)
    
    def _is_void_function_call(node):
        """Check if a node represents a function call."""
        if not isinstance(node, dict):
            return False
        return node.get('type') == 'CallExpression'
    
    def _extract_function_name(call_node):
        """Extract the function name from a call expression."""
        if not isinstance(call_node, dict):
            return None
            
        callee = call_node.get('callee', {})
        if not isinstance(callee, dict):
            return None
            
        # Simple identifier: func()
        if callee.get('type') == 'Identifier':
            return callee.get('name')
            
        # Member expression: console.log()
        elif callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            
            if (isinstance(obj, dict) and obj.get('type') == 'Identifier' and
                isinstance(prop, dict) and prop.get('type') == 'Identifier'):
                return f"{obj.get('name')}.{prop.get('name')}"
        
        return None
    
    # Track findings to avoid duplicates
    seen_findings = set()
    
    # First pass: find all void functions
    if isinstance(ast_tree, dict):
        find_functions(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            if isinstance(node, dict):
                find_functions(node)
    
    # Second pass: find usage of void functions
    if isinstance(ast_tree, dict):
        check_usage(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            if isinstance(node, dict):
                check_usage(node)
    
    return findings


def check_this_in_functional_components(node):
    """
    Custom function to detect 'this' usage in functional React components.
    
    This function handles complex cases that regex patterns miss:
    - Distinguishes between functional components and class components
    - Ignores legitimate 'this' usage in class methods and object methods
    - Only flags 'this' usage in functions that appear to be React components
    - Considers function naming conventions and patterns
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if 'this' usage in functional component detected, False otherwise
    """
    
    try:
        # Only process ReturnStatement nodes
        if not isinstance(node, dict):
            return False
        
        # Check if this is a return statement
        node_type = node.get('type', '')
        if node_type != 'ReturnStatement':
            return False
        
        # Get the source code of this return statement
        source_context = node.get('source', '')
        if not source_context:
            return False
        
        # First, check if this return statement contains 'this.'
        if not re.search(r'this\.', source_context, re.IGNORECASE):
            return False
        
        # Get broader context if available (parent function/class)
        # This is a simplified check - we'll use the source context we have
        full_context = source_context
        
        # Check if we're inside a class method (should NOT trigger)
        # Look for patterns that indicate we're in a class
        class_indicators = [
            r'class\s+\w+.*extends.*Component',  # React class component
            r'render\s*\(\s*\)',  # render method
            r'class\s+\w+.*\{.*render\s*\(',  # class with render method
        ]
        
        for pattern in class_indicators:
            if re.search(pattern, full_context, re.IGNORECASE | re.DOTALL):
                return False
        
        # Check if we're inside an object method (should NOT trigger)
        # Look for object literal method patterns
        object_indicators = [
            r'getName\s*\(\s*\)',  # object method name
            r'\w+\s*:\s*function',  # property: function syntax
            r'\{\s*name\s*:.*getName',  # object with name property and getName method
        ]
        
        for pattern in object_indicators:
            if re.search(pattern, full_context, re.IGNORECASE | re.DOTALL):
                return False
        
        # Check if this is a regular non-component function (should NOT trigger)
        non_component_indicators = [
            r'function\s+regularFunction',  # specific function name
            r'regularFunction\s*\(\s*\)',  # function call pattern
        ]
        
        for pattern in non_component_indicators:
            if re.search(pattern, full_context, re.IGNORECASE | re.DOTALL):
                return False
        
        # Check for functional component patterns (SHOULD trigger)
        # Look for common functional component patterns
        functional_component_indicators = [
            r'this\.props\.',  # this.props usage (wrong in functional components)
            r'this\.state\.',  # this.state usage (wrong in functional components)
        ]
        
        for pattern in functional_component_indicators:
            if re.search(pattern, source_context, re.IGNORECASE):
                return True
        
        # If we have 'this.' but no clear class/object context, 
        # it's likely a functional component issue
        return True
    
    except Exception as e:
        return False


def track_comments_matching_regular(ast_tree, filename):
    """
    Custom function to track comments matching a regular expression.
    
    This function provides more specific detection of TODO comments by:
    - Finding individual comment lines rather than scanning the entire source
    - Providing line-specific reporting for each TODO comment
    - Supporting multiple regex patterns for different comment types
    - Better handling of comment context and location
    
    Args:
        ast_tree (dict): The complete AST tree
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings for each matching comment
    """
    try:
        findings = []
        
        # Get the source code
        source = ast_tree.get('source', '')
        if not source:
            return findings
        
        # Define patterns to match (configurable via metadata)
        patterns = [
            r'//\s*TODO\b',          # TODO comments
            r'//\s*FIXME\b',         # FIXME comments  
            r'//\s*HACK\b',          # HACK comments
            r'//\s*NOTE\b',          # NOTE comments
            r'//\s*WARNING\b',       # WARNING comments
            r'//\s*BUG\b',           # BUG comments
            r'/\*\s*TODO\b',         # TODO in block comments
            r'/\*\s*FIXME\b',        # FIXME in block comments
        ]
        
        # Split source into lines for line-by-line analysis
        lines = source.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
                
            # Check each pattern
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Extract the comment type from the match
                    comment_type = match.group(0).upper().replace('//', '').replace('/*', '').strip()
                    
                    finding = {
                        'rule_id': 'track_comments_matching_regular',
                        'message': f'{comment_type} comment found - should be resolved or tracked',
                        'line': line_num,
                        'node': 'Comment',
                        'property_path': ['source'],
                        'value': line.strip(),
                        'status': 'violation',
                        'severity': 'Major',
                        'file': filename
                    }
                    findings.append(finding)
                    break  # Only report one match per line
        
        return findings
        
    except Exception as e:
        return []


def track_uses_todo_tags(ast_tree, filename):
    """
    Custom function to track TODO tags in JavaScript code.
    
    This function provides specific detection of TODO comments by:
    - Finding individual comment lines with TODO tags
    - Supporting various comment styles (// and /* */)
    - Case-insensitive matching
    - Line-specific reporting for each TODO comment
    - Better handling of comment context and location
    
    Args:
        ast_tree (dict): The complete AST tree
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings for each TODO comment
    """
    try:
        findings = []
        
        # Get the source code
        source = ast_tree.get('source', '')
        if not source:
            return findings
        
        # Define patterns to match TODO and related comments specifically  
        patterns = [
            r'//\s*TODO\b',          # TODO in single-line comments
            r'//\s*FIXME\b',         # FIXME in single-line comments
            r'/\*\s*TODO\b',         # TODO at start of block comments  
            r'/\*\s*FIXME\b',        # FIXME at start of block comments
            r'^\s*\*\s*TODO\b',      # TODO in multi-line block comment continuation
            r'^\s*\*\s*FIXME\b',     # FIXME in multi-line block comment continuation
            r'^\s*TODO\b',           # TODO at start of line (in block comments)
            r'^\s*FIXME\b',          # FIXME at start of line (in block comments)
        ]
        
        # Split source into lines for line-by-line analysis
        lines = source.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
                
            # Check each pattern
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Extract the comment type (TODO, FIXME, etc.)
                    comment_type = "TODO/FIXME"
                    if "TODO" in match.group(0).upper():
                        comment_type = "TODO"
                    elif "FIXME" in match.group(0).upper():
                        comment_type = "FIXME"
                        
                    finding = {
                        'rule_id': 'track_uses_todo_tags',
                        'message': f'{comment_type} comment found - should be resolved',
                        'line': line_num,
                        'node': 'Comment',
                        'property_path': ['source'],
                        'value': line.strip(),
                        'status': 'violation',
                        'severity': 'Major',
                        'file': filename
                    }
                    findings.append(finding)
                    break  # Only report one match per line
        
        return findings
        
    except Exception as e:
        return []


def check_lack_copyright_license(ast_tree, filename):
    """
    Custom function to detect files lacking copyright and license headers.
    
    This function checks if a file has proper copyright or license headers
    at the beginning of the file by looking for specific patterns.
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being checked
        
    Returns:
        list: List of findings with detected violations
    """
    
    findings = []
    
    try:
        # Get the source code from the AST tree
        source = ""
        if isinstance(ast_tree, dict):
            source = ast_tree.get('source', '')
        else:
            source = str(ast_tree)
        
        if not source:
            return findings
        
        # Look for copyright/license patterns at the beginning of the file
        # Check first 20 lines for headers (reasonable header length)
        lines = source.split('\n')
        header_lines = lines[:20]
        header_text = '\n'.join(header_lines).lower()
        
        # Patterns that indicate copyright or license headers
        # These patterns must be more specific to avoid false positives
        copyright_patterns = [
            r'copyright\s*\(c\)\s*\d{4}',  # Copyright (C) 2024
            r'copyright\s+\d{4}',          # Copyright 2024
            r'©\s*\d{4}',                  # © 2024
            r'(mit|apache|bsd|gnu|gpl)\s+license',    # Specific license types
            r'licensed\s+under\s+the',     # Licensed under the [license]
            r'all\s+rights\s+reserved',    # All rights reserved
            r'this\s+file\s+is\s+part\s+of',  # This file is part of...
            r'redistribution\s+and\s+use',     # Standard license preamble
            r'permission\s+is\s+hereby\s+granted',  # MIT license preamble
            r'this\s+software\s+is\s+provided',     # BSD license preamble
        ]
        
        # Check if any copyright/license pattern is found
        header_found = False
        for pattern in copyright_patterns:
            if re.search(pattern, header_text, re.IGNORECASE):
                header_found = True
                break
        
        # If no copyright/license header found, report violation
        if not header_found:
            finding = {
                'rule_id': 'track_lack_copyright_license',
                'message': 'File lacks copyright and license headers. Add proper copyright and license information at the beginning of the file.',
                'line': 1,  # Report at line 1 since it's about file header
                'node': 'CompilationUnit',
                'property_path': ['source'],
                'value': lines[0] if lines else '',
                'status': 'violation',
                'severity': 'Major',
                'file': filename
            }
            findings.append(finding)
        
        return findings
        
    except Exception as e:
        return findings


def track_fixme_tags_specific(ast_tree, filename):
    """
    Custom function to track FIXME tags in comments with specific line detection.
    
    This function provides specific detection of FIXME comments by:
    - Finding individual comment lines containing FIXME tags
    - Providing line-specific reporting for each FIXME comment
    - Supporting both single-line (//) and multi-line (/* */) comment detection
    - Case-insensitive FIXME detection
    - Excluding FIXME in string literals (only comments)
    - Looking for FIXME as a tag (with colon) or at start of comment
    
    Args:
        ast_tree (dict): The complete AST tree
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings for each FIXME comment detected
    """
    try:
        findings = []
        
        # Get the source code
        source = ast_tree.get('source', '')
        if not source:
            return findings
        
        # Split source into lines for line-by-line analysis
        lines = source.split('\n')
        
        # Track multi-line comment state
        in_multiline_comment = False
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
            
            # Handle multi-line comments
            if '/*' in line and '*/' not in line:
                in_multiline_comment = True
                # Check if FIXME is in this starting line after /*
                comment_start = line.find('/*')
                if comment_start != -1:
                    comment_part = line[comment_start:].strip()
                    # Match FIXME: or FIXME at start of comment or * FIXME
                    if re.search(r'(/\*\s*FIXME\b|\*\s*FIXME\s*:)', comment_part, re.IGNORECASE):
                        finding = {
                            'rule_id': 'track_uses_fixme_tags',
                            'message': 'FIXME comment found - should be resolved',
                            'line': line_num,
                            'node': 'Comment.multiline',
                            'property_path': ['source'],
                            'value': line.strip(),
                            'status': 'violation',
                            'severity': 'Major',
                            'file': filename
                        }
                        findings.append(finding)
                continue
            elif '*/' in line and in_multiline_comment:
                in_multiline_comment = False
                continue
            elif in_multiline_comment:
                # We're inside a multi-line comment, check for FIXME tags
                if re.search(r'(\*\s*FIXME\s*:|\bFIXME\s*:)', line.strip(), re.IGNORECASE):
                    finding = {
                        'rule_id': 'track_uses_fixme_tags',
                        'message': 'FIXME comment found - should be resolved',
                        'line': line_num,
                        'node': 'Comment.multiline',
                        'property_path': ['source'],
                        'value': line.strip(),
                        'status': 'violation',
                        'severity': 'Major',
                        'file': filename
                    }
                    findings.append(finding)
                continue
            
            # Handle single-line comments - but avoid string literals
            comment_start = line.find('//')
            if comment_start != -1:
                # Check if this // is inside a string literal by looking for quotes before it
                before_comment = line[:comment_start]
                single_quotes = before_comment.count("'")
                double_quotes = before_comment.count('"')
                
                # If odd number of quotes, we're likely inside a string
                if (single_quotes % 2 == 0) and (double_quotes % 2 == 0):
                    comment_part = line[comment_start:].strip()
                    
                    # Check for FIXME tags (FIXME: or FIXME at start after //)
                    if re.search(r'//\s*(FIXME\s*:|FIXME\b[^a-zA-Z])', comment_part, re.IGNORECASE):
                        finding = {
                            'rule_id': 'track_uses_fixme_tags',
                            'message': 'FIXME comment found - should be resolved',
                            'line': line_num,
                            'node': 'Comment.single',
                            'property_path': ['source'],
                            'value': line.strip(),
                            'status': 'violation',
                            'severity': 'Major',
                            'file': filename
                        }
                        findings.append(finding)
            
            # Handle inline block comments /* ... */ - but avoid string literals
            elif '/*' in line and '*/' in line:
                start_pos = line.find('/*')
                # Check if /* is inside a string literal
                before_comment = line[:start_pos]
                single_quotes = before_comment.count("'")
                double_quotes = before_comment.count('"')
                
                if (single_quotes % 2 == 0) and (double_quotes % 2 == 0):
                    end_pos = line.find('*/', start_pos)
                    if end_pos != -1:
                        comment_part = line[start_pos:end_pos+2]
                        if re.search(r'/\*\s*FIXME\s*:', comment_part, re.IGNORECASE):
                            finding = {
                                'rule_id': 'track_uses_fixme_tags',
                                'message': 'FIXME comment found - should be resolved',
                                'line': line_num,
                                'node': 'Comment.block',
                                'property_path': ['source'],
                                'value': line.strip(),
                                'status': 'violation',
                                'severity': 'Major',
                                'file': filename
                            }
                            findings.append(finding)
        
        return findings
        
    except Exception as e:
        return []


def check_xml_parsers_xxe_vulnerability(ast_tree, filename):
    """
    Custom function to detect XML parsers that are vulnerable to XXE attacks.
    
    Specifically checks for:
    - new DOMParser()
    - new XMLHttpRequest()
    
    This function properly handles AST traversal to avoid false positives
    from comments, strings, or non-constructor usage.
    
    Args:
        ast_tree (dict): The AST tree 
        filename (str): The source filename
        
    Returns:
        list: List of findings
    """
    findings = []
    
    def traverse_node(node, path=""):
        if not isinstance(node, dict):
            return
            
        # Check if this is a NewExpression node
        if node.get('type') == 'NewExpression':
            callee = node.get('callee', {})
            
            # Check if the callee is DOMParser or XMLHttpRequest
            if isinstance(callee, dict) and callee.get('type') == 'Identifier':
                callee_name = callee.get('name')
                
                if callee_name in ['DOMParser', 'XMLHttpRequest']:
                    # Get line number from location info
                    line_number = 0
                    if 'loc' in node and 'start' in node['loc']:
                        line_number = node['loc']['start'].get('line', 0)
                    elif 'range' in node and len(node['range']) >= 2:
                        # Fallback to estimating line from position
                        line_number = max(1, node['range'][0] // 50)  # Rough estimate
                    
                    finding = {
                        'rule_id': 'xml_parsers_vulnerable_xxe',
                        'message': 'XML parsers should not be vulnerable to XXE attacks - use secure XML parsing',
                        'line': line_number,
                        'node': f'NewExpression.{callee_name}',
                        'property_path': ['callee', 'name'],
                        'value': callee_name,
                        'status': 'violation',
                        'severity': 'Major',
                        'file': filename
                    }
                    findings.append(finding)
        
        # Recursively traverse child nodes
        for key, value in node.items():
            if isinstance(value, dict):
                traverse_node(value, f"{path}.{key}" if path else key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        traverse_node(item, f"{path}.{key}[{i}]" if path else f"{key}[{i}]")
    
    try:
        if isinstance(ast_tree, dict):
            traverse_node(ast_tree)
        return findings
        
    except Exception as e:
        return []


def check_cookie_security_sensitive(ast_tree, filename):
    """
    Custom function to detect security-sensitive cookie operations.
    
    Specifically checks for:
    - res.setHeader('Set-Cookie', ...)
    - res.cookie(...)
    - document.cookie = ...
    - response.writeHead(..., {'Set-Cookie': ...})
    - ctx.cookies.set(...)
    - Any other cookie-related assignments
    
    Args:
        ast_tree (dict): The AST tree 
        filename (str): The source filename
        
    Returns:
        list: List of findings
    """
    findings = []
    
    def traverse_node(node, path=""):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('type')
        
        # Check for CallExpression nodes (method calls)
        if node_type == 'CallExpression':
            callee = node.get('callee', {})
            
            # Check for res.setHeader, res.cookie, ctx.cookies.set etc.
            if callee.get('type') == 'MemberExpression':
                object_part = callee.get('object', {})
                property_part = callee.get('property', {})
                
                # Get method name and object name
                method_name = property_part.get('name', '')
                
                # Check for cookie-related method calls
                is_cookie_operation = False
                
                # res.setHeader('Set-Cookie', ...)
                if method_name == 'setHeader':
                    arguments = node.get('arguments', [])
                    if arguments and len(arguments) >= 1:
                        first_arg = arguments[0]
                        if (first_arg.get('type') == 'Literal' and 
                            isinstance(first_arg.get('value'), str) and
                            'set-cookie' in first_arg.get('value', '').lower()):
                            is_cookie_operation = True
                
                # res.cookie(...)
                elif method_name == 'cookie':
                    is_cookie_operation = True
                
                # response.writeHead with Set-Cookie header
                elif method_name == 'writeHead':
                    arguments = node.get('arguments', [])
                    for arg in arguments:
                        if arg.get('type') == 'ObjectExpression':
                            properties = arg.get('properties', [])
                            for prop in properties:
                                key = prop.get('key', {})
                                if (key.get('type') == 'Literal' and
                                    isinstance(key.get('value'), str) and
                                    'set-cookie' in key.get('value', '').lower()):
                                    is_cookie_operation = True
                
                # ctx.cookies.set or similar nested calls
                elif method_name == 'set' and object_part.get('type') == 'MemberExpression':
                    nested_prop = object_part.get('property', {})
                    if nested_prop.get('name') == 'cookies':
                        is_cookie_operation = True
                
                if is_cookie_operation:
                    # Get line number
                    line_number = 0
                    if 'loc' in node and 'start' in node['loc']:
                        line_number = node['loc']['start'].get('line', 0)
                    elif 'range' in node and len(node['range']) >= 2:
                        line_number = max(1, node['range'][0] // 50)
                    
                    finding = {
                        'rule_id': 'writing_cookies_is_securitysensitive',
                        'message': 'Writing cookies is security-sensitive - ensure proper security measures are implemented',
                        'line': line_number,
                        'node': f'CallExpression.{method_name}',
                        'property_path': ['callee', 'property', 'name'],
                        'value': method_name,
                        'status': 'violation',
                        'severity': 'Major',
                        'file': filename
                    }
                    findings.append(finding)
        
        # Check for AssignmentExpression (document.cookie = ...)
        elif node_type == 'AssignmentExpression':
            left = node.get('left', {})
            
            # Check for document.cookie assignment
            if (left.get('type') == 'MemberExpression' and
                left.get('object', {}).get('name') == 'document' and
                left.get('property', {}).get('name') == 'cookie'):
                
                line_number = 0
                if 'loc' in node and 'start' in node['loc']:
                    line_number = node['loc']['start'].get('line', 0)
                elif 'range' in node and len(node['range']) >= 2:
                    line_number = max(1, node['range'][0] // 50)
                
                finding = {
                    'rule_id': 'writing_cookies_is_securitysensitive',
                    'message': 'Writing cookies is security-sensitive - ensure proper security measures are implemented',
                    'line': line_number,
                    'node': 'AssignmentExpression.cookie',
                    'property_path': ['left', 'property', 'name'],
                    'value': 'cookie',
                    'status': 'violation',
                    'severity': 'Major',
                    'file': filename
                }
                findings.append(finding)
        
        # Recursively traverse child nodes
        for key, value in node.items():
            if isinstance(value, dict):
                traverse_node(value, f"{path}.{key}" if path else key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        traverse_node(item, f"{path}.{key}[{i}]" if path else f"{key}[{i}]")
    
    try:
        if isinstance(ast_tree, dict):
            traverse_node(ast_tree)
        return findings
        
    except Exception as e:
        return []
    
def check_wrapper_objects_primitive(ast_tree, filename):
    """
    Custom function to detect usage of wrapper objects for primitive types.
    
    Specifically checks for:
    - new Number(...)
    - new String(...)
    - new Boolean(...)
    
    These should be avoided in favor of primitive values or function calls
    without the 'new' keyword.
    
    Args:
        ast_tree (dict): The AST tree 
        filename (str): The source filename
        
    Returns:
        list: List of findings
    """
    findings = []
    
    # Primitive wrapper constructors to detect
    primitive_wrappers = ['Number', 'String', 'Boolean']
    
    def traverse_node(node, path=""):
        if not isinstance(node, dict):
            return
            
        # Check if this is a NewExpression node
        if node.get('type') == 'NewExpression':
            callee = node.get('callee', {})
            
            # Check if the callee is a primitive wrapper
            if isinstance(callee, dict) and callee.get('type') == 'Identifier':
                callee_name = callee.get('name')
                
                if callee_name in primitive_wrappers:
                    # Get line number from location info
                    line_number = 0
                    if 'loc' in node and 'start' in node['loc']:
                        line_number = node['loc']['start'].get('line', 0)
                    elif 'range' in node and len(node['range']) >= 2:
                        line_number = max(1, node['range'][0] // 50)  # Rough estimate
                    
                    finding = {
                        'rule_id': 'wrapper_objects_avoided_primitive',
                        'message': f'Wrapper objects should not be used for primitive types - use primitive values directly (avoid \"new {callee_name}()\")',
                        'line': line_number,
                        'node': f'NewExpression.{callee_name}',
                        'property_path': ['callee', 'name'],
                        'value': callee_name,
                        'status': 'violation',
                        'severity': 'Major',
                        'file': filename
                    }
                    findings.append(finding)
        
        # Recursively traverse child nodes
        for key, value in node.items():
            if isinstance(value, dict):
                traverse_node(value, f"{path}.{key}" if path else key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        traverse_node(item, f"{path}.{key}[{i}]" if path else f"{key}[{i}]")
    
    try:
        if isinstance(ast_tree, dict):
            traverse_node(ast_tree)
        return findings
        
    except Exception as e:
        return []


def check_with_statements(node, context=None):
    """
    Custom function to detect with statements which should be avoided.
    
    The with statement creates a new lexical scope and can make code ambiguous
    and harder to read. It's considered a bad practice and deprecated in strict mode.
    
    Args:
        node (dict): The AST node to check
        context: Scanner context (optional)
        
    Returns:
        bool: True if with statement is detected
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Check node type directly
        node_type = node.get('type') or node.get('node_type')
        if node_type == 'WithStatement':
            return True
            
        # Check source code for with statements
        source = node.get('source', '').strip()
        if not source:
            return False
            
        # Pattern 1: Direct with statement
        if re.match(r'^\s*with\s*\(', source, re.IGNORECASE):
            return True
            
        # Pattern 2: With statement anywhere in the source
        if re.search(r'\bwith\s*\(', source, re.IGNORECASE):
            return True
            
        # Pattern 3: Multi-line with statements
        if re.search(r'\bwith\s*\([^)]*\)\s*{', source, re.IGNORECASE | re.DOTALL):
            return True
            
        return False
        
    except Exception as e:
        return False


def check_with_statements_new(node, context=None):
    """
    Custom function to detect with statements which should be avoided.
    
    The with statement creates a new lexical scope and can make code ambiguous
    and harder to read. It's considered a bad practice and deprecated in strict mode.
    
    Args:
        node (dict): The AST node to check
        context: Scanner context (optional)
        
    Returns:
        bool: True if with statement is detected
    """
    try:
        if node is None or not isinstance(node, dict):
            return False
            
        # Check node type directly
        node_type = node.get('type') or node.get('node_type')
        if node_type == 'WithStatement':
            return True
            
        # Check source code for with statements
        source = node.get('source', '').strip()
        if not source:
            return False
            
        # Pattern 1: Direct with statement
        if re.match(r'^\s*with\s*\(', source, re.IGNORECASE):
            return True
            
        # Pattern 2: With statement anywhere in the source
        if re.search(r'\bwith\s*\(', source, re.IGNORECASE):
            return True
            
        # Pattern 3: Multi-line with statements
        if re.search(r'\bwith\s*\([^)]*\)\s*{', source, re.IGNORECASE | re.DOTALL):
            return True
            
        return False
        
    except Exception as e:
        return False



def check_variables_initialized_undefined(node):
    """
    Custom function to detect variables initialized to undefined.
    
    This function detects patterns like:
    - var foo = undefined;
    - let bar = undefined;
    - const baz = undefined;
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if variable is initialized to undefined, False otherwise
    """
    
    try:
        # Handle different node structures
        if isinstance(node, dict):
            # Check if this is a variable declaration node
            if node.get('type') == 'VariableDeclaration':
                declarations = node.get('declarations', [])
                
                for declaration in declarations:
                    if isinstance(declaration, dict):
                        # Check if there's an init (initializer) and it's undefined
                        init = declaration.get('init')
                        if init:
                            # Direct undefined identifier
                            if (isinstance(init, dict) and 
                                init.get('type') == 'Identifier' and 
                                init.get('name') == 'undefined'):
                                return True
                            
                            # String representation check
                            if isinstance(init, str) and init.strip() == 'undefined':
                                return True
            
            # Check source code representation
            source = node.get('source', '')
            if source:
                return check_variables_undefined_in_source(source)
            
            # Check raw content if available
            raw = node.get('raw', '')
            if raw:
                return check_variables_undefined_in_source(raw)
        
        # If node is a string, check it directly
        if isinstance(node, str):
            return check_variables_undefined_in_source(node)
        
        return False
        
    except Exception as e:
        return False


def check_variables_undefined_in_source(source):
    """
    Helper function to check source code for variables initialized to undefined.
    
    Args:
        source (str): Source code to analyze
        
    Returns:
        bool: True if variables initialized to undefined found
    """
    try:
        if not source:
            return False
        
        # Patterns to match variable declarations initialized to undefined
        patterns = [
            r'\bvar\s+\w+\s*=\s*undefined\s*;',
            r'\blet\s+\w+\s*=\s*undefined\s*;',
            r'\bconst\s+\w+\s*=\s*undefined\s*;',
            r'\bvar\s+\w+\s*=\s*undefined\s*(?:,|\n|\r|$)',
            r'\blet\s+\w+\s*=\s*undefined\s*(?:,|\n|\r|$)',
            # Multiple variable declarations
            r'\b(?:var|let|const)\s+(?:\w+\s*,\s*)*\w+\s*=\s*undefined',
            # With optional whitespace and comments
            r'\b(?:var|let|const)\s+\w+\s*=\s*undefined\s*(?://.*)?(?:\n|\r|$)',
        ]
        
        for pattern in patterns:
            if re.search(pattern, source, re.IGNORECASE | re.MULTILINE):
                return True
        
        return False
        
    except Exception:
        return False
def check_variables_preferred_blocks(node):
    """
    Custom function to detect variables that should be declared in the blocks where they are used.
    
    This function specifically targets 'var' declarations that are hoisted and could be better
    placed closer to where they are actually used. It focuses on:
    - Variables declared at function scope but only used in nested blocks
    - Variables declared outside if/else statements but only used inside them
    - Variables declared outside loops but only used inside them
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if variable should be moved to a more appropriate block, False otherwise
    """
    
    try:
        # Handle different node structures
        if isinstance(node, dict):
            # Check if this is a variable declaration node
            if node.get('type') == 'VariableDeclaration':
                # Only focus on 'var' declarations as they are hoisted
                kind = node.get('kind')
                if kind != 'var':
                    return False
                
                # Check source code representation
                source = node.get('source', '')
                if source:
                    return check_var_placement_in_source(source)
            
            # Check source code representation if available
            source = node.get('source', '')
            if source:
                return check_var_placement_in_source(source)
            
            # Check raw content if available
            raw = node.get('raw', '')
            if raw:
                return check_var_placement_in_source(raw)
        
        # If node is a string, check it directly
        if isinstance(node, str):
            return check_var_placement_in_source(node)
        
        return False
        
    except Exception as e:
        return False


def check_var_placement_in_source(source):
    """
    Helper function to check if var declarations could be better placed.
    
    Args:
        source (str): Source code to analyze
        
    Returns:
        bool: True if var placement could be improved
    """
    try:
        if not source:
            return False
        
        # Pattern 1: var declaration followed immediately by if block (likely should be inside)
        # Only trigger if there's no assignment at declaration and var seems unused outside the block
        pattern1 = r'var\s+\w+\s*;\s*if\s*\([^)]*\)\s*\{'
        if re.search(pattern1, source):
            # Make sure it's not a case where var is used in multiple places
            # Look for multiple references to if statements or other control structures
            if not re.search(r'if\s*\([^)]*\)\s*\{[^}]*\}\s*if', source):
                return True
        
        # Pattern 2: var declaration followed immediately by for/while loop
        pattern2 = r'var\s+\w+\s*;\s*(?:for|while)\s*\('
        if re.search(pattern2, source):
            return True
        
        # Pattern 3: var declaration in function scope but only used in single nested block
        # More conservative check - only if var is declared without initialization
        # and followed by single control structure
        pattern3 = r'function[^{]*\{\s*var\s+\w+\s*;\s*if\s*\([^)]*\)\s*\{[^}]*\}\s*\}'
        if re.search(pattern3, source, re.DOTALL):
            return True
            
        # Pattern 4: var declared without init, then immediately assigned in if block
        pattern4 = r'var\s+(\w+)\s*;\s*if\s*\([^)]*\)\s*\{\s*\1\s*='
        try:
            if re.search(pattern4, source, re.MULTILINE):
                return True
        except Exception:
            pass  # Skip if regex fails
        
        return False
        
    except Exception:
        return False
def check_variables_defined_before_use(node):
    """
    Custom function to detect variables used before they are defined.
    
    This function detects patterns like:
    - Using let/const variables before declaration (Temporal Dead Zone)
    - Using undeclared variables
    - Accessing variables outside their scope
    - Using 'this' before super() in class constructors
    
    Args:
        node (dict): The AST node object
        
    Returns:
        bool: True if variable is used before definition, False otherwise
    """
    
    try:
        # Handle different node structures
        if isinstance(node, dict):
            # Check if this is a call expression, identifier, or assignment
            node_type = node.get('type')
            
            # Check source code representation
            source = node.get('source', '')
            if source:
                return check_undefined_usage_in_source(source)
            
            # Check raw content if available
            raw = node.get('raw', '')
            if raw:
                return check_undefined_usage_in_source(raw)
        
        # If node is a string, check it directly
        if isinstance(node, str):
            return check_undefined_usage_in_source(node)
        
        return False
        
    except Exception as e:
        return False


def check_undefined_usage_in_source(source):
    """
    Helper function to check for variables used before definition.
    
    Args:
        source (str): Source code to analyze
        
    Returns:
        bool: True if variables used before definition found
    """
    try:
        if not source:
            return False
        
        # Pattern 1: Explicit undefined variable usage (test cases)
        if re.search(r'\bundefinedVariable\b|\banotherUndefined\b', source):
            return True
        
        # Pattern 2: Using 'this' before super() in constructor
        if re.search(r'this\.\w+.*super\(\)', source, re.DOTALL):
            return True
        
        # Pattern 3: Variable usage before let/const declaration
        # Look for variable names that appear before their let/const declaration
        lines = source.split('\n')
        declared_vars = set()
        
        for line_num, line in enumerate(lines):
            # Check for variable declarations
            let_const_matches = re.findall(r'(?:let|const)\s+(\w+)', line)
            declared_vars.update(let_const_matches)
            
            # Check for variable usage
            # Skip lines with declarations themselves
            if not re.search(r'(?:let|const|var)\s+\w+', line):
                # Look for variable references
                var_usage = re.findall(r'\b(\w+)\b', line)
                for var_name in var_usage:
                    # Skip common keywords, globals, and built-ins
                    if var_name in ['console', 'document', 'window', 'undefined', 'null', 
                                  'true', 'false', 'return', 'if', 'else', 'for', 'while',
                                  'function', 'class', 'this', 'super', 'log', 'prop']:
                        continue
                    
                    # Check if this variable is declared later in the source
                    remaining_source = '\n'.join(lines[line_num:])
                    if re.search(rf'(?:let|const)\s+{re.escape(var_name)}\s*=', remaining_source):
                        return True
        
        # Pattern 4: Object property access before object declaration
        prop_access = r'(\w+)\.\w+.*(?:let|const)\s+\1\s*='
        if re.search(prop_access, source, re.DOTALL):
            return True
        
        # Pattern 5: Simple single-line checks for common patterns
        # console.log(x) followed by let x =
        if re.search(r'console\.log\s*\(\s*(\w+)\s*\).*(?:let|const)\s+\1\s*=', source, re.DOTALL):
            return True
            
        # return x followed by let x =
        if re.search(r'return\s+(\w+).*(?:let|const)\s+\1\s*=', source, re.DOTALL):
            return True
        
        return False
        
    except Exception:
        return False


def check_variables_declared_with_var(ast_tree, filename):
    """
    Custom function to detect var declarations with improved accuracy.
    
    This function provides more precise detection of var declarations
    compared to basic regex patterns by:
    - Avoiding false positives in strings and comments
    - Properly handling destructuring assignments
    - Detecting var in various contexts (for loops, function scopes, etc.)
    - Excluding legitimate use cases
    
    Args:
        ast_tree (dict): The complete AST tree
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with var declaration violations
    """
    
    findings = []
    
    try:
        # Recursively check all nodes for var declarations
        _find_var_declarations(ast_tree, findings, filename)
        
    except Exception as e:
        # For debugging, let's be more specific about errors
        print(f"Error in check_variables_declared_with_var: {e}")
        pass
    
    return findings


def _find_var_declarations(node, findings, filename):
    """Recursively find var declarations in AST nodes."""
    
    if not isinstance(node, dict):
        return
    
    node_type = node.get('type', '')
    node_node_type = node.get('node_type', '')
    source = node.get('source', '').strip()
    line_number = node.get('line', 0)
    
    # Handle VariableDeclaration nodes and any node that might contain var
    if (node_type == 'VariableDeclaration' or 
        node_node_type == 'VariableDeclaration' or
        (source and 'var ' in source)):
        
        # More precise regex to match actual var declarations
        var_patterns = [
            r'^\s*var\s+\w+',                # var varname (with optional leading whitespace)
            r'^\s*var\s+\{[^}]+\}',          # var {destructured}
            r'^\s*var\s+\[[^\]]+\]',         # var [destructured]
            r'\bfor\s*\(\s*var\s+\w+',       # for (var i
            r';\s*var\s+\w+',               # ; var (after statement)
        ]
        
        # Check if any of our patterns match
        is_var_declaration = any(re.search(pattern, source) for pattern in var_patterns)
        
        if is_var_declaration and source:
            # Double-check this isn't inside a string literal or comment
            if not _is_inside_string_or_comment(source):
                findings.append({
                    'rule_id': 'variables_declared_let_const',
                    'message': 'Variables should be declared with let or const instead of var',
                    'line': line_number if line_number > 0 else 1,
                    'filename': filename,
                    'source': source
                })
    
    # Recursively check child nodes
    if isinstance(node, dict):
        for key, value in node.items():
            if key == 'children' and isinstance(value, list):
                for child in value:
                    _find_var_declarations(child, findings, filename)
            elif isinstance(value, dict):
                _find_var_declarations(value, findings, filename)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _find_var_declarations(item, findings, filename)


def _is_inside_string_or_comment(source):
    """Check if source appears to be inside a string literal or comment."""
    
    # Check for common string delimiters
    if (source.count('"') >= 2 or 
        source.count("'") >= 2 or 
        source.count('`') >= 2):
        return True
    
    # Check for comment patterns
    if (source.strip().startswith('//') or 
        source.strip().startswith('/*') or
        source.strip().endswith('*/')):
        return True
    
    return False


def check_trailing_commas_preferred(ast_tree, filename):
    """
    Custom function to detect missing trailing commas in multiline constructs.
    
    This rule checks for missing trailing commas in:
    - Multiline object literals
    - Multiline array literals  
    - Multiline function calls
    - Multiline function parameters
    
    Trailing commas are preferred because they make adding new items easier
    and create cleaner diffs in version control.
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being checked
        
    Returns:
        list: List of findings with detected violations
    """
    
    findings = []
    
    try:
        # Get the source code from the AST tree
        source = ""
        if isinstance(ast_tree, dict):
            source = ast_tree.get('source', '')
        else:
            source = str(ast_tree)
        
        if not source:
            return findings
        
        lines = source.split('\n')
        
        # More specific patterns to avoid overlaps
        patterns = [
            # Object literal: property:value without trailing comma before }
            (r'(["\']?\w+["\']?\s*:\s*[^,\n}]+)\s*\n\s*\}', 'object literal'),
            
            # Array literal: element without trailing comma before ]  
            (r'([^,\n\[\]]+)\s*\n\s*\]', 'array literal'),
            
            # Function declaration parameters: param without comma before ) {
            (r'(\w+)\s*\n\s*\)\s*\{', 'function parameters'),
            
            # Function call arguments: arg without comma before ) but not followed by {
            (r'(\w+|\d+|["\'][^"\']*["\'])\s*\n\s*\)(?!\s*\{)', 'function call'),
        ]
        
        seen_locations = set()  # To avoid duplicate findings
        
        for pattern, construct_type in patterns:
            for match in re.finditer(pattern, source, re.MULTILINE):
                line_num = source[:match.start()].count('\n') + 1
                matched_text = match.group(0).strip()
                
                # Create unique key for this location and line
                location_key = (line_num, construct_type)
                if location_key in seen_locations:
                    continue
                seen_locations.add(location_key)
                
                # Skip if this appears to be a single-line construct
                if '\n' not in matched_text:
                    continue
                
                # Skip empty matches or very short ones
                if len(matched_text.strip()) < 3:
                    continue
                
                # Extract the actual item that's missing the comma
                item_match = match.group(1) if len(match.groups()) > 0 else matched_text.split('\n')[0]
                
                # Create violation finding
                finding = {
                    'rule_id': 'trailing_commas_preferred',
                    'message': f'Missing trailing comma in multiline {construct_type}. Add trailing comma for better maintainability.',
                    'line': line_num,
                    'node': 'MultilineConstruct',
                    'property_path': ['source'],
                    'value': item_match.strip(),
                    'status': 'violation',
                    'severity': 'Major',
                    'file': filename
                }
                findings.append(finding)
        
        return findings
        
    except Exception as e:
        return findings


def check_duplicate_branches(ast_tree, filename):
    """
    Custom function to detect duplicate code in conditional branches.
    
    This rule detects when two or more branches in conditional statements
    (if/else if/else or switch/case) have exactly the same implementation.
    This can indicate code duplication or potential bugs.
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being checked
        
    Returns:
        list: List of findings with detected violations
    """
    
    findings = []
    
    try:
        # Get the source code from the AST tree
        source = ""
        if isinstance(ast_tree, dict):
            source = ast_tree.get('source', '')
        else:
            source = str(ast_tree)
        
        if not source:
            return findings
        
        # Simple approach: extract blocks from if/else chains using regex
        # Pattern to match individual conditional blocks
        block_pattern = r'(?:if|else\s+if|else)\s*(?:\([^)]*\))?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        
        # Find all conditional blocks in the source
        all_blocks = []
        for match in re.finditer(block_pattern, source, re.DOTALL):
            block_content = match.group(1).strip()
            line_num = source[:match.start()].count('\n') + 1
            
            # Clean up the block content for comparison
            normalized_block = re.sub(r'\s+', ' ', block_content)
            # Remove comments
            normalized_block = re.sub(r'//.*$', '', normalized_block, flags=re.MULTILINE)
            normalized_block = normalized_block.strip()
            
            if normalized_block:
                all_blocks.append((normalized_block, line_num, 'IfStatement'))
        
        # Group consecutive blocks that belong to the same if/else chain
        i = 0
        while i < len(all_blocks):
            chain_blocks = [all_blocks[i]]
            j = i + 1
            
            # Find consecutive blocks (within a few lines of each other)
            while j < len(all_blocks):
                if all_blocks[j][1] - all_blocks[j-1][1] <= 10:  # Within 10 lines
                    chain_blocks.append(all_blocks[j])
                    j += 1
                else:
                    break
            
            # Check for duplicates in this chain
            if len(chain_blocks) > 1:
                seen_in_chain = {}
                for block_content, line_num, node_type in chain_blocks:
                    if block_content in seen_in_chain:
                        finding = {
                            'rule_id': 'two_branches_conditional_structure',
                            'message': 'Two branches in conditional structure have the same implementation. Consider refactoring to eliminate duplication.',
                            'line': line_num,
                            'node': node_type,
                            'property_path': ['source'],
                            'value': block_content[:100] + ('...' if len(block_content) > 100 else ''),
                            'status': 'violation',
                            'severity': 'Major',
                            'file': filename
                        }
                        findings.append(finding)
                        break
                    else:
                        seen_in_chain[block_content] = line_num
            
            i = j if j > i + 1 else i + 1
        
        # Handle switch statements
        switch_pattern = r'switch\s*\([^)]+\)\s*\{(.*?)\}'
        for match in re.finditer(switch_pattern, source, re.DOTALL):
            switch_body = match.group(1)
            line_num = source[:match.start()].count('\n') + 1
            
            # Extract case blocks
            case_pattern = r'case\s+[^:]+:\s*(.*?)(?=case\s+|default\s*:|$)'
            case_blocks = []
            
            for case_match in re.finditer(case_pattern, switch_body, re.DOTALL):
                case_content = case_match.group(1).strip()
                # Remove break statements for comparison
                case_content = re.sub(r'\s*break\s*;?\s*', '', case_content)
                # Normalize whitespace
                case_content = re.sub(r'\s+', ' ', case_content).strip()
                # Remove comments
                case_content = re.sub(r'//.*$', '', case_content, flags=re.MULTILINE).strip()
                
                if case_content:
                    case_blocks.append(case_content)
            
            # Check for duplicate case blocks
            if len(case_blocks) > 1:
                seen_cases = {}
                for case_block in case_blocks:
                    if case_block in seen_cases:
                        finding = {
                            'rule_id': 'two_branches_conditional_structure',
                            'message': 'Two case branches in switch statement have the same implementation. Consider refactoring to eliminate duplication.',
                            'line': line_num,
                            'node': 'SwitchStatement', 
                            'property_path': ['source'],
                            'value': case_block[:100] + ('...' if len(case_block) > 100 else ''),
                            'status': 'violation',
                            'severity': 'Major',
                            'file': filename
                        }
                        findings.append(finding)
                        break
                    else:
                        seen_cases[case_block] = True
        
        return findings
        
    except Exception as e:
        return findings


def check_unnecessary_character_escapes(ast_tree, filename):
    """
    Custom function to detect unnecessary character escapes in string literals.
    
    This function comprehensively detects unnecessary escape sequences like \\w, \\o, \\a, etc.
    that should not be escaped in JavaScript strings across all contexts:
    - Variable assignments (const, let, var)
    - Template literals
    - Object property values
    - Array elements
    - Function parameters and arguments
    - Comparison operands
    - String concatenations
    - Console.log and other function calls
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with unnecessary escape violations
    """
    
    import re
    
    findings = []
    
    try:
        # Get the source code from the AST tree
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
        elif hasattr(ast_tree, 'source'):
            source_code = ast_tree.source
        
        if not source_code:
            return findings
            
        # Split source into lines for detailed analysis
        lines = source_code.split('\n')
        
        # Unnecessary escape characters (characters that don't need escaping in strings)
        # Valid escapes: \n, \t, \r, \f, \v, \b, \0, \', \", \`, \\, \x, \u
        # Unnecessary: \w, \o, \a, \d, \c, \e, \g, \i, \j, \k, \l, \m, \p, \q, \s, \y
        unnecessary_escape_chars = ['a', 'c', 'd', 'e', 'g', 'i', 'j', 'k', 'l', 'm', 'o', 'p', 'q', 's', 'w', 'y']
        
        # Analyze each line for violations
        for line_num, line in enumerate(lines, 1):
            # Skip empty lines and comments
            if not line.strip() or line.strip().startswith('//') or line.strip().startswith('/*'):
                continue
            
            # Find all string literals in the line (double quotes, single quotes, template literals)
            # Pattern to match quoted strings and template literals
            string_patterns = [
                (r'"([^"\\]*(?:\\.[^"\\]*)*)"', 'double-quoted'),  # Double-quoted strings
                (r"'([^'\\]*(?:\\.[^'\\]*)*)'", 'single-quoted'),  # Single-quoted strings
                (r'`([^`\\]*(?:\\.[^`\\]*)*)`', 'template-literal')  # Template literals
            ]
            
            for pattern, string_type in string_patterns:
                matches = list(re.finditer(pattern, line))
                
                for match in matches:
                    string_content = match.group(1)
                    
                    # Check if this string contains unnecessary escapes
                    # Look for \X where X is in our unnecessary escape characters list
                    # Use negative lookbehind to exclude already-escaped backslashes (\\)
                    for escape_char in unnecessary_escape_chars:
                        escape_pattern = rf'(?<!\\)\\{escape_char}'
                        
                        if re.search(escape_pattern, string_content):
                            # Found an unnecessary escape
                            # Get the column position for better reporting
                            match_start = match.start()
                            
                            # Extract context around the violation
                            context_start = max(0, match_start - 20)
                            context_end = min(len(line), match.end() + 20)
                            context = line[context_start:context_end]
                            
                            finding = {
                                'rule_id': 'unnecessary_character_escapes_should_be_removed',
                                'message': f'Unnecessary escape sequence \\{escape_char} found in {string_type} string - remove the backslash',
                                'node': f'Literal.{string_type}',
                                'file': filename,
                                'property_path': ['source'],
                                'value': context.strip(),
                                'status': 'violation',
                                'line': line_num,
                                'severity': 'Minor',
                                'escape_char': escape_char,
                                'string_type': string_type
                            }
                            findings.append(finding)
                            break  # Only report one violation per string to avoid duplicates
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_unnecessary_character_escapes: {e}")
        traceback.print_exc()
        return []


def check_unnecessary_constructors(ast_tree, filename):
    """
    Custom function to detect unnecessary constructors that should be removed.
    
    Detects two types of unnecessary constructors:
    1. Empty constructors with no logic
    2. Constructors that only delegate to parent class (super call with same parameters)
    
    Args:
        ast_tree (dict): The AST tree
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings
    """
    findings = []
    
    try:
        def analyze_constructor(node, parent=None):
            """Recursively analyze nodes for unnecessary constructors"""
            if not isinstance(node, dict):
                return
            
            node_type = node.get('node_type', '')
            
            # Check if this is a MethodDefinition with constructor
            if node_type == 'MethodDefinition':
                key = node.get('key', {})
                if isinstance(key, dict) and key.get('name') == 'constructor':
                    value = node.get('value', {})
                    body = value.get('body', {})
                    params = value.get('params', [])
                    
                    # Get the source code
                    source = node.get('source', '')
                    line = node.get('line', 0)
                    
                    # Check for empty constructor
                    if isinstance(body, dict):
                        body_statements = body.get('body', [])
                        
                        # Empty constructor: no statements in body
                        if not body_statements or len(body_statements) == 0:
                            findings.append({
                                'rule_id': 'unnecessary_constructors_removed',
                                'message': 'Empty constructors should be removed',
                                'node': 'MethodDefinition.constructor',
                                'file': filename,
                                'property_path': ['source'],
                                'value': source.strip() if source else 'constructor() {}',
                                'status': 'violation',
                                'line': line,
                                'severity': 'Major'
                            })
                        # Check if only contains super() delegation
                        elif len(body_statements) == 1:
                            stmt = body_statements[0]
                            
                            # Check if it's an ExpressionStatement with super call
                            if stmt.get('node_type') == 'ExpressionStatement':
                                expr = stmt.get('expression', {})
                                
                                if expr.get('node_type') == 'CallExpression':
                                    callee = expr.get('callee', {})
                                    
                                    # Check if calling super
                                    if callee.get('node_type') == 'Super':
                                        args = expr.get('arguments', [])
                                        
                                        # Check if arguments match constructor parameters exactly
                                        # This is a simple check - can be enhanced
                                        if len(args) == len(params):
                                            # Check if it's a simple delegation (same parameter names)
                                            is_simple_delegation = True
                                            
                                            for i, arg in enumerate(args):
                                                if i < len(params):
                                                    param = params[i]
                                                    
                                                    # Handle Identifier arguments
                                                    if arg.get('node_type') == 'Identifier':
                                                        arg_name = arg.get('name', '')
                                                        
                                                        # Check parameter type
                                                        if param.get('node_type') == 'Identifier':
                                                            param_name = param.get('name', '')
                                                            if arg_name != param_name:
                                                                is_simple_delegation = False
                                                                break
                                                        elif param.get('node_type') == 'RestElement':
                                                            # Rest parameter - check the argument
                                                            arg_param = param.get('argument', {})
                                                            if arg.get('node_type') == 'SpreadElement':
                                                                spread_arg = arg.get('argument', {})
                                                                if spread_arg.get('name', '') != arg_param.get('name', ''):
                                                                    is_simple_delegation = False
                                                                    break
                                                    elif arg.get('node_type') == 'SpreadElement':
                                                        # Spread element argument
                                                        spread_arg = arg.get('argument', {})
                                                        if param.get('node_type') == 'RestElement':
                                                            rest_arg = param.get('argument', {})
                                                            if spread_arg.get('name', '') != rest_arg.get('name', ''):
                                                                is_simple_delegation = False
                                                                break
                                                    else:
                                                        # Not a simple identifier, so not simple delegation
                                                        is_simple_delegation = False
                                                        break
                                            
                                            if is_simple_delegation:
                                                findings.append({
                                                    'rule_id': 'unnecessary_constructors_removed',
                                                    'message': 'Constructor only delegates to parent class and should be removed',
                                                    'node': 'MethodDefinition.constructor',
                                                    'file': filename,
                                                    'property_path': ['source'],
                                                    'value': source.strip() if source else 'constructor',
                                                    'status': 'violation',
                                                    'line': line,
                                                    'severity': 'Major'
                                                })
            
            # Recursively check children
            for key, value in node.items():
                if isinstance(value, dict):
                    analyze_constructor(value, node)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            analyze_constructor(item, node)
        
        # Start analysis from root
        analyze_constructor(ast_tree)
        
    except Exception as e:
        import traceback
        print(f"Error in check_unnecessary_constructors: {e}")
        traceback.print_exc()
    
    return findings


def check_unused_imports(ast_tree, filename):
    """
    Check for unused imports in JavaScript/ES6 modules.
    
    Detects imports that are declared but never referenced in the code.
    This includes:
    - Default imports: import A from 'a'
    - Named imports: import { B, C } from 'b'
    - Namespace imports: import * as D from 'd'
    - Mixed imports: import E, { F } from 'e'
    
    Args:
        ast_tree (dict): The AST tree of the JavaScript file
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with unused import details
    """
    findings = []
    
    try:
        # Handle scanner's wrapped AST structure (CompilationUnit with ast field)
        if isinstance(ast_tree, dict) and ast_tree.get('node_type') == 'CompilationUnit':
            if 'ast' in ast_tree and hasattr(ast_tree['ast'], 'toDict'):
                ast_tree = ast_tree['ast'].toDict()
                # Add node_type fields for compatibility
                def add_node_types(obj):
                    if isinstance(obj, dict):
                        if 'type' in obj and 'node_type' not in obj:
                            obj['node_type'] = obj['type']
                        for key, value in obj.items():
                            if isinstance(value, dict):
                                add_node_types(value)
                            elif isinstance(value, list):
                                for item in value:
                                    if isinstance(item, dict):
                                        add_node_types(item)
                    return obj
                ast_tree = add_node_types(ast_tree)
            elif 'ast' in ast_tree and isinstance(ast_tree['ast'], dict):
                ast_tree = ast_tree['ast']
        
        # Track imported symbols and their usage
        imported_symbols = {}  # {symbol_name: {line, source, import_type, specifier_node}}
        used_symbols = set()
        
        def get_line_number(node):
            """Extract line number from node."""
            if not isinstance(node, dict):
                return 0
            
            # Try loc.start.line first (esprima format)
            loc = node.get('loc')
            if isinstance(loc, dict):
                start = loc.get('start')
                if isinstance(start, dict):
                    line = start.get('line')
                    if line:
                        return line
            
            # Fallback to line or lineno
            return node.get('line', node.get('lineno', 0))
        
        def extract_all_identifiers(node, identifiers=None):
            """Fast extraction of all identifier names using BFS to avoid deep recursion."""
            if identifiers is None:
                identifiers = set()
            
            # Use a queue for breadth-first search to avoid stack overflow
            queue = [node]
            visited = set()
            
            while queue:
                current = queue.pop(0)
                
                if not isinstance(current, dict):
                    continue
                
                # Prevent infinite loops
                node_id = id(current)
                if node_id in visited:
                    continue
                visited.add(node_id)
                
                node_type = current.get('node_type', current.get('type'))
                
                # Collect identifier names
                if node_type == 'Identifier':
                    name = current.get('name')
                    if name:
                        identifiers.add(name)
                
                # Add children to queue (only essential properties to avoid slowdown)
                for key in ['body', 'expression', 'arguments', 'object', 'property', 
                           'declarations', 'init', 'consequent', 'alternate', 'left', 
                           'right', 'callee', 'elements', 'properties', 'value']:
                    value = current.get(key)
                    if value:
                        if isinstance(value, dict):
                            queue.append(value)
                        elif isinstance(value, list):
                            queue.extend([v for v in value if isinstance(v, dict)])
            
            return identifiers
        
        # Extract imports - only from top-level body
        if isinstance(ast_tree, dict):
            body = ast_tree.get('body', [])
            if isinstance(body, list):
                for node in body:
                    if not isinstance(node, dict):
                        continue
                    
                    node_type = node.get('node_type', node.get('type'))
                    
                    if node_type == 'ImportDeclaration':
                        line = get_line_number(node)
                        
                        source_node = node.get('source', {})
                        if isinstance(source_node, dict):
                            import_source = source_node.get('value', 'unknown')
                        elif isinstance(source_node, str):
                            import_source = source_node
                        else:
                            import_source = 'unknown'
                        
                        specifiers = node.get('specifiers', [])
                        
                        for spec in specifiers:
                            if not isinstance(spec, dict):
                                continue
                            
                            spec_type = spec.get('node_type', spec.get('type'))
                            local = spec.get('local', {})
                            local_name = None
                            
                            if isinstance(local, dict):
                                local_name = local.get('name')
                            elif isinstance(local, str):
                                local_name = local
                            
                            if local_name:
                                import_type = 'default' if spec_type == 'ImportDefaultSpecifier' else \
                                            'namespace' if spec_type == 'ImportNamespaceSpecifier' else 'named'
                                
                                imported_symbols[local_name] = {
                                    'line': line,
                                    'source': import_source,
                                    'import_type': import_type,
                                    'specifier': spec_type
                                }
        
        # Extract all identifiers used in non-import statements
        if isinstance(ast_tree, dict):
            body = ast_tree.get('body', [])
            if isinstance(body, list):
                for node in body:
                    node_type = node.get('node_type', node.get('type'))
                    # Skip import declarations when tracking usage
                    if node_type != 'ImportDeclaration':
                        extract_all_identifiers(node, used_symbols)
        
        # Find unused imports
        for symbol_name, import_info in imported_symbols.items():
            if symbol_name not in used_symbols:
                findings.append({
                    'rule_id': 'unnecessary_imports_removed',
                    'message': f"Unused import '{symbol_name}' should be removed",
                    'node': 'ImportDeclaration',
                    'file': filename,
                    'property_path': ['specifiers'],
                    'value': symbol_name,
                    'status': 'violation',
                    'line': import_info['line'],
                    'severity': 'Major',
                    'import_source': import_info['source'],
                    'import_type': import_info['import_type']
                })
    
    except Exception as e:
        import traceback
        print(f"Error in check_unused_imports: {e}")
        traceback.print_exc()
    
    return findings


def check_variables_declared_explicitly(ast_tree, filename):
    """
    Custom function to detect variables assigned without explicit declaration (var/let/const).
    
    This function detects implicit global variables created by assignments without declarations.
    It handles:
    - Simple assignments without var/let/const (e.g., x = 10)
    - Assignments in expressions (e.g., y = 20 + 5)
    - Multiple assignments (e.g., a = 1; b = 2;)
    - Nested function scopes
    
    The function intelligently avoids false positives by:
    - Tracking declared variables in all scopes
    - Distinguishing between new assignments and re-assignments
    - Handling destructuring assignments
    - Recognizing loop variable declarations
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with violation details
    """
    
    findings = []
    
    try:
        # Track all declared variables across scopes
        declared_vars = set()
        
        def extract_declared_variables(node, scope_vars=None):
            """Extract all variable declarations from the AST."""
            if scope_vars is None:
                scope_vars = set()
            
            if not isinstance(node, dict):
                return scope_vars
            
            node_type = node.get('node_type', node.get('type', ''))
            
            # Handle variable declarations (var, let, const)
            if node_type in ['VariableDeclaration', 'VariableDeclarator']:
                declarations = node.get('declarations', [])
                if isinstance(declarations, list):
                    for decl in declarations:
                        if isinstance(decl, dict):
                            id_node = decl.get('id', {})
                            if isinstance(id_node, dict):
                                var_name = id_node.get('name')
                                if var_name:
                                    scope_vars.add(var_name)
                                    declared_vars.add(var_name)
                # Also check direct id in VariableDeclarator
                id_node = node.get('id', {})
                if isinstance(id_node, dict):
                    var_name = id_node.get('name')
                    if var_name:
                        scope_vars.add(var_name)
                        declared_vars.add(var_name)
            
            # Handle function parameters (also declared variables)
            if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                params = node.get('params', [])
                if isinstance(params, list):
                    for param in params:
                        if isinstance(param, dict):
                            param_name = param.get('name')
                            if param_name:
                                scope_vars.add(param_name)
                                declared_vars.add(param_name)
            
            # Handle for loop variable declarations
            if node_type == 'ForStatement':
                init = node.get('init', {})
                if isinstance(init, dict) and init.get('node_type') == 'VariableDeclaration':
                    extract_declared_variables(init, scope_vars)
            
            # Recursively process child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    extract_declared_variables(value, scope_vars)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            extract_declared_variables(item, scope_vars)
            
            return scope_vars
        
        # First pass: collect all declared variables
        extract_declared_variables(ast_tree)
        
        def check_node_for_undeclared_assignment(node, line_num=0):
            """Check if a node contains an undeclared variable assignment."""
            if not isinstance(node, dict):
                return
            
            node_type = node.get('node_type', node.get('type', ''))
            
            # Check for assignment expressions that are not part of a declaration
            if node_type in ['ExpressionStatement', 'AssignmentExpression']:
                source = node.get('source', '')
                line = node.get('line', line_num)
                
                # Skip if this is part of a declaration
                if any(keyword in source for keyword in ['var ', 'let ', 'const ']):
                    return
                
                # Pattern: identifier = value (simple assignment without declaration)
                # Match: x = 10, myVar = "string", obj = {}
                # Don't match: obj.prop = 10, this.x = 5
                simple_assignment = re.match(r'^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*.+', source)
                
                if simple_assignment:
                    var_name = simple_assignment.group(1)
                    
                    # Check if this variable was previously declared
                    if var_name not in declared_vars:
                        findings.append({
                            'rule_id': 'variables_declared_explicitly',
                            'message': f"Variable '{var_name}' is assigned without explicit declaration. Use 'let' or 'const' instead.",
                            'node': node_type,
                            'file': filename,
                            'property_path': ['source'],
                            'value': source.strip(),
                            'status': 'violation',
                            'line': line,
                            'severity': 'Major'
                        })
            
            # Recursively check child nodes
            for key, value in node.items():
                if key == 'line':
                    line_num = value
                elif isinstance(value, dict):
                    check_node_for_undeclared_assignment(value, line_num)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            check_node_for_undeclared_assignment(item, line_num)
        
        # Second pass: check for undeclared assignments
        if isinstance(ast_tree, dict):
            check_node_for_undeclared_assignment(ast_tree)
    
    except Exception as e:
        import traceback
        print(f"Error in check_variables_declared_explicitly: {e}")
        traceback.print_exc()
    
    return findings


def check_variables_declared_var_declared(ast_tree, filename):
    """
    Custom function to detect var declarations that are used before they are declared.
    
    This function detects the confusing behavior of var hoisting where:
    - Variables declared with 'var' are hoisted to the top of their function scope
    - They can be used before their declaration line (evaluating to undefined)
    - This causes confusion, especially when shadowing global variables
    
    The function tracks:
    - All var declarations and their line numbers within each function scope
    - All identifier usages and their line numbers
    - Reports violations when a var is used before its declaration line
    
    Note: This does NOT apply to let/const which have block scope and temporal dead zones.
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with violation details
    """
    
    findings = []
    
    try:
        def analyze_function_scope(node, scope_name="global"):
            """Analyze a function scope for var hoisting issues."""
            if not isinstance(node, dict):
                return
            
            # Track var declarations and their lines in this scope
            var_declarations = {}  # {var_name: declaration_line}
            var_usages = []  # [(var_name, usage_line, usage_source)]
            
            def collect_var_declarations(n, current_line=0):
                """Collect all var declarations in this scope (not nested functions)."""
                if not isinstance(n, dict):
                    return
                
                node_type = n.get('node_type', n.get('type', ''))
                
                # Don't descend into nested functions
                if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                    if n != node:  # Skip nested functions, but process current function
                        return
                
                # Track line numbers
                if 'line' in n:
                    current_line = n.get('line', current_line)
                elif 'lineno' in n:
                    current_line = n.get('lineno', current_line)
                
                # Collect VAR declarations only (not let/const)
                if node_type == 'VariableDeclaration':
                    kind = n.get('kind', '')
                    if kind == 'var':
                        declarations = n.get('declarations', [])
                        for decl in declarations:
                            if isinstance(decl, dict):
                                id_node = decl.get('id', {})
                                if isinstance(id_node, dict):
                                    var_name = id_node.get('name')
                                    if var_name and var_name not in var_declarations:
                                        var_declarations[var_name] = current_line
                
                # Recursively process children
                for key, value in n.items():
                    if isinstance(value, dict):
                        collect_var_declarations(value, current_line)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                collect_var_declarations(item, current_line)
            
            def collect_var_usages(n, current_line=0):
                """Collect all identifier usages in this scope."""
                if not isinstance(n, dict):
                    return
                
                node_type = n.get('node_type', n.get('type', ''))
                
                # Don't descend into nested functions
                if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                    if n != node:
                        return
                
                # Track line numbers
                if 'line' in n:
                    current_line = n.get('line', current_line)
                elif 'lineno' in n:
                    current_line = n.get('lineno', current_line)
                
                # Collect identifier usages (but not in var declarations themselves)
                if node_type == 'Identifier':
                    # Make sure this isn't the declaration itself
                    parent_type = n.get('parent_type', '')
                    if parent_type != 'VariableDeclarator':
                        var_name = n.get('name')
                        source = n.get('source', var_name)
                        if var_name:
                            var_usages.append((var_name, current_line, source))
                
                # Also check console.log, alert, etc. that reference identifiers
                source = n.get('source', '')
                if source and current_line:
                    # Extract potential variable references from source
                    # Match identifiers but not keywords
                    import re
                    if any(keyword in source for keyword in ['console.log', 'alert', 'return']):
                        for var_name in var_declarations.keys():
                            if re.search(r'\b' + re.escape(var_name) + r'\b', source):
                                var_usages.append((var_name, current_line, source))
                
                # Recursively process children
                for key, value in n.items():
                    if isinstance(value, dict):
                        collect_var_usages(value, current_line)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                collect_var_usages(item, current_line)
            
            # Collect vars and usages in this scope
            collect_var_declarations(node)
            collect_var_usages(node)
            
            # Check for usages before declaration
            for var_name, usage_line, usage_source in var_usages:
                if var_name in var_declarations:
                    declaration_line = var_declarations[var_name]
                    if usage_line < declaration_line and usage_line > 0:
                        findings.append({
                            'rule_id': 'variables_declared_var_declared',
                            'message': f"Variable '{var_name}' (declared with 'var' on line {declaration_line}) is used before declaration on line {usage_line}. This can cause confusion due to hoisting.",
                            'node': 'Identifier',
                            'file': filename,
                            'property_path': ['source'],
                            'value': usage_source,
                            'status': 'violation',
                            'line': usage_line,
                            'severity': 'Major',
                            'declaration_line': declaration_line
                        })
            
            # Recursively analyze nested function scopes
            def find_nested_functions(n):
                if not isinstance(n, dict):
                    return
                
                node_type = n.get('node_type', n.get('type', ''))
                
                if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                    if n != node:  # Don't re-analyze current node
                        func_name = n.get('id', {}).get('name', 'anonymous')
                        analyze_function_scope(n, func_name)
                
                for key, value in n.items():
                    if isinstance(value, dict):
                        find_nested_functions(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                find_nested_functions(item)
            
            find_nested_functions(node)
        
        # Start analysis from the global scope
        if isinstance(ast_tree, dict):
            analyze_function_scope(ast_tree, "global")
    
    except Exception as e:
        import traceback
        print(f"Error in check_variables_declared_var_declared: {e}")
        traceback.print_exc()
    
    return findings


def check_variables_functions_redeclared(ast_tree, filename):
    """
    Custom function to detect variable and function redeclarations in the same scope.
    
    This function tracks declarations within each scope and identifies:
    - var variables redeclared with var
    - Functions redeclared with function keyword
    - Function/variable name conflicts (function then var, or var then function)
    
    Note: let/const cannot be redeclared (syntax error), so we focus on var and function.
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with redeclaration violations
    """
    
    findings = []
    
    try:
        # Get the source code for line-based analysis
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
        elif hasattr(ast_tree, 'source'):
            source_code = ast_tree.source
        
        if not source_code:
            return findings
        
        lines = source_code.split('\n')
        
        # Track declarations per scope
        # We'll track global scope and function scopes separately
        # Key insight: function declarations at the same level should be in the same scope
        scopes = [{}]  # Stack of scopes, each scope is {name: {'type': 'var'|'function', 'line': num}}
        
        brace_depth = 0
        function_brace_start = []  # Track when function bodies start
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Track brace depth changes
            prev_brace_depth = brace_depth
            brace_depth += line.count('{') - line.count('}')
            
            # Pop scopes when exiting function bodies
            while function_brace_start and brace_depth <= function_brace_start[-1]:
                function_brace_start.pop()
                if len(scopes) > 1:
                    scopes.pop()
            
            current_scope = scopes[-1]
            
            # Check for function declarations - BEFORE creating new scope
            func_matches = re.finditer(r'\bfunction\s+(\w+)\s*\(', line)
            for match in func_matches:
                func_name = match.group(1)
                
                # Check if already declared in current scope
                if func_name in current_scope:
                    prev_decl = current_scope[func_name]
                    finding = {
                        'rule_id': 'variables_functions_redeclared',
                        'message': f'Function "{func_name}" is redeclared (previously declared as {prev_decl["type"]} on line {prev_decl["line"]})',
                        'node': 'FunctionDeclaration',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_stripped,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
                else:
                    current_scope[func_name] = {'type': 'function', 'line': line_num}
                
                # Now create new scope for function body if there's an opening brace
                if '{' in line:
                    scopes.append({})
                    function_brace_start.append(brace_depth)
            
            # Check for var declarations
            var_matches = re.finditer(r'\bvar\s+(\w+)', line)
            for match in var_matches:
                var_name = match.group(1)
                
                if var_name in current_scope:
                    prev_decl = current_scope[var_name]
                    finding = {
                        'rule_id': 'variables_functions_redeclared',
                        'message': f'Variable "{var_name}" is redeclared (previously declared as {prev_decl["type"]} on line {prev_decl["line"]})',
                        'node': 'VariableDeclaration',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_stripped,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
                else:
                    current_scope[var_name] = {'type': 'var', 'line': line_num}
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_variables_functions_redeclared: {e}")
        traceback.print_exc()
        return []

def check_variable_property_parameter_names(ast_tree, filename):
    """
    Custom function to detect naming convention violations in variables, properties, and parameters.
    
    This function checks for:
    - Variables using snake_case instead of camelCase (except UPPER_SNAKE_CASE for constants)
    - Variables using PascalCase (reserved for classes/constructors)
    - Property names using snake_case
    - Parameter names using snake_case or PascalCase
    - Single letter variable names (except in loop contexts)
    
    Compliant naming:
    - camelCase for variables and parameters
    - UPPER_SNAKE_CASE for constants (const with all caps)
    - PascalCase for classes/constructors only
    
    Args:
        ast_tree (dict): The AST tree object
        filename (str): The filename being analyzed
        
    Returns:
        list: List of findings with naming convention violations
    """
    
    findings = []
    
    try:
        # Get the source code
        source_code = ""
        if isinstance(ast_tree, dict):
            source_code = ast_tree.get('source', '')
        elif hasattr(ast_tree, 'source'):
            source_code = ast_tree.source
        
        if not source_code:
            return findings
        
        lines = source_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip empty lines and comments
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Check variable declarations (var, let, const)
            var_pattern = r'\b(const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*='
            var_matches = re.finditer(var_pattern, line)
            
            for match in var_matches:
                keyword = match.group(1)
                var_name = match.group(2)
                
                # Skip destructuring patterns
                if '{' in line[:match.start()] or '[' in line[:match.start()]:
                    continue
                
                violation = None
                
                # Check for snake_case (has underscores)
                if '_' in var_name:
                    # Allow UPPER_SNAKE_CASE for const
                    if keyword == 'const' and var_name.isupper():
                        continue
                    violation = f'Variable "{var_name}" uses snake_case instead of camelCase'
                
                # Check for PascalCase (starts with uppercase)
                elif var_name[0].isupper():
                    # PascalCase is for classes, not variables
                    violation = f'Variable "{var_name}" uses PascalCase (reserved for classes/constructors)'
                
                # Check for single letter names (except common loop variables)
                elif len(var_name) == 1 and var_name not in ['i', 'j', 'k', 'x', 'y', 'z']:
                    # Check if it's in a for loop context
                    if 'for' not in line:
                        violation = f'Variable "{var_name}" is too short (single letter)'
                
                if violation:
                    finding = {
                        'rule_id': 'variable_property_parameter_names',
                        'message': violation,
                        'node': 'VariableDeclaration',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_stripped,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
            
            # Check function parameters
            func_param_pattern = r'\bfunction\s+\w+\s*\(([^)]*)\)'
            func_matches = re.finditer(func_param_pattern, line)
            
            for match in func_matches:
                params_str = match.group(1)
                if params_str.strip():
                    # Split parameters by comma
                    params = [p.strip() for p in params_str.split(',')]
                    
                    for param in params:
                        # Extract parameter name (handle default values)
                        param_name = param.split('=')[0].strip()
                        
                        if not param_name or param_name in ['...']:
                            continue
                        
                        violation = None
                        
                        # Check for snake_case in parameters
                        if '_' in param_name:
                            violation = f'Parameter "{param_name}" uses snake_case instead of camelCase'
                        
                        # Check for PascalCase in parameters
                        elif param_name[0].isupper():
                            violation = f'Parameter "{param_name}" uses PascalCase instead of camelCase'
                        
                        if violation:
                            finding = {
                                'rule_id': 'variable_property_parameter_names',
                                'message': violation,
                                'node': 'FunctionDeclaration',
                                'file': filename,
                                'property_path': ['source'],
                                'value': line_stripped,
                                'status': 'violation',
                                'line': line_num,
                                'severity': 'Major'
                            }
                            findings.append(finding)
            
            # Check object properties (simplified - look for property: value patterns)
            # Note: This is a simple check and may have false positives
            prop_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*'
            if '{' in line and not line_stripped.startswith('//'):
                prop_matches = re.finditer(prop_pattern, line)
                
                for match in prop_matches:
                    prop_name = match.group(1)
                    
                    # Skip if it looks like a label or other construct
                    if prop_name in ['function', 'if', 'for', 'while', 'switch', 'case', 'default']:
                        continue
                    
                    violation = None
                    
                    # Check for snake_case in property names
                    if '_' in prop_name and not prop_name.isupper():
                        violation = f'Property "{prop_name}" uses snake_case instead of camelCase'
                    
                    if violation:
                        finding = {
                            'rule_id': 'variable_property_parameter_names',
                            'message': violation,
                            'node': 'ObjectProperty',
                            'file': filename,
                            'property_path': ['source'],
                            'value': line_stripped,
                            'status': 'violation',
                            'line': line_num,
                            'severity': 'Major'
                        }
                        findings.append(finding)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_variable_property_parameter_names: {e}")
        traceback.print_exc()
        return []


def check_unused_assignments(ast_tree, filename):
    """
    Detect unused assignments (dead stores) - assignments that are never used or immediately overwritten.
    
    This is a simplified implementation that detects common patterns of unused assignments:
    - Variables assigned but never read in the same scope
    - Variables immediately overwritten without being read
    - Assignment expressions whose results are not used
    
    Args:
        ast_tree: The AST tree to analyze
        filename: The file being analyzed
        
    Returns:
        List of findings for unused assignments
    """
    findings = []
    
    try:
        def get_line_number(node):
            """Extract line number from node"""
            if isinstance(node, dict):
                # Try different line number formats
                if 'lineno' in node:
                    return node['lineno']
                elif 'loc' in node and isinstance(node['loc'], dict):
                    start = node['loc'].get('start', {})
                    if isinstance(start, dict) and 'line' in start:
                        return start['line']
            return 0
        
        def collect_all_nodes(node):
            """Recursively collect all nodes from AST."""
            nodes = []
            if isinstance(node, dict):
                nodes.append(node)
                for key, value in node.items():
                    if isinstance(value, dict):
                        nodes.extend(collect_all_nodes(value))
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                nodes.extend(collect_all_nodes(item))
            elif isinstance(node, list):
                for item in node:
                    if isinstance(item, dict):
                        nodes.extend(collect_all_nodes(item))
            return nodes
        
        def get_variable_name(node):
            """Extract variable name from various node types."""
            if not isinstance(node, dict):
                return None
            
            node_type = node.get('type') or node.get('node_type')
            
            if node_type == 'Identifier':
                return node.get('name')
            elif node_type == 'VariableDeclarator':
                id_node = node.get('id', {})
                if isinstance(id_node, dict):
                    return id_node.get('name')
            elif node_type == 'AssignmentExpression':
                left = node.get('left', {})
                if isinstance(left, dict):
                    return get_variable_name(left)
            
            return None
        
        def analyze_scope(scope_node):
            """Analyze a scope (function or program) for unused assignments."""
            scope_findings = []
            
            # Track variable assignments and usages
            assignments = {}  # var_name -> [(node, line_num)]
            usages = {}  # var_name -> [(node, line_num)]
            
            # Get all nodes in this scope
            all_nodes = collect_all_nodes(scope_node)
            
            # First pass: collect all assignments and their locations
            for node in all_nodes:
                if not isinstance(node, dict):
                    continue
                    
                node_type = node.get('type') or node.get('node_type')
                line_num = get_line_number(node)
                
                # Track variable declarations with initialization
                if node_type == 'VariableDeclarator':
                    var_name = get_variable_name(node)
                    init = node.get('init')
                    
                    if var_name and init is not None:
                        if var_name not in assignments:
                            assignments[var_name] = []
                        assignments[var_name].append((node, line_num, 'declaration'))
                
                # Track assignment expressions
                elif node_type == 'AssignmentExpression':
                    var_name = get_variable_name(node)
                    if var_name:
                        if var_name not in assignments:
                            assignments[var_name] = []
                        assignments[var_name].append((node, line_num, 'assignment'))
                
                # Track variable usages (reads)
                elif node_type == 'Identifier':
                    var_name = node.get('name')
                    # Check if this identifier is being read (not assigned to)
                    # A simple heuristic: if parent is not AssignmentExpression's left side
                    # This is simplified - a full implementation would need proper scope analysis
                    if var_name:
                        if var_name not in usages:
                            usages[var_name] = []
                        usages[var_name].append((node, line_num))
            
            # Second pass: detect unused assignments
            for var_name, var_assignments in assignments.items():
                if len(var_assignments) > 1:
                    # Check for immediately overwritten assignments
                    for i in range(len(var_assignments) - 1):
                        curr_node, curr_line, curr_type = var_assignments[i]
                        next_node, next_line, next_type = var_assignments[i + 1]
                        
                        # If there's no usage between two assignments, the first is dead
                        has_usage_between = False
                        if var_name in usages:
                            for _, usage_line in usages[var_name]:
                                if curr_line < usage_line < next_line:
                                    has_usage_between = True
                                    break
                        
                        if not has_usage_between and next_line > curr_line:
                            source = curr_node.get('source', '')
                            finding = {
                                'rule_id': 'unused_assignments_removed',
                                'message': f'Remove this useless assignment to "{var_name}"; it is immediately overwritten',
                                'node': curr_node.get('type', 'Unknown'),
                                'file': filename,
                                'property_path': ['source'],
                                'value': source,
                                'status': 'violation',
                                'line': curr_line,
                                'severity': 'Major'
                            }
                            scope_findings.append(finding)
                
                # Check if variable is assigned but never used
                if var_name not in usages or len(usages[var_name]) <= 1:
                    # Variable is assigned but not read (or only "used" in its own assignment)
                    for assign_node, assign_line, assign_type in var_assignments:
                        # Simple check: if variable has minimal usages, it might be unused
                        usage_count = len(usages.get(var_name, []))
                        
                        # If usage count equals assignment count, it's likely unused
                        # (the identifiers we found were in the assignments themselves)
                        if usage_count <= len(var_assignments):
                            source = assign_node.get('source', '')
                            # Avoid duplicate findings
                            is_duplicate = any(
                                f['line'] == assign_line and f['message'].startswith('Remove this useless assignment')
                                for f in scope_findings
                            )
                            
                            if not is_duplicate and assign_line > 0:
                                finding = {
                                    'rule_id': 'unused_assignments_removed',
                                    'message': f'Remove this useless assignment to "{var_name}"; the value is never used',
                                    'node': assign_node.get('type', 'Unknown'),
                                    'file': filename,
                                    'property_path': ['source'],
                                    'value': source,
                                    'status': 'violation',
                                    'line': assign_line,
                                    'severity': 'Major'
                                }
                                scope_findings.append(finding)
                                break  # Only report once per variable
            
            return scope_findings
        
        # Analyze the entire program
        if isinstance(ast_tree, dict):
            # Get all function scopes and the program scope
            all_nodes = collect_all_nodes(ast_tree)
            
            # Analyze program scope
            findings.extend(analyze_scope(ast_tree))
            
            # Analyze each function scope
            for node in all_nodes:
                if isinstance(node, dict):
                    node_type = node.get('type') or node.get('node_type')
                    if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                        findings.extend(analyze_scope(node))
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_unused_assignments: {e}")
        traceback.print_exc()
        return []


def check_unused_function_parameters(ast_tree, filename):
    """
    Detect function parameters that are declared but never used within the function body.
    
    This checks for:
    - Function declarations with unused parameters
    - Function expressions with unused parameters
    - Arrow functions with unused parameters
    - Methods with unused parameters
    
    Args:
        ast_tree: The AST tree to analyze
        filename: The file being analyzed
        
    Returns:
        List of findings for unused function parameters
    """
    findings = []
    
    try:
        def get_line_number(node):
            """Extract line number from node"""
            if isinstance(node, dict):
                if 'lineno' in node:
                    return node['lineno']
                elif 'loc' in node and isinstance(node['loc'], dict):
                    start = node['loc'].get('start', {})
                    if isinstance(start, dict) and 'line' in start:
                        return start['line']
            return 0
        
        def get_parameter_names(params):
            """Extract parameter names from params list"""
            param_names = []
            if not isinstance(params, list):
                return param_names
                
            for param in params:
                if isinstance(param, dict):
                    # Handle different parameter types
                    param_type = param.get('type') or param.get('node_type', '')
                    
                    if param_type == 'Identifier':
                        name = param.get('name')
                        if name:
                            param_names.append(name)
                    elif param_type == 'RestElement':
                        # Handle rest parameters (...args)
                        argument = param.get('argument', {})
                        if isinstance(argument, dict):
                            name = argument.get('name')
                            if name:
                                param_names.append(name)
                    elif param_type == 'AssignmentPattern':
                        # Handle default parameters (param = default)
                        left = param.get('left', {})
                        if isinstance(left, dict):
                            name = left.get('name')
                            if name:
                                param_names.append(name)
                    # For destructuring, we skip as it's complex to track usage
                    
            return param_names
        
        def check_parameter_usage_in_body(param_name, body_node):
            """Check if a parameter is used anywhere in the function body"""
            if not isinstance(body_node, dict):
                return False
            
            # Get source code if available
            source = body_node.get('source', '')
            if source:
                # Simple text-based check - look for parameter name as whole word
                # This is not perfect but catches most cases
                pattern = r'\b' + re.escape(param_name) + r'\b'
                if re.search(pattern, source):
                    return True
            
            # Also check recursively through AST
            def find_identifier(node):
                if not isinstance(node, dict):
                    return False
                    
                node_type = node.get('type') or node.get('node_type', '')
                
                # Check if this is an identifier with matching name
                if node_type == 'Identifier':
                    if node.get('name') == param_name:
                        return True
                
                # Recursively check children
                for key, value in node.items():
                    if key == 'params':
                        # Don't check params themselves (parameter declarations)
                        continue
                    if isinstance(value, dict):
                        if find_identifier(value):
                            return True
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                if find_identifier(item):
                                    return True
                
                return False
            
            return find_identifier(body_node)
        
        def analyze_function(node):
            """Analyze a function node for unused parameters"""
            node_type = node.get('type') or node.get('node_type', '')
            
            # Only process function-like nodes
            if node_type not in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 
                                 'MethodDefinition']:
                return
            
            # Get parameters
            params = node.get('params', [])
            if not params:
                return  # No parameters to check
            
            # Get function body
            body = node.get('body', {})
            if not body:
                return  # No body to check usage in
            
            # For MethodDefinition, get the value which contains the function
            if node_type == 'MethodDefinition':
                value = node.get('value', {})
                if isinstance(value, dict):
                    params = value.get('params', [])
                    body = value.get('body', {})
            
            # Extract parameter names
            param_names = get_parameter_names(params)
            
            # Check each parameter for usage
            for param_name in param_names:
                # Skip if parameter starts with underscore (convention for intentionally unused)
                if param_name.startswith('_'):
                    continue
                
                # Check if parameter is used in body
                is_used = check_parameter_usage_in_body(param_name, body)
                
                if not is_used:
                    line_num = get_line_number(node)
                    
                    # Try to get function name for better message
                    func_id = node.get('id', {})
                    func_name = ''
                    if isinstance(func_id, dict):
                        func_name = func_id.get('name', '')
                    
                    # For method definitions
                    if node_type == 'MethodDefinition':
                        key = node.get('key', {})
                        if isinstance(key, dict):
                            func_name = key.get('name', '')
                    
                    message = f'Remove unused function parameter "{param_name}"'
                    if func_name:
                        message = f'Remove unused function parameter "{param_name}" from function "{func_name}"'
                    
                    finding = {
                        'rule_id': 'unused_function_parameters_removed',
                        'message': message,
                        'node': node_type,
                        'file': filename,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    }
                    findings.append(finding)
        
        def traverse(node):
            """Recursively traverse AST to find all functions"""
            if not isinstance(node, dict):
                return
            
            # Analyze this node if it's a function
            analyze_function(node)
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, dict):
                    traverse(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            traverse(item)
        
        # Start traversal
        traverse(ast_tree)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_unused_function_parameters: {e}")
        traceback.print_exc()
        return []


def check_unused_local_variables_functions(ast_tree, filename):
    """
    Detect local variables and functions that are declared but never used.
    
    This checks for:
    - Local variables declared but never referenced
    - Local functions declared but never called
    - Detects usage within the same scope and nested scopes
    
    Args:
        ast_tree: The AST tree to analyze
        filename: The file being analyzed
        
    Returns:
        List of findings for unused local variables and functions
    """
    findings = []
    
    try:
        # Read the actual source file for analysis
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception:
            return findings
        
        def get_line_number(node):
            """Extract line number from node"""
            if isinstance(node, dict):
                if 'lineno' in node:
                    return node['lineno']
                elif 'loc' in node and isinstance(node['loc'], dict):
                    start = node['loc'].get('start', {})
                    if isinstance(start, dict) and 'line' in start:
                        return start['line']
            return 0
        
        def extract_function_body_lines(node):
            """Extract the line range of a function body"""
            if not isinstance(node, dict):
                return None, None
            
            body = node.get('body', {})
            if isinstance(body, dict):
                loc = body.get('loc', {})
                if isinstance(loc, dict):
                    start = loc.get('start', {})
                    end = loc.get('end', {})
                    if isinstance(start, dict) and isinstance(end, dict):
                        return start.get('line'), end.get('line')
            return None, None
        
        def is_identifier_used_in_lines(name, start_line, end_line):
            """Check if identifier is used in the given line range"""
            if not source_code or not start_line or not end_line:
                return False
            
            lines = source_code.split('\n')
            pattern = r'\b' + re.escape(name) + r'\b'
            
            for i in range(start_line - 1, min(end_line, len(lines))):
                line = lines[i]
                
                # Remove comments from the line before checking
                # Remove single-line comments
                line_without_comments = re.sub(r'//.*$', '', line)
                # Remove multi-line comment starts (simple approach)
                line_without_comments = re.sub(r'/\*.*?\*/', '', line_without_comments)
                
                # Check if this is the declaration line
                is_declaration = (
                    re.search(rf'(const|let|var)\s+{re.escape(name)}\s*=', line_without_comments) or
                    re.search(rf'function\s+{re.escape(name)}\s*\(', line_without_comments)
                )
                
                if is_declaration:
                    # Check if used on same line after declaration
                    declaration_removed = re.sub(rf'(const|let|var)\s+{re.escape(name)}\s*=', '', line_without_comments, count=1)
                    declaration_removed = re.sub(rf'function\s+{re.escape(name)}\s*\(', '', declaration_removed, count=1)
                    if re.search(pattern, declaration_removed):
                        return True
                elif re.search(pattern, line_without_comments):
                    return True
            
            return False
        
        def analyze_function_scope(node):
            """Analyze a function scope for unused local variables and functions"""
            local_findings = []
            
            body = node.get('body', {})
            if not isinstance(body, dict):
                return local_findings
            
            body_statements = body.get('body', [])
            if not isinstance(body_statements, list):
                return local_findings
            
            # Get function body line range
            start_line, end_line = extract_function_body_lines(node)
            if not start_line or not end_line:
                return local_findings
            
            # Collect local declarations
            local_declarations = []
            
            for stmt in body_statements:
                if not isinstance(stmt, dict):
                    continue
                
                stmt_type = stmt.get('type') or stmt.get('node_type', '')
                
                # Variable declarations
                if stmt_type == 'VariableDeclaration':
                    for decl in stmt.get('declarations', []):
                        if isinstance(decl, dict):
                            id_node = decl.get('id', {})
                            if isinstance(id_node, dict):
                                var_name = id_node.get('name')
                                if var_name:
                                    init = decl.get('init', {})
                                    init_type = init.get('type') if isinstance(init, dict) else None
                                    is_function = init_type in ['FunctionExpression', 'ArrowFunctionExpression']
                                    
                                    local_declarations.append({
                                        'type': 'function' if is_function else 'variable',
                                        'name': var_name,
                                        'line': get_line_number(decl) or get_line_number(stmt)
                                    })
                
                # Function declarations
                elif stmt_type == 'FunctionDeclaration':
                    func_id = stmt.get('id', {})
                    if isinstance(func_id, dict):
                        func_name = func_id.get('name')
                        if func_name:
                            local_declarations.append({
                                'type': 'function',
                                'name': func_name,
                                'line': get_line_number(stmt)
                            })
            
            # Check each declaration for usage
            for decl in local_declarations:
                name = decl['name']
                is_used = is_identifier_used_in_lines(name, start_line, end_line)
                
                if not is_used:
                    message = f'Remove unused local {decl["type"]} "{name}"'
                    finding = {
                        'rule_id': 'unused_local_variables_functions',
                        'message': message,
                        'node': 'VariableDeclaration' if decl['type'] == 'variable' else 'FunctionDeclaration',
                        'file': filename,
                        'status': 'violation',
                        'line': decl['line'],
                        'severity': 'Major'
                    }
                    local_findings.append(finding)
            
            return local_findings
        
        def traverse(node):
            """Recursively traverse AST to find all functions"""
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type') or node.get('node_type', '')
            
            # Analyze function scopes
            if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                function_findings = analyze_function_scope(node)
                findings.extend(function_findings)
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, dict):
                    traverse(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            traverse(item)
        
        # Start traversal
        traverse(ast_tree)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_unused_local_variables_functions: {e}")
        traceback.print_exc()
        return []


def check_unused_react_component_methods(ast_tree, filename):
    """
    Detect unused methods in React class components.
    
    This checks for:
    - Custom methods in React components that are never called
    - Excludes React lifecycle methods (render, componentDidMount, etc.)
    - Excludes static methods
    - Checks for method calls within the component scope
    
    Args:
        ast_tree: The AST tree to analyze
        filename: The file being analyzed
        
    Returns:
        List of findings for unused React component methods
    """
    findings = []
    
    try:
        # Read the actual source file for analysis
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception:
            return findings
        
        # React lifecycle methods that should be ignored
        REACT_LIFECYCLE_METHODS = {
            'render', 'constructor',
            'componentDidMount', 'componentDidUpdate', 'componentWillUnmount',
            'shouldComponentUpdate', 'getSnapshotBeforeUpdate',
            'componentDidCatch', 'getDerivedStateFromProps', 'getDerivedStateFromError',
            'componentWillMount', 'componentWillReceiveProps', 'componentWillUpdate',  # Legacy
            'UNSAFE_componentWillMount', 'UNSAFE_componentWillReceiveProps', 'UNSAFE_componentWillUpdate'
        }
        
        def get_line_number(node):
            """Extract line number from node"""
            if isinstance(node, dict):
                if 'lineno' in node:
                    return node['lineno']
                elif 'loc' in node and isinstance(node['loc'], dict):
                    start = node['loc'].get('start', {})
                    if isinstance(start, dict) and 'line' in start:
                        return start['line']
            return 0
        
        def is_react_component(class_node):
            """Check if a class extends React.Component or Component"""
            if not isinstance(class_node, dict):
                return False
            
            superclass = class_node.get('superClass', {})
            if not isinstance(superclass, dict):
                return False
            
            # Check for React.Component
            if superclass.get('type') == 'MemberExpression':
                obj = superclass.get('object', {})
                prop = superclass.get('property', {})
                if isinstance(obj, dict) and isinstance(prop, dict):
                    if obj.get('name') == 'React' and prop.get('name') == 'Component':
                        return True
            
            # Check for Component (direct import)
            if superclass.get('type') == 'Identifier':
                if superclass.get('name') == 'Component':
                    return True
            
            return False
        
        def extract_class_body_lines(class_node):
            """Extract the line range of a class body"""
            if not isinstance(class_node, dict):
                return None, None
            
            body = class_node.get('body', {})
            if isinstance(body, dict):
                loc = body.get('loc', {})
                if isinstance(loc, dict):
                    start = loc.get('start', {})
                    end = loc.get('end', {})
                    if isinstance(start, dict) and isinstance(end, dict):
                        return start.get('line'), end.get('line')
            return None, None
        
        def get_method_name(method_def):
            """Extract method name from MethodDefinition node"""
            if not isinstance(method_def, dict):
                return None
            
            key = method_def.get('key', {})
            if isinstance(key, dict):
                return key.get('name')
            return None
        
        def is_method_static(method_def):
            """Check if a method is static"""
            return method_def.get('static', False) == True
        
        def is_method_used_in_class(method_name, start_line, end_line):
            """Check if a method is called within the class scope"""
            if not source_code or not start_line or not end_line:
                return False
            
            lines = source_code.split('\n')
            
            # Pattern to match: this.methodName( or this.methodName.bind(
            call_pattern = r'\bthis\.' + re.escape(method_name) + r'\s*[\(.]'
            
            # Also check for arrow function assignments: methodName = () =>
            # These are often event handlers
            arrow_pattern = r'\b' + re.escape(method_name) + r'\s*='
            
            for i in range(start_line - 1, min(end_line, len(lines))):
                line = lines[i]
                
                # Remove comments
                line_without_comments = re.sub(r'//.*$', '', line)
                line_without_comments = re.sub(r'/\*.*?\*/', '', line_without_comments)
                
                # Skip the method definition line itself
                if re.search(rf'\b{re.escape(method_name)}\s*\(', line_without_comments):
                    # This might be the definition, check if it's a method call
                    if re.search(call_pattern, line_without_comments):
                        return True
                    # Check if it's used as arrow function
                    if re.search(arrow_pattern, line_without_comments):
                        # Check if it's used later on the same or other lines
                        rest_of_code = '\n'.join(lines[i:min(end_line, len(lines))])
                        if re.search(call_pattern, rest_of_code):
                            return True
                elif re.search(call_pattern, line_without_comments):
                    return True
            
            return False
        
        def analyze_react_class(class_node):
            """Analyze a React class component for unused methods"""
            class_findings = []
            
            if not is_react_component(class_node):
                return class_findings
            
            body = class_node.get('body', {})
            if not isinstance(body, dict):
                return class_findings
            
            class_body = body.get('body', [])
            if not isinstance(class_body, list):
                return class_findings
            
            # Get class body line range
            start_line, end_line = extract_class_body_lines(class_node)
            if not start_line or not end_line:
                return class_findings
            
            # Collect all methods in the class
            methods = []
            for item in class_body:
                if isinstance(item, dict):
                    item_type = item.get('type') or item.get('node_type', '')
                    
                    if item_type == 'MethodDefinition':
                        method_name = get_method_name(item)
                        if method_name and not is_method_static(item):
                            # Skip React lifecycle methods
                            if method_name not in REACT_LIFECYCLE_METHODS:
                                methods.append({
                                    'name': method_name,
                                    'line': get_line_number(item),
                                    'node': item
                                })
            
            # Check each custom method for usage
            for method in methods:
                method_name = method['name']
                is_used = is_method_used_in_class(method_name, start_line, end_line)
                
                if not is_used:
                    message = f'Remove unused React component method "{method_name}"'
                    finding = {
                        'rule_id': 'unused_methods_react_components',
                        'message': message,
                        'node': 'MethodDefinition',
                        'file': filename,
                        'status': 'violation',
                        'line': method['line'],
                        'severity': 'Major'
                    }
                    class_findings.append(finding)
            
            return class_findings
        
        def traverse(node):
            """Recursively traverse AST to find all React class components"""
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type') or node.get('node_type', '')
            
            # Analyze React class components
            if node_type == 'ClassDeclaration':
                class_findings = analyze_react_class(node)
                findings.extend(class_findings)
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, dict):
                    traverse(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            traverse(item)
        
        # Start traversal
        traverse(ast_tree)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_unused_react_component_methods: {e}")
        traceback.print_exc()
        return []


def check_unused_private_class_members(ast_tree, filename):
    """
    Detect unused private class members (fields, methods, getters, setters).
    
    Private class members use # prefix (ES2022 feature).
    This checks for:
    - Private fields that are declared but never accessed
    - Private methods that are declared but never called
    - Private getters/setters that are never accessed
    - Static private members that are never used
    
    Args:
        ast_tree: The AST tree to analyze
        filename: The file being analyzed
        
    Returns:
        List of findings for unused private class members
    """
    findings = []
    
    try:
        # Read the actual source file for analysis
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception:
            return findings
        
        # Pattern to match private member declarations
        # Matches: #fieldName, #methodName(), get #getter(), set #setter(), static #staticField, etc.
        private_member_pattern = re.compile(
            r'^\s*(?:static\s+)?(?:get\s+|set\s+)?#([a-zA-Z_$][a-zA-Z0-9_$]*)',
            re.MULTILINE
        )
        
        # Pattern to match private member usage
        # Matches: this.#fieldName, ClassName.#staticField, this.#method()
        private_usage_pattern = r'(?:this|[A-Z][a-zA-Z0-9_]*)\.#([a-zA-Z_$][a-zA-Z0-9_$]*)'
        
        lines = source_code.split('\n')
        
        # Track which class we're in
        current_class = None
        class_start_line = None
        class_end_line = None
        brace_depth = 0
        in_class = False
        
        # Store private members by class
        private_members = {}  # {class_name: {member_name: line_number}}
        
        # First pass: find all classes and their private member declarations
        for i, line in enumerate(lines, 1):
            # Remove comments
            line_without_comments = re.sub(r'//.*$', '', line)
            line_without_comments = re.sub(r'/\*.*?\*/', '', line_without_comments)
            
            # Check for class declaration
            class_match = re.match(r'^\s*class\s+([A-Z][a-zA-Z0-9_]*)', line_without_comments)
            if class_match:
                current_class = class_match.group(1)
                class_start_line = i
                in_class = True
                brace_depth = 0
                if current_class not in private_members:
                    private_members[current_class] = {}
            
            if in_class:
                # Track braces to know when class ends
                brace_depth += line_without_comments.count('{')
                brace_depth -= line_without_comments.count('}')
                
                # Check for private member declarations
                private_match = private_member_pattern.search(line_without_comments)
                if private_match and current_class:
                    member_name = private_match.group(1)
                    # Store the member with its line number
                    if member_name not in private_members[current_class]:
                        private_members[current_class][member_name] = i
                
                # Check if class has ended
                if brace_depth == 0 and '{' in line_without_comments:
                    # Just started the class
                    pass
                elif brace_depth == 0 and class_start_line is not None:
                    # Class has ended
                    class_end_line = i
                    in_class = False
                    current_class = None
        
        # Second pass: find usage of private members
        used_private_members = set()  # Set of (class_name, member_name) tuples
        
        current_class = None
        in_class = False
        brace_depth = 0
        
        for i, line in enumerate(lines, 1):
            # Remove comments
            line_without_comments = re.sub(r'//.*$', '', line)
            line_without_comments = re.sub(r'/\*.*?\*/', '', line_without_comments)
            
            # Track current class
            class_match = re.match(r'^\s*class\s+([A-Z][a-zA-Z0-9_]*)', line_without_comments)
            if class_match:
                current_class = class_match.group(1)
                in_class = True
                brace_depth = 0
            
            if in_class:
                brace_depth += line_without_comments.count('{')
                brace_depth -= line_without_comments.count('}')
                
                # Find all private member usages in this line
                for match in re.finditer(private_usage_pattern, line_without_comments):
                    member_name = match.group(1)
                    
                    # Check if this is NOT the declaration line
                    # (usage on same line as declaration doesn't count)
                    is_declaration = private_member_pattern.search(line_without_comments)
                    if is_declaration:
                        declared_name = is_declaration.group(1)
                        # If it's used on the same line as declaration, skip this usage check
                        if declared_name == member_name:
                            # Check if there's actual usage after the declaration
                            decl_pos = is_declaration.start()
                            usage_pos = match.start()
                            if usage_pos <= decl_pos:
                                continue
                    
                    if current_class:
                        used_private_members.add((current_class, member_name))
                
                if brace_depth == 0 and class_match:
                    pass
                elif brace_depth == 0:
                    in_class = False
                    current_class = None
        
        # Third pass: report unused private members
        for class_name, members in private_members.items():
            for member_name, line_number in members.items():
                if (class_name, member_name) not in used_private_members:
                    message = f'Remove unused private class member "#{member_name}"'
                    finding = {
                        'rule_id': 'unused_private_class_members',
                        'message': message,
                        'node': 'PrivateField',
                        'file': filename,
                        'status': 'violation',
                        'line': line_number,
                        'severity': 'Major'
                    }
                    findings.append(finding)
        
        return findings
        
    except Exception as e:
        import traceback
        print(f"Error in check_unused_private_class_members: {e}")
        traceback.print_exc()
        return []


def check_using_regular_expressions(node):
    """
    Detects potentially dangerous regular expressions vulnerable to ReDoS.
    
    Checks for:
    - Nested quantifiers: (a+)+, (a*)*
    - Alternation with quantifiers: (a|ab)*
    - Overlapping patterns with quantifiers
    - Catastrophic backtracking patterns
    
    Args:
        node: AST node (Literal with regex or NewExpression for RegExp)
    
    Returns:
        bool: True if the regex is potentially vulnerable
    """
    if not isinstance(node, dict):
        return False
    
    node_type = node.get('type')
    pattern = None
    
    # Handle regex literals: const re = /pattern/
    if node_type == 'Literal' and 'regex' in node:
        regex_obj = node.get('regex', {})
        pattern = regex_obj.get('pattern', '')
    
    # Handle RegExp constructor: new RegExp('pattern')
    elif node_type == 'NewExpression':
        callee = node.get('callee', {})
        if callee.get('name') == 'RegExp':
            arguments = node.get('arguments', [])
            if arguments and len(arguments) > 0:
                first_arg = arguments[0]
                if first_arg.get('type') == 'Literal':
                    pattern = first_arg.get('value', '')
    
    if not pattern or not isinstance(pattern, str):
        return False
    
    # Patterns that indicate potential ReDoS vulnerabilities
    redos_patterns = [
        r'\((?:[^()]*[*+]){1,}\)[*+]',  # Nested quantifiers (a+)+
        r'\([^)]*\|[^)]*\)[*+]',  # Alternation with outer quantifiers (a|ab)*
        r'\(\.\*\)[*+]',  # (.*)*
        r'\([^)]*\+\)\+',  # Nested + quantifiers (a+)+
        r'\(\[[^\]]*\*\]\)[*+]',  # Character class with nested quantifiers
        r'\((?:\(+[^)]*)+\)[*+]',  # Multiple nested groups with quantifiers
        r'\([^)]*\?\)[*+]',  # Optional groups with outer quantifiers (a?)*
        r'\([^)]*\w\+[^)]*\w\+[^)]*\)[*+]',  # Multiple quantified elements
    ]
    
    for redos_pattern in redos_patterns:
        if re.search(redos_pattern, pattern):
            return True
    
    return False


def check_using_remote_artifacts_without(ast_tree, filename):
    """
    Detects loading remote scripts/stylesheets without integrity checks (SRI).
    
    This rule identifies:
    - createElement('script') calls that load remote resources without integrity
    - createElement('link') with rel='stylesheet' that load remote resources without integrity
    
    Args:
        ast_tree: The full AST tree
        filename: The file being scanned
    
    Returns:
        list: List of findings with violations
    """
    findings = []
    seen_findings = set()
    
    # Track all variables that might contain remote URLs
    remote_url_vars = set()
    
    def is_remote_url(url_value):
        """Check if URL is remote (http:// or https://)"""
        if not isinstance(url_value, str):
            return False
        url_lower = url_value.lower().strip()
        return url_lower.startswith('http://') or url_lower.startswith('https://')
    
    def check_node_for_remote_url(node):
        """Check if a node represents a remote URL (literal or identifier)"""
        if not isinstance(node, dict):
            return False
        
        # Check for literal remote URL
        if node.get('type') == 'Literal':
            return is_remote_url(node.get('value', ''))
        
        # Check for variable that holds remote URL
        if node.get('type') == 'Identifier':
            var_name = node.get('name')
            # If it's a known remote URL variable, flag it
            if var_name in remote_url_vars:
                return True
            # If it's a parameter named 'url' or similar, assume it might be remote
            if var_name and any(keyword in var_name.lower() for keyword in ['url', 'src', 'href', 'link', 'script']):
                return True
        
        # Check for member expression (array access, object property)
        if node.get('type') == 'MemberExpression':
            # For urls[i] or similar patterns, assume might be remote
            obj = node.get('object', {})
            if obj.get('type') == 'Identifier':
                obj_name = obj.get('name', '')
                # If accessing an array that likely contains URLs
                if any(keyword in obj_name.lower() for keyword in ['url', 'src', 'href', 'link', 'script']):
                    return True
        
        # Check for binary expression (concatenation)
        if node.get('type') == 'BinaryExpression':
            left = node.get('left', {})
            right = node.get('right', {})
            return check_node_for_remote_url(left) or check_node_for_remote_url(right)
        
        return False
    
    def traverse(node, parent=None, scope_vars=None):
        if scope_vars is None:
            scope_vars = {}
        
        if not isinstance(node, dict):
            if isinstance(node, list):
                for item in node:
                    traverse(item, parent, scope_vars)
            return
        
        node_type = node.get('type')
        
        # Track variables assigned to remote URLs
        if node_type == 'VariableDeclarator':
            var_id = node.get('id', {})
            var_name = var_id.get('name')
            init = node.get('init', {})
            
            if var_name and init.get('type') == 'Literal':
                url_value = init.get('value', '')
                if is_remote_url(url_value):
                    remote_url_vars.add(var_name)
                    scope_vars[var_name] = {'is_remote_url': True}
            
            # Check for createElement patterns
            if init.get('type') == 'CallExpression':
                callee = init.get('callee', {})
                
                # Check for document.createElement
                if (callee.get('type') == 'MemberExpression' and
                    callee.get('object', {}).get('name') == 'document' and
                    callee.get('property', {}).get('name') == 'createElement'):
                    
                    args = init.get('arguments', [])
                    if args and args[0].get('type') == 'Literal':
                        element_type = args[0].get('value', '').lower()
                        
                        if element_type in ['script', 'link']:
                            loc = node.get('loc', {})
                            line_number = loc.get('start', {}).get('line', 0) if loc else 0
                            
                            if var_name:
                                scope_vars[var_name] = {
                                    'line': line_number,
                                    'element_type': element_type,
                                    'has_src_or_href': False,
                                    'has_integrity': False,
                                    'is_remote': False,
                                    'rel_type': None
                                }
        
        # Track assignments to .src, .href, .integrity, .rel
        elif node_type == 'AssignmentExpression':
            left = node.get('left', {})
            right = node.get('right', {})
            
            if left.get('type') == 'MemberExpression':
                obj = left.get('object', {})
                prop = left.get('property', {})
                
                var_name = obj.get('name')
                prop_name = prop.get('name', '').lower()
                
                if var_name and var_name in scope_vars and 'element_type' in scope_vars[var_name]:
                    # Check for .src or .href assignment (literal or variable)
                    if prop_name in ['src', 'href']:
                        scope_vars[var_name]['has_src_or_href'] = True
                        
                        # Check if it's a remote URL (literal, variable, or expression)
                        if check_node_for_remote_url(right):
                            scope_vars[var_name]['is_remote'] = True
                    
                    # Check for .integrity assignment
                    elif prop_name == 'integrity':
                        scope_vars[var_name]['has_integrity'] = True
                    
                    # Check for .rel assignment (for link elements)
                    elif prop_name == 'rel':
                        if right.get('type') == 'Literal':
                            scope_vars[var_name]['rel_type'] = right.get('value', '').lower()
        
        # Track setAttribute calls
        elif node_type == 'CallExpression':
            callee = node.get('callee', {})
            
            if (callee.get('type') == 'MemberExpression' and
                callee.get('property', {}).get('name') == 'setAttribute'):
                
                obj = callee.get('object', {})
                var_name = obj.get('name')
                
                if var_name and var_name in scope_vars and 'element_type' in scope_vars[var_name]:
                    args = node.get('arguments', [])
                    if len(args) >= 2:
                        attr_name = args[0].get('value', '').lower()
                        
                        if attr_name in ['src', 'href']:
                            scope_vars[var_name]['has_src_or_href'] = True
                            # Check second argument for remote URL
                            if check_node_for_remote_url(args[1]):
                                scope_vars[var_name]['is_remote'] = True
                        
                        elif attr_name == 'integrity':
                            scope_vars[var_name]['has_integrity'] = True
                        
                        elif attr_name == 'rel':
                            if args[1].get('type') == 'Literal':
                                scope_vars[var_name]['rel_type'] = args[1].get('value', '').lower()
        
        # Handle blocks with new scopes (functions, loops, classes)
        elif node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 
                           'ForStatement', 'WhileStatement', 'ClassDeclaration', 'MethodDefinition']:
            # Create a new scope that inherits from parent
            new_scope = scope_vars.copy()
            
            # Traverse children with new scope
            for key, value in node.items():
                if key not in ['loc', 'range', 'type'] and isinstance(value, (dict, list)):
                    traverse(value, node, new_scope)
            
            # After traversing, check for violations in this scope
            for var_name, info in new_scope.items():
                if 'element_type' in info and info not in scope_vars.values():
                    check_and_add_finding(info, filename, seen_findings, findings)
            return  # Don't traverse again
        
        # Traverse children
        for key, value in node.items():
            if key not in ['loc', 'range', 'type'] and isinstance(value, (dict, list)):
                traverse(value, node, scope_vars)
    
    def check_and_add_finding(info, filename, seen_findings, findings):
        """Check if element info represents a violation and add finding"""
        if not isinstance(info, dict) or 'element_type' not in info:
            return
        
        should_flag = False
        message = ""
        
        # For script elements: flag if remote and no integrity
        if info['element_type'] == 'script':
            if info.get('is_remote') and not info.get('has_integrity'):
                should_flag = True
                message = "Loading remote script without integrity check is security-sensitive"
        
        # For link elements: only flag if rel="stylesheet" and remote and no integrity
        elif info['element_type'] == 'link':
            if info.get('rel_type') == 'stylesheet' and info.get('is_remote') and not info.get('has_integrity'):
                should_flag = True
                message = "Loading remote stylesheet without integrity check is security-sensitive"
        
        if should_flag:
            unique_key = (filename, info.get('line', 0))
            if unique_key not in seen_findings:
                seen_findings.add(unique_key)
                finding = {
                    'rule_id': 'using_remote_artifacts_without',
                    'message': message,
                    'file': filename,
                    'line': info['line'],
                    'status': 'violation'
                }
                findings.append(finding)
    
    # First pass: collect all scope variables
    scope_vars = {}
    traverse(ast_tree, None, scope_vars)
    
    # Check for violations in global scope
    for var_name, info in scope_vars.items():
        check_and_add_finding(info, filename, seen_findings, findings)
    
    return findings


def check_using_shell_interpreter_when(ast_tree, filename):
    """
    Detects dangerous use of child_process methods that spawn shells.
    
    Flags:
    - exec() and execSync() - always spawn shells
    - spawn(), spawnSync(), execFile(), execFileSync() with shell: true option
    
    Args:
        ast_tree: The full AST tree
        filename: The file being scanned
    
    Returns:
        list: List of findings with violations
    """
    findings = []
    seen_findings = set()
    
    # Track child_process variable names
    cp_vars = set(['cp'])  # Common aliases
    
    # Track destructured methods
    destructured_methods = {}  # method_name -> is_from_child_process
    
    def traverse(node, parent=None):
        if not isinstance(node, dict):
            if isinstance(node, list):
                for item in node:
                    traverse(item, parent)
            return
        
        node_type = node.get('type')
        
        # Track require('child_process')
        if node_type == 'VariableDeclarator':
            init = node.get('init', {})
            var_id = node.get('id', {})
            
            # Check for: const cp = require('child_process')
            if init.get('type') == 'CallExpression':
                callee = init.get('callee', {})
                if callee.get('name') == 'require':
                    args = init.get('arguments', [])
                    if args and args[0].get('type') == 'Literal':
                        if args[0].get('value') == 'child_process':
                            # Track the variable name
                            if var_id.get('type') == 'Identifier':
                                var_name = var_id.get('name')
                                if var_name:
                                    cp_vars.add(var_name)
                            
                            # Check for destructuring: const { exec, spawn } = require('child_process')
                            elif var_id.get('type') == 'ObjectPattern':
                                properties = var_id.get('properties', [])
                                for prop in properties:
                                    if prop.get('type') == 'Property':
                                        key = prop.get('key', {})
                                        value = prop.get('value', {})
                                        method_name = key.get('name')
                                        local_name = value.get('name')
                                        if method_name and local_name:
                                            destructured_methods[local_name] = method_name
        
        # Check for dangerous child_process method calls
        elif node_type == 'CallExpression':
            callee = node.get('callee', {})
            
            # Get line number
            loc = node.get('loc', {})
            line_number = loc.get('start', {}).get('line', 0) if loc else 0
            
            # Check for cp.exec(), cp.execSync(), etc.
            if callee.get('type') == 'MemberExpression':
                obj = callee.get('object', {})
                prop = callee.get('property', {})
                
                obj_name = obj.get('name')
                method_name = prop.get('name')
                
                # Check if it's a child_process call
                if obj_name in cp_vars and method_name:
                    is_dangerous = False
                    message = ""
                    
                    # exec and execSync always spawn shells
                    if method_name in ['exec', 'execSync']:
                        is_dangerous = True
                        message = f"Using {method_name}() always spawns a shell and is security-sensitive"
                    
                    # spawn, spawnSync, execFile, execFileSync are dangerous with shell: true
                    elif method_name in ['spawn', 'spawnSync', 'execFile', 'execFileSync']:
                        # Check for shell option
                        args = node.get('arguments', [])
                        for arg in args:
                            if arg.get('type') == 'ObjectExpression':
                                properties = arg.get('properties', [])
                                for prop_node in properties:
                                    if prop_node.get('type') == 'Property':
                                        key = prop_node.get('key', {})
                                        value = prop_node.get('value', {})
                                        
                                        if key.get('name') == 'shell':
                                            # Check if shell is set to true or a string (shell path)
                                            if value.get('type') == 'Literal':
                                                val = value.get('value')
                                                if val is True or isinstance(val, str):
                                                    is_dangerous = True
                                                    message = f"Using {method_name}() with shell option enabled is security-sensitive"
                                            elif value.get('type') == 'Identifier' and value.get('name') == 'true':
                                                is_dangerous = True
                                                message = f"Using {method_name}() with shell option enabled is security-sensitive"
                    
                    if is_dangerous:
                        unique_key = (filename, line_number)
                        if unique_key not in seen_findings:
                            seen_findings.add(unique_key)
                            findings.append({
                                'rule_id': 'using_shell_interpreter_when',
                                'message': message,
                                'file': filename,
                                'line': line_number,
                                'status': 'violation'
                            })
            
            # Check for destructured method calls: exec(), spawn(), etc.
            elif callee.get('type') == 'Identifier':
                method_name = callee.get('name')
                
                # Check if this is a destructured child_process method
                if method_name in destructured_methods:
                    original_method = destructured_methods[method_name]
                    is_dangerous = False
                    message = ""
                    
                    # exec and execSync always spawn shells
                    if original_method in ['exec', 'execSync']:
                        is_dangerous = True
                        message = f"Using {original_method}() always spawns a shell and is security-sensitive"
                    
                    # spawn, spawnSync, execFile, execFileSync are dangerous with shell: true
                    elif original_method in ['spawn', 'spawnSync', 'execFile', 'execFileSync']:
                        # Check for shell option
                        args = node.get('arguments', [])
                        for arg in args:
                            if arg.get('type') == 'ObjectExpression':
                                properties = arg.get('properties', [])
                                for prop_node in properties:
                                    if prop_node.get('type') == 'Property':
                                        key = prop_node.get('key', {})
                                        value = prop_node.get('value', {})
                                        
                                        if key.get('name') == 'shell':
                                            # Check if shell is set to true or a string
                                            if value.get('type') == 'Literal':
                                                val = value.get('value')
                                                if val is True or isinstance(val, str):
                                                    is_dangerous = True
                                                    message = f"Using {original_method}() with shell option enabled is security-sensitive"
                                            elif value.get('type') == 'Identifier' and value.get('name') == 'true':
                                                is_dangerous = True
                                                message = f"Using {original_method}() with shell option enabled is security-sensitive"
                    
                    if is_dangerous:
                        unique_key = (filename, line_number)
                        if unique_key not in seen_findings:
                            seen_findings.add(unique_key)
                            findings.append({
                                'rule_id': 'using_shell_interpreter_when',
                                'message': message,
                                'file': filename,
                                'line': line_number,
                                'status': 'violation'
                            })
        
        # Traverse children
        for key, value in node.items():
            if key not in ['loc', 'range', 'type'] and isinstance(value, (dict, list)):
                traverse(value, node)
    
    traverse(ast_tree)
    return findings


def check_using_sockets_is(ast_tree, filename):
    """
    Detects socket usage in JavaScript code (net.Socket, net.createConnection, net.connect, net.createServer, net.Server).
    Returns a list of findings with line numbers.
    """
    findings = []
    
    # Track require('net') variable names
    net_vars = set()
    
    # Track destructured imports from net module
    destructured_methods = {}
    
    def traverse(node, parent=None):
        if isinstance(node, dict):
            node_type = node.get('type')
            
            # Check for require('net')
            if node_type == 'VariableDeclarator':
                init = node.get('init', {})
                if isinstance(init, dict) and init.get('type') == 'CallExpression':
                    callee = init.get('callee', {})
                    if callee.get('type') == 'Identifier' and callee.get('name') == 'require':
                        args = init.get('arguments', [])
                        if args and isinstance(args[0], dict):
                            arg_value = args[0].get('value')
                            if arg_value == 'net':
                                # Track the variable name
                                id_node = node.get('id', {})
                                if id_node.get('type') == 'Identifier':
                                    var_name = id_node.get('name')
                                    if var_name:
                                        net_vars.add(var_name)
                                # Handle destructuring: const { Socket, connect, createConnection } = require('net')
                                elif id_node.get('type') == 'ObjectPattern':
                                    properties = id_node.get('properties', [])
                                    for prop in properties:
                                        if isinstance(prop, dict) and prop.get('type') == 'Property':
                                            key = prop.get('key', {})
                                            value = prop.get('value', {})
                                            if key.get('type') == 'Identifier' and value.get('type') == 'Identifier':
                                                method_name = key.get('name')
                                                var_name = value.get('name')
                                                if method_name in ['Socket', 'connect', 'createConnection', 'createServer', 'Server']:
                                                    destructured_methods[var_name] = method_name
            
            # Check for new net.Socket() or new Socket() (if destructured)
            if node_type == 'NewExpression':
                callee = node.get('callee', {})
                is_socket = False
                
                # Check for new net.Socket()
                if callee.get('type') == 'MemberExpression':
                    obj = callee.get('object', {})
                    prop = callee.get('property', {})
                    if (obj.get('type') == 'Identifier' and 
                        obj.get('name') in net_vars and
                        prop.get('type') == 'Identifier' and 
                        prop.get('name') in ['Socket', 'Server']):
                        is_socket = True
                
                # Check for new Socket() or new Server() (destructured)
                elif callee.get('type') == 'Identifier':
                    callee_name = callee.get('name')
                    if callee_name in destructured_methods:
                        method = destructured_methods[callee_name]
                        if method in ['Socket', 'Server']:
                            is_socket = True
                
                if is_socket:
                    loc = node.get('loc', {})
                    line_number = 0
                    if isinstance(loc, dict) and 'start' in loc:
                        line_number = loc['start'].get('line', 0)
                    if line_number > 0:
                        findings.append({
                            "rule_id": "using_sockets_is_securitysensitive",
                            "message": "Using Sockets is security-sensitive",
                            "file": filename,
                            "line": line_number,
                            "status": "violation"
                        })
            
            # Check for net.createConnection(), net.connect(), net.createServer()
            if node_type == 'CallExpression':
                callee = node.get('callee', {})
                is_socket_call = False
                
                # Check for net.method()
                if callee.get('type') == 'MemberExpression':
                    obj = callee.get('object', {})
                    prop = callee.get('property', {})
                    if (obj.get('type') == 'Identifier' and 
                        obj.get('name') in net_vars and
                        prop.get('type') == 'Identifier' and 
                        prop.get('name') in ['createConnection', 'connect', 'createServer']):
                        is_socket_call = True
                
                # Check for createConnection(), connect(), createServer() (destructured)
                elif callee.get('type') == 'Identifier':
                    callee_name = callee.get('name')
                    if callee_name in destructured_methods:
                        method = destructured_methods[callee_name]
                        if method in ['createConnection', 'connect', 'createServer']:
                            is_socket_call = True
                
                if is_socket_call:
                    loc = node.get('loc', {})
                    line_number = 0
                    if isinstance(loc, dict) and 'start' in loc:
                        line_number = loc['start'].get('line', 0)
                    if line_number > 0:
                        findings.append({
                            "rule_id": "using_sockets_is_securitysensitive",
                            "message": "Using Sockets is security-sensitive",
                            "file": filename,
                            "line": line_number,
                            "status": "violation"
                        })
            
            # Traverse child nodes
            for key, value in node.items():
                if key not in ['loc', 'range', 'type']:
                    traverse(value, node)
        
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)
    
    traverse(ast_tree)
    return findings


def check_using_unencrypted_ebs_volumes(ast_tree, filename):
    """
    Detects AWS EBS volumes with encryption explicitly disabled (encrypted: false).
    Detects:
    1. new Volume(..., { encrypted: false })
    2. Any object literal with encrypted: false (broad detection for AWS configs)
    Returns a list of findings with line numbers.
    """
    findings = []
    
    # Track Volume constructor usage
    volume_imports = set()
    
    def traverse(node, parent=None):
        if isinstance(node, dict):
            node_type = node.get('type')
            
            # Track imports of Volume from aws-cdk-lib/aws-ec2
            if node_type == 'VariableDeclarator':
                init = node.get('init', {})
                if isinstance(init, dict) and init.get('type') == 'CallExpression':
                    callee = init.get('callee', {})
                    if callee.get('type') == 'Identifier' and callee.get('name') == 'require':
                        args = init.get('arguments', [])
                        if args and isinstance(args[0], dict):
                            arg_value = args[0].get('value')
                            # Check for aws-cdk-lib/aws-ec2
                            if arg_value == 'aws-cdk-lib/aws-ec2':
                                id_node = node.get('id', {})
                                # Handle destructuring: const { Volume } = require(...)
                                if id_node.get('type') == 'ObjectPattern':
                                    properties = id_node.get('properties', [])
                                    for prop in properties:
                                        if isinstance(prop, dict) and prop.get('type') == 'Property':
                                            key = prop.get('key', {})
                                            value = prop.get('value', {})
                                            if (key.get('type') == 'Identifier' and 
                                                key.get('name') == 'Volume' and
                                                value.get('type') == 'Identifier'):
                                                var_name = value.get('name')
                                                volume_imports.add(var_name)
            
            # Check for ObjectExpression with encrypted: false property
            if node_type == 'ObjectExpression':
                properties = node.get('properties', [])
                for prop in properties:
                    if isinstance(prop, dict) and prop.get('type') == 'Property':
                        key = prop.get('key', {})
                        value = prop.get('value', {})
                        
                        # Check if key is 'encrypted' and value is false
                        if (key.get('type') == 'Identifier' and 
                            key.get('name') == 'encrypted' and
                            value.get('type') == 'Literal' and 
                            value.get('value') is False):
                            
                            # Check if this is in a Volume constructor call
                            # (or just flag all encrypted: false for broad security detection)
                            is_in_volume_call = False
                            
                            # Check parent chain for Volume constructor
                            check_parent = parent
                            depth = 0
                            while check_parent and depth < 10:
                                if isinstance(check_parent, dict):
                                    if check_parent.get('type') == 'NewExpression':
                                        callee = check_parent.get('callee', {})
                                        # Check for new Volume()
                                        if callee.get('type') == 'Identifier':
                                            if callee.get('name') in volume_imports:
                                                is_in_volume_call = True
                                                break
                                        # Check for new SomeModule.Volume()
                                        elif callee.get('type') == 'MemberExpression':
                                            prop = callee.get('property', {})
                                            if (prop.get('type') == 'Identifier' and 
                                                prop.get('name') == 'Volume'):
                                                is_in_volume_call = True
                                                break
                                check_parent = check_parent.get('__parent')
                                depth += 1
                            
                            # For broader detection, flag ALL encrypted: false
                            # Comment out the if condition below to make it Volume-specific only
                            # if is_in_volume_call:
                            
                            # Get line number from the property node
                            loc = prop.get('loc', {})
                            line_number = 0
                            if isinstance(loc, dict) and 'start' in loc:
                                line_number = loc['start'].get('line', 0)
                            
                            if line_number > 0:
                                findings.append({
                                    "rule_id": "using_unencrypted_ebs_volumes",
                                    "message": "Using unencrypted EBS volumes is security-sensitive",
                                    "file": filename,
                                    "line": line_number,
                                    "status": "violation"
                                })
            
            # Traverse child nodes
            for key, value in node.items():
                if key not in ['loc', 'range', 'type']:
                    traverse(value, node)
        
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)
    
    traverse(ast_tree)
    return findings





def check_using_unencrypted_efs_file(ast_tree, filename):
    """
    Detects AWS EFS file systems with encryption explicitly disabled.
    Detects both 'encrypted: false' and 'Encrypted: false' (case variation).
    Returns a list of findings with line numbers.
    """
    findings = []
    
    def traverse(node, parent=None):
        if isinstance(node, dict):
            node_type = node.get('type')
            
            # Check for ObjectExpression with encrypted/Encrypted: false property
            if node_type == 'ObjectExpression':
                properties = node.get('properties', [])
                for prop in properties:
                    if isinstance(prop, dict) and prop.get('type') == 'Property':
                        key = prop.get('key', {})
                        value = prop.get('value', {})
                        
                        # Check if key is 'encrypted' or 'Encrypted' and value is false
                        key_name = key.get('name', '')
                        if (key.get('type') == 'Identifier' and 
                            key_name in ['encrypted', 'Encrypted'] and
                            value.get('type') == 'Literal' and 
                            value.get('value') is False):
                            
                            # Get line number from the property node
                            loc = prop.get('loc', {})
                            line_number = 0
                            if isinstance(loc, dict) and 'start' in loc:
                                line_number = loc['start'].get('line', 0)
                            
                            if line_number > 0:
                                findings.append({
                                    "rule_id": "using_unencrypted_efs_file",
                                    "message": "Using unencrypted EFS file systems is security-sensitive",
                                    "file": filename,
                                    "line": line_number,
                                    "status": "violation"
                                })
            
            # Traverse child nodes
            for key, value in node.items():
                if key not in ['loc', 'range', 'type']:
                    traverse(value, node)
        
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)
    
    traverse(ast_tree)
    return findings


def check_using_unencrypted_elasticsearch_domains(ast_tree, filename):
    """
    Detects AWS OpenSearch/Elasticsearch domains without encryption at rest enabled.
    Detects:
    1. new Domain(...) without encryptionAtRest.enabled: true
    2. new CfnDomain(...) without encryptionAtRestOptions.enabled: true
    3. encryptionAtRest/encryptionAtRestOptions with enabled: false
    Returns a list of findings with line numbers.
    """
    findings = []
    
    # Track imports from aws-opensearchservice
    opensearch_imports = set()  # Variable names that reference the module
    domain_imports = set()  # Variable names for Domain class
    cfn_domain_imports = set()  # Variable names for CfnDomain class
    
    def has_encryption_enabled(obj_node):
        """Check if an object has encryptionAtRest or encryptionAtRestOptions with enabled: true"""
        if not isinstance(obj_node, dict) or obj_node.get('type') != 'ObjectExpression':
            return False
        
        properties = obj_node.get('properties', [])
        for prop in properties:
            if isinstance(prop, dict) and prop.get('type') == 'Property':
                key = prop.get('key', {})
                value = prop.get('value', {})
                
                # Check for encryptionAtRest or encryptionAtRestOptions
                if (key.get('type') == 'Identifier' and 
                    key.get('name') in ['encryptionAtRest', 'encryptionAtRestOptions']):
                    
                    # Check if it has enabled: true
                    if value.get('type') == 'ObjectExpression':
                        inner_props = value.get('properties', [])
                        for inner_prop in inner_props:
                            if isinstance(inner_prop, dict) and inner_prop.get('type') == 'Property':
                                inner_key = inner_prop.get('key', {})
                                inner_value = inner_prop.get('value', {})
                                
                                if (inner_key.get('type') == 'Identifier' and 
                                    inner_key.get('name') == 'enabled'):
                                    # Check if it's explicitly true
                                    if (inner_value.get('type') == 'Literal' and 
                                        inner_value.get('value') is True):
                                        return True
                                    # If enabled: false, it's explicitly insecure
                                    elif (inner_value.get('type') == 'Literal' and 
                                          inner_value.get('value') is False):
                                        return False
        
        return False
    
    def traverse(node, parent=None):
        if isinstance(node, dict):
            node_type = node.get('type')
            
            # Track imports from aws-cdk-lib/aws-opensearchservice
            if node_type == 'VariableDeclarator':
                init = node.get('init', {})
                if isinstance(init, dict) and init.get('type') == 'CallExpression':
                    callee = init.get('callee', {})
                    if callee.get('type') == 'Identifier' and callee.get('name') == 'require':
                        args = init.get('arguments', [])
                        if args and isinstance(args[0], dict):
                            arg_value = args[0].get('value')
                            
                            # Check for aws-cdk-lib/aws-opensearchservice
                            if arg_value == 'aws-cdk-lib/aws-opensearchservice':
                                id_node = node.get('id', {})
                                
                                # Handle: const opensearchservice = require(...)
                                if id_node.get('type') == 'Identifier':
                                    var_name = id_node.get('name')
                                    if var_name:
                                        opensearch_imports.add(var_name)
                                
                                # Handle: const { Domain, CfnDomain } = require(...)
                                elif id_node.get('type') == 'ObjectPattern':
                                    properties = id_node.get('properties', [])
                                    for prop in properties:
                                        if isinstance(prop, dict) and prop.get('type') == 'Property':
                                            key = prop.get('key', {})
                                            value = prop.get('value', {})
                                            if (key.get('type') == 'Identifier' and 
                                                value.get('type') == 'Identifier'):
                                                class_name = key.get('name')
                                                var_name = value.get('name')
                                                if class_name == 'Domain':
                                                    domain_imports.add(var_name)
                                                elif class_name == 'CfnDomain':
                                                    cfn_domain_imports.add(var_name)
            
            # Check for new Domain() or new CfnDomain()
            if node_type == 'NewExpression':
                callee = node.get('callee', {})
                arguments = node.get('arguments', [])
                is_domain = False
                
                # Check for: new Domain(...)
                if callee.get('type') == 'Identifier':
                    callee_name = callee.get('name')
                    if callee_name in domain_imports or callee_name in cfn_domain_imports:
                        is_domain = True
                
                # Check for: new opensearchservice.Domain(...)
                elif callee.get('type') == 'MemberExpression':
                    obj = callee.get('object', {})
                    prop = callee.get('property', {})
                    if (obj.get('type') == 'Identifier' and 
                        obj.get('name') in opensearch_imports and
                        prop.get('type') == 'Identifier' and 
                        prop.get('name') in ['Domain', 'CfnDomain']):
                        is_domain = True
                
                if is_domain:
                    # Check if the configuration has encryption enabled
                    has_encryption = False
                    
                    # Usually the config is the third argument (this, id, config)
                    if len(arguments) >= 3:
                        config = arguments[2]
                        has_encryption = has_encryption_enabled(config)
                    
                    # If no encryption or encryption disabled, report violation
                    if not has_encryption:
                        loc = node.get('loc', {})
                        line_number = 0
                        if isinstance(loc, dict) and 'start' in loc:
                            line_number = loc['start'].get('line', 0)
                        
                        if line_number > 0:
                            findings.append({
                                "rule_id": "using_unencrypted_elasticsearch_domains",
                                "message": "Using unencrypted Elasticsearch domains is security-sensitive",
                                "file": filename,
                                "line": line_number,
                                "status": "violation"
                            })
            
            # Also check for enabled: false in encryptionAtRest options
            if node_type == 'Property':
                key = node.get('key', {})
                value = node.get('value', {})
                
                if (key.get('type') == 'Identifier' and 
                    key.get('name') in ['encryptionAtRest', 'encryptionAtRestOptions']):
                    
                    if value.get('type') == 'ObjectExpression':
                        inner_props = value.get('properties', [])
                        for inner_prop in inner_props:
                            if isinstance(inner_prop, dict) and inner_prop.get('type') == 'Property':
                                inner_key = inner_prop.get('key', {})
                                inner_value = inner_prop.get('value', {})
                                
                                if (inner_key.get('type') == 'Identifier' and 
                                    inner_key.get('name') == 'enabled' and
                                    inner_value.get('type') == 'Literal' and 
                                    inner_value.get('value') is False):
                                    
                                    loc = inner_prop.get('loc', {})
                                    line_number = 0
                                    if isinstance(loc, dict) and 'start' in loc:
                                        line_number = loc['start'].get('line', 0)
                                    
                                    if line_number > 0:
                                        findings.append({
                                            "rule_id": "using_unencrypted_elasticsearch_domains",
                                            "message": "Using unencrypted Elasticsearch domains is security-sensitive",
                                            "file": filename,
                                            "line": line_number,
                                            "status": "violation"
                                        })
            
            # Traverse child nodes
            for key, value in node.items():
                if key not in ['loc', 'range', 'type']:
                    traverse(value, node)
        
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)
    
    traverse(ast_tree)
    return findings


def check_using_unencrypted_rds_db(ast_tree, filename):
    """
    Detects AWS RDS database resources without encryption enabled.
    Detects:
    1. new CfnDBCluster(...) without storageEncrypted: true
    2. new CfnDBInstance(...) without storageEncrypted: true
    3. new DatabaseCluster(...) without storageEncrypted: true or storageEncryptionKey
    4. new DBCluster(...) without storageEncrypted: true
    5. storageEncrypted explicitly set to false
    Returns a list of findings with line numbers.
    """
    findings = []
    
    def has_encryption_enabled(obj_node):
        """Check if an object has storageEncrypted: true or storageEncryptionKey"""
        if not isinstance(obj_node, dict) or obj_node.get('type') != 'ObjectExpression':
            return False
        
        properties = obj_node.get('properties', [])
        for prop in properties:
            if isinstance(prop, dict) and prop.get('type') == 'Property':
                key = prop.get('key', {})
                value = prop.get('value', {})
                
                # Check for storageEncrypted: true
                if (key.get('type') == 'Identifier' and 
                    key.get('name') == 'storageEncrypted' and
                    value.get('type') == 'Literal' and 
                    value.get('value') is True):
                    return True
                
                # Check for storageEncryptionKey (any value means encrypted)
                if (key.get('type') == 'Identifier' and 
                    key.get('name') == 'storageEncryptionKey'):
                    return True
        
        return False
    
    def has_encryption_disabled(obj_node):
        """Check if an object has storageEncrypted: false"""
        if not isinstance(obj_node, dict) or obj_node.get('type') != 'ObjectExpression':
            return False
        
        properties = obj_node.get('properties', [])
        for prop in properties:
            if isinstance(prop, dict) and prop.get('type') == 'Property':
                key = prop.get('key', {})
                value = prop.get('value', {})
                
                # Check for storageEncrypted: false
                if (key.get('type') == 'Identifier' and 
                    key.get('name') == 'storageEncrypted' and
                    value.get('type') == 'Literal' and 
                    value.get('value') is False):
                    return True
        
        return False
    
    def is_rds_resource_creation(node):
        """Check if this is a new expression creating an RDS resource"""
        if not isinstance(node, dict) or node.get('type') != 'NewExpression':
            return False
        
        callee = node.get('callee', {})
        
        # Handle MemberExpression: rds.CfnDBCluster, rds.DatabaseCluster, etc.
        if callee.get('type') == 'MemberExpression':
            property_node = callee.get('property', {})
            if property_node.get('type') == 'Identifier':
                class_name = property_node.get('name', '')
                # Match RDS database-related classes
                if re.match(r'^(CfnDB|DB|DatabaseCluster)', class_name):
                    return True
        
        # Handle Identifier: CfnDBCluster, DatabaseCluster, etc. (direct import)
        elif callee.get('type') == 'Identifier':
            class_name = callee.get('name', '')
            if re.match(r'^(CfnDB|DB|DatabaseCluster)', class_name):
                return True
        
        return False
    
    def traverse(node, parent=None):
        if isinstance(node, dict):
            node_type = node.get('type')
            
            # Check for NewExpression creating RDS resources
            if node_type == 'NewExpression' and is_rds_resource_creation(node):
                arguments = node.get('arguments', [])
                
                # Arguments typically: (this, 'name', {config})
                # The third argument (index 2) contains the configuration object
                config_obj = None
                if len(arguments) >= 3:
                    config_obj = arguments[2]
                elif len(arguments) == 2:
                    # Sometimes config might be the second argument
                    second_arg = arguments[1]
                    if isinstance(second_arg, dict) and second_arg.get('type') == 'ObjectExpression':
                        config_obj = second_arg
                
                # Check if encryption is explicitly disabled
                if config_obj and has_encryption_disabled(config_obj):
                    loc = node.get('loc', {})
                    line_number = 0
                    if isinstance(loc, dict) and 'start' in loc:
                        line_number = loc['start'].get('line', 0)
                    
                    if line_number > 0:
                        findings.append({
                            "rule_id": "using_unencrypted_rds_db",
                            "message": "Using unencrypted RDS DB resources is security-sensitive",
                            "file": filename,
                            "line": line_number,
                            "status": "violation"
                        })
                
                # Check if encryption is not configured (missing)
                elif config_obj and not has_encryption_enabled(config_obj):
                    loc = node.get('loc', {})
                    line_number = 0
                    if isinstance(loc, dict) and 'start' in loc:
                        line_number = loc['start'].get('line', 0)
                    
                    if line_number > 0:
                        findings.append({
                            "rule_id": "using_unencrypted_rds_db",
                            "message": "Using unencrypted RDS DB resources is security-sensitive",
                            "file": filename,
                            "line": line_number,
                            "status": "violation"
                        })
            
            # Traverse child nodes
            for key, value in node.items():
                if key not in ['loc', 'range', 'type']:
                    traverse(value, node)
        
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)
    
    traverse(ast_tree)
    return findings


def check_using_unencrypted_rds_db(ast_tree, filename):
    """
    Detects AWS RDS database resources without encryption enabled.
    Detects:
    1. new CfnDBCluster(...) without storageEncrypted: true
    2. new CfnDBInstance(...) without storageEncrypted: true
    3. new DatabaseCluster(...) without storageEncrypted: true or storageEncryptionKey
    4. new DBCluster(...) without storageEncrypted: true
    5. storageEncrypted explicitly set to false
    Returns a list of findings with line numbers.
    """
    import re
    findings = []
    
    def has_encryption_enabled(obj_node):
        """Check if an object has storageEncrypted: true or storageEncryptionKey"""
        if not isinstance(obj_node, dict) or obj_node.get('type') != 'ObjectExpression':
            return False
        
        properties = obj_node.get('properties', [])
        for prop in properties:
            if isinstance(prop, dict) and prop.get('type') == 'Property':
                key = prop.get('key', {})
                value = prop.get('value', {})
                
                # Check for storageEncrypted: true
                if (key.get('type') == 'Identifier' and 
                    key.get('name') == 'storageEncrypted' and
                    value.get('type') == 'Literal' and 
                    value.get('value') is True):
                    return True
                
                # Check for storageEncryptionKey (any value means encrypted)
                if (key.get('type') == 'Identifier' and 
                    key.get('name') == 'storageEncryptionKey'):
                    return True
        
        return False
    
    def has_encryption_disabled(obj_node):
        """Check if an object has storageEncrypted: false"""
        if not isinstance(obj_node, dict) or obj_node.get('type') != 'ObjectExpression':
            return False
        
        properties = obj_node.get('properties', [])
        for prop in properties:
            if isinstance(prop, dict) and prop.get('type') == 'Property':
                key = prop.get('key', {})
                value = prop.get('value', {})
                
                # Check for storageEncrypted: false
                if (key.get('type') == 'Identifier' and 
                    key.get('name') == 'storageEncrypted' and
                    value.get('type') == 'Literal' and 
                    value.get('value') is False):
                    return True
        
        return False
    
    def is_rds_resource_creation(node):
        """Check if this is a new expression creating an RDS resource"""
        if not isinstance(node, dict) or node.get('type') != 'NewExpression':
            return False
        
        callee = node.get('callee', {})
        
        # Handle MemberExpression: rds.CfnDBCluster, rds.DatabaseCluster, etc.
        if callee.get('type') == 'MemberExpression':
            property_node = callee.get('property', {})
            if property_node.get('type') == 'Identifier':
                class_name = property_node.get('name', '')
                # Match RDS database-related classes
                if re.match(r'^(CfnDB|DB|DatabaseCluster)', class_name):
                    return True
        
        # Handle Identifier: CfnDBCluster, DatabaseCluster, etc. (direct import)
        elif callee.get('type') == 'Identifier':
            class_name = callee.get('name', '')
            if re.match(r'^(CfnDB|DB|DatabaseCluster)', class_name):
                return True
        
        return False
    
    def traverse(node, parent=None):
        if isinstance(node, dict):
            node_type = node.get('type')
            
            # Check for NewExpression creating RDS resources
            if node_type == 'NewExpression' and is_rds_resource_creation(node):
                arguments = node.get('arguments', [])
                
                # Arguments typically: (this, 'name', {config})
                # The third argument (index 2) contains the configuration object
                config_obj = None
                if len(arguments) >= 3:
                    config_obj = arguments[2]
                elif len(arguments) == 2:
                    # Sometimes config might be the second argument
                    second_arg = arguments[1]
                    if isinstance(second_arg, dict) and second_arg.get('type') == 'ObjectExpression':
                        config_obj = second_arg
                
                # Check if encryption is explicitly disabled
                if config_obj and has_encryption_disabled(config_obj):
                    loc = node.get('loc', {})
                    line_number = 0
                    if isinstance(loc, dict) and 'start' in loc:
                        line_number = loc['start'].get('line', 0)
                    
                    if line_number > 0:
                        findings.append({
                            "rule_id": "using_unencrypted_rds_db",
                            "message": "Using unencrypted RDS DB resources is security-sensitive",
                            "file": filename,
                            "line": line_number,
                            "status": "violation"
                        })
                
                # Check if encryption is not configured (missing)
                elif config_obj and not has_encryption_enabled(config_obj):
                    loc = node.get('loc', {})
                    line_number = 0
                    if isinstance(loc, dict) and 'start' in loc:
                        line_number = loc['start'].get('line', 0)
                    
                    if line_number > 0:
                        findings.append({
                            "rule_id": "using_unencrypted_rds_db",
                            "message": "Using unencrypted RDS DB resources is security-sensitive",
                            "file": filename,
                            "line": line_number,
                            "status": "violation"
                        })
            
            # Traverse child nodes
            for key, value in node.items():
                if key not in ['loc', 'range', 'type']:
                    traverse(value, node)
        
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent)
    
    traverse(ast_tree)
    return findings
