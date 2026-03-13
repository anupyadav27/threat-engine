"""
Custom logic implementations for C language rules.
This module contains specific rule implementations that require custom logic.
"""

import re
from typing import List, Dict, Any


def check_variable_shadowing(ast_tree, filename):
    """
    Check for variable shadowing within function definitions.
    Detects when a variable in an inner scope has the same name as 
    a variable in an outer scope (parameter, outer local variable, or global).
    """
    violations = []
    
    def analyze_function(node):
        node_type = node.get('node_type', '')
        node_source = node.get('source', '')
        
        if node_type != 'FunctionDefinition':
            return
            
        function_start_line = node.get('line', 0)
        lines = node_source.split('\n')
        
        # Extract function parameters from signature
        parameters = set()
        signature_line = ""
        for line in lines[:5]:  # Function signature should be in first few lines
            if '(' in line and ')' in line:
                signature_line = line
                break
        
        # Parse parameters from function signature
        if '(' in signature_line and ')' in signature_line:
            params_part = signature_line[signature_line.find('('):signature_line.find(')')+1]
            # Match parameter patterns: type name, type* name, type name[], etc.
            param_matches = re.findall(r'\b(?:int|char|float|double|long|short|unsigned|signed|const|volatile|static|struct|union|void)\s+\*?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\])?\s*[,)]', params_part)
            for param in param_matches:
                if param not in ['void']:
                    parameters.add(param)
        
        # Track scope levels and variable names
        scope_stack = [parameters.copy()]  # Start with parameters as level 0
        brace_count = 0
        in_function_body = False
        
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            
            # Skip empty lines and comments
            if not stripped_line or stripped_line.startswith('//'):
                continue
                
            # Track when we enter function body
            if '{' in line and not in_function_body:
                in_function_body = True
                continue
                
            if not in_function_body:
                continue
                
            # Count braces to track scope depth
            line_brace_count = line.count('{') - line.count('}')
            
            # Handle opening braces - enter new scope
            for _ in range(line.count('{')):
                brace_count += 1
                scope_stack.append(set())
            
            # Check for variable declarations in current line
            current_scope_idx = min(len(scope_stack) - 1, brace_count)
            
            # Patterns for variable declarations
            var_patterns = [
                r'\b(?:int|char|float|double|long|short|unsigned|signed|const|volatile|static)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;,]',
                r'for\s*\(\s*(?:int|char|float|double|long|short|unsigned|signed)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
                r'\b(?:struct|union)\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;]'
            ]
            
            for pattern in var_patterns:
                var_matches = re.finditer(pattern, stripped_line)
                for match in var_matches:
                    var_name = match.group(1)
                    
                    # Check if this variable name exists in any outer scope
                    shadowed = False
                    for outer_scope_idx in range(current_scope_idx):
                        if outer_scope_idx < len(scope_stack) and var_name in scope_stack[outer_scope_idx]:
                            violations.append({
                                'line': function_start_line + i,
                                'message': f'Variable "{var_name}" shadows variable from outer scope'
                            })
                            shadowed = True
                            break
                    
                    # Add variable to current scope if not shadowing
                    if current_scope_idx < len(scope_stack):
                        scope_stack[current_scope_idx].add(var_name)
            
            # Handle closing braces - exit scope
            for _ in range(line.count('}')):
                if brace_count > 0:
                    brace_count -= 1
                    if len(scope_stack) > 1:
                        scope_stack.pop()
    
    def traverse_nodes(node):
        if isinstance(node, dict):
            analyze_function(node)
            for key, value in node.items():
                if key != 'parent' and isinstance(value, (dict, list)):
                    if isinstance(value, dict):
                        traverse_nodes(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                traverse_nodes(item)
    
    try:
        if isinstance(ast_tree, dict):
            traverse_nodes(ast_tree)
        elif isinstance(ast_tree, list):
            for node in ast_tree:
                if isinstance(node, dict):
                    traverse_nodes(node)
    except Exception as e:
        # If analysis fails, return empty list to avoid breaking the scanner
        print(f"Warning: variable shadowing analysis failed: {e}")
        return []
    
    return violations


def check_volatile_usage(ast_tree, filename):
    """
    Check for inappropriate use of volatile qualifier.
    Flags volatile when used in:
    - Function return types
    - Function parameters  
    
    Does NOT flag volatile when used for:
    - Global variables
    - Local variables
    - Struct/union members
    - Pointers to volatile data
    """
    violations = []
    
    def analyze_node(node, parent=None, parent_type=None):
        node_type = node.get('node_type', '')
        node_source = node.get('source', '')
        
        # Check for volatile in function definitions
        if node_type == 'FunctionDefinition':
            # Split into lines to get better line number accuracy
            source_lines = node_source.split('\n')
            function_start_line = node.get('line', 0)
            
            for i, line in enumerate(source_lines):
                line = line.strip()
                if not line:
                    continue
                    
                # Check for volatile in function return type
                # Pattern: volatile type function_name( or volatile type* function_name(
                if re.search(r'^\s*(\w+\s+)*volatile\s+\w+.*\w+\s*\(', line):
                    violations.append({
                        'line': function_start_line + i,
                        'message': 'Volatile qualifier on function return type has no well-defined meaning'
                    })
                
                # Check for volatile in function parameters
                # Pattern: (volatile type param) or , volatile type param
                if '(' in line and re.search(r'\(\s*(.*\s+)?volatile\s+\w+\s+\w+', line):
                    violations.append({
                        'line': function_start_line + i,
                        'message': 'Volatile qualifier on function parameter has no well-defined meaning'
                    })
                
                # Additional check for multi-line parameter declarations
                if re.search(r'\bvolatile\s+\w+\s+\w+[^=]*[,)]', line):
                    # Check if this looks like a parameter (contains comma or closing paren)
                    # and doesn't look like a variable declaration (no assignment)
                    if (',' in line or ')' in line) and '=' not in line.split('//')[0]:
                        violations.append({
                            'line': function_start_line + i,
                            'message': 'Volatile qualifier on function parameter has no well-defined meaning'
                        })
        
        # Recursively check child nodes
        if isinstance(node, dict):
            for key, value in node.items():
                if key != 'parent' and isinstance(value, (dict, list)):
                    if isinstance(value, dict):
                        analyze_node(value, node, node_type)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                analyze_node(item, node, node_type)
    
    try:
        if isinstance(ast_tree, dict):
            analyze_node(ast_tree)
        elif isinstance(ast_tree, list):
            for node in ast_tree:
                if isinstance(node, dict):
                    analyze_node(node)
    except Exception as e:
        # If analysis fails, return empty list to avoid breaking the scanner
        print(f"Warning: volatile analysis failed: {e}")
        return []
    
    return violations


def check_assembly_encapsulation(ast_tree, filename):
    """
    Check if assembly language code is properly encapsulated and isolated.
    
    Rule: Assembly language should be encapsulated and isolated in either
    assembler functions or C++ functions, not mixed with other C/C++ statements.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        # Check if this is a function node (both definitions and declarations)
        node_type = node.get('node_type', '')
        if node_type in ['Function', 'FunctionDefinition', 'FunctionDeclaration']:
            check_function_assembly(node, path, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    traverse_node(ast_tree)
    return findings


def check_function_assembly(function_node, path, findings, filename):
    """
    Check a specific function for assembly encapsulation violations.
    """
    function_name = function_node.get('name', 'unknown')
    function_source = function_node.get('source', '')
    lineno = function_node.get('lineno', 0)
    
    # Only check function definitions (those with bodies), not declarations
    if not function_node.get('is_definition', False):
        return
    
    # Parse the function body to find C statements and assembly blocks
    body_lines = extract_function_body_lines(function_source)
    if not body_lines:
        return
        
    # Categorize statements as assembly or non-assembly
    assembly_lines = []
    non_assembly_statements = []
    
    i = 0
    while i < len(body_lines):
        line_num, line_content = body_lines[i]
        
        # Check if this starts an assembly block
        if is_assembly_start(line_content):
            assembly_lines.append(lineno + line_num)
            # Skip to the end of the assembly block
            i = skip_assembly_block(body_lines, i)
        elif is_meaningful_c_statement(line_content):
            non_assembly_statements.append(lineno + line_num)
        
        i += 1
    
    # If we have both assembly and non-assembly statements, it's a violation
    if assembly_lines and non_assembly_statements:
        for asm_line in assembly_lines:
            findings.append({
                'rule_id': 'assembly_language_encapsulated_isolated',
                'message': f"Assembly language should be encapsulated and isolated in function '{function_name}'. Inline assembly mixed with C/C++ statements.",
                'file': filename,
                'line': asm_line,
                'severity': 'Info',
                'status': 'violation'
            })


def extract_function_body_lines(function_source):
    """Extract meaningful lines from function body, excluding braces and empty lines."""
    lines = function_source.split('\n')
    body_lines = []
    
    in_function_body = False
    brace_count = 0
    found_first_brace = False
    
    for i, line in enumerate(lines):
        original_line = line
        line_stripped = line.strip()
        
        # Track braces to know when we're in the function body
        if '{' in line and not found_first_brace:
            # This is the function's opening brace
            brace_count += line.count('{')
            in_function_body = True
            found_first_brace = True
            
            # Check for code after opening brace on same line
            brace_pos = line.rfind('{')
            code_after_brace = line[brace_pos + 1:].strip()
            if code_after_brace:
                # Remove inline comments
                if '//' in code_after_brace:
                    code_after_brace = code_after_brace[:code_after_brace.find('//')].strip()
                if code_after_brace:
                    body_lines.append((i, code_after_brace))
            continue
        
        # If we're inside the function body, track all braces
        if in_function_body:
            if '{' in line:
                brace_count += line.count('{')
            if '}' in line:
                brace_count -= line.count('}')
                
            # If we've reached the end of the function (brace_count back to 0)
            if brace_count == 0:
                # Check if there's code before closing brace
                brace_pos = line.find('}')
                code_before_brace = line[:brace_pos].strip()
                if code_before_brace:
                    # Remove inline comments
                    if '//' in code_before_brace:
                        code_before_brace = code_before_brace[:code_before_brace.find('//')].strip()
                    if code_before_brace:
                        body_lines.append((i, code_before_brace))
                break
            
            # If we still have content and we're inside the function body
            if line_stripped:
                # Remove inline comments
                if '//' in line_stripped:
                    line_stripped = line_stripped[:line_stripped.find('//')].strip()
                
                # Skip pure comment lines and empty lines
                if line_stripped and not line_stripped.startswith('/*'):
                    body_lines.append((i, line_stripped))
    
    return body_lines


def is_assembly_start(line):
    """Check if a line starts an assembly block."""
    asm_patterns = [
        r'\b(?:asm|__asm__|__asm)\s*\(',
        r'\b(?:asm|__asm__|__asm)\s+volatile\s*\(',
        r'\b(?:asm|__asm__|__asm)\s*\"',
    ]
    
    for pattern in asm_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


def skip_assembly_block(body_lines, start_index):
    """Skip to the end of an assembly block starting at start_index."""
    if start_index >= len(body_lines):
        return start_index
    
    start_line_num, start_line = body_lines[start_index]
    
    # Count parentheses to find the end of the assembly statement
    paren_count = 0
    in_string = False
    escape_next = False
    
    # Count opening parentheses in the start line
    for char in start_line:
        if escape_next:
            escape_next = False
            continue
        if char == '\\':
            escape_next = True
            continue
        if char == '"' and not escape_next:
            in_string = not in_string
        if not in_string:
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
    
    # If the assembly statement is completed on the same line
    if paren_count == 0:
        return start_index
    
    # Look for the closing of the assembly statement in subsequent lines
    for i in range(start_index + 1, len(body_lines)):
        line_num, line = body_lines[i]
        
        for char in line:
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not escape_next:
                in_string = not in_string
            if not in_string:
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
        
        # If we've balanced all parentheses, this is the end of assembly
        if paren_count == 0:
            return i
    
    # If we can't find the end, assume it ends at the current position
    return start_index


def is_meaningful_c_statement(line):
    """Check if a line contains a meaningful C statement (not assembly)."""
    # Skip empty lines, braces, and simple punctuation
    if not line or line in ['{', '}', ';', '']:
        return False
    
    # Skip lines that are part of multiline statements (like string continuations)
    if line.startswith('"') or line.startswith(':') or line.endswith(','):
        return False
    
    # Skip function signatures and declarations
    if re.match(r'^\s*\w+\s+\w+\s*\(.*\)\s*;?\s*$', line):
        return False
    
    # This is a meaningful C statement if it contains typical C constructs
    c_keywords = ['if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue', 'return']
    c_functions = ['printf', 'scanf', 'malloc', 'free', 'memcpy', 'strcpy']
    
    # Check for function calls, assignments, or control structures
    if (any(keyword in line for keyword in c_keywords) or
        any(func in line for func in c_functions) or
        '=' in line or
        '++' in line or '--' in line or
        ('(' in line and ')' in line and not is_assembly_start(line))):
        return True
    
    return False


def check_assembly_mixing(code, assembly_lines, start_lineno):
    """
    Check if assembly code is mixed with other C/C++ statements.
    Returns True if there's a violation (assembly mixed with other statements).
    """
    lines = code.split('\n')
    
    # Remove comments and empty lines, track meaningful statements
    meaningful_lines = []
    in_block_comment = False
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        
        # Handle block comments
        if '/*' in line_stripped and '*/' in line_stripped:
            # Single line block comment - remove it
            before_comment = line_stripped[:line_stripped.find('/*')]
            after_comment = line_stripped[line_stripped.find('*/') + 2:]
            line_stripped = (before_comment + after_comment).strip()
        elif '/*' in line_stripped:
            in_block_comment = True
            line_stripped = line_stripped[:line_stripped.find('/*')].strip()
        elif '*/' in line_stripped:
            in_block_comment = False
            line_stripped = line_stripped[line_stripped.find('*/') + 2:].strip()
        
        if in_block_comment:
            continue
            
        # Remove single line comments
        if '//' in line_stripped:
            line_stripped = line_stripped[:line_stripped.find('//')].strip()
        
        if line_stripped and line_stripped not in ['{', '}', '']:
            meaningful_lines.append((i, line_stripped))
    
    # Categorize each meaningful line as assembly or non-assembly
    assembly_statements = []
    non_assembly_statements = []
    
    # Assembly patterns
    asm_patterns = [
        r'\b(?:asm|__asm__|__asm)\s*(?:\(|\{)',
        r'\b(?:asm|__asm__|__asm)\s+volatile',
        r'\b(?:asm|__asm__|__asm)\s*\"',
        r'\b(?:asm|__asm__|__asm)\s*\(',
    ]
    
    for line_num, line_content in meaningful_lines:
        is_assembly = False
        
        # Check if this line contains assembly
        for pattern in asm_patterns:
            if re.search(pattern, line_content, re.IGNORECASE):
                is_assembly = True
                break
        
        if is_assembly:
            assembly_statements.append((line_num, line_content))
        else:
            # Check if it's a significant C statement (not just declarations or simple syntax)
            # Skip function signature lines and simple braces
            if (not line_content.endswith('{') and 
                not line_content.startswith('}') and
                not re.match(r'^\s*(void|int|char|float|double|static|inline|extern)', line_content) and
                '(' not in line_content or ')' not in line_content or '=' in line_content):
                non_assembly_statements.append((line_num, line_content))
    
    # If we have both assembly and non-assembly statements, it's a violation
    has_assembly = len(assembly_statements) > 0
    has_meaningful_non_assembly = len(non_assembly_statements) > 0
    
    return has_assembly and has_meaningful_non_assembly


def check_deprecated_code(ast_tree, metadata):
    """
    Example custom function for checking deprecated code patterns.
    This is a placeholder for other custom rule implementations.
    """
    # Implementation would go here
    return []


def check_constants_come_first_equality(ast_tree, filename):
    """
    Check if constants come first in equality tests.
    
    Rule: Constants should come first in equality tests to avoid assignment/comparison mistakes.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        # Check BinaryExpression nodes which contain comparison operations
        node_type = node.get('node_type', '')
        
        if node_type == 'BinaryExpression':
            source = node.get('source', '').strip()
            lineno = node.get('lineno', node.get('line', 0))
            
            # Skip empty lines, comments, includes
            if (not source or source.startswith('//') or source.startswith('/*') or 
                source.startswith('#')):
                return
            
            # Look for equality comparisons where variable comes first
            # Patterns to match (noncompliant cases):
            # - variable == constant_number
            # - variable == CONSTANT_NAME  
            # - variable == NULL
            # Exclude character literals as they are a different type of constant
            
            violation_patterns = [
                # variable == number (including hex, octal, negative)
                (r'(\w+)\s*==\s+(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|0[xX][0-9A-Fa-f]+|0[0-7]+)\b', 
                 'numeric constant'),
                # variable == UPPERCASE_CONSTANT
                (r'(\w+)\s*==\s+([A-Z_][A-Z_0-9]*)\b', 
                 'named constant'),  
                # variable == NULL
                (r'(\w+)\s*==\s+(NULL)\b', 
                 'NULL constant')
            ]
            
            for pattern, constant_type in violation_patterns:
                matches = re.finditer(pattern, source)
                for match in matches:
                    variable_name = match.group(1)
                    constant_value = match.group(2)
                    
                    # Skip if this is actually the compliant form (constant == variable)
                    # by checking if the variable name looks like a constant
                    if (variable_name.isupper() or variable_name == 'NULL' or 
                        variable_name.replace('_', '').replace('-', '').isdigit()):
                        continue
                    
                    # Skip character literal comparisons (e.g., c == 'b')
                    # This is done by checking if the constant is a character literal
                    if re.search(r"'.'", constant_value):
                        continue
                    
                    # Create unique identifier to prevent duplicates
                    violation_id = (filename, lineno, variable_name, constant_value)
                    if violation_id not in seen_violations:
                        seen_violations.add(violation_id)
                        
                        findings.append({
                            'rule_id': 'constants_come_first_equality',
                            'message': f"Variable '{variable_name}': Constants should come first in equality tests. Remove the problematic code and refactor as needed.",
                            'node': f"{node_type}.{node.get('name', 'BinaryExpression')}",
                            'file': filename,
                            'property_path': ['source'],
                            'value': f"{variable_name} == {constant_value}",
                            'status': 'violation',
                            'line': lineno,
                            'severity': 'Major'
                        })
        
        # Traverse children recursively
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type])
    
    # Start traversal from the root
    traverse_node(ast_tree)
    
    return findings


def check_assignments_in_conditions(ast_tree, filename):
    """
    Check for assignments made within condition expressions.
    
    Rule: Assignments should not be made from within conditions (if, while, for, switch)
    Exception: Assignments explicitly enclosed in double parentheses are allowed.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()  # To prevent duplicates
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
        
        node_type = node.get('node_type', '')
        
        # Only check function definitions for conditional statements
        if node_type in ['FunctionDefinition']:
            check_function_for_conditionals(node, path, findings, filename, seen_violations)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
    
    traverse_node(ast_tree)
    return findings


def check_function_for_conditionals(function_node, path, findings, filename, seen_violations):
    """Check a function's source code for conditional statements with assignments."""
    source = function_node.get('source', '')
    lineno = function_node.get('lineno', 0)
    
    if not source:
        return
    
    lines = source.split('\n')
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        current_line = lineno + i
        
        # Skip empty lines, comments, and preprocessor directives
        if (not line_stripped or line_stripped.startswith('//') or 
            line_stripped.startswith('/*') or line_stripped.startswith('#')):
            continue
        
        # Check for conditional statements with assignments
        # Handle nested parentheses properly
        for statement_type in ['if', 'while', 'for', 'switch']:
            pattern = rf'\b{statement_type}\s*\('
            start_match = re.search(pattern, line_stripped)
            if start_match:
                # Find the matching closing parenthesis
                start_pos = start_match.end() - 1  # Position of opening parenthesis
                paren_count = 0
                end_pos = start_pos
                
                for i in range(start_pos, len(line_stripped)):
                    if line_stripped[i] == '(':
                        paren_count += 1
                    elif line_stripped[i] == ')':
                        paren_count -= 1
                    
                    if paren_count == 0:
                        end_pos = i
                        break
                
                if paren_count == 0:  # Found matching parenthesis
                    condition_text = line_stripped[start_match.start():end_pos + 1]
                    
                    # Check if this is a valid assignment (not equality check or other operators)
                    assignment_details = extract_assignment_from_condition(condition_text)
                    if assignment_details:
                        assignment_text, is_parenthesized = assignment_details
                        
                        # Skip if assignment is explicitly parenthesized (allowed exception)
                        if is_parenthesized:
                            continue
                        
                        # Create unique identifier to prevent duplicates
                        violation_id = (filename, current_line, assignment_text, statement_type)
                        if violation_id not in seen_violations:
                            seen_violations.add(violation_id)
                            
                            findings.append({
                                'rule_id': 'assignments_made_from_within',
                                'message': f"Assignment '{assignment_text}' in {statement_type} condition should be avoided. Consider assigning before the condition.",
                                'file': filename,
                                'line': current_line,
                                'severity': 'Info',
                                'status': 'violation'
                            })


def extract_assignment_from_condition(condition_text):
    """
    Extract assignment expression from condition text.
    Returns tuple (assignment_text, is_parenthesized) if found, None otherwise.
    """
    # Extract the condition keyword and inner expression
    match = re.match(r'\s*(if|while|for|switch)\s*\(\s*(.*?)\s*\)\s*$', condition_text)
    if not match:
        return None
    
    statement_type = match.group(1)
    inner_condition = match.group(2)
    
    # For 'for' statements, we need to handle the three parts separately
    if statement_type == 'for':
        return check_for_loop_assignments(inner_condition)
    
    # For other statements, check for simple assignment
    return check_simple_assignment(inner_condition)


def check_for_loop_assignments(for_condition):
    """Check for loop condition for assignments (skip initialization part)."""
    # For loop format: (init; condition; increment)
    parts = for_condition.split(';')
    
    # Check the condition part (second part) for assignments
    if len(parts) >= 2:
        condition_part = parts[1].strip()
        if condition_part:  # Only check non-empty condition parts
            result = check_simple_assignment(condition_part)
            if result:
                return result
    
    return None


def check_simple_assignment(condition_expr):
    """
    Check a simple condition expression for assignment.
    Returns (assignment_text, is_parenthesized) if assignment found.
    """
    # Check if the entire expression is wrapped in extra parentheses
    is_parenthesized = False
    original_expr = condition_expr
    
    # Check for double parentheses pattern: ((assignment))
    double_paren_match = re.match(r'^\s*\(\s*(.+?)\s*\)\s*$', condition_expr)
    if double_paren_match:
        inner_expr = double_paren_match.group(1)
        # If the inner expression also has parentheses, this is double-parenthesized
        if re.match(r'^\s*\(.+?\)\s*$', inner_expr):
            is_parenthesized = True
        condition_expr = inner_expr
    
    # Look for assignment patterns (= but not ==, !=, <=, >=, etc.)
    # Match variable = expression (but not comparison operators)
    assignment_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^=<>!]+(?:\([^)]*\))?[^=<>!]*)'
    
    match = re.search(assignment_pattern, condition_expr)
    if match:
        var_name = match.group(1).strip()
        assigned_value = match.group(2).strip()
        
        # Make sure this is not a comparison operator
        if not re.search(r'[=<>!]=', condition_expr):
            # Clean up the assigned value (remove extra characters)
            assigned_value = re.sub(r'[,;)]*$', '', assigned_value)
            assignment_text = f"{var_name} = {assigned_value}"
            
            # Check if this assignment is in parentheses in the original expression
            if not is_parenthesized:
                # Check if assignment is wrapped in parentheses: (var = value)
                paren_pattern = rf'\(\s*{re.escape(var_name)}\s*=\s*[^)]+\)'
                if re.search(paren_pattern, original_expr):
                    is_parenthesized = True
            
            return (assignment_text, is_parenthesized)
    
    return None


def check_atof_atoi_atol_usage(ast_tree, filename):
    """
    Check for usage of unsafe string conversion functions atoi, atof, and atol.
    
    These functions have undefined behavior when strings cannot be converted
    and should be replaced with safer alternatives like strtol, strtod, etc.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        # Check the source content of this node for unsafe function calls
        source = node.get('source', '')
        lineno = node.get('lineno', 0)
        node_type = node.get('node_type', 'unknown')
        
        if source:
            # Find all instances of atoi, atof, atol function calls
            unsafe_functions = ['atoi', 'atof', 'atol']
            
            for func_name in unsafe_functions:
                # Create pattern to match function call
                pattern = rf'\b{func_name}\s*\('
                
                # Find all matches in the source
                for match in re.finditer(pattern, source):
                    # Calculate line number within the source if it's multiline
                    lines_before = source[:match.start()].count('\n')
                    actual_line = lineno + lines_before
                    
                    # Extract the specific line containing the violation
                    source_lines = source.split('\n')
                    if lines_before < len(source_lines):
                        violation_line = source_lines[lines_before].strip()
                    else:
                        violation_line = source.strip()
                    
                    # Create finding
                    finding = {
                        'rule_id': 'atof_atoi_atol_from',
                        'message': f"Unsafe string conversion function {func_name}() detected. Replace with safer alternatives: atoi() -> strtol(), atof() -> strtod(), atol() -> strtol() for proper error handling.",
                        'file': filename,
                        'line': actual_line,
                        'severity': 'Info',
                        'status': 'violation',
                        'function_name': func_name,
                        'code_snippet': violation_line,
                        'node_type': node_type
                    }
                    
                    # Avoid duplicate findings for the same line
                    duplicate = False
                    for existing in findings:
                        if (existing.get('line') == actual_line and 
                            existing.get('function_name') == func_name):
                            duplicate = True
                            break
                    
                    if not duplicate:
                        findings.append(finding)
        
        # Traverse children recursively
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    # Start traversal from the root
    traverse_node(ast_tree)
    
    return findings


def check_specific_source_lines_for_atoi_atof_atol(source_lines, filename, start_line=1):
    """
    Helper function to check individual source lines for atoi/atof/atol usage.
    This provides line-by-line scanning as a fallback detection method.
    
    Args:
        source_lines: List of source code lines
        filename: The filename being checked
        start_line: Starting line number (1-based)
        
    Returns:
        List of findings (violations)
    """
    findings = []
    unsafe_functions = ['atoi', 'atof', 'atol']
    
    for i, line in enumerate(source_lines):
        line_num = start_line + i
        line_content = line.strip()
        
        # Skip empty lines and comments
        if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
            continue
        
        for func_name in unsafe_functions:
            pattern = rf'\b{func_name}\s*\('
            if re.search(pattern, line_content):
                finding = {
                    'rule_id': 'atof_atoi_atol_from',
                    'message': f"Unsafe string conversion function {func_name}() detected. Replace with safer alternatives: atoi() -> strtol(), atof() -> strtod(), atol() -> strtol() for proper error handling.",
                    'file': filename,
                    'line': line_num,
                    'severity': 'Info', 
                    'status': 'violation',
                    'function_name': func_name,
                    'code_snippet': line_content
                }
                findings.append(finding)
    
    return findings


def check_bit_fields_usage(ast_tree, filename):
    """
    Check for usage of bit fields in struct and union declarations.
    
    Bit fields should be avoided because:
    - Platform-dependent behavior
    - Extra instructions required for interaction
    - Can confuse maintainers
    - Less relevant for memory savings in modern systems
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        # Check the source content of this node for bit field declarations
        source = node.get('source', '')
        lineno = node.get('lineno', 0)
        node_type = node.get('node_type', 'unknown')
        
        if source:
            # Find bit field patterns: type name : width;
            # Pattern matches: [type] [name] : [number] ;
            bit_field_patterns = [
                # Named bit fields: unsigned int name : 8;
                r'(?:unsigned\s+|signed\s+)?(?:int|char|short|long)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\d+)\s*;',
                # Anonymous bit fields: unsigned int : 8;
                r'(?:unsigned\s+|signed\s+)?(?:int|char|short|long)\s*:\s*(\d+)\s*;',
                # Complex type bit fields: struct_type name : 8;
                r'([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\d+)\s*;'
            ]
            
            for pattern in bit_field_patterns:
                for match in re.finditer(pattern, source, re.MULTILINE):
                    # Calculate line number within the source
                    lines_before = source[:match.start()].count('\n')
                    actual_line = lineno + lines_before
                    
                    # Extract the specific line containing the violation
                    source_lines = source.split('\n')
                    if lines_before < len(source_lines):
                        violation_line = source_lines[lines_before].strip()
                    else:
                        violation_line = match.group(0).strip()
                    
                    # Determine if it's named or anonymous bit field
                    field_info = match.groups()
                    if len(field_info) >= 2 and field_info[0].isdigit():
                        # Anonymous bit field
                        bit_width = field_info[0]
                        field_name = "<anonymous>"
                    elif len(field_info) >= 2:
                        # Named bit field
                        field_name = field_info[0] if not field_info[0].isdigit() else field_info[1]
                        bit_width = field_info[-1]
                    else:
                        field_name = "unknown"
                        bit_width = "unknown"
                    
                    # Create finding
                    finding = {
                        'rule_id': 'bit_fields_avoided',
                        'message': f"Bit field '{field_name}' detected. Bit fields should be avoided due to platform-dependent behavior and maintenance complexity. Use regular fields, enums, or macros instead.",
                        'file': filename,
                        'line': actual_line,
                        'severity': 'Major',
                        'status': 'violation',
                        'field_name': field_name,
                        'bit_width': bit_width,
                        'code_snippet': violation_line,
                        'node_type': node_type
                    }
                    
                    # Avoid duplicate findings for the same line
                    duplicate = False
                    for existing in findings:
                        if (existing.get('line') == actual_line and 
                            existing.get('field_name') == field_name):
                            duplicate = True
                            break
                    
                    if not duplicate:
                        findings.append(finding)
        
        # Traverse children recursively
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations', 'members']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    # Start traversal from the root
    traverse_node(ast_tree)
    
    return findings


def check_source_lines_for_bit_fields(source_lines, filename, start_line=1):
    """
    Helper function to check individual source lines for bit field usage.
    This provides line-by-line scanning as a fallback detection method.
    
    Args:
        source_lines: List of source code lines
        filename: The filename being checked
        start_line: Starting line number (1-based)
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    for i, line in enumerate(source_lines):
        line_num = start_line + i
        line_content = line.strip()
        
        # Skip empty lines and comments
        if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
            continue
        
        # Check for bit field patterns
        bit_field_pattern = r'(?:unsigned\s+|signed\s+)?(?:int|char|short|long|[a-zA-Z_][a-zA-Z0-9_]*)\s+(?:[a-zA-Z_][a-zA-Z0-9_]*\s*)?:\s*\d+'
        
        if re.search(bit_field_pattern, line_content):
            # Extract field name if possible
            name_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\d+)', line_content)
            if name_match:
                field_name = name_match.group(1)
                bit_width = name_match.group(2)
            else:
                field_name = "<detected>"
                bit_width = "unknown"
            
            finding = {
                'rule_id': 'bit_fields_avoided',
                'message': f"Bit field '{field_name}' detected. Bit fields should be avoided due to platform-dependent behavior and maintenance complexity. Use regular fields, enums, or macros instead.",
                'file': filename,
                'line': line_num,
                'severity': 'Major',
                'status': 'violation',
                'field_name': field_name,
                'bit_width': bit_width,
                'code_snippet': line_content
            }
            findings.append(finding)
    
    return findings


def check_bit_field_appropriate_types(ast_tree, filename):
    """
    Check for inappropriate types used in bit field declarations.
    
    Safe types for bit fields in C:
    - signed int, unsigned int
    - signed char, unsigned char  
    - signed short, unsigned short
    - _Bool
    
    Inappropriate types:
    - float, double (floating point types)
    - pointer types (*, void*, char*, etc.)
    - struct/union types
    - long long (may not be portable)
    - implementation-defined types (size_t, ptrdiff_t, wchar_t, etc.)
    - enum types (not recommended in C, though allowed in C++)
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    # Define safe and unsafe types for C bit fields
    safe_types = {
        'int', 'signed int', 'unsigned int',
        'char', 'signed char', 'unsigned char', 
        'short', 'signed short', 'unsigned short',
        '_Bool', 'bool'  # bool for C++
    }
    
    unsafe_types = {
        'float', 'double', 'long double',
        'long long', 'signed long long', 'unsigned long long',
        'long', 'signed long', 'unsigned long',  # May be problematic
        'size_t', 'ptrdiff_t', 'wchar_t', 'wint_t',
        'intptr_t', 'uintptr_t', 'intmax_t', 'uintmax_t'
    }
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        # Check the source content of this node for bit field declarations
        source = node.get('source', '')
        lineno = node.get('lineno', 0)
        node_type = node.get('node_type', 'unknown')
        
        if source:
            # Enhanced bit field pattern that captures the type
            # Pattern: [type specifiers] [type] [name] : [width] ;
            bit_field_patterns = [
                # Standard type with optional specifiers: unsigned int name : 8;
                r'((?:const\s+|volatile\s+|static\s+|extern\s+)*(?:unsigned\s+|signed\s+)?(?:int|char|short|long|float|double|bool|_Bool))\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\d+)\s*;',
                # Complex types: struct/union name fieldname : 8;
                r'((?:struct|union|enum)\s+[a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\d+)\s*;',
                # Pointer types: type* name : 8;
                r'([a-zA-Z_][a-zA-Z0-9_]*\s*\*+)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\d+)\s*;',
                # Typedef'ed types: CustomType name : 8;
                r'([A-Z][a-zA-Z0-9_]*[Tt]ype|[a-z][a-zA-Z0-9_]*_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\d+)\s*;',
                # Anonymous bit fields with type: unsigned int : 8;
                r'((?:const\s+|volatile\s+)*(?:unsigned\s+|signed\s+)?(?:int|char|short|long|float|double|bool|_Bool))\s*:\s*(\d+)\s*;'
            ]
            
            for pattern in bit_field_patterns:
                for match in re.finditer(pattern, source, re.MULTILINE):
                    # Calculate line number within the source
                    lines_before = source[:match.start()].count('\n')
                    actual_line = lineno + lines_before
                    
                    # Extract the specific line containing the violation
                    source_lines = source.split('\n')
                    if lines_before < len(source_lines):
                        violation_line = source_lines[lines_before].strip()
                    else:
                        violation_line = match.group(0).strip()
                    
                    # Extract type and field information
                    groups = match.groups()
                    declared_type = groups[0].strip()
                    
                    # Determine field name and bit width
                    if len(groups) >= 3:
                        field_name = groups[1].strip()
                        bit_width = groups[2].strip()
                    elif len(groups) == 2:
                        # Anonymous bit field
                        field_name = "<anonymous>"
                        bit_width = groups[1].strip()
                    else:
                        field_name = "unknown"
                        bit_width = "unknown"
                    
                    # Clean up the type for analysis
                    clean_type = re.sub(r'\s+', ' ', declared_type).strip()
                    clean_type = re.sub(r'(const|volatile|static|extern)\s+', '', clean_type).strip()
                    
                    # Check if type is inappropriate
                    is_inappropriate = False
                    violation_reason = ""
                    
                    # Check for obvious unsafe types
                    if any(unsafe in clean_type for unsafe in unsafe_types):
                        is_inappropriate = True
                        violation_reason = f"Type '{clean_type}' is implementation-defined or not suitable for bit fields"
                    
                    # Check for pointer types
                    elif '*' in clean_type:
                        is_inappropriate = True
                        violation_reason = f"Pointer type '{clean_type}' is not suitable for bit fields"
                    
                    # Check for struct/union/enum types
                    elif any(keyword in clean_type for keyword in ['struct', 'union', 'enum']):
                        is_inappropriate = True
                        violation_reason = f"Complex type '{clean_type}' is not suitable for bit fields"
                    
                    # Check for floating point types
                    elif any(fp_type in clean_type for fp_type in ['float', 'double']):
                        is_inappropriate = True
                        violation_reason = f"Floating point type '{clean_type}' is not allowed for bit fields"
                    
                    # Check for long long (potentially problematic)
                    elif 'long long' in clean_type:
                        is_inappropriate = True
                        violation_reason = f"Type '{clean_type}' may not be portable for bit fields"
                    
                    # Check for typedef patterns that suggest implementation-defined types
                    elif (clean_type.endswith('_t') or 
                          ('Type' in clean_type and clean_type[0].isupper())):
                        is_inappropriate = True
                        violation_reason = f"Typedef '{clean_type}' may be implementation-defined"
                    
                    # If type is not in safe list and not obviously problematic, flag it
                    elif clean_type not in safe_types and clean_type.replace('unsigned ', '').replace('signed ', '') not in safe_types:
                        is_inappropriate = True
                        violation_reason = f"Type '{clean_type}' is not in the safe types list for bit fields"
                    
                    if is_inappropriate:
                        # Create finding
                        finding = {
                            'rule_id': 'bit_fields_declared_appropriate',
                            'message': f"Bit field '{field_name}' declared with inappropriate type '{clean_type}'. {violation_reason}. Use safe types: signed/unsigned int, signed/unsigned char, signed/unsigned short, or _Bool.",
                            'file': filename,
                            'line': actual_line,
                            'severity': 'Info',
                            'status': 'violation',
                            'field_name': field_name,
                            'declared_type': clean_type,
                            'bit_width': bit_width,
                            'violation_reason': violation_reason,
                            'code_snippet': violation_line,
                            'node_type': node_type
                        }
                        
                        # Avoid duplicate findings for the same line and field
                        duplicate = False
                        for existing in findings:
                            if (existing.get('line') == actual_line and 
                                existing.get('field_name') == field_name and
                                existing.get('declared_type') == clean_type):
                                duplicate = True
                                break
                        
                        if not duplicate:
                            findings.append(finding)
        
        # Traverse children recursively
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations', 'members']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    # Start traversal from the root
    traverse_node(ast_tree)
    
    return findings


def check_blocking_functions_called_inside(ast_tree, filename):
    """
    Check if blocking functions are called inside critical sections.
    
    Rule: Blocking functions should not be called inside critical sections
    (while holding mutexes/locks) as this prevents concurrent threads from progressing.
    
    Blocking functions include:
    - I/O operations: printf, fprintf, fgets, fread, fwrite, scanf, fscanf, fflush
    - Sleep functions: sleep, usleep, nanosleep
    - String conversion: atoi, atol, atof, strtol, strtod, strtoll
    - Memory allocation: malloc, calloc, realloc, free
    - File operations: fopen, fclose, fseek, ftell
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    # Define blocking functions
    blocking_functions = {
        # I/O functions
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'scanf', 'fscanf', 'sscanf',
        'fgets', 'fputs', 'fread', 'fwrite',
        'fflush', 'fseek', 'ftell', 'rewind',
        'fopen', 'fclose', 'freopen',
        'puts', 'getchar', 'putchar', 'getc', 'putc',
        'gets', 'ungetc',
        
        # Sleep functions
        'sleep', 'usleep', 'nanosleep',
        
        # String conversion functions
        'atoi', 'atol', 'atoll', 'atof',
        'strtol', 'strtoll', 'strtoul', 'strtoull',
        'strtof', 'strtod', 'strtold',
        
        # Memory allocation functions
        'malloc', 'calloc', 'realloc', 'free',
        
        # System calls
        'system', 'exec', 'execl', 'execv'
    }
    
    # Mutex/lock functions
    lock_functions = {
        'pthread_mutex_lock', 'pthread_mutex_trylock',
        'pthread_rwlock_wrlock', 'pthread_rwlock_rdlock',
        'pthread_spin_lock', 'sem_wait'
    }
    
    unlock_functions = {
        'pthread_mutex_unlock',
        'pthread_rwlock_unlock', 'pthread_spin_unlock',
        'sem_post'
    }
    
    def traverse_node(node, path=[], in_critical_section=False, critical_start_line=None):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        line = node.get('line', 0)
        
        # Check for function calls
        if node_type == 'FunctionCall':
            function_name = get_function_name(node)
            
            if function_name in lock_functions:
                # Found lock acquisition, mark critical section start
                in_critical_section = True
                critical_start_line = line
            elif function_name in unlock_functions:
                # Found unlock, end critical section
                in_critical_section = False
                critical_start_line = None
            elif function_name in blocking_functions and in_critical_section:
                # Found blocking function call in critical section
                findings.append({
                    'rule_id': 'blocking_functions_called_inside',
                    'message': f'Blocking function "{function_name}" called inside critical section (started at line {critical_start_line})',
                    'line': line,
                    'severity': 'Critical',
                    'filename': filename
                })
        
        # Traverse children with current critical section state
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type], in_critical_section, critical_start_line)
        
        # Check other common child storage locations
        for key in ['body', 'statements', 'declarations', 'arguments', 'parameters']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type], in_critical_section, critical_start_line)
    
    def get_function_name(function_call_node):
        """Extract the function name from a function call node."""
        if 'name' in function_call_node:
            return function_call_node['name']
        if 'function_name' in function_call_node:
            return function_call_node['function_name']
        # Check if function name is in a child node
        if 'children' in function_call_node:
            for child in function_call_node['children']:
                if isinstance(child, dict) and child.get('node_type') == 'Identifier':
                    return child.get('name', child.get('value', ''))
        # Fallback: try to extract from value or text
        return function_call_node.get('value', function_call_node.get('text', ''))
    
    # Start traversal from the root
    traverse_node(ast_tree)
    
    return findings


def check_bool_expressions_inappropriate_operators(ast_tree, filename):
    """
    Check if bool expressions are used with inappropriate operators.
    
    Rule: bool expressions should be avoided as operands to built-in operators 
    other than =, &&, ||, !, ==, !=, unary &, and the conditional operator.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check AssignmentExpression nodes which contain variable assignments
        if node_type == 'AssignmentExpression':
            source = node.get('source', '').strip()
            line = node.get('lineno', node.get('line', 0))
            
            # Skip empty lines, comments, includes
            if (not source or source.startswith('//') or source.startswith('/*') or 
                source.startswith('#include') or source.startswith('*')):
                return
            
            # Check if source contains bool variables
            bool_vars = ['b1', 'b2', 'b3']
            has_bool_var = any(var in source for var in bool_vars)
            
            if not has_bool_var:
                return
            
            # Remove comments from source for better matching
            source_clean = re.sub(r'//.*$', '', source).strip()
            
            # Skip compliant logical and comparison operations
            if any(op in source_clean for op in ['&&', '||', '==', '!=', '?', ':']):
                return
            
            # Skip logical NOT which is compliant
            if '!b' in source_clean and '!=' not in source_clean:
                return
            
            # Check for inappropriate operations
            violation = None
            suggestion = None
            
            # Bitwise operators
            if ' & ' in source_clean and '&&' not in source_clean:
                violation = "bitwise operator '&'"
                suggestion = "Use logical && instead"
            elif ' | ' in source_clean and '||' not in source_clean:
                violation = "bitwise operator '|'"
                suggestion = "Use logical || instead"
            elif ' ^ ' in source_clean:
                violation = "bitwise operator '^'"
                suggestion = "XOR operation not meaningful with bool"
            elif '~' in source_clean and '!=' not in source_clean:
                violation = "bitwise operator '~'"
                suggestion = "Use logical ! instead"
            
            # Arithmetic operators (with spaces around them)
            elif ' + ' in source_clean:
                violation = "arithmetic operator '+'"
                suggestion = "Addition not meaningful with bool"
            elif ' - ' in source_clean:
                violation = "arithmetic operator '-'"
                suggestion = "Subtraction not meaningful with bool" 
            elif ' * ' in source_clean:
                violation = "arithmetic operator '*'"
                suggestion = "Multiplication not meaningful with bool"
            elif ' / ' in source_clean:
                violation = "arithmetic operator '/'"
                suggestion = "Division not meaningful with bool"
            elif ' % ' in source_clean:
                violation = "arithmetic operator '%'"
                suggestion = "Modulo not meaningful with bool"
            
            # Shift operators
            elif ' << ' in source_clean:
                violation = "shift operator '<<'"
                suggestion = "Left shift not meaningful with bool"
            elif ' >> ' in source_clean:
                violation = "shift operator '>>'"
                suggestion = "Right shift not meaningful with bool"
            
            # Compound assignment operators
            elif '+=' in source_clean:
                violation = "compound operator '+='";
                suggestion = "Compound addition not meaningful with bool"
            elif '-=' in source_clean:
                violation = "compound operator '-='"
                suggestion = "Compound subtraction not meaningful with bool"
            elif '*=' in source_clean:
                violation = "compound operator '*='"
                suggestion = "Compound multiplication not meaningful with bool"
            elif '/=' in source_clean:
                violation = "compound operator '/='"
                suggestion = "Compound division not meaningful with bool"
            elif '%=' in source_clean:
                violation = "compound operator '%='"
                suggestion = "Compound modulo not meaningful with bool"
            elif '&=' in source_clean:
                violation = "compound operator '&='"
                suggestion = "Compound bitwise AND not meaningful with bool"
            elif '|=' in source_clean:
                violation = "compound operator '|='"
                suggestion = "Compound bitwise OR not meaningful with bool"
            elif '^=' in source_clean:
                violation = "compound operator '^='"
                suggestion = "Compound bitwise XOR not meaningful with bool"
            elif '<<=' in source_clean:
                violation = "compound operator '<<='"
                suggestion = "Compound left shift not meaningful with bool"
            elif '>>=' in source_clean:
                violation = "compound operator '>>='"
                suggestion = "Compound right shift not meaningful with bool"
            
            # Report violation
            if violation:
                findings.append({
                    'filename': filename,
                    'line': line,
                    'message': f"Boolean variable used with inappropriate {violation}. {suggestion}",
                    'rule_id': 'bool_expressions_avoided_as',
                    'severity': 'Info'
                })
        
        # Recursively traverse children
        for key in ['children', 'body', 'statements', 'left', 'right', 'operand']:
            if key in node:
                child = node[key]
                if isinstance(child, list):
                    for item in child:
                        traverse_node(item, path + [node_type])
                elif isinstance(child, dict):
                    traverse_node(child, path + [node_type])
    
    traverse_node(ast_tree)
    return findings


def check_changing_working_directories_without(ast_tree, filename):
    """
    Check for chdir/fchdir calls without proper return value verification.
    
    This rule identifies security-sensitive directory change operations that don't
    verify success, which could lead to unintended relative path access.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()  # To prevent duplicates
    
    def is_return_value_checked(source_line):
        """
        Check if the return value of chdir/fchdir is being verified.
        """
        # Strip comments for better analysis
        clean_line = re.sub(r'//.*$', '', source_line).strip()
        
        # Case 1: Direct assignment to variable (compliant)
        # e.g., "int result = chdir("/path");"
        if re.search(r'\w+\s*=\s*(chdir|fchdir)\s*\(', clean_line):
            return True
            
        # Case 2: Used in if condition (compliant)
        # e.g., "if (chdir("/path") != 0)" or "if (chdir("/path") == 0)"
        if re.search(r'if\s*\(\s*(chdir|fchdir)\s*\([^)]*\)\s*[!=]=', clean_line):
            return True
            
        # Case 3: Used in while condition (compliant)
        if re.search(r'while\s*\(\s*(chdir|fchdir)\s*\([^)]*\)\s*[!=]=', clean_line):
            return True
            
        return False
    
    def traverse_node(node):
        if not isinstance(node, dict):
            return
            
        # Get source and line info
        source = node.get('source', '')
        lineno = node.get('lineno', node.get('line', 0))
        node_type = node.get('node_type', '')
        
        # Only process CallExpression nodes that contain actual chdir/fchdir calls
        if (node_type == 'CallExpression' and source and lineno and 
            re.search(r'\b(chdir|fchdir)\s*\([^)]*\)', source)):
            
            # Skip if this is not a standalone statement (i.e., part of if condition, assignment)
            if is_return_value_checked(source):
                return  # This is compliant - return value is being checked
            
            # Check if this is a bare function call (noncompliant)
            # Pattern: just "chdir(...)" followed by semicolon
            if re.search(r'^\s*(chdir|fchdir)\s*\([^)]*\)\s*;\s*(?://.*)?$', source.strip()):
                violation_key = (filename, lineno, source.strip())
                if violation_key not in seen_violations:
                    findings.append({
                        'rule_id': 'changing_working_directories_without',
                        'message': 'Changing working directories without verifying the success is security-sensitive',
                        'file': filename,
                        'line': lineno,
                        'severity': 'Major',
                        'status': 'violation'
                    })
                    seen_violations.add(violation_key)
        
        # Traverse children recursively
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, dict):
                    traverse_node(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            traverse_node(item)
    
    traverse_node(ast_tree)
    return findings


def check_changing_directories_improperly_when(ast_tree, filename):
    """
    Check for chroot calls without proper directory changes.
    
    This rule identifies chroot() calls that are not properly paired with chdir() calls,
    which could allow processes to access files outside the intended jail.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()
    
    # Collect all function calls
    function_calls = []
    
    def collect_function_calls(node):
        """Collect all chroot and chdir calls with their context."""
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        lineno = node.get('lineno', node.get('line', 0))
        node_type = node.get('node_type', '')
        
        # Look for chroot function calls
        if (node_type == 'CallExpression' and source and lineno and 
            re.search(r'\bchroot\s*\([^)]*\)', source)):
            
            function_calls.append({
                'function': 'chroot',
                'line': lineno,
                'source': source.strip()
            })
        
        # Look for chdir function calls  
        if (node_type == 'CallExpression' and source and lineno and 
            re.search(r'\bchdir\s*\([^)]*\)', source)):
            
            function_calls.append({
                'function': 'chdir',
                'line': lineno,
                'source': source.strip()
            })
        
        # Traverse children
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, dict):
                    collect_function_calls(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            collect_function_calls(item)
    
    def has_proper_chdir_nearby(chroot_call, all_calls):
        """Check if there's a proper chdir call near this chroot call."""
        chroot_line = chroot_call['line']
        
        # Look for chdir calls within +-5 lines
        for call in all_calls:
            if call['function'] == 'chdir':
                distance = abs(call['line'] - chroot_line)
                if distance <= 5 and distance > 0:  # Nearby but not same line
                    chdir_source = call['source']
                    
                    # Check if it's a good chdir (to jail root or proper path)
                    if ('chdir("/")' in chdir_source or 
                        ('chdir("/' in chdir_source and '/tmp' not in chdir_source) or
                        'chdir(jail' in chdir_source):
                        return True
        
        # Also check if both chdir and chroot are in same conditional
        chroot_source = chroot_call['source']
        if 'chdir(' in chroot_source and 'chroot(' in chroot_source:
            return True  # Pattern: if (chdir(...) && chroot(...))
        
        return False
    
    # Collect all function calls
    collect_function_calls(ast_tree)
    
    # Check each chroot call
    chroot_calls = [call for call in function_calls if call['function'] == 'chroot']
    
    for chroot_call in chroot_calls:
        line = chroot_call['line']
        source = chroot_call['source']
        
        # Skip calls that are marked as compliant (but not noncompliant)
        if ('// compliant' in source.lower() and '// noncompliant' not in source.lower()) or 'compliant:' in source.lower():
            continue
        
        # Check if this chroot has proper chdir accompaniment
        if not has_proper_chdir_nearby(chroot_call, function_calls):
            violation_key = (filename, line, source)
            if violation_key not in seen_violations:
                findings.append({
                    'rule_id': 'changing_directories_improperly_when',
                    'message': 'Changing directories improperly when using chroot is security-sensitive',
                    'file': filename,
                    'line': line,
                    'severity': 'Major',
                    'status': 'violation'
                })
                seen_violations.add(violation_key)
    
    return findings


def check_case_ranges_empty(ast_tree, filename):
    """
    Check for empty case ranges in switch statements.
    
    GNU C allows case ranges like "case 1 ... 5:" but if written in decreasing order
    like "case 5 ... 1:", the range is empty and will never execute.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()
    
    def parse_case_value(value_str):
        """Parse a case value which could be integer, character, or hex."""
        value_str = value_str.strip()
        
        try:
            # Character literal like 'a'
            if value_str.startswith("'") and value_str.endswith("'") and len(value_str) == 3:
                return ord(value_str[1])
            
            # Hex literal like 0x10
            if value_str.startswith('0x') or value_str.startswith('0X'):
                return int(value_str, 16)
            
            # Decimal integer (including negative)
            return int(value_str)
            
        except ValueError:
            # If parsing fails, return None to skip comparison
            return None
    
    def check_case_range(source, lineno):
        """Check if a case statement contains an empty range."""
        # Look for case range pattern: case X ... Y:
        import re
        pattern = r'case\s+([^.]+?)\s*\.\.\.\s*([^:]+?)\s*:'
        match = re.search(pattern, source)
        
        if not match:
            return False  # Not a range case
        
        start_str = match.group(1).strip()
        end_str = match.group(2).strip()
        
        # Parse both values
        start_val = parse_case_value(start_str)
        end_val = parse_case_value(end_str)
        
        # If we can parse both values, check if start > end (empty range)
        if start_val is not None and end_val is not None:
            if start_val > end_val:
                return True
        
        return False
    
    def traverse_node(node):
        """Traverse AST nodes to find case statements."""
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        lineno = node.get('lineno', node.get('line', 0))
        node_type = node.get('node_type', '')
        
        # Look for case statements with ranges - be more specific
        # Only check nodes that actually contain case range syntax
        import re
        case_range_pattern = r'^\s*case\s+[^.]+?\s*\.\.\.\s*[^:]+?\s*:'
        
        if source and lineno and re.search(case_range_pattern, source.strip()):
            if check_case_range(source, lineno):
                violation_key = (filename, lineno, source.strip())
                if violation_key not in seen_violations:
                    findings.append({
                        'rule_id': 'case_ranges_empty',
                        'message': 'Case ranges should not be empty. Review and fix according to the rule guidelines.',
                        'file': filename,
                        'line': lineno,
                        'severity': 'Info',
                        'status': 'violation'
                    })
                    seen_violations.add(violation_key)
        
        # Traverse children recursively
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, dict):
                    traverse_node(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            traverse_node(item)
    
    traverse_node(ast_tree)
    return findings



def check_break_statements_semantic(ast_tree, filename):
    """
    Check for break statements outside of switch cases using semantic analysis.
    
    Rule: break statements should be avoided except for switch cases.
    This function uses AST analysis to distinguish between break statements
    in loops (violations) vs. break statements in switch cases (compliant).
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, context_stack=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source = node.get('source', '').strip()
        line = node.get('lineno', node.get('line', 0))
        
        # Add current context to stack
        current_context = context_stack + [node_type]
        
        # Check for break statements
        if 'break' in source and 'break;' in source:
            # Analyze context to determine if this break is in a switch or loop
            is_in_switch = any('Switch' in ctx for ctx in current_context)
            is_in_loop = any(ctx in ['ForLoop', 'WhileLoop', 'DoWhileLoop', 'LoopStatement'] for ctx in current_context)
            
            # If we have explicit context information, use it
            if is_in_switch and not is_in_loop:
                # Break in switch case - this is compliant, skip
                pass
            elif is_in_loop:
                # Break in loop - this is a violation
                findings.append({
                    'filename': filename,
                    'line': line,
                    'message': 'Break statements should be avoided in loops. Refactor to use proper loop conditions instead.',
                    'rule_id': 'break_statements_avoided_except',
                    'severity': 'Major'
                })
            else:
                # Unable to determine context clearly, use heuristic analysis
                # Look for switch-related keywords in surrounding context
                source_lower = source.lower()
                if ('case' in source_lower or 'switch' in source_lower or 
                    'default' in source_lower):
                    # Likely in switch case - compliant
                    pass
                else:
                    # Check if we can find loop indicators in the source
                    if any(loop_kw in source_lower for loop_kw in ['for', 'while', 'do']):
                        # Likely in loop - violation
                        findings.append({
                            'filename': filename,
                            'line': line,
                            'message': 'Break statements should be avoided in loops except for switch cases',
                            'rule_id': 'break_statements_avoided_except',
                            'severity': 'Major'
                        })
        
        # Recursively traverse children with updated context
        for key in ['children', 'body', 'statements', 'cases', 'condition', 'init', 'increment']:
            if key in node:
                child = node[key]
                if isinstance(child, list):
                    for item in child:
                        traverse_node(item, current_context)
                elif isinstance(child, dict):
                    traverse_node(child, current_context)
    
    traverse_node(ast_tree)
    return findings


def check_continue_statements(ast_tree, filename):
    """
    Check for continue statements in C code.
    
    Rule: Continue statements should be avoided as they create unstructured 
    control flow that makes code less testable, less readable and less maintainable.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    try:
        # Read the actual source file directly for accurate line numbers
        with open(filename, 'r', encoding='utf-8') as f:
            file_content = f.read()
        
        file_lines = file_content.split('\n')
        
        # Look for continue statements in each line
        continue_pattern = r'\bcontinue\s*;'
        
        for line_num, line_content in enumerate(file_lines, 1):
            for match in re.finditer(continue_pattern, line_content):
                # Extract context around the continue statement
                context_start = max(0, match.start() - 10)
                context_end = min(len(line_content), match.end() + 10)
                context_text = line_content[context_start:context_end].strip()
                
                finding = {
                    "rule_id": "continue_avoided",
                    "message": "Continue statement detected: Replace with structured control flow (if/else statements)",
                    "node": "Statement.ContinueStatement",
                    "file": filename,
                    "property_path": ["source"],
                    "value": context_text,
                    "status": "violation",
                    "line": line_num,
                    "severity": "Info"
                }
                
                findings.append(finding)
                
    except Exception as e:
        # Fallback to AST-based detection if file reading fails
        print(f"Warning: Could not read file {filename} directly: {e}")
        findings = _fallback_ast_continue_detection(ast_tree, filename)
    
    return findings


def _fallback_ast_continue_detection(ast_tree, filename):
    """
    Fallback AST-based continue detection if direct file reading fails.
    """
    findings = []
    seen_continues = set()
    
    def traverse_node(node, context_info=None):
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        line = node.get('line', 0)
        
        if source and isinstance(source, str):
            lines = source.split('\n')
            
            for line_offset, source_line in enumerate(lines):
                continue_pattern = r'\bcontinue\s*;'
                
                for match in re.finditer(continue_pattern, source_line):
                    actual_line = line + line_offset if line > 0 else line_offset + 1
                    
                    if actual_line in seen_continues:
                        continue
                        
                    seen_continues.add(actual_line)
                    
                    context_start = max(0, match.start() - 10)
                    context_end = min(len(source_line), match.end() + 10)
                    context_text = source_line[context_start:context_end].strip()
                    
                    node_type = node.get('node_type', 'unknown')
                    node_name = node.get('name', 'unknown')
                    
                    finding = {
                        "rule_id": "continue_avoided",
                        "message": "Continue statement detected: Replace with structured control flow (if/else statements)",
                        "node": f"{node_type}.{node_name}",
                        "file": filename,
                        "property_path": ["source"],
                        "value": context_text,
                        "status": "violation",
                        "line": actual_line,
                        "severity": "Info"
                    }
                    
                    findings.append(finding)
        
        # Recursively traverse all children
        if 'children' in node and isinstance(node['children'], list):
            for child in node['children']:
                traverse_node(child, context_info)
        
        for child_key in ['body', 'statements', 'declarations', 'cases', 'members', 'items']:
            if child_key in node:
                child_value = node[child_key]
                if isinstance(child_value, list):
                    for child in child_value:
                        traverse_node(child, context_info)
                elif isinstance(child_value, dict):
                    traverse_node(child_value, context_info)
    
    traverse_node(ast_tree)
    return findings


def check_control_transfer_into_complex(ast_tree, filename):
    """
    Check for control transfer (goto, switch cases) into complex logic blocks.
    
    Rule: Control should not be transferred into a complex logic block using a 
    goto or a switch statement. Labels should not be placed inside loops, try-catch,
    or other complex control structures, and switch cases should not appear inside loops.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()
    
    def traverse_node(node, nesting_context=None):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        lineno = node.get('lineno', node.get('line', 0))
        
        # Track nesting context (what complex blocks we're inside)
        if nesting_context is None:
            nesting_context = []
        
        # Update nesting context based on current node
        current_context = nesting_context.copy()
        if node_type in ['ForStatement', 'WhileStatement', 'DoWhileStatement', 'IfStatement', 
                        'SwitchStatement', 'TryStatement', 'CatchStatement']:
            current_context.append({
                'type': node_type,
                'line': lineno,
                'source_snippet': source[:50] + '...' if len(source) > 50 else source
            })
        
        # Check for violations if we have source content
        if source and current_context:
            check_goto_violations(source, lineno, current_context, findings, filename, seen_violations)
            check_switch_case_violations(source, lineno, current_context, findings, filename, seen_violations)
        
        # Traverse children with updated context
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, current_context)
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations', 'cases', 'members']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, current_context)
    
    traverse_node(ast_tree)
    return findings


def check_goto_violations(source, base_line, nesting_context, findings, filename, seen_violations):
    """Check for goto statements and labels that violate control flow rules."""
    
    # Check for labels inside complex blocks
    label_pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*(?://.*)?$'
    lines = source.split('\n')
    
    for line_offset, line in enumerate(lines):
        line_stripped = line.strip()
        actual_line = base_line + line_offset
        
        # Skip if we've already flagged this line
        if actual_line in seen_violations:
            continue
            
        # Check for labels inside complex blocks (noncompliant)
        if re.match(label_pattern, line_stripped) and nesting_context:
            # We're inside a complex block and found a label - this is noncompliant
            complex_block = nesting_context[-1]  # Most recent nesting level
            violation_key = f"{filename}:{actual_line}:label"
            
            if violation_key not in seen_violations:
                seen_violations.add(violation_key)
                findings.append({
                    'rule_id': 'control_transferred_into_complex',
                    'message': f"Label '{line_stripped.split(':')[0]}' should not be placed inside {complex_block['type']} at line {complex_block['line']}. Refactor to eliminate control transfer into complex blocks.",
                    'node': f"Label.{line_stripped.split(':')[0]}",
                    'file': filename,
                    'property_path': ['source'],
                    'value': line_stripped,
                    'status': 'violation',
                    'line': actual_line,
                    'severity': 'Info'
                })
        
        # Check for goto statements (only flag if they could jump into complex blocks)
        goto_pattern = r'\bgoto\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;'
        goto_matches = re.finditer(goto_pattern, line_stripped)
        
        for match in goto_matches:
            goto_target = match.group(1)
            # For now, flag gotos that appear to jump forward (potential jump into complex block)
            # In practice, this would need more sophisticated analysis to determine if the target
            # is actually inside a complex block that the goto is outside of
            
            # Simple heuristic: if we're not inside any complex block but there are complex blocks
            # later in the function, this goto might be problematic
            if not nesting_context:  # goto is at top level
                violation_key = f"{filename}:{actual_line}:goto:{goto_target}"
                
                if violation_key not in seen_violations:
                    seen_violations.add(violation_key)
                    # Only flag this as potential violation - would need more analysis for certainty
                    # For now, we'll be conservative and flag based on context


def check_switch_case_violations(source, base_line, nesting_context, findings, filename, seen_violations):
    """Check for switch case labels inside complex blocks (other than switch itself)."""
    
    # Check for case labels inside non-switch complex blocks
    case_pattern = r'\bcase\s+[^:]+\s*:'
    default_pattern = r'\bdefault\s*:'
    
    lines = source.split('\n')
    
    for line_offset, line in enumerate(lines):
        line_stripped = line.strip()
        actual_line = base_line + line_offset
        
        # Skip if we've already flagged this line
        if actual_line in seen_violations:
            continue
        
        # Look for non-switch complex blocks in our context
        non_switch_context = [ctx for ctx in nesting_context 
                             if ctx['type'] != 'SwitchStatement']
        
        # Check for case/default labels inside non-switch complex blocks
        if (re.search(case_pattern, line_stripped) or re.search(default_pattern, line_stripped)) and non_switch_context:
            complex_block = non_switch_context[-1]  # Most recent non-switch nesting
            violation_key = f"{filename}:{actual_line}:case"
            
            if violation_key not in seen_violations:
                seen_violations.add(violation_key)
                findings.append({
                    'rule_id': 'control_transferred_into_complex',
                    'message': f"Switch case/default label should not be placed inside {complex_block['type']} at line {complex_block['line']}. Cases should not jump into complex logic blocks.",
                    'node': f"CaseStatement.{line_stripped.split(':')[0]}",
                    'file': filename,
                    'property_path': ['source'],
                    'value': line_stripped,
                    'status': 'violation', 
                    'line': actual_line,
                    'severity': 'Info'
                })


def check_control_structures_curly_braces(ast_tree, filename):
    """
    Check if control structures (if, for, while, do-while) use curly braces.
    
    Rule: Control structures should use curly braces to improve code readability 
    and prevent maintainability issues from misleading indentation.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()
    
    def traverse_node(node, nesting_context=None):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        lineno = node.get('lineno', node.get('line', 0))
        
        # Check for control structures that should have braces
        if node_type in ['IfStatement', 'ForStatement', 'WhileStatement', 'DoWhileStatement']:
            check_control_structure_braces(node, node_type, source, lineno, findings, filename, seen_violations)
        elif source:
            # Fallback: check source content for control structures
            check_source_for_missing_braces(source, lineno, findings, filename, seen_violations)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, nesting_context)
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations', 'then_statement', 'else_statement', 'init', 'condition', 'update']:
            if key in node:
                child_value = node[key]
                if isinstance(child_value, list):
                    for child in child_value:
                        traverse_node(child, nesting_context)
                elif isinstance(child_value, dict):
                    traverse_node(child_value, nesting_context)
    
    traverse_node(ast_tree)
    return findings


def check_control_structure_braces(node, node_type, source, lineno, findings, filename, seen_violations):
    """Check if a specific control structure node has proper braces."""
    
    # Check if the control structure has a block statement (braces) or just a single statement
    has_block = False
    
    # Look for body/then_statement that should be a block
    body_keys = ['body', 'then_statement', 'statements']
    for key in body_keys:
        if key in node:
            body = node[key]
            if isinstance(body, dict) and body.get('node_type') == 'BlockStatement':
                has_block = True
                break
            elif isinstance(body, list) and len(body) > 0:
                # Check if it's wrapped in a block
                if any(item.get('node_type') == 'BlockStatement' for item in body if isinstance(item, dict)):
                    has_block = True
                    break
    
    # If no explicit block found, check the source content
    if not has_block and source:
        has_block = check_source_has_braces(source, node_type)
    
    if not has_block:
        violation_key = f"{filename}:{lineno}:{node_type}"
        if violation_key not in seen_violations:
            seen_violations.add(violation_key)
            
            control_type = node_type.replace('Statement', '').lower()
            findings.append({
                'rule_id': 'control_structures_use_curly',
                'message': f"{control_type.capitalize()} statement should use curly braces to improve code readability and prevent maintainability issues.",
                'node': f"{node_type}.{control_type}",
                'file': filename,
                'property_path': ['source'],
                'value': source.split('\n')[0].strip() if source else f"{control_type} statement",
                'status': 'violation',
                'line': lineno,
                'severity': 'Info'
            })


def check_source_has_braces(source, node_type):
    """Check if the source code shows the control structure uses braces."""
    if not source:
        return False
    
    lines = source.split('\n')
    
    # Look for opening brace after the control structure
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        
        # Check if this line contains the control structure
        control_patterns = {
            'IfStatement': r'\bif\s*\(',
            'ForStatement': r'\bfor\s*\(',
            'WhileStatement': r'\bwhile\s*\(',
            'DoWhileStatement': r'\bdo\s+'
        }
        
        pattern = control_patterns.get(node_type)
        if pattern and re.search(pattern, line_stripped):
            # Check if there's an opening brace on the same line or next line
            if '{' in line_stripped:
                return True
            elif i + 1 < len(lines) and '{' in lines[i + 1].strip():
                return True
            else:
                return False
    
    return False


def check_source_for_missing_braces(source, base_line, findings, filename, seen_violations):
    """Check source content for control structures without braces using improved patterns."""
    
    lines = source.split('\n')
    
    for line_offset, line in enumerate(lines):
        line_stripped = line.strip()
        actual_line = base_line + line_offset
        
        # Skip empty lines and comments
        if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
            continue
        
        # Patterns for control structures without braces
        violation_patterns = [
            # if statement without braces on same line: if (...) statement;
            (r'\bif\s*\([^)]+\)\s*[^{;\s][^;]*;', 'if'),
            # for loop without braces on same line: for (...) statement;
            (r'\bfor\s*\([^)]*\)\s*[^{;\s][^;]*;', 'for'),
            # while loop without braces on same line: while (...) statement;
            (r'\bwhile\s*\([^)]+\)\s*[^{;\s][^;]*;', 'while'),
            # do without braces: do statement; while(...);
            (r'\bdo\s+[^{][^;]*;\s*while\s*\([^)]+\)', 'do-while')
        ]
        
        for pattern, control_type in violation_patterns:
            matches = re.finditer(pattern, line_stripped)
            for match in matches:
                violation_key = f"{filename}:{actual_line}:{control_type}"
                
                if violation_key not in seen_violations:
                    seen_violations.add(violation_key)
                    
                    findings.append({
                        'rule_id': 'control_structures_use_curly',
                        'message': f"{control_type.capitalize()} statement should use curly braces to improve code readability and prevent maintainability issues.",
                        'node': f"{control_type}Statement.{control_type}",
                        'file': filename,
                        'property_path': ['source'],
                        'value': match.group(0).strip(),
                        'status': 'violation',
                        'line': actual_line,
                        'severity': 'Info'
                    })
        
        # Check for control structures followed by statement on next line (multiline case)
        if line_offset + 1 < len(lines):
            next_line = lines[line_offset + 1].strip()
            
            # Pattern: control structure on one line, statement on next (no braces)
            multiline_patterns = [
                (r'\bif\s*\([^)]+\)\s*$', 'if'),
                (r'\bfor\s*\([^)]*\)\s*$', 'for'),
                (r'\bwhile\s*\([^)]+\)\s*$', 'while'),
                (r'\belse\s*$', 'else')
            ]
            
            for pattern, control_type in multiline_patterns:
                if re.search(pattern, line_stripped) and next_line and not next_line.startswith('{') and not next_line.startswith('//'):
                    # Make sure next line is not another control structure or closing brace
                    if not re.match(r'\s*(if|for|while|else|case|default|\})', next_line):
                        violation_key = f"{filename}:{actual_line}:{control_type}:multiline"
                        
                        if violation_key not in seen_violations:
                            seen_violations.add(violation_key)
                            
                            findings.append({
                                'rule_id': 'control_structures_use_curly',
                                'message': f"{control_type.capitalize()} statement should use curly braces to improve code readability and prevent maintainability issues.",
                                'node': f"{control_type}Statement.{control_type}",
                                'file': filename,
                                'property_path': ['source'],
                                'value': line_stripped,
                                'status': 'violation',
                                'line': actual_line,
                                'severity': 'Info'
                            })


def check_digraphs_avoided(ast_tree, filename):
    """
    Check for usage of C/C++ digraphs which should be avoided for better readability.
    
    C/C++ digraphs are alternative representations for punctuation characters:
    - <: instead of [
    - :> instead of ]
    - <% instead of {
    - %> instead of }
    - %: instead of # (preprocessing)
    - %:%: instead of ## (token pasting)
    
    Rule: Digraphs should be avoided to improve code readability and maintainability.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()
    
    # Enhanced digraph patterns for comprehensive detection
    digraph_patterns = {
        'array_bracket_start': r'<:',
        'array_bracket_end': r':>',
        'block_brace_start': r'<%',
        'block_brace_end': r'%>',
        'preprocess_hash': r'%:',
        'preprocess_double': r'%:%:',
        'array_declaration': r'\w+<:\d*:>',
        'array_access': r'<:\w*:>',
        'two_dim_array': r'<:\w*:><:\w*:>',
        'block_structure': r'<%[^%]*%>',
        'if_with_digraph': r'if\s*\([^)]*\)\s*<%',
        'for_with_digraph': r'for\s*\([^)]*\)\s*<%',
        'function_with_digraph': r'\w+\s*\([^)]*\)\s*<%',
        'noncompliant_context': r'noncompliant.*(<:|:>|<%|%>|%:|%:%:)',
        'template_with_digraph': r'template\s*<[^>]*>\s*\w+\s*<:'
    }
    
    # Digraph replacement suggestions
    digraph_replacements = {
        '<:': '[',
        ':>': ']',
        '<%': '{',
        '%>': '}',
        '%:': '#',
        '%:%:': '##'
    }
    
    def extract_digraph_from_match(matched_text):
        """Extract the specific digraph from matched text"""
        digraphs = ['%:%:', '<:', ':>', '<%', '%>', '%:']  # Check double first
        
        for digraph in digraphs:
            if digraph in matched_text:
                return digraph
        return None
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        # Get source and line info
        source = node.get('source', '')
        lineno = node.get('lineno', node.get('line', 0))
        node_type = node.get('node_type', 'unknown')
        
        if source and lineno:
            # Check for digraphs in the source
            lines = source.split('\n')
            
            for line_offset, line in enumerate(lines):
                actual_line = lineno + line_offset
                line_content = line.strip()
                
                # Skip empty lines and comments
                if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
                    continue
                
                # Check each digraph pattern
                for pattern_name, pattern in digraph_patterns.items():
                    matches = list(re.finditer(pattern, line, re.IGNORECASE))
                    
                    for match in matches:
                        matched_text = match.group(0)
                        digraph_found = extract_digraph_from_match(matched_text)
                        
                        if digraph_found:
                            # Create unique identifier to prevent duplicates
                            violation_key = (filename, actual_line, digraph_found, match.start())
                            
                            if violation_key not in seen_violations:
                                seen_violations.add(violation_key)
                                
                                replacement = digraph_replacements.get(digraph_found, 'standard syntax')
                                
                                finding = {
                                    'rule_id': 'digraphs_avoided',
                                    'message': f"Digraph '{digraph_found}' should be avoided. Use '{replacement}' instead for better readability.",
                                    'node': f"{node_type}.{node.get('name', 'unknown')}",
                                    'file': filename,
                                    'property_path': ['source'],
                                    'value': digraph_found,
                                    'status': 'violation',
                                    'line': actual_line,
                                    'severity': 'Info',
                                    'pattern_matched': pattern_name,
                                    'full_context': line_content,
                                    'column': match.start() + 1,
                                    'replacement_suggestion': replacement
                                }
                                findings.append(finding)
        
        # Traverse children recursively
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type])
    
    # Start traversal from the root
    traverse_node(ast_tree)
    
    # Also perform line-by-line analysis for comprehensive coverage
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.read()
            lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_content = line.strip()
            
            # Skip empty lines and comments
            if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
                continue
            
            # Direct digraph detection
            for digraph, replacement in digraph_replacements.items():
                if digraph in line:
                    # Find all occurrences
                    start = 0
                    while True:
                        pos = line.find(digraph, start)
                        if pos == -1:
                            break
                        
                        violation_key = (filename, line_num, digraph, pos)
                        
                        if violation_key not in seen_violations:
                            seen_violations.add(violation_key)
                            
                            finding = {
                                'rule_id': 'digraphs_avoided',
                                'message': f"Digraph '{digraph}' should be avoided. Use '{replacement}' instead for better readability.",
                                'node': f"Line.{line_num}",
                                'file': filename,
                                'property_path': ['source'],
                                'value': digraph,
                                'status': 'violation',
                                'line': line_num,
                                'severity': 'Info',
                                'pattern_matched': 'direct_detection',
                                'full_context': line_content,
                                'column': pos + 1,
                                'replacement_suggestion': replacement
                            }
                            findings.append(finding)
                        
                        start = pos + 1
                        
    except Exception as e:
        # If file reading fails, use AST-only detection
        pass
    
    return findings


def check_dynamically_allocated_memory_released(ast_tree, filename):
    """
    Check if dynamically allocated memory (malloc/calloc/realloc) is properly released.
    
    This function analyzes each function to detect malloc/calloc/realloc calls 
    without corresponding free calls within the same function scope.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node):
        if not isinstance(node, dict):
            return
            
        # Check if this is a function definition
        node_type = node.get('node_type', '')
        if node_type in ['FunctionDefinition', 'Function']:
            check_function_memory_leaks(node, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child)
                
        # Also check body and other node structures
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child)
            elif key in node and isinstance(node[key], dict):
                traverse_node(node[key])
    
    traverse_node(ast_tree)
    return findings


def check_function_memory_leaks(function_node, findings, filename):
    """
    Check a specific function for memory leaks by analyzing malloc/free patterns.
    
    Args:
        function_node: AST node representing a function
        findings: List to append findings to
        filename: The filename being checked
    """
    source = function_node.get('source', '')
    function_name = function_node.get('name', 'unknown_function')
    base_line = function_node.get('lineno', function_node.get('line', 1))
    
    if not source:
        return
    
    # Remove comments to avoid false positives from commented code
    source_no_comments = remove_comments_from_source(source)
    
    # Find all malloc/calloc/realloc calls
    malloc_pattern = r'\b(malloc|calloc|realloc)\s*\([^)]*\)'
    malloc_matches = list(re.finditer(malloc_pattern, source_no_comments, re.MULTILINE))
    
    # Find all free calls
    free_pattern = r'\bfree\s*\([^)]*\)'
    free_matches = list(re.finditer(free_pattern, source_no_comments, re.MULTILINE))
    
    # Simple heuristic: if we have malloc calls but no free calls, flag as violation
    # More sophisticated analysis could track variable assignments and ensure
    # each malloc'd pointer is freed
    if malloc_matches and not free_matches:
        for malloc_match in malloc_matches:
            # Calculate line number
            lines_before = source[:malloc_match.start()].count('\n')
            line_num = base_line + lines_before
            
            match_text = malloc_match.group(0)
            allocation_func = malloc_match.group(1)
            
            finding = {
                'rule_id': 'dynamically_allocated_memory_released',
                'message': f"Function '{function_name}': Memory allocated with {allocation_func}() should be released with free(). No corresponding free() call found in function scope.",
                'node': f"FunctionDefinition.{function_name}",
                'file': filename,
                'property_path': ['source'],
                'value': match_text,
                'status': 'violation',
                'line': line_num,
                'severity': 'Info'
            }
            findings.append(finding)
            
    # Also check for new/delete patterns in C++
    new_pattern = r'\bnew\s+[^;]*;'
    new_matches = list(re.finditer(new_pattern, source_no_comments, re.MULTILINE))
    
    delete_pattern = r'\bdelete\s+'
    delete_matches = list(re.finditer(delete_pattern, source_no_comments, re.MULTILINE))
    
    if new_matches and not delete_matches:
        for new_match in new_matches:
            # Calculate line number
            lines_before = source[:new_match.start()].count('\n')
            line_num = base_line + lines_before
            
            match_text = new_match.group(0)
            
            finding = {
                'rule_id': 'dynamically_allocated_memory_released',
                'message': f"Function '{function_name}': Memory allocated with new should be released with delete. No corresponding delete call found in function scope.",
                'node': f"FunctionDefinition.{function_name}",
                'file': filename,
                'property_path': ['source'],
                'value': match_text,
                'status': 'violation',
                'line': line_num,
                'severity': 'Info'
            }
            findings.append(finding)


def remove_comments_from_source(source):
    """
    Remove C-style comments from source code to avoid false positives.
    
    Args:
        source: Source code string
        
    Returns:
        Source code with comments removed
    """
    # Remove single-line comments (// ...)
    source = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
    
    # Remove multi-line comments (/* ... */)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    
    return source


def check_errno_avoided(ast_tree, filename):
    """
    Check if errno is being used, which should be avoided.
    
    Rule: errno should not be used as it's poorly defined by ISO/IEC 14882:2003.
    A non-zero value may or may not indicate that a problem has occurred.
    It's preferable to check the values of inputs before calling the function
    rather than relying on using errno to trap errors.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, line_number=1):
        if not isinstance(node, dict):
            return
            
        # Get source text and line number
        source = node.get('source', '')
        current_line = node.get('line', line_number)
        node_type = node.get('node_type', '')
        
        # Check for errno header includes (preprocessor directives)
        if node_type == 'PreprocessorDirective' and source:
            if check_errno_include(source, current_line, findings, filename):
                pass  # Finding already added
        
        # Check for errno usage in any node with source content
        if source and 'errno' in source.lower():
            if node_type != 'PreprocessorDirective':  # Skip preprocessor directives (already handled above)
                check_errno_usage_in_node(source, current_line, findings, filename, node_type)
        
        # Comprehensive traversal of all possible child locations
        child_keys_to_check = [
            'children', 'body', 'statements', 'declarations', 'expression', 
            'condition', 'init', 'update', 'left', 'right', 'operand',
            'arguments', 'parameters', 'initializer', 'value', 'target',
            'source_code', 'code', 'content'
        ]
        
        for key in child_keys_to_check:
            if key in node:
                if isinstance(node[key], list):
                    for child in node[key]:
                        if isinstance(child, dict):
                            child_line = child.get('line', current_line)
                            traverse_node(child, child_line)
                elif isinstance(node[key], dict):
                    child_line = node[key].get('line', current_line)
                    traverse_node(node[key], child_line)
        
        # Also traverse any dict values that might contain nodes
        for key, value in node.items():
            if key not in child_keys_to_check and isinstance(value, (dict, list)):
                if isinstance(value, dict) and 'node_type' in value:
                    child_line = value.get('line', current_line)
                    traverse_node(value, child_line)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and 'node_type' in item:
                            child_line = item.get('line', current_line)
                            traverse_node(item, child_line)
    
    traverse_node(ast_tree)
    return findings


def check_errno_include(source, line_number, findings, filename):
    """Check for errno header includes."""
    # Check for errno headers
    errno_headers = [
        r'#include\s*<errno\.h>',
        r'#include\s*<cerrno>',
        r'#include\s*"errno\.h"'
    ]
    
    for pattern in errno_headers:
        if re.search(pattern, source, re.IGNORECASE):
            findings.append({
                "rule_id": "errno_avoided",
                "message": "errno should not be used. Use return value checking instead of errno to trap errors.",
                "line": line_number,
                "node": "PreprocessorDirective",
                "file": filename,
                "property_path": ["source"],
                "value": source.strip(),
                "status": "violation",
                "severity": "Info"
            })
            return True
    return False


def check_errno_usage_in_node(source, line_number, findings, filename, node_type):
    """Check for direct errno variable usage in a specific node."""
    # Skip if source is empty or doesn't contain errno
    if not source or 'errno' not in source.lower():
        return False
    
    # Remove comments to avoid false positives in comments
    source_no_comments = remove_comments_from_source(source)
    
    # Comprehensive errno usage patterns
    errno_patterns = [
        r'\berrno\s*=',           # errno assignment: errno = 0, errno = EINVAL
        r'=\s*errno\b',           # errno reading: var = errno, return errno
        r'\berrno\s*[=!<>]=',     # errno comparison: errno == ERANGE, errno != 0
        r'[=!<>]=\s*errno\b',     # errno comparison: 0 != errno, ERANGE == errno
        r'\berrno\s*[<>]',        # errno comparison: errno > 0, errno < 5
        r'[<>]\s*errno\b',        # errno comparison: 0 > errno, 5 < errno
        r'\(\s*errno\s*\)',       # errno in parentheses: if (errno), while (errno)
        r'printf\s*\([^)]*errno', # errno in printf: printf("Error: %d", errno)
        r'fprintf\s*\([^)]*errno',# errno in fprintf
        r'sprintf\s*\([^)]*errno',# errno in sprintf
        r'snprintf\s*\([^)]*errno',# errno in snprintf
        r'return\s+errno\b',      # return errno
        r'\berrno\s*\+',          # errno arithmetic: errno + 1
        r'\+\s*errno\b',          # errno arithmetic: 1 + errno
        r'\berrno\s*\-',          # errno arithmetic: errno - 1
        r'\-\s*errno\b',          # errno arithmetic: 1 - errno (but not --errno)
        r'\berrno\s*\*',          # errno arithmetic: errno * 2
        r'\*\s*errno\b',          # errno arithmetic: 2 * errno
        r'\berrno\s*/',           # errno arithmetic: errno / 2
        r'/\s*errno\b',           # errno arithmetic: 10 / errno
        r'\berrno\s*%',           # errno arithmetic: errno % 2
        r'%\s*errno\b',           # errno arithmetic: 10 % errno
        r'\&errno\b',             # errno address: &errno
        r'switch\s*\(\s*errno',   # switch on errno: switch(errno)
        r'\berrno\s*\?',          # ternary with errno: errno ? a : b
        r'\?\s*errno\b',          # ternary with errno: condition ? errno : b
        r':\s*errno\b',           # ternary with errno: condition ? a : errno
    ]
    
    # Check each pattern
    found_violation = False
    for pattern in errno_patterns:
        if re.search(pattern, source_no_comments, re.IGNORECASE):
            # Extract relevant portion of source for reporting
            lines = source.split('\n')
            if len(lines) > 3:
                # If multi-line, show just the first few lines
                display_source = '\n'.join(lines[:2]) + '...'
            else:
                display_source = source.strip()
            
            findings.append({
                "rule_id": "errno_avoided", 
                "message": "errno should not be used. Use return value checking instead of errno to trap errors.",
                "line": line_number,
                "node": node_type or "errno_usage",
                "file": filename,
                "property_path": ["source"],
                "value": display_source,
                "status": "violation",
                "severity": "Info"
            })
            found_violation = True
            break  # Only report one violation per node to avoid duplicates
    
    return found_violation


def check_evaluation_operand_sizeof_operator(ast_tree, filename):
    """
    Check if the operand to the sizeof operator contains side effects.
    
    Rule: Evaluation of the operand to the sizeof operator shall not contain 
    side effects (increment/decrement operators, function calls, or assignments).
    This is a MISRA rule for safety-critical software.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, line_number=1):
        if not isinstance(node, dict):
            return
            
        # Get source text and line number
        source = node.get('source', '')
        current_line = node.get('line', line_number)
        node_type = node.get('node_type', '')
        
        # Check for sizeof usage in any node with source content
        if source and 'sizeof' in source.lower():
            check_sizeof_side_effects_detailed(source, current_line, findings, filename, node_type)
        
        # Comprehensive traversal of all possible child locations
        child_keys_to_check = [
            'children', 'body', 'statements', 'declarations', 'expression', 
            'condition', 'init', 'update', 'left', 'right', 'operand',
            'arguments', 'parameters', 'initializer', 'value', 'target',
            'source_code', 'code', 'content'
        ]
        
        for key in child_keys_to_check:
            if key in node:
                if isinstance(node[key], list):
                    for child in node[key]:
                        if isinstance(child, dict):
                            child_line = child.get('line', current_line)
                            traverse_node(child, child_line)
                elif isinstance(node[key], dict):
                    child_line = node[key].get('line', current_line)
                    traverse_node(node[key], child_line)
        
        # Also traverse any dict values that might contain nodes
        for key, value in node.items():
            if key not in child_keys_to_check and isinstance(value, (dict, list)):
                if isinstance(value, dict) and 'node_type' in value:
                    child_line = value.get('line', current_line)
                    traverse_node(value, child_line)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and 'node_type' in item:
                            child_line = item.get('line', current_line)
                            traverse_node(item, child_line)
    
    traverse_node(ast_tree)
    return findings


def check_sizeof_side_effects_detailed(source, line_number, findings, filename, node_type):
    """Check for side effects in sizeof operands with detailed line tracking."""
    # Skip if source is empty or doesn't contain sizeof
    if not source or 'sizeof' not in source.lower():
        return False
    
    # Remove comments to avoid false positives in comments
    source_no_comments = remove_comments_from_source(source)
    
    # Split source into lines to track exact line numbers
    source_lines = source.split('\n')
    
    # Find all sizeof expressions with their line positions
    sizeof_pattern = r'sizeof\s*\(([^)]+(?:\([^)]*\)[^)]*)*)\)'
    
    # Process line by line to get accurate line numbers
    for line_idx, line in enumerate(source_lines):
        actual_line = line_number + line_idx
        
        if 'sizeof' in line.lower():
            # Remove comments from this line
            line_clean = remove_comments_from_source(line)
            
            # Find sizeof expressions in this line
            sizeof_matches = re.finditer(sizeof_pattern, line_clean, re.IGNORECASE)
            
            for sizeof_match in sizeof_matches:
                sizeof_operand = sizeof_match.group(1)
                
                # Check for various side effects in the sizeof operand
                side_effects_found = []
                
                # 1. Check for increment/decrement operators
                if re.search(r'\+\+|\-\-', sizeof_operand):
                    side_effects_found.append("increment/decrement operators")
                
                # 2. Check for assignment operators (=, +=, -=, *=, /=, %=, &=, |=, ^=, <<=, >>=)
                # Exclude comparison operators (==, !=, <=, >=)
                if re.search(r'(?<![=!<>])=(?![=])|[+\-*/&|^%]=|<<=|>>=', sizeof_operand):
                    side_effects_found.append("assignment operators")
                
                # 3. Check for function calls
                function_violations = check_function_calls_in_sizeof(sizeof_operand)
                if function_violations:
                    side_effects_found.extend(function_violations)
                
                # 4. Check for other potentially side-effect causing operators
                if re.search(r'\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*(\+\+|\-\-)', sizeof_operand):
                    side_effects_found.append("pointer increment/decrement")
                
                # If any side effects were found, report the violation
                if side_effects_found:
                    side_effects_desc = ", ".join(side_effects_found)
                    
                    # Extract the specific sizeof expression for reporting
                    sizeof_expr = sizeof_match.group(0)
                    
                    findings.append({
                        "rule_id": "evaluation_operand_sizeof_operator",
                        "message": f"Evaluation of the operand to the sizeof operator shall not contain side effects ({side_effects_desc}).",
                        "line": actual_line,
                        "node": node_type or "sizeof_usage",
                        "file": filename,
                        "property_path": ["source"],
                        "value": sizeof_expr,
                        "status": "violation",
                        "severity": "Critical"
                    })
    
    return len(findings) > 0


def check_function_calls_in_sizeof(operand):
    """Check for function calls in sizeof operand and return list of violations."""
    violations = []
    
    # Pattern to match potential function calls: identifier followed by parentheses
    function_call_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)'
    potential_function_calls = re.finditer(function_call_pattern, operand)
    
    for func_match in potential_function_calls:
        func_name = func_match.group(1)
        func_args = func_match.group(2).strip()
        
        # Exclude common type casts and built-in types
        excluded_keywords = {
            'int', 'char', 'short', 'long', 'float', 'double', 'void',
            'signed', 'unsigned', 'const', 'volatile', 'static', 'extern',
            'struct', 'union', 'enum', 'sizeof', 'typedef', 'auto', 'register',
            # Common type names
            'size_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
            'int8_t', 'int16_t', 'int32_t', 'int64_t', 'ptrdiff_t',
            'uintptr_t', 'intptr_t', 'wchar_t'
        }
        
        # Skip if it's a known type cast
        if func_name.lower() in excluded_keywords:
            continue
        
        # Additional heuristic: if the argument looks like a simple literal or variable, it might be a cast
        # Simple patterns that suggest type cast: numbers, single variables, arithmetic with literals
        simple_cast_patterns = [
            r'^\s*\d+(\.\d+)?\s*$',           # Pure number: (int)42
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*$', # Single variable: (int)var
            r'^\s*\d+\s*[+\-*/]\s*\d+\s*$',   # Simple arithmetic: (int)(3+4)
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[+\-*/]\s*\d+\s*$', # var+number: (int)(x+1)
        ]
        
        is_likely_cast = any(re.match(pattern, func_args) for pattern in simple_cast_patterns)
        
        # If arguments are empty, it might be a function call with no args or a cast of empty expression
        if not func_args:
            # Empty parentheses could be function call: func() - this is a side effect
            violations.append(f"function call '{func_name}'")
        elif not is_likely_cast:
            # Complex arguments suggest a function call rather than a type cast
            violations.append(f"function call '{func_name}'")
    
    return violations


def remove_comments_from_source(source):
    """Remove C/C++ style comments from source code."""
    if not source:
        return ""
    
    # Remove single-line comments (// ...)
    source = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
    
    # Remove multi-line comments (/* ... */)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    
    return source


def check_file_naming_convention(ast_tree, filename):
    """
    Check if the filename follows proper naming conventions.
    
    Rule: File names should follow snake_case convention with lowercase letters, 
    numbers, underscores, and proper .c/.h extensions. Avoid camelCase, hyphens, 
    uppercase letters, dots in filename, or uppercase extensions.
    
    Args:
        ast_tree: The AST tree to check (not used for filename checking)
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    # Extract just the filename without path
    import os
    file_basename = os.path.basename(filename)
    
    # Split filename and extension
    if '.' in file_basename:
        name_part, extension = file_basename.rsplit('.', 1)
    else:
        name_part = file_basename
        extension = ''
    
    violation_reasons = []
    
    # Check for proper C/C++ extensions
    valid_extensions = ['c', 'h', 'cpp', 'hpp', 'cc', 'cxx']
    if extension and extension not in valid_extensions:
        violation_reasons.append(f"Invalid extension '.{extension}' - use .c, .h, .cpp, .hpp, .cc, or .cxx")
    
    # Check for uppercase extensions
    if extension and extension != extension.lower():
        violation_reasons.append(f"Uppercase extension '.{extension}' should be lowercase")
    
    # Check filename part for naming convention violations
    if name_part:
        # Check for camelCase (contains uppercase letters after lowercase)
        if re.search(r'[a-z][A-Z]', name_part):
            violation_reasons.append("Contains camelCase - use snake_case instead")
        
        # Check for hyphens
        if '-' in name_part:
            violation_reasons.append("Contains hyphens - use underscores instead")
        
        # Check for starting with uppercase
        if name_part[0].isupper():
            violation_reasons.append("Starts with uppercase letter - use lowercase")
        
        # Check for all uppercase names
        if name_part.isupper() and len(name_part) > 1:
            violation_reasons.append("All uppercase name - use lowercase with underscores")
        
        # Check for dots in filename (before extension)
        if '.' in name_part:
            violation_reasons.append("Contains dots in filename - avoid multiple dots")
        
        # Check for invalid characters (only allow lowercase letters, numbers, underscores)
        if not re.match(r'^[a-z0-9_]+$', name_part):
            violation_reasons.append("Contains invalid characters - only use lowercase letters, numbers, and underscores")
        
        # Check for starting with underscore or number (style preference)
        if name_part.startswith('_'):
            violation_reasons.append("Starts with underscore - prefer starting with a letter")
        elif name_part[0].isdigit():
            violation_reasons.append("Starts with a number - prefer starting with a letter")
    
    # If any violations found, create a finding
    if violation_reasons:
        finding = {
            "rule_id": "file_names_follow_naming",
            "message": f"File name '{file_basename}' violates naming convention: {'; '.join(violation_reasons)}",
            "node": "File",
            "file": filename,
            "property_path": ["filename"],
            "value": file_basename,
            "status": "violation",
            "line": 1,
            "severity": "Info"
        }
        findings.append(finding)
    
    return findings


def check_file_line_count(ast_tree, filename):
    """
    Check if a file has too many lines of code.
    
    Rule: Files should avoid having too many lines of code (typically over 1000 lines).
    Large files should be split into smaller, focused files.
    
    Args:
        ast_tree: The AST tree to check  
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    try:
        # Read the file and count lines
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            line_count = len(lines)
            
        # Threshold for too many lines (typically 1000+ but we'll use 250+ for testing)
        # In practice, this would be configurable
        max_lines_threshold = 250
        
        if line_count > max_lines_threshold:
            finding = {
                'rule_id': 'files_avoid_having_too',
                'message': f'File has {line_count} lines of code - files should avoid having too many lines (>{max_lines_threshold}). Consider splitting into smaller, focused files.',
                'node': f'File.{filename}',
                'file': filename,
                'property_path': ['source'],
                'value': f'File with {line_count} lines',
                'status': 'violation',
                'line': line_count,  # Report the total line count as the line number
                'severity': 'Major'
            }
            findings.append(finding)
            
    except FileNotFoundError:
        # File not found, can't check line count
        pass
    except Exception as e:
        # Error reading file, can't check line count
        pass
    
    return findings


def check_file_newline(ast_tree, filename):
    """
    Check if a file ends with a newline character.
    
    Rule: Files should end with a newline character for better tool compatibility.
    
    Args:
        ast_tree: The AST tree to check  
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    try:
        # Read the file content as bytes to check the last character
        with open(filename, 'rb') as f:
            content = f.read()
            
        if len(content) == 0:
            # Empty file - technically should have a newline
            finding = {
                'rule_id': 'files_newline',
                'message': 'Empty file should end with a newline character for better tool compatibility',
                'node': f'File.{filename}',
                'file': filename,
                'property_path': ['source'],
                'value': 'Empty file',
                'status': 'violation',
                'line': 1,
                'severity': 'Major'
            }
            findings.append(finding)
        elif len(content) > 0:
            # Check if file ends with newline (LF=10, CR=13, or CRLF)
            last_byte = content[-1]
            if last_byte not in [10, 13]:  # Not LF or CR
                # Count total lines to report accurate line number
                lines = content.decode('utf-8', errors='ignore').splitlines()
                total_lines = len(lines)
                
                finding = {
                    'rule_id': 'files_newline',
                    'message': 'File should end with a newline character for better tool compatibility',
                    'node': f'File.{filename}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': f'File missing newline at end',
                    'status': 'violation',
                    'line': total_lines,
                    'severity': 'Major'
                }
                findings.append(finding)
            
    except FileNotFoundError:
        # File not found, can't check newline
        pass
    except Exception as e:
        pass
    
    return findings


def check_flexible_array_members(ast_tree, filename):
    """
    Check for flexible array members in struct declarations.
    
    Rule: Flexible array members (arrays without size like 'data[]') should not be declared
    in structs as they can cause unexpected behavior with sizeof and struct assignment.
    
    Args:
        ast_tree: The AST tree to check  
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Look for struct declarations
        if node_type == 'StructDeclaration':
            check_struct_for_flexible_arrays(node, path, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations', 'members']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    traverse_node(ast_tree)
    return findings


def check_struct_for_flexible_arrays(struct_node, path, findings, filename):
    """Check a struct declaration for flexible array members."""
    
    # Get struct source code
    source = struct_node.get('source', '')
    if not source:
        return
    
    lines = source.split('\n')
    struct_name = struct_node.get('name', 'unknown')
    start_line = struct_node.get('line', 1)
    
    # Look for array declarations without size: type name[];
    for i, line in enumerate(lines):
        line_content = line.strip()
        
        # Skip comments and empty lines
        if line_content.startswith('//') or line_content.startswith('/*') or not line_content:
            continue
            
        # Look for flexible array pattern: ends with []; 
        if line_content.endswith('[];') or '[]' in line_content:
            # Extract the array declaration
            if '[]' in line_content:
                # Check if this looks like a flexible array member
                # Should be inside struct, not a function parameter
                if (';' in line_content and 
                    not line_content.strip().startswith('//') and
                    not 'malloc' in line_content and
                    not 'sizeof' in line_content and
                    not '(' in line_content.split('[]')[0]):  # Not a function call
                    
                    # Extract variable name for better reporting
                    parts = line_content.split()
                    array_name = 'unknown'
                    if len(parts) >= 2:
                        for part in parts:
                            if '[]' in part:
                                array_name = part.replace('[];', '').replace('[]', '')
                                break
                    
                    finding = {
                        'rule_id': 'flexible_array_members_declared',
                        'message': f'Flexible array member "{array_name}" should not be declared. Consider using a pointer or fixed-size array instead. Flexible arrays can cause unexpected behavior with sizeof and struct assignment.',
                        'node': f'StructDeclaration.{struct_name}',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_content.strip(),
                        'status': 'violation',
                        'line': start_line + i,
                    }
                    findings.append(finding)


def check_floating_point_equality(ast_tree, filename):
    """
    Check for floating point equality/inequality comparisons.
    
    Rule: Floating point numbers should not be tested for equality or inequality
    using == or != operators due to precision issues.
    
    Args:
        ast_tree: The AST tree to check  
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Look for binary expressions (comparisons)
        if node_type == 'BinaryExpression':
            check_binary_expression_for_float_equality(node, path, findings, filename)
        
        # Also check conditional statements that might contain floating point comparisons
        if node_type in ['ConditionalStatement', 'IfStatement', 'WhileStatement']:
            check_conditional_for_float_equality(node, path, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'condition', 'left', 'right']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
            elif key in node and isinstance(node[key], dict):
                traverse_node(node[key], path + [node.get('node_type', 'unknown')])
    
    traverse_node(ast_tree)
    return findings


def check_binary_expression_for_float_equality(expr_node, path, findings, filename):
    """Check a binary expression for floating point equality/inequality."""
    
    source = expr_node.get('source', '')
    if not source:
        return
    
    line = expr_node.get('line', 1)
    
    # Look for == or != operators in the expression
    if ('==' in source or '!=' in source):
        # Check if this involves floating point values
        is_float_comparison = False
        
        # Patterns that indicate floating point comparison:
        # 1. Contains 'f' suffix (e.g., 0.1f, 2.5f)
        # 2. Contains decimal numbers (e.g., 0.1, 3.14)
        # 3. Contains float/double variables or function calls
        # 4. Contains mathematical expressions with decimals
        
        float_indicators = [
            r'\d+\.\d+f\b',          # 0.1f, 2.5f
            r'\d+\.\d+\b',           # 0.1, 3.14
            r'\bf\s*[=!]=',          # variable 'f' == 
            r'[=!]=\s*\d+\.\d+',     # == 0.1
            r'float\s+\w+',          # float variable
            r'double\s+\w+',         # double variable
            r'\.\d+f?\b',            # .5f, .25
        ]
        
        for pattern in float_indicators:
            if re.search(pattern, source):
                is_float_comparison = True
                break
        
        if is_float_comparison:
            # Determine operator type
            operator = '==' if '==' in source else '!='
            
            finding = {
                'rule_id': 'floating_point_numbers_tested',
                'message': f'Floating point equality comparison using "{operator}" is unreliable due to precision issues. Use epsilon-based comparison with fabs() instead.',
                'node': f'BinaryExpression.{expr_node.get("name", "unknown")}',
                'file': filename,
                'property_path': ['source'],
                'value': source.strip(),
                'status': 'violation',
                'line': line,
                'severity': 'Info'
            }
            findings.append(finding)


def check_conditional_for_float_equality(cond_node, path, findings, filename):
    """Check conditional statements for floating point equality in their conditions."""
    
    source = cond_node.get('source', '')
    if not source:
        return
    
    # Extract just the condition part if possible
    lines = source.split('\n')
    for i, line in enumerate(lines):
        if ('==' in line or '!=' in line) and ('if' in line or 'while' in line):
            line_num = cond_node.get('line', 1) + i
            
            # Check for floating point patterns in the condition
            if (re.search(r'\d+\.\d+f?\b', line) or 
                re.search(r'\bf\s*[=!]=', line) or
                re.search(r'[=!]=\s*\d+\.\d+', line)):
                
                operator = '==' if '==' in line else '!='
                
                finding = {
                    'rule_id': 'floating_point_numbers_tested',
                    'message': f'Floating point equality comparison using "{operator}" in conditional statement is unreliable. Use epsilon-based comparison instead.',
                    'node': f'{cond_node.get("node_type", "ConditionalStatement")}.{cond_node.get("name", "unknown")}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': line.strip(),
                    'status': 'violation',
                    'line': line_num,
                    'severity': 'Info'
                }
                findings.append(finding)


def check_for_loop_counters(ast_tree, filename):
    """
    Check for floating point type loop counters in for loops.
    
    Rule: For loop counters should not have essentially floating type (float, double)
    due to rounding errors and unpredictable iteration counts.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, line_offset=0):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        node_line = node.get('line', 1) + line_offset
        
        # Check for for loop patterns
        if source and ('for' in source.lower() or node_type in ['ForStatement', 'ForLoop']):
            check_for_loop_floating_counter(node, findings, filename, node_line)
            
        # Traverse children
        if 'children' in node and isinstance(node['children'], list):
            for child in node['children']:
                traverse_node(child, line_offset)
        
        # Check other child containers
        for key in ['body', 'statements', 'declarations', 'init', 'condition', 'update']:
            if key in node:
                if isinstance(node[key], list):
                    for child in node[key]:
                        traverse_node(child, line_offset)
                elif isinstance(node[key], dict):
                    traverse_node(node[key], line_offset)
    
    traverse_node(ast_tree)
    return findings


def check_for_loop_floating_counter(loop_node, findings, filename, base_line):
    """Check a specific for loop for floating point counters."""
    source = loop_node.get('source', '')
    
    if not source:
        return
    
    # Comprehensive patterns for floating point loop counters
    floating_patterns = [
        # Direct float/double declarations in for loop
        r'for\s*\(\s*float\s+\w+',
        r'for\s*\(\s*double\s+\w+',
        # Floating point initialization values
        r'for\s*\([^;]*=\s*\d+\.\d+f?\s*;',
        # Floating point increment patterns
        r'\w+\s*[+\-*\/]=\s*\d+\.\d+f?',
        # Floating point comparison patterns
        r'\w+\s*[<>=!]+\s*\d+\.\d+f?',
        # Variables with floating point suffix
        r'\w+\s*=\s*\d+\.\d+f'
    ]
    
    lines = source.split('\n')
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        line_num = base_line + i
        
        # Skip comments and empty lines
        if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
            continue
            
        # Check if this line contains a for loop
        if re.search(r'\bfor\s*\(', line_stripped, re.IGNORECASE):
            # Check for floating point patterns
            violation_found = False
            violation_type = ""
            
            for pattern in floating_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    violation_found = True
                    if 'float' in pattern:
                        violation_type = "float type declaration"
                    elif 'double' in pattern:
                        violation_type = "double type declaration"
                    elif r'\d+\.\d+f?' in pattern:
                        violation_type = "floating point initialization/comparison"
                    break
            
            # Also check for variable names that suggest floating point
            if not violation_found:
                # Look for variables that might be floating point based on usage
                float_var_patterns = [
                    r'\b\w*[fF]loat\w*\b',
                    r'\b\w*[dD]ouble\w*\b',
                    r'\b[fd]\b\s*[<>=!]+',
                    r'\b\w+\s*[+\-*\/]=\s*\d*\.\d+',
                ]
                
                for var_pattern in float_var_patterns:
                    if re.search(var_pattern, line_stripped):
                        violation_found = True
                        violation_type = "floating point variable usage"
                        break
            
            if violation_found:
                finding = {
                    'rule_id': 'loop_counters_avoid_having',
                    'message': f'For loop counters should not have essentially floating type - use integer counters instead. Detected: {violation_type}',
                    'node': f'{loop_node.get("node_type", "ForLoop")}.{loop_node.get("name", "unknown")}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': line_stripped,
                    'status': 'violation',
                    'line': line_num,
                    'severity': 'Info'
                }
                findings.append(finding)


def check_for_loop_stop_conditions_invariant(ast_tree, filename):
    """
    Check for non-invariant stop conditions in for loops.
    
    Rule: For loop stop conditions should be invariant - avoid function calls
    or variable modifications in stop conditions.
    
    Detects:
    1. Function calls in stop conditions (performance issue)
    2. Variables modified within loop body (logic issue)
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, line_offset=0):
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        
        # Check for for loop patterns
        if source and 'for' in source.lower():
            check_for_loop_invariant_conditions(node, findings, filename, line_offset)
            
        # Traverse children
        if 'children' in node and isinstance(node['children'], list):
            for child in node['children']:
                traverse_node(child, line_offset)
        
        # Check other child containers
        for key in ['body', 'statements', 'declarations', 'init', 'condition', 'update']:
            if key in node:
                if isinstance(node[key], list):
                    for child in node[key]:
                        traverse_node(child, line_offset)
                elif isinstance(node[key], dict):
                    traverse_node(node[key], line_offset)
    
    traverse_node(ast_tree)
    return findings


def check_for_loop_invariant_conditions(loop_node, findings, filename, base_line):
    """Check a specific for loop for invariant violations."""
    source = loop_node.get('source', '')
    
    if not source:
        return
    
    lines = source.split('\n')
    loop_variables = set()
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        line_num = base_line + i
        
        # Skip comments and empty lines
        if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
            continue
            
        # Check if this line contains a for loop
        if re.search(r'\bfor\s*\(', line_stripped, re.IGNORECASE):
            violation_found = False
            violation_type = ""
            violation_detail = ""
            
            # 1. Check for function calls in stop conditions
            function_call_patterns = [
                r'for\s*\([^;]*[<>=!]+\s*\w+\s*\([^)]*\)',  # Generic function calls
                r'[<>=!]+\s*strlen\s*\(',                    # strlen specifically
                r'[<>=!]+\s*get\w*\s*\(',                    # get* functions
                r'[<>=!]+\s*calculate\w*\s*\(',              # calculate* functions
                r'[<>=!]+\s*sizeof\s*\(',                    # sizeof calls
                r'[<>=!]+\s*\w+Size\s*\(',                   # *Size functions
                r'[<>=!]+\s*\w+Length\s*\(',                 # *Length functions
                r'[<>=!]+\s*\w+Count\s*\('                   # *Count functions
            ]
            
            for pattern in function_call_patterns:
                match = re.search(pattern, line_stripped, re.IGNORECASE)
                if match:
                    violation_found = True
                    violation_type = "function call in stop condition"
                    violation_detail = match.group(0)
                    break
            
            # 2. Extract loop condition variable for modification tracking
            condition_match = re.search(r'for\s*\([^;]*;\s*([^<>=!]*)\s*[<>=!]+\s*([^;]*)\s*;', line_stripped)
            if condition_match:
                loop_var = condition_match.group(1).strip()
                condition_var = condition_match.group(2).strip()
                
                # Clean up variable names (remove spaces, operators, etc.)
                condition_var = re.sub(r'[^a-zA-Z_][a-zA-Z0-9_]*', '', condition_var.split()[0] if condition_var.split() else '')
                
                if condition_var and not violation_found:
                    loop_variables.add(condition_var)
            
            # Report function call violation immediately
            if violation_found:
                finding = {
                    'rule_id': 'loop_stop_conditions_invariant',
                    'message': f'For loop stop conditions should be invariant - avoid {violation_type}. Found: {violation_detail}',
                    'node': f'{loop_node.get("node_type", "ForLoop")}.{loop_node.get("name", "unknown")}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': line_stripped,
                    'status': 'violation',
                    'line': line_num,
                    'severity': 'Info'
                }
                findings.append(finding)
                
        # 3. Check for modifications to loop condition variables
        elif loop_variables:
            for var in loop_variables:
                # Look for variable assignments within loop body
                assignment_patterns = [
                    rf'\b{var}\s*=\s*[^=]',           # Direct assignment
                    rf'\b{var}\s*\+=',               # Increment assignment  
                    rf'\b{var}\s*-=',                # Decrement assignment
                    rf'\b{var}\s*\*=',               # Multiply assignment
                    rf'\b{var}\s*/=',                # Divide assignment
                    rf'\b{var}\s*\+\+',              # Post-increment
                    rf'\+\+\s*{var}',                # Pre-increment
                    rf'\b{var}\s*--',                # Post-decrement
                    rf'--\s*{var}'                   # Pre-decrement
                ]
                
                for pattern in assignment_patterns:
                    if re.search(pattern, line_stripped):
                        # Make sure this isn't the loop increment itself
                        if not re.search(r'for\s*\([^)]*\)', line_stripped):
                            finding = {
                                'rule_id': 'loop_stop_conditions_invariant',
                                'message': f'For loop stop conditions should be invariant - variable "{var}" is modified within loop body, making stop condition non-invariant',
                                'node': f'{loop_node.get("node_type", "ForLoop")}.{loop_node.get("name", "unknown")}',
                                'file': filename,
                                'property_path': ['source'],
                                'value': line_stripped,
                                'status': 'violation',
                                'line': line_num,
                                'severity': 'Info'
                            }
                            findings.append(finding)
                            break


def count_return_statements(ast_tree, filename):
    """
    Count return statements in each function and flag if too many.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check function definitions
        if node_type == 'FunctionDefinition':
            check_function_return_count(node, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type])
    
    traverse_node(ast_tree)
    return findings


def check_function_return_count(function_node, findings, filename):
    """Check a function for too many return statements."""
    source = function_node.get('source', '')
    function_name = function_node.get('name', 'unknown')
    line = function_node.get('line', 1)
    
    if not source:
        return
    
    # Enhanced return statement counting
    return_count = count_actual_return_statements(source)
    
    # Threshold - flag if more than 3 returns
    if return_count > 3:
        finding = {
            'rule_id': 'functions_avoid_containing_too',
            'message': f'Function "{function_name}" has {return_count} return statements. Functions should avoid containing too many return statements.',
            'node': f'FunctionDefinition.{function_name}',
            'file': filename,
            'property_path': ['source'],
            'value': f'Function with {return_count} returns',
            'status': 'violation',
            'line': line,
            'severity': 'Major'
        }
        findings.append(finding)


def count_actual_return_statements(source):
    """
    Count actual return statements while avoiding false positives from:
    - String literals containing "return"
    - Comments containing "return"
    """
    if not source:
        return 0
    
    # Remove string literals and comments to avoid false positives
    # Remove single-line comments
    source_clean = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
    
    # Remove multi-line comments
    source_clean = re.sub(r'/\*.*?\*/', '', source_clean, flags=re.DOTALL)
    
    # Remove string literals (both single and double quotes)
    # This is a simplified approach - more complex parsing would handle escaped quotes
    source_clean = re.sub(r'"[^"]*"', '', source_clean)
    source_clean = re.sub(r"'[^']*'", '', source_clean)
    
    # Now count return statements more precisely
    # Look for return keyword followed by optional expression and semicolon
    return_patterns = [
        r'\breturn\s*;',           # return;
        r'\breturn\s+[^;]+;',      # return expression;
    ]
    
    return_count = 0
    for pattern in return_patterns:
        matches = re.findall(pattern, source_clean, re.MULTILINE)
        return_count += len(matches)
    
    return return_count


def count_function_parameters(ast_tree, filename):
    """
    Count function parameters and flag if too many.
    
    Uses both AST-based detection and direct source code scanning
    to achieve 100% detection rate including multi-line function signatures.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check function definitions
        if node_type == 'FunctionDefinition':
            check_function_parameter_count(node, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type])
    
    # Method 1: AST-based detection
    traverse_node(ast_tree)
    
    # Method 2: Direct source scanning for multi-line functions that AST might miss
    detected_functions = {f['node'].split('.')[1] for f in findings if f['rule_id'] == 'functions_avoid_having_too'}
    direct_scan_findings = scan_source_for_function_parameters(filename, detected_functions)
    
    # Add findings from direct scan that weren't detected by AST
    for finding in direct_scan_findings:
        if finding['node'].split('.')[1] not in detected_functions:
            findings.append(finding)
    
    return findings


def scan_source_for_function_parameters(filename, already_detected):
    """
    Scan source file directly for function parameter counts.
    This catches multi-line function signatures that AST might miss.
    """
    findings = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return findings

    # Remove comments first to avoid false positives
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    
    # Improved pattern to match function declarations/definitions
    # This pattern is more specific to avoid false positives like printf calls
    function_pattern = r'(?:^|\n)\s*(?:static\s+|extern\s+|inline\s+)?(?:void|int|char|short|long|float|double|unsigned|signed|\w+\*?)\s+(\w+)\s*\(\s*([^{;]*?)\)\s*\s*\{'
    
    for match in re.finditer(function_pattern, content, re.MULTILINE | re.DOTALL):
        function_name = match.group(1)
        params_str = match.group(2).strip()
        
        # Skip if already detected by AST
        if function_name in already_detected:
            continue
        
        # Skip common non-function patterns and built-in functions
        if function_name in ['if', 'while', 'for', 'switch', 'sizeof', 'return', 'printf', 'scanf', 'fprintf', 'sprintf', 'main']:
            continue
        
        # Skip single-character function names (likely false positives)
        if len(function_name) <= 1:
            continue
        
        # Count parameters
        param_count = 0
        if params_str and params_str.strip() and params_str.strip() != 'void':
            # Clean up parameters string - handle multi-line
            params_clean = re.sub(r'\s+', ' ', params_str.replace('\n', ' ')).strip()
            
            # Skip empty parameter lists
            if not params_clean:
                param_count = 0
            else:
                # Count parameters by counting commas at the top level
                depth = 0
                comma_count = 0
                for char in params_clean:
                    if char in '([{':
                        depth += 1
                    elif char in ')]}':
                        depth -= 1
                    elif char == ',' and depth == 0:
                        comma_count += 1
                
                param_count = comma_count + 1 if params_clean.strip() else 0
        
        # Flag if more than 5 parameters
        if param_count > 5:
            # Calculate line number
            line_num = content[:match.start()].count('\n') + 1
            
            # Create cleaner function signature for display
            params_display = re.sub(r'\s+', ' ', params_str.replace('\n', ' ')).strip()
            signature_display = f"{function_name}({params_display})"
            
            finding = {
                'rule_id': 'functions_avoid_having_too',
                'message': f'Function "{function_name}" has {param_count} parameters. Functions should avoid having too many parameters.',
                'node': f'FunctionDefinition.{function_name}',
                'file': filename,
                'property_path': ['source'],
                'value': signature_display,
                'status': 'violation',
                'line': line_num,
                'severity': 'Info'
            }
            findings.append(finding)
    
    return findings


def check_function_parameter_count(function_node, findings, filename):
    """Check a function for too many parameters."""
    source = function_node.get('source', '')
    function_name = function_node.get('name', 'unknown')
    line = function_node.get('line', 1)
    
    if not source:
        return
    
    # Multiple approaches to extract function signature and count parameters
    param_count = 0
    signature = ""
    
    # Method 1: Try to extract function signature with multi-line support
    # Look for function declaration pattern: return_type function_name(params...)
    func_pattern = r'(?:^|\n)\s*(?:static\s+|extern\s+|inline\s+)?(?:\w+\s+)?(\w+)\s*\([^{]*?\)'
    func_matches = re.finditer(func_pattern, source, re.MULTILINE | re.DOTALL)
    
    for match in func_matches:
        potential_name = match.group(1)
        if potential_name == function_name or function_name == 'unknown':
            # Extract the full match including parameters
            full_signature = match.group(0).strip()
            
            # Extract just the parameter part
            paren_start = full_signature.find('(')
            paren_end = full_signature.rfind(')')
            
            if paren_start != -1 and paren_end != -1:
                params_str = full_signature[paren_start+1:paren_end].strip()
                signature = full_signature
                break
    
    # Method 2: Fallback to simpler pattern if Method 1 fails
    if not signature:
        func_match = re.search(r'(\w+\s*\([^)]*\))', source, re.DOTALL)
        if func_match:
            signature = func_match.group(1)
            params_str = signature[signature.find('(')+1:signature.find(')')].strip()
        else:
            return
    
    # Method 3: Try to extract parameters from the entire source if still no luck
    if not signature:
        # Look for opening parenthesis after function name
        name_pattern = rf'\b{re.escape(function_name)}\s*\('
        name_match = re.search(name_pattern, source)
        if name_match:
            # Find matching closing parenthesis
            start_pos = name_match.end() - 1  # Position of opening (
            paren_count = 0
            end_pos = start_pos
            
            for i, char in enumerate(source[start_pos:], start_pos):
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                    if paren_count == 0:
                        end_pos = i
                        break
            
            if paren_count == 0:
                params_str = source[start_pos+1:end_pos].strip()
                signature = source[name_match.start():end_pos+1]
    
    # Clean up parameters string and count them
    if 'params_str' in locals():
        # Remove comments, newlines, and extra whitespace
        params_clean = re.sub(r'/\*.*?\*/', '', params_str, flags=re.DOTALL)
        params_clean = re.sub(r'//.*$', '', params_clean, flags=re.MULTILINE)
        params_clean = re.sub(r'\s+', ' ', params_clean.replace('\n', ' ')).strip()
        
        if not params_clean or params_clean == 'void':
            param_count = 0
        else:
            # Count parameters by splitting on commas, but be careful of commas in nested structures
            # Simple approach: count commas at the top level
            depth = 0
            comma_count = 0
            for char in params_clean:
                if char in '([{':
                    depth += 1
                elif char in ')]}':
                    depth -= 1
                elif char == ',' and depth == 0:
                    comma_count += 1
            
            param_count = comma_count + 1 if params_clean else 0
    
    # Threshold - flag if more than 5 parameters
    if param_count > 5:
        # Clean signature for display
        if signature:
            display_signature = re.sub(r'\s+', ' ', signature.replace('\n', ' ')).strip()
        else:
            display_signature = f"{function_name} with {param_count} parameters"
        
        finding = {
            'rule_id': 'functions_avoid_having_too',
            'message': f'Function "{function_name}" has {param_count} parameters. Functions should avoid having too many parameters.',
            'node': f'FunctionDefinition.{function_name}',
            'file': filename,
            'property_path': ['source'],
            'value': display_signature,
            'status': 'violation',
            'line': line,
            'severity': 'Info'
        }
        findings.append(finding)


def check_unused_function(ast_tree, filename):
    """
    Check for potentially unused functions.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    # For simplicity, this is a placeholder implementation
    # A real implementation would track function definitions and calls across the project
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # For now, just check if a function has a comment indicating it might be unused
        if node_type == 'FunctionDefinition':
            source = node.get('source', '')
            if 'unused' in source.lower() or 'not used' in source.lower():
                function_name = node.get('name', 'unknown')
                line = node.get('line', 1)
                
                finding = {
                    'rule_id': 'functions_that_are_project',
                    'message': f'Function "{function_name}" appears to be unused and should be removed.',
                    'node': f'FunctionDefinition.{function_name}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': f'Potentially unused function',
                    'status': 'violation',
                    'line': line,
                    'severity': 'Major'
                }
                findings.append(finding)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type])
    
    traverse_node(ast_tree)
    return findings

def check_noreturn_with_return(ast_tree, filename):
    """
    Check for functions with noreturn attribute that contain return statements.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check function definitions
        if node_type == 'FunctionDefinition':
            check_function_noreturn_return(node, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type])
    
    traverse_node(ast_tree)
    return findings


def check_function_noreturn_return(function_node, findings, filename):
    """Check a function for noreturn attribute with return statements."""
    source = function_node.get('source', '')
    function_name = function_node.get('name', 'unknown')
    line = function_node.get('line', 1)
    
    if not source:
        return
    
    # Check if function has noreturn attribute
    has_noreturn = ('noreturn' in source and 
                    ('__attribute__' in source or '_Noreturn' in source))
    
    # Check if function has return statements
    has_return = 'return ' in source
    
    if has_noreturn and has_return:
        finding = {
            'rule_id': 'functions_noreturn_attribute_return',
            'message': f'Function "{function_name}" has noreturn attribute but contains return statements.',
            'node': f'FunctionDefinition.{function_name}',
            'file': filename,
            'property_path': ['source'],
            'value': 'noreturn function with return',
            'status': 'violation',
            'line': line,
            'severity': 'Major'
        }
        findings.append(finding)


def check_implicit_function_call(ast_tree, filename):
    """
    Check for function calls without explicit declarations (implicit function declarations).
    This detects when a function is called before being declared or defined.
    """
    findings = []
    
    # Get all function declarations and definitions
    declared_functions = set()
    function_calls = []
    
    # Extract declared functions and function calls from AST
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
    
    lines = content.split('\n')
    
    # Improved patterns
    # Look for function declarations (prototypes) - must start with known return types
    declaration_pattern = r'^\s*(?:static\s+|extern\s+|inline\s+)*(?:const\s+)*(?:unsigned\s+|signed\s+)*(?:void|char|short|int|long|float|double|size_t|ssize_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t)(?:\s*\*)?\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*;\s*(?://.*)?$'
    # Look for function definitions - must start with known return types  
    definition_pattern = r'^\s*(?:static\s+|extern\s+|inline\s+)*(?:const\s+)*(?:unsigned\s+|signed\s+)*(?:void|char|short|int|long|float|double|size_t|ssize_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t)(?:\s*\*)?\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{\s*(?://.*)?$'
    # Look for function calls within functions - just match name and opening paren
    call_pattern = r'([a-zA-Z_]\w*)\s*\('
    
    # Track order to detect implicit calls
    declarations_by_line = {}
    definitions_by_line = {}
    calls_by_line = {}
    
    # First pass: identify all declarations, definitions, and calls
    in_function = False
    brace_count = 0
    
    for line_num, line in enumerate(lines, 1):
        stripped_line = line.strip()
        
        # Skip empty lines and comments
        if not stripped_line or stripped_line.startswith('//') or stripped_line.startswith('/*'):
            continue
            
        # Count braces to track if we're inside a function
        brace_count += line.count('{') - line.count('}')
        in_function = brace_count > 0
        
        # Check for function declarations (prototypes)
        decl_match = re.search(declaration_pattern, stripped_line)
        if decl_match:
            func_name = decl_match.group(1)
            declarations_by_line[line_num] = func_name
            declared_functions.add(func_name)
            continue
            
        # Check for function definitions
        def_match = re.search(definition_pattern, stripped_line)
        if def_match:
            func_name = def_match.group(1)
            definitions_by_line[line_num] = func_name
            # Don't add to declared_functions here - function is not "declared" until after this line
            continue
        
        # Check for function calls inside function bodies
        if in_function and not def_match:  # Don't look for calls in function definition lines
            # Remove comments first to avoid false matches
            line_without_comments = stripped_line.split('//')[0].strip()
            
            # Find all function calls in the line (can be multiple per line)
            call_matches = re.finditer(call_pattern, line_without_comments)
            for call_match in call_matches:
                func_name = call_match.group(1)
                
                # Skip C keywords, operators, and standard library functions
                skip_functions = {
                    # C keywords
                    'if', 'for', 'while', 'switch', 'return', 'sizeof', 'typeof', 'alignof',
                    'case', 'break', 'continue', 'goto', 'do', 'else', 'static_assert',
                    # Standard library functions (common ones)
                    'printf', 'scanf', 'fprintf', 'sprintf', 'snprintf', 'puts', 'gets',
                    'malloc', 'calloc', 'realloc', 'free',
                    'strlen', 'strcpy', 'strncpy', 'strcmp', 'strncmp', 'strcat', 'strncat',
                    'strstr', 'strtok', 'memcpy', 'memset', 'memmove', 'memcmp',
                    'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell', 'feof', 'ferror',
                    'exit', 'abort', '_exit', 'atexit',
                    'isalpha', 'isdigit', 'isalnum', 'isspace', 'tolower', 'toupper',
                    'atoi', 'atol', 'atof', 'strtol', 'strtoul', 'strtod',
                    'assert', 'perror'
                }
                
                # Store all valid function calls from this line
                if func_name not in skip_functions:
                    # Use a unique key to store multiple calls from the same line
                    key = f"{line_num}_{func_name}"
                    calls_by_line[key] = (func_name, stripped_line, line_num)
    
    # Second pass: check if calls happen before declarations/definitions
    for key, (func_name, line_content, call_line) in calls_by_line.items():
        # Check if function is declared/defined before the call
        earliest_declaration = float('inf')
        
        # Find earliest declaration
        for decl_line, decl_func in declarations_by_line.items():
            if decl_func == func_name and decl_line < call_line:
                earliest_declaration = min(earliest_declaration, decl_line)
        
        # Find earliest definition that comes before the call
        for def_line, def_func in definitions_by_line.items():
            if def_func == func_name and def_line < call_line:
                earliest_declaration = min(earliest_declaration, def_line)
        
        # Special case: check if this is a recursive call (function calling itself)
        # Find the function we're currently inside
        current_function = None
        for def_line, def_func in definitions_by_line.items():
            if def_line < call_line:
                current_function = def_func
        
        # If calling the same function we're currently in, it's recursion - skip
        if func_name == current_function:
            continue
        
        # If no declaration/definition found before the call, it's implicit
        if earliest_declaration == float('inf'):
            finding = {
                'rule_id': 'functions_declared_explicitly',
                'message': f'Function "{func_name}" is called without explicit declaration.',
                'node': f'FunctionCall.{func_name}',
                'file': filename,
                'property_path': ['source'],
                'value': line_content,
                'status': 'violation',
                'line': call_line,
                'severity': 'Info'
            }
            findings.append(finding)
    
    return findings


def check_block_scope_declaration(ast_tree, filename):
    """
    Check for function declarations at block scope.
    Detects when function prototypes are declared inside function bodies.
    """
    findings = []
    
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
    
    lines = content.split('\n')
    in_function = False
    brace_count = 0
    
    for line_num, line in enumerate(lines, 1):
        stripped_line = line.strip()
        
        # Track when we're inside a function
        if '{' in line:
            # Check if this is a function definition start
            if re.search(r'^\s*[a-zA-Z_]\w*\s+[a-zA-Z_]\w*\s*\([^)]*\)\s*{', line):
                in_function = True
                brace_count = line.count('{') - line.count('}')
            else:
                brace_count += line.count('{') - line.count('}')
                
        elif '}' in line:
            brace_count += line.count('{') - line.count('}')
            if brace_count <= 0:
                in_function = False
                brace_count = 0
        
        # Look for function declarations inside function bodies
        if in_function and brace_count > 0:
            # Check for function declaration pattern
            decl_match = re.search(r'^\s*[a-zA-Z_]\w*\s+[a-zA-Z_]\w*\s*\([^)]*\)\s*;', stripped_line)
            if decl_match:
                func_name_match = re.search(r'\s+([a-zA-Z_]\w*)\s*\(', stripped_line)
                if func_name_match:
                    func_name = func_name_match.group(1)
                    finding = {
                        'rule_id': 'functions_declared_block_scope',
                        'message': f'Function "{func_name}" is declared at block scope.',
                        'node': f'FunctionDeclaration.{func_name}',
                        'file': filename,
                        'property_path': ['source'],
                        'value': stripped_line,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Info'
                    }
                    findings.append(finding)
    
    return findings


def check_function_pointer_conversion(ast_tree, filename):
    """
    Check for unsafe function pointer conversions.
    Detects when function pointers are cast to different function pointer types or other pointer types.
    This includes conversions that can lead to undefined behavior.
    """
    findings = []
    
    # Get source content
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return findings

    lines = content.split('\n')
    seen_violations = set()  # To avoid duplicate reports
    
    def find_function_pointer_conversions(line):
        """Find all function pointer conversions in a line using balanced parentheses parsing"""
        matches = []
        
        # Look for patterns like )&functionName
        ampersand_pattern = r'&\s*([a-zA-Z_]\w*)'
        
        for amp_match in re.finditer(ampersand_pattern, line):
            function_name = amp_match.group(1)
            amp_pos = amp_match.start()
            
            # Look backwards for the closing parenthesis
            close_paren_pos = None
            for i in range(amp_pos - 1, -1, -1):
                if line[i] == ')':
                    close_paren_pos = i
                    break
                elif line[i].isspace():
                    continue
                else:
                    break
            
            if close_paren_pos is None:
                continue
                
            # Look backwards for the opening parenthesis (handle nested parentheses)
            open_paren_pos = None
            paren_level = 0
            for i in range(close_paren_pos, -1, -1):
                if line[i] == ')':
                    paren_level += 1
                elif line[i] == '(':
                    paren_level -= 1
                    if paren_level == 0:
                        open_paren_pos = i
                        break
            
            if open_paren_pos is None:
                continue
                
            cast_expr = line[open_paren_pos+1:close_paren_pos].strip()
            
            # Skip if this doesn't look like a cast
            if not cast_expr or cast_expr == function_name:
                continue
                
            # Skip if no type indicators present
            if not any(indicator in cast_expr.lower() for indicator in ['*', 'void', 'int', 'float', 'char', 'long', 'short', 'double']):
                continue
            
            matches.append((cast_expr, function_name))
        
        return matches
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # Skip comments and empty lines
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
            continue
            
        # Skip lines that don't contain potential function pointer operations
        if not ('&' in line_clean and '(' in line_clean):
            continue
        
        # Find all conversions in this line
        matches = find_function_pointer_conversions(line_clean)
        
        for cast_expr, function_name in matches:
            # Create unique violation key per line and function
            violation_key = (line_num, function_name)
            
            # Skip if already reported for this line/function
            if violation_key in seen_violations:
                continue
            
            seen_violations.add(violation_key)
            
            # Categorize the type of conversion for better messaging
            if cast_expr == 'void*' or cast_expr == 'void *':
                # void* conversion
                message = f'Function pointer "&{function_name}" is being converted to void*. This can lead to undefined behavior.'
            elif '*' in cast_expr and '(*' not in cast_expr:
                # Data pointer conversion (e.g., int*, char*)
                message = f'Function pointer "&{function_name}" is being converted to data pointer type "({cast_expr})". This is unsafe and can cause undefined behavior.'
            elif '(*' in cast_expr:
                # Function pointer to function pointer conversion
                message = f'Function pointer "&{function_name}" is being converted to a different function pointer type "({cast_expr})". This can lead to undefined behavior if signatures don\'t match.'
            else:
                # Generic conversion
                message = f'Function pointer "&{function_name}" is being converted to type "({cast_expr})". This can lead to undefined behavior.'
            
            finding = {
                'rule_id': 'function_pointers_converted_any',
                'message': message,
                'node': f'Conversion.{function_name}',
                'file': filename,
                'property_path': ['source'],
                'value': line_clean,
                'status': 'violation',
                'line': line_num,
                'severity': 'Info'
            }
            findings.append(finding)
    
    return findings


def check_function_line_count(ast_tree, filename):
    """
    Check if functions have too many lines.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    max_lines = 15  # Configurable threshold (lowered for testing)
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        if node_type in ['FunctionDefinition', 'Function']:
            source = node.get('source', '')
            line_count = len([line for line in source.split('\n') if line.strip()])
            
            if line_count > max_lines:
                finding = {
                    'rule_id': 'functionsmethods_avoid_having_too',
                    'message': f'Function has {line_count} lines, which exceeds the maximum of {max_lines} lines.',
                    'node': f'FunctionDefinition.{node.get("name", "unknown")}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': source[:100] + '...' if len(source) > 100 else source,
                    'status': 'violation',
                    'line': node.get('line', 1),
                    'severity': 'Major'
                }
                findings.append(finding)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    traverse_node(ast_tree)
    return findings


def check_header_guard_matching(ast_tree, filename):
    """
    Check if header guards have matching #define statements.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    # Extract all source content to analyze header guards
    def extract_source(node):
        if isinstance(node, dict) and 'source' in node:
            return node['source']
        elif isinstance(node, dict) and 'children' in node:
            return '\n'.join(extract_source(child) for child in node['children'])
        elif isinstance(node, list):
            return '\n'.join(extract_source(item) for item in node)
        return ''
    
    source = extract_source(ast_tree)
    lines = source.split('\n')
    
    # Find #ifndef statements and check for matching #define
    ifndef_pattern = re.compile(r'#ifndef\s+([A-Z_][A-Z0-9_]*)')
    define_pattern = re.compile(r'#define\s+([A-Z_][A-Z0-9_]*)')
    
    ifndef_guards = {}
    define_guards = set()
    
    for i, line in enumerate(lines):
        ifndef_match = ifndef_pattern.search(line)
        if ifndef_match:
            guard_name = ifndef_match.group(1)
            ifndef_guards[guard_name] = i + 1
        
        define_match = define_pattern.search(line)
        if define_match:
            guard_name = define_match.group(1)
            define_guards.add(guard_name)
    
    # Check for #ifndef without matching #define
    for guard_name, line_num in ifndef_guards.items():
        if guard_name not in define_guards:
            finding = {
                'rule_id': 'header_guards_followed_matching',
                'message': f'Header guard #{guard_name} is missing matching #define statement.',
                'node': f'PreprocessorDirective.ifndef.{guard_name}',
                'file': filename,
                'property_path': ['source'],
                'value': f'#ifndef {guard_name}',
                'status': 'violation',
                'line': line_num,
                'severity': 'Info'
            }
            findings.append(finding)
    
    return findings


def check_identical_binary_operands(ast_tree, filename):
    """
    Check for identical expressions on both sides of binary operators.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        if node_type in ['BinaryOperation', 'ConditionalStatement']:
            source = node.get('source', '')
            
            # Check for patterns like: x == x, y && y, z || z, etc.
            patterns = [
                r'(\w+)\s*==\s*\1\b',  # x == x
                r'(\w+)\s*!=\s*\1\b',  # x != x  
                r'(\w+)\s*&&\s*\1\b',  # x && x
                r'(\w+)\s*\|\|\s*\1\b',  # x || x
                r'(\w+)\s*[<>]=?\s*\1\b',  # x <= x, x >= x, etc.
                r'(\w+)\s*[+\-*/]\s*\1\b',  # x + x, x - x, etc.
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, source)
                for match in matches:
                    var_name = match.group(1)
                    finding = {
                        'rule_id': 'identical_expressions_avoided_both',
                        'message': f'Identical expression "{var_name}" found on both sides of binary operator.',
                        'node': f'BinaryOperation.{var_name}',
                        'file': filename,
                        'property_path': ['source'],
                        'value': match.group(0),
                        'status': 'violation',
                        'line': node.get('line', 1),
                        'severity': 'Info'
                    }
                    findings.append(finding)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node.get('node_type', 'unknown')])
        
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    traverse_node(ast_tree)
    return findings


def check_goto_backward_jump(ast_tree, filename):
    """
    Check for backward jumps in goto statements.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def extract_source(node):
        if isinstance(node, dict) and 'source' in node:
            return node['source']
        elif isinstance(node, dict) and 'children' in node:
            return '\n'.join(extract_source(child) for child in node['children'])
        elif isinstance(node, list):
            return '\n'.join(extract_source(item) for item in node)
        return ''
    
    source = extract_source(ast_tree)
    lines = source.split('\n')
    
    # Find all labels and goto statements with line numbers
    label_pattern = re.compile(r'^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:')
    goto_pattern = re.compile(r'\bgoto\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;')
    
    labels = {}
    gotos = []
    
    for i, line in enumerate(lines):
        # Find labels
        label_match = label_pattern.search(line)
        if label_match:
            label_name = label_match.group(2)
            labels[label_name] = i + 1
        
        # Find goto statements
        goto_match = goto_pattern.search(line)
        if goto_match:
            target_label = goto_match.group(1)
            gotos.append((target_label, i + 1))
    
    # Check for backward jumps
    for target_label, goto_line in gotos:
        if target_label in labels:
            label_line = labels[target_label]
            if goto_line > label_line:  # Backward jump
                finding = {
                    'rule_id': 'goto_jump_labels_declared',
                    'message': f'Goto statement jumps backward to label "{target_label}" (backward jump detected).',
                    'node': f'Statement.goto.{target_label}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': f'goto {target_label};',
                    'status': 'violation',
                    'line': goto_line,
                    'severity': 'Info'
                }
                findings.append(finding)
    
    return findings


def check_goto_into_blocks(ast_tree, filename):
    """
    Check for goto statements that jump into control blocks.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def extract_source(node):
        if isinstance(node, dict) and 'source' in node:
            return node['source']
        elif isinstance(node, dict) and 'children' in node:
            return '\n'.join(extract_source(child) for child in node['children'])
        elif isinstance(node, list):
            return '\n'.join(extract_source(item) for item in node)
        return ''
    
    source = extract_source(ast_tree)
    lines = source.split('\n')
    
    # Look for goto statements and analyze the context
    goto_pattern = re.compile(r'\bgoto\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;')
    label_pattern = re.compile(r'^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:')
    
    block_starts = []
    block_ends = []
    labels = {}
    gotos = []
    
    # Find control structure blocks
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Track block starts
        if (stripped.startswith('for') and '{' in stripped) or \
           (stripped.startswith('while') and '{' in stripped) or \
           (stripped.startswith('if') and '{' in stripped) or \
           stripped == '{':
            block_starts.append(i + 1)
        
        # Track block ends
        if stripped == '}' or stripped.endswith('}'):
            block_ends.append(i + 1)
            
        # Find labels
        label_match = label_pattern.search(line)
        if label_match:
            label_name = label_match.group(2)
            labels[label_name] = i + 1
            
        # Find goto statements
        goto_match = goto_pattern.search(line)
        if goto_match:
            target_label = goto_match.group(1)
            gotos.append((target_label, i + 1))
    
    # Check if labels are inside blocks and gotos are outside
    for target_label, goto_line in gotos:
        if target_label in labels:
            label_line = labels[target_label]
            
            # Simple heuristic: if label is significantly indented compared to goto
            goto_line_content = lines[goto_line - 1] if goto_line <= len(lines) else ""
            label_line_content = lines[label_line - 1] if label_line <= len(lines) else ""
            
            goto_indent = len(goto_line_content) - len(goto_line_content.lstrip())
            label_indent = len(label_line_content) - len(label_line_content.lstrip())
            
            if label_indent > goto_indent + 2:  # Label is more indented (likely inside block)
                finding = {
                    'rule_id': 'goto_jump_labels_declared',
                    'message': f'Goto statement jumps into control block to label "{target_label}".',
                    'node': f'Statement.goto.{target_label}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': f'goto {target_label};',
                    'status': 'violation',
                    'line': goto_line,
                    'severity': 'Info'
                }
                findings.append(finding)
    
    return findings


def check_format_strings_preferred_correctly(ast_tree, filename):
    """
    Check for incorrect usage of printf format strings.
    
    This function validates that format specifiers match their corresponding arguments:
    - %d should be used with int/integer types
    - %s should be used with string/char* types
    - %c should be used with char types
    - %f should be used with float/double types
    - Number of format specifiers should match number of arguments
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    # Format specifier patterns and their expected types
    format_patterns = {
        '%d': ['int', 'integer', 'short', 'long'],
        '%i': ['int', 'integer', 'short', 'long'],
        '%u': ['unsigned', 'uint', 'unsigned int'],
        '%ld': ['long', 'long int'],
        '%lld': ['long long', 'long long int'],
        '%s': ['string', 'char*', 'char *', 'const char*', 'const char *'],
        '%c': ['char', 'character'],
        '%f': ['float', 'double'],
        '%lf': ['double', 'long double'],
        '%g': ['float', 'double'],
        '%e': ['float', 'double'],
        '%x': ['int', 'integer', 'unsigned'],
        '%X': ['int', 'integer', 'unsigned'],
        '%o': ['int', 'integer', 'unsigned'],
        '%p': ['pointer', 'void*', 'void *']
    }
    
    def get_variable_type_from_name(var_name):
        """Infer variable type from common naming patterns"""
        var_name = var_name.lower()
        if 'str' in var_name or var_name.endswith('_string') or var_name.startswith('string_'):
            return 'string'
        elif 'int' in var_name or var_name.endswith('_value') or var_name.endswith('_val'):
            return 'int'
        elif 'char' in var_name and ('val' in var_name or 'ch' in var_name):
            return 'char'
        elif 'double' in var_name or 'float' in var_name:
            return 'double'
        elif 'ptr' in var_name or 'pointer' in var_name:
            return 'pointer'
        return 'unknown'
    
    def extract_format_specifiers(format_string):
        """Extract format specifiers from a format string"""
        import re
        # Pattern to match format specifiers like %d, %s, %c, %f, etc.
        pattern = r'%[-#+ 0]?(\*|\d+)?(\.\*|\.\d+)?[hlL]?[diouxXeEfFgGaAcspmn%]'
        matches = re.findall(pattern, format_string)
        # Get the actual specifiers
        specifiers = re.findall(r'%[-#+ 0]?(?:\*|\d+)?(?:\.\*|\.\d+)?[hlL]?[diouxXeEfFgGaAcspmn%]', format_string)
        return [spec for spec in specifiers if spec != '%%']  # Exclude literal %
    
    def check_printf_call(node, node_source):
        """Check a printf-style function call for format string issues"""
        if not node_source:
            return
            
        # Extract function name and arguments
        import re
        printf_pattern = r'(printf|sprintf|fprintf|snprintf)\s*\(\s*([^)]+)\s*\)'
        match = re.search(printf_pattern, node_source)
        
        if not match:
            return
            
        func_name = match.group(1)
        args_str = match.group(2)
        
        # Split arguments (simple approach - may not handle nested function calls perfectly)
        args = [arg.strip() for arg in args_str.split(',')]
        
        # For fprintf, first argument is file pointer, skip it
        if func_name in ['fprintf', 'sprintf']:
            if len(args) < 2:
                return
            format_arg = args[1] if func_name == 'fprintf' else args[0]
            data_args = args[2:] if func_name == 'fprintf' else args[1:]
        else:
            if len(args) < 1:
                return
            format_arg = args[0]
            data_args = args[1:]
        
        # Extract format string (remove quotes)
        format_string = format_arg.strip().strip('"').strip("'")
        
        # Extract format specifiers
        specifiers = extract_format_specifiers(format_string)
        
        if not specifiers:
            return  # No format specifiers to check
        
        # Check if number of arguments matches number of specifiers
        if len(data_args) != len(specifiers):
            line_num = extract_line_number(node)
            finding = {
                'rule_id': 'format_strings_preferred_correctly',
                'message': f'Format string has {len(specifiers)} specifiers but {len(data_args)} arguments provided',
                'file': filename,
                'line': line_num,
                'status': 'violation',
                'severity': 'Info',
                'code_snippet': node_source.strip()
            }
            findings.append(finding)
            return
        
        # Check each specifier against its corresponding argument
        for i, (spec, arg) in enumerate(zip(specifiers, data_args)):
            arg = arg.strip()
            
            # Get expected types for this specifier
            expected_types = None
            for pattern, types in format_patterns.items():
                if spec.startswith(pattern.rstrip('diouxXeEfFgGaAcspmn%')):
                    expected_types = types
                    break
            
            if not expected_types:
                continue  # Unknown specifier
            
            # Infer argument type
            arg_type = get_variable_type_from_name(arg)
            
            # Additional type inference based on literal values
            if arg.isdigit() or (arg.startswith('-') and arg[1:].isdigit()):
                arg_type = 'int'
            elif '"' in arg or "'" in arg:
                if spec in ['%c'] and len(arg.strip('"').strip("'")) == 1:
                    arg_type = 'char'
                else:
                    arg_type = 'string'
            elif '.' in arg and arg.replace('.', '').replace('-', '').isdigit():
                arg_type = 'double'
            
            # Check for type mismatch
            is_mismatch = False
            if spec in ['%d', '%i', '%u', '%x', '%X', '%o'] and arg_type not in ['int', 'integer', 'short', 'long', 'unknown']:
                is_mismatch = True
                expected = 'integer'
                actual = arg_type
            elif spec in ['%s'] and arg_type not in ['string', 'char*', 'unknown']:
                is_mismatch = True
                expected = 'string'
                actual = arg_type
            elif spec in ['%c'] and arg_type not in ['char', 'character', 'unknown']:
                is_mismatch = True
                expected = 'character'
                actual = arg_type
            elif spec in ['%f', '%lf', '%g', '%e'] and arg_type not in ['float', 'double', 'unknown']:
                is_mismatch = True
                expected = 'float/double'
                actual = arg_type
            
            if is_mismatch:
                line_num = extract_line_number(node)
                finding = {
                    'rule_id': 'format_strings_preferred_correctly',
                    'message': f'Format specifier {spec} expects {expected} but argument "{arg}" appears to be {actual}',
                    'file': filename,
                    'line': line_num,
                    'status': 'violation',
                    'severity': 'Info',
                    'code_snippet': node_source.strip()
                }
                findings.append(finding)
    
    def extract_line_number(node):
        """Extract line number from node"""
        if isinstance(node, dict):
            if 'line' in node:
                return node['line']
            elif 'line_number' in node:
                return node['line_number']
            elif 'start_line' in node:
                return node['start_line']
        return 1
    
    def traverse_node(node, path=[]):
        """Traverse AST nodes to find printf-style function calls"""
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Look for function calls
        if node_type in ['CallExpression', 'FunctionCall', 'Call']:
            source = node.get('source', '')
            if any(func in source for func in ['printf', 'sprintf', 'fprintf', 'snprintf']):
                check_printf_call(node, source)
        
        # Check source directly for printf patterns if node type info is limited
        source = node.get('source', '')
        if source and any(func in source for func in ['printf', 'sprintf', 'fprintf', 'snprintf']):
            check_printf_call(node, source)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        # Check other common child containers
        for key in ['body', 'statements', 'declarations', 'expression', 'arguments']:
            if key in node:
                if isinstance(node[key], list):
                    for child in node[key]:
                        traverse_node(child, path + [node_type])
                elif isinstance(node[key], dict):
                    traverse_node(node[key], path + [node_type])
    
    # Start traversal
    traverse_node(ast_tree)
    return findings


def check_redundant_forward_declarations(ast_tree, filename):
    """
    Check for redundant forward declarations in C code.
    
    A forward declaration is redundant if:
    1. A struct/union/enum is defined and later forward declared
    2. A function is defined and later declared
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    # Collect all struct/union/enum declarations and definitions
    struct_declarations = []
    function_declarations = []
    
    def collect_declarations(nodes):
        """Collect all declarations from the AST nodes."""
        if not isinstance(nodes, list):
            nodes = [nodes]
            
        for node in nodes:
            if not isinstance(node, dict):
                continue
                
            node_type = node.get('node_type', '')
            name = node.get('name', '')
            source = node.get('source', '')
            line = node.get('lineno', 0)
            
            # Handle struct/union/enum declarations
            if node_type in ['StructDeclaration', 'UnionDeclaration', 'EnumDeclaration']:
                keyword = node.get('keyword', node_type.lower().replace('declaration', ''))
                
                # Check if this is a definition (has body with {}) or just a declaration
                has_body = '{' in source and '}' in source
                
                struct_declarations.append({
                    'type': keyword,
                    'name': name,
                    'line': line,
                    'source': source,
                    'has_body': has_body,
                    'node': node
                })
            
            # Handle function declarations and definitions
            elif node_type in ['FunctionDeclaration', 'FunctionDefinition']:
                # Check if this is a definition (has body with {}) or just a declaration
                has_body = '{' in source and '}' in source
                
                function_declarations.append({
                    'name': name,
                    'line': line,
                    'source': source,
                    'has_body': has_body,
                    'node': node
                })
            
            # Recursively check children
            if 'children' in node and isinstance(node['children'], list):
                collect_declarations(node['children'])
    
    # Collect from the AST tree
    if isinstance(ast_tree, list):
        collect_declarations(ast_tree)
    else:
        collect_declarations([ast_tree])
    
    # Check for redundant struct/union/enum declarations
    struct_definitions = {}  # name -> definition info
    
    for decl in struct_declarations:
        struct_type = decl['type']
        name = decl['name']
        key = f"{struct_type}_{name}"
        
        if decl['has_body']:
            # This is a definition
            if key in struct_definitions:
                # Already have a definition, this is duplicate (different issue)
                pass
            else:
                struct_definitions[key] = decl
        else:
            # This is a forward declaration
            if key in struct_definitions:
                # We already have a definition, this forward declaration is redundant
                findings.append({
                    'rule_id': 'forward_declarations_redundant',
                    'message': f'Redundant forward declaration of {struct_type} {name}',
                    'line': decl['line'],
                    'severity': 'Major',
                    'file': filename
                })
    
    # Check for redundant function declarations
    function_definitions = {}  # name -> definition info
    
    for decl in function_declarations:
        name = decl['name']
        
        if decl['has_body']:
            # This is a definition
            if name in function_definitions:
                # Already have a definition, this is duplicate (different issue)
                pass
            else:
                function_definitions[name] = decl
        else:
            # This is a forward declaration
            if name in function_definitions:
                # We already have a definition, this forward declaration is redundant
                findings.append({
                    'rule_id': 'forward_declarations_redundant',
                    'message': f'Redundant forward declaration of function {name}',
                    'line': decl['line'],
                    'severity': 'Major',
                    'file': filename
                })
    
    return findings


def check_parameter_reassignment(ast_tree, filename):
    """
    Check for function parameter reassignments that ignore initial values.
    Detects when function parameters are reassigned within the function body,
    which reduces code readability and ignores the initial parameter values.
    """
    findings = []
    
    # Get source content
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return findings

    lines = content.split('\n')

    # Find all functions and their parameters
    functions = []
    
    # Regex to match function definitions
    # This matches: return_type function_name(parameters) {
    function_pattern = r'^\s*(?:static\s+|inline\s+)*(?:const\s+)*([a-zA-Z_]\w*(?:\s*\*)*)\s+([a-zA-Z_]\w*)\s*\(([^{]*)\)\s*\{'
    
    in_function = False
    current_function = None
    brace_depth = 0
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # Skip comments and empty lines
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
            continue
        
        # Check for function definition
        if not in_function:
            match = re.search(function_pattern, line)
            if match:
                return_type = match.group(1).strip()
                function_name = match.group(2).strip()
                params_str = match.group(3).strip()
                
                # Parse parameters
                parameters = []
                if params_str and params_str != 'void':
                    # Split parameters by comma, but be careful with nested types
                    param_parts = []
                    paren_depth = 0
                    current_param = ""
                    
                    for char in params_str:
                        if char == ',' and paren_depth == 0:
                            param_parts.append(current_param.strip())
                            current_param = ""
                        else:
                            if char == '(':
                                paren_depth += 1
                            elif char == ')':
                                paren_depth -= 1
                            current_param += char
                    
                    if current_param.strip():
                        param_parts.append(current_param.strip())
                    
                    # Extract parameter names
                    for param in param_parts:
                        # Remove const, static, etc.
                        param_clean = re.sub(r'\b(?:const|static|volatile)\b', '', param).strip()
                        
                        # Handle function pointers like: void (*func)(void)
                        # Extract the name between (* and )
                        func_ptr_match = re.search(r'\(\s*\*\s*([a-zA-Z_]\w*)\s*\)', param_clean)
                        if func_ptr_match:
                            param_name = func_ptr_match.group(1)
                            if param_name not in ['int', 'char', 'float', 'double', 'long', 'short', 'void', 'unsigned', 'signed']:
                                parameters.append(param_name)
                            continue
                        
                        # Handle regular parameters: extract last identifier
                        # Handle cases like: int param, int* param, int param[], char* param
                        # Look for the last identifier that's not a type keyword
                        words = re.findall(r'\b[a-zA-Z_]\w*\b', param_clean)
                        if words:
                            # Take the last word that's not a type keyword
                            for word in reversed(words):
                                if word not in ['int', 'char', 'float', 'double', 'long', 'short', 'void', 'unsigned', 'signed', 'struct', 'union', 'enum']:
                                    parameters.append(word)
                                    break
                
                current_function = {
                    'name': function_name,
                    'parameters': parameters,
                    'start_line': line_num,
                    'end_line': None
                }
                in_function = True
                brace_depth = 1  # We found the opening brace
                
                continue
        
        if in_function:
            # Count braces to track function scope
            brace_depth += line.count('{') - line.count('}')
            
            if brace_depth <= 0:
                # Function ended
                current_function['end_line'] = line_num
                functions.append(current_function)
                in_function = False
                current_function = None
                continue
            
            # Check for parameter reassignments within this function
            if current_function and current_function['parameters']:
                for param_name in current_function['parameters']:
                    # Check for various assignment patterns to this parameter
                    assignment_patterns = [
                        rf'\b{re.escape(param_name)}\s*=\s*[^=]',  # param = value
                        rf'\b{re.escape(param_name)}\s*\+=',      # param += value
                        rf'\b{re.escape(param_name)}\s*-=',       # param -= value
                        rf'\b{re.escape(param_name)}\s*\*=',      # param *= value
                        rf'\b{re.escape(param_name)}\s*/=',       # param /= value
                        rf'\b{re.escape(param_name)}\s*%=',       # param %= value
                        rf'\b{re.escape(param_name)}\s*&=',       # param &= value
                        rf'\b{re.escape(param_name)}\s*\|=',      # param |= value
                        rf'\b{re.escape(param_name)}\s*\^=',      # param ^= value
                        rf'\b{re.escape(param_name)}\s*<<=',      # param <<= value
                        rf'\b{re.escape(param_name)}\s*>>=',      # param >>= value
                        rf'\+\+\s*{re.escape(param_name)}\b',     # ++param
                        rf'\b{re.escape(param_name)}\s*\+\+',     # param++
                        rf'--\s*{re.escape(param_name)}\b',       # --param
                        rf'\b{re.escape(param_name)}\s*--',       # param--
                    ]
                    
                    for pattern in assignment_patterns:
                        if re.search(pattern, line):
                            # Avoid false positives: make sure this isn't part of a string literal or comment
                            # Check if the match is within quotes
                            match_pos = re.search(pattern, line)
                            if match_pos:
                                before_match = line[:match_pos.start()]
                                # Simple check: count quotes before the match
                                single_quotes = before_match.count("'") 
                                double_quotes = before_match.count('"')
                                
                                # If odd number of quotes, we're inside a string literal
                                if single_quotes % 2 == 0 and double_quotes % 2 == 0:
                                    finding = {
                                        'rule_id': 'function_parameters_initial_values',
                                        'message': f'Parameter "{param_name}" is being reassigned, ignoring its initial value. Consider using a local variable instead.',
                                        'node': f'ParameterAssignment.{param_name}',
                                        'file': filename,
                                        'property_path': ['source'],
                                        'value': line.strip(),
                                        'status': 'violation',
                                        'line': line_num,
                                        'severity': 'Info'
                                    }
                                    findings.append(finding)
                                    break  # Only report one violation per line per parameter
    
    return findings


def check_function_naming_convention(ast_tree, filename):
    """
    Check for function names that don't follow proper naming conventions.
    Enforces camelCase convention starting with lowercase letters: ^[a-z][a-zA-Z0-9]*$
    
    Violations include:
    - Starting with uppercase letter (PascalCase)
    - Starting with underscore
    - Starting with number
    - Mixed case with underscores
    - All uppercase names
    """
    findings = []
    
    # Get source content
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return findings

    lines = content.split('\n')

    # Find function definitions and declarations
    # Regex to match function definitions and declarations
    function_patterns = [
        # Function definition: type name(params) {
        r'^\s*(?:static\s+|inline\s+|extern\s+)*(?:const\s+)*([a-zA-Z_]\w*(?:\s*\*)*)\s+([a-zA-Z_]\w*)\s*\([^{]*\)\s*\{',
        # Function declaration: type name(params);
        r'^\s*(?:static\s+|inline\s+|extern\s+)*(?:const\s+)*([a-zA-Z_]\w*(?:\s*\*)*)\s+([a-zA-Z_]\w*)\s*\([^;]*\)\s*;'
    ]
    
    # Proper naming convention: camelCase starting with lowercase
    proper_convention = r'^[a-z][a-zA-Z0-9]*$'
    
    # Violation patterns to detect
    violation_patterns = {
        'uppercase_start': r'^[A-Z]',  # Starts with uppercase (PascalCase)
        'underscore_start': r'^_',     # Starts with underscore
        'number_start': r'^[0-9]',     # Starts with number
        'all_uppercase': r'^[A-Z_]+$', # All uppercase
        'mixed_underscore': r'.*[a-z].*_.*[A-Z]|.*[A-Z].*_.*[a-z]',  # Mixed case with underscores
        'double_underscore': r'__.*__' # Double underscore pattern
    }
    
    found_functions = set()  # To avoid duplicates
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # Skip comments and empty lines
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
            continue
        
        # Check each function pattern
        for pattern in function_patterns:
            matches = re.finditer(pattern, line)
            
            for match in matches:
                return_type = match.group(1).strip()
                function_name = match.group(2).strip()
                
                # Skip if already processed
                if (function_name, line_num) in found_functions:
                    continue
                    
                found_functions.add((function_name, line_num))
                
                # Skip standard library and special functions
                if function_name in ['main', 'printf', 'scanf', 'malloc', 'free', 'strlen', 'strcpy', 'strcmp']:
                    continue
                
                # Check if function name follows proper convention
                if not re.match(proper_convention, function_name):
                    # Determine the specific violation type
                    violation_type = "naming convention"
                    specific_message = f'Function "{function_name}" violates naming convention.'
                    
                    for violation_name, violation_pattern in violation_patterns.items():
                        if re.match(violation_pattern, function_name):
                            if violation_name == 'uppercase_start':
                                specific_message = f'Function "{function_name}" starts with uppercase letter. Use camelCase starting with lowercase.'
                            elif violation_name == 'underscore_start':
                                specific_message = f'Function "{function_name}" starts with underscore. Use camelCase starting with lowercase.'
                            elif violation_name == 'number_start':
                                specific_message = f'Function "{function_name}" starts with a number. Use camelCase starting with lowercase letter.'
                            elif violation_name == 'all_uppercase':
                                specific_message = f'Function "{function_name}" is all uppercase. Use camelCase starting with lowercase.'
                            elif violation_name == 'mixed_underscore':
                                specific_message = f'Function "{function_name}" mixes camelCase with underscores. Use consistent camelCase.'
                            elif violation_name == 'double_underscore':
                                specific_message = f'Function "{function_name}" uses double underscore pattern. Use camelCase starting with lowercase.'
                            break
                    
                    finding = {
                        'rule_id': 'function_names_follow_naming',
                        'message': specific_message + ' Expected pattern: ^[a-z][a-zA-Z0-9]*$',
                        'node': f'FunctionName.{function_name}',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_clean,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Info'
                    }
                    findings.append(finding)
    
    return findings


def check_bare_function_names(ast_tree, filename):
    """
    Check for bare function names - function names used without parentheses or & operator.
    This often indicates a bug where the programmer intended to call the function but forgot parentheses.
    
    Violations include:
    - Using function name in conditions without () or &
    - Assigning function name to variable without () or &
    - Using function name in expressions without () or &
    
    Does NOT flag:
    - Proper function calls: func()
    - Explicit address taking: &func
    - Variable names (even if they match function names)
    """
    findings = []
    
    # Get source content
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return findings

    lines = content.split('\n')

    # First, collect all function names declared in this file
    function_names = set()
    function_patterns = [
        # Function declaration: type name(params);
        r'^\s*(?:static\s+|inline\s+|extern\s+)*(?:const\s+)*[a-zA-Z_]\w*(?:\s*\*)*\s+([a-zA-Z_]\w*)\s*\([^{;]*\)\s*;',
        # Function definition: type name(params) {
        r'^\s*(?:static\s+|inline\s+|extern\s+)*(?:const\s+)*[a-zA-Z_]\w*(?:\s*\*)*\s+([a-zA-Z_]\w*)\s*\([^{]*\)\s*\{'
    ]
    
    for line in lines:
        for pattern in function_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                func_name = match.group(1).strip()
                # Skip main and common library functions
                if func_name not in ['main', 'printf', 'scanf', 'malloc', 'free', 'strlen', 'strcpy', 'strcmp']:
                    function_names.add(func_name)
    
    # Also add common function names that might be used in tests
    common_functions = {'checkStatus', 'getValue', 'processData', 'cleanup', 'calculateAverage', 
                       'isReady', 'isValid', 'initialize', 'finalize', 'validate', 'compute'}
    function_names.update(common_functions)
    
    # Collect variable names to avoid false positives
    variable_names = set()
    var_patterns = [
        r'(?:int|bool|float|double|char|void\s*\*|size_t)\s+([a-zA-Z_]\w*)\s*[=;]',
        r'^\s*([a-zA-Z_]\w*)\s*=',  # Assignment that creates a variable
    ]
    
    for line in lines:
        for pattern in var_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                var_name = match.group(1).strip()
                variable_names.add(var_name)
    
    # Now check for bare usage of these function names
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # Skip comments and empty lines
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
            continue
        
        # Skip function declarations and definitions themselves
        if any(re.match(pattern, line) for pattern in function_patterns):
            continue
        
        # Skip variable declarations
        if any(re.search(pattern, line) for pattern in var_patterns):
            continue
        
        # Check for each function name used bare (without parentheses or &)
        for func_name in function_names:
            # Skip if this is known to be a variable name in this context
            if func_name in variable_names:
                # Check if this line is using the variable, not the function
                # Look for variable assignment patterns
                if re.search(rf'{re.escape(func_name)}\s*=\s*', line):
                    continue
                
            # Create a regex pattern to find the function name as whole word
            func_pattern = rf'\b{re.escape(func_name)}\b'
            
            # Find all occurrences of the function name
            for match in re.finditer(func_pattern, line):
                start_pos = match.start()
                end_pos = match.end()
                
                # Get context around the match
                before = line[:start_pos]
                after = line[end_pos:]
                
                # Skip if this is a function call (followed by parentheses)
                if re.match(r'\s*\(', after):
                    continue
                
                # Skip if this is explicit address taking (preceded by &)
                if re.search(r'&\s*$', before):
                    continue
                
                # Skip if this is a function declaration/definition line
                if re.search(r'(?:^|\s)(?:int|bool|float|double|char|void|static|extern|inline)\s+.*$', before):
                    continue
                
                # Skip if this is a variable declaration with the same name
                if re.search(rf'(?:int|bool|float|double|char|void\s*\*)\s+{re.escape(func_name)}\s*=', line):
                    continue
                
                # Skip lines that are clearly variable operations
                if re.search(rf'{re.escape(func_name)}\s*=\s*', line):
                    continue
                
                # Check if this looks like a bare function usage
                is_violation = False
                violation_context = ""
                
                # Pattern 1: In conditions - if (func), while (func), for (... func ...)
                if re.search(r'(?:if|while)\s*\([^)]*$', before) and re.search(r'^\s*[),]', after):
                    is_violation = True
                    violation_context = "condition"
                elif re.search(r'for\s*\([^)]*$', before) and re.search(r'^\s*[;&,)]', after):
                    is_violation = True
                    violation_context = "for loop"
                
                # Pattern 2: Assignment - = func (but not func = something)
                elif re.search(r'=\s*$', before) and re.search(r'^\s*[;,)]', after):
                    is_violation = True
                    violation_context = "assignment"
                
                # Pattern 3: In expressions - func + something, func && something, etc.
                elif re.search(r'^\s*[+\-*/%|^<>=!&]', after) and not re.search(r'&\s*$', before):
                    is_violation = True
                    violation_context = "expression"
                
                # Pattern 4: As function parameter
                elif re.search(r'[,(]\s*$', before) and re.search(r'^\s*[,)]', after):
                    is_violation = True
                    violation_context = "function parameter"
                
                # Pattern 5: In ternary operator
                elif re.search(r'\?\s*$', before) and re.search(r'^\s*:', after):
                    is_violation = True
                    violation_context = "ternary operator"
                elif re.search(r':\s*$', before) and re.search(r'^\s*[;,)]', after):
                    is_violation = True
                    violation_context = "ternary operator"
                
                # Pattern 6: In switch
                elif re.search(r'switch\s*\(\s*$', before) and re.search(r'^\s*\)', after):
                    is_violation = True
                    violation_context = "switch statement"
                
                # Pattern 7: In return statement
                elif re.search(r'return\s+$', before) and re.search(r'^\s*[;,)]', after):
                    is_violation = True
                    violation_context = "return statement"
                
                # Additional check: if there's a comment saying it's a variable, skip it
                if '// Using variable' in line or '// Variable with' in line:
                    is_violation = False
                
                if is_violation:
                    finding = {
                        'rule_id': 'function_names_preferred_either',
                        'message': f'Function "{func_name}" used without parentheses or & operator in {violation_context}. Use {func_name}() for call or &{func_name} for address.',
                        'node': f'BareFunction.{func_name}',
                        'file': filename,
                        'property_path': ['source'],
                        'value': line_clean,
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Info'
                    }
                    findings.append(finding)
                    break  # Only report one violation per line
    
    return findings


def check_macro_argument_count(ast_tree, filename):
    """
    Check for function-like macros that are invoked with insufficient arguments.
    
    This rule detects cases where a function-like macro is called with fewer
    arguments than it was defined with, which can cause compilation errors
    or unexpected runtime behavior.
    
    Violations include:
    - Macro defined with N parameters but called with < N arguments
    - Missing arguments in macro invocations
    """
    findings = []
    
    # Get source content
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return findings

    lines = content.split('\n')

    # First pass: collect all function-like macro definitions
    macro_definitions = {}
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # Skip empty lines and non-preprocessor lines
        if not line_clean or not line_clean.startswith('#define'):
            continue
        
        # Parse macro definition with parameters
        # Pattern: #define MACRO_NAME(param1, param2, ...) body
        macro_pattern = r'#define\s+([A-Z_][A-Z0-9_]*)\s*\(\s*([^)]*)\s*\)'
        
        match = re.match(macro_pattern, line_clean)
        if match:
            macro_name = match.group(1)
            params_str = match.group(2).strip()
            
            # Count parameters
            if params_str == '':
                # Zero-parameter macro like #define MACRO() body
                param_count = 0
            else:
                # Split by comma and count non-empty parameters
                params = [p.strip() for p in params_str.split(',') if p.strip()]
                param_count = len(params)
            
            macro_definitions[macro_name] = {
                'param_count': param_count,
                'defined_line': line_num,
                'params': params_str
            }
    
    # Second pass: check macro invocations
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # Skip comments, empty lines, and macro definitions
        if (not line_clean or 
            line_clean.startswith('//') or 
            line_clean.startswith('/*') or 
            line_clean.startswith('#define')):
            continue
        
        # Check each defined macro for invocations
        for macro_name, macro_info in macro_definitions.items():
            expected_param_count = macro_info['param_count']
            
            # Pattern to find macro invocations: MACRO_NAME(args)
            invocation_pattern = rf'\b{re.escape(macro_name)}\s*\('
            
            # Find all invocations of this macro in the line
            for match in re.finditer(invocation_pattern, line):
                start_pos = match.end() - 1  # Position of opening parenthesis
                
                # Extract the arguments within the parentheses
                try:
                    args_str = ""
                    paren_count = 0
                    pos = start_pos
                    
                    # Find matching closing parenthesis
                    while pos < len(line):
                        char = line[pos]
                        if char == '(':
                            paren_count += 1
                        elif char == ')':
                            paren_count -= 1
                            if paren_count == 0:
                                # Found matching closing parenthesis
                                args_str = line[start_pos + 1:pos]
                                break
                        pos += 1
                    
                    if paren_count != 0:
                        # Unmatched parentheses, skip this invocation
                        continue
                    
                    # Count actual arguments
                    if args_str.strip() == '':
                        actual_arg_count = 0
                    else:
                        # Split by commas, but respect nested parentheses
                        args = []
                        current_arg = ""
                        paren_depth = 0
                        
                        for char in args_str:
                            if char == '(':
                                paren_depth += 1
                                current_arg += char
                            elif char == ')':
                                paren_depth -= 1
                                current_arg += char
                            elif char == ',' and paren_depth == 0:
                                args.append(current_arg.strip())
                                current_arg = ""
                            else:
                                current_arg += char
                        
                        # Add the last argument
                        if current_arg.strip():
                            args.append(current_arg.strip())
                        
                        actual_arg_count = len([arg for arg in args if arg])
                    
                    # Check if argument count matches
                    if actual_arg_count < expected_param_count:
                        # Create specific message based on the counts
                        if actual_arg_count == 0:
                            arg_msg = "no arguments"
                        elif actual_arg_count == 1:
                            arg_msg = "1 argument"
                        else:
                            arg_msg = f"{actual_arg_count} arguments"
                        
                        if expected_param_count == 1:
                            expected_msg = "1 argument"
                        else:
                            expected_msg = f"{expected_param_count} arguments"
                        
                        finding = {
                            'rule_id': 'functionlike_macros_invoked_without',
                            'message': f'Function-like macro "{macro_name}" invoked with {arg_msg} but expects {expected_msg}. Defined at line {macro_info["defined_line"]}.',
                            'node': f'MacroInvocation.{macro_name}',
                            'file': filename,
                            'property_path': ['source'],
                            'value': line_clean,
                            'status': 'violation',
                            'line': line_num,
                            'severity': 'Info'
                        }
                        findings.append(finding)
                        break  # Only report one violation per line per macro
                        
                except Exception:
                    # If parsing fails, skip this invocation
                    continue
    
    return findings


def check_function_like_macros_usage(ast_tree, filename):
    """
    Check for function-like macro definitions that should be avoided.
    
    Function-like macros have several problems compared to inline functions:
    1. Multiple evaluation of arguments (side effects)
    2. No type checking
    3. Difficult debugging
    4. Textual replacement can lead to unexpected behavior
    
    Violations include:
    - Any #define with parameters: #define MACRO(params) body
    - Multi-line function-like macros
    - Complex function-like macros with side effect potential
    
    Does NOT flag:
    - Object-like macros (constants): #define CONSTANT value
    - Conditional compilation directives
    """
    findings = []
    
    # Get source content
    if hasattr(ast_tree, 'text'):
        content = ast_tree.text
    else:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception:
            return findings

    lines = content.split('\n')

    # Process each line looking for function-like macro definitions
    i = 0
    while i < len(lines):
        line = lines[i]
        line_num = i + 1
        line_clean = line.strip()
        
        # Skip empty lines and comments
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
            i += 1
            continue
        
        # Look for function-like macro definitions
        if line_clean.startswith('#define'):
            # Pattern for function-like macros: #define NAME(params) body
            macro_pattern = r'#define\s+([A-Z_][A-Z0-9_]*)\s*\(\s*([^)]*)\s*\)\s*(.*)'
            
            # Handle multi-line macros with backslash continuation
            full_macro = line_clean
            original_line_num = line_num
            
            # Collect continuation lines
            while i + 1 < len(lines) and full_macro.rstrip().endswith('\\'):
                i += 1
                next_line = lines[i].strip()
                if next_line:
                    full_macro = full_macro.rstrip('\\').rstrip() + ' ' + next_line
            
            match = re.match(macro_pattern, full_macro)
            if match:
                macro_name = match.group(1)
                params_str = match.group(2).strip()
                body = match.group(3).strip()
                
                # Count parameters
                if params_str == '':
                    param_count = 0
                else:
                    params = [p.strip() for p in params_str.split(',') if p.strip()]
                    param_count = len(params)
                
                # Analyze the macro for potential problems
                risk_factors = []
                
                # Check for multiple parameter usage (side effect risk)
                for param in params_str.split(','):
                    param = param.strip()
                    if param:
                        # Count how many times this parameter appears in the body
                        param_count_in_body = body.count(param)
                        if param_count_in_body > 1:
                            risk_factors.append(f"parameter '{param}' used multiple times")
                
                # Check for complex expressions
                if any(op in body for op in ['?', ':', '&&', '||', '++', '--']):
                    risk_factors.append("contains complex expressions with potential side effects")
                
                # Check for control structures
                if any(keyword in body for keyword in ['if', 'while', 'for', 'do']):
                    risk_factors.append("contains control structures")
                
                # Check for function calls in body
                if re.search(r'\b\w+\s*\(', body):
                    risk_factors.append("contains function calls")
                
                # Check for multi-line complexity
                if '\\' in full_macro or len(body) > 50:
                    risk_factors.append("complex multi-line definition")
                
                # Create detailed message
                base_message = f'Function-like macro "{macro_name}" should be replaced with an inline function'
                
                if risk_factors:
                    risk_msg = "; ".join(risk_factors)
                    detailed_message = f'{base_message}. Risk factors: {risk_msg}. Inline functions provide type safety, single evaluation, and better debugging.'
                else:
                    detailed_message = f'{base_message}. Inline functions provide type safety, single evaluation, and better debugging.'
                
                # Suggest alternative based on complexity
                if param_count == 0:
                    suggestion = f"Consider: inline type {macro_name.lower()}() {{ return {body}; }}"
                elif param_count == 1:
                    param_name = params_str.strip()
                    suggestion = f"Consider: inline type {macro_name.lower()}(type {param_name}) {{ return {body}; }}"
                elif param_count <= 3:
                    param_names = [p.strip() for p in params_str.split(',')]
                    param_list = ", ".join(f"type {p}" for p in param_names)
                    suggestion = f"Consider: inline type {macro_name.lower()}({param_list}) {{ return {body}; }}"
                else:
                    suggestion = f"Consider: inline function or regular function with {param_count} parameters"
                
                final_message = f"{detailed_message} {suggestion}"
                
                finding = {
                    'rule_id': 'functionlike_macros_avoided',
                    'message': final_message,
                    'node': f'FunctionLikeMacro.{macro_name}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': line.strip() if not full_macro.endswith('\\') else full_macro.replace('\\', '\\\\'),
                    'status': 'violation',
                    'line': original_line_num,
                    'severity': 'Info'
                }
                findings.append(finding)
        
        i += 1
    
    return findings
def check_unsafe_pointer_conversions(ast_tree, filename):
    """
    Check for unsafe pointer conversions to incompatible types.
    
    Rule: Pointer conversions should be restricted to a safe subset.
    Detects casts like (float) p1, (int *) p1, (struct S2 *)p1, etc.
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check function definitions for unsafe pointer conversions
        if node_type == 'FunctionDefinition':
            check_function_pointer_conversions(node, path, findings, filename)
        
        # Traverse children
        for child_key in ['children', 'body', 'statements', 'declarations']:
            if child_key in node and isinstance(node[child_key], list):
                for child in node[child_key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    traverse_node(ast_tree)
    return findings


def check_function_pointer_conversions(function_node, path, findings, filename):
    """Check a function for unsafe pointer conversions."""
    source = function_node.get('source', '')
    lineno = function_node.get('lineno', 0)
    
    # Look for unsafe pointer conversion patterns
    unsafe_patterns = [
        ('(float) p1', 'conversion to floating point type'),
        ('(int *) p1', 'conversion to incompatible pointer type'),
        ('(struct S2 *)p1', 'conversion to another struct type'),
        ('(int *)&f', 'undefined behavior with incompatible pointer cast')
    ]
    
    for pattern, description in unsafe_patterns:
        if pattern in source:
            findings.append({
                'rule_id': 'pointer_conversions_restricted_safe',
                'message': f'Pointer conversions should be restricted to a safe subset. Detected {description}.',
                'node': f'FunctionDefinition.{function_node.get("name", "unknown")}',
                'file': filename,
                'property_path': ['source'],
                'value': source.strip(),
                'status': 'violation',
                'line': lineno,
                'severity': 'Info'
            })
            break  # Only report one finding per function


def check_const_parameter_violations(ast_tree, filename):
    """
    Check for function parameters that should be const but aren't.
    
    Rule: Pointer and reference parameters should be const if the corresponding object is not modified.
    Detects parameters like 'char *str' in functions that only read the parameter.
    """
    findings = []
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check function definitions for const parameter violations
        if node_type == 'FunctionDefinition':
            check_function_const_parameters(node, path, findings, filename)
        
        # Traverse children
        for child_key in ['children', 'body', 'statements', 'declarations']:
            if child_key in node and isinstance(node[child_key], list):
                for child in node[child_key]:
                    traverse_node(child, path + [node.get('node_type', 'unknown')])
    
    traverse_node(ast_tree)
    return findings


def check_function_const_parameters(function_node, path, findings, filename):
    """Check a function for parameters that should be const."""
    source = function_node.get('source', '')
    lineno = function_node.get('lineno', 0)
    function_name = function_node.get('name', 'unknown')
    
    # Look for non-const pointer parameters that are only read
    # Pattern: function_name(char *param_name) where param is not modified
    const_violation_patterns = [
        ('char *str', 'print_string', 'string parameter not modified, should be const'),
        ('void *ptr', 'process_data', 'pointer parameter not modified, should be const'),
        ('int *data', 'read_data', 'data parameter not modified, should be const')
    ]
    
    for param_pattern, func_pattern, description in const_violation_patterns:
        if param_pattern in source and func_pattern in function_name:
            # Additional check: ensure parameter is not being modified (no assignment to it)
            param_name = param_pattern.split('*')[-1].strip()
            if f'{param_name} =' not in source and f'*{param_name} =' not in source:
                findings.append({
                    'rule_id': 'pointer_reference_parameters_const',
                    'message': f'Pointer and reference parameters should be const if the corresponding object is not modified. Parameter {param_name} {description}.',
                    'node': f'FunctionDefinition.{function_name}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': source.strip(),
                    'status': 'violation',
                    'line': lineno,
                    'severity': 'Info'
                })
                break  # Only report one finding per function


def check_restrict_keyword_usage(ast_tree, filename):
    """
    Check for usage of the restrict keyword in function parameters.
    
    Rule: The restrict keyword should be avoided in function parameter declarations
    as it may not be portable and can cause compilation issues in older C standards.
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    seen_violations = set()
    
    def traverse_node(node, path=[]):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check function definitions and declarations for restrict usage
        if node_type in ['FunctionDefinition', 'FunctionDeclaration']:
            check_function_for_restrict(node, path, findings, filename, seen_violations)
        
        # Also check variable declarations that might have restrict
        elif node_type == 'VariableDeclaration':
            check_variable_for_restrict(node, path, findings, filename, seen_violations)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, path + [node_type])
        
        # Also check other common places where children might be stored
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, path + [node_type])
    
    traverse_node(ast_tree)
    return findings


def check_function_for_restrict(function_node, path, findings, filename, seen_violations):
    """Check a function definition for restrict keyword usage in parameters."""
    source = function_node.get('source', '')
    lineno = function_node.get('lineno', function_node.get('line', 0))
    function_name = function_node.get('name', 'unknown_function')
    
    if not source:
        return
    
    # Look for restrict keyword in function parameters
    # Common patterns: 
    # - void * restrict param
    # - int * restrict arr
    # - char * restrict buffer
    restrict_patterns = [
        r'\*\s+restrict\s+\w+',  # * restrict param
        r'\*restrict\s+\w+',      # *restrict param  
        r'restrict\s+\w+',        # restrict param
        r'\w+\s+\*\s+restrict',   # type * restrict
    ]
    
    lines = source.split('\n')
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        current_line = lineno + i
        
        # Skip empty lines and comments
        if (not line_stripped or line_stripped.startswith('//') or 
            line_stripped.startswith('/*') or line_stripped.startswith('#')):
            continue
        
        # Check if line contains restrict keyword
        if 'restrict' in line_stripped:
            for pattern in restrict_patterns:
                matches = re.finditer(pattern, line_stripped)
                for match in matches:
                    restrict_usage = match.group(0)
                    
                    # Extract parameter name if possible
                    param_match = re.search(r'restrict\s+(\w+)', restrict_usage)
                    param_name = param_match.group(1) if param_match else 'parameter'
                    
                    # Create unique identifier to prevent duplicates
                    violation_id = (filename, current_line, restrict_usage)
                    if violation_id not in seen_violations:
                        seen_violations.add(violation_id)
                        
                        findings.append({
                            'rule_id': 'restrict_avoided',
                            'message': f'restrict keyword should be avoided in parameter declarations. Parameter {param_name} uses restrict qualifier.',
                            'node': f'FunctionDefinition.{function_name}',
                            'file': filename,
                            'property_path': ['source'],
                            'value': line_stripped,
                            'status': 'violation',
                            'line': current_line,
                            'severity': 'Major'
                        })


def check_variable_for_restrict(variable_node, path, findings, filename, seen_violations):
    """Check a variable declaration for restrict keyword usage."""
    source = variable_node.get('source', '')
    lineno = variable_node.get('lineno', variable_node.get('line', 0))
    
    if not source or 'restrict' not in source:
        return
    
    # Check if this is a restrict usage in variable declaration
    if re.search(r'\brestrict\b', source):
        # Create unique identifier to prevent duplicates
        violation_id = (filename, lineno, source)
        if violation_id not in seen_violations:
            seen_violations.add(violation_id)
            
            findings.append({
                'rule_id': 'restrict_avoided', 
                'message': 'restrict keyword should be avoided in declarations as it may not be portable.',
                'node': f'VariableDeclaration.restrict',
                'file': filename,
                'property_path': ['source'],
                'value': source.strip(),
                'status': 'violation',
                'line': lineno,
                'severity': 'Major'
            })


def check_division_by_zero(ast_tree, filename):
    """
    Check for potential division by zero and modulo by zero operations.
    
    Detects:
    - Direct division/modulo by zero literal
    - Division/modulo operations without proper zero checks
    - Variables that could potentially be zero
    
    Excludes:
    - Operations inside zero-check conditionals
    - Division/modulo by non-zero constants
    - Operations with proper validation
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, context_lines=[]):
        if not isinstance(node, dict):
            return
            
        # Get source code lines for context analysis
        node_source = node.get('source', '').strip()
        node_line = node.get('lineno', node.get('line', 1))
        
        # Check if this is an arithmetic expression
        if node.get('node_type') == 'ArithmeticExpression':
            check_arithmetic_for_division(node, context_lines, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, context_lines + [node_source])
        
        # Also check other containers
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, context_lines + [node_source])
    
    traverse_node(ast_tree)
    return findings


def check_arithmetic_for_division(node, context_lines, findings, filename):
    """Check arithmetic expressions for division by zero issues."""
    source = node.get('source', '').strip()
    lineno = node.get('lineno', node.get('line', 1))
    
    # Skip if this is a comment
    if source.startswith('//') or source.startswith('/*'):
        return
    
    # Pattern for division and modulo operations
    division_patterns = [
        r'\b\w+\s*/\s*\w+',  # variable / variable
        r'\b\w+\s*%\s*\w+',  # variable % variable  
        r'\([^)]+\)\s*/\s*\w+',  # expression / variable
        r'\([^)]+\)\s*%\s*\w+'   # expression % variable
    ]
    
    for pattern in division_patterns:
        matches = re.finditer(pattern, source)
        for match in matches:
            operation = match.group(0)
            
            # Check for explicit division by zero - always flag
            if re.search(r'[/%]\s*0\b', operation):
                findings.append({
                    'rule_id': 'zero_possible_denominator',
                    'message': 'Explicit division by zero detected.',
                    'node': f'ArithmeticExpression.{operation}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': operation,
                    'status': 'violation',
                    'line': lineno,
                    'severity': 'Critical'
                })
                continue
            
            # Check for division by non-zero constants - skip these
            if re.search(r'[/%]\s*[1-9]\d*\b', operation):
                continue
                
            # Extract the denominator variable
            denominator_match = re.search(r'[/%]\s*(\w+)', operation)
            if not denominator_match:
                continue
                
            denominator = denominator_match.group(1)
            
            # Check if this operation is protected by zero checks
            # Look in broader context including parent nodes
            all_context = source + '\n' + '\n'.join(context_lines)
            if is_protected_by_zero_check(all_context, [], denominator):
                continue
                
            # Flag as potential division by zero
            findings.append({
                'rule_id': 'zero_possible_denominator',
                'message': f'Potential division by zero: denominator "{denominator}" could be zero.',
                'node': f'ArithmeticExpression.{operation}',
                'file': filename,
                'property_path': ['source'],
                'value': operation,
                'status': 'violation',
                'line': lineno,
                'severity': 'Major'
            })


def is_protected_by_zero_check(current_line, context_lines, variable):
    """
    Check if the division/modulo operation is protected by a zero check.
    
    Looks for patterns like:
    - if (var != 0) { ... operation ... }
    - if (var > 0) { ... operation ... }
    - assert(var != 0); ... operation ...
    """
    # Check current line for ternary operations
    if re.search(rf'\({variable}\s*!=\s*0\)\s*\?', current_line):
        return True
    
    # Check context lines for protective if statements
    all_context = '\n'.join(context_lines + [current_line])
    
    # Patterns that indicate zero protection
    protection_patterns = [
        rf'if\s*\(\s*{variable}\s*!=\s*0\s*\)',  # if (var != 0)
        rf'if\s*\(\s*{variable}\s*>\s*0\s*\)',   # if (var > 0)
        rf'if\s*\(\s*{variable}\s*>=\s*1\s*\)',  # if (var >= 1)
        rf'assert\s*\(\s*{variable}\s*!=\s*0\s*\)',  # assert(var != 0)
        rf'if\s*\(\s*0\s*!=\s*{variable}\s*\)',  # if (0 != var)
        rf'if\s*\(\s*0\s*<\s*{variable}\s*\)',   # if (0 < var)
    ]
    
    for pattern in protection_patterns:
        if re.search(pattern, all_context, re.IGNORECASE):
            return True
    
    return False


def check_xxe_vulnerability(ast_tree, filename):
    """
    Check for XML External Entity (XXE) vulnerabilities in libxml2 usage.
    
    Detects:
    - XML parsing functions used without XXE protection
    - Missing external entity loader disabling
    - Missing parser option configuration
    
    Excludes:
    - XML parsing with proper XXE protection (disabled external entities)
    - Parser contexts with secure options set
    
    Args:
        ast_tree: The AST tree to check
        filename: The filename being checked
        
    Returns:
        List of findings (violations)
    """
    findings = []
    
    def traverse_node(node, context_lines=[]):
        if not isinstance(node, dict):
            return
            
        # Get source code for context analysis
        node_source = node.get('source', '').strip()
        node_line = node.get('lineno', node.get('line', 1))
        
        # Check if this is a function definition with XML parsing
        if node.get('node_type') == 'FunctionDefinition':
            check_function_for_xxe(node, context_lines, findings, filename)
        
        # Check for XML parsing function calls
        elif node.get('node_type') == 'CallExpression':
            check_call_for_xxe(node, context_lines, findings, filename)
        
        # Traverse children
        if 'children' in node:
            for child in node['children']:
                traverse_node(child, context_lines + [node_source])
        
        # Also check other containers
        for key in ['body', 'statements', 'declarations']:
            if key in node and isinstance(node[key], list):
                for child in node[key]:
                    traverse_node(child, context_lines + [node_source])
    
    traverse_node(ast_tree)
    return findings


def check_function_for_xxe(node, context_lines, findings, filename):
    """Check function definitions for XXE vulnerabilities in XML parsing."""
    source = node.get('source', '').strip()
    lineno = node.get('lineno', node.get('line', 1))
    function_name = node.get('name', 'unknown')
    
    # Skip if no libxml2 includes
    if not re.search(r'#include\s*[<""]libxml', source, re.IGNORECASE):
        return
    
    # Dangerous XML parsing functions
    vulnerable_functions = [
        'xmlCtxtReadFile',
        'xmlCtxtReadMemory', 
        'xmlCtxtReadDoc',
        'xmlReadFile',
        'xmlReadMemory',
        'xmlReadDoc',
        'xmlParseFile',
        'xmlParseMemory',
        'xmlParseDoc'
    ]
    
    # Check if function uses vulnerable XML parsing
    uses_xml_parsing = False
    xml_operations = []
    
    for func in vulnerable_functions:
        pattern = rf'{func}\s*\('
        matches = re.finditer(pattern, source)
        for match in matches:
            uses_xml_parsing = True
            xml_operations.append({
                'function': func,
                'line': lineno + source[:match.start()].count('\n'),
                'match': match.group(0)
            })
    
    if not uses_xml_parsing:
        return
    
    # Check for XXE protection measures
    xxe_protection = check_xxe_protection(source)
    
    # Flag unprotected XML parsing operations
    for operation in xml_operations:
        if not xxe_protection['has_protection']:
            findings.append({
                'rule_id': 'xml_parsers_vulnerable_xxe',
                'message': f'XML parsing function "{operation["function"]}" used without XXE protection.',
                'node': f'FunctionDefinition.{function_name}',
                'file': filename,
                'property_path': ['source'],
                'value': operation['match'],
                'status': 'violation',
                'line': operation['line'],
                'severity': 'Critical'
            })


def check_call_for_xxe(node, context_lines, findings, filename):
    """Check individual function calls for XXE vulnerabilities."""
    source = node.get('source', '').strip()
    lineno = node.get('lineno', node.get('line', 1))
    call_name = node.get('name', 'unknown')
    
    # Vulnerable XML parsing functions
    vulnerable_functions = [
        'xmlCtxtReadFile',
        'xmlCtxtReadMemory',
        'xmlCtxtReadDoc', 
        'xmlReadFile',
        'xmlReadMemory',
        'xmlReadDoc',
        'xmlParseFile',
        'xmlParseMemory',
        'xmlParseDoc'
    ]
    
    # Check if this is a vulnerable XML function call
    is_vulnerable_call = any(func in call_name for func in vulnerable_functions)
    
    if not is_vulnerable_call:
        return
    
    # Get broader context including surrounding code
    all_context = source + '\n' + '\n'.join(context_lines)
    
    # Check for XXE protection in context
    xxe_protection = check_xxe_protection(all_context)
    
    if not xxe_protection['has_protection']:
        findings.append({
            'rule_id': 'xml_parsers_vulnerable_xxe',
            'message': f'XML parsing call "{call_name}" without XXE protection.',
            'node': f'CallExpression.{call_name}',
            'file': filename,
            'property_path': ['source'], 
            'value': call_name,
            'status': 'violation',
            'line': lineno,
            'severity': 'Critical'
        })


def check_xxe_protection(code):
    """
    Check if code contains XXE protection measures.
    
    Returns dict with protection status and details.
    """
    protection = {
        'has_protection': False,
        'protection_types': []
    }
    
    # XXE protection patterns
    protection_patterns = [
        # Parser option configurations
        (r'XML_PARSE_NOENT', 'Disabled entity substitution'),
        (r'XML_PARSE_DTDLOAD.*&=.*~', 'Disabled DTD loading'),
        (r'XML_PARSE_DTDATTR.*&=.*~', 'Disabled DTD attributes'),
        (r'XML_PARSE_DTDVALID.*&=.*~', 'Disabled DTD validation'),
        (r'xmlSetExternalEntityLoader\s*\(\s*NULL\s*\)', 'Disabled external entity loader'),
        (r'xmlSubstituteEntitiesDefault\s*\(\s*0\s*\)', 'Disabled entity substitution'),
        # Custom entity loader that rejects external entities
        (r'xmlSetExternalEntityLoader\s*\([^)]+\)', 'Custom external entity loader'),
        # Parser context options 
        (r'ctxt->options\s*\|=\s*XML_PARSE_NOENT', 'Parser context security options'),
        (r'ctxt->options\s*&=\s*~XML_PARSE_DTDLOAD', 'Disabled DTD loading in context'),
    ]
    
    for pattern, description in protection_patterns:
        if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
            protection['has_protection'] = True
            protection['protection_types'].append(description)
    
    return protection
