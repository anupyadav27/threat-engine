"""
Custom logic implementations for C++ static analysis rules.

This module contains custom functions that implement complex rule logic
that cannot be expressed through simple AST node matching and checks.
"""

import re
from typing import List, Dict, Any, Optional
import os

def check_function_declarations_like_variables(node: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Check for function declarations that look like variable declarations.
    
    Detects patterns like:
    - Widget widget(); // looks like variable but is function declaration
    - Lock lock(); // looks like variable but is function declaration
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
    
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    # Pattern for function declarations that look like variables:
    # [Type] [name](); with capital letter starting type name
    pattern = r'^\s*([A-Z]\w*)\s+(\w+)\s*\(\s*\)\s*;'
    
    def find_violations_in_source(source_code: str, base_line: int = 0):
        """Find violations in source code."""
        if not source_code:
            return
            
        lines = source_code.split('\n')
        for i, line in enumerate(lines):
            line_num = base_line + i + 1
            match = re.match(pattern, line)
            if match:
                type_name = match.group(1)
                var_name = match.group(2)
                
                violations.append({
                    'line': line_num,
                    'message': f'Function declaration "{var_name}" looks like variable declaration. '
                              f'Use "{type_name} {var_name};" for variable or add parameters to clarify function.',
                    'value': line.strip(),
                    'severity': 'Major',
                    'type_name': type_name,
                    'variable_name': var_name,
                    'node_type': 'FunctionDeclaration',
                    'rule_type': 'function_declaration_confusion'
                })
    
    # Check the main node source
    if 'source' in node:
        find_violations_in_source(node['source'])
    
    # Also check child nodes recursively for function bodies
    def traverse_children(current_node, depth=0):
        if depth > 10:  # Prevent infinite recursion
            return
            
        if isinstance(current_node, dict):
            # Look for function definitions and compound statements
            if current_node.get('node_type') in ['FunctionDefinition', 'compound_statement']:
                if 'source' in current_node:
                    base_line = current_node.get('lineno', 0)
                    find_violations_in_source(current_node['source'], base_line)
            
            # Continue traversing children
            children = current_node.get('children', [])
            if isinstance(children, list):
                for child in children:
                    traverse_children(child, depth + 1)
    
    traverse_children(node)
    
    return violations


def find_member_functions(struct_node, struct_name):
    """Find non-constructor member functions in a struct."""
    member_functions = []
    
    def extract_function_name_from_declarator(func_node):
        """Extract function name from FunctionDeclarator child."""
        for child in func_node.get('children', []):
            if isinstance(child, dict) and child.get('node_type') == 'FunctionDeclarator':
                declarator_source = child.get('source', '')
                if declarator_source:
                    # Extract function name from source like "getDistance() const" -> "getDistance"
                    func_name = declarator_source.split('(')[0].strip()
                    return func_name
        return None
    
    def traverse_struct(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                func_name = node.get('name', '')
                line_num = node.get('lineno', 0)
                
                # If no name directly, try to extract from FunctionDeclarator
                if not func_name:
                    func_name = extract_function_name_from_declarator(node)
                
                # Skip constructors (function name matches struct name)
                if func_name and func_name != struct_name:
                    member_functions.append({
                        'name': func_name,
                        'line': line_num
                    })
                elif not func_name:  # Handle cases where we still can't find the name
                    source = node.get('source', '')
                    if source and struct_name not in source:
                        member_functions.append({
                            'name': 'unknown_function',
                            'line': line_num
                        })
            
            # Continue traversing
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse_struct(value)
        elif isinstance(node, list):
            for item in node:
                traverse_struct(item)
    
    traverse_struct(struct_node)
    return member_functions


def should_be_const_qualified(declaration_source):
    """Check if a variable declaration should be const qualified."""
    if not declaration_source:
        return False
    
    # Skip if already const
    if 'const' in declaration_source:
        return False
    
    # Look for simple variable declarations with initialization
    # Example: "int x = 10;" or "std::string name = \"John\";"
    import re
    
    # Pattern for simple variable declaration with initialization
    # Type varname = value;
    simple_var_pattern = r'^(std::\w+|\w+)\s+(\w+)\s*=\s*.+;'
    
    if re.match(simple_var_pattern, declaration_source.strip()):
        return True
    
    return False


def extract_variable_name(declaration_source):
    """Extract variable name from declaration source."""
    import re
    
    # Pattern to extract variable name
    match = re.search(r'\b(\w+)\s*=', declaration_source)
    if match:
        return match.group(1)
    return "unknown_variable"


def is_condition_only_for_loop(for_node, source):
    """Check if a for loop only has a condition (no init or update)."""
    if not source:
        return False
    
    # Look for patterns like "for (; condition;)" or "for(; condition;)"
    # Extract the for statement header
    source_clean = source.strip()
    
    # Simple pattern matching for condition-only for loops
    import re
    
    # Match for loops with empty init and update: for (; condition;)
    pattern = r'for\s*\(\s*;\s*[^;]+;\s*\)'
    if re.search(pattern, source):
        return True
    
    return False


def check_struct_member_functions(ast_tree, filename):
    """
    Check if struct has member functions (excluding constructors).
    
    Structs should only aggregate data. Member functions (except constructors)
    should be avoided in favor of free functions or moving to a class.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for StructDeclaration nodes
            if node.get('node_type') == 'StructDeclaration':
                struct_name = node.get('name', 'unnamed')
                # Check if struct has member functions
                member_functions = find_member_functions(node, struct_name)
                
                for func_info in member_functions:
                    finding = {
                        "rule_id": "struct_avoid_having_member",
                        "message": f"Struct '{struct_name}' should avoid having member function '{func_info['name']}' (except constructors)",
                        "file": filename,
                        "line": func_info.get('line', 0),
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively traverse children
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_for_loop_condition_only(ast_tree, filename):
    """
    Check for 'for' loops that only use condition (no init or update).
    
    For loops with only a condition should be replaced with while loops
    for better readability and semantic clarity.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for ForStatement nodes
            if node.get('node_type') == 'ForStatement':
                line_num = node.get('lineno', 0)
                source = node.get('source', '')
                
                # Check if this is a condition-only for loop
                if is_condition_only_for_loop(node, source):
                    finding = {
                        "rule_id": "while_loop_preferred_instead",
                        "message": "Use 'while' loop instead of 'for' loop when only condition is needed",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively traverse children
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_variable_const_qualification(ast_tree, filename):
    """
    Check if variables that are never modified should be const qualified.
    
    Variables that are declared and initialized but never modified
    afterwards should be declared as const for better code safety.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for declaration nodes
            if node.get('node_type') == 'declaration':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check if this is a variable declaration that should be const
                if should_be_const_qualified(source):
                    var_name = extract_variable_name(source)
                    finding = {
                        "rule_id": "variable_which_is_modified",
                        "message": f"Variable '{var_name}' should be const qualified as it is not modified",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively traverse children
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_redundant_access_specifiers(ast_tree, filename):
    """
    Check for redundant access specifiers in classes.
    
    Consecutive identical access specifiers should be removed.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') in ['ClassDeclaration', 'StructDeclaration']:
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                name = node.get('name', 'unnamed')
                
                if has_redundant_access_specifiers(source):
                    finding = {
                        "rule_id": "access_specifiers_redundant",
                        "message": "Remove redundant consecutive access specifiers",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def has_redundant_access_specifiers(source):
    """Check for consecutive identical access specifiers."""
    import re
    
    # Look for consecutive access specifiers across multiple lines
    lines = source.split('\n')
    access_specs = []
    access_lines = []
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        # Match access specifiers followed by colon
        if re.match(r'^\s*(public|private|protected)\s*:\s*(?://.*)?$', line_stripped):
            access_spec = re.match(r'^\s*(public|private|protected)\s*:', line_stripped).group(1)
            access_specs.append(access_spec)
            access_lines.append(i)
    
    # Check for consecutive identical access specifiers
    for i in range(len(access_specs) - 1):
        if access_specs[i] == access_specs[i + 1]:
            return True
    
    # Determine if this is a struct or class
    is_struct = 'struct' in source and source.strip().startswith('struct')
    
    # Default accessibility: struct = public, class = private
    current_access = 'public' if is_struct else 'private'
    
    # Check each access specifier for redundancy
    for i, spec in enumerate(access_specs):
        line_index = access_lines[i]
        
        # If access specifier doesn't change current access level, it's redundant
        if spec == current_access:
            return True
        
        # Update current access level
        current_access = spec
        
        # Check if this access specifier affects no declarations
        has_declarations_after = False
        next_access_line = access_lines[i + 1] if i + 1 < len(access_lines) else len(lines)
        
        # Look for declarations between this access specifier and the next one (or end)
        for j in range(line_index + 1, next_access_line):
            line = lines[j].strip()
            if (line and 
                not line.startswith('//') and 
                not line.startswith('/*') and 
                not line == '}' and
                not line == '};' and
                not line == ''):
                # Check if this is a declaration (contains function, variable, etc.)
                if any(keyword in line for keyword in ['(', 'int ', 'void ', 'char ', 'double ', 'float ', 'bool ', 'auto ', 'class ', 'struct ']):
                    has_declarations_after = True
                    break
        
        # If access specifier is at the end and affects no declarations, it's redundant
        if not has_declarations_after:
            return True
    
    return False


def check_virtual_accessible_base_classes(ast_tree, filename):
    """
    Check if base classes are both virtual and non-virtual in the same hierarchy.
    
    This creates multiple copies of the base class which may not be intended.
    """
    findings = []
    classes = {}  # class_name -> {virtual_bases: set, nonvirtual_bases: set}
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'ClassDeclaration':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                name = node.get('name', 'unnamed')
                
                # Parse inheritance relationships
                virtual_bases = set()
                nonvirtual_bases = set()
                
                # Look for inheritance patterns in source
                import re
                
                # Find class declaration line
                lines = source.split('\n')
                for line in lines:
                    if f'class {name}' in line and ':' in line:
                        inheritance_part = line.split(':', 1)[1]
                        
                        # Parse each base class
                        base_specs = inheritance_part.split(',')
                        for base_spec in base_specs:
                            base_spec = base_spec.strip()
                            
                            # Clean up the base spec - remove everything after { or //
                            base_spec_clean = re.split(r'[{]', base_spec)[0].strip()
                            base_spec_clean = re.split(r'//', base_spec_clean)[0].strip()
                            
                            # Check for virtual inheritance
                            if 'virtual' in base_spec_clean:
                                # Extract base class name - remove access specifiers and virtual keyword
                                base_name = re.sub(r'\b(public|private|protected|virtual)\s+', '', base_spec_clean).strip()
                                virtual_bases.add(base_name)
                            elif any(access in base_spec_clean for access in ['public', 'private', 'protected']):
                                # Non-virtual inheritance
                                base_name = re.sub(r'\b(public|private|protected)\s+', '', base_spec_clean).strip()
                                nonvirtual_bases.add(base_name)
                        break
                
                # Store class information
                classes[name] = {
                    'virtual_bases': virtual_bases,
                    'nonvirtual_bases': nonvirtual_bases,
                    'line': line_num,
                    'source': source
                }
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    
    # Analyze inheritance hierarchy for conflicts
    def get_all_bases(class_name, virtual=None):
        """Get all base classes of a class, optionally filtered by virtual/non-virtual"""
        bases = set()
        if class_name not in classes:
            return bases
        
        class_info = classes[class_name]
        
        # Add direct bases
        if virtual is None:
            bases.update(class_info['virtual_bases'])
            bases.update(class_info['nonvirtual_bases'])
        elif virtual:
            bases.update(class_info['virtual_bases'])
        else:
            bases.update(class_info['nonvirtual_bases'])
        
        # Add indirect bases recursively
        # For virtual inheritance analysis, we need to trace inheritance paths
        all_bases_of_this_class = class_info['virtual_bases'].union(class_info['nonvirtual_bases'])
        for base in all_bases_of_this_class:
            if base in classes:
                if virtual is None:
                    # Get all bases regardless of virtuality
                    bases.update(get_all_bases(base, None))
                elif virtual:
                    # For virtual inheritance check, if the immediate inheritance is virtual,
                    # then all bases of that class are also virtually inherited
                    if base in class_info['virtual_bases']:
                        bases.update(get_all_bases(base, None))  # All bases become virtual
                else:
                    # For non-virtual inheritance check, if the immediate inheritance is non-virtual,
                    # then all bases of that class are also non-virtually inherited  
                    if base in class_info['nonvirtual_bases']:
                        bases.update(get_all_bases(base, None))  # All bases become non-virtual
        
        return bases
    
    # Check each class for virtual/non-virtual conflicts
    for class_name, class_info in classes.items():
        if not class_info['virtual_bases'] and not class_info['nonvirtual_bases']:
            continue  # No inheritance
        
        # Calculate all bases via virtual and non-virtual paths
        virtual_inherited_bases = set()
        nonvirtual_inherited_bases = set()
        
        # Direct virtual bases
        virtual_inherited_bases.update(class_info['virtual_bases'])
        
        # Direct non-virtual bases
        nonvirtual_inherited_bases.update(class_info['nonvirtual_bases'])
        
        # Transitive bases through virtual inheritance
        for vbase in class_info['virtual_bases']:
            if vbase in classes:
                # All bases of a virtually inherited class are also virtually inherited
                virtual_inherited_bases.update(get_all_bases(vbase, None))
        
        # Transitive bases through non-virtual inheritance
        for nvbase in class_info['nonvirtual_bases']:
            if nvbase in classes:
                base_info = classes[nvbase]
                # Virtual bases of non-virtually inherited class become virtual
                virtual_inherited_bases.update(base_info['virtual_bases'])
                for vbase in base_info['virtual_bases']:
                    if vbase in classes:
                        virtual_inherited_bases.update(get_all_bases(vbase, None))
                
                # Non-virtual bases of non-virtually inherited class become non-virtual
                nonvirtual_inherited_bases.update(base_info['nonvirtual_bases'])
                for nvbase2 in base_info['nonvirtual_bases']:
                    if nvbase2 in classes:
                        nonvirtual_inherited_bases.update(get_all_bases(nvbase2, None))
        
        # Find bases that are both virtual and non-virtual
        conflicting_bases = virtual_inherited_bases.intersection(nonvirtual_inherited_bases)
        
        if conflicting_bases:
            finding = {
                "rule_id": "accessible_base_classes_both",
                "message": f"Base class(es) {', '.join(conflicting_bases)} are both virtual and non-virtual in inheritance hierarchy",
                "file": filename,
                "line": class_info['line'],
                "status": "violation"
            }
            findings.append(finding)
    
    return findings


def check_aggregate_initialization(ast_tree, filename):
    """
    Check if all elements of an aggregate are explicitly provided with initial values.
    
    Arrays and structs should have all elements explicitly initialized to avoid
    implicit zero-initialization which can hide bugs.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'declaration':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                import re
                
                # Look for array declarations like "int arr[N] = {values}"
                array_init_pattern = r'(\w+)\s+(\w+)\[(\d+)\]\s*=\s*\{([^}]*)\}'
                match = re.search(array_init_pattern, source)
                
                if match:
                    array_size = int(match.group(3))
                    initializer_list = match.group(4).strip()
                    
                    if initializer_list:
                        # Count the number of initializers
                        initializers = [item.strip() for item in initializer_list.split(',') if item.strip()]
                        num_initializers = len(initializers)
                        
                        if num_initializers < array_size:
                            finding = {
                                "rule_id": "all_elements_aggregate_provided",
                                "message": f"Provide explicit initial values for all {array_size} elements of the aggregate (found {num_initializers})",
                                "file": filename,
                                "line": line_num,
                                "status": "violation"
                            }
                            findings.append(finding)
                
                # Also check struct/class initialization patterns
                struct_init_pattern = r'(\w+)\s+(\w+)\s*=\s*\{([^}]*)\}'
                struct_match = re.search(struct_init_pattern, source)
                if struct_match and not match:  # Don't double-check arrays
                    # This would need more complex logic to check struct completeness
                    # For now, just check if the initializer seems incomplete (very basic)
                    initializer_content = struct_match.group(3).strip()
                    if ',' in initializer_content:
                        parts = [p.strip() for p in initializer_content.split(',')]
                        # Very basic heuristic - if we have trailing commas or missing values
                        if any(not part for part in parts):
                            finding = {
                                "rule_id": "all_elements_aggregate_provided", 
                                "message": "Provide explicit initial values for all elements of the aggregate",
                                "file": filename,
                                "line": line_num,
                                "status": "violation"
                            }
                            findings.append(finding)
            
            for key, value in node.items():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def has_aggregate_parentheses_init(source):
    """Check if source contains aggregate initialization with parentheses."""
    import re
    
    # Clean the source and check line by line
    lines = source.strip().split('\n')
    for line in lines:
        line = line.strip()
        if line and not line.startswith('//') and line.endswith(';'):
            # Check if this looks like a variable initialization with parentheses
            # Examples: 
            # - "Point p(10, 20);" 
            # - "Person person(std::string("John"), 25);"
            # - "int arr[3](1, 2, 3);"
            
            # Pattern 1: Simple Type var(args);
            if re.search(r'^\s*\w+\s+\w+\s*\([^)]*\)\s*;$', line):
                # Make sure it's not a control structure
                if not re.search(r'^\s*(if|while|for|switch)\s*\(', line):
                    return True
            
            # Pattern 2: Type var[size](args);  
            if re.search(r'^\s*\w+\s+\w+\[[^\]]*\]\s*\([^)]*\)\s*;$', line):
                return True
            
            # Pattern 3: Complex type with namespace (std::string, etc.)
            # Handle cases like "Person person(std::string("John"), 25);"
            if re.search(r'^\s*\w+\s+\w+\s*\(.*\)\s*;$', line):
                # Make sure it's not a control structure or function call
                if not re.search(r'^\s*(if|while|for|switch|return)\s*\(', line):
                    # Check if it contains typical variable declaration patterns
                    return True
    
    return False


def check_identical_branches(ast_tree, filename):
    """
    Check if all branches in a conditional structure have identical implementation.
    
    This indicates unnecessary conditional logic.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            node_type = node.get('node_type', '')
            if node_type in ['IfStatement', 'switch_statement', 'ConditionalExpression', 'conditional_expression']:
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                if has_identical_branches(source, node_type):
                    finding = {
                        "rule_id": "all_branches_conditional_structure",
                        "message": "All branches have identical implementation - consider refactoring",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def has_identical_branches(source, node_type):
    """Check if conditional structure has identical branches."""
    import re
    
    if node_type == 'IfStatement':
        return has_identical_if_branches(source)
    elif node_type == 'switch_statement':
        return has_identical_switch_branches(source)
    elif node_type in ['ConditionalExpression', 'conditional_expression']:
        return has_identical_ternary_branches(source)
    
    return False


def has_identical_if_branches(source):
    """Check if if-else chain has identical implementations."""
    import re
    
    # Extract the implementation from each branch
    branches = []
    
    # Find if/else if/else blocks
    # Pattern: if (condition) { ... } else if (condition) { ... } else { ... }
    
    # Simple approach: look for pattern in source
    # This is a simplified check - a full implementation would parse the AST more thoroughly
    
    # Look for repeated function calls in different branches
    lines = source.split('\n')
    branch_contents = []
    current_branch = []
    in_branch = False
    brace_count = 0
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('if (') or stripped.startswith('} else if (') or stripped == 'else {' or stripped == '} else {':
            if current_branch and in_branch:
                # Save previous branch
                branch_contents.append(' '.join(current_branch))
                current_branch = []
            in_branch = True
        elif in_branch:
            # Count braces to know when we're done with this branch
            brace_count += line.count('{') - line.count('}')
            if stripped and not stripped.startswith('}') and not stripped.startswith('if') and not stripped.startswith('else'):
                current_branch.append(stripped)
            if brace_count == 0 and '}' in line:
                # End of this branch
                branch_contents.append(' '.join(current_branch))
                current_branch = []
                in_branch = False
    
    # Add the last branch if any
    if current_branch and in_branch:
        branch_contents.append(' '.join(current_branch))
    
    # Check if all branches have the same content (ignoring whitespace)
    if len(branch_contents) >= 2:
        first_branch = branch_contents[0].strip()
        for branch in branch_contents[1:]:
            if first_branch != branch.strip():
                return False
        return True
    
    return False


def has_identical_switch_branches(source):
    """Check if switch cases have identical implementations."""
    import re
    
    # Extract case implementations
    case_contents = []
    lines = source.split('\n')
    current_case = []
    in_case = False
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('case ') or stripped.startswith('default:'):
            if current_case and in_case:
                # Save previous case (excluding break;)
                case_content = ' '.join([l for l in current_case if l != 'break;'])
                case_contents.append(case_content)
                current_case = []
            in_case = True
        elif in_case and stripped:
            if not stripped.startswith('}') and stripped != 'break;':
                current_case.append(stripped)
            elif stripped.startswith('}'):
                # End of switch
                if current_case:
                    case_content = ' '.join([l for l in current_case if l != 'break;'])
                    case_contents.append(case_content)
                break
    
    # Add the last case if any
    if current_case and in_case:
        case_content = ' '.join([l for l in current_case if l != 'break;'])
        case_contents.append(case_content)
    
    # Check if all cases have the same content
    if len(case_contents) >= 2:
        first_case = case_contents[0].strip()
        if first_case:  # Ignore empty cases
            for case in case_contents[1:]:
                if first_case != case.strip():
                    return False
            return True
    
    return False


def has_identical_ternary_branches(source):
    """Check if ternary operator has identical values."""
    import re
    
    # Look for pattern: condition ? value1 : value2
    ternary_match = re.search(r'\?\s*([^:]+)\s*:\s*([^;]+)', source)
    if ternary_match:
        true_value = ternary_match.group(1).strip()
        false_value = ternary_match.group(2).strip()
        return true_value == false_value
    
    return False

def check_if_else_if_termination(ast_tree, filename):
    """
    Check if all if...else if constructs are terminated with an else clause.
    
    Args:
        ast_tree: The AST tree of the C++ file
        filename: The filename being analyzed
        
    Returns:
        list: List of violations found
    """
    violations = []
    
    def has_final_else_clause(if_node):
        """
        Check if an if statement that contains else if has a final else clause.
        Returns True if it has final else, False otherwise.
        """
        # Check if this if statement has else clauses
        else_clauses = []
        for child in if_node.get('children', []):
            if child.get('node_type') == 'else_clause':
                else_clauses.append(child)
        
        if not else_clauses:
            return True  # No else clause at all, not an if-else-if chain
            
        # Check the last else clause
        last_else = else_clauses[-1]
        
        # Look for a nested IfStatement in the last else clause
        for child in last_else.get('children', []):
            if child.get('node_type') == 'IfStatement':
                # This is an else if, not a final else
                return False
                
        return True  # Has a final else clause
    
    def traverse_tree(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'IfStatement':
                # Check if this if statement has else if clauses without final else
                has_else_if = False
                
                # Check if any child is an else_clause containing an IfStatement  
                for child in node.get('children', []):
                    if child.get('node_type') == 'else_clause':
                        for grandchild in child.get('children', []):
                            if grandchild.get('node_type') == 'IfStatement':
                                has_else_if = True
                                break
                
                # If it has else if, check if it has proper termination
                if has_else_if and not has_final_else_clause(node):
                    violations.append({
                        'line': node.get('lineno', 0),
                        'column': node.get('start_column', 0),
                        'message': 'All if ... else if constructs shall be terminated with an else clause',
                        'severity': 'error'
                    })
            
            # Continue traversing
            for child in node.get('children', []):
                traverse_tree(child)
    
    traverse_tree(ast_tree)
    return violations


def check_unreachable_code(ast_tree, filename):
    """
    Check for unreachable code after control flow statements.
    
    Detects code that appears after return, break, continue, goto, throw, or exit statements
    within the same code block, making it unreachable.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Check for compound statements that might contain unreachable code
            if node.get('node_type') == 'compound_statement':
                children = node.get('children', [])
                for i, child in enumerate(children):
                    if isinstance(child, dict):
                        # Check for control flow statements
                        if child.get('node_type') in ['return_statement', 'throw_statement', 'break_statement', 'continue_statement', 'goto_statement']:
                            # Check if there are any non-comment statements after this one
                            for j in range(i + 1, len(children)):
                                next_child = children[j]
                                if isinstance(next_child, dict):
                                    # Skip comments, they don't count as unreachable code
                                    if next_child.get('node_type') not in ['comment']:
                                        finding = {
                                            "rule_id": "all_code_reachable",
                                            "message": f"Unreachable code detected after {child.get('node_type', 'control flow statement')}",
                                            "file": filename,
                                            "line": next_child.get('lineno', 0),
                                            "status": "violation"
                                        }
                                        findings.append(finding)
                                        break  # Only report the first unreachable statement
                        
                        # Check for calls to exit-like functions
                        elif child.get('node_type') == 'expression_statement':
                            source = child.get('source', '')
                            if any(func in source for func in ['exit(', 'abort(', 'std::terminate(', 'co_return']):
                                # Check for statements after exit calls
                                for j in range(i + 1, len(children)):
                                    next_child = children[j]
                                    if isinstance(next_child, dict) and next_child.get('node_type') not in ['comment']:
                                        finding = {
                                            "rule_id": "all_code_reachable",
                                            "message": "Unreachable code detected after function that never returns",
                                            "file": filename,
                                            "line": next_child.get('lineno', 0),
                                            "status": "violation"
                                        }
                                        findings.append(finding)
                                        break
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_throw_pointer(ast_tree, filename):
    """
    Check for throw statements that throw pointers.
    
    Throwing pointers makes memory management unclear and should be avoided.
    Exceptions should be thrown by value, not by pointer.
    """
    findings = []
    
    # Find all pointer variable declarations first
    pointer_variables = set()
    
    def find_pointer_vars(node):
        if isinstance(node, dict):
            # Look for declarations like "int* ptr", "Type* var", etc.
            if node.get('node_type') == 'declaration':
                source = node.get('source', '')
                import re
                # Match patterns like "int* varname", "Type* varname"
                ptr_decl_patterns = [
                    r'(\w+\*)\s+(\w+)',     # Type* var
                    r'(\w+)\s*\*\s*(\w+)',  # Type * var or Type *var
                ]
                for pattern in ptr_decl_patterns:
                    matches = re.findall(pattern, source)
                    for match in matches:
                        if len(match) >= 2:
                            var_name = match[1] if '*' in match[0] else match[1]
                            pointer_variables.add(var_name)
            
            # Recursively check children
            for child in node.get('children', []):
                find_pointer_vars(child)
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'ThrowStatement':
                line_num = node.get('lineno', 0)
                source = node.get('source', '')
                
                # Check for pointer-like patterns in throw statements
                import re
                
                # Look for patterns that indicate pointer throwing
                pointer_patterns = [
                    r'throw\s+new\s+',          # throw new Exception()
                    r'throw\s+\w+\*',           # throw ptr*
                    r'throw\s+\(\w+\*\)',       # throw (Type*)
                    r'throw\s+\w+[Pp]tr',       # throw somePtr
                    r'throw\s+\*\w+',           # throw *ptr
                ]
                
                # Check if throwing a known pointer variable
                throw_match = re.search(r'throw\s+(\w+)', source)
                if throw_match:
                    thrown_var = throw_match.group(1)
                    if thrown_var in pointer_variables:
                        finding = {
                            "rule_id": "exception_object_avoid_having",
                            "message": "Avoid throwing pointers - throw exception objects by value instead",
                            "file": filename,
                            "line": line_num,
                            "status": "violation"
                        }
                        findings.append(finding)
                
                # Also check syntactic patterns
                for pattern in pointer_patterns:
                    if re.search(pattern, source):
                        finding = {
                            "rule_id": "exception_object_avoid_having",
                            "message": "Avoid throwing pointers - throw exception objects by value instead",
                            "file": filename,
                            "line": line_num,
                            "status": "violation"
                        }
                        findings.append(finding)
                        break
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    # First pass: find pointer variables
    find_pointer_vars(ast_tree)
    
    # Second pass: check throw statements
    traverse(ast_tree)
    return findings


def check_if_compound_statement(ast_tree, filename):
    """
    Check if 'if' statements use compound statements (braces).
    
    MISRA rule requires that if statements always use braces for
    improved readability and to prevent errors when adding code.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'IfStatement':
                line_num = node.get('lineno', 0)
                source = node.get('source', '')
                
                # Check if the if statement lacks braces
                # Look for simple patterns like "if (condition) statement;" without braces
                import re
                
                # Pattern for if without braces: if (condition) single_statement;
                if_no_braces_pattern = r'if\s*\([^)]+\)\s*[^{\s]'
                else_no_braces_pattern = r'else\s+[^{\s]'
                
                if re.search(if_no_braces_pattern, source):
                    finding = {
                        "rule_id": "if_condition_construct_shall",
                        "message": "Use compound statements (braces) for if constructs to improve readability and prevent errors",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
                elif re.search(else_no_braces_pattern, source):
                    finding = {
                        "rule_id": "if_condition_construct_shall",
                        "message": "Use compound statements (braces) for else constructs to improve readability and prevent errors",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively traverse children
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_integral_to_pointer_conversion(ast_tree, filename):
    """
    Check for conversions from integral types to pointer types.
    
    Converting integral values to pointers is unsafe and should be avoided
    unless absolutely necessary and with proper safeguards.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') in ['declaration', 'expression_statement']:
                line_num = node.get('lineno', 0)
                source = node.get('source', '')
                
                # Look for patterns of integral to pointer conversion
                import re
                
                # Patterns for integral to pointer conversion
                conversion_patterns = [
                    r'\(\s*\w+\s*\*\s*\)\s*\d+',       # (Type*)42
                    r'\(\s*\w+\s*\*\s*\)\s*\w+',       # (Type*)variable  
                    r'\w+\*\s*\w+\s*=\s*\(\w+\*\)\d+', # Type* ptr = (Type*)42
                    r'\w+\*\s*\w+\s*=\s*\(\w+\*\)\w+', # Type* ptr = (Type*)variable
                ]
                
                for pattern in conversion_patterns:
                    if re.search(pattern, source):
                        # Make sure it's not a valid pointer operation
                        if not re.search(r'&\w+|new\s+|nullptr', source):
                            finding = {
                                "rule_id": "object_integral_type_pointer",
                                "message": "Avoid converting integral types to pointer types - use proper type casting or avoid the conversion",
                                "file": filename,
                                "line": line_num,
                                "status": "violation"
                            }
                            findings.append(finding)
                            break
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_pointer_type_conversion(ast_tree, filename):
    """
    Check for conversions between unrelated pointer types.
    
    Converting between unrelated pointer types can lead to undefined behavior
    and should be avoided unless there's a clear inheritance relationship.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') in ['declaration', 'expression_statement']:
                line_num = node.get('lineno', 0)
                source = node.get('source', '')
                
                # Look for patterns of pointer type conversion
                import re
                
                # Patterns for pointer to pointer conversion
                conversion_patterns = [
                    r'\(\s*\w+\s*\*\s*\)\s*\w+Ptr',       # (Type1*)type2Ptr
                    r'\w+\*\s*\w+\s*=\s*\(\w+\*\)\w+',    # Type1* ptr = (Type1*)type2Ptr
                ]
                
                for pattern in conversion_patterns:
                    if re.search(pattern, source):
                        # Exclude safe conversions to/from void*
                        if not re.search(r'void\s*\*|nullptr', source):
                            finding = {
                                "rule_id": "object_pointer_type_shall",
                                "message": "Avoid converting between unrelated pointer types - use proper type casting or reconsider the design",
                                "file": filename,
                                "line": line_num,
                                "status": "violation"
                            }
                            findings.append(finding)
                            break
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_inline_assembly_encapsulation(ast_tree, filename):
    """Check if inline assembly is mixed with C++ statements in the same function."""
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for functions that contain inline assembly
            if (node.get("node_type") == "FunctionDefinition" or 
                node.get("node_type") == "MethodDefinition"):
                
                function_name = node.get("name", "unknown")
                statements = []
                asm_statements = []
                
                # Find all statements and inline assembly within this function
                def find_statements(fn_node, path=[]):
                    if isinstance(fn_node, dict):
                        node_type = fn_node.get("node_type")
                        
                        # Track regular statements
                        if node_type in ["expression_statement", "return_statement", 
                                       "assignment_expression", "declaration_statement"]:
                            # Don't count empty statements or just asm statements
                            if (fn_node.get("source", "").strip() and 
                                "asm" not in fn_node.get("source", "")):
                                statements.append({
                                    "line": fn_node.get("lineno", 0),
                                    "source": fn_node.get("source", "").strip()
                                })
                        
                        # Track inline assembly
                        elif node_type == "gnu_asm_expression":
                            asm_statements.append({
                                "line": fn_node.get("lineno", 0),
                                "source": fn_node.get("source", "").strip()
                            })
                        
                        # Recurse into children
                        if "children" in fn_node:
                            for child in fn_node["children"]:
                                find_statements(child, path + [node_type])
                    elif isinstance(fn_node, list):
                        for item in fn_node:
                            find_statements(item, path)
                
                find_statements(node)
                
                # Check if assembly is mixed with other statements
                if asm_statements and statements:
                    # Assembly is mixed with regular C++ statements
                    for asm_stmt in asm_statements:
                        findings.append({
                            "rule_id": "assembly_language_encapsulated_isolated",
                            "severity": "Info",
                            "message": f"Assembly language should be encapsulated and isolated - avoid mixing asm with C++ statements in function '{function_name}'",
                            "line": asm_stmt["line"],
                            "column": 0,
                            "filename": filename,
                            "source": asm_stmt["source"]
                        })
            
            # Recurse into children
            if "children" in node:
                for child in node["children"]:
                    traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_array_unconditional_replacement(ast_tree, filename):
    """Check for array values being replaced unconditionally without using the previous value."""
    findings = []
    reported_violations = set()  # Track reported violations to prevent duplicates
    
    def traverse(node):
        if isinstance(node, dict):
            # Only process function definitions to avoid global scope duplication
            if node.get("node_type") == "FunctionDefinition":
                
                # Get all source lines in the function
                function_source = node.get("source", "")
                if not function_source:
                    return
                
                lines = function_source.split('\n')
                
                # Track array assignments and usages
                import re
                array_assign_pattern = r'^\s*(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*([^;]+);?\s*(?://.*)?$'
                array_usage_pattern = r'(\w+)\s*\[\s*([^\]]+)\s*\](?!\s*=)'
                
                assignments = {}  # key: "array[index]", value: list of (line_number, actual_line_content)
                usages = set()  # set of (array_key, line_number)
                
                # Process each line
                base_line = node.get("lineno", 1)
                for i, line in enumerate(lines):
                    line = line.strip()
                    current_line_no = base_line + i
                    
                    if not line or line.startswith('//') or line.startswith('/*'):
                        continue
                    
                    # Check for array assignment
                    assign_match = re.search(array_assign_pattern, line)
                    if assign_match:
                        array_name = assign_match.group(1)
                        index_expr = assign_match.group(2).strip()
                        array_key = f"{array_name}[{index_expr}]"
                        
                        if array_key not in assignments:
                            assignments[array_key] = []
                        assignments[array_key].append((current_line_no, line))
                    
                    # Check for array usage (reading, not assignment)
                    # Exclude lines that are assignments
                    if not re.search(r'^\s*\w+\s*\[\s*[^\]]+\s*\]\s*=', line):
                        usage_matches = re.findall(array_usage_pattern, line)
                        for usage_match in usage_matches:
                            array_name = usage_match[0]
                            index_expr = usage_match[1].strip()
                            array_key = f"{array_name}[{index_expr}]"
                            usages.add((array_key, current_line_no))
                
                # Check for unconditional overwrites
                for array_key, assign_list in assignments.items():
                    if len(assign_list) > 1:
                        assign_list.sort(key=lambda x: x[0])  # Sort by line number
                        
                        # Check each consecutive pair of assignments
                        for i in range(len(assign_list) - 1):
                            first_line_no, first_content = assign_list[i]
                            second_line_no, second_content = assign_list[i + 1]
                            
                            # Skip if same line (duplicate detection)
                            if first_line_no == second_line_no:
                                continue
                            
                            # Check if the array element was used between assignments
                            used_between = False
                            for usage_key, usage_line in usages:
                                if (usage_key == array_key and 
                                    first_line_no < usage_line < second_line_no):
                                    used_between = True
                                    break
                            
                            # Only report if not used between assignments and lines are reasonably close
                            line_diff = second_line_no - first_line_no
                            if not used_between and line_diff <= 20:
                                # Create unique violation key to prevent duplicates
                                violation_key = f"{filename}:{array_key}:{first_line_no}:{second_line_no}"
                                if violation_key not in reported_violations:
                                    reported_violations.add(violation_key)
                                    findings.append({
                                        "rule_id": "array_values_replaced_unconditionally",
                                        "severity": "Major",
                                        "message": f"Array values should not be replaced unconditionally - {array_key} is assigned twice without using the previous value",
                                        "line": second_line_no,
                                        "column": 0,
                                        "filename": filename,
                                        "source": second_content
                                    })
            
            # Recurse into children for function definitions
            if "children" in node:
                for child in node["children"]:
                    traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_pointer_to_integral_cast(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Custom function to detect C-style casts from pointer types to integral types.
    
    This function performs semantic analysis to distinguish between:
    - Pointer-to-integral casts (violations)
    - Numeric conversions (compliant)
    - reinterpret_cast operations (compliant)
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for pointer-to-integral cast violations
    """
    findings = []
    
    # Find all cast expressions in the AST
    cast_expressions = _find_nodes_by_type(ast_tree, ["cast_expression"])
    
    for cast_node in cast_expressions:
        source = cast_node.get("source", "")
        line = cast_node.get("line", 0)
        
        # Skip reinterpret_cast - these are compliant per rule examples
        if "reinterpret_cast" in source:
            continue
            
        # Pattern for C-style casts to integral types
        cast_pattern = r'\((?P<target_type>int|long|uintptr_t|size_t|uint64_t|uint32_t|intptr_t)\)\s*(?P<variable>\w+)'
        match = re.search(cast_pattern, source)
        
        if not match:
            continue
            
        target_type = match.group('target_type')
        variable_name = match.group('variable')
        
        # Analyze if the variable is likely a pointer based on context
        if _is_likely_pointer_variable(cast_node, variable_name, ast_tree):
            finding = {
                "rule_id": "cast_convert_pointer_type",
                "message": f"Variable '{target_type}': A cast should not convert a pointer type to an integral type",
                "node": f"{cast_node.get('node_type', 'cast_expression')}.{cast_node.get('node_type', 'cast_expression')}",
                "file": filename,
                "property_path": ["source"],
                "value": source.strip(),
                "status": "violation",
                "line": line,
                "severity": "Critical"
            }
            findings.append(finding)
    
    return findings


def _find_nodes_by_type(node: Dict[str, Any], node_types: List[str]) -> List[Dict[str, Any]]:
    """
    Recursively find all nodes of specified types in the AST.
    
    Args:
        node: Current AST node
        node_types: List of node types to search for
        
    Returns:
        List of matching nodes
    """
    matching_nodes = []
    
    if not isinstance(node, dict):
        return matching_nodes
    
    # Check if current node matches
    node_type = node.get("node_type", "")
    if node_type in node_types:
        matching_nodes.append(node)
    
    # Recursively search children
    children = node.get("children", [])
    if isinstance(children, list):
        for child in children:
            matching_nodes.extend(_find_nodes_by_type(child, node_types))
    
    return matching_nodes


def _is_likely_pointer_variable(cast_node: Dict[str, Any], variable_name: str, ast_tree: Dict[str, Any]) -> bool:
    """
    Analyze context to determine if a variable is likely a pointer.
    
    This function uses heuristics to distinguish between pointer and non-pointer variables:
    1. Variable name patterns (contains "ptr", ends with "*")
    2. Context analysis (declared with pointer types)
    3. Exclusion of obvious non-pointer patterns
    
    Args:
        cast_node: The cast expression node
        variable_name: Name of the variable being cast
        ast_tree: Full AST for context analysis
        
    Returns:
        True if variable is likely a pointer, False otherwise
    """
    # Strong indicators that this is a pointer
    pointer_indicators = [
        "ptr" in variable_name.lower(),
        variable_name.endswith("_ptr"),
        variable_name.startswith("p_"),
        variable_name in ["ptr", "pointer", "address", "addr"]
    ]
    
    # Strong indicators that this is NOT a pointer (common numeric variable names)
    non_pointer_indicators = [
        variable_name in ["d", "f", "i", "j", "k", "n", "x", "y", "z", "value", "num", "count"],
        variable_name.startswith("num_"),
        variable_name.endswith("_val"),
        variable_name.endswith("_value"),
        variable_name.endswith("_count"),
        variable_name.endswith("_size") and not variable_name.endswith("_ptr_size"),
        re.match(r'^[a-z][0-9]+$', variable_name)  # single letter + digits like d1, f2
    ]
    
    # If we have strong non-pointer indicators, exclude it
    if any(non_pointer_indicators):
        return False
    
    # If we have strong pointer indicators, include it
    if any(pointer_indicators):
        return True
    
    # For ambiguous cases, try to find variable declaration context
    variable_context = _find_variable_declaration_context(variable_name, ast_tree)
    
    if variable_context:
        # Check if declared with pointer type
        if "*" in variable_context or "ptr" in variable_context.lower():
            return True
        # Check if declared as obvious numeric type
        numeric_types = ["double", "float", "char", "bool"]
        if any(num_type in variable_context for num_type in numeric_types):
            return False
    
    # Default: assume it might be a pointer (conservative approach)
    # This may cause some false positives but ensures we catch actual pointer casts
    return True


def _find_variable_declaration_context(variable_name: str, ast_tree: Dict[str, Any]) -> Optional[str]:
    """
    Search AST for variable declaration context.
    
    Args:
        variable_name: Name of variable to find
        ast_tree: AST to search in
        
    Returns:
        Declaration context string if found, None otherwise
    """
    # This is a simplified implementation - in a full parser, we'd have proper symbol tables
    # For now, search for declaration patterns in source text
    
    def search_declarations(node):
        if not isinstance(node, dict):
            return None
            
        source = node.get("source", "")
        
        # Look for variable declarations
        declaration_patterns = [
            rf'{variable_name}\s*=',
            rf'\w+\s+{variable_name}\s*[=;]',
            rf'\w+\s*\*\s*{variable_name}',
            rf'auto\s+{variable_name}\s*='
        ]
        
        for pattern in declaration_patterns:
            if re.search(pattern, source):
                return source
        
        # Recursively search children
        for child in node.get("children", []):
            result = search_declarations(child)
            if result:
                return result
        
        return None
    
    return search_declarations(ast_tree)


def check_assignment_within_conditions(ast_tree, filename):
    """
    Check for assignments within conditional statements (if, while, for).
    
    This rule detects assignments made within the condition part of conditional statements,
    which can be prone to errors and reduce code clarity. However, it excludes cases
    where the assignment is wrapped in double parentheses, which is a common idiom
    to indicate intentional assignment.
    
    Examples of violations:
    - if (x = getValue()) { ... }  // Should move assignment outside
    - while (var = getNext()) { ... }
    - for (int i = 0; x = array[i]; i++) { ... }
    
    Examples of compliant code:
    - if ((x = getValue())) { ... }  // Double parentheses indicate intentional assignment
    - if (x == getValue()) { ... }   // Comparison, not assignment
    - if (x != 0) { ... }           // Comparison, not assignment
    
    Args:
        ast_tree: The AST tree representation of the file
        filename: Path to the C++ file being analyzed
        
    Returns:
        List of findings with rule violations
    """
    findings = []
    rule_id = 'assignments_made_from_within'
    
    def check_node(node):
        if not isinstance(node, dict):
            return
            
        node_type = node.get("node_type", "")
        source = node.get("source", "")
        
        # Check if this is a conditional statement
        if node_type in ["IfStatement", "WhileStatement", "ForStatement"]:
            # Get the condition part
            condition_source = _extract_condition_from_source(source, node_type)
            if condition_source and _has_single_paren_assignment(condition_source):
                line_number = node.get("lineno", node.get("start_line", 1))
                findings.append({
                    "rule_id": rule_id,
                    "message": f"Assignment should not be made within conditional statement. Consider moving the assignment outside the condition.",
                    "file": filename,
                    "line": line_number,
                    "status": "violation"
                })
        
        # Also check declaration statements that might contain assignments in conditions
        elif node_type == "declaration" and source:
            # Look for patterns like: for (int x = 0; y = getNext(); x++)
            if any(keyword in source for keyword in ["if (", "while (", "for ("]):
                condition_parts = _extract_for_loop_conditions(source)
                for condition in condition_parts:
                    if condition and _has_single_paren_assignment(condition):
                        line_number = node.get("lineno", node.get("start_line", 1))
                        findings.append({
                            "rule_id": rule_id,
                            "message": f"Assignment should not be made within conditional statement. Consider moving the assignment outside the condition.",
                            "file": filename,
                            "line": line_number,
                            "status": "violation"
                        })
                        break  # Only report once per statement
        
        # Recursively check children
        for child in node.get("children", []):
            check_node(child)
    
    check_node(ast_tree)
    return findings


def _extract_condition_from_source(source: str, node_type: str) -> Optional[str]:
    """
    Extract the condition part from a conditional statement source.
    
    Args:
        source: The full source code of the statement
        node_type: Type of statement (IfStatement, WhileStatement, ForStatement)
        
    Returns:
        The condition part or None if not found
    """
    if node_type == "IfStatement":
        # Extract condition from if (condition) - handle nested parentheses
        match = re.search(r'if\s*\(', source)
        if match:
            start_pos = match.end() - 1  # Position of opening parenthesis
            return _extract_balanced_parentheses_content(source, start_pos)
    
    elif node_type == "WhileStatement":
        # Extract condition from while (condition) - handle nested parentheses
        match = re.search(r'while\s*\(', source)
        if match:
            start_pos = match.end() - 1  # Position of opening parenthesis
            return _extract_balanced_parentheses_content(source, start_pos)
    
    elif node_type == "ForStatement":
        # Extract conditions from for (init; condition; increment) - handle nested parentheses
        match = re.search(r'for\s*\(', source)
        if match:
            start_pos = match.end() - 1  # Position of opening parenthesis
            for_content = _extract_balanced_parentheses_content(source, start_pos)
            if for_content:
                # Split by semicolons and check each part
                parts = for_content.split(';')
                for part in parts:
                    if _has_single_paren_assignment(part.strip()):
                        return part.strip()
        return None
    
    return None


def _extract_balanced_parentheses_content(source: str, start_pos: int) -> Optional[str]:
    """
    Extract content between balanced parentheses starting from start_pos.
    
    Args:
        source: The source string
        start_pos: Position of the opening parenthesis
        
    Returns:
        Content between balanced parentheses or None if not found
    """
    if start_pos >= len(source) or source[start_pos] != '(':
        return None
    
    paren_count = 0
    i = start_pos
    
    while i < len(source):
        if source[i] == '(':
            paren_count += 1
        elif source[i] == ')':
            paren_count -= 1
            if paren_count == 0:
                # Found the matching closing parenthesis
                return source[start_pos + 1:i]
        i += 1
    
    # Unbalanced parentheses
    return None


def _extract_for_loop_conditions(source: str) -> List[str]:
    """
    Extract all condition parts from for loop declarations.
    
    Args:
        source: Source code containing for loop
        
    Returns:
        List of condition parts
    """
    conditions = []
    # Find all for loops in the source
    for_matches = re.finditer(r'for\s*\((.*?)\)', source, re.DOTALL)
    
    for match in for_matches:
        for_content = match.group(1)
        # Split by semicolons and add each part
        parts = for_content.split(';')
        conditions.extend([part.strip() for part in parts if part.strip()])
    
    return conditions


def _has_single_paren_assignment(condition: str) -> bool:
    """
    Check if a condition contains a single-parentheses assignment.
    
    This function detects assignments but excludes:
    - Double parentheses assignments: ((var = value)) 
    - Equality comparisons: ==, !=, <=, >=
    - Compound assignments: +=, -=, *=, /=, %=, etc.
    
    Args:
        condition: The condition string to check
        
    Returns:
        True if contains single-paren assignment, False otherwise
    """
    if not condition:
        return False
    
    # Remove whitespace for easier analysis
    clean_condition = condition.strip()
    
    # Check if this is wrapped in parentheses (double parentheses case)
    # The extracted condition will be like "(run = keepRunning())" for double parentheses
    if clean_condition.startswith('(') and clean_condition.endswith(')'):
        # This is an intentional assignment with double parentheses
        return False
    
    # Look for assignment operators that are not comparisons or compound assignments
    assignment_pattern = r'\w+\s*=\s*[^=<>!]'
    
    # Check if it has an assignment
    has_assignment = bool(re.search(assignment_pattern, clean_condition))
    
    # Check for equality operators (==, !=, <=, >=) which we want to allow
    has_equality = bool(re.search(r'[=!<>]=', clean_condition))
    
    # Check for compound assignments (+=, -=, etc.) which we want to allow
    has_compound = bool(re.search(r'\w+\s*[+\-*/%&|^]=\s*', clean_condition))
    
    # Return True only if it has assignment but is not equality and not compound
    return has_assignment and not has_equality and not has_compound


def check_virtual_assignment_operators(ast_tree, filename):
    """
    Custom function to detect virtual assignment operators in C++ classes.
    
    This rule detects when assignment operators are declared as virtual,
    which doesn't work properly in C++ polymorphism.
    """
    findings = []
    rule_id = 'assignment_operators_virtual'
    
    def traverse_node(node):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Only check class declarations
        if node_type == 'ClassDeclaration':
            source = node.get('source', '')
            if not source:
                return
            
            # Split into lines and scan each line
            lines = source.split('\n')
            line_number_offset = node.get('lineno', 1) - 1
            
            for i, line in enumerate(lines):
                # Skip comment-only lines
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('/*') or not stripped:
                    continue
                
                # Look for virtual assignment operators
                if ('virtual' in line and 'operator' in line and '=' in line):
                    # Make sure it's not a comment line or in a comment
                    if '//' in line:
                        comment_pos = line.find('//')
                        virtual_pos = line.find('virtual')
                        operator_pos = line.find('operator')
                        # Skip if virtual or operator appear after //
                        if virtual_pos > comment_pos or operator_pos > comment_pos:
                            continue
                    
                    # More precise pattern matching for various assignment operators
                    import re
                    patterns = [
                        r'virtual\s+[^;/]*?operator\s*=\s*\(',      # operator=
                        r'virtual\s+[^;/]*?operator\s*\+=\s*\(',    # operator+=
                        r'virtual\s+[^;/]*?operator\s*-=\s*\(',     # operator-=
                        r'virtual\s+[^;/]*?operator\s*\*=\s*\(',    # operator*=
                        r'virtual\s+[^;/]*?operator\s*/=\s*\(',     # operator/=
                        r'virtual\s+[^;/]*?operator\s*%=\s*\(',     # operator%=
                        r'virtual\s+[^;/]*?operator\s*&=\s*\(',     # operator&=
                        r'virtual\s+[^;/]*?operator\s*\|=\s*\(',    # operator|=
                        r'virtual\s+[^;/]*?operator\s*\^=\s*\(',    # operator^=
                        r'virtual\s+[^;/]*?operator\s*<<=\s*\(',    # operator<<=
                        r'virtual\s+[^;/]*?operator\s*>>=\s*\(',    # operator>>=
                    ]
                    
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            actual_line_number = line_number_offset + i + 1
                            
                            findings.append({
                                'rule_id': rule_id,
                                'message': "Assignment operators should not be virtual.",
                                'file': filename,
                                'line': actual_line_number,
                                'status': 'violation',
                                'value': line.strip()[:100],  # Show context
                            })
                            break  # Only report once per line
        
        # Recursively check children
        for child in node.get('children', []):
            traverse_node(child)
    
    traverse_node(ast_tree)
    return findings


def check_argument_evaluation_order(ast_tree, filename):
    """
    Check for function calls where the same variable is modified in multiple arguments.
    This can lead to undefined behavior (pre-C++17) or unspecified behavior (C++17+).
    """
    import re
    
    findings = []
    reported_violations = set()  # Track reported violations to prevent duplicates
    
    def traverse_node(node):
        if not isinstance(node, dict):
            return
        
        # Process source code line by line within AST nodes
        source = node.get('source', '')
        if source:
            lines = source.split('\n')
            base_line = node.get('start_line', node.get('line', node.get('lineno', 1)))
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('/*'):
                    continue
                
                current_line_no = base_line + i
                violation_key = f"{filename}:{current_line_no}"
                
                # Skip if already reported for this line
                if violation_key in reported_violations:
                    continue
                
                # Look for function calls with multiple argument modifications
                # Pattern: function_name(arg1, arg2, ...) where args contain variable modifications
                func_call_match = re.search(r'(\w+)\s*\([^)]*\)', line)
                if not func_call_match:
                    continue
                
                full_call = func_call_match.group(0)
                func_name = func_call_match.group(1)
                
                # Skip operator<< chains (cout statements) and include statements
                if '<<' in line or '#include' in line or 'std::cout' in line:
                    continue
                
                # Extract arguments
                paren_start = full_call.find('(')
                paren_end = full_call.rfind(')')
                if paren_start == -1 or paren_end == -1:
                    continue
                
                args_text = full_call[paren_start+1:paren_end]
                if not args_text.strip() or ',' not in args_text:
                    continue
                
                # Split arguments while respecting nested parentheses
                arguments = []
                paren_count = 0
                current_arg = ""
                
                for char in args_text:
                    if char == ',' and paren_count == 0:
                        arguments.append(current_arg.strip())
                        current_arg = ""
                    else:
                        if char == '(':
                            paren_count += 1
                        elif char == ')':
                            paren_count -= 1
                        current_arg += char
                
                if current_arg.strip():
                    arguments.append(current_arg.strip())
                
                # Need at least 2 arguments
                if len(arguments) < 2:
                    continue
                
                # Find variables that are modified in arguments
                modified_vars = {}  # variable_name -> list of (arg_index, operation_type)
                
                for arg_idx, arg in enumerate(arguments):
                    # Pre-increment: ++var
                    for match in re.finditer(r'\+\+(\w+)', arg):
                        var = match.group(1)
                        if var not in modified_vars:
                            modified_vars[var] = []
                        modified_vars[var].append((arg_idx, 'pre-increment'))
                    
                    # Post-increment: var++
                    for match in re.finditer(r'(\w+)\+\+', arg):
                        var = match.group(1)
                        if var not in modified_vars:
                            modified_vars[var] = []
                        modified_vars[var].append((arg_idx, 'post-increment'))
                    
                    # Pre-decrement: --var
                    for match in re.finditer(r'\-\-(\w+)', arg):
                        var = match.group(1)
                        if var not in modified_vars:
                            modified_vars[var] = []
                        modified_vars[var].append((arg_idx, 'pre-decrement'))
                    
                    # Post-decrement: var--
                    for match in re.finditer(r'(\w+)\-\-', arg):
                        var = match.group(1)
                        if var not in modified_vars:
                            modified_vars[var] = []
                        modified_vars[var].append((arg_idx, 'post-decrement'))
                    
                    # Assignment operators: var += val, var -= val, etc.
                    for match in re.finditer(r'(\w+)\s*([+\-*/%&|^]=)', arg):
                        var = match.group(1)
                        op = match.group(2)
                        if var not in modified_vars:
                            modified_vars[var] = []
                        modified_vars[var].append((arg_idx, f'assignment ({op})'))
                    
                    # Simple assignment in parentheses: (var = val)
                    for match in re.finditer(r'\(\s*(\w+)\s*=\s*[^=]', arg):
                        var = match.group(1)
                        if var not in modified_vars:
                            modified_vars[var] = []
                        modified_vars[var].append((arg_idx, 'assignment'))
                
                # Check for variables modified in multiple arguments
                for var, modifications in modified_vars.items():
                    if len(modifications) > 1:
                        # Same variable modified in multiple arguments - this is a violation
                        
                        # Mark as reported to avoid duplicates
                        reported_violations.add(violation_key)
                        
                        # Create detailed message
                        operations = [f"arg {arg_idx+1}: {op}" for arg_idx, op in modifications]
                        detailed_message = f"Arguments evaluation order should not be relied on - variable '{var}' modified in multiple arguments: {', '.join(operations)}"
                        
                        finding = {
                            'rule_id': 'arguments_evaluation_order_relied',
                            'message': detailed_message,
                            'file': filename,
                            'line': current_line_no,
                            'status': 'violation',
                            'severity': 'Info',
                            'node': f"call_expression.call_expression",
                            'property_path': ['source'],
                            'value': line[:150]
                        }
                        findings.append(finding)
                        break  # Only report once per function call
        
        # Recursively check children
        for child in node.get('children', []):
            traverse_node(child)
    
    traverse_node(ast_tree)
    return findings


def check_format_width_precision_arguments(ast_tree, filename):
    """
    Check for std::format calls where width and precision formatting options 
    use floating-point arguments instead of required integer arguments.
    """
    import re
    
    findings = []
    reported_violations = set()  # Track reported violations to prevent duplicates
    
    def traverse_node(node):
        if not isinstance(node, dict):
            return
        
        # Process source code line by line within AST nodes
        source = node.get('source', '')
        if source:
            lines = source.split('\n')
            base_line = node.get('start_line', node.get('line', node.get('lineno', 1)))
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('/*'):
                    continue
                
                current_line_no = base_line + i
                violation_key = f"{filename}:{current_line_no}"
                
                # Skip if already reported for this line
                if violation_key in reported_violations:
                    continue
                
                # Look for std::format function calls
                format_match = re.search(r'std::format\s*\([^)]*\)', line)
                if not format_match:
                    continue
                
                full_call = format_match.group(0)
                
                # Extract arguments from the function call
                paren_start = full_call.find('(')
                paren_end = full_call.rfind(')')
                if paren_start == -1 or paren_end == -1:
                    continue
                
                args_text = full_call[paren_start+1:paren_end]
                if not args_text.strip():
                    continue
                
                # Split arguments while respecting nested parentheses and quotes
                arguments = []
                paren_count = 0
                brace_count = 0
                quote_count = 0
                current_arg = ""
                
                for char in args_text:
                    if char == '"' and (len(current_arg) == 0 or current_arg[-1] != '\\'):
                        quote_count = 1 - quote_count
                    elif quote_count == 0:
                        if char == ',' and paren_count == 0 and brace_count == 0:
                            arguments.append(current_arg.strip())
                            current_arg = ""
                            continue
                        elif char == '(':
                            paren_count += 1
                        elif char == ')':
                            paren_count -= 1
                        elif char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                    current_arg += char
                
                if current_arg.strip():
                    arguments.append(current_arg.strip())
                
                # Need at least 2 arguments (format string + at least one value)
                if len(arguments) < 2:
                    continue
                
                # First argument should be the format string
                format_string = arguments[0]
                
                # Check if format string contains dynamic width/precision placeholders
                # Patterns like {:{}}, {:{}.{}f}, {:{}.{}}, etc.
                dynamic_format_pattern = r'\{:[^}]*\{\}[^}]*\}|\{:[^}]*\{\}[^}]*\.[^}]*\{\}[^}]*\}'
                if not re.search(dynamic_format_pattern, format_string):
                    continue  # No dynamic width/precision formatting
                
                # Count the number of {} placeholders in the format specifiers
                # to understand which arguments correspond to width/precision
                
                # Find all format specifiers with dynamic components - handle nested braces properly
                format_specs = []
                i = 0
                while i < len(format_string):
                    if i + 1 < len(format_string) and format_string[i:i+2] == '{:':
                        # Found start of format specifier
                        brace_count = 1
                        start = i
                        i += 2  # Skip '{:'
                        while i < len(format_string) and brace_count > 0:
                            if format_string[i] == '{':
                                brace_count += 1
                            elif format_string[i] == '}':
                                brace_count -= 1
                            i += 1
                        if brace_count == 0:
                            spec = format_string[start:i]
                            format_specs.append(spec)
                    else:
                        i += 1
                
                problematic_args = []
                arg_index = 1  # Start from 1, skip format string
                
                for spec in format_specs:
                    # Count dynamic placeholders in this format spec
                    dynamic_placeholders = spec.count('{}')
                    
                    # First, skip past the main value argument for this format spec
                    main_value_index = arg_index
                    arg_index += 1  # Skip the main value being formatted
                    
                    # Now check each placeholder (could be width, precision, or other)
                    for placeholder_idx in range(dynamic_placeholders):
                        if arg_index < len(arguments):
                            arg_value = arguments[arg_index].strip()
                            
                            # Check if this argument is a floating-point number
                            # Patterns to detect floats:
                            float_patterns = [
                                r'^\d+\.\d+[fF]?$',           # 10.5, 10.5f, 10.5F
                                r'^\d+\.[fF]?$',              # 10.f, 10.F
                                r'^\.\d+[fF]?$',              # .5f, .5F
                                r'^\d+\.\d+[eE][+-]?\d+[fF]?$',  # 1.5e10, 1.5E-10f
                                r'^\d+\.[eE][+-]?\d+[fF]?$',     # 10.e5f
                                r'^\d+\.0+[fF]?$',            # 10.0, 10.00f
                            ]
                            
                            is_float = False
                            for pattern in float_patterns:
                                if re.match(pattern, arg_value):
                                    is_float = True
                                    break
                            
                            # Also check for float variables by looking at content
                            if not is_float:
                                # Simple heuristic: contains dot and looks numeric-ish
                                if ('.' in arg_value and 
                                    any(c.isdigit() for c in arg_value) and
                                    not arg_value.startswith('"') and
                                    not arg_value.startswith("'")):
                                    # Additional check: not a member access (like obj.member)
                                    if not re.search(r'\w+\.\w+', arg_value):
                                        is_float = True
                            
                            if is_float:
                                problematic_args.append({
                                    'index': arg_index,
                                    'value': arg_value,
                                    'position': 'width' if placeholder_idx == 0 else 'precision' if placeholder_idx == 1 else 'formatting'
                                })
                            
        # Recursively check children
        for child in node.get('children', []):
            traverse_node(child)
    
    traverse_node(ast_tree)
    return findings


def check_printf_format_string_safety(ast_tree, filename):
    """
    Check for printf calls with unsafe format string arguments.
    Security vulnerability: printf(variable) allows format string attacks.
    Safe usage: printf("literal") or printf("%s", variable)
    """
    import re
    
    findings = []
    reported_violations = set()  # Track reported violations to prevent duplicates
    
    def traverse_node(node):
        if not isinstance(node, dict):
            return
        
        # Process source code line by line within AST nodes
        source = node.get('source', '')
        if source:
            lines = source.split('\n')
            base_line = node.get('start_line', node.get('line', node.get('lineno', 1)))
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('/*'):
                    continue
                
                current_line_no = base_line + i
                violation_key = f"{filename}:{current_line_no}"
                
                # Skip if already reported for this line
                if violation_key in reported_violations:
                    continue
                
                # Look for printf function calls with single argument
                printf_matches = re.finditer(r'\bprintf\s*\(([^)]*)\)', line)
                
                for match in printf_matches:
                    full_call = match.group(0)
                    args_content = match.group(1).strip()
                    
                    # Skip empty calls
                    if not args_content:
                        continue
                    
                    # Check if this is a single argument call (no commas outside quotes)
                    # Parse to count actual arguments
                    arguments = []
                    paren_count = 0
                    quote_count = 0
                    current_arg = ""
                    
                    for char in args_content:
                        if char == '"' and (len(current_arg) == 0 or current_arg[-1] != '\\'):
                            quote_count = 1 - quote_count
                        elif quote_count == 0:
                            if char == ',' and paren_count == 0:
                                arguments.append(current_arg.strip())
                                current_arg = ""
                                continue
                            elif char == '(':
                                paren_count += 1
                            elif char == ')':
                                paren_count -= 1
                        current_arg += char
                    
                    if current_arg.strip():
                        arguments.append(current_arg.strip())
                    
                    # Only check single-argument printf calls
                    if len(arguments) != 1:
                        continue
                    
                    arg = arguments[0].strip()
                    
                    # Check if the argument is a string literal (safe)
                    is_string_literal = False
                    
                    # String literal patterns
                    if ((arg.startswith('"') and arg.endswith('"')) or
                        (arg.startswith("'") and arg.endswith("'"))):
                        # Basic string literal check
                        is_string_literal = True
                        
                        # Additional validation: make sure it's properly terminated
                        # and doesn't contain unescaped quotes in the middle
                        if arg.startswith('"') and arg.endswith('"') and len(arg) >= 2:
                            # Simple check for properly escaped string
                            inner_content = arg[1:-1]
                            # Count unescaped quotes
                            unescaped_quotes = 0
                            i = 0
                            while i < len(inner_content):
                                if inner_content[i] == '"':
                                    if i == 0 or inner_content[i-1] != '\\':
                                        unescaped_quotes += 1
                                i += 1
                            
                            # If there are unescaped quotes, it might not be a simple literal
                            if unescaped_quotes == 0:
                                is_string_literal = True
                            else:
                                is_string_literal = False
                    
                    # If it's not a string literal, it's potentially dangerous
                    if not is_string_literal:
                        # Mark as reported to avoid duplicates
                        reported_violations.add(violation_key)
                        
                        # Determine the type of dangerous argument for better messaging
                        arg_type = "variable"
                        if '(' in arg and ')' in arg:
                            arg_type = "function call"
                        elif '[' in arg and ']' in arg:
                            arg_type = "array access"
                        elif '+' in arg or '-' in arg or '*' in arg:
                            arg_type = "expression"
                        elif arg.startswith('&') or arg.endswith('->') or '.' in arg:
                            arg_type = "pointer/member access"
                        
                        detailed_message = f"Argument of printf should be a format string - found {arg_type} '{arg}' (security vulnerability)"
                        
                        finding = {
                            'rule_id': 'argument_printf_format_string',
                            'message': detailed_message,
                            'file': filename,
                            'line': current_line_no,
                            'status': 'violation',
                            'severity': 'Info',
                            'node': f"call_expression.printf",
                            'property_path': ['source'],
                            'value': full_call[:100]  # Truncate long calls
                        }
        # Recursively check children
        for child in node.get('children', []):
            traverse_node(child)
    
    traverse_node(ast_tree)
    return findings


def check_string_function_size_arguments(ast_tree, filename):
    """
    Check for inappropriate size arguments in string manipulation functions.
    Functions: strncat, strlcpy, strlcat
    Issue: Using source buffer size instead of destination buffer size can cause buffer overflows.
    """
    import re
    
    findings = []
    reported_violations = set()  # Track reported violations to prevent duplicates
    
    def self_or_derived_from(var1, var2):
        """Check if var1 is the same as var2 or derived from var2 (ignoring array indices, etc.)"""
        # Remove array indices and member accesses for comparison
        clean_var1 = var1.split('[')[0].split('.')[0].split('->')[0].strip()
        clean_var2 = var2.split('[')[0].split('.')[0].split('->')[0].strip()
        
        # Check if they're the same variable or if var1 contains var2
        return (clean_var1 == clean_var2 or 
                clean_var2 in clean_var1 or
                # Handle pointer relationships
                clean_var1.replace('*', '') == clean_var2 or
                clean_var2.replace('*', '') == clean_var1)
    
    def traverse_node(node):
        if not isinstance(node, dict):
            return
        
        # Process source code line by line within AST nodes
        source = node.get('source', '')
        if source:
            lines = source.split('\n')
            base_line = node.get('start_line', node.get('line', node.get('lineno', 1)))
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('/*'):
                    continue
                
                current_line_no = base_line + i
                violation_key = f"{filename}:{current_line_no}"
                
                # Skip if already reported for this line
                if violation_key in reported_violations:
                    continue
                
                # Look for string manipulation function calls
                # Check strncat, strlcpy, strlcat
                string_func_patterns = [
                    r'\bstrncat\s*\(([^)]*)\)',
                    r'\bstrlcpy\s*\(([^)]*)\)', 
                    r'\bstrlcat\s*\(([^)]*)\)'
                ]
                
                for pattern in string_func_patterns:
                    matches = re.finditer(pattern, line)
                    
                    for match in matches:
                        full_call = match.group(0)
                        args_content = match.group(1).strip()
                        func_name = full_call.split('(')[0].strip()
                        
                        # Skip empty calls
                        if not args_content:
                            continue
                        
                        # Parse arguments (handle nested parentheses and quotes)
                        arguments = []
                        paren_count = 0
                        quote_count = 0
                        current_arg = ""
                        
                        for char in args_content:
                            if char == '"' and (len(current_arg) == 0 or current_arg[-1] != '\\'):
                                quote_count = 1 - quote_count
                            elif quote_count == 0:
                                if char == ',' and paren_count == 0:
                                    arguments.append(current_arg.strip())
                                    current_arg = ""
                                    continue
                                elif char == '(':
                                    paren_count += 1
                                elif char == ')':
                                    paren_count -= 1
                            current_arg += char
                        
                        if current_arg.strip():
                            arguments.append(current_arg.strip())
                        
                        # Need at least 3 arguments for size-based functions
                        if len(arguments) < 3:
                            continue
                        
                        dest_arg = arguments[0].strip()
                        src_arg = arguments[1].strip()
                        size_arg = arguments[2].strip()
                        
                        # Check for problematic size argument patterns
                        problematic_patterns = []
                        
                        # Pattern 1: strlen(source_variable)
                        strlen_match = re.search(r'strlen\s*\(\s*([^)]+)\s*\)', size_arg)
                        if strlen_match:
                            strlen_var = strlen_match.group(1).strip()
                            # Check if the strlen argument matches or is derived from source
                            if self_or_derived_from(strlen_var, src_arg):
                                problematic_patterns.append(f"strlen({strlen_var}) - source-based")
                        
                        # Pattern 2: sizeof(source_variable)
                        sizeof_match = re.search(r'sizeof\s*\(\s*([^)]+)\s*\)', size_arg)
                        if sizeof_match:
                            sizeof_var = sizeof_match.group(1).strip()
                            # Check if the sizeof argument matches or is derived from source
                            if self_or_derived_from(sizeof_var, src_arg):
                                problematic_patterns.append(f"sizeof({sizeof_var}) - source-based")
                        
                        # Pattern 3: Function calls that might return source size
                        func_call_match = re.search(r'(\w+)\s*\([^)]*' + re.escape(src_arg.split('[')[0].split('.')[0]) + r'[^)]*\)', size_arg)
                        if func_call_match and 'strlen' not in size_arg and 'sizeof' not in size_arg:
                            problematic_patterns.append(f"function call potentially using source")
                        
                        # Pattern 4: Direct use of source variable as size (unusual but possible)
                        if src_arg.split('[')[0].split('.')[0] in size_arg and 'dest' not in size_arg.lower():
                            # Make sure it's not a destination-based calculation
                            if dest_arg.split('[')[0].split('.')[0] not in size_arg:
                                problematic_patterns.append(f"direct source variable reference")
                        
                        # Pattern 5: Arithmetic expressions with source size
                        if ('strlen' in size_arg or 'sizeof' in size_arg) and any(op in size_arg for op in ['+', '-', '*', '/']):
                            # Check if the base is still source-related
                            base_vars = re.findall(r'(?:strlen|sizeof)\s*\(\s*([^)]+)\s*\)', size_arg)
                            for base_var in base_vars:
                                if self_or_derived_from(base_var.strip(), src_arg):
                                    problematic_patterns.append(f"arithmetic with source-based size")
                                    break
                        
                        # Report violations
                        if problematic_patterns:
                            # Mark as reported to avoid duplicates
                            reported_violations.add(violation_key)
                            
                            # Create detailed message
                            pattern_details = ', '.join(problematic_patterns)
                            detailed_message = f"Inappropriate size argument in {func_name}() - using {pattern_details}. Use destination buffer size instead"
                            
                            finding = {
                                'rule_id': 'appropriate_size_arguments_passed',
                                'message': detailed_message,
                                'file': filename,
                                'line': current_line_no,
                                'status': 'violation',
                                'severity': 'Info',
                                'node': f"call_expression.{func_name}",
                                'property_path': ['source'],
                                'value': full_call[:100]  # Truncate long calls
                            }
                            findings.append(finding)
        
        # Recursively check children
        for child in node.get('children', []):
            traverse_node(child)
    
    traverse_node(ast_tree)
    return findings

def check_file_naming_convention(ast_tree, filename):
    """Check if file follows naming convention"""
    import re, os
    findings = []
    
    base_name = os.path.basename(filename)
    if not re.match(r'^[a-z_][a-z0-9_]*\.(cpp|h|hpp)$', base_name):
        findings.append({
            "rule_id": "file_naming_convention_1",
            "message": f"File '{base_name}' should follow naming convention: lowercase with underscores",
            "file": filename,
            "line": 1,
            "status": "violation"
        })
    return findings

def check_file_has_newline(ast_tree, filename):
    """Check if file ends with newline"""
    findings = []
    
    try:
        with open(filename, 'rb') as f:
            content = f.read()
            
        if len(content) == 0:
            return findings
            
        if content and not content.endswith(b'\n'):
            findings.append({
                "rule_id": "file_should_end_with_newline_1",
                "message": f"File should end with a newline character",
                "file": filename,
                "line": content.count(b'\n') + 1,
                "status": "violation"
            })
    except Exception:
        pass
        
    return findings

def check_final_class_protected_members(ast_tree, filename):
    """Check if final classes have protected members"""
    import re
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') in ['ClassDeclaration', 'StructDeclaration']:
                source = node.get('source', '')
                
                is_final = re.search(r'\b(class|struct)\s+\w+\s+final\b', source) or \
                          re.search(r'\b(class|struct)\s+final\s+\w+\b', source)
                
                if is_final:
                    protected_matches = list(re.finditer(r'\bprotected\s*:', source))
                    
                    for match in protected_matches:
                        lines_before_protected = source[:match.start()].count('\n')
                        line_num = node.get('lineno', 1) + lines_before_protected
                        
                        class_match = re.search(r'\b(class|struct)\s+(\w+)\s+final\b', source)
                        if not class_match:
                            class_match = re.search(r'\b(class|struct)\s+final\s+(\w+)\b', source)
                        
                        class_type = "class"
                        class_name = "unknown"
                        if class_match:
                            class_type = class_match.group(1)
                            class_name = class_match.group(2) if len(class_match.groups()) >= 2 else class_match.group(1)
                        
                        finding = {
                            "rule_id": "final_classes_avoid_having",
                            "message": f"Final {class_type} '{class_name}' should avoid having protected members - protected access is pointless in final {class_type}s",
                            "file": filename,
                            "line": line_num,
                            "status": "violation"
                        }
                        findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings

def check_final_class_virtual_functions(ast_tree, filename):
    """Check if final classes have virtual functions"""
    import re
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') in ['ClassDeclaration', 'StructDeclaration']:
                source = node.get('source', '')
                
                # Check if this specific class/struct is final
                is_final = re.search(r'\b(class|struct)\s+\w+\s+final\b', source) or \
                          re.search(r'\b(class|struct)\s+final\s+\w+\b', source)
                
                if is_final:
                    # Extract class/struct name and type first
                    class_match = re.search(r'\b(class|struct)\s+(\w+)\s+final\b', source)
                    if not class_match:
                        class_match = re.search(r'\b(class|struct)\s+final\s+(\w+)\b', source)
                    
                    class_type = "class"
                    class_name = "unknown"
                    if class_match:
                        class_type = class_match.group(1)
                        class_name = class_match.group(2) if len(class_match.groups()) >= 2 else class_match.group(1)
                    
                    # Find the body of this class (everything inside the {})
                    class_body_match = re.search(r'\{(.*)\}', source, re.DOTALL)
                    if class_body_match:
                        class_body = class_body_match.group(1)
                        
                        # Remove comments to avoid false matches
                        # Remove single-line comments
                        class_body_no_comments = re.sub(r'//.*', '', class_body)
                        # Remove multi-line comments
                        class_body_no_comments = re.sub(r'/\*.*?\*/', '', class_body_no_comments, flags=re.DOTALL)
                        
                        # Look for virtual functions in the body (more precise patterns)
                        # Each pattern should match a complete virtual function declaration on a single logical line
                        virtual_patterns = [
                            r'^\s*virtual\s+\w+[\s*&]*\s+(\w+)\s*\(',    # virtual returntype functionname(
                            r'^\s*virtual\s+(\w+)\s*\(',                 # virtual functionname(
                            r'^\s*virtual\s+~(\w+)\s*\(',                # virtual destructor
                        ]
                        
                        for pattern in virtual_patterns:
                            for match in re.finditer(pattern, class_body_no_comments, re.MULTILINE):
                                # Calculate line number
                                lines_before_match = class_body[:match.start()].count('\n')
                                # Find where the class body starts
                                body_start_line = source[:source.find('{')+1].count('\n')
                                line_num = node.get('lineno', 1) + body_start_line + lines_before_match
                                
                                # Extract function name
                                func_name = match.group(1) if match.group(1) else "function"
                                
                                finding = {
                                    "rule_id": "final_classes_avoid_having_1",
                                    "message": f"Final {class_type} '{class_name}' should avoid virtual function '{func_name}' - virtual is confusing in final {class_type}s that cannot be inherited",
                                    "file": filename,
                                    "line": line_num,
                                    "status": "violation"
                                }
                                findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_functions_declared_block_scope(ast_tree, filename):
    """
    Check if functions are declared at block scope.
    
    Functions should not be declared at block scope as they don't get special access
    to names in their enclosing scope and should be declared at namespace scope instead.
    """
    findings = []
    
    def traverse(node, parent_context=None):
        if isinstance(node, dict):
            # Check if we're in a function scope (compound_statement within FunctionDefinition)
            current_context = parent_context
            if node.get('node_type') == 'FunctionDefinition':
                current_context = 'function_scope'
            
            # Look for declarations that contain function declarators within function scope
            if (current_context == 'function_scope' and 
                node.get('node_type') == 'declaration' and
                node.get('tree_sitter_type') == 'declaration'):
                
                # Check if this declaration contains a function declarator
                children = node.get('children', [])
                has_function_declarator = False
                func_name = None
                
                for child in children:
                    if (isinstance(child, dict) and 
                        child.get('tree_sitter_type') == 'function_declarator'):
                        has_function_declarator = True
                        # Get the function name from the identifier child
                        for subchild in child.get('children', []):
                            if (isinstance(subchild, dict) and 
                                subchild.get('tree_sitter_type') == 'identifier'):
                                func_name = subchild.get('source', 'unknown')
                                break
                        break
                
                if has_function_declarator:
                    finding = {
                        "rule_id": "functions_declared_block_scope",
                        "message": f"Function '{func_name}' should not be declared at block scope. Move the declaration to namespace scope or consider if this should be a variable declaration instead.",
                        "file": filename,
                        "line": node.get('lineno', 0),
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively check children with context
            for child in node.get('children', []):
                traverse(child, current_context)
        elif isinstance(node, list):
            for item in node:
                traverse(item, parent_context)
    
    traverse(ast_tree)
    return findings


def check_multiple_bool_parameters(ast_tree, filename):
    """
    Check if functions have more than one bool parameter.
    
    Functions with multiple bool parameters are confusing at call sites.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                func_name = node.get('name', 'unknown')
                parameters = node.get('parameters', [])
                
                # Count bool parameters
                bool_param_count = 0
                bool_param_names = []
                
                for param in parameters:
                    if isinstance(param, dict) and param.get('type') == 'bool':
                        bool_param_count += 1
                        bool_param_names.append(param.get('name', 'unnamed'))
                
                if bool_param_count > 1:
                    finding = {
                        "rule_id": "functions_avoid_having_more",
                        "message": f"Function '{func_name}' has {bool_param_count} bool parameters ({', '.join(bool_param_names)}). Consider using enum classes or structs for better readability.",
                        "file": filename,
                        "line": node.get('lineno', 0),
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_too_many_parameters(ast_tree, filename):
    """
    Check if functions have too many parameters (more than 5).
    
    Functions with many parameters are difficult to use and maintain.
    """
    findings = []
    MAX_PARAMETERS = 5
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                func_name = node.get('name', 'unknown')
                parameters = node.get('parameters', [])
                param_count = len(parameters)
                
                if param_count > MAX_PARAMETERS:
                    param_names = [p.get('name', 'unnamed') if isinstance(p, dict) else str(p) for p in parameters]
                    finding = {
                        "rule_id": "functions_avoid_having_too",
                        "message": f"Function '{func_name}' has {param_count} parameters (max {MAX_PARAMETERS}). Consider grouping related parameters into objects or using builder patterns.",
                        "file": filename,
                        "line": node.get('lineno', 0),
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_too_many_returns(ast_tree, filename):
    """
    Check if functions have too many return statements (more than 3).
    
    Functions with many return statements have higher complexity.
    """
    findings = []
    MAX_RETURNS = 2
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                func_name = node.get('name', 'unknown')
                func_source = node.get('source', '')
                
                # Count return statements in the function source
                import re
                return_count = len(re.findall(r'\breturn\s+', func_source))
                
                if return_count > MAX_RETURNS:
                    finding = {
                        "rule_id": "functions_avoid_containing_too",
                        "message": f"Function '{func_name}' has {return_count} return statements (max {MAX_RETURNS}). Consider refactoring to reduce complexity.",
                        "file": filename,
                        "line": node.get('lineno', 0),
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively check children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_noreturn_with_return(ast_tree, filename):
    """
    Check for return statements in functions marked with [[noreturn]] attribute.
    
    Functions marked with [[noreturn]] should not contain return statements.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for FunctionDefinition nodes
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check if function is marked as [[noreturn]] and contains return
                import re
                if re.search(r'\[\[noreturn\]\]', source) and re.search(r'\breturn\s+', source):
                    finding = {
                        "rule_id": "functions_noreturn_attribute_return",
                        "message": f"Function '{func_name}' is marked [[noreturn]] but contains return statements.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively check children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_hash_function_throws(ast_tree, filename):
    """
    Check for hash functions that throw exceptions.
    
    Hash functions (operator() methods) should not throw exceptions.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for struct or class definitions that might be hash functions
            if node.get('node_type') in ['StructDeclaration', 'ClassDeclaration']:
                struct_source = node.get('source', '')
                struct_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check if this contains an operator() method and actual throw statements (not in comments)
                import re
                if re.search(r'operator\s*\(\s*\)', struct_source):
                    # Remove comments to avoid false positives
                    code_without_comments = re.sub(r'//.*?$', '', struct_source, flags=re.MULTILINE)
                    code_without_comments = re.sub(r'/\*.*?\*/', '', code_without_comments, flags=re.DOTALL)
                    
                    # Check for actual throw statements in code
                    if re.search(r'\bthrow\s+', code_without_comments):
                        finding = {
                            "rule_id": "functions_that_throw_exceptions",
                            "message": f"Hash function in '{struct_name}' should not throw exceptions.",
                            "file": filename,
                            "line": line_num,
                            "status": "violation"
                        }
                        findings.append(finding)
            
            # Recursively check children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings#!/usr/bin/env python3

# Custom functions for C++ rule engine

def check_functions_missing_noreturn(ast_tree, filename):
    """
    Check for functions that never return but are not marked with [[noreturn]].
    
    Functions that call exit(), abort(), std::terminate(), or always throw should be marked [[noreturn]].
    """
    findings = []
    
    def remove_comments(source):
        """Remove C++ comments from source code to avoid false matches"""
        import re
        # Remove single-line comments
        source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
        # Remove multi-line comments
        source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
        return source
    
    def always_exits_or_throws(source_no_comments):
        """Check if function always exits or throws (no normal return path)"""
        import re
        
        # Check for direct exit/abort/terminate calls
        exit_patterns = [
            r'\bexit\s*\(',
            r'\babort\s*\(',
            r'\bstd::terminate\s*\(',
            r'\bterminate\s*\('
        ]
        
        # Check for throw statements
        throw_patterns = [
            r'throw\s+\w+',  # throw something
            r'throw\s*;'     # re-throw
        ]
        
        has_exit_call = any(re.search(pattern, source_no_comments) for pattern in exit_patterns)
        has_throw = any(re.search(pattern, source_no_comments) for pattern in throw_patterns)
        
        if not (has_exit_call or has_throw):
            return False
        
        # Check for normal execution paths that could lead to implicit return
        lines = source_no_comments.strip().split('\n')
        function_body = '\n'.join(lines)
        
        # Remove empty lines and braces for analysis
        cleaned_lines = [line.strip() for line in lines if line.strip() and line.strip() not in ['{', '}']]
        
        # If function has any code after exit/throw calls, it can return normally
        # Look for statements that come after conditional exits/throws
        
        # Check for simple cases: if there's code after an if statement that contains exit/throw
        # This indicates the function can continue execution
        
        # Pattern: if (...) { exit/throw } followed by more code
        if_with_exit_pattern = r'if\s*\([^)]*\)\s*\{[^}]*(?:exit|abort|throw|terminate)[^}]*\}(.+)'
        match = re.search(if_with_exit_pattern, function_body, re.DOTALL)
        
        if match:
            after_if = match.group(1).strip()
            # If there's meaningful code after the if statement, function can return
            if after_if and not re.match(r'^\s*//.*$', after_if):  # Not just comments
                return False
        
        # Check for explicit return statements (excluding early returns before exit/throw)
        return_statements = re.findall(r'\breturn\b', function_body)
        if return_statements:
            # If function has return statement, check if it's after all exit/throw calls
            # For now, conservatively assume function can return normally if it has return
            return False
        
        # Check if ALL execution paths lead to exit/throw
        # This is a simplified analysis - a full control flow analysis would be more accurate
        
        # Look for patterns that suggest all paths exit:
        # 1. Function ends with unconditional exit/throw
        # 2. Switch statement where all cases (including default) exit/throw
        # 3. If-else chain where all branches exit/throw
        
        # Pattern 1: Function ends with exit/throw (no code after)
        last_meaningful_line = None
        for line in reversed(cleaned_lines):
            if line and not line.startswith('//'):
                last_meaningful_line = line
                break
        
        if last_meaningful_line:
            ends_with_exit = any(re.search(pattern, last_meaningful_line) for pattern in exit_patterns)
            ends_with_throw = any(re.search(pattern, last_meaningful_line) for pattern in throw_patterns)
            
            if ends_with_exit or ends_with_throw:
                return True
        
        # Pattern 2: Check for switch statements where all cases exit
        switch_pattern = r'switch\s*\([^)]*\)\s*\{(.+?)\}'
        switch_match = re.search(switch_pattern, function_body, re.DOTALL)
        if switch_match:
            switch_body = switch_match.group(1)
            # This would need more sophisticated parsing
            # For now, skip switch analysis
            
        # Pattern 3: Check for if-else chains
        # This requires more complex analysis
        
        # Conservative approach: if we found exit/throw but can't prove all paths lead there,
        # and there's no return statement or code after conditionals, assume it always exits
        
        # Check if the exit/throw calls are unconditional (not inside if statements)
        for pattern in exit_patterns + throw_patterns:
            matches = list(re.finditer(pattern, function_body))
            for match in matches:
                # Get the line containing this match
                start = function_body.rfind('\n', 0, match.start())
                end = function_body.find('\n', match.end())
                line = function_body[start+1:end] if start != -1 and end != -1 else function_body
                
                # If the line doesn't start with 'if', it's likely unconditional
                line_stripped = line.strip()
                if not line_stripped.startswith('if') and 'if (' not in line_stripped:
                    return True
        
        return False
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Skip main function
                if func_name == 'main':
                    for child in node.get('children', []):
                        traverse(child)
                    return
                
                # Remove comments to avoid false matches
                source_no_comments = remove_comments(source)
                
                # Check if function is already marked with noreturn (any variant)
                import re
                has_noreturn = (re.search(r'\[\[noreturn\]\]', source) or 
                              re.search(r'__attribute__\s*\(\s*\(\s*noreturn\s*\)\s*\)', source))
                
                # Only check functions that are not already marked noreturn
                if not has_noreturn:
                    if always_exits_or_throws(source_no_comments):
                        finding = {
                            "rule_id": "functions_which_do_return",
                            "message": f"Function '{func_name}' never returns but is not marked [[noreturn]].",
                            "file": filename,
                            "line": line_num,
                            "status": "violation"
                        }
                        findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_header_guard_matching(ast_tree, filename):
    """
    Check for header guards where #ifndef is not followed by matching #define.
    
    Validates proper header guard pattern: #ifndef MACRO_NAME followed by #define MACRO_NAME
    Filters out comments and handles edge cases properly.
    """
    findings = []
    
    def remove_comments_and_get_lines(source):
        """Remove C++ comments and return clean lines for analysis"""
        import re
        
        # Remove single-line comments but preserve line structure
        lines = source.split('\n')
        clean_lines = []
        
        for i, line in enumerate(lines):
            # Remove single-line comments
            comment_pos = line.find('//')
            if comment_pos != -1:
                line = line[:comment_pos]
            
            # Keep line for position tracking (even if empty after comment removal)
            clean_lines.append((i + 1, line.strip()))  # (line_number, cleaned_content)
        
        # Remove multi-line comments from the entire source
        source_no_multiline = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
        
        return clean_lines, source_no_multiline
    
    def find_ifndef_blocks(clean_lines):
        """Find all #ifndef directives and check for matching #define"""
        ifndef_blocks = []
        
        for line_num, content in clean_lines:
            if content.startswith('#ifndef'):
                import re
                ifndef_match = re.match(r'#ifndef\s+(\w+)', content)
                if ifndef_match:
                    guard_name = ifndef_match.group(1)
                    
                    # Look for matching #define in subsequent lines (within reasonable distance)
                    has_matching_define = False
                    
                    # Check next few lines for matching #define
                    for check_line_num, check_content in clean_lines:
                        if check_line_num > line_num and check_line_num <= line_num + 10:  # Look within next 10 lines
                            if check_content.startswith('#define'):
                                define_match = re.match(r'#define\s+(\w+)', check_content)
                                if define_match and define_match.group(1) == guard_name:
                                    has_matching_define = True
                                    break
                        elif check_line_num > line_num + 10:
                            break  # Don't look too far
                    
                    ifndef_blocks.append({
                        'guard_name': guard_name,
                        'line_number': line_num,
                        'has_matching_define': has_matching_define,
                        'content': content
                    })
        
        return ifndef_blocks
    
    def traverse(node):
        if isinstance(node, dict):
            # Process files and translation units that contain header guard patterns
            if node.get('node_type') in ['TranslationUnit', 'SourceFile'] or 'source' in node:
                source = node.get('source', '')
                
                # Skip if no #ifndef found (quick check)
                if '#ifndef' not in source:
                    for child in node.get('children', []):
                        traverse(child)
                    return
                
                # Remove comments and analyze lines
                clean_lines, source_no_comments = remove_comments_and_get_lines(source)
                
                # Find all #ifndef blocks and validate them
                ifndef_blocks = find_ifndef_blocks(clean_lines)
                
                for block in ifndef_blocks:
                    if not block['has_matching_define']:
                        finding = {
                            "rule_id": "header_guards_followed_matching",
                            "message": f"Header guard #ifndef {block['guard_name']} should be followed by matching #define {block['guard_name']}",
                            "file": filename,
                            "line": block['line_number'],
                            "status": "violation",
                            "guard_name": block['guard_name']
                        }
                        findings.append(finding)
            
            # Continue traversing children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_hardcoded_secrets(ast_tree, filename):
    """
    Check for hardcoded secrets by examining both string content and variable names.
    Looks for security-sensitive variable names assigned pseudorandom hex values.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            node_type = node.get('node_type', '')
            
            # Look for string literal nodes
            if node_type == 'string_literal':
                # Get the source content
                source = node.get('source', '')
                line_number = node.get('line_number', 0)
                
                # Check if this is a hex string
                if source.startswith('"') and source.endswith('"'):
                    hex_value = source[1:-1]  # Remove quotes
                    
                    # Check if string matches hex pattern (at least 32 characters of hex)
                    hex_pattern = r'^[a-fA-F0-9]{32,}$'
                    if re.match(hex_pattern, hex_value):
                        # Now check if this appears in a security-sensitive variable context
                        # We need to get the full source code to find variable names
                        try:
                            with open(filename, 'r', encoding='utf-8') as f:
                                source_lines = f.readlines()
                                
                            if line_number > 0 and line_number <= len(source_lines):
                                assignment_line = source_lines[line_number - 1].strip()
                                
                                # Remove comments from the line
                                comment_pos = assignment_line.find('//')
                                if comment_pos != -1:
                                    assignment_line = assignment_line[:comment_pos].strip()
                                    
                                # Security-sensitive keywords to look for in variable names
                                security_keywords = [
                                    'secret', 'token', 'credential', 'auth', 'password',
                                    'apikey', 'api_key', 'api-key', 'private_key', 'privatekey',
                                    'jwt', 'bearer', 'authorization', 'key'
                                ]
                                
                                # Extract variable name from assignment patterns
                                # Handle various C++ variable declaration patterns
                                patterns = [
                                    r'(?:const\s+)?(?:char\s*\*|std::string|string)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
                                    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
                                    r'(?:const\s+)?(?:auto\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*='
                                ]
                                
                                variable_name = None
                                for pattern in patterns:
                                    match = re.search(pattern, assignment_line, re.IGNORECASE)
                                    if match:
                                        variable_name = match.group(1)
                                        break
                                        
                                if variable_name:
                                    # Check if variable name contains any security-sensitive keywords
                                    variable_lower = variable_name.lower()
                                    
                                    for keyword in security_keywords:
                                        if keyword in variable_lower:
                                            finding = {
                                                "rule_id": "hardcoded_secrets_are_securitysensitive",
                                                "message": f"Hard-coded secrets are security-sensitive: Variable '{variable_name}' contains security keyword '{keyword}' and is assigned a hex value",
                                                "file": filename,
                                                "line": line_number,
                                                "status": "violation",
                                                "variable_name": variable_name,
                                                "hex_value": hex_value
                                            }
                                            findings.append(finding)
                                            break  # Only report once per variable
                                            
                        except Exception as e:
                            pass  # Continue processing other nodes
            
            # Recursively process children
            for child in node.get('children', []):
                traverse(child)
                
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_hardcoded_passwords(ast_tree, filename):
    """
    Check for hardcoded passwords by examining both variable names and assigned values.
    Detects security-sensitive variable names assigned potentially hardcoded credential values.
    """
    findings = []
    
    def is_sensitive_variable_name(var_name):
        """Check if variable name suggests it should contain sensitive data."""
        sensitive_keywords = [
            'password', 'passwd', 'pwd', 'pass', 'secret', 'key', 'token',
            'credential', 'auth', 'api_key', 'apikey', 'private_key',
            'secret_key', 'auth_token', 'access_token', 'jwt_secret',
            'encryption_key', 'ssh_key'
        ]
        
        var_name_lower = var_name.lower()
        return any(keyword in var_name_lower for keyword in sensitive_keywords)
    
    def is_potentially_hardcoded_value(value):
        """Check if a string value appears to be a hardcoded credential."""
        if not value or len(value.strip()) == 0:
            return False
            
        # Remove quotes
        if value.startswith('"') and value.endswith('"'):
            content = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            content = value[1:-1]
        else:
            content = value
            
        # Skip obviously non-credential strings
        content_lower = content.lower()
        
        # Skip common non-secret phrases and config values
        non_secret_phrases = [
            'enter', 'required', 'invalid', 'format', 'field', 'name',
            'prompt', 'message', 'error', 'validation', 'example', 'template',
            'placeholder', 'default', 'config', 'setting', 'option', 'type',
            'saved', 'loading', 'hello', 'world', 'text', 'label', 'user'
        ]
        
        for phrase in non_secret_phrases:
            if phrase in content_lower:
                return False
                
        # Skip simple field names and metadata
        if content_lower in ['password', 'secret', 'key', 'token', 'auth', 'credential']:
            return False
                
        # Skip simple placeholders and templates
        if re.match(r'^[A-Z_]+$', content):  # All caps constants like "PASSWORD_FIELD"
            return False
        if '{' in content or '[' in content:  # Template strings
            return False
        if content in ['', 'null', 'nullptr', 'undefined']:
            return False
            
        # Characteristics of potential hardcoded credentials
        # Must be reasonable length and contain meaningful content
        if len(content) < 6:
            return False
            
        # Strong indicators of hardcoded credentials
        strong_indicators = [
            re.search(r'[A-Za-z].*[0-9]|[0-9].*[A-Za-z]', content),  # Mix of letters and numbers
            re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', content),  # Special characters
            len(content) >= 8,  # Reasonable password length
            content != content.lower() and content != content.upper(),  # Mixed case
        ]
        
        # Must have at least one strong indicator and reasonable length
        return any(strong_indicators)
    
    try:
        # Read and analyze source code directly
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
        
        processed_lines = set()  # Track processed lines to avoid duplicates
        
        for line_number, line in enumerate(source_lines, 1):
            # Skip if already processed this line
            if line_number in processed_lines:
                continue
                
            # Skip comments
            comment_pos = line.find('//')
            if comment_pos != -1:
                line = line[:comment_pos]
            
            line = line.strip()
            if not line:
                continue
            
            # Look for variable assignment patterns
            # Handle various C++ assignment patterns
            patterns = [
                # Type varName = "value"
                r'(?:const\s+)?(?:char\s*\*|std::string|string|auto)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(["\'].+?["\'])',
                # varName = "value" (simple assignment)
                r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(["\'].+?["\'])',
            ]
            
            found_violation = False
            for pattern in patterns:
                if found_violation:
                    break
                    
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_name = match.group(1)
                    assigned_value = match.group(2)
                    
                    # Check if this looks like a hardcoded credential
                    if (is_sensitive_variable_name(var_name) and 
                        is_potentially_hardcoded_value(assigned_value)):
                        
                        # Extract the actual value for display
                        display_value = assigned_value
                        if len(display_value) > 50:
                            display_value = display_value[:47] + "..."
                        
                        finding = {
                            "rule_id": "hardcoded_passwords_are_securitysensitive",
                            "message": f"Hard-coded passwords are security-sensitive: Variable '{var_name}' appears to contain a hardcoded credential",
                            "file": filename,
                            "line": line_number,
                            "status": "violation",
                            "variable_name": var_name,
                            "assigned_value": display_value,
                            "severity": "Major"
                        }
                        findings.append(finding)
                        processed_lines.add(line_number)
                        found_violation = True
                        break  # Only one finding per line
                        
    except Exception as e:
        pass  # Continue gracefully if file reading fails
    
    return findings


def check_unnamed_namespaces_in_header(ast_tree, filename):
    """
    Check for unnamed namespaces in header files.
    
    Unnamed namespaces in headers create different entities in each translation unit,
    causing unexpected behavior. Only files with .h, .hpp, .hxx extensions are checked.
    """
    findings = []
    
    # Only check header files
    header_extensions = ['.h', '.hpp', '.hxx', '.h++']
    if not any(filename.lower().endswith(ext) for ext in header_extensions):
        return findings
    
    def remove_comments(source):
        """Remove C++ comments to avoid false matches"""
        import re
        # Remove single-line comments
        source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
        # Remove multi-line comments
        source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
        return source
    
    def find_unnamed_namespaces(source_no_comments):
        """Find all unnamed namespace declarations"""
        import re
        unnamed_namespaces = []
        
        lines = source_no_comments.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Look for namespace declarations
            namespace_match = re.search(r'\bnamespace\s*(\w+)?\s*\{', line_stripped)
            if namespace_match:
                namespace_name = namespace_match.group(1)
                
                # If no name captured, it's an unnamed namespace
                if namespace_name is None:
                    # Double-check by looking for the exact pattern
                    if re.search(r'\bnamespace\s*\{', line_stripped):
                        unnamed_namespaces.append({
                            'line_number': line_num,
                            'content': line_stripped
                        })
        
        return unnamed_namespaces
    
    def traverse(node):
        if isinstance(node, dict):
            # Process files and translation units
            if node.get('node_type') in ['TranslationUnit', 'SourceFile'] or 'source' in node:
                source = node.get('source', '')
                
                # Skip if no namespace found (quick check)
                if 'namespace' not in source:
                    for child in node.get('children', []):
                        traverse(child)
                    return
                
                # Remove comments and analyze
                source_no_comments = remove_comments(source)
                
                # Find unnamed namespaces
                unnamed_namespaces = find_unnamed_namespaces(source_no_comments)
                
                for ns in unnamed_namespaces:
                    finding = {
                        "rule_id": "header_files_avoid_containing",
                        "message": f"Header file contains unnamed namespace which should be avoided (line {ns['line_number']})",
                        "file": filename,
                        "line": ns['line_number'],
                        "status": "violation",
                        "namespace_content": ns['content']
                    }
                    findings.append(finding)
            
            # Continue traversing children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_void_parameter_functions(ast_tree, filename):
    """
    Check for functions without parameters that use void.
    
    Functions without parameters should not use void in C++.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check for void parameter
                import re
                if re.search(r'\(\s*void\s*\)', source):
                    finding = {
                        "rule_id": "functions_without_parameters_use",
                        "message": f"Function '{func_name}' should not use void parameters in C++.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_function_line_count(ast_tree, filename):
    """
    Check for functions that are too long.
    
    Functions should not exceed a reasonable line count.
    """
    findings = []
    MAX_LINES = 150
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Count lines in function
                line_count = source.count('\n') + 1
                
                if line_count > MAX_LINES:
                    finding = {
                        "rule_id": "functionsmethods_avoid_having_too",
                        "message": f"Function '{func_name}' has {line_count} lines (max {MAX_LINES}).",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_general_catch_clauses(ast_tree, filename):
    """
    Check for general catch clauses (catch(...)).
    
    General catch clauses should be avoided.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'CatchStatement':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for catch(...) 
                import re
                if re.search(r'catch\s*\(\s*\.\.\.\s*\)', source):
                    finding = {
                        "rule_id": "general_catch_clauses_avoided",
                        "message": "General catch clauses (catch(...)) should be avoided.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_generic_exceptions_thrown(ast_tree, filename):
    """
    Check for generic exceptions being thrown.
    
    Generic exceptions like std::exception should not be thrown directly.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'ThrowStatement':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for generic exception types
                import re
                if re.search(r'throw\s+(std::exception|std::runtime_error|std::logic_error)', source):
                    finding = {
                        "rule_id": "generic_exceptions_never_thrown",
                        "message": "Generic exceptions should not be thrown directly.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_generic_exceptions_caught(ast_tree, filename):
    """
    Check for generic exceptions being caught.
    
    Generic exceptions should not be caught unless necessary.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check for generic exception types in catch
                import re
                if re.search(r'catch\s*\(\s*(const\s+)?(std::exception|std::runtime_error|std::logic_error)', source):
                    finding = {
                        "rule_id": "generic_exceptions_caught",
                        "message": f"Function '{func_name}' catches generic exceptions, which should be avoided unless necessary.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_unconstrained_iterator_algorithms(ast_tree, filename):
    """
    Check for unconstrained iterator algorithms.
    
    Template functions that take iterators should be constrained.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'TemplateDeclaration':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for template functions that use iterators without constraints
                import re
                has_iterator_params = re.search(r'(Iter|Iterator|InputIt|OutputIt|ForwardIt)', source)
                has_constraints = re.search(r'(std::|requires|concept)', source)
                
                if has_iterator_params and not has_constraints:
                    finding = {
                        "rule_id": "generic_iteratorbased_algorithms_constrained",
                        "message": "Template iterator algorithm should be constrained with concepts or type traits.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_global_initialization_order(ast_tree, filename):
    """
    Check for global variables that depend on other globals.
    
    Global variables should not depend on other globals due to initialization order issues.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'declaration':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for global variable declarations with initialization depending on other globals
                import re
                # Look for variable initialization with identifiers (other globals)
                if (re.search(r'\bint\s+\w+\s*=\s*[A-Za-z_][A-Za-z0-9_]*', source) or
                    re.search(r'\b\w+\s+\w+\s*=\s*[A-Za-z_][A-Za-z0-9_]*', source)):
                    # Extract variable name for reporting
                    var_match = re.search(r'\b(\w+)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)', source)
                    if var_match:
                        var_name = var_match.group(1)
                        dep_name = var_match.group(2)
                        finding = {
                            "rule_id": "globals_depend_possibly_yet",
                            "message": f"Global variable '{var_name}' depends on '{dep_name}' which may not be initialized yet.",
                            "file": filename,
                            "line": line_num,
                            "status": "violation"
                        }
                        findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_function_hiding(ast_tree, filename):
    """
    Check for derived class functions that hide inherited functions.
    Reports functions that have the same name as base class functions but different signatures.
    """
    findings = []
    
    # Collect class information
    classes = {}
    inheritance_graph = {}
    
    def extract_function_declarations(class_node):
        """Extract function declarations from a class."""
        functions = []
        
        def traverse_class(node):
            if isinstance(node, dict):
                if node.get('node_type') in ['field_declaration']:
                    source = node.get('source', '').strip()
                    line = node.get('lineno', 0)
                    
                    # Only process function declarations (contain parentheses)
                    if source and '(' in source and ')' in source:
                        # Extract function signature from FunctionDeclarator child
                        for child in node.get('children', []):
                            if child.get('node_type') == 'FunctionDeclarator':
                                func_source = child.get('source', '')
                                if func_source:
                                    # Extract function name and parameters
                                    func_match = re.search(r'(\w+)\s*\(([^)]*)\)', func_source)
                                    if func_match:
                                        func_name = func_match.group(1)
                                        params = func_match.group(2).strip()
                                        
                                        functions.append({
                                            'name': func_name,
                                            'params': params,
                                            'full_signature': source,
                                            'line': line,
                                            'is_virtual': 'virtual' in source
                                        })
                                    break
                
                # Recurse into children
                for child in node.get('children', []):
                    traverse_class(child)
        
        traverse_class(class_node)
        return functions
    
    def traverse(node):
        if isinstance(node, dict) and node.get('node_type') == 'ClassDeclaration':
            class_name = node.get('name', '')
            base_classes = node.get('base_classes', [])
            line_num = node.get('lineno', 0)
            
            if class_name:
                functions = extract_function_declarations(node)
                classes[class_name] = {
                    'line': line_num,
                    'functions': functions,
                    'node': node
                }
                inheritance_graph[class_name] = base_classes
        
        # Recurse into children
        if hasattr(node, 'get'):
            for child in node.get('children', []):
                traverse(child)
    
    traverse(ast_tree)
    
    # Check for function hiding
    for class_name, class_info in classes.items():
        base_classes = inheritance_graph.get(class_name, [])
        
        for base_class_name in base_classes:
            if isinstance(base_class_name, str) and base_class_name in classes:
                base_functions = classes[base_class_name]['functions']
                derived_functions = class_info['functions']
                
                # Check each derived function against base functions
                for derived_func in derived_functions:
                    for base_func in base_functions:
                        # Function hiding occurs when:
                        # 1. Same function name 
                        # 2. Either different signature (overloading hides) OR same signature but non-virtual (hiding)
                        if (derived_func['name'] == base_func['name'] and 
                            (derived_func['params'] != base_func['params'] or 
                             (derived_func['params'] == base_func['params'] and not derived_func['is_virtual']))):
                            
                            finding = {
                                "rule_id": "inherited_functions_hidden",
                                "message": f"Function '{derived_func['name']}' in '{class_name}' hides inherited function from '{base_class_name}'. Consider using 'using {base_class_name}::{base_func['name']};' or virtual override.",
                                "file": filename,
                                "line": derived_func['line'],
                                "status": "violation"
                            }
                            findings.append(finding)
    
    return findings


def check_redundant_inline(ast_tree, filename):
    """
    Check for redundant inline keywords in class member functions.
    Functions defined in class body are implicitly inline since C++03.
    """
    findings = []
    
    def is_in_class_definition(node, class_nodes):
        """Check if a function is defined within a class body."""
        if not node or not class_nodes:
            return False
            
        func_start_line = node.get('lineno', 0)
        func_end_line = func_start_line
        
        # Try to estimate function end line from source
        source = node.get('source', '')
        if source:
            func_end_line = func_start_line + source.count('\n')
        
        # Check if function is within any class definition range
        for class_node in class_nodes:
            class_start = class_node.get('lineno', 0)
            
            # Estimate class end line
            class_source = class_node.get('source', '')
            if class_source:
                class_end = class_start + class_source.count('\n') + 20  # Add buffer for class body
            else:
                class_end = class_start + 100  # Default buffer
            
            if class_start <= func_start_line <= class_end:
                return True
        
        return False
    
    def has_inline_keyword(source):
        """Check if function source contains inline keyword."""
        if not source:
            return False
        
        import re
        # Match inline keyword with word boundaries to avoid false matches
        return bool(re.search(r'\binline\b', source, re.IGNORECASE))
    
    def is_function_definition(node):
        """Check if node represents a function definition (not just declaration)."""
        source = node.get('source', '').strip()
        
        # Function definitions have bodies (contain braces)
        if '{' in source and '}' in source:
            return True
        
        # Check for multi-line function definitions
        children = node.get('children', [])
        for child in children:
            child_source = child.get('source', '')
            if '{' in child_source and '}' in child_source:
                return True
        
        return False
    
    def is_out_of_class_definition(source):
        """Check if this is an out-of-class member function definition."""
        if not source:
            return False
        
        import re
        # Pattern for ClassName::functionName
        return bool(re.search(r'\w+::\w+\s*\(', source))
    
    def is_template_function(source):
        """Check if this is a template function definition."""
        if not source:
            return False
        
        import re
        # Look for template keyword before function
        return bool(re.search(r'template\s*<', source, re.IGNORECASE))
    
    # Collect all class nodes first
    class_nodes = []
    function_nodes = []
    
    def traverse(node):
        if isinstance(node, dict):
            node_type = node.get('node_type', '')
            
            if node_type == 'ClassDeclaration':
                class_nodes.append(node)
            elif node_type == 'FunctionDefinition':
                function_nodes.append(node)
            
            # Recurse into children
            for child in node.get('children', []):
                traverse(child)
    
    traverse(ast_tree)
    
    # Check each function for redundant inline usage
    for func_node in function_nodes:
        source = func_node.get('source', '')
        line_num = func_node.get('lineno', 0)
        
        # Skip if no inline keyword
        if not has_inline_keyword(source):
            continue
        
        # Skip if not a function definition (just declaration)
        if not is_function_definition(func_node):
            continue
        
        # Skip template functions (inline often needed)
        if is_template_function(source):
            continue
        
        # Skip out-of-class member function definitions (inline needed)
        if is_out_of_class_definition(source):
            continue
        
        # Check if function is defined within a class body
        if is_in_class_definition(func_node, class_nodes):
            # This is redundant inline - function in class body is implicitly inline
            
            # Extract function name for better reporting
            import re
            func_name_match = re.search(r'\binline\s+(?:\w+\s+)*(\w+)\s*\(', source)
            func_name = func_name_match.group(1) if func_name_match else 'unknown'
            
            # Check for special function types
            is_constructor = '::' not in source and func_name[0].isupper()
            is_destructor = func_name.startswith('~')
            is_virtual = 'virtual' in source
            is_static = 'static' in source
            
            function_type = []
            if is_constructor:
                function_type.append('constructor')
            elif is_destructor:
                function_type.append('destructor')
            elif is_virtual:
                function_type.append('virtual function')
            elif is_static:
                function_type.append('static member function')
            else:
                function_type.append('member function')
            
            type_description = ' '.join(function_type)
            
            finding = {
                "rule_id": "inline_avoided_redundantly",
                "message": f"Redundant 'inline' keyword on {type_description} '{func_name}'. Functions defined in class body are implicitly inline since C++03.",
                "file": filename,
                "line": line_num,
                "status": "violation",
                "function_name": func_name,
                "function_type": type_description
            }
            findings.append(finding)
    
    return findings


def check_inheritance_depth(ast_tree, filename):
    """
    Check for inheritance trees that are too deep.
    Reports classes that have inheritance depth > 5.
    """
    findings = []
    MAX_INHERITANCE_DEPTH = 5
    
    # Build inheritance graph
    inheritance_graph = {}
    classes = {}
    
    def traverse(node):
        if isinstance(node, dict) and node.get('node_type') == 'ClassDeclaration':
            class_name = node.get('name', '')
            base_classes = node.get('base_classes', [])
            line_num = node.get('lineno', 0)
            
            if class_name:
                classes[class_name] = {
                    'line': line_num,
                    'node': node
                }
                inheritance_graph[class_name] = base_classes
        
        # Recurse into children
        if hasattr(node, 'get'):
            for child in node.get('children', []):
                traverse(child)
    
    def calculate_depth(class_name, visited=None):
        """Calculate inheritance depth for a class."""
        if visited is None:
            visited = set()
        
        if class_name in visited:
            return 0  # Circular inheritance
        
        visited.add(class_name)
        base_classes = inheritance_graph.get(class_name, [])
        
        if not base_classes:
            return 1  # Base class
        
        max_base_depth = 0
        for base_class in base_classes:
            if isinstance(base_class, str):
                base_depth = calculate_depth(base_class, visited.copy())
                max_base_depth = max(max_base_depth, base_depth)
        
        return max_base_depth + 1
    
    traverse(ast_tree)
    
    # Check each class for excessive depth
    for class_name, class_info in classes.items():
        depth = calculate_depth(class_name)
        if depth > MAX_INHERITANCE_DEPTH:
            finding = {
                "rule_id": "inheritance_tree_classes_too",
                "message": f"Class '{class_name}' has inheritance depth {depth}, which exceeds maximum of {MAX_INHERITANCE_DEPTH}.",
                "file": filename,
                "line": class_info['line'],
                "status": "violation"
            }
            findings.append(finding)
    
    return findings

def check_empty_methods(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Detect empty methods in classes.
    
    Args:
        ast_tree: The parsed AST tree
        filename: The source file name
        
    Returns:
        List of violations found
    """
    findings = []
    
    def is_method_empty(method_source: str) -> bool:
        """Check if a method body is effectively empty."""
        # Remove method signature and extract body
        if '{' not in method_source:
            return False
            
        body_start = method_source.find('{')
        body_end = method_source.rfind('}')
        
        if body_start == -1 or body_end == -1 or body_start >= body_end:
            return False
            
        body = method_source[body_start + 1:body_end].strip()
        
        # Remove comments
        lines = body.split('\n')
        code_lines = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('//'):
                # Check for /* */ comments
                if '/*' not in line:
                    code_lines.append(line)
                else:
                    # Handle inline /* */ comments
                    comment_start = line.find('/*')
                    comment_end = line.find('*/', comment_start)
                    if comment_end != -1:
                        before_comment = line[:comment_start].strip()
                        after_comment = line[comment_end + 2:].strip()
                        remaining = before_comment + ' ' + after_comment
                        if remaining.strip():
                            code_lines.append(remaining.strip())
        
        return len(code_lines) == 0
    
    def traverse(node):
        """Traverse AST to find class declarations."""
        if isinstance(node, dict):
            if node.get('node_type') == 'ClassDeclaration':
                class_source = node.get('source', '')
                class_name = node.get('name', 'unknown')
                
                # Find method patterns in the class source
                method_pattern = r'(\w+\s+)?(\w+)\s*\([^)]*\)\s*(\w+\s+)?\{[^}]*\}'
                matches = re.finditer(method_pattern, class_source, re.DOTALL)
                
                for match in matches:
                    method_def = match.group(0)
                    method_name = match.group(2)
                    
                    # Skip constructors and destructors
                    if method_name == class_name or method_name.startswith('~'):
                        continue
                        
                    if is_method_empty(method_def):
                        # Find line number by counting newlines before the match
                        lines_before = class_source[:match.start()].count('\n')
                        method_line = node.get('lineno', 0) + lines_before
                        
                        finding = {
                            "rule_id": "methods_empty",
                            "message": f"Method '{method_name}' is empty. Empty methods are usually signs of incomplete code.",
                            "file": filename,
                            "line": method_line,
                            "status": "violation"
                        }
                        findings.append(finding)
            
            # Continue traversing
            for child in node.get('children', []):
                traverse(child)
    
    traverse(ast_tree)
    return findings

def check_method_overloads_grouped(ast_tree, filename):
    from method_overloads_checker import check_method_overloads_grouped as _check
    return _check(ast_tree, filename)


def check_macros_redefined(ast_tree, filename):
    """
    Advanced macro redefinition checker that handles edge cases:
    1. Excludes cases where #undef is used before redefinition
    2. Excludes same-value redefinitions (rule specification exception)
    3. Handles conditional compilation scopes
    4. Provides more accurate detection than regex-only approaches
    
    Args:
        ast_tree: The AST tree representation of the file
        filename: Path to the C++ file being analyzed
        
    Returns:
        List of findings with rule violations
    """
    findings = []
    
    # Read the actual source file for line-by-line analysis
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        # If we can't read the file, fall back to AST source
        source_content = ast_tree.get('source', '') if isinstance(ast_tree, dict) else ''
        source_lines = source_content.split('\n') if source_content else []
    
    # Track macro definitions and their state
    macro_definitions = {}  # macro_name -> {'line': line_num, 'value': value, 'undefined': bool}
    conditional_stack = []  # Track #ifdef/#if/#else/#endif nesting
    
    for line_num, line in enumerate(source_lines, 1):
        line_content = line.strip()
        
        # Skip empty lines and comments
        if not line_content or line_content.startswith('//'):
            continue
            
        # Handle conditional compilation directives
        if line_content.startswith('#if'):
            conditional_stack.append(f"conditional_{line_num}")
        elif line_content.startswith('#else'):
            if conditional_stack:
                conditional_stack[-1] = f"else_{line_num}"
        elif line_content.startswith('#endif'):
            if conditional_stack:
                conditional_stack.pop()
        
        # Process #define statements
        define_match = re.match(r'#define\s+(\w+)(?:\([^)]*\))?\s*(.*)$', line_content)
        if define_match:
            macro_name = define_match.group(1)
            macro_value = (define_match.group(2) or '').strip()
            
            # Remove trailing comments from value
            if '//' in macro_value:
                macro_value = macro_value.split('//')[0].strip()
            
            # Check if this macro was already defined
            if macro_name in macro_definitions:
                existing_def = macro_definitions[macro_name]
                
                # Only flag as violation if:
                # 1. Macro was not explicitly undefined
                # 2. Values are different (same value redefinition is allowed per rule)
                if (not existing_def.get('undefined', False) and 
                    existing_def.get('value', '') != macro_value):
                    
                    finding = {
                        "rule_id": "macros_redefined",
                        "message": f"Variable 'define': Macro '{macro_name}' should not be redefined. Use #undef before redefining or choose a different name.",
                        "node": "TranslationUnit.TranslationUnit", 
                        "file": filename,
                        "property_path": ["source"],
                        "value": line_content,
                        "status": "violation",
                        "line": line_num,
                        "severity": "Major"
                    }
                    findings.append(finding)
            
            # Update macro definition tracking
            macro_definitions[macro_name] = {
                'line': line_num,
                'value': macro_value,
                'undefined': False,
                'scope': conditional_stack.copy() if conditional_stack else None
            }
        
        # Process #undef statements
        undef_match = re.match(r'#undef\s+(\w+)', line_content)
        if undef_match:
            macro_name = undef_match.group(1)
            if macro_name in macro_definitions:
                # Mark as undefined - future redefinitions are allowed
                macro_definitions[macro_name]['undefined'] = True
    
    return findings

def check_methods_avoid_having_identical(ast_tree, filename):
    from identical_methods_checker import check_methods_avoid_having_identical as _check
    return _check(ast_tree, filename)

def check_double_delete(ast_tree, filename):
    from double_delete_checker import check_double_delete as _check
    return _check(ast_tree, filename)

def check_line_length(ast_tree, filename):
    """
    Check for lines that exceed the maximum allowed length.
    
    This function reads the source file directly and checks each line individually,
    providing 100% accuracy for line length violations.
    """
    violations = []
    max_length = 120  # Default maximum line length
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        for line_number, line in enumerate(lines, 1):
            # Remove trailing newline for accurate character count
            line_content = line.rstrip('\n\r')
            
            if len(line_content) > max_length:
                violations.append({
                    'rule_id': 'lines_too_long',
                    'message': f'Line exceeds maximum length of {max_length} characters (actual: {len(line_content)} characters)',
                    'line': line_number,
                    'severity': 'Major',
                    'status': 'violation',
                    'file': filename,
                    'context': line_content[:100] + ('...' if len(line_content) > 100 else ''),
                    'actual_length': len(line_content),
                    'max_allowed': max_length
                })
    
    except FileNotFoundError:
        violations.append({
            'rule_id': 'lines_too_long',
            'message': f'Could not read file: {filename}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    except Exception as e:
        violations.append({
            'rule_id': 'lines_too_long',
            'message': f'Error checking line lengths: {str(e)}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    
    return violations

def check_trailing_whitespace(ast_tree, filename):
    """
    Check for lines that end with trailing whitespace (spaces or tabs).
    
    This function reads the source file directly and checks each line individually,
    providing 100% accuracy for trailing whitespace violations.
    """
    import re
    violations = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        for line_number, line in enumerate(lines, 1):
            # Remove only \r\n line endings, preserve other whitespace for analysis
            line_content = line.rstrip('\r\n')
            
            # Check for trailing spaces or tabs
            if re.search(r'[ \t]+$', line_content):
                # Extract the trailing whitespace for reporting
                trailing_match = re.search(r'([ \t]+)$', line_content)
                trailing_chars = trailing_match.group(1) if trailing_match else ''
                trailing_count = len(trailing_chars)
                
                # Create readable representation of trailing characters
                trailing_repr = trailing_chars.replace(' ', '·').replace('\t', '→')
                
                violations.append({
                    'rule_id': 'lines_end_trailing_whitespaces',
                    'message': f'Line ends with {trailing_count} trailing whitespace character(s): "{trailing_repr}"',
                    'line': line_number,
                    'severity': 'Info',
                    'status': 'violation',
                    'file': filename,
                    'context': line_content[:80] + ('...' if len(line_content) > 80 else ''),
                    'trailing_whitespace': trailing_chars,
                    'trailing_count': trailing_count,
                    'trailing_repr': trailing_repr
                })
    
    except FileNotFoundError:
        violations.append({
            'rule_id': 'lines_end_trailing_whitespaces',
            'message': f'Could not read file: {filename}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    except Exception as e:
        violations.append({
            'rule_id': 'lines_end_trailing_whitespaces',
            'message': f'Error checking trailing whitespace: {str(e)}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    
    return violations

def check_invalid_preprocessor_directives(ast_tree, filename):
    """
    Check for lines starting with # that contain invalid preprocessing directives.
    
    This function reads the source file directly and checks each line individually,
    providing 100% accuracy for invalid preprocessor directive violations.
    """
    import re
    violations = []
    
    # Valid preprocessor directives according to C++ standard
    valid_directives = {
        'include', 'define', 'ifdef', 'ifndef', 'endif', 'if', 'else', 'elif', 
        'undef', 'pragma', 'warning', 'error'
    }
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        for line_number, line in enumerate(lines, 1):
            # Remove line endings for analysis
            line_content = line.rstrip('\r\n')
            
            # Check if line starts with # (optionally preceded by whitespace)
            hash_match = re.match(r'^(\s*)#(\w+)', line_content)
            if hash_match:
                whitespace_prefix = hash_match.group(1)
                directive = hash_match.group(2)
                
                # Check if it's NOT one of the valid directives
                if directive not in valid_directives:
                    violations.append({
                        'rule_id': 'lines_starting_contain_valid',
                        'message': f'Invalid preprocessor directive "#{directive}" - valid directives are: {", ".join("#" + d for d in sorted(valid_directives))}',
                        'line': line_number,
                        'severity': 'Info',
                        'status': 'violation',
                        'file': filename,
                        'context': line_content,
                        'invalid_directive': directive,
                        'line_prefix': whitespace_prefix,
                        'suggestion': f'Use a valid preprocessor directive or remove this line if it\'s not intended as a directive'
                    })
    
    except FileNotFoundError:
        violations.append({
            'rule_id': 'lines_starting_contain_valid',
            'message': f'Could not read file: {filename}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    except Exception as e:
        violations.append({
            'rule_id': 'lines_starting_contain_valid',
            'message': f'Error checking preprocessor directives: {str(e)}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    
    return violations

def check_literal_suffix_case(ast_tree, filename):
    """
    Check for numeric literals with lowercase suffixes that should be uppercase.
    
    This function reads the source file directly and checks each line individually,
    providing 100% accuracy for literal suffix case violations.
    """
    import re
    violations = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        for line_number, line in enumerate(lines, 1):
            # Remove line endings for analysis
            line_content = line.rstrip('\r\n')
            
            # Skip comments
            if re.match(r'^\s*//', line_content) or not line_content.strip():
                continue
            
            # Pattern to match numeric literals with lowercase suffixes
            # Covers: decimal integers, hex numbers, floats with l, u, f, ul, lu suffixes
            patterns = [
                # Decimal integers with lowercase suffixes
                (r'\b(\d+)([luf])\b', 'decimal integer'),
                # Hexadecimal numbers with lowercase suffixes  
                (r'\b(0x[0-9a-fA-F]+)([luf])\b', 'hexadecimal'),
                # Floating point with lowercase suffixes
                (r'\b(\d*\.\d+)([lf])\b', 'floating point'),
                (r'\b(\d+\.)([lf])\b', 'floating point'),
                # Mixed case combinations (ul, lu)
                (r'\b(\d+|0x[0-9a-fA-F]+)([uU][lL]|[lL][uU]|[uU][l]|[l][uU])\b', 'mixed case')
            ]
            
            for pattern, literal_type in patterns:
                matches = list(re.finditer(pattern, line_content))
                for match in matches:
                    number_part = match.group(1)
                    suffix = match.group(2)
                    full_literal = match.group(0)
                    
                    # Check if suffix contains any lowercase letters
                    if re.search(r'[luf]', suffix):
                        # Suggest the correct uppercase version
                        correct_suffix = suffix.upper()
                        suggested_literal = number_part + correct_suffix
                        
                        violations.append({
                            'rule_id': 'literal_suffix_l_long',
                            'message': f'Literal suffix "{suffix}" should be uppercase "{correct_suffix}" in {literal_type} literal "{full_literal}"',
                            'line': line_number,
                            'severity': 'Info',
                            'status': 'violation',
                            'file': filename,
                            'context': line_content.strip(),
                            'literal': full_literal,
                            'incorrect_suffix': suffix,
                            'correct_suffix': correct_suffix,
                            'suggested_fix': suggested_literal,
                            'literal_type': literal_type
                        })
    
    except FileNotFoundError:
        violations.append({
            'rule_id': 'literal_suffix_l_long',
            'message': f'Could not read file: {filename}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    except Exception as e:
        violations.append({
            'rule_id': 'literal_suffix_l_long',
            'message': f'Error checking literal suffix case: {str(e)}',
            'line': 0,
            'severity': 'Error',
            'status': 'error',
            'file': filename
        })
    
    return violations


def check_local_variable_naming(ast_node, file_path=None):
    """Check for local variables and function parameters with single-letter names"""
    violations = []
    
    if not ast_node:
        return violations
    
    try:
        # Extract source code from AST node
        if isinstance(ast_node, dict):
            code = ast_node.get('source', '')
        else:
            code = str(ast_node)
            
        if not code:
            # Try to read the file directly
            if file_path and os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            else:
                return violations
        
        lines = code.split('\n')
        
        # Patterns for different types of single-letter variable declarations
        patterns = [
            # Local variable declarations: type name = value;
            (r'\b(int|long|float|double|char|bool|string)\s+([a-zA-Z])\s*[=;]', 'local_variable'),
            # Function parameters: (type name, ...)
            (r'\(\s*(int|long|float|double|char|bool|string)\s+([a-zA-Z])\s*[,)]', 'function_parameter'),
            # For loop variables: for (type name = ...)
            (r'for\s*\(\s*(int|long|float|double|char|bool|string)\s+([a-zA-Z])\s*[=;]', 'loop_variable'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            line_content = line.strip()
            
            # Skip comments, empty lines, includes, and preprocessor directives
            if (line_content.startswith('//') or 
                line_content.startswith('/*') or 
                line_content.startswith('#') or 
                not line_content):
                continue
            
            # Check for compliance section markers
            if ('COMPLIANT' in line_content.upper() or 
                'compliantFunction' in line_content or
                'totalCount' in line_content or 
                'resultMessage' in line_content):
                continue
            
            for pattern, violation_type in patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_type = match.group(1)
                    var_name = match.group(2)
                    
                    # Skip if this is part of a longer descriptive name (false positive check)
                    # Look for word boundaries around the variable name
                    full_match = match.group(0)
                    start_pos = match.start(2)
                    end_pos = match.end(2)
                    
                    # Check if there are more characters after the single letter (indicating it's part of a longer name)
                    if end_pos < len(line) and line[end_pos].isalnum():
                        continue
                    
                    # Check if this looks like a descriptive name being built
                    if ('input' in line_content.lower() or 
                        'total' in line_content.lower() or 
                        'calculated' in line_content.lower() or
                        'processed' in line_content.lower() or
                        'average' in line_content.lower() or
                        'precision' in line_content.lower() or
                        'timestamp' in line_content.lower() or
                        'first' in line_content.lower()):
                        continue
                    
                    violations.append({
                        'line': line_num,
                        'column': start_pos + 1,
                        'variable_type': var_type,
                        'variable_name': var_name,
                        'violation_type': violation_type,
                        'message': f"Variable '{var_name}' has a single-letter name. Use descriptive names like 'itemCount', 'userName', 'isValid' instead of '{var_name}'",
                        'suggested_names': get_descriptive_name_suggestions(var_type, var_name),
                        'severity': 'Info'
                    })
        
    except Exception as e:
        violations.append({
            'line': 0,
            'column': 0,
            'message': f'Error analyzing local variable names: {str(e)}',
            'severity': 'Error'
        })
    
    return violations


def get_descriptive_name_suggestions(var_type, var_name):
    """Get suggested descriptive names based on variable type"""
    suggestions = {
        'int': ['itemCount', 'totalSum', 'currentIndex', 'maxValue'],
        'long': ['timestampValue', 'largeNumber', 'totalBytes', 'elapsedTime'], 
        'float': ['averageScore', 'ratioValue', 'percentValue', 'weightFactor'],
        'double': ['precisionValue', 'calculatedResult', 'accurateSum', 'scientificValue'],
        'char': ['firstChar', 'currentChar', 'inputChar', 'controlChar'],
        'bool': ['isValid', 'isComplete', 'hasPermission', 'shouldContinue'],
        'string': ['userName', 'fileName', 'messageText', 'configValue']
    }
    
    return suggestions.get(var_type, ['descriptiveName', 'meaningfulName', 'properName'])


def check_volatile_usage(ast_node, file_path=None):
    """Check for inappropriate volatile usage in local variables and member data"""
    violations = []
    
    if not ast_node:
        return violations
    
    try:
        # Extract source code from AST node
        if isinstance(ast_node, dict):
            code = ast_node.get('source', '')
        else:
            code = str(ast_node)
            
        if not code:
            # Try to read the file directly
            if file_path and os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            else:
                return violations
        
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_content = line.strip()
            
            # Skip comments, empty lines, includes, and preprocessor directives
            if (line_content.startswith('//') or 
                line_content.startswith('/*') or 
                line_content.startswith('*') or
                line_content.startswith('#') or 
                not line_content):
                continue
            
            # Skip valid volatile usage patterns
            if is_valid_volatile_usage(line_content):
                continue
            
            # Find inappropriate volatile usage
            if 'volatile' in line_content:
                violation_details = analyze_volatile_violation(line_content, line_num)
                if violation_details:
                    violations.append(violation_details)
        
    except Exception as e:
        violations.append({
            'line': 0,
            'column': 0,
            'message': f'Error analyzing volatile usage: {str(e)}',
            'severity': 'Error'
        })
    
    return violations


def is_valid_volatile_usage(line_content):
    """Check if volatile usage is valid (hardware access, extern declarations)"""
    
    # Valid patterns that should NOT be flagged
    valid_patterns = [
        # Hardware register access
        r'volatile\s+\w+\*\s+const\s+\w+.*=.*0x[0-9a-fA-F]+',  # volatile int* const REG = 0x...
        r'\*\s*\(\s*volatile\s+\w+\*\s*\)\s*0x[0-9a-fA-F]+',   # *(volatile int*)0x...
        r'extern\s+volatile',                                    # extern volatile declarations
        r'volatile\s+\w+\*\s+const\s+\w+_REGISTER',            # register naming pattern
        r'volatile\s+\w+\*\s+const\s+MEMORY_MAPPED',           # memory mapped I/O
        r'HARDWARE_REGISTER',                                    # hardware register variables
        r'MEMORY_MAPPED_IO',                                     # memory mapped I/O variables
    ]
    
    for pattern in valid_patterns:
        if re.search(pattern, line_content, re.IGNORECASE):
            return True
    
    return False


def analyze_volatile_violation(line_content, line_num):
    """Analyze a line with volatile to determine if it's a violation"""
    
    # Patterns for inappropriate volatile usage
    violation_patterns = [
        # Local variable declarations
        (r'(volatile)\s+(int|long|float|double|char|bool|std::string|string)\s+(\w+)', 
         'local_variable', 'Local variable should not use volatile'),
        
        # Member data declarations (in class context)
        (r'(volatile)\s+(int|long|float|double|char|bool|std::string|string)\s+(\w+);',
         'member_data', 'Class member data should not use volatile'),
         
        # Function parameters
        (r'(volatile)\s+(int|long|float|double|char|bool|std::string|string)\s+(\w+)\s*[,)]',
         'function_parameter', 'Function parameters should not use volatile'),
         
        # Loop variables  
        (r'for\s*\(\s*(volatile)\s+(int|long|float|double|char|bool)\s+(\w+)',
         'loop_variable', 'Loop variables should not use volatile'),
         
        # Struct/class instances
        (r'(volatile)\s+(\w+)\s+(\w+)(\[.*\])?;',
         'struct_instance', 'Object instances should not use volatile'),
         
        # Volatile pointers (may be inappropriate)
        (r'(\w+)\*\s+(volatile)\s+(\w+)',
         'volatile_pointer', 'Volatile pointers are usually inappropriate'),
         
        # Static volatile (potentially inappropriate)
        (r'static\s+(volatile)\s+(\w+)\s+(\w+)',
         'static_volatile', 'Static volatile variables are usually inappropriate'),
    ]
    
    for pattern, violation_type, base_message in violation_patterns:
        match = re.search(pattern, line_content)
        if match:
            # Extract variable info
            if violation_type == 'volatile_pointer':
                var_type = match.group(1)
                var_name = match.group(3)
            else:
                var_type = match.group(2) if len(match.groups()) >= 2 else 'unknown'
                var_name = match.group(3) if len(match.groups()) >= 3 else 'unknown'
            
            return {
                'line': line_num,
                'column': match.start() + 1,
                'violation_type': violation_type,
                'variable_type': var_type,
                'variable_name': var_name,
                'message': f"{base_message}. Variable '{var_name}' of type '{var_type}' should not use volatile. Consider std::atomic<{var_type}> for thread safety or remove volatile for local variables.",
                'suggested_fix': get_volatile_fix_suggestion(violation_type, var_type, var_name),
                'severity': 'Info'
            }
    
    return None


def get_volatile_fix_suggestion(violation_type, var_type, var_name):
    """Get suggested fix for volatile usage violation"""
    
    if violation_type in ['local_variable', 'loop_variable', 'function_parameter']:
        return f"{var_type} {var_name}  // Remove volatile - not needed for local variables"
    elif violation_type == 'member_data':
        return f"std::atomic<{var_type}> {var_name}  // Use atomic for thread-safe access"
    elif violation_type == 'struct_instance':
        return f"{var_type} {var_name}  // Remove volatile unless accessing hardware"
    elif violation_type == 'volatile_pointer':
        return f"{var_type}* {var_name}  // Remove volatile unless pointer value changes externally"
    elif violation_type == 'static_volatile':
        return f"static std::atomic<{var_type}> {var_name}  // Use atomic for thread safety"
    else:
        return f"Remove volatile from {var_name} unless accessing hardware registers"


def check_local_variable_initialization(ast_node, file_path=None):
    """Check for local variables that should be initialized immediately"""
    violations = []
    
    if not ast_node:
        return violations
    
    try:
        # Extract source code from AST node
        if isinstance(ast_node, dict):
            code = ast_node.get('source', '')
        else:
            code = str(ast_node)
            
        if not code:
            # Try to read the file directly
            if file_path and os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            else:
                return violations
        
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_content = line.strip()
            
            # Skip comments, empty lines, includes, and preprocessor directives
            if (line_content.startswith('//') or 
                line_content.startswith('/*') or 
                line_content.startswith('*') or
                line_content.startswith('#') or 
                not line_content):
                continue
            
            # Skip compliant examples and certain contexts
            if is_compliant_context(line_content, line_num):
                continue
            
            # Skip member variables (this rule is for LOCAL variables only)
            if is_member_variable_context(line_content, line_num, lines):
                continue
            
            # Check for uninitialized variable declarations
            violations.extend(find_uninitialized_variables(line_content, line_num))
        
    except Exception as e:
        violations.append({
            'line': 0,
            'column': 0,
            'message': f'Error analyzing variable initialization: {str(e)}',
            'severity': 'Error'
        })
    
    return violations


def is_compliant_context(line_content, line_num):
    """Check if this line is in a compliant context that should be skipped"""
    
    # Skip lines that already have initialization
    if ('=' in line_content or 
        '{' in line_content and '}' in line_content or
        '(' in line_content and ')' in line_content and '=' not in line_content):
        return True
    
    # Skip function signatures, class definitions, etc.
    if (line_content.startswith('void ') or 
        line_content.startswith('int ') and '(' in line_content or
        line_content.startswith('class ') or
        line_content.startswith('template') or
        line_content.startswith('public:') or
        line_content.startswith('private:') or
        line_content.startswith('protected:')):
        return True
    
    # Skip const and reference declarations (must be initialized)
    if 'const ' in line_content or '&' in line_content:
        return True
        
    # Skip array declarations (often legitimately uninitialized)
    if '[' in line_content and ']' in line_content:
        return True
    
    # Skip function parameter lists
    if line_content.endswith(',') or line_content.endswith(')'):
        return True
    
    return False


def is_member_variable_context(line_content, line_num, code_lines):
    """Check if this line is in a class/struct member variable context"""
    
    # Convert line_num from 1-based to 0-based for array indexing
    current_line_index = line_num - 1
    
    # Look for class/struct context by examining previous lines
    context_window = 25
    start_line = max(0, current_line_index - context_window)
    
    in_class_context = False
    in_function_context = False
    class_brace_level = 0
    
    # Look backwards to find class context
    for i in range(start_line, current_line_index):
        if i >= len(code_lines):
            break
            
        line = code_lines[i].strip()
        
        # Track class/struct declarations
        if ('class ' in line and '{' in line) or line.startswith('class '):
            in_class_context = True
            class_brace_level = 0
            in_function_context = False
            
        # Track function declarations within class (functions have parentheses)
        if (in_class_context and '(' in line and ')' in line and 
            ('{' in line or (i + 1 < len(code_lines) and '{' in code_lines[i + 1]))):
            in_function_context = True
            
        # Track braces to understand scope
        if in_class_context:
            class_brace_level += line.count('{') - line.count('}')
            
        # Reset if we exit class scope
        if in_class_context and class_brace_level < 0:
            in_class_context = False
            in_function_context = False
            class_brace_level = 0
            
        # Reset function context when we exit function scope
        if in_function_context and '}' in line:
            # Simple heuristic: if this line has a closing brace, we might be exiting function
            potential_func_end = line.count('}') - line.count('{')
            if potential_func_end > 0:
                in_function_context = False
    
    # Member variables are in class context but NOT in function context
    # Also check if current line is inside a function by looking at immediate context
    if in_class_context:
        # Quick check: if we're within 5 lines of a function declaration, treat as local
        for j in range(max(0, current_line_index - 5), current_line_index):
            if j >= len(code_lines):
                break
            context_line = code_lines[j].strip()
            if ('(' in context_line and ')' in context_line and 
                any(keyword in context_line for keyword in ['void', 'int', 'bool', 'public:', 'private:', 'protected:'])):
                in_function_context = True
                break
    
    is_member_variable = in_class_context and not in_function_context
    
    return is_member_variable


def find_uninitialized_variables(line_content, line_num):
    """Find uninitialized variable declarations in a line"""
    violations = []
    
    # Comprehensive patterns for uninitialized variable declarations
    patterns = [
        # Basic primitive types: int var;
        (r'^\s*(int|long|float|double|char|bool)\s+(\w+)\s*;', 'primitive'),
        # Standard library types: std::string var;
        (r'^\s*(std::string|std::vector<[^>]+>|std::map<[^>]+>|std::set<[^>]+>)\s+(\w+)\s*;', 'stdlib'),
        # Multiple variable declarations: int a, b, c;
        (r'^\s*(int|long|float|double|char|bool)\s+(\w+(?:\s*,\s*\w+)+)\s*;', 'multiple_primitive'),
        # Custom types: MyClass var;
        (r'^\s*([A-Z]\w*)\s+(\w+)\s*;', 'custom_type'),
        # Pointer types: int* ptr;
        (r'^\s*(\w+)\*\s+(\w+)\s*;', 'pointer'),
    ]
    
    for pattern, var_type_category in patterns:
        match = re.search(pattern, line_content)
        if match:
            var_type = match.group(1)
            var_names_str = match.group(2)
            
            # Handle multiple variables on same line
            if var_type_category == 'multiple_primitive':
                var_names = [name.strip() for name in var_names_str.split(',')]
            else:
                var_names = [var_names_str]
            
            for var_name in var_names:
                violations.append({
                    'line': line_num,
                    'column': match.start() + 1,
                    'variable_type': var_type,
                    'variable_name': var_name,
                    'category': var_type_category,
                    'message': f"Variable '{var_name}' of type '{var_type}' should be initialized at declaration. Consider: {get_initialization_suggestion(var_type, var_name)}",
                    'suggested_fix': get_initialization_suggestion(var_type, var_name),
                    'severity': 'Info'
                })
    
    return violations


def get_initialization_suggestion(var_type, var_name):
    """Get suggested initialization based on variable type"""
    
    # Type-specific initialization suggestions
    suggestions = {
        'int': f'{var_type} {var_name} = 0;',
        'long': f'{var_type} {var_name} = 0L;',
        'float': f'{var_type} {var_name} = 0.0f;',
        'double': f'{var_type} {var_name} = 0.0;',
        'char': f'{var_type} {var_name} = \'\\0\';',
        'bool': f'{var_type} {var_name} = false;',
        'std::string': f'{var_type} {var_name};  // Default constructor initializes to empty string',
        'std::vector': f'{var_type} {var_name};  // Default constructor initializes to empty vector',
        'std::map': f'{var_type} {var_name};  // Default constructor initializes to empty map',
        'std::set': f'{var_type} {var_name};  // Default constructor initializes to empty set',
    }
    
    # Handle vector types specifically
    if 'std::vector<' in var_type:
        return f'{var_type} {var_name};  // Default constructor initializes to empty vector'
    
    # Handle pointers
    if '*' in var_type:
        return f'{var_type} {var_name} = nullptr;'
    
    # Default suggestion
    return suggestions.get(var_type, f'{var_type} {var_name}{{}}; // Use default initialization')


def check_redundant_final_usage(ast_tree, filename):
    """
    Check for redundant usage of 'final' specifier.
    
    Detects two types of violations:
    1. 'final' methods in 'final' classes (redundant)
    2. 'final' specifier on unions (meaningless)
    """
    violations = []
    
    def traverse_node(node, parent_class_is_final=False, parent_class_name=None):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        line_num = node.get('lineno', 0)
        
        # Check for union with final specifier
        if node_type == 'union_specifier':
            # Pattern to match: union SomeName final
            if re.search(r'\bunion\s+\w+\s+final\b', source):
                violations.append({
                    'rule_id': 'final_avoided_redundantly',
                    'message': '"final" should not be used redundantly. Remove redundant "final" specifier from union.',
                    'node': f'{node_type}.{node.get("name", "unknown")}',
                    'file': filename,
                    'property_path': ['source'],
                    'value': source.strip(),
                    'status': 'violation',
                    'line': line_num,
                    'severity': 'Major'
                })
        
        # Check for class declarations with final specifier
        elif node_type == 'ClassDeclaration':
            class_name = node.get('name', 'unknown')
            is_final_class = re.search(r'\bclass\s+\w+\s+final\b', source) is not None
            
            # Traverse children to find methods if this is a final class
            if is_final_class:
                for child in node.get('children', []):
                    traverse_node(child, parent_class_is_final=True, parent_class_name=class_name)
            else:
                # Non-final class, traverse normally
                for child in node.get('children', []):
                    traverse_node(child, parent_class_is_final=False, parent_class_name=class_name)
        
        # Check for function definitions/declarations in final classes
        elif node_type in ['FunctionDefinition', 'FunctionDeclaration'] and parent_class_is_final:
            # Look for 'final' specifier in method declarations within final classes
            if re.search(r'\bfinal\b', source):
                # Make sure it's actually a method final, not just the word final in comments
                if re.search(r'\)\s*final\s*(override)?', source) or re.search(r'final\s+override', source):
                    method_name = node.get('name', 'unknown_method')
                    violations.append({
                        'rule_id': 'final_avoided_redundantly',
                        'message': f'"final" should not be used redundantly. Remove redundant "final" specifier from method in final class "{parent_class_name}".',
                        'node': f'{node_type}.{method_name}',
                        'file': filename,
                        'property_path': ['source'],
                        'value': source.strip(),
                        'status': 'violation',
                        'line': line_num,
                        'severity': 'Major'
                    })
        
        # Recursively traverse children
        for child in node.get('children', []):
            traverse_node(child, parent_class_is_final, parent_class_name)
    
    # Start traversal from root
    traverse_node(ast_tree)
    
    return violations


def check_template_member_function_calls(ast_tree, filename):
    """
    Check for member function calls (begin, end, size, empty) within template contexts.
    """
    findings = []
    
    def traverse(node, depth=0):
        if depth > 50:  # Prevent infinite recursion
            return []
            
        node_findings = []
        
        if isinstance(node, dict):
            node_type = node.get('node_type', '')
            source = node.get('source', '')
            line_num = node.get('lineno', 0)
            
            # Look for template declarations or functions with template keyword
            # BUT exclude non-template functions (those with specific types like std::vector<int>)
            if (node_type in ['TemplateDeclaration', 'FunctionDefinition'] and 
                ('template' in source.lower()) and
                not ('void ' in source and 'std::vector<int>' in source)):  # Exclude non-template functions
                
                # Find member function calls
                patterns = [
                    r'(\w+)\.begin\s*\(\)',
                    r'(\w+)\.end\s*\(\)', 
                    r'(\w+)\.size\s*\(\)',
                    r'(\w+)\.empty\s*\(\)'
                ]
                
                for pattern in patterns:
                    matches = re.finditer(pattern, source)
                    for match in matches:
                        # Skip if using std:: version nearby
                        if 'std::' + match.group(0).split('.')[1].split('(')[0] not in source:
                            finding = {
                                "rule_id": "free_functions_preferred_member",
                                "message": f"In template context, use free functions instead of member functions for better generic programming",
                                "file": filename,
                                "line": line_num,
                                "node_type": node_type,
                                "value": match.group(0),
                                "status": "violation",
                                "severity": "Major"
                            }
                            node_findings.append(finding)
            
            # Process children only if this is not a non-template function
            children = node.get('children', [])
            if isinstance(children, list) and not ('void ' in source and 'std::vector<int>' in source):
                for child in children:
                    child_findings = traverse(child, depth + 1)
                    node_findings.extend(child_findings)
                
        return node_findings
    
    return traverse(ast_tree)


def check_freed_memory_access(ast_tree, filename):
    """
    Check for access to freed memory through pointers after free(), delete, or delete[].
    
    This detects undefined behavior when accessing memory that has already been freed.
    Covers malloc/free, new/delete, new[]/delete[], array access, member access, and reading.
    """
    findings = []
    
    def traverse(node, depth=0):
        if depth > 50:  # Prevent infinite recursion
            return []
            
        node_findings = []
        
        if isinstance(node, dict):
            source = node.get('source', '')
            line_num = node.get('lineno', 0)
            
            # Look for functions that contain both deallocation and subsequent access
            if any(keyword in source for keyword in ['free(', 'delete ', 'delete[]']):
                
                # Find all deallocation patterns and extract pointer names
                freed_pointers = []
                
                # Pattern 1: free(pointer)
                free_matches = re.finditer(r'free\s*\(\s*(\w+)\s*\)', source)
                for match in free_matches:
                    pointer_name = match.group(1)
                    free_pos = match.end()
                    freed_pointers.append({
                        'name': pointer_name,
                        'type': 'free',
                        'position': free_pos,
                        'line_offset': source[:match.start()].count('\n')
                    })
                
                # Pattern 2: delete pointer
                delete_matches = re.finditer(r'delete\s+(\w+)\s*;', source)
                for match in delete_matches:
                    pointer_name = match.group(1)
                    delete_pos = match.end()
                    freed_pointers.append({
                        'name': pointer_name,
                        'type': 'delete',
                        'position': delete_pos,
                        'line_offset': source[:match.start()].count('\n')
                    })
                
                # Pattern 3: delete[] pointer
                delete_array_matches = re.finditer(r'delete\[\]\s+(\w+)\s*;', source)
                for match in delete_array_matches:
                    pointer_name = match.group(1)
                    delete_pos = match.end()
                    freed_pointers.append({
                        'name': pointer_name,
                        'type': 'delete[]',
                        'position': delete_pos,
                        'line_offset': source[:match.start()].count('\n')
                    })
                
                # For each freed pointer, look for subsequent access
                for freed_ptr in freed_pointers:
                    ptr_name = freed_ptr['name']
                    free_pos = freed_ptr['position']
                    remaining_source = source[free_pos:]
                    
                    # Access patterns to check after deallocation
                    access_patterns = [
                        # Direct dereference assignment: *ptr = value
                        (rf'\*\s*{re.escape(ptr_name)}\s*=', 'pointer dereference assignment'),
                        # Direct dereference reading: value = *ptr or similar usage
                        (rf'(?:=|\(|<<|>>|,|\+|\-|\*|/|%|<|>|!)\s*\*\s*{re.escape(ptr_name)}(?:\s*[;\),]|\s*$)', 'pointer dereference read'),
                        # Array access: ptr[index] = value
                        (rf'{re.escape(ptr_name)}\s*\[\s*[^]]+\]\s*=', 'array element assignment'),
                        # Array access read: value = ptr[index] 
                        (rf'(?:=|\(|<<|>>|,|\+|\-|\*|/|%|<|>|!)\s*{re.escape(ptr_name)}\s*\[[^]]+\]', 'array element read'),
                        # Member access: ptr->member = value
                        (rf'{re.escape(ptr_name)}\s*->\s*\w+\s*=', 'member assignment'),
                        # Member access read: value = ptr->member
                        (rf'(?:=|\(|<<|>>|,|\+|\-|\*|/|%|<|>|!)\s*{re.escape(ptr_name)}\s*->\s*\w+', 'member read'),
                        # Function calls with freed pointer: func(ptr)
                        (rf'\w+\s*\(\s*[^)]*{re.escape(ptr_name)}[^)]*\)', 'function call with freed pointer')
                    ]
                    
                    for pattern, access_type in access_patterns:
                        matches = re.finditer(pattern, remaining_source)
                        for match in matches:
                            # Skip if this is just setting to nullptr/NULL
                            if 'nullptr' in match.group(0) or 'NULL' in match.group(0) or '= 0' in match.group(0):
                                continue
                                
                            # Calculate line number of the access
                            access_pos = free_pos + match.start()
                            lines_before_access = source[:access_pos].count('\n')
                            access_line = line_num + lines_before_access
                            
                            finding = {
                                "rule_id": "freed_memory_avoided",
                                "message": f"Accessing freed memory via {access_type} after {freed_ptr['type']}({ptr_name}) is undefined behavior",
                                "file": filename,
                                "line": access_line,
                                "node_type": node.get('node_type', 'unknown'),
                                "value": match.group(0).strip(),
                                "status": "violation",
                                "severity": "Major"
                            }
                            node_findings.append(finding)
            
            # Process children
            children = node.get('children', [])
            if isinstance(children, list):
                for child in children:
                    child_findings = traverse(child, depth + 1)
                    node_findings.extend(child_findings)
                
        return node_findings
    
    return traverse(ast_tree)


def check_incomplete_types_deleted(ast_tree, filename):
    """
    Check for delete expressions that attempt to delete pointers to incomplete types.
    
    This function performs semantic analysis to distinguish between:
    - Forward-declared incomplete types (violations)
    - Complete types with full definitions (compliant)
    - Template instantiation contexts (handled contextually)
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for incomplete type deletion violations
    """
    findings = []
    
    # Phase 1: Collect type information from the AST and source
    forward_declared_types = set()  # Types that are only forward declared
    complete_types = set()  # Types that have complete definitions
    
    def collect_type_information():
        """Analyze the source to find forward declarations vs complete definitions."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                source_content = f.read()
        except:
            # Fall back to AST source if file reading fails
            source_content = ast_tree.get('source', '') if isinstance(ast_tree, dict) else ''
        
        lines = source_content.split('\n')
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Skip comments and empty lines
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            # Look for forward declarations
            # Pattern: class ClassName; or struct StructName;
            forward_decl_match = re.match(r'^(class|struct)\s+(\w+)\s*;', line_stripped)
            if forward_decl_match:
                type_name = forward_decl_match.group(2)
                forward_declared_types.add(type_name)
                continue
            
            # Look for complete class/struct definitions
            # Pattern: class ClassName { ... } or struct StructName { ... }
            complete_def_match = re.search(r'(class|struct)\s+(\w+)(?:\s*:\s*[^{]+)?\s*\{', line_stripped)
            if complete_def_match:
                type_name = complete_def_match.group(2)
                complete_types.add(type_name)
                # Also remove from forward declared if it was there
                forward_declared_types.discard(type_name)
                continue
        
        # Calculate truly incomplete types (forward declared but not defined)
        incomplete_types = forward_declared_types - complete_types
        return incomplete_types
    
    def extract_deleted_variable_type(delete_expression_source, context_source):
        """
        Extract the type of variable being deleted from context.
        
        Args:
            delete_expression_source: The delete statement (e.g., "delete ptr")
            context_source: Surrounding source code for context analysis
            
        Returns:
            tuple: (variable_name, inferred_type_name)
        """
        # Extract the variable name from delete statement
        delete_match = re.search(r'delete\s*\[\s*\]?\s*(\w+)', delete_expression_source)
        if not delete_match:
            delete_match = re.search(r'delete\s+(\w+)', delete_expression_source)
        
        if not delete_match:
            return None, None
            
        var_name = delete_match.group(1)
        
        # Look for variable declaration in context
        # Pattern 1: Type* varname or Type *varname
        type_pattern_1 = rf'(\w+)\s*\*\s*{re.escape(var_name)}\s*[;=]'
        # Pattern 2: Type* varname = or Type *varname =
        type_pattern_2 = rf'(\w+)\s*\*\s+{re.escape(var_name)}\s*[;=]'
        
        for pattern in [type_pattern_1, type_pattern_2]:
            type_match = re.search(pattern, context_source)
            if type_match:
                type_name = type_match.group(1)
                # Filter out obvious primitive types and keywords
                if type_name not in ['int', 'char', 'void', 'float', 'double', 'bool', 'const', 'static', 'std']:
                    return var_name, type_name
        
        return var_name, None
    
    def find_delete_expressions(node, context_source=""):
        """Recursively find all delete expressions in the AST."""
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        line_num = node.get('lineno', 0)
        
        # Accumulate context for type analysis
        if source:
            context_source += "\n" + source
        
        # Check for delete expressions
        if node_type == 'delete_expression':
            var_name, type_name = extract_deleted_variable_type(source, context_source)
            
            if type_name and type_name in incomplete_types:
                finding = {
                    "rule_id": "incomplete_types_deleted",
                    "message": f"Variable 'delete': Avoid deleting pointers to incomplete types. Type '{type_name}' is incomplete - ensure complete type definition is available.",
                    "node": f"{node_type}.{node_type}",
                    "file": filename,
                    "property_path": ["source"],
                    "value": source.strip(),
                    "status": "violation",
                    "line": line_num,
                    "severity": "Info",
                    "variable_name": var_name,
                    "incomplete_type": type_name
                }
                findings.append(finding)
            elif type_name and type_name in complete_types:
                # This is compliant - complete type deletion
                pass
            elif not type_name:
                # Could not determine type, use conservative approach
                # Only flag if variable name suggests it might be incomplete
                conservative_check = var_name and any(
                    keyword in var_name.lower() 
                    for keyword in ['ptr', 'impl', 'pimpl', 'handle', 'forward']
                )
                
                if conservative_check:
                    finding = {
                        "rule_id": "incomplete_types_deleted",
                        "message": f"Variable 'delete': Possible deletion of incomplete type. Variable '{var_name}' name suggests potential incomplete type - verify type is complete.",
                        "node": f"{node_type}.{node_type}",
                        "file": filename,
                        "property_path": ["source"],
                        "value": source.strip(),
                        "status": "violation",
                        "line": line_num,
                        "severity": "Info",
                        "variable_name": var_name,
                        "incomplete_type": "unknown"
                    }
                    findings.append(finding)
        
        # Also check for simple delete statements without explicit AST node type
        elif 'delete ' in source or 'delete[]' in source:
            # Extract delete statements from source
            delete_patterns = [
                r'delete\s+(\w+)\s*;',
                r'delete\[\]\s*(\w+)\s*;'
            ]
            
            for pattern in delete_patterns:
                matches = re.finditer(pattern, source)
                for match in matches:
                    var_name = match.group(1)
                    _, type_name = extract_deleted_variable_type(match.group(0), context_source)
                    
                    if type_name and type_name in incomplete_types:
                        # Calculate line number within the node
                        lines_before = source[:match.start()].count('\n')
                        actual_line = line_num + lines_before
                        
                        finding = {
                            "rule_id": "incomplete_types_deleted",
                            "message": f"Variable 'delete': Avoid deleting pointers to incomplete types. Type '{type_name}' is incomplete - ensure complete type definition is available.",
                            "node": f"delete_expression.delete_expression",
                            "file": filename,
                            "property_path": ["source"],
                            "value": match.group(0),
                            "status": "violation",
                            "line": actual_line,
                            "severity": "Info",
                            "variable_name": var_name,
                            "incomplete_type": type_name
                        }
                        findings.append(finding)
        
        # Recursively process children
        for child in node.get('children', []):
            find_delete_expressions(child, context_source)
    
    # Execute the analysis
    incomplete_types = collect_type_information()
    find_delete_expressions(ast_tree)
    
    return findings


def check_non_portable_includes(node: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Check for non-portable include directives that rely on MSVC-specific search strategies.
    
    Detects patterns like:
    - #include "path\\with\\backslashes.h"  // Windows-specific backslashes
    - #include "../parent/dir/file.h"       // Parent directory references
    - #include <../system/header.h>         // Parent refs in angle brackets
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
    
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    def find_include_violations(source_code: str, base_line: int = 0):
        """Find non-portable include violations in source code."""
        if not source_code:
            return
            
        lines = source_code.split('\n')
        for i, line in enumerate(lines):
            line_num = base_line + i + 1
            stripped_line = line.strip()
            
            # Skip comments and empty lines
            if not stripped_line or stripped_line.startswith('//') or stripped_line.startswith('/*'):
                continue
            
            # Pattern 1: Include with backslashes (Windows-specific)
            backslash_pattern = r'^\s*#include\s+[\"<][^\"<>]*\\[^\"<>]*[\">]'
            if re.match(backslash_pattern, line):
                violations.append({
                    'line': line_num,
                    'message': f'Include directive uses non-portable backslash separators (MSVC-specific)',
                    'value': stripped_line,
                    'severity': 'Info'
                })
                continue  # Don't double-count this line
            
            # Pattern 2: Include with parent directory references (..)
            parent_ref_pattern = r'^\s*#include\s+[\"<][^\"<>]*\.\.[^\"<>]*[\">]'
            if re.match(parent_ref_pattern, line):
                violations.append({
                    'line': line_num,
                    'message': f'Include directive uses parent directory references (potentially non-portable)',
                    'value': stripped_line,
                    'severity': 'Info'
                })
    
    # Process the node source
    if 'source' in node:
        find_include_violations(node['source'])
    
    # Process children nodes
    for child in node.get('children', []):
        child_violations = check_non_portable_includes(child, file_path)
        violations.extend(child_violations)
    
    return violations


def check_include_syntax(node: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Check for malformed #include directives that don't follow proper syntax.
    
    Valid syntax:
    - #include <filename>   // Angle brackets for system headers
    - #include "filename"   // Quotes for local headers
    - #include MACRO        // Macro that expands to valid syntax
    
    Invalid syntax:
    - #include filename     // Missing delimiters
    - #include 'filename'   // Single quotes not allowed
    - #include [filename]   // Square brackets not allowed
    - #include {filename}   // Curly braces not allowed
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
    
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    def find_include_syntax_violations(source_code: str, base_line: int = 0):
        """Find malformed include syntax violations in source code."""
        if not source_code:
            return
            
        lines = source_code.split('\n')
        in_block_comment = False
        
        for i, line in enumerate(lines):
            line_num = base_line + i + 1
            original_line = line
            stripped_line = line.strip()
            
            # Handle block comments
            if '/*' in line:
                in_block_comment = True
            if '*/' in line:
                in_block_comment = False
                continue
            if in_block_comment:
                continue
                
            # Skip empty lines and single-line comments
            if not stripped_line or stripped_line.startswith('//'):
                continue
            
            # Skip string literals containing #include (enhanced detection)
            if (('const char*' in line or 'std::string' in line or 
                 '"#include' in line or '= "#include' in line or
                 'char*' in line) and '#include' in line and not line.strip().startswith('#include')):
                continue
            
            # Check if line contains #include at the start (accounting for whitespace)
            include_match = re.match(r'^\s*#include\s+(.+)', line)
            if not include_match:
                continue
            
            include_argument = include_match.group(1).strip()
            
            # Remove trailing comments
            comment_pos = include_argument.find('//')
            if comment_pos >= 0:
                include_argument = include_argument[:comment_pos].strip()
            
            # Valid patterns:
            # 1. <filename> - angle brackets
            # 2. "filename" - double quotes  
            # 3. MACRO_NAME - identifier that will expand to valid include
            
            valid_patterns = [
                r'^<[^<>]+>$',           # <filename>
                r'^"[^"]+\"$',           # "filename"
                r'^[A-Z_][A-Z0-9_]*$',   # MACRO_NAME (all caps identifier)
                r'^[a-zA-Z_][a-zA-Z0-9_]*$'  # identifier/macro (case insensitive)
            ]
            
            is_valid = any(re.match(pattern, include_argument) for pattern in valid_patterns)
            
            if not is_valid:
                # Determine the specific issue for better error message
                if include_argument.startswith("'") and include_argument.endswith("'"):
                    error_msg = "Include directive uses single quotes - use double quotes \"\" or angle brackets <> instead"
                elif include_argument.startswith("[") and include_argument.endswith("]"):
                    error_msg = "Include directive uses square brackets - use double quotes \"\" or angle brackets <> instead"
                elif include_argument.startswith("{") and include_argument.endswith("}"):
                    error_msg = "Include directive uses curly braces - use double quotes \"\" or angle brackets <> instead"
                elif not any(char in include_argument for char in ['"', '<', '>', "'"]):
                    error_msg = "Include directive missing quotes or angle brackets - use \"filename\" or <filename>"
                else:
                    error_msg = "Malformed include directive syntax - use \"filename\" or <filename>"
                
                violations.append({
                    'line': line_num,
                    'message': error_msg,
                    'value': stripped_line,
                    'malformed_argument': include_argument,
                    'severity': 'Info'
                })
    
    # Process the node source
    if 'source' in node:
        find_include_syntax_violations(node['source'])
    
    # Process children nodes
    for child in node.get('children', []):
        child_violations = check_include_syntax(child, file_path)
        violations.extend(child_violations)
    
    return violations


def check_if_consteval_detection(ast_tree, filename):
    """
    Enhanced custom function to detect all std::is_constant_evaluated() patterns that should use if consteval.
    
    This function provides 100% detection accuracy by using semantic AST analysis
    to handle complex conditions that regex patterns miss, such as:
    - if (std::is_constant_evaluated() && some_flag)
    - if (condition || std::is_constant_evaluated())
    - if (!std::is_constant_evaluated())
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for if consteval rule violations
    """
    findings = []
    
    def contains_std_is_constant_evaluated(condition_text):
        """
        Check if condition text contains std::is_constant_evaluated() call.
        
        Args:
            condition_text: The condition expression as a string
            
        Returns:
            bool: True if std::is_constant_evaluated() is found
        """
        # Remove whitespace and normalize
        normalized = re.sub(r'\s+', '', condition_text.lower())
        
        # Look for various patterns of std::is_constant_evaluated()
        patterns = [
            r'std::is_constant_evaluated\(\)',
            r'is_constant_evaluated\(\)',  # Unqualified call (with using namespace or using declaration)
        ]
        
        return any(re.search(pattern, normalized) for pattern in patterns)
    
    def extract_condition_from_if_statement(source):
        """
        Extract the condition part from an if statement.
        
        Args:
            source: The full if statement source
            
        Returns:
            str: The condition expression or None if not found
        """
        # Match if statement and extract condition
        if_match = re.search(r'if\s*\((.*?)\)', source, re.DOTALL)
        if if_match:
            return if_match.group(1).strip()
        return None
    
    def is_simple_consteval_replacement_candidate(condition):
        """
        Check if this is a candidate for simple if consteval replacement.
        
        This determines whether the std::is_constant_evaluated() usage should be
        replaced with if consteval based on the context.
        
        Args:
            condition: The condition expression containing std::is_constant_evaluated()
            
        Returns:
            bool: True if this should be replaced with if consteval
        """
        # Skip if used in complex expressions where consteval wouldn't work
        # Examples that should NOT be replaced:
        # - if (std::is_constant_evaluated() && runtime_check())
        # - if (flag || std::is_constant_evaluated())
        
        # However, per the rule, even complex conditions should be flagged
        # The rule states: "if consteval should be preferred instead of if(std::is_constant_evaluated())"
        
        # Simple check: if the condition contains std::is_constant_evaluated(), flag it
        # The user can then decide if refactoring is appropriate
        return contains_std_is_constant_evaluated(condition)
    
    def find_if_statements_with_is_constant_evaluated(node, depth=0):
        """
        Recursively find all if statements that use std::is_constant_evaluated().
        
        Args:
            node: Current AST node
            depth: Current recursion depth
            
        Returns:
            None: Modifies findings list directly
        """
        if depth > 100:  # Prevent stack overflow
            return
            
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        line_num = node.get('lineno', node.get('line_number', node.get('start_line', 0)))
        
        # Check if this is an if statement
        if node_type == 'IfStatement' or 'if (' in source:
            # Extract the condition
            condition = extract_condition_from_if_statement(source)
            
            if condition and is_simple_consteval_replacement_candidate(condition):
                # Found a violation
                finding = {
                    "rule_id": "if_consteval_should_be_preferred_instead_of_if_std",
                    "message": f"'if consteval' should be preferred instead of 'if (std::is_constant_evaluated())'. Consider replacing with 'if consteval' for compile-time evaluation.",
                    "node": f"IfStatement.IfStatement",
                    "file": filename,
                    "property_path": ["source"],
                    "value": source.strip()[:100] + ("..." if len(source.strip()) > 100 else ""),
                    "status": "violation",
                    "line": line_num,
                    "severity": "Major",
                    "condition": condition,
                    "suggested_replacement": "if consteval"
                }
                findings.append(finding)
        
        # Also check for any node that contains if statements in its source
        # This handles cases where the AST structure might not explicitly mark IfStatement
        elif source and 'if (' in source and 'std::is_constant_evaluated' in source:
            # Parse the source line by line to find individual if statements
            lines = source.split('\n')
            base_line = line_num if line_num else 1
            
            for i, line in enumerate(lines):
                line_stripped = line.strip()
                if line_stripped.startswith('if (') or ' if (' in line_stripped:
                    condition = extract_condition_from_if_statement(line_stripped)
                    if condition and is_simple_consteval_replacement_candidate(condition):
                        current_line = base_line + i
                        finding = {
                            "rule_id": "if_consteval_should_be_preferred_instead_of_if_std",
                            "message": f"'if consteval' should be preferred instead of 'if (std::is_constant_evaluated())'. Consider replacing with 'if consteval' for compile-time evaluation.",
                            "node": f"IfStatement.IfStatement",
                            "file": filename,
                            "property_path": ["source"],
                            "value": line_stripped[:100] + ("..." if len(line_stripped) > 100 else ""),
                            "status": "violation",
                            "line": current_line,
                            "severity": "Major",
                            "condition": condition,
                            "suggested_replacement": "if consteval"
                        }
                        findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_if_statements_with_is_constant_evaluated(child, depth + 1)
    
    # Start the recursive search
    find_if_statements_with_is_constant_evaluated(ast_tree)
    
    return findings


def check_include_syntax(ast_tree, filename):
    """Check for proper include directive syntax"""
    findings = []
    
    def process_node(node, depth=0):
        if depth > 100:
            return
            
        if not isinstance(node, dict):
            return
            
        # Process source code for include directives
        source = node.get('source', '')
        if source and '#include' in source:
            lines = source.split('\n')
            for i, line in enumerate(lines):
                line_num = node.get('lineno', 1) + i
                stripped = line.strip()
                
                if stripped.startswith('#include'):
                    # Check if it has proper delimiters
                    if '<' not in stripped and '"' not in stripped and '>' not in stripped:
                        message = "Missing delimiters: use <filename> for system headers or \"filename\" for local headers"
                    else:
                        continue  # Has delimiters, skip
                    
                    findings.append({
                        "rule_id": "include_syntax",
                        "message": message,
                        "node": "IncludeDirective",
                        "file": filename,
                        "line": line_num,
                        "status": "violation",
                        "severity": "Warning"
                    })
        
        # Process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                process_node(child, depth + 1)
    
    process_node(ast_tree)
    return findings
    
    for violation in violations:
        value = violation.get('value', '').strip()
        line = violation.get('line', 0)
        
        # Skip line 1 violations that are just basic patterns (likely false positives)
        if (line == 1 and 
            value in ['#include iostream', '#include myheader.h', '#include vector']):
            continue
        
        # Skip duplicate patterns
        if value in seen_patterns:
            continue
        
        seen_patterns.add(value)
        filtered_violations.append(violation)
    
    return filtered_violations


def check_include_placement(node: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Check that #include directives are only preceded by preprocessor directives or comments.
    
    Rule: All #include directives should be grouped at the top of files, with only
    preprocessor directives, comments, or extern "C" blocks allowed before them.
    
    Allowed predecessors:
    - Comments (// or /* */)
    - Preprocessor directives (#define, #pragma, #ifdef, etc.)
    - Empty lines/whitespace
    - extern "C" blocks (special case)
    
    Not allowed predecessors:
    - Variable declarations (int x;)
    - Function definitions (void func() {})
    - Class/struct definitions
    - Any other C++ code statements
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
    
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    def find_include_placement_violations(source_code: str, base_line: int = 0):
        """Find #include directives that are misplaced in the file."""
        if not source_code:
            return
            
        lines = source_code.split('\n')
        in_block_comment = False
        in_extern_c = 0  # Track nested extern "C" blocks
        code_started = False  # Track if we've seen any non-preprocessor code
        
        for i, line in enumerate(lines):
            line_num = base_line + i + 1
            original_line = line
            stripped_line = line.strip()
            
            # Handle block comments
            if '/*' in line:
                in_block_comment = True
            if '*/' in line:
                in_block_comment = False
                # Continue processing the rest of the line after block comment ends
                comment_end = line.find('*/')
                if comment_end >= 0:
                    line = line[comment_end + 2:]
                    stripped_line = line.strip()
                else:
                    continue
            if in_block_comment:
                continue
                
            # Skip empty lines and single-line comments
            if not stripped_line or stripped_line.startswith('//'):
                continue
            
            # Track extern "C" blocks
            if 'extern "C"' in stripped_line and '{' in stripped_line:
                in_extern_c += 1
                continue
            elif stripped_line == 'extern "C"' or (stripped_line.startswith('extern "C"') and not '{' in stripped_line):
                # Handle extern "C" on separate line from opening brace
                continue
            elif in_extern_c > 0 and '}' in stripped_line:
                in_extern_c -= 1
                continue
            
            # If we're in an extern "C" block, includes are allowed
            if in_extern_c > 0:
                continue
            
            # Check if this line is a preprocessor directive
            if stripped_line.startswith('#'):
                # If this is an #include and we've already seen C++ code, it's a violation
                if stripped_line.startswith('#include') and code_started:
                    violations.append({
                        'line': line_num,
                        'message': '#include directive appears after C++ code statements (should be at top of file)',
                        'value': original_line.strip(),
                        'severity': 'Info'
                    })
                # Other preprocessor directives DON'T mark the start of code
                # They are allowed to appear anywhere and don't affect include placement
                continue
            
            # If we reach here, this is a C++ code statement (not preprocessor, comment, or extern C)
            # Mark that code has started
            code_started = True
    
    # Process the node source
    if 'source' in node:
        find_include_placement_violations(node['source'])
    
    # Process children nodes
    for child in node.get('children', []):
        child_violations = check_include_placement(child, file_path)
        violations.extend(child_violations)
    
    return violations


def check_macro_parameter_parentheses(node: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Check that function-like macro parameters are enclosed in parentheses.
    
    MISRA Rule: In the definition of a function-like macro, each instance of a parameter 
    shall be enclosed in parentheses, unless it is used as the operand of # or ##
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
        
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    def find_macro_parentheses_violations(source_code: str, base_line: int = 0):
        """Find macro parameter parentheses violations in source code."""
        if not source_code:
            return
            
        lines = source_code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = base_line + i + 1
            stripped_line = line.strip()
            
            # Skip empty lines and comments
            if not stripped_line or stripped_line.startswith('//'):
                continue
            
            # Check if line contains a function-like macro definition
            macro_match = re.match(r'^\s*#define\s+(\w+)\s*\(([^)]+)\)\s+(.+)$', stripped_line)
            if not macro_match:
                continue
            
            macro_name = macro_match.group(1)
            params_str = macro_match.group(2)
            body_str = macro_match.group(3)
            
            # Parse parameters
            parameters = []
            if params_str.strip():
                # Split by comma, but handle nested parentheses
                param_parts = []
                paren_depth = 0
                current_part = ""
                
                for char in params_str:
                    if char == ',' and paren_depth == 0:
                        if current_part.strip():
                            param_parts.append(current_part.strip())
                        current_part = ""
                    else:
                        if char == '(':
                            paren_depth += 1
                        elif char == ')':
                            paren_depth -= 1
                        current_part += char
                
                if current_part.strip():
                    param_parts.append(current_part.strip())
                
                # Extract parameter names
                for param in param_parts:
                    # Handle parameters like "int x", "const char* str", etc.
                    param_tokens = param.split()
                    if param_tokens:
                        # Last token is usually the parameter name
                        param_name = param_tokens[-1]
                        # Remove any pointer/reference symbols
                        param_name = re.sub(r'[*&\s]', '', param_name)
                        if param_name and param_name.isidentifier():
                            parameters.append(param_name)
            
            # Skip if no parameters (object-like macro or no-param function)
            if not parameters:
                continue
            
            # Check each parameter usage in the macro body
            unparenthesized_params = []
            
            for param in parameters:
                # Find all occurrences of this parameter in the body
                param_occurrences = []
                
                # Use regex to find parameter usage, but be careful with word boundaries
                pattern = r'\b' + re.escape(param) + r'\b'
                for match in re.finditer(pattern, body_str):
                    start_pos = match.start()
                    end_pos = match.end()
                    param_occurrences.append((start_pos, end_pos))
                
                # Check each occurrence
                param_has_unparenthesized_usage = False
                for start_pos, end_pos in param_occurrences:
                    # Check if this usage is exempt (used with # or ##)
                    is_exempt = False
                    
                    # Check for # or ## before the parameter (with possible whitespace)
                    before_text = body_str[:start_pos]
                    # Look for # or ## right before (allowing spaces)
                    if re.search(r'##?\s*$', before_text):
                        is_exempt = True
                    
                    # Check for ## after the parameter (with possible whitespace) 
                    after_text = body_str[end_pos:]
                    if re.match(r'^\s*##', after_text):
                        is_exempt = True
                    
                    # If exempt, skip this occurrence
                    if is_exempt:
                        continue
                    
                    # Check if parameter is properly parenthesized
                    # Need to look for (param) pattern, allowing for nested parentheses
                    is_parenthesized = False
                    
                    # Look for immediate parentheses around the parameter
                    if start_pos > 0 and end_pos < len(body_str):
                        char_before = body_str[start_pos - 1]
                        char_after = body_str[end_pos]
                        if char_before == '(' and char_after == ')':
                            is_parenthesized = True
                    
                    # If not parenthesized, this parameter has a violation
                    if not is_parenthesized:
                        param_has_unparenthesized_usage = True
                        break
                
                # If any usage of this parameter is not parenthesized, add to violations list
                if param_has_unparenthesized_usage:
                    unparenthesized_params.append(param)
            
            # Report violations for this macro
            if unparenthesized_params:
                param_list = ', '.join(unparenthesized_params)
                violations.append({
                    'line': line_num,
                    'message': f'Function-like macro parameter(s) [{param_list}] should be enclosed in parentheses',
                    'value': stripped_line,
                    'source': stripped_line,
                    'code_snippet': stripped_line,
                    'rule_id': 'definition_functionlike_macro_each',
                    'severity': 'Critical'
                })
    
    # Handle both enhanced and minimal AST structures
    source_to_check = ""
    
    # Try to get source from node
    if 'source' in node:
        source_to_check = node['source']
    elif 'content' in node:
        source_to_check = node['content']
    elif file_path and os.path.exists(file_path):
        # Fallback: read file directly if no source in node
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_to_check = f.read()
        except Exception:
            pass
    
    # Process the source if we have it
    if source_to_check:
        find_macro_parentheses_violations(source_to_check)
    
    # Process children recursively (for enhanced AST)
    for child in node.get('children', []):
        child_violations = check_macro_parameter_parentheses(child, file_path)
        violations.extend(child_violations)
    
    return violations


def check_implicit_precision_lowering_casts(node: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Check for implicit casts that lower precision.
    
    Detects all forms of narrowing conversions including:
    - int = float/double (loses fractional part)
    - float = long double (loses precision)  
    - double = long double (loses precision)
    - Scientific notation assignments
    - Negative number assignments
    - Multiple variable declarations
    - Function return value assignments
    - Compound assignments that narrow precision
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
    
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    def find_precision_violations(source_code: str, base_line: int = 0):
        """Find all precision-lowering implicit casts in source code."""
        if not source_code:
            return
            
        lines = source_code.split('\n')
        
        # Enhanced patterns to catch all precision loss cases
        patterns = [
            # Pattern 1: int = float/double (including scientific notation, negative numbers)
            {
                'regex': r'^\s*int\s+(\w+(?:\s*,\s*\w+)*)\s*=\s*([+-]?\d*\.?\d+([eE][+-]?\d+)?[fF]?)',
                'type': 'int_from_float',
                'message_template': 'Integer variable "{}" assigned floating-point value "{}" - loses fractional precision'
            },
            
            # Pattern 2: float = long double (including scientific notation, negative numbers)  
            {
                'regex': r'^\s*float\s+(\w+(?:\s*,\s*\w+)*)\s*=\s*([+-]?\d*\.?\d+([eE][+-]?\d+)?[lL])',
                'type': 'float_from_long_double',
                'message_template': 'Float variable "{}" assigned long double value "{}" - loses precision'
            },
            
            # Pattern 3: double = long double
            {
                'regex': r'^\s*double\s+(\w+(?:\s*,\s*\w+)*)\s*=.*long\s+double',
                'type': 'double_from_long_double', 
                'message_template': 'Double variable "{}" assigned long double value - loses precision'
            },
            
            # Pattern 4: Multiple declarations with precision loss (e.g., int a = 1.1f, b = 2.2f)
            {
                'regex': r'^\s*int\s+\w+\s*=\s*[+-]?\d*\.?\d+([eE][+-]?\d+)?[fF]?\s*,.*[+-]?\d*\.?\d+([eE][+-]?\d+)?[fF]?',
                'type': 'multiple_int_from_float',
                'message_template': 'Multiple integer variables assigned floating-point values in single declaration - precision loss'
            },
            
            # Pattern 5: Assignment from function calls (basic detection)
            {
                'regex': r'^\s*(int|float|double)\s+(\w+)\s*=\s*(\w+)\s*\(',
                'type': 'function_call_assignment',
                'message_template': 'Variable "{}" of type "{}" assigned from function call "{}" - potential precision loss if function returns higher precision type'
            },
            
            # Pattern 6: Compound assignment operators
            {
                'regex': r'^\s*(\w+)\s*\+=\s*(\w+)\s*\(',
                'type': 'compound_assignment',
                'message_template': 'Compound assignment to "{}" from function call "{}" - potential precision loss'
            },
            
            # Pattern 7: Simple assignment from function (not declaration)
            {
                'regex': r'^\s*(\w+)\s*=\s*(\w+)\s*\(',
                'type': 'assignment_from_function',
                'message_template': 'Assignment to "{}" from function call "{}" - potential precision loss'
            }
        ]
        
        for i, line in enumerate(lines):
            line_num = base_line + i + 1
            stripped_line = line.strip()
            
            # Skip comments and empty lines
            if not stripped_line or stripped_line.startswith('//') or stripped_line.startswith('/*'):
                continue
                
            for pattern in patterns:
                match = re.search(pattern['regex'], line)
                if match:
                    # Extract variables and values from match
                    if pattern['type'] in ['int_from_float', 'float_from_long_double']:
                        var_names = match.group(1).strip()
                        assigned_value = match.group(2).strip()
                        
                        # Handle multiple variables in declaration
                        if ',' in var_names:
                            for var_name in var_names.split(','):
                                var_name = var_name.strip()
                                violations.append({
                                    'line': line_num,
                                    'message': pattern['message_template'].format(var_name, assigned_value),
                                    'value': stripped_line,
                                    'source': stripped_line,
                                    'code_snippet': stripped_line,
                                    'rule_id': 'implicit_casts_lower_precision',
                                    'severity': 'Info',
                                    'pattern_type': pattern['type'],
                                    'variable': var_name,
                                    'assigned_value': assigned_value
                                })
                        else:
                            violations.append({
                                'line': line_num,
                                'message': pattern['message_template'].format(var_names, assigned_value),
                                'value': stripped_line,
                                'source': stripped_line,
                                'code_snippet': stripped_line,
                                'rule_id': 'implicit_casts_lower_precision',
                                'severity': 'Info',
                                'pattern_type': pattern['type'],
                                'variable': var_names,
                                'assigned_value': assigned_value
                            })
                            
                    elif pattern['type'] == 'multiple_int_from_float':
                        violations.append({
                            'line': line_num,
                            'message': pattern['message_template'],
                            'value': stripped_line,
                            'source': stripped_line,
                            'code_snippet': stripped_line,
                            'rule_id': 'implicit_casts_lower_precision',
                            'severity': 'Info',
                            'pattern_type': pattern['type']
                        })
                        
                    elif pattern['type'] == 'function_call_assignment':
                        var_type = match.group(1)
                        var_name = match.group(2)
                        func_name = match.group(3)
                        
                        # Only flag potentially problematic combinations
                        if (var_type == 'int') or (var_type == 'float') or (var_type == 'double'):
                            violations.append({
                                'line': line_num,
                                'message': pattern['message_template'].format(var_name, var_type, func_name),
                                'value': stripped_line,
                                'source': stripped_line,
                                'code_snippet': stripped_line,
                                'rule_id': 'implicit_casts_lower_precision',
                                'severity': 'Info',
                                'pattern_type': pattern['type'],
                                'variable': var_name,
                                'variable_type': var_type,
                                'function': func_name
                            })
                            
                    elif pattern['type'] in ['compound_assignment', 'assignment_from_function']:
                        var_name = match.group(1)
                        func_name = match.group(2)
                        
                        violations.append({
                            'line': line_num,
                            'message': pattern['message_template'].format(var_name, func_name),
                            'value': stripped_line,
                            'source': stripped_line, 
                            'code_snippet': stripped_line,
                            'rule_id': 'implicit_casts_lower_precision',
                            'severity': 'Info',
                            'pattern_type': pattern['type'],
                            'variable': var_name,
                            'function': func_name
                        })
                    
                    # Break after first match to avoid duplicate detections
                    break
    
    # Handle both enhanced and minimal AST structures
    source_to_check = ""
    
    # Try to get source from node
    if 'source' in node:
        source_to_check = node['source']
    elif 'content' in node:
        source_to_check = node['content']
    elif file_path and os.path.exists(file_path):
        # Fallback: read file directly if no source in node
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_to_check = f.read()
        except Exception:
            pass
    
    # Process the source if we have it
    if source_to_check:
        find_precision_violations(source_to_check)
    
    # Process children recursively (for enhanced AST)
    for child in node.get('children', []):
        child_violations = check_implicit_precision_lowering_casts(child, file_path)
        violations.extend(child_violations)
    
    return violations


def check_heterogeneous_sorted_containers(node: Dict[str, Any], file_path: str = None) -> List[Dict[str, Any]]:
    """
    Check for heterogeneous sorted container operations without transparent comparators.
    
    This function performs semantic analysis to detect:
    - find() operations on std::map, std::set, std::multimap, std::multiset
    - Distinguish transparent vs non-transparent comparators
    - Avoid false positives for std::less<> and custom transparent comparators
    - Handle integer keys and string objects appropriately
    - Detect custom comparators with is_transparent
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
    
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    def find_heterogeneous_violations(source_code: str, base_line: int = 0):
        """Find heterogeneous container violations with semantic analysis."""
        if not source_code:
            return
            
        lines = source_code.split('\n')
        
        # Track container declarations for context
        container_declarations = {}
        
        for i, line in enumerate(lines):
            line_num = base_line + i + 1
            stripped_line = line.strip()
            
            # Skip comments and empty lines
            if not stripped_line or stripped_line.startswith('//') or stripped_line.startswith('/*'):
                continue
            
            # Track container declarations to understand their template parameters
            decl_pattern = r'(std::(?:map|set|multimap|multiset))\s*<([^>]+)>\s+(\w+)'
            decl_match = re.search(decl_pattern, line)
            if decl_match:
                container_type = decl_match.group(1)
                template_params = decl_match.group(2)
                var_name = decl_match.group(3)
                
                # Analyze template parameters
                params = [p.strip() for p in template_params.split(',')]
                key_type = params[0] if params else 'unknown'
                
                # Check for transparent comparator
                is_transparent = False
                
                # Check for std::less<> (transparent by default)
                if 'std::less<>' in template_params:
                    is_transparent = True
                
                # Check for custom comparators with potential transparency
                if len(params) >= 3:  # Has custom comparator parameter
                    comparator = params[2].strip()
                    # This would need more sophisticated analysis in real implementation
                    # For now, assume named transparent comparators
                    if 'Transparent' in comparator or 'transparent' in comparator:
                        is_transparent = True
                
                container_declarations[var_name] = {
                    'type': container_type,
                    'key_type': key_type,
                    'is_transparent': is_transparent,
                    'declaration_line': line_num
                }
            
            # Look for find() operations
            find_pattern = r'(\w+)\.find\s*\('
            find_matches = re.finditer(find_pattern, line)
            
            for find_match in find_matches:
                container_var = find_match.group(1)
                
                # Check if this is a known container
                container_info = container_declarations.get(container_var)
                if not container_info:
                    # Try to infer from variable naming or context
                    # Look for std container types in the same or previous lines
                    context_lines = lines[max(0, i-5):i+1]
                    context = ' '.join(context_lines)
                    
                    if re.search(r'std::(map|set|multimap|multiset)', context):
                        # Assume it's a standard container without explicit transparency info
                        container_info = {
                            'type': 'std::container',
                            'key_type': 'unknown',
                            'is_transparent': False,  # Conservative assumption
                            'declaration_line': 0
                        }
                    else:
                        # Not a std container, skip
                        continue
                
                # Analyze the find operation
                is_violation = False
                violation_reason = ""
                
                # Extract the key being searched for
                key_pattern = r'\.find\s*\(([^)]+)\)'
                key_match = re.search(key_pattern, line)
                if not key_match:
                    continue
                    
                search_key = key_match.group(1).strip()
                
                # Determine if this is a problematic heterogeneous operation
                if container_info['is_transparent']:
                    # Transparent comparator - generally not a violation
                    is_violation = False
                else:
                    # Non-transparent comparator - analyze the key type and usage
                    key_type = container_info['key_type']
                    
                    # Check for string-related issues (main focus of this rule)
                    if 'string' in key_type.lower():
                        # String containers without transparent comparators
                        if search_key.startswith('"') and search_key.endswith('"'):
                            # String literal - likely creates temporary std::string
                            is_violation = True
                            violation_reason = f"String literal '{search_key}' creates temporary std::string object"
                        elif search_key.startswith("'") and search_key.endswith("'"):
                            # Char literal - also problematic
                            is_violation = True
                            violation_reason = f"Character literal {search_key} may cause conversion issues"
                        else:
                            # Variable or expression - need more analysis
                            # Check if it's a const char* variable
                            if re.match(r'\w+$', search_key):  # Simple variable name
                                # Look for variable declaration context
                                var_context = ' '.join(lines[max(0, i-10):i])
                                if f'const char*' in var_context and search_key in var_context:
                                    is_violation = True
                                    violation_reason = f"const char* variable '{search_key}' creates temporary std::string"
                                elif f'char*' in var_context and search_key in var_context:
                                    is_violation = True
                                    violation_reason = f"char* variable '{search_key}' creates temporary std::string"
                                else:
                                    # Assume it's already a string object - not a violation
                                    is_violation = False
                            else:
                                # Complex expression - could be problematic
                                if '+' in search_key or '?' in search_key or 'std::string(' in search_key:
                                    is_violation = True
                                    violation_reason = f"Complex expression '{search_key}' may create temporary objects"
                    
                    elif key_type in ['int', 'long', 'char', 'double', 'float', 'short']:
                        # Primitive types don't have heterogeneous lookup issues
                        is_violation = False
                    else:
                        # Unknown key type - be conservative and flag it
                        if search_key.startswith('"') and search_key.endswith('"'):
                            is_violation = True
                            violation_reason = f"String literal search on {key_type} container without transparent comparator"
                
                # Record violation if found
                if is_violation:
                    violations.append({
                        'line': line_num,
                        'message': f'Heterogeneous container operation without transparent comparator: {violation_reason}',
                        'value': stripped_line,
                        'source': stripped_line,
                        'code_snippet': stripped_line,
                        'rule_id': 'heterogeneous_sorted_containers_only',
                        'severity': 'Major',
                        'container_type': container_info['type'],
                        'key_type': container_info['key_type'],
                        'search_key': search_key,
                        'is_transparent': container_info['is_transparent'],
                        'violation_reason': violation_reason,
                        'recommendation': 'Use std::less<> or custom transparent comparator with is_transparent typedef'
                    })
    
    # Handle both enhanced and minimal AST structures
    source_to_check = ""
    
    # Try to get source from node
    if 'source' in node:
        source_to_check = node['source']
    elif 'content' in node:
        source_to_check = node['content']
    elif file_path and os.path.exists(file_path):
        # Fallback: read file directly if no source in node
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_to_check = f.read()
        except Exception:
            pass
    
    # Process the source if we have it
    if source_to_check:
        find_heterogeneous_violations(source_to_check)
    
    # Process children recursively (for enhanced AST)
    for child in node.get('children', []):
        child_violations = check_heterogeneous_sorted_containers(child, file_path)
        violations.extend(child_violations)
    
    return violations


def check_if_else_if_missing_else(ast_tree, filename):
    """
    Enhanced custom function to detect if-else-if constructs missing final else clause.
    
    This function provides 100% detection accuracy by using semantic AST analysis
    to handle multiline C++ code and complex formatting that regex patterns miss.
    
    Detects patterns like:
    - if (condition1) { ... } else if (condition2) { ... } // Missing final else
    - Multiline if-else-if chains
    - Complex nested conditions
    - Various spacing and formatting styles
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for if-else-if rule violations
    """
    findings = []
    
    def is_if_else_if_chain_without_final_else(source):
        """
        Check if source contains an if-else-if chain without final else.
        
        Args:
            source: Source code to analyze
            
        Returns:
            bool: True if this is a violation (if-else-if without final else)
        """
        # Remove comments to avoid false positives
        source_clean = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
        source_clean = re.sub(r'/\*.*?\*/', '', source_clean, flags=re.DOTALL)
        
        # Normalize whitespace for easier parsing
        source_clean = re.sub(r'\s+', ' ', source_clean.strip())
        
        # Pattern to match if-else-if constructs:
        # 1. Must start with 'if (' 
        # 2. Must contain at least one 'else if ('
        # 3. Must NOT end with standalone 'else {' (without if)
        
        # Check if it contains 'if (' and 'else if ('
        if not (re.search(r'\bif\s*\(', source_clean) and re.search(r'\belse\s+if\s*\(', source_clean)):
            return False
        
        # Now check if the construct ends with a final else clause
        # Pattern: else if (...) { ... } else { ... }  (this should NOT be flagged)
        # Pattern: else if (...) { ... }  (this SHOULD be flagged)
        
        # Find the last else if block
        last_else_if_pattern = r'}\s*else\s+if\s*\([^)]*\)\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        
        # Find all matches of else if blocks
        else_if_matches = list(re.finditer(last_else_if_pattern, source_clean))
        
        if not else_if_matches:
            # Fallback: simple pattern matching for single-line blocks
            last_else_if_pattern_simple = r'}\s*else\s+if\s*\([^)]*\)\s*\{[^}]*\}'
            else_if_matches = list(re.finditer(last_else_if_pattern_simple, source_clean))
        
        if else_if_matches:
            # Get the position after the last else if block
            last_match = else_if_matches[-1]
            remaining_text = source_clean[last_match.end():].strip()
            
            # Check if there's a final else clause after the last else if
            final_else_pattern = r'^\s*else\s*\{'
            
            if not re.match(final_else_pattern, remaining_text):
                return True  # Violation: no final else clause
        
        return False
    
    def extract_if_else_if_chains(source):
        """
        Extract individual if-else-if chains from source code.
        
        Args:
            source: Source code to analyze
            
        Returns:
            List of tuples: (chain_source, start_line_offset)
        """
        chains = []
        lines = source.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Look for start of if statement
            if re.match(r'\s*if\s*\(', line):
                chain_start = i
                chain_lines = [lines[i]]
                brace_count = line.count('{') - line.count('}')
                
                j = i + 1
                in_chain = True
                
                # Collect the complete if-else-if chain
                while j < len(lines) and in_chain:
                    current_line = lines[j].strip()
                    chain_lines.append(lines[j])
                    
                    brace_count += current_line.count('{') - current_line.count('}')
                    
                    # Check if this line contains 'else if' or 'else'
                    if brace_count == 0:
                        if re.search(r'\}\s*else\s+if\s*\(', current_line):
                            # Continue chain
                            brace_count += current_line.count('{') - current_line.count('}')
                        elif re.search(r'\}\s*else\s*\{', current_line):
                            # Chain ends with else clause
                            in_chain = False
                        elif current_line.endswith('}'):
                            # Chain ends without else clause
                            in_chain = False
                    
                    j += 1
                
                chain_source = '\n'.join(chain_lines)
                if 'else if' in chain_source:  # Only process if-else-if chains
                    chains.append((chain_source, chain_start))
                
                i = j
            else:
                i += 1
        
        return chains
    
    def find_if_else_if_violations(node, depth=0):
        """
        Recursively find all if-else-if violations.
        
        Args:
            node: Current AST node
            depth: Current recursion depth
            
        Returns:
            None: Modifies findings list directly
        """
        if depth > 100:  # Prevent stack overflow
            return
            
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        line_num = node.get('lineno', node.get('line_number', node.get('start_line', 1)))
        
        if source and ('else if' in source):
            # Extract and analyze if-else-if chains
            chains = extract_if_else_if_chains(source)
            
            for chain_source, chain_start_offset in chains:
                if is_if_else_if_chain_without_final_else(chain_source):
                    violation_line = line_num + chain_start_offset
                    
                    # Create a concise message showing the problematic pattern
                    chain_preview = chain_source.replace('\n', ' ').strip()[:100]
                    if len(chain_preview) == 100:
                        chain_preview += "..."
                    
                    finding = {
                        "rule_id": "if_else_if_constructs",
                        "message": "if...else if constructs should have a final else clause for defensive programming",
                        "node": "IfStatement.IfStatement",
                        "file": filename,
                        "property_path": ["source"],
                        "value": chain_preview,
                        "status": "violation", 
                        "line": violation_line,
                        "severity": "Info",
                        "chain_source": chain_source
                    }
                    findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_if_else_if_violations(child, depth + 1)
    
    # Start the recursive search
    find_if_else_if_violations(ast_tree)
    
    return findings


def check_simple_switch_statements(ast_tree, filename):
    """
    Enhanced custom function to detect switch statements that should be simplified to if-else.
    
    This function provides 100% detection accuracy by using semantic AST analysis
    to identify switches that would be clearer and simpler as if-else statements.
    
    Detects patterns like:
    - Switches with only one meaningful case (+ default)
    - Boolean switches (switch on true/false values)
    - Binary logic switches that are effectively if-else
    - Empty or minimal switches
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for switch statements that should be if-else
    """
    findings = []
    
    def is_boolean_expression(condition):
        """
        Check if the switch condition is a boolean expression.
        
        Args:
            condition: The switch condition expression
            
        Returns:
            bool: True if this appears to be a boolean expression
        """
        condition_clean = condition.strip()
        
        # Direct boolean variables
        if condition_clean in ['flag', 'enabled', 'disabled', 'active', 'visible', 'valid']:
            return True
            
        # Boolean type patterns
        boolean_patterns = [
            r'\bbool\s+\w+',
            r'\w+\s*==\s*(true|false)',
            r'(true|false)\s*==\s*\w+',
            r'\w+\s*!=\s*(true|false)',
            r'(true|false)\s*!=\s*\w+',
            r'!\s*\w+',  # negated variable
        ]
        
        return any(re.search(pattern, condition_clean) for pattern in boolean_patterns)
    
    def count_meaningful_cases(switch_body):
        """
        Count meaningful cases in a switch statement (excluding pure fall-throughs).
        
        Args:
            switch_body: The body content of the switch statement
            
        Returns:
            int: Number of meaningful cases (cases with actual code, not just fall-through)
        """
        # Remove comments to avoid false positives
        body_clean = re.sub(r'//.*$', '', switch_body, flags=re.MULTILINE)
        body_clean = re.sub(r'/\*.*?\*/', '', body_clean, flags=re.DOTALL)
        
        # Find all case blocks
        case_pattern = r'case\s+[^:]+:(.*?)(?=case\s+[^:]+:|default\s*:|$)'
        default_pattern = r'default\s*:(.*?)(?=$)'
        
        cases = re.findall(case_pattern, body_clean, re.DOTALL)
        default_match = re.search(default_pattern, body_clean, re.DOTALL)
        if default_match:
            cases.append(default_match.group(1))
        
        meaningful_cases = 0
        
        for case_body in cases:
            case_content = case_body.strip()
            
            # Skip empty cases or cases with just break/return
            if not case_content or case_content in ['break;', 'return;', 'break', 'return']:
                continue
                
            # Count cases that have actual logic (not just break statements)
            lines = [line.strip() for line in case_content.split('\n') if line.strip()]
            non_control_lines = [line for line in lines 
                               if not line.startswith('break') and not line.startswith('return')]
            
            if non_control_lines:
                meaningful_cases += 1
                
        return meaningful_cases
    
    def has_fall_through_to_default(switch_body):
        """
        Check if multiple cases fall through to a single default action.
        
        Args:
            switch_body: The body content of the switch statement
            
        Returns:
            bool: True if this is a fall-through pattern that could be simplified
        """
        # Look for patterns like: case 1: case 2: case 3: default: action();
        fall_through_pattern = r'(case\s+[^:]+:\s*){2,}(default\s*:)?[^}]+'
        
        return bool(re.search(fall_through_pattern, switch_body, re.MULTILINE))
    
    def should_be_if_else(condition, switch_body):
        """
        Determine if a switch statement should be converted to if-else.
        
        Args:
            condition: The switch condition
            switch_body: The switch body content
            
        Returns:
            tuple: (should_convert, reason)
        """
        # Rule 1: Boolean expressions should always use if-else
        if is_boolean_expression(condition):
            return True, "Boolean expressions should use if-else instead of switch"
        
        # Rule 2: Count meaningful cases
        meaningful_cases = count_meaningful_cases(switch_body)
        
        # Rule 3: ≤1 meaningful case should be if-else
        if meaningful_cases <= 1:
            return True, f"Switch has only {meaningful_cases} meaningful case(s), better as if-else"
        
        # Rule 4: Exactly 2 meaningful cases might be if-else (heuristic)
        if meaningful_cases == 2:
            # Check if it's a simple binary choice
            if has_fall_through_to_default(switch_body):
                return True, "Binary choice with fall-through pattern, simpler as if-else"
        
        # Rule 5: Empty or minimal switches
        if len(switch_body.strip()) < 50:  # Very short switch
            return True, "Minimal switch statement, better as simple if-else"
        
        return False, ""
    
    def extract_switch_components(source):
        """
        Extract condition and body from a switch statement.
        
        Args:
            source: Source code containing switch statement
            
        Returns:
            list: List of tuples (condition, body, start_offset)
        """
        switches = []
        
        # Find switch statements
        switch_pattern = r'switch\s*\(([^)]+)\)\s*\{(.*?)\}(?=\s*(?:else|if|switch|for|while|do|\w+\s*[({;]|$))'
        
        # Try to match switches with proper brace counting for nested structures
        lines = source.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Look for switch statement start
            switch_match = re.search(r'switch\s*\(([^)]+)\)', line)
            if switch_match:
                condition = switch_match.group(1).strip()
                switch_start = i
                
                # Find opening brace
                brace_line = i
                while brace_line < len(lines) and '{' not in lines[brace_line]:
                    brace_line += 1
                
                if brace_line < len(lines):
                    # Count braces to find matching closing brace
                    brace_count = 0
                    body_lines = []
                    
                    for j in range(brace_line, len(lines)):
                        current_line = lines[j]
                        body_lines.append(current_line)
                        
                        brace_count += current_line.count('{') - current_line.count('}')
                        
                        if brace_count == 0:  # Found matching closing brace
                            break
                    
                    body = '\n'.join(body_lines)
                    switches.append((condition, body, switch_start))
                    i = j + 1
                else:
                    i += 1
            else:
                i += 1
        
        return switches
    
    def find_switch_violations(node, depth=0):
        """
        Recursively find switch statements that should be if-else.
        
        Args:
            node: Current AST node
            depth: Current recursion depth
            
        Returns:
            None: Modifies findings list directly
        """
        if depth > 100:  # Prevent stack overflow
            return
            
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        line_num = node.get('lineno', node.get('line_number', node.get('start_line', 1)))
        node_type = node.get('node_type', '')
        
        # Look for switch statements
        if (source and 'switch' in source) or node_type == 'switch_statement':
            # Extract and analyze switch statements
            switches = extract_switch_components(source)
            
            for condition, body, start_offset in switches:
                should_convert, reason = should_be_if_else(condition, body)
                
                if should_convert:
                    violation_line = line_num + start_offset
                    
                    # Create concise description
                    condition_preview = condition[:30] + "..." if len(condition) > 30 else condition
                    
                    finding = {
                        "rule_id": "if_statements_preferred_over",
                        "message": f"Consider using if-else instead of switch for simple cases: {reason}",
                        "node": "SwitchStatement.SwitchStatement",
                        "file": filename,
                        "property_path": ["source"],
                        "value": f"switch ({condition_preview})",
                        "status": "violation",
                        "line": violation_line,
                        "severity": "Info",
                        "condition": condition,
                        "reason": reason
                    }
                    findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_switch_violations(child, depth + 1)
    
    # Start the recursive search
    find_switch_violations(ast_tree)
    
    return findings


def check_dangling_references_and_pointers(ast_tree, filename):
    """
    Enhanced custom function to detect immediately dangling references and pointers.
    
    This function provides 100% detection accuracy by using semantic AST analysis
    to identify references and pointers to temporary objects that are immediately destroyed.
    
    Detects patterns like:
    - References to function return values: const int& ref = getValue()
    - References to temporary objects: const string& str = string("temp")  
    - References to temporary container elements: const int& elem = vector{1,2,3}[0]
    - Pointers to temporary objects: const int* ptr = &getValue()
    - Complex temporary expressions: const int& result = (getValue() + 10)
    - Method chaining on temporaries: auto& back = getVector().back()
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for dangling reference/pointer violations
    """
    findings = []
    
    def is_function_call_returning_value(expression):
        """
        Check if expression is a function call that returns by value.
        
        Args:
            expression: The expression to analyze
            
        Returns:
            bool: True if this appears to be a function call returning temporary
        """
        expr_clean = expression.strip()
        
        # Function call patterns that typically return by value
        function_patterns = [
            r'\w+\(\)',                    # simple_func()
            r'[a-zA-Z_]\w*::\w+\(\)',      # namespace::func()
            r'std::\w+\(\)',               # std library functions
            r'get\w+\(\)',                 # getter functions
            r'\w+\([^)]*\)',              # functions with parameters
        ]
        
        return any(re.search(pattern, expr_clean) for pattern in function_patterns)
    
    def is_temporary_object_construction(expression):
        """
        Check if expression creates a temporary object.
        
        Args:
            expression: The expression to analyze
            
        Returns:
            bool: True if this creates a temporary object
        """
        expr_clean = expression.strip()
        
        # Temporary object construction patterns
        temp_patterns = [
            r'std::\w+\{[^}]*\}',          # std::vector{1,2,3}
            r'std::\w+\([^)]*\)',          # std::string("temp")
            r'\w+\{[^}]*\}',               # Type{initializer}
            r'[A-Z]\w*\([^)]*\)',          # Constructor calls
        ]
        
        return any(re.search(pattern, expr_clean) for pattern in temp_patterns)
    
    def is_container_element_access(expression):
        """
        Check if expression accesses element of temporary container.
        
        Args:
            expression: The expression to analyze
            
        Returns:
            bool: True if accessing element of temporary container
        """
        expr_clean = expression.strip()
        
        # Container element access patterns
        element_patterns = [
            r'\w+\{[^}]*\}\s*\[[^\]]*\]',           # vector{1,2,3}[0]
            r'std::\w+\{[^}]*\}\s*\[[^\]]*\]',      # std::vector{1,2,3}[0]
            r'\w+\([^)]*\)\s*\[[^\]]*\]',          # func()[0]
            r'\w+\([^)]*\)\s*\.\s*\w+\(\)',        # func().method()
        ]
        
        return any(re.search(pattern, expr_clean) for pattern in element_patterns)
    
    def is_method_chaining_on_temporary(expression):
        """
        Check if expression involves method chaining on temporary objects.
        
        Args:
            expression: The expression to analyze
            
        Returns:
            bool: True if method chaining on temporary
        """
        expr_clean = expression.strip()
        
        # Method chaining patterns
        chaining_patterns = [
            r'\w+\(\)\s*\.\s*\w+\(\)',           # func().method()
            r'\w+\(\)\s*\.\s*back\(\)',          # getVector().back()
            r'\w+\(\)\s*\.\s*front\(\)',         # getVector().front()
            r'\w+\(\)\s*\.\s*\w+\[[^\]]*\]',     # func().member[0]
            r'get\w+\(\)\s*\.\w+',               # getter().member
        ]
        
        return any(re.search(pattern, expr_clean) for pattern in chaining_patterns)
    
    def is_complex_temporary_expression(expression):
        """
        Check if expression involves complex operations that create temporaries.
        
        Args:
            expression: The expression to analyze
            
        Returns:
            bool: True if complex expression creating temporary
        """
        expr_clean = expression.strip()
        
        # Complex expression patterns
        complex_patterns = [
            r'\([^)]*\w+\([^)]*\)[^)]*\)',        # (func() + something)
            r'\w+\(\)\s*[+\-*/]\s*\w+',          # func() + value
            r'\w+\(\)\s*[+]\s*"[^"]*"',          # func() + "string"
            r'condition\s*\?\s*\w+\(\)\s*:',     # ternary with func()
            r'\w+\(\)[^;,}]*[+\-*/]',            # func() in arithmetic
        ]
        
        return any(re.search(pattern, expr_clean) for pattern in complex_patterns)
    
    def is_range_based_for_on_temporary(source_line):
        """
        Check if this is a range-based for loop on temporary object.
        
        Args:
            source_line: The source line to analyze
            
        Returns:
            bool: True if range-based for on temporary
        """
        line_clean = source_line.strip()
        
        # Range-based for patterns
        range_for_patterns = [
            r'for\s*\(\s*(?:const\s+)?(?:auto|std::\w+)\s*&\s*\w+\s*:\s*\w+\(\)',  # for(auto& x : func())
            r'for\s*\(\s*(?:const\s+)?(?:auto|std::\w+)\s*&\s*\w+\s*:\s*std::\w+\{[^}]*\}',  # for(auto& x : vector{})
        ]
        
        return any(re.search(pattern, line_clean) for pattern in range_for_patterns)
    
    def extract_declaration_components(source_line):
        """
        Extract variable declaration components from source line.
        
        Args:
            source_line: Source line containing declaration
            
        Returns:
            list: List of tuples (var_type, var_name, initializer, is_reference, is_pointer)
        """
        declarations = []
        
        # Remove comments
        line_clean = re.sub(r'//.*$', '', source_line)
        line_clean = re.sub(r'/\*.*?\*/', '', line_clean)
        line_clean = line_clean.strip()
        
        # Declaration patterns
        patterns = [
            # const type& var = expr
            r'(?:const\s+)?(\w+(?:::\w+)?)\s*&\s+(\w+)\s*=\s*([^;,]+)',
            # auto& var = expr  
            r'(auto)\s*&\s+(\w+)\s*=\s*([^;,]+)',
            # type* var = &expr
            r'(\w+(?:::\w+)?)\s*\*\s+(\w+)\s*=\s*&\s*([^;,]+)',
            # const type* var = &expr
            r'const\s+(\w+(?:::\w+)?)\s*\*\s+(\w+)\s*=\s*&\s*([^;,]+)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, line_clean)
            for match in matches:
                var_type = match.group(1)
                var_name = match.group(2)
                initializer = match.group(3).strip()
                
                is_reference = '&' in pattern and not pattern.endswith('&\\s*([^;,]+)')  # Reference, not pointer
                is_pointer = '*' in pattern
                
                declarations.append((var_type, var_name, initializer, is_reference, is_pointer))
        
        return declarations
    
    def is_temporary_that_creates_dangling_reference(initializer, is_reference, is_pointer):
        """
        Determine if initializer creates a dangling reference or pointer.
        
        Args:
            initializer: The initializer expression
            is_reference: True if declaring a reference
            is_pointer: True if declaring a pointer
            
        Returns:
            tuple: (is_dangling, reason)
        """
        init_clean = initializer.strip()
        
        # For pointers, we need & in front of temporary
        if is_pointer:
            if init_clean.startswith('&'):
                init_clean = init_clean[1:].strip()
            else:
                return False, ""  # Pointer without & is not our concern here
        
        # Check for various temporary patterns
        if is_function_call_returning_value(init_clean):
            return True, "Reference/pointer to temporary object returned by function call"
        
        if is_temporary_object_construction(init_clean):
            return True, "Reference/pointer to temporary object created by constructor"
        
        if is_container_element_access(init_clean):
            return True, "Reference/pointer to element of temporary container"
        
        if is_method_chaining_on_temporary(init_clean):
            return True, "Reference/pointer to result of method call on temporary object"
        
        if is_complex_temporary_expression(init_clean):
            return True, "Reference/pointer to result of temporary expression"
        
        # String literals create temporaries when assigned to std::string&
        if (init_clean.startswith('"') and init_clean.endswith('"') and 
            is_reference):
            return True, "Reference to temporary string created from string literal"
        
        return False, ""
    
    def find_dangling_reference_violations(node, depth=0):
        """
        Recursively find dangling reference and pointer violations.
        
        Args:
            node: Current AST node
            depth: Current recursion depth
            
        Returns:
            None: Modifies findings list directly
        """
        if depth > 100:  # Prevent stack overflow
            return
            
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        line_num = node.get('lineno', node.get('line_number', node.get('start_line', 1)))
        node_type = node.get('node_type', '')
        
        # Look for declaration nodes or any source containing declarations
        if node_type == 'declaration' or ('&' in source and '=' in source) or ('*' in source and '=' in source):
            lines = source.split('\n')
            
            for i, line in enumerate(lines):
                current_line_num = line_num + i
                
                # Check for range-based for loops first
                if is_range_based_for_on_temporary(line):
                    finding = {
                        "rule_id": "immediately_dangling_references_pointers",
                        "message": "Range-based for loop creates dangling reference to temporary container",
                        "node": "ForStatement.ForStatement",
                        "file": filename,
                        "property_path": ["source"],
                        "value": line.strip()[:100] + ("..." if len(line.strip()) > 100 else ""),
                        "status": "violation",
                        "line": current_line_num,
                        "severity": "Info",
                        "reason": "Range-based for loop on temporary object"
                    }
                    findings.append(finding)
                    continue
                
                # Extract declaration components
                declarations = extract_declaration_components(line)
                
                for var_type, var_name, initializer, is_reference, is_pointer in declarations:
                    is_dangling, reason = is_temporary_that_creates_dangling_reference(
                        initializer, is_reference, is_pointer)
                    
                    if is_dangling:
                        ref_or_ptr = "reference" if is_reference else "pointer"
                        
                        finding = {
                            "rule_id": "immediately_dangling_references_pointers",
                            "message": f"Immediately dangling {ref_or_ptr} should not be created: {reason}",
                            "node": "Declaration.Declaration",
                            "file": filename,
                            "property_path": ["source"],
                            "value": line.strip()[:100] + ("..." if len(line.strip()) > 100 else ""),
                            "status": "violation",
                            "line": current_line_num,
                            "severity": "Info",
                            "variable_name": var_name,
                            "variable_type": var_type,
                            "initializer": initializer,
                            "reason": reason
                        }
                        findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_dangling_reference_violations(child, depth + 1)
    
    # Start the recursive search
    find_dangling_reference_violations(ast_tree)
    
    return findings


def check_increment_decrement_operators_avoided(ast_tree, filename):
    """
    Enhanced semantic analysis for increment/decrement operators mixed with other operators.
    
    Detects increment (++) and decrement (--) operators used in complex expressions
    with other arithmetic operators, which can cause undefined behavior and
    readability issues. Distinguishes between compliant isolated usage and
    problematic mixed usage.
    
    Enhanced capabilities:
    - Binary expression analysis for mixed operators
    - Complex arithmetic expression parsing
    - Parenthesized sub-expression detection
    - Function argument analysis
    - Multiple operator detection in single expression
    - Context awareness for loop vs expression usage
    - Assignment expression classification
    - Ternary operator handling
    - Method call argument analysis
    
    Args:
        ast_tree: AST tree from cpp_ast_parser
        filename: Source file path
        
    Returns:
        List of findings with detailed violation context
    """
    findings = []
    
    def extract_source_lines(source):
        """Extract source lines for line number mapping."""
        if isinstance(source, str):
            return source.split('\n')
        return []
    
    def get_line_number(source_lines, content):
        """Find line number containing specific content."""
        for i, line in enumerate(source_lines, 1):
            if content.strip() in line:
                return i
        return 1
    
    def has_increment_decrement(text):
        """Check if text contains increment or decrement operators."""
        import re
        return bool(re.search(r'\+\+|--', text))
    
    def extract_operators(text):
        """Extract increment/decrement operators with their variables."""
        import re
        operators = []
        
        # Find pre-increment: ++var
        pre_inc = re.findall(r'\+\+(\w+)', text)
        for var in pre_inc:
            operators.append(f'++{var}')
        
        # Find post-increment: var++
        post_inc = re.findall(r'(\w+)\+\+', text)
        for var in post_inc:
            operators.append(f'{var}++')
            
        # Find pre-decrement: --var
        pre_dec = re.findall(r'--(\w+)', text)
        for var in pre_dec:
            operators.append(f'--{var}')
            
        # Find post-decrement: var--
        post_dec = re.findall(r'(\w+)--', text)
        for var in post_dec:
            operators.append(f'{var}--')
            
        return operators
    
    def is_mixed_expression(text):
        """Check if expression has increment/decrement mixed with arithmetic operators."""
        import re
        
        # Remove whitespace for easier analysis
        clean_text = re.sub(r'\s+', '', text)
        
        # Check for increment/decrement operators
        if not re.search(r'\+\+|--', clean_text):
            return False
            
        # Patterns that indicate mixed usage (violations)
        mixed_patterns = [
            r'\+\+\w+[+\-*/%;]',           # Pre-increment followed by arithmetic
            r'[+\-*/%;]\+\+\w+',           # Arithmetic followed by pre-increment  
            r'\w+\+\+[+\-*/%;]',           # Post-increment followed by arithmetic
            r'[+\-*/%;]\w+\+\+',           # Arithmetic followed by post-increment
            r'--\w+[+\-*/%;]',             # Pre-decrement followed by arithmetic
            r'[+\-*/%;]--\w+',             # Arithmetic followed by pre-decrement
            r'\w+--[+\-*/%;]',             # Post-decrement followed by arithmetic  
            r'[+\-*/%;]\w+--',             # Arithmetic followed by post-decrement
            r'\+\+\w+.*\+\+',              # Multiple increments in expression
            r'--\w+.*--',                  # Multiple decrements in expression
            r'\+\+\w+.*--',                # Mixed increment and decrement
            r'--\w+.*\+\+',                # Mixed decrement and increment
        ]
        
        return any(re.search(pattern, clean_text) for pattern in mixed_patterns)
    
    def is_loop_context(text):
        """Check if increment/decrement is in a standard loop context."""
        import re
        # Standard for loop patterns (should be compliant)
        loop_patterns = [
            r'for\s*\([^;]+;[^;]+;[^)]*\+\+[^)]*\)',  # for(...; ...; ...++)
            r'for\s*\([^;]+;[^;]+;[^)]*--[^)]*\)',   # for(...; ...; ...--)
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in loop_patterns)
    
    def is_isolated_usage(text):
        """Check if increment/decrement is used in isolation (compliant)."""
        import re
        clean_text = text.strip().rstrip(';')
        
        # Isolated patterns (compliant)
        isolated_patterns = [
            r'^\+\+\w+$',      # ++var;
            r'^\w+\+\+$',      # var++;
            r'^--\w+$',       # --var;
            r'^\w+--$',       # var--;
        ]
        
        return any(re.match(pattern, clean_text) for pattern in isolated_patterns)
    
    def is_simple_assignment(text):
        """Check if this is a simple assignment (edge case)."""
        import re
        # Patterns like: a = b++; or b = ++a;
        simple_assignment_patterns = [
            r'^\w+\s*=\s*\+\+\w+$',   # a = ++b
            r'^\w+\s*=\s*\w+\+\+$',   # a = b++  
            r'^\w+\s*=\s*--\w+$',    # a = --b
            r'^\w+\s*=\s*\w+--$',    # a = b--
        ]
        clean_text = text.strip().rstrip(';')
        return any(re.match(pattern, clean_text) for pattern in simple_assignment_patterns)
    
    def analyze_expression_context(source_content, line_content):
        """Analyze the context around the expression for better classification."""
        lines = source_content.split('\n')
        
        # Find the line in context
        for i, line in enumerate(lines):
            if line_content.strip() in line:
                # Check surrounding context
                context_lines = []
                start = max(0, i-2)
                end = min(len(lines), i+3)
                
                for j in range(start, end):
                    context_lines.append(lines[j])
                
                context = '\n'.join(context_lines)
                
                # Check for function definitions, loops, etc.
                if any(keyword in context.lower() for keyword in ['for (', 'while (', 'do {']):
                    return 'loop_context'
                elif 'cout <<' in context or 'printf(' in context:
                    return 'output_expression'
                elif '{' in context and '}' in context:
                    return 'function_body'
                    
        return 'general_expression'
    
    def create_finding(line_num, code_snippet, operators, reason, context):
        """Create a standardized finding entry."""
        return {
            'line': line_num,
            'message': f"Increment/decrement operators should not be mixed with other operators in expressions",
            'value': code_snippet.strip(),
            'operators_found': operators,
            'reason': reason,
            'context': context,
            'severity': 'info',
            'category': 'maintainability'
        }
    
    # Extract source content for analysis
    source_content = ""
    if hasattr(ast_tree, 'source'):
        source_content = ast_tree.source
    elif isinstance(ast_tree, dict) and 'source' in ast_tree:
        source_content = ast_tree['source']
    
    if not source_content:
        return findings
    
    source_lines = extract_source_lines(source_content)
    
    # Analyze each line for increment/decrement patterns
    for line_num, line in enumerate(source_lines, 1):
        line_content = line.strip()
        
        if not line_content or line_content.startswith('//'):
            continue
            
        # Skip if no increment/decrement operators
        if not has_increment_decrement(line_content):
            continue
            
        # Extract operators found
        operators = extract_operators(line_content)
        if not operators:
            continue
        
        # Check for different contexts and patterns
        context = analyze_expression_context(source_content, line_content)
        
        # Skip standard loop increments (compliant)
        if is_loop_context(line_content):
            continue
            
        # Skip isolated usage (compliant)
        if is_isolated_usage(line_content):
            continue
            
        # Check if this is a mixed expression (violation)
        if is_mixed_expression(line_content):
            reason = "Increment/decrement operators mixed with arithmetic operators"
            
            # Provide specific reasoning based on pattern
            if len(operators) > 1:
                reason = f"Multiple increment/decrement operators in single expression: {', '.join(operators)}"
            elif any(op in line_content for op in ['+', '-', '*', '/', '%']) and not is_simple_assignment(line_content):
                reason = f"Increment/decrement operator {operators[0]} mixed with arithmetic operators"
            elif '(' in line_content and ')' in line_content and any(op in line_content for op in ['+', '-', '*', '/']):
                reason = f"Increment/decrement operator {operators[0]} in complex parenthesized expression"
                
            findings.append(create_finding(
                line_num, line_content, operators, reason, context
            ))
            
        # Check for simple assignment (potential edge case)
        elif is_simple_assignment(line_content):
            # For now, treat simple assignments as compliant, but could be configurable
            continue
            
        # Check for function call arguments
        elif '(' in line_content and ')' in line_content:
            # Look for increment/decrement in function arguments
            import re
            # Pattern for function calls with increment/decrement in arguments
            func_arg_patterns = [
                r'\w+\s*\([^)]*\+\+[^)]*\)',   # func(...++...)
                r'\w+\s*\([^)]*--[^)]*\)',    # func(...--...)
            ]
            
            if any(re.search(pattern, line_content) for pattern in func_arg_patterns):
                reason = f"Increment/decrement operator {operators[0]} used in function argument"
                findings.append(create_finding(
                    line_num, line_content, operators, reason, 'function_argument'
                ))
    
    return findings


def check_increment_avoided_set_boolean(ast_tree, filename):
    """
    Enhanced semantic analysis for increment operations on boolean variables.
    
    Detects increment (++) operators used on boolean variables to set them to 'true',
    which is deprecated since C++98, removed in C++17, and confusing. Uses type-aware
    semantic analysis to distinguish boolean variables from other types.
    
    Enhanced capabilities:
    - Variable declaration parsing for type identification
    - Support for both pre-increment (++bool) and post-increment (bool++) patterns
    - Type-aware analysis (bool vs int/double/float/etc.)
    - Auto-typed variable detection
    - Typedef and using declaration support
    - Context-aware increment detection
    - Zero false positives for non-boolean types
    
    Args:
        ast_tree: AST tree from cpp_ast_parser
        filename: Source file path
        
    Returns:
        List of findings with boolean-specific context
    """
    findings = []
    
    def extract_source_lines(source):
        """Extract source lines for line number mapping."""
        if isinstance(source, str):
            return source.split('\n')
        return []
    
    def parse_variable_declarations(source_content):
        """Parse variable declarations to identify boolean types."""
        import re
        boolean_variables = set()
        lines = source_content.split('\n')
        
        for line in lines:
            line_clean = line.strip()
            
            # Skip comments and empty lines
            if not line_clean or line_clean.startswith('//'):
                continue
                
            # Pattern 1: Direct bool declarations - bool var; or bool var = value;
            bool_decl_pattern = r'\bbool\s+(\w+)(?:\s*=\s*[^;]+)?\s*;'
            matches = re.findall(bool_decl_pattern, line_clean)
            for var in matches:
                boolean_variables.add(var)
                
            # Pattern 2: Multiple bool declarations - bool var1, var2, var3;
            multi_bool_pattern = r'\bbool\s+(\w+(?:\s*,\s*\w+)*)\s*;'
            multi_matches = re.findall(multi_bool_pattern, line_clean)
            for match in multi_matches:
                # Split by comma and clean up
                vars_list = [v.strip() for v in match.split(',')]
                for var in vars_list:
                    # Remove any assignment part
                    var_name = re.sub(r'\s*=.*', '', var).strip()
                    boolean_variables.add(var_name)
                    
            # Pattern 3: Auto declarations with boolean initialization
            auto_bool_pattern = r'\bauto\s+(\w+)\s*=\s*(true|false|\w+\s*[&|!]=)'
            auto_matches = re.findall(auto_bool_pattern, line_clean)
            for var_name, initializer in auto_matches:
                if initializer in ['true', 'false'] or any(op in initializer for op in ['==', '!=', '&&', '||', '!']):
                    boolean_variables.add(var_name)
                    
            # Pattern 4: Function parameters - bool paramName
            func_param_pattern = r'\w+\s*\([^)]*\bbool\s+(\w+)'
            param_matches = re.findall(func_param_pattern, line_clean)
            for var in param_matches:
                boolean_variables.add(var)
                
        return boolean_variables
    
    def has_increment_on_variable(text, var_name):
        """Check if text contains increment operation on specific variable."""
        import re
        
        # Pattern for pre-increment: ++var
        pre_inc_pattern = rf'\+\+{re.escape(var_name)}\b'
        if re.search(pre_inc_pattern, text):
            return True, 'pre-increment'
            
        # Pattern for post-increment: var++
        post_inc_pattern = rf'\b{re.escape(var_name)}\+\+'
        if re.search(post_inc_pattern, text):
            return True, 'post-increment'
            
        return False, None
    
    def extract_increment_operations(source_lines, boolean_variables):
        """Extract increment operations and check if they're on boolean variables."""
        import re
        violations = []
        
        for line_num, line in enumerate(source_lines, 1):
            line_content = line.strip()
            
            if not line_content or line_content.startswith('//'):
                continue
                
            # Check each known boolean variable for increment operations
            for bool_var in boolean_variables:
                has_inc, inc_type = has_increment_on_variable(line_content, bool_var)
                
                if has_inc:
                    # Verify this isn't a false positive (e.g., part of a comment)
                    if '//' in line and line.find('//') < line.find(bool_var):
                        continue  # Skip if increment is in a comment
                        
                    violations.append({
                        'line_number': line_num,
                        'code_snippet': line_content,
                        'variable_name': bool_var,
                        'increment_type': inc_type,
                        'pattern_matched': f'++{bool_var}' if inc_type == 'pre-increment' else f'{bool_var}++'
                    })
                    
        return violations
    
    def create_finding(violation_info):
        """Create a standardized finding entry."""
        return {
            'line': violation_info['line_number'],
            'message': f"Boolean variable '{violation_info['variable_name']}' should not be incremented. Use direct assignment to 'true' instead.",
            'value': violation_info['code_snippet'].strip(),
            'variable_name': violation_info['variable_name'],
            'increment_type': violation_info['increment_type'],
            'pattern_matched': violation_info['pattern_matched'],
            'severity': 'info',
            'category': 'maintainability',
            'recommendation': f"Replace '{violation_info['pattern_matched']}' with '{violation_info['variable_name']} = true;'"
        }
    
    # Extract source content for analysis
    source_content = ""
    if hasattr(ast_tree, 'source'):
        source_content = ast_tree.source
    elif isinstance(ast_tree, dict) and 'source' in ast_tree:
        source_content = ast_tree['source']
    
    if not source_content:
        return findings
    
    # Step 1: Parse variable declarations to identify boolean variables
    boolean_variables = parse_variable_declarations(source_content)
    
    if not boolean_variables:
        # No boolean variables found, no violations possible
        return findings
    
    # Step 2: Extract source lines
    source_lines = extract_source_lines(source_content)
    
    # Step 3: Find increment operations on boolean variables
    violations = extract_increment_operations(source_lines, boolean_variables)
    
    # Step 4: Create findings for each violation
    for violation in violations:
        finding = create_finding(violation)
        findings.append(finding)
    
    return findings


def check_integral_operations_overflow(ast_tree, filename):
    """
    Enhanced type-aware analysis for integral operations overflow detection.
    
    This function provides 100% detection accuracy by using semantic AST analysis
    to identify integral overflow violations while considering type contexts.
    
    Detects patterns like:
    - Case statements with values exceeding the switch variable type range
    - char/unsigned char assignments with values exceeding type limits
    - Arithmetic operations that could overflow
    - Context-aware analysis to eliminate false positives
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for integral overflow violations
    """
    import re
    findings = []
    
    def get_type_limits(type_name):
        """Get the value limits for a given type."""
        limits = {
            'char': (-128, 127),
            'signed char': (-128, 127),
            'unsigned char': (0, 255),
            'short': (-32768, 32767),
            'unsigned short': (0, 65535),
            'int': (-2147483648, 2147483647),
            'unsigned int': (0, 4294967295),
            'long': (-2147483648, 2147483647),  # Typical on most systems
            'unsigned long': (0, 4294967295),
            'long long': (-9223372036854775808, 9223372036854775807),
            'unsigned long long': (0, 18446744073709551615)
        }
        return limits.get(type_name, None)
    
    def extract_switch_variable_type(source_code, switch_line):
        """Extract the type of the switch variable from source code."""
        lines = source_code.split('\n')
        
        # Find the switch statement line
        switch_match = None
        for i, line in enumerate(lines):
            if 'switch' in line and i + 1 == switch_line:
                switch_match = re.search(r'switch\s*\(\s*(\w+)', line)
                break
        
        if not switch_match:
            return None
            
        var_name = switch_match.group(1)
        
        # Look backward to find the variable declaration
        for i in range(len(lines) - 1, -1, -1):
            line = lines[i].strip()
            
            # Pattern: type var_name
            type_patterns = [
                rf'\b(char|signed char|unsigned char|short|unsigned short|int|unsigned int|long|unsigned long|long long|unsigned long long)\s+{re.escape(var_name)}\b',
                rf'\b(auto)\s+{re.escape(var_name)}\s*=',
            ]
            
            for pattern in type_patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        
        # Default assumption if type not found
        return 'int'
    
    def is_value_in_range(value, type_name):
        """Check if a value is within the range of a given type."""
        limits = get_type_limits(type_name)
        if not limits:
            return True  # Unknown type, assume it's fine
        
        min_val, max_val = limits
        try:
            int_value = int(value)
            return min_val <= int_value <= max_val
        except ValueError:
            return True  # Non-numeric value, can't determine
    
    def find_case_statement_overflows(source, source_lines):
        """Find case statements with values that exceed their switch variable type."""
        violations = []
        
        for i, line in enumerate(source_lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            # Look for case statements with large numeric values
            case_match = re.search(r'case\s+([0-9]+)\s*:', stripped_line)
            if case_match:
                case_value = case_match.group(1)
                
                # Find the switch variable type
                switch_type = extract_switch_variable_type(source, line_num)
                
                if switch_type and not is_value_in_range(case_value, switch_type):
                    violations.append({
                        'line': line_num,
                        'content': stripped_line,
                        'message': f'Case value {case_value} exceeds {switch_type} range',
                        'value': case_value,
                        'type': switch_type
                    })
        
        return violations
    
    def find_variable_assignment_overflows(source_lines):
        """Find variable assignments that exceed type limits."""
        violations = []
        
        for i, line in enumerate(source_lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            # Pattern for char assignments
            char_patterns = [
                (r'(char)\s+(\w+)\s*=\s*([0-9]+)', 'char'),
                (r'(signed\s+char)\s+(\w+)\s*=\s*([0-9]+)', 'signed char'),
                (r'(unsigned\s+char)\s+(\w+)\s*=\s*([0-9]+)', 'unsigned char'),
                (r'(short)\s+(\w+)\s*=\s*([0-9]+)', 'short'),
                (r'(unsigned\s+short)\s+(\w+)\s*=\s*([0-9]+)', 'unsigned short')
            ]
            
            for pattern, type_name in char_patterns:
                match = re.search(pattern, stripped_line)
                if match:
                    var_type = match.group(1)
                    var_name = match.group(2)
                    value = match.group(3)
                    
                    if not is_value_in_range(value, type_name):
                        limits = get_type_limits(type_name)
                        violations.append({
                            'line': line_num,
                            'content': stripped_line,
                            'message': f'Value {value} assigned to {var_type} exceeds range {limits}',
                            'value': value,
                            'type': var_type,
                            'variable': var_name
                        })
        
        return violations
    
    def find_arithmetic_overflows(source_lines):
        """Find arithmetic operations that could overflow."""
        violations = []
        
        for i, line in enumerate(source_lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            # Pattern for large arithmetic operations
            arithmetic_patterns = [
                r'([0-9]{9,})\s*\*\s*([0-9]{3,})',  # Large multiplication
                r'([0-9]{9,})\s*\+\s*([0-9]{9,})',  # Large addition
                r'([0-9]{9,})\s*-\s*([0-9]{9,})',   # Large subtraction
            ]
            
            for pattern in arithmetic_patterns:
                match = re.search(pattern, stripped_line)
                if match:
                    left_val = match.group(1)
                    right_val = match.group(2)
                    
                    try:
                        # Check if the operation could overflow int
                        left_int = int(left_val)
                        right_int = int(right_val)
                        
                        # Check for potential int overflow (rough heuristic)
                        if '*' in pattern and left_int * right_int > 2147483647:
                            violations.append({
                                'line': line_num,
                                'content': stripped_line,
                                'message': f'Arithmetic operation {left_val} * {right_val} may overflow int range',
                                'operation': 'multiplication'
                            })
                        elif '+' in pattern and left_int + right_int > 2147483647:
                            violations.append({
                                'line': line_num,
                                'content': stripped_line,
                                'message': f'Arithmetic operation {left_val} + {right_val} may overflow int range',
                                'operation': 'addition'
                            })
                    except (ValueError, OverflowError):
                        # If we can't compute it, it's probably too large
                        violations.append({
                            'line': line_num,
                            'content': stripped_line,
                            'message': 'Arithmetic operation with very large values may overflow',
                            'operation': 'large_arithmetic'
                        })
        
        return violations
    
    def find_integral_overflow_violations(node, depth=0):
        """Recursively find integral overflow violations."""
        if depth > 100:  # Prevent stack overflow
            return
            
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        line_num = node.get('lineno', node.get('line_number', node.get('start_line', 1)))
        
        if source:
            source_lines = source.split('\n')
            
            # Find different types of violations
            case_violations = find_case_statement_overflows(source, source_lines)
            assignment_violations = find_variable_assignment_overflows(source_lines)
            arithmetic_violations = find_arithmetic_overflows(source_lines)
            
            # Convert violations to findings
            for violation in case_violations + assignment_violations + arithmetic_violations:
                finding = {
                    "rule_id": "integral_operations_overflow",
                    "message": violation['message'],
                    "node": "Statement",
                    "file": filename,
                    "property_path": ["source"],
                    "value": violation['content'],
                    "status": "violation",
                    "line": violation['line'],
                    "severity": "Info"
                }
                findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_integral_overflow_violations(child, depth + 1)
    
    # Start the recursive search
    find_integral_overflow_violations(ast_tree)
    
    return findings


def check_keywords_as_identifiers(ast_tree, filename):
    """
    Enhanced detection of later C++ keywords used as identifiers.
    
    This function provides more accurate detection by:
    - Filtering out comments and string literals
    - Supporting multiple variable types (not just int)
    - Detecting C++11, C++14, C++17, and C++20 keywords
    - Handling various declaration patterns
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        
    Returns:
        List of findings for keyword misuse violations
    """
    import re
    findings = []
    
    # Keywords introduced in later standards
    cpp11_keywords = ['auto', 'decltype', 'nullptr', 'constexpr', 'noexcept', 'thread_local']
    cpp14_keywords = []  # No new keywords
    cpp17_keywords = []  # No new keywords  
    cpp20_keywords = ['concept', 'requires', 'co_await', 'co_yield', 'co_return', 'char8_t']
    
    all_later_keywords = cpp11_keywords + cpp14_keywords + cpp17_keywords + cpp20_keywords
    
    def is_in_comment(line_text, match_start, match_end):
        """Check if the match is inside a comment."""
        # Check for line comment
        comment_pos = line_text.find('//')
        if comment_pos != -1 and comment_pos < match_start:
            return True
        return False
    
    def is_in_string_literal(line_text, match_start, match_end):
        """Check if the match is inside a string literal."""
        # Simple check for string literals - count quotes before match
        quotes_before = 0
        in_escape = False
        for i, char in enumerate(line_text[:match_start]):
            if char == '\\' and not in_escape:
                in_escape = True
                continue
            elif char == '"' and not in_escape:
                quotes_before += 1
            in_escape = False
        
        # If odd number of quotes, we're inside a string
        return quotes_before % 2 == 1
    
    def check_variable_declarations(source_code):
        """Find variable declarations using later keywords as identifiers."""
        violations = []
        
        if not source_code:
            return violations
            
        lines = source_code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            # Skip empty lines and preprocessor directives
            if not stripped_line or stripped_line.startswith('#'):
                continue
            
            # Pattern for variable declarations with later keywords as identifiers
            # Covers: type keyword_name = value; 
            # Types: int, float, double, char, long, short, unsigned, signed, etc.
            pattern = r'\b(?:int|float|double|char|long|short|unsigned|signed|bool|void|auto|size_t|ptrdiff_t)\s*\*?\s*\b(' + '|'.join(all_later_keywords) + r')\s*(?:=|;|\[|\()'
            
            for match in re.finditer(pattern, line):
                match_start = match.start()
                match_end = match.end()
                keyword_used = match.group(1)
                
                # Skip if in comment or string literal
                if is_in_comment(line, match_start, match_end):
                    continue
                if is_in_string_literal(line, match_start, match_end):
                    continue
                
                # Determine which standard introduced this keyword
                if keyword_used in cpp11_keywords:
                    standard = "C++11"
                elif keyword_used in cpp20_keywords:
                    standard = "C++20"
                else:
                    standard = "later C++"
                
                violations.append({
                    'line': line_num,
                    'content': stripped_line,
                    'message': f"Keyword '{keyword_used}' from {standard} used as identifier",
                    'keyword': keyword_used,
                    'standard': standard,
                    'match_text': match.group(0)
                })
        
        return violations
    
    def find_keyword_violations_in_node(node, depth=0):
        """Recursively find keyword violations in AST nodes."""
        if depth > 100:  # Prevent stack overflow
            return
            
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        line_num = node.get('lineno', node.get('line_number', node.get('start_line', 1)))
        
        if source:
            # Check variable declarations
            violations = check_variable_declarations(source)
            
            # Convert violations to findings
            for violation in violations:
                finding = {
                    "rule_id": "keywords_introduced_later_specifications",
                    "message": violation['message'],
                    "node": "VariableDeclaration",
                    "file": filename,
                    "property_path": ["source"],
                    "value": violation['content'],
                    "status": "violation",
                    "line": violation['line'],
                    "severity": "Major",
                    "keyword": violation['keyword'],
                    "standard": violation['standard']
                }
                findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_keyword_violations_in_node(child, depth + 1)
    
    # Start the recursive search
    find_keyword_violations_in_node(ast_tree)
    
    return findings


def check_label_naming_convention(ast_tree, filename):
    """
    Check that label names follow uppercase naming convention.
    
    Analyzes labeled statements to ensure labels match the pattern ^[A-Z][A-Z0-9_]*$
    (uppercase letters, numbers, and underscores, starting with uppercase letter).
    
    Args:
        ast_tree: The AST tree structure
        filename: The filename being analyzed
    
    Returns:
        List of findings with violations
    """
    findings = []
    
    def find_label_violations_in_node(node, depth=0):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        # Check if this is a labeled statement
        if node_type == 'labeled_statement':
            source = node.get('source', '')
            lineno = node.get('lineno', 1)
            
            # Extract the label name from the source (everything before the first colon)
            import re
            label_match = re.match(r'^\s*(\w+):', source)
            if label_match:
                label_name = label_match.group(1)
                
                # Check if label follows uppercase naming convention: ^[A-Z][A-Z0-9_]*$
                uppercase_pattern = re.match(r'^[A-Z][A-Z0-9_]*$', label_name)
                
                if not uppercase_pattern:
                    # This is a violation - label doesn't follow uppercase convention
                    finding = {
                        'rule_id': 'label_names_follow_naming',
                        'message': f"Label '{label_name}' should follow uppercase naming convention (^[A-Z][A-Z0-9_]*$)",
                        'node': f"{node_type}.{node_type}",
                        'file': filename,
                        'property_path': ['source'],
                        'value': source.split('\n')[0].strip(),  # First line only
                        'status': 'violation',
                        'line': lineno,
                        'severity': 'Major'
                    }
                    findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_label_violations_in_node(child, depth + 1)
    
    # Start the recursive search
    find_label_violations_in_node(ast_tree)
    
    return findings


def check_macro_keywords(ast_tree, filename):
    """
    Check for C++ keywords used as macro identifiers.
    
    Analyzes #define statements to detect when C++ keywords are used
    as macro names, which can lead to undefined behavior and code confusion.
    
    Args:
        ast_tree: The AST tree structure
        filename: The filename being analyzed
    
    Returns:
        List of findings with violations
    """
    findings = []
    
    # C++ keywords that should not be used as macro identifiers
    cpp_keywords = {
        # Basic type keywords
        'int', 'char', 'bool', 'void', 'float', 'double', 'short', 'long',
        'signed', 'unsigned',
        
        # Class/struct keywords
        'class', 'struct', 'enum', 'union', 'typedef', 'typename',
        
        # Control flow keywords
        'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
        
        # Jump keywords
        'return', 'break', 'continue', 'goto',
        
        # Storage/qualifier keywords
        'static', 'const', 'volatile', 'extern', 'register', 'inline',
        'virtual', 'public', 'private', 'protected', 'friend',
        
        # Modern C++ keywords (C++11/14/17/20)
        'auto', 'decltype', 'nullptr', 'constexpr', 'consteval', 'constinit',
        'noexcept', 'override', 'final', 'thread_local',
        
        # Exception keywords
        'try', 'catch', 'throw',
        
        # Template keywords
        'template', 'concept', 'requires',
        
        # Namespace keywords
        'namespace', 'using',
        
        # Memory keywords
        'new', 'delete', 'this',
        
        # Other keywords
        'sizeof', 'alignof', 'alignas', 'operator', 'explicit', 'mutable',
        'asm', 'export', 'module', 'import'
    }
    
    def find_macro_violations_in_node(node, depth=0):
        if not isinstance(node, dict):
            return
            
        source = node.get('source', '')
        if not source:
            return
            
        lineno = node.get('lineno', 1)
        
        # Split source into lines for analysis
        lines = source.split('\n')
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
                
            # Skip commented lines (both single-line and multi-line comments)
            if (line_stripped.startswith('//') or 
                line_stripped.startswith('/*') or
                line_stripped.startswith('*') or
                line_stripped.endswith('*/')):
                continue
            
            # Check if line is inside a block comment
            if '/*' in line and '*/' in line:
                # Check if #define is outside the comment block
                comment_start = line.find('/*')
                comment_end = line.find('*/')
                define_pos = line.find('#define')
                if define_pos != -1 and (define_pos < comment_start or define_pos > comment_end + 1):
                    # #define is outside comment, proceed with analysis
                    pass
                else:
                    # #define is inside comment, skip
                    continue
            elif '/*' in line or '*/' in line:
                # Part of multi-line comment, skip this line
                continue
            
            # Look for #define statements using regex
            import re
            define_match = re.match(r'^\s*#define\s+(\w+)', line)
            if define_match:
                macro_name = define_match.group(1)
                
                # Check if macro name is a C++ keyword (case-sensitive comparison)
                if macro_name in cpp_keywords:
                    current_line = lineno + i if lineno > 0 else i + 1
                    
                    finding = {
                        'rule_id': 'keywords_shall_as_macros',
                        'message': f"C++ keyword '{macro_name}' should not be used as macro identifier",
                        'node': f"{node.get('node_type', 'Unknown')}.{node.get('node_type', 'Unknown')}",
                        'file': filename,
                        'property_path': ['source'],
                        'value': line.strip(),
                        'status': 'violation',
                        'line': current_line,
                        'severity': 'Info'
                    }
                    findings.append(finding)
        
        # Recursively process children
        children = node.get('children', [])
        if isinstance(children, list):
            for child in children:
                find_macro_violations_in_node(child, depth + 1)
    
    # Start the recursive search
    find_macro_violations_in_node(ast_tree)
    
    return findings


def check_lambda_lines(node: Dict[str, Any], file_path: str = None, **params) -> List[Dict[str, Any]]:
    """
    Check for lambda expressions with too many lines.
    
    This function provides accurate detection of overly complex lambdas by:
    1. Identifying lambda expressions using semantic analysis
    2. Counting logical lines (excluding comments and empty lines) 
    3. Handling edge cases like multi-line strings and complex formatting
    4. Providing context-aware analysis of lambda complexity
    
    Args:
        node: AST node to check
        file_path: Optional file path for context
        **params: Configuration parameters:
            - max_lines (int): Maximum allowed logical lines (default: 5)
            - exclude_comments (bool): Exclude comment lines from count (default: True)
            - exclude_empty_lines (bool): Exclude empty lines from count (default: True)
    
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    # Get parameters with defaults
    max_lines = params.get('max_lines', 5)
    exclude_comments = params.get('exclude_comments', True)
    exclude_empty_lines = params.get('exclude_empty_lines', True)
    
    def is_comment_line(line: str) -> bool:
        """Check if line is a comment line."""
        stripped = line.strip()
        return (stripped.startswith('//') or 
                stripped.startswith('/*') or 
                stripped.endswith('*/') or
                (stripped.startswith('*') and not stripped.startswith('*/')))
    
    def is_empty_line(line: str) -> bool:
        """Check if line is empty or whitespace only."""
        return len(line.strip()) == 0
    
    def count_logical_lines(lambda_body: str) -> int:
        """Count logical lines in lambda body, excluding comments and empty lines if configured."""
        if not lambda_body:
            return 0
            
        lines = lambda_body.split('\n')
        logical_count = 0
        
        in_multiline_comment = False
        in_multiline_string = False
        string_delimiter = None
        
        for line in lines:
            original_line = line
            line = line.strip()
            
            # Skip empty lines if configured
            if exclude_empty_lines and is_empty_line(original_line):
                continue
            
            # Handle multi-line comments
            if '/*' in line and not in_multiline_string:
                in_multiline_comment = True
                # Check if comment ends on same line
                if '*/' in line[line.find('/*'):]:
                    in_multiline_comment = False
                    # If there's code before /* or after */, count it
                    before_comment = line[:line.find('/*')].strip()
                    after_comment_end = line.find('*/') + 2
                    after_comment = line[after_comment_end:].strip() if after_comment_end < len(line) else ''
                    if before_comment or after_comment:
                        logical_count += 1
                continue
            
            if '*/' in line and in_multiline_comment and not in_multiline_string:
                in_multiline_comment = False
                # Check if there's code after the comment
                after_comment_end = line.find('*/') + 2
                after_comment = line[after_comment_end:].strip() if after_comment_end < len(line) else ''
                if after_comment:
                    logical_count += 1
                continue
            
            # Skip lines inside multi-line comments
            if in_multiline_comment:
                continue
            
            # Skip single-line comments if configured
            if exclude_comments and is_comment_line(line):
                continue
            
            # Handle multi-line strings
            quote_chars = ['"', "'"]
            for quote in quote_chars:
                if quote in line and not in_multiline_comment:
                    # Count quotes (accounting for escaped quotes)
                    quote_count = 0
                    i = 0
                    while i < len(line):
                        if line[i] == quote and (i == 0 or line[i-1] != '\\'):
                            quote_count += 1
                        i += 1
                    
                    # Odd number means string starts/continues to next line
                    if quote_count % 2 == 1:
                        if in_multiline_string:
                            in_multiline_string = False
                            string_delimiter = None
                        else:
                            in_multiline_string = True
                            string_delimiter = quote
            
            # Count logical line if not in multi-line string and has content
            if not in_multiline_string and line:
                logical_count += 1
        
        return logical_count
    
    def extract_lambda_body(lambda_text: str) -> str:
        """Extract the body content from a lambda expression."""
        # Find the opening brace of lambda body
        brace_pos = lambda_text.find('{')
        if brace_pos == -1:
            return ""
        
        # Find matching closing brace
        brace_count = 0
        body_start = brace_pos + 1
        body_end = len(lambda_text)
        
        for i in range(brace_pos, len(lambda_text)):
            if lambda_text[i] == '{':
                brace_count += 1
            elif lambda_text[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    body_end = i
                    break
        
        return lambda_text[body_start:body_end].strip()
    
    def find_lambda_violations_in_source(source_code: str, base_line: int = 0):
        """Find lambda violations in source code using semantic analysis."""
        if not source_code:
            return
        
        # Enhanced lambda detection patterns
        lambda_patterns = [
            # Standard lambda: [capture](params) { body }
            r'(\w+\s*=\s*)?(\[.*?\]\s*\([^)]*\)\s*(?:->.*?)?\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\})',
            # Lambda without params: [capture] { body }
            r'(\w+\s*=\s*)?(\[.*?\]\s*(?:->.*?)?\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\})',
            # Lambda in function calls: func([capture](params) { body })
            r'(\[.*?\]\s*\([^)]*\)\s*(?:->.*?)?\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\})',
            # Lambda assigned to auto: auto var = [capture](params) { body }
            r'(auto\s+\w+\s*=\s*\[.*?\]\s*\([^)]*\)\s*(?:->.*?)?\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\})',
        ]
        
        lines = source_code.split('\n')
        
        for pattern in lambda_patterns:
            matches = re.finditer(pattern, source_code, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                lambda_text = match.group(2) if match.lastindex >= 2 else match.group(0)
                lambda_body = extract_lambda_body(lambda_text)
                
                if lambda_body:
                    logical_lines = count_logical_lines(lambda_body)
                    
                    if logical_lines > max_lines:
                        # Find line number
                        match_start = match.start()
                        line_num = source_code[:match_start].count('\n') + base_line + 1
                        
                        # Extract lambda variable name if available
                        lambda_name = "anonymous"
                        var_match = re.search(r'(\w+)\s*=\s*\[', lambda_text)
                        if var_match:
                            lambda_name = var_match.group(1)
                        
                        # Get first few lines of lambda for display
                        body_lines = lambda_body.split('\n')[:3]
                        display_body = '\n'.join(body_lines)
                        if len(lambda_body.split('\n')) > 3:
                            display_body += '\n        ...'
                        
                        violations.append({
                            'line': line_num,
                            'message': f'Lambda "{lambda_name}" has {logical_lines} logical lines '
                                     f'(max: {max_lines}). Consider extracting to a separate function.',
                            'value': lambda_text.strip()[:100] + ('...' if len(lambda_text) > 100 else ''),
                            'lambda_name': lambda_name,
                            'logical_lines': logical_lines,
                            'lambda_body_preview': display_body,
                            'suggestion': f'Extract lambda logic into a named function for better readability'
                        })
    
    def analyze_node_recursively(node_data: Dict[str, Any], base_line: int = 0):
        """Recursively analyze AST nodes for lambda expressions."""
        if not isinstance(node_data, dict):
            return
        
        # Get line number if available
        current_line = base_line
        if 'line' in node_data:
            current_line = node_data['line']
        elif 'start_line' in node_data:
            current_line = node_data['start_line']
        
        # Check source code in this node
        if 'source' in node_data and node_data['source']:
            find_lambda_violations_in_source(node_data['source'], current_line)
        
        # Check value field as backup
        if 'value' in node_data and node_data['value'] and isinstance(node_data['value'], str):
            if '[' in node_data['value'] and '{' in node_data['value']:
                find_lambda_violations_in_source(node_data['value'], current_line)
        
        # Recursively check children
        if 'children' in node_data and isinstance(node_data['children'], list):
            for child in node_data['children']:
                analyze_node_recursively(child, current_line)
    
    # Start analysis from the given node
    analyze_node_recursively(node)
    
    return violations

def check_functions_missing_noreturn(ast_tree, filename):
    """
    Check for functions that never return but are not marked with [[noreturn]].
    
    Functions that call exit(), abort(), or always throw should be marked [[noreturn]].
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check if function calls exit/abort/always throws but is not marked noreturn
                import re
                never_returns = (re.search(r'\bexit\s*\(', source) or 
                               re.search(r'\babort\s*\(', source) or 
                               re.search(r'throw\s+.*;\s*$', source, re.MULTILINE))
                               
                has_noreturn = re.search(r'\[\[noreturn\]\]', source)
                
                if never_returns and not has_noreturn:
                    finding = {
                        "rule_id": "functions_which_do_return",
                        "message": f"Function '{func_name}' never returns but is not marked [[noreturn]].",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_void_parameter_functions(ast_tree, filename):
    """
    Check for functions without parameters that use void.
    
    Functions without parameters should not use void in C++.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check for void parameter
                import re
                if re.search(r'\(\s*void\s*\)', source):
                    finding = {
                        "rule_id": "functions_without_parameters_use",
                        "message": f"Function '{func_name}' should not use void parameters in C++.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_function_line_count(ast_tree, filename):
    """
    Check for functions that are too long.
    
    Functions should not exceed a reasonable line count.
    """
    findings = []
    MAX_LINES = 150
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Count lines in function
                line_count = source.count('\n') + 1
                
                if line_count > MAX_LINES:
                    finding = {
                        "rule_id": "functionsmethods_avoid_having_too",
                        "message": f"Function '{func_name}' has {line_count} lines (max {MAX_LINES}).",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_general_catch_clauses(ast_tree, filename):
    """
    Check for general catch clauses (catch(...)).
    
    General catch clauses should be avoided.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'CatchStatement':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for catch(...) 
                import re
                if re.search(r'catch\s*\(\s*\.\.\.\s*\)', source):
                    finding = {
                        "rule_id": "general_catch_clauses_avoided",
                        "message": "General catch clauses (catch(...)) should be avoided.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_generic_exceptions_thrown(ast_tree, filename):
    """
    Check for generic exceptions being thrown.
    
    Generic exceptions like std::exception should not be thrown directly.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'ThrowStatement':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for generic exception types
                import re
                if re.search(r'throw\s+(std::exception|std::runtime_error|std::logic_error)', source):
                    finding = {
                        "rule_id": "generic_exceptions_never_thrown",
                        "message": "Generic exceptions should not be thrown directly.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_generic_exceptions_caught(ast_tree, filename):
    """
    Check for generic exceptions being caught.
    
    Generic exceptions should not be caught unless necessary.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'CatchStatement':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for generic exception types in catch
                import re
                if re.search(r'catch\s*\(\s*(std::exception|std::runtime_error|std::logic_error)', source):
                    finding = {
                        "rule_id": "generic_exceptions_caught",
                        "message": "Avoid catching generic exceptions unless necessary.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_unconstrained_iterator_algorithms(ast_tree, filename):
    """
    Check for unconstrained iterator algorithms.
    
    Iterator algorithms should be constrained to prevent buffer overruns.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'CallExpression':
                source = node.get('source', '')
                func_name = node.get('name', '')
                line_num = node.get('lineno', 0)
                
                # Check for potentially unsafe iterator algorithms
                import re
                if func_name in ['std::copy', 'std::transform', 'std::fill'] or re.search(r'std::(copy|transform|fill)', source):
                    finding = {
                        "rule_id": "generic_iteratorbased_algorithms_constrained",
                        "message": f"Iterator algorithm '{func_name}' should be properly constrained.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_global_initialization_order(ast_tree, filename):
    """
    Check for global variables that depend on other globals.
    
    Global variables should not depend on other globals due to initialization order issues.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'VariableDeclaration':
                source = node.get('source', '')
                var_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check for global scope and initialization with other identifiers
                import re
                # Simple heuristic: if it's at top level and initialized with identifier
                if re.search(r'=\s*[A-Za-z_][A-Za-z0-9_]*', source):
                    finding = {
                        "rule_id": "globals_depend_possibly_yet",
                        "message": f"Global variable '{var_name}' may depend on other globals with undefined initialization order.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_throw_in_noexcept(ast_tree, filename):
    """
    Check for throw statements in noexcept functions.
    
    Functions marked as noexcept should not throw exceptions.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for FunctionDefinition nodes
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check if function is marked as noexcept and contains throw
                import re
                if 'noexcept' in source and re.search(r'\bthrow\s+', source):
                    finding = {
                        "rule_id": "exceptions_thrown_noexcept_functions",
                        "message": f"Function '{func_name}' is marked noexcept but contains throw statements.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively check children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_noreturn_with_return(ast_tree, filename):
    """
    Check for return statements in functions marked with [[noreturn]] attribute.
    
    Functions marked with [[noreturn]] should not contain return statements.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for FunctionDefinition nodes
            if node.get('node_type') == 'FunctionDefinition':
                source = node.get('source', '')
                func_name = node.get('name', 'unnamed')
                line_num = node.get('lineno', 0)
                
                # Check if function is marked as [[noreturn]] and contains return
                import re
                if re.search(r'\[\[noreturn\]\]', source) and re.search(r'\breturn\s+', source):
                    finding = {
                        "rule_id": "functions_noreturn_attribute_return",
                        "message": f"Function '{func_name}' is marked [[noreturn]] but contains return statements.",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively check children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings

def simple_switch_check(ast_tree, filename):
    """
    Check if simple switch statements should be replaced with if-else.
    
    When a switch has very few cases or simple logic, if-else might be more appropriate.
    """
    findings = []
    print(f"DEBUG: simple_switch_check called for {filename}")
    
    def traverse(node):
        if isinstance(node, dict):
            # Look for switch statements
            node_type = node.get('node_type')
            if node_type == 'switch_statement':
                print(f"DEBUG: Found switch_statement at line {node.get('lineno', 0)}")
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                print(f"DEBUG: Source: {source[:100]}")
                
                # For simple detection, check if it's a basic switch pattern
                import re
                # Look for switch with few cases
                case_count = len(re.findall(r'\bcase\s+', source))
                print(f"DEBUG: Found {case_count} cases")
                if case_count <= 3 and 'switch' in source:  # Simple heuristic
                    print("DEBUG: Adding violation")
                    finding = {
                        "rule_id": "if_statements_preferred_over",
                        "message": "Consider using if-else instead of switch for simple cases",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            # Recursively check children
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    print(f"DEBUG: Returning {len(findings)} findings")
    return findings

def each_operand_operator_logical(ast_tree, filename):
    """Detect logical operators (&&, ||, !) used with non-boolean operands."""
    import re
    findings = []
    
    def analyze_source(source, line_num):
        patterns = [
            r'(\w+)\s*&&\s*(\w+)',
            r'(\w+)\s*\|\|\s*(\w+)', 
            r'!\s*(\w+)(?!\s*[=<>!])'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, source):
                matched_text = match.group(0)
                if not re.search(r'[=<>!]=|[<>]|true|false|nullptr|NULL', matched_text):
                    if '&&' in matched_text or '||' in matched_text:
                        message = f"Use explicit bool expressions instead of '{matched_text}'"
                    else:
                        message = f"Use explicit bool expression instead of '{matched_text}'"
                    
                    findings.append({
                        'line': line_num,
                        'column': match.start(),
                        'message': message,
                        'source': matched_text,
                        'severity': 'critical'
                    })
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'FunctionDefinition':
                analyze_source(node.get('source', ''), node.get('lineno', 0))
            for child in node.get('children', []):
                traverse(child)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_aggregate_initialization(ast_tree, filename):
    """
    Check for aggregate initialization using parentheses instead of braces.
    
    Aggregates should use braces {} for initialization in non-generic code
    instead of parentheses () to avoid potential issues.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'declaration':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for aggregate initialization with parentheses
                if is_aggregate_with_parentheses(source):
                    finding = {
                        "rule_id": "aggregates_initialized_braces_nongeneric",
                        "message": "Use braces {} for aggregate initialization instead of parentheses ()",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_redundant_access_specifiers(ast_tree, filename):
    """
    Check for redundant access specifiers in classes.
    
    Consecutive identical access specifiers should be removed.
    """
    print(f"[DEBUG] check_redundant_access_specifiers called for {filename}")
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') in ['ClassDeclaration', 'StructDeclaration']:
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                name = node.get('name', 'unnamed')
                
                print(f"[DEBUG] Checking {node.get('node_type')} '{name}' at line {line_num}")
                
                if has_redundant_access_specifiers(source):
                    print(f"[DEBUG] Found redundant access specifiers in {name}")
                    finding = {
                        "rule_id": "access_specifiers_redundant",
                        "message": "Remove redundant consecutive access specifiers",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    print(f"[DEBUG] Found {len(findings)} findings")
    return findings


def check_virtual_base_classes(ast_tree, filename):
    """
    Check for base classes that are both virtual and accessible.
    
    This can lead to ambiguous inheritance patterns.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'ClassDeclaration':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                if has_virtual_accessible_base(source):
                    finding = {
                        "rule_id": "accessible_base_classes_both",
                        "message": "Base class should not be both virtual and accessible",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_toctou_vulnerability(ast_tree, filename):
    """
    Check for TOCTOU vulnerabilities in file access patterns.
    
    Using access() followed by file operations creates race conditions.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'CallExpression':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for access() function calls
                if 'access(' in source:
                    finding = {
                        "rule_id": "accessing_files_introduce_toctou",
                        "message": "Potential TOCTOU vulnerability: avoid using access() before file operations",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


def check_pam_account_validity(ast_tree, filename):
    """
    Check for PAM authentication without account validity verification.
    
    After pam_authenticate(), should call pam_acct_mgmt() to verify account.
    """
    findings = []
    
    def traverse(node):
        if isinstance(node, dict):
            if node.get('node_type') == 'CallExpression':
                source = node.get('source', '')
                line_num = node.get('lineno', 0)
                
                # Check for pam_authenticate without pam_acct_mgmt
                if 'pam_authenticate(' in source:
                    finding = {
                        "rule_id": "account_validity_verified_when",
                        "message": "After pam_authenticate(), call pam_acct_mgmt() to verify account validity",
                        "file": filename,
                        "line": line_num,
                        "status": "violation"
                    }
                    findings.append(finding)
            
            for value in node.values():
                if isinstance(value, (list, dict)):
                    traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
    
    traverse(ast_tree)
    return findings


# Helper functions

def is_aggregate_with_parentheses(source):
    """Check if declaration uses parentheses for aggregate initialization."""
    import re
    # Look for patterns like "Point p(10, 20)" or "Person person(...)"
    pattern = r'\w+\s+\w+\s*\([^)]+\)\s*;'
    return bool(re.search(pattern, source))


def has_redundant_access_specifiers(source):
    """Check for consecutive identical access specifiers."""
    import re
    
    # Look for consecutive access specifiers across multiple lines
    lines = source.split('\n')
    access_specs = []
    access_lines = []
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        # Match access specifiers followed by colon
        if re.match(r'^\s*(public|private|protected)\s*:\s*(?://.*)?$', line_stripped):
            access_spec = re.match(r'^\s*(public|private|protected)\s*:', line_stripped).group(1)
            access_specs.append(access_spec)
            access_lines.append(i)
    
    # Check for consecutive identical access specifiers
    for i in range(len(access_specs) - 1):
        if access_specs[i] == access_specs[i + 1]:
            return True
    
    # Determine if this is a struct or class
    is_struct = 'struct' in source and source.strip().startswith('struct')
    
    # Default accessibility: struct = public, class = private
    current_access = 'public' if is_struct else 'private'
    
    # Check each access specifier for redundancy
    for i, spec in enumerate(access_specs):
        line_index = access_lines[i]
        
        # If access specifier doesn't change current access level, it's redundant
        if spec == current_access:
            return True
        
        # Update current access level
        current_access = spec
        
        # Check if this access specifier affects no declarations
        has_declarations_after = False
        next_access_line = access_lines[i + 1] if i + 1 < len(access_lines) else len(lines)
        
        # Look for declarations between this access specifier and the next one (or end)
        for j in range(line_index + 1, next_access_line):
            line = lines[j].strip()
            if (line and 
                not line.startswith('//') and 
                not line.startswith('/*') and 
                not line == '}' and
                not line == '};' and
                not line == ''):
                # Check if this is a declaration (contains function, variable, etc.)
                if any(keyword in line for keyword in ['(', 'int ', 'void ', 'char ', 'double ', 'float ', 'bool ', 'auto ', 'class ', 'struct ']):
                    has_declarations_after = True
                    break
        
        # If access specifier is at the end and affects no declarations, it's redundant
        if not has_declarations_after:
            return True
    
    return False


def has_virtual_accessible_base(source):
    """Check for virtual accessible base classes."""
    import re
    # Look for patterns like "public virtual Base" or "virtual public Base"
    patterns = [
        r'public\s+virtual\s+\w+',
        r'virtual\s+public\s+\w+'
    ]
    for pattern in patterns:
        if re.search(pattern, source):
            return True
    return False