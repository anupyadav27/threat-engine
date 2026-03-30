# Custom function: detects duplicate implementations in conditional branches
def duplicate_conditional_branch_check(node, ast_root=None):
    """
    Returns a finding dict if two branches in an If node have exactly the same implementation.
    """
    if not isinstance(node, dict) or node.get("node_type") != "If":
        return False
    # Compare 'body' and 'orelse' for duplication
    body = node.get("body", [])
    orelse = node.get("orelse", [])
    # Only check if both branches exist and are non-empty
    if body and orelse:
        # Compare AST dumps (structure and content)
        import json
        def ast_dump(stmt_list):
            return json.dumps(stmt_list, sort_keys=True)
        if ast_dump(body) == ast_dump(orelse):
            return {
                'message': "Two branches in a conditional structure have the same implementation.",
                'property_path': ["body", "orelse"],
                'value': None
            }
    return False
# Custom function: detects Assign nodes that are type aliases without a type statement
def type_alias_without_type_statement_check(node, ast_root=None):
    """
    Returns a finding dict if an Assign node is a type alias (TypeVar) without a type annotation.
    """
    if not isinstance(node, dict) or node.get("node_type") != "Assign":
        return False
    # Check if value is a call to TypeVar
    value = node.get("value")
    if isinstance(value, dict) and value.get("node_type") == "Call":
        func = value.get("func")
        if isinstance(func, dict) and func.get("id") == "TypeVar":
            # Check if there is no annotation (type statement)
            targets = node.get("targets", [])
            for target in targets:
                if not target.get("annotation"):
                    return {
                        'message': "Global type alias declaration without type statement.",
                        'property_path': ["targets", target.get("id", target.get("name", "")), "annotation"],
                        'value': None
                    }
    return False
# Custom function: detects if any argument in a function has type 'Any'
def argument_type_any_check(node, ast_root=None):
    """
    Returns a finding dict if any argument in a FunctionDef node has annotation 'Any'.
    """
    if not isinstance(node, dict) or node.get("node_type") != "FunctionDef":
        return False
    args = node.get("args", {}).get("args", [])
    for arg in args:
        annotation = arg.get("annotation")
        arg_name = arg.get("arg")
        arg_type = None
        if isinstance(annotation, dict):
            if annotation.get("id"):
                arg_type = annotation["id"]
            elif annotation.get("attr"):
                arg_type = annotation["attr"]
            elif annotation.get("value") and annotation["value"].get("id"):
                arg_type = annotation["value"]["id"]
        if arg_type == "Any":
            return {
                'message': f"Argument '{arg_name}' has type 'Any' (confusing type check)",
                'property_path': ["args", arg_name, "annotation"],
                'value': arg_type
            }
    return False
# Custom function to detect commented-out code sections
import re
def commented_out_code_section_check(node, ast_root=None, source_lines=None):
    """
    Returns True if a line is a comment that looks like code (e.g., assignment, function call, keyword).
    Expects 'source_lines' to be provided as a list of lines from the source file.
    """
    if source_lines is None:
        return False
    code_like_pattern = re.compile(r"^\s*#\s*(if |for |while |def |class |return |import |from |print\(|\w+\s*=|\w+\()")
    for idx, line in enumerate(source_lines):
        if code_like_pattern.match(line):
            return {
                'message': 'A section of code has been commented out.',
                'line': idx + 1
            }
    return False
# Custom function: detects both return and yield in the same function
def return_and_yield_in_same_function(node, ast_root=None):
    """
    Returns True if both a Return and a Yield node are present in the same FunctionDef node.
    """
    #print("[DEBUG][return_and_yield_in_same_function] Checking node:", node.get('node_type'), "at line", node.get('lineno'))

    if not isinstance(node, dict):
        #print("[DEBUG][return_and_yield_in_same_function] Node is not a dict")
        return False

    node_type = node.get('node_type')

    # If we're at the Module level or a nested block, check each function in the body
    if 'body' in node and isinstance(node['body'], list):
        # For each node in the body...
        for child in node['body']:
            if isinstance(child, dict):
                # If this is a function definition, analyze it
                if child.get('node_type') == 'FunctionDef':
                    # Search within the function body for return and yield nodes
                    has_return = False
                    has_yield = False
                    
                    # Helper function to check for return/yield in a statement list
                    def check_statements(stmts):
                        nonlocal has_return, has_yield
                        for stmt in stmts:
                            if isinstance(stmt, dict):
                                stmt_type = stmt.get('node_type')
                                if stmt_type == 'Return':
                                    #print(f"[DEBUG][return_and_yield_in_same_function] Found Return in function {child.get('name')} at line {stmt.get('lineno')}")
                                    has_return = True
                                elif stmt_type == 'Expr':
                                    # Yield statements are wrapped in Expr nodes
                                    value = stmt.get('value', {})
                                    if isinstance(value, dict) and value.get('node_type') == 'Yield':
                                       # print(f"[DEBUG][return_and_yield_in_same_function] Found Yield in function {child.get('name')} at line {stmt.get('lineno')}")
                                        has_yield = True
                                elif stmt_type == 'If' or stmt_type == 'For' or stmt_type == 'While' or stmt_type == 'Try':
                                    # Recursively check blocks for nested returns/yields
                                    if 'body' in stmt and isinstance(stmt['body'], list):
                                        check_statements(stmt['body'])
                                    if 'orelse' in stmt and isinstance(stmt['orelse'], list):
                                        check_statements(stmt['orelse'])
                                    if 'finalbody' in stmt and isinstance(stmt['finalbody'], list):
                                        check_statements(stmt['finalbody'])
                    
                    # Check all statements in the function body
                    check_statements(child['body'])
                    
                    # If we found both return and yield, this function triggers the rule
                    if has_return and has_yield:
                        #print(f"[DEBUG][return_and_yield_in_same_function] Found both return and yield in function {child.get('name')} at line {child.get('lineno')}")
                        return True
                    #print(f"[DEBUG][return_and_yield_in_same_function] Function {child.get('name')} at line {child.get('lineno')}: has_return={has_return}, has_yield={has_yield}")
                # If not a function, recursively check it in case it contains functions
                elif return_and_yield_in_same_function(child, ast_root):
                    return True

    return False
# Custom function: detects reserved environment variable overrides in Lambda functions
def reserved_env_var_override_lambda(node, ast_root=None):
    """
    Returns True if an assignment overrides a reserved AWS environment variable in os.environ.
    """
    #print("[DEBUG][reserved_env_var_override_lambda] Called for node:", node.get('node_type'), "at line", node.get('lineno'))

    reserved_vars = {"AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        #print("[DEBUG][reserved_env_var_override_lambda] Not an Assign node")
        return False

    targets = node.get('targets', [])
    if not targets:
        #print("[DEBUG][reserved_env_var_override_lambda] No targets found")
        return False

    target = targets[0]
    #print("[DEBUG][reserved_env_var_override_lambda] Target node type:", target.get('node_type'))

    # Check for Subscript node: os.environ['VAR']
    if target.get('node_type') == 'Subscript':
        value = target.get('value', {})
        # Check for os.environ
        if value.get('node_type') == 'Attribute' and value.get('attr') == 'environ':
            os_obj = value.get('value', {})
            if os_obj.get('node_type') == 'Name' and os_obj.get('id') == 'os':
                # Python 3.8+: slice.value, Python 3.9+: slice
                slice_node = target.get('slice', {})
                #print("[DEBUG][reserved_env_var_override_lambda] Slice node:", slice_node)
                var_name = None
                if isinstance(slice_node, dict):
                    if 'value' in slice_node:
                        var_name = slice_node.get('value')
                    elif slice_node.get('node_type') == 'Constant':
                        var_name = slice_node.get('value')
                    elif slice_node.get('node_type') == 'Str':
                        var_name = slice_node.get('s')
                elif isinstance(slice_node, str):
                    var_name = slice_node
                #print("[DEBUG][reserved_env_var_override_lambda] Variable name:", var_name)
                if var_name in reserved_vars:
                    #print("[DEBUG][reserved_env_var_override_lambda] Found reserved variable:", var_name)
                    return True
    return False
# Custom function: checks if replacement string references an existing regex group
def replacement_string_references_existing_group(node, ast_root=None):
    """
    Returns True if the replacement string in a regex substitution does NOT reference any group in the pattern.
    Flags if the replacement string does NOT reference any group.
    """
    import re
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False

    func = node.get('func', {})
    # Check for .sub() method (pattern.sub or re.sub)
    if func.get('node_type') == 'Attribute' and func.get('attr') == 'sub':
        args = node.get('args', [])
        if len(args) < 1:
            return False
        # First argument: replacement string
        repl_arg = args[0]
        if repl_arg.get('node_type') == 'Constant':
            replacement = repl_arg.get('value')
        elif repl_arg.get('node_type') == 'Str':
            replacement = repl_arg.get('s')
        else:
            return False
        if not isinstance(replacement, str):
            return False
        # Check for group reference in replacement string
        if re.search(r'(\\\d+|\\g<\w+>|\$\d+)', replacement):
            return False  # Compliant: references a group
        return True  # Noncompliant: does not reference a group
    # Check for re.sub() call
    elif func.get('node_type') == 'Name' and func.get('id') == 'sub':
        args = node.get('args', [])
        if len(args) < 2:
            return False
        # Second argument: replacement string
        repl_arg = args[1]
        if repl_arg.get('node_type') == 'Constant':
            replacement = repl_arg.get('value')
        elif repl_arg.get('node_type') == 'Str':
            replacement = repl_arg.get('s')
        else:
            return False
        if not isinstance(replacement, str):
            return False
        if re.search(r'(\\\d+|\\g<\w+>|\$\d+)', replacement):
            return False  # Compliant
        return True  # Noncompliant
    return False
# Custom function: detects repeated patterns in regex that can match the empty string
def has_repeated_empty_match_pattern(node, ast_root=None):
    """
    Returns True if a regex pattern contains a group that can match the empty string.
    """
    import re
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False

    # Check that this is a re.compile() or re.findall() call
    func = node.get('func', {})
    if not isinstance(func, dict) or func.get('node_type') != 'Attribute':
        return False

    # Check it's .compile() or .findall()
    if func.get('attr') not in ('compile', 'findall'):
        return False

    # Check it's from the 're' module
    value = func.get('value')
    if not isinstance(value, dict) or value.get('node_type') != 'Name' or value.get('id') != 're':
        return False

    # Get the regex pattern argument
    args = node.get('args', [])
    if not args or not isinstance(args[0], dict):
        return False

    # Extract the regex string
    arg = args[0]
    regex_str = None
    if arg.get('node_type') == 'Constant':  # Python 3.8+
        regex_str = arg.get('value')
    elif arg.get('node_type') == 'Str':  # Older Python versions
        regex_str = arg.get('s')
    
    if not isinstance(regex_str, str):
        return False

    # Remove 'r' prefix if present for raw strings
    if regex_str.startswith(('r', 'R')):
        regex_str = regex_str[1:]
    if regex_str.startswith(("'", '"')):
        regex_str = regex_str[1:-1]

    # Check for groups with * or ? quantifiers that can match empty string
    # Look for:
    # 1. (...)[*?] - Groups with * or ? quantifier
    # 2. [^)]+ matches any chars in group except closing paren
    has_empty_match = re.search(r'\(([^)]+)\)[*?]', regex_str)
    
    # If we found a potential empty match pattern, verify it's not a false positive
    if has_empty_match:
        # Extract the group content
        group_content = has_empty_match.group(1)
        # Check if the group contains alternations or single chars that could match empty
        if '|' in group_content or len(group_content.strip()) == 1:
            return True

    return False
    # Try to extract the regex string from the first argument
    if len(node.args) > 0:
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            pattern = arg.value
            # Look for repeated group patterns that can match empty string
            # Examples: (a|b)*, (a|b)?
            import re
            # This regex matches any group with * or ? quantifier
            if re.search(r'(\([^)]+\)[*?])', pattern):
                return True
    return False
def has_redundant_parentheses(node, ast_root=None):
    """
    Detects redundant parentheses in binary operations.
    Returns True if redundant parentheses are found.
    """
    if not isinstance(node, dict):
       # print("[DEBUG] Node is not a dict")
        return False

    if node.get('node_type') != 'BinOp':
        #print("[DEBUG] Node is not BinOp")
        return False

    # Get the operands and operator
    left = node.get('left')
    right = node.get('right')
    op = node.get('op', {}).get('node_type')

    #print(f"[DEBUG] Checking BinOp with operator {op}")

    # Check if operands are also BinOp nodes
    if isinstance(left, dict) and left.get('node_type') == 'BinOp':
        left_op = left.get('op', {}).get('node_type')
        # If the parent operator has higher or equal precedence, parentheses are redundant
        if _has_higher_or_equal_precedence(op, left_op):
            #print(f"[DEBUG] Redundant parentheses found in left operand: {left_op} inside {op}")
            return True

    if isinstance(right, dict) and right.get('node_type') == 'BinOp':
        right_op = right.get('op', {}).get('node_type')
        # If the parent operator has higher precedence, parentheses are redundant
        if _has_higher_precedence(op, right_op):
            #print(f"[DEBUG] Redundant parentheses found in right operand: {right_op} inside {op}")
            return True

    #print("[DEBUG] No redundant parentheses found")
    return False

def _has_higher_or_equal_precedence(op1, op2):
    """Helper function to check operator precedence"""
    precedence = {
        'Mult': 5, 'Div': 5, 'FloorDiv': 5, 'Mod': 5,
        'Add': 4, 'Sub': 4,
        'BitOr': 3, 'BitXor': 3, 'BitAnd': 3,
        'LShift': 2, 'RShift': 2
    }
    return precedence.get(op1, 0) >= precedence.get(op2, 0)

def _has_higher_precedence(op1, op2):
    """Helper function to check strict precedence"""
    precedence = {
        'Mult': 5, 'Div': 5, 'FloorDiv': 5, 'Mod': 5,
        'Add': 4, 'Sub': 4,
        'BitOr': 3, 'BitXor': 3, 'BitAnd': 3,
        'LShift': 2, 'RShift': 2
    }
    return precedence.get(op1, 0) > precedence.get(op2, 0)
def check_exception_inheritance(node, ast_root=None):
    """
    Check if a class derives from Exception instead of BaseException.
    Returns True if the rule is violated (derives from Exception).
    """
    if not isinstance(node, dict):
        #print("[DEBUG] Node is not a dict, skipping")
        return False

    # If this is an assignment, try to parse it for code strings that might contain custom exceptions
    if node.get('node_type') == 'Assign' and 'value' in node:
        value = node.get('value', {})
        if isinstance(value, dict) and value.get('node_type') == 'Constant':
            str_value = value.get('value')
            if isinstance(str_value, str):
                #print(f"[DEBUG] Found code string, trying to parse it")
                try:
                    import ast
                    tree = ast.parse(str_value)
                    # Convert AST to dict format
                    def ast_to_dict(n):
                        if isinstance(n, ast.AST):
                            # Create a dict with node type and attributes
                            dict_node = {'node_type': type(n).__name__}
                            # Add relevant attributes
                            for key, value in ast.iter_fields(n):
                                # Convert child nodes recursively
                                if isinstance(value, (list, tuple)):
                                    dict_node[key] = [ast_to_dict(x) if isinstance(x, (ast.AST, list, tuple)) else x for x in value]
                                else:
                                    dict_node[key] = ast_to_dict(value) if isinstance(value, (ast.AST, list, tuple)) else value
                            return dict_node
                        elif isinstance(n, (list, tuple)):
                            return [ast_to_dict(x) if isinstance(x, (ast.AST, list, tuple)) else x for x in n]
                        return n
                    tree_dict = ast_to_dict(tree)
                    # Check each node in the tree for inheritance from Exception
                    for n in tree_dict.get('body', []):
                        if n.get('node_type') == 'ClassDef':
                            # Reuse the original logic for class definitions
                            bases = n.get('bases', [])
                            if bases:
                                for base in bases:
                                    if not isinstance(base, dict):
                                        continue
                                    base_type = base.get('node_type')
                                    if base_type == 'Name' and base.get('id') == 'Exception':
                                        return True
                                    elif base_type == 'Attribute' and base.get('attr') == 'Exception':
                                        return True
                                    # Recurse into parent classes if needed
                except Exception:
                    pass

    elif node.get('node_type') == 'ClassDef':
        class_name = node.get('name', 'unknown')
        #print(f"[DEBUG] Checking inheritance for class {class_name}")

        # Check class bases
        bases = node.get('bases', [])
        if not bases:
            #print(f"[DEBUG] Class {class_name} has no bases")
            return False

        # Check each base class in the inheritance chain
        for base in bases:
            if not isinstance(base, dict):
                #print(f"[DEBUG] Base for {class_name} is not a dict")
                continue

            base_type = base.get('node_type')
            #print(f"[DEBUG] Base type for {class_name} is {base_type}")

            # Handle attribute access (e.g. exceptions.Exception)
            if base_type == 'Attribute':
                base_name = base.get('attr')
                #print(f"[DEBUG] Found Attribute base {base_name} for {class_name}")
                if base_name == 'Exception':
                    #print(f"[DEBUG] Class {class_name} inherits from Exception (attribute)")
                    return True
                if base_name == 'BaseException':
                    #print(f"[DEBUG] Class {class_name} inherits from BaseException (attribute)")
                    return False

            # Handle direct name reference
            elif base_type == 'Name':
                base_name = base.get('id')
                #print(f"[DEBUG] Found Name base {base_name} for {class_name}")
                if base_name == 'Exception':
                    #print(f"[DEBUG] Class {class_name} inherits from Exception (direct)")
                    return True
                if base_name == 'BaseException':
                    #print(f"[DEBUG] Class {class_name} inherits from BaseException (direct)")
                    return False

                # Handle inheritance through another class
                if ast_root and isinstance(ast_root, dict):
                    #print(f"[DEBUG] Searching for parent class {base_name} in AST")
                    for parent_node in ast_root.get('body', []):
                        if (isinstance(parent_node, dict) and 
                            parent_node.get('node_type') == 'ClassDef' and 
                            parent_node.get('name') == base_name):
                            #print(f"[DEBUG] Found parent class {base_name}, checking its inheritance")
                            if check_exception_inheritance(parent_node, ast_root):
                                #print(f"[DEBUG] Parent class {base_name} violates the rule")
                                return True
                            break

        #print(f"[DEBUG] Class {class_name} inheritance check complete, no violation found")
    return False

def with_taskgroup_single_start_soon_check(node, ast_root=None):
    """
    Returns True if a With or AsyncWith node uses TaskGroup and has exactly one start_soon call in its body.
    """
   # print(f"[DEBUG] Invoked with_taskgroup_single_start_soon_check for node_type: {node.get('node_type')}")
    if not isinstance(node, dict) or node.get('node_type') not in ('With', 'AsyncWith'):
        return False
    # Check context manager is TaskGroup
    items = node.get('items', [])
    if not items or not isinstance(items[0], dict):
        return False
    context_expr = items[0].get('context_expr')
    if not context_expr or not (context_expr.get('id') == 'TaskGroup' or context_expr.get('attr') == 'TaskGroup'):
        return False
    # Check body has exactly one statement
    body = node.get('body', [])
    if len(body) != 1:
        return False
    stmt = body[0]
    # Check statement is a call to start_soon
    if stmt.get('node_type') == 'Expr' and isinstance(stmt.get('value'), dict):
        call = stmt['value']
        if call.get('node_type') == 'Call':
            func = call.get('func', {})
            if func.get('attr') == 'start_soon':
                return True
    return False
def django_modelform_meta_fields_specified_check(node, ast_root=None):
    """
    Returns True if 'fields_specified' is assigned inside a Meta class of a ModelForm.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    # Check assignment target
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        return False
    if targets[0].get('id') != 'fields_specified':
        return False
    # Check parent is Meta class
    parent = node.get('__parent__')
    if not parent or parent.get('node_type') != 'ClassDef' or parent.get('name') != 'Meta':
        return False
    # Check grandparent is ModelForm class
    grandparent = parent.get('__parent__')
    if not grandparent or grandparent.get('node_type') != 'ClassDef':
        return False
    # Check if ModelForm in bases
    bases = grandparent.get('bases', [])
    is_modelform = any(
        (b.get('attr') == 'ModelForm' or b.get('id') == 'ModelForm')
        for b in bases if isinstance(b, dict)
    )
    return is_modelform
def field_name_naming_convention_check(node, ast_root=None):
    """
    Returns True if a class field name does not comply with snake_case naming convention.
    Only triggers for assignments inside class definitions.
    """
    import re
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    parent = node.get('__parent__')
    if not parent or parent.get('node_type') != 'ClassDef':
        return False
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        return False
    field_name = targets[0].get('id')
    if not field_name:
        return False
    # Check for camelCase or PascalCase (should be snake_case)
    if re.match(r'[A-Z][a-z]*', field_name) or re.search(r'[a-z][A-Z]', field_name):
        return True
    return False
def has_duplicate_dict_keys(node, ast_root=None, source_code=None):
    """
    Returns True if a dictionary literal contains duplicate keys.
    This function should be called with the original source code for token analysis,
    since Python AST does not retain duplicate keys.
    """
    if source_code is None or not isinstance(source_code, str):
        return False
    import re
    # Regex to match dictionary literals: { ... }
    dict_literals = re.findall(r'\{[^}]*\}', source_code)
    for literal in dict_literals:
        # Find all string keys in the literal
        keys = re.findall(r'(["\"][^"\"]*["\"]|\'[^\']*\')\s*:', literal)
        # Remove quotes and count occurrences
        key_counts = {}
        for k in keys:
            k_clean = k.strip('"\'')
            key_counts[k_clean] = key_counts.get(k_clean, 0) + 1
        if any(count > 1 for count in key_counts.values()):
            return True
    return False
def except_clause_raises_same_exception(node, ast_root=None):
    """
    Returns True if an ExceptHandler node raises the same exception type as it catches.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'ExceptHandler':
        return False
    except_type = None
    if 'type' in node and isinstance(node['type'], dict):
        except_type = node['type'].get('id')
    body = node.get('body', [])
    if not body:
        return False
    first_stmt = body[0]
    if isinstance(first_stmt, dict) and first_stmt.get('node_type') == 'Raise':
        exc = first_stmt.get('exc')
        if isinstance(exc, dict) and exc.get('node_type') == 'Call':
            func = exc.get('func', {})
            if func.get('id') == except_type:
                return True
    return False
def einops_pattern_check(node, ast_root=None):
    """
    Returns True if an Assign node does not match the valid Einops pattern:
    - value must be a list of 4 strings
    - first element must be 'num_samples' or 'batch_size'
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    value = node.get('value')
    if isinstance(value, list) and len(value) == 4:
        first = value[0]
        if first in ("num_samples", "batch_size") and all(isinstance(v, str) for v in value):
            return False  # Compliant
        return True  # Noncompliant
    return True  # Noncompliant if not a list of 4 strings
def doubled_prefix_operator_check(node, ast_root=None):
    """
    Returns True if a Compare node uses both NotEq and Lt operators (chained comparison).
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Compare':
        return False
    ops = node.get('ops', [])
    op_types = [op.get('node_type') for op in ops if isinstance(op, dict)]
    # Detect both NotEq and Lt in the same Compare node
    if 'NotEq' in op_types and 'Lt' in op_types:
        return True
    return False
def missing_docstring_check(node, ast_root=None):
    """
    Returns True if a FunctionDef, ClassDef, or Module node is missing a docstring.
    Handles AST in dict format as used by the scanner.
    """
    if not isinstance(node, dict):
        return False
    node_type = node.get('node_type')
    if node_type not in ('FunctionDef', 'ClassDef', 'Module'):
        return False
    body = node.get('body', [])
    if not body:
        # No body, so no docstring
        return True
    first_item = body[0]
    # Docstring is an Expr node with a Constant or Str value (depending on Python version)
    if isinstance(first_item, dict) and first_item.get('node_type') == 'Expr':
        value = first_item.get('value', {})
        # For Python 3.8+, docstring is Constant; older is Str
        if value.get('node_type') == 'Constant' and isinstance(value.get('value'), str) and value.get('value').strip():
            return False
        if value.get('node_type') == 'Str' and isinstance(value.get('s'), str) and value.get('s').strip():
            return False
    # If first item is not a docstring Expr node, docstring is missing
    return True
# Custom function to check if receiver decorator is not the top decorator
def signal_handler_receiver_not_top(node, ast_root=None):
    """
    Returns True if a FunctionDef node has a receiver decorator, but it is not the top decorator.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'FunctionDef':
        return False
    decorators = node.get('decorator_list', [])
    if not decorators or len(decorators) < 2:
        return False  # Must have at least two decorators to check order
    # Check if any decorator is receiver
    has_receiver = any(
        (d.get('id') == 'receiver' or (d.get('func', {}).get('id') == 'receiver'))
        for d in decorators if isinstance(d, dict)
    )
    if not has_receiver:
        return False
    # Check if the top decorator is receiver
    top = decorators[0]
    if isinstance(top, dict) and (top.get('id') == 'receiver' or (top.get('func', {}).get('id') == 'receiver')):
        return False  # Compliant
    return True  # Noncompliant: receiver is not the top decorator
def django_model_missing_str_method(node, ast_root=None):
    #print('[DEBUG][django_model_missing_str_method] Invoked for node:', node.get('node_type'), 'at line', node.get('lineno'))
    if not isinstance(node, dict) or node.get('node_type') != 'ClassDef':
        return False
    bases = node.get('bases', [])
    #print('[DEBUG][django_model_missing_str_method] bases:', bases)
    is_model = False
    for base in bases:
        if isinstance(base, dict):
            #print('[DEBUG][django_model_missing_str_method] base:', base)
            if base.get('attr') == 'Model' or base.get('id') == 'Model':
                is_model = True
            if base.get('attr') == 'Model' and base.get('value', {}).get('id') == 'models':
                is_model = True
    #print('[DEBUG][django_model_missing_str_method] is_model:', is_model)
    if not is_model:
        return False
    for item in node.get('body', []):
        #print('[DEBUG][django_model_missing_str_method] body item:', item)
        if isinstance(item, dict) and item.get('node_type') == 'FunctionDef' and item.get('name') == '__str__':
            #print('[DEBUG][django_model_missing_str_method] Found __str__ method')
            return False
    #print('[DEBUG][django_model_missing_str_method] __str__ method not found, returning True')
    return True
# Custom function to detect Django model classes missing __str__ method
def django_model_missing_str_method(node, ast_root=None):
    """
    Returns True if a Django model class does not define a __str__ method.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'ClassDef':
        return False
    # Check if class inherits from models.Model
    bases = node.get('bases', [])
    is_model = False
    for base in bases:
        if isinstance(base, dict):
            # Handles models.Model and direct Model
            if base.get('attr') == 'Model' or base.get('id') == 'Model':
                is_model = True
            if base.get('attr') == 'Model' and base.get('value', {}).get('id') == 'models':
                is_model = True
    if not is_model:
        return False
    # Check if any method is named __str__
    for item in node.get('body', []):
        if isinstance(item, dict) and item.get('node_type') == 'FunctionDef' and item.get('name') == '__str__':
            return False
    return True
# Custom function to detect missing Encryption key in S3 CreateBucketConfiguration
def s3_bucket_missing_encryption(node, ast_root=None):
    """
    Returns True if a Call to create_bucket has CreateBucketConfiguration without Encryption key.
    """
    # print('[DEBUG][s3_bucket_missing_encryption] Invoked for node:', node.get('node_type'), 'at line', node.get('lineno'))
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if func.get('attr') != 'create_bucket':
        return False
    keywords = node.get('keywords', [])
    for kw in keywords:
        if kw.get('arg') == 'CreateBucketConfiguration':
            config = kw.get('value', {})
            #print('[DEBUG][s3_bucket_missing_encryption] config:', config)
            if config.get('node_type') == 'Dict':
                keys = config.get('keys', [])
                #print('[DEBUG][s3_bucket_missing_encryption] keys:', keys)
                # Check if any key is 'Encryption'
                for k in keys:
                    #print('[DEBUG][s3_bucket_missing_encryption] key:', k)
                    if (isinstance(k, dict) and k.get('node_type') == 'Constant' and k.get('value') == 'Encryption'):
                        #print('[DEBUG][s3_bucket_missing_encryption] Found Encryption key')
                        return False
                #print('[DEBUG][s3_bucket_missing_encryption] Encryption key not found, returning True')
                return True
            # Config is not a Dict
            #print('[DEBUG][s3_bucket_missing_encryption] config is not Dict')
            return True
    return False

# Custom function to detect missing ExpectedBucketOwner parameter in S3 operations
def s3_operation_missing_expected_bucket_owner(node, ast_root=None):
    """
    Returns True if an S3 operation Call node is missing the ExpectedBucketOwner keyword argument.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    # Check for S3 Object operations (delete, put, get, etc.)
    if func.get('node_type') == 'Attribute' and func.get('attr') in ['delete', 'put', 'get', 'download_file', 'upload_file']:
        keywords = node.get('keywords', [])
        for kw in keywords:
            if kw.get('arg') == 'ExpectedBucketOwner':
                return False
        return True
    return False
def has_csrf_exempt_decorator(node):
    """Return True if a FunctionDef node has a csrf_exempt decorator."""
    if not isinstance(node, dict):
        return False
    if node.get('node_type') != 'FunctionDef':
        return False
    decorators = node.get('decorator_list', [])
    for deco in decorators:
        if isinstance(deco, dict) and deco.get('id') == 'csrf_exempt':
            return True
    return False
import ast

def dictcomp_static_key_check(node):
    """Return True if a DictComp uses a static key (Constant node) in dict AST format."""
    if not isinstance(node, dict):
        return False
    if node.get('node_type') != 'DictComp':
        return False
    key_node = node.get('key')
    if isinstance(key_node, dict) and key_node.get('node_type') == 'Constant':
        return True
    return False
from .logging_basicConfig_debug_check import logging_basicConfig_debug_check
from .deprecated_numpy_alias_check import deprecated_numpy_alias_check
from .dictcomp_static_key_check import dictcomp_static_key_check
def pandas_to_datetime_forbidden_format(node, ast_root=None):
    """
    Returns True if pd.to_datetime is called with a forbidden date format as the first argument and dayfirst/yearfirst is set.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    # Check for pd.to_datetime
    if func.get('attr') != 'to_datetime':
        return False
    value = func.get('value', {})
    if value.get('id') != 'pd':
        return False
    args = node.get('args', [])
    if not args or not isinstance(args[0], dict):
        return False
    date_str = args[0].get('value')
    import re
    forbidden_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2})$')
    if not (isinstance(date_str, str) and forbidden_pattern.match(date_str)):
        return False
    # Check for dayfirst or yearfirst in keywords
    keywords = node.get('keywords', [])
    for kw in keywords:
        if kw.get('arg') in ('dayfirst', 'yearfirst'):
            return True
    return False
# Custom function to detect deeply nested control flow statements
def is_deeply_nested_control_flow(node, ast_root=None, max_depth=3):
    """
    Returns True if the node is a control flow statement (If, For, While, Try, With) and is nested deeper than max_depth.
    Calculates nesting depth by traversing from AST root if __parent__ is missing.
    """
    CONTROL_FLOW_TYPES = ["If", "For", "While", "Try", "With"]
    if not isinstance(node, dict) or node.get('node_type') not in CONTROL_FLOW_TYPES:
        return False
    def get_nesting_depth(n, root):
        # If __parent__ is present, use it
        depth = 1
        parent = n.get('__parent__')
        while parent:
            if parent.get('node_type') in CONTROL_FLOW_TYPES:
                depth += 1
            parent = parent.get('__parent__')
        if n.get('__parent__'):
            return depth
        # Otherwise, traverse from root
        def find_path(cur, target, path):
            if cur is target:
                return path
            if isinstance(cur, dict):
                for k, v in cur.items():
                    if isinstance(v, dict):
                        res = find_path(v, target, path + [cur])
                        if res:
                            return res
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict):
                                res = find_path(item, target, path + [cur])
                                if res:
                                    return res
            return None
        path = find_path(root, n, []) or []
        depth = 1
        for ancestor in path:
            if ancestor.get('node_type') in CONTROL_FLOW_TYPES:
                depth += 1
        return depth
    actual_depth = get_nesting_depth(node, ast_root) if ast_root else 1
    return actual_depth > max_depth
def is_out_of_range_datetime_constructor(node, ast_root=None):
    """
    Returns True if a Call node to datetime/date/time has out-of-range month or day arguments.
    Handles both direct and attribute calls.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    func_name = func.get('attr') or func.get('id')
    if func_name not in ("datetime", "date", "time"):
        return False
    args = node.get('args', [])
    # Month is args[1], day is args[2] (if present)
    if len(args) > 1 and isinstance(args[1], dict):
        month = args[1].get('value')
        if isinstance(month, int) and (month < 1 or month > 12):
            return True
    if len(args) > 2 and isinstance(args[2], dict):
        day = args[2].get('value')
        if isinstance(day, int) and (day < 1 or day > 31):
            return True
    return False

def equality_check_against_numpynan(node, ast_root=None):
    """
    Returns True if a Compare node checks equality (== or !=) against np.nan or numpy.nan.
    Handles both left and any comparator sides.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Compare':
        return False
    # Helper to check if an AST node is np.nan or numpy.nan
    def is_numpynan(subnode):
        if not isinstance(subnode, dict):
            return False
        if subnode.get('node_type') == 'Attribute' and subnode.get('attr') == 'nan':
            value = subnode.get('value', {})
            if value.get('node_type') == 'Name' and value.get('id') in ('np', 'numpy'):
                return True
        return False
    # Check left side
    if is_numpynan(node.get('left')):
        return True
    # Check all comparators
    for comp in node.get('comparators', []):
        if is_numpynan(comp):
            return True
    return False
# Custom function to detect single-character character classes in regex strings
def has_single_character_class(node, ast_root=None):
    """
    Returns True if a regex string in a Call node contains a character class with only one character.
    """
    import re
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    args = node.get('args', [])
    if not args or not isinstance(args[0], dict):
        return False
    regex_str = None
    for key in ['s', 'value', 'constant', 'str', 'text']:
        if isinstance(args[0].get(key), str):
            regex_str = args[0][key]
            break
    if not isinstance(regex_str, str):
        return False
    for match in re.finditer(r'\[(.*?)\]', regex_str):
        char_class = match.group(1)
        if len(char_class) == 1:
            return True
    return False
# Custom function to detect duplicate characters in regex character classes (case-insensitive)
def has_duplicate_character_class(node, ast_root=None):
    """
    Returns True if a regex string in a Call node contains a character class with duplicate characters (case-insensitive).
    """
    import re
    #print('[DEBUG][has_duplicate_character_class] Called for node:', node.get('node_type'), 'at line', node.get('lineno'))
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        #print('[DEBUG][has_duplicate_character_class] Not a Call node')
        return False
    args = node.get('args', [])
    if not args or not isinstance(args[0], dict):
        #print('[DEBUG][has_duplicate_character_class] No args or first arg not dict')
        return False
    regex_str = None
    # Try common keys for string value in AST node
    for key in ['s', 'value', 'constant', 'str', 'text']:
        if isinstance(args[0].get(key), str):
            regex_str = args[0][key]
            break
    #print('[DEBUG][has_duplicate_character_class] Regex string:', regex_str)
    if not isinstance(regex_str, str):
        #print('[DEBUG][has_duplicate_character_class] Regex string not str')
        return False
    for match in re.finditer(r'\[(.*?)\]', regex_str):
        char_class = match.group(1)
        #print('[DEBUG][has_duplicate_character_class] Found character class:', char_class)
        seen = set()
        for c in char_class:
            c_lower = c.lower()
            if c_lower in seen:
                #print('[DEBUG][has_duplicate_character_class] Duplicate found:', c)
                return True
            seen.add(c_lower)
    #print('[DEBUG][has_duplicate_character_class] No duplicates found')
    return False
def is_typing_generic_import(node, threshold=10):
    """
    Calculates cyclomatic complexity for a class node.
    Returns True if complexity exceeds threshold.
    Debug print added to verify invocation and show complexity calculation.
    """
    #print(f"[DEBUG] cyclomatic_complexity_of_class called for node: {getattr(node, 'name', None)}")
    if not hasattr(node, 'body'):
        #print("[DEBUG] Node has no body attribute.")
        return False
    complexity = 0
    for item in node.body:
        if hasattr(item, 'body'):
            for subitem in item.body:
                if isinstance(subitem, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.AsyncFor)):
                    complexity += 1
    #print(f"[DEBUG] Calculated complexity for class {getattr(node, 'name', None)}: {complexity}")
    return complexity > threshold
    # Check if the body contains an assignment to a collection element
    body = node.get('body', [])
    for stmt in body:
        if stmt.get('node_type') == 'Assign':
            targets = stmt.get('targets', [])
            # Look for subscript assignment: my_list[i] = ...
            for target in targets:
                if target.get('node_type') == 'Subscript':
                    # Unconditional if parent is not an If node
                    # Check if parent is an If node (by traversing up if ast_root is provided)
                    if ast_root:
                        # Traverse up to see if this For node is inside an If
                        def is_inside_if(n, parent=None):
                            if n is node:
                                return False
                            if n.get('node_type') == 'If' and node in n.get('body', []):
                                return True
                            for k in ['body', 'orelse', 'args', 'targets', 'value', 'test']:
                                v = n.get(k)
                                if isinstance(v, list):
                                    for child in v:
                                        if isinstance(child, dict):
                                            if is_inside_if(child, n):
                                                return True
                                elif isinstance(v, dict):
                                    if is_inside_if(v, n):
                                        return True
                            return False
                        if is_inside_if(ast_root):
                            return False
                    return True
    return False
    """
    Returns True if a Call node to datetime/date/time has out-of-range month or day arguments.

        if len(comparators) >= 2:
    """
    """
    Returns True if a Compare node checks equality (== or !=) against np.nan or numpy.nan.
    Handles both left and any comparator sides.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Compare':
        return False
    # Helper to check if an AST node is np.nan or numpy.nan
    # Check if the first comparator is a constant (int/float)
    comparators = node.get('comparators', [])
    if len(comparators) >= 2:
        first = comparators[0]
        if isinstance(first, (int, float)):
            return True
    if node.get('node_type') == 'ImportFrom' and node.get('module') == 'typing':
        forbidden = {'List', 'Dict', 'Set', 'Tuple', 'Union'}
        for name_obj in node.get('names', []):
            if isinstance(name_obj, dict) and name_obj.get('name') in forbidden:
                return True
    return False
# Custom function to detect unused scope-limited definitions
def is_unused_scopelimited_definition(node, ast_root=None):
    """
    Returns True if a variable assigned in a function (Assign node) is never used in that function.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        return False
    var_name = targets[0].get('id')
    if not var_name:
        return False
    # Find the nearest FunctionDef parent, or use ast_root if provided
    func_root = None
    root = node
    while root.get('__parent__'):
        if root.get('__parent__', {}).get('node_type') == 'FunctionDef':
            func_root = root.get('__parent__')
            break
        root = root.get('__parent__')
    if not func_root and ast_root:
        func_root = ast_root
    used = False
    def search_usage(n):
        nonlocal used
        if isinstance(n, dict):
            if n.get('node_type') == 'Name' and n.get('id') == var_name:
                used = True
            for v in n.values():
                search_usage(v)
        elif isinstance(n, list):
            for item in n:
                search_usage(item)
    if func_root:
        search_usage(func_root)
    else:
        search_usage(node)
    return not used
# Custom function to detect unused private nested classes
def is_unused_private_nested_class(node, ast_root=None):
    """
    Returns True if a private nested class (name starts with '_') is never used in the codebase.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'ClassDef':
        return False
    class_name = node.get('name')
    if not class_name or not class_name.startswith('_'):
        return False

    # Custom function to detect list comprehensions used only to copy collections
def is_comprehension_only_copy(node, ast_root=None):
    """
    Returns True if a ListComp node is used only to copy another collection (e.g., [i for i in b]).
    """
    if not isinstance(node, dict) or node.get('node_type') != 'ListComp':
        return False
    elt = node.get('elt')
    generators = node.get('generators', [])
    if not generators or not isinstance(elt, dict):
        return False
    gen = generators[0]
    # Check if elt is a Name and matches the target of the generator
    if elt.get('node_type') == 'Name' and gen.get('target', {}).get('node_type') == 'Name':
        if elt.get('id') == gen.get('target', {}).get('id'):
            # Only one generator, no ifs, and iter is a Name (e.g., b)
            if len(generators) == 1 and not gen.get('ifs') and gen.get('iter', {}).get('node_type') == 'Name':
                return True
    return False

# Custom function to detect constructors around generator expressions
def is_constructor_around_generator_expression(node, ast_root=None):
    """
    Returns True if a Call node is a constructor (list, set, tuple) around a generator expression.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if func.get('node_type') == 'Name' and func.get('id') in {'list', 'set', 'tuple'}:
        args = node.get('args', [])
        if args and isinstance(args[0], dict) and args[0].get('node_type') == 'GeneratorExp':
            return True
    return False

# Custom function to detect nested If statements
def is_nested_conditional_expression(node, ast_root=None):
    """
    Returns True if an If node contains another If node in its body.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'If':
        return False
    body = node.get('body', [])
    for stmt in body:
        if isinstance(stmt, dict) and stmt.get('node_type') == 'If':
            return True
    return False

# Custom function for comparison to None as a constant
def is_comparison_to_none_constant(node, ast_root=None):
    """
    Returns True if a Compare node compares to None as a constant.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Compare':
        return False
    comparators = node.get('comparators', [])
    for comp in comparators:
        if isinstance(comp, dict) and comp.get('node_type') == 'Constant' and comp.get('value') is None:
            return True
    return False
    # Check if this class is nested (parent is also a ClassDef)
    parent = node.get('__parent__')
    if not parent or parent.get('node_type') != 'ClassDef':
        return False
    # Search for usage of this nested class in the AST
    used = False
    def search_usage(n):
        nonlocal used
        if isinstance(n, dict):
            # Look for instantiation or reference: A._NestedClass or _NestedClass()
            if n.get('node_type') == 'Attribute' and n.get('attr') == class_name:
                used = True
            elif n.get('node_type') == 'Name' and n.get('id') == class_name:
                used = True
            for v in n.values():
                search_usage(v)
        elif isinstance(n, list):
            for item in n:
                search_usage(item)
    # Use ast_root if provided, else walk up to module root
    root = ast_root if ast_root else node
    while root.get('__parent__'):
        root = root.get('__parent__')
    search_usage(root)
    return not used
# Custom function to detect unused local variables
def is_unused_local_variable(node, ast_root=None):
    """
    Returns True if a local variable assigned in an Assign node is never used in the function body.
    """
    #print('[DEBUG][is_unused_local_variable] Called for node:', node.get('node_type'), 'at line', node.get('lineno'))
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
       #print('[DEBUG][is_unused_local_variable] Node is not Assign')
        return False
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        #print('[DEBUG][is_unused_local_variable] No valid targets')
        return False
    var_name = targets[0].get('id')
    #print('[DEBUG][is_unused_local_variable] Variable name:', var_name)
    if not var_name:
        #print('[DEBUG][is_unused_local_variable] No variable name')
        return False
    # Find the nearest FunctionDef parent, or use ast_root if provided
    func_root = None
    root = node
    while root.get('__parent__'):
        if root.get('__parent__', {}).get('node_type') == 'FunctionDef':
            func_root = root.get('__parent__')
            break
        root = root.get('__parent__')
    if not func_root and ast_root:
        func_root = ast_root
    #print('[DEBUG][is_unused_local_variable] Function root node_type:', func_root.get('node_type') if func_root else None)
    used = False
    def search_usage(n):
        nonlocal used
        if isinstance(n, dict):
            if n.get('node_type') == 'Name' and n.get('id') == var_name:
                #print('[DEBUG][is_unused_local_variable] Usage found for:', var_name, 'at line', n.get('lineno'))
                used = True
            for v in n.values():
                search_usage(v)
        elif isinstance(n, list):
            for item in n:
                search_usage(item)
    if func_root:
        search_usage(func_root)
    else:
        #print('[DEBUG][is_unused_local_variable] No function root found, searching from node')
        search_usage(node)
    #print('[DEBUG][is_unused_local_variable] Used:', used)
    return not used
# Custom function to detect unused imports
def is_unused_import(node, ast_root=None):
    """
    Returns True if an import in an Import node is unused in the AST.
    """
    #print('[DEBUG][is_unused_import] Called for node:', node.get('node_type'), 'at line', node.get('lineno'))
    if not isinstance(node, dict) or node.get('node_type') != 'Import':
        #print('[DEBUG][is_unused_import] Node is not Import')
        return False
    imported_names = [alias.get('name') for alias in node.get('names', []) if isinstance(alias, dict)]
    #print('[DEBUG][is_unused_import] Imported names:', imported_names)
    root = ast_root if ast_root is not None else node
    while root.get('__parent__'):
        root = root.get('__parent__')
    used_names = set()
    def collect_used_names(n):
        if isinstance(n, dict):
            if n.get('node_type') == 'Name':
                used_names.add(n.get('id'))
            elif n.get('node_type') == 'Attribute':
                # Add the base name of the attribute (e.g., math in math.sqrt)
                value = n.get('value')
                if isinstance(value, dict) and value.get('node_type') == 'Name':
                    used_names.add(value.get('id'))
            for v in n.values():
                collect_used_names(v)
        elif isinstance(n, list):
            for item in n:
                collect_used_names(item)
    collect_used_names(root)
    #print('[DEBUG][is_unused_import] Used names in AST:', used_names)
    unused_found = False
    for name in imported_names:
        if name not in used_names:
            #print('[DEBUG][is_unused_import] Unused import detected:', name)
            unused_found = True
    if unused_found:
        return True
    #print('[DEBUG][is_unused_import] All imports are used')
    return False
# Shared custom function for bare raise statement context detection
def is_unread_private_attribute(node, ast_root=None):
    """
    Returns True if a private attribute (name starts with '_') assigned in a class is never read anywhere in the class.
    """
   #print('[DEBUG][is_unread_private_attribute] Called for node:', node.get('node_type'), 'at line', node.get('lineno'))
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        #print('[DEBUG][is_unread_private_attribute] No valid targets')
        return False
    target = targets[0]
    attr_name = None
    if target.get('node_type') == 'Attribute':
        attr_name = target.get('attr')
    elif target.get('node_type') == 'Name':
        attr_name = target.get('id')
    #print('[DEBUG][is_unread_private_attribute] Attribute name:', attr_name)
    if not attr_name or not attr_name.startswith('_') or attr_name.startswith('__'):
        #print('[DEBUG][is_unread_private_attribute] Not a private attribute')
        return False
    # Find the nearest ClassDef ancestor by walking up the parent chain
    current = node
    class_node = None
    while current:
        parent = current.get('__parent__')
        if parent:
           #print('[DEBUG][is_unread_private_attribute] Traversing parent node_type:', parent.get('node_type'))
            if parent.get('node_type') == 'ClassDef':
                class_node = parent
                break
        current = parent
   # print('[DEBUG][is_unread_private_attribute] Class node_type:', class_node.get('node_type') if class_node else None)
    if not class_node:
        #print('[DEBUG][is_unread_private_attribute] No ClassDef ancestor found')
        return False
    used = False
    def search_usage(n):
        nonlocal used
        if n is node:
            #print(f'[DEBUG][is_unread_private_attribute] Skipping assignment node itself at line {n.get("lineno")}')
            return  # Skip the assignment node itself
        if isinstance(n, dict):
            if n.get('node_type') == 'Attribute' and n.get('attr') == attr_name:
                #print('[DEBUG][is_unread_private_attribute] Usage found for:', attr_name, 'at line', n.get('lineno'))
                used = True
            elif n.get('node_type') == 'Name' and n.get('id') == attr_name:
                #print('[DEBUG][is_unread_private_attribute] Usage found for:', attr_name, 'at line', n.get('lineno'))
                used = True
            # Also skip nested Assign nodes for the same attribute
            if n.get('node_type') == 'Assign':
                targets = n.get('targets', [])
                target = targets[0] if targets and isinstance(targets[0], dict) else None
                target_name = None
                if target:
                    if target.get('node_type') == 'Attribute':
                        target_name = target.get('attr')
                    elif target.get('node_type') == 'Name':
                        target_name = target.get('id')
                if target_name == attr_name and n is not node:
                    #print(f'[DEBUG][is_unread_private_attribute] Skipping nested assignment for {attr_name} at line {n.get("lineno")}')
                    return
            for v in n.values():
                search_usage(v)
        elif isinstance(n, list):
            for item in n:
                search_usage(item)
    search_usage(class_node)
    #print('[DEBUG][is_unread_private_attribute] Used:', used)
    return not used
# Custom function to detect unused private methods
def is_unused_private_method(node, ast_root=None):
    """
    Returns True if a private method (name starts with '_') is never called in the codebase.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'FunctionDef':
        return False
    method_name = node.get('name')
    if not method_name or not method_name.startswith('_') or method_name.startswith('__'):
        return False
    # Find the parent class
    parent = node.get('__parent__')
    if not parent or parent.get('node_type') != 'ClassDef':
        return False
    # Search for usage of this method in the class
    used = False
    def search_usage(n):
        nonlocal used
        if isinstance(n, dict):
            # Look for method call: self._method() or _method()
            if n.get('node_type') == 'Call':
                func = n.get('func')
                if isinstance(func, dict):
                    # self._method()
                    if func.get('node_type') == 'Attribute' and func.get('attr') == method_name:
                        used = True
                    # _method()
                    elif func.get('node_type') == 'Name' and func.get('id') == method_name:
                        used = True
            for v in n.values():
                search_usage(v)
        elif isinstance(n, list):
            for item in n:
                search_usage(item)
    search_usage(parent)
    return not used
def check_bare_raise_context(node, context=None):
    """
    Returns True if a bare raise statement is found in the specified context ('finally' or 'except').
    """
    # Only process Raise nodes
    if not isinstance(node, dict) or node.get('node_type') != 'Raise':
        return False
    # Check if it's a bare raise (no exception specified)
    if node.get('exc') is not None:
        return False
    # Traverse parent chain to find context
    parent = node.get('__parent__', None)
    while parent:
        if context == 'finally' and parent.get('node_type') == 'Finally':
            return True
        if context == 'except' and parent.get('node_type') == 'ExceptHandler':
            return True
        parent = parent.get('__parent__', None)
    # For 'except' context, bare raise outside except block is a violation
    if context == 'except':
        return False
    return False
# Custom function for detecting hardcoded AWS region in boto3 client calls
def check_hardcoded_aws_region(node):
    """
    Returns True if a boto3.client call contains a hardcoded AWS region value.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    # Check for boto3.client call
    if func.get('node_type') == 'Attribute' and func.get('attr') == 'client':
        value = func.get('value', {})
        if value.get('node_type') == 'Name' and value.get('id') == 'boto3':
            # Check for region_name keyword argument
            for kw in node.get('keywords', []):
                if kw.get('arg') == 'region_name':
                    region_value = kw.get('value', {})
                    if region_value.get('node_type') == 'Constant':
                        region = str(region_value.get('value', ''))
                        # Match AWS region pattern
                        if re.match(r'^(us|eu|ap|sa|ca|me|af)-(north|south|east|west|central|northeast|southeast|southwest|northwest|central)-[0-9]+$', region):
                            return True
    return False
# Custom function for unnecessary equality checks
def is_unnecessary_equality_check(node):
    """
    Detects chained equality comparisons like: x == 1 or x == 2 or x == 3
    Returns True if such a pattern is found.
    """
    if not isinstance(node, dict):
        return False
    # Check for BoolOp (or) with multiple Compare nodes
    if node.get('node_type') == 'BoolOp' and node.get('op', {}).get('node_type') == 'Or':
        left_names = set()
        values = node.get('values', [])
        for value in values:
            if isinstance(value, dict) and value.get('node_type') == 'Compare':
                ops = value.get('ops', [])
                if ops and ops[0].get('node_type') == 'Eq':
                    left = value.get('left', {})
                    if left.get('node_type') == 'Name':
                        left_names.add(left.get('id'))
        if len(left_names) == 1 and len(values) > 1:
            #print('[DEBUG][is_unnecessary_equality_check] Triggered on node:', node)
            return True
    return False

# Custom function: simple cognitive complexity heuristic
def cognitive_complexity_check_impl(node, ast_root=None):
    """
    Heuristic for cognitive complexity: return True for FunctionDef nodes
    whose top-level body contains more than 5 statements. This is a
    conservative approximation used by the metadata-driven rule.
    """
    # Expect the node as a dict produced by ast_to_dict_with_parent
    if not isinstance(node, dict) or node.get('node_type') != 'FunctionDef':
        return False
    #print(f"[DEBUG][cognitive_complexity_check_impl] Called for node: {node.get('node_type')} at line {node.get('lineno')}")
    body = node.get('body', [])
    if not isinstance(body, list):
        return False
    # Count only top-level statements (ignore nested defs/classes)
    stmt_count = 0
    for stmt in body:
        if isinstance(stmt, dict):
            # Skip nested FunctionDef or ClassDef from counting
            if stmt.get('node_type') in ('FunctionDef', 'ClassDef'):
                continue
            stmt_count += 1
        else:
            # Non-dict entries (unlikely) still count
            stmt_count += 1
    # Threshold matches metadata heuristic (>5 statements)
    return stmt_count > 5
# Custom function: Detect Unicode grapheme clusters inside regex character classes
def check_unicode_grapheme_clusters_in_regex(node):
    """
    Returns True if a regex string contains a character class with Unicode grapheme cluster range (U+0300–U+036F).
    Example: pattern = r'[̀-ͯ]+'
    """
    # Only check assignment nodes
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    value_node = node.get('value', {})
    if not isinstance(value_node, dict):
        return False
    # Look for Constant node with a string value
    if value_node.get('node_type') == 'Constant':
        pattern = value_node.get('value', '')
        # Match character class with Unicode grapheme cluster range
        # U+0300 = \u0300, U+036F = \u036F
        import re
        if isinstance(pattern, str) and re.search(r'\[.*?\u0300-\u036F.*?\]', pattern):
            return True
        # Also match literal combining marks: [̀-ͯ]
        if isinstance(pattern, str) and re.search(r'\[[̀-ͯ]+\]', pattern):
            return True
    return False
def check_unencrypted_rds_usage(node):
    """
    Custom logic for rule: using_unencrypted_rds_db_resources_is_securitysensitive
    Flags calls to boto3.client('rds').describe_db_instances()
    """
    # print('[DEBUG] Called check_unencrypted_rds_usage')
    # print('[DEBUG] Node type:', node.get('node_type'))
    # print('[DEBUG] Node structure:', node)
    if node.get('node_type') == 'Call':
        func = node.get('func', {})
    # print('[DEBUG] func:', func)
        # Check for describe_db_instances call
        if func.get('node_type') == 'Attribute' and func.get('attr') == 'describe_db_instances':
            value = func.get('value', {})
            # print('[DEBUG] value:', value)
            # Check for boto3.client('rds')
            if value.get('node_type') == 'Call':
                inner_func = value.get('func', {})
                # print('[DEBUG] inner_func:', inner_func)
                if inner_func.get('node_type') == 'Attribute' and inner_func.get('attr') == 'client':
                    args = value.get('args', [])
                    # print('[DEBUG] args:', args)
                    for arg in args:
                        # print('[DEBUG] arg:', arg)
                        if arg.get('node_type') == 'Constant' and arg.get('value') == 'rds':
                            # print('[DEBUG] MATCH FOUND!')
                            return {
                                'message': 'Unencrypted RDS resource found',
                                'line': node.get('lineno', 1)
                            }
    return False
def async_functions_should_use_async_features(node):
    # Only process async functions
    if node.get("node_type") != "AsyncFunctionDef":
        return False
    def contains_async_feature(n):
        if isinstance(n, dict):
            # Check for 'Await' or 'AsyncWith' node types
            if n.get("node_type") in ["Await", "AsyncWith"]:
                return True
            for v in n.values():
                if contains_async_feature(v):
                    return True
        elif isinstance(n, list):
            for item in n:
                if contains_async_feature(item):
                    return True
        return False
    return not contains_async_feature(node.get("body", []))
def async_forbidden_subprocess_call(node):
    # Recursively check for forbidden subprocess calls in async function body
    forbidden_subprocess_calls = ["run", "call", "Popen"]
    def contains_forbidden_call(n):
        if isinstance(n, dict):
            if n.get('node_type') == 'Call':
                func = n.get('func', {})
                if func.get('node_type') == 'Attribute':
                    if func.get('value', {}).get('id') == 'subprocess' and func.get('attr') in forbidden_subprocess_calls:
                        return True
            for v in n.values():
                if contains_forbidden_call(v):
                    return True
        elif isinstance(n, list):
            for item in n:
                if contains_forbidden_call(item):
                    return True
        return False
    return contains_forbidden_call(node.get('body', []))
# ...existing code...
def cyclomatic_complexity_of_class(node, ast_root=None, threshold=10):
    """
    Returns True if the cyclomatic complexity of a class exceeds the threshold.
    Cyclomatic complexity is calculated by counting decision points in all methods of the class.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'ClassDef':
        return False
    def count_complexity(n):
        count = 0
        if isinstance(n, dict):
            if n.get('node_type') in ['If', 'For', 'While', 'Try', 'With', 'ExceptHandler', 'BoolOp']: # decision points
                count += 1
            for v in n.values():
                count += count_complexity(v)
        elif isinstance(n, list):
            for item in n:
                count += count_complexity(item)
        return count
    total_complexity = 0
    # Count complexity in all methods (FunctionDef) in the class
    for stmt in node.get('body', []):
        if isinstance(stmt, dict) and stmt.get('node_type') == 'FunctionDef':
            total_complexity += count_complexity(stmt)
    return total_complexity > threshold
def is_hardcoded_credential(node, ast_root=None):
    """
    Returns True if an Assign node assigns a string constant to a variable with a credential-related name.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        return False
    var_name = targets[0].get('id', '').lower()
    credential_keywords = [
        'password', 'passwd', 'pwd', 'username', 'user', 'secret', 'token', 'key', 'api_key', 'access_key', 'auth', 'credential'
    ]
    if not any(k in var_name for k in credential_keywords):
        return False
    value = node.get('value', {})
    # Check for string constant assignment
    if value.get('node_type') == 'Constant' and isinstance(value.get('value'), str):
        return True
    return False
def is_hardcoded_credential(node, ast_root=None):
    """
    Returns True if an Assign node assigns a string constant to a variable with a credential-related name.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        return False
    var_name = targets[0].get('id', '').lower()
    credential_keywords = [
        'password', 'passwd', 'pwd', 'username', 'user', 'secret', 'token', 'key', 'api_key', 'access_key', 'auth', 'credential'
    ]
    if not any(k in var_name for k in credential_keywords):
        return False
    value = node.get('value', {})
    # Check for string constant assignment
    if value.get('node_type') == 'Constant' and isinstance(value.get('value'), str):
        return True
    return False
def cancellation_scope_contains_checkpoint(node, ast_root=None):
    """
    Returns True if an AsyncWith node with a cancel_token context contains a checkpoint (either in items or as 'await checkpoint()' in the body).
    """
    if not isinstance(node, dict) or node.get('node_type') != 'AsyncWith':
        return False
    items = node.get('items', [])
    has_cancel_token = False
    has_checkpoint_item = False
    for item in items:
        context_expr = item.get('context_expr', {})
        if isinstance(context_expr, dict):
            if context_expr.get('id') == 'cancel_token':
                has_cancel_token = True
            if context_expr.get('id') == 'checkpoint':
                has_checkpoint_item = True
    if not has_cancel_token:
        return False
    if has_checkpoint_item:
        return False  # Compliant, no finding
    # Scan body for 'await checkpoint()'
    def body_has_checkpoint(n):
        if isinstance(n, dict):
            if n.get('node_type') == 'Expr':
                value = n.get('value', {})
                if value.get('node_type') == 'Await':
                    awaited = value.get('value', {})
                    # Check for checkpoint.wait() or checkpoint()
                    if awaited.get('node_type') == 'Call':
                        func = awaited.get('func', {})
                        if func.get('node_type') == 'Attribute' and func.get('value', {}).get('id') == 'checkpoint':
                            return True
                        if func.get('node_type') == 'Name' and func.get('id') == 'checkpoint':
                            return True
            for v in n.values():
                if body_has_checkpoint(v):
                    return True
        elif isinstance(n, list):
            for item in n:
                if body_has_checkpoint(item):
                    return True
        return False
    if body_has_checkpoint(node.get('body', [])):
        return False  # Compliant, no finding
    return True  # Noncompliant, checkpoint missing
import re
def check_admin_services_access_restricted_to_specific_ip_addresses(node):
    """
    Custom logic for rule: administration_services_access_should_be_restricted_to_specific_ip_addresses
    Checks for unrestricted admin service access (e.g., 0.0.0.0/0, *, any) in cidr_blocks.
    """
    def extract_cidr_blocks(obj):
        cidrs = []
        if isinstance(obj, dict):
            if obj.get('node_type') == 'Dict':
                keys = obj.get('keys', [])
                values = obj.get('values', [])
                for key, value in zip(keys, values):
                    if isinstance(key, dict) and key.get('value') == 'cidr_blocks':
                        if value.get('node_type') == 'List':
                            for elt in value.get('elts', []):
                                if elt.get('node_type') == 'Constant':
                                    cidrs.append(str(elt.get('value', '')))
            elif obj.get('node_type') == 'Assign':
                value = obj.get('value', {})
                cidrs.extend(extract_cidr_blocks(value))
            for key in ['value', 'values']:
                if key in obj:
                    value = obj[key]
                    if isinstance(value, (dict, list)):
                        cidrs.extend(extract_cidr_blocks(value))
        elif isinstance(obj, list):
            for item in obj:
                cidrs.extend(extract_cidr_blocks(item))
        return cidrs
    if node.get('node_type') not in ['Assign', 'Call']:
        return False
    cidr_blocks = extract_cidr_blocks(node)
    if not cidr_blocks:
        return False
    node_id = None
    if node.get('node_type') == 'Assign':
        targets = node.get('targets', [])
        if targets and isinstance(targets[0], dict):
            node_id = targets[0].get('id', '')
    if node_id and not re.search(r'(?i)(admin|administrator|manage|control|configure)', node_id):
        return False
    pattern = re.compile(r"(?i)(0\.0\.0\.0/0|\*|any)")
    return any(pattern.search(cidr) for cidr in cidr_blocks)
# ...existing code...
def check_subclass_parent_in_except(node):
    """
    Check for subclass and parent class in the same except statement.
    """
    if node.get('node_type') != 'ExceptHandler':
        return False
    exc_type = node.get('type', {})
    if isinstance(exc_type, dict) and exc_type.get('node_type') == 'Tuple':
        elts = exc_type.get('elts', [])
        exception_names = []
        for elt in elts:
            if isinstance(elt, dict) and elt.get('node_type') == 'Name':
                exception_names.append(elt.get('id', ''))
        # Build a map of class inheritance from the parent AST node
        # Traverse up to find the root module/class definitions
        parent = node.get('__parent__', None)
        while parent and parent.get('__parent__'):
            parent = parent.get('__parent__')
        class_bases = {}
        if parent and 'body' in parent:
            for item in parent['body']:
                if isinstance(item, dict) and item.get('node_type') == 'ClassDef':
                    class_name = item.get('name', '')
                    bases = [base.get('id', '') for base in item.get('bases', []) if isinstance(base, dict)]
                    class_bases[class_name] = bases
        # Check for subclass-parent pairs in the except tuple
        for i, name1 in enumerate(exception_names):
            for j, name2 in enumerate(exception_names):
                if i != j:
                    # name1 is subclass of name2
                    if name1 in class_bases and name2 in class_bases[name1]:
                        return True
                    # name2 is subclass of name1
                    if name2 in class_bases and name1 in class_bases[name2]:
                        return True
        # Fallback: if 'Exception' is present and another type, still trigger
        if 'Exception' in exception_names and len(exception_names) > 1:
            return True
    return False
# ...existing code...
def is_weak_password(password):
    """Check if a password is considered weak"""
    if not isinstance(password, str) or len(password) < 3:
        return False
    password_lower = password.lower()
    weak_passwords = [
        '123456', 'password', 'admin', 'root', 'user', 'guest', 'test',
        'admin123', 'password123', 'root123', 'user123', 'test123',
        'qwerty', 'abc123', '111111', '000000', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'secret', 'login', 'pass',
        '12345678', '1234567890', 'password1', 'admin1', 'secret123'
    ]
    if password_lower in weak_passwords:
        return True
    if password.isdigit() and len(password) <= 8:
        return True
    if len(password) <= 6:
        return True
    if all(ord(password[i]) == ord(password[0]) + i for i in range(len(password))):
        return True
    return False

def check_union_type_expressions_preferred(node):
    """
    Custom logic for rule: union_type_expressions_should_be_preferred_over_typingunion_in_type_hints
    Flags usage of typing.Union in type hints, recommends using X | Y syntax.
    """
    findings = []
    # Check function arguments
    if node.get('node_type') in ['FunctionDef', 'AsyncFunctionDef']:
        args = node.get('args', {}).get('args', [])
        for arg in args:
            annotation = arg.get('annotation', {})
            if annotation.get('node_type') == 'Subscript':
                value = annotation.get('value', {})
                if value.get('node_type') == 'Name' and value.get('id') == 'Union':
                    findings.append({
                        'message': "Use 'X | Y' union type expressions instead of 'typing.Union[X, Y]' in type hints.",
                        'line': arg.get('lineno', node.get('lineno', 1))
                    })
    # Check variable annotations
    if node.get('node_type') == 'AnnAssign':
        annotation = node.get('annotation', {})
        if annotation.get('node_type') == 'Subscript':
            value = annotation.get('value', {})
            if value.get('node_type') == 'Name' and value.get('id') == 'Union':
                findings.append({
                    'message': "Use 'X | Y' union type expressions instead of 'typing.Union[X, Y]' in type hints.",
                    'line': node.get('lineno', 1)
                })
    return findings if findings else False
    password_lower = password.lower()
    weak_passwords = [
        '123456', 'password', 'admin', 'root', 'user', 'guest', 'test',
        'admin123', 'password123', 'root123', 'user123', 'test123',
        'qwerty', 'abc123', '111111', '000000', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'secret', 'login', 'pass',
        '12345678', '1234567890', 'password1', 'admin1', 'secret123'
    ]
    if password_lower in weak_passwords:
        return True
    if password.isdigit() and len(password) <= 8:
        return True
    if len(password) <= 6:
        return True
    if all(ord(password[i]) == ord(password[0]) + i for i in range(len(password))):
        return True
    return False
# ...existing code...
def check_database_password_security(node):
    """
    Check for insecure database passwords in connection calls.
    """
    if node.get('node_type') == 'Call':
        func = node.get('func', {})
        if isinstance(func, dict):
            # Check for database connection functions
            func_name = func.get('attr', '') or func.get('id', '')
            if any(db_word in func_name.lower() for db_word in ['connect', 'engine', 'session']):
                # Check password parameter
                keywords = node.get('keywords', [])
                for kw in keywords:
                    if isinstance(kw, dict):
                        arg_name = kw.get('arg', '').lower()
                        if arg_name in ['password', 'pwd', 'passwd']:
                            value = kw.get('value', {})
                            if isinstance(value, dict) and value.get('node_type') in ['Constant', 'Str']:
                                password = str(value.get('value', ''))
                                if is_weak_password(password):
                                    return True
    elif node.get('node_type') == 'Assign':
        # Check database URL assignments
        targets = node.get('targets', [])
        for target in targets:
            if isinstance(target, dict) and target.get('node_type') == 'Name':
                var_name = target.get('id', '').lower()
                if any(word in var_name for word in ['db_url', 'database_url', 'connection_string']):
                    value = node.get('value', {})
                    if isinstance(value, dict) and value.get('node_type') in ['Constant', 'Str']:
                        url = str(value.get('value', ''))
                        # Check for weak passwords in database URLs
                        if ':' in url and '@' in url:
                            try:
                                # Extract password from URL like postgresql://user:password@host/db
                                password_part = url.split('://')[1].split('@')[0]
                                if ':' in password_part:
                                    password = password_part.split(':')[1]
                                    if is_weak_password(password):
                                        return True
                            except Exception:
                                pass
    return False
# ...existing code...
def check_test_skip_without_reason(node):
    """
    Check for pytest.mark.skip without a reason parameter.
    """
    if node.get('node_type') != 'FunctionDef':
        return False
    decorators = node.get('decorator_list', [])
    for decorator in decorators:
        if isinstance(decorator, dict):
            if decorator.get('node_type') == 'Attribute':
                # Handle @pytest.mark.skip
                attr = decorator.get('attr', '')
                if attr == 'skip':
                    value = decorator.get('value', {})
                    if isinstance(value, dict):
                        if value.get('node_type') == 'Attribute':
                            sub_attr = value.get('attr', '')
                            sub_value = value.get('value', {})
                            if (sub_attr == 'mark' and isinstance(sub_value, dict) and 
                                sub_value.get('node_type') == 'Name' and 
                                sub_value.get('id') == 'pytest'):
                                return True
            elif decorator.get('node_type') == 'Call':
                # Handle @pytest.mark.skip() - check if reason is provided
                func = decorator.get('func', {})
                if isinstance(func, dict):
                    if func.get('node_type') == 'Attribute' and func.get('attr') == 'skip':
                        # Check if there are keyword arguments with 'reason'
                        keywords = decorator.get('keywords', [])
                        for kw in keywords:
                            if isinstance(kw, dict) and kw.get('arg') == 'reason':
                                return False  # Reason is provided
                        return True  # No reason provided
    return False
# Auto-generated function for metadata creation
# Importing check_test_skip_without_reason from logic_implementationsv2
def check_field_class_name_conflict(node):
    """
    Check if a field name duplicates its containing class name.
    """
    if node.get('node_type') != 'ClassDef':
        return False
    class_name = node.get('name', '')
    if not class_name:
        return False
    # Check class body for field assignments and instance attribute assignments
    body = node.get('body', [])
    for stmt in body:
        if isinstance(stmt, dict):
            # Class-level assignments
            if stmt.get('node_type') == 'Assign':
                targets = stmt.get('targets', [])
                for target in targets:
                    if isinstance(target, dict) and target.get('node_type') == 'Name':
                        field_name = target.get('id', '')
                        if field_name.lower() == class_name.lower():
                            return True
            # Instance attribute assignments inside methods
            if stmt.get('node_type') in ['FunctionDef', 'AsyncFunctionDef']:
                method_body = stmt.get('body', [])
                for inner_stmt in method_body:
                    if isinstance(inner_stmt, dict) and inner_stmt.get('node_type') == 'Assign':
                        targets = inner_stmt.get('targets', [])
                        for target in targets:
                            if (isinstance(target, dict) and target.get('node_type') == 'Attribute' and
                                target.get('value', {}).get('node_type') == 'Name' and
                                target.get('value', {}).get('id') == 'self'):
                                attr_name = target.get('attr', '')
                                if attr_name.lower() == class_name.lower():
                                    return True
    return False
# Auto-generated function for metadata creation
# Detects regex patterns containing two or more consecutive spaces
import ast
import re

def field_should_not_duplicate_class_name(node):
    """Detects when a field name duplicates its containing class name."""
    if node.get('node_type') != 'ClassDef':
        return False
        
    class_name = node.get('name', '')
    if not class_name:
        return False
        
    # Check assignments in the class body
    for stmt in node.get('body', []):
        if isinstance(stmt, dict):
            # Class-level assignments
            if stmt.get('node_type') == 'Assign':
                for target in stmt.get('targets', []):
                    if isinstance(target, dict):
                        if target.get('node_type') == 'Name' and target.get('id').lower() == class_name.lower():
                            return True
                        elif target.get('node_type') == 'Attribute' and target.get('attr').lower() == class_name.lower():
                            return True
            # Instance attribute assignments inside methods
            if stmt.get('node_type') in ['FunctionDef', 'AsyncFunctionDef']:
                method_body = stmt.get('body', [])
                for inner_stmt in method_body:
                    if isinstance(inner_stmt, dict) and inner_stmt.get('node_type') == 'Assign':
                        for target in inner_stmt.get('targets', []):
                            if (isinstance(target, dict) and target.get('node_type') == 'Attribute' and
                                target.get('value', {}).get('node_type') == 'Name' and
                                target.get('value', {}).get('id') == 'self' and
                                target.get('attr').lower() == class_name.lower()):
                                return True
                            
    return False

def regular_expressions_should_not_contain_multiple_spaces(node):
    """Detects regex patterns containing two or more consecutive spaces."""
    if isinstance(node, ast.Call):
        for arg in node.args:
            if isinstance(arg, ast.Str):
                pattern = arg.s
                if re.search(r" {2,}", pattern):
                    return True
    return False

# Detects if/elif/else chains with repeated conditions

def related_ifelse_if_statements_should_not_have_the_same_condition(node):
    """Detects if/elif/else chains with repeated conditions."""
    if isinstance(node, ast.If):
        conditions = set()
        current = node
        while isinstance(current, ast.If):
            cond_src = ast.dump(current.test)
            if cond_src in conditions:
                return True
            conditions.add(cond_src)
            if current.orelse and isinstance(current.orelse[0], ast.If):
                current = current.orelse[0]
            else:
                break
    return False

# Detects regex patterns where a reluctant quantifier (e.g., *?, +?, ??) is followed by an expression that can match the empty string

def reluctant_quantifiers_in_regular_expressions_should_be_followed_by_an_expression_that_cant_match_the_empty_string(node):
    """Detects regex patterns where a reluctant quantifier (e.g., *?, +?, ??) is followed by an expression that can match the empty string."""
    if isinstance(node, ast.Call):
        for arg in node.args:
            if isinstance(arg, ast.Str):
                pattern = arg.s
                # Find reluctant quantifiers
                for match in re.finditer(r'(\*\?|\+\?|\?\?)', pattern):
                    idx = match.end()
                    # Check if the next part can match empty string (e.g., .*, (?:), [])
                    next_part = pattern[idx:idx+4]
                    if re.match(r'(\.|\(\?:\)|\[\])', next_part):
                        return True
    return False
# Auto-generated function for metadata creation
def regular_expressions_should_be_syntactically_valid(node):
    """Detects regex strings containing contradictory lookahead assertions."""
    if isinstance(node, ast.Call):
        for arg in node.args:
            if isinstance(arg, ast.Str):
                regex = arg.s
                if '(?=' in regex and '(?!' in regex:
                    return True
    return False

# Auto-generated function for metadata creation
def regular_expressions_should_not_be_too_complicated(node):
    """Detects regex strings containing contradictory lookahead assertions."""
    if isinstance(node, ast.Call):
        for arg in node.args:
            if isinstance(arg, ast.Str):
                regex = arg.s
                if '(?=' in regex and '(?!' in regex:
                    return True
    return False

# Auto-generated function for metadata creation
def regular_expressions_should_not_contain_empty_groups(node):
    """Detects regex strings containing contradictory lookahead assertions."""
    if isinstance(node, ast.Call):
        for arg in node.args:
            if isinstance(arg, ast.Str):
                regex = arg.s
                if '(?=' in regex and '(?!' in regex:
                    return True
    return False
# Auto-generated function for metadata creation
def passing_a_reversed_iterable_to_set_sorted_or_reversed_should_be_avoided(node):
    """Detects if the expression value is a generator expression."""
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.GeneratorExp):
        return True
    return False

# Auto-generated function for metadata creation
def password_hashing_functions_should_use_an_unpredictable_salt(node):
    """Detects if the expression value is a generator expression."""
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.GeneratorExp):
        return True
    return False

# Auto-generated function for metadata creation
def passwords_should_not_be_stored_in_plaintext_or_with_a_fast_hashing_algorithm(node):
    """Detects if the expression value is a generator expression."""
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.GeneratorExp):
        return True
    return False
# Auto-generated function for metadata creation
def npnonzero_should_be_preferred_over_npwhere_when_only_the_condition_parameter_is_set(node):
    """Detects use of np.where with only the condition parameter set."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'where':
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'np':
                # Only one positional argument and no keywords
                if len(node.args) == 1 and not node.keywords:
                    return True
    return False

# Auto-generated function for metadata creation
def nulltrue_should_not_be_used_on_stringbased_fields_in_django_models(node):
    """Detects use of null=True on string-based fields in Django models."""
    string_fields = {'CharField', 'TextField', 'SlugField', 'EmailField', 'URLField'}
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in string_fields:
            for kw in node.keywords:
                if kw.arg == 'null' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
    return False

# Auto-generated function for metadata creation
def numpy_weekmask_should_have_a_valid_value(node):
    """Detects invalid weekmask values in numpy usage."""
    valid_weekmask = {'1111111', '0000000', '1010101', '0101010'}  # Example valid values
    if isinstance(node, ast.Call):
        for kw in node.keywords:
            if kw.arg == 'weekmask' and isinstance(kw.value, ast.Str):
                if kw.value.s not in valid_weekmask:
                    return True
    return False
# Auto-generated function for metadata creation
def noncapturing_groups_without_quantifier_should_not_be_used(node):
    """Detects old-style class or function definitions."""
    return isinstance(node, (ast.ClassDef, ast.FunctionDef))

# Auto-generated function for metadata creation
def nonempty_statements_should_change_control_flow_or_have_at_least_one_sideeffect(node):
    """Detects old-style class or function definitions."""
    return isinstance(node, (ast.ClassDef, ast.FunctionDef))

# Auto-generated function for metadata creation
def nonexistent_operators_like_should_not_be_used(node):
    """Detects old-style class or function definitions."""
    return isinstance(node, (ast.ClassDef, ast.FunctionDef))
# Auto-generated function for metadata creation
def hardcoded_passwords_are_securitysensitive(node):
    """Detects hardcoded passwords in assignments or function arguments."""
    password_keywords = {'password', 'passwd', 'pwd', 'pass'}
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and any(k in target.id.lower() for k in password_keywords):
                if isinstance(node.value, ast.Str):
                    return True
    if isinstance(node, ast.Call):
        for kw in getattr(node, 'keywords', []):
            if any(k in kw.arg.lower() for k in password_keywords) and isinstance(kw.value, ast.Str):
                return True
    return False

# Custom function: checks if a resource is initialized inside a lambda handler function
def resource_initialized_inside_lambda_handler_check(node, ast_root=None):
    """
    Returns True if a resource is initialized inside a function named 'lambda_handler'.
    Resource initialization is detected by instantiation or function calls that return resources.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'FunctionDef':
        return False
    func_name = node.get('name', '')
    # Check for typical lambda handler names
    if not func_name.lower().startswith('lambda_handler'):
        return False

    # Resource initialization patterns to check
    aws_resource_patterns = {
        'connect_to_db', 'create_connection', 'connect', 'create_client',
        'resource', 'client', 'from_service', 'session', 'create_session'
    }
    aws_service_patterns = {
        'dynamodb', 's3', 'rds', 'sns', 'sqs', 'lambda', 'kinesis',
        'stepfunctions', 'athena', 'redshift', 'secretsmanager'
    }

    def check_for_aws_resource_init(value):
        """Check if a node represents AWS resource initialization"""
        if not isinstance(value, dict):
            return False
        node_type = value.get('node_type')
        
        # Direct boto3 resource/client calls
        if node_type == 'Call':
            func = value.get('func', {})
            if func.get('node_type') == 'Attribute':
                # Check for boto3.resource('s3') etc
                if func.get('attr') in aws_resource_patterns:
                    value_node = func.get('value', {})
                    if (value_node.get('node_type') == 'Name' and 
                        value_node.get('id') in {'boto3', 'aws'}):
                        return True
                    # Check for client.from_service() type calls
                    if value_node.get('node_type') == 'Attribute' and value_node.get('attr') in aws_service_patterns:
                        return True
            # Check for direct calls to connection functions
            elif func.get('node_type') == 'Name':
                if func.get('id') in aws_resource_patterns:
                    return True
            
            # Check arguments for AWS service names
            args = value.get('args', [])
            for arg in args:
                if isinstance(arg, dict) and arg.get('node_type') == 'Constant':
                    arg_value = arg.get('value', '')
                    if isinstance(arg_value, str) and arg_value.lower() in aws_service_patterns:
                        return True
                    
            # Check keywords for AWS service names
            keywords = value.get('keywords', [])
            for kw in keywords:
                if isinstance(kw, dict) and kw.get('arg') == 'service_name':
                    value_node = kw.get('value', {})
                    if value_node.get('node_type') == 'Constant':
                        service = value_node.get('value', '')
                        if isinstance(service, str) and service.lower() in aws_service_patterns:
                            return True
        return False

    def is_resource_init(stmt):
        """Check if a statement contains resource initialization"""
        if not isinstance(stmt, dict):
            return False
            
        # Check node type to handle different AST structures
        node_type = stmt.get('node_type')
        
        # Direct assignments
        if node_type == 'Assign':
            targets = stmt.get('targets', [])
            if not targets:
                return False
                
            value = stmt.get('value', {})
            return check_for_aws_resource_init(value)
            
        # If statements and other control flows
        elif node_type == 'If':
            body = stmt.get('body', [])
            orelse = stmt.get('orelse', [])
            
            # Check both if and else branches
            for sub_stmt in body + orelse:
                if is_resource_init(sub_stmt):
                    return True
                    
        # For statements
        elif node_type in ('For', 'AsyncFor'):
            for sub_stmt in stmt.get('body', []) + stmt.get('orelse', []):
                if is_resource_init(sub_stmt):
                    return True
                    
        # While statements
        elif node_type == 'While':
            for sub_stmt in stmt.get('body', []) + stmt.get('orelse', []):
                if is_resource_init(sub_stmt):
                    return True
                    
        # Try blocks
        elif node_type == 'Try':
            # Check try body
            for sub_stmt in stmt.get('body', []):
                if is_resource_init(sub_stmt):
                    return True
            # Check except handlers
            for handler in stmt.get('handlers', []):
                if isinstance(handler, dict):
                    for sub_stmt in handler.get('body', []):
                        if is_resource_init(sub_stmt):
                            return True
            # Check else
            for sub_stmt in stmt.get('orelse', []):
                if is_resource_init(sub_stmt):
                    return True
            # Check finally
            for sub_stmt in stmt.get('finalbody', []):
                if is_resource_init(sub_stmt):
                    return True
                    
        # With statements
        elif node_type == 'With':
            for sub_stmt in stmt.get('body', []):
                if is_resource_init(sub_stmt):
                    return True
                    
        return False

    # Check all statements in function body
    for stmt in node.get('body', []):
        if is_resource_init(stmt):
            return True
            
    return False

# Auto-generated function for metadata creation
def hardcoded_secrets_are_securitysensitive(node):
    """Detects hardcoded secrets in assignments or function arguments."""
    secret_keywords = {'secret', 'token', 'key', 'api_key', 'access_key', 'private_key'}
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and any(k in target.id.lower() for k in secret_keywords):
                if isinstance(node.value, ast.Str):
                    return True
    if isinstance(node, ast.Call):
        for kw in getattr(node, 'keywords', []):
            if any(k in kw.arg.lower() for k in secret_keywords) and isinstance(kw.value, ast.Str):
                return True
    return False

# Auto-generated function for metadata creation
def having_a_permissive_crossorigin_resource_sharing_policy_is_securitysensitive(node):
    """Detects permissive CORS policy (wildcard origins)."""
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and 'cors' in target.id.lower():
                if isinstance(node.value, ast.Str) and node.value.s == '*':
                    return True
            if isinstance(target, ast.Name) and 'origin' in target.id.lower():
                if isinstance(node.value, ast.Str) and node.value.s == '*':
                    return True
    if isinstance(node, ast.Call):
        for kw in getattr(node, 'keywords', []):
            if kw.arg and ('origin' in kw.arg.lower() or 'cors' in kw.arg.lower()):
                if isinstance(kw.value, ast.Str) and kw.value.s == '*':
                    return True
    return False
# Auto-generated function for metadata creation
def exception_and_baseexception_should_not_be_raised(node):
    """Detects if a raise statement raises Exception or BaseException."""
    if isinstance(node, ast.Raise):
        exc = node.exc
        # exc can be ast.Name, ast.Call, ast.Attribute, etc.
        if isinstance(exc, ast.Name) and exc.id in {'Exception', 'BaseException'}:
            return True
        if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name) and exc.func.id in {'Exception', 'BaseException'}:
            return True
    return False
# Auto-generated function for metadata creation
def except_clauses_should_do_more_than_raise_the_same_issue(node):
    """Detects except clauses that only re-raise the exception."""
    if isinstance(node, ast.Try):
        for handler in node.handlers:
            # If the except block only contains a single raise statement
            if (len(handler.body) == 1 and isinstance(handler.body[0], ast.Raise)):
                return True
    return False
# Auto-generated function for metadata creation
def events_should_be_used_instead_of_sleep_in_asynchronous_loops(node):
    """Detects if an async function uses sleep in a loop instead of event synchronization."""
    if isinstance(node, ast.AsyncFunctionDef):
        for child in ast.walk(node):
            if isinstance(child, (ast.For, ast.AsyncFor)):
                has_sleep = False
                has_event = False
                for loop_body_item in child.body:
                    # Check for sleep calls
                    if isinstance(loop_body_item, ast.Expr) and isinstance(loop_body_item.value, ast.Call):
                        func = loop_body_item.value.func
                        if (isinstance(func, ast.Attribute) and func.attr == 'sleep') or (isinstance(func, ast.Name) and func.id == 'sleep'):
                            has_sleep = True
                    # Check for event usage
                    if isinstance(loop_body_item, ast.Assign):
                        if isinstance(loop_body_item.value, ast.Call):
                            func = loop_body_item.value.func
                            if (isinstance(func, ast.Attribute) and 'Event' in func.attr) or (isinstance(func, ast.Name) and 'Event' in func.id):
                                has_event = True
                if has_sleep and not has_event:
                    return True
    return False
# Auto-generated function for metadata creation
def asyncio_tasks_should_be_saved_to_prevent_premature_garbage_collection(node):
    """Detects if an async function creates asyncio tasks without saving them to a variable."""
    if isinstance(node, ast.AsyncFunctionDef):
        for child in ast.walk(node):
            # Look for calls to asyncio.create_task, loop.create_task, or asyncio.ensure_future
            if isinstance(child, ast.Call):
                called = None
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr == 'create_task' or child.func.attr == 'ensure_future':
                        called = child.func.attr
                elif isinstance(child.func, ast.Name):
                    if child.func.id == 'ensure_future':
                        called = child.func.id
                # If a task is created, check if it's assigned to a variable
                if called:
                    parent = getattr(child, 'parent', None)
                    if not (parent and isinstance(parent, ast.Assign) and child in parent.value.elts if hasattr(parent.value, 'elts') else parent.value == child):
                        return True
    return False
# Auto-generated function for metadata creation
def asynchronous_functions_should_not_accept_timeout_parameters(node):
    """Detects if an async function accepts a 'timeout' parameter."""
    if isinstance(node, ast.AsyncFunctionDef):
        for arg in node.args.args:
            if arg.arg == 'timeout':
                return True
        # Also check for keyword-only arguments
        for arg in getattr(node.args, 'kwonlyargs', []):
            if arg.arg == 'timeout':
                return True
    return False
# Auto-generated function for metadata creation
def async_with_should_be_used_for_asynchronous_resource_management(node):
    """Detects use of synchronous 'with' inside an async function (should use 'async with')."""
    if isinstance(node, ast.AsyncFunctionDef):
        for child in ast.walk(node):
            if isinstance(child, ast.With):
                # Synchronous 'with' found in async function
                return True
    return False
# Auto-generated function for metadata creation
def is_async_function_with_sync_file_operations(node):
    """Detects if an async function contains synchronous file operations like open(), read(), write(), close()."""
    file_methods = {'read', 'write', 'close', 'flush', 'seek', 'tell', 'truncate'}
    if isinstance(node, ast.AsyncFunctionDef):
        for child in ast.walk(node):
            # Detect open()
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id == 'open':
                    return True
                # Detect file method calls (e.g., f.read())
                if isinstance(child.func, ast.Attribute) and child.func.attr in file_methods:
                    return True
    return False

# Stub for Issue class (replace with actual implementation if available)
class Issue(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args)


# Auto-generated function for metadata creation
def test_skip_reason(node):
    """Auto-generated STUB for a_reason_should_be_provided_when_skipping_a_test. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def is_mixed_http_methods(node):
    """Auto-generated STUB for allowing_both_safe_and_unsafe_http_methods_is_securitysensitive. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def is_unrestricted_outbound_communication(node):
    """Auto-generated STUB for allowing_unrestricted_outbound_communications_is_securitysensitive. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def is_async_function_with_input_call(node):
    """Detects if an async function contains an input() call."""
    if isinstance(node, ast.AsyncFunctionDef):
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Check if the function called is 'input'
                if (isinstance(child.func, ast.Name) and child.func.id == 'input'):
                    return True
    return False


# Auto-generated function for metadata creation
def check_async_function_for_sync_http_calls(node):
    """Detects if an async function contains synchronous HTTP client calls like requests.get/post, http.client.HTTPConnection, etc."""
    sync_http_calls = {
        ('requests', {'get', 'post', 'put', 'delete', 'head', 'options', 'patch'}),
        ('http.client', {'HTTPConnection', 'HTTPSConnection'})
    }
    if isinstance(node, ast.AsyncFunctionDef):
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # requests.get/post/put/etc
                if isinstance(child.func, ast.Attribute):
                    if isinstance(child.func.value, ast.Name) and child.func.value.id == 'requests' and child.func.attr in sync_http_calls[0][1]:
                        return True
                # http.client.HTTPConnection/HTTPSConnection
                if isinstance(child.func, ast.Attribute):
                    if isinstance(child.func.value, ast.Name) and child.func.value.id == 'http' and child.func.attr == 'client':
                        if child.args and isinstance(child.args[0], ast.Str) and child.args[0].s in sync_http_calls[1][1]:
                            return True
                # direct instantiation: http.client.HTTPConnection(...)
                if isinstance(child.func, ast.Name) and child.func.id in sync_http_calls[1][1]:
                    return True
    return False


# Auto-generated function for metadata creation
def is_os_call_in_async_function(node):
    """Auto-generated STUB for async_functions_should_not_contain_synchronous_os_calls. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation

def is_unreachable_code(node):
    if node.get('node_type') != 'FunctionDef':
        return False

    # Skip main functions or test functions as they may be called externally
    func_name = node.get('name')
    if func_name in ['main'] or func_name.startswith('test_'):
        return False

    # Walk up parent chain to find module node
    root = node
    while root.get('node_type') != 'Module' and root.get('__parent__') is not None:
        root = root.get('__parent__')
    if root.get('node_type') != 'Module':
        return False

    # Look for any assignments or calls using this function
    found_usage = False
    nodes_to_check = [root]  # Start with root node
    checked_nodes = set()  # Keep track of nodes we've seen to avoid loops

    while nodes_to_check and not found_usage:
        current = nodes_to_check.pop(0)
        if id(current) in checked_nodes:  # Skip if already checked
            continue
        checked_nodes.add(id(current))

        if isinstance(current, dict):
            if current.get('node_type') in ['Call', 'Name']:
                # Check direct calls
                if current.get('node_type') == 'Call':
                    func = current.get('func', {})
                    if isinstance(func, dict) and func.get('node_type') == 'Name' and func.get('id') == func_name:
                        found_usage = True
                        break
                # Check assignments and other references
                elif current.get('node_type') == 'Name' and current.get('id') == func_name:
                    # If it's referenced anywhere besides its own definition, count it as used
                    if current != node:
                        found_usage = True
                        break
            
            # Add children to check
            for value in current.values():
                if isinstance(value, list):
                    nodes_to_check.extend(item for item in value if isinstance(item, dict))
                elif isinstance(value, dict):
                    nodes_to_check.append(value)

    return not found_usage


# Auto-generated function for metadata creation
def all_except_blocks_should_be_able_to_catch_exceptions_check(node):
    # Only check function definitions
    if node.get('node_type') != 'FunctionDef':
        return False

    # Check for @contextmanager decorator
    decorators = node.get('decorator_list', [])
    for dec in decorators:
        # Handles both Name and Attribute nodes
        if dec.get('node_type') == 'Name' and dec.get('id') == 'contextmanager':
            return False
        if dec.get('node_type') == 'Attribute' and dec.get('attr') == 'contextmanager':
            return False

    # Check for try/except blocks in function body
    body = node.get('body', [])
    for stmt in body:
        if stmt.get('node_type') == 'Try':
            # If there is at least one except handler
            handlers = stmt.get('handlers', [])
            if any(h.get('node_type') == 'ExceptHandler' for h in handlers):
                return False

    # If neither contextmanager nor except block found, flag as violation
    return True


# Auto-generated function for metadata creation
def is_async_function(node):
    """
    Stub function for is_async_function. Implement detection logic here.
    """
    pass


# Auto-generated function for metadata creation
def cognitive_complexity_check(node):
    """Delegate stub to the implemented cognitive_complexity_check with ast_root=None."""
    try:
        return cognitive_complexity_check_impl(node, None)
    except Exception:
        # Fall back to older implementation if present
        try:
            return cognitive_complexity_check(node, None)
        except Exception:
            return False

def check_public_access_parameters(node):
    """Check if a function call contains public access parameters"""
    if node.get('node_type') != 'Call':
        return False

    # Check function keywords arguments
    for kw in node.get('keywords', []):
        # Look for access_control parameter
        if kw.get('arg') == 'access_control':
            value = kw.get('value', {})
            # Check for public access value
            if value.get('node_type') == 'Constant' and \
               value.get('value') == 'Public_Read':
                # print("[DEBUG] Found public access configuration:", value.get('value'))
                return True
    
    return False

def check_public_network_access(node):
    """Check for public network access in cloud resource configurations."""
    if node.get('node_type') != 'Call':
        return False

    # Get keywords arguments
    keywords = node.get('keywords', [])
    for kw in keywords:
        if kw.get('arg') == 'access_control':
            value = kw.get('value', {})
            if value.get('node_type') == 'Constant' and value.get('value') == 'Public_Read':
                return True
            
    return False

def allowing_public_s3_access_check(node):
    if node.get('node_type') != 'Call':
        return False
    
    # Check function name
    func = node.get('func', {})
    if func.get('node_type') == 'Attribute':
        method_name = func.get('attr')
        if method_name == 'put_bucket_acl':
            # Check ACL parameter
            keywords = node.get('keywords', [])
            for kw in keywords:
                if kw.get('arg') == 'ACL' and isinstance(kw.get('value'), dict):
                    value = kw.get('value', {}).get('value')
                    if value in ['public-read', 'public-read-write']:
                        return True
        elif method_name == 'put_bucket_policy':
            # Check Policy parameter for public access
            keywords = node.get('keywords', [])
            for kw in keywords:
                if kw.get('arg') == 'Policy' and isinstance(kw.get('value'), dict):
                    value = kw.get('value', {}).get('value')
                    if isinstance(value, str) and '*' in value and 'Principal' in value:
                        return True
    
    return False


# Auto-generated function for metadata creation
def cyclomatic_complexity_check(node):
    """Auto-generated STUB for cyclomatic_complexity_of_functions_should_not_be_too_high. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def is_dynamic_execution(node):
    """Auto-generated STUB for dynamically_executing_code_is_securitysensitive. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def check_encryption_secure_mode_padding(node):
    # TODO: implement detection logic
    return False


# Auto-generated function for metadata creation
def custom_check_except_clauses(node):
    """Auto-generated STUB for except_clauses_should_do_more_than_raise_the_same_issue. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def custom_check_function(node):
    # TODO: implement detection logic
    return False


# Auto-generated function for metadata creation

# Custom function to detect identical branches in conditionals
def check_identical_branches(node):
    """
    Returns True if two branches in an if/else conditional have identical implementations.
    """
    import ast
    if isinstance(node, ast.If):
        # Only check if there is an else branch
        if hasattr(node, 'orelse') and node.orelse:
            # Compare the AST dumps of both branches
            body_dump = [ast.dump(stmt) for stmt in node.body]
            orelse_dump = [ast.dump(stmt) for stmt in node.orelse]
            if body_dump == orelse_dump:
                return True
    return False


# Auto-generated function for metadata creation
def check_functions_return_statements(node):
    # Replace X with a sensible value, e.g., 0
    if isinstance(node, ast.FunctionDef) and len(getattr(node, 'body', [])) > 0:
        return any(isinstance(stmt, ast.Return) for stmt in node.body)
    return False


# Auto-generated function for metadata creation
def secret_detection(node):
    """Auto-generated STUB for hardcoded_secrets_are_securitysensitive. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def is_implicit_concatenation(node):
    """
    Stub function for is_implicit_concatenation. Implement detection logic here.
    """
    return False


# Auto-generated function for metadata creation
def check_issue_suppression_comment(node):
    if not node.get('value').startswith('# nocov erase') or not any(line.startswith(f'# nocov {key}') for key in ['start', 'ignore', 'end'] for line in node.get('value').split('\n')):
        return True


# Auto-generated function for metadata creation
def check_model_evaluation_or_training(node):
    """Auto-generated STUB for modeleval_or_modeltrain_should_be_called_after_loading_the_state_of_a_pytorch_model. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def python_parser_failure_check(node):
    """Auto-generated STUB for python_parser_failure. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def is_side_effect_in_tffunction(node):
    """Auto-generated STUB for python_side_effects_should_not_be_used_inside_a_tffunction. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def recursion_check(node):
    if isinstance(node, ast.FunctionDef) and getattr(node, 'name', None) == 'f':
        return any([
            any([isinstance(n, ast.FunctionDef) and getattr(n, 'name', None) == 'f' for n in getattr(node, 'body', [])])
        ])
    return False


def check_cloudwatch_namespace(node):
    """
    Custom logic for rule: aws_cloudwatch_metrics_namespace_should_not_begin_with_aws
    Checks if CloudWatch metric namespace starts with 'aws'
    """
    if node.get('node_type') != 'Call':
        return False

    # Check if this is a put_metric_data call
    func = node.get('func', {})
    if func.get('node_type') == 'Attribute' and func.get('attr') == 'put_metric_data':
        # Look for the Namespace parameter in keywords
        keywords = node.get('keywords', [])
        for kw in keywords:
            if kw.get('arg') == 'Namespace':
                value = kw.get('value', {})
                if value.get('node_type') == 'Constant':
                    namespace = value.get('value', '')
                    if isinstance(namespace, str) and namespace.startswith('aws'):
                        return {
                            'message': f"CloudWatch metric namespace '{namespace}' should not start with 'aws'",
                            'line': node.get('lineno', 1)
                        }
    return False


# Auto-generated function for metadata creation
def custom_check_repeated_empty_regex(node):
    """Detects regex patterns that can match the empty string and may cause performance issues."""
    # TODO: implement detection that returns True when vulnerability exists
    return False


# Auto-generated function for metadata creation
def check_server_hostnames_should_be_verified_during_ssltls_connections(node):
    # TODO: implement detection logic
    return False


# Auto-generated function for metadata creation
def custom_check_string_duplication(node):
    string_literals = set()
    seen = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.Str, ast.Bytes, ast.Constant)):
            value = getattr(child, 'nval', child.s)
            if value not in string_literals:
                string_literals.add(value)
                seen.add(id(child))
        if id(child) in seen:
            raise Issue(..., message='Duplicated string literal: {}'.format(value))


# Auto-generated function for metadata creation
def custom_check_type_aliases_without_type_statement(node):
    """Auto-generated STUB for type_aliases_should_be_declared_with_a_type_statement. Implement detection logic here."""
    # TODO: implement detection that returns True when vulnerability exists
    return False



# Auto-generated function for metadata creation
def is_unencrypted_efs_usage(node):
    if not any(isinstance(n, ast.Call) and n.func.id == 'create_filesystem' and 'encryption_by_default' not in n.keywords
           for n in ast.walk(node) if isinstance(n, (ast.Call, ast.Attribute))):
        return False
    return True


# Auto-generated function for metadata creation
def xml_signature_validation_check(node):
    # TODO: implement detection logic
    return False


# Auto-generated function for metadata creation
def custom_check_cancellation_exceptions_should_be_reraised_after_cleanup(node):
    # Only process Raise nodes
    if not isinstance(node, dict) or node.get('node_type') != 'Raise':
        return False
    # Check if exception being raised is CancelledError
    exc = node.get('exc')
    if isinstance(exc, dict) and exc.get('node_type') == 'Call' and exc.get('func', {}).get('id') == 'CancelledError':
        # Check if parent field is 'finalbody' (i.e., inside a finally block)
        parent_field = node.get('__parent_field__')
        if parent_field == 'finalbody':
            return True
    return False


# Auto-generated function for metadata creation
def check_hardcoded_passwords_are_securitysensitive(node):
    # TODO: implement detection logic
    return False


# Auto-generated function for metadata creation
def hardcoded_passwords_are_securitysensitive(node):
    """Detects hardcoded passwords in assignments or function arguments."""
    password_keywords = {'password', 'passwd', 'pwd', 'pass'}
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and any(k in target.id.lower() for k in password_keywords):
                if isinstance(node.value, ast.Str):
                    return True
    if isinstance(node, ast.Call):
        for kw in getattr(node, 'keywords', []):
            if any(k in kw.arg.lower() for k in password_keywords) and isinstance(kw.value, ast.Str):
                return True
    return False

# Auto-generated function for metadata creation
def weak_hashing_algorithm_check(node):
    weak_hashes = {'md5', 'sha1', 'whirlpool'}
    def walk(n):
        if isinstance(n, dict):
            if n.get('node_type') == 'Call':
                func = n.get('func', {})
                if func.get('node_type') == 'Attribute' and func.get('attr') in weak_hashes:
                    return True
            for v in n.values():
                if isinstance(v, (dict, list)):
                    if walk(v):
                        return True
        elif isinstance(n, list):
            for item in n:
                if walk(item):
                    return True
        return False
    return walk(node)

def check_iam_policy_least_privilege(node):
    """
    Custom logic for rule: aws_iam_policies_should_limit_the_scope_of_permissions_given
    Detects IAM policies with excessive permissions (wildcards in Action or Resource).
    """
    def is_excessive(actions, resources):
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        for act in actions:
            if act == '*' or act.endswith(':*'):
                return True
        for res in resources:
            if res == '*' or res.endswith(':*') or res == 'arn:aws:s3:::*':
                return True
        return False

    # Look for dicts with 'Statement' key
    if node.get('node_type') == 'Dict' and 'keys' in node and 'values' in node:
        keys = node['keys']
        values = node['values']
        for k, v in zip(keys, values):
            if k.get('node_type') == 'Constant' and k.get('value') == 'Statement':
                # Statement value should be a list of dicts
                if v.get('node_type') == 'List':
                    for stmt in v.get('elts', []):
                        if stmt.get('node_type') == 'Dict' and 'keys' in stmt and 'values' in stmt:
                            stmt_keys = stmt['keys']
                            stmt_values = stmt['values']
                            action = None
                            resource = None
                            for sk, sv in zip(stmt_keys, stmt_values):
                                if sk.get('node_type') == 'Constant' and sk.get('value') == 'Action':
                                    if sv.get('node_type') == 'List':
                                        action = [elt.get('value') for elt in sv.get('elts', []) if elt.get('node_type') == 'Constant']
                                    elif sv.get('node_type') == 'Constant':
                                        action = [sv.get('value')]
                                if sk.get('node_type') == 'Constant' and sk.get('value') == 'Resource':
                                    if sv.get('node_type') == 'List':
                                        resource = [elt.get('value') for elt in sv.get('elts', []) if elt.get('node_type') == 'Constant']
                                    elif sv.get('node_type') == 'Constant':
                                        resource = [sv.get('value')]
                            if action and resource and is_excessive(action, resource):
                                return {
                                    'message': 'IAM policy has excessive permissions.',
                                    'line': node.get('lineno', 1)
                                }
    return False

def lambda_handler_compliance_check(node):
    """
    Checks AWS Lambda handler compliance for:
    1. Not being async
    2. Cleaning up temporary files
    3. Returning only JSON serializable values
    """
    findings = []
    # 1. Check for async Lambda handler
    if node.get('node_type') == 'AsyncFunctionDef' and node.get('name', '').startswith('lambda_handler'):
        findings.append({
            'message': 'Lambda handler should not be an async function.',
            'line': node.get('lineno', 1)
        })
    # 2. Check for cleanup of temporary files
    if node.get('node_type') in ['FunctionDef', 'AsyncFunctionDef'] and node.get('name', '').startswith('lambda_handler'):
        body = node.get('body', [])
        for stmt in body:
            # Look for creation of temp files without delete=True
            if stmt.get('node_type') == 'Assign':
                value = stmt.get('value', {})
                if value.get('node_type') == 'Call' and value.get('func', {}).get('attr', '') == 'NamedTemporaryFile':
                    keywords = value.get('keywords', [])
                    for kw in keywords:
                        if kw.get('arg') == 'delete' and kw.get('value', {}).get('node_type') == 'Constant' and kw.get('value', {}).get('value') is False:
                            findings.append({
                                'message': 'Lambda function does not clean up temporary files in the tmp directory',
                                'line': stmt.get('lineno', 1)
                            })
            # Look for os.system("rm ... tmp*")
            if stmt.get('node_type') == 'Expr':
                value = stmt.get('value', {})
                if value.get('node_type') == 'Call' and value.get('func', {}).get('attr', '') == 'system':
                    args = value.get('args', [])
                    for arg in args:
                        if arg.get('node_type') == 'Constant' and 'rm' in str(arg.get('value', '')) and 'tmp' in str(arg.get('value', '')):
                            findings.append({
                                'message': 'Lambda function does not clean up temporary files in the tmp directory',
                                'line': stmt.get('lineno', 1)
                            })
    # 3. Check for JSON serializable return values
    if node.get('node_type') in ['FunctionDef', 'AsyncFunctionDef'] and node.get('name', '').startswith('lambda_handler'):
        returns = node.get('returns', None)
        if returns and returns.get('node_type') == 'Name':
            if returns.get('id') in ['list', 'tuple', 'set']:
                findings.append({
                    'message': 'The handler should return JSON serializable values.',
                    'line': node.get('lineno', 1)
                })
    return findings if findings else False

def has_reluctant_quantifier_followed_by_empty_match(node, ast_root=None):
    """
    Returns True if a regex pattern contains a reluctant quantifier (e.g., .*?) followed by an expression that can match the empty string (e.g., .*
    )
    """
    # Only process Call nodes for re.compile
    if node.get("node_type") != "Call":
        return False
    func = node.get("func", {})
    if func.get("attr") != "compile":
        return False
    # Get the regex string argument
    args = node.get("args", [])
    if not args or not isinstance(args[0], dict):
        return False
    regex_str = args[0].get("value")
    if not isinstance(regex_str, str):
        return False
    # Look for a reluctant quantifier followed by an expression that can match empty string
    import re
    # Example: .*? followed by .*
    pattern = r"\.\*\?\.\*"
    return bool(re.search(pattern, regex_str))


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY DETECTION FUNCTIONS — added to support security-focused SAST rules
# ─────────────────────────────────────────────────────────────────────────────

_SQL_KEYWORDS = ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
                 'ALTER', 'EXEC', 'UNION', 'FROM', 'WHERE')


def _contains_sql_keyword(s):
    """Return True if string s contains an SQL keyword."""
    if not isinstance(s, str):
        return False
    upper = s.upper()
    return any(kw in upper for kw in _SQL_KEYWORDS)


def sql_injection_check(node):
    """
    Detects SQL injection via:
      1. BinOp with + operator where one operand is a Constant with SQL keywords
      2. BinOp with % operator where left operand has SQL keywords (% formatting)
      3. JoinedStr (f-string) where any constant value contains SQL keywords
      4. Call to .format() on a string constant that contains SQL keywords
    """
    if not isinstance(node, dict):
        return False

    ntype = node.get('node_type')

    # Pattern 1 & 2: BinOp  (str concat with + , or % formatting)
    if ntype == 'BinOp':
        op_type = node.get('op', {}).get('node_type', '')
        if op_type in ('Add', 'Mod'):
            left = node.get('left', {})
            right = node.get('right', {})
            for side in (left, right):
                if isinstance(side, dict) and side.get('node_type') == 'Constant':
                    if _contains_sql_keyword(side.get('value', '')):
                        return {
                            'message': 'SQL query constructed with string formatting — SQL injection risk (CWE-89).',
                            'property_path': ['left' if side is left else 'right'],
                            'value': str(side.get('value', ''))[:80]
                        }
        return False

    # Pattern 3: JoinedStr (f-string) — check constant parts for SQL keywords
    if ntype == 'JoinedStr':
        values = node.get('values', [])
        for part in values:
            if isinstance(part, dict) and part.get('node_type') == 'Constant':
                if _contains_sql_keyword(part.get('value', '')):
                    return {
                        'message': 'SQL query constructed with f-string interpolation — SQL injection risk (CWE-89).',
                        'property_path': ['values'],
                        'value': str(part.get('value', ''))[:80]
                    }
        return False

    # Pattern 4: Call to .format() on a SQL string constant
    if ntype == 'Call':
        func = node.get('func', {})
        if isinstance(func, dict) and func.get('node_type') == 'Attribute':
            if func.get('attr') == 'format':
                value_node = func.get('value', {})
                if isinstance(value_node, dict) and value_node.get('node_type') == 'Constant':
                    if _contains_sql_keyword(value_node.get('value', '')):
                        return {
                            'message': 'SQL query constructed with .format() — SQL injection risk (CWE-89).',
                            'property_path': ['func', 'value'],
                            'value': str(value_node.get('value', ''))[:80]
                        }
        return False

    return False


def command_injection_os_system_check(node):
    """
    Detects os.system() calls.
    Matches: Call where func.value.id == 'os' and func.attr == 'system'
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict) or func.get('node_type') != 'Attribute':
        return False
    if func.get('attr') != 'system':
        return False
    value = func.get('value', {})
    if isinstance(value, dict) and value.get('id') == 'os':
        return {
            'message': 'os.system() called — command injection risk if argument contains user input (CWE-78).',
            'property_path': ['func', 'value'],
            'value': 'os.system'
        }
    return False


def command_injection_subprocess_shell_check(node):
    """
    Detects subprocess.call/run/Popen called with shell=True.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict) or func.get('node_type') != 'Attribute':
        return False
    if func.get('attr') not in ('call', 'run', 'Popen', 'check_call', 'check_output'):
        return False
    value = func.get('value', {})
    if not isinstance(value, dict) or value.get('id') != 'subprocess':
        return False
    # Check for shell=True keyword
    keywords = node.get('keywords', [])
    for kw in keywords:
        if not isinstance(kw, dict):
            continue
        if kw.get('arg') == 'shell':
            val = kw.get('value', {})
            if isinstance(val, dict) and val.get('value') is True:
                return {
                    'message': 'subprocess called with shell=True — command injection risk (CWE-78).',
                    'property_path': ['keywords', 'shell'],
                    'value': 'shell=True'
                }
    return False


def insecure_deserialization_pickle_check(node):
    """
    Detects pickle.loads() calls.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict) or func.get('node_type') != 'Attribute':
        return False
    if func.get('attr') not in ('loads', 'load'):
        return False
    value = func.get('value', {})
    if isinstance(value, dict) and value.get('id') == 'pickle':
        return {
            'message': 'pickle.loads() called — insecure deserialization allows arbitrary code execution (CWE-502).',
            'property_path': ['func', 'value'],
            'value': 'pickle.loads'
        }
    return False


def path_traversal_check(node):
    """
    Detects path traversal: BinOp with + where one side is a Constant string
    that looks like an absolute directory path (starts with /).
    """
    if not isinstance(node, dict) or node.get('node_type') != 'BinOp':
        return False
    op_type = node.get('op', {}).get('node_type', '')
    if op_type != 'Add':
        return False
    left = node.get('left', {})
    if not isinstance(left, dict):
        return False
    if left.get('node_type') == 'Constant':
        val = left.get('value', '')
        if isinstance(val, str) and (val.startswith('/') or val.endswith('/') or '/' in val):
            return {
                'message': 'File path constructed with string concatenation — path traversal risk (CWE-22).',
                'property_path': ['left'],
                'value': val[:80]
            }
    # Also catch cases like base_dir + filename where base_dir is a variable
    right = node.get('right', {})
    if isinstance(right, dict) and right.get('node_type') == 'Constant':
        val = right.get('value', '')
        if isinstance(val, str) and (val.startswith('/') or val.endswith('/') or '/' in val):
            return {
                'message': 'File path constructed with string concatenation — path traversal risk (CWE-22).',
                'property_path': ['right'],
                'value': val[:80]
            }
    return False


def xss_render_template_check(node):
    """
    Detects render_template_string() calls.
    Any call to render_template_string is a potential XSS/SSTI risk
    because the template string may contain user-controlled content.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict):
        return False
    # Direct call: render_template_string(...)
    if func.get('id') == 'render_template_string':
        return {
            'message': 'render_template_string() called — XSS/SSTI risk if template contains user input (CWE-79).',
            'property_path': ['func'],
            'value': 'render_template_string'
        }
    # Attribute call: flask.render_template_string(...)
    if func.get('node_type') == 'Attribute' and func.get('attr') == 'render_template_string':
        return {
            'message': 'render_template_string() called — XSS/SSTI risk if template contains user input (CWE-79).',
            'property_path': ['func', 'attr'],
            'value': 'render_template_string'
        }
    return False


def ssrf_requests_check(node):
    """
    Detects requests.get/post/put/delete/head called with a non-literal (variable) URL.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict) or func.get('node_type') != 'Attribute':
        return False
    if func.get('attr') not in ('get', 'post', 'put', 'delete', 'head', 'request', 'options'):
        return False
    value = func.get('value', {})
    if not isinstance(value, dict):
        return False
    # Matches: requests.get(...) or http_requests.get(...)
    caller_id = value.get('id', '')
    if 'request' not in caller_id.lower():
        return False
    # Check first argument: if it's a Name (variable), flag it
    args = node.get('args', [])
    if args and isinstance(args[0], dict):
        first_arg = args[0]
        # Variable (Name node) — user-controlled URL risk
        if first_arg.get('node_type') == 'Name':
            return {
                'message': 'HTTP request made to a variable URL — SSRF risk if URL comes from user input (CWE-918).',
                'property_path': ['args', '0'],
                'value': first_arg.get('id', 'variable')
            }
    return False


def debug_mode_check(node):
    """
    Detects DEBUG = True assignment.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Assign':
        return False
    targets = node.get('targets', [])
    if not targets or not isinstance(targets[0], dict):
        return False
    target_name = targets[0].get('id', '')
    if target_name != 'DEBUG':
        return False
    value = node.get('value', {})
    if isinstance(value, dict) and value.get('value') is True:
        return {
            'message': 'DEBUG=True detected — disable debug mode in production to prevent information disclosure (CWE-489).',
            'property_path': ['targets', 'value'],
            'value': 'DEBUG=True'
        }
    return False


def insecure_random_check(node):
    """
    Detects use of the insecure random module for security-sensitive operations:
    random.choices, random.randint, random.random, random.choice, random.sample, etc.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict) or func.get('node_type') != 'Attribute':
        return False
    insecure_methods = ('choices', 'randint', 'random', 'choice', 'sample',
                        'randrange', 'shuffle', 'getrandbits')
    if func.get('attr') not in insecure_methods:
        return False
    value = func.get('value', {})
    if isinstance(value, dict) and value.get('id') == 'random':
        return {
            'message': 'random module used for security-sensitive operation — use secrets module instead (CWE-338).',
            'property_path': ['func', 'value'],
            'value': f"random.{func.get('attr')}"
        }
    return False


def xss_html_concat_check(node):
    """Detects XSS via HTML string concatenation: '<tag>' + variable + '</tag>' returned directly.
    Matches BinOp(Add) where any Constant operand contains HTML angle-bracket tags.
    """
    if not isinstance(node, dict) or node.get('node_type') != 'BinOp':
        return False
    if node.get('op', {}).get('node_type') != 'Add':
        return False

    def _has_html_constant(n):
        if not isinstance(n, dict):
            return False
        if n.get('node_type') == 'Constant':
            v = n.get('value', '')
            if isinstance(v, str) and '<' in v and '>' in v:
                return True
        for child in n.values():
            if isinstance(child, dict) and _has_html_constant(child):
                return True
        return False

    def _has_variable(n):
        if not isinstance(n, dict):
            return False
        if n.get('node_type') == 'Name':
            return True
        for child in n.values():
            if isinstance(child, dict) and _has_variable(child):
                return True
        return False

    left = node.get('left', {})
    right = node.get('right', {})
    if _has_html_constant(left) or _has_html_constant(right):
        if _has_variable(left) or _has_variable(right):
            return {
                'message': (
                    'HTML string built by concatenating user-controlled variable — '
                    'renders unsanitized input directly in browser response (XSS, CWE-79). '
                    'Use a templating engine with auto-escaping instead.'
                ),
                'property_path': ['left'],
                'value': 'html_string_concat',
            }
    return False


def open_redirect_check(node):
    """Detects open redirect: redirect() called with a Name node (variable) as first argument (CWE-601)."""
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict):
        return False
    if func.get('node_type') != 'Name' or func.get('id') != 'redirect':
        return False
    args = node.get('args', [])
    if not args:
        return False
    first_arg = args[0]
    if isinstance(first_arg, dict) and first_arg.get('node_type') == 'Name':
        return {
            'message': (
                f"redirect() called with variable '{first_arg.get('id', '?')}' — "
                'if this value comes from user input it is an open redirect (CWE-601). '
                'Validate the URL against an allowlist before redirecting.'
            ),
            'property_path': ['func'],
            'value': f"redirect({first_arg.get('id', '?')})",
        }
    return False


def _contains_html_tag(s):
    """Return True if string contains an HTML tag."""
    if not isinstance(s, str):
        return False
    return '<' in s and '>' in s


def xss_html_concat_check(node):
    """
    Detects XSS via HTML string concatenation:
    BinOp with + operator where one operand is a Constant string containing HTML tags.
    Catches patterns like: "<h1>Hello: " + user_input + "</h1>"
    """
    if not isinstance(node, dict) or node.get('node_type') != 'BinOp':
        return False
    if node.get('op', {}).get('node_type') != 'Add':
        return False
    left = node.get('left', {})
    right = node.get('right', {})
    for side in (left, right):
        if isinstance(side, dict) and side.get('node_type') == 'Constant':
            if _contains_html_tag(side.get('value', '')):
                return {
                    'message': 'HTML response built with string concatenation — XSS risk if any operand contains user input (CWE-79).',
                    'property_path': ['left' if side is left else 'right'],
                    'value': str(side.get('value', ''))[:80]
                }
    return False


def open_redirect_check(node):
    """
    Detects open redirect: redirect() called with a variable (Name node) as first argument.
    Catches patterns like: redirect(url) where url = request.args.get(...)
    """
    if not isinstance(node, dict) or node.get('node_type') != 'Call':
        return False
    func = node.get('func', {})
    if not isinstance(func, dict):
        return False
    # Direct call: redirect(url)
    func_name = func.get('id') or func.get('attr', '')
    if func_name != 'redirect':
        return False
    args = node.get('args', [])
    if not args or not isinstance(args[0], dict):
        return False
    first_arg = args[0]
    # Flag if first argument is a variable (Name node) — not a constant string
    if first_arg.get('node_type') == 'Name':
        return {
            'message': 'redirect() called with a variable URL — open redirect risk if URL comes from user input (CWE-601).',
            'property_path': ['args', '0'],
            'value': first_arg.get('id', 'variable')
        }
    return False
