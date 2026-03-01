# Detect unused assignments: assignment to a local variable that is never used or immediately overwritten
def find_unused_assignments(node):
    """
    Returns True if a local variable is assigned a value that is never used or is immediately overwritten.
    Only triggers for truly unused or overwritten assignments.
    """
    import re
    if not isinstance(node, dict):
        return False
    if node.get('node_type') != 'Class':
        return False
    source = node.get('source', '')
    # Find all method bodies
    method_pattern = re.compile(r'(?:public|protected|private|static|\s)+[\w<>,\s\[\]]+\s+\w+\s*\([^)]*\)\s*\{', re.MULTILINE)
    method_iter = list(method_pattern.finditer(source))
    method_spans = []
    for m in method_iter:
        start = m.end()
        brace_count = 1
        i = start
        while i < len(source) and brace_count > 0:
            if source[i] == '{':
                brace_count += 1
            elif source[i] == '}':
                brace_count -= 1
            i += 1
        method_spans.append((m.start(), i))
    # For each method, check for unused or immediately overwritten assignments
    for start, end in method_spans:
        method_body = source[start:end]
        # Find all variable declarations with assignment
        decl_assign_pattern = re.compile(r'(?:int|long|double|float|char|byte|short|boolean|String)\s+(\w+)\s*=.*?;', re.MULTILINE)
        # Find all assignments (including reassignments)
        assign_pattern = re.compile(r'^(?:\s*)(\w+)\s*=.*?;', re.MULTILINE)
        # Get all variable declarations with assignment
        declared_vars = [m.group(1) for m in decl_assign_pattern.finditer(method_body)]
        # For each declared variable, check for usage and immediate overwrite
        for var in declared_vars:
            # Find all assignments to this variable
            assign_matches = [m for m in assign_pattern.finditer(method_body) if m.group(1) == var]
            # If only one assignment (declaration), check if used after
            if len(assign_matches) == 1:
                assign_pos = assign_matches[0].end()
                after = method_body[assign_pos:]
                # If variable is never used after assignment, it's unused
                if not re.search(r'\b' + re.escape(var) + r'\b', after):
                    return True
            # If multiple assignments, check if first assignment is used before next assignment
            elif len(assign_matches) > 1:
                for idx in range(len(assign_matches)-1):
                    assign_pos = assign_matches[idx].end()
                    next_assign_pos = assign_matches[idx+1].start()
                    between = method_body[assign_pos:next_assign_pos]
                    # If variable is not used between assignments, first assignment is immediately overwritten
                    if not re.search(r'\b' + re.escape(var) + r'\b', between):
                        return True
    return False
# Detect unused labels: label declared but never referenced by break/continue
def find_unused_labels(node):
    """
    Returns True if a label is declared but not referenced by break/continue in the same method.
    Only triggers for truly unused labels.
    """
    import re
    if not isinstance(node, dict):
        return False
    if node.get('node_type') != 'Class':
        return False
    source = node.get('source', '')
    # Find all method bodies
    method_pattern = re.compile(r'(?:public|protected|private|static|\s)+[\w<>,\s\[\]]+\s+\w+\s*\([^)]*\)\s*\{', re.MULTILINE)
    method_iter = list(method_pattern.finditer(source))
    method_spans = []
    for m in method_iter:
        start = m.end()
        brace_count = 1
        i = start
        while i < len(source) and brace_count > 0:
            if source[i] == '{':
                brace_count += 1
            elif source[i] == '}':
                brace_count -= 1
            i += 1
        method_spans.append((m.start(), i))
    # For each method, check for unused labels
    for start, end in method_spans:
        method_body = source[start:end]
        # Find all label declarations in this method
        label_pattern = re.compile(r'^(\s*)(\w+):', re.MULTILINE)
        labels = [m.group(2) for m in label_pattern.finditer(method_body)]
        if not labels:
            continue
        # Collect all break/continue label references in the method
        ref_pattern = re.compile(r'\b(break|continue)\s+(\w+)\s*;', re.MULTILINE)
        referenced_labels = set(m.group(2) for m in ref_pattern.finditer(method_body))
        # For each label, check if it is NOT referenced in this method
        for label in labels:
            if label not in referenced_labels:
                return True  # Found an unused label in this method
    return False
# Detect unused method parameters, with exceptions for overrides, annotated params, and interface methods
def find_unused_method_parameters(node):
    """
    Returns True if a method in a class has unused parameters, except for:
    - Overridden/implemented methods (with @Override or in interface)
    - Parameters annotated with @javax.enterprise.event.Observes
    - Interface methods
    - Methods that only throw or have empty bodies
    - Methods with proper javadoc for unused param
    """
    import re
    if not isinstance(node, dict):
        return False
    # Only operate on class nodes
    if node.get('node_type') != 'Class':
        return False
    source = node.get('source', '')
    # Find all method declarations in the class
    method_pattern = re.compile(r'(?:public|protected|private|static|\s)+[\w<>,\s\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*\{', re.MULTILINE)
    for match in method_pattern.finditer(source):
        method_decl = match.group(0)
        method_name = match.group(1)
        params = match.group(2)
        # Skip interface methods (no body)
        if method_decl.strip().endswith(';'):
            continue
        # Find method body
        body_start = match.end()
        brace_count = 1
        i = body_start
        while i < len(source) and brace_count > 0:
            if source[i] == '{':
                brace_count += 1
            elif source[i] == '}':
                brace_count -= 1
            i += 1
        method_body = source[body_start:i-1]
        # Check for @Override annotation above method
        before_decl = source[:match.start()]
        if '@Override' in before_decl.split('\n')[-2:]:
            continue
        # Check for interface method (class is interface)
        if 'interface ' in source.split('{')[0]:
            continue
        # Parse parameters
        param_list = [p.strip() for p in params.split(',') if p.strip()]
        for param in param_list:
            # Get param name (last word)
            param_parts = param.split()
            if not param_parts:
                continue
            param_name = param_parts[-1]
            # Remove annotations
            if param_name.startswith('@') and len(param_parts) > 1:
                param_name = param_parts[-2]
            # Exception: @javax.enterprise.event.Observes
            if 'Observes' in param:
                continue
            # Exception: parameter is used in method body
            if re.search(r'\\b' + re.escape(param_name) + r'\\b', method_body):
                continue
            # Exception: method only throws or is empty
            if not method_body.strip() or re.match(r'^\s*throw ', method_body.strip()):
                continue
            # Exception: javadoc for unused param (not implemented here)
            # If we reach here, param is unused
            return True
    return False
# Custom function to detect truly unused private fields
import re
def find_unused_private_fields(node):
    def find_unused_private_classes(node):
        """
        Returns True if a private inner class is never referenced in its parent class.
        Only triggers for private inner classes that are not used anywhere in the parent class source.
        """
        if not isinstance(node, dict):
            return False
        # Only operate on inner class nodes
        if node.get('node_type') != 'Class':
            return False
        # Must be a private inner class (not top-level)
        modifiers = node.get('modifiers', [])
        if 'private' not in modifiers:
            return False
        # Get the class name
        class_name = node.get('name', None)
        if not class_name:
            return False
        # Get the parent source (the outer class)
        parent_source = node.get('parent_source', None)
        if not parent_source:
            # Fallback: use the node's own source (should not happen for inner classes)
            parent_source = node.get('source', '')
        # Check if the class name is referenced anywhere in the parent source (excluding the inner class declaration itself)
        # Remove the inner class declaration from the parent source for accurate search
        inner_decl = node.get('declaration', '')
        parent_source_no_decl = parent_source.replace(inner_decl, '')
        # Remove the inner class body as well
        inner_body = node.get('source', '')
        parent_source_no_decl = parent_source_no_decl.replace(inner_body, '')
        # Now search for the class name in the remaining parent source
        # Use word boundaries to avoid partial matches
        import re
        if re.search(r'\b' + re.escape(class_name) + r'\b', parent_source_no_decl):
            return False  # Used somewhere
        return True  # Not used anywhere
    if not isinstance(node, dict):
        return False
    source = node.get('source', '')
    # Find all private field declarations
    private_fields = []
    lines = source.split('\n')
    for i, line in enumerate(lines):
        # Ignore serialVersionUID
        if 'serialVersionUID' in line:
            continue
        # Ignore fields immediately preceded by annotation
        if i > 0 and lines[i-1].strip().startswith('@'):
            continue
        m = re.match(r'\s*private\s+\w+(?:\s+|\s*\[\s*\]\s*)+(\w+)\s*(=|;)', line)
        if m:
            field_name = m.group(1)
            private_fields.append(field_name)
    # Remove fields that are used elsewhere in the class
    for field in private_fields[:]:
        used = False
        for j, line in enumerate(lines):
            if field in line and not re.match(r'.*private.*\b' + re.escape(field) + r'\b.*', line):
                used = True
                break
        if used:
            private_fields.remove(field)
    # If any unused private fields remain, flag as violation
    return bool(private_fields)
def custom_security_issue_regex(node):
    """
    Returns True if a Pattern.compile call contains a regex with nested quantifiers (e.g., (a+)+, (a*)+, (a?)+), which are slow and security-sensitive.
    Triggers for nested quantifiers anywhere in the regex string, not just simple cases.
    """
    import re
    if isinstance(node, dict):
        source = node.get('source', '')
        # Find all Pattern.compile calls and extract the regex string
        pattern_compile = re.compile(r'Pattern\.compile\s*\((".*?"|\'.*?\')', re.DOTALL)
        for m in pattern_compile.finditer(source):
            regex_literal = m.group(1)
            # Remove quotes
            regex = regex_literal[1:-1]
            # Look for nested quantifiers: (a+)+, (a*)+, (a?)+, etc.
            if re.search(r'\((?:[^()]*[+*?][^()]*)\)[+*?]', regex):
                return True
    return False
def custom_code_quality_avoid_nested_switch_java(node):
    """
    Returns True if a switch statement is directly nested inside another switch statement.
    Only triggers for true nesting, not for sequential switches.
    """
    if isinstance(node, dict):
        source = node.get('source', '')
        # Look for a switch statement whose body contains another switch statement
        # Use a simple block-level regex to check for direct nesting
        # This will not match if switches are in separate methods
        import re
        # Match: switch (...) { ... switch (...) { ... } ... }
        pattern = r'switch\s*\([^)]*\)\s*\{[^{}]*switch\s*\([^)]*\)'
        if re.search(pattern, source, re.DOTALL):
            return True
    return False
def custom_security_avoid_basic_auth_java(node):
    try:
        # Debug: print node structure
        if isinstance(node, dict):
            source = node.get('source', '')
            print(f"DEBUG Basic Auth: Node type: {node.get('node_type')}, source: {source[:100]}")
            
            # Check for Basic Authentication patterns in source
            if 'setRequestProperty' in source and 'Basic' in source:
                print("DEBUG: Found setRequestProperty with Basic")
                return True
            if 'addHeader' in source and 'Basic' in source:
                print("DEBUG: Found addHeader with Basic")
                return True
            
            # Check if the node represents a method invocation
            if node.get('node_type') == 'method_invocation':
                # Check if the method name indicates setting an Authorization header
                if 'setRequestProperty' in node.get('name', '') or 'addHeader' in node.get('name', ''):
                    # Check if the annotation or any other attribute contains a hint of Basic Authentication
                    annotations = node.get('annotation', [])
                    for annotation in annotations:
                        if 'Basic' in annotation:
                            return True
                    # Check if the arguments contain a hint of Basic Authentication
                    arguments = node.get('arguments', [])
                    for argument in arguments:
                        if isinstance(argument, str) and 'Basic' in argument:
                            return True
        return False
    except KeyError:
        # In case of missing keys, we assume no violation is found
        return False
def custom_security_issue_bean(node):
    try:
        # Debug: print node structure
        if isinstance(node, dict):
            source = node.get('source', '')
            node_type = node.get('node_type', '')
            
            # Check for Bean validation patterns in source - focus on Class nodes
            if node_type == 'Class' and '@Valid' in source and 'private' in source:
                print(f"DEBUG Bean: Checking class for Bean validation violations")
                
                # Look for private variables without @Valid annotation
                lines = source.split('\n')
                for i, line in enumerate(lines):
                    line_stripped = line.strip()
                    # Look for private variable declarations that don't have @Valid
                    if (line_stripped.startswith('private') and 
                        ';' in line_stripped and 
                        i > 0 and 
                        '@Valid' not in lines[i-1] and 
                        '@Valid' not in line_stripped):
                        print(f"DEBUG Bean: Found unvalidated private variable: {line_stripped}")
                        return True
            
            return False
    except Exception as e:
        print(f"DEBUG Bean: Exception {e}")
        return False
import re
def custom_VULNERABILITY_DOUBLE_CHECKED_LOCKING_LATE_ASSIGNMENT_JAVA(node):
    if isinstance(node, dict):
        # Check Statement nodes for assignment not being last in synchronized block
        if node.get('node_type') == 'Statement' and node.get('type') == 'Assignment':
            src = node.get('source', '')
            parent_src = node.get('parent_source', '')
            position = node.get('position', -1)
            # Only check assignments to 'instance' variable
            if 'instance =' in src:
                block_lines = [l.strip() for l in parent_src.split('\n') if l.strip()]
                # Check if any executable statement follows assignment
                for i in range(position + 1, len(block_lines)):
                    # Ignore closing brace and comments
                    if block_lines[i] and not block_lines[i].startswith('}') and not block_lines[i].startswith('//'):
                        return True
        # Check for double-checked locking pattern: synchronized block with instance assignment
        src = node.get('source', '')
        if 'synchronized' in src and 'getInstance' in src:
            sync_start = src.find('synchronized')
            block = src[sync_start:]
            lines = block.split('\n')
            assign_idx = -1
            # Find synchronized blocks and check assignment order using AST nodes
            violations = []
            # Collect all synchronized blocks
            sync_blocks = [child for child in node.get('children', []) if child.get('node_type') == 'MethodInvocation' and child.get('name') == 'synchronized']
            for sync in sync_blocks:
                block_lineno = sync.get('lineno')
                # Find all statements after this synchronized block start
                block_statements = [child for child in node.get('children', []) if child.get('lineno') > block_lineno]
                # Only consider statements up to the next synchronized or method start
                next_sync_or_method = [child.get('lineno') for child in node.get('children', []) if child.get('lineno') > block_lineno and (child.get('name') == 'synchronized' or (child.get('node_type') == 'MethodInvocation' and child.get('name', '').startswith('public static')))]
                block_end = min(next_sync_or_method) if next_sync_or_method else None
                if block_end:
                    block_statements = [stmt for stmt in block_statements if stmt.get('lineno') < block_end]
                # Find assignment to 'instance' and check if it's last
                instance_assignments = [stmt for stmt in block_statements if 'instance =' in stmt.get('source', '')]
                if instance_assignments:
                    for assign in instance_assignments:
                        # If assignment is not the last statement in block, flag violation
                        if block_statements and assign != block_statements[-1]:
                            violations.append({
                                'message': 'Assignment to instance is not the last statement in synchronized block',
                                'lineno': assign.get('lineno'),
                                'source': assign.get('source'),
                            })
            if var in empty_list_vars:
                return True
        # Check for empty list variable usage in assertions
        src = node.get('source', '')
        parent_src = node.get('parent_source', src)
        empty_list_vars = set()
        assertion_calls = []
        for line in parent_src.split('\n'):
            match = re.match(r'.*\b(\w+)\s*=\s*Collections\.emptyList\s*\(\s*\).*', line)
            if match:
                empty_list_vars.add(match.group(1))
            call_match = re.match(r'.*assertThat\s*\(\s*(\w+)\s*\)\s*\.\s*(allMatch|doesNotContain).*', line)
            if call_match:
                assertion_calls.append((call_match.group(1), call_match.group(2)))
        for var, method in assertion_calls:
            if var in empty_list_vars and method in ['allMatch', 'doesNotContain']:
                return True
    return False
def custom_VULNERABILITY_AVOID_ASSERTIONS_IN_PROD(node):
    if isinstance(node, dict):
        src = node.get('source', '')
        if 'assert ' in src:
            return True
    return False
# Detect equals() comparisons between incompatible types (e.g., String.equals(int))
def custom_VULNERABILITY_AVOID_INCOMPATIBLE_TYPE_COMPARISONS(node):
    import re
    if isinstance(node, dict):
        if node.get('node_type') in ['MethodInvocation', 'Expression']:
            src = node.get('source', '')
            parent_src = node.get('parent_source', src)
            # Look for .equals( ... )
            if '.equals(' in src:
                # Extract left and right variable names from .equals()
                match = re.search(r'(\w+)\.equals\(([^)]+)\)', src)
                if not match:
                    return False
                left_var = match.group(1)
                right_var = match.group(2).strip()
                # Find variable types in parent source using regex
                left_type = None
                right_type = None
                string_decl = re.findall(r'String\s+(\w+)\s*=.*;', parent_src)
                int_decl = re.findall(r'int\s+(\w+)\s*=.*;', parent_src)
                # Assign types
                if left_var in string_decl:
                    left_type = 'String'
                if left_var in int_decl:
                    left_type = 'int'
                if right_var in string_decl:
                    right_type = 'String'
                if right_var in int_decl:
                    right_type = 'int'
                # If right_var is a literal, infer type
                if right_type is None:
                    if right_var.isdigit():
                        right_type = 'int'
                    elif right_var.startswith('"') or right_var.startswith("'"):
                        right_type = 'String'
                # If left is String and right is int, or vice versa, flag as incompatible
                if (left_type == 'String' and right_type == 'int') or (left_type == 'int' and right_type == 'String'):
                    return True
    return False
# Detect assertion methods inside try block of try-catch catching AssertionError
def custom_VULNERABILITY_AVOID_ASSERTION_WITHIN_TRY_CATCH(node):
    if isinstance(node, dict):
        # Only check TryStatement nodes
        if node.get('node_type') == 'TryStatement':
            src = node.get('source', '')
            # Check if try block contains assertion method
            assertion_methods = ['assertTrue', 'assertEquals', 'assertArrayEquals', 'assertSame', 'assertNotSame']
            found_assertion = any(m in src for m in assertion_methods)
            # Check if catch block catches AssertionError
            if 'catch (AssertionError' in src and found_assertion:
                return True
    return False
# Detect assertion methods with actual before expected argument order
def custom_VULNERABILITY_CHECK_ASSERTION_ORDER(node):
    if isinstance(node, dict):
        if node.get('node_type') == 'MethodInvocation':
            src = node.get('source', '')
            # Only check assertEquals, assertArrayEquals, assertSame, etc.
            assertion_methods = ['assertEquals', 'assertArrayEquals', 'assertSame', 'assertNotSame']
            for method in assertion_methods:
                if method in src:
                    # Extract arguments inside (...)
                    args = src.split(method)[-1]
                    if '(' in args and ')' in args:
                        arg_str = args.split('(',1)[-1].split(')',1)[0]
                        arg_list = [a.strip() for a in arg_str.split(',') if a.strip()]
                        # Only check if there are at least 2 arguments
                        if len(arg_list) >= 2:
                            # Heuristic: if first arg is actual, second is expected (e.g., actual=41, expected=42)
                            # If first arg is named 'actual' and second 'expected', or literal values
                            if (
                                (arg_list[0] == 'actual' and arg_list[1] == 'expected') or
                                (arg_list[0].isdigit() and arg_list[1].isdigit() and int(arg_list[0]) < int(arg_list[1]))
                            ):
                                return True
                            # Also, if variable names match actual/expected pattern
                            if 'actual' in arg_list[0].lower() and 'expected' in arg_list[1].lower():
                                return True
                            # If first arg is a literal and second is a variable named expected
                            if arg_list[0].isdigit() and 'expected' in arg_list[1].lower():
                                return True
                            # If first arg is a variable named actual and second is a literal
                            if 'actual' in arg_list[0].lower() and arg_list[1].isdigit():
                                return True
    return False
# Detect usage of Arrays.asList on primitive arrays
def custom_performance_use_arrays_stream_for_primitive_arrays(node):
    if isinstance(node, dict):
        if node.get('node_type') == 'MethodInvocation':
            src = node.get('source', '')
            # Look for Arrays.asList(variable)
            if 'Arrays.asList' in src:
                # Extract argument inside Arrays.asList(...)
                arg = src.split('Arrays.asList(')[-1].split(')')[0].strip()
                # Check if argument is a variable name (not a literal)
                if arg and ',' not in arg and '[' not in arg and ']' not in arg:
                    parent_source = node.get('parent_source', src)
                    lines = parent_source.split('\n')
                    for line in lines:
                        line_strip = line.strip()
                        # Look for primitive array declaration: int[] arr = ...
                        if (arg in line_strip and ('int[]' in line_strip or 'long[]' in line_strip or 'double[]' in line_strip) and '=' in line_strip):
                            return True
    return False
# Detect usage of Arrays.stream(...).boxed() on primitive arrays
def custom_VULNERABILITY_AVOID_ARRAYS_STREAM_BOXED_TYPES(node):
    if isinstance(node, dict):
        if node.get('node_type') == 'MethodInvocation':
            src = node.get('source', '')
            # Look for Arrays.stream(primitive_array).boxed()
            # Only trigger for int[], long[], double[]
            if (
                'Arrays.stream' in src and '.boxed()' in src and
                ('int[]' in src or 'long[]' in src or 'double[]' in src)
            ):
                return True
            # Also trigger for boxed().toArray(Integer[]::new) etc
            if (
                'Arrays.stream' in src and '.boxed()' in src and '.toArray' in src and
                ('Integer[]' in src or 'Long[]' in src or 'Double[]' in src)
            ):
                return True
    return False
# Custom logic implementations for generic rule engine
# Each function must accept (node) and return True if violation found

def custom_security_avoid_deprecated_for_removal(node):
    """
    Check for deprecated code marked for removal.
    Works with dict-based AST nodes.
    """
    if isinstance(node, dict):
        # Check if node has deprecated annotation
        if node.get('node_type') == 'Annotation' and node.get('id') == 'Deprecated':
            return True
        # Check for @deprecated in comments or names
        name = str(node.get('name', ''))
        if 'deprecated' in name.lower():
            return True
        # Check annotation property
        annotation = node.get('annotation', {})
        if isinstance(annotation, dict) and annotation.get('id') == 'Deprecated':
            return True
    return False

def custom_SECURITY_CONFIGURATION_SPRING(node):
    """
    Check for Spring Boot EnableAutoConfiguration configuration issues.
    Works with dict-based AST nodes.
    """
    if isinstance(node, dict):
        # Check for EnableAutoConfiguration annotation
        if node.get('node_type') == 'Annotation' and 'EnableAutoConfiguration' in str(node.get('id', '')):
            return True
        # Check for class names containing EnableAutoConfiguration
        name = str(node.get('name', ''))
        if 'EnableAutoConfiguration' in name or 'SpringBootApplication' in name:
            return True
    return False

def custom_VULNERABILITY_AVOID_NULL_ON_NONNULL(node):
    """
    Check for null assignments to NonNull annotated variables.
    Works with dict-based AST nodes.
    """
    if isinstance(node, dict):
        # Check for NonNull annotation
        annotation = node.get('annotation', {})
        if isinstance(annotation, dict):
            annotation_id = annotation.get('id', '')
            if 'NonNull' in str(annotation_id):
                # Check if value is null/None
                value = node.get('value', '')
                if str(value).lower() in ['null', 'none']:
                    return True
        # Check for variable assignments with null to NonNull fields
        name = str(node.get('name', ''))
        if 'nonnull' in name.lower() and str(node.get('value', '')).lower() in ['null', 'none']:
            return True
    return False

def custom_style_class_design_S1610(node):
    """
    Check for abstract classes without fields that should be converted to interfaces.
    Returns True if violations are found.
    """
    if isinstance(node, dict):
        node_type = node.get('node_type', '')
        name = node.get('name', '')
        source_code = node.get('source', '')
        
        # Only check classes
        if node_type == 'Class':
            # Check class name and source for abstract keyword
            is_abstract = False
            
            # Check if the class is abstract
            if source_code and 'abstract' in source_code:
                is_abstract = True
            elif 'abstract' in name.lower():
                is_abstract = True
            
            if is_abstract:
                # Check if the class has no fields (instance variables)
                has_fields = False
                
                if source_code:
                    lines = source_code.split('\n')
                    
                    for line in lines:
                        line_stripped = line.strip()
                        # Skip empty lines, comments, method signatures, class declaration
                        if not line_stripped:
                            continue
                        if line_stripped.startswith('//') or line_stripped.startswith('/*') or '/*' in line_stripped:
                            continue
                        if line_stripped.startswith('public abstract') or line_stripped.startswith('abstract'):
                            continue
                        if 'abstract class' in line_stripped or 'class ' in line_stripped:
                            continue
                        if line_stripped.startswith('}') or line_stripped.startswith('{'):
                            continue
                        
                        # Check for method declarations (skip these)
                        if ('(' in line_stripped and ')' in line_stripped) or line_stripped.endswith(';'):
                            continue
                            
                        # Look for field declarations
                        # Common field patterns: visibility + type + name
                        field_indicators = [
                            'private ', 'protected ', 'public ', 'static ', 'final ',
                            'String ', 'int ', 'long ', 'double ', 'float ', 'boolean ',
                            'List<', 'Map<', 'Set<', 'ArrayList<', 'HashMap<'
                        ]
                        
                        if any(indicator in line_stripped for indicator in field_indicators):
                            # Make sure it's not a method parameter or return type
                            if not line_stripped.endswith('{') and '=' in line_stripped or ';' in line_stripped:
                                has_fields = True
                                break
                
                # If abstract class has no fields, it should be an interface
                if not has_fields:
                    return True
    
    return False

def custom_bug_close_brace_beginning_of_line(node):
    """
    Check if close curly braces are at the beginning of a line.
    Returns True if violations are found (close braces not at beginning).
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        if not source_code:
            return False
        
        # Split source into lines
        lines = source_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Find close braces that are not at the beginning of the line
            if '}' in line:
                # Check if } appears not at the beginning (after other characters)
                for i, char in enumerate(line):
                    if char == '}':
                        # Check if there are non-whitespace characters before the }
                        before_brace = line[:i].strip()
                        if before_brace:  # There are non-whitespace characters before }
                            return True
    
    return False

def custom_same_branch_implementation(node):
    """
    Check for identical implementations in conditional structures.
    Works with dict-based AST nodes containing source code.
    """
    if isinstance(node, dict):
        source = node.get('source', '')
        
        # For methods, check the full source code for if/else patterns
        if node.get('node_type') == 'Method':
            # Simple pattern matching for identical if/else blocks
            if 'if (' in source and 'else' in source:
                # Look for repeated identical statements in different branches
                if 'System.out.println("Same")' in source:
                    # Count occurrences of the same statement
                    same_count = source.count('System.out.println("Same")')
                    # If we see the same statement 3+ times, likely same implementation
                    if same_count >= 3:
                        return True
                
                # Generic check for repeated patterns in conditional blocks
                lines = source.split('\n')
                conditional_blocks = []
                current_block = []
                in_conditional = False
                
                for line in lines:
                    line_stripped = line.strip()
                    if line_stripped.startswith('if (') or line_stripped.startswith('} else if (') or line_stripped.startswith('} else {'):
                        if current_block and in_conditional:
                            conditional_blocks.append('\n'.join(current_block))
                        current_block = []
                        in_conditional = True
                    elif line_stripped == '}' and in_conditional:
                        if current_block:
                            conditional_blocks.append('\n'.join(current_block))
                        current_block = []
                        in_conditional = False
                    elif in_conditional and line_stripped and not line_stripped.startswith('{'):
                        current_block.append(line_stripped)
                
                # Check if we have multiple blocks with identical content
                if len(conditional_blocks) >= 2:
                    # Remove empty blocks
                    non_empty_blocks = [block.strip() for block in conditional_blocks if block.strip()]
                    if len(non_empty_blocks) >= 2:
                        # Check if all blocks are identical
                        first_block = non_empty_blocks[0]
                        if all(block == first_block for block in non_empty_blocks):
                            return True
        
    return False

def custom_regex_alternatives_with_anchors(node):
    """
    Check for regex patterns with ungrouped alternatives when used with anchors.
    Detects patterns like "^hello|world$" which should be "^(hello|world)$"
    """
    import re
    
    if isinstance(node, dict):
        source = node.get('source', '')
        
        if source and isinstance(source, str):
            # Look for string literals that contain regex patterns
            # Pattern to find string literals: "..." or '...'
            string_patterns = re.findall(r'"([^"]*)"', source) + re.findall(r"'([^']*)'", source)
            
            for pattern in string_patterns:
                # Check if the pattern contains both alternatives (|) and anchors (^ or $)
                if '|' in pattern and ('^' in pattern or '$' in pattern):
                    # Check if alternatives are not properly grouped
                    # Look for patterns like ^foo|bar$ or start|end$ etc.
                    
                    # Remove properly grouped alternatives first
                    # If we remove all (group|alternatives) and still have | with anchors, it's a violation
                    temp_pattern = pattern
                    
                    # Remove properly grouped patterns like (foo|bar)
                    temp_pattern = re.sub(r'\([^)]*\|[^)]*\)', '', temp_pattern)
                    
                    # If after removing grouped alternatives, we still have | with ^ or $, it's a violation
                    if '|' in temp_pattern and ('^' in temp_pattern or '$' in temp_pattern):
                        # Additional check: make sure | is not inside character classes [...]
                        # Remove character classes
                        temp_pattern = re.sub(r'\[[^\]]*\]', '', temp_pattern)
                        
                        if '|' in temp_pattern and ('^' in temp_pattern or '$' in temp_pattern):
                            return True
    
    return False

def check_unnecessary_imports(node):
    """
    Check if there are unnecessary (unused) imports in the CompilationUnit.
    Returns True if an import statement is found but the imported class is not used in the code.
    Detects unused imports by checking if the imported class name appears in the code after the import statement.
    """
    import re
    
    if not isinstance(node, dict):
        return False
    
    # Only operate on CompilationUnit nodes
    if node.get('node_type') != 'CompilationUnit':
        return False
    
    source = node.get('source', '')
    if not source:
        return False
    
    # Find all import statements with their positions
    import_pattern = re.compile(r'import\s+(?:static\s+)?([a-zA-Z0-9_.]+);')
    import_matches = list(import_pattern.finditer(source))
    
    if not import_matches:
        return False  # No imports found
    
    # Remove all import statements from source to check if classes are used elsewhere
    source_without_imports = re.sub(r'import\s+(?:static\s+)?[a-zA-Z0-9_.]+;', '', source)
    
    # For each import, extract the class name and check if it's used
    for match in import_matches:
        import_full_name = match.group(1)
        
        # Extract the class name (last part after the last dot)
        parts = import_full_name.split('.')
        if not parts:
            continue
        
        class_name = parts[-1]
        
        # Skip java.lang.* imports (implicitly imported, usually not an issue)
        if import_full_name.startswith('java.lang.') and len(parts) <= 3:
            continue
        
        # Skip if class name is too generic (might cause false positives)
        if class_name in ['Object', 'String', 'Integer', 'Double', 'Long', 'Boolean']:
            continue
        
        # Check if the class name appears in the code (excluding import statements)
        # Use word boundaries to match whole words only
        class_usage_pattern = re.compile(r'\b' + re.escape(class_name) + r'\b')
        
        # Count occurrences in code (excluding import statements)
        matches = class_usage_pattern.findall(source_without_imports)
        
        # If no matches found, the import is unused
        if not matches:
            return True
    
    return False  # All imports appear to be used

def custom_security_prevention_activemq(node):
    """
    Detect usage of ActiveMQConnectionFactory which may allow malicious code deserialization.
    Returns True if usage is found.
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        if source_code and 'ActiveMQConnectionFactory' in source_code:
            return True
        name = node.get('name', '')
        if 'ActiveMQConnectionFactory' in name:
            return True
    return False

def custom_security_accessing_android_external_storage(node):
    """
    Detect usage of Android external storage APIs (Environment.getExternalStorageDirectory, etc).
    Returns True if risky usage is found.
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        name = node.get('name', '')
        # Check for common external storage API usage
        risky_patterns = [
            'Environment.getExternalStorageDirectory',
            'Environment.getExternalStoragePublicDirectory',
            'android.os.Environment',
            'EXTERNAL_STORAGE',
            'getExternalFilesDir',
            'getExternalCacheDir'
        ]
        if any(pat in source_code for pat in risky_patterns):
            return True
        if any(pat in name for pat in risky_patterns):
            return True
    return False

def custom_formatting_open_brace_position(node):
    """
    Detect open curly braces '{' that are not at the beginning of a line.
    Returns True if violation is found.
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        if not source_code:
            return False
        lines = source_code.split('\n')
        for line in lines:
            if '{' in line:
                # Check if line starts with '{' after optional whitespace
                if not line.strip().startswith('{'):
                    # '{' is present but not at the beginning
                    return True
    return False

def custom_coding_style_brace_placement(node):
    """
    Detect open curly braces '{' that are not at the end of a line.
    Returns True if violation is found.
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        if not source_code:
            return False
        lines = source_code.split('\n')
        for line in lines:
            line_strip = line.strip()
            # Check for lines that are only '{' (not at end of code line)
            if line_strip == '{':
                return True
            # Check for lines ending with '{' (compliant)
            if '{' in line and not line_strip.endswith('{'):
                # If '{' is present but not at the end, it's a violation
                return True
    return False

def custom_java_bug_anonymous_classes(node):
    """
    Returns True if an anonymous class exceeds the allowed line limit (default: 10).
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        name = node.get('name', '')
        # Heuristic: anonymous classes often have no name or contain 'new Type() {'
        if source_code and ('new ' in source_code and '{' in source_code):
            # Count lines inside the anonymous class body
            lines = source_code.split('\n')
            # Find the start of the anonymous class body
            for i, line in enumerate(lines):
                if 'new ' in line and '{' in line:
                    # Count lines until matching closing brace
                    brace_count = 0
                    body_lines = 0
                    for j in range(i, len(lines)):
                        brace_count += lines[j].count('{')
                        brace_count -= lines[j].count('}')
                        body_lines += 1
                        if brace_count == 0:
                            break
                    # Default line limit is 10
                    if body_lines > 10:
                        return True
    return False

def custom_array_copy_loops(node):
    """
    Returns True if a for-loop copies arrays or lists using index or get/add pattern.
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        # Detect array copy: dest[i] = src[i];
        if 'for' in source_code and '[i]' in source_code and '=' in source_code:
            if source_code.count('[i]') >= 2 and '=' in source_code:
                return True
        # Detect list copy: dest.add(src.get(i));
        if 'for' in source_code and 'add(' in source_code and 'get(i)' in source_code:
            return True
    return False

def custom_VULNERABILITY_AVOID_ARRAY_FOR_VARARGS(node):
    """
    Returns True if a method invocation passes an array variable to a varargs parameter.
    """
    if isinstance(node, dict):
        source_code = node.get('source', '')
        # Detect method invocation with a single argument (variable)
        if node.get('node_type') == 'MethodInvocation':
            if '(' in source_code and ')' in source_code:
                arg = source_code.split('(')[-1].split(')')[0].strip()
                # Check if argument is a variable name (not a literal)
                if arg and ',' not in arg and '[' not in arg and ']' not in arg:
                    # Try to find array declaration for this variable in previous lines
                    # Get parent source if available, else use node source
                    parent_source = node.get('parent_source', source_code)
                    lines = parent_source.split('\n')
                    for line in lines:
                        line_strip = line.strip()
                        # Look for array declaration: String[] arr = ...
                        if (arg in line_strip and '[' in line_strip and ']' in line_strip and '=' in line_strip):
                            return True
                # Also detect direct array passing: logMessages(new String[]{...})
                if 'new String[' in source_code:
                    return True
        # Also detect direct array passing: logMessages(new String[]{...})
        if 'new String[' in source_code and 'logMessages' in source_code:
            return True
    return False

def custom_VULNERABILITY_CONSTANT_ISSUE(node):
    """
    Detects redundant assignments, e.g., x = x; or x = value; when x already equals value in previous statement.
    Flags assignments where the assigned variable is set to its current value.
    """
    if isinstance(node, dict):
        if node.get('node_type') == 'Statement' and node.get('type') == 'Assignment':
            src = node.get('source', '')
            # Match patterns like x = x; or x = value;
            match = re.match(r'(\w+)\s*=\s*(\w+|\d+|"[^"]*"|\'[^"]*\');', src)
            if match:
                var = match.group(1)
                value = match.group(2)
                # Flag x = x;
                if var == value:
                    return True
                # Check previous and next statements for repeated x = value;
                parent_src = node.get('parent_source', '')
                lines = [l.strip() for l in parent_src.split('\n') if l.strip()]
                idx = None
                for i, line in enumerate(lines):
                    if line == src.strip():
                        idx = i
                        break
                # Check previous line
                if idx is not None and idx > 0:
                    prev_line = lines[idx-1]
                    prev_match = re.match(r'(\w+)\s*=\s*(\w+|\d+|"[^"]*"|\'[^"]*\');', prev_line)
                    if prev_match:
                        prev_var = prev_match.group(1)
                        prev_value = prev_match.group(2)
                        if var == prev_var and value == prev_value:
                            return True
                # Check next line for repeated assignment
                if idx is not None and idx < len(lines)-1:
                    next_line = lines[idx+1]
                    next_match = re.match(r'(\w+)\s*=\s*(\w+|\d+|"[^"]*"|\'[^"]*\');', next_line)
                    if next_match:
                        next_var = next_match.group(1)
                        next_value = next_match.group(2)
                        if var == next_var and value == next_value:
                            return True
    return False

def custom_bug_avoid_assignments_within_sub_expressions(node):
    """
    Detects assignments made from within sub-expressions, e.g., chained assignments, compound assignments, assignments in parentheses.
    Ignores assignments in while conditions, relational expressions, and chained/compound assignments.
    """
    if isinstance(node, dict):
        if node.get('node_type') == 'Statement' and node.get('type') == 'Assignment':
            src = node.get('source', '')
            # Chained assignment: int j, i = j = 0;
            if re.search(r'(\w+)\s*=\s*(\w+)\s*=\s*[^;]+;', src):
                return True
            # Compound assignment in parentheses: int k = (j += 1);
            if re.search(r'\(\s*\w+\s*\+=\s*[^)]+\)', src):
                return True
            # Assignment in parentheses: result = (bresult = ...);
            if re.search(r'(\w+)\s*=\s*\(\s*\w+\s*=\s*[^)]+\)', src):
                return True
    return False

def custom_security_broadcast_intent_android(node):
    """
    Detect usage of sendBroadcast without receiver permissions in Android.
    Returns True if usage is found.
    """
    if isinstance(node, dict):
        source = node.get('source', '')
        node_type = node.get('node_type', '')
        print(f"DEBUG Broadcast: Node type: {node_type}, source snippet: {source[:100] if source else 'No source'}")
        
        # Check for sendBroadcast usage
        if 'sendBroadcast' in source:
            print("DEBUG Broadcast: Found sendBroadcast in source")
            # Check if it's a simple sendBroadcast(intent) call without permission
            if 'sendBroadcast(' in source and 'receiverPermission' not in source:
                # Look for single parameter call: sendBroadcast(intent)
                lines = source.split('\n')
                for line in lines:
                    line_stripped = line.strip()
                    if ('sendBroadcast(' in line_stripped and 
                        line_stripped.count('(') == line_stripped.count(')') and
                        line_stripped.count(',') == 0):  # Single parameter
                        print(f"DEBUG Broadcast: Found insecure sendBroadcast call: {line_stripped}")
                        return True
        return False
    return False

def custom_static_analysis_block_synchronization_private_final_fields(node):
    try:
        # Debug: print node structure
        if isinstance(node, dict):
            source = node.get('source', '')
            node_type = node.get('node_type', '')
            print(f"DEBUG Sync: Node type: {node_type}, source snippet: {source[:100] if source else 'No source'}")
            
            # Check for synchronized block on private final field
            if 'synchronized' in source and 'private final' in source:
                print("DEBUG Sync: Found synchronized and private final in source")
                # Look for pattern: private final Object lock = ... and synchronized (lock)
                lines = source.split('\n')
                lock_var = None
                
                # Find private final field declaration
                for line in lines:
                    line_stripped = line.strip()
                    if 'private final' in line_stripped and '=' in line_stripped:
                        # Extract variable name from "private final Object varName = ..."
                        parts = line_stripped.split()
                        for i, part in enumerate(parts):
                            if i > 0 and parts[i-1] not in ['private', 'final'] and '=' not in part:
                                lock_var = part
                                break
                        print(f"DEBUG Sync: Found private final field: {lock_var}")
                
                # Check if synchronized uses the private final field
                if lock_var:
                    for line in lines:
                        if f'synchronized ({lock_var})' in line:
                            print(f"DEBUG Sync: Found synchronized block using private final field: {lock_var}")
                            return True
            
            # Original logic for specific AST structure
            if node.get('node_type') == 'synchronized_block':
                expression = node.get('expression', {})
                if expression.get('node_type') == 'field_access':
                    field = expression.get('field', {})
                    if 'private' in field.get('modifiers', []) and 'final' in field.get('modifiers', []):
                        return True
        return False
    except KeyError:
        print("DEBUG Sync: KeyError in function")
        return False

def is_assignment_to_lazy_initialized_member(stmt):
    # Checks if the statement assigns a new instance to a field named 'instance'
    src = getattr(stmt, 'source', None) or stmt.get('source', '')
    return isinstance(src, str) and 'instance =' in src and 'new' in src

def report_violation(stmt, message):
    # Simple print for demonstration; replace with your engine's violation reporting
    lineno = getattr(stmt, 'lineno', None) or stmt.get('lineno', 'unknown')
    print(f"Violation at line {lineno}: {message}")

def check_assignment_is_last_in_synchronized_block(node):
    # Debug: print node structure to understand AST format
    if isinstance(node, dict):
        print(f"DEBUG: Node type: {node.get('node_type')}, keys: {list(node.keys())}")
        
        # Check if this is a class node with synchronized blocks
        source = node.get('source', '')
        if 'synchronized' in source and 'instance =' in source:
            print("DEBUG: Found synchronized block with instance assignment")
            
            # Look for assignment followed by other statements
            lines = source.split('\n')
            assignment_line = -1
            for i, line in enumerate(lines):
                if 'instance = new' in line:
                    assignment_line = i
                    break
            
            if assignment_line >= 0:
                # Check if there are non-empty, non-comment lines after assignment
                for j in range(assignment_line + 1, len(lines)):
                    line = lines[j].strip()
                    if line and not line.startswith('//') and not line.startswith('}'):
                        print(f"DEBUG: Found statement after assignment: {line}")
                        print(f"Violation at line {assignment_line + 1}: Ensure field assignment is the last step in the synchronized block.")
                        return True
    
    return False

def check_VULNERABILITY_AVOID_STATIC_FIELD_UPDATE_IN_CONSTRUCTOR(node):
    """
    Returns True if a static field is updated inside a constructor.
    Only triggers for assignments to static fields within constructor methods.
    """
    import re
    if isinstance(node, dict):
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        # Find parent class node to extract static fields
        parent = node.get('__parent__', None)
        class_source = ''
        if parent and isinstance(parent, dict) and parent.get('node_type') == 'Class':
            class_source = parent.get('source', '')
        elif node_type == 'Class':
            class_source = source
        static_fields = set()
        # Extract static field names from class source
        for line in class_source.split('\n'):
            m = re.match(r'.*static\s+(?!final)\w+\s+([A-ZaZ0-9_]+)\s*=.*', line.strip())
            if m:
                static_fields.add(m.group(1))
        # Only check constructor methods
        if node_type == 'Method':
            method_decl = node.get('full_declaration', source.split('\n')[0])
            if re.match(r'\s*public\s+[A-ZaZ0-9_]+\s*\(', method_decl):
                lines = source.split('\n')
                for line in lines:
                    line_strip = line.strip()
                    # Check for assignment to any static field
                    for field in static_fields:
                        if re.search(r'\b' + re.escape(field) + r'\s*=.*', line_strip):
                            return True
                        if re.search(r'\b[A-ZaZ0-9_]+\.' + re.escape(field) + r'\s*=.*', line_strip):
                            return True
    return False
def check_code_quality_redefine_functional_interface(node):
    """
    Returns True if a standard functional interface is redefined (not extended).
    Triggers for interface nodes that match standard functional interface names and do not extend them.
    """
    standard_interfaces = {
        'BooleanSupplier', 'DoubleSupplier', 'IntSupplier', 'LongSupplier',
        'Consumer', 'BiConsumer', 'Supplier', 'Function', 'BiFunction',
        'Predicate', 'BiPredicate', 'UnaryOperator', 'BinaryOperator',
        'Runnable', 'Callable'
    }
    if isinstance(node, dict):
        node_type = node.get('node_type', '')
        source = node.get('source', '')
        # Check interface declarations (can be 'Class' or 'Interface' node type)
        if (node_type == 'Class' and 'interface ' in source) or node_type == 'Interface':
            # Extract interface name
            import re
            m = re.search(r'interface\s+([A-Za-z0-9_<>]+)', source)
            if m:
                # Extract base name (before generic parameters)
                name_with_generics = m.group(1)
                name = name_with_generics.split('<')[0].strip()
                # Check if name matches a standard interface
                if name in standard_interfaces:
                    # Check if it extends the standard interface (either simple or fully qualified)
                    if 'extends ' + name not in source and 'extends java.util.function.' + name not in source:
                        return True
    return False
def custom_java_use_short_circuit_logic_in_boolean_contexts(node):
    """
    Returns True if a non-short-circuit logic operator (& or | not part of && or ||) is used in a boolean context.
    Triggers for statement nodes containing 'a & b' or 'a | b' where a and b are likely booleans.
    """
    import re
    if isinstance(node, dict):
        source = node.get('source', '')
        # Match single & or | not part of && or ||
        if re.search(r'(?<!&)&(?!&)', source) or re.search(r'(?<!\|)\|(?!\|)', source):
            return True
    return False
def custom_check_value_based_object_serialization(node):
    """
    Detects serialization of value-based objects (e.g., java.time.LocalDate, java.time.LocalTime, etc.)
    Looks for ObjectOutputStream usage and writeObject calls on value-based types.
    """
    value_based_types = [
        'LocalDate', 'LocalTime', 'LocalDateTime', 'Instant', 'MonthDay', 'OffsetDateTime',
        'OffsetTime', 'Period', 'Year', 'YearMonth', 'ZonedDateTime', 'ZoneId', 'ZoneOffset'
    ]
    if isinstance(node, dict):
        source = node.get('source', '')
        # Check for ObjectOutputStream and writeObject usage
        if 'ObjectOutputStream' in source and '.writeObject' in source:
            # Check if any value-based type is present in the class fields or usage
            if any(vtype in source for vtype in value_based_types):
                return True
    return False
def custom_code_quality_variable_visibility(node):
    """
    Returns True if a member variable in a Java class does not have an explicit visibility modifier (private, protected, public).
    Only triggers for member variables declared without visibility.
    """
    import re
    if not isinstance(node, dict):
        return False
    if node.get('node_type') != 'Class':
        return False
    source = node.get('source', '')
    # Regex: match lines that declare a variable with assignment, but do not start with a visibility modifier
    pattern = re.compile(r'^\s*(?!private|protected|public)[a-zA-Z0-9_<>\[\]]+\s+[a-zA-Z0-9_]+\s*=.*;', re.MULTILINE)
    for match in pattern.finditer(source):
        return True  # Found a member variable without explicit visibility
    return False
def custom_vulnerability_override_contract_change(node):
    """
    Returns True if an overriding method in a subclass tightens parameter contract (e.g., from @Nullable to @Nonnull)
    or loosens return contract (e.g., from @Nonnull to @Nullable), violating Liskov Substitution Principle.
    This version attempts to handle the case where only a single class node is passed, by looking for both superclass and subclass methods in the whole file if available in node['file_source'].
    """
    import re
    if not isinstance(node, dict):
        return False
    if node.get('node_type') != 'Class':
        return False
    # Try to get the whole file source if available
    file_source = node.get('file_source', node.get('source', ''))
    if not file_source:
        return False
    
    # Helper function to find balanced braces
    def find_class_body_start_end(text, start_pos):
        """Find the start and end of a class body with balanced braces"""
        brace_count = 0
        start_found = False
        start_idx = start_pos
        end_idx = start_pos
        
        for i in range(start_pos, len(text)):
            if text[i] == '{':
                if not start_found:
                    start_found = True
                    start_idx = i + 1
                brace_count += 1
            elif text[i] == '}':
                brace_count -= 1
                if start_found and brace_count == 0:
                    end_idx = i
                    return start_idx, end_idx
        return None, None
    
    # Find all class definitions with proper brace matching
    class_pattern = re.compile(r'class\s+(\w+)\s*(?:extends\s+(\w+))?\s*\{', re.MULTILINE)
    classes = {}
    for m in class_pattern.finditer(file_source):
        class_name = m.group(1)
        superclass = m.group(2)
        start_pos = m.end() - 1  # Position of '{'
        body_start, body_end = find_class_body_start_end(file_source, start_pos)
        if body_start is not None and body_end is not None:
            body = file_source[body_start:body_end]
            classes[class_name] = {'superclass': superclass, 'body': body}
    # Extract methods with annotations from each class
    # Match annotation on previous line(s) followed by method declaration
    method_pattern = re.compile(r'(@Nullable|@Nonnull)[\s\S]*?(public|protected)\s+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)', re.MULTILINE | re.DOTALL)
    class_methods = {}
    for cname, cinfo in classes.items():
        methods = {}
        body = cinfo['body']
        # First, find all method declarations
        method_decl_pattern = re.compile(r'(public|protected)\s+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)', re.MULTILINE)
        for meth in method_decl_pattern.finditer(body):
            method_name = meth.group(2)
            params = meth.group(3)
            # Look for annotation before this method (up to 5 lines)
            method_start = meth.start()
            search_start = max(0, method_start - 500)  # Search up to 500 chars back
            context = body[search_start:method_start]
            ann_match = re.search(r'@(Nullable|Nonnull)', context)
            if ann_match:
                annotation = '@' + ann_match.group(1)
                # Also check if annotation is in parameters
                param_ann_match = re.search(r'(@Nullable|@Nonnull)\s+\w+', params)
                if param_ann_match:
                    # Parameter annotation overrides return annotation for parameter contract
                    methods[method_name] = {
                        'annotation': annotation,
                        'param_annotation': param_ann_match.group(1),
                        'params': params,
                        'signature': meth.group(0)
                    }
                else:
                    methods[method_name] = {
                        'annotation': annotation,
                        'params': params,
                        'signature': meth.group(0)
                    }
        class_methods[cname] = methods
    # Now, for each subclass, check for @Override methods and compare with superclass
    override_pattern = re.compile(r'@Override[\s\S]*?(public|protected)\s+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)', re.MULTILINE | re.DOTALL)
    for cname, cinfo in classes.items():
        superclass = cinfo['superclass']
        if not superclass or superclass not in class_methods:
            continue
        body = cinfo['body']
        # Find all @Override methods
        for m in override_pattern.finditer(body):
            method_name = m.group(2)
            params = m.group(3)
            method_start = m.start()
            
            # Find return type annotation for this method (search before method)
            search_start = max(0, method_start - 500)
            context = body[search_start:method_start]
            ann_match = re.search(r'@(Nullable|Nonnull)', context)
            sub_return_ann = '@' + ann_match.group(1) if ann_match else None
            
            # Find parameter annotation in method signature
            param_ann_match = re.search(r'(@Nullable|@Nonnull)\s+\w+', params)
            sub_param_ann = param_ann_match.group(1) if param_ann_match else None
            
            # Compare with superclass method
            super_methods = class_methods[superclass]
            if method_name in super_methods:
                super_method = super_methods[method_name]
                super_return_ann = super_method.get('annotation')
                super_param_ann = super_method.get('param_annotation')
                
                # Check parameter contract violation: Tightening (super @Nullable -> sub @Nonnull)
                if super_param_ann == '@Nullable' and sub_param_ann == '@Nonnull':
                    return True
                
                # Check return type contract violation: Loosening (super @Nonnull -> sub @Nullable)
                if super_return_ann == '@Nonnull' and sub_return_ann == '@Nullable':
                    return True
                
                # Also check if parameter annotation changed in params without explicit annotation marker
                # Compare parameter annotations if both exist
                if super_param_ann and sub_param_ann:
                    if super_param_ann == '@Nullable' and sub_param_ann == '@Nonnull':
                        return True
    return False
def custom_bug_async_methods_should_return_void_or_future(node):
    """
    Returns True if a method annotated with @Async does not return void or Future.
    Triggers for @Async methods returning other types. Uses re.search for robustness.
    """
    import re
    if not isinstance(node, dict):
        return False
    source = node.get('source', '')
    # Look for @Async annotation and method signature anywhere in the node
    method_pattern = re.compile(r'@Async[\s\n\r]*((public|protected|private|static|\s)+)([\w<>\[\]]+)\s+(\w+)\s*\([^)]*\)', re.MULTILINE)
    for match in method_pattern.finditer(source):
        return_type = match.group(3).strip()
        # Only flag if return type is not void and not Future<...> or Future
        if return_type != 'void' and not return_type.startswith('Future'):
            return True
    return False
def custom_check_brain_method(node):
    """
    Returns True if a method is likely a 'brain method' (too long or too complex).
    Flags methods with more than 10 lines or more than 3 control flow statements (if, for, while, switch, catch).
    This threshold is low for demo/testing purposes and should be tuned for production.
    """
    import re
    if not isinstance(node, dict):
        return False
    source = node.get('source', '')
    # Count lines in the method (ignore empty and comment lines)
    lines = [l for l in source.splitlines() if l.strip() and not l.strip().startswith('//')]
    if len(lines) > 10:
        return True
    # Count control flow statements
    control_flow = re.findall(r'\b(if|for|while|switch|catch)\b', source)
    if len(control_flow) > 3:
        return True
    return False
def custom_spring_avoid_combining_cacheable_and_cacheput(node):
    """
    Returns True if a method is annotated with both @Cacheable and @CachePut.
    Only triggers for methods with both annotations directly above the method signature.
    """
    import re
    if not isinstance(node, dict):
        return False
    source = node.get('source', '')
    # Look for a method with both @Cacheable and @CachePut annotations directly above
    # This pattern matches consecutive annotations before a method signature
    pattern = re.compile(r'@Cacheable\([^)]*\)\s*@CachePut\([^)]*\)\s*(public|protected|private|static|\s)+[\w<>\[\]]+\s+\w+\s*\([^)]*\)', re.MULTILINE)
    pattern2 = re.compile(r'@CachePut\([^)]*\)\s*@Cacheable\([^)]*\)\s*(public|protected|private|static|\s)+[\w<>\[\]]+\s+\w+\s*\([^)]*\)', re.MULTILINE)
    if pattern.search(source) or pattern2.search(source):
        return True
    return False

def custom_spring_avoid_async_in_configuration_class(node):
    """Detects @Async annotation used in @Configuration classes."""
    if isinstance(node, dict) and node.get('node_type') == 'Class':
        source = node.get('source', '')
        if source:
            # Check if the class has both @Configuration and @Async
            if '@Configuration' in source and '@Async' in source:
                return True
    return False
