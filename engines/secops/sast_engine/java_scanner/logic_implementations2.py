def custom_spring_avoid_combining_cacheable_and_cacheput(node):
    """Detects methods annotated with both @Cacheable and @CachePut."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Look for both @Cacheable and @CachePut annotations in the same method/class
            if '@Cacheable' in source and '@CachePut' in source:
                return True
    return False
def custom_spring_avoid_cache_annotations_on_abstract_classes(node):
    """Detects @Cache* annotations on abstract classes or interfaces."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for @Cacheable, @CachePut, or @CacheEvict annotation
            if re.search(r'@(Cacheable|CachePut|CacheEvict)', source):
                # Check if class is abstract or interface
                if re.search(r'(abstract\s+class|interface)', source):
                    return True
    return False
def custom_reliability_avoid_contradictory_regex_lookahead(node):
    """Detects contradictory regex lookahead assertions like (?=a)(?!a)."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for Pattern.compile with both (?=...) and (?!...) for the same character
            m = re.search(r'Pattern\.compile\(".*\(\?=([^"]+)\)\(\?!\1\).*"\)', source)
            if m:
                return True
    return False
def custom_maintainability_avoid_custom_getter_record(node):
    """Detects custom getter methods in Java records."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for 'record' declaration with a method that has the same name as a component
            if re.search(r'record\s+\w+\s*\(([^)]*)\)', source):
                # Find all component names
                m = re.search(r'record\s+\w+\s*\(([^)]*)\)', source)
                if m:
                    components = [c.strip().split()[-1] for c in m.group(1).split(',') if c.strip()]
                    for comp in components:
                        # Look for a method with the same name as a component
                        if re.search(r'public\s+\w+\s+' + re.escape(comp) + r'\s*\(', source):
                            return True
    return False
def custom_maintainability_avoid_complex_constants(node):
    """Detects methods returning Page or Slice without Pageable parameter."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for method returning Page or Slice without Pageable parameter
            if re.search(r'public\s+(Page|Slice)<\w+>\s+\w+\s*\([^)]*\)', source):
                if 'Pageable' not in source:
                    return True
    return False
def custom_maintainability_avoid_brain_method(node):
    """Detects methods that are too long (brain methods)."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Heuristic: if method has more than 50 lines, flag as brain method
            lines = source.split('\n')
            if len(lines) > 50:
                return True
    return False
def custom_bug_async_methods_should_return_void_or_future(node):
    """Detects @Async methods that do not return void or Future."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for @Async annotation and method declaration not returning void or Future
            if '@Async' in source:
                # Match method signature: public <type> <name>(...)
                m = re.search(r'public\s+(\w+)\s+\w+\s*\(', source)
                if m:
                    return_type = m.group(1)
                    if return_type not in ['void', 'Future']:
                        return True
    return False
def custom_android_intent_redirection(node):
    """Detects startActivity(intent) calls without validation."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for startActivity called with intent as argument, without any isTrustedSource or validation
            if re.search(r'startActivity\s*\(\s*intent\s*\)', source) and 'isTrustedSource' not in source:
                return True
    return False
def custom_check_array_index_out_of_bounds(node):
    """Detects array access with a constant out-of-bounds index like arr[5]."""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for array access with a numeric index (e.g., arr[5])
            if re.search(r'\w+\s*=\s*\w+\[\d+\]', source):
                return True
    return False
def check_vulnerability_excessive_lines_in_lambda(node):
    """Check for lambda expressions that have too many lines"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for lambda expressions with multiple lines
            lambda_matches = re.findall(r'->\s*\{[^}]*\}', source, re.DOTALL)
            for match in lambda_matches:
                # Count lines in the lambda body
                lines = match.split('\n')
                if len(lines) > 5:  # Threshold for too many lines
                    return True
    return False

def check_vulnerability_list_remove_ascending_for_loops(node):
    """Check for list.remove() calls in ascending for loops"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for for loops that increment and call remove()
            if re.search(r'for\s*\([^)]*\+\+[^)]*\).*\.remove\(', source, re.DOTALL):
                return True
            # Also check for explicit i++ patterns
            if 'for (' in source and '++' in source and '.remove(' in source:
                return True
    return False

def check_java_naming_convention_local_variable_and_method_parameter(node):
    """Check for local variables and parameters that don't follow camelCase convention"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for variable declarations and method parameters
            var_patterns = [
                r'\b(?:int|String|double|float|boolean|long)\s+([a-z_][A-Z_][a-zA-Z0-9_]*)\b',  # Bad: starts with lowercase then uppercase
                r'\b(?:int|String|double|float|boolean|long)\s+([A-Z][a-zA-Z0-9_]*)\b',  # Bad: starts with uppercase
                r'\b(?:int|String|double|float|boolean|long)\s+([a-z]+_[a-z]+)\b',  # Bad: uses underscores
            ]
            for pattern in var_patterns:
                if re.search(pattern, source):
                    return True
    return False

def check_java_refactor_lambda_to_method_reference(node):
    """Check for lambdas that should be method references"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for simple lambda patterns that could be method references
            method_ref_patterns = [
                r'x\s*->\s*System\.out\.println\(x\)',  # x -> System.out.println(x) should be System.out::println
                r'x\s*->\s*x\.toString\(\)',  # x -> x.toString() should be Object::toString
                r'x\s*->\s*Math\.abs\(x\)',  # x -> Math.abs(x) should be Math::abs
            ]
            for pattern in method_ref_patterns:
                if re.search(pattern, source):
                    return True
    return False

def check_security_check_ldap(node):
    """Check for LDAP authentication without proper security checks"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Look for LDAP connection without authentication
            ldap_patterns = [
                'LdapContext' in source and 'SECURITY_AUTHENTICATION' not in source,
                'InitialLdapContext' in source and 'simple' not in source,
                'DirContext' in source and 'bind(' not in source,
            ]
            if any(ldap_patterns):
                return True
    return False

def check_security_vulnerability_ldap(node):
    """Check for LDAP injection vulnerabilities"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Look for LDAP search with user input
            if ('search(' in source and 
                ('userInput' in source or 'request.getParameter(' in source or 'param' in source)):
                return True
            # Also check for string concatenation in LDAP filters
            if 'search(' in source and '+' in source and '"' in source:
                return True
    return False

def check_java_bug_long_lines(node):
    """Check for lines that exceed maximum length (typically 120 characters)"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            lines = source.split('\n')
            for line in lines:
                # Check line length, excluding leading whitespace for indentation
                if len(line.rstrip()) > 120:  # Standard line length limit
                    return True
    return False

def check_style_naming_conventions_local_constants(node):
    """Check for local constants that don't follow UPPER_CASE naming convention"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for final variable declarations (local constants)
            final_declarations = re.findall(r'final\s+\w+\s+(\w+)\s*=', source)
            for const_name in final_declarations:
                # Check if it follows UPPER_CASE convention
                if not re.match(r'^[A-Z][A-Z0-9_]*$', const_name):
                    return True
    return False

def check_style_lambda_single_statement(node):
    """Check for single-statement lambdas that are unnecessarily wrapped in blocks"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for lambda expressions with single statements in blocks
            # Pattern: x -> { single_statement; }
            lambda_patterns = [
                r'->\s*\{\s*[^{}]+;\s*\}',  # Simple single statement in block
                r'->\s*\{\s*return\s+[^{}]+;\s*\}',  # Single return statement in block
            ]
            for pattern in lambda_patterns:
                matches = re.findall(pattern, source)
                for match in matches:
                    # Make sure it's truly a single statement (no semicolons except the end)
                    content = match.strip('{}').strip()
                    semicolon_count = content.count(';')
                    if semicolon_count == 1:  # Only the ending semicolon
                        return True
    return False

def check_java_prevent_future_keyword_conflicts(node):
    """Check for use of future Java keywords like underscore"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Look for underscore used as variable name
            import re
            # Pattern for underscore as variable: Type _ = ... or parameter: method(Type _)
            if re.search(r'\b_\s*[=)]', source) or re.search(r'\(\s*\w+\s+_\s*\)', source):
                return True
    return False

def check_security_formatting_sql(node):
    """Check for SQL injection vulnerabilities in query formatting"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Look for SQL string concatenation patterns
            sql_patterns = [
                'createQuery(' in source and '+' in source,
                'prepareStatement(' in source and '+' in source,
                'String.format(' in source and ('SELECT' in source or 'FROM' in source or 'WHERE' in source),
                'executeQuery(' in source and '+' in source
            ]
            if any(sql_patterns):
                return True
    return False

def check_style_final_classes_should_not_have_protected_members(node):
    """Check for protected members in final classes"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if node.get('node_type') == 'Class' and 'final class' in source and 'protected' in source:
            return True
    return False

def check_vulnerability_check_format_strings(node):
    """Check for improper format string usage"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if 'printf' in source:
            # Look for format string issues
            if '"%' in source and (',' in source or ')' in source):
                # Basic check for format string usage
                return True
        # Also check for user input in format strings
        if ('printf(' in source and 'userInput' in source):
            return True
    return False

def check_bug_maintain_for_loop_counter(node):
    """Check for for-loops where counter is not updated in increment clause"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if 'for (' in source:
            # Look for for loops with empty increment clause
            import re
            # Pattern: for (type var = init; condition; ) or for (type var = init; condition; /* empty */)
            pattern = r'for\s*\(\s*\w+\s+\w+\s*=\s*[^;]+;\s*[^;]+;\s*\)\s*\{'
            if re.search(pattern, source):
                return True
    return False

def check_numeric_operations_bug_floating(node):
    """Check for direct equality comparisons on floating point numbers"""
    if isinstance(node, dict):
        source = node.get('source', '')
        # Look for floating point equality comparisons
        if source and ('==' in source or '!=' in source):
            # Check for float or double variables being compared
            if ('float ' in source or 'double ' in source or '.0' in source or 'f' in source):
                return True
    return False

def check_java_avoid_null_finalize(node):
    """Check for setting fields to null in finalize methods"""
    if isinstance(node, dict):
        source = node.get('source', '')
        # Look for Class nodes that contain finalize methods with null assignments
        if node.get('node_type') == 'Class' and 'finalize' in source and '= null' in source:
            return True
    return False

def check_bug_for_loop_termination_invariant(node):
    """Check for for-loops where termination condition variables are modified in loop body"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if 'for (' in source and 'limit' in source:
            # Simple check for modification of loop condition variables
            if 'limit++' in source or 'array =' in source:
                return True
    return False

def check_vulnerability_misleading_for_loop(node):
    """Check for for-loops where counter moves in wrong direction"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if 'for (' in source:
            # Look for misleading patterns in for loops
            if ('i < 10; i--' in source or 'j > 0; j++' in source):
                return True
            # Alternative regex patterns
            import re
            wrong_patterns = [
                r'i\s*<\s*\d+.*i--',  # i < number but i--
                r'j\s*>\s*\d+.*j\+\+',  # j > number but j++
            ]
            for pattern in wrong_patterns:
                if re.search(pattern, source, re.DOTALL):
                    return True
    return False

def check_code_quality_functional_specialized(node):
    """Check for unspecialized functional interface usage"""
    if isinstance(node, dict):
        source = node.get('source', '')
        # Look for generic Function usage where specialized versions exist
        unspecialized_patterns = [
            'Function<Integer, Integer>',  # Should use IntUnaryOperator
            'Function<String, Integer>',   # Should use ToIntFunction<String>
            'Predicate<Integer>',          # Should use IntPredicate
        ]
        return any(pattern in source for pattern in unspecialized_patterns)
    return False

def check_logged_and_rethrown_exceptions(node):
    """Check for logging and rethrowing exceptions in the same catch block"""
    if isinstance(node, dict):
        parent_source = node.get('parent_source', '')
        if 'catch' in parent_source and 'log' in parent_source and 'throw' in parent_source:
            # Look for both logging and throwing in the same parent source (catch block)
            if 'LOGGER.log' in parent_source and 'throw new' in parent_source:
                return True
    return False

def check_vulnerability_avoid_exception_testing_junit(node):
    """Check for @Test(expected=...) patterns in JUnit tests"""
    if isinstance(node, dict):
        source = node.get('source', '')
        # Look for @Test(expected=...) patterns
        if '@Test(' in source and 'expected' in source:
            return True
        # Also check individual nodes
        if node.get('node_type') == 'Annotation' and 'expected' in source:
            return True
    return False

def check_java_bug_rspec_2060(node):
    """Check for Externalizable classes without no-arg constructors"""
    if isinstance(node, dict):
        if node.get('node_type') == 'Class':
            source = node.get('source', '')
            # Check if class implements Externalizable
            if 'implements Externalizable' in source:
                # Check if there's a parameterized constructor but no no-arg constructor
                has_param_constructor = 'public ' in source and '(' in source and ')' in source
                has_noarg_constructor = 'public ' in source and '()' in source
                if has_param_constructor and not has_noarg_constructor:
                    return True
    return False

def check_security_expand_archive_files_security_sensitive(node):
    """Check for risky archive file expansion operations"""
    if isinstance(node, dict):
        source = node.get('source', '')
        # Look for zip extraction operations
        risky_patterns = [
            'ZipInputStream',
            'ZipEntry', 
            'getNextEntry',
            'TarInputStream',
            'unzip',
            'extract'
        ]
        if any(pattern in source for pattern in risky_patterns):
            return True
    return False

def check_vulnerability_avoid_side_effects_in_assert(node):
    """Check for side effects in assert expressions like method calls"""
    if isinstance(node, dict):
        if node.get('node_type') == 'MethodInvocation':
            source = node.get('source', '')
            # Look for assert methods with method calls in arguments
            if ('assertThat' in source or 'assertEquals' in source) and '()' in source:
                # Check if arguments contain method calls (side effects)
                if 'method()' in source or '.get(' in source or '.size()' in source:
                    return True
        # Also check Class nodes for assert patterns
        elif node.get('node_type') == 'Class':
            source = node.get('source', '')
            if 'assertThat' in source and ('method()' in source or '.get(' in source):
                return True
    return False

def check_vulnerability_avoid_unnecessary_exception_catch(node):
    """Check for catching broad Exception when more specific exceptions could be caught"""
    if isinstance(node, dict):
        if node.get('node_type') == 'TryStatement':
            source = node.get('source', '')
            # Look for catch (Exception e) patterns
            if 'catch (Exception' in source:
                return True
        elif node.get('node_type') == 'MethodInvocation' and 'catch (Exception' in node.get('source', ''):
            return True
    return False

def check_expression_complexity(node):
    """Check for overly complex expressions with too many logical operators"""
    if isinstance(node, dict):
        if node.get('node_type') == 'MethodInvocation' and node.get('name') == 'if':
            source = node.get('source', '')
            # Count logical operators: &&, ||, ? :
            logical_op_count = source.count('&&') + source.count('||')
            ternary_count = source.count('?')
            
            # Rule: more than 3 logical operators is too complex
            total_complexity = logical_op_count + ternary_count
            if total_complexity > 3:
                return True
    return False

def check_throw_in_finally(node):
    """Check for throw statements inside finally blocks"""
    if isinstance(node, dict):
        if node.get('node_type') == 'MethodInvocation' and node.get('name', '').startswith('throw new'):
            source = node.get('source', '')
            parent_source = node.get('parent_source', '')
            line_no = node.get('lineno', 0)
            
            # Split parent source into lines and find the current line
            lines = parent_source.split('\n')
            if line_no <= len(lines):
                # Check context around this line to see if it's in finally block
                # Look backwards from current line to find if we're in a finally block
                for i in range(min(line_no - 1, len(lines) - 1), -1, -1):
                    line = lines[i].strip()
                    if 'finally {' in line or line == 'finally {' or line.endswith('finally {'):
                        # We found a finally block start above us
                        return True
                    elif line.startswith('try {') or 'try {' in line:
                        # We found a try block, so we're not in finally
                        break
                    elif line == '}' and i > 0:
                        # Found a closing brace, check if it ends a try block
                        prev_line = lines[i-1].strip()
                        if 'throw' in prev_line:
                            # Previous line was a throw, this could be end of try block
                            continue
            return False
    return False

def custom_security_avoid_basic_auth_java(node):
    try:
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

def check_vuln_remove_empty_package_info(node):
    """Check for empty package statements like 'package;'"""
    if isinstance(node, dict):
        # Check the full source of the compilation unit
        if node.get('node_type') == 'CompilationUnit':
            source = node.get('source', '')
            if 'package;' in source:
                return True
        # Also check parent_source for any node
        parent_source = node.get('parent_source', '')
        if parent_source and 'package;' in parent_source:
            return True
    return False

def check_vulnerability_nonnull_equals_method(node):
    """Check for @Nonnull parameters in equals methods"""
    if isinstance(node, dict):
        if node.get('node_type') == 'MethodInvocation':
            source = node.get('source', '')
            # Look for equals method with @Nonnull parameter
            if 'equals(' in source and '@Nonnull' in source:
                return True
            if 'public boolean equals' in source and '@Nonnull' in source:
                return True
    return False

def check_security_use_secure_mode_and_padding_scheme(node):
    """Check for insecure cipher modes or padding schemes"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Look for insecure cipher configurations
            insecure_patterns = [
                'Cipher.getInstance("AES")',  # No mode/padding specified
                'Cipher.getInstance("DES")',  # Weak algorithm
                'Cipher.getInstance("RC4")',  # Weak algorithm
                '/ECB/',  # Insecure mode
                '/NONE/',  # No padding
            ]
            return any(pattern in source for pattern in insecure_patterns)
    return False

def check_security_xss_reflected_endpoints(node):
    """Check for XSS vulnerabilities in web endpoints"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            # Look for web endpoint annotations with request parameters
            if ('@RequestMapping' in source or '@GetMapping' in source or '@PostMapping' in source):
                # Check if method has request parameters that might be reflected
                if ('String' in source and 'return' in source and 
                    ('request.' in source or 'param' in source)):
                    return True
    return False

def check_java_vulnerability_s2973(node):
    """Check for escaped unicode characters used for printable characters"""
    if isinstance(node, dict):
        source = node.get('source', '')
        if source:
            import re
            # Look for unicode escape sequences like \u0041 for printable characters
            # Printable ASCII characters are in range \u0020-\u007E