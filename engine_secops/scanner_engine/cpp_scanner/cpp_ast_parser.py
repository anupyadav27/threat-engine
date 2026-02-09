"""
Enhanced C++ AST Parser using Tree-Sitter

This module replaces the regex-based AST extraction with a real C++ parser
while maintaining complete compatibility with the existing rule engine.

Features:
- Real C++ grammar parsing via tree-sitter
- Preprocessor macro expansion
- Build context awareness (compile_commands.json)
- Template parsing and instantiation
- Header dependency resolution
- Compatible AST node schema
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union
import re

# Tree-sitter imports with compatibility handling
try:
    import tree_sitter_cpp as tscpp
    from tree_sitter import Language, Parser, Node, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: tree-sitter not available: {e}")
    TREE_SITTER_AVAILABLE = False
    # Create dummy classes for fallback
    class Language: pass
    class Parser: pass
    class Node: pass
    class Tree: pass

# Compatibility imports for existing infrastructure
from dataclasses import dataclass


@dataclass
class BuildContext:
    """Build context information from compile_commands.json or defaults."""
    include_paths: List[str]
    defines: Dict[str, str]
    compiler_flags: List[str]
    standard: str = "c++17"
    
    @classmethod
    def from_compile_commands(cls, compile_commands_path: str, source_file: str) -> 'BuildContext':
        """Extract build context for a specific source file."""
        if not os.path.exists(compile_commands_path):
            return cls.default()
        
        try:
            with open(compile_commands_path, 'r') as f:
                commands = json.load(f)
            
            # Find entry for our source file
            for entry in commands:
                if source_file in entry.get('file', ''):
                    return cls._parse_command(entry.get('command', ''))
        except Exception:
            pass
        
        return cls.default()
    
    @classmethod
    def default(cls) -> 'BuildContext':
        """Default build context for standalone analysis."""
        return cls(
            include_paths=['/usr/include', '/usr/local/include'],
            defines={'__cplusplus': '201703L'},
            compiler_flags=['-std=c++17'],
            standard='c++17'
        )
    
    @classmethod
    def _parse_command(cls, command: str) -> 'BuildContext':
        """Parse compiler command to extract build context."""
        include_paths = []
        defines = {}
        flags = []
        standard = "c++17"
        
        # Split command respecting quotes
        parts = []
        current = ""
        in_quotes = False
        
        for char in command:
            if char == '"' and not in_quotes:
                in_quotes = True
            elif char == '"' and in_quotes:
                in_quotes = False
            elif char == ' ' and not in_quotes:
                if current:
                    parts.append(current)
                    current = ""
                continue
            current += char
        
        if current:
            parts.append(current)
        
        i = 0
        while i < len(parts):
            part = parts[i]
            if part.startswith('-I'):
                if len(part) > 2:
                    include_paths.append(part[2:])
                elif i + 1 < len(parts):
                    include_paths.append(parts[i + 1])
                    i += 1
            elif part.startswith('-D'):
                define_str = part[2:] if len(part) > 2 else parts[i + 1] if i + 1 < len(parts) else ""
                if '=' in define_str:
                    key, value = define_str.split('=', 1)
                    defines[key] = value
                else:
                    defines[define_str] = "1"
                if len(part) == 2:
                    i += 1
            elif part.startswith('-std='):
                standard = part[5:]
            
            flags.append(part)
            i += 1
        
        return cls(include_paths, defines, flags, standard)


class CppPreprocessor:
    """Handles C++ preprocessor directives and macro expansion."""
    
    def __init__(self, build_context: BuildContext):
        self.build_context = build_context
        self.included_files: Set[str] = set()
        self.macro_definitions: Dict[str, str] = build_context.defines.copy()
        
    def preprocess(self, source_code: str, source_file: str) -> Tuple[str, Dict[str, Any]]:
        """
        Preprocess C++ source code, handling includes and macros.
        
        Returns:
            - Preprocessed source code
            - Metadata about preprocessing (included files, active macros, etc.)
        """
        lines = source_code.split('\n')
        output_lines = []
        preprocessing_info = {
            'included_files': [],
            'active_macros': {},
            'conditional_blocks': [],
            'line_mapping': {}  # original_line -> preprocessed_line
        }
        
        original_line = 0
        output_line = 0
        conditional_stack = []  # Track #ifdef/#ifndef/#if states
        
        for line in lines:
            original_line += 1
            line_stripped = line.strip()
            
            if line_stripped.startswith('#'):
                directive_info = self._process_directive(line_stripped, source_file)
                
                if directive_info['type'] == 'include':
                    # Handle #include directive
                    included_content, included_info = self._handle_include(
                        directive_info['file'], source_file
                    )
                    if included_content:
                        preprocessing_info['included_files'].append(included_info)
                        # Add included content
                        for inc_line in included_content.split('\n'):
                            if inc_line.strip():
                                output_lines.append(inc_line)
                                preprocessing_info['line_mapping'][original_line] = output_line
                                output_line += 1
                
                elif directive_info['type'] == 'define':
                    # Handle #define directive
                    self.macro_definitions[directive_info['name']] = directive_info['value']
                    preprocessing_info['active_macros'][directive_info['name']] = directive_info['value']
                
                elif directive_info['type'] in ['ifdef', 'ifndef', 'if']:
                    # Handle conditional compilation
                    should_include = self._evaluate_condition(directive_info)
                    conditional_stack.append(should_include)
                    preprocessing_info['conditional_blocks'].append({
                        'line': original_line,
                        'condition': directive_info.get('condition', ''),
                        'active': should_include
                    })
                
                elif directive_info['type'] == 'endif':
                    if conditional_stack:
                        conditional_stack.pop()
                
                elif directive_info['type'] == 'else':
                    if conditional_stack:
                        conditional_stack[-1] = not conditional_stack[-1]
                
                # Don't include directive lines in output
                continue
            
            # Check if we're in an active conditional block
            if not conditional_stack or all(conditional_stack):
                # Expand macros in the line
                expanded_line = self._expand_macros(line)
                output_lines.append(expanded_line)
                preprocessing_info['line_mapping'][original_line] = output_line
                output_line += 1
        
        return '\n'.join(output_lines), preprocessing_info
    
    def _process_directive(self, line: str, source_file: str) -> Dict[str, Any]:
        """Process a preprocessor directive and return information about it."""
        line = line.strip()
        
        if line.startswith('#include'):
            match = re.match(r'#include\s*[<"](.*?)[>"]', line)
            if match:
                return {
                    'type': 'include',
                    'file': match.group(1),
                    'is_system': line.find('<') != -1
                }
        
        elif line.startswith('#define'):
            match = re.match(r'#define\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(.*)', line)
            if match:
                return {
                    'type': 'define',
                    'name': match.group(1),
                    'value': match.group(2).strip()
                }
        
        elif line.startswith('#ifdef'):
            match = re.match(r'#ifdef\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
            if match:
                return {
                    'type': 'ifdef',
                    'macro': match.group(1)
                }
        
        elif line.startswith('#ifndef'):
            match = re.match(r'#ifndef\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
            if match:
                return {
                    'type': 'ifndef', 
                    'macro': match.group(1)
                }
        
        elif line.startswith('#if'):
            return {
                'type': 'if',
                'condition': line[3:].strip()
            }
        
        elif line.startswith('#endif'):
            return {'type': 'endif'}
        
        elif line.startswith('#else'):
            return {'type': 'else'}
        
        return {'type': 'unknown', 'line': line}
    
    def _handle_include(self, include_file: str, source_file: str) -> Tuple[str, Dict[str, Any]]:
        """Handle #include directive and return included content."""
        if include_file in self.included_files:
            return "", {}  # Avoid circular includes
        
        # Find the include file
        include_path = self._resolve_include_path(include_file, source_file)
        if not include_path or not os.path.exists(include_path):
            return "", {}
        
        self.included_files.add(include_file)
        
        try:
            with open(include_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Recursively preprocess included file
            preprocessed_content, _ = self.preprocess(content, include_path)
            
            return preprocessed_content, {
                'file': include_file,
                'resolved_path': include_path,
                'size': len(content)
            }
        except Exception:
            return "", {}
    
    def _resolve_include_path(self, include_file: str, source_file: str) -> Optional[str]:
        """Resolve include file to actual file path."""
        # Try relative to source file first
        source_dir = os.path.dirname(source_file)
        relative_path = os.path.join(source_dir, include_file)
        if os.path.exists(relative_path):
            return relative_path
        
        # Try include paths
        for include_dir in self.build_context.include_paths:
            candidate = os.path.join(include_dir, include_file)
            if os.path.exists(candidate):
                return candidate
        
        return None
    
    def _evaluate_condition(self, directive_info: Dict[str, Any]) -> bool:
        """Evaluate conditional compilation directive."""
        if directive_info['type'] == 'ifdef':
            return directive_info['macro'] in self.macro_definitions
        elif directive_info['type'] == 'ifndef':
            return directive_info['macro'] not in self.macro_definitions
        elif directive_info['type'] == 'if':
            # Simplified evaluation - real preprocessor would be much more complex
            condition = directive_info['condition']
            # Handle basic defined() checks
            if 'defined(' in condition:
                for macro in re.findall(r'defined\(([a-zA-Z_][a-zA-Z0-9_]*)\)', condition):
                    condition = condition.replace(f'defined({macro})', 
                        '1' if macro in self.macro_definitions else '0')
            return bool(eval(condition.replace('&&', ' and ').replace('||', ' or ')) if condition.strip() else False)
        
        return True
    
    def _expand_macros(self, line: str) -> str:
        """Expand macros in a line of code."""
        result = line
        for macro, value in self.macro_definitions.items():
            # Simple macro replacement - real preprocessor is much more complex
            pattern = r'\b' + re.escape(macro) + r'\b'
            # Escape the replacement value to avoid regex interpretation issues
            escaped_value = value.replace('\\', r'\\').replace(r'\g', r'\\g')
            result = re.sub(pattern, escaped_value, result)
        return result


class EnhancedCppParser:
    """
    Enhanced C++ parser using tree-sitter that produces AST nodes compatible
    with the existing rule engine schema.
    """
    
    def __init__(self):
        if not TREE_SITTER_AVAILABLE:
            raise ImportError("tree-sitter not available")
            
        # Initialize tree-sitter C++ parser with version compatibility
        try:
            # Try newer tree-sitter API (language property)
            import tree_sitter
            self.parser = tree_sitter.Parser()
            self.language = tree_sitter.Language(tscpp.language())
            self.parser.language = self.language
        except Exception as e:
            try:
                # Try older tree-sitter API (set_language method)
                import tree_sitter
                self.parser = tree_sitter.Parser()
                self.language = tree_sitter.Language(tscpp.language())
                self.parser.set_language(self.language)
            except Exception as e2:
                raise ImportError(f"Failed to initialize tree-sitter parser: {e}, {e2}")
        
        # Node type mapping from tree-sitter to our schema
        self.node_type_mapping = {
            'translation_unit': 'TranslationUnit',
            'function_definition': 'FunctionDefinition',
            'function_declarator': 'FunctionDeclarator',
            'class_specifier': 'ClassDeclaration',
            'struct_specifier': 'StructDeclaration',
            'namespace_definition': 'NamespaceDeclaration',
            'template_declaration': 'TemplateDeclaration',
            'template_instantiation': 'TemplateInstantiation',
            'variable_declaration': 'VariableDeclaration',
            'parameter_declaration': 'ParameterDeclaration',
            'if_statement': 'IfStatement',
            'while_statement': 'WhileStatement',
            'for_statement': 'ForStatement',
            'call_expression': 'FunctionCall',
            'binary_expression': 'BinaryExpression',
            'unary_expression': 'UnaryExpression',
            'assignment_expression': 'Assignment',
            'using_declaration': 'UsingDeclaration',
            'preproc_include': 'PreprocessorDirective',
            'preproc_def': 'PreprocessorDirective',
            'lambda_expression': 'LambdaExpression',
            'try_statement': 'TryStatement',
            'catch_clause': 'CatchStatement',
            'throw_statement': 'ThrowStatement',
        }
    
    def parse_file_with_context(self, file_path: str, 
                               compile_commands_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse C++ file with full build context awareness.
        
        Returns AST compatible with existing rule engine while providing
        enhanced semantic information.
        """
        # Load build context
        build_context = BuildContext.default()
        if compile_commands_path:
            build_context = BuildContext.from_compile_commands(compile_commands_path, file_path)
        
        # Read source file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            original_source = f.read()
        
        # Preprocess the source
        preprocessor = CppPreprocessor(build_context)
        preprocessed_source, preprocessing_info = preprocessor.preprocess(original_source, file_path)
        
        # Parse with tree-sitter
        tree = self.parser.parse(bytes(preprocessed_source, 'utf8'))
        
        # Convert to compatible AST
        ast_root = self._convert_node_to_ast(tree.root_node, preprocessed_source, 
                                            original_source, preprocessing_info)
        
        # Add metadata for enhanced capabilities
        ast_root.update({
            'filename': file_path,
            'source': original_source,
            'preprocessed_source': preprocessed_source,
            'preprocessing_info': preprocessing_info,
            'build_context': {
                'include_paths': build_context.include_paths,
                'defines': build_context.defines,
                'compiler_flags': build_context.compiler_flags,
                'standard': build_context.standard
            },
            'line_count': len(original_source.splitlines()),
            'language': 'cpp',
            'parser_version': 'tree_sitter_enhanced'
        })
        
        return ast_root
    
    def _convert_node_to_ast(self, node: Node, source: str, original_source: str,
                           preprocessing_info: Dict[str, Any]) -> Dict[str, Any]:
        """Convert tree-sitter node to compatible AST format."""
        node_type = self.node_type_mapping.get(node.type, node.type)
        
        # Calculate line number in original source
        start_line = node.start_point[0] + 1
        original_line = self._map_to_original_line(start_line, preprocessing_info)
        
        # Extract node text
        node_text = source[node.start_byte:node.end_byte]
        
        # Build base AST node
        ast_node = {
            'node_type': node_type,
            'lineno': original_line,
            'start_line': start_line,
            'end_line': node.end_point[0] + 1,
            'start_column': node.start_point[1],
            'end_column': node.end_point[1],
            'source': node_text,
            'tree_sitter_type': node.type,  # Keep original for debugging
            'children': []
        }
        
        # Add type-specific information
        self._add_semantic_info(ast_node, node, source)
        
        # Process children
        for child in node.children:
            if not child.is_named:
                continue  # Skip punctuation and keywords
                
            child_ast = self._convert_node_to_ast(child, source, original_source, preprocessing_info)
            ast_node['children'].append(child_ast)
        
        return ast_node
    
    def _add_semantic_info(self, ast_node: Dict[str, Any], node: Node, source: str):
        """Add semantic information specific to node types."""
        node_type = node.type
        
        if node_type == 'function_definition':
            self._extract_function_info(ast_node, node, source)
        elif node_type in ['class_specifier', 'struct_specifier']:
            self._extract_class_info(ast_node, node, source)
        elif node_type == 'namespace_definition':
            self._extract_namespace_info(ast_node, node, source)
        elif node_type == 'template_declaration':
            self._extract_template_info(ast_node, node, source)
        elif node_type == 'variable_declaration':
            self._extract_variable_info(ast_node, node, source)
        elif node_type == 'call_expression':
            self._extract_call_info(ast_node, node, source)
    
    def _extract_function_info(self, ast_node: Dict[str, Any], node: Node, source: str):
        """Extract function-specific information."""
        ast_node['name'] = ''
        ast_node['return_type'] = ''
        ast_node['parameters'] = []
        ast_node['is_constructor'] = False
        ast_node['is_destructor'] = False
        ast_node['is_virtual'] = False
        ast_node['is_static'] = False
        ast_node['is_const'] = False
        ast_node['is_template'] = False
        
        # Find function declarator to extract name and parameters
        for child in node.children:
            if child.type == 'function_declarator':
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        ast_node['name'] = source[subchild.start_byte:subchild.end_byte]
                    elif subchild.type == 'parameter_list':
                        ast_node['parameters'] = self._extract_parameters(subchild, source)
            elif child.type in ['primitive_type', 'type_identifier', 'qualified_identifier']:
                ast_node['return_type'] = source[child.start_byte:child.end_byte]
        
        # Check for function modifiers
        function_text = source[node.start_byte:node.end_byte]
        ast_node['is_virtual'] = 'virtual' in function_text.split('{')[0]
        ast_node['is_static'] = 'static' in function_text.split('{')[0]
        ast_node['is_const'] = function_text.split('{')[0].strip().endswith('const')
    
    def _extract_class_info(self, ast_node: Dict[str, Any], node: Node, source: str):
        """Extract class/struct-specific information."""
        ast_node['name'] = ''
        ast_node['base_classes'] = []
        ast_node['members'] = []
        ast_node['is_template'] = False
        
        for child in node.children:
            if child.type == 'type_identifier':
                ast_node['name'] = source[child.start_byte:child.end_byte]
            elif child.type == 'base_class_clause':
                ast_node['base_classes'] = self._extract_base_classes(child, source)
            elif child.type == 'field_declaration_list':
                ast_node['members'] = self._extract_class_members(child, source)
    
    def _extract_namespace_info(self, ast_node: Dict[str, Any], node: Node, source: str):
        """Extract namespace-specific information."""
        ast_node['name'] = ''
        
        for child in node.children:
            if child.type == 'identifier':
                ast_node['name'] = source[child.start_byte:child.end_byte]
                break
    
    def _extract_template_info(self, ast_node: Dict[str, Any], node: Node, source: str):
        """Extract template-specific information."""
        ast_node['template_params'] = []
        ast_node['template_type'] = 'unknown'
        
        for child in node.children:
            if child.type == 'template_parameter_list':
                ast_node['template_params'] = self._extract_template_parameters(child, source)
            elif child.type in ['class_specifier', 'struct_specifier']:
                ast_node['template_type'] = 'class'
            elif child.type == 'function_definition':
                ast_node['template_type'] = 'function'
    
    def _extract_variable_info(self, ast_node: Dict[str, Any], node: Node, source: str):
        """Extract variable declaration information."""
        ast_node['name'] = ''
        ast_node['type'] = ''
        ast_node['is_const'] = False
        ast_node['is_static'] = False
        ast_node['is_reference'] = False
        ast_node['is_pointer'] = False
        
        declaration_text = source[node.start_byte:node.end_byte]
        ast_node['is_const'] = 'const' in declaration_text
        ast_node['is_static'] = 'static' in declaration_text
        ast_node['is_reference'] = '&' in declaration_text and not '&&' in declaration_text
        ast_node['is_pointer'] = '*' in declaration_text
    
    def _extract_call_info(self, ast_node: Dict[str, Any], node: Node, source: str):
        """Extract function call information."""
        ast_node['function_name'] = ''
        ast_node['arguments'] = []
        
        for child in node.children:
            if child.type == 'identifier':
                ast_node['function_name'] = source[child.start_byte:child.end_byte]
            elif child.type == 'argument_list':
                ast_node['arguments'] = self._extract_arguments(child, source)
    
    def _extract_parameters(self, param_list_node: Node, source: str) -> List[Dict[str, Any]]:
        """Extract function parameters."""
        parameters = []
        for child in param_list_node.children:
            if child.type == 'parameter_declaration':
                param_info = {'name': '', 'type': '', 'default_value': ''}
                # Extract parameter details
                for subchild in child.children:
                    if subchild.type == 'identifier':
                        param_info['name'] = source[subchild.start_byte:subchild.end_byte]
                    elif subchild.type in ['primitive_type', 'type_identifier']:
                        param_info['type'] = source[subchild.start_byte:subchild.end_byte]
                parameters.append(param_info)
        return parameters
    
    def _extract_base_classes(self, base_clause_node: Node, source: str) -> List[str]:
        """Extract base class names from inheritance clause."""
        base_classes = []
        for child in base_clause_node.children:
            if child.type == 'type_identifier':
                base_classes.append(source[child.start_byte:child.end_byte])
        return base_classes
    
    def _extract_class_members(self, members_node: Node, source: str) -> List[Dict[str, Any]]:
        """Extract class member information."""
        members = []
        # This would be a detailed implementation
        # For now, return basic structure
        return members
    
    def _extract_template_parameters(self, template_params_node: Node, source: str) -> List[str]:
        """Extract template parameter names."""
        params = []
        for child in template_params_node.children:
            if child.type == 'type_parameter_declaration':
                param_text = source[child.start_byte:child.end_byte]
                params.append(param_text.strip())
        return params
    
    def _extract_arguments(self, arg_list_node: Node, source: str) -> List[str]:
        """Extract function call arguments."""
        arguments = []
        for child in arg_list_node.children:
            if child.is_named:  # Skip commas
                arguments.append(source[child.start_byte:child.end_byte])
        return arguments
    
    def _map_to_original_line(self, preprocessed_line: int, 
                            preprocessing_info: Dict[str, Any]) -> int:
        """Map preprocessed line number back to original source line."""
        line_mapping = preprocessing_info.get('line_mapping', {})
        # Find the closest original line
        for orig_line, prep_line in line_mapping.items():
            if prep_line == preprocessed_line:
                return orig_line
        return preprocessed_line  # Fallback