"""
Go AST Parser Module

Enhanced Go parser using tree-sitter for accurate syntax parsing.
Provides real AST parsing capabilities for Go source code.
"""

import os
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

@dataclass
class GoContext:
    """Build context for Go parsing."""
    go_mod_path: Optional[str] = None
    build_tags: List[str] = None
    go_version: str = "1.19"
    
    def __post_init__(self):
        if self.build_tags is None:
            self.build_tags = []

class EnhancedGoParser:
    """Enhanced Go parser with AST generation."""
    
    def __init__(self):
        self.tree_sitter_available = self._check_tree_sitter()
    
    def _check_tree_sitter(self) -> bool:
        """Check if tree-sitter is available."""
        try:
            import tree_sitter
            import tree_sitter_go
            
            # Test that we can actually create a parser with correct API
            language = tree_sitter.Language(tree_sitter_go.language())
            parser = tree_sitter.Parser(language)
            return True
        except (ImportError, AttributeError, Exception) as e:
            print(f"Tree-sitter not available: {e}")
            print("Using fallback parser instead.")
            return False
    
    def parse_file_with_context(self, file_path: str, 
                              go_mod_path: Optional[str] = None,
                              build_context: Optional[str] = None) -> Dict[str, Any]:
        """Parse Go file with enhanced context."""
        
        if self.tree_sitter_available:
            return self._parse_with_tree_sitter(file_path, go_mod_path, build_context)
        else:
            return self._parse_fallback(file_path, go_mod_path, build_context)
    
    def _parse_with_tree_sitter(self, file_path: str, 
                               go_mod_path: Optional[str],
                               build_context: Optional[str]) -> Dict[str, Any]:
        """Parse using tree-sitter Go parser."""
        try:
            import tree_sitter
            import tree_sitter_go
            
            # Initialize parser with correct API
            language = tree_sitter.Language(tree_sitter_go.language())
            parser = tree_sitter.Parser(language)
            
            # Read source code
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Parse the source
            tree = parser.parse(source_code.encode('utf-8'))
            root_node = tree.root_node
            
            # Convert to our AST format
            ast = self._convert_tree_sitter_to_ast(root_node, source_code, file_path)
            
            # Add enhanced flag
            ast['enhanced_parsing'] = True
            ast['parser_type'] = 'tree_sitter'
            
            # Add context information
            if go_mod_path:
                ast['go_mod_path'] = go_mod_path
                ast['module_info'] = self._parse_go_mod(go_mod_path)
            
            if build_context:
                ast['build_context'] = build_context
            
            return ast
            
        except Exception as e:
            print(f"Tree-sitter parsing failed: {e}")
            return self._parse_fallback(file_path, go_mod_path, build_context)
    
    def _convert_tree_sitter_to_ast(self, node, source_code: str, file_path: str) -> Dict[str, Any]:
        """Convert tree-sitter node to AST format."""
        lines = source_code.split('\n')
        
        # Extract package name
        package_name = "main"
        for line in lines:
            if line.strip().startswith('package '):
                package_name = line.strip().split()[1]
                break
        
        ast = {
            'node_type': 'SourceFile',
            'filename': file_path,
            'package_name': package_name,
            'language': 'go',
            'line_count': len(lines),
            'source': source_code,
            'children': [],
            'imports': [],
            'functions': [],    # Add top-level functions array
            'variables': [],    # Add top-level variables array
            'types': []         # Add top-level types array
        }
        
        # Parse children recursively
        ast['children'] = self._parse_node_children(node, source_code)
        
        # Extract imports
        ast['imports'] = self._extract_imports(source_code)
        
        # Extract top-level elements for easier processing
        self._extract_toplevel_elements(ast, ast['children'])
        
        return ast
    
    def _parse_node_children(self, node, source_code: str) -> List[Dict[str, Any]]:
        """Parse child nodes recursively."""
        children = []
        
        for child in node.children:
            child_ast = {
                'node_type': child.type,
                'line': child.start_point[0] + 1,
                'column': child.start_point[1] + 1,
                'end_line': child.end_point[0] + 1,
                'end_column': child.end_point[1] + 1,
                'source_text': source_code[child.start_byte:child.end_byte],
                'children': self._parse_node_children(child, source_code)
            }
            
            # Add node-specific properties
            if child.type == 'function_declaration':
                child_ast['properties'] = self._extract_function_properties(child, source_code)
            elif child.type == 'variable_declaration':
                child_ast['properties'] = self._extract_variable_properties(child, source_code)
            elif child.type == 'call_expression':
                child_ast['properties'] = self._extract_call_properties(child, source_code)
            
            children.append(child_ast)
        
        return children
    
    def _extract_toplevel_elements(self, ast: Dict[str, Any], children: List[Dict[str, Any]]) -> None:
        """Extract top-level functions, types, and variables for easier processing."""
        
        def walk_nodes(nodes):
            for node in nodes:
                if node['node_type'] == 'function_declaration':
                    # Convert to expected function format
                    func_info = {
                        'node_type': 'function',
                        'name': node.get('properties', {}).get('name', 'unknown'),
                        'line': node.get('line', 0),
                        'column': node.get('column', 0),
                        'end_line': node.get('end_line', 0),
                        'parameters': self._parse_function_parameters(node),
                        'return_types': self._parse_function_returns(node),
                        'source_text': node.get('source_text', ''),
                        'is_exported': node.get('properties', {}).get('is_exported', False),
                        'ast_node': node
                    }
                    ast['functions'].append(func_info)
                    
                elif node['node_type'] == 'variable_declaration' or node['node_type'] == 'short_var_declaration':
                    var_info = {
                        'node_type': 'variable',
                        'name': node.get('properties', {}).get('name', 'unknown'),
                        'line': node.get('line', 0),
                        'type': node.get('properties', {}).get('type', 'unknown'),
                        'ast_node': node
                    }
                    ast['variables'].append(var_info)
                    
                elif node['node_type'] == 'type_declaration':
                    type_info = {
                        'node_type': 'type',
                        'name': node.get('properties', {}).get('name', 'unknown'),
                        'line': node.get('line', 0),
                        'ast_node': node
                    }
                    ast['types'].append(type_info)
                
                # Recursively walk children
                if 'children' in node:
                    walk_nodes(node['children'])
        
        walk_nodes(children)
    
    def _parse_function_parameters(self, func_node: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse function parameters from AST node."""
        # Simple parameter parsing from source text
        source_text = func_node.get('source_text', '')
        param_match = re.search(r'\((.*?)\)', source_text.split('\n')[0])
        
        if not param_match:
            return []
            
        params_str = param_match.group(1).strip()
        if not params_str:
            return []
        
        parameters = []
        # Simple parameter splitting (doesn't handle complex types)
        for param in params_str.split(','):
            param = param.strip()
            if param:
                parts = param.split()
                if len(parts) >= 2:
                    parameters.append({
                        'name': parts[0],
                        'type': parts[1],
                        'node_type': 'parameter'
                    })
        
        return parameters
    
    def _parse_function_returns(self, func_node: Dict[str, Any]) -> List[str]:
        """Parse function return types from AST node."""
        # Simple return type parsing from source text
        source_text = func_node.get('source_text', '')
        first_line = source_text.split('\n')[0]
        
        # Look for return type after closing parenthesis
        return_match = re.search(r'\)[^{]*?(\w+)\s*\{', first_line)
        if return_match:
            return [return_match.group(1)]
        
        return []
        
        return children
    
    def _extract_function_properties(self, node, source_code: str) -> Dict[str, Any]:
        """Extract function-specific properties."""
        source_text = source_code[node.start_byte:node.end_byte]
        
        # Extract function name
        name_match = re.search(r'func\s+(\w+)', source_text)
        name = name_match.group(1) if name_match else 'unknown'
        
        # Extract parameters
        param_match = re.search(r'func\s+\w+\s*\((.*?)\)', source_text, re.DOTALL)
        parameters = param_match.group(1) if param_match else ''
        
        return {
            'name': name,
            'parameters': parameters.strip(),
            'is_exported': name[0].isupper() if name != 'unknown' else False
        }
    
    def _extract_variable_properties(self, node, source_code: str) -> Dict[str, Any]:
        """Extract variable-specific properties."""
        source_text = source_code[node.start_byte:node.end_byte]
        
        # Simple variable extraction
        if 'var ' in source_text:
            var_match = re.search(r'var\s+(\w+)', source_text)
            name = var_match.group(1) if var_match else 'unknown'
        else:
            name = 'unknown'
        
        return {
            'name': name,
            'type': 'variable'
        }
    
    def _extract_call_properties(self, node, source_code: str) -> Dict[str, Any]:
        """Extract call expression properties."""
        source_text = source_code[node.start_byte:node.end_byte]
        
        # Extract function being called
        func_match = re.search(r'(\w+(?:\.\w+)*)\s*\(', source_text)
        function = func_match.group(1) if func_match else 'unknown'
        
        properties = {'function': function}
        
        # Classify risk category
        if 'exec.Command' in function:
            properties['risk_category'] = 'command_injection'
        elif any(db_func in function for db_func in ['sql.Open', 'db.Query', 'db.Exec']):
            properties['risk_category'] = 'sql_injection'
        elif any(crypto_func in function for crypto_func in ['aes.NewCipher', 'md5.New']):
            properties['risk_category'] = 'crypto_weakness'
        
        return properties
    
    def _extract_imports(self, source_code: str) -> List[str]:
        """Extract import statements."""
        imports = []
        lines = source_code.split('\n')
        in_import_block = False
        
        for line in lines:
            line = line.strip()
            if line == 'import (':
                in_import_block = True
            elif line == ')' and in_import_block:
                in_import_block = False
            elif in_import_block:
                if line and not line.startswith('//'):
                    # Extract package path
                    import_match = re.search(r'"([^"]+)"', line)
                    if import_match:
                        imports.append(import_match.group(1))
            elif line.startswith('import '):
                # Single import
                import_match = re.search(r'"([^"]+)"', line)
                if import_match:
                    imports.append(import_match.group(1))
        
        return imports
    
    def _parse_fallback(self, file_path: str, 
                       go_mod_path: Optional[str],
                       build_context: Optional[str]) -> Dict[str, Any]:
        """Fallback parser when tree-sitter is not available."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
                
            lines = source_code.split('\n')
            
            # Extract package name
            package_name = "main"
            for line in lines:
                if line.strip().startswith('package '):
                    package_name = line.strip().split()[1]
                    break
            
            # Basic AST structure
            ast = {
                'node_type': 'SourceFile',
                'filename': file_path,
                'package_name': package_name,
                'language': 'go',
                'line_count': len(lines),
                'source': source_code,
                'children': self._parse_fallback_children(lines),
                'imports': self._extract_imports(source_code),
                'enhanced_capabilities': False
            }
            
            if go_mod_path:
                ast['go_mod_path'] = go_mod_path
                ast['module_info'] = self._parse_go_mod(go_mod_path)
                
            return ast
            
        except Exception as e:
            return {
                'node_type': 'SourceFile',
                'filename': file_path,
                'package_name': 'unknown',
                'language': 'go',
                'line_count': 0,
                'source': '',
                'children': [],
                'imports': [],
                'error': str(e),
                'enhanced_capabilities': False
            }
    
    def _parse_fallback_children(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse children using regex fallback."""
        children = []
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Function declarations
            if line_stripped.startswith('func '):
                func_match = re.match(r'func\s+(\w+)\s*\((.*?)\)', line_stripped)
                if func_match:
                    children.append({
                        'node_type': 'function_declaration',
                        'line': i,
                        'column': 1,
                        'source_text': line_stripped,
                        'properties': {
                            'name': func_match.group(1),
                            'parameters': func_match.group(2),
                            'is_exported': func_match.group(1)[0].isupper()
                        },
                        'children': []
                    })
            
            # Variable declarations  
            elif line_stripped.startswith('var ') or ':=' in line_stripped:
                var_name = 'unknown'
                if line_stripped.startswith('var '):
                    var_match = re.search(r'var\s+(\w+)', line_stripped)
                    var_name = var_match.group(1) if var_match else 'unknown'
                elif ':=' in line_stripped:
                    var_match = re.search(r'(\w+)\s*:=', line_stripped)
                    var_name = var_match.group(1) if var_match else 'unknown'
                
                children.append({
                    'node_type': 'variable_declaration',
                    'line': i,
                    'column': 1,
                    'source_text': line_stripped,
                    'properties': {
                        'name': var_name,
                        'type': 'variable'
                    },
                    'children': []
                })
            
            # Call expressions
            elif '(' in line_stripped and any(pattern in line_stripped for pattern in [
                'exec.Command', 'sql.', 'aes.', 'md5.', 'fmt.', 'http.'
            ]):
                func_match = re.search(r'(\w+(?:\.\w+)*)\s*\(', line_stripped)
                if func_match:
                    function = func_match.group(1)
                    properties = {'function': function}
                    
                    # Risk categorization
                    if 'exec.Command' in function:
                        properties['risk_category'] = 'command_injection'
                    elif any(db_func in function for db_func in ['sql.Open', 'db.Query', 'db.Exec']):
                        properties['risk_category'] = 'sql_injection' 
                    elif any(crypto_func in function for crypto_func in ['aes.NewCipher', 'md5.New']):
                        properties['risk_category'] = 'crypto_weakness'
                    
                    children.append({
                        'node_type': 'call_expression',
                        'line': i,
                        'column': 1,
                        'source_text': line_stripped,
                        'properties': properties,
                        'children': []
                    })
            
            # Assignment expressions (for data flow tracking)
            elif '=' in line_stripped and not any(op in line_stripped for op in ['==', '!=', '<=', '>=']):
                if ':=' in line_stripped:
                    # Short variable declaration
                    var_match = re.search(r'(\w+)\s*:=\s*(.+)', line_stripped)
                    if var_match:
                        children.append({
                            'node_type': 'assignment_expression',
                            'line': i,
                            'column': 1,
                            'source_text': line_stripped,
                            'properties': {
                                'variable': var_match.group(1),
                                'value': var_match.group(2),
                                'assignment_type': 'short_declaration',
                                'contains_literal': '"' in var_match.group(2) or "'" in var_match.group(2)
                            },
                            'children': []
                        })
                elif '=' in line_stripped and not line_stripped.startswith('func'):
                    # Regular assignment
                    var_match = re.search(r'(\w+)\s*=\s*(.+)', line_stripped)
                    if var_match:
                        children.append({
                            'node_type': 'assignment_expression', 
                            'line': i,
                            'column': 1,
                            'source_text': line_stripped,
                            'properties': {
                                'variable': var_match.group(1),
                                'value': var_match.group(2),
                                'assignment_type': 'assignment',
                                'contains_literal': '"' in var_match.group(2) or "'" in var_match.group(2)
                            },
                            'children': []
                        })
            
            # Go statements (goroutines)
            elif line_stripped.startswith('go '):
                go_match = re.search(r'go\s+(\w+(?:\.\w+)*)\s*\(', line_stripped)
                if go_match:
                    children.append({
                        'node_type': 'go_statement',
                        'line': i,
                        'column': 1,
                        'source_text': line_stripped,
                        'properties': {
                            'called_function': go_match.group(1)
                        },
                        'children': []
                    })
        
        return children
    
    def _parse_go_mod(self, go_mod_path: str) -> Dict[str, Any]:
        """Parse go.mod file."""
        try:
            with open(go_mod_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            module_info = {'module_name': '', 'go_version': '', 'dependencies': []}
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('module '):
                    module_info['module_name'] = line[7:].strip()
                elif line.startswith('go '):
                    module_info['go_version'] = line[3:].strip()
                elif line and not line.startswith('//') and not line.startswith('module') and not line.startswith('go'):
                    if '(' not in line and ')' not in line and 'require' not in line:
                        module_info['dependencies'].append(line)
            
            return module_info
            
        except Exception:
            return {'module_name': '', 'go_version': '', 'dependencies': []}