"""
Docker AST Parser Module
=========================

This module provides a comprehensive lexer and parser for Dockerfiles.
It tokenizes Dockerfile source code and builds an Abstract Syntax Tree (AST)
similar to how SonarSource analyzes Docker files for security and quality rules.

AST Structure:
--------------
DockerfileNode (root)
 ├── InstructionNode (FROM, RUN, COPY, etc.)
 │     ├── ArgumentNode (arguments/values)
 │     ├── FlagNode (--flag=value)
 │     └── CommandNode (shell/exec commands)
 └── CommentNode (comments)

The AST enables pattern matching and rule application based on JSON metadata.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from enum import Enum


class NodeType(Enum):
    """Enumeration of AST node types."""
    DOCKERFILE = "Dockerfile"
    INSTRUCTION = "Instruction"
    ARGUMENT = "Argument"
    FLAG = "Flag"
    COMMAND = "Command"
    COMMENT = "Comment"
    KEY_VALUE = "KeyValue"
    IMAGE = "Image"
    PORT = "Port"
    PATH = "Path"


@dataclass
class ASTNode:
    """Base class for all AST nodes."""
    node_type: NodeType
    line: int
    column: int = 0
    raw: str = ""
    parent: Optional['ASTNode'] = None
    children: List['ASTNode'] = field(default_factory=list)
    
    def add_child(self, child: 'ASTNode'):
        """Add a child node and set parent reference."""
        child.parent = self
        self.children.append(child)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert AST node to dictionary for compatibility."""
        return {
            'node_type': self.node_type.value,
            'line': self.line,
            'column': self.column,
            'raw': self.raw,
            'children': [child.to_dict() for child in self.children]
        }


@dataclass
class CommentNode(ASTNode):
    """Represents a comment in Dockerfile."""
    text: str = ""
    
    def __init__(self, line=0, column=0, text="", raw=""):
        super().__init__(node_type=NodeType.COMMENT, line=line, column=column, raw=raw)
        self.text = text


@dataclass
class FlagNode(ASTNode):
    """Represents a flag like --platform=linux/amd64 or --chown=user:group."""
    name: str = ""
    value: str = ""
    
    def __init__(self, line=0, column=0, name="", value="", raw=""):
        super().__init__(node_type=NodeType.FLAG, line=line, column=column, raw=raw)
        self.name = name
        self.value = value
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({'name': self.name, 'value': self.value})
        return d


@dataclass
class ArgumentNode(ASTNode):
    """Represents an argument to an instruction."""
    value: str = ""
    
    def __init__(self, line=0, column=0, value="", raw=""):
        super().__init__(node_type=NodeType.ARGUMENT, line=line, column=column, raw=raw)
        self.value = value
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d['value'] = self.value
        return d


@dataclass
class KeyValueNode(ASTNode):
    """Represents key-value pairs in ENV, LABEL, ARG instructions."""
    key: str = ""
    value: str = ""
    has_space_before_equal: bool = False  # For detecting "KEY =VALUE" pattern
    
    def __init__(self, line=0, column=0, key="", value="", has_space_before_equal=False, raw=""):
        super().__init__(node_type=NodeType.KEY_VALUE, line=line, column=column, raw=raw)
        self.key = key
        self.value = value
        self.has_space_before_equal = has_space_before_equal
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({
            'key': self.key,
            'value': self.value,
            'has_space_before_equal': self.has_space_before_equal
        })
        return d


@dataclass
class ImageNode(ASTNode):
    """Represents a Docker image reference in FROM instruction."""
    name: str = ""
    tag: str = "latest"
    digest: str = ""
    registry: str = ""
    alias: str = ""
    
    def __init__(self, line=0, column=0, name="", tag="latest", digest="", registry="", alias="", raw=""):
        super().__init__(node_type=NodeType.IMAGE, line=line, column=column, raw=raw)
        self.name = name
        self.tag = tag
        self.digest = digest
        self.registry = registry
        self.alias = alias
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({
            'name': self.name,
            'tag': self.tag,
            'digest': self.digest,
            'registry': self.registry,
            'alias': self.alias
        })
        return d


@dataclass
class PortNode(ASTNode):
    """Represents a port in EXPOSE instruction."""
    port: str = ""
    protocol: str = "tcp"
    
    def __init__(self, line=0, column=0, port="", protocol="tcp", raw=""):
        super().__init__(node_type=NodeType.PORT, line=line, column=column, raw=raw)
        self.port = port
        self.protocol = protocol
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({'port': self.port, 'protocol': self.protocol})
        return d


@dataclass
class CommandNode(ASTNode):
    """Represents a command in RUN, CMD, ENTRYPOINT instructions."""
    form: str = "shell"  # "shell" or "exec"
    command: str = ""
    command_array: List[str] = field(default_factory=list)
    
    def __init__(self, line=0, column=0, form="shell", command="", command_array=None, raw=""):
        super().__init__(node_type=NodeType.COMMAND, line=line, column=column, raw=raw)
        self.form = form
        self.command = command
        self.command_array = command_array or []
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({
            'form': self.form,
            'command': self.command,
            'command_array': self.command_array
        })
        return d


@dataclass
class InstructionNode(ASTNode):
    """Represents a Dockerfile instruction (FROM, RUN, COPY, etc.)."""
    instruction: str = ""  # FROM, RUN, COPY, ADD, USER, etc.
    value: str = ""  # Raw value after instruction
    
    # Instruction-specific attributes
    image: Optional[ImageNode] = None
    flags: List[FlagNode] = field(default_factory=list)
    arguments: List[ArgumentNode] = field(default_factory=list)
    key_values: List[KeyValueNode] = field(default_factory=list)
    command: Optional[CommandNode] = None
    ports: List[PortNode] = field(default_factory=list)
    
    # Additional metadata
    user: str = ""
    group: str = ""
    source: str = ""
    destination: str = ""
    path: str = ""
    form: str = "shell"  # For RUN, CMD, ENTRYPOINT
    
    def __init__(self, line=0, column=0, instruction="", value="", raw=""):
        super().__init__(node_type=NodeType.INSTRUCTION, line=line, column=column, raw=raw)
        self.instruction = instruction
        self.value = value
        self.image = None
        self.flags = []
        self.arguments = []
        self.key_values = []
        self.command = None
        self.ports = []
        self.user = ""
        self.group = ""
        self.source = ""
        self.destination = ""
        self.path = ""
        self.form = "shell"
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({
            'instruction': self.instruction,
            'value': self.value,
            'user': self.user,
            'group': self.group,
            'source': self.source,
            'destination': self.destination,
            'path': self.path,
            'form': self.form,
            'lineno': self.line,  # For backward compatibility
        })
        
        # Add parsed children
        if self.image:
            d['image'] = self.image.name
            d['tag'] = self.image.tag
            d['digest'] = self.image.digest
            d['alias'] = self.image.alias
        
        if self.flags:
            d['flags'] = [f.to_dict() for f in self.flags]
        
        if self.arguments:
            d['arguments'] = [a.to_dict() for a in self.arguments]
        
        if self.key_values:
            d['key_values'] = [kv.to_dict() for kv in self.key_values]
            # Also provide as dict for easy access
            d['env_vars'] = {kv.key: kv.value for kv in self.key_values}
            d['labels'] = {kv.key: kv.value for kv in self.key_values}
        
        if self.command:
            d['command'] = self.command.to_dict()
            d['command_array'] = self.command.command_array
        
        if self.ports:
            d['ports'] = [p.to_dict() for p in self.ports]
        
        return d


@dataclass
class DockerfileNode(ASTNode):
    """Root node representing the entire Dockerfile."""
    filename: str = ""
    source: str = ""
    instructions: List[InstructionNode] = field(default_factory=list)
    
    def __init__(self, line=0, column=0, filename="", source="", raw=""):
        super().__init__(node_type=NodeType.DOCKERFILE, line=line, column=column, raw=raw)
        self.filename = filename
        self.source = source
        self.instructions = []
    
    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({
            'filename': self.filename,
            'source': self.source,
            'instructions': [inst.to_dict() for inst in self.instructions]
        })
        return d


class DockerLexer:
    """
    Tokenizes Dockerfile source code.
    Handles multi-line continuations, comments, and various instruction formats.
    """
    
    def __init__(self, source: str):
        self.source = source
        self.lines = source.splitlines()
        self.tokens = []
    
    def tokenize(self) -> List[Dict[str, Any]]:
        """Tokenize the Dockerfile source."""
        current_line_tokens = []
        current_line_num = 0
        continuation = False
        
        for idx, line in enumerate(self.lines, 1):
            original_line = line
            stripped = line.strip()
            
            # Skip empty lines
            if not stripped:
                if continuation:
                    current_line_tokens.append({
                        'type': 'NEWLINE',
                        'value': '\n',
                        'line': idx,
                        'raw': original_line
                    })
                continue
            
            # Handle comments
            if stripped.startswith('#') and not continuation:
                self.tokens.append({
                    'type': 'COMMENT',
                    'value': stripped[1:].strip(),
                    'line': idx,
                    'raw': original_line
                })
                continue
            
            # Check for line continuation
            has_continuation = stripped.endswith('\\')
            
            if not continuation:
                # Start of new instruction
                current_line_num = idx
                current_line_tokens = []
            
            # Remove continuation character
            if has_continuation:
                stripped = stripped[:-1].strip()
            
            # Tokenize the line
            if not continuation:
                # Extract instruction keyword
                match = re.match(r'^([A-Z][A-Z_]*)\s+(.*)$', stripped, re.IGNORECASE)
                if match:
                    current_line_tokens.append({
                        'type': 'INSTRUCTION',
                        'value': match.group(1).upper(),
                        'line': idx,
                        'column': 0,
                        'raw': original_line
                    })
                    
                    # Tokenize the rest
                    rest = match.group(2)
                    self._tokenize_instruction_value(rest, idx, current_line_tokens)
                else:
                    # Not a valid instruction
                    current_line_tokens.append({
                        'type': 'TEXT',
                        'value': stripped,
                        'line': idx,
                        'raw': original_line
                    })
            else:
                # Continuation of previous instruction
                self._tokenize_instruction_value(stripped, idx, current_line_tokens)
            
            # If no continuation, finalize the instruction
            if not has_continuation:
                self.tokens.extend(current_line_tokens)
                self.tokens.append({'type': 'EOL', 'line': idx})
                continuation = False
            else:
                continuation = True
        
        return self.tokens
    
    def _tokenize_instruction_value(self, value: str, line: int, tokens: List[Dict]):
        """Tokenize instruction value (flags, arguments, etc.)."""
        # Extract flags (--flag=value or --flag)
        flag_pattern = r'(--[\w-]+(?:=\S+)?)'
        parts = re.split(flag_pattern, value)
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            if part.startswith('--'):
                # Flag token
                if '=' in part:
                    flag_name, flag_value = part.split('=', 1)
                    tokens.append({
                        'type': 'FLAG',
                        'name': flag_name,
                        'value': flag_value,
                        'line': line
                    })
                else:
                    tokens.append({
                        'type': 'FLAG',
                        'name': part,
                        'value': '',
                        'line': line
                    })
            else:
                # Regular value token
                tokens.append({
                    'type': 'VALUE',
                    'value': part,
                    'line': line
                })


class DockerParser:
    """
    Parses tokenized Dockerfile into an Abstract Syntax Tree (AST).
    """
    
    def __init__(self, source: str, filename: str = "Dockerfile"):
        self.source = source
        self.filename = filename
        self.lexer = DockerLexer(source)
        self.tokens = []
        self.current = 0
    
    def parse(self) -> DockerfileNode:
        """Parse the Dockerfile source into an AST."""
        self.tokens = self.lexer.tokenize()
        
        dockerfile = DockerfileNode(
            line=0,
            column=0,
            filename=self.filename,
            source=self.source,
            raw=self.source
        )
        
        while self.current < len(self.tokens):
            token = self.tokens[self.current]
            
            if token['type'] == 'COMMENT':
                comment = CommentNode(
                    line=token['line'],
                    text=token['value'],
                    raw=token.get('raw', '')
                )
                dockerfile.add_child(comment)
                self.current += 1
            
            elif token['type'] == 'INSTRUCTION':
                instruction = self._parse_instruction()
                if instruction:
                    dockerfile.add_child(instruction)
                    dockerfile.instructions.append(instruction)
            
            elif token['type'] == 'EOL':
                self.current += 1
            
            else:
                self.current += 1
        
        return dockerfile
    
    def _parse_instruction(self) -> Optional[InstructionNode]:
        """Parse a single instruction."""
        if self.current >= len(self.tokens):
            return None
        
        token = self.tokens[self.current]
        if token['type'] != 'INSTRUCTION':
            return None
        
        instruction_name = token['value']
        line = token['line']
        raw = token.get('raw', '')
        
        self.current += 1
        
        # Collect all tokens until EOL
        value_tokens = []
        while self.current < len(self.tokens) and self.tokens[self.current]['type'] not in ['EOL', 'INSTRUCTION']:
            value_tokens.append(self.tokens[self.current])
            self.current += 1
        
        # Build instruction value string
        value_parts = []
        for vt in value_tokens:
            if vt['type'] == 'VALUE':
                value_parts.append(vt['value'])
            elif vt['type'] == 'FLAG':
                flag_str = vt['name']
                if vt.get('value'):
                    flag_str += '=' + vt['value']
                value_parts.append(flag_str)
        
        value = ' '.join(value_parts)
        
        # Create instruction node
        instruction = InstructionNode(
            instruction=instruction_name,
            value=value,
            line=line,
            raw=raw
        )
        
        # Parse instruction-specific details
        self._parse_instruction_details(instruction, value_tokens)
        
        return instruction
    
    def _parse_instruction_details(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse instruction-specific details based on instruction type."""
        instruction_name = instruction.instruction
        
        if instruction_name == 'FROM':
            self._parse_from_instruction(instruction, tokens)
        elif instruction_name in ['RUN', 'CMD', 'ENTRYPOINT']:
            self._parse_command_instruction(instruction, tokens)
        elif instruction_name == 'ENV':
            self._parse_env_instruction(instruction, tokens)
        elif instruction_name == 'ARG':
            self._parse_arg_instruction(instruction, tokens)
        elif instruction_name == 'LABEL':
            self._parse_label_instruction(instruction, tokens)
        elif instruction_name in ['COPY', 'ADD']:
            self._parse_copy_add_instruction(instruction, tokens)
        elif instruction_name == 'USER':
            self._parse_user_instruction(instruction, tokens)
        elif instruction_name == 'WORKDIR':
            self._parse_workdir_instruction(instruction, tokens)
        elif instruction_name == 'EXPOSE':
            self._parse_expose_instruction(instruction, tokens)
        elif instruction_name == 'HEALTHCHECK':
            self._parse_healthcheck_instruction(instruction, tokens)
        
        # Extract flags
        for token in tokens:
            if token['type'] == 'FLAG':
                flag = FlagNode(
                    name=token['name'],
                    value=token.get('value', ''),
                    line=token['line'],
                    raw=f"{token['name']}={token.get('value', '')}"
                )
                instruction.flags.append(flag)
                instruction.add_child(flag)
    
    def _parse_from_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse FROM instruction: FROM [--platform=<platform>] <image>[:<tag>|@<digest>] [AS <name>]"""
        value = instruction.value
        
        # Remove flags first
        value_no_flags = re.sub(r'--[\w-]+(=\S+)?\s*', '', value).strip()
        
        # Parse image reference
        # Format: [registry/]name[:tag|@digest] [AS alias]
        as_match = re.search(r'\s+AS\s+(\S+)', value_no_flags, re.IGNORECASE)
        alias = as_match.group(1) if as_match else ""
        
        image_part = re.sub(r'\s+AS\s+\S+', '', value_no_flags, flags=re.IGNORECASE).strip()
        
        # Parse digest
        digest = ""
        if '@' in image_part:
            image_part, digest = image_part.split('@', 1)
        
        # Parse tag
        tag = "latest"
        if ':' in image_part:
            image_part, tag = image_part.rsplit(':', 1)
        
        # Parse registry and name
        registry = ""
        name = image_part
        if '/' in image_part and '.' in image_part.split('/')[0]:
            parts = image_part.split('/', 1)
            registry = parts[0]
            name = parts[1] if len(parts) > 1 else ""
        
        image_node = ImageNode(
            name=name,
            tag=tag,
            digest=digest,
            registry=registry,
            alias=alias,
            line=instruction.line,
            raw=value
        )
        
        instruction.image = image_node
        instruction.add_child(image_node)
    
    def _parse_command_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse RUN, CMD, ENTRYPOINT instructions."""
        value = instruction.value.strip()
        
        # Detect exec form (JSON array) vs shell form
        if value.startswith('['):
            # Exec form
            try:
                import json
                command_array = json.loads(value)
                command_node = CommandNode(
                    form='exec',
                    command=' '.join(command_array),
                    command_array=command_array,
                    line=instruction.line,
                    raw=value
                )
                instruction.form = 'exec'
            except:
                # Malformed JSON, treat as shell
                command_node = CommandNode(
                    form='shell',
                    command=value,
                    line=instruction.line,
                    raw=value
                )
                instruction.form = 'shell'
        else:
            # Shell form
            command_node = CommandNode(
                form='shell',
                command=value,
                line=instruction.line,
                raw=value
            )
            instruction.form = 'shell'
        
        instruction.command = command_node
        instruction.add_child(command_node)
    
    def _parse_env_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse ENV instruction: ENV <key>=<value> ... or ENV <key> <value>"""
        value = instruction.value
        
        # Check for space before equal sign pattern (security issue)
        space_before_equal_pattern = r'(\w+)\s+(=)'
        
        if '=' in value:
            # Key=value format
            pairs = re.findall(r'(\S+?)\s*(=)\s*([^\s]+)', value)
            for key, eq, val in pairs:
                has_space = bool(re.search(rf'{re.escape(key)}\s+{re.escape(eq)}', value))
                kv_node = KeyValueNode(
                    key=key,
                    value=val.strip('"').strip("'"),
                    has_space_before_equal=has_space,
                    line=instruction.line,
                    raw=f"{key}={val}"
                )
                instruction.key_values.append(kv_node)
                instruction.add_child(kv_node)
        else:
            # Key value format (space-separated, only one pair)
            parts = value.split(None, 1)
            if len(parts) == 2:
                kv_node = KeyValueNode(
                    key=parts[0],
                    value=parts[1].strip('"').strip("'"),
                    has_space_before_equal=False,
                    line=instruction.line,
                    raw=value
                )
                instruction.key_values.append(kv_node)
                instruction.add_child(kv_node)
    
    def _parse_arg_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse ARG instruction: ARG <name>[=<default value>]"""
        value = instruction.value
        
        # Check for space before equal sign
        has_space = bool(re.search(r'\w+\s+=', value))
        
        if '=' in value:
            key, val = value.split('=', 1)
            kv_node = KeyValueNode(
                key=key.strip(),
                value=val.strip(),
                has_space_before_equal=has_space,
                line=instruction.line,
                raw=value
            )
            instruction.key_values.append(kv_node)
            instruction.add_child(kv_node)
        else:
            kv_node = KeyValueNode(
                key=value.strip(),
                value="",
                has_space_before_equal=False,
                line=instruction.line,
                raw=value
            )
            instruction.key_values.append(kv_node)
            instruction.add_child(kv_node)
    
    def _parse_label_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse LABEL instruction: LABEL <key>=<value> <key>=<value> ..."""
        value = instruction.value
        
        # Similar to ENV with = format
        pairs = re.findall(r'(\S+?)\s*(=)\s*([^\s]+)', value)
        for key, eq, val in pairs:
            has_space = bool(re.search(rf'{re.escape(key)}\s+{re.escape(eq)}', value))
            kv_node = KeyValueNode(
                key=key,
                value=val.strip('"').strip("'"),
                has_space_before_equal=has_space,
                line=instruction.line,
                raw=f"{key}={val}"
            )
            instruction.key_values.append(kv_node)
            instruction.add_child(kv_node)
    
    def _parse_copy_add_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse COPY/ADD instructions."""
        value_tokens = [t for t in tokens if t['type'] == 'VALUE']
        
        if len(value_tokens) >= 2:
            # Last token is destination
            instruction.destination = value_tokens[-1]['value']
            # Everything else is source
            instruction.source = ' '.join(t['value'] for t in value_tokens[:-1])
    
    def _parse_user_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse USER instruction: USER <user>[:<group>]"""
        value = instruction.value
        
        if ':' in value:
            instruction.user, instruction.group = value.split(':', 1)
        else:
            instruction.user = value
    
    def _parse_workdir_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse WORKDIR instruction."""
        instruction.path = instruction.value
    
    def _parse_expose_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse EXPOSE instruction: EXPOSE <port>[/<protocol>] ..."""
        value = instruction.value
        
        port_specs = re.findall(r'(\d+)(?:/(\w+))?', value)
        for port, protocol in port_specs:
            port_node = PortNode(
                port=port,
                protocol=protocol or 'tcp',
                line=instruction.line,
                raw=f"{port}/{protocol or 'tcp'}"
            )
            instruction.ports.append(port_node)
            instruction.add_child(port_node)
    
    def _parse_healthcheck_instruction(self, instruction: InstructionNode, tokens: List[Dict]):
        """Parse HEALTHCHECK instruction."""
        value = instruction.value.strip()
        
        if value.upper().startswith('NONE'):
            instruction.form = 'none'
        else:
            instruction.form = 'cmd'


def parse_dockerfile_to_ast(file_path: str) -> DockerfileNode:
    """
    Main entry point to parse a Dockerfile into an AST.
    
    Args:
        file_path: Path to Dockerfile
        
    Returns:
        DockerfileNode (root of AST)
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source = f.read()
    
    parser = DockerParser(source, file_path)
    ast_tree = parser.parse()
    
    return ast_tree


# For backward compatibility
def parse_dockerfile(file_path: str) -> Dict[str, Any]:
    """
    Parse Dockerfile and return as dictionary (backward compatible).
    
    Args:
        file_path: Path to Dockerfile
        
    Returns:
        Dictionary representation of AST
    """
    ast_tree = parse_dockerfile_to_ast(file_path)
    return ast_tree.to_dict()
