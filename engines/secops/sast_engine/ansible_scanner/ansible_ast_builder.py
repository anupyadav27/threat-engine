"""
Ansible AST Builder - Inspired by SonarSource's approach
Builds a structured tree representation of Ansible playbooks with precise node types.
"""

import os
import yaml
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field

try:
    from ruamel.yaml import YAML
    HAS_RUAMEL = True
except ImportError:
    HAS_RUAMEL = False


@dataclass
class AnsibleNode:
    """Base class for all Ansible AST nodes."""
    node_type: str
    line_number: int
    source_file: str
    raw_data: Dict = field(default_factory=dict)
    
    def get_location(self) -> Dict[str, int]:
        return {"line": self.line_number, "file": self.source_file}


@dataclass
class Task(AnsibleNode):
    """Represents an Ansible task."""
    name: Optional[str] = None
    module: Optional[str] = None
    module_args: Dict = field(default_factory=dict)
    when: Optional[str] = None
    become: Optional[bool] = None
    become_user: Optional[str] = None
    loop: Optional[Any] = None
    register: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.node_type = "task"


@dataclass
class Play(AnsibleNode):
    """Represents an Ansible play."""
    name: Optional[str] = None
    hosts: Optional[str] = None
    tasks: List[Task] = field(default_factory=list)
    pre_tasks: List[Task] = field(default_factory=list)
    post_tasks: List[Task] = field(default_factory=list)
    handlers: List[Task] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    vars: Dict = field(default_factory=dict)
    become: Optional[bool] = None
    
    def __post_init__(self):
        self.node_type = "play"


@dataclass
class Playbook(AnsibleNode):
    """Represents an Ansible playbook file."""
    plays: List[Play] = field(default_factory=list)
    
    def __post_init__(self):
        self.node_type = "playbook"


class AnsibleASTBuilder:
    """
    Builds a structured AST from Ansible YAML files.
    Follows SonarSource's pattern of creating domain-specific objects.
    """
    
    # Ansible task keywords that are not module names
    TASK_KEYWORDS = {
        'name', 'when', 'with_items', 'loop', 'loop_control', 'register', 
        'become', 'become_user', 'become_method', 'become_flags',
        'tags', 'notify', 'changed_when', 'failed_when', 'ignore_errors',
        'vars', 'environment', 'delegate_to', 'delegate_facts', 'run_once',
        'until', 'retries', 'delay', 'check_mode', 'diff', 'any_errors_fatal',
        'throttle', 'connection', 'remote_user', 'port', 'timeout',
        'no_log', 'args', 'local_action', 'block', 'rescue', 'always'
    }
    
    # Common Ansible modules for quick detection
    COMMON_MODULES = {
        'copy', 'file', 'template', 'lineinfile', 'blockinfile',
        'shell', 'command', 'script', 'raw',
        'apt', 'yum', 'dnf', 'package', 'pip',
        'service', 'systemd', 'user', 'group',
        'git', 'subversion',
        'docker_container', 'docker_image', 'docker_network', 'docker_volume',
        'k8s', 'kubernetes', 'kubectl',
        'aws_s3', 'ec2', 's3_bucket',
        'uri', 'get_url', 'unarchive',
        'set_fact', 'debug', 'assert', 'fail', 'meta',
        'include', 'include_tasks', 'include_role', 'import_playbook',
        'import_tasks', 'import_role'
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.source_lines = []
        
    def parse(self) -> Playbook:
        """Parse an Ansible file and return a Playbook AST."""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            self.source_lines = content.splitlines()
        
        # Parse YAML
        if HAS_RUAMEL:
            yaml_parser = YAML()
            yaml_parser.preserve_quotes = True
            from io import StringIO
            data = yaml_parser.load(StringIO(content))
        else:
            data = yaml.safe_load(content)
        
        if data is None:
            return Playbook(line_number=1, source_file=self.file_path)
        
        # Build playbook
        playbook = Playbook(
            node_type='playbook',
            line_number=1,
            source_file=self.file_path,
            raw_data={'type': 'playbook'}
        )
        
        # Parse plays
        if isinstance(data, list):
            for play_data in data:
                if isinstance(play_data, dict):
                    play = self._parse_play(play_data)
                    if play:
                        playbook.plays.append(play)
        
        return playbook
    
    def _parse_play(self, play_data: Dict) -> Optional[Play]:
        """Parse a play from YAML data."""
        if not isinstance(play_data, dict):
            return None
        
        line_number = self._get_line_number(play_data)
        
        play = Play(
            node_type='play',
            line_number=line_number,
            source_file=self.file_path,
            raw_data=play_data
        )
        
        # Extract play attributes
        play.name = play_data.get('name')
        play.hosts = play_data.get('hosts')
        play.become = play_data.get('become')
        play.vars = play_data.get('vars', {})
        
        # Parse roles
        if 'roles' in play_data:
            roles_data = play_data['roles']
            if isinstance(roles_data, list):
                for role in roles_data:
                    if isinstance(role, str):
                        play.roles.append(role)
                    elif isinstance(role, dict) and 'role' in role:
                        play.roles.append(role['role'])
        
        # Parse tasks
        if 'tasks' in play_data:
            play.tasks = self._parse_tasks(play_data['tasks'])
        
        if 'pre_tasks' in play_data:
            play.pre_tasks = self._parse_tasks(play_data['pre_tasks'])
        
        if 'post_tasks' in play_data:
            play.post_tasks = self._parse_tasks(play_data['post_tasks'])
        
        if 'handlers' in play_data:
            play.handlers = self._parse_tasks(play_data['handlers'])
        
        return play
    
    def _parse_tasks(self, tasks_data: Any) -> List[Task]:
        """Parse a list of tasks."""
        tasks = []
        
        if not isinstance(tasks_data, list):
            return tasks
        
        for task_data in tasks_data:
            if isinstance(task_data, dict):
                task = self._parse_task(task_data)
                if task:
                    tasks.append(task)
        
        return tasks
    
    def _parse_task(self, task_data: Dict) -> Optional[Task]:
        """Parse a single task from YAML data."""
        if not isinstance(task_data, dict):
            return None
        line_number = self._get_line_number(task_data)
        
        task = Task(
            node_type='task',
            line_number=line_number,
            source_file=self.file_path,
            raw_data=task_data
        )
        
        # Extract task attributes
        task.name = task_data.get('name')
        task.when = task_data.get('when')
        task.become = task_data.get('become')
        task.become_user = task_data.get('become_user')
        task.register = task_data.get('register')
        task.loop = task_data.get('loop') or task_data.get('with_items')
        
        # Extract tags
        if 'tags' in task_data:
            tags = task_data['tags']
            if isinstance(tags, list):
                task.tags = tags
            elif isinstance(tags, str):
                task.tags = [tags]
        
        # Find the module name and args
        module_name, module_args = self._extract_module(task_data)
        task.module = module_name
        task.module_args = module_args
        
        return task
    
    def _extract_module(self, task_data: Dict) -> tuple[Optional[str], Dict]:
        """
        Extract module name and arguments from task data.
        This is the core logic that identifies what Ansible module is being used.
        """
        for key, value in task_data.items():
            # Skip known task keywords
            if key in self.TASK_KEYWORDS:
                continue
            
            # Skip private/internal keys
            if key.startswith('_'):
                continue
            
            # This is likely the module
            module_name = key
            module_args = {}
            
            # Parse module arguments
            if isinstance(value, dict):
                module_args = value
            elif isinstance(value, str):
                # Inline module arguments (e.g., shell: "echo hello")
                module_args = {'_raw': value}
            elif value is not None:
                module_args = {'value': value}
            
            return module_name, module_args
        
        return None, {}
    
    def to_generic_ast(self, playbook: Playbook) -> Dict:
        """
        Convert the structured Playbook AST to generic dict format
        compatible with the existing generic_rule_engine.
        """
        nodes = []
        
        for play in playbook.plays:
            # Add play node
            play_node = {
                'node_type': 'play',
                'type': 'play',
                'name': play.name or 'unnamed_play',
                'hosts': play.hosts,
                'become': play.become,
                'lineno': play.line_number,
                '__line__': play.line_number,
                'source': yaml.dump(play.raw_data, default_flow_style=False) if play.raw_data else '',
                'parent_source': '',
                'data': play.raw_data
            }
            nodes.append(play_node)
            
            # Add all tasks
            all_tasks = play.tasks + play.pre_tasks + play.post_tasks + play.handlers
            for task in all_tasks:
                task_node = self._task_to_node(task)
                nodes.append(task_node)
        
        return {
            'node_type': 'CompilationUnit',
            'filename': playbook.source_file,
            'source': '\n'.join(self.source_lines),
            'children': nodes
        }
    
    def _task_to_node(self, task: Task) -> Dict:
        """Convert a Task object to a generic AST node."""
        # Determine specific node type based on module
        node_type = 'task'
        if task.module:
            # Map specific modules to node types
            if task.module in ['docker_container', 'docker_image', 'docker_network', 'docker_volume']:
                node_type = 'docker_container'
            elif task.module in ['k8s', 'kubernetes']:
                node_type = 'kubernetes'
            elif task.module in ['shell', 'command', 'copy', 'file']:
                node_type = task.module
        
        task_node = {
            'node_type': node_type,
            'type': node_type,
            'name': task.name or 'unnamed_task',
            'module': task.module,
            'action': task.module,  # Alias for module
            'module_params': task.module_args,
            'lineno': task.line_number,
            '__line__': task.line_number,
            '_line_number': task.line_number,
            'source': yaml.dump(task.raw_data, default_flow_style=False) if task.raw_data else '',
            'parent_source': '\n'.join(self.source_lines),
            'data': task.raw_data,
            'become': task.become,
            'become_user': task.become_user,
            'when': task.when,
            'loop': task.loop,
            'register': task.register,
            'tags': task.tags,
        }
        
        # Add module-specific attributes to make them accessible via property_path
        if task.module_args:
            for key, value in task.module_args.items():
                task_node[key] = value
        
        return task_node
    
    def _get_line_number(self, data: Any) -> int:
        """
        Extract line number from YAML data.
        Uses ruamel.yaml's line tracking if available.
        """
        # Try ruamel.yaml line info
        if HAS_RUAMEL and hasattr(data, 'lc'):
            return data.lc.line + 1  # Convert to 1-based
        
        # Try to find in source by matching content
        if isinstance(data, dict):
            # Look for 'name' field
            if 'name' in data:
                name = str(data['name'])
                for idx, line in enumerate(self.source_lines, 1):
                    if 'name:' in line and name in line:
                        return idx
            
            # Look for 'hosts' field (play)
            if 'hosts' in data:
                hosts = str(data['hosts'])
                for idx, line in enumerate(self.source_lines, 1):
                    if 'hosts:' in line and hosts in line:
                        return idx
        
        # Default to line 1
        return 1


class AnsibleTreeVisitor:
    """
    Visitor pattern for traversing Ansible AST.
    Similar to SonarSource's CheckTree pattern.
    """
    
    def visit_playbook(self, playbook: Playbook):
        """Visit a playbook node."""
        for play in playbook.plays:
            self.visit_play(play)
    
    def visit_play(self, play: Play):
        """Visit a play node."""
        for task in play.tasks:
            self.visit_task(task)
        for task in play.pre_tasks:
            self.visit_task(task)
        for task in play.post_tasks:
            self.visit_task(task)
        for task in play.handlers:
            self.visit_task(task)
    
    def visit_task(self, task: Task):
        """Visit a task node. Override this in subclasses."""
        pass


def parse_ansible_file(file_path: str) -> Playbook:
    """Convenience function to parse an Ansible file."""
    builder = AnsibleASTBuilder(file_path)
    return builder.parse()


def parse_ansible_to_generic_ast(file_path: str) -> Dict:
    """
    Parse Ansible file and convert to generic AST format
    compatible with generic_rule_engine.
    """
    builder = AnsibleASTBuilder(file_path)
    playbook = builder.parse()
    return builder.to_generic_ast(playbook)
