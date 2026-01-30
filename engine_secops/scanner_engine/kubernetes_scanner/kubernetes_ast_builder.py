"""
Kubernetes YAML to AST/PSI Builder - SonarSource-inspired approach

This module converts Kubernetes YAML manifests into a structured semantic model (AST/PSI tree)
that can be analyzed by the generic rule engine.

Pipeline:
1. Lexing - Tokenize YAML text
2. Parsing - Build PSI tree from tokens
3. Schema Binding - Match to Kubernetes resource schemas
4. Semantic Model - Create analyzable object tree with metadata
5. Rule Analysis - Generic rules can traverse this model
"""

import yaml
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Node types in the Kubernetes PSI tree."""
    DOCUMENT = "Document"
    MAPPING = "Mapping"
    SEQUENCE = "Sequence"
    KEY_VALUE = "KeyValue"
    SCALAR = "Scalar"
    RESOURCE = "KubernetesResource"
    CONTAINER = "Container"
    VOLUME = "Volume"
    PORT = "Port"
    ENV_VAR = "EnvVar"
    SECURITY_CONTEXT = "SecurityContext"
    RESOURCE_REQUIREMENTS = "ResourceRequirements"


@dataclass
class Position:
    """Position information for YAML nodes."""
    line: int
    column: int = 0


@dataclass
class ASTNode:
    """Base AST/PSI node for Kubernetes YAML."""
    node_type: str  # Using string for compatibility with generic rule engine
    type: str  # Alias for node_type (for compatibility)
    value: Any = None
    children: List['ASTNode'] = field(default_factory=list)
    parent: Optional['ASTNode'] = None
    position: Optional[Position] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Additional fields for Kubernetes-specific context
    kind: Optional[str] = None
    api_version: Optional[str] = None
    resource_name: Optional[str] = None
    
    # Source tracking
    source: str = ""
    raw_yaml: str = ""
    
    def __post_init__(self):
        """Ensure type and node_type are synchronized."""
        if not self.type:
            self.type = self.node_type
        if not self.node_type:
            self.node_type = self.type
    
    def to_dict(self) -> Dict:
        """Convert AST node to dictionary for generic rule engine."""
        result = {
            'node_type': self.node_type,
            'type': self.type,
            'value': self.value,
            'kind': self.kind,
            'apiVersion': self.api_version,
            'name': self.resource_name,
            'metadata': self.metadata,
            'source': self.source,
            '__line__': self.position.line if self.position else 0
        }
        
        # Add children as a list (preserve hierarchy)
        if self.children:
            result['children'] = []
            for i, child in enumerate(self.children):
                child_dict = child.to_dict()
                result['children'].append(child_dict)
                # Also merge child properties into parent for easy traversal
                for key, value in child_dict.items():
                    if key not in result:
                        result[key] = value
        
        # Add metadata fields directly to result for easier property_path access
        for key, value in self.metadata.items():
            if key not in result:
                result[key] = value
        
        return result


class KubernetesASTBuilder:
    """
    Builds a semantic AST/PSI tree from Kubernetes YAML.
    Follows SonarSource's approach: Lexing → Parsing → Schema Binding → Semantic Model.
    """
    
    # Kubernetes resource schemas - simplified version
    RESOURCE_SCHEMAS = {
        'Pod': {
            'apiVersion': ['v1'],
            'security_sensitive_fields': [
                'spec.hostNetwork', 'spec.hostPID', 'spec.hostIPC',
                'spec.containers[].securityContext',
                'spec.volumes[].hostPath'
            ]
        },
        'Deployment': {
            'apiVersion': ['apps/v1', 'extensions/v1beta1'],
            'security_sensitive_fields': [
                'spec.template.spec.hostNetwork',
                'spec.template.spec.containers[].securityContext',
                'spec.template.spec.containers[].image'
            ]
        },
        'Service': {
            'apiVersion': ['v1'],
            'security_sensitive_fields': [
                'spec.type', 'spec.ports[]'
            ]
        },
        'NetworkPolicy': {
            'apiVersion': ['networking.k8s.io/v1'],
            'security_sensitive_fields': [
                'spec.ingress', 'spec.egress'
            ]
        },
        'Role': {
            'apiVersion': ['rbac.authorization.k8s.io/v1'],
            'security_sensitive_fields': [
                'rules[].verbs', 'rules[].resources'
            ]
        },
        'RoleBinding': {
            'apiVersion': ['rbac.authorization.k8s.io/v1'],
            'security_sensitive_fields': [
                'subjects', 'roleRef'
            ]
        },
        'ClusterRole': {
            'apiVersion': ['rbac.authorization.k8s.io/v1'],
            'security_sensitive_fields': [
                'rules[].verbs', 'rules[].resources'
            ]
        },
        'ClusterRoleBinding': {
            'apiVersion': ['rbac.authorization.k8s.io/v1'],
            'security_sensitive_fields': [
                'subjects', 'roleRef'
            ]
        },
        'Ingress': {
            'apiVersion': ['networking.k8s.io/v1', 'extensions/v1beta1'],
            'security_sensitive_fields': [
                'spec.tls', 'spec.rules[].http'
            ]
        },
        'StatefulSet': {
            'apiVersion': ['apps/v1'],
            'security_sensitive_fields': [
                'spec.template.spec.containers[].securityContext'
            ]
        },
        'DaemonSet': {
            'apiVersion': ['apps/v1'],
            'security_sensitive_fields': [
                'spec.template.spec.containers[].securityContext'
            ]
        },
        'CronJob': {
            'apiVersion': ['batch/v1', 'batch/v1beta1'],
            'security_sensitive_fields': [
                'spec.jobTemplate.spec.template.spec.containers[].securityContext'
            ]
        },
        'Job': {
            'apiVersion': ['batch/v1'],
            'security_sensitive_fields': [
                'spec.template.spec.containers[].securityContext'
            ]
        },
        'ConfigMap': {
            'apiVersion': ['v1'],
            'security_sensitive_fields': ['data']
        },
        'Secret': {
            'apiVersion': ['v1'],
            'security_sensitive_fields': ['data', 'stringData']
        },
        'ServiceAccount': {
            'apiVersion': ['v1'],
            'security_sensitive_fields': ['automountServiceAccountToken']
        }
    }
    
    def __init__(self):
        self.line_map = {}  # Maps YAML keys to line numbers
    
    def build_ast(self, yaml_content: str, filename: str = "unknown") -> List[ASTNode]:
        """
        Main entry point: Convert YAML content to list of AST nodes.
        Handles multi-document YAML.
        """
        # Step 1 & 2: Lex and Parse YAML
        documents = self._parse_yaml_with_positions(yaml_content)
        
        # Step 3 & 4: Schema Binding and Semantic Model Creation
        ast_nodes = []
        for doc, start_line in documents:
            if doc and isinstance(doc, dict):
                ast_node = self._build_semantic_model(doc, filename, start_line)
                if ast_node:
                    ast_nodes.append(ast_node)
        
        return ast_nodes
    
    def _parse_yaml_with_positions(self, yaml_content: str) -> List[Tuple[Dict, int]]:
        """
        Parse YAML and track line positions.
        Returns list of (document, start_line) tuples.
        """
        documents = []
        
        # Split by document separator
        yaml_docs = yaml_content.split('\n---\n')
        current_line = 1
        
        for doc_text in yaml_docs:
            if not doc_text.strip():
                continue
            
            try:
                # Parse the document
                doc = yaml.safe_load(doc_text)
                
                if doc:
                    documents.append((doc, current_line))
                
                # Update line counter
                current_line += doc_text.count('\n') + 1
            
            except yaml.YAMLError as e:
                import sys
                print(f"YAML parsing error at line {current_line}: {e}", file=sys.stderr)
                continue
        
        # Build line map for property path tracking
        self._build_line_map(yaml_content)
        
        return documents
    
    def _build_line_map(self, yaml_content: str):
        """
        Build a map of YAML keys to line numbers for accurate reporting.
        """
        lines = yaml_content.split('\n')
        self.line_map = {}
        
        for line_num, line in enumerate(lines, 1):
            # Extract key from line (before ':')
            match = re.match(r'^(\s*)([^:\s]+)\s*:', line)
            if match:
                indent = len(match.group(1))
                key = match.group(2)
                self.line_map[f"{indent}:{key}"] = line_num
    
    def _build_semantic_model(self, doc: Dict, filename: str, start_line: int) -> Optional[ASTNode]:
        """
        Build semantic model (AST) from parsed YAML document.
        This is Step 4 in SonarSource's pipeline.
        """
        if not isinstance(doc, dict):
            return None
        
        # Check if this is a Kubernetes resource
        kind = doc.get('kind')
        api_version = doc.get('apiVersion')
        
        if not kind or not api_version:
            # Not a valid Kubernetes resource
            return None
        
        # Get resource metadata
        metadata = doc.get('metadata', {})
        resource_name = metadata.get('name', 'unnamed')
        namespace = metadata.get('namespace', 'default')
        
        # Create root resource node
        resource_node = ASTNode(
            node_type=NodeType.RESOURCE.value,
            type=kind,
            kind=kind,
            api_version=api_version,
            resource_name=resource_name,
            position=Position(line=start_line),
            source=filename,
            raw_yaml=str(doc),
            metadata={
                'namespace': namespace,
                'labels': metadata.get('labels', {}),
                'annotations': metadata.get('annotations', {}),
                'schema': self.RESOURCE_SCHEMAS.get(kind, {})
            }
        )
        
        # Build semantic tree based on resource kind
        if kind in ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job']:
            self._process_workload_resource(resource_node, doc)
        elif kind == 'CronJob':
            self._process_cronjob(resource_node, doc)
        elif kind == 'Service':
            self._process_service(resource_node, doc)
        elif kind == 'Ingress':
            self._process_ingress(resource_node, doc)
        elif kind in ['Role', 'ClusterRole']:
            self._process_role(resource_node, doc)
        elif kind in ['RoleBinding', 'ClusterRoleBinding']:
            self._process_role_binding(resource_node, doc)
        elif kind == 'NetworkPolicy':
            self._process_network_policy(resource_node, doc)
        elif kind == 'Secret':
            self._process_secret(resource_node, doc)
        elif kind == 'ConfigMap':
            self._process_configmap(resource_node, doc)
        elif kind == 'ServiceAccount':
            self._process_service_account(resource_node, doc)
        else:
            # Generic resource processing
            self._process_generic_resource(resource_node, doc)
        
        return resource_node
    
    def _process_workload_resource(self, parent: ASTNode, doc: Dict):
        """Process Pod, Deployment, StatefulSet, DaemonSet, etc."""
        spec = doc.get('spec', {})
        
        # Handle different spec structures
        if parent.kind == 'Pod':
            pod_spec = spec
        else:
            # Deployment, StatefulSet, etc. have spec.template.spec
            template = spec.get('template', {})
            pod_spec = template.get('spec', {})
            
            # Add replicas info if present
            if 'replicas' in spec:
                parent.metadata['replicas'] = spec['replicas']
        
        # Process containers
        containers = pod_spec.get('containers', [])
        self._process_containers(parent, containers, 'containers')
        
        # Process init containers
        init_containers = pod_spec.get('initContainers', [])
        if init_containers:
            self._process_containers(parent, init_containers, 'initContainers')
        
        # Process volumes
        volumes = pod_spec.get('volumes', [])
        if volumes:
            self._process_volumes(parent, volumes)
        
        # Process security-sensitive pod-level settings
        self._extract_pod_security_settings(parent, pod_spec)
    
    def _process_containers(self, parent: ASTNode, containers: List[Dict], container_type: str):
        """Process container specifications."""
        for i, container in enumerate(containers):
            container_node = ASTNode(
                node_type=NodeType.CONTAINER.value,
                type='Container',
                value=container.get('name', f'container-{i}'),
                parent=parent,
                metadata={
                    'container_type': container_type,
                    'index': i,
                    'image': container.get('image', ''),
                    'imagePullPolicy': container.get('imagePullPolicy', ''),
                    'command': container.get('command', []),
                    'args': container.get('args', [])
                }
            )
            
            # Process security context
            security_context = container.get('securityContext', {})
            if security_context:
                self._process_security_context(container_node, security_context)
            
            # Process resource requirements
            resources = container.get('resources', {})
            if resources:
                self._process_resource_requirements(container_node, resources)
            
            # Process environment variables
            env = container.get('env', [])
            if env:
                self._process_env_vars(container_node, env)
                # Store env list in metadata for duplicate checking
                container_node.metadata['env'] = env
            
            # Process ports
            ports = container.get('ports', [])
            if ports:
                self._process_ports(container_node, ports)
            
            # Process volume mounts
            volume_mounts = container.get('volumeMounts', [])
            if volume_mounts:
                container_node.metadata['volumeMounts'] = volume_mounts
            
            parent.children.append(container_node)
    
    def _process_security_context(self, parent: ASTNode, security_context: Dict):
        """Process security context settings."""
        sec_node = ASTNode(
            node_type=NodeType.SECURITY_CONTEXT.value,
            type='SecurityContext',
            parent=parent,
            metadata={
                'privileged': security_context.get('privileged', False),
                'allowPrivilegeEscalation': security_context.get('allowPrivilegeEscalation'),
                'runAsUser': security_context.get('runAsUser'),
                'runAsGroup': security_context.get('runAsGroup'),
                'runAsNonRoot': security_context.get('runAsNonRoot'),
                'readOnlyRootFilesystem': security_context.get('readOnlyRootFilesystem'),
                'capabilities': security_context.get('capabilities', {}),
                'seLinuxOptions': security_context.get('seLinuxOptions', {}),
                'seccompProfile': security_context.get('seccompProfile', {})
            }
        )
        parent.children.append(sec_node)
        parent.metadata['securityContext'] = security_context
    
    def _process_resource_requirements(self, parent: ASTNode, resources: Dict):
        """Process resource requests and limits."""
        res_node = ASTNode(
            node_type=NodeType.RESOURCE_REQUIREMENTS.value,
            type='ResourceRequirements',
            parent=parent,
            metadata={
                'requests': resources.get('requests', {}),
                'limits': resources.get('limits', {})
            }
        )
        parent.children.append(res_node)
        parent.metadata['resources'] = resources
    
    def _process_env_vars(self, parent: ASTNode, env_vars: List[Dict]):
        """Process environment variables."""
        for env in env_vars:
            env_node = ASTNode(
                node_type=NodeType.ENV_VAR.value,
                type='EnvVar',
                value=env.get('name', ''),
                parent=parent,
                metadata={
                    'name': env.get('name', ''),
                    'value': env.get('value', ''),
                    'valueFrom': env.get('valueFrom', {})
                }
            )
            parent.children.append(env_node)
    
    def _process_ports(self, parent: ASTNode, ports: List[Dict]):
        """Process container ports."""
        for port in ports:
            port_node = ASTNode(
                node_type=NodeType.PORT.value,
                type='Port',
                value=port.get('containerPort'),
                parent=parent,
                metadata={
                    'containerPort': port.get('containerPort'),
                    'hostPort': port.get('hostPort'),
                    'protocol': port.get('protocol', 'TCP'),
                    'name': port.get('name', '')
                }
            )
            parent.children.append(port_node)
    
    def _process_volumes(self, parent: ASTNode, volumes: List[Dict]):
        """Process volume specifications."""
        for volume in volumes:
            volume_node = ASTNode(
                node_type=NodeType.VOLUME.value,
                type='Volume',
                value=volume.get('name', ''),
                parent=parent,
                metadata={
                    'name': volume.get('name', ''),
                    'hostPath': volume.get('hostPath', {}),
                    'emptyDir': volume.get('emptyDir', {}),
                    'configMap': volume.get('configMap', {}),
                    'secret': volume.get('secret', {}),
                    'persistentVolumeClaim': volume.get('persistentVolumeClaim', {})
                }
            )
            parent.children.append(volume_node)
    
    def _extract_pod_security_settings(self, parent: ASTNode, pod_spec: Dict):
        """Extract pod-level security settings."""
        parent.metadata.update({
            'hostNetwork': pod_spec.get('hostNetwork', False),
            'hostPID': pod_spec.get('hostPID', False),
            'hostIPC': pod_spec.get('hostIPC', False),
            'serviceAccountName': pod_spec.get('serviceAccountName', 'default'),
            'automountServiceAccountToken': pod_spec.get('automountServiceAccountToken', True)
        })
        
        # Pod-level security context
        if 'securityContext' in pod_spec:
            parent.metadata['podSecurityContext'] = pod_spec['securityContext']
    
    def _process_cronjob(self, parent: ASTNode, doc: Dict):
        """Process CronJob resource."""
        spec = doc.get('spec', {})
        parent.metadata['schedule'] = spec.get('schedule', '')
        
        # Process job template
        job_template = spec.get('jobTemplate', {})
        job_spec = job_template.get('spec', {})
        template = job_spec.get('template', {})
        pod_spec = template.get('spec', {})
        
        containers = pod_spec.get('containers', [])
        self._process_containers(parent, containers, 'containers')
        
        # Process volumes
        volumes = pod_spec.get('volumes', [])
        if volumes:
            self._process_volumes(parent, volumes)
    
    def _process_service(self, parent: ASTNode, doc: Dict):
        """Process Service resource."""
        spec = doc.get('spec', {})
        parent.metadata.update({
            'type': spec.get('type', 'ClusterIP'),
            'ports': spec.get('ports', []),
            'selector': spec.get('selector', {}),
            'externalIPs': spec.get('externalIPs', [])
        })
    
    def _process_ingress(self, parent: ASTNode, doc: Dict):
        """Process Ingress resource."""
        spec = doc.get('spec', {})
        parent.metadata.update({
            'tls': spec.get('tls', []),
            'rules': spec.get('rules', []),
            'ingressClassName': spec.get('ingressClassName', '')
        })
    
    def _process_role(self, parent: ASTNode, doc: Dict):
        """Process Role/ClusterRole resource."""
        rules = doc.get('rules', [])
        parent.metadata['rules'] = rules
        
        # Extract all verbs and resources for analysis
        all_verbs = []
        all_resources = []
        for rule in rules:
            all_verbs.extend(rule.get('verbs', []))
            all_resources.extend(rule.get('resources', []))
        
        parent.metadata['all_verbs'] = list(set(all_verbs))
        parent.metadata['all_resources'] = list(set(all_resources))
    
    def _process_role_binding(self, parent: ASTNode, doc: Dict):
        """Process RoleBinding/ClusterRoleBinding resource."""
        parent.metadata.update({
            'subjects': doc.get('subjects', []),
            'roleRef': doc.get('roleRef', {})
        })
    
    def _process_network_policy(self, parent: ASTNode, doc: Dict):
        """Process NetworkPolicy resource."""
        spec = doc.get('spec', {})
        parent.metadata.update({
            'podSelector': spec.get('podSelector', {}),
            'ingress': spec.get('ingress', []),
            'egress': spec.get('egress', []),
            'policyTypes': spec.get('policyTypes', [])
        })
    
    def _process_secret(self, parent: ASTNode, doc: Dict):
        """Process Secret resource."""
        parent.metadata.update({
            'type': doc.get('type', 'Opaque'),
            'data': doc.get('data', {}),
            'stringData': doc.get('stringData', {})
        })
    
    def _process_configmap(self, parent: ASTNode, doc: Dict):
        """Process ConfigMap resource."""
        parent.metadata['data'] = doc.get('data', {})
    
    def _process_service_account(self, parent: ASTNode, doc: Dict):
        """Process ServiceAccount resource."""
        parent.metadata['automountServiceAccountToken'] = doc.get(
            'automountServiceAccountToken', True
        )
    
    def _process_generic_resource(self, parent: ASTNode, doc: Dict):
        """Generic processing for unknown resource types."""
        parent.metadata['spec'] = doc.get('spec', {})


def parse_kubernetes_to_ast(yaml_content: str, filename: str = "unknown") -> List[Dict]:
    """
    Main function to convert Kubernetes YAML to AST/Semantic Model.
    Returns list of AST dictionaries compatible with generic rule engine.
    
    Args:
        yaml_content: Raw YAML content as string
        filename: Name of the source file
    
    Returns:
        List of AST dictionaries ready for rule analysis
    """
    builder = KubernetesASTBuilder()
    ast_nodes = builder.build_ast(yaml_content, filename)
    
    # Convert AST nodes to dictionaries for generic rule engine
    return [node.to_dict() for node in ast_nodes]


def parse_kubernetes_file_to_ast(file_path: str) -> List[Dict]:
    """
    Parse a Kubernetes YAML file to AST.
    
    Args:
        file_path: Path to the Kubernetes YAML file
    
    Returns:
        List of AST dictionaries
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    return parse_kubernetes_to_ast(content, file_path)
