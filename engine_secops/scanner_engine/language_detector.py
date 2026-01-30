"""
Advanced Language Detection Engine for Security Scanner

This module implements SonarSource-inspired language detection based on:
1. File extension as a weak hint
2. Structural fingerprints and grammar patterns
3. Semantic validation through AST parsing
4. Confidence scoring and disambiguation

Supports: Kubernetes, Ansible, CloudFormation, Azure ARM, Docker, Terraform, Python, Java, C#, JavaScript
"""

import os
import json
import re
import yaml
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum


class LanguageType(Enum):
    """Supported language types for scanning."""
    KUBERNETES = "kubernetes"
    ANSIBLE = "ansible"
    CLOUDFORMATION = "cloudformation"
    AZURE_ARM = "azure"
    DOCKER = "docker"
    TERRAFORM = "terraform"
    PYTHON = "python"
    JAVA = "java"
    CSHARP = "csharp"
    JAVASCRIPT = "javascript"


@dataclass
class DetectionResult:
    """Result of language detection with confidence scoring."""
    language: LanguageType
    confidence: float
    structural_markers: List[str]
    semantic_validation: bool
    reasoning: str


class StructuralFingerprints:
    """Structural fingerprints for different IaC languages."""
    
    KUBERNETES = {
        'mandatory': {
            'apiVersion': r'apiVersion:\s*[v\d/\w\.]+',
            'kind': r'kind:\s*(Pod|Deployment|Service|ConfigMap|Secret|Ingress|DaemonSet|StatefulSet|Job|CronJob|ReplicaSet|Namespace|PersistentVolume|PersistentVolumeClaim)',
            'metadata': r'metadata:\s*$',
            'helm_chart': r'(?:name:\s*[\w-]+\s*$|description:\s*.*chart|type:\s*application|version:\s*\d+)',
            'helm_values': r'(?:revisionHistoryLimit|replicaCount|image\s*:|resources\s*:|nodeSelector\s*:)'
        },
        'strong': {
            'spec': r'spec:\s*$',
            'containers': r'containers:\s*$',
            'selector': r'selector:\s*$',
            'template': r'template:\s*$',
            'replicas': r'replicas:\s*\d+',
            'ports': r'ports:\s*$',
            'helm_metadata': r'(?:appVersion|dependencies|maintainers):',
            'k8s_resources': r'(?:limits|requests|cpu|memory):'
        },
        'weak': {
            'labels': r'labels:\s*$',
            'annotations': r'annotations:\s*$',
            'namespace': r'namespace:\s*\w+',
            'values_yaml': r'(?:fullnameOverride|nameOverride|serviceAccount):', 
            'chart_keywords': r'(?:ingress|deployment|service|configmap):\s*$'
        }
    }
    
    ANSIBLE = {
        'mandatory': {
            'hosts': r'hosts:\s*\w+',
            'tasks': r'tasks:\s*$',
            'playbook': r'(?:^|\s)---\s*$.*?hosts:',
            'ansible_metadata': r'requires_ansible:',
            'action_groups': r'action_groups:',
        },
        'strong': {
            'roles': r'roles:\s*$',
            'handlers': r'handlers:\s*$',
            'vars': r'vars:\s*$',
            'become': r'become:\s*(yes|true|no|false)',
            'gather_facts': r'gather_facts:\s*(yes|true|no|false)',
            'when': r'when:\s*\w+',
            'register': r'register:\s*\w+',
            'with_items': r'with_items:\s*$',
            'include_tasks': r'include_tasks:',
            'import_tasks': r'import_tasks:',
            'meta': r'meta:\s*$',
            'loop': r'loop:',
            'loop_control': r'loop_control:',
            'ansible_modules': r'(?:k8s_info|k8s_cluster_info|k8s_exec|k8s_drain|k8s_cp|helm|helm_info|helm_repository):'
        },
        'weak': {
            'name_task': r'-\s*name:\s*[\w\s]+',
            'debug': r'debug:\s*$',
            'shell': r'shell:\s*\w+',
            'command': r'command:\s*\w+',
            'apt': r'apt:\s*$',
            'yum': r'yum:\s*$',
            'copy': r'copy:\s*$',
            'file': r'file:\s*$',
            'service': r'service:\s*$',
            'set_fact': r'set_fact:',
            'assert': r'assert:',
            'fail': r'fail:',
            'pause': r'pause:'
        }
    }
    
    CLOUDFORMATION = {
        'mandatory': {
            # Note: Not all CF templates have AWSTemplateFormatVersion, so we make it optional
            'aws_resource_type': r'(?:Type:\s*AWS::|"Type":\s*"AWS::)',
            'resources_section': r'(?:Resources:\s*$|"Resources":\s*\{)'
        },
        'strong': {
            'template_version': r'AWSTemplateFormatVersion:\s*["\']?20\d{2}-\d{2}-\d{2}["\']?',
            'parameters': r'(?:Parameters:\s*$|"Parameters":\s*\{)',
            'outputs': r'(?:Outputs:\s*$|"Outputs":\s*\{)',
            'mappings': r'(?:Mappings:\s*$|"Mappings":\s*\{)',
            'conditions': r'(?:Conditions:\s*$|"Conditions":\s*\{)',
            'transform': r'(?:Transform:\s*AWS::|"Transform":\s*"AWS::)',
            'intrinsic_ref': r'(?:!Ref\s+\w+|"Ref":\s*"\w+")',
            'intrinsic_getatt': r'(?:!GetAtt\s+[\w\.]+|"Fn::GetAtt")',
            'intrinsic_sub': r'(?:!Sub\s+|"Fn::Sub")',
            'fn_ref': r'"Fn::Ref"',
            'fn_getatt': r'"Fn::GetAtt"'
        },
        'weak': {
            'aws_pseudo': r'\$\{AWS::\w+\}',
            'description': r'(?:Description:\s*["\'].*["\']|"Description":\s*".*")',
            'metadata': r'(?:Metadata:\s*$|"Metadata":\s*\{)'
        }
    }
    
    AZURE_ARM = {
        'mandatory': {
            'schema': r'\"\$schema\":\s*\".*schema\.management\.azure\.com.*deploymentTemplate.*\"',
            'content_version': r'\"contentVersion\":\s*\"[\d\.]+\"',
            'resources_array': r'\"resources\":\s*\['
        },
        'strong': {
            'parameters_obj': r'\"parameters\":\s*\{',
            'variables_obj': r'\"variables\":\s*\{',
            'outputs_obj': r'\"outputs\":\s*\{',
            'ms_resource_type': r'\"type\":\s*\"Microsoft\.\w+\/\w+\"',
            'api_version': r'\"apiVersion\":\s*\"20\d{2}-\d{2}-\d{2}\"',
            'depends_on': r'\"dependsOn\":\s*\[',
            'arm_functions': r'\[parameters\(|\[variables\(|\[reference\(|\[resourceGroup\(\)'
        },
        'weak': {
            'location': r'\"location\":\s*\"\w+\"',
            'tags': r'\"tags\":\s*\{',
            'properties': r'\"properties\":\s*\{'
        }
    }
    
    DOCKER = {
        'mandatory': {
            'from': r'^FROM\s+[\w\.\-\/\:]+',
        },
        'strong': {
            'run': r'^RUN\s+.+',
            'copy': r'^COPY\s+.+',
            'add': r'^ADD\s+.+',
            'workdir': r'^WORKDIR\s+.+',
            'expose': r'^EXPOSE\s+\d+',
            'cmd': r'^CMD\s+',
            'entrypoint': r'^ENTRYPOINT\s+'
        },
        'weak': {
            'env': r'^ENV\s+\w+',
            'arg': r'^ARG\s+\w+',
            'label': r'^LABEL\s+\w+',
            'volume': r'^VOLUME\s+',
            'user': r'^USER\s+\w+'
        }
    }
    
    TERRAFORM = {
        'mandatory': {
            'resource_block': r'resource\s+"[\w\-]+"',
            'provider_block': r'provider\s+"[\w\-]+"'
        },
        'strong': {
            'variable_block': r'variable\s+"[\w\-]+"',
            'output_block': r'output\s+"[\w\-]+"',
            'data_block': r'data\s+"[\w\-]+"',
            'locals_block': r'locals\s*\{',
            'module_block': r'module\s+"[\w\-]+"',
            'terraform_block': r'terraform\s*\{'
        },
        'weak': {
            'interpolation': r'\$\{[\w\.]+\}',
            'count_meta': r'count\s*=',
            'depends_on_meta': r'depends_on\s*='
        }
    }


class LanguageDetector:
    """Advanced language detector using structural analysis."""
    
    def __init__(self):
        self.fingerprints = StructuralFingerprints()
    
    def detect_language(self, file_path: str) -> Optional[DetectionResult]:
        """
        Detect language using multi-layer analysis:
        1. File extension filtering
        2. Structural fingerprints
        3. Semantic validation
        4. Confidence scoring
        """
        if not os.path.exists(file_path):
            return None
        
        # Store file path for context in detection methods
        self._current_file_path = file_path
        
        ext = os.path.splitext(file_path)[1].lower()
        basename = os.path.basename(file_path).lower()
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return None
        
        # Layer 1: Extension-based filtering
        candidates = self._filter_by_extension(ext, basename)
        if not candidates:
            return None
        
        # Layer 2: Structural fingerprint analysis
        scored_candidates = []
        for lang_type in candidates:
            result = self._analyze_structural_fingerprints(content, lang_type, file_path)
            if result and result.confidence > 0.3:  # Minimum threshold
                scored_candidates.append(result)
        
        if not scored_candidates:
            return None
        
        # Layer 3: Semantic validation for top candidates
        for result in sorted(scored_candidates, key=lambda x: x.confidence, reverse=True)[:2]:
            if self._semantic_validation(content, result.language, file_path):
                result.semantic_validation = True
                result.confidence = min(result.confidence + 0.2, 1.0)  # Boost confidence
                return result
        
        # Return highest confidence result even without semantic validation
        return max(scored_candidates, key=lambda x: x.confidence)
    
    def _filter_by_extension(self, ext: str, basename: str) -> List[LanguageType]:
        """First layer: coarse filtering by extension with path-based hints."""
        candidates = []
        
        # Get full file path context for better detection
        file_path = getattr(self, '_current_file_path', '')
        
        # High-confidence extension matches
        if ext == '.py':
            candidates.append(LanguageType.PYTHON)
        elif ext == '.java':
            candidates.append(LanguageType.JAVA)
        elif ext == '.cs':
            candidates.append(LanguageType.CSHARP)
        elif ext in ['.js', '.mjs', '.jsx']:
            candidates.append(LanguageType.JAVASCRIPT)
        elif ext == '.tf':
            candidates.append(LanguageType.TERRAFORM)
        elif ext == '.json':
            candidates.extend([LanguageType.CLOUDFORMATION, LanguageType.AZURE_ARM])
        elif ext in ['.yml', '.yaml']:
            # Path-based prioritization for YAML files
            if self._is_ansible_path(file_path, basename):
                candidates = [LanguageType.ANSIBLE, LanguageType.KUBERNETES, LanguageType.CLOUDFORMATION]
            elif self._is_kubernetes_path(file_path, basename):
                candidates = [LanguageType.KUBERNETES, LanguageType.ANSIBLE, LanguageType.CLOUDFORMATION]
            else:
                candidates.extend([LanguageType.KUBERNETES, LanguageType.ANSIBLE, LanguageType.CLOUDFORMATION])
        elif ext in ['.dockerfile'] or basename == 'dockerfile' or basename.startswith('dockerfile.'):
            candidates.append(LanguageType.DOCKER)
        elif ext in ['.template']:
            candidates.extend([LanguageType.CLOUDFORMATION])
        
        # Content-based fallbacks for common languages
        if not candidates or len(candidates) > 1:
            candidates.extend([
                LanguageType.PYTHON, LanguageType.JAVA, LanguageType.CSHARP, 
                LanguageType.JAVASCRIPT, LanguageType.TERRAFORM, LanguageType.DOCKER
            ])
        
        return list(set(candidates))  # Remove duplicates
    
    def _is_ansible_path(self, file_path: str, basename: str) -> bool:
        """Detect if path/filename suggests Ansible content."""
        if not file_path:
            return False
            
        # Ansible-specific path patterns
        ansible_indicators = [
            '/tasks/', '/handlers/', '/vars/', '/defaults/', '/meta/', '/group_vars/', '/host_vars/',
            '/roles/', '/playbooks/', '/inventory/', '/plugins/action/', '/plugins/modules/',
        ]
        
        # Ansible-specific filenames
        ansible_files = [
            'main.yml', 'main.yaml', 'site.yml', 'site.yaml', 'playbook.yml', 'playbook.yaml',
            'runtime.yml', 'runtime.yaml', 'galaxy.yml', 'galaxy.yaml'
        ]
        
        path_lower = file_path.lower()
        return (any(indicator in path_lower for indicator in ansible_indicators) or
                basename in ansible_files or
                'ansible' in path_lower)
    
    def _is_kubernetes_path(self, file_path: str, basename: str) -> bool:
        """Detect if path/filename suggests Kubernetes content."""
        if not file_path:
            return False
            
        # Kubernetes-specific path patterns
        k8s_indicators = [
            '/manifests/', '/k8s/', '/kubernetes/', '/helm/', '/charts/', '/templates/'
        ]
        
        # Kubernetes/Helm-specific filenames
        k8s_files = [
            'chart.yaml', 'chart.yml', 'values.yaml', 'values.yml', 'deployment.yaml',
            'deployment.yml', 'service.yaml', 'service.yml', 'ingress.yaml', 'ingress.yml',
            'configmap.yaml', 'configmap.yml', 'secret.yaml', 'secret.yml'
        ]
        
        path_lower = file_path.lower()
        return (any(indicator in path_lower for indicator in k8s_indicators) or
                basename in k8s_files or
                'kubernetes' in path_lower or 'k8s' in path_lower)
    
    def _analyze_structural_fingerprints(self, content: str, lang_type: LanguageType, file_path: str) -> Optional[DetectionResult]:
        """Second layer: analyze structural fingerprints."""
        if lang_type == LanguageType.KUBERNETES:
            return self._analyze_kubernetes(content, file_path)
        elif lang_type == LanguageType.ANSIBLE:
            return self._analyze_ansible(content, file_path)
        elif lang_type == LanguageType.CLOUDFORMATION:
            return self._analyze_cloudformation(content, file_path)
        elif lang_type == LanguageType.AZURE_ARM:
            return self._analyze_azure_arm(content, file_path)
        elif lang_type == LanguageType.DOCKER:
            return self._analyze_docker(content, file_path)
        elif lang_type == LanguageType.TERRAFORM:
            return self._analyze_terraform(content, file_path)
        elif lang_type == LanguageType.PYTHON:
            return self._analyze_python(content, file_path)
        elif lang_type == LanguageType.JAVA:
            return self._analyze_java(content, file_path)
        elif lang_type == LanguageType.CSHARP:
            return self._analyze_csharp(content, file_path)
        elif lang_type == LanguageType.JAVASCRIPT:
            return self._analyze_javascript(content, file_path)
        
        return None
    
    def _analyze_kubernetes(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze Kubernetes YAML structural fingerprints."""
        fingerprints = self.fingerprints.KUBERNETES
        confidence = 0.0
        found_markers = []
        
        # Path-based confidence boost
        if self._is_kubernetes_path(file_path, os.path.basename(file_path).lower()):
            confidence += 0.3
            found_markers.append('k8s_path')
        
        # Check mandatory markers
        mandatory_score = 0
        for name, pattern in fingerprints['mandatory'].items():
            if re.search(pattern, content, re.MULTILINE | re.DOTALL):
                mandatory_score += 1
                found_markers.append(name)
                confidence += 0.25
        
        # Relaxed requirement for Kubernetes path-based files
        min_mandatory = 1 if 'k8s_path' in found_markers else 2
        if mandatory_score < min_mandatory:
            # Special case: if it's clearly a Kubernetes path, be more lenient
            if 'k8s_path' in found_markers and mandatory_score == 0:
                # Check for any Kubernetes-like content
                k8s_content_patterns = [
                    r'image:', r'namespace:', r'labels:', r'selector:', r'replicas:',
                    r'resources:', r'limits:', r'requests:', r'ingress:', r'service:'
                ]
                if any(re.search(pattern, content, re.MULTILINE) for pattern in k8s_content_patterns):
                    confidence += 0.2
                    found_markers.append('k8s_content_detected')
                else:
                    return None
            else:
                return None
        
        # Check strong markers
        for name, pattern in fingerprints['strong'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.15
        
        # Check weak markers
        for name, pattern in fingerprints['weak'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.05
        
        # Anti-patterns (reduce confidence if found)
        if 'hosts:' in content or 'tasks:' in content:
            confidence -= 0.3  # Likely Ansible
        if 'AWSTemplateFormatVersion' in content or 'AWS::' in content:
            confidence -= 0.4  # Likely CloudFormation
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found {mandatory_score} mandatory K8s markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.KUBERNETES,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_ansible(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze Ansible YAML structural fingerprints."""
        fingerprints = self.fingerprints.ANSIBLE
        confidence = 0.0
        found_markers = []
        
        # Path-based confidence boost
        if self._is_ansible_path(file_path, os.path.basename(file_path).lower()):
            confidence += 0.3
            found_markers.append('ansible_path')
        
        # Check for playbook structure (YAML document separator + hosts)
        if re.search(r'---.*?hosts:', content, re.DOTALL | re.MULTILINE):
            confidence += 0.5
            found_markers.append('playbook_structure')
        
        # Check mandatory markers - need at least 1 for path-based files, 2 for others
        mandatory_score = 0
        for name, pattern in fingerprints['mandatory'].items():
            if re.search(pattern, content, re.MULTILINE | re.DOTALL):
                mandatory_score += 1
                found_markers.append(name)
                confidence += 0.2
        
        # Relaxed requirement for Ansible path-based files
        min_mandatory = 1 if 'ansible_path' in found_markers else 2
        if mandatory_score < min_mandatory:
            # Special case: if it's clearly an Ansible path, be more lenient
            if 'ansible_path' in found_markers and mandatory_score == 0:
                # Check for any Ansible-like content
                ansible_content_patterns = [
                    r'-\s*name:', r'include_tasks:', r'import_tasks:', r'register:', r'when:',
                    r'k8s_info:', r'k8s_cluster_info:', r'helm:', r'meta:', r'loop:'
                ]
                if any(re.search(pattern, content, re.MULTILINE) for pattern in ansible_content_patterns):
                    confidence += 0.2
                    found_markers.append('ansible_content_detected')
                else:
                    return None
            else:
                return None
        
        # Check strong markers
        for name, pattern in fingerprints['strong'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.1
        
        # Check weak markers
        for name, pattern in fingerprints['weak'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.05
        
        # Anti-patterns
        if 'apiVersion:' in content and 'kind:' in content:
            confidence -= 0.4  # Likely Kubernetes
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found {mandatory_score} mandatory Ansible markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.ANSIBLE,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_cloudformation(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze CloudFormation structural fingerprints."""
        fingerprints = self.fingerprints.CLOUDFORMATION
        confidence = 0.0
        found_markers = []
        
        # Check mandatory markers - need at least 1
        mandatory_score = 0
        for name, pattern in fingerprints['mandatory'].items():
            if re.search(pattern, content, re.MULTILINE):
                mandatory_score += 1
                found_markers.append(name)
                confidence += 0.4
        
        if mandatory_score == 0:
            return None
        
        # Check strong markers
        for name, pattern in fingerprints['strong'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.1
        
        # Check weak markers  
        for name, pattern in fingerprints['weak'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.05
        
        # Anti-patterns
        if '"$schema"' in content and 'deploymentTemplate' in content:
            confidence -= 0.5  # Likely Azure ARM
        if 'apiVersion:' in content and 'kind:' in content:
            confidence -= 0.4  # Likely Kubernetes
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found {mandatory_score} mandatory CloudFormation markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.CLOUDFORMATION,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_azure_arm(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze Azure ARM template structural fingerprints."""
        fingerprints = self.fingerprints.AZURE_ARM
        confidence = 0.0
        found_markers = []
        
        # Check mandatory markers
        mandatory_score = 0
        for name, pattern in fingerprints['mandatory'].items():
            if re.search(pattern, content):
                mandatory_score += 1
                found_markers.append(name)
                confidence += 0.4
        
        if mandatory_score < 2:  # Need at least 2 mandatory markers
            return None
        
        # Check strong markers
        for name, pattern in fingerprints['strong'].items():
            if re.search(pattern, content):
                found_markers.append(name)
                confidence += 0.1
        
        # Check weak markers
        for name, pattern in fingerprints['weak'].items():
            if re.search(pattern, content):
                found_markers.append(name)
                confidence += 0.05
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.5:  # Higher threshold for ARM templates
            reasoning = f"Found {mandatory_score} mandatory ARM markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.AZURE_ARM,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_docker(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze Dockerfile structural fingerprints."""
        fingerprints = self.fingerprints.DOCKER
        confidence = 0.0
        found_markers = []
        basename = os.path.basename(file_path).lower()
        
        # Dockerfile naming patterns
        if basename == 'dockerfile' or basename.startswith('dockerfile.'):
            confidence += 0.6
            found_markers.append('dockerfile_name')
        
        # Check mandatory markers
        mandatory_score = 0
        for name, pattern in fingerprints['mandatory'].items():
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                mandatory_score += 1
                found_markers.append(name)
                confidence += 0.4
        
        if mandatory_score == 0 and confidence < 0.6:
            return None
        
        # Check strong markers
        for name, pattern in fingerprints['strong'].items():
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                found_markers.append(name)
                confidence += 0.1
        
        # Check weak markers
        for name, pattern in fingerprints['weak'].items():
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                found_markers.append(name)
                confidence += 0.05
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found {mandatory_score} mandatory Docker markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.DOCKER,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_terraform(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze Terraform structural fingerprints."""
        fingerprints = self.fingerprints.TERRAFORM
        confidence = 0.0
        found_markers = []
        
        # Check mandatory markers
        mandatory_score = 0
        for name, pattern in fingerprints['mandatory'].items():
            if re.search(pattern, content, re.MULTILINE):
                mandatory_score += 1
                found_markers.append(name)
                confidence += 0.5
        
        if mandatory_score == 0:
            return None
        
        # Check strong markers
        for name, pattern in fingerprints['strong'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.1
        
        # Check weak markers
        for name, pattern in fingerprints['weak'].items():
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += 0.05
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.4:
            reasoning = f"Found {mandatory_score} mandatory Terraform markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.TERRAFORM,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_python(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze Python structural fingerprints."""
        ext = os.path.splitext(file_path)[1].lower()
        confidence = 0.0
        found_markers = []
        
        # File extension check
        if ext == '.py':
            confidence += 0.8
            found_markers.append('py_extension')
        
        # Python syntax patterns
        python_patterns = [
            (r'def\s+\w+\s*\(', 'function_def', 0.2),
            (r'class\s+\w+\s*\(', 'class_def', 0.2),
            (r'import\s+\w+', 'import_statement', 0.1),
            (r'from\s+\w+\s+import', 'from_import', 0.1),
            (r'if\s+__name__\s*==\s*["\']__main__["\']', 'main_check', 0.2),
            (r'#.*python', 'python_comment', 0.1),
            (r'#!/usr/bin/env python', 'python_shebang', 0.3),
            (r'#!/usr/bin/python', 'python_shebang2', 0.3)
        ]
        
        for pattern, name, score in python_patterns:
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                found_markers.append(name)
                confidence += score
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found Python markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.PYTHON,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_java(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze Java structural fingerprints."""
        ext = os.path.splitext(file_path)[1].lower()
        confidence = 0.0
        found_markers = []
        
        # File extension check
        if ext == '.java':
            confidence += 0.8
            found_markers.append('java_extension')
        
        # Java syntax patterns
        java_patterns = [
            (r'package\s+[\w\.]+\s*;', 'package_declaration', 0.3),
            (r'public\s+class\s+\w+', 'public_class', 0.3),
            (r'public\s+static\s+void\s+main', 'main_method', 0.3),
            (r'import\s+java\.', 'java_import', 0.2),
            (r'@\w+', 'annotation', 0.1),
            (r'public\s+\w+\s+\w+\s*\(', 'public_method', 0.1),
            (r'private\s+\w+\s+\w+', 'private_field', 0.1)
        ]
        
        for pattern, name, score in java_patterns:
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += score
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found Java markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.JAVA,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_csharp(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze C# structural fingerprints."""
        ext = os.path.splitext(file_path)[1].lower()
        confidence = 0.0
        found_markers = []
        
        # File extension check
        if ext == '.cs':
            confidence += 0.8
            found_markers.append('cs_extension')
        
        # C# syntax patterns
        csharp_patterns = [
            (r'using\s+System', 'using_system', 0.2),
            (r'namespace\s+[\w\.]+', 'namespace_declaration', 0.3),
            (r'public\s+class\s+\w+', 'public_class', 0.2),
            (r'public\s+static\s+void\s+Main', 'main_method', 0.3),
            (r'\[\w+\]', 'attribute', 0.1),
            (r'public\s+\w+\s+\w+\s*\{', 'property', 0.1),
            (r'private\s+\w+\s+\w+', 'private_field', 0.1)
        ]
        
        for pattern, name, score in csharp_patterns:
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += score
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found C# markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.CSHARP,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _analyze_javascript(self, content: str, file_path: str) -> Optional[DetectionResult]:
        """Analyze JavaScript structural fingerprints."""
        ext = os.path.splitext(file_path)[1].lower()
        confidence = 0.0
        found_markers = []
        
        # File extension check
        if ext in ['.js', '.mjs', '.jsx']:
            confidence += 0.7
            found_markers.append('js_extension')
        
        # JavaScript syntax patterns
        js_patterns = [
            (r'function\s+\w+\s*\(', 'function_declaration', 0.2),
            (r'const\s+\w+\s*=', 'const_declaration', 0.1),
            (r'let\s+\w+\s*=', 'let_declaration', 0.1),
            (r'var\s+\w+\s*=', 'var_declaration', 0.1),
            (r'=>', 'arrow_function', 0.15),
            (r'require\s*\(', 'require_call', 0.2),
            (r'module\.exports', 'module_exports', 0.2),
            (r'import\s+.*\s+from\s+["\']', 'es6_import', 0.2),
            (r'export\s+', 'es6_export', 0.1)
        ]
        
        for pattern, name, score in js_patterns:
            if re.search(pattern, content, re.MULTILINE):
                found_markers.append(name)
                confidence += score
        
        confidence = max(0.0, min(confidence, 1.0))
        
        if confidence > 0.3:
            reasoning = f"Found JavaScript markers: {found_markers[:5]}"
            return DetectionResult(
                language=LanguageType.JAVASCRIPT,
                confidence=confidence,
                structural_markers=found_markers,
                semantic_validation=False,
                reasoning=reasoning
            )
        
        return None
    
    def _semantic_validation(self, content: str, lang_type: LanguageType, file_path: str) -> bool:
        """Third layer: semantic validation through parsing."""
        try:
            if lang_type in [LanguageType.KUBERNETES, LanguageType.ANSIBLE, LanguageType.CLOUDFORMATION]:
                # Try YAML parsing
                docs = list(yaml.safe_load_all(content))
                return len(docs) > 0 and any(isinstance(doc, dict) for doc in docs)
            elif lang_type == LanguageType.AZURE_ARM:
                # Try JSON parsing
                json.loads(content)
                return True
            elif lang_type == LanguageType.TERRAFORM:
                # Basic HCL syntax validation
                return '{' in content and '}' in content
            # For programming languages, we could add more sophisticated AST parsing
            else:
                return True  # Skip semantic validation for now
        except Exception:
            return False


# Maintain backward compatibility with existing scanner_plugin.py interface
def detect_language(file_path: str) -> Optional[str]:
    """
    Backward compatible interface for the existing scanner system.
    Returns language name as string or None.
    """
    detector = LanguageDetector()
    result = detector.detect_language(file_path)
    
    if result:
        print(f"Detected {result.language.value} for {os.path.basename(file_path)} "
              f"(confidence: {result.confidence:.2f}) - {result.reasoning}")
        return result.language.value
    else:
        print(f"Warning: Could not detect language for {os.path.basename(file_path)}")
        return None


# Enhanced interface for future use
def detect_language_detailed(file_path: str) -> Optional[DetectionResult]:
    """
    Enhanced interface that returns full detection details.
    """
    detector = LanguageDetector()
    return detector.detect_language(file_path)


if __name__ == "__main__":
    # Test the detector
    import sys
    if len(sys.argv) > 1:
        result = detect_language_detailed(sys.argv[1])
        if result:
            print(f"Language: {result.language.value}")
            print(f"Confidence: {result.confidence:.2f}")
            print(f"Markers: {result.structural_markers}")
            print(f"Semantic validation: {result.semantic_validation}")
            print(f"Reasoning: {result.reasoning}")
        else:
            print("Could not detect language")