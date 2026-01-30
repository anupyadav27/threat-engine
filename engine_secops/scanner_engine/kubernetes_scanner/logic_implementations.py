"""
Kubernetes Rule Logic Implementations

This module contains custom logic functions for Kubernetes security rules.
Each function implements specific security checks that cannot be expressed
through generic rule metadata alone.

Function signatures can be either:
1. Node-based: func(node) -> bool
2. Manifest-based: func(manifest, filename) -> List[Dict]
"""


def check_privilege_escalation_containers(manifest, filename):
    """
    Check for containers with allowPrivilegeEscalation: true
    
    This function checks all containers in Pod-like resources for the
    allowPrivilegeEscalation security setting.
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        # Fallback: check if container properties are merged at root level
        security_context = manifest.get('securityContext', {})
        if security_context.get('allowPrivilegeEscalation') == True:
            findings.append({
                "rule_id": "allowing_process_privilege_escalations",
                "message": f"{kind} '{resource_name}' allows privilege escalation (allowPrivilegeEscalation: true). This exposes the Pod to attacks that exploit setuid binaries.",
                "resource": f"{kind}/{resource_name}",
                "file": filename,
                "line": line,
                "severity": "Major",
                "status": "violation",
                "property_path": ["securityContext", "allowPrivilegeEscalation"],
                "value": True
            })
        return findings
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Check allowPrivilegeEscalation in metadata.securityContext
            metadata = child.get('metadata', {})
            security_context = metadata.get('securityContext', {})
            
            if security_context.get('allowPrivilegeEscalation') == True:
                findings.append({
                    "rule_id": "allowing_process_privilege_escalations",
                    "message": f"Container '{container_name}' allows privilege escalation. This exposes the Pod to attacks that exploit setuid binaries.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": child.get('__line__', line),
                    "severity": "Major",
                    "status": "violation",
                    "property_path": ["containers", container_name, "securityContext", "allowPrivilegeEscalation"],
                    "value": True
                })
    
    return findings


def check_helm_template_whitespace(manifest, filename):
    """
    Check for Helm template directives without proper whitespace.
    
    This function checks all string values in a Kubernetes manifest for Helm
    template directives ({{ ... }}) that don't have whitespace after {{ and before }}.
    
    Valid: {{ .Values.name }}
    Invalid: {{.Values.name}}, {{ .Values.name}}, {{.Values.name }}
    
    Returns: List of findings
    """
    import re
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Regex pattern to detect improper whitespace in Helm templates
    # Must match: {{ without space OR }} without space before, for complete {{...}} blocks
    # Pattern matches complete template blocks that violate whitespace rules:
    # {{X}} or {{ X}} or {{X }} where X is non-whitespace
    bad_template_pattern = r'\{\{(?:\S|.*\S)\}\}'  # Matches {{...}} where no space after {{ OR no space before }}
    
    def check_string_value(value, path=[]):
        """Recursively check string values for bad template patterns."""
        if isinstance(value, str) and '{{' in value and '}}' in value:
            # Find all template directives
            templates = re.finditer(r'\{\{.*?\}\}', value)
            for match in templates:
                template = match.group()
                # Check if template has proper whitespace: {{ SPACE content SPACE }}
                # Valid: "{{ .Value }}" - starts with space after {{ and ends with space before }}
                # Invalid: "{{.Value}}", "{{ .Value}}", "{{.Value }}"
                if not (template.startswith('{{ ') and template.endswith(' }}')):
                    findings.append({
                        "rule_id": "ensure_whitespace_inbetween_braces",
                        "message": f"Template directive in '{'.'.join(map(str, path))}' does not have proper whitespace after '{{{{' and before '}}}}'.",
                        "resource": f"{kind}/{resource_name}",
                        "file": filename,
                        "line": line,
                        "severity": "Info",
                        "status": "violation",
                        "property_path": path,
                        "value": value
                    })
                    return  # Only report once per value
        elif isinstance(value, dict):
            for k, v in value.items():
                # Skip internal fields like metadata, children, __line__ to avoid duplicates
                if k not in ['metadata', 'children', '__line__', 'node_type', 'type']:
                    check_string_value(v, path + [k])
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                check_string_value(item, path + [f"[{idx}]"])
    
    # Check only the direct manifest fields (skip metadata to avoid duplicates)
    for key, value in manifest.items():
        if key not in ['metadata', 'children', '__line__', 'kind', 'apiVersion', 'name']:
            check_string_value(value, [key])
    
    return findings


def check_duplicate_environment_variables(manifest, filename):
    """
    Check for duplicate environment variable names in containers.
    
    This function checks all containers in Pod-like resources for duplicate
    environment variable names. The last declared variable overwrites previous ones,
    leading to unpredictable behavior.
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Get env variables from metadata
            metadata = child.get('metadata', {})
            env_vars = metadata.get('env', [])
            
            if not isinstance(env_vars, list):
                continue
            
            # Track env variable names and their occurrences
            env_name_count = {}
            for env_var in env_vars:
                if isinstance(env_var, dict):
                    env_name = env_var.get('name')
                    if env_name:
                        if env_name in env_name_count:
                            env_name_count[env_name] += 1
                        else:
                            env_name_count[env_name] = 1
            
            # Report duplicates
            for env_name, count in env_name_count.items():
                if count > 1:
                    findings.append({
                        "rule_id": "environment_variables_container_duplicated",
                        "message": f"Container '{container_name}' has duplicate environment variable '{env_name}' declared {count} times. The last value will overwrite previous ones, causing unpredictable behavior.",
                        "resource": f"{kind}/{resource_name}",
                        "file": filename,
                        "line": child.get('__line__', line),
                        "severity": "Info",
                        "status": "violation",
                        "property_path": ["containers", container_name, "env", env_name],
                        "value": f"Duplicate count: {count}"
                    })
    
    return findings


def check_administration_ports(manifest, filename):
    """
    Check for containers exposing common administration service ports.
    
    This function checks all containers in Pod-like resources for containerPort
    declarations that match common administration services like SSH, RDP, Telnet, etc.
    These ports increase the attack surface and should be avoided.
    
    Common administration ports:
    - 22: SSH
    - 23: Telnet
    - 3389: RDP (Remote Desktop Protocol)
    - 5900-5906: VNC
    - 5985, 5986: WinRM
    - 873: rsync
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Define administration service ports
    admin_ports = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP (Remote Desktop Protocol)",
        5900: "VNC",
        5901: "VNC",
        5902: "VNC",
        5903: "VNC",
        5904: "VNC",
        5905: "VNC",
        5906: "VNC",
        5985: "WinRM (HTTP)",
        5986: "WinRM (HTTPS)",
        873: "rsync"
    }
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Get port children (ports are stored as Port nodes in the container's children)
            container_children = child.get('children', [])
            
            # Check each port child
            for port_node in container_children:
                if not isinstance(port_node, dict):
                    continue
                
                # Check if this is a Port node
                if port_node.get('node_type') == 'Port' or port_node.get('type') == 'Port':
                    container_port = port_node.get('value') or port_node.get('containerPort')
                    
                    # Check if port is in admin ports list
                    if container_port in admin_ports:
                        service_name = admin_ports[container_port]
                        findings.append({
                            "rule_id": "exposing_administration_services_containers",
                            "message": f"Container '{container_name}' exposes administration service port {container_port} ({service_name}). This increases the attack surface and may lead to unauthorized access or privilege escalation.",
                            "resource": f"{kind}/{resource_name}",
                            "file": filename,
                            "line": port_node.get('__line__', child.get('__line__', line)),
                            "severity": "Info",
                            "status": "violation",
                            "property_path": ["containers", container_name, "ports", "containerPort"],
                            "value": container_port
                        })
    
    return findings


def check_docker_socket_exposure(manifest, filename):
    """
    Check for Docker socket exposure through hostPath volumes.
    
    This function checks if any volume mounts the Docker socket (/var/run/docker.sock)
    from the host, which is a critical security risk as it grants full control over
    the Docker daemon.
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (volumes)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Check each volume child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a Volume node
        if child.get('node_type') == 'Volume' or child.get('type') == 'Volume':
            volume_name = child.get('value', 'unknown')
            
            # Check the volume's metadata for hostPath
            metadata = child.get('metadata', {})
            host_path = metadata.get('hostPath', {})
            
            if isinstance(host_path, dict):
                path = host_path.get('path', '')
                
                # Check if the path is the Docker socket
                if path and ('docker.sock' in path or path == '/var/run/docker.sock'):
                    findings.append({
                        "rule_id": "exposing_docker_sockets_is",
                        "message": f"Volume '{volume_name}' exposes Docker socket ({path}). This grants the container full control over the Docker daemon and could compromise the entire host system.",
                        "resource": f"{kind}/{resource_name}",
                        "file": filename,
                        "line": child.get('__line__', line),
                        "severity": "Major",
                        "status": "violation",
                        "property_path": ["volumes", volume_name, "hostPath", "path"],
                        "value": path
                    })
    
    return findings


def check_hardcoded_credentials(manifest, filename):
    """
    Check for hard-coded credentials in environment variables.
    
    This function checks all containers in Pod-like resources for environment
    variables with credential-related names (password, pwd, secret, token, etc.)
    that have hard-coded values instead of using valueFrom with secretKeyRef.
    
    Credential patterns checked:
    - password, passwd, pwd
    - secret
    - token
    - credential, cred
    - auth, authorization
    - api_key, apikey, api-key
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Credential-related keywords to check for
    credential_keywords = [
        'password', 'passwd', 'pwd',
        'secret',
        'token',
        'credential', 'cred',
        'auth', 'authorization',
        'api_key', 'apikey', 'api-key', 'api.key'
    ]
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Get env variables from metadata
            metadata = child.get('metadata', {})
            env_vars = metadata.get('env', [])
            
            if not isinstance(env_vars, list):
                continue
            
            # Check each environment variable
            for env_var in env_vars:
                if isinstance(env_var, dict):
                    env_name = env_var.get('name', '').lower()
                    
                    # Check if the env variable name matches credential keywords
                    is_credential = any(keyword in env_name for keyword in credential_keywords)
                    
                    if is_credential:
                        # Check if it uses 'value' (hard-coded) instead of 'valueFrom'
                        if 'value' in env_var and 'valueFrom' not in env_var:
                            findings.append({
                                "rule_id": "hardcoded_credentials_are_securitysensitive",
                                "message": f"Container '{container_name}' has hard-coded credential in environment variable '{env_var.get('name')}'. Use 'valueFrom' with 'secretKeyRef' to reference secrets securely instead of hard-coding values.",
                                "resource": f"{kind}/{resource_name}",
                                "file": filename,
                                "line": child.get('__line__', line),
                                "severity": "Major",
                                "status": "violation",
                                "property_path": ["containers", container_name, "env", env_var.get('name')],
                                "value": env_var.get('value', '')
                            })
    
    return findings


def check_hardcoded_secrets(manifest, filename):
    """
    Check for hard-coded secrets with pseudorandom/high-entropy values.
    
    This function checks all containers in Pod-like resources for environment
    variables with secret-related names (secret, token, credential, auth, api_key)
    that have pseudorandom hard-coded values (high entropy, non-human-readable strings).
    
    Secret patterns checked:
    - secret
    - token
    - credential, cred
    - auth, authorization
    - api_key, apikey, api-key, api.key
    
    The value is considered pseudorandom if it:
    - Has sufficient length (>= 16 characters)
    - Has high entropy (mix of characters, numbers, special chars)
    - Is not easily human-readable
    
    Returns: List of findings
    """
    import re
    import math
    
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Secret-related keywords to check for
    secret_keywords = [
        'secret',
        'token',
        'credential', 'cred',
        'auth', 'authorization',
        'api_key', 'apikey', 'api-key', 'api.key'
    ]
    
    def calculate_entropy(value):
        """Calculate Shannon entropy of a string."""
        if not value:
            return 0.0
        
        # Count frequency of each character
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(value)
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_pseudorandom_value(value):
        """
        Check if a value appears to be a pseudorandom secret.
        
        Criteria:
        - Length >= 16 characters (meaningful secrets are typically long)
        - High entropy (> 3.8 bits per character indicates good randomness)
        - Contains mix of alphanumeric characters
        - Not common readable patterns (e.g., simple words, URLs, hyphenated phrases)
        """
        if not isinstance(value, str):
            return False
        
        # Too short to be a meaningful secret token
        if len(value) < 16:
            return False
        
        # Check if it looks like a URL, path, or simple word pattern
        if value.startswith(('http://', 'https://', '/', './')):
            return False
        
        # Check if it's mostly spaces or repeating characters
        if len(set(value.strip())) < 8:
            return False
        
        # Check for human-readable patterns (words separated by common delimiters)
        # If string has multiple hyphen/underscore separators suggesting readable words
        separator_count = value.count('-') + value.count('_') + value.count(' ')
        if separator_count >= 2:
            # Likely human-readable like "development-token-for-testing"
            return False
        
        # Check for common word patterns (5+ consecutive lowercase letters repeated)
        # This catches things like "my-application-secret", "development-token"
        # But won't catch random strings like "7h3s3cr3tk3y1sf0rt0k3ng3n3r4t10n"
        word_pattern_count = len(re.findall(r'[a-z]{5,}', value.lower()))
        if word_pattern_count >= 3:
            # Multiple common word-like patterns suggest human-readable
            return False
        
        # Check for common API key/token prefixes that indicate secrets
        # These are strong indicators of pseudorandom secrets
        secret_prefixes = [
            'sk_', 'pk_', 'Bearer ', 'ya29.', 'eyJ',  # API keys, OAuth tokens, JWT
            'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',  # GitHub tokens
        ]
        has_secret_prefix = any(value.startswith(prefix) for prefix in secret_prefixes)
        
        # Calculate entropy
        entropy = calculate_entropy(value)
        
        # Entropy threshold depends on whether it has a known secret prefix
        # With prefix: lower threshold (> 3.5) since prefix is a strong indicator
        # Without prefix: higher threshold (> 3.8) to avoid false positives
        entropy_threshold = 3.5 if has_secret_prefix else 3.8
        
        # For reference: "aaaaaaa" has entropy ~0, "a1b2c3d4" has entropy ~3.0,
        # "f7a9s8d7f6as98df" has entropy ~3.8+
        # "development-token-for-testing" has entropy ~3.6 (but has word patterns)
        if entropy < entropy_threshold:
            return False
        
        # Check for alphanumeric mix (not just one type)
        has_letters = bool(re.search(r'[a-zA-Z]', value))
        has_numbers = bool(re.search(r'[0-9]', value))
        
        # Pseudorandom secrets typically have both letters and numbers
        # Or are very long strings with letters only (like base64)
        if has_letters and (has_numbers or len(value) >= 24):
            return True
        
        return False
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Get env variables from metadata
            metadata = child.get('metadata', {})
            env_vars = metadata.get('env', [])
            
            if not isinstance(env_vars, list):
                continue
            
            # Check each environment variable
            for env_var in env_vars:
                if isinstance(env_var, dict):
                    env_name = env_var.get('name', '').lower()
                    
                    # Check if the env variable name matches secret keywords
                    is_secret = any(keyword in env_name for keyword in secret_keywords)
                    
                    if is_secret:
                        # Check if it uses 'value' (hard-coded) instead of 'valueFrom'
                        if 'value' in env_var and 'valueFrom' not in env_var:
                            value = env_var.get('value', '')
                            
                            # Check if the value appears to be pseudorandom
                            if is_pseudorandom_value(value):
                                findings.append({
                                    "rule_id": "hardcoded_secrets_are_securitysensitive",
                                    "message": f"Container '{container_name}' has hard-coded pseudorandom secret in environment variable '{env_var.get('name')}'. The value appears to be a randomly generated secret. Use 'valueFrom' with 'secretKeyRef' to reference secrets securely.",
                                    "resource": f"{kind}/{resource_name}",
                                    "file": filename,
                                    "line": child.get('__line__', line),
                                    "severity": "Info",
                                    "status": "violation",
                                    "property_path": ["containers", container_name, "env", env_var.get('name')],
                                    "value": value
                                })
    
    return findings


def check_service_account_permissions(manifest, filename):
    """
    Check for overly permissive service account permissions in RBAC Roles and ClusterRoles.
    
    This function checks Role and ClusterRole resources for overly broad permissions
    that could be exploited if a pod is compromised. It looks for dangerous verbs
    and resource combinations that grant excessive access.
    
    Dangerous patterns checked:
    - Wildcard verb "*" (grants all permissions)
    - "create" on pods (can create new workloads)
    - "delete" on critical resources
    - "escalate" verb (can escalate privileges)
    - "bind" verb on roles/clusterroles (can bind elevated privileges)
    - "impersonate" verb (can impersonate users/groups)
    - Access to secrets with "get", "list", or "watch"
    - "patch" or "update" on pods/deployments (can modify workloads)
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a Role or ClusterRole
    if kind not in ['Role', 'ClusterRole']:
        return findings
    
    # Get the rules
    rules = manifest.get('rules', [])
    if not isinstance(rules, list):
        return findings
    
    # Dangerous verbs that grant excessive permissions
    dangerous_verbs = ['*', 'create', 'delete', 'escalate', 'bind', 'impersonate']
    sensitive_verbs_for_secrets = ['get', 'list', 'watch']
    modify_verbs = ['patch', 'update']
    
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        
        resources = rule.get('resources', [])
        verbs = rule.get('verbs', [])
        api_groups = rule.get('apiGroups', [])
        
        if not isinstance(resources, list) or not isinstance(verbs, list):
            continue
        
        # Check for wildcard verb (grants all permissions)
        if '*' in verbs:
            findings.append({
                "rule_id": "service_account_permissions_restricted",
                "message": f"{kind} '{resource_name}' grants wildcard (*) permissions in rule {idx}. This allows all operations on the specified resources and should be avoided.",
                "resource": f"{kind}/{resource_name}",
                "file": filename,
                "line": line,
                "severity": "Critical",
                "status": "violation",
                "property_path": ["rules", idx, "verbs"],
                "value": verbs
            })
            continue
        
        # Check for dangerous verb combinations
        for verb in verbs:
            # Check for escalate permission
            if verb == 'escalate':
                findings.append({
                    "rule_id": "service_account_permissions_restricted",
                    "message": f"{kind} '{resource_name}' allows 'escalate' permission in rule {idx}. This can be used to escalate privileges beyond the service account's permissions.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": line,
                    "severity": "Critical",
                    "status": "violation",
                    "property_path": ["rules", idx, "verbs"],
                    "value": verbs
                })
            
            # Check for bind permission on roles/clusterroles
            if verb == 'bind' and any(r in resources for r in ['roles', 'clusterroles']):
                findings.append({
                    "rule_id": "service_account_permissions_restricted",
                    "message": f"{kind} '{resource_name}' allows 'bind' permission on roles/clusterroles in rule {idx}. This can be used to bind elevated privileges to service accounts.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": line,
                    "severity": "Critical",
                    "status": "violation",
                    "property_path": ["rules", idx, "verbs"],
                    "value": verbs
                })
            
            # Check for impersonate permission
            if verb == 'impersonate':
                findings.append({
                    "rule_id": "service_account_permissions_restricted",
                    "message": f"{kind} '{resource_name}' allows 'impersonate' permission in rule {idx}. This allows impersonating users, groups, or service accounts.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": line,
                    "severity": "Critical",
                    "status": "violation",
                    "property_path": ["rules", idx, "verbs"],
                    "value": verbs
                })
            
            # Check for create permission on pods
            if verb == 'create' and 'pods' in resources:
                findings.append({
                    "rule_id": "service_account_permissions_restricted",
                    "message": f"{kind} '{resource_name}' allows 'create' permission on pods in rule {idx}. This can be exploited to create malicious workloads in the cluster.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": line,
                    "severity": "Critical",
                    "status": "violation",
                    "property_path": ["rules", idx, "verbs"],
                    "value": verbs
                })
            
            # Check for delete permission on critical resources
            if verb == 'delete' and any(r in resources for r in ['pods', 'deployments', 'services', 'configmaps', 'secrets']):
                critical_resources = [r for r in ['pods', 'deployments', 'services', 'configmaps', 'secrets'] if r in resources]
                findings.append({
                    "rule_id": "service_account_permissions_restricted",
                    "message": f"{kind} '{resource_name}' allows 'delete' permission on critical resources ({', '.join(critical_resources)}) in rule {idx}. This can cause service disruption.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": line,
                    "severity": "Critical",
                    "status": "violation",
                    "property_path": ["rules", idx, "verbs"],
                    "value": verbs
                })
            
            # Check for access to secrets
            if verb in sensitive_verbs_for_secrets and 'secrets' in resources:
                findings.append({
                    "rule_id": "service_account_permissions_restricted",
                    "message": f"{kind} '{resource_name}' allows '{verb}' permission on secrets in rule {idx}. This grants access to sensitive data like passwords and API keys.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": line,
                    "severity": "Critical",
                    "status": "violation",
                    "property_path": ["rules", idx, "verbs"],
                    "value": verbs
                })
    
    return findings


def check_privileged_mode_containers(manifest, filename):
    """
    Check for containers running in privileged mode.
    
    This function checks all containers in Pod-like resources for the
    privileged: true setting in securityContext. Running containers in
    privileged mode grants them almost the same privileges as processes
    running on the host, which significantly weakens container isolation.
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Check privileged mode in metadata.securityContext
            metadata = child.get('metadata', {})
            security_context = metadata.get('securityContext', {})
            
            if security_context.get('privileged') == True:
                findings.append({
                    "rule_id": "running_containers_privileged_mode",
                    "message": f"Container '{container_name}' is running in privileged mode. This grants the container almost all capabilities of the host machine and significantly weakens security isolation.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": child.get('__line__', line),
                    "severity": "Major",
                    "status": "violation",
                    "property_path": ["containers", container_name, "securityContext", "privileged"],
                    "value": True
                })
    
    return findings


def check_sensitive_filesystem_paths(manifest, filename):
    """
    Check for mounting sensitive file system paths from the host.
    
    This function checks all volumes in Pod-like resources for hostPath volumes
    that mount sensitive system directories. These paths can contain sensitive
    information or binaries that could be exploited.
    
    Sensitive paths checked:
    - /etc - System configuration files
    - /var - Variable data (logs, caches, databases)
    - /sys - System and kernel information
    - /proc - Process and kernel information
    - /root - Root user home directory
    - /boot - Boot loader files
    - /dev - Device files
    - /lib - System libraries
    - /bin, /sbin, /usr/bin, /usr/sbin - System binaries
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Sensitive paths that should not be mounted
    sensitive_paths = [
        '/etc', '/var', '/sys', '/proc', '/root', '/boot', '/dev',
        '/lib', '/lib64', '/bin', '/sbin', '/usr/bin', '/usr/sbin',
        '/usr/lib', '/usr/lib64'
    ]
    
    # Look for children (volumes)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Check each volume child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a Volume node
        if child.get('node_type') == 'Volume' or child.get('type') == 'Volume':
            volume_name = child.get('value', 'unknown')
            
            # Check the volume's metadata for hostPath
            metadata = child.get('metadata', {})
            host_path = metadata.get('hostPath', {})
            
            if isinstance(host_path, dict):
                path = host_path.get('path', '')
                
                if path:
                    # Check if the path starts with any sensitive path
                    for sensitive_path in sensitive_paths:
                        if path == sensitive_path or path.startswith(sensitive_path + '/'):
                            findings.append({
                                "rule_id": "mounting_sensitive_file_system",
                                "message": f"Volume '{volume_name}' mounts sensitive file system path '{path}'. This can lead to information disclosure and compromise of the host system. Avoid mounting system directories.",
                                "resource": f"{kind}/{resource_name}",
                                "file": filename,
                                "line": child.get('__line__', line),
                                "severity": "Info",
                                "status": "violation",
                                "property_path": ["volumes", volume_name, "hostPath", "path"],
                                "value": path
                            })
                            break  # Only report once per volume
    
    return findings


def check_parsing_failure(manifest, filename):
    """
    Check for YAML parsing failures in Kubernetes manifest files.
    
    This function attempts to detect if a file has YAML syntax errors by checking
    if the manifest is empty, invalid, or has parsing indicators.
    
    Note: This function is called AFTER parsing, so it will only catch files that
    partially parse or have subtle issues. Complete parsing failures are caught
    by the parser itself.
    
    Returns: List of findings
    """
    import yaml
    
    findings = []
    
    # Try to re-read and parse the file to catch any parsing errors
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file is empty
        if not content.strip():
            findings.append({
                "rule_id": "kubernetes_parsing_failure",
                "message": "Kubernetes manifest file is empty. No valid YAML content found.",
                "resource": "File/unknown",
                "file": filename,
                "line": 1,
                "severity": "Major",
                "status": "violation",
                "property_path": [],
                "value": "Empty file"
            })
            return findings
        
        # Try to parse all documents
        yaml_docs = content.split('\n---\n')
        parsed_count = 0
        failed_count = 0
        current_line = 1
        
        for doc_idx, doc_text in enumerate(yaml_docs):
            if not doc_text.strip():
                continue
            
            try:
                doc = yaml.safe_load(doc_text)
                if doc is not None:
                    parsed_count += 1
                current_line += doc_text.count('\n') + 1
            except yaml.YAMLError as e:
                failed_count += 1
                error_line = current_line
                error_msg = str(e)
                
                # Extract line number from error message if available
                import re
                line_match = re.search(r'line (\d+)', error_msg)
                if line_match:
                    error_line = int(line_match.group(1))
                
                findings.append({
                    "rule_id": "kubernetes_parsing_failure",
                    "message": f"YAML parsing error in document {doc_idx + 1}: {error_msg}. This prevents the file from being analyzed for security issues.",
                    "resource": f"File/document-{doc_idx + 1}",
                    "file": filename,
                    "line": error_line,
                    "severity": "Major",
                    "status": "violation",
                    "property_path": [],
                    "value": error_msg[:100]
                })
                
                current_line += doc_text.count('\n') + 1
        
        # If no documents were successfully parsed, report it
        if parsed_count == 0 and failed_count == 0:
            findings.append({
                "rule_id": "kubernetes_parsing_failure",
                "message": "No valid Kubernetes YAML documents found in file. Check YAML syntax and structure.",
                "resource": "File/unknown",
                "file": filename,
                "line": 1,
                "severity": "Major",
                "status": "violation",
                "property_path": [],
                "value": "No valid documents"
            })
    
    except Exception as e:
        # Catch any other file reading or processing errors
        findings.append({
            "rule_id": "kubernetes_parsing_failure",
            "message": f"Failed to process Kubernetes manifest file: {str(e)}",
            "resource": "File/unknown",
            "file": filename,
            "line": 1,
            "severity": "Major",
            "status": "violation",
            "property_path": [],
                "value": str(e)
        })
    
    return findings


def check_capabilities_settings(manifest, filename):
    """
    Check for containers with capabilities set in securityContext.
    
    This function checks all containers in Pod-like resources for the
    capabilities field in securityContext. Setting capabilities (add or drop)
    is security-sensitive and should be reviewed carefully as it can lead to
    privilege escalation and container escapes.
    
    Dangerous capabilities include:
    - SYS_ADMIN: Can mount filesystems, perform system administration tasks
    - NET_ADMIN: Can configure network interfaces
    - SYS_PTRACE: Can trace arbitrary processes
    - SYS_MODULE: Can load kernel modules
    - DAC_OVERRIDE: Can bypass file permission checks
    - And many others...
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        # Fallback: check if container properties are merged at root level
        security_context = manifest.get('securityContext', {})
        capabilities = security_context.get('capabilities', {})
        
        if capabilities:
            if capabilities.get('add') or capabilities.get('drop'):
                add_caps = capabilities.get('add', [])
                drop_caps = capabilities.get('drop', [])
                caps_info = []
                if add_caps:
                    caps_info.append(f"add: {', '.join(add_caps)}")
                if drop_caps:
                    caps_info.append(f"drop: {', '.join(drop_caps)}")
                
                findings.append({
                    "rule_id": "setting_capabilities_is_securitysensitive",
                    "message": f"{kind} '{resource_name}' sets capabilities ({'; '.join(caps_info)}). This is security-sensitive and can lead to privilege escalation and container escapes. Review carefully to ensure only necessary capabilities are granted.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": line,
                    "severity": "Major",
                    "status": "violation",
                    "property_path": ["securityContext", "capabilities"],
                    "value": capabilities
                })
        return findings
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Check capabilities in metadata.securityContext
            metadata = child.get('metadata', {})
            security_context = metadata.get('securityContext', {})
            capabilities = security_context.get('capabilities', {})
            
            if capabilities:
                add_caps = capabilities.get('add', [])
                drop_caps = capabilities.get('drop', [])
                
                # Only report if capabilities are actually being set (add or drop)
                if add_caps or drop_caps:
                    caps_info = []
                    if add_caps:
                        caps_info.append(f"add: {', '.join(add_caps)}")
                    if drop_caps:
                        caps_info.append(f"drop: {', '.join(drop_caps)}")
                    
                    # Highlight especially dangerous capabilities
                    dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 
                                     'DAC_OVERRIDE', 'SETUID', 'SETGID', 'SYS_CHROOT',
                                     'SYS_BOOT', 'SYS_TIME', 'SYS_RAWIO']
                    dangerous_found = [cap for cap in add_caps if cap in dangerous_caps]
                    
                    severity = "Critical" if dangerous_found else "Major"
                    extra_msg = f" Dangerous capabilities detected: {', '.join(dangerous_found)}." if dangerous_found else ""
                    
                    findings.append({
                        "rule_id": "setting_capabilities_is_securitysensitive",
                        "message": f"Container '{container_name}' sets capabilities ({'; '.join(caps_info)}).{extra_msg} This is security-sensitive and can lead to privilege escalation and container escapes. Review carefully to ensure only necessary capabilities are granted.",
                        "resource": f"{kind}/{resource_name}",
                        "file": filename,
                        "line": child.get('__line__', line),
                        "severity": severity,
                        "status": "violation",
                        "property_path": ["containers", container_name, "securityContext", "capabilities"],
                        "value": capabilities
                    })
    
    return findings


def check_image_version_tags(manifest, filename):
    """
    Check for containers using images without specific version tags.
    
    This function checks all containers in Pod-like resources for images that:
    - Use the ':latest' tag explicitly
    - Have no tag specified (defaults to :latest)
    - Use tag patterns like 'stable', 'dev', 'master', etc.
    
    Using specific version tags (e.g., nginx:1.21.6) is a best practice because:
    - Ensures reproducible builds
    - Prevents unexpected updates
    - Reduces version mismatch issues
    - Improves security by controlling what runs
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Non-specific tags that should be avoided
    non_specific_tags = ['latest', 'stable', 'master', 'main', 'dev', 'develop', 
                         'development', 'test', 'testing', 'prod', 'production', 
                         'release', 'edge', 'nightly', 'canary']
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Get image from metadata
            metadata = child.get('metadata', {})
            image = metadata.get('image', '')
            
            if not image:
                continue
            
            # Parse image to check for tag
            violation_detected = False
            violation_reason = ""
            
            # Check if image has no tag (no ':' separator)
            if ':' not in image:
                violation_detected = True
                violation_reason = "no version tag specified (defaults to :latest)"
            else:
                # Split image into name and tag
                image_parts = image.rsplit(':', 1)
                if len(image_parts) == 2:
                    image_name, image_tag = image_parts
                    
                    # Check if tag is in the non-specific list
                    if image_tag.lower() in non_specific_tags:
                        violation_detected = True
                        violation_reason = f"uses non-specific tag ':{image_tag}'"
                    # Check for SHA digest (these are good - sha256:abc123...)
                    elif image_tag.startswith('sha256:'):
                        violation_detected = False
                    # Check if tag looks like a digest reference
                    elif '@sha256:' in image:
                        violation_detected = False
            
            if violation_detected:
                findings.append({
                    "rule_id": "specific_version_tag_image",
                    "message": f"Container '{container_name}' uses image '{image}' which {violation_reason}. Use a specific version tag (e.g., 'nginx:1.21.6') to ensure reproducible builds and prevent unexpected updates.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": child.get('__line__', line),
                    "severity": "Info",
                    "status": "violation",
                    "property_path": ["containers", container_name, "image"],
                        "value": image
                    })
    
    return findings


def check_todo_tags(manifest, filename):
    """
    Check for TODO/FIXME/HACK tags in Kubernetes YAML comments.
    
    This function scans the YAML file for comments containing TODO, FIXME, HACK,
    XXX, or BUG tags that indicate incomplete or temporary code. These tags often
    get overlooked and should be tracked and addressed.
    
    Common tags detected:
    - TODO: Work that needs to be done
    - FIXME: Code that needs fixing
    - HACK: Temporary or non-ideal solutions
    - XXX: Warning about problematic code
    - BUG: Known bugs that need fixing
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Tags to search for (case-insensitive)
    todo_tags = ['TODO', 'FIXME', 'HACK', 'XXX', 'BUG', 'TEMP', 'TEMPORARY']
    
    try:
        # Read the file to scan for comments
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Scan each line for TODO tags in comments
        for line_num, line in enumerate(lines, start=1):
            # Check if line contains a comment (starts with # or has # after content)
            comment_match = line.find('#')
            if comment_match != -1:
                comment_text = line[comment_match:].strip()
                
                # Check for each TODO tag
                for tag in todo_tags:
                    # Case-insensitive search for the tag
                    if tag.lower() in comment_text.lower():
                        # Extract a meaningful portion of the comment (first 100 chars)
                        comment_preview = comment_text[:100].strip()
                        if len(comment_text) > 100:
                            comment_preview += "..."
                        
                        # Determine severity based on tag type
                        if tag in ['BUG', 'FIXME']:
                            severity = "Critical"
                        elif tag in ['HACK', 'XXX', 'TEMPORARY', 'TEMP']:
                            severity = "Major"
                        else:  # TODO and others
                            severity = "Info"
                        
                        findings.append({
                            "rule_id": "track_uses_todo_tags",
                            "message": f"Found {tag} comment: '{comment_preview}'. This indicates incomplete or temporary code that should be addressed before production deployment.",
                            "resource": f"File/{filename}",
                            "file": filename,
                            "line": line_num,
                            "severity": severity,
                            "status": "violation",
                            "property_path": ["comment", "line", str(line_num)],
                            "value": comment_preview
                        })
                        
                        # Only report once per line (don't report multiple tags on same line)
                        break
    
    except Exception as e:
        # If we can't read the file, just return empty findings
        pass
    
    return findings


def check_cleartext_protocols(manifest, filename):
    """
    Check for usage of clear-text protocols (HTTP, FTP, Telnet)
    
    This function scans for insecure protocols in:
    - Container images (http:// URLs)
    - Environment variables (URLs with http://, ftp://, telnet://)
    - Container args and commands (protocol references)
    - Service ports (21 for FTP, 23 for Telnet, 80 for HTTP)
    - ConfigMap/Secret data (URLs)
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Patterns to detect cleartext protocols
    import re
    cleartext_patterns = {
        'http': re.compile(r'\bhttp://[^\s]+', re.IGNORECASE),
        'ftp': re.compile(r'\bftp://[^\s]+', re.IGNORECASE),
        'telnet': re.compile(r'\btelnet://[^\s]+', re.IGNORECASE),
    }
    
    # Common cleartext ports
    cleartext_ports = {
        21: 'FTP',
        23: 'Telnet',
        80: 'HTTP'
    }
    
    # Check workload resources for containers
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    
    def check_string_for_protocols(value, context_path):
        """Helper to check a string value for cleartext protocols"""
        if not isinstance(value, str):
            return
        
        for protocol, pattern in cleartext_patterns.items():
            matches = pattern.findall(value)
            if matches:
                for match in matches:
                    findings.append({
                        "rule_id": "using_cleartext_protocols_is",
                        "message": f"Clear-text {protocol.upper()} protocol detected in {context_path}: '{match[:100]}'. This exposes data to interception and man-in-the-middle attacks. Use HTTPS, SFTP, or SSH instead.",
                        "resource": f"{kind}/{resource_name}",
                        "file": filename,
                        "line": line,
                        "severity": "Critical",
                        "status": "violation",
                        "property_path": context_path.split('.'),
                        "value": match[:100]
                    })
    
    def check_dict_recursively(data, path=""):
        """Recursively check dictionary for cleartext protocols"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, str):
                    check_string_for_protocols(value, current_path)
                elif isinstance(value, (dict, list)):
                    check_dict_recursively(value, current_path)
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                current_path = f"{path}[{idx}]"
                if isinstance(item, str):
                    check_string_for_protocols(item, current_path)
                elif isinstance(item, (dict, list)):
                    check_dict_recursively(item, current_path)
    
    # Check container images
    if kind in workload_kinds:
        children = manifest.get('children', [])
        for child in children:
            if not isinstance(child, dict):
                continue
            
            # Check image URL
            image = child.get('image', '')
            if image:
                check_string_for_protocols(image, f"container.{child.get('name', 'unknown')}.image")
            
            # Check environment variables
            env_vars = child.get('env', [])
            if isinstance(env_vars, list):
                for env in env_vars:
                    if isinstance(env, dict):
                        env_name = env.get('name', '')
                        env_value = env.get('value', '')
                        if env_value:
                            check_string_for_protocols(env_value, f"container.{child.get('name', 'unknown')}.env.{env_name}")
            
            # Check command and args
            for field in ['command', 'args']:
                values = child.get(field, [])
                if isinstance(values, list):
                    for idx, val in enumerate(values):
                        if isinstance(val, str):
                            check_string_for_protocols(val, f"container.{child.get('name', 'unknown')}.{field}[{idx}]")
    
    # Check Service ports
    if kind == 'Service':
        # Try both 'spec' and direct access (AST builder may flatten structure)
        spec_data = manifest.get('spec', {})
        ports = spec_data.get('ports', []) if spec_data else manifest.get('ports', [])
        
        if isinstance(ports, list):
            for port_def in ports:
                if isinstance(port_def, dict):
                    port = port_def.get('port')
                    target_port = port_def.get('targetPort')
                    
                    for port_num in [port, target_port]:
                        if port_num in cleartext_ports:
                            protocol_name = cleartext_ports[port_num]
                            findings.append({
                                "rule_id": "using_cleartext_protocols_is",
                                "message": f"Service exposes {protocol_name} port {port_num} which uses clear-text protocol. This allows traffic interception and man-in-the-middle attacks. Use secure alternatives (HTTPS/443, SFTP/22, SSH/22).",
                                "resource": f"{kind}/{resource_name}",
                                "file": filename,
                                "line": line,
                                "severity": "Critical",
                                "status": "violation",
                                "property_path": ["spec", "ports", "port"],
                                "value": port_num
                            })
    
    # Check ConfigMap data
    if kind == 'ConfigMap':
        data = manifest.get('data', {})
        check_dict_recursively(data, "data")
    
    # Check Secret data (base64 decoded values are already available)
    if kind == 'Secret':
        data = manifest.get('data', {})
        check_dict_recursively(data, "data")
    
    # Check Ingress for non-TLS configuration
    if kind == 'Ingress':
        # Try both 'spec' and direct access
        spec_data = manifest.get('spec', {})
        tls = spec_data.get('tls', []) if spec_data else manifest.get('tls', [])
        rules = spec_data.get('rules', []) if spec_data else manifest.get('rules', [])
        
        # If there are rules but no TLS, it's using HTTP
        if rules and not tls:
            findings.append({
                "rule_id": "using_cleartext_protocols_is",
                "message": f"Ingress '{resource_name}' is not configured with TLS, exposing traffic over HTTP. This allows interception of sensitive data. Configure spec.tls to enable HTTPS.",
                "resource": f"{kind}/{resource_name}",
                "file": filename,
                "line": line,
                "severity": "Critical",
                "status": "violation",
                "property_path": ["spec", "tls"],
                "value": None
            })
    
    return findings


def check_host_namespaces(manifest, filename):
    """
    Check for usage of host operating system namespaces (hostPID, hostIPC, hostNetwork)
    
    This function detects when Pod-like resources use host namespaces, which can
    compromise host system security by allowing containers to:
    - Access host processes (hostPID: true)
    - Access host IPC mechanisms (hostIPC: true)
    - Use host networking (hostNetwork: true)
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check workload resources that can use host namespaces
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    
    if kind not in workload_kinds:
        return findings
    
    # Check for host namespace settings
    host_settings = {
        'hostPID': {
            'name': 'hostPID',
            'description': 'host process namespace',
            'risk': 'allows containers to see and interact with all processes on the host system'
        },
        'hostIPC': {
            'name': 'hostIPC',
            'description': 'host IPC namespace',
            'risk': 'allows containers to access host inter-process communication mechanisms'
        },
        'hostNetwork': {
            'name': 'hostNetwork',
            'description': 'host network namespace',
            'risk': 'allows containers to access host network interfaces and services'
        }
    }
    
    # Check spec level (for Pods) or template.spec level (for controllers)
    spec_data = manifest.get('spec', {})
    
    # For controllers, check template.spec
    if kind in ['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet']:
        template = spec_data.get('template', {})
        spec_data = template.get('spec', spec_data)
    elif kind == 'CronJob':
        job_template = spec_data.get('jobTemplate', {})
        template = job_template.get('spec', {}).get('template', {})
        spec_data = template.get('spec', spec_data)
    elif kind == 'Job':
        template = spec_data.get('template', {})
        spec_data = template.get('spec', spec_data)
    
    # Check each host setting
    for setting_key, setting_info in host_settings.items():
        # Check both in spec_data and root manifest (AST builder may flatten)
        setting_value = spec_data.get(setting_key) or manifest.get(setting_key)
        
        if setting_value is True:
            findings.append({
                "rule_id": "using_host_operating_system",
                "message": f"{kind} '{resource_name}' uses {setting_info['description']} ({setting_key}: true). This {setting_info['risk']}, potentially compromising host security. Remove or set to false.",
                "resource": f"{kind}/{resource_name}",
                "file": filename,
                "line": line,
                "severity": "Critical",
                "status": "violation",
                "property_path": ["spec", setting_key],
                "value": True
            })
    
    return findings


def check_rbac_wildcards(manifest, filename):
    """
    Check for wildcard usage in RBAC Role and ClusterRole permissions
    
    This function detects when Role or ClusterRole resources use wildcards (*)
    in their rules for:
    - verbs (actions like get, list, create, delete, etc.)
    - resources (resource types like pods, secrets, configmaps, etc.)
    - apiGroups (API groups)
    
    Using wildcards grants overly broad permissions and violates least privilege principle.
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Only check Role and ClusterRole resources
    if kind not in ['Role', 'ClusterRole']:
        return findings
    
    # Get rules from spec or root level (AST builder may flatten)
    rules = manifest.get('rules', [])
    if not rules:
        rules = manifest.get('spec', {}).get('rules', [])
    
    if not isinstance(rules, list):
        return findings
    
    # Check each rule for wildcards
    for rule_idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        
        # Check verbs for wildcards
        verbs = rule.get('verbs', [])
        if isinstance(verbs, list) and '*' in verbs:
            findings.append({
                "rule_id": "wildcards_avoided_define_rbac",
                "message": f"{kind} '{resource_name}' uses wildcard (*) in verbs, granting all actions (get, list, create, update, patch, delete, etc.). This violates least privilege principle. Specify explicit verbs instead.",
                "resource": f"{kind}/{resource_name}",
                "file": filename,
                "line": line,
                "severity": "Info",
                "status": "violation",
                "property_path": ["rules", str(rule_idx), "verbs"],
                "value": "*"
            })
        
        # Check resources for wildcards
        resources = rule.get('resources', [])
        if isinstance(resources, list) and '*' in resources:
            findings.append({
                "rule_id": "wildcards_avoided_define_rbac",
                "message": f"{kind} '{resource_name}' uses wildcard (*) in resources, granting access to all resource types (pods, secrets, configmaps, etc.). This violates least privilege principle. Specify explicit resource types instead.",
                "resource": f"{kind}/{resource_name}",
                "file": filename,
                "line": line,
                "severity": "Info",
                "status": "violation",
                "property_path": ["rules", str(rule_idx), "resources"],
                "value": "*"
            })
        
        # Check apiGroups for wildcards
        api_groups = rule.get('apiGroups', [])
        if isinstance(api_groups, list) and '*' in api_groups:
            findings.append({
                "rule_id": "wildcards_avoided_define_rbac",
                "message": f"{kind} '{resource_name}' uses wildcard (*) in apiGroups, granting access to all API groups. This violates least privilege principle. Specify explicit API groups instead.",
                "resource": f"{kind}/{resource_name}",
                "file": filename,
                "line": line,
                "severity": "Info",
                "status": "violation",
                "property_path": ["rules", str(rule_idx), "apiGroups"],
                "value": "*"
            })
    
    return findings


def check_cpu_limits_in_containers(manifest, filename):
    """
    Check for containers missing CPU limits (resources.limits.cpu).
    
    This function specifically checks containers in Pod-like resources to ensure
    they have CPU limits defined to prevent resource monopolization.
    
    Returns: List of findings
    """
    findings = []
    
    if not isinstance(manifest, dict):
        return findings
    
    # Get resource info
    kind = manifest.get('kind', 'Unknown')
    resource_name = manifest.get('name', 'unknown')
    line = manifest.get('__line__', 0)
    
    # Check if this is a workload resource
    workload_kinds = ['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet']
    if kind not in workload_kinds:
        return findings
    
    # Look for children (containers)
    children = manifest.get('children', [])
    if not children or not isinstance(children, list):
        return findings
    
    # Check each container child
    for child in children:
        if not isinstance(child, dict):
            continue
        
        # Check if this is a container node
        if child.get('node_type') == 'Container' or child.get('type') == 'Container':
            container_name = child.get('value', 'unknown')
            
            # Check for resources.limits.cpu in metadata
            metadata = child.get('metadata', {})
            resources = metadata.get('resources', {})
            limits = resources.get('limits', {})
            cpu_limit = limits.get('cpu')
            
            if cpu_limit is None:
                findings.append({
                    "rule_id": "cpu_limits_enforced",
                    "message": f"Container '{container_name}' is missing CPU limits. Set resources.limits.cpu to prevent CPU resource monopolization.",
                    "resource": f"{kind}/{resource_name}",
                    "file": filename,
                    "line": child.get('__line__', line),
                    "severity": "Critical",
                    "status": "violation",
                    "property_path": ["containers", container_name, "resources", "limits", "cpu"],
                    "value": None
                })
    
    return findings





