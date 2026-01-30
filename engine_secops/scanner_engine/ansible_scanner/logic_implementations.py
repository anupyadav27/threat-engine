"""
Ansible Logic Implementations

Custom logic functions for Ansible rule checking.
Each function should accept an AST node and return True if the rule condition is met.
"""

import re
import yaml


def check_privilege_escalation(node):
    """
    Check for privilege escalation vulnerabilities in Kubernetes and Docker containers.
    
    Detects:
    - allowPrivilegeEscalation: true in Kubernetes securityContext
    - no_new_privs: false in Docker containers
    - Missing no-new-privileges security option in Docker
    
    Args:
        node: AST node to check (returns True/False for generic rule engine)
        
    Returns:
        bool: True if privilege escalation vulnerability is found, False otherwise
    """
    # Check if this is a dict node
    if not isinstance(node, dict):
        return False
    
    node_type = node.get('node_type') or node.get('type')
    module = node.get('module', '')
    module_params = node.get('module_params', {})
    
    # Kubernetes modules (k8s, kubernetes.core.k8s, community.kubernetes.k8s)
    if module and 'k8s' in module:
        # Check if definition exists
        definition = module_params.get('definition', {})
        if not isinstance(definition, dict):
            return False
        
        # Convert definition to YAML string for easier searching
        definition_yaml = yaml.dump(definition, default_flow_style=False)
        
        # Check for allowPrivilegeEscalation: true
        if re.search(r'allowPrivilegeEscalation:\s*[tT]rue', definition_yaml):
            return True
        if re.search(r'allowPrivilegeEscalation:\s*[\'"]true[\'"]', definition_yaml):
            return True
        
        # Check for allow_privilege_escalation (snake_case variant)
        if re.search(r'allow_privilege_escalation:\s*[tT]rue', definition_yaml):
            return True
        if re.search(r'allow_privilege_escalation:\s*yes', definition_yaml):
            return True
    
    # Docker container modules
    if module and 'docker_container' in module:
        # Check for no_new_privs: false
        no_new_privs = module_params.get('no_new_privs')
        if no_new_privs is False or str(no_new_privs).lower() == 'false':
            return True
        
        # Check security_opt for no-new-privileges:false
        security_opt = module_params.get('security_opt', [])
        if isinstance(security_opt, list):
            for opt in security_opt:
                if isinstance(opt, str) and 'no-new-privileges:false' in opt.lower():
                    return True
        
        # Convert module_params to YAML for regex search
        params_yaml = yaml.dump(module_params, default_flow_style=False)
        if re.search(r'no_new_privs:\s*[fF]alse', params_yaml):
            return True
        if re.search(r'security_opt:.*no-new-privileges:false', params_yaml):
            return True
    
    return False


def check_parsing_failure(node):
    """
    Check if the AST node represents a parsing failure.
    
    This function detects if the Ansible file failed to parse properly.
    The parse error is stored in the AST metadata.
    
    Args:
        node: AST node to check (typically the root CompilationUnit)
        
    Returns:
        bool: True if parsing failed, False otherwise
    """
    if not isinstance(node, dict):
        return False
    
    # Check for parse_error marker in the AST
    parse_error = node.get('parse_error')
    if parse_error:
        return True
    
    # Check for parsing_failed flag
    if node.get('parsing_failed', False):
        return True
    
    # Check for error node type
    if node.get('node_type') == 'ParseError' or node.get('type') == 'ParseError':
        return True
    
    return False


def check_hardcoded_credentials(node):
    """
    Check for hard-coded credentials in Ansible tasks.
    
    Detects:
    - Hard-coded passwords (various formats)
    - API keys and tokens
    - AWS credentials
    - Private keys
    - Database passwords
    - JWT secrets
    - Encryption keys
    - Bearer tokens
    
    Args:
        node: AST node to check
        
    Returns:
        bool: True if hard-coded credential is found, False otherwise
    """
    import sys
    if not isinstance(node, dict):
        return False
    
    # Get the source YAML representation
    source = node.get('source', '')
    if not source:
        return False
    
    # DEBUG
    print(f"DEBUG: Checking node, has source={bool(source)}, len={len(source) if source else 0}", file=sys.stderr)
    
    # Don't skip sources with variables - we need to check for hard-coded values mixed with variables
    # Only skip if the specific value being checked is ONLY a variable reference
    
    # Pattern categories for hard-coded credentials
    patterns = [
        # Passwords (various formats) - match any password field with literal value
        (r'password:\s*["\'][^"\'{}\s][^"\'{}]{5,}["\']', 'password'),
        (r'db_password:\s*["\'][^"\'{}\s][^"\'{}]{5,}["\']', 'database password'),
        (r'smtp_password:\s*["\'][^"\'{}\s][^"\'{}]{5,}["\']', 'SMTP password'),
        (r'login_password:\s*["\'][^"\'{}\s][^"\'{}]{5,}["\']', 'login password'),
        
        # API Keys and Tokens
        (r'api_key\s*=\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?', 'API key'),
        (r'api-key:\s*["\'][a-zA-Z0-9_\-=+/]{16,}["\']', 'API key'),
        (r'SECRET_KEY:\s*["\'][a-zA-Z0-9_\-]{15,}["\']', 'secret key'),
        (r'DATABASE_PASSWORD:\s*["\'][a-zA-Z0-9_\-]{5,}["\']', 'database password'),
        
        # AWS Credentials
        (r'aws_access_key_id\s*=\s*[A-Z0-9]{16,}', 'AWS access key'),
        (r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40,}', 'AWS secret key'),
        
        # Bearer Tokens (in various contexts)
        (r'Bearer [A-Za-z0-9\-._~+/]+=*', 'Bearer token'),
        (r'AUTH_TOKEN\s*=\s*["\']Bearer [^"\']+["\']', 'Bearer token'),
        
        # Private Keys
        (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'private key'),
        
        # Redis Password
        (r'requirepass [A-Za-z0-9!@#$%^&*()_+\-=]{8,}', 'Redis password'),
        
        # JWT Secret
        (r'jwt_secret:\s*[a-zA-Z0-9_\-]{10,}', 'JWT secret'),
        
        # Encryption Key
        (r'ENCRYPTION_KEY\s*=\s*[A-Z0-9_\-]{15,}', 'encryption key'),
        
        # Base64 encoded values in Kubernetes secrets
        (r'(?:password|api-key|secret):\s*["\'][A-Za-z0-9+/]{12,}={0,2}["\']', 'base64 encoded secret'),
    ]
    
    # Check each pattern
    for pattern, credential_type in patterns:
        match = re.search(pattern, source)
        if match:
            # DEBUG
            print(f"DEBUG: MATCH! Pattern '{credential_type}' matched: {match.group()[:100]}", file=sys.stderr)
            return True
    
    return False
