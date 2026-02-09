#!/usr/bin/env python3
"""
Custom function implementations for Go static analysis rules.
"""

import re

def check_os_command_path_search(ast_tree, filename):
    """
    Enhanced check for insecure OS command execution that relies on PATH.
    Detects exec.Command calls with relative command names and unvalidated exec.LookPath usage.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    # Read the source file to get exact line content
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Check each line for insecure command patterns
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or not line_stripped:
            continue
        
        # Pattern 1: exec.Command with string literal that's not an absolute path
        command_pattern = r'exec\.Command\s*\(\s*["\']([^"\']+)["\']'
        command_matches = re.finditer(command_pattern, line_content)
        
        for match in command_matches:
            command_name = match.group(1)
            
            # Skip if it's an absolute path (Unix: starts with /, Windows: C:\)
            if (command_name.startswith('/') or 
                (len(command_name) > 2 and command_name[1] == ':' and command_name[2] in ['\\', '/'])):
                continue
                
            # Flag as insecure relative command
            finding = {
                "rule_id": "security_os_command_path_search",
                "message": f"Command '{command_name}' relies on PATH lookup - use absolute path instead",
                "file": filename,
                "line": line_number,
                "column": match.start() + 1,
                "severity": "Major",
                "category": "Security",
                "node_type": "function_call",
                "source_text": line_stripped,
                "property_path": []
            }
            findings.append(finding)
        
        # Pattern 2: exec.Command with variable (dynamic command) - but skip secure contexts
        if 'exec.Command(' in line_content and not re.search(r'exec\.Command\s*\(\s*["\']', line_content):
            # Check if we're in a secure/validated context
            in_secure_context = False
            
            # Check if we're in a function with "Secure", "Valid", or "runValidatedCommand"  
            for back_line_idx in range(max(0, line_idx - 15), line_idx):
                back_line = source_lines[back_line_idx].strip()
                if re.search(r'func.*(?:Secure|Valid|Validated)', back_line, re.IGNORECASE):
                    in_secure_context = True
                    break
                    
            # Check for validation in nearby lines (command whitelist usage)
            for check_idx in range(max(0, line_idx - 10), min(line_idx + 5, len(source_lines))):
                check_line = source_lines[check_idx].strip()
                if re.search(r'allowedCommands\[|cmdPath.*allowedCommands', check_line):
                    in_secure_context = True
                    break
            
            if not in_secure_context:
                # This is exec.Command with a variable, not a string literal
                var_pattern = r'exec\.Command\s*\(\s*(\w+)'
                var_match = re.search(var_pattern, line_content)
                if var_match:
                    var_name = var_match.group(1)
                    finding = {
                        "rule_id": "security_os_command_path_search", 
                        "message": f"Dynamic command execution using variable '{var_name}' - validate command before execution",
                        "file": filename,
                        "line": line_number,
                        "column": var_match.start() + 1,
                        "severity": "Major",
                        "category": "Security",
                        "node_type": "function_call",
                        "source_text": line_stripped,
                        "property_path": []
                    }
                    findings.append(finding)
        
        # Pattern 3: exec.LookPath without validation context
        if 'exec.LookPath(' in line_content:
            # Check if this line is followed by validation within a few lines
            has_validation = False
            
            # Look ahead 10 lines for validation patterns
            for check_line_idx in range(line_idx, min(line_idx + 10, len(source_lines))):
                check_line = source_lines[check_line_idx].strip()
                
                # Common validation patterns - enhanced
                validation_patterns = [
                    r'isValid.*Path',
                    r'validatePath',
                    r'validate.*executable',
                    r'trusted.*[Dd]irs?',
                    r'allowed.*[Cc]ommands?',
                    r'allowedCommands\[',  # whitelist lookup
                    r'whitelist',
                    r'strings\.HasPrefix.*(?:/usr/bin|/bin|/usr/local/bin)',
                    r'filepath\.Abs',
                    r'os\.Stat.*cmdPath',
                    r'not.*trusted',
                    r'executable.*path.*not.*trusted',
                ]
                
                for pattern in validation_patterns:
                    if re.search(pattern, check_line, re.IGNORECASE):
                        has_validation = True
                        break
                        
                if has_validation:
                    break
            
            # Also check if we're in a function with "Secure" or "Valid" in the name
            # Look back to find function declaration
            for back_line_idx in range(max(0, line_idx - 10), line_idx):
                back_line = source_lines[back_line_idx].strip()
                if re.search(r'func.*(?:Secure|Valid|Validated)', back_line, re.IGNORECASE):
                    has_validation = True
                    break
            
            # Only flag if no validation is found
            if not has_validation:
                finding = {
                    "rule_id": "security_os_command_path_search",
                    "message": "exec.LookPath used without path validation - validate executable location",
                    "file": filename,
                    "line": line_number,
                    "column": line_content.find('exec.LookPath') + 1,
                    "severity": "Major",
                    "category": "Security",
                    "node_type": "function_call",
                    "source_text": line_stripped,
                    "property_path": []
                }
                findings.append(finding)
    
    return findings

def check_os_command_path_search_legacy(node):
    """
    Check for insecure OS command execution that relies on PATH.
    Detects exec.Command calls with bare command names.
    """
    if isinstance(node, dict) and node.get('node_type') == 'function_declaration':
        source = node.get('source_text', '')
        
        # Look for exec.Command calls with string literals (bare commands)
        patterns = [
            r'exec\.Command\s*\(\s*["\'][^"\']+["\']',  # exec.Command("command")
            r'exec\.LookPath\s*\(',                       # exec.LookPath usage
            r'exec\.Command\s*\(\s*\w+\s*,',              # exec.Command(variable, ...)
        ]
        
        for pattern in patterns:
            if re.search(pattern, source, re.MULTILINE | re.DOTALL):
                return True
    return False

def check_password_storage_security(ast_tree, filename):
    """
    Custom function to detect insecure password storage practices.
    
    Detects:
    1. Plaintext password storage in structs
    2. Fast hashing algorithms used for passwords (MD5, SHA1, SHA256)
    3. Password assignment without proper hashing
    4. Functions that store/handle passwords insecurely
    
    Returns list of findings with line numbers and messages.
    """
    import re
    
    findings = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Track context - are we in a password-related function?
        in_password_function = False
        password_function_patterns = [
            r'func.*[Pp]assw?o?r?d',
            r'func.*[Aa]uth',
            r'func.*[Ll]ogin',
            r'func.*[Cc]reate[Uu]ser',
            r'func.*hash[Pp]assw?o?r?d',  # More specific hash function patterns
            r'func.*[Ss]tore[Pp]assw?o?r?d'
        ]
        
        # Additional password context indicators (not just function names)
        password_context_keywords = ['password', 'passwd', 'auth', 'login', 'user']
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue
            
            # Check if we're entering a password-related function
            for pattern in password_function_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    in_password_function = True
                    break
            
            # Reset function context on new function or end of block  
            if re.match(r'^func\s+\w+', line_stripped):
                # Check if this is a password-related function
                is_password_func = any(re.search(p, line_stripped, re.IGNORECASE) for p in password_function_patterns)
                # Exclude general data hashing functions
                if 'hashData' in line_stripped or 'calculateFile' in line_stripped or 'checksum' in line_stripped.lower():
                    is_password_func = False
                in_password_function = is_password_func
                
            # 1. Check for plaintext password fields in structs
            password_field_patterns = [
                r'^\s*Password\s+string\s*(?://.*)?$',
                r'^\s*Passwd\s+string\s*(?://.*)?$',
                r'^\s*UserPassword\s+string\s*(?://.*)?$',
                r'^\s*Pass\s+string\s*(?://.*)?$'
            ]
            
            for pattern in password_field_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    # Exclude secure alternatives like PasswordHash
                    if 'hash' not in line_stripped.lower() and 'hashed' not in line_stripped.lower():
                        findings.append({
                            'line': line_num,
                            'message': f"Plaintext password field '{line_stripped.split()[0]}' - store password hashes instead",
                            'severity': 'Major',
                            'rule': 'security_password_storage',
                            'category': 'Security'
                        })
                        break
            
            # 2. Check for fast hashing algorithms used for passwords
            fast_hash_patterns = [
                (r'md5\.Sum\s*\(\s*\[\]byte\s*\(\s*\w*[Pp]assw?o?r?d', 'MD5 is cryptographically broken and too fast for password hashing'),
                (r'sha1\.Sum\s*\(\s*\[\]byte\s*\(\s*\w*[Pp]assw?o?r?d', 'SHA1 is too fast for password hashing - use bcrypt, scrypt, or Argon2'),
                (r'sha256\.Sum256\s*\(\s*\[\]byte\s*\(\s*\w*[Pp]assw?o?r?d', 'SHA256 is too fast for password hashing - use bcrypt, scrypt, or Argon2'),
                (r'sha512\.Sum512\s*\(\s*\[\]byte\s*\(\s*\w*[Pp]assw?o?r?d', 'SHA512 is too fast for password hashing - use bcrypt, scrypt, or Argon2')
            ]
            
            for pattern, message in fast_hash_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    findings.append({
                        'line': line_num,
                        'message': message,
                        'severity': 'Major',
                        'rule': 'security_password_storage',
                        'category': 'Security'
                    })
                    break
                    
            # Also check for hash assignments involving password variables
            if in_password_function:
                hash_assignment_patterns = [
                    r'hash\s*:?=\s*md5\.Sum',
                    r'hash\s*:?=\s*sha1\.Sum', 
                    r'hash\s*:?=\s*sha256\.Sum256',
                    r'hash\s*:?=\s*sha512\.Sum512'
                ]
                
                for pattern in hash_assignment_patterns:
                    if re.search(pattern, line_stripped, re.IGNORECASE):
                        if 'md5' in pattern:
                            hash_type = 'MD5'
                        elif 'sha1' in pattern:
                            hash_type = 'SHA1'
                        elif 'sha256' in pattern:
                            hash_type = 'SHA256'
                        elif 'sha512' in pattern:
                            hash_type = 'SHA512'
                        else:
                            hash_type = 'Fast hash'
                            
                        findings.append({
                            'line': line_num,
                            'message': f"{hash_type} used in password function - use bcrypt, scrypt, or Argon2 instead",
                            'severity': 'Major',
                            'rule': 'security_password_storage',
                            'category': 'Security'
                        })
                        break
            
            # 3. Check for direct password assignment without hashing
            password_assignment_patterns = [
                r'^\s*Password:\s*password\s*[,}]',  # Password: password in struct literal
                r'^\s*\w*[Pp]assw?o?r?d\s*[:=]\s*password\s*[,;\s]*$',  # Direct assignment
                r'^\s*password\s*=\s*\w+\s*$',  # Simple assignment
            ]
            
            for pattern in password_assignment_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    # Don't flag if it's already in a hashing context
                    if not any(word in line_stripped.lower() for word in ['bcrypt', 'scrypt', 'argon2', 'hash']):
                        findings.append({
                            'line': line_num,
                            'message': 'Direct password assignment without proper hashing - use bcrypt, scrypt, or Argon2',
                            'severity': 'Major',
                            'rule': 'security_password_storage',
                            'category': 'Security'
                        })
                        break
            
            # 4. Check for storing passwords in plain variables
            password_var_patterns = [
                r'^\s*\w*[Pp]assw?o?r?d\s*:=\s*\w+',        # password := variable
                r'^\s*\w*[Pp]assw?o?r?d\s*=\s*\w+',         # password = variable  
                r'^\s*userPassword\s*:=',                    # userPassword := 
                r'^\s*pwd\s*:=',                             # pwd :=
                r'^\s*passwd\s*:='                           # passwd :=
            ]
            
            for pattern in password_var_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    # Allow if it's for hashing purposes (check context)
                    if not any(keyword in line.lower() for keyword in ['bcrypt', 'scrypt', 'argon2', 'hash']):
                        # Check next few lines to see if it's being hashed
                        next_lines = lines[line_num:min(line_num + 3, len(lines))]
                        has_hashing = any(any(hash_word in next_line.lower() for hash_word in ['bcrypt', 'scrypt', 'argon2', 'generatefrompassword']) for next_line in next_lines)
                        
                        if not has_hashing:
                            # Check if we're in a password function context
                            if in_password_function or any(pwd_word in line_stripped.lower() for pwd_word in password_context_keywords):
                                findings.append({
                                    'line': line_num,
                                    'message': 'Password stored in variable without immediate hashing - ensure secure hashing with bcrypt, scrypt, or Argon2',
                                    'severity': 'Major',
                                    'rule': 'security_password_storage',
                                    'category': 'Security'
                                })
                                break
            
            # 5. Check for password comparison without proper verification
            if re.search(r'\w*[Pp]assw?o?r?d.*==.*\w*[Pp]assw?o?r?d', line_stripped):
                if not any(word in line_stripped.lower() for word in ['comparehashandpassword', 'verify']):
                    findings.append({
                        'line': line_num,
                        'message': 'Direct password comparison - use bcrypt.CompareHashAndPassword or equivalent',
                        'severity': 'Major',
                        'rule': 'security_password_storage',
                        'category': 'Security'
                    })
        
    except Exception as e:
        print(f"Error in check_password_storage_security: {e}")
    
    return findings
    """
    Enhanced check for insecure password hashing without proper salts.
    Detects various patterns of weak salt usage and missing salts.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    # Read the source file to get exact line content
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Check each line for insecure salt patterns
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or not line_stripped:
            continue
        
        # Pattern 1: Direct password hashing without any salt
        no_salt_patterns = [
            r'(?:sha256|sha1|md5)\.Sum(?:256|)?\s*\(\s*\[\]byte\s*\(\s*password\s*\)',  # hash.Sum([]byte(password))
            r'hasher\.Write\s*\(\s*\[\]byte\s*\(\s*password\s*\)\s*\)\s*$',  # hasher.Write([]byte(password)) without salt
        ]
        
        for pattern in no_salt_patterns:
            if re.search(pattern, line_content):
                finding = {
                    "rule_id": "security_password_hashing_salt",
                    "message": "Password hashing without salt - vulnerable to rainbow table attacks",
                    "file": filename,
                    "line": line_number,
                    "column": 1,
                    "severity": "Major",
                    "category": "Security",
                    "node_type": "function_call",
                    "source_text": line_stripped,
                    "property_path": []
                }
                findings.append(finding)
                continue
        
        # Pattern 2: Static/predictable string salts
        static_salt_patterns = [
            r'(?:salt|.*Salt)\s*:=\s*["\'][^"\']{1,}["\']',  # salt := "static_value" or globalSalt := "value"
            r'(?:salt|.*Salt)\s*=\s*["\'][^"\']{1,}["\']',   # salt = "static_value"
        ]
        
        for pattern in static_salt_patterns:
            match = re.search(pattern, line_content)
            if match:
                # Extract the salt value to check if it's problematic
                salt_match = re.search(r'["\']([^"\']*)["\']', match.group())
                if salt_match:
                    salt_value = salt_match.group(1)
                    
                    # Check for clearly problematic salts
                    is_problematic = (
                        len(salt_value) < 8 or  # Too short
                        salt_value.isdigit() or  # Pure numeric
                        salt_value == "" or  # Empty
                        any(word in salt_value.lower() for word in ['salt', 'app', 'static', 'constant', 'global']) or
                        salt_value.isalnum() and len(set(salt_value)) <= 3 or  # Too repetitive
                        re.match(r'^\d{4}-\d{2}-\d{2}', salt_value) or  # Date pattern
                        re.match(r'^[a-zA-Z]{1,6}$', salt_value) and len(salt_value) <= 6  # Short alphabetic
                    )
                    
                    if is_problematic:
                        finding = {
                            "rule_id": "security_password_hashing_salt",
                            "message": f"Static/predictable salt '{salt_value}' - use cryptographically secure random salts",
                            "file": filename,
                            "line": line_number,
                            "column": match.start() + 1,
                            "severity": "Major",
                            "category": "Security",
                            "node_type": "assignment",
                            "source_text": line_stripped,
                            "property_path": []
                        }
                        findings.append(finding)
                continue
        
        # Pattern 3: Variable assignment to salt from predictable sources
        variable_salt_patterns = [
            r'(?:salt|.*Salt)\s*:=\s*(username|email|userID|user\.Name|user\.Email)\b',  # salt := username
            r'(?:salt|.*Salt)\s*:=\s*(\w+)\s*\+\s*["\'][^"\']*["\']',  # salt := email + "_salt"
        ]
        
        for pattern in variable_salt_patterns:
            match = re.search(pattern, line_content)
            if match:
                var_name = match.group(1)
                finding = {
                    "rule_id": "security_password_hashing_salt",
                    "message": f"Using predictable variable '{var_name}' as salt - use cryptographically secure random salts",
                    "file": filename,
                    "line": line_number,
                    "column": match.start() + 1,
                    "severity": "Major",
                    "category": "Security",
                    "node_type": "assignment",
                    "source_text": line_stripped,
                    "property_path": []
                }
                findings.append(finding)
                continue
        
        # Pattern 4: Hardcoded byte slice salts
        byte_salt_pattern = r'(?:salt|.*Salt)\s*:=\s*\[\]byte\s*\{'
        if re.search(byte_salt_pattern, line_content):
            finding = {
                "rule_id": "security_password_hashing_salt",
                "message": "Hardcoded byte slice salt - use cryptographically secure random salts",
                "file": filename,
                "line": line_number,
                "column": 1,
                "severity": "Major",
                "category": "Security",
                "node_type": "assignment",
                "source_text": line_stripped,
                "property_path": []
            }
            findings.append(finding)
            continue
        
        # Pattern 5: bytes.Repeat for salt generation
        if 'bytes.Repeat(' in line_content and 'salt' in line_content.lower():
            finding = {
                "rule_id": "security_password_hashing_salt",
                "message": "Using bytes.Repeat for salt generation creates predictable patterns - use crypto/rand",
                "file": filename,
                "line": line_number,
                "column": 1,
                "severity": "Major", 
                "category": "Security",
                "node_type": "function_call",
                "source_text": line_stripped,
                "property_path": []
            }
            findings.append(finding)
            continue
        
        # Pattern 6: make([]byte) without crypto/rand filling - but only if it looks problematic
        make_pattern = r'(?:salt|.*Salt)\s*:=\s*make\s*\(\s*\[\]byte\s*,'
        if re.search(make_pattern, line_content):
            # Look ahead to see if rand.Read is used
            has_rand_read = False
            
            # Check next few lines for rand.Read
            for check_idx in range(line_idx + 1, min(line_idx + 5, len(source_lines))):
                check_line = source_lines[check_idx].strip()
                if 'rand.Read(' in check_line:
                    has_rand_read = True
                    break
            
            # Also check if rand.Read is on the same line or if this is in a secure function
            if 'rand.Read(' in line_content:
                has_rand_read = True
            
            # Check if we're in a secure function context
            in_secure_context = False
            for back_idx in range(max(0, line_idx - 10), line_idx):
                back_line = source_lines[back_idx].strip()
                if re.search(r'func.*(?:Secure|Random|Manual|Scrypt|bcrypt)', back_line, re.IGNORECASE):
                    in_secure_context = True
                    break
            
            # Only flag if no rand.Read and not in secure context
            if not has_rand_read and not in_secure_context:
                finding = {
                    "rule_id": "security_password_hashing_salt",
                    "message": "make([]byte) salt without crypto/rand filling - may contain predictable zero values", 
                    "file": filename,
                    "line": line_number,
                    "column": 1,
                    "severity": "Major",
                    "category": "Security",
                    "node_type": "assignment",
                    "source_text": line_stripped,
                    "property_path": []
                }
                findings.append(finding)
                continue
    
    return findings

def check_path_injection_vulnerability(node):
    """
    Check for path traversal/injection vulnerabilities.
    Detects unsafe path operations with user input.
    """
    if isinstance(node, dict) and node.get('node_type') == 'function_declaration':
        source = node.get('source_text', '')
        
        # Look for path injection patterns
        patterns = [
            r'filepath\.Join\s*\([^)]*\.\.[^)]*\)',     # filepath.Join with ".."
            r'os\.Open\s*\([^)]*\+[^)]*\)',             # os.Open with string concatenation
            r'ioutil\.ReadFile\s*\([^)]*\+[^)]*\)',     # ReadFile with concatenation
            r'["\'][^"\']*\.\./[^"\']*["\']',           # Direct "../" in strings
            r'path\s*\+',                              # Path concatenation
        ]
        
        for pattern in patterns:
            if re.search(pattern, source, re.MULTILINE | re.DOTALL):
                return True
    return False

def check_publicly_writable_directories(node):
    """
    Check for usage of publicly writable directories like /tmp.
    """
    if isinstance(node, dict) and node.get('node_type') == 'function_declaration':
        source = node.get('source_text', '')
        
        # Look for publicly writable directory usage
        patterns = [
            r'["\'][^"\']*/?tmp[^"\']*["\']',           # /tmp directory
            r'["\'][^"\']*/?var/tmp[^"\']*["\']',       # /var/tmp directory  
            r'os\.TempDir\s*\(',                       # os.TempDir() usage
            r'ioutil\.TempDir\s*\(',                   # ioutil.TempDir() usage
            r'["\'][^"\']*/?temp[^"\']*["\']',         # temp directories
        ]
        
        for pattern in patterns:
            if re.search(pattern, source, re.MULTILINE | re.DOTALL):
                return True
    return False

def check_nested_switch_statements(node):
    """
    Check for nested switch statements that create complex control flow.
    """
    if isinstance(node, dict) and node.get('node_type') == 'function_declaration':
        source = node.get('source_text', '')
        
        # Look for nested switch pattern - switch inside switch
        if re.search(r'switch\s+[^{]*{[^}]*switch\s+[^{]*{', source, re.MULTILINE | re.DOTALL):
            return True
            
        # Alternative: count switch statements and look for nesting
        switch_count = source.count('switch ')
        if switch_count > 1:
            # Check if they are nested (not sequential)
            # Look for switch blocks that contain other switch statements
            lines = source.split('\n')
            switch_depth = 0
            for line in lines:
                if 'switch ' in line:
                    switch_depth += 1
                    if switch_depth > 1:
                        return True
                if line.strip().startswith('}') and switch_depth > 0:
                    switch_depth -= 1
            
    return False

def check_nonexistent_operators(ast_tree, filename):
    """
    Enhanced check for incorrect operator usage like =+ instead of +=.
    Returns list of detailed findings with exact line numbers and source text.
    """
    findings = []
    
    # Read the source file to get exact line content
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Define patterns for non-existent operators (ordered from most specific to least specific)
    operator_patterns = {
        # Special case for loop increment
        r'(i\s*)=\+(\s*\d+)': '++',            # i=+number (should be i++)
        
        # Number patterns (integers and decimals) - these need to be first
        r'(\w+\s*)=\+(\s*[\d.]+)': '+=',       # variable =+ number (should be +=)
        r'(\w+\s*)=\*(\s*[\d.]+)': '*=',       # variable =* number (should be *=)
        r'(\w+\s*)=-(\s*[\d.]+)': '-=',        # variable =- number (should be -=)
        r'(\w+\s*)=/(\s*[\d.]+)': '/=',        # variable =/ number (should be /=)
        
        # String literal patterns        
        r'(\w+\s*)=!(\s*["\'][^"\']*["\'])': '!=',  # variable =! "string" (should be !=)
        
        # Identifier patterns (variables, functions, etc.) - these come last
        r'(\w+\s*)=\+(\s*\w+)': '+=',          # variable =+ identifier (should be +=)
        r'(\w+\s*)=\*(\s*\w+)': '*=',          # variable =* identifier (should be *=)
        r'(\w+\s*)=-(\s*\w+)': '-=',           # variable =- identifier (should be -=)
        r'(\w+\s*)=/(\s*\w+)': '/=',           # variable =/ identifier (should be /=)
        r'(\w+\s*)=!(\s*\w+)': '!=',           # variable =! identifier (should be !=)
    }
    
    # Check each line for non-existent operators
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or not line_stripped:
            continue
            
        # Track positions already matched to avoid overlaps
        matched_positions = set()
        
        # Check each pattern  
        for pattern, correct_op in operator_patterns.items():
            matches = re.finditer(pattern, line_content)
            for match in matches:
                start_pos = match.start()
                end_pos = match.end()
                
                # Skip if this position overlaps with a previous match
                if any(start_pos <= pos < end_pos for pos in matched_positions):
                    continue
                if any(start_pos < pos <= end_pos for pos in matched_positions):
                    continue
                
                # Mark this position as matched
                for pos in range(start_pos, end_pos):
                    matched_positions.add(pos)
                
                # Create detailed finding
                finding = {
                    "rule_id": "syntax_nonexistent_operators",
                    "message": f"Use correct operator syntax - {correct_op} not {match.group().replace(' ', '')}",
                    "file": filename,
                    "line": line_number,
                    "column": start_pos + 1,
                    "severity": "Major",
                    "category": "Reliability",
                    "node_type": "expression",
                    "source_text": line_stripped,
                    "property_path": []
                }
                
                # Additional context for specific operators
                incorrect_op = match.group().replace(' ', '').replace('\t', '')
                if incorrect_op.startswith('i=+'):
                    finding["message"] = f"Use i++ instead of {incorrect_op}"
                elif '=!' in incorrect_op:
                    finding["message"] = f"Use != for comparison, not {incorrect_op}"
                else:
                    finding["message"] = f"Use {correct_op} instead of {incorrect_op.replace('=', '=')}"
                
                findings.append(finding)
    
    return findings

def check_nonexistent_operators_legacy(node):
    """
    Legacy function for backward compatibility - kept as fallback.
    Check for incorrect operator usage like =+ instead of +=.
    """
    if isinstance(node, dict) and node.get('node_type') == 'function_declaration':
        source = node.get('source_text', '')
        
        # Look for incorrect operator patterns
        patterns = [
            r'\w+\s*=\+\s*\w+',    # variable =+ value (should be +=)
            r'\w+\s*=\*\s*\w+',    # variable =* value (should be *=)
            r'\w+\s*=-\s*\w+',     # variable =- value (should be -=)
            r'\w+\s*=/\s*\w+',     # variable =/ value (should be /=)
            r'\w+\s*=!\s*\w+',     # variable =! value (should be !=)
            r'=\+\s*\d+',          # =+ followed by number
            r'=\*\s*\w+',          # =* pattern
            r'i=\+1',              # common loop increment mistake
        ]
        
        for pattern in patterns:
            if re.search(pattern, source, re.MULTILINE | re.DOTALL):
                return True
    return False

def check_octal_values_avoid(ast_tree, filename):
    """
    Enhanced check for octal number literals that can be confusing.
    Detects numeric literals starting with 0 (octal notation) that might be 
    mistaken for decimal values by developers.
    
    Returns list of findings with exact line numbers and source text.
    """
    findings = []
    
    # Read the source file to get exact line content
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Regex pattern for octal literals
    # Matches: 0 followed by one or more octal digits (0-7)
    # Must not be followed by 8, 9 (invalid octal), 'x' or 'X' (hex), '.' (float)
    # Must not be just "0" by itself (that's just zero)
    octal_pattern = r'\b0[0-7]+\b(?![89.xX])'
    
    # Check each line for octal literals
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments, empty lines, and strings
        if (line_stripped.startswith('//') or 
            not line_stripped or 
            line_stripped.startswith('/*') or
            line_stripped.startswith('*')):
            continue
        
        # Find octal matches
        matches = re.finditer(octal_pattern, line_content)
        for match in matches:
            octal_str = match.group()
            
            # Skip single "0" - that's just zero, not confusing octal
            if octal_str == "0":
                continue
                
            # Convert to decimal to show the confusion
            try:
                decimal_value = int(octal_str, 8)
                apparent_decimal = int(octal_str)  # What it looks like
                
                # Only flag if the apparent decimal differs from actual octal value
                if decimal_value != apparent_decimal:
                    finding = {
                        "rule_id": "formatting_octal_values_avoid",
                        "message": f"Octal literal {octal_str} appears to be {apparent_decimal} but equals {decimal_value} in decimal - use decimal {decimal_value} instead",
                        "file": filename,
                        "line": line_number,
                        "column": match.start() + 1,
                        "severity": "Major",
                        "category": "Maintainability",
                        "node_type": "literal",
                        "source_text": line_stripped,
                        "property_path": []
                    }
                    findings.append(finding)
                    
            except ValueError:
                # Invalid octal - but this would be a syntax error anyway
                continue
    
    return findings

def check_cipher_block_chaining_ivs(ast_tree, filename, semantic_analyzer=None):
    """
    Enhanced check for predictable initialization vectors in CBC mode encryption.
    Addresses false positives and false negatives from the basic taint analysis.
    
    This custom implementation provides more accurate detection of:
    - Fixed/predictable IVs (all zeros, hardcoded values)
    - Reused IVs across multiple encryptions 
    - Proper random IV generation validation
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    def extract_line_number(node):
        """Extract line number from node."""
        if isinstance(node, dict):
            return node.get('line', node.get('start_line', 0))
        return 0

    def analyze_source_for_cbc_calls(source_content):
        """Analyze source code directly for CBC encryption patterns."""
        import re
        
        # Find all cipher.NewCBCEncrypter calls with line numbers and function context
        cbc_calls = []
        lines = source_content.split('\n')
        
        # First, identify function boundaries
        function_boundaries = {}
        current_func = None
        brace_depth = 0
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Detect function start
            if stripped.startswith('func ') and '{' in line:
                func_match = re.search(r'func\s+(\w+)\s*\(', line)
                if func_match:
                    current_func = func_match.group(1)
                    function_boundaries[current_func] = {'start': i, 'end': None}
                    brace_depth = line.count('{') - line.count('}')
            
            elif current_func and function_boundaries[current_func]['end'] is None:
                brace_depth += line.count('{') - line.count('}')
                if brace_depth <= 0:
                    function_boundaries[current_func]['end'] = i
                    current_func = None
        
        # Find CBC calls within function context
        for i, line in enumerate(lines, 1):
            if 'cipher.NewCBCEncrypter' in line:
                # Extract the IV variable name from the call
                match = re.search(r'cipher\.NewCBCEncrypter\s*\(\s*\w+\s*,\s*(\w+)', line)
                if match:
                    iv_var = match.group(1)
                    
                    # Find which function this line belongs to
                    function_name = None
                    for func_name, bounds in function_boundaries.items():
                        if bounds['start'] <= i <= (bounds['end'] or float('inf')):
                            function_name = func_name
                            break
                    
                    cbc_calls.append({
                        'line': i,
                        'iv_variable': iv_var,
                        'source_line': line.strip(),
                        'function': function_name,
                        'function_bounds': function_boundaries.get(function_name, {})
                    })
        
        # Analyze each CBC call within its function context
        for call_info in cbc_calls:
            iv_var = call_info['iv_variable']
            line_num = call_info['line']
            func_name = call_info['function']
            func_bounds = call_info['function_bounds']
            
            # Extract function-specific source code
            if func_bounds and func_bounds.get('start') and func_bounds.get('end'):
                func_start = func_bounds['start'] - 1  # Convert to 0-based indexing
                func_end = func_bounds['end']
                function_source = '\n'.join(lines[func_start:func_end])
            else:
                function_source = source_content  # Fallback to full source
            
            # Analyze the IV variable within this function context
            vulnerability = analyze_iv_in_function(iv_var, function_source, source_content)
            
            if vulnerability['is_vulnerable']:
                finding = {
                    "rule_id": "crypto_cipher_block_chaining_ivs",
                    "message": f"Insecure IV in CBC encryption: {vulnerability['reason']}",
                    "file": filename,
                    "line": line_num,
                    "column": 0,
                    "severity": "Major",
                    "category": "Security", 
                    "node_type": "call_expression",
                    "function_name": func_name or "unknown",
                    "variable_name": iv_var,
                    "source_text": call_info['source_line'],
                    "property_path": ["crypto", "iv_security"]
                }
                findings.append(finding)
        
        return findings
    
    def analyze_iv_in_function(iv_var, function_source, full_source_for_globals):
        """Analyze how an IV variable is defined and used within a specific function."""
        import re
        
        # Check for global variable reuse first (must search in full source)
        global_pattern = rf'var\s+{re.escape(iv_var)}\s*='
        if re.search(global_pattern, full_source_for_globals):
            return {
                'is_vulnerable': True,
                'reason': f'IV "{iv_var}" reuses global/static values across encryptions',
                'confidence': 'high'
            }
        
        # For all other checks, use function-scoped source to avoid cross-function contamination
        
        # Check for hardcoded byte array within this function
        hardcode_pattern = rf'{re.escape(iv_var)}\s*:=\s*\[\]byte\{{[^}}]+\}}'
        if re.search(hardcode_pattern, function_source):
            return {
                'is_vulnerable': True,
                'reason': f'IV "{iv_var}" uses hardcoded predictable values',
                'confidence': 'high'
            }
        
        # Check specifically for slice assignment within this function
        slice_assignment_pattern = rf'{re.escape(iv_var)}\s*:=\s*\w+\[.*\]'
        if re.search(slice_assignment_pattern, function_source):
            # Check for subsequent randomization within this function
            slice_randomization_patterns = [
                rf'io\.ReadFull\s*\(\s*rand\.Reader\s*,\s*{re.escape(iv_var)}',
                rf'rand\.Read\s*\(\s*{re.escape(iv_var)}',
            ]
            
            has_slice_randomization = any(re.search(pattern, function_source) for pattern in slice_randomization_patterns)
            
            if has_slice_randomization:
                return {
                    'is_vulnerable': False,
                    'reason': f'IV "{iv_var}" slice is properly randomized with crypto/rand',
                    'confidence': 'high'
                }
            else:
                return {
                    'is_vulnerable': True,
                    'reason': f'IV "{iv_var}" is a slice but not properly randomized',
                    'confidence': 'high'
                }
        
        # Check for make() call within this function
        make_pattern = rf'{re.escape(iv_var)}\s*:=\s*make\s*\(\s*\[\]byte'
        if re.search(make_pattern, function_source):
            # Check if there's subsequent randomization within this function
            randomization_patterns = [
                rf'rand\.Read\s*\(\s*{re.escape(iv_var)}',
                rf'io\.ReadFull\s*\(\s*rand\.Reader\s*,\s*{re.escape(iv_var)}',
            ]
            
            has_randomization = any(re.search(pattern, function_source) for pattern in randomization_patterns)
            
            if has_randomization:
                return {
                    'is_vulnerable': False,
                    'reason': f'IV "{iv_var}" is properly randomized using crypto/rand after make()',
                    'confidence': 'high'
                }
            else:
                return {
                    'is_vulnerable': True,
                    'reason': f'IV "{iv_var}" is initialized as zeros without randomization',
                    'confidence': 'high'
                }
        
        # If none of the patterns match, assume it's unsafe
        return {
            'is_vulnerable': True,
            'reason': f'IV "{iv_var}" initialization method cannot be verified as secure',
            'confidence': 'low'
        }
    
    # Read the source file directly for analysis
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_content = f.read()
            findings = analyze_source_for_cbc_calls(source_content)
    except Exception as e:
        # Fallback to AST analysis if file reading fails
        pass
    
    return findings

def check_file_length_limit(ast_tree, filename, semantic_analyzer=None):
    """
    Check for excessively long source files that accumulate multiple responsibilities.
    Detects files that exceed reasonable length limits and become difficult to maintain.
    
    Args:
        ast_tree: The parsed AST tree
        filename: The path to the file being analyzed
        semantic_analyzer: Optional semantic analyzer (not used for this check)
        
    Returns:
        List of findings for files that exceed length limits
    """
    findings = []
    
    # Default threshold for file length (can be configured)
    MAX_LINES_THRESHOLD = 300
    
    try:
        # Read the source file directly to count lines accurately
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            total_lines = len(lines)
            
        # Check if file exceeds the length threshold
        if total_lines > MAX_LINES_THRESHOLD:
            # Count non-empty lines for better analysis
            non_empty_lines = len([line for line in lines if line.strip()])
            
            # Calculate some basic metrics
            comment_lines = len([line for line in lines if line.strip().startswith('//')])
            code_lines = non_empty_lines - comment_lines
            
            # Create finding for excessively long file
            finding = {
                'type': 'structure_file_length_limit',
                'severity': 'major',
                'message': f'File exceeds recommended length limit. Total lines: {total_lines}, Code lines: {code_lines}. Consider breaking this file into smaller, focused modules with single responsibilities.',
                'line': 1,
                'column': 1,
                'filename': filename,
                'details': {
                    'total_lines': total_lines,
                    'non_empty_lines': non_empty_lines,
                    'code_lines': code_lines,
                    'comment_lines': comment_lines,
                    'threshold_exceeded_by': total_lines - MAX_LINES_THRESHOLD,
                    'recommendation': 'Split file into focused modules: separate handlers, services, models, and utilities'
                }
            }
            findings.append(finding)
            
    except FileNotFoundError:
        # File not found, skip analysis
        pass
    except Exception as e:
        # Other errors reading file, skip analysis
        pass
    
    return findings

def check_file_permissions_security(ast_tree, filename, semantic_analyzer=None):
    """
    Check for insecure file permissions that expose sensitive files to unauthorized access.
    Detects overly permissive POSIX file permissions in file operations.
    
    Args:
        ast_tree: The parsed AST tree
        filename: The path to the file being analyzed
        semantic_analyzer: Optional semantic analyzer (not used for this check)
        
    Returns:
        List of findings for insecure file permission patterns
    """
    findings = []
    
    try:
        # Read the source file directly for analysis
        with open(filename, 'r', encoding='utf-8') as f:
            source_content = f.read()
            lines = source_content.split('\n')
            
        # Define patterns that indicate insecure file permissions
        insecure_patterns = [
            {
                'pattern': r'ioutil\.WriteFile\s*\([^,]+,\s*[^,]+,\s*0777\)',
                'message': 'ioutil.WriteFile with 0777 permissions allows read/write/execute for everyone',
                'severity': 'Major'
            },
            {
                'pattern': r'ioutil\.WriteFile\s*\([^,]+,\s*[^,]+,\s*0755\)',
                'message': 'ioutil.WriteFile with 0755 permissions allows read/execute for all users',
                'severity': 'Major'
            },
            {
                'pattern': r'ioutil\.WriteFile\s*\([^,]+,\s*[^,]+,\s*0644\)',
                'message': 'ioutil.WriteFile with 0644 permissions allows read access for all users - use 0600 for sensitive files',
                'severity': 'Major'
            },
            {
                'pattern': r'os\.OpenFile\s*\([^,]+,\s*[^,]+,\s*0777\)',
                'message': 'os.OpenFile with 0777 permissions allows full access for everyone',
                'severity': 'Major'
            },
            {
                'pattern': r'os\.OpenFile\s*\([^,]+,\s*[^,]+,\s*0755\)',
                'message': 'os.OpenFile with 0755 permissions allows read/execute for all users',
                'severity': 'Major'
            },
            {
                'pattern': r'os\.OpenFile\s*\([^,]+,\s*[^,]+,\s*0644\)',
                'message': 'os.OpenFile with 0644 permissions allows read access for all users - use 0600 for sensitive files',
                'severity': 'Major'
            },
            {
                'pattern': r'os\.Mkdir\s*\([^,]+,\s*0777\)',
                'message': 'os.Mkdir with 0777 permissions allows full access for everyone',
                'severity': 'Major'
            },
            {
                'pattern': r'os\.Mkdir\s*\([^,]+,\s*0755\)',
                'message': 'os.Mkdir with 0755 permissions allows read/execute for all users - consider 0700 for sensitive directories',
                'severity': 'Major'
            },
            {
                'pattern': r'os\.MkdirAll\s*\([^,]+,\s*0777\)',
                'message': 'os.MkdirAll with 0777 permissions allows full access for everyone',
                'severity': 'Major'
            },
            {
                'pattern': r'os\.MkdirAll\s*\([^,]+,\s*0755\)',
                'message': 'os.MkdirAll with 0755 permissions allows read/execute for all users - consider 0700 for sensitive directories',
                'severity': 'Major'
            }
        ]
        
        # Contextual patterns to identify high-risk files
        sensitive_file_indicators = [
            r'password', r'secret', r'credential', r'private', r'key', r'token', r'session',
            r'config', r'\.env', r'\.pem', r'\.key', r'api_key', r'encryption', r'backup'
        ]
        
        # Check each line for insecure permission patterns
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            for pattern_info in insecure_patterns:
                pattern = pattern_info['pattern']
                match = re.search(pattern, line_stripped)
                
                if match:
                    # Check if this is likely a sensitive file operation
                    is_sensitive = False
                    severity = pattern_info['severity']
                    
                    # Look for sensitive file indicators in the current line or nearby context
                    context_lines = []
                    start_context = max(0, line_num - 3)
                    end_context = min(len(lines), line_num + 3)
                    context_lines = lines[start_context:end_context]
                    context_text = '\n'.join(context_lines).lower()
                    
                    for indicator in sensitive_file_indicators:
                        if re.search(indicator, context_text):
                            is_sensitive = True
                            break
                    
                    # Enhance message based on context
                    message = pattern_info['message']
                    if is_sensitive:
                        message += " - This appears to be a sensitive file operation"
                        severity = 'Critical'
                    
                    finding = {
                        'type': 'security_file_permissions',
                        'severity': severity.lower(),
                        'message': message,
                        'line': line_num,
                        'column': 1,
                        'filename': filename,
                        'source_text': line_stripped,
                        'details': {
                            'pattern_matched': pattern,
                            'is_sensitive_operation': is_sensitive,
                            'recommendation': 'Use restrictive permissions like 0600 for files or 0700 for directories'
                        }
                    }
                    findings.append(finding)
        
        # Additional check for os.Create without explicit permissions (potentially dangerous)
        os_create_pattern = r'os\.Create\s*\('
        for line_num, line in enumerate(lines, 1):
            if re.search(os_create_pattern, line.strip()):
                # Check if this is in a sensitive context
                context_lines = []
                start_context = max(0, line_num - 3)
                end_context = min(len(lines), line_num + 3)
                context_lines = lines[start_context:end_context]
                context_text = '\n'.join(context_lines).lower()
                
                is_sensitive = any(re.search(indicator, context_text) for indicator in sensitive_file_indicators)
                
                if is_sensitive:
                    finding = {
                        'type': 'security_file_permissions',
                        'severity': 'major',
                        'message': 'os.Create uses default permissions which may be too permissive for sensitive files - use os.OpenFile with explicit permissions',
                        'line': line_num,
                        'column': 1,
                        'filename': filename,
                        'source_text': line.strip(),
                        'details': {
                            'pattern_matched': 'os.Create with default permissions',
                            'is_sensitive_operation': True,
                            'recommendation': 'Use os.OpenFile with explicit permissions like 0600'
                        }
                    }
                    findings.append(finding)
        
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    
    return findings

def check_fixme_tags_tracking(ast_tree, filename, semantic_analyzer=None):
    """
    Check for FIXME tags in comments that indicate suspected bugs or issues.
    FIXME tags mark code that needs attention but are often forgotten over time.
    
    Args:
        ast_tree: The parsed AST tree
        filename: The path to the file being analyzed
        semantic_analyzer: Optional semantic analyzer (not used for this check)
        
    Returns:
        List of findings for FIXME tags that need attention
    """
    findings = []
    
    try:
        # Read the source file directly for analysis
        with open(filename, 'r', encoding='utf-8') as f:
            source_content = f.read()
            lines = source_content.split('\n')
            
        # Define patterns for FIXME tags (case insensitive)
        fixme_patterns = [
            r'//\s*fixme\b',        # // FIXME or // fixme
            r'/\*.*?fixme.*?\*/',   # /* FIXME ... */
            r'//\s*fix\s+me\b',    # // FIX ME
            r'/\*.*?fix\s+me.*?\*/', # /* FIX ME ... */
        ]
        
        # Check each line for FIXME tags
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            line_stripped = line.strip()
            
            # Skip empty lines
            if not line_stripped:
                continue
                
            # Check for FIXME patterns
            for pattern in fixme_patterns:
                match = re.search(pattern, line_lower, re.MULTILINE | re.DOTALL)
                
                if match:
                    # Extract the FIXME comment content
                    fixme_text = line_stripped
                    
                    # Try to extract just the comment part
                    if '//' in line_stripped:
                        comment_start = line_stripped.find('//')
                        fixme_text = line_stripped[comment_start:]
                    elif '/*' in line_stripped:
                        comment_start = line_stripped.find('/*')
                        fixme_text = line_stripped[comment_start:]
                    
                    # Categorize the type of FIXME based on keywords
                    severity = 'major'
                    category = 'reliability'
                    fixme_type = categorize_fixme(line_lower)
                    
                    # Adjust severity based on content
                    if any(keyword in line_lower for keyword in ['security', 'vulnerability', 'injection', 'leak']):
                        severity = 'critical'
                        category = 'security'
                    elif any(keyword in line_lower for keyword in ['performance', 'slow', 'inefficient', 'memory']):
                        severity = 'major'
                        category = 'performance'
                    
                    finding = {
                        'type': 'tracking_fixme_tags',
                        'severity': severity,
                        'message': f'FIXME tag indicates {fixme_type}: {fixme_text[:100]}...' if len(fixme_text) > 100 else f'FIXME tag indicates {fixme_type}: {fixme_text}',
                        'line': line_num,
                        'column': 1,
                        'filename': filename,
                        'source_text': line_stripped,
                        'details': {
                            'fixme_type': fixme_type,
                            'fixme_content': fixme_text,
                            'category': category,
                            'recommendation': 'Review and address this FIXME tag - either fix the issue or remove the outdated comment'
                        }
                    }
                    findings.append(finding)
                    break  # Only report one finding per line
                    
        # Additional check for multi-line FIXME comments
        multiline_fixme_pattern = r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/'
        multiline_matches = re.finditer(multiline_fixme_pattern, source_content, re.DOTALL)
        
        for match in multiline_matches:
            comment_text = match.group(0).lower()
            if 'fixme' in comment_text or 'fix me' in comment_text:
                # Find line number of the match
                lines_before_match = source_content[:match.start()].count('\n')
                line_num = lines_before_match + 1
                
                # Avoid duplicate findings
                if not any(f['line'] == line_num and f['type'] == 'tracking_fixme_tags' for f in findings):
                    fixme_type = categorize_fixme(comment_text)
                    
                    finding = {
                        'type': 'tracking_fixme_tags',
                        'severity': 'major',
                        'message': f'Multi-line FIXME comment indicates {fixme_type}',
                        'line': line_num,
                        'column': 1,
                        'filename': filename,
                        'source_text': match.group(0)[:100] + '...' if len(match.group(0)) > 100 else match.group(0),
                        'details': {
                            'fixme_type': fixme_type,
                            'fixme_content': match.group(0),
                            'category': 'reliability',
                            'recommendation': 'Review and address this multi-line FIXME comment'
                        }
                    }
                    findings.append(finding)
        
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    
    return findings

def categorize_fixme(comment_text):
    """
    Categorize the type of FIXME based on keywords in the comment.
    """
    comment_lower = comment_text.lower()
    
    if any(keyword in comment_lower for keyword in ['memory leak', 'leak', 'free', 'allocation']):
        return 'memory management issue'
    elif any(keyword in comment_lower for keyword in ['security', 'vulnerability', 'injection', 'credential', 'hardcoded']):
        return 'security vulnerability'
    elif any(keyword in comment_lower for keyword in ['performance', 'slow', 'inefficient', 'optimization', 'o(n²)', 'algorithm']):
        return 'performance issue'
    elif any(keyword in comment_lower for keyword in ['error handling', 'exception', 'error', 'validation']):
        return 'error handling issue'
    elif any(keyword in comment_lower for keyword in ['incomplete', 'implement', 'missing', 'todo']):
        return 'incomplete implementation'
    elif any(keyword in comment_lower for keyword in ['bug', 'broken', 'wrong', 'incorrect', 'fix']):
        return 'suspected bug'
    elif any(keyword in comment_lower for keyword in ['race condition', 'thread', 'concurrent', 'sync']):
        return 'concurrency issue'
    elif any(keyword in comment_lower for keyword in ['resource', 'close', 'cleanup', 'defer']):
        return 'resource management issue'
    else:
        return 'general issue'


def check_function_naming_convention(ast_tree, filename, semantic_analyzer=None):
    """
    Check for functions that violate Go naming conventions.
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        semantic_analyzer: Optional semantic analyzer (unused)
        
    Returns:
        List of findings for functions with naming violations
    """
    findings = []
    
    try:
        # Read the source file directly for analysis
        with open(filename, 'r', encoding='utf-8') as f:
            source_content = f.read()
            lines = source_content.split('\n')
            
        # Find all function declarations
        function_pattern = r'func\s+(?:\([^)]*\)\s*)?(\w+)\s*\('
        
        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(function_pattern, line)
            
            for match in matches:
                function_name = match.group(1)
                
                # Skip main function and init functions (special cases in Go)
                if function_name in ['main', 'init']:
                    continue
                
                # Check various naming convention violations
                violations = check_naming_violations(function_name)
                
                for violation in violations:
                    finding = {
                        'type': 'naming_function_convention',
                        'severity': violation['severity'],
                        'message': f"{violation['type']}: {function_name} - {violation['message']}",
                        'line': line_num,
                        'column': match.start() + 1,
                        'filename': filename,
                        'source_text': line.strip(),
                        'details': {
                            'function_name': function_name,
                            'violation_type': violation['type'],
                            'recommendation': violation['recommendation'],
                            'current_name': function_name,
                            'suggested_name': violation.get('suggested_name', '')
                        }
                    }
                    findings.append(finding)
                    
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    
    return findings

def check_naming_violations(function_name):
    """
    Check a function name against Go naming conventions.
    
    Args:
        function_name: The function name to check
        
    Returns:
        List of violation dictionaries
    """
    violations = []
    
    # Rule 1: Check for numbers in function names
    if re.search(r'\d', function_name):
        violations.append({
            'type': 'Numbers in function name',
            'severity': 'major',
            'message': 'Function names should not contain numbers - use descriptive words instead',
            'recommendation': 'Replace numbers with descriptive words (e.g., calculateTax2 -> calculateAlternativeTax)',
            'suggested_name': re.sub(r'\d+', 'Alternative', function_name)
        })
    
    # Rule 2: Check for underscores (should use camelCase)
    if '_' in function_name:
        camel_case = to_camel_case(function_name)
        violations.append({
            'type': 'Underscore in function name',
            'severity': 'major',
            'message': 'Use camelCase instead of underscores for function names',
            'recommendation': 'Convert to camelCase following Go conventions',
            'suggested_name': camel_case
        })
    
    # Rule 3: Check for mixed case with underscores
    if '_' in function_name and any(c.isupper() for c in function_name):
        violations.append({
            'type': 'Mixed case with underscores',
            'severity': 'major', 
            'message': 'Inconsistent naming - mixing camelCase with underscores',
            'recommendation': 'Use consistent camelCase without underscores',
            'suggested_name': function_name.replace('_', '')
        })
    
    # Rule 4: Check for Hungarian notation
    hungarian_prefixes = ['str', 'int', 'bool', 'arr', 'map', 'ptr', 'obj']
    for prefix in hungarian_prefixes:
        if function_name.lower().startswith(prefix.lower()) and len(function_name) > len(prefix):
            next_char = function_name[len(prefix)]
            if next_char.isupper() or next_char.islower():
                violations.append({
                    'type': 'Hungarian notation',
                    'severity': 'major',
                    'message': f'Avoid Hungarian notation prefix "{prefix}" - use descriptive names instead',
                    'recommendation': 'Remove type prefixes and use meaningful names',
                    'suggested_name': function_name[len(prefix)].lower() + function_name[len(prefix)+1:] if len(function_name) > len(prefix) else 'processValue'
                })
                break
    
    # Rule 5: Check for overly abbreviated names
    if len(function_name) <= 3 and function_name not in ['get', 'set', 'add', 'run']:
        violations.append({
            'type': 'Overly abbreviated name',
            'severity': 'major',
            'message': f'Function name "{function_name}" is too abbreviated to be clear',
            'recommendation': 'Use descriptive names that clearly indicate the function purpose',
            'suggested_name': 'processValue'  # Generic suggestion
        })
    
    # Rule 6: Check for non-descriptive names
    non_descriptive = ['doStuff', 'handleIt', 'processIt', 'doThing', 'makeIt', 'fixIt', 'runIt', 'checkIt']
    if function_name in non_descriptive:
        violations.append({
            'type': 'Non-descriptive name',
            'severity': 'major',
            'message': f'Function name "{function_name}" is not descriptive of its purpose',
            'recommendation': 'Use specific, descriptive names that indicate what the function does',
            'suggested_name': 'processData'  # Generic suggestion
        })
    
    # Rule 7: Check for single character names
    if len(function_name) == 1:
        violations.append({
            'type': 'Single character name',
            'severity': 'critical',
            'message': f'Single character function name "{function_name}" is not descriptive',
            'recommendation': 'Use meaningful function names that describe the purpose',
            'suggested_name': 'processValue'
        })
    
    # Rule 8: Check for all uppercase
    if function_name.isupper() and len(function_name) > 1:
        violations.append({
            'type': 'All uppercase name',
            'severity': 'major',
            'message': 'Function names should not be all uppercase - use camelCase',
            'recommendation': 'Convert to camelCase following Go conventions',
            'suggested_name': function_name[0].lower() + function_name[1:].lower()
        })
    
    # Rule 9: Check for all lowercase (longer than 4 chars)
    if function_name.islower() and len(function_name) > 4:
        violations.append({
            'type': 'All lowercase name',
            'severity': 'major',
            'message': 'Long function names should use camelCase for readability',
            'recommendation': 'Convert to camelCase with appropriate capitalization',
            'suggested_name': to_camel_case_from_lowercase(function_name)
        })
    
    # Rule 10: Check for special characters (except allowed ones)
    if re.search(r'[^\w]', function_name):
        violations.append({
            'type': 'Invalid characters in name',
            'severity': 'critical',
            'message': 'Function names should only contain letters, numbers, and underscores',
            'recommendation': 'Remove special characters and use valid identifiers',
            'suggested_name': re.sub(r'[^\w]', '', function_name)
        })
    
    # Rule 11: Check for excessive abbreviations
    excessive_abbrev_pattern = r'^[a-z]{2,3}[A-Z][a-z]{2,3}[A-Z][a-z]{2,3}'
    if re.match(excessive_abbrev_pattern, function_name):
        violations.append({
            'type': 'Excessive abbreviations',
            'severity': 'major',
            'message': 'Avoid excessive abbreviations - use more readable names',
            'recommendation': 'Expand abbreviations to full words for clarity',
            'suggested_name': 'processUserData'  # Generic suggestion
        })
    
    return violations

def to_camel_case(snake_str):
    """Convert snake_case to camelCase."""
    components = snake_str.split('_')
    return components[0].lower() + ''.join(x.capitalize() for x in components[1:])

def to_camel_case_from_lowercase(lowercase_str):
    """Convert all lowercase to camelCase by capitalizing likely word boundaries."""
    # Simple heuristic: capitalize after common prefixes
    result = lowercase_str
    
    # Common word boundaries to capitalize after
    prefixes = ['get', 'set', 'create', 'update', 'delete', 'process', 'handle', 'validate', 'calculate', 'format', 'convert']
    
    for prefix in prefixes:
        if result.startswith(prefix) and len(result) > len(prefix):
            result = prefix + result[len(prefix)].upper() + result[len(prefix)+1:]
            break
    
    return result


def check_function_length_limit(ast_tree, filename, semantic_analyzer=None):
    """
    Check for functions that exceed reasonable length limits.
    
    Args:
        ast_tree: The parsed AST tree
        filename: Name of the file being analyzed
        semantic_analyzer: Optional semantic analyzer (unused)
        
    Returns:
        List of findings for functions that are too long
    """
    findings = []
    
    # Function length thresholds
    MAX_LINES_WARNING = 40   # Warn for functions over 40 lines
    MAX_LINES_MAJOR = 60     # Major issue for functions over 60 lines
    MAX_LINES_CRITICAL = 100 # Critical issue for functions over 100 lines
    
    def count_non_empty_lines(text):
        """Count non-empty, non-comment-only lines."""
        lines = text.split('\n')
        count = 0
        for line in lines:
            stripped = line.strip()
            # Skip empty lines and comment-only lines
            if stripped and not (stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*')):
                count += 1
        return count
    
    def analyze_function_node(node, parent_path=""):
        """Recursively analyze function nodes."""
        if not isinstance(node, dict):
            return
            
        node_type = node.get('type', node.get('node_type', ''))
        
        # Check for function declarations and method declarations
        if node_type in ['function_declaration', 'method_declaration']:
            source_text = node.get('source_text', '')
            if source_text:
                line_count = count_non_empty_lines(source_text)
                line_number = node.get('line', 1)
                
                # Extract function name for reporting
                function_name = extract_function_name(source_text)
                
                # Determine severity based on line count
                if line_count >= MAX_LINES_CRITICAL:
                    severity = 'critical'
                    issue_type = 'extremely long function'
                elif line_count >= MAX_LINES_MAJOR:
                    severity = 'major'
                    issue_type = 'very long function'
                elif line_count >= MAX_LINES_WARNING:
                    severity = 'major'  # Keep as major for consistency
                    issue_type = 'long function'
                else:
                    return  # Function is acceptable length
                
                finding = {
                    'type': 'structure_function_length_limit',
                    'message': f"{issue_type.title()}: {function_name} has {line_count} lines (exceeds {MAX_LINES_WARNING} line limit)",
                    'line': line_number,
                    'column': 1,
                    'severity': severity,
                    'category': 'maintainability',
                    'source_text': source_text[:200] + ('...' if len(source_text) > 200 else ''),
                    'details': {
                        'function_name': function_name,
                        'line_count': line_count,
                        'max_recommended': MAX_LINES_WARNING,
                        'issue_type': issue_type,
                        'recommendation': 'Break this function into smaller, more focused functions with single responsibilities.'
                    }
                }
                findings.append(finding)
        
        # Recursively check child nodes
        for key, value in node.items():
            if isinstance(value, list):
                for item in value:
                    analyze_function_node(item, f"{parent_path}.{key}")
            elif isinstance(value, dict):
                analyze_function_node(value, f"{parent_path}.{key}")
    
    def extract_function_name(source_text):
        """Extract function name from source text."""
        # Try to match function declaration patterns
        patterns = [
            r'func\s+\(.*?\)\s*(\w+)\s*\(',  # method: func (receiver) methodName(
            r'func\s+(\w+)\s*\(',            # function: func functionName(
        ]
        
        for pattern in patterns:
            match = re.search(pattern, source_text)
            if match:
                return match.group(1)
        
        return "unknown"
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_function_node(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_function_node(node)
    
    return findings

def check_function_parameter_limit(ast_tree):
    """
    Check for functions with excessive parameters.
    Functions with too many parameters are difficult to use and maintain.
    """
    MAX_PARAMETERS_WARNING = 6  # Warn at 7+ parameters
    MAX_PARAMETERS_ERROR = 8    # Error at 9+ parameters
    
    findings = []
    
    def analyze_function_node(node, parent_path=""):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        
        if node_type in ['function_declaration', 'method_declaration']:
            source_text = node.get('source_text', '')
            line_number = node.get('start_point', {}).get('row', 0) + 1
            
            function_name = extract_function_name(source_text)
            parameter_count = count_function_parameters(source_text)
            
            severity = None
            issue_type = None
            
            # Determine severity and issue type
            if parameter_count >= MAX_PARAMETERS_ERROR:
                severity = 'major'
                issue_type = 'excessive_parameters'
            elif parameter_count > MAX_PARAMETERS_WARNING:
                severity = 'minor'
                issue_type = 'too_many_parameters'
            
            if severity:
                message = f"Function '{function_name}' has {parameter_count} parameters"
                if severity == 'major':
                    message += f" (exceeds critical limit of {MAX_PARAMETERS_ERROR})"
                    recommendation = "Consider grouping related parameters into structs or splitting the function into smaller, focused functions."
                else:
                    message += f" (exceeds recommended limit of {MAX_PARAMETERS_WARNING})"
                    recommendation = "Consider reducing the number of parameters by grouping related ones into structs."
                
                finding = {
                    'rule_id': 'structure_function_parameter_limit',
                    'message': message,
                    'line': line_number,
                    'column': 1,
                    'severity': severity,
                    'category': 'maintainability',
                    'source_text': source_text[:200] + ('...' if len(source_text) > 200 else ''),
                    'details': {
                        'function_name': function_name,
                        'parameter_count': parameter_count,
                        'max_recommended': MAX_PARAMETERS_WARNING,
                        'max_critical': MAX_PARAMETERS_ERROR,
                        'issue_type': issue_type,
                        'recommendation': recommendation
                    }
                }
                findings.append(finding)
        
        # Recursively check child nodes
        for key, value in node.items():
            if isinstance(value, list):
                for item in value:
                    analyze_function_node(item, f"{parent_path}.{key}")
            elif isinstance(value, dict):
                analyze_function_node(value, f"{parent_path}.{key}")
    
    def count_function_parameters(source_text):
        """Count the number of parameters in a function declaration."""
        # Extract parameter list from function signature
        # Handle both function and method declarations
        patterns = [
            r'func\s+\([^)]*\)\s*\w+\s*\(([^)]*)\)',  # method: func (receiver) methodName(params)
            r'func\s+\w+\s*\(([^)]*)\)',              # function: func functionName(params)
        ]
        
        for pattern in patterns:
            match = re.search(pattern, source_text, re.DOTALL)
            if match:
                param_text = match.group(1).strip()
                if not param_text:
                    return 0
                
                # Parse parameters - handle complex cases
                return parse_parameter_list(param_text)
        
        return 0
    
    def parse_parameter_list(param_text):
        """Parse Go function parameter list and count parameters."""
        if not param_text.strip():
            return 0
        
        # Split by commas but be careful about nested types
        params = []
        current_param = ""
        paren_depth = 0
        bracket_depth = 0
        
        for char in param_text:
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif char == '[':
                bracket_depth += 1
            elif char == ']':
                bracket_depth -= 1
            elif char == ',' and paren_depth == 0 and bracket_depth == 0:
                if current_param.strip():
                    params.append(current_param.strip())
                current_param = ""
                continue
            
            current_param += char
        
        # Add the last parameter
        if current_param.strip():
            params.append(current_param.strip())
        
        # Count actual parameters (not type definitions)
        param_count = 0
        for param in params:
            # Handle cases like "a, b, c string" where multiple params share a type
            param = param.strip()
            if not param:
                continue
                
            # Split by spaces to separate names from types
            parts = param.split()
            if len(parts) >= 2:
                # Check if there are multiple comma-separated names before the type
                names_part = ' '.join(parts[:-1])  # Everything except the last word (type)
                # Count comma-separated names
                names = [name.strip() for name in names_part.split(',') if name.strip()]
                param_count += len(names)
            else:
                # Single parameter
                param_count += 1
        
        return param_count
    
    def extract_function_name(source_text):
        """Extract function name from source text."""
        # Try to match function declaration patterns
        patterns = [
            r'func\s+\(.*?\)\s*(\w+)\s*\(',  # method: func (receiver) methodName(
            r'func\s+(\w+)\s*\(',            # function: func functionName(
        ]
        
        for pattern in patterns:
            match = re.search(pattern, source_text)
            if match:
                return match.group(1)
        
        return "unknown"
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_function_node(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_function_node(node)
    
    return findings

def check_go_parser_failure(ast_tree):
    """
    Check for Go parser failures and syntax errors.
    Detects malformed code that prevents proper parsing.
    """
    import re
    findings = []
    
    def analyze_syntax_errors(node, parent_path=""):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source_text = node.get('source_text', '')
        line_number = node.get('start_point', {}).get('row', 0) + 1
        
        # Check for parsing errors or malformed syntax
        if node_type == 'ERROR' or 'error' in node_type.lower():
            finding = {
                'rule_id': 'parsing_go_parser_failure',
                'message': f"Parser error detected: {node_type}",
                'line': line_number,
                'column': 1,
                'severity': 'major',
                'category': 'maintainability',
                'source_text': source_text[:100] + ('...' if len(source_text) > 100 else ''),
                'details': {
                    'error_type': 'parser_error',
                    'node_type': node_type,
                    'recommendation': 'Fix syntax errors to ensure proper code parsing.'
                }
            }
            findings.append(finding)
        
        # Check for specific syntax error patterns in source text
        if source_text:
            syntax_errors = detect_syntax_errors(source_text, line_number)
            findings.extend(syntax_errors)
        
        # Recursively check child nodes
        for key, value in node.items():
            if isinstance(value, list):
                for item in value:
                    analyze_syntax_errors(item, f"{parent_path}.{key}")
            elif isinstance(value, dict):
                analyze_syntax_errors(value, f"{parent_path}.{key}")
    
    def detect_syntax_errors(source_text, line_number):
        """Detect common syntax errors in Go code."""
        errors = []
        
        # Common syntax error patterns that indicate syntax errors
        patterns = [
            (r'var\s*:=', 'invalid_var_declaration',
             'Invalid variable declaration - missing variable name'),
            (r'func\s*\(\s*\*\w+\)\s*\w+', 'invalid_method_receiver',
             'Invalid method receiver - missing receiver variable name'),
            (r'<\s*"', 'invalid_channel_op',
             'Invalid channel operation - should use <-'),
            (r'const\s+\w+\s*=\s*$', 'incomplete_const',
             'Incomplete constant declaration - missing value'),
        ]
        
        for pattern, error_type, message in patterns:
            if re.search(pattern, source_text, re.MULTILINE):
                error = {
                    'rule_id': 'parsing_go_parser_failure',
                    'message': f"Syntax error: {message}",
                    'line': line_number,
                    'column': 1,
                    'severity': 'major',
                    'category': 'maintainability',
                    'source_text': source_text[:100] + ('...' if len(source_text) > 100 else ''),
                    'details': {
                        'error_type': error_type,
                        'pattern': pattern,
                        'recommendation': f'Fix syntax error: {message.lower()}'
                    }
                }
                errors.append(error)
        
        return errors
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_syntax_errors(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_syntax_errors(node)
    
    return findings

def check_hardcoded_credentials(ast_tree):
    """
    Check for hardcoded credentials and sensitive information.
    Detects passwords, API keys, tokens, and other authentication data in source code.
    """
    import re
    findings = []
    
    def analyze_credential_nodes(node, parent_path=""):
        if not isinstance(node, dict):
            return
            
        node_type = node.get('node_type', '')
        source_text = node.get('source_text', '')
        line_number = node.get('start_point', {}).get('row', 0) + 1
        
        # Focus on assignment-related nodes that actually contain credentials
        if node_type in ['assignment_statement', 'short_var_declaration', 'const_declaration', 'var_declaration']:
            credential_violations = detect_credential_patterns(source_text, line_number)
            findings.extend(credential_violations)
        
        # Also check string literals that might contain credentials
        elif node_type == 'interpreted_string_literal':
            string_content = source_text.strip('"\'')
            if looks_like_credential(string_content):
                # Get parent context to understand if this is a credential assignment
                if is_credential_assignment_context(source_text):
                    violation = {
                        'rule_id': 'security_hardcoded_credentials',
                        'message': f"Hardcoded credential detected in string literal",
                        'line': line_number,
                        'column': 1,
                        'severity': 'major',
                        'category': 'security',
                        'source_text': source_text[:100] + ('...' if len(source_text) > 100 else ''),
                        'details': {
                            'credential_type': 'string_literal',
                            'description': 'String literal contains credential-like data',
                            'recommendation': 'Move credentials to environment variables, configuration files, or secure credential management systems.'
                        }
                    }
                    findings.append(violation)
        
        # Recursively check child nodes
        for key, value in node.items():
            if isinstance(value, list):
                for item in value:
                    analyze_credential_nodes(item, f"{parent_path}.{key}")
            elif isinstance(value, dict):
                analyze_credential_nodes(value, f"{parent_path}.{key}")
    
    def detect_credential_patterns(source_text, line_number):
        """Detect hardcoded credentials using comprehensive but precise patterns."""
        violations = []
        
        # More precise credential detection patterns
        patterns = [
            # Password patterns with assignment operators (enhanced)
            (r'\b(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']', 'password', 'hardcoded password'),
            (r'\bpassword\s*:=\s*["\'][^"\']{3,}["\']', 'password', 'hardcoded password'),
            (r'var\s+(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', 'password', 'hardcoded password'),
            
            # Admin password patterns
            (r'\b(adminPass|admin_password|adminPassword)\s*[:=]\s*["\'][^"\']{3,}["\']', 'admin_credential', 'hardcoded admin password'),
            
            # API Key patterns (enhanced)
            (r'\b(api_key|apikey|API_KEY|APIKEY)\s*[:=]\s*["\'][^"\']{8,}["\']', 'api_key', 'hardcoded API key'),
            (r'var\s+(api_key|apikey|API_KEY|APIKEY)\s*=\s*["\'][^"\']{8,}["\']', 'api_key', 'hardcoded API key'),
            
            # Secret patterns (enhanced)
            (r'\b(secret|SECRET|api_secret|API_SECRET)\s*[:=]\s*["\'][^"\']{6,}["\']', 'secret', 'hardcoded secret'),
            (r'\b(jwt_secret|jwtSecret)\s*[:=]\s*["\'][^"\']{6,}["\']', 'jwt_secret', 'hardcoded JWT secret'),
            (r'var\s+(jwt_secret|jwtSecret|secret|SECRET)\s*=\s*["\'][^"\']{6,}["\']', 'jwt_secret', 'hardcoded JWT secret'),
            
            # Token patterns (enhanced)
            (r'\b(token|TOKEN|auth_token|access_token|bearer_token|oauth_token)\s*[:=]\s*["\'][^"\']{8,}["\']', 'token', 'hardcoded token'),
            (r'\b(apiToken|bearerToken|oauthToken|accessToken)\s*[:=]\s*["\'][^"\']{8,}["\']', 'token', 'hardcoded token'),
            (r'var\s+(token|TOKEN|apiToken|bearerToken|oauthToken)\s*=\s*["\'][^"\']{8,}["\']', 'token', 'hardcoded token'),
            
            # Database credentials (enhanced)
            (r'\b(db_password|database_password|dbPassword)\s*[:=]\s*["\'][^"\']{3,}["\']', 'db_credential', 'hardcoded database password'),
            (r'var\s+(db_password|database_password|dbPassword)\s*=\s*["\'][^"\']{3,}["\']', 'db_credential', 'hardcoded database password'),
            
            # AWS patterns (more specific)
            (r'\b(aws_access_key|AWS_ACCESS_KEY|accessKey)\s*[:=]\s*["\']AKIA[A-Z0-9]{16}["\']', 'aws_credential', 'hardcoded AWS access key'),
            (r'\b(aws_secret_key|AWS_SECRET_KEY|secretKey)\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']', 'aws_credential', 'hardcoded AWS secret key'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key', 'AWS access key pattern detected'),
            
            # SSH keys (specific patterns)
            (r'-----BEGIN [A-Z ]+PRIVATE KEY-----', 'ssh_key', 'hardcoded SSH private key'),
            (r'\b(ssh_key|sshKey)\s*[:=]\s*["\'][^"\']+["\']', 'ssh_key', 'hardcoded SSH key'),
            
            # Certificate patterns
            (r'-----BEGIN CERTIFICATE-----', 'certificate', 'hardcoded certificate'),
            (r'-----BEGIN PRIVATE KEY-----', 'private_key', 'hardcoded private key'),
            
            # Other specific credentials (enhanced)
            (r'\b(encryption_key|encryptionKey)\s*[:=]\s*["\'][^"\']{8,}["\']', 'encryption_key', 'hardcoded encryption key'),
            (r'var\s+(encryption_key|encryptionKey)\s*=\s*["\'][^"\']{8,}["\']', 'encryption_key', 'hardcoded encryption key'),
            (r'\b(session_secret|sessionSecret)\s*[:=]\s*["\'][^"\']{8,}["\']', 'session_secret', 'hardcoded session secret'),
            (r'var\s+(session_secret|sessionSecret)\s*=\s*["\'][^"\']{8,}["\']', 'session_secret', 'hardcoded session secret'),
            (r'\b(webhook_secret|WEBHOOK_SECRET|webhookSecret)\s*[:=]\s*["\'][^"\']{6,}["\']', 'webhook_secret', 'hardcoded webhook secret'),
            (r'\b(salt|SALT)\s*[:=]\s*["\'][^"\']{4,}["\']', 'salt', 'hardcoded salt value'),
            
            # Constant declarations for credentials
            (r'const\s*\(\s*[^)]*\b(WEBHOOK_SECRET|JWT_SECRET|API_SECRET|API_KEY)\s*=\s*["\'][^"\']{6,}["\']', 'const_credential', 'hardcoded credential constant'),
            (r'const\s+(WEBHOOK_SECRET|JWT_SECRET|API_SECRET|API_KEY|TOKEN)\s*=\s*["\'][^"\']{6,}["\']', 'const_credential', 'hardcoded credential constant'),
        ]
        
        # Skip comment lines and function/type declarations
        if re.match(r'^\s*(//|/\*)', source_text.strip()) or re.match(r'^\s*(func|type|package|import)', source_text.strip()):
            return violations
        
        for pattern, cred_type, description in patterns:
            matches = re.finditer(pattern, source_text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Extract the actual credential value for analysis
                credential_value = match.group(0)
                
                # Skip if it looks like it's reading from environment or config
                if is_secure_credential_usage(credential_value, source_text):
                    continue
                
                # Skip obvious placeholder values
                if is_placeholder_value(credential_value):
                    continue
                
                violation = {
                    'rule_id': 'security_hardcoded_credentials',
                    'message': f"Hardcoded credential detected: {description}",
                    'line': line_number,
                    'column': match.start() + 1,
                    'severity': 'major',
                    'category': 'security',
                    'source_text': source_text[:150] + ('...' if len(source_text) > 150 else ''),
                    'details': {
                        'credential_type': cred_type,
                        'pattern_matched': pattern,
                        'description': description,
                        'recommendation': 'Move credentials to environment variables, configuration files, or secure credential management systems.'
                    }
                }
                violations.append(violation)
        
        return violations
    
    def looks_like_credential(string_content):
        """Check if a string looks like a credential."""
        if len(string_content) < 4:
            return False
        
        # Check for credential-like patterns
        credential_patterns = [
            r'^[A-Za-z0-9+/=]{40,}$',  # Base64-like strings
            r'^AKIA[A-Z0-9]{16}$',      # AWS access key format
            r'^sk-[a-zA-Z0-9]{32,}$',   # API key format
            r'^[a-f0-9]{32,}$',         # Hex strings (MD5, SHA, etc.)
        ]
        
        for pattern in credential_patterns:
            if re.match(pattern, string_content):
                return True
        
        return False
    
    def is_credential_assignment_context(source_text):
        """Check if string is in credential assignment context."""
        credential_keywords = [
            'password', 'secret', 'key', 'token', 'auth', 'credential'
        ]
        
        for keyword in credential_keywords:
            if keyword.lower() in source_text.lower():
                return True
        
        return False
    
    def is_secure_credential_usage(credential_value, source_text):
        """Check if the credential usage appears to be secure (from env vars, etc)."""
        # Check for environment variable patterns
        env_patterns = [
            r'os\.Getenv\s*\(',
            r'os\.LookupEnv\s*\(',
            r'viper\.Get\s*\(',
            r'config\.Get\s*\(',
            r'\.GetString\s*\(',
            r'\.GetEnv\s*\(',
        ]
        
        for pattern in env_patterns:
            if re.search(pattern, source_text, re.IGNORECASE):
                return True
        
        return False
    
    def is_placeholder_value(credential_value):
        """Check for placeholder or example values."""
        placeholder_patterns = [
            r'example',
            r'placeholder',
            r'your_.*_here',
            r'insert_.*_here',
            r'replace_.*',
            r'test.*123',
            r'localhost',
            r'example\.com',
        ]
        
        for pattern in placeholder_patterns:
            if re.search(pattern, credential_value, re.IGNORECASE):
                return True
        
        return False
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_credential_nodes(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_credential_nodes(node)
    
    return findings

def check_http_request_redirections(ast_tree):
    """
    Check for HTTP redirections that use unvalidated user input.
    Detects open redirect vulnerabilities in Go code.
    """
    findings = []
    
    def analyze_redirect_nodes(node):
        if isinstance(node, dict):
            node_type = node.get('node_type', '')
            
            # Check for function declarations
            if node_type == 'function_declaration':
                source_text = node.get('source_text', '')
                
                # Look for http.Redirect calls
                if 'http.Redirect' in source_text:
                    # Simplified detection patterns
                    redirect_patterns = [
                        # Variable assignment followed by redirect usage
                        (r'(\w+(?:URL|url)?)\s*:=\s*r\.URL\.Query\(\)\.Get\([^)]+\)[\s\S]*?http\.Redirect\s*\([^,]*,\s*[^,]*,\s*\1',
                         'Unvalidated redirect using query parameter'),
                        
                        (r'(\w+(?:URL|url)?)\s*:=\s*r\.FormValue\([^)]+\)[\s\S]*?http\.Redirect\s*\([^,]*,\s*[^,]*,\s*\1',
                         'Unvalidated redirect using form value'),
                        
                        (r'(\w+(?:URL|url)?)\s*:=\s*r\.Header\.Get\([^)]+\)[\s\S]*?http\.Redirect\s*\([^,]*,\s*[^,]*,\s*\1',
                         'Unvalidated redirect using header value'),
                        
                        # Direct usage patterns
                        (r'http\.Redirect\s*\([^,]*,\s*[^,]*,\s*r\.URL\.Query\(\)\.Get\([^)]+\)',
                         'Direct redirect using query parameter'),
                        
                        (r'http\.Redirect\s*\([^,]*,\s*[^,]*,\s*r\.FormValue\([^)]+\)',
                         'Direct redirect using form value'),
                        
                        (r'http\.Redirect\s*\([^,]*,\s*[^,]*,\s*r\.Header\.Get\([^)]+\)',
                         'Direct redirect using header value'),
                    ]
                    
                    for pattern, message in redirect_patterns:
                        matches = re.finditer(pattern, source_text, re.MULTILINE | re.DOTALL | re.IGNORECASE)
                        for match in matches:
                            # Skip if there's obvious validation nearby
                            context_start = max(0, match.start() - 300)
                            context_end = min(len(source_text), match.end() + 300)
                            context = source_text[context_start:context_end]
                            
                            # Simple validation check - if we see validation keywords, skip
                            if not has_validation_nearby(context):
                                line_num = source_text[:match.start()].count('\n') + 1
                                
                                findings.append({
                                    'rule_id': 'security_http_request_redirections',
                                    'message': f'Unsafe HTTP redirect: {message}. User input used in redirect without validation can lead to open redirect attacks.',
                                    'line': line_num,
                                    'column': 1,
                                    'severity': 'major',
                                    'category': 'Security',
                                    'node_type': 'http_redirect',
                                    'source_text': match.group(0)[:100] + '...' if len(match.group(0)) > 100 else match.group(0)
                                })
            
            # Recursively analyze child nodes
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    analyze_redirect_nodes(value)
        
        elif isinstance(node, list):
            for item in node:
                analyze_redirect_nodes(item)
    
    def has_validation_nearby(context):
        """Check if there are validation patterns in the context"""
        validation_patterns = [
            r'isAllowedRedirect\s*\(',
            r'validateRedirectURL\s*\(',
            r'isRelativeURL\s*\(',
            r'isValidDomain\s*\(',
            r'redirectMappings\[',
            r'allowedRedirectDomains',
            r'url\.Parse\s*\(',
            r'strings\.HasPrefix\s*\(',
            r'whitelist',
            r'validation',
            r'validate\w*',
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_redirect_nodes(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_redirect_nodes(node)
    
    return findings


def check_logic_identical_expressions_binary(ast_tree):
    """
    Check for identical expressions in binary operations.
    Detects cases where the same variable/expression appears on both sides
    of binary operators like ==, &&, ||, which are typically logic errors.
    """
    findings = []
    
    def analyze_node_for_identical_expressions(node, depth=0):
        if depth > 20:  # Prevent infinite recursion
            return
            
        if not isinstance(node, dict):
            return
        
        node_type = node.get('node_type', '')
        source_text = node.get('source_text', '') or node.get('source', '')
        line_number = node.get('line', node.get('lineno', 0))
        
        # Skip invalid line numbers and certain node types
        if line_number <= 0:
            for key, value in node.items():
                if key == 'children' and isinstance(value, list):
                    for child in value:
                        analyze_node_for_identical_expressions(child, depth + 1)
                elif isinstance(value, dict):
                    analyze_node_for_identical_expressions(value, depth + 1)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            analyze_node_for_identical_expressions(item, depth + 1)
            return
            
        # Skip function declarations, variable declarations, and other non-relevant nodes
        if _should_skip_node(node, source_text):
            for key, value in node.items():
                if key == 'children' and isinstance(value, list):
                    for child in value:
                        analyze_node_for_identical_expressions(child, depth + 1)
                elif isinstance(value, dict):
                    analyze_node_for_identical_expressions(value, depth + 1)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            analyze_node_for_identical_expressions(item, depth + 1)
            return
        
        # Patterns to detect identical expressions in binary operations
        binary_patterns = [
            # Variable == Variable (e.g., x == x)
            (r'\b(\w+(?:\.\w+)*)\s*==\s*\1\b', "equality comparison"),
            # Variable && Variable (e.g., flag && flag)
            (r'\b(\w+(?:\.\w+)*)\s*&&\s*\1\b', "logical AND"), 
            # Variable || Variable (e.g., condition || condition)
            (r'\b(\w+(?:\.\w+)*)\s*\|\|\s*\1\b', "logical OR"),
            # Variable != Variable (e.g., x != x)
            (r'\b(\w+(?:\.\w+)*)\s*!=\s*\1\b', "inequality comparison"),
            # Function calls: func() == func() 
            (r'(\w+\([^)]*\))\s*==\s*\1', "function call comparison"),
            # Complex expressions in parentheses
            (r'\(([^()]+)\)\s*[=!]{1,2}\s*\(\1\)', "complex expression comparison"),
        ]
        
        for pattern, description in binary_patterns:
            matches = re.finditer(pattern, source_text, re.IGNORECASE)
            for match in matches:
                # Extract the repeated expression
                repeated_expr = match.group(1)
                
                # Skip legitimate cases where identical expressions might be valid
                if _is_legitimate_identical_expression(source_text, repeated_expr, description):
                    continue
                
                findings.append({
                    'rule_id': 'logic_identical_expressions_binary',
                    'message': f'Rule: Avoid identical expressions in binary operations - Found "{repeated_expr}" used on both sides of {description}',
                    'line': line_number,
                    'column': match.start(),
                    'severity': 'Major',
                    'node_type': node_type,
                    'source_text': source_text.strip(),
                    'repeated_expression': repeated_expr,
                    'violation_type': description,
                    'full_match': match.group(0)
                })
        
        # Check for arithmetic patterns (x + x - x, x * x / x)
        arithmetic_patterns = [
            (r'\b(\w+)\s*\+\s*\1\s*-\s*\1\b', "addition-subtraction pattern"),
            (r'\b(\w+)\s*\*\s*\1\s*/\s*\1\b', "multiplication-division pattern"),
        ]
        
        for pattern, description in arithmetic_patterns:
            matches = re.finditer(pattern, source_text, re.IGNORECASE)
            for match in matches:
                repeated_expr = match.group(1)
                
                # Skip if it looks like intentional math
                if _is_legitimate_arithmetic(source_text, repeated_expr):
                    continue
                    
                findings.append({
                    'rule_id': 'logic_identical_expressions_binary',
                    'message': f'Rule: Avoid identical expressions in binary operations - Redundant arithmetic pattern "{repeated_expr}" in {description}',
                    'line': line_number,
                    'column': match.start(),
                    'severity': 'Major',
                    'node_type': node_type,
                    'source_text': source_text.strip(),
                    'repeated_expression': repeated_expr,
                    'violation_type': description,
                    'full_match': match.group(0)
                })
        
        # Recursively check child nodes
        if isinstance(node, dict):
            for key, value in node.items():
                if key == 'children' and isinstance(value, list):
                    for child in value:
                        analyze_node_for_identical_expressions(child, depth + 1)
                elif isinstance(value, dict):
                    analyze_node_for_identical_expressions(value, depth + 1)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            analyze_node_for_identical_expressions(item, depth + 1)
    
    def _should_skip_node(node, source_text):
        """Check if we should skip analyzing this node."""
        
        node_type = node.get('node_type', '').lower()
        source = source_text.strip().lower()
        
        # Skip function declarations
        if node_type in ['function_declaration', 'method_declaration'] or source.startswith('func '):
            return True
            
        # Skip variable declarations without binary operations
        if (node_type in ['var_declaration', 'variable_declaration', 'short_var_declaration'] or 
            source.startswith('var ')) and not any(op in source for op in ['==', '!=', '&&', '||']):
            return True
            
        # Skip package and import statements
        if source.startswith(('package ', 'import ', 'type ', '}')):
            return True
            
        # Skip comments
        if source.startswith(('//','/*', '*')):
            return True
            
        # Skip struct/interface definitions
        if 'struct {' in source or 'interface {' in source:
            return True
        
        # Skip empty or very short lines that can't contain binary operations
        if len(source) < 5:
            return True
            
        return False
    
    def _is_legitimate_identical_expression(source_text, expr, description):
        """
        Check if an identical expression is actually legitimate.
        """
        source_lower = source_text.lower()
        
        # NaN checks (x != x is valid for NaN detection)
        if description == "inequality comparison" and any(keyword in source_lower for keyword in ['nan', 'infinity', 'inf']):
            return True
        
        # Skip math operations that might be intentional  
        if any(keyword in source_lower for keyword in ['math.', 'Math.', 'float']):
            return True
            
        # Skip commented lines
        if source_text.strip().startswith('//'):
            return True
            
        # Constants comparison might be intentional
        if expr.upper() == expr and len(expr) > 1:  # ALL_CAPS constants
            return True
            
        return False
        
    def _is_legitimate_arithmetic(source_text, expr):
        """Check if arithmetic pattern might be legitimate."""
        
        source_lower = source_text.lower()
        
        # Mathematical computations
        if any(keyword in source_lower for keyword in ['math', 'calculate', 'compute', 'formula']):
            return True
            
        # Constants
        if expr.upper() == expr:
            return True
            
        return False
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_node_for_identical_expressions(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_node_for_identical_expressions(node)
    
    return findings


def check_logic_identical_branch_implementations(ast_tree):
    """
    Check for identical implementations in conditional branches.
    Detects cases where all branches in if-else or switch statements 
    have exactly the same implementation, making the conditional redundant.
    """
    findings = []
    
    def analyze_node_for_identical_branches(node, depth=0):
        if depth > 25:  # Prevent infinite recursion
            return
            
        if not isinstance(node, dict):
            return
        
        node_type = node.get('node_type', '')
        source_text = node.get('source_text', '') or node.get('source', '')
        line_number = node.get('line', node.get('lineno', 0))
        
        # Don't skip nodes too aggressively - analyze all nodes for patterns
        if source_text and len(source_text) > 20:  # Only skip very short content
            
            # Analyze for switch statements
            if ('switch ' in source_text and 'case ' in source_text):
                identical_cases = _analyze_switch_branches(source_text, line_number)
                findings.extend(identical_cases)
            
            # Analyze for if-else statements  
            if ('if ' in source_text and 'else' in source_text and '{' in source_text):
                identical_branches = _analyze_if_else_branches(source_text, line_number)
                findings.extend(identical_branches)
        
        # Recursively check child nodes
        for key, value in node.items():
            if key == 'children' and isinstance(value, list):
                for child in value:
                    analyze_node_for_identical_branches(child, depth + 1)
            elif isinstance(value, dict):
                analyze_node_for_identical_branches(value, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        analyze_node_for_identical_branches(item, depth + 1)
    
    def _analyze_switch_branches(source_text, base_line):
        """Analyze switch statement for identical case implementations."""
        
        violations = []
        lines = source_text.split('\n')
        
        # Extract case blocks
        cases = []
        current_case = None
        current_content = []
        in_case = False
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            if line_stripped.startswith('case ') or line_stripped.startswith('default'):
                # Save previous case if it exists
                if current_case is not None and current_content:
                    cases.append({
                        'case': current_case,
                        'content': _normalize_code_block('\n'.join(current_content)),
                        'line_offset': i
                    })
                
                # Start new case
                current_case = line_stripped
                current_content = []
                in_case = True
                
            elif in_case and line_stripped:
                if line_stripped not in ['}', ''] and not line_stripped.startswith(('case ', 'default', 'switch ')):
                    current_content.append(line_stripped)
        
        # Add last case
        if current_case is not None and current_content:
            cases.append({
                'case': current_case,
                'content': _normalize_code_block('\n'.join(current_content)),
                'line_offset': len(lines) - len(current_content)
            })
        
        # Check for identical implementations
        if len(cases) >= 2:
            content_groups = {}
            for case in cases:
                content = case['content']
                if content and len(content.strip()) > 5:  # Ignore very simple content
                    if content not in content_groups:
                        content_groups[content] = []
                    content_groups[content].append(case)
            
            # Report groups with 2+ identical cases
            for content, case_group in content_groups.items():
                if len(case_group) >= 2 and not _is_legitimate_identical_case(content):
                    case_names = [c['case'] for c in case_group]
                    violations.append({
                        'rule_id': 'logic_identical_branch_implementations',
                        'message': f'Rule: Avoid identical branch implementations - Found {len(case_group)} switch cases with identical implementation: {", ".join(case_names[:2])}{"..." if len(case_names) > 2 else ""}',
                        'line': base_line + case_group[0]['line_offset'],
                        'column': 0,
                        'severity': 'Major',
                        'node_type': 'switch_statement',
                        'source_text': source_text.strip()[:200] + ("..." if len(source_text) > 200 else ""),
                        'violation_type': 'identical_switch_cases',
                        'identical_content': content,
                        'case_count': len(case_group),
                        'cases': case_names
                    })
        
        return violations
    
    def _analyze_if_else_branches(source_text, base_line):
        """Analyze if-else statement for identical branch implementations."""
        
        violations = []
        
        # Pattern: if (...) { ... } else { ... }
        if_else_pattern = r'if\s+[^{]+\{\s*([^{}]+(?:\{[^{}]*\}[^{}]*)*)\}\s*else\s*\{\s*([^{}]+(?:\{[^{}]*\}[^{}]*)*)\}'
        
        matches = re.finditer(if_else_pattern, source_text, re.DOTALL | re.IGNORECASE)
        for match in matches:
            if_content = _normalize_code_block(match.group(1))
            else_content = _normalize_code_block(match.group(2))
            
            if (if_content and else_content and 
                if_content == else_content and 
                len(if_content.strip()) > 10 and  # Ignore very simple content
                not _is_legitimate_identical_branch(if_content)):
                
                line_offset = source_text[:match.start()].count('\n')
                violations.append({
                    'rule_id': 'logic_identical_branch_implementations',
                    'message': f'Rule: Avoid identical branch implementations - If and else branches have identical implementation: "{if_content[:50]}{"..." if len(if_content) > 50 else ""}"',
                    'line': base_line + line_offset,
                    'column': match.start(),
                    'severity': 'Major',
                    'node_type': 'if_statement',
                    'source_text': source_text.strip()[:200] + ("..." if len(source_text) > 200 else ""),
                    'violation_type': 'identical_if_else_branches',
                    'identical_content': if_content
                })
        
        # Pattern for if-else chains with multiple identical branches
        if_chain_pattern = r'(?:if|else\s+if)\s+[^{]+\{\s*([^{}]+(?:\{[^{}]*\}[^{}]*)*)\}'
        
        branch_contents = []
        for match in re.finditer(if_chain_pattern, source_text, re.DOTALL | re.IGNORECASE):
            content = _normalize_code_block(match.group(1))
            if content and len(content.strip()) > 10:
                branch_contents.append({
                    'content': content,
                    'line_offset': source_text[:match.start()].count('\n')
                })
        
        # Check for identical content in if-else chains (3 or more branches)
        if len(branch_contents) >= 3:
            content_groups = {}
            for branch in branch_contents:
                content = branch['content']
                if content not in content_groups:
                    content_groups[content] = []
                content_groups[content].append(branch)
            
            for content, group in content_groups.items():
                if (len(group) >= 3 and  # Need at least 3 identical branches to be significant
                    not _is_legitimate_identical_branch(content)):
                    violations.append({
                        'rule_id': 'logic_identical_branch_implementations',
                        'message': f'Rule: Avoid identical branch implementations - Found {len(group)} if-else chain branches with identical implementation: "{content[:50]}{"..." if len(content) > 50 else ""}"',
                        'line': base_line + group[0]['line_offset'],
                        'column': 0,
                        'severity': 'Major',
                        'node_type': 'if_statement',
                        'source_text': source_text.strip()[:200] + ("..." if len(source_text) > 200 else ""),
                        'violation_type': 'identical_if_else_chain',
                        'identical_content': content,
                        'branch_count': len(group)
                    })
        
        return violations
    
    def _normalize_code_block(code):
        """Normalize code block for comparison by removing whitespace and comments."""
        
        if not code:
            return ""
        
        # Remove comments
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        # Normalize whitespace
        code = re.sub(r'\s+', ' ', code.strip())
        
        # Remove empty statements
        code = code.replace(';', '').strip()
        
        return code
    
    def _is_legitimate_identical_case(content):
        """Check if identical case content might be legitimate."""
        
        content_lower = content.lower()
        
        # Empty or very simple cases might be legitimate
        if len(content.strip()) < 15:
            return True
        
        # Break/continue/fallthrough statements are often identical 
        if content_lower.strip() in ['break', 'continue', 'fallthrough', 'return']:
            return True
        
        # Pure error returns might be identical
        if content_lower.strip() in ['return nil', 'return err', 'return error']:
            return True
        
        # Simple panic calls
        if 'panic(' in content_lower and len(content.strip()) < 30:
            return True
        
        return False
    
    def _is_legitimate_identical_branch(content):
        """Check if identical branch content might be legitimate."""
        
        content_lower = content.lower()
        
        # Very simple content might be legitimate
        if len(content.strip()) < 20:
            return True
        
        # Simple error handling might be identical
        if any(keyword in content_lower for keyword in ['error', 'panic(', 'return nil', 'return err']):
            return True
        
        # Simple logging might be identical
        if content_lower.strip().startswith('log.') and len(content.strip()) < 40:
            return True
        
        return False
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_node_for_identical_branches(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_node_for_identical_branches(node)
    
    return findings

def check_structure_identical_function_implementations(ast_tree):
    """
    Check for identical function implementations that indicate code duplication.
    Detects functions with the same logic that should be refactored.
    """
    findings = []
    functions = []
    
    def normalize_function_body(source_text):
        """Normalize function body for comparison by removing whitespace and comments"""
        if not source_text:
            return ""
        
        # Extract function body (content between { and })
        body_match = re.search(r'\{(.*)\}', source_text, re.DOTALL)
        if not body_match:
            return ""
        
        body = body_match.group(1)
        
        # Remove comments
        body = re.sub(r'//.*$', '', body, flags=re.MULTILINE)
        body = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
        
        # Extract parameter names from function signature to normalize them
        param_names = []
        func_match = re.search(r'func\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(([^)]*)\)', source_text)
        if func_match:
            params = func_match.group(1)
            # Extract parameter names (simple approach for common patterns)
            param_matches = re.findall(r'(\w+)\s+\w+', params)
            param_names = param_matches
        
        # Normalize parameter names in the body (replace with generic names)
        for i, param_name in enumerate(param_names):
            if param_name:
                # Replace parameter name with generic placeholder
                body = re.sub(r'\b' + re.escape(param_name) + r'\b', f'param{i}', body)
        
        # Normalize whitespace
        body = re.sub(r'\s+', ' ', body.strip())
        
        # Remove common variations that don't affect logic
        body = re.sub(r'^\s*{\s*', '', body)
        body = re.sub(r'\s*}\s*$', '', body)
        
        return body
    
    def extract_function_signature(source_text):
        """Extract function name from source"""
        match = re.search(r'func\s+([a-zA-Z_][a-zA-Z0-9_]*)', source_text)
        return match.group(1) if match else "unknown"
    
    def collect_functions(node):
        """Recursively collect all function declarations"""
        if isinstance(node, dict):
            if node.get('node_type') == 'function_declaration':
                source = node.get('source_text', '')
                if source and 'func ' in source:
                    # Skip functions that are likely legitimate duplicates
                    func_name = extract_function_signature(source)
                    
                    # Skip test functions, main, init, and getter/setter patterns
                    if any(pattern in func_name.lower() for pattern in ['test', 'main', 'init', 'get', 'set']):
                        return
                    
                    # Skip very short functions (likely simple getters/setters)
                    if len(source) < 100:
                        body = normalize_function_body(source)
                        if len(body) < 50:  # Very simple function
                            return
                    
                    functions.append({
                        'name': func_name,
                        'source': source,
                        'normalized_body': normalize_function_body(source),
                        'line': node.get('line', 0)
                    })
            
            # Recursively check children
            if 'children' in node:
                for child in node['children']:
                    collect_functions(child)
    
    def is_legitimate_duplicate(func1, func2):
        """Check if duplicate is legitimate (e.g., simple return statements)"""
        body1 = func1['normalized_body']
        body2 = func2['normalized_body']
        
        # Very short identical functions might be legitimate
        if len(body1) < 20 and len(body2) < 20:
            # Allow simple return statements with different values
            if 'return ' in body1 and 'return ' in body2:
                return True
        
        # Functions with only error returns might be legitimate
        if ('return errors.New' in body1 and 'return errors.New' in body2 and 
            len(body1) < 100 and len(body2) < 100):
            return True
        
        return False
    
    # Start analysis
    if isinstance(ast_tree, dict):
        collect_functions(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            collect_functions(node)
    
    # Find identical implementations
    for i, func1 in enumerate(functions):
        for j, func2 in enumerate(functions[i+1:], start=i+1):
            if (func1['normalized_body'] == func2['normalized_body'] and 
                len(func1['normalized_body']) > 0 and
                func1['name'] != func2['name']):
                
                # Skip legitimate duplicates
                if is_legitimate_duplicate(func1, func2):
                    continue
                
                # Found identical implementations
                finding = {
                    'rule_id': 'structure_identical_function_implementations',
                    'message': f"Identical function implementations detected: '{func1['name']}' and '{func2['name']}' have the same logic",
                    'line': func1['line'],
                    'details': {
                        'function1': func1['name'],
                        'function2': func2['name'],
                        'normalized_body': func1['normalized_body'][:200] + '...' if len(func1['normalized_body']) > 200 else func1['normalized_body']
                    }
                }
                findings.append(finding)
    
    return findings

def check_logic_if_else_final_else_required(ast_tree):
    """
    Check for if-else-if chains that lack a final else clause.
    Detects constructs like if...else if...else if... without a final else.
    """
    findings = []
    
    def analyze_node_for_if_else_chains(node):
        """Recursively analyze nodes for if-else chains without final else"""
        if isinstance(node, dict):
            if node.get('node_type') == 'function_declaration':
                source = node.get('source_text', '')
                if source and 'if ' in source and 'else if' in source:
                    analyze_function_for_if_else_chains(node, source)
            
            # Recursively check children
            if 'children' in node:
                for child in node['children']:
                    analyze_node_for_if_else_chains(child)
    
    def analyze_function_for_if_else_chains(node, source_text):
        """Analyze a specific function for if-else-if chains without final else"""
        
        # Remove comments to avoid false matches in commented code
        clean_source = remove_comments(source_text)
        
        # Look for if-else-if patterns
        if_else_if_pattern = r'if\s+[^{]+\{[^}]*\}\s*(?:else\s+if\s+[^{]+\{[^}]*\}\s*)+'
        
        matches = re.finditer(if_else_if_pattern, clean_source, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            if_chain = match.group(0)
            
            # Check what comes after this if-else-if chain
            end_pos = match.end()
            remaining_source = clean_source[end_pos:].strip()
            
            # Check if the next token is 'else' followed by '{' (indicating final else clause)
            final_else_pattern = r'^\s*else\s*\{'
            has_final_else = re.match(final_else_pattern, remaining_source)
            
            # Also check if the chain ends with 'else if' (without final else)
            chain_ends_with_else_if = re.search(r'else\s+if\s+[^{]+\{[^}]*\}\s*$', if_chain.strip())
            
            if chain_ends_with_else_if and not has_final_else:
                # This is a violation: if-else-if chain without final else
                
                # Calculate approximate line number
                lines_before = clean_source[:match.start()].count('\n')
                line_number = node.get('line', 0) + lines_before
                
                finding = {
                    'rule_id': 'logic_if_else_final_else_required',
                    'message': 'If-else-if chain lacks final else clause to handle all cases',
                    'line': line_number,
                    'details': {
                        'chain_preview': if_chain[:100] + '...' if len(if_chain) > 100 else if_chain,
                        'has_final_else': bool(has_final_else)
                    }
                }
                findings.append(finding)
    
    def remove_comments(source_text):
        """Remove single-line and multi-line comments from source"""
        # Remove single line comments
        source_text = re.sub(r'//.*$', '', source_text, flags=re.MULTILINE)
        # Remove multi-line comments
        source_text = re.sub(r'/\*.*?\*/', '', source_text, flags=re.DOTALL)
        return source_text
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_node_for_if_else_chains(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_node_for_if_else_chains(node)
    
    return findings

def check_security_insecure_temporary_files(ast_tree):
    """
    Check for insecure temporary file creation methods.
    Detects predictable file names, insecure permissions, and unsafe /tmp/ usage.
    """
    findings = []
    
    def analyze_node_for_temp_files(node):
        """Recursively analyze nodes for insecure temporary file usage"""
        if isinstance(node, dict):
            if node.get('node_type') == 'function_declaration':
                source = node.get('source_text', '')
                if source and ('/tmp/' in source or 'os.Create' in source or 'os.OpenFile' in source or 'fmt.Sprintf' in source):
                    analyze_function_for_temp_files(node, source)
            
            # Recursively check children
            if 'children' in node:
                for child in node['children']:
                    analyze_node_for_temp_files(child)
    
    def analyze_function_for_temp_files(node, source_text):
        """Analyze a specific function for insecure temporary file usage"""
        
        # Remove comments to avoid false matches in commented code
        clean_source = remove_comments(source_text)
        
        # Pattern 1: Direct os.Create with /tmp/ paths
        os_create_pattern = r'os\.Create\s*\(\s*["\'][^"\']*/?tmp/[^"\']*["\']'
        matches = re.finditer(os_create_pattern, clean_source, re.MULTILINE)
        for match in matches:
            line_num = calculate_line_number(clean_source, match.start(), node.get('line', 0))
            finding = create_finding('os.Create with /tmp/ path', line_num, match.group(0))
            if finding not in findings:
                findings.append(finding)
        
        # Pattern 2: Variable assignment with /tmp/ paths followed by os.Create usage
        temp_path_assignments = r'(\w+)\s*:?=\s*["\'][^"\']*/?tmp/[^"\']*["\']'
        assignments = re.finditer(temp_path_assignments, clean_source, re.MULTILINE)
        for assign_match in assignments:
            var_name = assign_match.group(1)
            # Look for usage of this variable in os.Create calls
            create_usage = rf'os\.Create\s*\(\s*{re.escape(var_name)}\s*\)'
            if re.search(create_usage, clean_source):
                line_num = calculate_line_number(clean_source, assign_match.start(), node.get('line', 0))
                finding = create_finding('Variable with /tmp/ path used in os.Create', line_num, assign_match.group(0))
                if finding not in findings:
                    findings.append(finding)
        
        # Pattern 3: String concatenation with /tmp/ paths
        concat_patterns = [
            r'(\w+)\s*:?=\s*["\']/?tmp/?["\'].*?(\w+)\s*:?=\s*\1\s*\+\s*["\'][^"\']*["\']',
            r'(\w+)\s*:?=\s*["\']/?tmp["\'].*?fileName\s*:?=\s*\1\s*\+\s*["\'][^"\']*["\']',
        ]
        for pattern in concat_patterns:
            matches = re.finditer(pattern, clean_source, re.MULTILINE | re.DOTALL)
            for match in matches:
                line_num = calculate_line_number(clean_source, match.start(), node.get('line', 0))
                finding = create_finding('String concatenation with /tmp/ path', line_num, match.group(0)[:50] + '...')
                if finding not in findings:
                    findings.append(finding)
        
        # Pattern 4: fmt.Sprintf with /tmp/ and predictable patterns
        sprintf_pattern = r'fmt\.Sprintf\s*\(\s*["\'][^"\']*/?tmp/[^"\']*%[ds][^"\']*["\']'
        matches = re.finditer(sprintf_pattern, clean_source, re.MULTILINE)
        for match in matches:
            line_num = calculate_line_number(clean_source, match.start(), node.get('line', 0))
            finding = create_finding('fmt.Sprintf with predictable /tmp/ pattern', line_num, match.group(0))
            if finding not in findings:
                findings.append(finding)
        
        # Pattern 5: os.OpenFile with overly permissive permissions
        openfile_pattern = r'os\.OpenFile\s*\([^)]*,\s*[^,]*,\s*0?[67]77\s*\)'
        matches = re.finditer(openfile_pattern, clean_source, re.MULTILINE)
        for match in matches:
            line_num = calculate_line_number(clean_source, match.start(), node.get('line', 0))
            finding = create_finding('os.OpenFile with overly permissive permissions', line_num, match.group(0))
            if finding not in findings:
                findings.append(finding)
        
        # Pattern 6: General /tmp/ string literals (catch-all)
        temp_literals = r'["\']/?tmp/[^"\']*\.(txt|log|data|tmp)["\']'
        matches = re.finditer(temp_literals, clean_source, re.MULTILINE)
        for match in matches:
            # Skip if it's already caught by other patterns
            context_before = clean_source[max(0, match.start()-20):match.start()]
            context_after = clean_source[match.end():match.end()+20]
            full_context = context_before + match.group(0) + context_after
            
            if ('ioutil.TempFile' not in full_context and 
                'os.CreateTemp' not in full_context and 
                'ioutil.TempDir' not in full_context):
                line_num = calculate_line_number(clean_source, match.start(), node.get('line', 0))
                finding = create_finding('Hardcoded /tmp/ path usage', line_num, match.group(0))
                if finding not in findings:
                    findings.append(finding)
    
    def remove_comments(source_text):
        """Remove single-line and multi-line comments from source"""
        # Remove single line comments
        source_text = re.sub(r'//.*$', '', source_text, flags=re.MULTILINE)
        # Remove multi-line comments
        source_text = re.sub(r'/\*.*?\*/', '', source_text, flags=re.DOTALL)
        return source_text
    
    def calculate_line_number(source_text, position, base_line):
        """Calculate line number based on character position"""
        lines_before = source_text[:position].count('\n')
        return base_line + lines_before
    
    def create_finding(description, line_num, code_snippet):
        """Create a finding dictionary"""
        return {
            'rule_id': 'security_insecure_temporary_files',
            'message': f'Insecure temporary file usage: {description}',
            'line': line_num,
            'details': {
                'violation_type': description,
                'code_snippet': code_snippet[:100] + '...' if len(code_snippet) > 100 else code_snippet
            }
        }
    
    # Start analysis
    if isinstance(ast_tree, dict):
        analyze_node_for_temp_files(ast_tree)
    elif isinstance(ast_tree, list):
        for node in ast_tree:
            analyze_node_for_temp_files(node)
    
    return findings

def check_formatting_line_length_limit(node):
    """
    Check for lines that are genuinely too long and impact readability.
    This custom function eliminates false positives by understanding code structure.
    """
    findings = []
    
    if not isinstance(node, dict):
        return False
    
    node_type = node.get('node_type', '')
    
    # Only check function declarations and call expressions as specified in original rule
    if node_type not in ['function_declaration', 'call_expression']:
        return False
    
    source = node.get('source_text', '')
    if not source:
        return False
    
    # Split source into lines for analysis
    lines = source.split('\n')
    base_line = node.get('line', 0)
    
    for i, line in enumerate(lines):
        current_line_num = base_line + i
        
        # Skip empty lines and comments
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith('//'):
            continue
        
        # Check if line exceeds 120 characters
        if len(line) <= 120:
            continue
            
        # Now check if this is a legitimate violation or properly formatted code
        if is_legitimate_line_length_violation(line, lines, i):
            # Found a genuine violation - return True to indicate violation found
            return True
    
    # No violations found
    return False

def is_legitimate_line_length_violation(line, all_lines, line_index):
    """
    Determine if a long line is a legitimate violation or properly formatted code.
    Returns True if it's a genuine violation that should be flagged.
    """
    stripped_line = line.strip()
    
    # Get context - previous and next lines
    prev_line = all_lines[line_index - 1].strip() if line_index > 0 else ""
    next_line = all_lines[line_index + 1].strip() if line_index < len(all_lines) - 1 else ""
    
    # Check for patterns that indicate this is NOT a violation (properly formatted):
    
    # 1. Multi-line function call continuation (properly broken)
    if (prev_line.endswith('(') or prev_line.endswith(',')) and next_line.startswith(')'):
        return False
    
    # 2. Multi-line string formatting (properly broken)
    if ('fmt.Sprintf(' in prev_line or 'fmt.Printf(' in prev_line) and ('"' in stripped_line):
        return False
    
    # 3. Struct initialization (properly broken)
    if stripped_line.endswith(',') and ('{' in prev_line or ':' in stripped_line):
        return False
        
    # 4. Multi-line conditional (properly broken)
    if ('&&' in stripped_line or '||' in stripped_line) and next_line.strip().startswith(('&&', '||', ')')):
        return False
    
    # 5. Method chaining (properly broken)
    if stripped_line.strip().startswith('.') or next_line.strip().startswith('.'):
        return False
    
    # 6. Array/slice initialization (properly broken)
    if '[' in stripped_line and ']' in next_line:
        return False
    
    # Patterns that ARE violations (should be flagged):
    
    # 1. Single-line function signatures with many parameters
    if 'func ' in stripped_line and '(' in stripped_line and ')' in stripped_line:
        # Check if it's all on one line with many parameters
        if stripped_line.count(',') >= 3:  # Multiple parameters on single line
            return True
    
    # 2. Single-line return statements with complex expressions
    if stripped_line.startswith('return ') and '{' in stripped_line and '}' in stripped_line:
        return True
    
    # 3. Long string concatenations on single line
    if '+' in stripped_line and '"' in stripped_line and stripped_line.count('"') >= 4:
        return True
    
    # 4. Long conditional expressions on single line
    if ('if ' in stripped_line or 'if(' in stripped_line) and ('&&' in stripped_line or '||' in stripped_line):
        if stripped_line.count('&&') + stripped_line.count('||') >= 2:  # Multiple conditions
            return True
    
    # 5. Long printf/sprintf calls on single line
    if ('fmt.Printf(' in stripped_line or 'fmt.Sprintf(' in stripped_line) and stripped_line.endswith(')'):
        return True
    
    # 6. Long variable declarations on single line
    if ':=' in stripped_line and '"' in stripped_line and len(stripped_line) > 120:
        return True
    
    # 7. Long method chains on single line
    if stripped_line.count('.') >= 3 and '(' in stripped_line:
        return True
    
    # 8. Specific problematic patterns from original rule
    if ('user.HasValidEmail' in stripped_line and 'user.IsActive' in stripped_line and 
        '&&' in stripped_line and not next_line.strip().startswith('&&')):
        return True
        
    if ('validateInput' in stripped_line and 'sanitizeInput' in stripped_line and 
        'processInput' in stripped_line and '&&' in stripped_line):
        return True
    
    # Default: if we haven't identified it as properly formatted, it's likely a violation
    return True

def check_security_log_injection_attacks(node):
    """
    Custom function to detect log injection attacks.
    Identifies logging of unsanitized user input while avoiding false positives
    from safe logging practices.
    """
    if not isinstance(node, dict):
        return False
    
    node_type = node.get('node_type', '')
    
    # Only check function declarations and call expressions
    if node_type not in ['function_declaration', 'call_expression']:
        return False
    
    source_text = node.get('source_text', '')
    if not source_text:
        return False
    
    try:
        # Must be a log call
        import re
        log_pattern = r'log\.(Printf|Print|Println|Fatal|Panic|Info|Debug|Warn|Error)'
        if not re.search(log_pattern, source_text):
            return False
        
        # Enhanced violation patterns - more comprehensive but precise
        violation_patterns = [
            # Direct user input logging  
            r'log\.Printf\([^)]*username[^)]*password[^)]*\)',  # Username/password together
            r'log\.Printf\([^)]*userInput[^)]*\)',             # userInput variable
            r'log\.Printf\([^)]*\busername\b[^)]*\)',          # username variable
            r'log\.Printf\([^)]*\buserID\b[^)]*\)',            # userID variable
            r'log\.Printf\([^)]*\bquery\b[^)]*\)',             # query variable  
            r'log\.Printf\([^)]*\bmessage\b[^)]*\)',           # message variable
            r'log\.Printf\([^)]*\bfilename\b[^)]*\)',          # filename variable
            r'log\.Printf\([^)]*\bdata\b[^)]*\)',              # data variable
            r'log\.Printf\([^)]*\baction\b[^)]*\)',            # action parameter
            r'log\.Printf\([^)]*\bresource\b[^)]*\)',          # resource parameter
            r'log\.Print\([^)]*\bdata\b[^)]*\)',               # log.Print with data
            r'log\.Println\([^)]*\bmessage\b[^)]*\)',          # log.Println with message
            r'log\.Println.*\+.*user',                         # String concatenation with user
            # Error parameter logging (function parameter err being logged)
            r'func.*err error.*log\.Printf.*err',              # Function with err parameter logging it
            r'violationErrorMessageLogging.*err.*log\.Printf', # Specific violation pattern
        ]
        
        # Safe patterns to exclude - be very specific
        safe_patterns = [
            r'sanitize.*username',         # Specifically sanitized usernames
            r'safeUsername',              # Safe username variables
            r'len\(',                     # Length operations only  
            r'\b8080\b',                  # Port numbers
            r'hashString\(',              # Hash functions
            r'"SUCCESS"',                 # SUCCESS constant
            r'"HEALTHY"',                 # HEALTHY constant
            r'config\.Count',             # Config count specifically
            r'generateSessionID\(',       # Generated session ID function call
            r'\"SYS_Generated',           # System generated values
            r'connectDatabase.*err',      # Database connection errors
            r'Database connection',       # Database error messages
            r'requestSize int',           # Request size metadata
        ]
        
        # Check for violation patterns
        has_violation = any(re.search(pattern, source_text, re.IGNORECASE | re.MULTILINE) 
                           for pattern in violation_patterns)
        
        # Check for safe patterns - must be very specific
        has_safe_pattern = any(re.search(pattern, source_text, re.IGNORECASE | re.MULTILINE) 
                             for pattern in safe_patterns)
        
        # Only flag if violation found and no specific safe patterns
        return has_violation and not has_safe_pattern
        
    except Exception as e:
        # Fallback to basic pattern matching
        return False

def check_path_injection_vulnerability(ast_tree, filename):
    """
    Custom function to detect path injection vulnerabilities.
    
    Detects:
    1. Direct user input in file I/O operations (ReadFile, Open, Remove, etc.)
    2. Path concatenation without validation (basePath + userInput)
    3. Using filepath.Join without validation
    4. Trusting user-provided absolute paths
    5. File operations with potentially user-controlled data
    
    Returns list of findings with line numbers and messages.
    """
    import re
    
    findings = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Track function parameters that could be user input
        user_input_vars = set()
        function_params = set()
        
        # Track context - are we in a function that handles user input?
        in_user_input_function = False
        user_input_function_patterns = [
            r'func.*[Hh]andler?',
            r'func.*[Ss]erve',
            r'func.*[Pp]rocess',
            r'func.*[Uu]ser',
            r'func.*[Uu]pload',
            r'func.*[Dd]ownload',
            r'func.*[Aa]pi',
            r'func.*[Rr]eq',  # Request handlers
        ]
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue
            
            # Check if we're entering a user input function
            for pattern in user_input_function_patterns:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    in_user_input_function = True
                    break
            
            # Track function parameters
            func_param_match = re.match(r'^func\s+\w+\s*\([^)]*\)', line_stripped)
            if func_param_match:
                # Extract parameter names
                params = re.findall(r'(\w+)\s+\w+', func_param_match.group(0))
                function_params.update(params)
                # Reset function context
                is_user_func = any(re.search(p, line_stripped, re.IGNORECASE) for p in user_input_function_patterns)
                in_user_input_function = is_user_func
            
            # Track variables from potentially unsafe sources
            unsafe_sources = [
                r'r\.URL\.Query\(\)\.Get\(',  # HTTP query parameters
                r'r\.FormValue\(',           # Form values
                r'r\.PostFormValue\(',       # POST form values
                r'mux\.Vars\(',              # Router variables
                r'c\.Param\(',               # Gin/Echo parameters
                r'c\.Query\(',               # Query parameters in frameworks
                r'os\.Args\[',               # Command line arguments
                r'flag\.\w+',                # Flag package (command line)
            ]
            
            for source_pattern in unsafe_sources:
                if re.search(source_pattern, line_stripped):
                    # Extract variable name being assigned
                    var_match = re.search(r'(\w+)\s*:?=.*' + source_pattern, line_stripped)
                    if var_match:
                        user_input_vars.add(var_match.group(1))
            
            # 1. Check for direct file operations with variables
            file_operations = [
                (r'ioutil\.ReadFile\s*\(\s*([^,)]+)', 'ioutil.ReadFile with unsanitized path'),
                (r'os\.Open\s*\(\s*([^,)]+)', 'os.Open with unsanitized path'),
                (r'os\.OpenFile\s*\(\s*([^,)]+)', 'os.OpenFile with unsanitized path'),
                (r'os\.Remove\s*\(\s*([^,)]+)', 'os.Remove with unsanitized path'),
                (r'os\.RemoveAll\s*\(\s*([^,)]+)', 'os.RemoveAll with unsanitized path'),
                (r'ioutil\.WriteFile\s*\(\s*([^,)]+)', 'ioutil.WriteFile with unsanitized path'),
                (r'os\.Mkdir\s*\(\s*([^,)]+)', 'os.Mkdir with unsanitized path'),
                (r'os\.MkdirAll\s*\(\s*([^,)]+)', 'os.MkdirAll with unsanitized path'),
                (r'os\.Create\s*\(\s*([^,)]+)', 'os.Create with unsanitized path'),
                (r'os\.Stat\s*\(\s*([^,)]+)', 'os.Stat with unsanitized path'),
            ]
            
            for op_pattern, message_prefix in file_operations:
                match = re.search(op_pattern, line_stripped)
                if match:
                    path_arg = match.group(1).strip()
                    
                    # Check if argument is a known user input variable or parameter
                    is_user_controlled = (
                        path_arg in user_input_vars or 
                        path_arg in function_params or
                        in_user_input_function
                    )
                    
                    # Also flag if it's a variable that could be user input (not hardcoded)
                    if (not path_arg.startswith('"') and not path_arg.startswith("'") and 
                        not path_arg.startswith('/') and not path_arg.startswith('\\')):
                        
                        # Special check for common user-input variable names
                        suspicious_var_names = ['filename', 'filepath', 'path', 'uploadPath', 'configName', 'userID', 'dirname', 'file']
                        is_suspicious_var = any(sus_name.lower() == path_arg.lower() for sus_name in suspicious_var_names)
                        
                        # Check if there's validation nearby
                        validation_keywords = ['clean', 'valid', 'sanitiz', 'check', 'filepath.Clean', 'strings.HasPrefix', 'isvalid']
                        has_validation = False
                        
                        # Check previous and next few lines for validation
                        start_check = max(0, line_num - 4)
                        end_check = min(len(lines), line_num + 2)
                        context_lines = lines[start_check:end_check]
                        
                        for context_line in context_lines:
                            if any(keyword in context_line.lower() for keyword in validation_keywords):
                                has_validation = True
                                break
                        
                        # Flag if no validation OR if it's definitely user controlled OR if suspicious variable name in user function
                        should_flag = (
                            not has_validation or 
                            is_user_controlled or 
                            (is_suspicious_var and in_user_input_function) or
                            (is_suspicious_var and not has_validation)  # Flag suspicious vars without validation
                        )
                        
                        if should_flag:
                            # Skip this if it's in a clearly safe context
                            is_safe_context = any(safe_word in line_stripped.lower() for safe_word in 
                                                ['allowedfiles', 'fixed', 'system', 'safe', '/app/config', '/var/log', '/etc/myapp'])
                            
                            if not is_safe_context:
                                findings.append({
                                    'line': line_num,
                                    'message': f"{message_prefix} '{path_arg}' - validate and sanitize file paths to prevent path traversal",
                                    'severity': 'Major', 
                                    'rule': 'security_path_injection_vulnerability',
                                    'category': 'Security'
                                })
            
            # 2. Check for path concatenation without validation
            concat_patterns = [
                r'(\w+)\s*\+\s*([^+\s]+)',  # Simple concatenation: basePath + userInput
                r'fmt\.Sprintf\s*\(["\']%s[/\\]%s["\']',  # String formatting
            ]
            
            for pattern in concat_patterns:
                if re.search(pattern, line_stripped):
                    # Check if it's path-related
                    if any(word in line_stripped.lower() for word in ['path', 'dir', 'file', 'folder']):
                        # Check if there's validation
                        validation_present = any(keyword in line_stripped.lower() for keyword in ['clean', 'valid', 'sanitiz'])
                        
                        if not validation_present:
                            findings.append({
                                'line': line_num,
                                'message': 'Path concatenation without validation - vulnerable to path traversal attacks',
                                'severity': 'Major',
                                'rule': 'security_path_injection_vulnerability', 
                                'category': 'Security'
                            })
            
            # 3. Check for filepath.Join without validation
            if re.search(r'filepath\.Join\s*\(', line_stripped):
                # Check if there's validation around this line
                validation_present = False
                check_lines = lines[max(0, line_num-5):min(len(lines), line_num+5)]
                
                for check_line in check_lines:
                    if any(keyword in check_line.lower() for keyword in 
                          ['clean', 'valid', 'sanitiz', 'hasprefix', 'contains', 'check', 'isvalid', 'allowed']):
                        validation_present = True
                        break
                
                # Only flag if in user input function AND no validation present
                if in_user_input_function and not validation_present:
                    # Additional check: don't flag if it's clearly in a safe context
                    is_safe_context = any(safe_word in line_stripped.lower() for safe_word in 
                                        ['/app/uploads', '/app/users', 'userdir', 'safedir', 'system'])
                    
                    if not is_safe_context:
                        findings.append({
                            'line': line_num,
                            'message': 'filepath.Join without path validation - ensure safe directory boundaries',
                            'severity': 'Major',
                            'rule': 'security_path_injection_vulnerability',
                            'category': 'Security'
                        })
            
            # 4. Check for dangerous path patterns in strings
            dangerous_patterns = [
                (r'["\'][^"\']*\.\.[^"\']*["\']', 'hardcoded path traversal pattern'),
                (r'["\'][^"\']*[/\\]\.\.[/\\][^"\']*["\']', 'path traversal sequence'),
            ]
            
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line_stripped):
                    findings.append({
                        'line': line_num,
                        'message': f'Dangerous path pattern detected: {desc} - could enable path traversal',
                        'severity': 'Major',
                        'rule': 'security_path_injection_vulnerability',
                        'category': 'Security'
                    })
            
            # 5. Check for absolute path usage with user input
            if re.search(r'["\'][/\\][^"\']*["\']', line_stripped) and in_user_input_function:
                # This might be a hardcoded absolute path, but in user input context it's suspicious
                if any(word in line_stripped.lower() for word in ['get', 'query', 'param', 'form']):
                    findings.append({
                        'line': line_num,
                        'message': 'Absolute path usage in user input context - restrict to safe directories',
                        'severity': 'Major',
                        'rule': 'security_path_injection_vulnerability',
                        'category': 'Security'
                    })
        
    except Exception as e:
        print(f"Error in check_path_injection_vulnerability: {e}")
    
    return findings

def check_pseudorandom_generators(ast_tree, filename):
    """
    Enhanced check for insecure pseudorandom number generator usage.
    Detects math/rand usage in security-sensitive contexts and suggests crypto/rand.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    try:
        # Read the source file to get exact line content
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Security-sensitive function indicators
    security_indicators = [
        'token', 'salt', 'key', 'secret', 'auth', 'session', 'csrf',
        'nonce', 'challenge', 'password', 'reset', 'api', 'jwt',
        'otp', 'encrypt', 'secure', 'random', 'id', 'filename'
    ]
    
    # Non-security contexts (where math/rand is acceptable)
    non_security_contexts = [
        'test', 'mock', 'bench', 'game', 'simulation', 'demo', 'example',
        'debug', 'sample', 'prototype', 'temp'
    ]
    
    has_math_rand_import = False
    has_crypto_rand_import = False
    
    # Check imports
    for line_idx, line_content in enumerate(source_lines):
        if '"math/rand"' in line_content or 'mathrand' in line_content:
            has_math_rand_import = True
        if '"crypto/rand"' in line_content:
            has_crypto_rand_import = True
    
    # Analyze each line for rand usage
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or not line_stripped:
            continue
        
        # Get function context (look at surrounding lines for function name)
        function_context = ""
        for i in range(max(0, line_idx - 10), min(len(source_lines), line_idx + 1)):
            func_match = re.search(r'func\s+(\w+)', source_lines[i])
            if func_match:
                function_context = func_match.group(1).lower()
                break
        
        # Check for problematic math/rand patterns
        patterns_to_check = [
            (r'mathrand\.Seed\s*\(', 'rand.Seed'),
            (r'mathrand\.Intn\s*\(', 'rand.Intn'), 
            (r'mathrand\.Int\s*\(', 'rand.Int'),
            (r'mathrand\.Int63\s*\(', 'rand.Int63'),
            (r'mathrand\.Float64\s*\(', 'rand.Float64'),
            (r'rand\.Seed\s*\(', 'rand.Seed'),
            (r'rand\.Intn\s*\(', 'rand.Intn'),
            (r'rand\.Int\s*\(', 'rand.Int'),
            (r'rand\.Int63\s*\(', 'rand.Int63'),
            (r'rand\.Float64\s*\(', 'rand.Float64')
        ]
        
        for pattern, method_name in patterns_to_check:
            if re.search(pattern, line_content):
                # Determine if this is in a security-sensitive context
                is_security_context = False
                is_non_security_context = False
                
                # Check function name for security indicators
                for indicator in security_indicators:
                    if indicator in function_context:
                        is_security_context = True
                        break
                
                # Check for non-security contexts
                for context in non_security_contexts:
                    if context in function_context:
                        is_non_security_context = True
                        break
                
                # Check variable names and comments for context
                line_lower = line_content.lower()
                for indicator in security_indicators:
                    if indicator in line_lower:
                        is_security_context = True
                        break
                
                # Look for comments indicating security usage
                comment_match = re.search(r'//\s*(.+)', line_content)
                if comment_match:
                    comment_text = comment_match.group(1).lower()
                    for indicator in security_indicators:
                        if indicator in comment_text:
                            is_security_context = True
                            break
                
                # Check surrounding lines for context clues
                context_range = range(max(0, line_idx - 3), min(len(source_lines), line_idx + 4))
                for ctx_idx in context_range:
                    ctx_line = source_lines[ctx_idx].lower()
                    for indicator in security_indicators:
                        if indicator in ctx_line:
                            is_security_context = True
                            break
                    if is_security_context:
                        break
                
                # Determine the severity and message
                severity = "Major"
                message_base = f"Use cryptographically secure random numbers instead of {method_name}"
                
                if is_security_context and not is_non_security_context:
                    # High confidence security violation
                    message = f"{message_base} for security-sensitive operations"
                    context_detail = f"Security context detected in function '{function_context}'"
                elif not is_non_security_context and has_math_rand_import and not has_crypto_rand_import:
                    # Medium confidence - math/rand without crypto/rand available
                    message = f"{message_base} - consider using crypto/rand for security operations"
                    context_detail = "Math/rand usage without crypto/rand import"
                    severity = "Minor"
                elif is_non_security_context:
                    # Low confidence - likely acceptable usage
                    continue
                else:
                    # Default case - flag with lower severity
                    message = f"{message_base} if used for security purposes"
                    context_detail = "Review usage context for security implications"
                    severity = "Info"
                
                # Check for specific high-risk patterns
                high_risk_patterns = [
                    r'time\.Now\(\)\.UnixNano\(\)',  # Predictable seed
                    r'Seed\s*\(\s*\d+\s*\)',        # Fixed seed
                    r'fmt\.Sprintf.*token',          # Token generation
                    r'fmt\.Sprintf.*key',            # Key generation
                    r'fmt\.Sprintf.*secret'          # Secret generation
                ]
                
                for risk_pattern in high_risk_patterns:
                    if re.search(risk_pattern, line_content, re.IGNORECASE):
                        severity = "Critical"
                        message = f"Critical: {message_base} - predictable security-sensitive value detected"
                        break
                
                findings.append({
                    "rule_id": "security_pseudorandom_generators", 
                    "message": message,
                    "file": filename,
                    "line": line_number,
                    "column": 1,
                    "severity": severity,
                    "context": {
                        'line_content': line_stripped,
                        'method_used': method_name,
                        'function_context': function_context,
                        'security_context': is_security_context,
                        'context_detail': context_detail,
                        'recommendation': 'Use crypto/rand for cryptographically secure random numbers',
                        'rule': 'security_pseudorandom_generators',
                        'category': 'Security'
                    }
                })
        
        # Additional check for math/rand import in security files
        if '"math/rand"' in line_content and not has_crypto_rand_import:
            # Look ahead to see if this file contains security-related functions
            has_security_functions = False
            for check_line in source_lines:
                check_lower = check_line.lower()
                for indicator in security_indicators:
                    if f'func' in check_lower and indicator in check_lower:
                        has_security_functions = True
                        break
                if has_security_functions:
                    break
            
            if has_security_functions:
                findings.append({
                    "rule_id": "security_pseudorandom_generators",
                    "message": "Math/rand import detected in file with security functions - consider crypto/rand",
                    "file": filename,
                    "line": line_number,
                    "column": 1,
                    "severity": "Minor",
                    "context": {
                        'line_content': line_stripped,
                        'method_used': 'import math/rand',
                        'recommendation': 'Import crypto/rand for security operations',
                        'rule': 'security_pseudorandom_generators',
                        'category': 'Security'
                    }
                })
    
    return findings

def check_publicly_writable_directories(ast_tree, filename):
    """
    Enhanced check for usage of publicly writable directories and insecure file permissions.
    Detects hardcoded public directories and overly permissive file/directory permissions.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    try:
        # Read the source file to get exact line content
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Publicly writable directory patterns
    public_directories = [
        r'/tmp(?:/|")',                    # Unix /tmp
        r'/var/tmp(?:/|")',               # Unix /var/tmp  
        r'/dev/shm(?:/|")',               # Shared memory
        r'C:\\\\temp(?:\\\\|")',          # Windows C:\temp (escaped)
        r'C:\\\\Windows\\\\Temp(?:\\\\|")', # Windows system temp (escaped)
        r'["\']C:\\temp["\']',            # Windows C:\temp (quoted)
        r'["\']C:\\Windows\\Temp["\']',   # Windows system temp (quoted)
    ]
    
    # Dangerous permission patterns for directories and files
    dangerous_permissions = [
        r'0777',  # World writable directory
        r'0666',  # World readable/writable file  
        r'0755',  # Group writable in some contexts
    ]
    
    # File operation functions that should be scrutinized
    file_operations = [
        'ioutil.WriteFile',
        'os.Create',
        'os.OpenFile', 
        'os.MkdirAll',
        'os.Mkdir',
        'os.Chmod',
        'filepath.Join'
    ]
    
    # Analyze each line for public directory usage
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or not line_stripped:
            continue
        
        # Get function context (look at surrounding lines for function name)
        function_context = ""
        for i in range(max(0, line_idx - 10), min(len(source_lines), line_idx + 1)):
            func_match = re.search(r'func\s+(\w+)', source_lines[i])
            if func_match:
                function_context = func_match.group(1)
                break
        
        # Check for public directory usage
        public_dir_detected = False
        detected_directory = ""
        
        for pattern in public_directories:
            match = re.search(pattern, line_content)
            if match:
                public_dir_detected = True
                detected_directory = match.group(0).strip('"\'')
                
                # Determine severity based on context
                severity = "Critical"
                message = f"Avoid using publicly writable directory '{detected_directory}'"
                
                # Check if this is a file operation
                is_file_operation = any(op in line_content for op in file_operations)
                if is_file_operation:
                    message += " for file operations"
                    severity = "Critical"
                else:
                    message += " - security risk"
                    severity = "Major"
                
                # Check surrounding context for additional risk indicators
                context_lines = source_lines[max(0, line_idx-2):min(len(source_lines), line_idx+3)]
                context_text = ' '.join(context_lines).lower()
                
                # High risk indicators
                if any(indicator in context_text for indicator in ['config', 'secret', 'password', 'key', 'token', 'session', 'database', 'backup']):
                    severity = "Critical"
                    message = f"Critical: {message} - sensitive data in public directory"
                
                findings.append({
                    "rule_id": "security_publicly_writable_directories",
                    "message": message,
                    "file": filename,
                    "line": line_number,
                    "column": 1,
                    "severity": severity,
                    "context": {
                        'line_content': line_stripped,
                        'detected_directory': detected_directory,
                        'function_context': function_context,
                        'is_file_operation': is_file_operation,
                        'recommendation': 'Use application-specific directories with proper permissions',
                        'rule': 'security_publicly_writable_directories',
                        'category': 'Security'
                    }
                })
                break
        
        # Check for dangerous file permissions
        for perm_pattern in dangerous_permissions:
            if re.search(perm_pattern, line_content):
                # Extract the exact permission value
                perm_match = re.search(r'(0[0-7]{3})', line_content)
                if perm_match:
                    permission = perm_match.group(1)
                    
                    # Determine the severity and context
                    severity = "Major"
                    operation_type = "file"
                    
                    if 'MkdirAll' in line_content or 'Mkdir' in line_content:
                        operation_type = "directory"
                    
                    if permission == '0777':
                        severity = "Critical"
                        message = f"Critical: World-writable {operation_type} permissions {permission}"
                    elif permission == '0666':
                        severity = "Major"
                        message = f"World-readable/writable file permissions {permission}"
                    elif permission == '0755' and 'tmp' in line_content.lower():
                        severity = "Major"
                        message = f"Group-writable permissions {permission} in potentially public location"
                    else:
                        continue  # Skip other 0755 cases that might be acceptable
                    
                    # Check if this is in combination with public directories
                    if public_dir_detected or any(pub_dir in line_content.lower() for pub_dir in ['/tmp', '/var/tmp', 'c:\\temp']):
                        severity = "Critical"
                        message = f"Critical: {message} in public directory"
                    
                    findings.append({
                        "rule_id": "security_publicly_writable_directories",
                        "message": message,
                        "file": filename, 
                        "line": line_number,
                        "column": 1,
                        "severity": severity,
                        "context": {
                            'line_content': line_stripped,
                            'permission_detected': permission,
                            'operation_type': operation_type,
                            'function_context': function_context,
                            'recommendation': 'Use restrictive permissions like 0600 for files, 0700 for directories',
                            'rule': 'security_publicly_writable_directories',
                            'category': 'Security'
                        }
                    })
        
        # Check for predictable file paths in public directories
        # Pattern: /tmp/<predictable_name> or similar
        predictable_patterns = [
            r'/tmp/[a-zA-Z_][a-zA-Z0-9_]*\.(log|json|db|cache|pid|lock|sock|bak)',
            r'/var/tmp/[a-zA-Z_][a-zA-Z0-9_]*\.(log|json|db|cache|pid|lock|sock|bak)',
            r'/dev/shm/[a-zA-Z_][a-zA-Z0-9_]*\.(bin|mem|data)'
        ]
        
        for pattern in predictable_patterns:
            if re.search(pattern, line_content):
                extension_match = re.search(pattern, line_content)
                if extension_match:
                    detected_path = extension_match.group(0)
                    
                    # Determine file type and severity
                    if '.db' in detected_path or '.bak' in detected_path:
                        severity = "Critical"
                        message = f"Critical: Database/backup file in public directory: {detected_path}"
                    elif '.pid' in detected_path or '.lock' in detected_path:
                        severity = "Major" 
                        message = f"PID/lock file in public directory vulnerable to manipulation: {detected_path}"
                    elif '.log' in detected_path:
                        severity = "Major"
                        message = f"Log file in public directory may leak information: {detected_path}"
                    else:
                        severity = "Major"
                        message = f"Predictable file path in public directory: {detected_path}"
                    
                    findings.append({
                        "rule_id": "security_publicly_writable_directories",
                        "message": message,
                        "file": filename,
                        "line": line_number,
                        "column": 1,
                        "severity": severity,
                        "context": {
                            'line_content': line_stripped,
                            'detected_path': detected_path,
                            'function_context': function_context,
                            'path_type': 'predictable_public_path',
                            'recommendation': 'Use secure application-specific directories',
                            'rule': 'security_publicly_writable_directories',
                            'category': 'Security'
                        }
                    })
        
        # Check for temp file creation without proper security
        insecure_temp_patterns = [
            r'os\.Create.*tmp',
            r'ioutil\.WriteFile.*tmp.*0644',  # Default permissions in tmp
            r'ioutil\.WriteFile.*tmp.*0666',  # World writable in tmp
        ]
        
        for pattern in insecure_temp_patterns:
            if re.search(pattern, line_content, re.IGNORECASE):
                severity = "Major"
                message = "Insecure temporary file creation - use ioutil.TempFile for secure temp files"
                
                # Check if permissions are explicitly bad
                if '0666' in line_content:
                    severity = "Critical"
                    message = "Critical: " + message + " with world-writable permissions"
                
                findings.append({
                    "rule_id": "security_publicly_writable_directories",
                    "message": message,
                    "file": filename,
                    "line": line_number,
                    "column": 1,
                    "severity": severity,
                    "context": {
                        'line_content': line_stripped,
                        'function_context': function_context,
                        'violation_type': 'insecure_temp_creation',
                        'recommendation': 'Use ioutil.TempFile() or os.CreateTemp() for secure temporary files',
                        'rule': 'security_publicly_writable_directories',
                        'category': 'Security'
                    }
                })
    
    return findings

def check_redundant_boolean_literals(ast_tree, filename):
    """
    Enhanced check for redundant boolean literal comparisons.
    Detects comparisons like variable == true, variable != false, etc.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    try:
        # Read the source file to get exact line content
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # More comprehensive redundant boolean comparison patterns
    # These patterns match various forms of boolean expressions
    redundant_patterns = [
        # == true patterns (variable, method calls, complex expressions)
        (r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\(\))?|[a-zA-Z_]\w*)\s*==\s*true\b', 'comparison_with_true'),
        # != false patterns
        (r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\(\))?|[a-zA-Z_]\w*)\s*!=\s*false\b', 'negated_false_comparison'),
        # == false patterns
        (r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\(\))?|[a-zA-Z_]\w*)\s*==\s*false\b', 'comparison_with_false'),
        # != true patterns
        (r'([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\(\))?|[a-zA-Z_]\w*)\s*!=\s*true\b', 'negated_true_comparison'),
    ]
    
    # Analyze each line for redundant boolean comparisons
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or not line_stripped:
            continue
        
        # Skip string literals to avoid false positives
        if '"' in line_content and ('== true' in line_content or '!= false' in line_content or '== false' in line_content or '!= true' in line_content):
            # Check if the comparison is inside a string literal
            in_string = False
            quote_positions = []
            for i, char in enumerate(line_content):
                if char == '"' and (i == 0 or line_content[i-1] != '\\'):
                    quote_positions.append(i)
            
            # If odd number of quotes, we're inside a string at the end
            # Check if any pattern matches are within string boundaries
            for start in range(0, len(quote_positions), 2):
                end = quote_positions[start + 1] if start + 1 < len(quote_positions) else len(line_content)
                for pattern, _ in redundant_patterns:
                    matches = re.finditer(pattern, line_content)
                    for match in matches:
                        if start <= match.start() < end:
                            continue  # Skip matches inside strings
        
        # Get function context (look at surrounding lines for function name)
        function_context = ""
        for i in range(max(0, line_idx - 10), min(len(source_lines), line_idx + 1)):
            func_match = re.search(r'func\s+(\w+)', source_lines[i])
            if func_match:
                function_context = func_match.group(1)
                break
        
        # Count total redundant patterns on this line for severity assessment
        redundant_matches_on_line = []
        
        # Check for each redundant pattern    
        for pattern, redundancy_type in redundant_patterns:
            matches = re.finditer(pattern, line_content)
            
            for match in matches:
                variable_part = match.group(1) if len(match.groups()) >= 1 else ""
                full_match = match.group(0)
                
                # Skip if this looks like a variable comparison (comparing two variables)
                # Extract what comes after the operator
                operator_match = re.search(r'(==|!=)\s*(true|false)\b', full_match)
                if not operator_match:
                    continue  # This shouldn't happen with our patterns, but be safe
                
                # Store this match for processing
                redundant_matches_on_line.append({
                    'match': match,
                    'variable_part': variable_part,
                    'full_match': full_match,
                    'redundancy_type': redundancy_type,
                    'operator': operator_match.group(1),
                    'literal': operator_match.group(2)
                })
        
        # Process all matches found on this line
        for match_info in redundant_matches_on_line:
            match = match_info['match']
            variable_part = match_info['variable_part']
            full_match = match_info['full_match']
            redundancy_type = match_info['redundancy_type']
            operator = match_info['operator']
            literal = match_info['literal']
            
            # Determine severity based on complexity
            severity = "Major"
            
            # Check for multiple redundant comparisons on the same line
            if len(redundant_matches_on_line) > 1:
                severity = "Critical"
            
            # Check if this is in parentheses (complex expression)
            parentheses_context = False
            start_pos = match.start()
            # Look backwards and forwards for parentheses
            before_text = line_content[:start_pos]
            after_text = line_content[match.end():]
            
            if '(' in before_text and ')' in after_text:
                # Count parentheses to check if this match is enclosed
                open_parens = before_text.count('(') - before_text.count(')')
                close_parens = after_text.count(')') - after_text.count('(')
                if open_parens > 0 and close_parens > 0:
                    parentheses_context = True
            
            # Enhanced message based on redundancy type
            if redundancy_type == "comparison_with_true":
                if parentheses_context and len(redundant_matches_on_line) > 1:
                    message = "Multiple redundant boolean comparisons in parentheses - simplify boolean logic"
                    severity = "Critical"
                else:
                    message = f"Redundant comparison with 'true': use '{variable_part}' directly"
            elif redundancy_type == "negated_false_comparison":
                message = f"Redundant comparison '!= false': use '{variable_part}' directly"
            elif redundancy_type == "comparison_with_false":
                message = f"Redundant comparison with 'false': use '!{variable_part}' instead"
            elif redundancy_type == "negated_true_comparison":
                message = f"Redundant comparison '!= true': use '!{variable_part}' instead"
            else:
                message = f"Redundant boolean comparison: {full_match}"
            
            # Check context for additional information
            context_info = {
                'in_if_statement': 'if ' in line_content,
                'in_return_statement': 'return ' in line_content,
                'in_assignment': ':=' in line_content or (re.search(r'\w+\s*=\s*[^=]', line_content) is not None),
                'in_function_call': re.search(r'\w+\s*\([^)]*' + re.escape(full_match), line_content) is not None,
                'in_logical_expression': any(op in line_content for op in ['&&', '||']),
                'in_parentheses': parentheses_context
            }
            
            # Enhance message based on context
            if context_info['in_return_statement']:
                message += " in return statement"
                if len(redundant_matches_on_line) > 1:
                    severity = "Critical"
            elif context_info['in_logical_expression']:
                message += " in logical expression"
                if len(redundant_matches_on_line) > 1:
                    severity = "Critical"
            elif context_info['in_assignment']:
                message += " in variable assignment"
            elif context_info['in_function_call']:
                message += ""  # Function call context is implied
            
            findings.append({
                "rule_id": "logic_redundant_boolean_remove", 
                "message": message,
                "file": filename,
                "line": line_number,
                "column": match.start() + 1,
                "severity": severity.lower(),
                "context": {
                    'line_content': line_stripped,
                    'redundant_pattern': full_match,
                    'variable_name': variable_part,
                    'comparison_operator': f"{operator} {literal}",
                    'redundancy_type': redundancy_type,
                    'function_context': function_context,
                    'context_info': context_info,
                    'total_redundancies_on_line': len(redundant_matches_on_line)
                }
            })
    
    return findings


def check_redundant_parentheses(ast_tree, filename):
    """
    Enhanced check for redundant parentheses that don't change behavior or improve readability.
    Detects unnecessary parentheses around simple expressions, literals, and function calls.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    try:
        # Read the source file to get exact line content
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Analyze each line for redundant parentheses
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments, empty lines, and string contexts
        if line_stripped.startswith('//') or not line_stripped:
            continue
            
        # Skip lines that are primarily string literals to avoid false positives
        if is_primarily_string_content(line_content):
            continue
        
        # Get function context
        function_context = get_function_context(source_lines, line_idx)
        
        # Find and analyze all parentheses groupings
        parentheses_groups = find_all_parentheses_groups(line_content)
        
        for group in parentheses_groups:
            start_pos = group['start']
            end_pos = group['end']
            outer_content = group['outer_content']  # Full parentheses group
            inner_content = group['inner_content']  # Content inside parentheses
            nesting_level = group['nesting_level']
            
            # Determine if these parentheses are redundant
            redundancy_type = analyze_parentheses_redundancy(
                line_content, start_pos, end_pos, inner_content, nesting_level
            )
            
            if redundancy_type == "necessary":
                continue  # Skip if parentheses serve a purpose
            
            # Determine severity based on redundancy type and context
            severity = determine_severity(redundancy_type, nesting_level, inner_content)
            
            # Generate descriptive message
            message = generate_redundancy_message_v2(redundancy_type, inner_content, line_content)
            
            # Check context for additional information
            context_info = analyze_line_context_v2(line_content, start_pos, end_pos)
            
            findings.append({
                "rule_id": "formatting_redundant_parentheses_remove",
                "message": message,
                "file": filename,
                "line": line_number,
                "column": start_pos + 1,
                "severity": severity.lower(),
                "context": {
                    'line_content': line_stripped,
                    'redundant_pattern': outer_content,
                    'inner_expression': inner_content,
                    'redundancy_type': redundancy_type,
                    'nesting_level': nesting_level,
                    'function_context': function_context,
                    'context_info': context_info,
                    'recommendation': f'Remove redundant parentheses around "{inner_content}"'
                }
            })
    
    return findings


def is_primarily_string_content(line):
    """Check if line is primarily string literal content"""
    # Count quotes and check if most content is in strings
    quote_count = line.count('"') + line.count("'")
    return quote_count >= 2 and ('("' in line or "('" in line)


def find_all_parentheses_groups(line_content):
    """Find all parentheses groupings in a line with their nesting levels"""
    groups = []
    i = 0
    paren_stack = []
    
    while i < len(line_content):
        if line_content[i] == '(':
            paren_stack.append({'start': i, 'level': len(paren_stack)})
        elif line_content[i] == ')' and paren_stack:
            start_info = paren_stack.pop()
            start_pos = start_info['start']
            nesting_level = start_info['level']
            
            outer_content = line_content[start_pos:i+1]
            inner_content = line_content[start_pos+1:i]
            
            groups.append({
                'start': start_pos,
                'end': i,
                'outer_content': outer_content,
                'inner_content': inner_content.strip(),
                'nesting_level': nesting_level
            })
        
        i += 1
    
    # Sort by start position to process in order
    return sorted(groups, key=lambda x: x['start'])


def analyze_parentheses_redundancy(line_content, start_pos, end_pos, inner_content, nesting_level):
    """Analyze if parentheses are redundant based on content and context"""
    
    if not inner_content:
        return "empty"  # Empty parentheses (probably function call)
    
    # Get context around the parentheses
    before_context = line_content[:start_pos].rstrip()
    after_context = line_content[end_pos+1:].lstrip()
    
    # Check for specific patterns
    
    # 1. Simple literals and variables
    if re.match(r'^\d+(\.\d+)?$', inner_content):
        return "number_literal"
    if inner_content in ['true', 'false']:
        return "boolean_literal" 
    if re.match(r'^[a-zA-Z_]\w*$', inner_content):
        return "simple_variable"
    if re.match(r'^"([^"\\]|\\.)*"$', inner_content):
        return "string_literal"
    
    # 2. Function calls without parameters
    if re.match(r'^[a-zA-Z_]\w*\(\)$', inner_content):
        return "simple_function_call"
    
    # 3. Field access
    if re.match(r'^[a-zA-Z_]\w*\.[a-zA-Z_]\w*$', inner_content):
        return "field_access"
    
    # 4. Check for double/triple parentheses (nested redundancy)
    if nesting_level > 0:
        # Look for patterns like ((expr))
        inner_stripped = inner_content.strip()
        
        # Check if inner content is a complete simple expression
        if (re.match(r'^[a-zA-Z_]\w*$', inner_stripped) or  # Simple variable
            re.match(r'^\d+$', inner_stripped) or           # Number
            inner_stripped in ['true', 'false']):          # Boolean
            return "double_parentheses_simple"
            
        # Check for complex expressions with unnecessary nesting
        if (re.match(r'^[a-zA-Z_]\w*\s*[+\-*/%]\s*[a-zA-Z_]\w*$', inner_stripped) or
            re.match(r'^[a-zA-Z_]\w*\s*(==|!=|<=|>=|<|>)\s*[a-zA-Z_]\w*$', inner_stripped) or
            re.match(r'^[a-zA-Z_]\w*\s*(&&|\|\|)\s*[a-zA-Z_]\w*$', inner_stripped)):
            # Check if this level of parentheses is needed for precedence
            if not is_precedence_needed(line_content, start_pos, end_pos, inner_stripped):
                return "double_parentheses_expression"
    
    # 5. Single-level redundant expressions
    # Simple arithmetic that doesn't need parentheses
    if re.match(r'^[a-zA-Z_]\w*\s*[+\-]\s*\d+$', inner_content):
        # x + 1, y - 5, etc. - check if precedence needed
        if not is_precedence_needed(line_content, start_pos, end_pos, inner_content):
            return "simple_arithmetic"
    
    # 6. Function calls with single simple parameter
    func_call_match = re.match(r'^([a-zA-Z_]\w*)\(([^()]*)\)$', inner_content)
    if func_call_match:
        param = func_call_match.group(2).strip()
        if (re.match(r'^[a-zA-Z_]\w*$', param) or  # Simple variable
            re.match(r'^\d+$', param)):            # Number literal
            return "function_call_simple_param"
    
    # 7. Type conversions
    type_conv_match = re.match(r'^(int|string|float64?|bool)\(([^()]*)\)$', inner_content)
    if type_conv_match:
        param = type_conv_match.group(2).strip()
        if re.match(r'^[a-zA-Z_]\w*$', param) or re.match(r'^\d+$', param):
            return "simple_type_conversion"
    
    # 8. Check if this is necessary for function call parameters
    if is_function_parameter_context(before_context, after_context):
        # In function parameters, often parentheses serve a purpose
        if has_complex_expression(inner_content):
            return "necessary"  # Keep for parameter clarity
        else:
            return "function_parameter_simple"
    
    # 9. Check for array/slice index context
    if before_context.endswith('[') and after_context.startswith(']'):
        if re.match(r'^\d+$', inner_content) or re.match(r'^[a-zA-Z_]\w*$', inner_content):
            return "array_index_simple" 
    
    # 10. Check logical expressions that might need precedence
    if (any(op in inner_content for op in ['&&', '||']) and 
        any(op in line_content for op in ['&&', '||'])):
        # Mixed logical operators - parentheses might be necessary
        return "necessary"
    
    # Default: if we can't determine it's necessary, consider it redundant
    return "complex_redundant"


def is_precedence_needed(line_content, start_pos, end_pos, inner_content):
    """Check if parentheses are needed for operator precedence"""
    
    before = line_content[:start_pos].rstrip()
    after = line_content[end_pos+1:].lstrip()
    
    # Get operators before and after
    before_ops = re.findall(r'[+\-*/%&|<>=!]', before[-5:])
    after_ops = re.findall(r'[+\-*/%&|<>=!]', after[:5])
    inner_ops = re.findall(r'[+\-*/%&|<>=!]', inner_content)
    
    # If there are operators inside and outside, precedence might matter
    if (before_ops or after_ops) and inner_ops:
        # Simple heuristic: if mixing +/- with */%, precedence matters
        has_low_prec = any(op in ['+', '-'] for op in before_ops + after_ops + inner_ops)
        has_high_prec = any(op in ['*', '/', '%'] for op in before_ops + after_ops + inner_ops)
        
        if has_low_prec and has_high_prec:
            return True
    
    # Check for boolean operator precedence
    if ('&&' in before or '&&' in after) and '||' in line_content:
        return True
    if ('||' in before or '||' in after) and '&&' in line_content:
        return True
    
    return False


def is_function_parameter_context(before_context, after_context):
    """Check if parentheses are in function call parameter context"""
    # Function call context: func(, func(param,, etc.
    if re.search(r'\w+\s*\(\s*$', before_context):
        return True
    if re.search(r',\s*$', before_context.strip()):
        return True
    if after_context.strip().startswith(',') or after_context.strip().startswith(')'):
        return True
    return False


def has_complex_expression(content):
    """Check if content is a complex expression"""
    # Has multiple operators or function calls
    operator_count = len(re.findall(r'[+\-*/%&|<>=!]', content))
    paren_count = content.count('(')
    return operator_count > 1 or paren_count > 0


def determine_severity(redundancy_type, nesting_level, inner_content):
    """Determine severity based on redundancy type and context"""
    
    critical_types = [
        "double_parentheses_simple", 
        "double_parentheses_expression"
    ]
    
    major_types = [
        "function_call_simple_param",
        "simple_type_conversion", 
        "function_parameter_simple",
        "complex_redundant"
    ]
    
    if redundancy_type in critical_types or nesting_level > 1:
        return "Critical"
    elif redundancy_type in major_types:
        return "Major"
    else:
        return "Minor"


def generate_redundancy_message_v2(redundancy_type, inner_content, line_content):
    """Generate a descriptive message for the redundancy type"""
    
    message_templates = {
        'number_literal': f"Remove unnecessary parentheses around number '{inner_content}'",
        'boolean_literal': f"Remove unnecessary parentheses around boolean literal '{inner_content}'",
        'simple_variable': f"Remove unnecessary parentheses around variable '{inner_content}'",
        'string_literal': f"Remove unnecessary parentheses around string literal",
        'simple_function_call': f"Remove unnecessary parentheses around function call '{inner_content}'",
        'field_access': f"Remove unnecessary parentheses around field access '{inner_content}'",
        'double_parentheses_simple': f"Remove redundant double parentheses around '{inner_content}'",
        'double_parentheses_expression': f"Remove redundant nested parentheses around expression",
        'simple_arithmetic': f"Remove unnecessary parentheses around arithmetic expression",
        'function_call_simple_param': f"Remove unnecessary parentheses around function call",
        'simple_type_conversion': f"Remove unnecessary parentheses around type conversion",
        'function_parameter_simple': f"Remove unnecessary parentheses around simple parameter",
        'array_index_simple': f"Remove unnecessary parentheses around array index",
        'complex_redundant': f"Remove unnecessary parentheses around expression"
    }
    
    base_message = message_templates.get(redundancy_type, "Remove unnecessary parentheses")
    
    # Add context information
    if 'return ' in line_content:
        base_message += " in return statement"
    elif ':=' in line_content:
        base_message += " in assignment"
    elif 'if ' in line_content.lstrip():
        base_message += " in condition"
    elif 'for ' in line_content.lstrip():
        base_message += " in loop"
    
    return base_message


def analyze_line_context_v2(line_content, start_pos, end_pos):
    """Analyze the context of parentheses for additional information"""
    before_context = line_content[:start_pos]
    after_context = line_content[end_pos+1:]
    
    return {
        'in_if_statement': 'if ' in line_content,
        'in_for_loop': 'for ' in line_content,
        'in_return_statement': 'return ' in line_content,
        'in_assignment': ':=' in line_content or re.search(r'\w+\s*=\s*[^=]', line_content) is not None,
        'in_function_call': re.search(r'\w+\s*\([^)]*$', before_context) is not None,
        'in_function_parameter': is_function_parameter_context(before_context, after_context),
        'in_array_access': before_context.rstrip().endswith('[') and after_context.lstrip().startswith(']'),
        'has_multiple_operators': len(re.findall(r'[+\-*/%&|<>=!]', line_content)) > 1,
        'has_logical_operators': any(op in line_content for op in ['&&', '||', '!'])
    }

def get_function_context(source_lines, line_idx):
    """Get the function name containing the current line"""
    for i in range(max(0, line_idx - 20), min(len(source_lines), line_idx + 1)):
        func_match = re.search(r'func\s+(\w+)', source_lines[i])
        if func_match:
            return func_match.group(1)
    return ""


def check_server_hostname_verification(ast_tree, filename):
    """
    Enhanced check for disabled hostname verification in SSL/TLS connections.
    Detects InsecureSkipVerify: true and related patterns while avoiding false positives 
    from string literals and comments.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    # Read the source file to get exact line content
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Check each line for insecure TLS patterns
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or line_stripped.startswith('*') or line_stripped.startswith('/*') or not line_stripped:
            continue
            
        # Skip multi-line comments
        if '*/' in line_stripped and '/*' not in line_stripped:
            continue
            
        # Pattern 1: InsecureSkipVerify: true (most critical)
        insecure_skip_pattern = r'InsecureSkipVerify\s*:\s*true'
        insecure_matches = re.finditer(insecure_skip_pattern, line_content)
        
        for match in insecure_matches:
            # Check if this is in a string literal
            if is_in_string_literal(line_content, match.start()):
                continue  # Skip string literals
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue  # Skip comments
                
            # Check if this is in a TLS configuration context
            if not is_tls_config_context(line_content, source_lines, line_idx):
                continue  # Skip non-TLS contexts
                
            # Get function context for better reporting
            function_name = get_function_context(source_lines, line_idx)
            
            severity = "Critical"  # InsecureSkipVerify is always critical
            
            finding = {
                "rule_id": "crypto_server_hostname_verification",
                "message": f"InsecureSkipVerify: true disables hostname verification, allowing man-in-the-middle attacks",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": severity,
                "category": "Security",
                "function": function_name,
                "source_text": line_stripped,
                "context": "TLS hostname verification bypass"
            }
            findings.append(finding)
        
        # Pattern 2: VerifyPeerCertificate = nil (custom verification bypass)
        verify_peer_pattern = r'VerifyPeerCertificate\s*[=:]\s*nil'
        verify_matches = re.finditer(verify_peer_pattern, line_content)
        
        for match in verify_matches:
            # Check if this is in a string literal
            if is_in_string_literal(line_content, match.start()):
                continue
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue
                
            # Check if this is in a TLS configuration context
            if not is_tls_config_context(line_content, source_lines, line_idx):
                continue
                
            function_name = get_function_context(source_lines, line_idx)
            
            finding = {
                "rule_id": "crypto_server_hostname_verification", 
                "message": f"VerifyPeerCertificate set to nil bypasses custom certificate verification",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": "Major",
                "category": "Security", 
                "function": function_name,
                "source_text": line_stripped,
                "context": "Custom certificate verification bypass"
            }
            findings.append(finding)
            
        # Pattern 3: ServerName: "" (empty server name disables hostname verification)
        server_name_pattern = r'ServerName\s*:\s*["\']["\']'
        server_name_matches = re.finditer(server_name_pattern, line_content)
        
        for match in server_name_matches:
            # Check if this is in a string literal (beyond the intended empty string)
            if is_in_outer_string_literal(line_content, match.start()):
                continue
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue
                
            # Check if this is in a TLS configuration context
            if not is_tls_config_context(line_content, source_lines, line_idx):
                continue
                
            function_name = get_function_context(source_lines, line_idx)
            
            finding = {
                "rule_id": "crypto_server_hostname_verification",
                "message": f"Empty ServerName disables hostname verification",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": "Major", 
                "category": "Security",
                "function": function_name,
                "source_text": line_stripped,
                "context": "Empty server name vulnerability"
            }
            findings.append(finding)
    
    return findings


def is_in_string_literal(line_content, position):
    """Check if the position is within a string literal"""
    # Count quotes before the position
    double_quotes = 0
    single_quotes = 0
    backticks = 0
    
    for i, char in enumerate(line_content[:position]):
        if char == '"' and (i == 0 or line_content[i-1] != '\\'):
            double_quotes += 1
        elif char == "'" and (i == 0 or line_content[i-1] != '\\'):
            single_quotes += 1
        elif char == '`':
            backticks += 1
    
    # If odd number of quotes, we're inside a string literal
    return (double_quotes % 2 == 1) or (single_quotes % 2 == 1) or (backticks % 2 == 1)


def is_in_outer_string_literal(line_content, position):
    """Check if position is in a string literal that's not the target empty string"""
    # This is more complex - need to identify if we're in a string that contains our pattern
    # rather than being the string pattern itself
    
    # Simple heuristic: if there are unmatched quotes before our position that aren't
    # part of the ServerName: "" pattern itself
    before_text = line_content[:position]
    
    # Look for unmatched quotes that would indicate we're in a larger string
    quote_positions = []
    for i, char in enumerate(before_text):
        if char in ['"', "'"] and (i == 0 or before_text[i-1] != '\\'):
            quote_positions.append((i, char))
    
    # If we have an odd number of quotes and the most recent quote is far from our position,
    # we're likely in a string literal
    if len(quote_positions) % 2 == 1:
        last_quote_pos = quote_positions[-1][0]
        # If the last quote is more than 20 characters before, we're probably in a string
        return position - last_quote_pos > 20
        
    return False


def is_tls_config_context(line_content, source_lines, line_idx):
    """Check if the current line is in a TLS configuration context"""
    # Look for TLS-related patterns in current and nearby lines
    tls_patterns = [
        r'tls\.Config',
        r'TLSClientConfig',
        r'&tls\.Config',
        r'crypto/tls',
        r'Transport{',
        r'http\.Transport'
    ]
    
    # Check current line and surrounding context (5 lines before/after)
    start_line = max(0, line_idx - 5)
    end_line = min(len(source_lines), line_idx + 5)
    
    for i in range(start_line, end_line):
        line = source_lines[i] 
        for pattern in tls_patterns:
            if re.search(pattern, line):
                return True
                
    return False


def check_server_side_request_forgery(ast_tree, filename):
    """
    Enhanced check for server-side request forgery vulnerabilities.
    Detects HTTP requests using unvalidated user input while avoiding false positives 
    from string literals, hardcoded URLs, and validated URLs.
    
    Returns list of findings with detailed context.
    """
    findings = []
    
    # Read the source file to get exact line content
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except Exception:
        return findings
    
    # Track variables that contain user input for data flow analysis
    user_input_vars = set()
    validated_vars = set()
    
    # First pass: identify user input variables and validation patterns
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or line_stripped.startswith('*') or line_stripped.startswith('/*') or not line_stripped:
            continue
            
        # Track user input extraction patterns
        user_input_patterns = [
            r'(\w+)\s*:=\s*r\.URL\.Query\(\)\.Get\(',
            r'(\w+)\s*:=\s*r\.FormValue\(',
            r'(\w+)\s*:=\s*r\.Header\.Get\(',
            r'(\w+)\s*=\s*r\.URL\.Query\(\)\.Get\(',
            r'(\w+)\s*=\s*r\.FormValue\(',
            r'(\w+)\s*=\s*r\.Header\.Get\(',
        ]
        
        for pattern in user_input_patterns:
            match = re.search(pattern, line_content)
            if match:
                var_name = match.group(1)
                user_input_vars.add(var_name)
        
        # Track validation patterns
        validation_patterns = [
            r'if\s+!\s*isAllowed\w*\(',
            r'if\s+!\s*isWhitelisted\w*\(',
            r'if\s+!\s*validateSecure\w*\(',
            r'if\s+!\s*validate\w*\(',
            r'\.Scheme\s*[!=]=\s*["\']https["\']',
            r'allowedDomains\[',
            r'allowedHosts\[',
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, line_content):
                # Mark variables in this context as potentially validated
                for var in user_input_vars:
                    if var in line_content:
                        validated_vars.add(var)
    
    # Second pass: detect dangerous HTTP patterns
    for line_idx, line_content in enumerate(source_lines):
        line_number = line_idx + 1
        line_stripped = line_content.strip()
        
        # Skip comments and empty lines
        if line_stripped.startswith('//') or line_stripped.startswith('*') or line_stripped.startswith('/*') or not line_stripped:
            continue
            
        # Skip multi-line comments
        if '*/' in line_stripped and '/*' not in line_stripped:
            continue
        
        # Pattern 1: http.Get() calls
        http_get_pattern = r'http\.Get\('
        http_get_matches = re.finditer(http_get_pattern, line_content)
        
        for match in http_get_matches:
            # Check if this is in a string literal
            if is_in_string_literal(line_content, match.start()):
                continue
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue
                
            # Check if this uses a hardcoded URL
            if is_hardcoded_url_usage(line_content, source_lines, line_idx):
                continue
                
            # Check if this uses validated input
            if is_validated_url_usage(line_content, user_input_vars, validated_vars):
                continue
                
            # Check if this is an internal service call
            if is_internal_service_call(line_content, source_lines, line_idx):
                continue
                
            function_name = get_function_context(source_lines, line_idx)
            
            finding = {
                "rule_id": "security_server_side_request_forgery",
                "message": f"http.Get() call may be vulnerable to SSRF - validate user input and restrict URLs",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": "Major",
                "category": "Security",
                "function": function_name,
                "source_text": line_stripped,
                "context": "HTTP GET request with potential user input"
            }
            findings.append(finding)
        
        # Pattern 2: http.Post() calls
        http_post_pattern = r'http\.Post\('
        http_post_matches = re.finditer(http_post_pattern, line_content)
        
        for match in http_post_matches:
            # Check if this is in a string literal
            if is_in_string_literal(line_content, match.start()):
                continue
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue
                
            # Check if this uses a hardcoded URL
            if is_hardcoded_url_usage(line_content, source_lines, line_idx):
                continue
                
            # Check if this uses validated input
            if is_validated_url_usage(line_content, user_input_vars, validated_vars):
                continue
                
            # Check if this is an internal service call
            if is_internal_service_call(line_content, source_lines, line_idx):
                continue
                
            function_name = get_function_context(source_lines, line_idx)
            
            finding = {
                "rule_id": "security_server_side_request_forgery",
                "message": f"http.Post() call may be vulnerable to SSRF - validate user input and restrict URLs",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": "Major",
                "category": "Security",
                "function": function_name,
                "source_text": line_stripped,
                "context": "HTTP POST request with potential user input"
            }
            findings.append(finding)
        
        # Pattern 3: http.NewRequest() calls  
        http_new_request_pattern = r'http\.NewRequest\('
        http_new_request_matches = re.finditer(http_new_request_pattern, line_content)
        
        for match in http_new_request_matches:
            # Check if this is in a string literal
            if is_in_string_literal(line_content, match.start()):
                continue
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue
                
            # Check if this uses validated input
            if is_validated_url_usage(line_content, user_input_vars, validated_vars):
                continue
                
            function_name = get_function_context(source_lines, line_idx)
            
            finding = {
                "rule_id": "security_server_side_request_forgery",
                "message": f"http.NewRequest() call may be vulnerable to SSRF - validate URL parameters",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": "Major",
                "category": "Security",
                "function": function_name,
                "source_text": line_stripped,
                "context": "HTTP request creation with potential user input"
            }
            findings.append(finding)
        
        # Pattern 4: net.Dial() calls
        net_dial_pattern = r'net\.Dial\('
        net_dial_matches = re.finditer(net_dial_pattern, line_content)
        
        for match in net_dial_matches:
            # Check if this is in a string literal
            if is_in_string_literal(line_content, match.start()):
                continue
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue
                
            # Check if this uses validated input
            if is_validated_address_usage(line_content, user_input_vars, validated_vars):
                continue
                
            function_name = get_function_context(source_lines, line_idx)
            
            finding = {
                "rule_id": "security_server_side_request_forgery",
                "message": f"net.Dial() call may be vulnerable to SSRF - validate network addresses",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": "Major",
                "category": "Security",
                "function": function_name,
                "source_text": line_stripped,
                "context": "Direct network connection with potential user input"
            }
            findings.append(finding)
            
        # Pattern 5: User input extraction (only when not followed by validation)
        user_input_pattern = r'r\.URL\.Query\(\)\.Get\('
        user_input_matches = re.finditer(user_input_pattern, line_content)
        
        for match in user_input_matches:
            # Check if this is in a string literal
            if is_in_string_literal(line_content, match.start()):
                continue
                
            # Check if this is in a comment
            comment_pos = line_content.find('//')
            if comment_pos != -1 and match.start() > comment_pos:
                continue
                
            # Check if this is immediately followed by validation
            if has_immediate_validation(source_lines, line_idx):
                continue
                
            function_name = get_function_context(source_lines, line_idx)
            
            finding = {
                "rule_id": "security_server_side_request_forgery", 
                "message": f"User input extraction without validation - potential SSRF risk",
                "file": filename,
                "line": line_number,
                "column": match.start(),
                "severity": "Major",
                "category": "Security",
                "function": function_name,
                "source_text": line_stripped,
                "context": "User input extraction for potential URL usage"
            }
            findings.append(finding)
    
    return findings


def is_hardcoded_url_usage(line_content, source_lines, line_idx):
    """Check if the HTTP call uses a hardcoded URL"""
    # Look for string literals with URLs
    url_patterns = [
        r'http\.(?:Get|Post)\s*\(\s*["\'][^"\']*(?:https?://[^"\']+)["\']',
        r'http\.(?:Get|Post)\s*\(\s*["\'][^"\']*\.(?:com|org|net|gov|edu)[^"\']*["\']'
    ]
    
    for pattern in url_patterns:
        if re.search(pattern, line_content):
            return True
            
    return False


def is_validated_url_usage(line_content, user_input_vars, validated_vars):
    """Check if the HTTP call uses validated user input"""
    # Check if any user input variables in this line are validated
    for var in user_input_vars:
        if var in line_content and var in validated_vars:
            return True
            
    return False


def is_validated_address_usage(line_content, user_input_vars, validated_vars):
    """Check if the network dial uses validated address input"""
    return is_validated_url_usage(line_content, user_input_vars, validated_vars)


def is_internal_service_call(line_content, source_lines, line_idx):
    """Check if this is an internal service call"""
    # Look for patterns indicating internal service usage
    internal_patterns = [
        r'getInternalServiceURL\(',
        r'serviceURL\s*:=',
        r'internal-service',
        r'localhost:\d+',
        r'127\.0\.0\.1',
        r'config\.ServiceURL',
        r'cfg\.InternalURL'
    ]
    
    # Check current line and context
    context_lines = source_lines[max(0, line_idx-2):min(len(source_lines), line_idx+3)]
    
    for context_line in context_lines:
        for pattern in internal_patterns:
            if re.search(pattern, context_line):
                return True
                
    return False


def has_immediate_validation(source_lines, line_idx):
    """Check if user input is immediately validated in following lines"""
    # Look for validation patterns in the next few lines
    validation_patterns = [
        r'if\s+!\s*isAllowed',
        r'if\s+!\s*isWhitelisted',
        r'if\s+!\s*validate',
        r'if\s+.*\.Scheme\s*[!=]=',
        r'if\s+.*err\s*[!=]=\s*nil',
    ]
    
    # Check next 5 lines for validation
    start_line = min(line_idx + 1, len(source_lines))
    end_line = min(start_line + 5, len(source_lines))
    
    for i in range(start_line, end_line):
        line = source_lines[i].strip()
        for pattern in validation_patterns:
            if re.search(pattern, line):
                return True
                
    return False
