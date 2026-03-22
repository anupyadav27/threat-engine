"""
Custom logic implementations for Docker rules

This module contains custom functions that implement complex rule logic
that cannot be expressed purely through generic JSON-based checks.
"""

import re
from typing import Dict, List, Any, Optional, Set


def check_arg_variable_scope(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Check for ARG variables accessed outside their scope.
    
    ARG scope rules:
    1. ARG before any FROM: Only available in FROM instructions
    2. ARG after FROM: Available in that build stage until next FROM
    3. Using ARG outside its scope results in empty value
    
    Args:
        ast_tree: Parsed Dockerfile AST
        filename: Path to the Dockerfile
        
    Returns:
        List of findings for out-of-scope ARG access
    """
    findings = []
    
    # Extract all instructions
    instructions = ast_tree.get('instructions', [])
    if not instructions:
        return findings
    
    # Track ARG definitions and their scopes
    global_args = set()  # ARGs before first FROM
    all_stage_args = {}  # {stage_index: set(arg_names)} - all args defined in each stage
    current_stage_args = set()  # ARGs currently available in the current stage
    current_stage = -1   # -1 = before first FROM, 0+ = stage index
    first_from_seen = False
    args_before_current_from = set()  # Track ARGs defined just before current FROM
    
    # Process instructions in order, tracking ARG availability as we go
    for idx, instruction in enumerate(instructions):
        inst_type = instruction.get('instruction', '').upper()
        inst_value = instruction.get('value', '')
        line_num = instruction.get('line', idx + 1)
        
        # Track ARG declarations
        if inst_type == 'ARG':
            value = instruction.get('value', '')
            arg_name = value.split('=')[0].strip() if '=' in value else value.strip()
            
            if not first_from_seen:
                # Global ARG (before any FROM)
                global_args.add(arg_name)
                args_before_current_from.add(arg_name)
            else:
                # Stage-specific ARG - immediately available in current stage
                current_stage_args.add(arg_name)
                if current_stage not in all_stage_args:
                    all_stage_args[current_stage] = set()
                all_stage_args[current_stage].add(arg_name)
                args_before_current_from.add(arg_name)
        
        elif inst_type == 'FROM':
            # ARGs defined between stages can be used in the next FROM
            available_in_from = global_args | args_before_current_from
            
            # Check variable usage in FROM instruction
            variables_used = extract_variables(inst_value)
            for var in variables_used:
                if var not in available_in_from and not is_builtin_arg(var):
                    # Check if it's a stage-specific ARG from a previous stage
                    is_defined_in_stage = any(var in args for args in all_stage_args.values())
                    if is_defined_in_stage:
                        findings.append({
                            "rule_id": "access_variable_which_is",
                            "message": f"Variable '${var}' is not available in FROM instruction. Only global ARGs (defined before first FROM) can be used here.",
                            "file": filename,
                            "line": line_num,
                            "instruction": inst_type,
                            "severity": "Info",
                            "status": "violation"
                        })
            
            # Move to new stage - reset current stage ARGs
            if not first_from_seen:
                first_from_seen = True
                current_stage = 0
            else:
                current_stage += 1
            
            current_stage_args = set()  # Reset ARGs for new stage
            args_before_current_from = set()  # Reset before-FROM args
        
        elif current_stage >= 0:
            # Check variable usage in other instructions (not FROM, not ARG)
            variables_used = extract_variables(inst_value)
            
            for var in variables_used:
                # Check if variable is available in current scope
                if var not in current_stage_args and not is_builtin_arg(var):
                    # Check if it's defined in a different stage
                    defined_in_other_stage = any(
                        var in args for stage_idx, args in all_stage_args.items() 
                        if stage_idx != current_stage
                    )
                    
                    if defined_in_other_stage:
                        findings.append({
                            "rule_id": "access_variable_which_is",
                            "message": f"Variable '${var}' is not available in the current build stage. ARG variables are scoped to their build stage.",
                            "file": filename,
                            "line": line_num,
                            "instruction": inst_type,
                            "severity": "Info",
                            "status": "violation"
                        })
                    elif var in global_args:
                        # Global ARG used in non-FROM instruction (not allowed)
                        findings.append({
                            "rule_id": "access_variable_which_is",
                            "message": f"Variable '${var}' is a global ARG and only available in FROM instructions. Re-declare it with ARG in this stage to use it here.",
                            "file": filename,
                            "line": line_num,
                            "instruction": inst_type,
                            "severity": "Info",
                            "status": "violation"
                        })
    
    return findings


def extract_variables(text: str) -> Set[str]:
    """
    Extract variable references from text.
    Supports both ${VAR} and $VAR syntax.
    
    Args:
        text: Text to search for variables
        
    Returns:
        Set of variable names
    """
    variables = set()
    
    # Match ${VAR} and $VAR patterns
    # Pattern: ${ followed by word chars } OR $ followed by word chars
    patterns = [
        r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}',  # ${VAR}
        r'\$([A-Za-z_][A-Za-z0-9_]*)',      # $VAR
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text)
        variables.update(matches)
    
    return variables


def is_builtin_arg(var_name: str) -> bool:
    """
    Check if variable is a Docker built-in ARG.
    
    Docker provides several built-in ARGs:
    - HTTP_PROXY, HTTPS_PROXY, FTP_PROXY, NO_PROXY
    - TARGETPLATFORM, TARGETOS, TARGETARCH, TARGETVARIANT
    - BUILDPLATFORM, BUILDOS, BUILDARCH, BUILDVARIANT
    
    Args:
        var_name: Variable name to check
        
    Returns:
        True if it's a built-in ARG
    """
    builtin_args = {
        'HTTP_PROXY', 'http_proxy',
        'HTTPS_PROXY', 'https_proxy',
        'FTP_PROXY', 'ftp_proxy',
        'NO_PROXY', 'no_proxy',
        'TARGETPLATFORM', 'TARGETOS', 'TARGETARCH', 'TARGETVARIANT',
        'BUILDPLATFORM', 'BUILDOS', 'BUILDARCH', 'BUILDVARIANT',
    }
    
    return var_name in builtin_args


def check_sorted_run_arguments(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Check if arguments in long RUN instructions are sorted alphabetically.
    
    This rule focuses on package installation commands where multiple packages
    are listed. Having packages sorted alphabetically improves readability and
    makes it easier to track changes in version control.
    
    Args:
        ast_tree: Parsed Dockerfile AST
        filename: Path to the Dockerfile
        
    Returns:
        List of findings for unsorted arguments in RUN instructions
    """
    findings = []
    
    # Extract all instructions
    instructions = ast_tree.get('instructions', [])
    if not instructions:
        return findings
    
    # Package manager install commands that should have sorted packages
    install_patterns = [
        r'apt-get\s+install',
        r'apt\s+install',
        r'apk\s+add',
        r'yum\s+install',
        r'dnf\s+install',
        r'zypper\s+install',
        r'pip\s+install',
        r'npm\s+install',
        r'gem\s+install',
    ]
    
    for instruction in instructions:
        inst_type = instruction.get('instruction', '').upper()
        
        if inst_type != 'RUN':
            continue
        
        inst_value = instruction.get('value', '')
        line_num = instruction.get('line', 0)
        
        # Check if this is an install command
        is_install_cmd = False
        for pattern in install_patterns:
            if re.search(pattern, inst_value, re.IGNORECASE):
                is_install_cmd = True
                break
        
        if not is_install_cmd:
            continue
        
        # Extract package names from the command
        packages = extract_package_names(inst_value)
        
        # Only check if there are 3 or more packages (makes it a "long" instruction)
        if len(packages) < 3:
            continue
        
        # Check if packages are sorted alphabetically (case-insensitive)
        sorted_packages = sorted(packages, key=str.lower)
        
        if packages != sorted_packages:
            unsorted_list = ', '.join(packages[:5])  # Show first 5 packages
            if len(packages) > 5:
                unsorted_list += ', ...'
            
            sorted_list = ', '.join(sorted_packages[:5])
            if len(sorted_packages) > 5:
                sorted_list += ', ...'
            
            findings.append({
                "rule_id": "arguments_long_run_instructions",
                "message": f"Arguments in long RUN instruction should be sorted alphabetically. Found: [{unsorted_list}]. Expected: [{sorted_list}]",
                "file": filename,
                "line": line_num,
                "instruction": inst_type,
                "severity": "Info",
                "status": "violation"
            })
    
    return findings


def extract_package_names(command: str) -> List[str]:
    """
    Extract package names from a package installation command.
    
    Handles various package managers and their specific syntax:
    - Filters out flags (starting with -)
    - Removes version specifications (package=version, package:version)
    - Handles line continuations with backslashes
    
    Args:
        command: The RUN command value
        
    Returns:
        List of package names in order they appear
    """
    # Remove line continuations and normalize whitespace
    command = command.replace('\\', ' ')
    command = re.sub(r'\s+', ' ', command)
    
    # Remove common flags and options
    # Remove everything after && or ; (multiple commands)
    command = re.split(r'[;&]', command)[0]
    
    # Split into tokens
    tokens = command.split()
    
    packages = []
    skip_next = False
    found_install = False
    
    for i, token in enumerate(tokens):
        # Skip if this token should be skipped
        if skip_next:
            skip_next = False
            continue
        
        # Check if we've reached the install command
        if re.search(r'^(apt-get|apt|apk|yum|dnf|zypper|pip|npm|gem)$', token, re.IGNORECASE):
            continue
        
        if token.lower() in ['install', 'add']:
            found_install = True
            continue
        
        # Skip flags and options
        if token.startswith('-'):
            # Check if next token is a value for this flag
            if '=' not in token and i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                skip_next = True
            continue
        
        # Skip package manager keywords
        if token.lower() in ['update', 'upgrade', 'clean', 'autoclean', 'autoremove', 
                              'purge', 'remove', 'cache', '&&', '||', '|']:
            continue
        
        # If we haven't found install yet, skip
        if not found_install:
            continue
        
        # Remove version specifications and extract package name
        # Handle formats like: package=1.0, package:1.0, package>=1.0
        package = re.split(r'[=:<>]', token)[0].strip()
        
        # Skip empty strings and shell redirects
        if package and not package.startswith('>') and not package.startswith('<'):
            packages.append(package)
    
    return packages


def check_dockerfile_parsing_errors(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Check if the Dockerfile has parsing errors or invalid syntax.
    
    This function detects various parsing issues:
    - Missing required instructions (e.g., no FROM)
    - Invalid instruction syntax
    - Malformed arguments
    - Parsing exceptions
    
    Args:
        ast_tree: Parsed Dockerfile AST
        filename: Path to the Dockerfile
        
    Returns:
        List of findings for parsing errors
    """
    findings = []
    
    # Check if AST tree is valid
    if not ast_tree or not isinstance(ast_tree, dict):
        findings.append({
            "rule_id": "dockerfile_parsing_failure",
            "message": "Dockerfile parsing failed. The file structure is invalid or could not be parsed.",
            "file": filename,
            "line": 1,
            "instruction": "PARSING",
            "severity": "Major",
            "status": "violation"
        })
        return findings
    
    # Check for parsing errors in the AST
    if ast_tree.get('error') or ast_tree.get('parse_error'):
        error_msg = ast_tree.get('error_message', 'Unknown parsing error')
        findings.append({
            "rule_id": "dockerfile_parsing_failure",
            "message": f"Dockerfile parsing failed: {error_msg}",
            "file": filename,
            "line": ast_tree.get('error_line', 1),
            "instruction": "PARSING",
            "severity": "Major",
            "status": "violation"
        })
        return findings
    
    # Check for minimum required instructions
    instructions = ast_tree.get('instructions', [])
    
    # A valid Dockerfile must have at least one FROM instruction
    has_from = any(inst.get('instruction', '').upper() == 'FROM' for inst in instructions)
    
    if not has_from and instructions:
        findings.append({
            "rule_id": "dockerfile_parsing_failure",
            "message": "Dockerfile parsing issue: Missing required FROM instruction. Every Dockerfile must start with a FROM instruction.",
            "file": filename,
            "line": 1,
            "instruction": "FROM",
            "severity": "Major",
            "status": "violation"
        })
    
    # Check for invalid or unknown instructions
    valid_instructions = {
        'FROM', 'RUN', 'CMD', 'LABEL', 'EXPOSE', 'ENV', 'ADD', 'COPY',
        'ENTRYPOINT', 'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD',
        'STOPSIGNAL', 'HEALTHCHECK', 'SHELL', 'MAINTAINER'
    }
    
    for instruction in instructions:
        inst_type = instruction.get('instruction', '').upper()
        line_num = instruction.get('line', 1)
        
        # Check for empty or invalid instruction names
        if not inst_type or inst_type.strip() == '':
            findings.append({
                "rule_id": "dockerfile_parsing_failure",
                "message": "Dockerfile parsing issue: Invalid or empty instruction found.",
                "file": filename,
                "line": line_num,
                "instruction": "UNKNOWN",
                "severity": "Major",
                "status": "violation"
            })
        elif inst_type not in valid_instructions:
            findings.append({
                "rule_id": "dockerfile_parsing_failure",
                "message": f"Dockerfile parsing issue: Unknown instruction '{inst_type}'. This may indicate a syntax error or typo.",
                "file": filename,
                "line": line_num,
                "instruction": inst_type,
                "severity": "Major",
                "status": "violation"
            })
    
    return findings


def check_mandatory_labels(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Check if mandatory descriptive labels are present in each stage of the Dockerfile.
    
    Common mandatory labels include:
    - maintainer (or org.opencontainers.image.authors)
    - version (or org.opencontainers.image.version)
    - description (or org.opencontainers.image.description)
    
    Args:
        ast_tree: Parsed Dockerfile AST
        filename: Path to the Dockerfile
        
    Returns:
        List of findings for missing mandatory labels
    """
    findings = []
    
    # Extract all instructions
    instructions = ast_tree.get('instructions', [])
    if not instructions:
        return findings
    
    # Define mandatory labels (case-insensitive)
    mandatory_labels = {
        'maintainer': ['maintainer', 'org.opencontainers.image.authors'],
        'version': ['version', 'org.opencontainers.image.version'],
        'description': ['description', 'org.opencontainers.image.description']
    }
    
    # Split Dockerfile into stages (each starting with FROM)
    stages = []
    current_stage = []
    
    for instruction in instructions:
        inst_type = instruction.get('instruction', '').upper()
        
        if inst_type == 'FROM':
            if current_stage:  # Save previous stage
                stages.append(current_stage)
            current_stage = [instruction]  # Start new stage
        else:
            current_stage.append(instruction)
    
    # Add the last stage
    if current_stage:
        stages.append(current_stage)
    
    # Check each stage for mandatory labels
    for stage_idx, stage in enumerate(stages):
        # Track found labels for this stage
        found_labels = {key: False for key in mandatory_labels.keys()}
        from_line = stage[0].get('line', 1) if stage else 1
        
        # Scan for LABEL instructions in this stage
        for instruction in stage:
            inst_type = instruction.get('instruction', '').upper()
            
            if inst_type == 'LABEL':
                inst_value = instruction.get('value', '')
                
                # Parse label key-value pairs
                # Handle formats: LABEL key=value, LABEL key="value", LABEL key value
                label_pairs = []
                
                # Split by whitespace but respect quotes
                if '=' in inst_value:
                    # Format: key=value or key="value"
                    parts = re.split(r'\s+(?=\w+=)', inst_value)
                    for part in parts:
                        if '=' in part:
                            key = part.split('=', 1)[0].strip().strip('"').strip("'")
                            label_pairs.append(key.lower())
                else:
                    # Format: key value (space-separated, older format)
                    tokens = inst_value.split()
                    if tokens:
                        key = tokens[0].strip().strip('"').strip("'")
                        label_pairs.append(key.lower())
                
                # Check if any mandatory label is present
                for label_type, aliases in mandatory_labels.items():
                    for label_key in label_pairs:
                        if label_key in [alias.lower() for alias in aliases]:
                            found_labels[label_type] = True
        
        # Check for missing labels in this stage
        missing_labels = [label_type for label_type, found in found_labels.items() if not found]
        
        if missing_labels:
            missing_list = ', '.join(missing_labels)
            findings.append({
                "rule_id": "descriptive_labels_are_mandatory",
                "message": f"Missing mandatory descriptive label(s): {missing_list}. Add LABEL instructions for better image documentation (e.g., LABEL maintainer=\"email@example.com\" version=\"1.0\" description=\"App description\").",
                "file": filename,
                "line": from_line,
                "instruction": "LABEL",
                "severity": "Info",
                "status": "violation"
            })
    
    return findings


def check_env_unset_different_layer(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Check for environment variables being unset on a different layer than they were set.
    
    The issue: ENV creates a new layer with the variable. Using RUN unset only removes
    it from that specific layer, but the variable is still accessible in the previous layer,
    which is a security concern especially for secrets.
    
    Args:
        ast_tree: Parsed Dockerfile AST
        filename: Path to the Dockerfile
        
    Returns:
        List of findings for ENV variables unset in different layers
    """
    findings = []
    
    instructions = ast_tree.get('instructions', [])
    if not instructions:
        return findings
    
    # Track ENV variable definitions: {var_name: (line_num, layer_index)}
    env_vars = {}
    current_layer = 0
    
    # Track which variables have been unset and where
    unset_vars = {}  # {var_name: (unset_line, unset_layer)}
    
    # Process instructions sequentially
    for idx, instruction in enumerate(instructions):
        inst_type = instruction.get('instruction', '').upper()
        inst_value = instruction.get('value', '')
        line_num = instruction.get('line', idx + 1)
        
        # Each instruction creates a new layer
        current_layer = idx
        
        if inst_type == 'ENV':
            # Parse ENV variable name(s)
            # ENV can be: ENV KEY=value, ENV KEY value, ENV K1=v1 K2=v2
            if '=' in inst_value:
                # Format: KEY=value or KEY="value"
                parts = inst_value.split()
                for part in parts:
                    if '=' in part:
                        var_name = part.split('=', 1)[0].strip()
                        if var_name:
                            env_vars[var_name] = (line_num, current_layer)
            else:
                # Format: KEY value (space-separated, older format)
                tokens = inst_value.split(None, 1)
                if tokens:
                    var_name = tokens[0].strip()
                    if var_name:
                        env_vars[var_name] = (line_num, current_layer)
        
        elif inst_type == 'RUN':
            # Check for unset commands in RUN instructions
            # Look for patterns: unset VAR, unset VAR1 VAR2, etc.
            unset_pattern = r'\bunset\s+([A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)'
            matches = re.finditer(unset_pattern, inst_value)
            
            for match in matches:
                # Extract all variable names from the unset command
                var_names_str = match.group(1)
                var_names = var_names_str.split()
                
                for var_name in var_names:
                    var_name = var_name.strip()
                    if var_name in env_vars:
                        env_line, env_layer = env_vars[var_name]
                        
                        # Check if unset is on a different layer than where it was set
                        if env_layer != current_layer:
                            findings.append({
                                "rule_id": "environment_variables_unset_different",
                                "message": f"Environment variable '{var_name}' was set with ENV at line {env_line} but unset with RUN at line {line_num} on a different layer. The variable remains accessible from the previous layer. Consider using ARG instead of ENV for build-time secrets, or use RUN export/unset in the same command as ENV.",
                                "file": filename,
                                "line": line_num,
                                "instruction": inst_type,
                                "severity": "Info",
                                "status": "violation",
                                "details": {
                                    "variable": var_name,
                                    "set_line": env_line,
                                    "unset_line": line_num,
                                    "set_layer": env_layer,
                                    "unset_layer": current_layer
                                }
                            })
                            unset_vars[var_name] = (line_num, current_layer)
    
    return findings


def check_consecutive_run_instructions(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Check for consecutive RUN instructions that should be combined.
    
    Multiple consecutive RUN instructions increase the image size and build time
    as each creates a new layer. Combining them with && reduces layers.
    
    Args:
        ast_tree: Parsed Dockerfile AST
        filename: Path to the Dockerfile
        
    Returns:
        List of findings for consecutive RUN instructions
    """
    findings = []
    
    # Extract all instructions
    instructions = ast_tree.get('instructions', [])
    if not instructions:
        return findings
    
    consecutive_runs = []
    i = 0
    
    while i < len(instructions):
        instruction = instructions[i]
        inst_type = instruction.get('instruction', '').upper()
        
        if inst_type == 'RUN':
            # Start tracking consecutive RUN instructions
            run_group = [instruction]
            j = i + 1
            
            # Look for consecutive RUN instructions (skip comments between them)
            while j < len(instructions):
                next_inst = instructions[j]
                next_type = next_inst.get('instruction', '').upper()
                
                if next_type == 'RUN':
                    run_group.append(next_inst)
                    j += 1
                elif next_type == 'COMMENT':
                    # Skip comments between RUN instructions
                    j += 1
                else:
                    # Different instruction type, break the sequence
                    break
            
            # If we found 2 or more consecutive RUN instructions, report it
            if len(run_group) >= 2:
                consecutive_runs.append(run_group)
                
                # Report the violation at the first RUN instruction of the group
                first_run = run_group[0]
                last_run = run_group[-1]
                first_line = first_run.get('line', 0)
                last_line = last_run.get('line', 0)
                
                findings.append({
                    "rule_id": "reduce_amount_consecutive_run",
                    "message": f"Found {len(run_group)} consecutive RUN instructions (lines {first_line}-{last_line}). Consider combining them with && to reduce image layers and build time. Example: RUN command1 && command2 && command3",
                    "file": filename,
                    "line": first_line,
                    "instruction": "RUN",
                    "severity": "Info",
                    "status": "violation",
                    "details": {
                        "consecutive_count": len(run_group),
                        "first_line": first_line,
                        "last_line": last_line,
                        "lines": [run.get('line', 0) for run in run_group]
                    }
                })
            
            # Move to the instruction after the last RUN
            i = j
        else:
            i += 1
    
    return findings


def check_todo_tags(ast_tree: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    """
    Check for TODO tags and similar markers in Dockerfile comments.
    
    Tracks TODO, FIXME, HACK, XXX, BUG tags that indicate incomplete work.
    
    Args:
        ast_tree: Parsed Dockerfile AST
        filename: Path to the Dockerfile
        
    Returns:
        List of findings for TODO tag occurrences
    """
    findings = []
    
    # TODO tag patterns to detect
    todo_patterns = [
        (r'\bTODO\b', 'TODO'),
        (r'\bFIXME\b', 'FIXME'),
        (r'\bHACK\b', 'HACK'),
        (r'\bXXX\b', 'XXX'),
        (r'\bBUG\b', 'BUG'),
    ]
    
    # Check comments in the AST
    if 'children' in ast_tree:
        for child in ast_tree.get('children', []):
            if child.get('node_type') == 'Comment':
                line_num = child.get('line', 0)
                text = child.get('text', '')
                raw = child.get('raw', '')
                
                # Check each pattern
                for pattern, tag_name in todo_patterns:
                    if re.search(pattern, text, re.IGNORECASE) or re.search(pattern, raw, re.IGNORECASE):
                        findings.append({
                            "rule_id": "track_uses_todo_tags",
                            "message": f"Track uses of TODO tags. This comment contains a {tag_name} marker indicating incomplete or pending work. TODO tags often get overlooked or forgotten, leading to unfinished code. Review and resolve the {tag_name} item, or create a tracked issue/ticket for it.",
                            "file": filename,
                            "line": line_num,
                            "instruction": "COMMENT",
                            "severity": "Critical",
                            "status": "violation",
                            "details": {
                                "tag_type": tag_name,
                                "comment_text": text[:100]  # First 100 chars
                            }
                        })
                        # Only report the first matching pattern per comment
                        break
    
    # Also check instructions for inline TODO comments
    instructions = ast_tree.get('instructions', [])
    for instruction in instructions:
        raw = instruction.get('raw', '')
        line_num = instruction.get('line', 0)
        
        # Check for inline comments with TODO tags
        if '#' in raw:
            comment_part = raw[raw.index('#'):]
            for pattern, tag_name in todo_patterns:
                if re.search(pattern, comment_part, re.IGNORECASE):
                    findings.append({
                        "rule_id": "track_uses_todo_tags",
                        "message": f"Track uses of TODO tags. This comment contains a {tag_name} marker indicating incomplete or pending work. TODO tags often get overlooked or forgotten, leading to unfinished code. Review and resolve the {tag_name} item, or create a tracked issue/ticket for it.",
                        "file": filename,
                        "line": line_num,
                        "instruction": instruction.get('instruction', 'UNKNOWN'),
                        "severity": "Critical",
                        "status": "violation",
                        "details": {
                            "tag_type": tag_name,
                            "comment_text": comment_part[:100]
                        }
                    })
                    # Only report the first matching pattern per line
                    break
    
    return findings
