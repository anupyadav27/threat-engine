"""
Docker Scanner Engine
A comprehensive scanner for analyzing Dockerfiles based on JSON metadata rules.
Uses AST (Abstract Syntax Tree) parsing to analyze Dockerfile structure and security.

How it works:
1. Load rule metadata from JSON files
2. Parse Dockerfile into AST using docker_ast_parser
3. Apply generic rules from metadata to AST nodes
4. Detect vulnerabilities based on AST structure and patterns
"""

import sys
import re
import os
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from docker_scanner import docker_generic_rule
from docker_scanner.docker_ast_parser import parse_dockerfile_to_ast, DockerfileNode


@dataclass
class Finding:
    """Represents a single rule violation finding."""
    rule_id: str
    message: str
    file: str
    line: Optional[int]
    severity: str
    instruction: str

    def __hash__(self) -> int:
        """Enable finding deduplication based on core attributes."""
        return hash((self.rule_id, self.file, self.line, self.message))


def load_rule_metadata(folder="docker_docs"):
    """
    Load all rule metadata JSON files from the specified folder.
    
    Args:
        folder: Directory containing *_metadata.json files
        
    Returns:
        Dictionary mapping rule_id to metadata
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder)
    
    if not os.path.isdir(folder_path):
        raise ValueError(f"Metadata folder '{folder}' not found in {script_dir}.")
    
    rules_meta = {}
    for filename in os.listdir(folder_path):
        if filename.endswith("_metadata.json"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "rule_id" in data:
                        rules_meta[data["rule_id"]] = data
            except Exception as e:
                print(f"Warning: Failed to load {filename}: {e}", file=sys.stderr)
                continue
    
    return rules_meta


def get_all_dockerfiles(scan_path):
    """
    Recursively find all Dockerfiles in the scan path.
    
    Args:
        scan_path: File or directory path to scan
        
    Returns:
        List of Dockerfile paths
    """
    dockerfiles = []
    
    if os.path.isfile(scan_path):
        # Single file
        basename = os.path.basename(scan_path)
        if basename == "Dockerfile" or basename.startswith("Dockerfile.") or basename.endswith(".dockerfile"):
            dockerfiles.append(scan_path)
    else:
        # Directory - recursively search
        for root, _, files in os.walk(scan_path):
            for file in files:
                if file == "Dockerfile" or file.startswith("Dockerfile.") or file.endswith(".dockerfile"):
                    dockerfiles.append(os.path.join(root, file))
    
    return dockerfiles


def parse_dockerfile(file_path):
    """
    Parse a Dockerfile into an AST (Abstract Syntax Tree).
    
    This function uses docker_ast_parser to build a comprehensive AST that represents
    the Dockerfile structure including:
    - Instructions (FROM, RUN, COPY, etc.)
    - Arguments and flags
    - Key-value pairs (ENV, ARG, LABEL)
    - Commands (shell vs exec form)
    - Image references with tags and digests
    
    Args:
        file_path: Path to Dockerfile
        
    Returns:
        DockerfileNode AST or dictionary representation
    """
    try:
        # Use the new AST parser
        ast_tree = parse_dockerfile_to_ast(file_path)
        # Return as dictionary for compatibility with generic rule engine
        return ast_tree.to_dict()
    except Exception as e:
        print(f"Error parsing {file_path} with AST parser: {e}", file=sys.stderr)
        # Fallback to legacy parser
        return _parse_dockerfile_legacy(file_path)


def _parse_dockerfile_legacy(file_path):
    """
    Legacy Dockerfile parser (backward compatibility).
    Used as fallback if AST parser fails.
    
    Args:
        file_path: Path to Dockerfile
        
    Returns:
        Dictionary with instructions list and metadata
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    lines = source_code.splitlines()
    instructions = []
    current_instruction = None
    current_line_num = 0
    
    for idx, line in enumerate(lines, 1):
        original_line = line
        line_stripped = line.strip()
        
        # Skip empty lines
        if not line_stripped:
            continue
        
        # Skip comments (but not inline comments)
        if line_stripped.startswith('#'):
            continue
        
        # Check if this is a continuation of previous instruction
        if current_instruction:
            # Remove leading whitespace and add to current instruction
            current_instruction['value'] += ' ' + line_stripped.rstrip('\\').strip()
            current_instruction['raw'] += '\n' + original_line
            
            # Check if line continues
            if not line_stripped.endswith('\\'):
                # Instruction is complete
                instructions.append(current_instruction)
                current_instruction = None
            continue
        
        # Extract instruction (FROM, RUN, COPY, etc.)
        # Instructions are typically at the start of a line
        match = re.match(r'^([A-Z][A-Z_]*)\s+(.*)$', line_stripped, re.IGNORECASE)
        
        if match:
            instruction_name = match.group(1).upper()
            instruction_value = match.group(2).rstrip('\\').strip()
            
            current_instruction = {
                'instruction': instruction_name,
                'value': instruction_value,
                'line': idx,
                'lineno': idx,
                'raw': original_line
            }
            
            # Check if instruction continues on next line
            if not line_stripped.endswith('\\'):
                instructions.append(current_instruction)
                current_instruction = None
        else:
            # Not a valid instruction, might be a comment or continuation
            # Handle inline comments after instructions
            if '#' in line_stripped:
                continue
    
    # Handle any remaining instruction
    if current_instruction:
        instructions.append(current_instruction)
    
    # Parse instruction-specific details
    for instruction in instructions:
        instruction_name = instruction['instruction']
        value = instruction['value']
        
        # Parse FROM instruction details
        if instruction_name == 'FROM':
            # FROM [--platform=<platform>] <image>[:<tag>] [AS <name>]
            from_match = re.match(r'^(?:--platform=\S+\s+)?(\S+?)(?::(\S+?))?\s*(?:AS\s+(\S+))?$', value, re.IGNORECASE)
            if from_match:
                instruction['image'] = from_match.group(1)
                instruction['tag'] = from_match.group(2) or 'latest'
                instruction['alias'] = from_match.group(3)
        
        # Parse USER instruction
        elif instruction_name == 'USER':
            # USER <user>[:<group>] or USER <UID>[:<GID>]
            instruction['user'] = value.split(':')[0]
            if ':' in value:
                instruction['group'] = value.split(':')[1]
        
        # Parse EXPOSE instruction
        elif instruction_name == 'EXPOSE':
            # EXPOSE <port> [<port>/<protocol>...]
            ports = re.findall(r'(\d+)(?:/(\w+))?', value)
            instruction['ports'] = [{'port': p[0], 'protocol': p[1] or 'tcp'} for p in ports]
        
        # Parse ENV instruction
        elif instruction_name == 'ENV':
            # ENV <key>=<value> ... or ENV <key> <value>
            if '=' in value:
                # Key=value format
                env_vars = {}
                for pair in re.findall(r'(\w+)=([^\s]+)', value):
                    env_vars[pair[0]] = pair[1]
                instruction['env_vars'] = env_vars
            else:
                # Key value format (only one variable)
                parts = value.split(None, 1)
                if len(parts) == 2:
                    instruction['env_vars'] = {parts[0]: parts[1]}
        
        # Parse ARG instruction
        elif instruction_name == 'ARG':
            # ARG <name>[=<default value>]
            if '=' in value:
                key, val = value.split('=', 1)
                instruction['arg_name'] = key.strip()
                instruction['arg_default'] = val.strip()
            else:
                instruction['arg_name'] = value.strip()
        
        # Parse COPY/ADD instructions
        elif instruction_name in ['COPY', 'ADD']:
            # COPY [--from=<name>] <src>... <dest>
            # ADD [--chown=<user>:<group>] <src>... <dest>
            copy_match = re.match(r'^(?:--\S+=\S+\s+)?(.+)\s+(\S+)$', value)
            if copy_match:
                instruction['source'] = copy_match.group(1)
                instruction['destination'] = copy_match.group(2)
        
        # Parse WORKDIR instruction
        elif instruction_name == 'WORKDIR':
            instruction['path'] = value
        
        # Parse HEALTHCHECK instruction
        elif instruction_name == 'HEALTHCHECK':
            if value.strip().upper().startswith('NONE'):
                instruction['healthcheck_type'] = 'NONE'
            else:
                instruction['healthcheck_type'] = 'CMD'
                instruction['healthcheck_cmd'] = value
        
        # Parse LABEL instruction
        elif instruction_name == 'LABEL':
            # LABEL <key>=<value> <key>=<value> ...
            labels = {}
            for pair in re.findall(r'(\S+)=([^\s]+)', value):
                labels[pair[0]] = pair[1].strip('"')
            instruction['labels'] = labels
        
        # Detect exec form vs shell form for RUN, CMD, ENTRYPOINT
        if instruction_name in ['RUN', 'CMD', 'ENTRYPOINT']:
            # Exec form starts with [
            if value.strip().startswith('['):
                instruction['form'] = 'exec'
                # Try to parse JSON array
                try:
                    instruction['command_array'] = json.loads(value)
                except:
                    instruction['form'] = 'shell'
            else:
                instruction['form'] = 'shell'
    
    return {
        'node_type': 'Dockerfile',
        'filename': file_path,
        'source': source_code,
        'instructions': instructions,
        'children': instructions  # For compatibility with generic rule engine
    }


def run_scanner(scan_path):
    """
    Main scanner function to analyze Dockerfiles.
    
    Args:
        scan_path: File or directory path to scan
        
    Returns:
        List of findings (violations)
    """
    # Load all rule metadata
    rules_meta = load_rule_metadata()
    rules = list(rules_meta.values())
    
    # Filter out disabled rules
    rules = [rule for rule in rules if rule.get('status') != 'disabled']
    
    print(f"Loaded {len(rules)} active rules", file=sys.stderr)
    
    # Get all Dockerfiles
    dockerfiles = get_all_dockerfiles(scan_path)
    print(f"Found {len(dockerfiles)} Dockerfile(s) to scan", file=sys.stderr)
    
    all_findings = []
    
    # Scan each Dockerfile
    for dockerfile in dockerfiles:
        print(f"Scanning: {dockerfile}", file=sys.stderr)
        
        try:
            # Parse Dockerfile
            ast_tree = parse_dockerfile(dockerfile)
            
            # Run each rule
            for rule in rules:
                try:
                    findings = docker_generic_rule.run_rule(rule, ast_tree, dockerfile)
                    
                    if findings:
                        for finding in findings:
                            finding['file'] = dockerfile
                            all_findings.append(finding)
                except Exception as e:
                    print(f"Warning: Rule {rule.get('rule_id', 'unknown')} failed on {dockerfile}: {e}", file=sys.stderr)
                    continue
        
        except Exception as e:
            print(f"Error parsing {dockerfile}: {e}", file=sys.stderr)
            continue
    
    # Deduplicate findings
    seen = set()
    deduped = []
    
    for f in all_findings:
        key = (f.get('rule_id'), f.get('file'), f.get('line'), f.get('message'))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    print(f"Found {len(deduped)} unique violations", file=sys.stderr)
    
    return deduped


def run_scan(file_path):
    """
    Compatibility wrapper for the scanner plugin system.
    Scans a single file or directory path and returns findings.
    """
    return run_scanner(file_path)


def clean_for_json(obj, depth=0, max_depth=10):
    """
    Clean objects for JSON serialization.
    Removes circular references and non-serializable objects.
    """
    if depth > max_depth:
        return f"<Max depth {max_depth} reached>"
    
    if isinstance(obj, dict):
        # Remove parent references
        obj = {k: v for k, v in obj.items() if k not in ['__parent__', 'parent']}
        return {key: clean_for_json(value, depth+1, max_depth) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [clean_for_json(item, depth+1, max_depth) for item in obj]
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return str(obj)
    else:
        return obj


def format_findings_report(findings: List[Dict], output_format: str = 'json') -> str:
    """
    Format findings for different output formats.
    
    Args:
        findings: List of finding dictionaries
        output_format: 'json', 'text', or 'sarif'
        
    Returns:
        Formatted report string
    """
    if output_format == 'json':
        return json.dumps(findings, indent=2)
    
    elif output_format == 'text':
        if not findings:
            return "No violations found! ✓"
        
        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        output = []
        output.append("=" * 80)
        output.append(f"Docker Scanner Report - {len(findings)} violations found")
        output.append("=" * 80)
        
        severity_order = ['Critical', 'Major', 'Minor', 'Info', 'Unknown']
        
        for severity in severity_order:
            if severity not in by_severity:
                continue
            
            findings_list = by_severity[severity]
            output.append(f"\n{severity} ({len(findings_list)} findings):")
            output.append("-" * 80)
            
            for finding in findings_list:
                line = finding.get('line', '?')
                message = finding.get('message', 'Unknown issue')
                rule_id = finding.get('rule_id', 'unknown')
                instruction = finding.get('instruction', '')
                file = finding.get('file', '')
                
                output.append(f"\n  {file}:{line}")
                output.append(f"  {message}")
                output.append(f"  Rule: {rule_id}")
                if instruction:
                    output.append(f"  Instruction: {instruction}")
        
        output.append("\n" + "=" * 80)
        return "\n".join(output)
    
    elif output_format == 'sarif':
        # SARIF format for integration with tools
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Docker Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/yourusername/docker-scanner"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for finding in findings:
            result = {
                "ruleId": finding.get('rule_id', 'unknown'),
                "level": finding.get('severity', 'warning').lower(),
                "message": {
                    "text": finding.get('message', 'Unknown violation')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get('file', '')
                            },
                            "region": {
                                "startLine": finding.get('line', 1)
                            }
                        }
                    }
                ]
            }
            sarif['runs'][0]['results'].append(result)
        
        return json.dumps(sarif, indent=2)
    
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on core attributes."""
    return list(set(findings))


def main():
    """Main entry point for the Docker scanner."""
    if len(sys.argv) < 2:
        print("Usage: docker_scanner.py <input_path> [output_format]")
        print("  input_path: Path to Dockerfile or directory containing Dockerfiles")
        print("  output_format: json (default), text, or sarif")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_format = sys.argv[2].lower() if len(sys.argv) > 2 else "json"
    
    if not os.path.exists(input_path):
        print(f"Error: Path '{input_path}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Run the scanner
        findings = run_scanner(input_path)
        
        # Count files scanned
        files_scanned = len(get_all_dockerfiles(input_path))
        
        if output_format == 'json':
            # JSON output with metadata
            result = {
                "language": "docker",
                "files_scanned": files_scanned,
                "total_violations": len(findings),
                "findings": clean_for_json(findings)
            }
            print(json.dumps(result, indent=2))
        
        elif output_format == 'text':
            # Human-readable text output
            print(f"\nScanned {files_scanned} Dockerfile(s)\n")
            print(format_findings_report(findings, 'text'))
        
        elif output_format == 'sarif':
            # SARIF format output
            print(format_findings_report(findings, 'sarif'))
        
        else:
            print(f"Error: Unknown output format '{output_format}'", file=sys.stderr)
            sys.exit(1)
        
        # Exit with error code if violations found
        sys.exit(1 if len(findings) > 0 else 0)
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
