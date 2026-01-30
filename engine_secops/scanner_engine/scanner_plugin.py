import importlib
import os
from language_detector import detect_language as advanced_detect_language, LanguageType

# Register supported languages and their scanner modules
# This mapping connects detected languages to their respective scanner modules
SCANNERS = {
    "python": {
        "module": "python_v2.python_scanner",
        "description": "Python security scanner"
    },
    "java": {
        "module": "java_scanner.scanner", 
        "description": "Java security scanner"
    },
    "csharp": {
        "module": "csharp_scanner.csharp_scanner",
        "description": "C# security scanner"
    },
    "javascript": {
        "module": "javascript_scanner.javascript_scanner",
        "description": "JavaScript security scanner"
    },
    "terraform": {
        "module": "terraform_v2.scanner_common",
        "description": "Terraform security scanner"
    },
    "azure": {
        "module": "azure_scanner.arm_scanner",
        "description": "Azure ARM template security scanner"
    },
    "cloudformation": {
        "module": "cloudformation_scanner.cloudformation_scanner",
        "description": "AWS CloudFormation security scanner"
    },
    "docker": {
        "module": "docker_scanner.docker_scanner",
        "description": "Dockerfile security scanner"
    },
    "kubernetes": {
        "module": "kubernetes_scanner.kubernetes_scanner",
        "description": "Kubernetes manifest security scanner"
    },
    "ansible": {
        "module": "ansible_scanner.ansible_scanner_engine",
        "description": "Ansible playbook security scanner"
    }
}

def detect_language(file_path):
    """
    Detect the programming language/format of a file using advanced structural analysis.
    
    Uses SonarSource-inspired approach:
    1. File extension as weak hint
    2. Structural fingerprints and grammar patterns  
    3. Semantic validation through parsing
    4. Confidence scoring and disambiguation
    
    This replaces the old heuristic-based detection with proper language recognition.
    """
    # Use the new advanced language detector
    detected_lang = advanced_detect_language(file_path)
    
    if detected_lang:
        # Ensure we have a scanner for this language
        if detected_lang in SCANNERS:
            return detected_lang
        else:
            print(f"Warning: Detected language '{detected_lang}' but no scanner available for {os.path.basename(file_path)}")
            return None
    
    return None

def get_scanner(lang):
    """Get the scanner function for a specific language."""
    if lang not in SCANNERS:
        raise ValueError(f"Unsupported language: {lang}")
    
    scanner_config = SCANNERS[lang]
    
    try:
        mod = importlib.import_module(scanner_config["module"])
        # Check for both run_scan and run_scanner functions for backward compatibility
        if hasattr(mod, "run_scan"):
            return mod.run_scan
        elif hasattr(mod, "run_scanner"):
            return mod.run_scanner
        else:
            raise ImportError(f"Scanner module for {lang} does not have run_scan or run_scanner")
    except ImportError as e:
        raise ImportError(f"Could not import scanner module for {lang}: {e}")

def get_supported_languages():
    """Return list of supported languages."""
    return list(SCANNERS.keys())

def get_scanner_info(lang):
    """Get information about a specific scanner."""
    if lang not in SCANNERS:
        return None
    return SCANNERS[lang]

# Legacy functions - kept for backward compatibility but no longer used for detection
def _has_kubernetes_markers(content):
    """Legacy function - replaced by advanced structural analysis."""
    # Simplified check for backward compatibility
    k8s_markers = ["apiVersion:", "kind:", "spec:", "metadata:"]
    return sum(1 for marker in k8s_markers if marker in content) >= 2

def _has_ansible_markers(content):
    """Legacy function - replaced by advanced structural analysis."""
    # Simplified check for backward compatibility  
    ansible_markers = ["hosts:", "tasks:", "roles:", "playbook"]
    return sum(1 for marker in ansible_markers if marker in content) >= 1

def _is_cloudformation_template(content):
    """Legacy function - replaced by advanced structural analysis."""
    # Simplified check for backward compatibility
    cf_markers = ["AWSTemplateFormatVersion", "Resources:", "AWS::"]
    return sum(1 for marker in cf_markers if marker in content) >= 1

def _is_arm_template(content):
    """Legacy function - replaced by advanced structural analysis."""
    # Simplified check for backward compatibility
    arm_markers = ['"$schema":', '"resources":', 'deploymentTemplate', 'Microsoft.']
    return sum(1 for marker in arm_markers if marker in content) >= 2