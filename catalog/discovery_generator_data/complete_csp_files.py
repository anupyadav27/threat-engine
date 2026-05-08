#!/usr/bin/env python3
"""
Complete CSP files generation script for IBM, OCI, and AliCloud
Generates dependency_index.json and direct_vars.json for services missing these files
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

def is_read_operation(op_name: str, csp: str = "aws") -> bool:
    """Check if operation is a read operation"""
    if csp == "ibm":
        # IBM uses operations like list_*, get_*
        return op_name.startswith(('list_', 'get_', 'describe_', 'search_', 'lookup_'))
    elif csp == "oci":
        # OCI uses operations like get_*, list_*
        return op_name.startswith(('get_', 'list_', 'describe_', 'search_', 'lookup_'))
    elif csp == "alicloud":
        # AliCloud uses operations like Describe*, List*, Get*
        return op_name.startswith(('Describe', 'List', 'Get', 'Search', 'Lookup'))
    else:
        # Default: List, Get, Describe, Search, Lookup
        return op_name.startswith(('List', 'Get', 'Describe', 'Search', 'Lookup'))

def camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def snake_to_camel(name: str) -> str:
    """Convert snake_case to CamelCase"""
    components = name.split('_')
    return ''.join(word.capitalize() for word in components)

def normalize_field_name(name: str) -> str:
    """Normalize field name for matching"""
    return re.sub(r'[_-]', '', name.lower())

