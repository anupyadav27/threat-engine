#!/usr/bin/env python3
"""
OCI Compliance Engine - Main Entry Point
Runs compliance checks across all OCI services using YAML rule definitions
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set default max workers
os.environ.setdefault("COMPLIANCE_ENGINE_MAX_WORKERS", "8")

# Use enhanced OCI engine
from engine.enhanced_oci_engine import main

if __name__ == "__main__":
    main()
