"""
IBM Cloud Compliance Engine - Entry Point
"""

import os

os.environ.setdefault("COMPLIANCE_ENGINE_MAX_WORKERS", "4")

# Use V2 engine with real SDK methods
from ibm_compliance_python_engine.engine.ibm_sdk_engine_v2 import main

if __name__ == "__main__":
    main()

