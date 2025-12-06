"""
OCI Compliance Engine - Entry Point

Run compliance checks against Oracle Cloud Infrastructure.
"""

import os

os.environ.setdefault("COMPLIANCE_ENGINE_MAX_WORKERS", "16")

from oci_compliance_python_engine.engine.oci_sdk_engine import main

if __name__ == "__main__":
    main()

