"""
AliCloud Compliance Engine - Entry Point

Run compliance checks against AliCloud infrastructure.
"""

import os

# Optional default concurrency; override via environment if needed
os.environ.setdefault("COMPLIANCE_ENGINE_MAX_WORKERS", "16")

from alicloud_compliance_python_engine.engine.alicloud_sdk_engine import main

if __name__ == "__main__":
    main()

