import os

# Optional default concurrency; override via environment if needed
os.environ.setdefault("COMPLIANCE_ENGINE_MAX_WORKERS", "16")

from aws_compliance_python_engine.engine.boto3_engine import main

if __name__ == "__main__":
    main() 