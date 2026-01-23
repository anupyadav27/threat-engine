"""
Pytest configuration and fixtures
"""
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Add onboarding_engine to path so internal imports work
onboarding_engine_path = os.path.join(project_root, "onboarding_engine")
sys.path.insert(0, onboarding_engine_path)
