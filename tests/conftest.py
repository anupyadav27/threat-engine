"""
Pytest configuration and fixtures
"""
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Add engine_onboarding to path so internal imports work
engine_onboarding_path = os.path.join(project_root, "engine_onboarding")
sys.path.insert(0, engine_onboarding_path)
