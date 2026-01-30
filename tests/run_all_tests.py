"""
Run all local tests
"""
import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_all_tests():
    """Run all test files that can run locally"""
    test_files = [
        "tests/test_storage_paths.py",
        "tests/test_api_models.py",
        "tests/test_retry_handler.py",
        "tests/test_circuit_breaker.py",
        "tests/test_webhook_sender.py",
        "tests/test_integration_simple.py"
    ]
    
    # Run tests with verbose output
    exit_code = pytest.main(["-v", "--tb=short"] + test_files)
    return exit_code


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
