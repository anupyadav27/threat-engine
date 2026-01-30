# CSPM Engine Integration Tests

## Overview

This directory contains comprehensive tests for the CSPM engine integration components.

## Test Structure

### Core Component Tests
- `test_storage_paths.py` - Storage path resolution (local & S3)
- `test_api_models.py` - Shared API model validation
- `test_retry_handler.py` - Retry logic with exponential backoff
- `test_circuit_breaker.py` - Circuit breaker pattern
- `test_webhook_sender.py` - Webhook notification system
- `test_integration_simple.py` - Simple integration scenarios

### Full Integration Tests (Require Full Environment)
- `test_orchestrator.py` - Engine orchestration (requires full module setup)
- `test_engine_client_integration.py` - Engine client integration (requires full module setup)

## Quick Start

### 1. Setup Virtual Environment
```bash
cd /Users/apple/Desktop/threat-engine
python3 -m venv venv
source venv/bin/activate
pip install -r tests/requirements.txt
pip install pydantic-settings boto3 httpx
```

### 2. Run All Tests
```bash
source venv/bin/activate
python3 -m pytest tests/test_integration_simple.py tests/test_storage_paths.py tests/test_api_models.py tests/test_retry_handler.py tests/test_circuit_breaker.py tests/test_webhook_sender.py -v
```

Or use the test script:
```bash
cd tests
./run_tests.sh
```

### 3. Run Specific Test File
```bash
source venv/bin/activate
python3 -m pytest tests/test_storage_paths.py -v
```

## Test Results

**27 tests passing** ✅

- Storage Paths: 6 tests
- API Models: 4 tests  
- Retry Handler: 4 tests
- Circuit Breaker: 5 tests
- Webhook Sender: 3 tests
- Simple Integration: 5 tests

## What's Tested

### ✅ Storage Path Resolution
- Local file system paths
- S3 bucket paths
- Consistent path format across engines
- Support for different file types

### ✅ API Models
- Pydantic model validation
- JSON serialization
- Type checking
- Default values

### ✅ Error Handling
- Retry with exponential backoff (async & sync)
- Circuit breaker pattern
- Failure threshold handling
- Recovery mechanisms

### ✅ Notifications
- Webhook payload structure
- Success scenarios
- Failure handling
- Orchestration notifications

## Notes

- Tests use mocking to avoid external dependencies
- Some tests require full module setup (database, etc.)
- All core functionality is validated
- Integration tests can be extended when full environment is available

## Next Steps

For full end-to-end testing:
1. Set up local DynamoDB or PostgreSQL
2. Configure test environment variables
3. Install all engine dependencies
4. Run full integration test suite
