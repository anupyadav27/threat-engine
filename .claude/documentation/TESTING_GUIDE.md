# Testing Guide

> How to run tests, test structure, and writing new tests.

---

## Test Structure

```
tests/
├── conftest.py                     # Pytest configuration & fixtures
├── requirements.txt                # Test dependencies
├── run_all_tests.py                # Run all tests
├── run_all_integration_tests.sh    # Run integration tests
├── run_tests.sh                    # Quick test runner
│
├── test_api_gateway.py             # API Gateway tests
├── test_api_models.py              # Pydantic model tests
├── test_circuit_breaker.py         # Circuit breaker tests
├── test_consolidated_services.py   # DB service tests
├── test_e2e_workflows.py           # End-to-end workflows
├── test_engine_client_integration.py
├── test_integration_simple.py
├── test_migration_validation.py    # Schema migration tests
├── test_orchestrator.py            # Scan orchestrator tests
├── test_retry_handler.py           # Retry logic tests
├── test_storage_paths.py           # Storage path tests
├── test_webhook_sender.py          # Webhook tests
│
└── integration/                    # Integration test suites
    ├── test_check_engine/
    ├── test_compliance_engine/
    ├── test_discoveries_engine/
    ├── test_inventory_engine/
    ├── test_threat_engine/
    └── ...
```

---

## Running Tests

### Prerequisites

```bash
pip install -r tests/requirements.txt
```

### Run All Tests

```bash
# From repo root
python -m pytest tests/ -v

# Or use the test runner
python tests/run_all_tests.py
```

### Run Specific Test File

```bash
python -m pytest tests/test_api_gateway.py -v
```

### Run Specific Test Function

```bash
python -m pytest tests/test_api_gateway.py::test_health_endpoint -v
```

### Run Integration Tests

```bash
cd tests
bash run_all_integration_tests.sh
```

### Run with Coverage

```bash
python -m pytest tests/ --cov=engine_common --cov-report=html -v
```

---

## Test Categories

### Unit Tests
Test individual functions and classes without external dependencies.

```bash
python -m pytest tests/test_api_models.py -v
python -m pytest tests/test_circuit_breaker.py -v
python -m pytest tests/test_retry_handler.py -v
python -m pytest tests/test_storage_paths.py -v
```

### Integration Tests
Test engine interactions with databases and other services. Requires running PostgreSQL.

```bash
python -m pytest tests/test_consolidated_services.py -v
python -m pytest tests/test_engine_client_integration.py -v
```

### End-to-End Tests
Test full scan pipeline workflows.

```bash
python -m pytest tests/test_e2e_workflows.py -v
```

---

## Environment for Testing

### Local Testing (Mock DB)

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=postgres
export DB_PASSWORD=test_password
export LOG_LEVEL=DEBUG
```

### CI/CD Testing

```bash
# Use Docker Compose test environment
cd deployment
docker-compose -f docker-compose.test.yml up -d
python -m pytest tests/ -v
docker-compose -f docker-compose.test.yml down
```

---

## Writing New Tests

### Test File Naming
- Unit tests: `test_<module_name>.py`
- Integration tests: `tests/integration/test_<engine>/test_<feature>.py`

### Test Example

```python
import pytest
from unittest.mock import patch, MagicMock

class TestThreatDetector:
    """Tests for threat detector module."""

    def test_group_findings_by_resource(self):
        """Findings should be grouped by resource_uid."""
        findings = [
            {"resource_uid": "arn:aws:s3:::bucket1", "rule_id": "rule1"},
            {"resource_uid": "arn:aws:s3:::bucket1", "rule_id": "rule2"},
            {"resource_uid": "arn:aws:s3:::bucket2", "rule_id": "rule1"},
        ]
        grouped = group_findings(findings)
        assert len(grouped) == 2
        assert len(grouped["arn:aws:s3:::bucket1"]) == 2

    def test_risk_score_formula(self):
        """Risk score should follow the composite formula."""
        score = compute_risk_score(
            severity="high",
            blast_radius=4,
            mitre_impact=0.785,
            internet_reachable=False
        )
        # severity(0.8*40=32) + blast(0.4*25=10) + mitre(0.785*25=19.6) + reach(0)
        assert 55 <= score <= 65

    @patch('threat_engine.storage.threat_db_writer.get_db_connection')
    def test_save_to_database(self, mock_db):
        """Detections should be persisted to database."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__ = lambda s: mock_conn
        # ... test database writes
```

### Fixtures (conftest.py)

```python
@pytest.fixture
def sample_threat_detection():
    return {
        "detection_id": "test-uuid",
        "tenant_id": "test-tenant",
        "severity": "high",
        "resource_arn": "arn:aws:s3:::test-bucket",
        "mitre_techniques": ["T1190", "T1562"]
    }

@pytest.fixture
def db_connection():
    """Provide a test database connection."""
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        dbname="threat_engine_test"
    )
    yield conn
    conn.rollback()
    conn.close()
```
