---
paths:
  - "engine_*/**/*.py"
  - "consolidated_services/**/*.py"
  - "src/**/*.py"
---

# Python Code Standards

## Type Hints (Required)

All function arguments and return types must have type hints (PEP 484).

```python
from typing import List, Dict, Optional, Union, Any
from uuid import UUID

# ✅ CORRECT
def process_findings(
    scan_id: UUID,
    findings: List[Dict[str, Any]],
    severity_filter: Optional[str] = None
) -> Dict[str, int]:
    """Process findings and return summary statistics."""
    pass

# ❌ WRONG
def process_findings(scan_id, findings, severity_filter=None):
    pass
```

### Complex Types
```python
from typing import TypedDict, Literal, Protocol
from dataclasses import dataclass

# TypedDict for structured dicts
class Finding(TypedDict):
    finding_id: str
    severity: Literal["critical", "high", "medium", "low"]
    resource_arn: str
    status: str

# Dataclass for data containers
@dataclass
class ScanResult:
    scan_id: UUID
    findings: List[Finding]
    total_count: int
    critical_count: int

# Protocol for structural subtyping
class Scanner(Protocol):
    def scan(self, resource_id: str) -> ScanResult: ...
```

## Docstrings (Google Style)

All public functions, classes, and modules require docstrings.

```python
def discover_resources(
    provider: str,
    service: str,
    region: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Discover cloud resources from specified provider and service.

    This function enumerates all resources in the given service and region,
    applying optional filters to narrow the results. Results are returned
    as raw API responses in list format.

    Args:
        provider: Cloud provider identifier ('aws', 'azure', 'gcp', 'oci')
        service: Service name (e.g., 'ec2', 's3', 'rds')
        region: Optional AWS region (e.g., 'us-east-1'). If None, scans all regions.
        filters: Optional filter criteria as key-value pairs

    Returns:
        List of discovered resources as dictionaries with raw API response data

    Raises:
        AuthenticationError: If provider credentials are invalid
        ServiceNotSupportedError: If service is not implemented for provider
        RateLimitExceeded: If API rate limit is hit

    Example:
        >>> resources = discover_resources('aws', 's3', region='us-east-1')
        >>> len(resources)
        42
    """
    pass
```

## Imports Organization

Group imports in three sections (stdlib → third-party → local) and sort alphabetically within groups.

```python
# Standard library
import asyncio
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID, uuid4

# Third-party packages
import boto3
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, select

# Local application imports
from consolidated_services.database.config import get_db_connection
from engine_discoveries.scanner import AWSScanner, AzureScanner
from engine_discoveries.models import DiscoveryFinding
```

## Async/Await Patterns

Use async for I/O-bound operations (network calls, database queries).

```python
import asyncio
from typing import List
import httpx

async def fetch_resource(client: httpx.AsyncClient, url: str) -> dict:
    """Fetch single resource asynchronously."""
    response = await client.get(url)
    response.raise_for_status()
    return response.json()

async def fetch_all_resources(urls: List[str]) -> List[dict]:
    """Fetch multiple resources concurrently."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        tasks = [fetch_resource(client, url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        return [r for r in results if not isinstance(r, Exception)]
```

## Error Handling

Use specific exceptions, never bare `except:`.

```python
# ✅ CORRECT
from psycopg2 import OperationalError, DatabaseError
from fastapi import HTTPException

try:
    result = db.execute(query)
except OperationalError as e:
    logger.error(f"Database connection failed: {e}")
    raise HTTPException(status_code=503, detail="Database unavailable")
except DatabaseError as e:
    logger.error(f"Database error: {e}")
    raise HTTPException(status_code=500, detail="Internal database error")

# ❌ WRONG
try:
    result = db.execute(query)
except:
    print("Error occurred")
    raise
```

### Custom Exceptions
```python
class ThreatEngineError(Exception):
    """Base exception for threat engine errors."""
    pass

class DiscoveryError(ThreatEngineError):
    """Raised when resource discovery fails."""
    pass

class AuthenticationError(ThreatEngineError):
    """Raised when cloud provider authentication fails."""
    pass

class RateLimitExceeded(ThreatEngineError):
    """Raised when API rate limit is exceeded."""
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after} seconds")
```

## Pydantic Models (FastAPI)

Use Pydantic for request/response validation.

```python
from pydantic import BaseModel, Field, validator
from typing import List, Optional
from uuid import UUID
from datetime import datetime

class ScanRequest(BaseModel):
    """Request model for initiating a discovery scan."""

    provider: str = Field(..., description="Cloud provider (aws, azure, gcp)")
    account_id: str = Field(..., description="Cloud account identifier")
    services: List[str] = Field(default_factory=list, description="Services to scan")
    regions: List[str] = Field(default_factory=list, description="Regions to scan")

    @validator('provider')
    def validate_provider(cls, v):
        allowed = ['aws', 'azure', 'gcp', 'oci']
        if v not in allowed:
            raise ValueError(f"Provider must be one of {allowed}")
        return v

    class Config:
        schema_extra = {
            "example": {
                "provider": "aws",
                "account_id": "123456789012",
                "services": ["ec2", "s3", "rds"],
                "regions": ["us-east-1", "us-west-2"]
            }
        }

class ScanResponse(BaseModel):
    """Response model for scan operation."""

    scan_id: UUID = Field(..., description="Unique scan identifier")
    orchestration_id: UUID = Field(..., description="Orchestration tracking ID")
    status: str = Field(..., description="Scan status (queued, running, completed)")
    created_at: datetime = Field(..., description="Scan creation timestamp")

    class Config:
        orm_mode = True  # Allow Pydantic to work with SQLAlchemy models
```

## Logging

Use structured logging with appropriate levels.

```python
import logging
from uuid import UUID

logger = logging.getLogger(__name__)

def process_scan(scan_id: UUID) -> None:
    """Process discovery scan."""
    logger.info(f"Starting scan processing", extra={
        "scan_id": str(scan_id),
        "operation": "process_scan"
    })

    try:
        # Processing logic
        logger.debug(f"Retrieved {len(resources)} resources", extra={
            "scan_id": str(scan_id),
            "resource_count": len(resources)
        })

    except Exception as e:
        logger.error(f"Scan processing failed", extra={
            "scan_id": str(scan_id),
            "error": str(e),
            "error_type": type(e).__name__
        }, exc_info=True)
        raise

    logger.info(f"Scan processing completed", extra={
        "scan_id": str(scan_id),
        "duration_seconds": elapsed_time
    })
```

### Logging Levels
- **DEBUG**: Detailed diagnostic information
- **INFO**: General informational messages (scan started, completed)
- **WARNING**: Warning messages (deprecated features, fallbacks)
- **ERROR**: Error messages (failures that don't crash the app)
- **CRITICAL**: Critical errors (system-level failures)

## Code Formatting

Use **Black** for automatic formatting (4-space indentation, line length 100).

```bash
# Format code
black /Users/apple/Desktop/threat-engine/engine_discoveries/

# Check formatting
black --check /Users/apple/Desktop/threat-engine/engine_discoveries/
```

### Line Length
- **Max 100 characters** for code
- **Max 80 characters** for docstrings and comments
- Use parentheses for line continuation

```python
# ✅ CORRECT
result = some_function(
    very_long_argument_name="value",
    another_long_argument="another_value",
    yet_another_argument="yet_another_value"
)

# ❌ WRONG
result = some_function(very_long_argument_name="value", another_long_argument="another_value", yet_another_argument="yet_another_value")
```

## Testing

Write tests for all public functions using pytest.

```python
import pytest
from uuid import uuid4
from engine_discoveries.scanner import AWSScanner

@pytest.fixture
def aws_scanner():
    """Fixture providing configured AWS scanner."""
    return AWSScanner(
        account_id="123456789012",
        region="us-east-1",
        credentials={"role_arn": "arn:aws:iam::..."}
    )

def test_discover_ec2_instances(aws_scanner):
    """Test EC2 instance discovery returns expected structure."""
    results = aws_scanner.discover("ec2")

    assert isinstance(results, list)
    assert len(results) > 0

    instance = results[0]
    assert "InstanceId" in instance
    assert "InstanceType" in instance

@pytest.mark.asyncio
async def test_async_discovery():
    """Test asynchronous resource discovery."""
    scanner = AWSScanner(account_id="123456789012")
    results = await scanner.discover_async(["ec2", "s3", "rds"])

    assert len(results) == 3
    assert all(isinstance(r, list) for r in results)

def test_discovery_handles_rate_limit(aws_scanner, mocker):
    """Test scanner handles rate limit gracefully."""
    from botocore.exceptions import ClientError

    # Mock AWS client to raise rate limit error
    mocker.patch.object(
        aws_scanner.ec2_client,
        "describe_instances",
        side_effect=ClientError(
            {"Error": {"Code": "Throttling"}},
            "describe_instances"
        )
    )

    with pytest.raises(RateLimitExceeded):
        aws_scanner.discover("ec2")
```

## Configuration Management

Use Pydantic Settings for environment-based configuration.

```python
from pydantic import BaseSettings, PostgresDsn, validator
from typing import Optional

class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Database
    db_host: str
    db_port: int = 5432
    db_name: str
    db_user: str
    db_password: str
    database_url: Optional[PostgresDsn] = None

    @validator("database_url", pre=True)
    def assemble_db_url(cls, v, values):
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("db_user"),
            password=values.get("db_password"),
            host=values.get("db_host"),
            port=str(values.get("db_port")),
            path=f"/{values.get('db_name') or ''}"
        )

    # AWS
    aws_region: str = "us-east-1"
    aws_account_id: str

    # Application
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8001

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Usage
settings = Settings()
logger.setLevel(settings.log_level)
```

## Performance Best Practices

### List Comprehensions
```python
# ✅ Faster
resource_ids = [r["ResourceId"] for r in resources if r["Status"] == "active"]

# ❌ Slower
resource_ids = []
for r in resources:
    if r["Status"] == "active":
        resource_ids.append(r["ResourceId"])
```

### Generator Expressions for Large Data
```python
# ✅ Memory efficient
total = sum(r["Size"] for r in large_resource_list)

# ❌ Memory inefficient
total = sum([r["Size"] for r in large_resource_list])
```

### Use built-in functions
```python
# ✅ Fast
unique_ids = list(set(resource_ids))

# ❌ Slow
unique_ids = []
for rid in resource_ids:
    if rid not in unique_ids:
        unique_ids.append(rid)
```

## Important Notes
- Run `mypy` for type checking before committing
- Run `black` for formatting before committing
- Run `pylint` to catch code quality issues
- Write tests for new features and bug fixes
- Keep functions small and focused (< 50 lines)
- Avoid global variables
- Use context managers (`with` statements) for resource management
