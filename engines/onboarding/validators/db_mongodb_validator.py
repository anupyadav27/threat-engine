"""
MongoDB credential validator.
"""
from typing import Any, Dict

from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult


class DBMongodbValidator(BaseValidator):
    """Validates self-hosted MongoDB credentials via a live connection."""

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Connect to MongoDB and verify the connection is usable.

        Args:
            credentials: Must contain uri (mongodb://host:port/dbname or
                         mongodb+srv://...).  username and password may be
                         embedded in the URI or provided separately.

        Returns:
            ValidationResult with account_number set to the host extracted
            from the URI.
        """
        uri = (credentials.get("uri") or "").strip()
        if not uri:
            return self._create_error_result(
                "Missing required field: uri",
                errors=["Field 'uri' is required (e.g. mongodb://host:27017/dbname)"],
            )

        try:
            import pymongo
            from pymongo.errors import ConnectionFailure, OperationFailure
        except ImportError:
            return self._create_error_result(
                "pymongo is not installed in this environment",
                errors=["Install pymongo to validate MongoDB credentials"],
            )

        try:
            client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=10_000)
            info = client.server_info()
            client.close()

            version   = info.get("version", "unknown")
            # Extract host for account_number (strip credentials from URI)
            from urllib.parse import urlparse
            parsed        = urlparse(uri)
            account_number = f"{parsed.hostname}:{parsed.port or 27017}"

            return self._create_success_result(
                f"Connected successfully — MongoDB {version}",
                account_number=account_number,
            )

        except ConnectionFailure as e:
            return self._create_error_result(
                f"Connection failed: {e}",
                errors=[str(e)],
            )
        except OperationFailure as e:
            return self._create_error_result(
                f"Authentication failed: {e}",
                errors=[str(e)],
            )
        except Exception as e:
            return self._create_error_result(
                f"Unexpected error during validation: {e}",
                errors=[str(e)],
            )
