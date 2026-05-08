"""
PostgreSQL credential validator.
Connects to the target instance and runs a lightweight query to confirm
reachability and authentication before storing credentials.
"""
from typing import Any, Dict

from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult


class DBPostgresValidator(BaseValidator):
    """Validates self-hosted PostgreSQL credentials via a live connection."""

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Connect to PostgreSQL and verify the connection is usable.

        Args:
            credentials: Must contain host, port, dbname, username, password.
                         ssl_mode is optional (defaults to 'prefer').

        Returns:
            ValidationResult with account_number set to 'host:port/dbname'.
        """
        required = ("host", "port", "dbname", "username", "password")
        missing = [k for k in required if not credentials.get(k)]
        if missing:
            return self._create_error_result(
                f"Missing required fields: {', '.join(missing)}",
                errors=[f"Field '{k}' is required" for k in missing],
            )

        host     = credentials["host"].strip()
        port     = int(credentials.get("port", 5432))
        dbname   = credentials["dbname"].strip()
        username = credentials["username"].strip()
        password = credentials["password"]
        ssl_mode = credentials.get("ssl_mode", "prefer")

        try:
            import psycopg2
        except ImportError:
            return self._create_error_result(
                "psycopg2 is not installed in this environment",
                errors=["Install psycopg2-binary to validate PostgreSQL credentials"],
            )

        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                dbname=dbname,
                user=username,
                password=password,
                sslmode=ssl_mode,
                connect_timeout=10,
            )
            cur = conn.cursor()
            cur.execute("SELECT version();")
            version_row = cur.fetchone()
            cur.close()
            conn.close()

            version = version_row[0].split("\n")[0] if version_row else "unknown"
            account_number = f"{host}:{port}/{dbname}"
            return self._create_success_result(
                f"Connected successfully — {version}",
                account_number=account_number,
            )

        except psycopg2.OperationalError as e:
            return self._create_error_result(
                f"Connection failed: {e}",
                errors=[str(e)],
            )
        except Exception as e:
            return self._create_error_result(
                f"Unexpected error during validation: {e}",
                errors=[str(e)],
            )
