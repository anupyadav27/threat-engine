"""
MySQL / MariaDB credential validator.
"""
from typing import Any, Dict

from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult


class DBMysqlValidator(BaseValidator):
    """Validates self-hosted MySQL/MariaDB credentials via a live connection."""

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Connect to MySQL and verify the connection is usable.

        Args:
            credentials: Must contain host, port, dbname, username, password.
                         ssl is optional boolean (defaults to False).

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
        port     = int(credentials.get("port", 3306))
        dbname   = credentials["dbname"].strip()
        username = credentials["username"].strip()
        password = credentials["password"]
        use_ssl  = bool(credentials.get("ssl", False))

        try:
            import pymysql
        except ImportError:
            return self._create_error_result(
                "pymysql is not installed in this environment",
                errors=["Install pymysql to validate MySQL credentials"],
            )

        try:
            ssl_opts = {"ssl": {}} if use_ssl else {}
            conn = pymysql.connect(
                host=host,
                port=port,
                database=dbname,
                user=username,
                password=password,
                connect_timeout=10,
                **ssl_opts,
            )
            cur = conn.cursor()
            cur.execute("SELECT VERSION();")
            version_row = cur.fetchone()
            cur.close()
            conn.close()

            version = version_row[0] if version_row else "unknown"
            account_number = f"{host}:{port}/{dbname}"
            return self._create_success_result(
                f"Connected successfully — MySQL {version}",
                account_number=account_number,
            )

        except pymysql.OperationalError as e:
            return self._create_error_result(
                f"Connection failed: {e}",
                errors=[str(e)],
            )
        except Exception as e:
            return self._create_error_result(
                f"Unexpected error during validation: {e}",
                errors=[str(e)],
            )
