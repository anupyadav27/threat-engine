"""
Oracle Database credential validator.
"""
from typing import Any, Dict

from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult


class DBOracleValidator(BaseValidator):
    """Validates self-hosted Oracle Database credentials via a live connection."""

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Connect to Oracle DB and verify the connection is usable.

        Args:
            credentials: Must contain host, port, service_name, username,
                         password.

        Returns:
            ValidationResult with account_number set to 'host:port/service_name'.
        """
        required = ("host", "port", "service_name", "username", "password")
        missing = [k for k in required if not credentials.get(k)]
        if missing:
            return self._create_error_result(
                f"Missing required fields: {', '.join(missing)}",
                errors=[f"Field '{k}' is required" for k in missing],
            )

        host         = credentials["host"].strip()
        port         = int(credentials.get("port", 1521))
        service_name = credentials["service_name"].strip()
        username     = credentials["username"].strip()
        password     = credentials["password"]

        try:
            import oracledb
        except ImportError:
            return self._create_error_result(
                "oracledb is not installed in this environment",
                errors=["Install python-oracledb to validate Oracle credentials"],
            )

        dsn = f"{host}:{port}/{service_name}"

        try:
            conn = oracledb.connect(
                user=username,
                password=password,
                dsn=dsn,
            )
            cur = conn.cursor()
            cur.execute("SELECT banner FROM v$version WHERE rownum = 1")
            version_row = cur.fetchone()
            cur.close()
            conn.close()

            version = version_row[0].strip() if version_row else "unknown"
            account_number = f"{host}:{port}/{service_name}"
            return self._create_success_result(
                f"Connected successfully — {version}",
                account_number=account_number,
            )

        except oracledb.DatabaseError as e:
            return self._create_error_result(
                f"Connection failed: {e}",
                errors=[str(e)],
            )
        except Exception as e:
            return self._create_error_result(
                f"Unexpected error during validation: {e}",
                errors=[str(e)],
            )
