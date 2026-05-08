"""
Microsoft SQL Server credential validator.
"""
from typing import Any, Dict

from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult


class DBMssqlValidator(BaseValidator):
    """Validates self-hosted SQL Server credentials via a live connection."""

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Connect to SQL Server and verify the connection is usable.

        Args:
            credentials: Must contain host, port, dbname, username, password.
                         instance is optional (named instance, e.g. SQLEXPRESS).
                         encrypt is optional boolean (defaults to True).

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
        port     = int(credentials.get("port", 1433))
        dbname   = credentials["dbname"].strip()
        username = credentials["username"].strip()
        password = credentials["password"]
        instance = credentials.get("instance", "").strip()
        encrypt  = "yes" if credentials.get("encrypt", True) else "no"

        server = f"{host}\\{instance},{port}" if instance else f"{host},{port}"

        try:
            import pyodbc
        except ImportError:
            return self._create_error_result(
                "pyodbc is not installed in this environment",
                errors=["Install pyodbc and the MSSQL ODBC driver to validate SQL Server credentials"],
            )

        # Try available ODBC drivers in preference order
        _DRIVERS = [
            "ODBC Driver 18 for SQL Server",
            "ODBC Driver 17 for SQL Server",
            "ODBC Driver 13 for SQL Server",
            "SQL Server",
        ]

        driver = None
        for d in _DRIVERS:
            if d in pyodbc.drivers():
                driver = d
                break

        if not driver:
            return self._create_error_result(
                "No suitable ODBC driver found for SQL Server",
                errors=[f"Available drivers: {pyodbc.drivers()}"],
            )

        conn_str = (
            f"DRIVER={{{driver}}};"
            f"SERVER={server};"
            f"DATABASE={dbname};"
            f"UID={username};"
            f"PWD={password};"
            f"Encrypt={encrypt};"
            "TrustServerCertificate=yes;"
            "Connection Timeout=10;"
        )

        try:
            conn = pyodbc.connect(conn_str)
            cur = conn.cursor()
            cur.execute("SELECT @@VERSION")
            version_row = cur.fetchone()
            cur.close()
            conn.close()

            version = version_row[0].split("\n")[0].strip() if version_row else "unknown"
            account_number = f"{host}:{port}/{dbname}"
            return self._create_success_result(
                f"Connected successfully — {version}",
                account_number=account_number,
            )

        except pyodbc.OperationalError as e:
            return self._create_error_result(
                f"Connection failed: {e}",
                errors=[str(e)],
            )
        except Exception as e:
            return self._create_error_result(
                f"Unexpected error during validation: {e}",
                errors=[str(e)],
            )
