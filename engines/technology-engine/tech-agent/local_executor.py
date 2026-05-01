"""
local_executor.py — Runs discovery locally on the host.

Dispatches each discovery entry to the appropriate transport:
- SQL techs     : connect to localhost DB, run SQL query
- SSH techs     : subprocess.run() — commands execute locally (agent IS the host)
- Docker        : subprocess or docker SDK
- PowerShell    : subprocess.run(["pwsh", "-Command", ...])
- MongoDB/Cassandra: native client to localhost

No raw config data leaves the host — only result dicts are returned.
"""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Transport groupings
SQL_TECHS = frozenset(
    {"postgresql", "mysql", "oracle_db", "ibm_db2", "sql_server", "mariadb"}
)
MONGO_TECHS = frozenset({"mongodb", "cassandra"})
SSH_TECHS = frozenset(
    {
        "ubuntu", "debian", "rhel", "centos", "suse", "alibaba_linux", "redhat",
        "apache_http", "nginx", "tomcat", "websphere",
        "vmware_esxi", "cisco_ios_xe", "cisco_asa", "palo_alto",
    }
)
DOCKER_TECHS = frozenset({"docker"})
POWERSHELL_TECHS = frozenset({"iis"})

COMMAND_TIMEOUT = 10  # seconds


class LocalExecutor:
    """Runs all discovery entries for a tech_type on the local host.

    Args:
        tech_type: Technology identifier, e.g. ``postgresql``, ``ubuntu``.
        credential: Optional dict of DB credentials for SQL transports.
            Keys: ``dbname``, ``username``, ``password``, ``port``.
            Defaults to environment variables when not provided.
    """

    def __init__(
        self,
        tech_type: str,
        credential: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._tech_type = tech_type.lower()
        self._credential = credential or {}

    # ── public API ────────────────────────────────────────────────────────────

    def run(self, discovery_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute all discovery entries and return results keyed by discovery_id.

        Args:
            discovery_entries: List of discovery entry dicts from the catalog.

        Returns:
            Dict mapping ``discovery_id`` to a raw result dict.
        """
        results: Dict[str, Any] = {}
        for entry in discovery_entries:
            disc_id = entry.get("discovery_id", "")
            if not disc_id:
                continue
            try:
                result = self._execute_entry(entry)
                results[disc_id] = result
            except Exception as exc:
                logger.warning("Entry %s failed: %s", disc_id, exc)
                results[disc_id] = {"error": str(exc)}
        return results

    # ── dispatch ──────────────────────────────────────────────────────────────

    def _execute_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one discovery entry to the correct transport."""
        if self._tech_type in SQL_TECHS:
            return self._run_sql_entry(entry)
        if self._tech_type in MONGO_TECHS:
            return self._run_mongo_entry(entry)
        if self._tech_type in SSH_TECHS:
            return self._run_command_entry(entry)
        if self._tech_type in DOCKER_TECHS:
            return self._run_docker_entry(entry)
        if self._tech_type in POWERSHELL_TECHS:
            return self._run_powershell_entry(entry)
        logger.warning("No transport for tech_type=%s, skipping", self._tech_type)
        return {"error": f"unsupported tech_type: {self._tech_type}"}

    # ── SQL transport ─────────────────────────────────────────────────────────

    def _run_sql_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a SQL discovery entry against the local DB instance."""
        sql = self._extract_sql(entry)
        if not sql:
            return {"error": "no sql found in entry"}

        conn = self._get_sql_connection()
        try:
            rows = self._execute_sql(conn, sql)
            if rows:
                return rows[0] if len(rows) == 1 else {"rows": rows}
            return {}
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _extract_sql(self, entry: Dict[str, Any]) -> str:
        """Extract SQL from entry.query, entry.sql, or first calls[].query."""
        sql = entry.get("query") or entry.get("sql") or ""
        if not sql:
            for call in entry.get("calls", []):
                if call.get("action") in ("query_setting", "query_table"):
                    sql = call.get("query") or call.get("sql") or ""
                    break
        return sql.strip()

    def _get_sql_connection(self) -> Any:
        """Create a local DB connection using env vars or credential dict."""
        cred = self._credential
        host = cred.get("host") or os.getenv("DB_HOST", "127.0.0.1")
        port_raw = cred.get("port") or os.getenv("DB_PORT", "5432")
        dbname = cred.get("dbname") or os.getenv("DB_NAME", "postgres")
        user = cred.get("username") or os.getenv("DB_USER", "postgres")
        password = cred.get("password") or os.getenv("DB_PASSWORD", "")

        if self._tech_type == "postgresql":
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(
                host=host, port=int(port_raw),
                dbname=dbname, user=user, password=password,
                connect_timeout=10,
            )
            conn.autocommit = True
            return conn

        if self._tech_type in ("mysql", "mariadb"):
            import pymysql
            import pymysql.cursors
            return pymysql.connect(
                host=host, port=int(port_raw),
                database=dbname, user=user, password=password,
                connect_timeout=10, cursorclass=pymysql.cursors.DictCursor,
            )

        if self._tech_type == "sql_server":
            import pymssql  # type: ignore
            return pymssql.connect(
                server=host, port=int(port_raw),
                database=dbname, user=user, password=password, timeout=10,
            )

        if self._tech_type == "oracle_db":
            import oracledb  # type: ignore
            dsn = f"{host}:{port_raw}/{cred.get('service_name', 'ORCL')}"
            return oracledb.connect(user=user, password=password, dsn=dsn)

        if self._tech_type == "ibm_db2":
            raise NotImplementedError("ibm_db2 requires ibm_db — connect manually")

        raise ValueError(f"No SQL driver for tech_type={self._tech_type!r}")

    def _execute_sql(self, conn: Any, sql: str) -> List[Dict[str, Any]]:
        """Run SQL and return list of row dicts."""
        if self._tech_type == "postgresql":
            import psycopg2.extras
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                return [dict(r) for r in (cur.fetchall() or [])]

        # pymysql / pymssql / oracledb — all expose .cursor()
        cur = conn.cursor()
        cur.execute(sql)
        raw = cur.fetchall() or []
        if raw and isinstance(raw[0], dict):
            return list(raw)
        cols = [d[0] for d in cur.description] if cur.description else []
        return [dict(zip(cols, row)) for row in raw]

    # ── MongoDB / Cassandra ───────────────────────────────────────────────────

    def _run_mongo_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Run a MongoDB discovery entry (basic server info)."""
        cred = self._credential
        host = cred.get("host") or os.getenv("DB_HOST", "127.0.0.1")
        port = int(cred.get("port") or os.getenv("DB_PORT", "27017"))

        import pymongo  # type: ignore

        uri = cred.get("uri") or f"mongodb://{host}:{port}"
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=10_000)
        try:
            info = client.server_info()
            return {"server_version": info.get("version"), "ok": info.get("ok", 0)}
        finally:
            client.close()

    # ── SSH / local command transport ─────────────────────────────────────────

    def _run_command_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Run a shell command locally (no SSH — agent IS on the host)."""
        command = self._extract_command(entry)
        if not command:
            return {"error": "no command found in entry"}

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )
            return {
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
                "returncode": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"error": "command timed out", "command": command}

    def _extract_command(self, entry: Dict[str, Any]) -> str:
        """Extract shell command from entry."""
        cmd = entry.get("command") or ""
        if not cmd:
            for call in entry.get("calls", []):
                if call.get("action") == "run_command":
                    cmd = call.get("command") or ""
                    break
        return cmd.strip()

    # ── Docker transport ──────────────────────────────────────────────────────

    def _run_docker_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Run a Docker discovery entry via CLI subprocess."""
        for call in entry.get("calls", []):
            if call.get("action") == "docker_api_call":
                endpoint = call.get("endpoint", "/info")
                return self._docker_api(endpoint)

        command = self._extract_command(entry)
        if command:
            return self._run_command_entry(entry)

        return self._docker_api("/info")

    def _docker_api(self, endpoint: str) -> Dict[str, Any]:
        """Call Docker via CLI (avoids SDK dependency on Alpine)."""
        cmd_map: Dict[str, str] = {
            "/info": "docker info --format '{{json .}}'",
            "/version": "docker version --format '{{json .}}'",
            "/containers/json": "docker ps --format '{{json .}}'",
        }
        cmd = cmd_map.get(endpoint, f"docker info --format '{{{{json .}}}}'")
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=COMMAND_TIMEOUT
        )
        return {"stdout": proc.stdout.strip(), "returncode": proc.returncode}

    # ── PowerShell transport ──────────────────────────────────────────────────

    def _run_powershell_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Run a PowerShell command via pwsh."""
        command = self._extract_command(entry)
        if not command:
            return {"error": "no command found in entry"}

        try:
            proc = subprocess.run(
                ["pwsh", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )
            return {
                "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(),
                "returncode": proc.returncode,
            }
        except FileNotFoundError:
            return {"error": "pwsh not found — PowerShell not installed"}
        except subprocess.TimeoutExpired:
            return {"error": "powershell command timed out"}
