"""
Database connector factory.
Returns the right connector for each DB tech_type.
Sprint 1 implements each connector; this module wires them.
"""
from __future__ import annotations
from typing import Any, Dict, Optional


def get_db_connector(tech_type: str, credential: Dict[str, Any]) -> "BaseDBConnector":
    """Return the appropriate DB connector for the given tech_type."""
    tech_type = tech_type.lower()
    if tech_type == "postgres":
        from .postgres_connector import PostgresConnector
        return PostgresConnector(credential)
    if tech_type == "mysql":
        from .mysql_connector import MySQLConnector
        return MySQLConnector(credential)
    if tech_type == "mariadb":
        from .mariadb_connector import MariaDBConnector
        return MariaDBConnector(credential)
    if tech_type == "mssql":
        from .mssql_connector import MSSQLConnector
        return MSSQLConnector(credential)
    if tech_type == "mongodb":
        from .mongodb_connector import MongoDBConnector
        return MongoDBConnector(credential)
    if tech_type == "oracle":
        from .oracle_connector import OracleConnector
        return OracleConnector(credential)
    if tech_type == "cassandra":
        from .cassandra_connector import CassandraConnector
        return CassandraConnector(credential)
    if tech_type == "ibm_db2":
        from .ibm_db2_connector import IBMDB2Connector
        return IBMDB2Connector(credential)
    raise ValueError(f"Unsupported DB tech_type: {tech_type}")


class BaseDBConnector:
    """Abstract base for all DB connectors."""

    def __init__(self, credential: Dict[str, Any]) -> None:
        self.credential = credential
        self.host = credential.get("host", "")
        self.port = credential.get("port")
        self.dbname = credential.get("dbname", "")
        self.username = credential.get("username", "")
        self.password = credential.get("password", "")
        self._conn: Optional[Any] = None

    def connect(self) -> None:
        raise NotImplementedError

    def execute_query(self, query: str) -> list[dict]:
        raise NotImplementedError

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


class PostgresConnector(BaseDBConnector):
    """Sprint 1 — implement full connector using psycopg2."""

    def connect(self) -> None:
        import psycopg2
        import psycopg2.extras
        self._conn = psycopg2.connect(
            host=self.host, port=self.port or 5432,
            dbname=self.dbname, user=self.username, password=self.password,
            sslmode=self.credential.get("ssl_mode", "prefer"),
            connect_timeout=10,
        )
        self._conn.autocommit = True

    def execute_query(self, query: str) -> list[dict]:
        import psycopg2.extras
        with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query)
            return [dict(row) for row in (cur.fetchall() or [])]


class MySQLConnector(BaseDBConnector):
    """Sprint 1 — implement full connector using pymysql."""

    def connect(self) -> None:
        import pymysql
        import pymysql.cursors
        self._conn = pymysql.connect(
            host=self.host, port=self.port or 3306,
            database=self.dbname, user=self.username, password=self.password,
            connect_timeout=10, cursorclass=pymysql.cursors.DictCursor,
        )

    def execute_query(self, query: str) -> list[dict]:
        with self._conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchall() or []


class MariaDBConnector(MySQLConnector):
    """MariaDB uses the same protocol as MySQL."""


class MSSQLConnector(BaseDBConnector):
    """Sprint 1 — implement using pyodbc."""

    def connect(self) -> None:
        import pyodbc
        conn_str = (
            f"DRIVER={{ODBC Driver 18 for SQL Server}};"
            f"SERVER={self.host},{self.port or 1433};"
            f"DATABASE={self.dbname};UID={self.username};PWD={self.password};"
            "TrustServerCertificate=yes;Connection Timeout=10;"
        )
        self._conn = pyodbc.connect(conn_str)

    def execute_query(self, query: str) -> list[dict]:
        cur = self._conn.cursor()
        cur.execute(query)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in (cur.fetchall() or [])]


class MongoDBConnector(BaseDBConnector):
    """Sprint 1 — implement using pymongo."""

    def connect(self) -> None:
        import pymongo
        uri = self.credential.get("uri") or f"mongodb://{self.username}:{self.password}@{self.host}:{self.port or 27017}"
        self._client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=10_000)
        self._client.server_info()  # raises if unreachable

    def execute_query(self, query: str) -> list[dict]:
        # For MongoDB, query is a command dict or collection query — handled by scanner
        raise NotImplementedError("Use execute_command() for MongoDB")

    def execute_command(self, db_name: str, command: dict) -> dict:
        return self._client[db_name].command(command)

    def close(self) -> None:
        if hasattr(self, "_client"):
            self._client.close()


class OracleConnector(BaseDBConnector):
    """Sprint 1 — implement using oracledb."""

    def connect(self) -> None:
        import oracledb
        dsn = f"{self.host}:{self.port or 1521}/{self.credential.get('service_name', 'ORCL')}"
        self._conn = oracledb.connect(user=self.username, password=self.password, dsn=dsn)

    def execute_query(self, query: str) -> list[dict]:
        cur = self._conn.cursor()
        cur.execute(query)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in (cur.fetchall() or [])]


class CassandraConnector(BaseDBConnector):
    """Sprint 1 — implement using cassandra-driver."""

    def connect(self) -> None:
        from cassandra.cluster import Cluster
        from cassandra.auth import PlainTextAuthProvider
        auth = PlainTextAuthProvider(username=self.username, password=self.password)
        self._cluster = Cluster([self.host], port=self.port or 9042, auth_provider=auth)
        self._session = self._cluster.connect()

    def execute_query(self, query: str) -> list[dict]:
        rows = self._session.execute(query)
        return [row._asdict() for row in rows]

    def close(self) -> None:
        if hasattr(self, "_cluster"):
            self._cluster.shutdown()


class IBMDB2Connector(BaseDBConnector):
    """Sprint 1 — implement using ibm_db."""

    def connect(self) -> None:
        import ibm_db
        dsn = (
            f"DATABASE={self.dbname};HOSTNAME={self.host};PORT={self.port or 50000};"
            f"PROTOCOL=TCPIP;UID={self.username};PWD={self.password};"
        )
        self._conn = ibm_db.connect(dsn, "", "")

    def execute_query(self, query: str) -> list[dict]:
        import ibm_db
        stmt = ibm_db.exec_immediate(self._conn, query)
        rows = []
        row = ibm_db.fetch_assoc(stmt)
        while row:
            rows.append(row)
            row = ibm_db.fetch_assoc(stmt)
        return rows
