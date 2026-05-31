"""
tech-ciem — K8s Job entry point.

Pulls live session and statistics data from each target technology
and runs 10 MITRE ATT&CK–mapped detectors.

Log sources by tech_type:
  postgres  → pg_stat_activity, pg_stat_database, pg_roles, pg_auth_members
              + pgaudit log table (if pgaudit installed and log_destination=csvlog)
  mysql     → information_schema.PROCESSLIST,
              performance_schema.events_statements_history_long,
              performance_schema.accounts
  others    → stub (empty events list, Sprint 5+)

Usage::

    python run_ciem.py \\
        --scan-run-id 337a7425-... \\
        --account-id acct_abc123

CIEM_LOOKBACK_HOURS env var controls analysis window (default 24 h).
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from common.database.tech_db_manager import TechDBManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("tech_ciem")

LOOKBACK_HOURS = int(os.getenv("CIEM_LOOKBACK_HOURS", "24"))

# ── CIEM rule definitions ────────────────────────────────────────────────────
CIEM_RULES: List[Tuple[str, str, str, str, str, str]] = [
    ("TCIEM-001", "T1110", "Credential Access",   "high",     "Brute force / failed login spike",          "detect_brute_force"),
    ("TCIEM-002", "T1078", "Initial Access",       "critical", "Login from unexpected external IP",         "detect_external_ip_login"),
    ("TCIEM-003", "T1068", "Privilege Escalation", "critical", "New superuser role granted",                "detect_new_superuser"),
    ("TCIEM-004", "T1078", "Persistence",          "high",     "Login outside business hours (22-06 UTC)",  "detect_off_hours_login"),
    ("TCIEM-005", "T1562", "Defense Evasion",      "high",     "Audit config / ACL modification",          "detect_acl_change"),
    ("TCIEM-006", "T1552", "Credential Access",    "critical", "Mass export / credential dump query",      "detect_mass_export"),
    ("TCIEM-007", "T1098", "Persistence",          "high",     "Admin/superuser role grant",               "detect_admin_grant"),
    ("TCIEM-008", "T1530", "Collection",           "high",     "Bulk data read (high row count query)",    "detect_data_exfiltration"),
    ("TCIEM-009", "T1611", "Privilege Escalation", "critical", "Session running as OS-level root / sudo", "detect_root_session"),
    ("TCIEM-010", "T1490", "Impact",               "critical", "DB shutdown / DROP DATABASE command",      "detect_destructive_command"),
]

_BRUTE_ROLLBACK_THRESHOLD = 50   # xact_rollback spike vs baseline
_BRUTE_SESSION_THRESHOLD  = 5    # same actor, many sessions
_HIGH_ROW_THRESHOLD       = 10_000  # rows fetched in one query (MySQL PS)


def _finding_id(rule_id: str, actor: str, scan_run_id: str) -> str:
    return hashlib.sha256(f"{rule_id}|{actor}|{scan_run_id}".encode()).hexdigest()[:16]


def _make_finding(
    rule_id: str, mitre_technique: str, mitre_tactic: str, severity: str,
    account: Dict[str, Any], scan_run_id: str,
    actor: str, source_ip: Optional[str],
    event_time: Optional[datetime], evidence: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "finding_id":      _finding_id(rule_id, actor, scan_run_id),
        "scan_run_id":     scan_run_id,
        "tenant_id":       account.get("tenant_id", ""),
        "account_id":      account["account_id"],
        "credential_ref":  account.get("credential_ref"),
        "credential_type": account.get("credential_type"),
        "provider":        account.get("tech_type", account.get("provider", "")),
        "tech_category":   account.get("tech_category", ""),
        "region":          f"{account.get('host','')}:{account.get('port','')}",
        "resource_uid":    f"{account['account_id']}:{actor}",
        "resource_type":   "auth_event",
        "rule_id":         rule_id,
        "mitre_technique": mitre_technique,
        "mitre_tactic":    mitre_tactic,
        "actor":           actor,
        "source_ip":       source_ip,
        "event_time":      event_time.isoformat() if isinstance(event_time, datetime) else event_time,
        "severity":        severity,
        "status":          "open",
        "evidence":        evidence,
    }


# ── log source collectors ────────────────────────────────────────────────────

def _collect_postgres(credential: Dict[str, Any], since: datetime) -> Dict[str, Any]:
    """
    Returns a structured snapshot from PostgreSQL system catalogs.
    Keys: sessions, db_stats, superusers, role_grants, pgaudit_events
    """
    data: Dict[str, Any] = {
        "sessions":             [],
        "db_stats":             [],
        "superusers":           [],
        "role_grants":          [],
        "pgaudit_events":       [],
        "_expected_superusers": {"postgres"},
    }
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor

        conn = psycopg2.connect(
            host            = credential["host"],
            port            = int(credential.get("port", 5432)),
            dbname          = credential.get("dbname", "postgres"),
            user            = credential["username"],
            password        = credential["password"],
            connect_timeout = 10,
        )
        conn.autocommit = True

        with conn.cursor(cursor_factory=RealDictCursor) as cur:

            # 1 — active sessions
            cur.execute("""
                SELECT pid, usename, client_addr::text AS source_ip,
                       backend_start, state, application_name,
                       EXTRACT(EPOCH FROM (NOW() - backend_start))::int AS age_seconds,
                       left(query, 500) AS current_query
                FROM   pg_stat_activity
                WHERE  pid <> pg_backend_pid()
                  AND  backend_start > %s
                ORDER  BY backend_start
            """, (since,))
            data["sessions"] = [dict(r) for r in cur.fetchall()]

            # 2 — db-level stats (connection count, rollbacks, deadlocks)
            cur.execute("""
                SELECT datname, numbackends, xact_commit, xact_rollback,
                       deadlocks, temp_files, blks_hit, blks_read
                FROM   pg_stat_database
                WHERE  datname NOT IN ('template0', 'template1')
            """)
            data["db_stats"] = [dict(r) for r in cur.fetchall()]

            # 3 — current superusers
            cur.execute("""
                SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin
                FROM   pg_roles
                WHERE  rolsuper = true
                ORDER  BY rolname
            """)
            data["superusers"] = [dict(r) for r in cur.fetchall()]

            # 4 — role memberships (detect new admin grants)
            cur.execute("""
                SELECT r.rolname, m.rolname AS member, a.admin_option
                FROM   pg_auth_members a
                JOIN   pg_roles r ON r.oid = a.roleid
                JOIN   pg_roles m ON m.oid = a.member
                WHERE  r.rolsuper = true OR r.rolcreaterole = true
            """)
            data["role_grants"] = [dict(r) for r in cur.fetchall()]

            # 5 — pgaudit events (only if pgaudit is installed + log_destination=csvlog)
            try:
                cur.execute("""
                    SELECT installed_version
                    FROM   pg_available_extensions
                    WHERE  name = 'pgaudit' AND installed_version IS NOT NULL
                """)
                if cur.fetchone():
                    # pgaudit installed — check if audit_log table exists (custom setups)
                    cur.execute("""
                        SELECT table_name FROM information_schema.tables
                        WHERE  table_schema = 'public'
                          AND  table_name IN ('pgaudit_log', 'audit_log', 'pg_audit_log')
                        LIMIT  1
                    """)
                    tbl = cur.fetchone()
                    if tbl:
                        tname = tbl["table_name"]
                        cur.execute(f"""
                            SELECT * FROM {tname}
                            WHERE  log_time > %s
                            LIMIT  1000
                        """, (since,))
                        data["pgaudit_events"] = [dict(r) for r in cur.fetchall()]
                        logger.info("pgaudit events fetched from %s: %d", tname, len(data["pgaudit_events"]))
            except Exception as pgaudit_exc:
                logger.debug("pgaudit query skipped: %s", pgaudit_exc)

        conn.close()
        logger.info(
            "Postgres log snapshot: sessions=%d db_stats=%d superusers=%d",
            len(data["sessions"]), len(data["db_stats"]), len(data["superusers"]),
        )
    except Exception as exc:
        logger.warning("Postgres log collection failed: %s", exc)

    return data


def _collect_mysql(credential: Dict[str, Any], since: datetime) -> Dict[str, Any]:
    """
    Returns structured log data from MySQL performance_schema and information_schema.
    Keys: sessions, stmt_history, account_stats
    """
    data: Dict[str, Any] = {
        "sessions":             [],
        "stmt_history":         [],
        "account_stats":        [],
        "_expected_superusers": {"root"},
    }
    try:
        import pymysql
        conn = pymysql.connect(
            host            = credential["host"],
            port            = int(credential.get("port", 3306)),
            db              = credential.get("dbname", "mysql"),
            user            = credential["username"],
            password        = credential["password"],
            connect_timeout = 10,
            cursorclass     = pymysql.cursors.DictCursor,
        )
        with conn.cursor() as cur:

            # 1 — active sessions
            cur.execute("""
                SELECT id AS pid, user AS usename, host AS source_ip,
                       db, command, time AS age_seconds, state,
                       left(info, 500) AS current_query
                FROM   information_schema.PROCESSLIST
                WHERE  user != 'event_scheduler'
            """)
            data["sessions"] = list(cur.fetchall())

            # 2 — recent statement history (performance_schema)
            try:
                cur.execute("""
                    SELECT event_id, thread_id, event_name,
                           sql_text, digest_text, rows_sent, rows_examined,
                           execution_engine
                    FROM   performance_schema.events_statements_history_long
                    ORDER  BY event_id DESC
                    LIMIT  500
                """)
                data["stmt_history"] = list(cur.fetchall())
            except Exception:
                pass  # performance_schema may be disabled

            # 3 — per-account connection stats
            try:
                cur.execute("""
                    SELECT user, host, current_connections,
                           total_connections, total_ssl_connections
                    FROM   performance_schema.accounts
                    WHERE  user IS NOT NULL
                    ORDER  BY total_connections DESC
                    LIMIT  50
                """)
                data["account_stats"] = list(cur.fetchall())
            except Exception:
                pass

        conn.close()
        logger.info("MySQL log snapshot: sessions=%d stmt_history=%d", len(data["sessions"]), len(data["stmt_history"]))
    except Exception as exc:
        logger.warning("MySQL log collection failed: %s", exc)

    return data


def _collect_oracle(credential: Dict[str, Any], since: datetime) -> Dict[str, Any]:
    """
    Returns structured audit data from Oracle via V$SESSION, DBA_AUDIT_TRAIL,
    DBA_ROLE_PRIVS, and V$SQLAREA.
    Keys: sessions, db_stats, superusers, role_grants, stmt_history
    """
    data: Dict[str, Any] = {
        "sessions":             [],
        "db_stats":             [],
        "superusers":           [],
        "role_grants":          [],
        "stmt_history":         [],
        "_expected_superusers": {"SYS", "SYSTEM"},
    }
    try:
        try:
            import oracledb as ora
        except ImportError:
            import cx_Oracle as ora  # type: ignore[import]

        dsn = f"{credential['host']}:{int(credential.get('port', 1521))}/{credential.get('dbname', credential.get('service_name', 'ORCL'))}"
        conn = ora.connect(user=credential["username"], password=credential["password"], dsn=dsn)

        def _rows(cur: Any) -> List[Dict[str, Any]]:
            cols = [d[0].lower() for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

        with conn.cursor() as cur:
            # 1 — active sessions
            cur.execute("""
                SELECT s.sid              AS pid,
                       s.username         AS usename,
                       s.machine          AS source_ip,
                       s.logon_time       AS backend_start,
                       s.status           AS state,
                       s.program          AS application_name,
                       SUBSTR(NVL(q.sql_text, s.sql_id), 1, 500) AS current_query
                FROM   v$session s
                LEFT   JOIN v$sqlarea q ON s.sql_id = q.sql_id
                WHERE  s.username IS NOT NULL
            """)
            data["sessions"] = _rows(cur)

            # 2 — failed logins as brute-force proxy (xact_rollback equivalent)
            try:
                cur.execute("""
                    SELECT NVL(username, 'unknown') AS datname,
                           COUNT(*) AS xact_rollback
                    FROM   dba_audit_trail
                    WHERE  returncode != 0
                    GROUP  BY username
                """)
                data["db_stats"] = _rows(cur)
            except Exception:
                pass  # requires AUDIT_ADMIN or AUDIT_VIEWER privilege

            # 3 — DBA / SYSDBA / SYSOPER holders (superusers)
            cur.execute("""
                SELECT DISTINCT grantee AS rolname, 1 AS rolsuper
                FROM   dba_role_privs
                WHERE  granted_role IN ('DBA', 'SYSDBA', 'SYSOPER')
            """)
            data["superusers"] = _rows(cur)

            # 4 — role grants for privileged roles
            cur.execute("""
                SELECT granted_role AS rolname,
                       grantee      AS member,
                       CASE admin_option WHEN 'YES' THEN 1 ELSE 0 END AS admin_option
                FROM   dba_role_privs
                WHERE  granted_role IN ('DBA', 'SYSDBA', 'SYSOPER')
            """)
            data["role_grants"] = _rows(cur)

            # 5 — recent SQL (statement history)
            try:
                cur.execute("""
                    SELECT sql_text,
                           executions,
                           rows_processed    AS rows_sent,
                           parsing_user_id   AS thread_id
                    FROM   (
                        SELECT sql_text, executions, rows_processed,
                               parsing_user_id
                        FROM   v$sqlarea
                        ORDER  BY last_active_time DESC
                    )
                    WHERE  ROWNUM <= 500
                """)
                data["stmt_history"] = _rows(cur)
            except Exception:
                pass

        conn.close()
        logger.info(
            "Oracle log snapshot: sessions=%d superusers=%d",
            len(data["sessions"]), len(data["superusers"]),
        )
    except Exception as exc:
        logger.warning("Oracle log collection failed: %s", exc)

    return data


def _collect_mssql(credential: Dict[str, Any], since: datetime) -> Dict[str, Any]:
    """
    Returns structured audit data from SQL Server via sys.dm_exec_sessions,
    sys.server_principals, sys.server_role_members, and sys.dm_exec_query_stats.
    Keys: sessions, db_stats, superusers, role_grants, stmt_history
    """
    data: Dict[str, Any] = {
        "sessions":             [],
        "db_stats":             [],
        "superusers":           [],
        "role_grants":          [],
        "stmt_history":         [],
        "_expected_superusers": {"sa"},
    }
    try:
        import pymssql  # type: ignore[import]

        conn = pymssql.connect(
            server          = credential["host"],
            port            = int(credential.get("port", 1433)),
            user            = credential["username"],
            password        = credential["password"],
            database        = credential.get("dbname", "master"),
            login_timeout   = 10,
            as_dict         = True,
        )
        with conn.cursor(as_dict=True) as cur:

            # 1 — active sessions with current query text
            cur.execute("""
                SELECT s.session_id   AS pid,
                       s.login_name   AS usename,
                       s.host_name    AS source_ip,
                       s.login_time   AS backend_start,
                       s.status       AS state,
                       s.program_name AS application_name,
                       LEFT(CAST(t.text AS NVARCHAR(MAX)), 500) AS current_query
                FROM   sys.dm_exec_sessions s
                OUTER  APPLY sys.dm_exec_sql_text(s.most_recent_sql_handle) t
                WHERE  s.is_user_process = 1
                  AND  s.login_time > %s
            """, (since,))
            data["sessions"] = list(cur.fetchall())

            # 2 — failed logins from security ring buffer (SQL Server 2008+)
            try:
                cur.execute("""
                    SELECT
                        CONVERT(xml, record).value(
                            '(./Record/LoginTracker/LoginName)[1]', 'nvarchar(256)'
                        ) AS datname,
                        COUNT(*) AS xact_rollback
                    FROM   sys.dm_os_ring_buffers
                    WHERE  ring_buffer_type = N'RING_BUFFER_SECURITY_ERROR'
                    GROUP  BY CONVERT(xml, record).value(
                        '(./Record/LoginTracker/LoginName)[1]', 'nvarchar(256)'
                    )
                """)
                data["db_stats"] = list(cur.fetchall())
            except Exception:
                pass

            # 3 — sysadmin members (superusers)
            cur.execute("""
                SELECT p.name AS rolname, 1 AS rolsuper
                FROM   sys.server_principals p
                WHERE  p.type IN ('S', 'U', 'G')
                  AND  IS_SRVROLEMEMBER('sysadmin', p.name) = 1
            """)
            data["superusers"] = list(cur.fetchall())

            # 4 — privileged role memberships
            cur.execute("""
                SELECT r.name AS rolname,
                       m.name AS member,
                       0      AS admin_option
                FROM   sys.server_role_members rm
                JOIN   sys.server_principals r ON r.principal_id = rm.role_principal_id
                JOIN   sys.server_principals m ON m.principal_id = rm.member_principal_id
                WHERE  r.name IN ('sysadmin', 'securityadmin', 'dbcreator', 'processadmin')
            """)
            data["role_grants"] = list(cur.fetchall())

            # 5 — recent query stats
            try:
                cur.execute("""
                    SELECT TOP 500
                           LEFT(t.text, 500) AS sql_text,
                           CAST(qs.total_rows / NULLIF(qs.execution_count, 0) AS BIGINT) AS rows_sent,
                           CAST(qs.plan_handle AS NVARCHAR(128)) AS thread_id
                    FROM   sys.dm_exec_query_stats qs
                    CROSS  APPLY sys.dm_exec_sql_text(qs.sql_handle) t
                    WHERE  qs.last_execution_time > %s
                    ORDER  BY qs.last_execution_time DESC
                """, (since,))
                data["stmt_history"] = list(cur.fetchall())
            except Exception:
                pass

        conn.close()
        logger.info(
            "MSSQL log snapshot: sessions=%d superusers=%d",
            len(data["sessions"]), len(data["superusers"]),
        )
    except Exception as exc:
        logger.warning("MSSQL log collection failed: %s", exc)

    return data


def _collect_mongodb(credential: Dict[str, Any], since: datetime) -> Dict[str, Any]:
    """
    Returns structured audit data from MongoDB via currentOp, usersInfo,
    and system.profile (when profiling is enabled).
    Keys: sessions, db_stats, superusers, role_grants, stmt_history
    """
    data: Dict[str, Any] = {
        "sessions":             [],
        "db_stats":             [],
        "superusers":           [],
        "role_grants":          [],
        "stmt_history":         [],
        "_expected_superusers": {"admin"},
    }
    try:
        import pymongo  # type: ignore[import]

        client = pymongo.MongoClient(
            host                        = credential["host"],
            port                        = int(credential.get("port", 27017)),
            username                    = credential["username"],
            password                    = credential["password"],
            authSource                  = credential.get("dbname", "admin"),
            serverSelectionTimeoutMS    = 10_000,
        )
        admin_db = client["admin"]

        # 1 — current operations (sessions equivalent)
        try:
            current_op = admin_db.command("currentOp", {"$all": True})
            for op in current_op.get("inprog", []):
                client_str  = op.get("client", "") or ""
                source_ip   = client_str.split(":")[0] if client_str else ""
                users       = op.get("effectiveUsers") or []
                usename     = users[0].get("user", "unknown") if users else op.get("user", "unknown")
                app_name    = (op.get("client_metadata") or {}).get("application", {}).get("name", "")
                data["sessions"].append({
                    "pid":              op.get("opid"),
                    "usename":          usename,
                    "source_ip":        source_ip,
                    "backend_start":    op.get("currentOpTime"),
                    "state":            op.get("type", ""),
                    "application_name": app_name,
                    "current_query":    str(op.get("command", op.get("op", "")))[:500],
                })
        except Exception as exc:
            logger.debug("MongoDB currentOp failed: %s", exc)

        # 2 — users with admin roles (superusers + role_grants)
        _ADMIN_ROLES = {"root", "dbAdminAnyDatabase", "userAdminAnyDatabase", "clusterAdmin"}
        try:
            users_info = admin_db.command("usersInfo")
            for user in users_info.get("users", []):
                uname = user.get("user", "unknown")
                roles = [r.get("role", "") for r in user.get("roles", [])]
                if any(r in _ADMIN_ROLES for r in roles):
                    data["superusers"].append({"rolname": uname, "rolsuper": 1})
                    for role in roles:
                        if role in _ADMIN_ROLES:
                            data["role_grants"].append({
                                "rolname":      role,
                                "member":       uname,
                                "admin_option": 0,
                            })
        except Exception as exc:
            logger.debug("MongoDB usersInfo failed: %s", exc)

        # 3 — system.profile (only when profiling level > 0)
        try:
            if admin_db.profiling_level() > 0:
                for rec in client["admin"]["system.profile"].find(
                    {"ts": {"$gt": since}},
                    limit=500,
                    sort=[("ts", pymongo.DESCENDING)],
                ):
                    data["stmt_history"].append({
                        "sql_text":  str(rec.get("command", rec.get("ns", "")))[:500],
                        "rows_sent": rec.get("nreturned", 0),
                        "thread_id": str(rec.get("client", "")),
                    })
        except Exception:
            pass

        client.close()
        logger.info(
            "MongoDB log snapshot: sessions=%d superusers=%d",
            len(data["sessions"]), len(data["superusers"]),
        )
    except Exception as exc:
        logger.warning("MongoDB log collection failed: %s", exc)

    return data


def _collect_cassandra(credential: Dict[str, Any], since: datetime) -> Dict[str, Any]:
    """
    Returns role and privilege data from Cassandra via system_auth keyspace.
    Sessions and statement history are not exposed in OSS Cassandra.
    Keys: sessions (empty), db_stats (empty), superusers, role_grants, stmt_history (empty)
    """
    data: Dict[str, Any] = {
        "sessions":             [],
        "db_stats":             [],
        "superusers":           [],
        "role_grants":          [],
        "stmt_history":         [],
        "_expected_superusers": {"cassandra"},
    }
    try:
        from cassandra.cluster import Cluster  # type: ignore[import]
        from cassandra.auth import PlainTextAuthProvider  # type: ignore[import]

        auth    = PlainTextAuthProvider(
            username=credential["username"],
            password=credential["password"],
        )
        cluster = Cluster(
            contact_points  = [credential["host"]],
            port            = int(credential.get("port", 9042)),
            auth_provider   = auth,
            connect_timeout = 10,
        )
        session = cluster.connect()

        # 1 — superuser roles and collect names for membership filter
        superuser_roles: set = set()
        rows = session.execute("SELECT role, is_superuser, can_login FROM system_auth.roles")
        for row in rows:
            if row.is_superuser:
                superuser_roles.add(row.role)
                data["superusers"].append({"rolname": row.role, "rolsuper": 1})

        # 2 — role memberships scoped to superuser roles
        try:
            rows = session.execute("SELECT role, member_of FROM system_auth.role_members")
            for row in rows:
                if row.member_of in superuser_roles:
                    data["role_grants"].append({
                        "rolname":      row.member_of,
                        "member":       row.role,
                        "admin_option": 0,
                    })
        except Exception:
            pass

        cluster.shutdown()
        logger.info(
            "Cassandra log snapshot: superusers=%d role_grants=%d",
            len(data["superusers"]), len(data["role_grants"]),
        )
    except Exception as exc:
        logger.warning("Cassandra log collection failed: %s", exc)

    return data


def _collect_events(tech_type: str, credential: Dict[str, Any], since: datetime) -> Optional[Dict[str, Any]]:
    """Dispatch to the right collector. Returns None for unknown tech types."""
    if tech_type == "postgres":
        return _collect_postgres(credential, since)
    if tech_type in ("mysql", "mariadb"):
        return _collect_mysql(credential, since)
    if tech_type == "oracle_db":
        return _collect_oracle(credential, since)
    if tech_type == "sql_server":
        return _collect_mssql(credential, since)
    if tech_type == "mongodb":
        return _collect_mongodb(credential, since)
    if tech_type == "cassandra":
        return _collect_cassandra(credential, since)
    logger.warning("tech-ciem: no collector implemented for tech_type=%s", tech_type)
    return None


# ── detectors ────────────────────────────────────────────────────────────────

def detect_brute_force(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-001: Spike in xact_rollback (Postgres) or high connection count (MySQL)."""
    findings: List[Dict[str, Any]] = []

    # Postgres: flag DBs where rollback > threshold (proxy for auth failures)
    for stat in data.get("db_stats", []):
        rollbacks = stat.get("xact_rollback", 0) or 0
        if rollbacks > _BRUTE_ROLLBACK_THRESHOLD:
            findings.append(_make_finding(
                "TCIEM-001", "T1110", "Credential Access", "high",
                account, scan_run_id,
                actor    = stat.get("datname", "unknown_db"),
                source_ip = None,
                event_time = None,
                evidence  = {"xact_rollback": rollbacks, "threshold": _BRUTE_ROLLBACK_THRESHOLD, "datname": stat.get("datname")},
            ))

    # MySQL: flag accounts with unusually high total_connections
    from collections import Counter
    session_actors = Counter(s.get("usename") or s.get("user") for s in data.get("sessions", []))
    for actor, count in session_actors.items():
        if actor and count >= _BRUTE_SESSION_THRESHOLD:
            findings.append(_make_finding(
                "TCIEM-001", "T1110", "Credential Access", "high",
                account, scan_run_id, actor=actor, source_ip=None, event_time=None,
                evidence={"session_count": count, "threshold": _BRUTE_SESSION_THRESHOLD},
            ))

    return findings


def detect_external_ip_login(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-002: Session from non-RFC1918 IP."""
    _PRIVATE = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                 "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                 "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
                 "127.", "::1", "")
    findings: List[Dict[str, Any]] = []
    for s in data.get("sessions", []):
        ip  = str(s.get("source_ip") or s.get("host") or "")
        ip  = ip.split(":")[0]  # strip port from MySQL host field
        actor = s.get("usename") or s.get("user") or "unknown"
        if ip and not any(ip.startswith(p) for p in _PRIVATE):
            findings.append(_make_finding(
                "TCIEM-002", "T1078", "Initial Access", "critical",
                account, scan_run_id,
                actor      = actor,
                source_ip  = ip,
                event_time = s.get("backend_start"),
                evidence   = {"source_ip": ip, "application": s.get("application_name"), "state": s.get("state")},
            ))
    return findings


def detect_new_superuser(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-003: Superuser account other than the expected default detected."""
    superusers = data.get("superusers", [])
    expected   = data.get("_expected_superusers", {"postgres"})
    return [
        _make_finding(
            "TCIEM-003", "T1068", "Privilege Escalation", "critical",
            account, scan_run_id,
            actor      = su.get("rolname", "unknown"),
            source_ip  = None,
            event_time = None,
            evidence   = {"rolname": su.get("rolname"), "rolsuper": True, "expected_accounts": sorted(expected)},
        )
        for su in superusers
        if su.get("rolname") not in expected
    ]


def detect_off_hours_login(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-004: Active session that started between 22:00 and 06:00 UTC."""
    findings: List[Dict[str, Any]] = []
    for s in data.get("sessions", []):
        t = s.get("backend_start")
        if isinstance(t, datetime) and (t.hour >= 22 or t.hour < 6):
            actor = s.get("usename") or s.get("user") or "unknown"
            findings.append(_make_finding(
                "TCIEM-004", "T1078", "Persistence", "high",
                account, scan_run_id,
                actor      = actor,
                source_ip  = str(s.get("source_ip") or ""),
                event_time = t,
                evidence   = {"hour_utc": t.hour, "application": s.get("application_name")},
            ))
    return findings


def detect_acl_change(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-005: DDL on pg_hba / REVOKE / ALTER ROLE in current queries."""
    _ACL_KW = ("revoke", "alter role", "alter user", "drop user", "drop role", "pg_hba", "reload_conf")
    findings: List[Dict[str, Any]] = []
    for s in data.get("sessions", []) + data.get("stmt_history", []):
        q = str(s.get("current_query") or s.get("sql_text") or s.get("digest_text") or "").lower()
        if any(kw in q for kw in _ACL_KW):
            actor = s.get("usename") or s.get("user") or "unknown"
            findings.append(_make_finding(
                "TCIEM-005", "T1562", "Defense Evasion", "high",
                account, scan_run_id,
                actor=actor, source_ip=str(s.get("source_ip") or ""),
                event_time=s.get("backend_start"),
                evidence={"query_snippet": q[:200]},
            ))
    return findings


def detect_mass_export(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-006: COPY / pg_dump / mysqldump / SELECT INTO OUTFILE patterns."""
    _EXPORT_KW = ("\\copy", " copy ", "pg_dump", "into outfile", "select into", "export data")
    findings: List[Dict[str, Any]] = []
    for s in data.get("sessions", []) + data.get("stmt_history", []):
        q = str(s.get("current_query") or s.get("sql_text") or "").lower()
        if any(kw in q for kw in _EXPORT_KW):
            actor = s.get("usename") or s.get("user") or "unknown"
            findings.append(_make_finding(
                "TCIEM-006", "T1552", "Credential Access", "critical",
                account, scan_run_id,
                actor=actor, source_ip=str(s.get("source_ip") or ""),
                event_time=s.get("backend_start"),
                evidence={"query_snippet": q[:200]},
            ))
    return findings


def detect_admin_grant(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-007: Unexpected role grants to admin roles."""
    expected = data.get("_expected_superusers", {"postgres"})
    findings: List[Dict[str, Any]] = []
    for grant in data.get("role_grants", []):
        member   = grant.get("member", "unknown")
        rolename = grant.get("rolname", "")
        if member not in expected:
            findings.append(_make_finding(
                "TCIEM-007", "T1098", "Persistence", "high",
                account, scan_run_id,
                actor=member, source_ip=None, event_time=None,
                evidence={"granted_role": rolename, "member": member, "admin_option": grant.get("admin_option")},
            ))
    return findings


def detect_data_exfiltration(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-008: MySQL statement history with very high rows_sent."""
    findings: List[Dict[str, Any]] = []
    for stmt in data.get("stmt_history", []):
        rows_sent = int(stmt.get("rows_sent") or 0)
        if rows_sent > _HIGH_ROW_THRESHOLD:
            findings.append(_make_finding(
                "TCIEM-008", "T1530", "Collection", "high",
                account, scan_run_id,
                actor=str(stmt.get("thread_id", "unknown")),
                source_ip=None, event_time=None,
                evidence={"rows_sent": rows_sent, "threshold": _HIGH_ROW_THRESHOLD,
                          "digest": str(stmt.get("digest_text", ""))[:200]},
            ))
    return findings


def detect_root_session(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-009: Session logged in as the postgres/root superuser from a remote IP."""
    _SU_NAMES = ("postgres", "root", "sa", "system", "sys", "admin")
    findings: List[Dict[str, Any]] = []
    for s in data.get("sessions", []):
        actor = s.get("usename") or s.get("user") or ""
        ip    = str(s.get("source_ip") or s.get("host") or "").split(":")[0]
        if actor.lower() in _SU_NAMES and ip and not ip.startswith(("127.", "::1", "")):
            findings.append(_make_finding(
                "TCIEM-009", "T1611", "Privilege Escalation", "critical",
                account, scan_run_id,
                actor=actor, source_ip=ip,
                event_time=s.get("backend_start"),
                evidence={"superuser_remote_login": True, "application": s.get("application_name")},
            ))
    return findings


def detect_destructive_command(
    data: Dict[str, Any], account: Dict[str, Any],
    scan_run_id: str, since: datetime,
) -> List[Dict[str, Any]]:
    """TCIEM-010: DROP DATABASE, TRUNCATE, or shutdown command in session."""
    _DESTRUCTIVE = ("drop database", "drop schema", "truncate", "shutdown", "pg_terminate_backend")
    findings: List[Dict[str, Any]] = []
    for s in data.get("sessions", []) + data.get("pgaudit_events", []) + data.get("stmt_history", []):
        q = str(s.get("current_query") or s.get("sql_text") or s.get("object_name") or "").lower()
        if any(kw in q for kw in _DESTRUCTIVE):
            actor = s.get("usename") or s.get("user") or "unknown"
            findings.append(_make_finding(
                "TCIEM-010", "T1490", "Impact", "critical",
                account, scan_run_id,
                actor=actor, source_ip=str(s.get("source_ip") or ""),
                event_time=s.get("backend_start"),
                evidence={"command_snippet": q[:200]},
            ))
    return findings


# ── dispatcher ───────────────────────────────────────────────────────────────

_DETECTOR_MAP = {
    "detect_brute_force":       detect_brute_force,
    "detect_external_ip_login": detect_external_ip_login,
    "detect_new_superuser":     detect_new_superuser,
    "detect_off_hours_login":   detect_off_hours_login,
    "detect_acl_change":        detect_acl_change,
    "detect_mass_export":       detect_mass_export,
    "detect_admin_grant":       detect_admin_grant,
    "detect_data_exfiltration": detect_data_exfiltration,
    "detect_root_session":      detect_root_session,
    "detect_destructive_command": detect_destructive_command,
}


def run(scan_run_id: str, account_id: str) -> None:
    db         = TechDBManager()
    credential = db.get_credential(account_id=account_id)
    if not credential:
        raise ValueError(f"No credential for account_id={account_id}")

    tech_type = credential["tech_type"]
    since     = datetime.now(tz=timezone.utc) - timedelta(hours=LOOKBACK_HOURS)

    logger.info("CIEM scan: tech_type=%s lookback=%dh scan_run_id=%s", tech_type, LOOKBACK_HOURS, scan_run_id)

    data = _collect_events(tech_type, credential, since)
    if data is None:
        logger.warning(
            "tech-ciem: no collector for tech_type=%s — engine cannot run for this account",
            tech_type,
        )
        db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-ciem", count=0)
        return

    all_findings: List[Dict[str, Any]] = []
    for rule_id, mitre_tech, mitre_tactic, severity, desc, detector_name in CIEM_RULES:
        detector = _DETECTOR_MAP.get(detector_name)
        if not detector:
            continue
        try:
            hits = detector(data, credential, scan_run_id, since)
            if hits:
                logger.info("Rule %s (%s): %d hits", rule_id, desc, len(hits))
                all_findings.extend(hits)
        except Exception as exc:
            logger.warning("Detector %s failed: %s", detector_name, exc)

    inserted = db.upsert_ciem_findings(all_findings)
    db.mark_engine_completed(scan_run_id=scan_run_id, engine="tech-ciem", count=inserted)
    logger.info("CIEM complete: %d findings for %s", inserted, tech_type)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-run-id", required=True)
    parser.add_argument("--account-id",  required=True)
    args = parser.parse_args()
    try:
        run(args.scan_run_id, args.account_id)
    except Exception as exc:
        logger.error("tech-ciem failed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
