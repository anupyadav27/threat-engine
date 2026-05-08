"""
RDS Audit Log parser — CSV from CloudWatch Logs.

MySQL audit log format:
  timestamp,serverhost,username,host,connectionid,queryid,operation,database,object,retcode

PostgreSQL audit log format (pgaudit):
  timestamp,user,database,process_id,remote_host,session_line_number,command_tag,object_type,object_name,statement,parameter
"""

import csv
import io
import json
import logging
from typing import Any, Dict, Generator

from .base_parser import BaseParser
from ..normalizer.schema import EventCategory

logger = logging.getLogger(__name__)


class RDSAuditParser(BaseParser):
    format_name = "rds_audit"

    def parse(self, raw_bytes: bytes) -> Generator[Dict[str, Any], None, None]:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")

            for line in text.strip().split("\n"):
                if not line.strip():
                    continue

                # Try JSON format first (Aurora)
                try:
                    record = json.loads(line)
                    record["_operation"] = record.get("command", record.get("operation", ""))
                    record["_user"] = record.get("databaseUser", record.get("user", ""))
                    record["_database"] = record.get("database", "")
                    record["_remote_host"] = record.get("remoteHost", record.get("host", ""))
                    yield record
                    continue
                except json.JSONDecodeError:
                    pass

                # CSV format (MySQL/PostgreSQL)
                try:
                    reader = csv.reader(io.StringIO(line))
                    fields = next(reader, [])
                    if len(fields) >= 8:
                        record = {
                            "timestamp": fields[0],
                            "serverhost": fields[1] if len(fields) > 1 else "",
                            "_user": fields[2] if len(fields) > 2 else "",
                            "_remote_host": fields[3] if len(fields) > 3 else "",
                            "connectionid": fields[4] if len(fields) > 4 else "",
                            "queryid": fields[5] if len(fields) > 5 else "",
                            "_operation": fields[6] if len(fields) > 6 else "",
                            "_database": fields[7] if len(fields) > 7 else "",
                            "object": fields[8] if len(fields) > 8 else "",
                            "retcode": fields[9] if len(fields) > 9 else "",
                        }
                        yield record
                except Exception:
                    continue

        except Exception as exc:
            logger.debug(f"RDS audit parse error: {exc}")

    def get_field_mapping(self) -> Dict[str, str]:
        return {
            "actor.principal": "_user",
            "actor.ip_address": "_remote_host",
            "operation": "_operation",
            "service": "_database",
        }

    def get_event_category(self) -> str:
        return EventCategory.DATA_ACCESS
