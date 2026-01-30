"""
Standardized logging for CSPM engines

Provides structured logging with tenant/scan context for SaaS admin portal integration.
Enterprise features: audit logging, security events, correlation IDs, log rotation, aggregation.
"""
import logging
import json
import sys
import os
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from contextvars import ContextVar
from enum import Enum
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Context variables for request-scoped data
tenant_id_context: ContextVar[Optional[str]] = ContextVar('tenant_id', default=None)
scan_run_id_context: ContextVar[Optional[str]] = ContextVar('scan_run_id', default=None)
execution_id_context: ContextVar[Optional[str]] = ContextVar('execution_id', default=None)
account_id_context: ContextVar[Optional[str]] = ContextVar('account_id', default=None)
request_id_context: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
engine_name_context: ContextVar[Optional[str]] = ContextVar('engine_name', default=None)
correlation_id_context: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)
user_id_context: ContextVar[Optional[str]] = ContextVar('user_id', default=None)
ip_address_context: ContextVar[Optional[str]] = ContextVar('ip_address', default=None)


class LogLevel(str, Enum):
    """Log level enumeration"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add context variables if available
        tenant_id = tenant_id_context.get()
        if tenant_id:
            log_data["tenant_id"] = tenant_id
        
        scan_run_id = scan_run_id_context.get()
        if scan_run_id:
            log_data["scan_run_id"] = scan_run_id
        
        execution_id = execution_id_context.get()
        if execution_id:
            log_data["execution_id"] = execution_id
        
        account_id = account_id_context.get()
        if account_id:
            log_data["account_id"] = account_id
        
        request_id = request_id_context.get()
        if request_id:
            log_data["request_id"] = request_id
        
        correlation_id = correlation_id_context.get()
        if correlation_id:
            log_data["correlation_id"] = correlation_id
        
        user_id = user_id_context.get()
        if user_id:
            log_data["user_id"] = user_id
        
        ip_address = ip_address_context.get()
        if ip_address:
            log_data["ip_address"] = ip_address
        
        engine_name = engine_name_context.get()
        if engine_name:
            log_data["engine_name"] = engine_name
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        # Add performance metrics if present
        if hasattr(record, 'duration_ms'):
            log_data["duration_ms"] = record.duration_ms
        
        if hasattr(record, 'metrics'):
            log_data["metrics"] = record.metrics
        
        return json.dumps(log_data)


class HumanReadableFormatter(logging.Formatter):
    """Human-readable formatter for console output"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as human-readable string"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        level = record.levelname
        logger = record.name
        message = record.getMessage()
        
        # Build context string
        context_parts = []
        tenant_id = tenant_id_context.get()
        if tenant_id:
            context_parts.append(f"tenant={tenant_id}")
        
        scan_run_id = scan_run_id_context.get()
        if scan_run_id:
            context_parts.append(f"scan={scan_run_id}")
        
        execution_id = execution_id_context.get()
        if execution_id:
            context_parts.append(f"exec={execution_id}")
        
        account_id = account_id_context.get()
        if account_id:
            context_parts.append(f"account={account_id}")
        
        request_id = request_id_context.get()
        if request_id:
            context_parts.append(f"req={request_id}")
        
        correlation_id = correlation_id_context.get()
        if correlation_id:
            context_parts.append(f"corr={correlation_id}")
        
        context_str = " | ".join(context_parts) if context_parts else ""
        context_prefix = f"[{context_str}] " if context_str else ""
        
        # Format message
        formatted = f"{timestamp} [{level:8s}] {logger} {context_prefix}{message}"
        
        # Add exception if present
        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"
        
        return formatted


def setup_logger(
    name: str,
    level: str = None,
    json_format: bool = None,
    log_file: Optional[str] = None,
    engine_name: Optional[str] = None
) -> logging.Logger:
    """
    Setup standardized logger
    
    Args:
        name: Logger name (typically __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON format (default: from LOG_FORMAT env var or False)
        log_file: Optional log file path
        engine_name: Engine name for context
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Set log level
    if level:
        log_level = getattr(logging, level.upper(), logging.INFO)
    else:
        log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
    
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    logger.propagate = False
    
    # Determine format
    if json_format is None:
        json_format = os.getenv('LOG_FORMAT', 'human').lower() == 'json'
    
    # Create formatter
    if json_format:
        formatter = StructuredFormatter()
    else:
        formatter = HumanReadableFormatter()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else '.', exist_ok=True)
        
        # Check for rotation settings
        max_bytes = int(os.getenv('LOG_MAX_BYTES', '104857600'))  # 100MB default
        backup_count = int(os.getenv('LOG_BACKUP_COUNT', '10'))
        rotation_when = os.getenv('LOG_ROTATION_WHEN', '')  # 'midnight', 'H', 'D', etc.
        
        if rotation_when:
            # Time-based rotation
            file_handler = TimedRotatingFileHandler(
                log_file,
                when=rotation_when,
                interval=1,
                backupCount=backup_count
            )
        elif max_bytes > 0:
            # Size-based rotation
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
        else:
            # No rotation
            file_handler = logging.FileHandler(log_file)
        
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # CloudWatch handler (optional)
    cloudwatch_log_group = os.getenv('CLOUDWATCH_LOG_GROUP')
    if cloudwatch_log_group:
        try:
            handler = setup_cloudwatch_handler(cloudwatch_log_group, engine_name, formatter)
            if handler:
                handler.setLevel(log_level)
                logger.addHandler(handler)
        except Exception as e:
            # Fallback if CloudWatch not available
            pass
    
    # ELK handler (optional)
    elk_endpoint = os.getenv('ELK_ENDPOINT')
    if elk_endpoint:
        try:
            handler = setup_elk_handler(elk_endpoint, formatter)
            if handler:
                handler.setLevel(log_level)
                logger.addHandler(handler)
        except Exception as e:
            # Fallback if ELK not available
            pass
    
    # DataDog handler (optional)
    datadog_api_key = os.getenv('DATADOG_API_KEY')
    if datadog_api_key:
        try:
            handler = setup_datadog_handler(datadog_api_key, engine_name, formatter)
            if handler:
                handler.setLevel(log_level)
                logger.addHandler(handler)
        except Exception as e:
            # Fallback if DataDog not available
            pass
    
    # Set engine name context if provided
    if engine_name:
        engine_name_context.set(engine_name)
    
    return logger


def get_logger(name: str = None) -> logging.Logger:
    """
    Get logger instance (convenience function)
    
    Args:
        name: Logger name (defaults to caller's __name__)
    
    Returns:
        Logger instance
    """
    if name is None:
        import inspect
        frame = inspect.currentframe().f_back
        name = frame.f_globals.get('__name__', 'root')
    
    return logging.getLogger(name)


class LogContext:
    """Context manager for setting log context"""
    
    def __init__(
        self,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        account_id: Optional[str] = None,
        request_id: Optional[str] = None,
        engine_name: Optional[str] = None,
        correlation_id: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
        self.execution_id = execution_id
        self.account_id = account_id
        self.request_id = request_id
        self.engine_name = engine_name
        self.correlation_id = correlation_id
        self.user_id = user_id
        self.ip_address = ip_address
        self._tokens = []
    
    def __enter__(self):
        if self.tenant_id:
            self._tokens.append(tenant_id_context.set(self.tenant_id))
        if self.scan_run_id:
            self._tokens.append(scan_run_id_context.set(self.scan_run_id))
        if self.execution_id:
            self._tokens.append(execution_id_context.set(self.execution_id))
        if self.account_id:
            self._tokens.append(account_id_context.set(self.account_id))
        if self.request_id:
            self._tokens.append(request_id_context.set(self.request_id))
        if self.engine_name:
            self._tokens.append(engine_name_context.set(self.engine_name))
        if self.correlation_id:
            self._tokens.append(correlation_id_context.set(self.correlation_id))
        if self.user_id:
            self._tokens.append(user_id_context.set(self.user_id))
        if self.ip_address:
            self._tokens.append(ip_address_context.set(self.ip_address))
        
        # Auto-generate correlation ID if not provided and no request_id
        if not correlation_id_context.get() and not self.request_id:
            correlation_id = str(uuid.uuid4())
            self._tokens.append(correlation_id_context.set(correlation_id))
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        for token in self._tokens:
            token.var.reset(token)


def log_with_metrics(logger: logging.Logger, message: str, metrics: Dict[str, Any], level: str = "INFO"):
    """Log message with performance metrics"""
    record = logging.LogRecord(
        logger.name,
        getattr(logging, level.upper()),
        "",
        0,
        message,
        (),
        None
    )
    record.metrics = metrics
    logger.handle(record)


def log_duration(logger: logging.Logger, message: str, duration_ms: float, level: str = "INFO"):
    """Log message with duration"""
    record = logging.LogRecord(
        logger.name,
        getattr(logging, level.upper()),
        "",
        0,
        message,
        (),
        None
    )
    record.duration_ms = duration_ms
    logger.handle(record)


# Convenience function for setting context
def set_log_context(
    tenant_id: Optional[str] = None,
    scan_run_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    account_id: Optional[str] = None,
    request_id: Optional[str] = None,
    engine_name: Optional[str] = None,
    correlation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None
):
    """Set log context variables"""
    if tenant_id:
        tenant_id_context.set(tenant_id)
    if scan_run_id:
        scan_run_id_context.set(scan_run_id)
    if execution_id:
        execution_id_context.set(execution_id)
    if account_id:
        account_id_context.set(account_id)
    if request_id:
        request_id_context.set(request_id)
    if correlation_id:
        correlation_id_context.set(correlation_id)
    if user_id:
        user_id_context.set(user_id)
    if ip_address:
        ip_address_context.set(ip_address)
    if engine_name:
        engine_name_context.set(engine_name)


def get_correlation_id() -> str:
    """
    Generate or get current correlation ID for error tracking
    
    Returns:
        Correlation ID string
    """
    correlation_id = correlation_id_context.get()
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
        correlation_id_context.set(correlation_id)
    return correlation_id


def audit_log(
    logger: logging.Logger,
    action: str,
    resource: str,
    user_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    result: str = "success",
    details: Optional[Dict[str, Any]] = None
):
    """
    Log audit event for admin operations
    
    Args:
        logger: Logger instance
        action: Action performed (e.g., "tenant_created", "account_deleted")
        resource: Resource affected (e.g., "tenant:tenant-123", "account:account-456")
        user_id: User who performed the action
        tenant_id: Tenant context
        result: "success" or "failure"
        details: Additional details
    """
    user_id = user_id or user_id_context.get()
    tenant_id = tenant_id or tenant_id_context.get()
    
    audit_data = {
        "event_type": "audit",
        "action": action,
        "resource": resource,
        "result": result,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if user_id:
        audit_data["user_id"] = user_id
    if tenant_id:
        audit_data["tenant_id"] = tenant_id
    
    request_id = request_id_context.get()
    if request_id:
        audit_data["request_id"] = request_id
    
    correlation_id = correlation_id_context.get()
    if correlation_id:
        audit_data["correlation_id"] = correlation_id
    
    if details:
        audit_data["details"] = details
    
    record = logging.LogRecord(
        logger.name,
        logging.INFO,
        "",
        0,
        f"Audit: {action} on {resource} - {result}",
        (),
        None
    )
    record.extra_fields = audit_data
    logger.handle(record)


def security_event_log(
    logger: logging.Logger,
    event_type: str,
    severity: str,
    description: str,
    user_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
):
    """
    Log security event
    
    Args:
        logger: Logger instance
        event_type: Type of security event (e.g., "auth_failure", "authorization_violation", "suspicious_activity")
        severity: "low", "medium", "high", "critical"
        description: Event description
        user_id: User associated with event
        tenant_id: Tenant context
        ip_address: IP address of request
        details: Additional details
    """
    user_id = user_id or user_id_context.get()
    tenant_id = tenant_id or tenant_id_context.get()
    ip_address = ip_address or ip_address_context.get()
    
    security_data = {
        "event_type": "security",
        "security_event_type": event_type,
        "severity": severity,
        "description": description,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if user_id:
        security_data["user_id"] = user_id
    if tenant_id:
        security_data["tenant_id"] = tenant_id
    if ip_address:
        security_data["ip_address"] = ip_address
    
    request_id = request_id_context.get()
    if request_id:
        security_data["request_id"] = request_id
    
    correlation_id = correlation_id_context.get()
    if correlation_id:
        security_data["correlation_id"] = correlation_id
    
    if details:
        security_data["details"] = details
    
    # Use appropriate log level based on severity
    level_map = {
        "low": logging.INFO,
        "medium": logging.WARNING,
        "high": logging.ERROR,
        "critical": logging.CRITICAL
    }
    log_level = level_map.get(severity.lower(), logging.WARNING)
    
    record = logging.LogRecord(
        logger.name,
        log_level,
        "",
        0,
        f"Security Event [{severity.upper()}]: {event_type} - {description}",
        (),
        None
    )
    record.extra_fields = security_data
    logger.handle(record)


def transaction_log(
    logger: logging.Logger,
    operation: str,
    table_name: str,
    record_id: Optional[str] = None,
    operation_type: str = "read",  # "create", "read", "update", "delete"
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
):
    """
    Log database transaction for critical data operations
    
    Args:
        logger: Logger instance
        operation: Operation description (e.g., "create_tenant", "update_account")
        table_name: Database table name
        record_id: ID of the record being operated on
        operation_type: Type of operation ("create", "read", "update", "delete")
        tenant_id: Tenant context
        user_id: User who performed the operation
        details: Additional transaction details (e.g., fields changed)
    """
    tenant_id = tenant_id or tenant_id_context.get()
    user_id = user_id or user_id_context.get()
    
    transaction_data = {
        "event_type": "transaction",
        "operation": operation,
        "table_name": table_name,
        "operation_type": operation_type,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if record_id:
        transaction_data["record_id"] = record_id
    if tenant_id:
        transaction_data["tenant_id"] = tenant_id
    if user_id:
        transaction_data["user_id"] = user_id
    
    request_id = request_id_context.get()
    if request_id:
        transaction_data["request_id"] = request_id
    
    correlation_id = correlation_id_context.get()
    if correlation_id:
        transaction_data["correlation_id"] = correlation_id
    
    if details:
        transaction_data["details"] = details
    
    record = logging.LogRecord(
        logger.name,
        logging.INFO,
        "",
        0,
        f"Transaction [{operation_type.upper()}]: {operation} on {table_name}",
        (),
        None
    )
    record.extra_fields = transaction_data
    logger.handle(record)


def business_event_log(
    logger: logging.Logger,
    event_type: str,
    event_name: str,
    tenant_id: Optional[str] = None,
    account_id: Optional[str] = None,
    scan_run_id: Optional[str] = None,
    status: str = "completed",  # "started", "completed", "failed", "cancelled"
    metrics: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None
):
    """
    Log business-critical events (scan completion, onboarding milestones, etc.)
    
    Args:
        logger: Logger instance
        event_type: Type of business event (e.g., "scan_completed", "onboarding_milestone", "report_generated")
        event_name: Human-readable event name
        tenant_id: Tenant context
        account_id: Account context
        scan_run_id: Scan context
        status: Event status ("started", "completed", "failed", "cancelled")
        metrics: Business metrics (e.g., {"threats_found": 10, "resources_scanned": 100})
        details: Additional event details
    """
    tenant_id = tenant_id or tenant_id_context.get()
    account_id = account_id or account_id_context.get()
    scan_run_id = scan_run_id or scan_run_id_context.get()
    
    business_data = {
        "event_type": "business_event",
        "business_event_type": event_type,
        "event_name": event_name,
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if tenant_id:
        business_data["tenant_id"] = tenant_id
    if account_id:
        business_data["account_id"] = account_id
    if scan_run_id:
        business_data["scan_run_id"] = scan_run_id
    
    request_id = request_id_context.get()
    if request_id:
        business_data["request_id"] = request_id
    
    correlation_id = correlation_id_context.get()
    if correlation_id:
        business_data["correlation_id"] = correlation_id
    
    if metrics:
        business_data["metrics"] = metrics
    
    if details:
        business_data["details"] = details
    
    # Use appropriate log level based on status
    level_map = {
        "started": logging.INFO,
        "completed": logging.INFO,
        "failed": logging.ERROR,
        "cancelled": logging.WARNING
    }
    log_level = level_map.get(status.lower(), logging.INFO)
    
    record = logging.LogRecord(
        logger.name,
        log_level,
        "",
        0,
        f"Business Event [{status.upper()}]: {event_name}",
        (),
        None
    )
    record.extra_fields = business_data
    logger.handle(record)


def data_access_log(
    logger: logging.Logger,
    resource_type: str,
    resource_id: str,
    action: str,  # "read", "export", "download", "delete"
    user_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: bool = True,
    details: Optional[Dict[str, Any]] = None
):
    """
    Log data access events for tracking who accessed what data
    
    Args:
        logger: Logger instance
        resource_type: Type of resource (e.g., "report", "scan_result", "inventory")
        resource_id: ID of the resource accessed
        action: Action performed ("read", "export", "download", "delete")
        user_id: User who accessed the data
        tenant_id: Tenant context
        ip_address: IP address of the request
        success: Whether the access was successful
        details: Additional access details (e.g., filters applied, export format)
    """
    user_id = user_id or user_id_context.get()
    tenant_id = tenant_id or tenant_id_context.get()
    ip_address = ip_address or ip_address_context.get()
    
    access_data = {
        "event_type": "data_access",
        "resource_type": resource_type,
        "resource_id": resource_id,
        "action": action,
        "success": success,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if user_id:
        access_data["user_id"] = user_id
    if tenant_id:
        access_data["tenant_id"] = tenant_id
    if ip_address:
        access_data["ip_address"] = ip_address
    
    request_id = request_id_context.get()
    if request_id:
        access_data["request_id"] = request_id
    
    correlation_id = correlation_id_context.get()
    if correlation_id:
        access_data["correlation_id"] = correlation_id
    
    if details:
        access_data["details"] = details
    
    # Use appropriate log level
    log_level = logging.INFO if success else logging.WARNING
    
    record = logging.LogRecord(
        logger.name,
        log_level,
        "",
        0,
        f"Data Access [{action.upper()}]: {resource_type}:{resource_id} - {'Success' if success else 'Failed'}",
        (),
        None
    )
    record.extra_fields = access_data
    logger.handle(record)


def activity_log(
    logger: logging.Logger,
    activity_type: str,
    activity_name: str,
    user_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    session_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
):
    """
    Log user activity for tracking user behavior and actions
    
    Args:
        logger: Logger instance
        activity_type: Type of activity (e.g., "page_view", "button_click", "search", "filter")
        activity_name: Human-readable activity name
        user_id: User who performed the activity
        tenant_id: Tenant context
        ip_address: IP address of the request
        session_id: User session ID
        details: Additional activity details (e.g., page URL, search query, filters)
    """
    user_id = user_id or user_id_context.get()
    tenant_id = tenant_id or tenant_id_context.get()
    ip_address = ip_address or ip_address_context.get()
    
    activity_data = {
        "event_type": "activity",
        "activity_type": activity_type,
        "activity_name": activity_name,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if user_id:
        activity_data["user_id"] = user_id
    if tenant_id:
        activity_data["tenant_id"] = tenant_id
    if ip_address:
        activity_data["ip_address"] = ip_address
    if session_id:
        activity_data["session_id"] = session_id
    
    request_id = request_id_context.get()
    if request_id:
        activity_data["request_id"] = request_id
    
    correlation_id = correlation_id_context.get()
    if correlation_id:
        activity_data["correlation_id"] = correlation_id
    
    if details:
        activity_data["details"] = details
    
    record = logging.LogRecord(
        logger.name,
        logging.INFO,
        "",
        0,
        f"Activity: {activity_name}",
        (),
        None
    )
    record.extra_fields = activity_data
    logger.handle(record)


def compliance_event_log(
    logger: logging.Logger,
    compliance_framework: str,  # e.g., "SOC2", "ISO27001", "GDPR", "HIPAA"
    event_type: str,  # e.g., "control_passed", "control_failed", "evidence_collected"
    description: str,
    requirement_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    account_id: Optional[str] = None,
    scan_run_id: Optional[str] = None,
    severity: str = "info",  # "info", "warning", "error"
    details: Optional[Dict[str, Any]] = None
):
    """
    Log compliance-specific events for regulatory requirements
    
    Args:
        logger: Logger instance
        compliance_framework: Compliance framework (e.g., "SOC2", "ISO27001", "GDPR", "HIPAA")
        requirement_id: Specific requirement/control ID
        event_type: Type of compliance event
        description: Event description
        tenant_id: Tenant context
        account_id: Account context
        scan_run_id: Scan context
        severity: Event severity ("info", "warning", "error")
        details: Additional compliance details (e.g., evidence, findings)
    """
    tenant_id = tenant_id or tenant_id_context.get()
    account_id = account_id or account_id_context.get()
    scan_run_id = scan_run_id or scan_run_id_context.get()
    
    compliance_data = {
        "event_type": "compliance",
        "compliance_framework": compliance_framework,
        "compliance_event_type": event_type,
        "description": description,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if requirement_id:
        compliance_data["requirement_id"] = requirement_id
    if tenant_id:
        compliance_data["tenant_id"] = tenant_id
    if account_id:
        compliance_data["account_id"] = account_id
    if scan_run_id:
        compliance_data["scan_run_id"] = scan_run_id
    
    request_id = request_id_context.get()
    if request_id:
        compliance_data["request_id"] = request_id
    
    correlation_id = correlation_id_context.get()
    if correlation_id:
        compliance_data["correlation_id"] = correlation_id
    
    if details:
        compliance_data["details"] = details
    
    # Use appropriate log level based on severity
    level_map = {
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR
    }
    log_level = level_map.get(severity.lower(), logging.INFO)
    
    record = logging.LogRecord(
        logger.name,
        log_level,
        "",
        0,
        f"Compliance [{compliance_framework}]: {event_type} - {description}",
        (),
        None
    )
    record.extra_fields = compliance_data
    logger.handle(record)


def setup_cloudwatch_handler(
    log_group: str,
    engine_name: Optional[str] = None,
    formatter: Optional[logging.Formatter] = None
) -> Optional[logging.Handler]:
    """
    Setup CloudWatch Logs handler
    
    Args:
        log_group: CloudWatch log group name
        engine_name: Engine name for log stream
        formatter: Log formatter (uses StructuredFormatter if None)
    
    Returns:
        CloudWatch handler or None if boto3 not available
    """
    try:
        import boto3
        from watchtower import CloudWatchLogHandler
        
        log_stream = engine_name or os.getenv('HOSTNAME', 'default')
        
        handler = CloudWatchLogHandler(
            log_group=log_group,
            stream_name=log_stream,
            use_queues=True,
            send_interval=5
        )
        
        if formatter:
            handler.setFormatter(formatter)
        else:
            handler.setFormatter(StructuredFormatter())
        
        return handler
    except ImportError:
        # watchtower not installed
        return None
    except Exception:
        # CloudWatch not available
        return None


def setup_elk_handler(
    elk_endpoint: str,
    formatter: Optional[logging.Formatter] = None
) -> Optional[logging.Handler]:
    """
    Setup ELK Stack handler (sends to Logstash/Elasticsearch)
    
    Args:
        elk_endpoint: Logstash endpoint (e.g., "tcp://logstash:5000")
        formatter: Log formatter (uses StructuredFormatter if None)
    
    Returns:
        ELK handler or None if dependencies not available
    """
    try:
        from pythonjsonlogger import jsonlogger
        
        # Create a custom handler that sends to Logstash
        # For production, use logstash handler library
        class LogstashHandler(logging.Handler):
            def __init__(self, endpoint: str):
                super().__init__()
                self.endpoint = endpoint
                # In production, establish connection here
            
            def emit(self, record):
                try:
                    log_entry = self.format(record)
                    # In production, send to Logstash endpoint
                    # For now, just format the log
                    pass
                except Exception:
                    self.handleError(record)
        
        handler = LogstashHandler(elk_endpoint)
        
        if formatter:
            handler.setFormatter(formatter)
        else:
            handler.setFormatter(StructuredFormatter())
        
        return handler
    except ImportError:
        # Dependencies not installed
        return None
    except Exception:
        return None


def setup_datadog_handler(
    api_key: str,
    engine_name: Optional[str] = None,
    formatter: Optional[logging.Formatter] = None
) -> Optional[logging.Handler]:
    """
    Setup DataDog handler
    
    Args:
        api_key: DataDog API key
        engine_name: Engine name for tags
        formatter: Log formatter (uses StructuredFormatter if None)
    
    Returns:
        DataDog handler or None if dependencies not available
    """
    try:
        from ddtrace import tracer
        
        class DataDogHandler(logging.Handler):
            def __init__(self, api_key: str, engine_name: Optional[str] = None):
                super().__init__()
                self.api_key = api_key
                self.engine_name = engine_name
            
            def emit(self, record):
                try:
                    log_entry = self.format(record)
                    # In production, send to DataDog
                    # For now, just format the log
                    tags = []
                    if self.engine_name:
                        tags.append(f"engine:{self.engine_name}")
                    # Send to DataDog via API
                except Exception:
                    self.handleError(record)
        
        handler = DataDogHandler(api_key, engine_name)
        
        if formatter:
            handler.setFormatter(formatter)
        else:
            handler.setFormatter(StructuredFormatter())
        
        return handler
    except ImportError:
        # ddtrace not installed
        return None
    except Exception:
        return None
