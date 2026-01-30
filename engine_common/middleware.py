"""
FastAPI middleware for request/response logging and correlation IDs

Provides automatic logging of all API requests/responses with context.
"""
import time
import uuid
from typing import Callable, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .logger import (
    setup_logger,
    LogContext,
    get_correlation_id,
    set_log_context,
    log_duration,
    security_event_log
)

logger = setup_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging all API requests and responses"""
    
    def __init__(self, app: ASGIApp, engine_name: Optional[str] = None):
        super().__init__(app)
        self.engine_name = engine_name
        self.logger = setup_logger(__name__, engine_name=engine_name)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log request/response"""
        start_time = time.time()
        
        # Generate request ID
        request_id = str(uuid.uuid4())
        
        # Extract tenant_id from headers or query params
        tenant_id = request.headers.get("X-Tenant-ID") or request.query_params.get("tenant_id")
        scan_run_id = request.headers.get("X-Scan-Run-ID") or request.query_params.get("scan_run_id")
        account_id = request.headers.get("X-Account-ID") or request.query_params.get("account_id")
        user_id = request.headers.get("X-User-ID") or request.query_params.get("user_id")
        
        # Get client IP
        client_ip = request.client.host if request.client else None
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        # Set log context
        with LogContext(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            account_id=account_id,
            request_id=request_id,
            user_id=user_id,
            ip_address=client_ip,
            engine_name=self.engine_name
        ):
            # Log incoming request
            self.logger.info(
                "Incoming request",
                extra={
                    "extra_fields": {
                        "method": request.method,
                        "path": str(request.url.path),
                        "query_params": dict(request.query_params),
                        "client_ip": client_ip,
                        "user_agent": request.headers.get("user-agent")
                    }
                }
            )
            
            # IMPORTANT: Do NOT read request.body() here.
            # BaseHTTPMiddleware + body consumption can break downstream handlers
            # and cause POST requests to hang or return empty bodies.
            
            # Process request
            try:
                response = await call_next(request)
                
                # Calculate duration
                duration_ms = (time.time() - start_time) * 1000
                
                # Log response
                log_duration(
                    self.logger,
                    "Request completed",
                    duration_ms,
                    level="INFO"
                )
                
                self.logger.info(
                    "Response sent",
                    extra={
                        "extra_fields": {
                            "status_code": response.status_code,
                            "response_size": response.headers.get("content-length", "unknown")
                        }
                    }
                )
                
                # Add correlation ID to response headers
                response.headers["X-Request-ID"] = request_id
                correlation_id = get_correlation_id()
                if correlation_id:
                    response.headers["X-Correlation-ID"] = correlation_id
                
                # Log security events for error responses
                if response.status_code >= 400:
                    if response.status_code == 401:
                        security_event_log(
                            self.logger,
                            "auth_failure",
                            "medium",
                            f"Authentication failed for {request.url.path}",
                            user_id=user_id,
                            tenant_id=tenant_id,
                            ip_address=client_ip
                        )
                    elif response.status_code == 403:
                        security_event_log(
                            self.logger,
                            "authorization_violation",
                            "high",
                            f"Authorization denied for {request.url.path}",
                            user_id=user_id,
                            tenant_id=tenant_id,
                            ip_address=client_ip
                        )
                    else:
                        # Log error with correlation ID
                        self.logger.error(
                            "Request failed",
                            extra={
                                "extra_fields": {
                                    "status_code": response.status_code,
                                    "correlation_id": correlation_id
                                }
                            }
                        )
                
                return response
                
            except Exception as e:
                # Log exception with correlation ID
                duration_ms = (time.time() - start_time) * 1000
                correlation_id = get_correlation_id()
                
                self.logger.error(
                    "Request exception",
                    exc_info=True,
                    extra={
                        "extra_fields": {
                            "duration_ms": duration_ms,
                            "correlation_id": correlation_id,
                            "path": str(request.url.path),
                            "method": request.method
                        }
                    }
                )
                
                # Create error response
                from fastapi.responses import JSONResponse
                error_response = JSONResponse(
                    status_code=500,
                    content={
                        "error": "Internal server error",
                        "correlation_id": correlation_id,
                        "request_id": request_id
                    }
                )
                error_response.headers["X-Request-ID"] = request_id
                error_response.headers["X-Correlation-ID"] = correlation_id
                return error_response
    
    def _sanitize_body(self, body: dict) -> dict:
        """Sanitize sensitive fields in request body"""
        sensitive_fields = [
            "password", "secret", "token", "key", "credential",
            "access_key", "secret_key", "api_key", "private_key"
        ]
        
        sanitized = body.copy()
        for key, value in sanitized.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_fields):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_body(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_body(item) if isinstance(item, dict) else item
                    for item in value
                ]
        
        return sanitized


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Middleware for generating and propagating correlation IDs"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Generate correlation ID and add to context"""
        # Check for existing correlation ID in headers
        correlation_id = request.headers.get("X-Correlation-ID")
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        # Set in context
        set_log_context(correlation_id=correlation_id)
        
        # Process request
        response = await call_next(request)
        
        # Add correlation ID to response headers
        response.headers["X-Correlation-ID"] = correlation_id
        
        return response
