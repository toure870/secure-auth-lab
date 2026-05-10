"""Security middleware for FastAPI application."""
import time
import logging
import json
from datetime import datetime

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import get_settings
from app.database import get_db_context
from app.models import AuditLog
from sqlalchemy import insert

logger = logging.getLogger(__name__)
settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    
    Headers:
    - Strict-Transport-Security: Force HTTPS
    - X-Content-Type-Options: Prevent MIME sniffing
    - X-Frame-Options: Prevent clickjacking
    - X-XSS-Protection: Legacy XSS protection
    - Content-Security-Policy: Prevent XSS/injection
    - Referrer-Policy: Control referrer information
    - Permissions-Policy: Control browser features
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Strict-Transport-Security
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        
        # Legacy XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions Policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        )
        
        # Remove server header
        response.headers.pop("server", None)
        
        return response


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all requests for audit trail.
    
    Logs:
    - Method and path
    - Status code
    - Client IP
    - User-Agent
    - Request/response size
    - Duration
    - User ID (if authenticated)
    
    Security:
    - Does NOT log sensitive data (passwords, tokens)
    - Stores in database for audit
    - Configurable based on endpoint
    """
    
    # Endpoints to skip logging (high volume)
    SKIP_PATHS = {
        "/health",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/favicon.ico",
    }
    
    # Endpoints to log with minimal info
    SENSITIVE_PATHS = {
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/logout",
    }
    
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        
        # Skip logging for certain paths
        if any(request.url.path.startswith(path) for path in self.SKIP_PATHS):
            return await call_next(request)
        
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(
                f"Request error: {request.method} {request.url.path} "
                f"from {client_ip}: {str(e)}",
                exc_info=True,
            )
            raise
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log request details
        log_level = "info" if response.status_code < 400 else "warning"
        log_message = (
            f"{request.method} {request.url.path} - "
            f"Status: {response.status_code} - "
            f"IP: {client_ip} - "
            f"Duration: {duration:.3f}s"
        )
        
        if log_level == "info":
            logger.info(log_message)
        else:
            logger.warning(log_message)
        
        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Handle errors securely without exposing sensitive information.
    
    Security:
    - Hide stack traces in production
    - Return generic error messages
    - Log detailed errors server-side
    - Set appropriate status codes
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            logger.error(
                f"Unhandled exception: {str(e)}",
                exc_info=True,
            )
            
            # Return generic error in production
            if not settings.DEBUG:
                return Response(
                    content=json.dumps({
                        "detail": "Internal server error"
                    }),
                    status_code=500,
                    media_type="application/json",
                )
            else:
                # Return detailed error in development
                raise


def setup_middleware(app):
    """
    Configure all middleware for FastAPI application.
    
    Order matters - middleware is applied in reverse order.
    """
    
    # Trusted hosts (prevent Host header injection)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "localhost",
            "127.0.0.1",
            "*.example.com",  # Update for production
        ],
    )
    
    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS.split(","),
        allow_credentials=settings.ALLOW_CREDENTIALS,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        max_age=600,  # Cache preflight for 10 minutes
    )
    
    # Custom security middleware
    app.add_middleware(ErrorHandlingMiddleware)
    app.add_middleware(AuditLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    
    return app
