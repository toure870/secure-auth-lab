"""Middleware pour les security headers."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import Response
from app.config import settings
import logging

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Ajoute les headers de sécurité essentiels à toutes les réponses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # HSTS (HTTP Strict-Transport-Security)
        hsts_header = f"max-age={settings.HSTS_MAX_AGE}"
        if settings.HSTS_INCLUDE_SUBDOMAINS:
            hsts_header += "; includeSubDomains"
        if settings.HSTS_PRELOAD:
            hsts_header += "; preload"
        response.headers["Strict-Transport-Security"] = hsts_header

        # X-Content-Type-Options (MIME sniffing prevention)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options (Clickjacking prevention)
        response.headers["X-Frame-Options"] = "DENY"

        # X-XSS-Protection (legacy)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content-Security-Policy (XSS prevention)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'"
        )
        response.headers["Content-Security-Policy"] = csp

        # Referrer-Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy (Feature Policy)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )

        # Disable caching pour les pages sensibles
        if request.url.path.startswith("/api/auth"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response
