"""Middleware pour logging détaillé des requêtes."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import Response
import logging
import time
import json
from typing import Optional

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Log toutes les requêtes HTTP avec détails sensibles."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Début
        start_time = time.time()
        request_id = request.headers.get("X-Request-ID", "")

        # Extraire les informations
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        query_string = request.url.query
        user_agent = request.headers.get("user-agent", "")

        # Log de la requête (ne pas logger les données sensibles)
        log_data = {
            "request_id": request_id,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "user_agent": user_agent[:100] if user_agent else "",
        }

        logger.info(f"Request: {method} {path}", extra=log_data)

        # Appeler le handler
        response = await call_next(request)

        # Fin
        duration = time.time() - start_time
        status_code = response.status_code

        # Log de la réponse
        log_response = {
            "request_id": request_id,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2),
            "client_ip": client_ip,
        }

        # Log les erreurs avec plus de détail
        if status_code >= 400:
            logger.warning(
                f"Response: {method} {path} -> {status_code}",
                extra=log_response
            )
        else:
            logger.info(
                f"Response: {method} {path} -> {status_code}",
                extra=log_response
            )

        # Ajouter les headers de timing pour la transparence
        response.headers["X-Process-Time"] = str(duration)
        response.headers["X-Request-ID"] = request_id

        return response
