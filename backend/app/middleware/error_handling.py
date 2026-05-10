"""Middleware pour la gestion centralisée des erreurs."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import logging
import traceback
from app.config import settings

logger = logging.getLogger(__name__)


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Gère les erreurs non capturées et retourne des réponses JSON sécurisées."""

    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except RequestValidationError as e:
            logger.warning(f"Validation error: {e}")
            return JSONResponse(
                status_code=422,
                content={
                    "detail": "Validation error",
                    "errors": e.errors() if settings.DEBUG else None,
                },
            )
        except Exception as e:
            logger.error(f"Unhandled error: {str(e)}", exc_info=True)

            # Ne pas révéler les détails d'erreur en production
            if settings.ENVIRONMENT == "production":
                content = {
                    "detail": "Internal server error",
                }
            else:
                content = {
                    "detail": str(e),
                    "traceback": traceback.format_exc() if settings.DEBUG else None,
                }

            return JSONResponse(
                status_code=500,
                content=content,
            )
