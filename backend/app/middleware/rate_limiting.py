"""Middleware pour le rate limiting globale."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
import redis
from app.config import settings
from app.security.rate_limiter import RateLimiter
import logging

logger = logging.getLogger(__name__)


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Applique le rate limiting basé sur l'IP."""

    def __init__(self, app):
        super().__init__(app)
        try:
            self.redis = redis.from_url(settings.REDIS_URL)
            self.redis.ping()
            self.rate_limiter = RateLimiter(self.redis)
            self.enabled = True
        except Exception as e:
            logger.error(f"Rate limiter initialization failed: {e}")
            self.enabled = False

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Obtenir l'IP du client
        client_ip = request.client.host if request.client else "unknown"
        identifier = f"ip:{client_ip}"

        # Vérifier le rate limit
        is_allowed, info = self.rate_limiter.is_allowed(identifier)

        if not is_allowed:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests",
                    "retry_after": info.get("reset_at"),
                },
            )

        # Procéder
        response = await call_next(request)

        # Ajouter les headers de rate limiting
        response.headers["X-RateLimit-Limit"] = str(info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(info["remaining"])
        response.headers["X-RateLimit-Reset"] = info["reset_at"]

        return response
