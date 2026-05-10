"""Rate limiting avec Redis pour protection DDoS et brute force."""

import redis
from datetime import datetime, timedelta
from typing import Tuple
from app.config import settings
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiting avec fenêtres glissantes (sliding window)."""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS
        self.max_requests = settings.RATE_LIMIT_REQUESTS

    def is_allowed(
        self,
        identifier: str,
        max_requests: int = None,
        window_seconds: int = None,
    ) -> Tuple[bool, dict]:
        """Vérifie si une requête est autorisée selon le rate limit.
        
        Args:
            identifier: Clé unique (IP, user_id, etc.)
            max_requests: Nombre max de requêtes (utilise la config sinon)
            window_seconds: Fenêtre de temps en secondes
        
        Returns:
            Tuple (is_allowed, info_dict)
        """
        if max_requests is None:
            max_requests = self.max_requests
        if window_seconds is None:
            window_seconds = self.window_seconds

        key = f"rate_limit:{identifier}"
        now = datetime.utcnow().timestamp()
        window_start = now - window_seconds

        try:
            # Utiliser une pipeline Redis pour l'atomicité
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)  # Supprimer les anciennes entrées
            pipe.zcard(key)  # Compter les requêtes dans la fenêtre
            pipe.zadd(key, {str(now): now})  # Ajouter la requête actuelle
            pipe.expire(key, window_seconds + 1)  # Expiration auto
            results = pipe.execute()

            current_count = results[1]
            is_allowed = current_count < max_requests
            remaining = max(0, max_requests - current_count - 1)

            info = {
                "allowed": is_allowed,
                "limit": max_requests,
                "remaining": remaining,
                "reset_at": datetime.fromtimestamp(
                    now + window_seconds
                ).isoformat(),
            }

            if not is_allowed:
                logger.warning(
                    f"Rate limit exceeded for {identifier}: {current_count}/{max_requests}"
                )

            return is_allowed, info

        except redis.RedisError as e:
            logger.error(f"Rate limiter Redis error: {str(e)}")
            # En cas d'erreur Redis, on laisse passer (fail open)
            return True, {"allowed": True, "limit": max_requests, "remaining": max_requests}

    def get_status(self, identifier: str, window_seconds: int = None) -> dict:
        """Obtient le statut actuel du rate limit."""
        if window_seconds is None:
            window_seconds = self.window_seconds

        key = f"rate_limit:{identifier}"
        now = datetime.utcnow().timestamp()
        window_start = now - window_seconds

        try:
            count = self.redis.zcount(key, window_start, now)
            return {
                "identifier": identifier,
                "requests_in_window": count,
                "limit": self.max_requests,
                "remaining": max(0, self.max_requests - count),
            }
        except redis.RedisError:
            return {}

    def reset(self, identifier: str) -> bool:
        """Réinitialise le compteur pour un identifier."""
        key = f"rate_limit:{identifier}"
        try:
            self.redis.delete(key)
            logger.info(f"Rate limit reset for {identifier}")
            return True
        except redis.RedisError as e:
            logger.error(f"Error resetting rate limit: {str(e)}")
            return False


class BruteForceProtector:
    """Protection contre les attaques par force brute sur login."""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.max_attempts = settings.BRUTE_FORCE_MAX_ATTEMPTS
        self.lockout_minutes = settings.BRUTE_FORCE_LOCKOUT_MINUTES

    def is_account_locked(self, user_identifier: str) -> Tuple[bool, int]:
        """Vérifie si un compte est temporairement verrouillé.
        
        Returns:
            Tuple (is_locked, minutes_remaining)
        """
        key = f"brute_force:lock:{user_identifier}"
        try:
            ttl = self.redis.ttl(key)
            if ttl > 0:
                minutes_remaining = (ttl + 59) // 60  # Round up
                return True, minutes_remaining
            return False, 0
        except redis.RedisError:
            return False, 0

    def record_failed_attempt(
        self, user_identifier: str
    ) -> Tuple[bool, int, int]:
        """Enregistre une tentative échouée.
        
        Returns:
            Tuple (should_lock, attempts, remaining_before_lock)
        """
        attempts_key = f"brute_force:attempts:{user_identifier}"
        lock_key = f"brute_force:lock:{user_identifier}"

        try:
            pipe = self.redis.pipeline()
            pipe.incr(attempts_key)
            pipe.expire(attempts_key, self.lockout_minutes * 60)
            results = pipe.execute()

            attempts = results[0]
            remaining = max(0, self.max_attempts - attempts)
            should_lock = attempts >= self.max_attempts

            if should_lock:
                # Verrouiller le compte
                self.redis.setex(
                    lock_key,
                    self.lockout_minutes * 60,
                    "locked",
                )
                logger.warning(
                    f"Account locked after {attempts} failed attempts: {user_identifier}"
                )

            return should_lock, attempts, remaining

        except redis.RedisError as e:
            logger.error(f"Brute force protector error: {str(e)}")
            return False, 0, self.max_attempts

    def reset_attempts(self, user_identifier: str) -> bool:
        """Réinitialise les tentatives échouées après login réussi."""
        attempts_key = f"brute_force:attempts:{user_identifier}"
        lock_key = f"brute_force:lock:{user_identifier}"

        try:
            pipe = self.redis.pipeline()
            pipe.delete(attempts_key)
            pipe.delete(lock_key)
            pipe.execute()
            return True
        except redis.RedisError as e:
            logger.error(f"Error resetting attempts: {str(e)}")
            return False
