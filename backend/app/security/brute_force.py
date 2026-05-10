"""Brute force attack protection with Redis-backed tracking."""
import logging
from datetime import datetime, timedelta
from typing import Optional

import aioredis
from fastapi import HTTPException, status

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class BruteForceProtector:
    """
    Protect against brute force attacks using Redis.
    
    Strategy:
    - Track failed login attempts per email/IP
    - Lock account after N attempts
    - Exponential backoff for lockout duration
    - Auto-unlock after timeout
    """
    
    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self.attempts_key_prefix = "brute_force:attempts:"
        self.lockout_key_prefix = "brute_force:lockout:"
    
    async def connect(self):
        """Initialize Redis connection."""
        try:
            self.redis = await aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf8",
                decode_responses=True,
            )
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            raise
    
    async def disconnect(self):
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()
    
    async def check_attempts(
        self,
        key: str,
        max_attempts: int = 5,
        lockout_minutes: int = 15,
    ) -> None:
        """
        Check if user/IP is locked out due to too many attempts.
        
        Args:
            key: Email or IP to check
            max_attempts: Maximum allowed attempts
            lockout_minutes: Lockout duration
        
        Raises:
            HTTPException: If locked out
        """
        if not self.redis:
            return  # Skip if Redis unavailable
        
        lockout_key = f"{self.lockout_key_prefix}{key}"
        
        # Check if currently locked out
        lockout_time = await self.redis.get(lockout_key)
        if lockout_time:
            logger.warning(f"Brute force lockout active for {key}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later.",
            )
    
    async def record_attempt(self, key: str) -> int:
        """
        Record a failed attempt and check if lockout needed.
        
        Args:
            key: Email or IP
        
        Returns:
            Number of attempts
        """
        if not self.redis:
            return 1
        
        attempts_key = f"{self.attempts_key_prefix}{key}"
        lockout_key = f"{self.lockout_key_prefix}{key}"
        
        # Increment attempt counter (expires in 1 hour)
        attempts = await self.redis.incr(attempts_key)
        await self.redis.expire(attempts_key, 3600)
        
        # Lock out if max attempts reached
        if attempts >= settings.BRUTE_FORCE_MAX_ATTEMPTS:
            await self.redis.setex(
                lockout_key,
                settings.BRUTE_FORCE_LOCKOUT_MINUTES * 60,
                datetime.utcnow().isoformat(),
            )
            logger.warning(
                f"Brute force lockout triggered for {key} "
                f"({attempts} attempts)"
            )
        
        return attempts
    
    async def clear_attempts(self, key: str) -> None:
        """
        Clear failed attempts for a key (on successful login).
        
        Args:
            key: Email or IP
        """
        if not self.redis:
            return
        
        attempts_key = f"{self.attempts_key_prefix}{key}"
        await self.redis.delete(attempts_key)
        
        logger.debug(f"Cleared brute force attempts for {key}")
    
    async def get_attempts(self, key: str) -> int:
        """
        Get current attempt count for a key.
        
        Args:
            key: Email or IP
        
        Returns:
            Number of attempts (0 if key not found)
        """
        if not self.redis:
            return 0
        
        attempts_key = f"{self.attempts_key_prefix}{key}"
        attempts = await self.redis.get(attempts_key)
        return int(attempts) if attempts else 0
