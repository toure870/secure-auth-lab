"""Rate limiting using sliding window algorithm with Redis."""
import logging
from datetime import datetime, timedelta
from typing import Optional

import aioredis
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiting using sliding window algorithm.
    
    Benefits:
    - Prevents DDoS attacks
    - Prevents brute force attacks
    - Fair rate limiting per user/IP
    - Configurable per endpoint
    - Redis-backed for distributed systems
    """
    
    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self.key_prefix = "rate_limit:"
    
    async def connect(self, redis_url: str):
        """Initialize Redis connection."""
        try:
            self.redis = await aioredis.from_url(
                redis_url,
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
    
    async def check_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> bool:
        """
        Check if request is within rate limit.
        
        Uses sliding window algorithm:
        - Track timestamps of requests
        - Remove old requests outside window
        - Check if within limit
        
        Args:
            key: Unique identifier (user_id, IP, email, etc.)
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            True if within limit
        
        Raises:
            HTTPException: If rate limit exceeded
        """
        if not self.redis:
            return True  # Skip if Redis unavailable
        
        redis_key = f"{self.key_prefix}{key}"
        now = datetime.utcnow().timestamp()
        window_start = now - window_seconds
        
        # Remove old requests outside the window
        await self.redis.zremrangebyscore(
            redis_key,
            0,
            window_start,
        )
        
        # Count requests in window
        request_count = await self.redis.zcard(redis_key)
        
        if request_count >= max_requests:
            logger.warning(
                f"Rate limit exceeded for {key}: "
                f"{request_count}/{max_requests} requests"
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
            )
        
        # Add current request
        await self.redis.zadd(redis_key, {str(now): now})
        
        # Set key expiration (cleanup old keys)
        await self.redis.expire(redis_key, window_seconds)
        
        return True
    
    async def get_remaining(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> int:
        """
        Get remaining requests for a key.
        
        Returns:
            Number of remaining requests
        """
        if not self.redis:
            return max_requests
        
        redis_key = f"{self.key_prefix}{key}"
        now = datetime.utcnow().timestamp()
        window_start = now - window_seconds
        
        # Count requests in window
        request_count = await self.redis.zcount(
            redis_key,
            window_start,
            now,
        )
        
        remaining = max(0, max_requests - request_count)
        return remaining
    
    async def reset(
        self,
        key: str,
    ) -> None:
        """
        Reset rate limit for a key.
        
        Args:
            key: Key to reset
        """
        if not self.redis:
            return
        
        redis_key = f"{self.key_prefix}{key}"
        await self.redis.delete(redis_key)
        logger.debug(f"Reset rate limit for {key}")
