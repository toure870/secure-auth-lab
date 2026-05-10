"""JWT token creation and verification with security best practices."""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging

from jose import JWTError, jwt
from pydantic import ValidationError

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class JWTHandler:
    """
    JWT token handler with best practices:
    - HS256 algorithm (symmetric)
    - Short-lived access tokens (15 min)
    - Longer refresh tokens (7 days)
    - Token type in claims
    - Issued-at and expiration validation
    """
    
    def __init__(
        self,
        secret_key: str = settings.SECRET_KEY,
        algorithm: str = settings.ALGORITHM,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """
        Create short-lived access token.
        
        Args:
            data: Claims to include (user_id, email, etc.)
        
        Returns:
            Signed JWT token
        """
        to_encode = data.copy()
        
        # Add standard claims
        now = datetime.utcnow()
        expires = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({
            "type": "access",  # Token type for validation
            "iat": now,  # Issued at
            "exp": expires,  # Expiration
        })
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.secret_key,
            algorithm=self.algorithm,
        )
        
        logger.debug(f"Access token created for user {data.get('sub')}")
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """
        Create long-lived refresh token.
        
        Args:
            data: Claims to include (user_id, email, etc.)
        
        Returns:
            Signed JWT token
        """
        to_encode = data.copy()
        
        # Add standard claims
        now = datetime.utcnow()
        expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
        to_encode.update({
            "type": "refresh",  # Token type for validation
            "iat": now,
            "exp": expires,
        })
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.secret_key,
            algorithm=self.algorithm,
        )
        
        logger.debug(f"Refresh token created for user {data.get('sub')}")
        return encoded_jwt
    
    def verify_token(
        self,
        token: str,
        token_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify JWT token signature and claims.
        
        Args:
            token: JWT token to verify
            token_type: Expected token type ("access", "refresh", or None)
        
        Returns:
            Decoded token payload
        
        Raises:
            JWTError: If token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
            )
            
            # Validate token type if specified
            if token_type and payload.get("type") != token_type:
                logger.warning(
                    f"Token type mismatch: expected {token_type}, "
                    f"got {payload.get('type')}"
                )
                raise JWTError("Invalid token type")
            
            # Extract subject (user_id)
            subject: str = payload.get("sub")
            if subject is None:
                raise JWTError("Token missing subject")
            
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT verification failed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected token verification error: {str(e)}")
            raise JWTError(f"Token verification failed: {str(e)}")
    
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Safely decode token without raising exception.
        
        Returns None if token is invalid.
        """
        try:
            return self.verify_token(token)
        except JWTError:
            return None
    
    def is_token_expired(self, token: str) -> bool:
        """
        Check if token is expired without full verification.
        """
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False},
            )
            exp = payload.get("exp")
            if exp:
                return datetime.fromtimestamp(exp) < datetime.utcnow()
            return False
        except Exception:
            return True
