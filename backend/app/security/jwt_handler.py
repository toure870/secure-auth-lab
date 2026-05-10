"""Gestion sécurisée des JWT tokens avec accès et refresh tokens."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from app.config import settings
import logging

logger = logging.getLogger(__name__)


class TokenPayload:
    """Payload structuré pour les tokens JWT."""

    def __init__(
        self,
        sub: str,
        user_id: str,
        email: str,
        username: str,
        is_2fa_enabled: bool = False,
        type: str = "access",
        iat: Optional[datetime] = None,
        exp: Optional[datetime] = None,
        jti: Optional[str] = None,
    ):
        self.sub = sub  # Subject (user_id)
        self.user_id = user_id
        self.email = email
        self.username = username
        self.is_2fa_enabled = is_2fa_enabled
        self.type = type  # "access" ou "refresh"
        self.iat = iat or datetime.now(timezone.utc)
        self.exp = exp
        self.jti = jti  # JWT ID pour revocation tracking

    def to_dict(self) -> Dict[str, Any]:
        """Convertit le payload en dictionnaire."""
        return {
            "sub": self.sub,
            "user_id": self.user_id,
            "email": self.email,
            "username": self.username,
            "is_2fa_enabled": self.is_2fa_enabled,
            "type": self.type,
            "iat": self.iat.timestamp(),
            "exp": self.exp.timestamp() if self.exp else None,
            "jti": self.jti,
        }


class JWTHandler:
    """Gestion sécurisée des JWT tokens."""

    @staticmethod
    def create_token(
        user_id: str,
        email: str,
        username: str,
        is_2fa_enabled: bool = False,
        token_type: str = "access",
        expires_delta: Optional[timedelta] = None,
        jti: Optional[str] = None,
    ) -> str:
        """Crée un JWT token signé.
        
        Args:
            user_id: ID de l'utilisateur
            email: Email de l'utilisateur
            username: Username de l'utilisateur
            is_2fa_enabled: Si 2FA est activé
            token_type: "access" ou "refresh"
            expires_delta: Délai d'expiration personnalisé
            jti: JWT ID pour le revocation tracking
        
        Returns:
            Token JWT signé
        """
        if expires_delta is None:
            if token_type == "access":
                expires_delta = timedelta(
                    minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
                )
            else:  # refresh
                expires_delta = timedelta(
                    days=settings.REFRESH_TOKEN_EXPIRE_DAYS
                )

        now = datetime.now(timezone.utc)
        expire = now + expires_delta

        payload = TokenPayload(
            sub=user_id,
            user_id=user_id,
            email=email,
            username=username,
            is_2fa_enabled=is_2fa_enabled,
            type=token_type,
            iat=now,
            exp=expire,
            jti=jti,
        )

        token = jwt.encode(
            payload.to_dict(),
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )

        logger.info(
            f"Token created",
            extra={
                "user_id": user_id,
                "token_type": token_type,
                "expires_at": expire.isoformat(),
            },
        )

        return token

    @staticmethod
    def create_access_token(
        user_id: str,
        email: str,
        username: str,
        is_2fa_enabled: bool = False,
    ) -> str:
        """Crée un access token avec expiration courte."""
        return JWTHandler.create_token(
            user_id=user_id,
            email=email,
            username=username,
            is_2fa_enabled=is_2fa_enabled,
            token_type="access",
        )

    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        """Crée un refresh token avec expiration longue."""
        return JWTHandler.create_token(
            user_id=user_id,
            email="",  # Refresh tokens n'ont pas besoin de l'email
            username="",
            token_type="refresh",
        )

    @staticmethod
    def create_token_pair(
        user_id: str,
        email: str,
        username: str,
        is_2fa_enabled: bool = False,
    ) -> Dict[str, str]:
        """Crée une paire access + refresh token."""
        access_token = JWTHandler.create_access_token(
            user_id=user_id,
            email=email,
            username=username,
            is_2fa_enabled=is_2fa_enabled,
        )
        refresh_token = JWTHandler.create_refresh_token(user_id=user_id)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    @staticmethod
    def verify_token(token: str, token_type: str = "access") -> Optional[TokenPayload]:
        """Vérifie et décode un JWT token.
        
        Args:
            token: Token JWT à vérifier
            token_type: Type attendu du token ("access" ou "refresh")
        
        Returns:
            TokenPayload si valide, None sinon
        """
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
            )

            # Vérifier que le type de token correspond
            if payload.get("type") != token_type:
                logger.warning(
                    f"Token type mismatch: expected {token_type}, got {payload.get('type')}"
                )
                return None

            return TokenPayload(
                sub=payload.get("sub"),
                user_id=payload.get("user_id"),
                email=payload.get("email", ""),
                username=payload.get("username", ""),
                is_2fa_enabled=payload.get("is_2fa_enabled", False),
                type=payload.get("type"),
                iat=datetime.fromtimestamp(
                    payload.get("iat"), tz=timezone.utc
                ),
                exp=datetime.fromtimestamp(
                    payload.get("exp"), tz=timezone.utc
                ) if payload.get("exp") else None,
                jti=payload.get("jti"),
            )

        except JWTError as e:
            logger.warning(f"Token verification failed: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return None

    @staticmethod
    def extract_user_id(token: str) -> Optional[str]:
        """Extrait l'user_id d'un token sans validation complète."""
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
            )
            return payload.get("user_id")
        except JWTError:
            return None
