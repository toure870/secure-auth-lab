"""Modèles SQLAlchemy pour les utilisateurs."""

from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Text, 
    LargeBinary, ForeignKey, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()


class User(Base):
    """Modèle utilisateur avec audit trail et 2FA."""
    __tablename__ = "users"

    # Identifiants
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)

    # Authentification
    password_hash = Column(String(255), nullable=False)  # Bcrypt hash
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)
    email_verified_at = Column(DateTime, nullable=True)

    # 2FA
    totp_secret = Column(String(32), nullable=True)  # Base32 encoded
    is_2fa_enabled = Column(Boolean, default=False)
    backup_codes = Column(Text, nullable=True)  # JSON encrypted

    # Audit Trail
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    last_password_change_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    account_locked_until = Column(DateTime, nullable=True)  # Pour brute force
    login_attempts = Column(Integer, default=0)  # Compteur pour brute force

    # Relations
    password_history = relationship("PasswordHistory", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint('email', name='uq_user_email'),
        UniqueConstraint('username', name='uq_user_username'),
        Index('ix_user_created_at', 'created_at'),
        Index('ix_user_is_active', 'is_active'),
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"


class PasswordHistory(Base):
    """Historique des mots de passe pour prévenir la réutilisation."""
    __tablename__ = "password_history"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relation
    user = relationship("User", back_populates="password_history")

    __table_args__ = (
        Index('ix_password_history_user_id', 'user_id'),
        Index('ix_password_history_created_at', 'created_at'),
    )


class Session(Base):
    """Sessions utilisateur avec tracking device et expiration."""
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    token = Column(String(512), unique=True, nullable=False, index=True)  # Hashed token
    device_info = Column(Text, nullable=True)  # JSON: user agent, ip, etc.
    ip_address = Column(String(45), nullable=True)  # IPv4 ou IPv6
    user_agent = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_activity_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relation
    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index('ix_session_user_id_active', 'user_id', 'is_active'),
        Index('ix_session_expires_at', 'expires_at'),
    )


class AuditLog(Base):
    """Audit trail pour toutes les actions sensibles."""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)  # LOGIN, LOGOUT, PASSWORD_CHANGE, etc.
    resource_type = Column(String(50), nullable=True)  # USER, SESSION, etc.
    resource_id = Column(String(36), nullable=True)
    status = Column(String(20), nullable=False)  # SUCCESS, FAILURE
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(Text, nullable=True)  # JSON: données additionnelles
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relation
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index('ix_audit_log_user_id', 'user_id'),
        Index('ix_audit_log_action', 'action'),
        Index('ix_audit_log_created_at', 'created_at'),
        Index('ix_audit_log_status', 'status'),
    )
