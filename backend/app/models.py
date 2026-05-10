"""SQLAlchemy models with audit trail and security features."""
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    """
    User account model with security audit trail.
    
    Fields:
    - Email (unique, indexed)
    - Username (unique, indexed)
    - Hashed password (Bcrypt)
    - 2FA settings (TOTP secret)
    - Account status (active, verified)
    - Timestamps (created, updated, last login)
    - IP tracking (created_ip, last_login_ip)
    - Audit relationships
    """
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    
    # Account status
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)
    is_2fa_enabled = Column(Boolean, default=False)
    
    # 2FA (TOTP) settings
    totp_secret = Column(String(255), nullable=True)  # Encrypted
    totp_backup_codes = Column(JSON, nullable=True)  # Encrypted
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # IP tracking
    created_ip = Column(String(45), nullable=True)  # IPv6 support
    last_login_ip = Column(String(45), nullable=True)
    
    # Relationships
    password_history = relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    sessions = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"


class PasswordHistory(Base):
    """
    Password history to prevent reuse.
    
    Stores hashes of previous passwords.
    Prevents users from reusing the same password.
    
    Fields:
    - User ID (foreign key)
    - Hashed password
    - Created timestamp
    """
    
    __tablename__ = "password_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="password_history")
    
    def __repr__(self):
        return f"<PasswordHistory(user_id={self.user_id})>"


class Session(Base):
    """
    User session management.
    
    Tracks active sessions for:
    - Device management
    - Session hijacking detection
    - Token revocation
    - Device fingerprinting
    
    Fields:
    - User ID (foreign key)
    - JWT refresh token
    - IP address
    - User-Agent (device info)
    - Expiration timestamp
    - Status (active/revoked)
    """
    
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(1000), nullable=False, index=True)  # JWT token
    
    # Device tracking
    ip_address = Column(String(45), nullable=False)  # IPv6 support
    user_agent = Column(String(500), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, index=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<Session(user_id={self.user_id}, ip={self.ip_address})>"


class AuditLog(Base):
    """
    Comprehensive audit log for security and compliance.
    
    Tracks all security-related events:
    - Login/logout
    - Password changes
    - Profile updates
    - Permission changes
    - Failed auth attempts
    - Admin actions
    
    Fields:
    - User ID (who performed the action)
    - Action (type of action)
    - Resource (what was affected)
    - IP address (where from)
    - Details (JSON with additional info)
    - Timestamp
    """
    
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    # Action details
    action = Column(String(100), nullable=False, index=True)  # e.g., LOGIN_SUCCESS
    resource = Column(String(100), nullable=False, index=True)  # e.g., "user", "auth"
    resource_id = Column(Integer, nullable=True)  # ID of affected resource
    
    # Request details
    ip_address = Column(String(45), nullable=False)  # IPv6 support
    user_agent = Column(String(500), nullable=True)
    
    # Additional details (JSON)
    details = Column(JSON, nullable=True)
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog(action={self.action}, user_id={self.user_id})>"
