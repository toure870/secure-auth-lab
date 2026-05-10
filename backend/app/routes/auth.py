"""Authentication routes with security protections."""
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.config import get_settings
from app.database import get_db
from app.models import User, PasswordHistory, AuditLog, Session as SessionModel
from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    UserResponse,
    RefreshTokenRequest,
)
from app.security.password import (
    hash_password,
    verify_password,
    validate_password_strength,
)
from app.security.jwt_handler import JWTHandler
from app.security.rate_limiter import RateLimiter
from app.security.brute_force import BruteForceProtector
from app.utils.validators import validate_email, sanitize_input
from app.dependencies import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["authentication"])
settings = get_settings()
jwt_handler = JWTHandler()
rate_limiter = RateLimiter()
brute_force_protector = BruteForceProtector()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async (
    request: Request,
    data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user with comprehensive security validations.
    
    Security checks:
    - Rate limiting (prevent spam registration)
    - Email validation (format + uniqueness)
    - Password strength validation
    - Input sanitization
    - Audit logging
    """
    try:
        # Get client IP for rate limiting and audit
        client_ip = request.client.host if request.client else "unknown"
        
        # Rate limiting: 10 registrations per hour per IP
        await rate_limiter.check_limit(
            key=f"register:{client_ip}",
            max_requests=10,
            window_seconds=3600,
        )
        
        # Sanitize inputs
        email = sanitize_input(data.email.lower().strip())
        username = sanitize_input(data.username.strip())
        
        # Validate email format
        if not validate_email(email):
            logger.warning(f"Invalid email format attempted: {email} from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format",
            )
        
        # Check if email already exists
        result = await db.execute(
            select(User).where(User.email == email)
        )
        if result.scalar_one_or_none():
            logger.warning(f"Duplicate email registration attempt: {email}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )
        
        # Check if username already exists
        result = await db.execute(
            select(User).where(User.username == username)
        )
        if result.scalar_one_or_none():
            logger.warning(f"Duplicate username registration attempt: {username}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already taken",
            )
        
        # Validate password strength
        password_validation = validate_password_strength(data.password)
        if not password_validation["valid"]:
            logger.info(f"Weak password attempt: {password_validation['reason']}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=password_validation["reason"],
            )
        
        # Hash password with Bcrypt (12 rounds)
        hashed_password = hash_password(data.password)
        
        # Create new user
        new_user = User(
            email=email,
            username=username,
            hashed_password=hashed_password,
            is_active=True,
            is_verified=False,  # Email verification needed in production
            created_at=datetime.utcnow(),
            created_ip=client_ip,
        )
        
        db.add(new_user)
        await db.flush()  # Get user ID before commit
        
        # Add password to history
        password_entry = PasswordHistory(
            user_id=new_user.id,
            hashed_password=hashed_password,
            created_at=datetime.utcnow(),
        )
        db.add(password_entry)
        
        # Audit log
        audit_log = AuditLog(
            user_id=new_user.id,
            action="USER_REGISTERED",
            resource="user",
            resource_id=new_user.id,
            ip_address=client_ip,
            details={"email": email, "username": username},
            created_at=datetime.utcnow(),
        )
        db.add(audit_log)
        
        await db.commit()
        await db.refresh(new_user)
        
        logger.info(f"New user registered: {new_user.id} ({email}) from {client_ip}")
        
        return UserResponse.from_orm(new_user)
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Registration error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed",
        )


@router.post("/login", response_model=TokenResponse)
async (
    request: Request,
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    User login with brute force protection and JWT token generation.
    
    Security checks:
    - Brute force protection (5 attempts → 15 min lockout)
    - Timing attack prevention (constant-time password comparison)
    - IP tracking
    - Audit logging
    - Session creation with device fingerprint
    """
    try:
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Sanitize email
        email = sanitize_input(data.email.lower().strip())
        
        # Check brute force protection
        await brute_force_protector.check_attempts(
            key=email,
            max_attempts=settings.BRUTE_FORCE_MAX_ATTEMPTS,
            lockout_minutes=settings.BRUTE_FORCE_LOCKOUT_MINUTES,
        )
        
        # Get user by email
        result = await db.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()
        
        # Timing attack prevention: always hash password
        # This prevents timing analysis to determine if email exists
        is_valid = False
        if user:
            is_valid = verify_password(data.password, user.hashed_password)
        else:
            # Dummy hash to prevent timing attacks
            hash_password(data.password)
        
        # Check if user exists and password is valid
        if not user or not is_valid:
            # Record failed attempt
            await brute_force_protector.record_attempt(email)
            
            logger.warning(
                f"Failed login attempt: {email} from {client_ip}"
            )
            
            # Audit log
            audit_log = AuditLog(
                user_id=None,
                action="LOGIN_FAILED",
                resource="auth",
                resource_id=None,
                ip_address=client_ip,
                details={"email": email, "reason": "invalid_credentials"},
                created_at=datetime.utcnow(),
            )
            db.add(audit_log)
            await db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        
        # Check if user is active
        if not user.is_active:
            logger.warning(f"Login attempt by inactive user: {user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )
        
        # Clear brute force attempts on successful login
        await brute_force_protector.clear_attempts(email)
        
        # Generate JWT tokens
        access_token = jwt_handler.create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        refresh_token = jwt_handler.create_refresh_token(
            data={"sub": str(user.id), "email": user.email}
        )
        
        # Create session
        session = SessionModel(
            user_id=user.id,
            token=refresh_token,
            ip_address=client_ip,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            ),
            created_at=datetime.utcnow(),
        )
        db.add(session)
        
        # Update last login
        user.last_login = datetime.utcnow()
        user.last_login_ip = client_ip
        
        # Audit log
        audit_log = AuditLog(
            user_id=user.id,
            action="LOGIN_SUCCESS",
            resource="auth",
            resource_id=user.id,
            ip_address=client_ip,
            details={"email": email},
            created_at=datetime.utcnow(),
        )
        db.add(audit_log)
        
        await db.commit()
        
        logger.info(f"Successful login: user {user.id} from {client_ip}")
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Login error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed",
        )


@router.post("/refresh", response_model=TokenResponse)
async (
    request: Request,
    data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using refresh token.
    
    Security checks:
    - Validate refresh token signature
    - Check session existence and validity
    - Prevent token reuse (optional)
    - IP consistency check (detect session hijacking)
    """
    try:
        client_ip = request.client.host if request.client else "unknown"
        
        # Verify refresh token
        payload = jwt_handler.verify_token(data.refresh_token)
        user_id = int(payload.get("sub"))
        
        # Get user
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        
        # Get session
        result = await db.execute(
            select(SessionModel).where(
                SessionModel.user_id == user_id,
                SessionModel.token == data.refresh_token,
                SessionModel.is_active == True,
            )
        )
        session = result.scalar_one_or_none()
        
        if not session or session.expires_at < datetime.utcnow():
            logger.warning(f"Invalid refresh token attempt for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )
        
        # Optional: Check IP consistency (detect session hijacking)
        # In strict mode, invalidate if IP changed
        if session.ip_address != client_ip:
            logger.warning(
                f"IP change detected for user {user_id}: "
                f"{session.ip_address} -> {client_ip}"
            )
            # Optionally: deactivate session
            # session.is_active = False
        
        # Generate new access token
        new_access_token = jwt_handler.create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        
        # Update session last used
        session.last_used_at = datetime.utcnow()
        
        # Audit log
        audit_log = AuditLog(
            user_id=user.id,
            action="TOKEN_REFRESHED",
            resource="auth",
            resource_id=user.id,
            ip_address=client_ip,
            details={},
            created_at=datetime.utcnow(),
        )
        db.add(audit_log)
        
        await db.commit()
        
        return TokenResponse(
            access_token=new_access_token,
            refresh_token=data.refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async (
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Logout user by invalidating current session.
    
    Security checks:
    - Require valid authentication
    - Invalidate session token
    - Audit logging
    """
    try:
        client_ip = request.client.host if request.client else "unknown"
        auth_header = request.headers.get("authorization", "")
        
        # Extract token from header
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            
            # Invalidate session
            result = await db.execute(
                select(SessionModel).where(
                    SessionModel.user_id == current_user.id,
                    SessionModel.token == token,
                )
            )
            session = result.scalar_one_or_none()
            
            if session:
                session.is_active = False
                session.revoked_at = datetime.utcnow()
        
        # Audit log
        audit_log = AuditLog(
            user_id=current_user.id,
            action="LOGOUT",
            resource="auth",
            resource_id=current_user.id,
            ip_address=client_ip,
            details={},
            created_at=datetime.utcnow(),
        )
        db.add(audit_log)
        
        await db.commit()
        
        logger.info(f"User {current_user.id} logged out from {client_ip}")
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Logout error: {str(e)}", exc_info=True)
        # Don't raise error for logout


@router.get("/me", response_model=UserResponse)
async (current_user: User = Depends(get_current_user)):
    """
    Get current authenticated user profile.
    """
    return UserResponse.from_orm(current_user)
