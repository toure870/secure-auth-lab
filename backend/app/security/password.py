"""Password security utilities: hashing, validation, strength checks."""
import re
import bcrypt
from typing import Dict, Any

from app.config import get_settings

settings = get_settings()


def hash_password(password: str) -> str:
    """
    Hash password using Bcrypt with 12 rounds.
    
    Security:
    - Bcrypt with 12 rounds provides good balance between security and speed
    - Automatically handles salt generation
    - Resistant to GPU/ASIC attacks
    """
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify password against hash using constant-time comparison.
    
    Security:
    - Uses bcrypt.checkpw for constant-time comparison
    - Prevents timing attacks that could leak password info
    """
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password against security requirements.
    
    Requirements:
    - Minimum length (configurable, default 12)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    
    Returns:
        Dict with 'valid' (bool) and 'reason' (str)
    """
    checks = {
        "length": len(password) >= settings.PASSWORD_MIN_LENGTH,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[!@#$%^&*()_+=\-\[\]{};:'\",.<>?/\\|`~]", password)),
    }
    
    # Check which conditions are required
    required = {
        "length": True,
        "uppercase": settings.PASSWORD_REQUIRE_UPPERCASE,
        "lowercase": settings.PASSWORD_REQUIRE_LOWERCASE,
        "digits": settings.PASSWORD_REQUIRE_DIGITS,
        "special": settings.PASSWORD_REQUIRE_SPECIAL,
    }
    
    # Validate
    reasons = []
    if not checks["length"]:
        reasons.append(
            f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
        )
    if required["uppercase"] and not checks["uppercase"]:
        reasons.append("Password must contain at least one uppercase letter")
    if required["lowercase"] and not checks["lowercase"]:
        reasons.append("Password must contain at least one lowercase letter")
    if required["digits"] and not checks["digits"]:
        reasons.append("Password must contain at least one digit")
    if required["special"] and not checks["special"]:
        reasons.append("Password must contain at least one special character")
    
    if reasons:
        return {"valid": False, "reason": ". ".join(reasons)}
    
    return {"valid": True, "reason": ""}


def check_password_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of password.
    
    Entropy > 50 is considered strong
    Returns entropy value (0-100)
    """
    import math
    
    if not password:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / len(password)
        entropy -= probability * math.log2(probability)
    
    # Normalize to 0-100
    max_entropy = math.log2(128)  # ASCII printable characters
    normalized_entropy = (entropy / max_entropy) * 100
    
    return min(normalized_entropy, 100.0)
