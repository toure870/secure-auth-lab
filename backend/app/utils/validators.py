"""Input validation and sanitization utilities."""
import re
from typing import Optional
from email_validator import validate_email as validate_email_lib, EmailNotValidError
import logging

logger = logging.getLogger(__name__)


def validate_email(email: str) -> bool:
    """
    Validate email format using industry standards.
    
    Security:
    - Uses email_validator library (handles RFC 5322)
    - Prevents invalid email injection
    - Checks DNS (optional)
    
    Args:
        email: Email address to validate
    
    Returns:
        True if valid, False otherwise
    """
    try:
        # Validate and normalize email
        validate_email_lib(email, check_deliverability=False)
        return True
    except EmailNotValidError as e:
        logger.debug(f"Invalid email format: {email} - {str(e)}")
        return False


def sanitize_input(value: str, max_length: int = 255) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks.
    
    Security:
    - Strip whitespace
    - Remove null bytes
    - Limit length
    - Remove control characters
    
    Args:
        value: Input value to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized value
    """
    if not isinstance(value, str):
        return str(value)[:max_length]
    
    # Strip whitespace
    value = value.strip()
    
    # Remove null bytes
    value = value.replace("\x00", "")
    
    # Remove control characters (except newline, tab)
    value = re.sub(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]", "", value)
    
    # Limit length
    value = value[:max_length]
    
    return value


def validate_username(username: str) -> bool:
    """
    Validate username format.
    
    Rules:
    - 3-50 characters
    - Alphanumeric, underscore, hyphen only
    - Cannot start/end with underscore or hyphen
    
    Args:
        username: Username to validate
    
    Returns:
        True if valid
    """
    if not isinstance(username, str):
        return False
    
    # Length check
    if len(username) < 3 or len(username) > 50:
        return False
    
    # Pattern check
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$", username):
        # Allow single character that's alphanumeric
        if len(username) == 1 and re.match(r"^[a-zA-Z0-9]$", username):
            return True
        return False
    
    return True


def escape_html(value: str) -> str:
    """
    Escape HTML special characters to prevent XSS.
    
    Args:
        value: String to escape
    
    Returns:
        HTML-escaped string
    """
    if not isinstance(value, str):
        return str(value)
    
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#x27;",
        ">": "&gt;",
        "<": "&lt;",
    }
    
    return "".join(html_escape_table.get(c, c) for c in value)


def validate_password_format(password: str) -> bool:
    """
    Quick password format validation (length only).
    
    Full validation in password.py with strength checks.
    
    Args:
        password: Password to validate
    
    Returns:
        True if minimum format requirements met
    """
    if not isinstance(password, str):
        return False
    
    # Minimum length check
    if len(password) < 12:
        return False
    
    # Maximum length check (prevent ReDoS attacks)
    if len(password) > 512:
        return False
    
    return True


def is_safe_filename(filename: str) -> bool:
    """
    Validate filename for upload security.
    
    Prevents:
    - Directory traversal (../, ..\\)
    - Null bytes
    - Path separators
    
    Args:
        filename: Filename to validate
    
    Returns:
        True if safe
    """
    if not filename or not isinstance(filename, str):
        return False
    
    # Check for directory traversal
    if ".." in filename or filename.startswith("/"):
        return False
    
    # Check for null bytes
    if "\x00" in filename:
        return False
    
    # Check for path separators
    if "\\" in filename or "/" in filename:
        return False
    
    # Only allow safe characters
    if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
        return False
    
    return True
