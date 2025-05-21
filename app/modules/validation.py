import re
from typing import Tuple

def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate email format using regex
    Returns: (is_valid, message)
    """
    # RFC 5322 compliant email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not email:
        return False, "Email is required"
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    return True, "Valid email"

def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username:
    - Length between 5 and 20 characters
    - No spaces or special characters
    - Only letters, numbers, and underscores
    Returns: (is_valid, message)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 5 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters"
    
    # Only allow letters, numbers, and underscores
    username_pattern = r'^[a-zA-Z0-9_]+$'
    if not re.match(username_pattern, username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, "Valid username"

def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password:
    - Length between 6 and 20 characters
    Returns: (is_valid, message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 6 or len(password) > 20:
        return False, "Password must be between 6 and 20 characters"
    
    return True, "Valid password" 