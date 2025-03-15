"""
Security utilities for ASIRA

Handles authentication, authorization, password hashing, and JWT tokens.
Last updated: 2025-03-15 12:00:46 UTC
"""
import jwt
import time
import secrets
import hashlib
import logging
from typing import Dict, Optional, Union, Any
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from src.common.config import Settings

# Initialize logger
logger = logging.getLogger("asira.security")

# Initialize settings
settings = Settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")

# JWT token functions
def create_access_token(data: Dict[str, Any], expires_delta: Optional[float] = None) -> str:
    """
    Create a JWT access token
    
    Args:
        data: Data to encode in the token
        expires_delta: Optional expiration time override in seconds
        
    Returns:
        JWT token as string
    """
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = time.time() + expires_delta
    else:
        expire = time.time() + (settings.token_expire_minutes * 60)
        
    to_encode.update({"exp": expire})
    
    # Create token
    try:
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm="HS256")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating JWT token: {e}")
        raise

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JWT access token
    
    Args:
        token: JWT token to decode
        
    Returns:
        Decoded token data or None if invalid
    """
    try:
        return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to decode token: {e}")
        return None

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Get the current user from the token
    Use as a FastAPI dependency
    
    Args:
        token: JWT token from request
        
    Returns:
        User data from token
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
    
    # Verify expiration
    exp = payload.get("exp")
    if not exp or exp < time.time():
        logger.warning(f"Token expired at {datetime.fromtimestamp(exp).isoformat() if exp else 'unknown'}")
        raise credentials_exception
    
    # Verify required fields
    if "sub" not in payload:
        logger.error("Token missing 'sub' field")
        raise credentials_exception
        
    return payload

async def get_current_active_admin(current_user: Dict = Depends(get_current_user)) -> Dict:
    """
    Verify the current user is active and has admin role
    
    Args:
        current_user: Current user data
    
    Returns:
        Current user data if admin
    
    Raises:
        HTTPException: If user is not an admin
    """
    if current_user.get("role") != "admin":
        logger.warning(f"User {current_user.get('sub')} attempted admin action without admin role")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    return current_user

# Password utilities
def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password
        
    Returns:
        True if password matches hash, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

# Generate secure token
def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token
    
    Args:
        length: Length of token in bytes
        
    Returns:
        Secure random token as hexadecimal string
    """
    return secrets.token_hex(length)

# Generate API key
def generate_api_key() -> str:
    """
    Generate a secure API key with ASIRA prefix
    
    Returns:
        API key string
    """
    # Create format: asira_{timestamp}_{random_token}
    timestamp = int(time.time())
    random_part = secrets.token_hex(16)
    api_key = f"asira_{timestamp}_{random_part}"
    
    # Hash for storage
    hashed_key = hash_data(api_key)
    
    return api_key

# Hash data (for non-password use)
def hash_data(data: Union[str, bytes]) -> str:
    """
    Hash data using SHA-256
    
    Args:
        data: Data to hash
        
    Returns:
        Hexadecimal string of hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

# Permission management
def has_permission(user: Dict, required_permission: str) -> bool:
    """
    Check if a user has a specific permission
    
    Args:
        user: User data with role
        required_permission: Permission to check
        
    Returns:
        True if user has permission, False otherwise
    """
    # Role-based permission mapping
    role_permissions = {
        "admin": ["read", "write", "delete", "execute_playbook", "manage_users"],
        "analyst": ["read", "write", "execute_playbook"],
        "readonly": ["read"]
    }
    
    user_role = user.get("role", "readonly")
    allowed_permissions = role_permissions.get(user_role, [])
    
    return required_permission in allowed_permissions

def validate_csrf_token(token: str, session_token: str) -> bool:
    """
    Validate CSRF token against session token
    
    Args:
        token: CSRF token from request
        session_token: Token stored in session
    
    Returns:
        True if valid, False otherwise
    """
    if not token or not session_token:
        return False
    return secrets.compare_digest(token, session_token)

# Security headers
def get_security_headers() -> Dict[str, str]:
    """
    Get recommended security headers for responses
    
    Returns:
        Dictionary of security headers
    """
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-store",
        "Pragma": "no-cache"
    }
