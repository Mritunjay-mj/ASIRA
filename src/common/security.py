"""
Security utilities for ASIRA

Handles authentication, authorization, password hashing, and JWT tokens.
Last updated: 2025-03-15 17:29:56 UTC
Last updated by: Rahul
"""
import jwt
import time
import secrets
import hashlib
import logging
import ipaddress
import re
import uuid
import base64
from typing import Dict, Optional, Union, Any, List, Tuple, Callable, Set
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader, APIKeyQuery
from fastapi.security.utils import get_authorization_scheme_param
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.common.config import Settings
from src.common.logging_config import get_logger

# Initialize logger
logger = get_logger("asira.security")

# Initialize settings
settings = Settings()

# Password hashing context with configurable rounds
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.bcrypt_rounds
)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")

# API key authentication schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

# In-memory cache for rate limiting (will use Redis in production)
_rate_limit_cache: Dict[str, Dict[str, Any]] = {}

# In-memory cache for blocked IPs
_blocked_ips: Set[str] = set()

# In-memory cache for API key validation (short-term cache)
_api_key_cache: Dict[str, Dict[str, Any]] = {}

# Encryption key derived from secret key
_encryption_key = None

def _get_encryption_key() -> bytes:
    """
    Get encryption key derived from application secret key
    
    Returns:
        32-byte encryption key
    """
    global _encryption_key
    if _encryption_key is None:
        # Use PBKDF2 to derive a secure key from the app secret
        salt = b'asira_encryption_salt'  # Fixed salt for deterministic derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        _encryption_key = base64.urlsafe_b64encode(
            kdf.derive(settings.secret_key.encode())
        )
    return _encryption_key

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
        
    to_encode.update({
        "exp": expire,
        "iat": time.time(),  # Issued at time
        "jti": str(uuid.uuid4())  # Unique token ID
    })
    
    # Create token
    try:
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)
        logger.debug(f"Created JWT token for {to_encode.get('sub')} expiring at {datetime.fromtimestamp(expire).isoformat()}")
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
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to decode token: {e}")
        return None

def create_refresh_token(user_id: str, expires_delta: Optional[float] = None) -> str:
    """
    Create a JWT refresh token with longer expiry
    
    Args:
        user_id: User ID to include in the token
        expires_delta: Optional expiration time override in seconds
        
    Returns:
        JWT refresh token as string
    """
    # Default refresh token lifetime is 7 days
    if expires_delta is None:
        expires_delta = 60 * 60 * 24 * 7  # 7 days in seconds
    
    data = {
        "sub": user_id,
        "token_type": "refresh"
    }
    
    return create_access_token(data, expires_delta)

def validate_refresh_token(token: str) -> Optional[str]:
    """
    Validate a refresh token and return the user ID
    
    Args:
        token: JWT refresh token
        
    Returns:
        User ID if token is valid, None otherwise
    """
    payload = decode_access_token(token)
    if not payload:
        return None
    
    # Verify this is a refresh token
    if payload.get("token_type") != "refresh":
        logger.warning("Invalid token type for refresh token")
        return None
    
    # Return user ID
    return payload.get("sub")

async def get_token_from_request(request: Request) -> Optional[str]:
    """
    Extract token from request (header or cookie)
    
    Args:
        request: FastAPI request object
        
    Returns:
        Token string if found, None otherwise
    """
    # Try Authorization header first
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, token = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            return token
    
    # Then try cookie
    token = request.cookies.get("access_token")
    if token:
        return token
    
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
    
    # Verify token type is not a refresh token
    if payload.get("token_type") == "refresh":
        logger.warning("Attempted to use refresh token for authentication")
        raise credentials_exception
        
    return payload

async def get_current_active_user(current_user: Dict = Depends(get_current_user)) -> Dict:
    """
    Verify the current user is active
    
    Args:
        current_user: Current user data
    
    Returns:
        Current user data if active
    
    Raises:
        HTTPException: If user is not active
    """
    if not current_user.get("is_active", True):
        logger.warning(f"Inactive user {current_user.get('sub')} attempted to access protected resource")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    return current_user

async def get_current_active_admin(current_user: Dict = Depends(get_current_active_user)) -> Dict:
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

async def get_api_key(
    api_key_header: str = Depends(api_key_header),
    api_key_query: str = Depends(api_key_query),
) -> str:
    """
    Get API key from header or query parameter
    
    Args:
        api_key_header: API key from header
        api_key_query: API key from query parameter
        
    Returns:
        API key string
        
    Raises:
        HTTPException: If API key is not provided
    """
    if api_key_header:
        return api_key_header
    if api_key_query:
        return api_key_query
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API key required",
        headers={"WWW-Authenticate": "ApiKey"},
    )

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

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength based on configured policy
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check length
    if len(password) < settings.password_min_length:
        return False, f"Password must be at least {settings.password_min_length} characters"
    
    # Check for uppercase
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for lowercase
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    # Check for digit
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    # Check for special character
    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character"
    
    # Check for common passwords (abbreviated list)
    common_passwords = {"password", "123456", "qwerty", "admin", "welcome", "letmein"}
    if password.lower() in common_passwords:
        return False, "Password is too common"
    
    return True, ""

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
    
    return api_key

def get_api_key_hash_and_prefix(api_key: str) -> Tuple[str, str]:
    """
    Get the hash and prefix of an API key
    
    Args:
        api_key: Full API key
        
    Returns:
        Tuple of (hashed_key, prefix)
    """
    # Hash for storage
    hashed_key = hash_data(api_key)
    
    # Extract prefix (first 8 chars) for lookup
    prefix = api_key[:8]
    
    return hashed_key, prefix

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

# Encryption utilities
def encrypt_data(data: Union[str, bytes]) -> str:
    """
    Encrypt data using Fernet symmetric encryption
    
    Args:
        data: Data to encrypt
        
    Returns:
        Base64-encoded encrypted data
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        f = Fernet(_get_encryption_key())
        encrypted_data = f.encrypt(data)
        return encrypted_data.decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise

def decrypt_data(encrypted_data: Union[str, bytes]) -> str:
    """
    Decrypt data using Fernet symmetric encryption
    
    Args:
        encrypted_data: Encrypted data to decrypt
        
    Returns:
        Decrypted data as string
    """
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    
    try:
        f = Fernet(_get_encryption_key())
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise

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
        "admin": [
            "read", "write", "delete", "execute_playbook", "manage_users", 
            "manage_settings", "view_system", "view_logs", "view_analytics"
        ],
        "analyst": [
            "read", "write", "execute_playbook", "view_analytics"
        ],
        "readonly": [
            "read", "view_analytics"
        ]
    }
    
    user_role = user.get("role", "readonly")
    allowed_permissions = role_permissions.get(user_role, [])
    
    return required_permission in allowed_permissions

def require_permissions(permissions: List[str]):
    """
    Create a dependency that requires specific permissions
    
    Args:
        permissions: List of required permissions
        
    Returns:
        Dependency function
    """
    async def dependency(current_user: Dict = Depends(get_current_active_user)):
        for permission in permissions:
            if not has_permission(current_user, permission):
                logger.warning(f"User {current_user.get('sub')} lacks permission {permission}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: {permission} required"
                )
        return current_user
    
    return dependency

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

def apply_security_headers(response: Response) -> None:
    """
    Apply security headers to a FastAPI response
    
    Args:
        response: FastAPI response object
    """
    headers = get_security_headers()
    for header_name, header_value in headers.items():
        response.headers[header_name] = header_value

# Rate limiting
def _get_client_ip(request: Request) -> str:
    """
    Get client IP address from request
    
    Args:
        request: FastAPI request
        
    Returns:
        Client IP address
    """
    # Check for X-Forwarded-For header (for clients behind proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Use first address in X-Forwarded-For as client IP
        return forwarded_for.split(",")[0].strip()
    
    # Fall back to request client address
    client_host = request.client.host if request.client else "unknown"
    return client_host

def _is_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """
    Check if an IP is in a CIDR range
    
    Args:
        ip_str: IP address string
        cidr_str: CIDR range string
        
    Returns:
        True if IP is in CIDR range, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str)
        return ip in network
    except ValueError:
        return False

def is_ip_allowed(ip_address: str, allowed_ips: Optional[List[str]] = None, 
                  blocked_ips: Optional[List[str]] = None) -> bool:
    """
    Check if an IP address is allowed
    
    Args:
        ip_address: IP address to check
        allowed_ips: List of allowed IPs or CIDR ranges (if None, all IPs allowed)
        blocked_ips: List of blocked IPs or CIDR ranges
        
    Returns:
        True if IP is allowed, False otherwise
    """
    # Check if IP is in blocked list
    if blocked_ips:
        for blocked in blocked_ips:
            if ip_address == blocked or _is_ip_in_cidr(ip_address, blocked):
                return False
    
    # Check if IP is in global blocked list
    if ip_address in _blocked_ips:
        return False
    
    # If allowed list exists, IP must be in it
    if allowed_ips:
        return any(ip_address == allowed or _is_ip_in_cidr(ip_address, allowed) 
                  for allowed in allowed_ips)
    
    # By default, if no allowed list is specified, all IPs are allowed
    return True

def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """
    Rate limiting dependency
    
    Args:
        max_requests: Maximum number of requests per window
        window_seconds: Time window in seconds
        
    Returns:
        Dependency function
    """
    async def rate_limit_dependency(request: Request):
        if not settings.rate_limit_enabled:
            return
        
        # Get client IP
        client_ip = _get_client_ip(request)
        
        # Current time
        now = time.time()
        
        # Create or get client entry
        if client_ip not in _rate_limit_cache:
            _rate_limit_cache[client_ip] = {
                "count": 0,
                "window_start": now
            }
        
        client_data = _rate_limit_cache[client_ip]
        
        # Reset count if window has passed
        if now - client_data["window_start"] > window_seconds:
            client_data["count"] = 0
            client_data["window_start"] = now
        
        # Increment request count
        client_data["count"] += 1
        
        # Check if rate limit exceeded
        if client_data["count"] > max_requests:
            logger.warning(f"Rate limit exceeded for IP {client_ip}")
            
            # Calculate retry-after header in seconds
            retry_after = int(window_seconds - (now - client_data["window_start"]))
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)}
            )
    
    return rate_limit_dependency

def get_content_type_validators() -> Dict[str, Callable]:
    """
    Get validators for different content types
    
    Returns:
        Dictionary mapping content types to validator functions
    """
    def validate_json(content: bytes) -> bool:
        """Validate JSON content"""
        try:
            import json
            json.loads(content.decode("utf-8"))
            return True
        except:
            return False
    
    def validate_xml(content: bytes) -> bool:
        """Validate XML content"""
        try:
            import xml.etree.ElementTree as ET
            ET.fromstring(content)
            return True
        except:
            return False
    
    return {
        "application/json": validate_json,
        "application/xml": validate_xml
    }

def sanitize_html(html_content: str) -> str:
    """
    Sanitize HTML content to prevent XSS attacks
    
    Args:
        html_content: HTML content to sanitize
        
    Returns:
        Sanitized HTML content
    """
    try:
        import html
        return html.escape(html_content)
    except ImportError:
        # Fallback to basic sanitization
        return (html_content
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks
    
    Args:
        filename: Filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove path components
    filename = os.path.basename(filename)
    
    # Replace dangerous characters
    return re.sub(r'[^\w\.-]', '_', filename)

def log_security_event(event_type: str, details: Dict[str, Any], user_id: Optional[str] = None) -> None:
    """
    Log a security event
    
    Args:
        event_type: Type of security event
        details: Event details
        user_id: Associated user ID if applicable
    """
    log_data = {
        "event_type": event_type,
        "timestamp": time.time(),
        "user_id": user_id,
        "ip_address": details.get("ip_address"),
        "details": details
    }
    
    logger.warning(f"Security event: {event_type}", extra={"data": log_data})

def block_ip(ip_address: str, reason: str, duration: Optional[int] = None) -> None:
    """
    Block an IP address
    
    Args:
        ip_address: IP address to block
        reason: Reason for blocking
        duration: Duration in seconds (None for permanent)
    """
    _blocked_ips.add(ip_address)
    
    log_security_event("ip_blocked", {
        "ip_address": ip_address,
        "reason": reason,
        "duration": duration
    })
    
    logger.warning(f"Blocked IP address {ip_address}: {reason}")

def unblock_ip(ip_address: str) -> bool:
    """
    Unblock an IP address
    
    Args:
        ip_address: IP address to unblock
        
    Returns:
        True if IP was blocked and is now unblocked, False otherwise
    """
    if ip_address in _blocked_ips:
        _blocked_ips.remove(ip_address)
        
        log_security_event("ip_unblocked", {
            "ip_address": ip_address
        })
        
        logger.info(f"Unblocked IP address {ip_address}")
        return True
    
    return False

# Security middleware
async def security_middleware(request: Request, call_next):
    """
    Security middleware for FastAPI
    
    Args:
        request: FastAPI request
        call_next: Next middleware or route handler
        
    Returns:
        Response
    """
    # Check if IP is blocked
    client_ip = _get_client_ip(request)
    if client_ip in _blocked_ips:
        return Response(
            content=json.dumps({"detail": "IP address blocked"}),
            status_code=403,
            media_type="application/json"
        )
    
    # Process request
    response = await call_next(request)
    
    # Add security headers
    apply_security_headers(response)
    
    return response

# Version information for this module
SECURITY_VERSION = "1.0.0"
SECURITY_LAST_UPDATED = "2025-03-15 17:29:56"
SECURITY_LAST_UPDATED_BY = "Rahul"
