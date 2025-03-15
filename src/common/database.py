"""
Database connections and utilities for ASIRA

Provides connections to PostgreSQL, Elasticsearch and Redis,
along with helper functions for common database operations.

Version: 1.0.0
Last updated: 2025-03-15 17:10:53
Last updated by: Rahul
"""
import logging
import time
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, TypeVar, Generic, Union, Tuple, Set, Iterator
from contextlib import contextmanager

# SQLAlchemy imports
from sqlalchemy import create_engine, text, MetaData, Table, Column, inspect, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, Query
from sqlalchemy.sql import select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError

# Elasticsearch imports
try:
    from elasticsearch import Elasticsearch, helpers, NotFoundError, ConflictError
    from elasticsearch.helpers import bulk, scan
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    NotFoundError = Exception
    ConflictError = Exception

# Redis imports
try:
    import redis
    from redis.exceptions import RedisError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    RedisError = Exception

# Import settings
from src.common.config import Settings

# Initialize logger
logger = logging.getLogger("asira.database")

# Initialize settings
settings = Settings()

# Type variables for generic functions
T = TypeVar('T')
ModelType = TypeVar('ModelType')
CreateSchemaType = TypeVar('CreateSchemaType')
UpdateSchemaType = TypeVar('UpdateSchemaType')

# SQLAlchemy setup
DATABASE_URL = settings.database_url

try:
    engine = create_engine(
        DATABASE_URL,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        echo=settings.db_echo,
        pool_pre_ping=True,  # Check connection validity before using from pool
        pool_recycle=3600,   # Recycle connections after 1 hour
        connect_args={
            "connect_timeout": settings.db_connection_timeout,
            "sslmode": "require" if settings.db_ssl else "prefer"
        }
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    logger.info(f"Connected to PostgreSQL at {settings.db_host}:{settings.db_port}/{settings.db_name}")
except Exception as e:
    logger.error(f"Failed to connect to PostgreSQL: {e}")
    # Create fallback for development/testing
    engine = None
    SessionLocal = None
    Base = declarative_base()

# Elasticsearch setup
es_client = None
if settings.es_enabled and ELASTICSEARCH_AVAILABLE:
    es_args = {
        "hosts": settings.es_hosts,
        "timeout": settings.es_timeout,
        "retry_on_timeout": settings.es_retry_on_timeout,
        "max_retries": settings.es_max_retries
    }
    if settings.es_username and settings.es_password:
        es_args["basic_auth"] = (settings.es_username, settings.es_password)
    
    try:
        es_client = Elasticsearch(**es_args)
        info = es_client.info()
        logger.info(f"Connected to Elasticsearch {info.get('version', {}).get('number', 'unknown')} at {', '.join(settings.es_hosts)}")
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch: {e}")
        es_client = None

# Redis setup
redis_client = None
if settings.redis_enabled and REDIS_AVAILABLE:
    try:
        redis_args = {
            "host": settings.redis_host,
            "port": settings.redis_port,
            "db": settings.redis_db,
            "decode_responses": True,
            "socket_timeout": settings.redis_timeout,
            "health_check_interval": settings.redis_health_check_interval
        }
        
        if settings.redis_password:
            redis_args["password"] = settings.redis_password
            
        if settings.redis_ssl:
            redis_args["ssl"] = True
            redis_args["ssl_cert_reqs"] = "required" if settings.verify_ssl else "none"
            
        # Create connection pool
        redis_pool = redis.ConnectionPool(
            **redis_args,
            max_connections=settings.redis_connection_pool_size
        )
        
        redis_client = redis.Redis(connection_pool=redis_pool)
        redis_client.ping()
        logger.info(f"Connected to Redis at {settings.redis_host}:{settings.redis_port}")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        redis_client = None


# Database dependency for FastAPI
def get_db():
    """
    Get a database session - use as a FastAPI dependency
    
    Yields:
        SQLAlchemy Session
    """
    if SessionLocal is None:
        logger.error("Database session not available")
        raise RuntimeError("Database connection not available")
        
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Context manager for database sessions
    
    Yields:
        SQLAlchemy Session
    """
    if SessionLocal is None:
        logger.error("Database session not available")
        raise RuntimeError("Database connection not available")
        
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_db_connection() -> bool:
    """
    Check if database connection is working
    
    Returns:
        True if connection is working, False otherwise
    """
    if engine is None:
        return False
        
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False


# SQLAlchemy helper functions
class CRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """
    Generic CRUD operations for SQLAlchemy models
    """
    def __init__(self, model: ModelType):
        """
        Initialize with model class
        
        Args:
            model: SQLAlchemy model class
        """
        self.model = model

    def get(self, db: Session, id: Any) -> Optional[ModelType]:
        """
        Get an object by ID
        
        Args:
            db: Database session
            id: Object ID
            
        Returns:
            Object if found, None otherwise
        """
        return db.query(self.model).filter(self.model.id == id).first()

    def get_multi(
        self, db: Session, *, skip: int = 0, limit: int = 100
    ) -> List[ModelType]:
        """
        Get multiple objects with pagination
        
        Args:
            db: Database session
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of objects
        """
        return db.query(self.model).offset(skip).limit(limit).all()

    def create(self, db: Session, *, obj_in: CreateSchemaType) -> ModelType:
        """
        Create a new object
        
        Args:
            db: Database session
            obj_in: Object creation data
            
        Returns:
            Created object
        """
        obj_in_data = obj_in if isinstance(obj_in, dict) else obj_in.dict()
        db_obj = self.model(**obj_in_data)
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def update(
        self, db: Session, *, db_obj: ModelType, obj_in: Union[UpdateSchemaType, Dict[str, Any]]
    ) -> ModelType:
        """
        Update an object
        
        Args:
            db: Database session
            db_obj: Database object to update
            obj_in: Update data
            
        Returns:
            Updated object
        """
        obj_data = db_obj.__dict__.copy()
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.dict(exclude_unset=True)
        for field in update_data:
            if field in obj_data:
                setattr(db_obj, field, update_data[field])
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def remove(self, db: Session, *, id: Any) -> ModelType:
        """
        Remove an object
        
        Args:
            db: Database session
            id: Object ID
            
        Returns:
            Removed object
        """
        obj = db.query(self.model).get(id)
        db.delete(obj)
        db.commit()
        return obj
        
    def exists(self, db: Session, *, id: Any) -> bool:
        """
        Check if an object exists
        
        Args:
            db: Database session
            id: Object ID
            
        Returns:
            True if object exists, False otherwise
        """
        count = db.query(func.count(self.model.id)).filter(self.model.id == id).scalar()
        return count > 0
    
    def count(self, db: Session) -> int:
        """
        Count all objects
        
        Args:
            db: Database session
            
        Returns:
            Number of objects
        """
        return db.query(func.count(self.model.id)).scalar()


def paginate(query: Query, page: int = 1, page_size: int = 20) -> Tuple[List[Any], int, int]:
    """
    Paginate a SQLAlchemy query
    
    Args:
        query: SQLAlchemy query object
        page: Page number (1-indexed)
        page_size: Number of items per page
        
    Returns:
        Tuple of (items, total_count, total_pages)
    """
    # Validate pagination parameters
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 1
    elif page_size > 100:
        page_size = 100  # Limit maximum page size to prevent excessive queries
    
    # Calculate total count
    total_count = query.count()
    
    # Calculate total pages
    total_pages = (total_count + page_size - 1) // page_size  # Ceiling division
    
    # Calculate offset
    offset = (page - 1) * page_size
    
    # Apply pagination
    items = query.limit(page_size).offset(offset).all()
    
    return items, total_count, total_pages

def sanitize_query_param(param: str) -> str:
    """
    Sanitize a query parameter to prevent SQL injection
    
    Args:
        param: Query parameter to sanitize
        
    Returns:
        Sanitized parameter
    """
    if param is None:
        return None
        
    # Remove potentially dangerous characters
    disallowed_chars = ["'", '"', ";", "--", "/*", "*/", "xp_"]
    result = param
    
    for char in disallowed_chars:
        result = result.replace(char, "")
        
    return result

def generate_uuid() -> str:
    """
    Generate a UUID for use as an ID
    
    Returns:
        UUID string
    """
    return str(uuid.uuid4())

def get_timestamp() -> float:
    """
    Get current timestamp in seconds since epoch
    
    Returns:
        Current timestamp as float
    """
    return datetime.now().timestamp()

def format_datetime(timestamp: float) -> str:
    """
    Format a timestamp as a human-readable string
    
    Args:
        timestamp: Timestamp in seconds since epoch
        
    Returns:
        Formatted date string
    """
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def hash_file(file_path: Path) -> str:
    """
    Compute SHA-256 hash of a file
    
    Args:
        file_path: Path to the file
        
    Returns:
        Hex digest of SHA-256 hash
    """
    sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read and update hash in chunks for memory efficiency
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)
            
    return sha256.hexdigest()

def validate_ip(ip_address: str) -> bool:
    """
    Validate if a string is a valid IP address
    
    Args:
        ip_address: String to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid domain, False otherwise
    """
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def safe_execute(func, *args, default_return=None, **kwargs):
    """
    Safely execute a function, returning default value if it fails
    
    Args:
        func: Function to execute
        *args: Positional arguments for the function
        default_return: Value to return if execution fails
        **kwargs: Keyword arguments for the function
        
    Returns:
        Function result or default_return on exception
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.exception(f"Error executing {func.__name__}: {e}")
        return default_return

def truncate_string(s: str, max_length: int = 100) -> str:
    """
    Truncate a string to maximum length, adding ellipsis if truncated
    
    Args:
        s: String to truncate
        max_length: Maximum length
        
    Returns:
        Truncated string
    """
    if not s:
        return ""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."

def get_module_version() -> Dict[str, str]:
    """
    Get version information for this module
    
    Returns:
        Dictionary with version information
    """
    return {
        "version": "1.0.0",
        "last_updated": "2025-03-15 17:13:00",
        "last_updated_by": "Mritunjay-mj"
    }

# Export version information for this module
MODULE_VERSION = "1.0.0"
MODULE_LAST_UPDATED = "2025-03-15 17:13:00"
MODULE_LAST_UPDATED_BY = "Rahul"
