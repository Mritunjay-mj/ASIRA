"""
Database connections and utilities for ASIRA

Provides connections to PostgreSQL, Elasticsearch and Redis,
along with helper functions for common database operations.

Version: 1.0.0
Last updated: 2025-03-15
"""
import logging
import time
import json
from typing import Dict, Any, List, Optional, Callable, TypeVar, Generic, Union
from contextlib import contextmanager

# SQLAlchemy imports
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Elasticsearch imports
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False

# Redis imports
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# Import settings
from src.common.config import Settings

# Initialize logger
logger = logging.getLogger("asira.database")

# Initialize settings
settings = Settings()

# SQLAlchemy setup
DATABASE_URL = f"postgresql://{settings.db_user}:{settings.db_password}@{settings.db_host}:{settings.db_port}/{settings.db_name}"

try:
    engine = create_engine(
        DATABASE_URL,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        echo=settings.db_echo
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
        redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            decode_responses=True
        )
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


# Elasticsearch helper functions
def es_create_index(index_name: str, mappings: Optional[Dict] = None, settings: Optional[Dict] = None) -> bool:
    """
    Create an Elasticsearch index with optional mappings and settings
    
    Args:
        index_name: Name of the index
        mappings: Optional index mappings
        settings: Optional index settings
        
    Returns:
        True if successful, False otherwise
    """
    if not es_client:
        logger.error("Elasticsearch client not initialized")
        return False
    
    # Add prefix to index name if not already there
    if not index_name.startswith(settings.es_index_prefix):
        index_name = f"{settings.es_index_prefix}{index_name}"
        
    try:
        # Check if index exists
        if es_client.indices.exists(index=index_name):
            logger.info(f"Elasticsearch index {index_name} already exists")
            return True
            
        # Prepare index creation request
        body = {}
        if mappings:
            body["mappings"] = mappings
        if settings:
            body["settings"] = settings
        else:
            # Default settings
            body["settings"] = {
                "index": {
                    "number_of_shards": settings.es_shards,
                    "number_of_replicas": settings.es_replicas
                }
            }
            
        # Create index
        es_client.indices.create(index=index_name, body=body)
        logger.info(f"Created Elasticsearch index {index_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to create Elasticsearch index {index_name}: {e}")
        return False


def es_index_document(index_name: str, document: Dict[str, Any], doc_id: Optional[str] = None) -> bool:
    """
    Index a document in Elasticsearch
    
    Args:
        index_name: Name of the index
        document: Document to index
        doc_id: Optional document ID
        
    Returns:
        True if successful, False otherwise
    """
    if not es_client:
        logger.error("Elasticsearch client not initialized")
        return False
        
    # Add prefix to index name if not already there
    if not index_name.startswith(settings.es_index_prefix):
        index_name = f"{settings.es_index_prefix}{index_name}"
        
    try:
        resp = es_client.index(
            index=index_name,
            document=document,
            id=doc_id
        )
        return resp["result"] in ["created", "updated"]
    except Exception as e:
        logger.error(f"Failed to index document: {e}")
        return False


def es_bulk_index(index_name: str, documents: List[Dict[str, Any]], id_field: str = "id") -> int:
    """
    Bulk index documents in Elasticsearch
    
    Args:
        index_name: Name of the index
        documents: List of documents to index
        id_field: Field to use as document ID
        
    Returns:
        Number of documents successfully indexed
    """
    if not es_client:
        logger.error("Elasticsearch client not initialized")
        return 0
        
    # Add prefix to index name if not already there
    if not index_name.startswith(settings.es_index_prefix):
        index_name = f"{settings.es_index_prefix}{index_name}"
        
    try:
        actions = [
            {
                "_index": index_name,
                "_id": doc.get(id_field),
                "_source": doc
            }
            for doc in documents
        ]
        
        success, failed = bulk(es_client, actions, stats_only=True)
        if failed:
            logger.warning(f"Failed to index {failed} documents in bulk operation")
        return success
    except Exception as e:
        logger.error(f"Failed to bulk index documents: {e}")
        return 0


def es_search(
    index_name: str, 
    query: Dict[str, Any], 
    size: int = 100,
    start: int = 0,
    sort: Optional[List] = None,
    source: Optional[Union[List, bool]] = None
) -> Dict[str, Any]:
    """
    Search documents in Elasticsearch
    
    Args:
        index_name: Name of the index
        query: Elasticsearch query
        size: Maximum number of results
        start: Starting offset
        sort: Optional sort criteria
        source: Fields to include in results
        
    Returns:
        Search results including hits and metadata
    """
    if not es_client:
        logger.error("Elasticsearch client not initialized")
        return {"hits": {"total": {"value": 0}, "hits": []}}
        
    # Add prefix to index name if not already there
    if not index_name.startswith(settings.es_index_prefix):
        index_name = f"{settings.es_index_prefix}{index_name}"
        
    try:
        body = {"query": query}
        
        if sort:
            body["sort"] = sort
            
        search_params = {
            "index": index_name,
            "body": body,
            "size": size,
            "from_": start
        }
        
        if source is not None:
            search_params["_source"] = source
            
        resp = es_client.search(**search_params)
        return resp
    except Exception as e:
        logger.error(f"Failed to search documents: {e}")
        return {"hits": {"total": {"value": 0}, "hits": []}}


def es_get_document(index_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a document from Elasticsearch by ID
    
    Args:
        index_name: Name of the index
        doc_id: Document ID
        
    Returns:
        Document if found, None otherwise
    """
    if not es_client:
        logger.error("Elasticsearch client not initialized")
        return None
        
    # Add prefix to index name if not already there
    if not index_name.startswith(settings.es_index_prefix):
        index_name = f"{settings.es_index_prefix}{index_name}"
        
    try:
        resp = es_client.get(index=index_name, id=doc_id)
        return resp.get("_source")
    except Exception as e:
        logger.error(f"Failed to get document {doc_id} from {index_name}: {e}")
        return None


def es_delete_document(index_name: str, doc_id: str) -> bool:
    """
    Delete a document from Elasticsearch
    
    Args:
        index_name: Name of the index
        doc_id: Document ID
        
    Returns:
        True if successful, False otherwise
    """
    if not es_client:
        logger.error("Elasticsearch client not initialized")
        return False
        
    # Add prefix to index name if not already there
    if not index_name.startswith(settings.es_index_prefix):
        index_name = f"{settings.es_index_prefix}{index_name}"
        
    try:
        resp = es_client.delete(index=index_name, id=doc_id)
        return resp["result"] == "deleted"
    except Exception as e:
        logger.error(f"Failed to delete document {doc_id} from {index_name}: {e}")
        return False


# Redis helper functions
def redis_set(key: str, value: Any, expire: Optional[int] = None) -> bool:
    """
    Set a key in Redis with optional expiration
    
    Args:
        key: Key name
        value: Value to store (will be JSON serialized if not a string)
        expire: Optional expiration time in seconds
        
    Returns:
        True if successful, False otherwise
    """
    if not redis_client:
        logger.error("Redis client not initialized")
        return False
        
    try:
        # JSON serialize non-string values
        if not isinstance(value, (str, int, float, bool)):
            value = json.dumps(value)
            
        if expire:
            return redis_client.set(key, value, ex=expire)
        else:
            return redis_client.set(key, value)
    except Exception as e:
        logger.error(f"Failed to set Redis key {key}: {e}")
        return False


def redis_get(key: str, default: Any = None) -> Any:
    """
    Get a value from Redis
    
    Args:
        key: Key name
        default: Default value if key doesn't exist
        
    Returns:
        Value if key exists, default otherwise
    """
    if not redis_client:
        logger.error("Redis client not initialized")
        return default
        
    try:
        value = redis_client.get(key)
        if value is None:
            return default
            
        # Try to JSON deserialize
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return value
    except Exception as e:
        logger.error(f"Failed to get Redis key {key}: {e}")
        return default


def redis_delete(key: str) -> bool:
    """
    Delete a key from Redis
    
    Args:
        key: Key name
        
    Returns:
        True if successful, False otherwise
    """
    if not redis_client:
        logger.error("Redis client not initialized")
        return False
        
    try:
        return redis_client.delete(key) > 0
    except Exception as e:
        logger.error(f"Failed to delete Redis key {key}: {e}")
        return False


def redis_exists(key: str) -> bool:
    """
    Check if a key exists in Redis
    
    Args:
        key: Key name
        
    Returns:
        True if key exists, False otherwise
    """
    if not redis_client:
        logger.error("Redis client not initialized")
        return False
        
    try:
        return redis_client.exists(key) > 0
    except Exception as e:
        logger.error(f"Failed to check Redis key {key}: {e}")
        return False


def redis_increment(key: str, amount: int = 1) -> int:
    """
    Increment a counter in Redis
    
    Args:
        key: Key name
        amount: Amount to increment
        
    Returns:
        New counter value or -1 on error
    """
    if not redis_client:
        logger.error("Redis client not initialized")
        return -1
        
    try:
        return redis_client.incrby(key, amount)
    except Exception as e:
        logger.error(f"Failed to increment Redis key {key}: {e}")
        return -1


# Health check function
def check_database_health() -> Dict[str, bool]:
    """
    Check health of all database connections
    
    Returns:
        Dictionary with connection status for each database
    """
    health = {
        "postgres": False,
        "elasticsearch": False,
        "redis": False
    }
    
    # Check PostgreSQL
    if engine:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            health["postgres"] = True
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
    
    # Check Elasticsearch
    if es_client:
        try:
            health["elasticsearch"] = es_client.ping()
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
    
    # Check Redis
    if redis_client:
        try:
            health["redis"] = redis_client.ping()
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
    
    return health
