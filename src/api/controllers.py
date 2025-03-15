"""
API Controllers for ASIRA
Handle business logic between API routes and data access layers

Version: 1.0.0
Last updated: 2025-03-15 16:51:45
Last updated by: Mritunjay-mj
"""
import time
import uuid
import logging
import os
import yaml
import json
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import hashlib
import ipaddress
import re

from src.common.security import hash_password
from src.common.database import es_index_document, es_search, es_update_document, es_delete_document
from src.api.models import (
    UserCreate,
    UserUpdate, 
    PlaybookCreate, 
    PlaybookUpdate,
    IncidentCreate, 
    IncidentUpdate,
    DetectionCreate,
    DetectionUpdate,
    SearchQuery,
    LogSourceConfig,
    BulkActionRequest
)

# Initialize logger
logger = logging.getLogger("asira.api.controllers")

# Current timestamp for use in this module
CURRENT_TIMESTAMP_STR = "2025-03-15 16:51:45"
# Parse the timestamp string to a datetime object and convert to timestamp
CURRENT_TIMESTAMP = datetime.strptime(CURRENT_TIMESTAMP_STR, "%Y-%m-%d %H:%M:%S").timestamp()

# User controllers

def get_user_by_username(db: Session, username: str):
    """
    Get a user by username
    
    Args:
        db: Database session
        username: Username to lookup
        
    Returns:
        User object if found, None otherwise
    """
    # In a real implementation, this would query the database
    # For this hackathon prototype, we'll use a mock user store
    users = {
        "admin": {
            'id': "usr_admin",
            'username': "admin",
            'email': "admin@example.com",
            'full_name': "System Administrator",
            'role': "admin",
            'hashed_password': "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "password"
            'is_active': True,
            'created_at': CURRENT_TIMESTAMP - 86400 * 30,  # 30 days ago
            'last_login': CURRENT_TIMESTAMP - 3600  # 1 hour ago
        },
        "analyst": {
            'id': "usr_analyst",
            'username': "analyst",
            'email': "analyst@example.com",
            'full_name': "Security Analyst",
            'role': "analyst",
            'hashed_password': "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "password"
            'is_active': True,
            'created_at': CURRENT_TIMESTAMP - 86400 * 15,  # 15 days ago
            'last_login': CURRENT_TIMESTAMP - 43200  # 12 hours ago
        },
        "readonly": {
            'id': "usr_readonly",
            'username': "readonly",
            'email': "readonly@example.com",
            'full_name': "Read Only User",
            'role': "readonly",
            'hashed_password': "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "password"
            'is_active': True,
            'created_at': CURRENT_TIMESTAMP - 86400 * 7,  # 7 days ago
            'last_login': CURRENT_TIMESTAMP - 86400  # 1 day ago
        }
    }
    
    if username in users:
        return type('User', (), users[username])
    return None

def get_all_users_from_db(db: Session, skip: int = 0, limit: int = 100):
    """
    Get all users from the database with pagination
    
    Args:
        db: Database session
        skip: Number of users to skip
        limit: Maximum number of users to return
        
    Returns:
        List of user objects
    """
    # In a real implementation, this would query the database with pagination
    # For this prototype, we'll use the same mock data and apply pagination
    users = [
        {
            'id': "usr_admin",
            'username': "admin",
            'email': "admin@example.com",
            'full_name': "System Administrator",
            'role': "admin",
            'is_active': True,
            'created_at': CURRENT_TIMESTAMP - 86400 * 30
        },
        {
            'id': "usr_analyst",
            'username': "analyst",
            'email': "analyst@example.com",
            'full_name': "Security Analyst",
            'role': "analyst",
            'is_active': True,
            'created_at': CURRENT_TIMESTAMP - 86400 * 15
        },
        {
            'id': "usr_readonly",
            'username': "readonly",
            'email': "readonly@example.com",
            'full_name': "Read Only User",
            'role': "readonly",
            'is_active': True,
            'created_at': CURRENT_TIMESTAMP - 86400 * 7
        },
        {
            'id': "usr_inactive",
            'username': "inactive",
            'email': "inactive@example.com",
            'full_name': "Deactivated User",
            'role': "analyst",
            'is_active': False,
            'created_at': CURRENT_TIMESTAMP - 86400 * 45
        }
    ]
    
    # Apply pagination
    return users[skip:skip+limit]

def create_user_in_db(db: Session, user: UserCreate):
    """
    Create a new user in the database
    
    Args:
        db: Database session
        user: User creation data
        
    Returns:
        Created user object
    """
    # Validate username doesn't contain invalid characters
    if not re.match(r"^[a-zA-Z0-9_-]+$", user.username):
        raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        
    # In a real implementation, this would save to the database
    # For this hackathon prototype, we'll return a mock response
    user_id = f"usr_{uuid.uuid4().hex[:8]}"
    
    # Hash the password
    hashed_password = hash_password(user.password)
    
    # Create user object
    user_data = {
        "id": user_id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": True,
        "created_at": CURRENT_TIMESTAMP,
        "last_login": None,
        "hashed_password": hashed_password
    }
    
    # Log user creation
    logger.info(f"Created new user: {user.username} with role {user.role}")
    
    # Return user data without password
    user_response = user_data.copy()
    user_response.pop("hashed_password")
    return user_response

def update_user_in_db(db: Session, username: str, user_data: UserUpdate):
    """
    Update a user in the database
    
    Args:
        db: Database session
        username: Username of user to update
        user_data: User update data
        
    Returns:
        Updated user object or None if not found
    """
    # Get existing user
    user = get_user_by_username(db, username)
    if not user:
        logger.warning(f"Attempted to update non-existent user: {username}")
        return None
    
    # Prepare update data
    updated_fields = {}
    
    if user_data.email is not None:
        updated_fields["email"] = user_data.email
        
    if user_data.full_name is not None:
        updated_fields["full_name"] = user_data.full_name
        
    if user_data.password is not None:
        updated_fields["hashed_password"] = hash_password(user_data.password)
        
    if user_data.role is not None:
        updated_fields["role"] = user_data.role
        
    if user_data.is_active is not None:
        updated_fields["is_active"] = user_data.is_active
    
    # In a real implementation, this would update the database with updated_fields
    logger.info(f"Updated user: {username} fields: {', '.join(updated_fields.keys())}")
    
    # Return updated user data
    return {
        "id": user.id,
        "username": user.username,
        "email": user_data.email if user_data.email is not None else user.email,
        "full_name": user_data.full_name if user_data.full_name is not None else getattr(user, "full_name", None),
        "role": user_data.role if user_data.role is not None else user.role,
        "is_active": user_data.is_active if user_data.is_active is not None else user.is_active,
        "created_at": user.created_at,
        "last_login": getattr(user, "last_login", None)
    }

def deactivate_user_in_db(db: Session, username: str):
    """
    Deactivate a user in the database
    
    Args:
        db: Database session
        username: Username of user to deactivate
        
    Returns:
        True if successful, False if user not found
    """
    # Get existing user
    user = get_user_by_username(db, username)
    if not user:
        logger.warning(f"Attempted to deactivate non-existent user: {username}")
        return False
    
    # In a real implementation, this would update the database
    logger.info(f"Deactivated user: {username}")
    
    return True

def update_last_login(db: Session, username: str):
    """
    Update a user's last login timestamp
    
    Args:
        db: Database session
        username: Username of user to update
        
    Returns:
        None
    """
    # In a real implementation, this would update the database
    logger.info(f"Updated last login for user: {username} to {CURRENT_TIMESTAMP_STR}")

# Detection controllers

def create_detection_in_db(db: Session, detection: DetectionCreate):
    """
    Create a new detection in the database
    
    Args:
        db: Database session
        detection: Detection creation data
        
    Returns:
        Created detection object
    """
    # Generate a detection ID
    detection_id = f"det_{uuid.uuid4().hex[:8]}"
    
    # Create detection data
    detection_data = {
        "id": detection_id,
        "event_id": detection.event_id,
        "anomaly_score": detection.anomaly_score,
        "detection_method": detection.detection_method,
        "explanation": detection.explanation,
        "related_events": detection.related_events,
        "confidence": detection.confidence,
        "timestamp": CURRENT_TIMESTAMP,
        "acknowledged": False,
        "acknowledged_by": None,
        "raw_data": detection.raw_data or {},
        "source_ip": detection.source_ip,
        "destination_ip": detection.destination_ip,
        "username": detection.username,
        "asset_id": detection.asset_id,
        "event_type": detection.event_type,
        "source_type": detection.source_type,
        "false_positive": False
    }
    
    # In a real implementation, this would save to the database
    # For Elasticsearch integration, we can index the detection
    es_index_document("asira_detections", detection_data, detection_id)
    
    logger.info(f"Created new detection {detection_id} with score {detection.anomaly_score}")
    
    return detection_data

def update_detection_in_db(db: Session, detection_id: str, detection_update: DetectionUpdate, updated_by: str):
    """
    Update a detection in the database
    
    Args:
        db: Database session
        detection_id: ID of detection to update
        detection_update: Detection update data
        updated_by: Username of updater
        
    Returns:
        Updated detection object or None if not found
    """
    # In a real implementation, this would get the detection from DB and update it
    # For this prototype, we'll create a mock updated detection
    detection = get_detection_by_id(db, detection_id)
    if not detection:
        logger.warning(f"Attempted to update non-existent detection: {detection_id}")
        return None
    
    # Update fields
    update_fields = {}
    
    if detection_update.anomaly_score is not None:
        update_fields["anomaly_score"] = detection_update.anomaly_score
        
    if detection_update.confidence is not None:
        update_fields["confidence"] = detection_update.confidence
        
    if detection_update.explanation is not None:
        update_fields["explanation"] = detection_update.explanation
        
    if detection_update.related_events is not None:
        update_fields["related_events"] = detection_update.related_events
        
    if detection_update.acknowledged is not None:
        update_fields["acknowledged"] = detection_update.acknowledged
        if detection_update.acknowledged:
            update_fields["acknowledged_by"] = updated_by
            
    if detection_update.false_positive is not None:
        update_fields["false_positive"] = detection_update.false_positive
        
    if detection_update.notes is not None:
        update_fields["notes"] = detection_update.notes
    
    # In a real implementation, this would update the database
    # For Elasticsearch, we would update the document
    es_update_document("asira_detections", detection_id, update_fields)
    
    logger.info(f"Updated detection {detection_id} by {updated_by}: {', '.join(update_fields.keys())}")
    
    # Return updated detection
    updated_detection = detection.copy()
    updated_detection.update(update_fields)
    return updated_detection

def get_detection_by_id(db: Session, detection_id: str):
    """
    Get a detection by ID
    
    Args:
        db: Database session
        detection_id: Detection ID
        
    Returns:
        Detection object or None if not found
    """
    # In a real implementation, this would fetch from the database
    # For this prototype, we'll return a mock detection
    
    # Check if the ID is in our expected format
    if not detection_id.startswith("det_"):
        return None
    
    # Create a deterministic detection based on the ID
    id_hash = int(hashlib.md5(detection_id.encode()).hexdigest(), 16) % 100000
    
    # Use the hash to create deterministic but varied values
    timestamp_offset = (id_hash % 86400)  # Last 24 hours
    method_index = id_hash % 5
    score = 0.7 + ((id_hash % 30) / 100)  # Score between 0.7 and 0.99
    
    detection_methods = ["isolation_forest", "autoencoder", "statistical", "deep_learning", "rule_based"]
    event_types = ["login", "file_access", "network", "process", "database"]
    event_type = event_types[id_hash % len(event_types)]
    
    # Create detection
    detection = {
        "id": detection_id,
        "event_id": f"{event_type}_event_{id_hash:04d}",
        "anomaly_score": round(score, 2),
        "detection_method": detection_methods[method_index],
        "explanation": {
            f"feature_{j}": round(0.9 - (j * 0.15), 2) for j in range(1, 4)
        },
        "related_events": [
            f"{event_type}_event_{(id_hash+1):04d}",
            f"{event_type}_event_{(id_hash+2):04d}"
        ],
        "confidence": round(score - 0.05, 2),
        "timestamp": CURRENT_TIMESTAMP - timestamp_offset,
        "acknowledged": id_hash % 5 == 0,  # Some are acknowledged
        "acknowledged_by": "analyst" if id_hash % 5 == 0 else None,
        "raw_data": {
            "timestamp": CURRENT_TIMESTAMP_STR,
            "source_ip": f"10.0.{id_hash % 255}.{(id_hash // 255) % 255}",
            "destination_ip": f"192.168.{id_hash % 255}.{(id_hash // 255) % 255}",
            "username": f"user{id_hash % 10}",
            "event_type": event_type,
            "details": {
                "success": id_hash % 2 == 0,
                "location": f"datacenter-{id_hash % 3 + 1}",
                "duration_ms": id_hash * 10
            }
        },
        "false_positive": id_hash % 10 == 0,
        "notes": "This appears to be a false positive" if id_hash % 10 == 0 else None,
        "source_ip": f"10.0.{id_hash % 255}.{(id_hash // 255) % 255}",
        "destination_ip": f"192.168.{id_hash % 255}.{(id_hash // 255) % 255}",
        "username": f"user{id_hash % 10}",
        "asset_id": f"asset-{id_hash % 50}",
        "event_type": event_type,
        "source_type": "endpoint" if id_hash % 3 == 0 else "network" if id_hash % 3 == 1 else "cloud",
        "detection_rule_id": f"rule-{id_hash % 10}" if id_hash % 2 == 0 else None,
        "mitre_tactics": ["Initial Access", "Execution"] if id_hash % 3 == 0 else ["Exfiltration"],
        "mitre_techniques": ["T1078", "T1059"] if id_hash % 3 == 0 else ["T1048"],
        "incident_id": f"inc_{id_hash:06d}" if id_hash % 4 == 0 else None
    }
    
    return detection

def get_detections_from_db(
    db: Session, 
    limit: int = 100, 
    offset: int = 0, 
    min_score: float = 0.0,
    method: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None
):
    """
    Get detection results from the database with advanced filtering
    
    Args:
        db: Database session
        limit: Maximum number of results to return
        offset: Number of results to skip
        min_score: Minimum anomaly score to include
        method: Filter by detection method
        acknowledged: Filter by acknowledged status
        start_time: Filter detections after timestamp
        end_time: Filter detections before timestamp
        
    Returns:
        List of detection objects
    """
    # In a real implementation, this would query the database or Elasticsearch
    # For this hackathon prototype, we'll return mock data
    results = []
    
    # Generate mock detections
    base_timestamp = CURRENT_TIMESTAMP
    detection_methods = ["isolation_forest", "autoencoder", "statistical", "deep_learning", "rule_based"]
    event_types = ["login", "file_access", "network", "process", "database"]
    
    for i in range(1, 30):
        # Calculate a deterministic but varied timestamp
        ts_offset = (i * 1800) % 86400  # Vary within the last 24 hours
        detection_timestamp = base_timestamp - ts_offset
        
        # Skip if outside time range
        if start_time and detection_timestamp < start_time:
            continue
            
        if end_time and detection_timestamp > end_time:
            continue
        
        # Alternate detection methods and create varied scores
        method_index = i % len(detection_methods)
        current_method = detection_methods[method_index]
        
        # Skip if method doesn't match
        if method and current_method != method:
            continue
        
        score_base = 0.7 + ((i % 3) * 0.1)  # Scores between 0.7 and 0.9
        
        # Skip if score is below minimum
        if score_base < min_score:
            continue
        
        # Set acknowledged status
        is_acknowledged = i % 5 == 0
        
        # Skip based on acknowledged filter
        if acknowledged is not None and is_acknowledged != acknowledged:
            continue
        
        # Create a unique event ID with a type
        event_type = event_types[i % len(event_types)]
        event_id = f"{event_type}_event_{i:04d}"
        
        # Prepare explanation with feature importances
        explanation = {
            f"feature_{j}": round(0.9 - (j * 0.15), 2) for j in range(1, 4)
        }
        
        # Add some related events
        related_events = [
            f"{event_type}_event_{(i+1):04d}",
            f"{event_type}_event_{(i+2):04d}"
        ]
        
        # Create the detection object
        detection = {
            "id": f"det_{uuid.uuid4().hex[:8]}",
            "event_id": event_id,
            "anomaly_score": round(score_base, 2),
            "detection_method": current_method,
            "explanation": explanation,
            "related_events": related_events,
            "confidence": round(score_base - 0.05, 2),
            "timestamp": detection_timestamp,
            "acknowledged": is_acknowledged,
            "acknowledged_by": "analyst" if is_acknowledged else None,
            "source_ip": f"10.0.{i % 255}.{(i // 255) % 255}",
            "destination_ip": f"192.168.{i % 255}.{(i // 255) % 255}" if i % 2 == 0 else None,
            "username": f"user{i % 10}" if i % 3 != 0 else None,
            "asset_id": f"asset-{i % 50}" if i % 4 != 0 else None,
            "event_type": event_type
        }
        
        results.append(detection)
    
    # Sort by timestamp, newest first
    results.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # Apply pagination
    paginated_results = results[offset:offset+limit]
    
    return paginated_results

def acknowledge_detection(db: Session, detection_id: str, username: str):
    """
    Mark a detection as acknowledged
    
    Args:
        db: Database session
        detection_id: ID of detection to acknowledge
        username: Username of person acknowledging
        
    Returns:
        Updated detection or None if not found
    """
    # Get the detection
    detection = get_detection_by_id(db, detection_id)
    if not detection:
        logger.warning(f"Attempted to acknowledge non-existent detection: {detection_id}")
        return None
    
    # In a real implementation, this would update the database
    
    # Return a response
    return {
        "id": detection_id,
        "acknowledged": True,
        "acknowledged_by": username,
        "acknowledged_at": CURRENT_TIMESTAMP,
        "original_score": detection.get("anomaly_score", 0.0)
    }

def bulk_acknowledge_detections(db: Session, detection_ids: List[str], username: str):
    """
    Mark multiple detections as acknowledged
    
    Args:
        db: Database session
        detection_ids: List of detection IDs to acknowledge
        username: Username of person acknowledging
        
    Returns:
        Result of the bulk operation
    """
    acknowledged = []
    failed = []
    
    for detection_id in detection_ids:
        result = acknowledge_detection(db, detection_id, username)
        if result:
            acknowledged.append(detection_id)
        else:
            failed.append(detection_id)
    
    logger.info(f"Bulk acknowledged {len(acknowledged)} detections by {username}")
    
    return {
        "acknowledged": acknowledged,
        "failed": failed,
        "timestamp": CURRENT_TIMESTAMP
    }

def search_detections(db: Session, query: SearchQuery):
    """
    Advanced search for detections
    
    Args:
        db: Database session
        query: Search query parameters
        
    Returns:
        List of matching detections
    """
    # In a real implementation, this would build a complex query
    # For this prototype, we'll return a subset of mock detections
    
    # Get all detections
    all_detections = get_detections_from_db(db, limit=100)
    
    # Helper function to check if a detection matches a criterion
    def matches_criterion(detection, criterion):
        field = criterion.field
        value = criterion.value
        operation = criterion.operation
        
        if field not in detection:
            return False
            
        if operation == "eq":
            return detection[field] == value
        elif operation == "neq":
            return detection[field] != value
        elif operation == "gt":
            return detection[field] > value
        elif operation == "lt":
            return detection[field] < value
        elif operation == "contains":
            if isinstance(detection[field], str):
                return value in detection[field]
            elif isinstance(detection[field], list):
                return value in detection[field]
            else:
                return False
        elif operation == "startswith":
            if isinstance(detection[field], str):
                return detection[field].startswith(value)
            else:
                return False
        else:
            return False
    
    # Filter detections based on criteria and operator
    results = []
    
    for detection in all_detections:
        if query.operator == "and":
            # All criteria must match
            matches = all(matches_criterion(detection, criterion) for criterion in query.criteria)
        else:  # "or"
            # At least one criterion must match
            matches = any(matches_criterion(detection, criterion) for criterion in query.criteria)
            
        if matches:
            results.append(detection)
    
    # Apply pagination
    paginated_results = results[query.offset:query.offset+query.limit]
    
    return paginated_results

async def upload_log_file(file, file_id, description, source_type):
    """
    Upload a log file for processing
    
    Args:
        file: Uploaded file object
        file_id: Generated file ID
        description: File description
        source_type: Type of log source
        
    Returns:
        File upload result
    """
    # In a real implementation, this would save the file to disk
    # For this prototype, we'll simulate file saving
    
    # Create directory for uploaded logs if it doesn't exist
    uploads_dir = Path("uploads/logs")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    
    # Save file
    file_path = uploads_dir / f"{file_id}_{file.filename}"
    
    try:
        # Read file content
        content = await file.read()
        
        # Check file size (limit to 100MB for security)
        if len(content) > 100 * 1024 * 1024:
            raise ValueError("File size exceeds maximum allowed (100MB)")
        
        # Write to disk
        with open(file_path, "wb") as f:
            f.write(content)
            
        # Log the upload
        size_bytes = len(content)
        logger.info(f"Uploaded log file: {file_id} ({size_bytes} bytes) of type {source_type}")
        
        return {
            "file_id": file_id,
            "file_path": str(file_path),
            "original_name": file.filename,
            "size_bytes": size_bytes,
            "upload_time": CURRENT_TIMESTAMP,
            "description": description,
            "source_type": source_type
        }
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        raise ValueError(f"File upload failed: {str(e)}")

def configure_log_source(db: Session, config: LogSourceConfig, created_by: str):
    """
    Configure a new log source
    
    Args:
        db: Database session
        config: Log source configuration
        created_by: Username of creator
        
    Returns:
        Created log source configuration
    """
    # Generate ID for the log source
    source_id = f"src_{uuid.uuid4().hex[:8]}"
    
    # In a real implementation, this would save to the database
    # For this prototype, we'll return a mock response
    
    # Create log source object
    source_data = {
        "id": source_id,
        "name": config.name,
        "source_type": config.source_type,
        "description": config.description,
        "path": config.path,
        "credentials_id": config.credentials_id,
        "polling_interval": config.polling_interval,
        "format": config.format,
        "parser_config": config.parser_config,
        "enabled": config.enabled,
        "normalizer_config": config.normalizer_config,
        "created_by": created_by,
        "created_at": CURRENT_TIMESTAMP,
        "last_polled": None,
        "status": "configured"
    }
    
    logger.info(f"Configured log source {source_id}: {config.name} ({config.source_type})")
    
    return source_data

def get_log_sources(db: Session):
    """
    Get all configured log sources
    
    Args:
        db: Database session
        
    Returns:
        List of log source configurations
    """
    # In a real implementation, this would query the database
    # For this prototype, we'll return mock data
    
    sources = [
        {
            "id": "src_abc12345",
            "name": "Windows DC Event Logs",
            "source_type": "windows_event",
            "description": "Domain Controller Security Events",
            "path": "\\\\dc01\\logs\\security",
            "credentials_id": "cred_windows_svc",
            "polling_interval": 300,
            "format": "evtx",
            "parser_config": {
                "event_ids": [4624, 4625, 4648, 4719, 4720, 4722, 4724, 4728, 4732, 4756, 4776]
            },
            "enabled": True,
            "created_at": CURRENT_TIMESTAMP - 86400 * 10,
            "created_by": "admin",
            "last_polled": CURRENT_TIMESTAMP - 300,
            "status": "active"
        },
        {
            "id": "src_def67890",
            "name": "Linux Syslog",
            "source_type": "syslog",
            "description": "Production Linux Servers Syslog",
            "path": "udp://10.0.1.15:514",
            "credentials_id": None,
            "polling_interval": None,  # Real-time
            "format": "syslog",
            "parser_config": {
                "facility": ["auth", "authpriv", "kern"],
                "severity": ["emerg", "alert", "crit", "err"]
            },
            "enabled": True,
            "created_at": CURRENT_TIMESTAMP - 86400 * 15,
            "created_by": "admin",
            "last_polled": None,
            "status": "active"
        },
        {
            "id": "src_ghi12345",
            "name": "AWS CloudTrail Logs",
            "source_type": "cloud_trail",
            "description": "AWS Account Activity Logs",
            "path": "s3://asira-logs/cloudtrail/",
            "credentials_id": "cred_aws_iam",
            "polling_interval": 900,
            "format": "json",
            "parser_config": {
                "region": "us-east-1",
                "account_id": "123456789012"
            },
            "enabled": True,
            "created_at": CURRENT_TIMESTAMP - 86400 * 5,
            "created_by": "admin",
            "last_polled": CURRENT_TIMESTAMP - 850,
            "status": "active"
        },
        {
            "id": "src_jkl67890",
            "name": "Database Audit Logs",
            "source_type": "database",
            "description": "SQL Server Audit Logs",
            "path": "jdbc:sqlserver://db01:1433;databaseName=master",
            "credentials_id": "cred_db_reader",
            "polling_interval": 600,
            "format": "sql",
            "parser_config": {
                "query": "SELECT * FROM sys.fn_get_audit_file ('/audit/*.sqlaudit', DEFAULT, DEFAULT)",
                "timestamp_field": "event_time"
            },
            "enabled": False,
            "created_at": CURRENT_TIMESTAMP - 86400 * 3,
            "created_by": "admin",
            "last_polled": CURRENT_TIMESTAMP - 86400,
            "status": "disabled"
        }
    ]
    
    return sources

# Incident controllers

def create_incident_in_db(db: Session, incident: IncidentCreate, created_by: str):
    """
    Create a new incident in the database
    
    Args:
        db: Database session
        incident: Incident creation data
        created_by: Username of creator
        
    Returns:
        Created incident object
    """
    # Generate an incident ID
    incident_id = f"inc_{uuid.uuid4().hex[:8]}"
    
    # Create incident data
    incident_data = {
        "id": incident_id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": "open",
        "created_at": CURRENT_TIMESTAMP,
        "updated_at": CURRENT_TIMESTAMP,
        "created_by": created_by,
        "last_updated_by": created_by,
        "assigned_to": None,
        "detection_id": incident.detection_id,
        "playbook_id": incident.playbook_id,
        "assets": incident.assets or [],
        "tags": incident.tags or [],
        "notes": None,
        "resolution": None,
        "playbook_execution_id": None,
        "source_ip": incident.source_ip,
        "username": incident.username
    }
    
    # Create timeline entry for incident creation
    timeline_entry = {
        "entry_id": f"timeline_{uuid.uuid4().hex[:8]}",
        "incident_id": incident_id,
        "timestamp": CURRENT_TIMESTAMP,
        "entry_type": "status_change",
        "user": created_by,
        "message": "Incident created",
        "details": {
            "status": "open",
            "severity": incident.severity
        }
    }
    
    # In a real implementation, this would save to the database
    # For Elasticsearch integration, we can index the incident
    es_index_document("asira_incidents", incident_data, incident_id)
    es_index_document("asira_incident_timeline", timeline_entry, timeline_entry["entry_id"])
    
    logger.info(f"Created incident {incident_id}: {incident.title} ({incident.severity}) by {created_by}")
    
    return incident_data

def update_incident_in_db(db: Session, incident_id: str, incident_update: IncidentUpdate, updated_by: str):
    """
    Update an incident in the database
    
    Args:
        db: Database session
        incident_id: ID of incident to update
        incident_update: Incident update data
        updated_by: Username of updater
        
    Returns:
        Updated incident object or None if not found
    """
    # Get existing incident
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        logger.warning(f"Attempted to update non-existent incident: {incident_id}")
        return None
    
    # Create update data
    update_data = {}
    timeline_entries = []
    
    # Update title if provided
    if incident_update.title is not None:
        update_data["title"] = incident_update.title
        
    # Update description if provided
    if incident_update.description is not None:
        update_data["description"] = incident_update.description
        
    # Update severity if provided
    if incident_update.severity is not None and incident_update.severity != incident["severity"]:
        old_severity = incident["severity"]
        update_data["severity"] = incident_update.severity
        
        # Create timeline entry for severity change
        timeline_entries.append({
            "entry_id": f"timeline_{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "timestamp": CURRENT_TIMESTAMP,
            "entry_type": "severity_change",
            "user": updated_by,
            "message": f"Severity changed from {old_severity} to {incident_update.severity}",
            "details": {
                "old_severity": old_severity,
                "new_severity": incident_update.severity
            }
        })
        
    # Update status if provided
    if incident_update.status is not None and incident_update.status != incident["status"]:
        old_status = incident["status"]
        update_data["status"] = incident_update.status
        
        # Create timeline entry for status change
        timeline_entries.append({
            "entry_id": f"timeline_{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "timestamp": CURRENT_TIMESTAMP,
            "entry_type": "status_change",
            "user": updated_by,
            "message": f"Status changed from {old_status} to {incident_update.status}",
            "details": {
                "old_status": old_status,
                "new_status": incident_update.status
            }
        })
        
    # Update assignment if provided
    if incident_update.assigned_to is not None and incident_update.assigned_to != incident.get("assigned_to"):
        old_assignee = incident.get("assigned_to", "unassigned")
        update_data["assigned_to"] = incident_update.assigned_to
        
        # Create timeline entry for assignment
        timeline_entries.append({
            "entry_id": f"timeline_{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "timestamp": CURRENT_TIMESTAMP,
            "entry_type": "assignment",
            "user": updated_by,
            "message": f"Incident assigned to {incident_update.assigned_to}" if incident_update.assigned_to else "Incident unassigned",
            "details": {
                "old_assignee": old_assignee,
                "new_assignee": incident_update.assigned_to
            }
        })
        
    # Update notes if provided
    if incident_update.notes is not None:
        update_data["notes"] = incident_update.notes
        
        # Create timeline entry for notes
        timeline_entries.append({
            "entry_id": f"timeline_{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "timestamp": CURRENT_TIMESTAMP,
            "entry_type": "comment",
            "user": updated_by,
            "message": "Notes updated",
            "details": {
                "notes": incident_update.notes
            }
        })
        
    # Update resolution if provided
    if incident_update.resolution is not None:
        update_data["resolution"] = incident_update.resolution
        
    # Update tags if provided
    if incident_update.tags is not None:
        update_data["tags"] = incident_update.tags
        
    # Update assets if provided
    if incident_update.assets is not None:
        update_data["assets"] = incident_update.assets
        
    # Update playbook execution ID if provided
    if incident_update.playbook_execution_id is not None:
        update_data["playbook_execution_id"] = incident_update.playbook_execution_id
        
        # Create timeline entry for playbook execution
        timeline_entries.append({
            "entry_id": f"timeline_{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "timestamp": CURRENT_TIMESTAMP,
            "entry_type": "playbook_execution",
            "user": updated_by,
            "message": f"Playbook execution {incident_update.playbook_execution_id} started",
            "details": {
                "execution_id": incident_update.playbook_execution_id
            }
        })
    
    # Always update these fields
    update_data["updated_at"] = CURRENT_TIMESTAMP
    update_data["last_updated_by"] = updated_by
    
    # In a real implementation, this would update the database
    # For Elasticsearch, we would update the document
    es_update_document("asira_incidents", incident_id, update_data)
    
    # Add timeline entries
    for entry in timeline_entries:
        es_index_document("asira_incident_timeline", entry, entry["entry_id"])
    
    logger.info(f"Updated incident {incident_id} by {updated_by}: {', '.join(update_data.keys())}")
    
    # Return updated incident
    updated_incident = incident.copy()
    updated_incident.update(update_data)
    return updated_incident

def close_incident_in_db(db: Session, incident_id: str, resolution: str, closed_by: str):
    """
    Close an incident
    
    Args:
        db: Database session
        incident_id: ID of incident to close
        resolution: Resolution details
        closed_by: Username of person closing
        
    Returns:
        Closed incident object or None if not found
    """
    # Get existing incident
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        logger.warning(f"Attempted to close non-existent incident: {incident_id}")
        return None
    
    # Check if incident is already closed
    if incident["status"] == "closed":
        raise ValueError("Incident is already closed")
    
    # Create update data
    update_data = {
        "status": "closed",
        "resolution": resolution,
        "updated_at": CURRENT_TIMESTAMP,
        "last_updated_by": closed_by,
    }
    
    # Create timeline entry for closing
    timeline_entry = {
        "entry_id": f"timeline_{uuid.uuid4().hex[:8]}",
        "incident_id": incident_id,
        "timestamp": CURRENT_TIMESTAMP,
        "entry_type": "status_change",
        "user": closed_by,
        "message": f"Incident closed",
        "details": {
            "old_status": incident["status"],
            "new_status": "closed",
            "resolution": resolution
        }
    }
    
    # In a real implementation, this would update the database
    # For Elasticsearch, we would update the document
    es_update_document("asira_incidents", incident_id, update_data)
    es_index_document("asira_incident_timeline", timeline_entry, timeline_entry["entry_id"])
    
    logger.info(f"Closed incident {incident_id} by {closed_by}")
    
    # Return closed incident
    closed_incident = incident.copy()
    closed_incident.update(update_data)
    return closed_incident

def get_incident_by_id(db: Session, incident_id: str):
    """
    Get an incident by ID
    
    Args:
        db: Database session
        incident_id: Incident ID
        
    Returns:
        Incident object or None if not found
    """
    # In a real implementation, this would fetch from the database
    
    # Check if the ID is in our expected format
    if not incident_id.startswith("inc_"):
        return None
    
    # Create a deterministic incident based on the ID
    id_hash = int(hashlib.md5(incident_id.encode()).hexdigest(), 16) % 100000
    
    # Use the hash to create deterministic but varied values
    days_ago = id_hash % 10
    hours_var = (id_hash * 3) % 24
    incident_timestamp = CURRENT_TIMESTAMP - (days_ago * 86400) - (hours_var * 3600)
    
    # Determine severity and status based on hash
    severities = ["low", "medium", "high", "critical"]
    statuses = ["open", "investigating", "contained", "remediated", "closed"]
    severity = severities[id_hash % len(severities)]
    
    # Newer incidents are more likely to be open
    if days_ago <= 2:
        status_index = id_hash % 3
    else:
        status_index = id_hash % len(statuses)
        
    status = statuses[status_index]
    
    # Incident types
    incident_types = [
        "Suspicious login activity",
        "Malware detection",
        "Data exfiltration attempt",
        "Privilege escalation",
        "DDoS attack",
        "Unauthorized access"
    ]
    incident_type = incident_types[id_hash % len(incident_types)]
    
    # Create assigned user for some incidents
    assigned_to = None
    if id_hash % 3 == 0:
        assigned_to = "analyst"
    elif id_hash % 5 == 0:
        assigned_to = "admin"
    
    # Create incident
    incident = {
        "id": incident_id,
        "title": f"{incident_type} - Server {id_hash:02d}",
        "description": f"Detailed description of {incident_type.lower()} on server-{id_hash:02d}. This incident was detected by the security monitoring system and requires investigation.",
        "severity": severity,
        "status": status,
        "created_at": incident_timestamp,
        "updated_at": incident_timestamp + ((id_hash % 5) * 3600),
        "created_by": "admin" if id_hash % 4 == 0 else "analyst",
        "last_updated_by": "admin" if id_hash % 4 == 0 else "analyst",
        "assigned_to": assigned_to,
        "detection_id": f"det_{id_hash:06d}" if id_hash % 2 == 0 else None,
        "playbook_id": f"pb_malware_containment" if id_hash % 3 == 0 else None,
        "assets": [f"server-{id_hash:02d}", f"database-{id_hash:02d}"] if id_hash % 2 == 0 else [f"server-{id_hash:02d}"],
        "tags": ["suspicious", "login"] if "login" in incident_type.lower() else ["malware"] if "malware" in incident_type.lower() else [],
        "notes": "Investigation notes will be added here" if status != "open" else None,
        "resolution": "Issue was resolved by..." if status == "closed" else None,
        "playbook_execution_id": f"exec_{id_hash:06d}" if status != "open" and id_hash % 3 == 0 else None,
        "source_ip": f"10.0.{id_hash % 255}.{(id_hash // 255) % 255}" if id_hash % 2 == 0 else None,
        "username": f"user{id_hash % 10}" if id_hash % 3 == 0 else None,
        "timeline": [
            {
                "entry_id": f"timeline_{id_hash}_1",
                "incident_id": incident_id,
                "timestamp": incident_timestamp,
                "entry_type": "status_change", 
                "user": "admin" if id_hash % 4 == 0 else "analyst",
                "message": "Incident created",
                "details": {
                    "status": "open",
                    "severity": severity
                }
            }
        ],
        "detections": [f"det_{id_hash:06d}"] if id_hash % 2 == 0 else [],
        "playbook_executions": [f"exec_{id_hash:06d}"] if status != "open" and id_hash % 3 == 0 else [],
        "time_to_response": (id_hash % 5) * 1800 if status != "open" else None,
        "mitre_tactics": ["Initial Access", "Execution"] if id_hash % 2 == 0 else ["Exfiltration"],
        "mitre_techniques": ["T1078", "T1059"] if id_hash % 2 == 0 else ["T1048"],
    }
    
    # Add additional timeline entries based on status
    if status != "open":
        # Add investigation started entry
        incident["timeline"].append({
            "entry_id": f"timeline_{id_hash}_2",
            "incident_id": incident_id,
            "timestamp": incident_timestamp + 1800,
            "entry_type": "status_change", 
            "user": assigned_to or "analyst",
            "message": "Investigation started",
            "details": {
                "old_status": "open",
                "new_status": "investigating"
            }
        })
    
    if status == "contained" or status == "remediated" or status == "closed":
        # Add containment entry
        incident["timeline"].append({
            "entry_id": f"timeline_{id_hash}_3",
            "incident_id": incident_id,
            "timestamp": incident_timestamp + 3600,
            "entry_type": "status_change", 
            "user": assigned_to or "analyst",
            "message": "Threat contained",
            "details": {
                "old_status": "investigating",
                "new_status": "contained"
            }
        })
    
    if status == "remediated" or status == "closed":
        # Add remediation entry
        incident["timeline"].append({
            "entry_id": f"timeline_{id_hash}_4",
            "incident_id": incident_id,
            "timestamp": incident_timestamp + 7200,
            "entry_type": "status_change", 
            "user": assigned_to or "analyst",
            "message": "Remediation completed",
            "details": {
                "old_status": "contained",
                "new_status": "remediated"
            }
        })
    
    if status == "closed":
        # Add closure entry
        incident["timeline"].append({
            "entry_id": f"timeline_{id_hash}_5",
            "incident_id": incident_id,
            "timestamp": incident_timestamp + 10800,
            "entry_type": "status_change", 
            "user": "admin",
            "message": "Incident closed",
            "details": {
                "old_status": "remediated",
                "new_status": "closed",
                "resolution": "Issue was resolved by applying security patches and resetting affected user credentials."
            }
        })
    
    return incident

def get_incidents_from_db(
    db: Session, 
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    created_after: Optional[float] = None,
    created_before: Optional[float] = None
):
    """
    Get incidents from the database
    
    Args:
        db: Database session
        status: Filter by status
        severity: Filter by severity
        assignee: Filter by assigned user
        limit: Maximum number of results to return
        offset: Number of results to skip
        created_after: Filter by creation time after timestamp
        created_before: Filter by creation time before timestamp
        
    Returns:
        List of incident objects
    """
    # In a real implementation, this would query the database
    # For this hackathon prototype, we'll return mock data
    base_timestamp = CURRENT_TIMESTAMP
    results = []
    
    # Generate a varied collection of incidents
    incident_types = [
        "Suspicious login activity",
        "Malware detection",
        "Data exfiltration attempt",
        "Privilege escalation",
        "DDoS attack",
        "Unauthorized access",
        "Ransomware activity",
        "Phishing campaign"
    ]
    
    severities = ["low", "medium", "high", "critical"]
    statuses = ["open", "investigating", "contained", "remediated", "closed"]
    
    for i in range(1, 35):
        # Calculate a deterministic but varied timestamp
        days_ago = i % 10  # Incidents from the last 10 days
        hours_var = (i * 3) % 24  # Vary the hour within the day
        incident_timestamp = base_timestamp - (days_ago * 86400) - (hours_var * 3600)
        
        # Skip if outside time range
        if created_after and incident_timestamp < created_after:
            continue
            
        if created_before and incident_timestamp > created_before:
            continue
        
        # Update timestamp varies
        update_offset = (i % 5) * 3600  # 0 to 4 hours after creation
        update_timestamp = incident_timestamp + update_offset
        
        # Select incident type, severity, status
        incident_type = incident_types[i % len(incident_types)]
        incident_severity = severities[i % len(severities)]
        
        # Skip if severity doesn't match filter
        if severity and incident_severity != severity:
            continue
        
        # Make distribution realistic - more open incidents for recent timestamps
        if days_ago <= 2:
            incident_status = statuses[i % 3]  # Only open, investigating, contained for recent
        else:
            incident_status = statuses[i % len(statuses)]
            
        # Skip if status doesn't match filter
        if status and incident_status != status:
            continue
            
        # Create assigned user for some incidents
        assigned_to = None
        if i % 3 == 0:
            assigned_to = "analyst"
        elif i % 5 == 0:
            assigned_to = "admin"
            
        # Skip if assignee doesn't match filter
        if assignee and assigned_to != assignee:
            continue
            
        # Create the incident
        incident = {
            "id": f"inc_{i:06d}",
            "title": f"{incident_type} - Server {i:02d}",
            "description": f"Detailed description of {incident_type.lower()} on server-{i:02d}",
            "severity": incident_severity,
            "status": incident_status,
            "created_at": incident_timestamp,
            "updated_at": update_timestamp,
            "created_by": "admin" if i % 4 == 0 else "analyst",
            "assigned_to": assigned_to,
            "detection_id": f"det_{i:06d}" if i % 2 == 0 else None,
            "playbook_id": f"pb_malware_containment" if i % 3 == 0 else None,
            "assets": [f"server-{i:02d}", f"database-{i:02d}"] if i % 2 == 0 else [f"server-{i:02d}"],
            "tags": ["suspicious", "login"] if "login" in incident_type.lower() else ["malware"] if "malware" in incident_type.lower() else [],
            "notes": "Investigation notes will be added here" if incident_status != "open" else None,
            "resolution": "Issue was resolved by..." if incident_status == "closed" else None,
            "playbook_execution_id": f"exec_{i:06d}" if incident_status != "open" and i % 3 == 0 else None,
            "source_ip": f"10.0.{i % 255}.{(i // 255) % 255}" if i % 2 == 0 else None,
            "username": f"user{i % 10}" if i % 3 == 0 else None,
        }
            
        results.append(incident)
    
    # Sort by creation time, newest first
    results.sort(key=lambda x: x["created_at"], reverse=True)
    
    # Apply pagination
    paginated_results = results[offset:offset+limit]
    
    return paginated_results

def search_incidents(db: Session, query: SearchQuery):
    """
    Advanced search for incidents
    
    Args:
        db: Database session
        query: Search query parameters
        
    Returns:
        List of matching incidents
    """
    # In a real implementation, this would build a complex query
    # For this prototype, we'll return a subset of mock incidents
    
    # Get all incidents
    all_incidents = get_incidents_from_db(db, limit=100)
    
    # Helper function to check if an incident matches a criterion
    def matches_criterion(incident, criterion):
        field = criterion.field
        value = criterion.value
        operation = criterion.operation
        
        if field not in incident:
            return False
            
        if operation == "eq":
            return incident[field] == value
        elif operation == "neq":
            return incident[field] != value
        elif operation == "gt":
            return incident[field] > value
        elif operation == "lt":
            return incident[field] < value
        elif operation == "contains":
            if isinstance(incident[field], str):
                return value in incident[field]
            elif isinstance(incident[field], list):
                return value in incident[field]
            else:
                return False
        elif operation == "startswith":
            if isinstance(incident[field], str):
                return incident[field].startswith(value)
            else:
                return False
        else:
            return False
    
    # Filter incidents based on criteria and operator
    results = []
    
    for incident in all_incidents:
        if query.operator == "and":
            # All criteria must match
            matches = all(matches_criterion(incident, criterion) for criterion in query.criteria)
        else:  # "or"
            # At least one criterion must match
            matches = any(matches_criterion(incident, criterion) for criterion in query.criteria)
            
        if matches:
            results.append(incident)
    
    # Apply pagination
    paginated_results = results[query.offset:query.offset+query.limit]
    
    return paginated_results

# Playbook controllers

def create_playbook_in_db(db: Session, playbook: PlaybookCreate, created_by: str):
    """
    Create a new playbook in the database
    
    Args:
        db: Database session
        playbook: Playbook creation data
        created_by: Username of creator
        
    Returns:
        Created playbook object
    """
    # Generate a playbook ID
    playbook_id = f"pb_{uuid.uuid4().hex[:8]}"
    current_time = CURRENT_TIMESTAMP
    
    # Create playbook data
    playbook_data = {
        "id": playbook_id,
        "name": playbook.name,
        "description": playbook.description,
        "actions": [action.dict() for action in playbook.actions],
        "enabled": playbook.enabled,
        "execution_mode": playbook.execution_mode,
        "created_at": current_time,
        "updated_at": current_time,
        "created_by": created_by,
        "tags": playbook.tags,
        "target_severity": playbook.target_severity,
        "execution_count": 0,
        "last_executed": None,
        "version": playbook.version,
        "author": playbook.author or created_by
    }
    
    # Save as YAML file in the playbooks directory
    try:
        from src.common.config import Settings
        
        settings = Settings()
        os.makedirs(settings.playbook_dir, exist_ok=True)
        
        with open(os.path.join(settings.playbook_dir, f"{playbook_id}.yml"), "w") as f:
            yaml.dump(playbook_data, f)
            
        logger.info(f"Created playbook {playbook_id}: {playbook.name}")
    except Exception as e:
        logger.error(f"Failed to save playbook YAML file: {e}")
    
    return playbook_data

def update_playbook_in_db(db: Session, playbook_id: str, playbook_update: PlaybookUpdate, updated_by: str):
    """
    Update a playbook in the database
    
    Args:
        db: Database session
        playbook_id: ID of playbook to update
        playbook_update: Playbook update data
        updated_by: Username of updater
        
    Returns:
        Updated playbook object or None if not found
    """
    # Get existing playbook
    playbook = get_playbook_by_id(db, playbook_id)
    if not playbook:
        logger.warning(f"Attempted to update non-existent playbook: {playbook_id}")
        return None
    
    # Create update data
    update_data = {
        "updated_at": CURRENT_TIMESTAMP
    }
    
    # Update fields if provided
    if playbook_update.name is not None:
        update_data["name"] = playbook_update.name
        
    if playbook_update.description is not None:
        update_data["description"] = playbook_update.description
        
    if playbook_update.actions is not None:
        update_data["actions"] = [action.dict() for action in playbook_update.actions]
        
    if playbook_update.enabled is not None:
        update_data["enabled"] = playbook_update.enabled
        
    if playbook_update.execution_mode is not None:
        update_data["execution_mode"] = playbook_update.execution_mode
        
    if playbook_update.tags is not None:
        update_data["tags"] = playbook_update.tags
        
    if playbook_update.target_severity is not None:
        update_data["target_severity"] = playbook_update.target_severity
        
    if playbook_update.version is not None:
        update_data["version"] = playbook_update.version
    
    # In a real implementation, this would update the database or file storage
    try:
        # Get file path for the playbook
        from src.common.config import Settings
        
        settings = Settings()
        playbook_file = os.path.join(settings.playbook_dir, f"{playbook_id}.yml")
        
        # Check if file exists
        if not os.path.exists(playbook_file):
            logger.warning(f"Playbook file not found: {playbook_file}")
            
            # Create a mock updated playbook
            updated_playbook = playbook.copy()
            updated_playbook.update(update_data)
            return updated_playbook
        
        # Read existing playbook
        with open(playbook_file, "r") as f:
            existing_data = yaml.safe_load(f)
            
        # Update playbook data
        existing_data.update(update_data)
        
        # Write updated playbook
        with open(playbook_file, "w") as f:
            yaml.dump(existing_data, f)
            
        logger.info(f"Updated playbook {playbook_id} by {updated_by}")
        
        return existing_data
        
    except Exception as e:
        logger.error(f"Failed to update playbook: {e}")
        
        # Return mock updated playbook anyway
        updated_playbook = playbook.copy()
        updated_playbook.update(update_data)
        return updated_playbook

def delete_playbook_from_db(db: Session, playbook_id: str):
    """
    Delete a playbook from the database
    
    Args:
        db: Database session
        playbook_id: ID of playbook to delete
        
    Returns:
        True if successful, False if not found
    """
    # Get existing playbook
    playbook = get_playbook_by_id(db, playbook_id)
    if not playbook:
        logger.warning(f"Attempted to delete non-existent playbook: {playbook_id}")
        return False
    
    # In a real implementation, this would delete from the database or file storage
    try:
        # Get file path for the playbook
        from src.common.config import Settings
        
        settings = Settings()
        playbook_file = os.path.join(settings.playbook_dir, f"{playbook_id}.yml")
        
        # Check if file exists
        if os.path.exists(playbook_file):
            # Delete file
            os.remove(playbook_file)
            
        logger.info(f"Deleted playbook {playbook_id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete playbook: {e}")
        return False

def get_playbook_by_id(db: Session, playbook_id: str):
    """
    Get a playbook by ID
    
    Args:
        db: Database session
        playbook_id: Playbook ID
        
    Returns:
        Playbook object or None if not found
    """
    # In a real implementation, this would fetch from the database or file storage
    # For this prototype, we'll check our preset mock data and return if found
    preset_playbooks = {
        "pb_account_lockdown": {
            "id": "pb_account_lockdown",
            "name": "Account Lockdown",
            "description": "Locks down a compromised user account",
            "actions": [
                {
                    "id": "disable_account",
                    "type": "command",
                    "command": "user_mgmt disable {username}",
                    "description": "Disable the user account"
                },
                {
                    "id": "reset_password",
                    "type": "command",
                    "command": "user_mgmt reset_pwd {username}",
                    "description": "Reset the user's password"
                },
                {
                    "id": "notify_user",
                    "type": "notification",
                    "template": "security_incident",
                    "channels": ["email"],
                    "description": "Notify the user about the incident"
                }
            ],
            "enabled": True,
            "execution_mode": "sequential",
            "created_at": CURRENT_TIMESTAMP - 86400 * 7,  # 1 week ago
            "updated_at": CURRENT_TIMESTAMP - 43200,      # 12 hours ago
            "created_by": "admin",
            "tags": ["account", "compromise", "identity"],
            "target_severity": ["medium", "high"],
            "execution_count": 12,
            "last_executed": CURRENT_TIMESTAMP - 7200,    # 2 hours ago
            "version": "1.0.0",
            "author": "admin"
        },
        "pb_malware_containment": {
            "id": "pb_malware_containment",
            "name": "Malware Containment",
            "description": "Contains a malware infection",
            "actions": [
                {
                    "id": "isolate_host",
                    "type": "containment",
                    "command": "edr isolate --hostname {hostname}",
                    "description": "Isolate infected host"
                },
                {
                    "id": "block_ioc",
                    "type": "containment",
                    "command": "firewall block {malware_c2}",
                    "description": "Block malware C2 server"
                },
                {
                    "id": "notify_team",
                    "type": "notification",
                    "template": "malware_alert",
                    "channels": ["slack"],
                    "description": "Notify security team"
                }
            ],
            "enabled": True,
            "execution_mode": "sequential",
            "created_at": CURRENT_TIMESTAMP - 86400 * 14,  # 2 weeks ago
            "updated_at": CURRENT_TIMESTAMP - 86400 * 3,   # 3 days ago
            "created_by": "admin",
            "tags": ["malware", "ransomware", "containment"],
            "target_severity": ["high", "critical"],
            "execution_count": 24,
            "last_executed": CURRENT_TIMESTAMP - 4500,     # 1.25 hours ago
            "version": "1.2.5",
            "author": "admin"
        }
    }
    
    # Check if ID is in our preset data
    if playbook_id in preset_playbooks:
        return preset_playbooks[playbook_id]
    
    # Try to check for file-based playbooks
    try:
        from src.common.config import Settings
        
        settings = Settings()
        playbook_file = os.path.join(settings.playbook_dir, f"{playbook_id}.yml")
        
        # Check if file exists
        if os.path.exists(playbook_file):
            with open(playbook_file, "r") as f:
                return yaml.safe_load(f)
                
    except Exception as e:
        logger.error(f"Error loading playbook file: {e}")
    
    # If ID doesn't match preset data and no file was found, generate a mock
    # but only if it follows our expected ID pattern
    if not playbook_id.startswith("pb_"):
        return None
        
    # Create a deterministic playbook based on the ID
    id_hash = int(hashlib.md5(playbook_id.encode()).hexdigest(), 16) % 100000
    
    # Generate days ago based on hash
    days_ago = id_hash % 30
    
    playbook = {
        "id": playbook_id,
        "name": f"Generated Playbook {id_hash}",
        "description": f"Auto-generated playbook for testing with ID {playbook_id}",
        "actions": [
            {
                "id": f"action_1_{id_hash}",
                "type": "command",
                "command": f"sample_command --param {id_hash}",
                "description": "First action in sequence"
            },
            {
                "id": f"action_2_{id_hash}",
                "type": "notification",
                "template": "alert_template",
                "channels": ["email"],
                "description": "Second action in sequence"
            }
        ],
        "enabled": id_hash % 5 != 0,  # 80% are enabled
        "execution_mode": "sequential",
        "created_at": CURRENT_TIMESTAMP - (days_ago * 86400),
        "updated_at": CURRENT_TIMESTAMP - ((days_ago / 2) * 86400),
        "created_by": "admin",
        "tags": ["generated", "test"],
        "target_severity": ["medium", "high"] if id_hash % 2 == 0 else ["low", "medium", "high", "critical"],
        "execution_count": id_hash % 50,
        "last_executed": CURRENT_TIMESTAMP - (id_hash % 86400) if id_hash % 3 == 0 else None,
        "version": "1.0.0",
        "author": "system"
    }
    
    return playbook

def get_playbooks_from_db(db: Session, enabled_only: bool = False, tag: Optional[str] = None, severity: Optional[str] = None):
    """
    Get playbooks from the database
    
    Args:
        db: Database session
        enabled_only: If True, only return enabled playbooks
        tag: Filter by tag
        severity: Filter by targeted severity
        
    Returns:
        List of playbook objects
    """
    # In a real implementation, this would query the database or file storage
    # For this hackathon prototype, we'll return mock data
    results = []
    
    # First add our preset playbooks
    preset_playbooks = [
        {
            "id": "pb_account_lockdown",
            "name": "Account Lockdown",
            "description": "Locks down a compromised user account",
            "enabled": True,
            "execution_mode": "sequential",
            "created_at": CURRENT_TIMESTAMP - 86400 * 7,
            "updated_at": CURRENT_TIMESTAMP - 43200,
            "created_by": "admin",
            "tags": ["account", "compromise", "identity"],
            "target_severity": ["medium", "high"],
            "execution_count": 12,
            "last_executed": CURRENT_TIMESTAMP - 7200,
            "version": "1.0.0",
            "author": "admin"
        },
        {
            "id": "pb_malware_containment",
            "name": "Malware Containment",
            "description": "Contains a malware infection",
            "enabled": True,
            "execution_mode": "sequential",
            "created_at": CURRENT_TIMESTAMP - 86400 * 14,
            "updated_at": CURRENT_TIMESTAMP - 86400 * 3,
            "created_by": "admin",
            "tags": ["malware", "ransomware", "containment"],
            "target_severity": ["high", "critical"],
            "execution_count": 24,
            "last_executed": CURRENT_TIMESTAMP - 4500,
            "version": "1.2.5",
            "author": "admin"
        },
        {
            "id": "pb_ddos_mitigation",
            "name": "DDoS Mitigation",
            "description": "Mitigates a DDoS attack by implementing traffic filtering",
            "enabled": True,
            "execution_mode": "parallel",
            "created_at": CURRENT_TIMESTAMP - 86400 * 21,
            "updated_at": CURRENT_TIMESTAMP - 86400 * 5,
            "created_by": "admin",
            "tags": ["ddos", "network", "mitigation"],
            "target_severity": ["high", "critical"],
            "execution_count": 5,
            "last_executed": CURRENT_TIMESTAMP - 86400,
            "version": "1.1.0",
            "author": "admin"
        },
        {
            "id": "pb_data_exfiltration_response",
            "name": "Data Exfiltration Response",
            "description": "Responds to data exfiltration attempts",
            "enabled": True,
            "execution_mode": "sequential",
            "created_at": CURRENT_TIMESTAMP - 86400 * 10,
            "updated_at": CURRENT_TIMESTAMP - 86400 * 2,
            "created_by": "analyst",
            "tags": ["exfiltration", "data-loss", "dlp"],
            "target_severity": ["medium", "high", "critical"],
            "execution_count": 8,
            "last_executed": CURRENT_TIMESTAMP - 86400 * 2,
            "version": "1.0.2",
            "author": "Mritunjay-mj"
        },
        {
            "id": "pb_phishing_response",
            "name": "Phishing Response",
            "description": "Handles phishing campaigns and compromised accounts",
            "enabled": False,  # Disabled playbook
            "execution_mode": "sequential",
            "created_at": CURRENT_TIMESTAMP - 86400 * 5,
            "updated_at": CURRENT_TIMESTAMP - 86400 * 1,
            "created_by": "analyst",
            "tags": ["phishing", "email", "compromise"],
            "target_severity": ["low", "medium"],
            "execution_count": 0,
            "last_executed": None,
            "version": "0.9.0",
            "author": "Mritunjay-mj"
        }
    ]
    
    # Add preset playbooks that match filters
    for playbook in preset_playbooks:
        if enabled_only and not playbook["enabled"]:
            continue
            
        if tag and tag not in playbook["tags"]:
            continue
            
        if severity and severity not in playbook["target_severity"]:
            continue
            
        results.append(playbook)
    
    # Try to load additional playbooks from the file system
    try:
        from src.common.config import Settings
        
        settings = Settings()
        
        if os.path.exists(settings.playbook_dir):
            for filename in os.listdir(settings.playbook_dir):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    file_path = os.path.join(settings.playbook_dir, filename)
                    try:
                        with open(file_path, "r") as f:
                            playbook_data = yaml.safe_load(f)
                            
                            # Check if this playbook matches our filters
                            if enabled_only and not playbook_data.get("enabled", True):
                                continue
                                
                            if tag and tag not in playbook_data.get("tags", []):
                                continue
                                
                            if severity and severity not in playbook_data.get("target_severity", []):
                                continue
                            
                            # Add playbook to results
                            results.append(playbook_data)
                    except Exception as e:
                        logger.error(f"Failed to load playbook from {file_path}: {e}")
    except Exception as e:
        logger.error(f"Error accessing playbook directory: {e}")
    
    return results

def get_playbook_execution_by_id(db: Session, execution_id: str):
    """
    Get a playbook execution by ID
    
    Args:
        db: Database session
        execution_id: Execution ID
        
    Returns:
        Playbook execution object or None if not found
    """
    # In a real implementation, this would fetch from the database
    
    # Check if the ID matches our expected format
    if not execution_id.startswith("exec_"):
        return None
    
    # Generate a deterministic execution based on the ID
    id_hash = int(hashlib.md5(execution_id.encode()).hexdigest(), 16) % 100000
    
    # Determine playbook and incident based on hash
    playbook_id = f"pb_{'malware_containment' if id_hash % 2 == 0 else 'account_lockdown'}"
    incident_id = f"inc_{id_hash:06d}" if id_hash % 3 != 0 else None
    
    # Calculate timestamps
    minutes_ago = id_hash % 360  # Up to 6 hours ago
    start_time = CURRENT_TIMESTAMP - (minutes_ago * 60)
    
    # Determine status based on how recent
    if minutes_ago < 5:
        status = "in_progress"
        end_time = None
        duration = None
    else:
        status = "completed" if id_hash % 10 != 0 else "failed"
        duration = (id_hash % 120) + 5  # 5-125 seconds
        end_time = start_time + duration
    
    # Create mock actions
    actions = []
    action_count = 2 + (id_hash % 3)  # 2-4 actions
    
    for i in range(action_count):
        action_start = start_time + (i * 10)  # Actions start 10 seconds apart
        action_duration = (id_hash % 10) + 2  # 2-12 seconds per action
        
        # For failed executions, make the last action fail
        action_status = "completed"
        action_error = None
        
        if status == "failed" and i == action_count - 1:
            action_status = "failed"
            action_error = "Command execution timed out after 30 seconds"
        
        action = {
            "action_id": f"action_{i+1}_{id_hash}",
            "status": action_status,
            "output": f"Action {i+1} output here..." if action_status == "completed" else None,
            "error": action_error,
            "start_time": action_start,
            "end_time": action_start + action_duration if action_status != "in_progress" else None,
            "duration_seconds": action_duration if action_status != "in_progress" else None
        }
        
        actions.append(action)
    
    # Create execution object
    execution = {
        "execution_id": execution_id,
        "playbook_id": playbook_id,
        "incident_id": incident_id,
        "start_time": start_time,
        "end_time": end_time,
        "status": status,
        "actions": actions,
        "triggered_by": "analyst" if id_hash % 3 == 0 else "admin",
        "summary": f"Execution {'completed successfully' if status == 'completed' else 'failed' if status == 'failed' else 'in progress'}",
        "duration_seconds": duration,
        "playbook_name": "Malware Containment" if playbook_id == "pb_malware_containment" else "Account Lockdown",
        "playbook_version": "1.2.5" if playbook_id == "pb_malware_containment" else "1.0.0",
        "environment": {
            "hostname": f"server-{id_hash % 10}",
            "ip_address": f"10.0.{id_hash % 255}.{(id_hash // 255) % 255}"
        },
        "input_parameters": {
            "hostname": f"server-{id_hash % 10}",
            "username": f"user{id_hash % 5}" if playbook_id == "pb_account_lockdown" else None,
            "malware_c2": f"evil{id_hash}.example.com" if playbook_id == "pb_malware_containment" else None
        },
        "logs": [
            {
                "timestamp": start_time,
                "level": "INFO",
                "message": f"Starting playbook execution {execution_id}"
            },
            {
                "timestamp": start_time + 1,
                "level": "INFO",
                "message": "Checking prerequisites..."
            },
            {
                "timestamp": end_time - 1 if end_time else start_time + 60,
                "level": "INFO" if status != "failed" else "ERROR",
                "message": "Playbook execution completed successfully" if status == "completed" else "Execution failed" if status == "failed" else "Execution in progress"
            }
        ],
        "success_rate": 1.0 if status == "completed" else 0.0 if status == "failed" else None
    }
    
    return execution

# Version information for the controllers module
CONTROLLERS_VERSION = "1.0.0"
CONTROLLERS_LAST_UPDATED = "2025-03-15 16:59:30"
CONTROLLERS_LAST_UPDATED_BY = "Rahul"
