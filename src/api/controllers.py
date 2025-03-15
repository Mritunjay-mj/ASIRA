"""
API Controllers for ASIRA
Handle business logic between API routes and data access layers
"""
import time
import uuid
import logging
import os
import yaml
import json
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import hashlib

from src.common.security import hash_password
from src.common.database import es_index_document, es_search
from src.api.models import (
    UserCreate, 
    PlaybookCreate, 
    PlaybookUpdate,
    IncidentCreate, 
    IncidentUpdate,
    DetectionCreate
)

# Initialize logger
logger = logging.getLogger("asira.api.controllers")

# Current timestamp for use in this module
CURRENT_TIMESTAMP = time.time()

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
        }
    }
    
    if username in users:
        return type('User', (), users[username])
    return None

def create_user_in_db(db: Session, user: UserCreate):
    """
    Create a new user in the database
    
    Args:
        db: Database session
        user: User creation data
        
    Returns:
        Created user object
    """
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

def update_user_in_db(db: Session, username: str, user_data):
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
    
    # In a real implementation, this would update the database
    # Log user update
    logger.info(f"Updated user: {username}")
    
    # Return updated user data
    return {
        "id": user.id,
        "username": user.username,
        "email": user_data.email if hasattr(user_data, "email") and user_data.email else user.email,
        "full_name": user_data.full_name if hasattr(user_data, "full_name") and user_data.full_name else getattr(user, "full_name", None),
        "role": user_data.role if hasattr(user_data, "role") and user_data.role else user.role,
        "is_active": user_data.is_active if hasattr(user_data, "is_active") and user_data.is_active is not None else user.is_active,
        "created_at": user.created_at,
        "last_login": user.last_login
    }

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
    logger.info(f"Updated last login for user: {username}")

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
        "raw_data": detection.raw_data or {}
    }
    
    # In a real implementation, this would save to the database
    # For Elasticsearch integration, we can index the detection
    es_index_document("asira_detections", detection_data, detection_id)
    
    logger.info(f"Created new detection {detection_id} with score {detection.anomaly_score}")
    
    return detection_data

def get_detections_from_db(db: Session, limit: int = 100, offset: int = 0, min_score: float = 0.0):
    """
    Get detection results from the database
    
    Args:
        db: Database session
        limit: Maximum number of results to return
        offset: Number of results to skip
        min_score: Minimum anomaly score to include
        
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
    
    for i in range(1, 15):
        # Calculate a deterministic but varied timestamp
        ts_offset = (i * 1800) % 86400  # Vary within the last 24 hours
        detection_timestamp = base_timestamp - ts_offset
        
        # Alternate detection methods and create varied scores
        method_index = i % len(detection_methods)
        score_base = 0.7 + ((i % 3) * 0.1)  # Scores between 0.7 and 0.9
        
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
            "detection_method": detection_methods[method_index],
            "explanation": explanation,
            "related_events": related_events,
            "confidence": round(score_base - 0.05, 2),
            "timestamp": detection_timestamp,
            "acknowledged": i % 5 == 0,  # Some are acknowledged
            "acknowledged_by": "analyst" if i % 5 == 0 else None
        }
        
        # Only include if score meets the minimum
        if detection["anomaly_score"] >= min_score:
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
    # In a real implementation, this would update the database
    # For this prototype, we'll just log it
    logger.info(f"Detection {detection_id} acknowledged by {username}")
    
    # Return a mock response
    return {
        "id": detection_id,
        "acknowledged": True,
        "acknowledged_by": username,
        "acknowledged_at": CURRENT_TIMESTAMP
    }

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
        "assigned_to": None,
        "detection_id": incident.detection_id,
        "playbook_id": incident.playbook_id,
        "assets": incident.assets or [],
        "tags": incident.tags or [],
        "notes": None,
        "resolution": None,
        "playbook_execution_id": None
    }
    
    # In a real implementation, this would save to the database
    # For Elasticsearch integration, we can index the incident
    es_index_document("asira_incidents", incident_data, incident_id)
    
    logger.info(f"Created incident {incident_id}: {incident.title} ({incident.severity})")
    
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
    # In a real implementation, this would fetch the incident from the database
    # and update it with new values
    
    # For this prototype, we'll create a mock updated incident
    mock_incident = {
        "id": incident_id,
        "title": incident_update.title or "Original incident title",
        "description": incident_update.description or "Original incident description",
        "severity": incident_update.severity or "medium",
        "status": incident_update.status or "open",
        "created_at": CURRENT_TIMESTAMP - 3600,
        "updated_at": CURRENT_TIMESTAMP,
        "created_by": "analyst",
        "assigned_to": incident_update.assigned_to,
        "detection_id": "det_12345678",
        "playbook_id": "pb_malware_containment",
        "notes": incident_update.notes or "Original notes",
        "resolution": incident_update.resolution,
        "assets": ["server-web-01", "db-prod-02"],
        "tags": ["malware", "ransomware"]
    }
    
    logger.info(f"Updated incident {incident_id} by {updated_by}: status={incident_update.status}")
    
    return mock_incident

def get_incidents_from_db(
    db: Session, 
    status: Optional[str] = None,
    severity: Optional[str] = None,
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
    
    for i in range(1, 20):
        # Calculate a deterministic but varied timestamp
        days_ago = i % 10  # Incidents from the last 10 days
        hours_var = (i * 3) % 24  # Vary the hour within the day
        incident_timestamp = base_timestamp - (days_ago * 86400) - (hours_var * 3600)
        
        # Update timestamp varies
        update_offset = (i % 5) * 3600  # 0 to 4 hours after creation
        update_timestamp = incident_timestamp + update_offset
        
        # Select incident type, severity, status
        incident_type = incident_types[i % len(incident_types)]
        incident_severity = severities[i % len(severities)]
        # Make distribution realistic - more open incidents for recent timestamps
        if days_ago <= 2:
            incident_status = statuses[i % 3]  # Only open, investigating, contained for recent
        else:
            incident_status = statuses[i % len(statuses)]
            
        # Create assigned user for some incidents
        assigned_to = None
        if i % 3 == 0:
            assigned_to = "analyst"
        elif i % 5 == 0:
            assigned_to = "admin"
            
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
            "playbook_execution_id": f"exec_{i:06d}" if incident_status != "open" and i % 3 == 0 else None
        }
        
        # Apply filters
        if status and incident["status"] != status:
            continue
            
        if severity and incident["severity"] != severity:
            continue
            
        if created_after and incident["created_at"] < created_after:
            continue
            
        if created_before and incident["created_at"] > created_before:
            continue
            
        results.append(incident)
    
    # Sort by creation time, newest first
    results.sort(key=lambda x: x["created_at"], reverse=True)
    
    # Apply pagination
    paginated_results = results[offset:offset+limit]
    
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
        "last_executed": None
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
    # In a real implementation, this would fetch the playbook from storage
    # and update it with new values
    
    # For this prototype, we'll return a mock response
    return {
        "id": playbook_id,
        "name": playbook_update.name or "Original playbook name",
        "description": playbook_update.description or "Original playbook description",
        "actions": playbook_update.actions or [],
        "enabled": playbook_update.enabled if playbook_update.enabled is not None else True,
        "execution_mode": playbook_update.execution_mode or "sequential",
        "created_at": CURRENT_TIMESTAMP - 86400,
        "updated_at": CURRENT_TIMESTAMP,
        "created_by": "admin",
        "tags": playbook_update.tags or [],
        "target_severity": playbook_update.target_severity or [],
        "execution_count": 5,
        "last_executed": CURRENT_TIMESTAMP - 3600
    }

def get_playbooks_from_db(db: Session, enabled_only: bool = False):
    """
    Get playbooks from the database
    
    Args:
        db: Database session
        enabled_only: If True, only return enabled playbooks
        
    Returns:
        List of playbook objects
    """
    # In a real implementation, this would query the database or file storage
    # For this hackathon prototype, we'll return mock data
    results = []
    
    # Account lockdown playbook
    account_lockdown = {
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
