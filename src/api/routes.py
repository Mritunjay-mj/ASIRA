"""
API Routes for ASIRA
Defines all REST API endpoints using FastAPI

Version: 1.0.0
Last updated: 2025-03-15 16:30:57
Last updated by: Mritunjay-mj
"""

import time
import logging
from typing import List, Dict, Any, Optional, Union
from fastapi import (
    APIRouter, 
    Depends, 
    HTTPException, 
    status, 
    BackgroundTasks, 
    Query, 
    Path, 
    File, 
    UploadFile, 
    Form,
    Body
)
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid
import json

from src.common.database import get_db
from src.common.security import (
    create_access_token, 
    hash_password, 
    verify_password,
    get_current_user,
    get_current_active_user,
    RoleChecker
)
from src.api.models import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
    Token,
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentDetailResponse,
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookResponse,
    PlaybookListResponse,
    DetectionCreate,
    DetectionUpdate,
    DetectionResultResponse,
    DetectionDetailResponse,
    PlaybookExecutionResult,
    PlaybookExecutionDetailResponse,
    DashboardStats,
    SearchQuery,
    BulkActionRequest,
    LogSourceConfig
)
from src.api.controllers import (
    get_user_by_username,
    create_user_in_db,
    update_user_in_db,
    deactivate_user_in_db,
    get_all_users_from_db,
    update_last_login,
    get_detections_from_db,
    get_detection_by_id,
    acknowledge_detection,
    create_detection_in_db,
    update_detection_in_db,
    create_incident_in_db,
    update_incident_in_db,
    close_incident_in_db,
    get_incidents_from_db,
    get_incident_by_id,
    create_playbook_in_db,
    update_playbook_in_db,
    delete_playbook_from_db,
    get_playbooks_from_db,
    get_playbook_by_id,
    get_playbook_execution_by_id,
    search_incidents,
    search_detections,
    upload_log_file,
    configure_log_source,
    get_log_sources,
    bulk_acknowledge_detections
)
from src.response.executor import PlaybookExecutor
from src.detection.processor import LogIngester
from src.common.config import Settings

# Initialize logger
logger = logging.getLogger("asira.api.routes")

# Create router
api_router = APIRouter(tags=["API"])

# Initialize settings
settings = Settings()

# Initialize playbook executor
playbook_executor = PlaybookExecutor({
    "execution_dir": settings.execution_dir,
    "playbook_dir": settings.playbook_dir,
    "max_execution_time": settings.max_execution_time,
    "sandbox_type": settings.sandbox_type
})

# Initialize log ingester
log_ingester = LogIngester({
    "batch_size": settings.log_batch_size,
    "normalizer": settings.log_normalizer_config
})

# Role checkers
require_admin = RoleChecker(["admin"])
require_admin_or_analyst = RoleChecker(["admin", "analyst"])

# ------------------------------------------------------------------------------
# Authentication routes
# ------------------------------------------------------------------------------

@api_router.post(
    "/auth/token", 
    response_model=Token,
    summary="Get access token",
    description="OAuth2 compatible token login, get an access token for future requests",
    tags=["Authentication"]
)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    OAuth2 compatible token login, get an access token for future requests
    
    - **username**: Your username
    - **password**: Your password
    
    Returns a token that can be used to authenticate other API calls
    """
    # Get user from database
    user = get_user_by_username(db, form_data.username)
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.is_active:
        logger.warning(f"Login attempt for deactivated user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login timestamp
    update_last_login(db, form_data.username)
    
    # Create access token with 24 hour expiration
    expires_delta = settings.token_expire_minutes * 60
    expires_at = time.time() + expires_delta
    
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "exp": expires_at}
    )
    
    logger.info(f"User {form_data.username} logged in successfully")
    
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "expires_at": expires_at,
        "user_id": user.id,
        "username": user.username,
        "role": user.role
    }

@api_router.post(
    "/auth/logout",
    summary="Logout current user",
    description="Logout the current user (client-side implementation required)",
    tags=["Authentication"]
)
async def logout(current_user: Dict = Depends(get_current_user)):
    """
    Logout endpoint
    
    Note: Since JWT tokens are stateless, actual logout needs to be implemented
    client-side by removing the token. This endpoint is provided for API completeness.
    """
    logger.info(f"User {current_user.get('sub')} logged out")
    return {"detail": "Logout successful"}

# ------------------------------------------------------------------------------
# User management routes
# ------------------------------------------------------------------------------

@api_router.post(
    "/users", 
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new user",
    description="Create a new user (admin access required)",
    tags=["Users"]
)
async def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    Create a new user (admin access required)
    
    - **username**: Required unique username
    - **email**: Valid email address
    - **password**: Strong password
    - **full_name**: User's full name (optional)
    - **role**: User role (admin, analyst, readonly)
    """
    # Check if user already exists
    db_user = get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Create user in database
    try:
        new_user = create_user_in_db(db, user)
        logger.info(f"User {user.username} created by {current_user.get('sub')}")
        return new_user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.get(
    "/users", 
    response_model=List[UserListResponse],
    summary="List users",
    description="Get a list of all users (admin access required)",
    tags=["Users"]
)
async def list_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of users to return"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    List all users (admin access required)
    
    Returns a list of users with basic information
    """
    users = get_all_users_from_db(db, skip=skip, limit=limit)
    return users

@api_router.get(
    "/users/me", 
    response_model=UserResponse,
    summary="Get current user",
    description="Get details about the currently authenticated user",
    tags=["Users"]
)
async def read_users_me(
    current_user: Dict = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get current logged in user
    
    Returns detailed information about the current authenticated user
    """
    user = get_user_by_username(db, current_user.get("sub"))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Convert user object to dict
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": getattr(user, "full_name", None),
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login": getattr(user, "last_login", None)
    }

@api_router.get(
    "/users/{username}", 
    response_model=UserResponse,
    summary="Get user by username",
    description="Get details about a specific user (admin access required)",
    tags=["Users"]
)
async def get_user(
    username: str = Path(..., description="Username to fetch"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    Get user by username (admin access required)
    
    Returns detailed information about the specified user
    """
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": getattr(user, "full_name", None),
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login": getattr(user, "last_login", None)
    }

@api_router.patch(
    "/users/{username}", 
    response_model=UserResponse,
    summary="Update user",
    description="Update user details (admin access required except for own account)",
    tags=["Users"]
)
async def update_user(
    username: str = Path(..., description="Username to update"),
    user_update: UserUpdate = Body(...),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Update a user
    
    - **email**: New email address
    - **full_name**: New full name
    - **password**: New password
    - **role**: New role (admin access required)
    - **is_active**: Account active status (admin access required)
    """
    # Check permissions - only admins can update other users
    if current_user.get("sub") != username and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    # Non-admins cannot change their own role or active status
    if current_user.get("role") != "admin":
        if user_update.role is not None or user_update.is_active is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot change role or active status"
            )
    
    # Update user in database
    try:
        updated_user = update_user_in_db(db, username, user_update)
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        logger.info(f"User {username} updated by {current_user.get('sub')}")
        return updated_user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.delete(
    "/users/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user",
    description="Delete a user (admin access required)",
    tags=["Users"]
)
async def delete_user(
    username: str = Path(..., description="Username to delete"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    Delete a user (admin access required)
    
    This endpoint deactivates a user instead of permanently deleting them.
    """
    # Prevent deleting yourself
    if current_user.get("sub") == username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    # Deactivate the user
    result = deactivate_user_in_db(db, username)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    logger.info(f"User {username} deactivated by {current_user.get('sub')}")
    return None

# ------------------------------------------------------------------------------
# Detection routes
# ------------------------------------------------------------------------------

@api_router.get(
    "/detections", 
    response_model=List[DetectionResultResponse],
    summary="Get detections",
    description="List anomaly detections with optional filtering",
    tags=["Detections"]
)
async def get_detections(
    limit: int = Query(20, ge=1, le=100, description="Max number of detections to return"),
    offset: int = Query(0, ge=0, description="Number of detections to skip"),
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Minimum anomaly score"),
    method: Optional[str] = Query(None, description="Filter by detection method"),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledged status"),
    start_time: Optional[float] = Query(None, description="Filter detections after timestamp"),
    end_time: Optional[float] = Query(None, description="Filter detections before timestamp"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get anomaly detection results
    
    Returns a list of detection results matching the specified filters
    """
    return get_detections_from_db(
        db, 
        limit=limit, 
        offset=offset, 
        min_score=min_score,
        method=method,
        acknowledged=acknowledged,
        start_time=start_time,
        end_time=end_time
    )

@api_router.get(
    "/detections/{detection_id}", 
    response_model=DetectionDetailResponse,
    summary="Get detection by ID",
    description="Get detailed information about a specific detection",
    tags=["Detections"]
)
async def get_detection(
    detection_id: str = Path(..., description="Detection ID to fetch"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get detailed information about a specific detection
    
    Returns complete detection details including related events and explanation data
    """
    detection = get_detection_by_id(db, detection_id)
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found"
        )
    
    return detection

@api_router.post(
    "/detections", 
    response_model=DetectionResultResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create detection",
    description="Create a new detection result (normally created by the detection engine)",
    tags=["Detections"]
)
async def create_detection(
    detection: DetectionCreate,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin_or_analyst)
):
    """
    Create a new detection result
    
    This endpoint is primarily used by the detection engine but can also
    be used to manually create detections.
    """
    try:
        result = create_detection_in_db(db, detection)
        logger.info(f"Detection created: {result['id']} by {current_user.get('sub')}")
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.post(
    "/detections/{detection_id}/acknowledge", 
    response_model=Dict[str, Any],
    summary="Acknowledge detection",
    description="Mark a detection as acknowledged by the current user",
    tags=["Detections"]
)
async def acknowledge_detection_endpoint(
    detection_id: str = Path(..., description="Detection ID to acknowledge"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Acknowledge a detection
    
    Marks a detection as reviewed by the current user
    """
    result = acknowledge_detection(db, detection_id, current_user.get("sub"))
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found"
        )
    
    logger.info(f"Detection {detection_id} acknowledged by {current_user.get('sub')}")
    return result

@api_router.post(
    "/detections/bulk/acknowledge", 
    response_model=Dict[str, Any],
    summary="Bulk acknowledge detections",
    description="Mark multiple detections as acknowledged by the current user",
    tags=["Detections"]
)
async def bulk_acknowledge_detections_endpoint(
    request: BulkActionRequest,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Bulk acknowledge detections
    
    Marks multiple detections as reviewed by the current user
    """
    if not request.ids or len(request.ids) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No detection IDs provided"
        )
    
    results = bulk_acknowledge_detections(db, request.ids, current_user.get("sub"))
    
    logger.info(f"{len(results['acknowledged'])} detections bulk acknowledged by {current_user.get('sub')}")
    return {
        "acknowledged": len(results["acknowledged"]),
        "failed": len(results["failed"]),
        "details": results
    }

@api_router.post(
    "/detections/search", 
    response_model=List[DetectionResultResponse],
    summary="Search detections",
    description="Advanced search for detections based on multiple criteria",
    tags=["Detections"]
)
async def search_detections_endpoint(
    query: SearchQuery,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Advanced search for detections
    
    Search for detections using multiple criteria with AND/OR logic
    """
    results = search_detections(db, query)
    return results

@api_router.post(
    "/detections/ingest",
    response_model=Dict[str, Any],
    summary="Ingest log file for detection",
    description="Upload a log file to be processed by the detection engine",
    tags=["Detections"]
)
async def ingest_log_file(
    file: UploadFile = File(...),
    description: str = Form(..., description="Description of the log file"),
    source_type: str = Form(..., description="Type of log source"),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin_or_analyst)
):
    """
    Ingest a log file for detection
    
    Upload a log file (JSON, CSV, syslog) to be processed by the detection engine
    """
    try:
        # Save the file for processing
        file_id = str(uuid.uuid4())
        result = await upload_log_file(file, file_id, description, source_type)
        
        # Process the file in background to avoid blocking the request
        if background_tasks:
            background_tasks.add_task(
                log_ingester.ingest_file,
                result["file_path"],
                source_type
            )
        
        logger.info(f"Log file uploaded: {result['file_id']} by {current_user.get('sub')}")
        
        return {
            "file_id": result["file_id"],
            "description": description,
            "source_type": source_type,
            "size_bytes": result["size_bytes"],
            "upload_time": result["upload_time"],
            "status": "queued_for_processing"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

# ------------------------------------------------------------------------------
# Log source configuration routes
# ------------------------------------------------------------------------------

@api_router.post(
    "/sources", 
    response_model=Dict[str, Any],
    summary="Configure log source",
    description="Configure a new log source for ongoing detection",
    tags=["Sources"]
)
async def configure_source(
    config: LogSourceConfig,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    Configure a new log source
    
    Set up a log source (file, syslog, API) for continuous monitoring
    """
    try:
        result = configure_log_source(db, config, current_user.get("sub"))
        logger.info(f"Log source configured: {result['id']} by {current_user.get('sub')}")
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.get(
    "/sources", 
    response_model=List[Dict[str, Any]],
    summary="Get log sources",
    description="List all configured log sources",
    tags=["Sources"]
)
async def get_sources(
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    List all configured log sources
    
    Returns all log sources configured for detection
    """
    return get_log_sources(db)

# ------------------------------------------------------------------------------
# Incident routes
# ------------------------------------------------------------------------------

@api_router.post(
    "/incidents", 
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create incident",
    description="Create a new security incident",
    tags=["Incidents"]
)
async def create_incident(
    incident: IncidentCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Create a new security incident
    
    - **title**: Incident title
    - **description**: Detailed description of the incident
    - **severity**: Incident severity (low, medium, high, critical)
    - **detection_id**: Associated detection ID (optional)
    - **playbook_id**: Playbook to execute automatically (optional)
    - **assets**: Affected assets (optional)
    - **tags**: Incident tags (optional)
    
    If a playbook_id is provided, it will be executed automatically.
    """
    # Create incident in database
    try:
        db_incident = create_incident_in_db(db, incident, current_user.get("sub"))
        
        # Trigger automated response if a playbook is specified
        if incident.playbook_id:
            background_tasks.add_task(
                playbook_executor.execute_playbook,
                incident.playbook_id,
                {
                    "id": db_incident["id"],
                    "title": db_incident["title"],
                    "description": db_incident["description"],
                    "severity": db_incident["severity"],
                    "detection_id": db_incident["detection_id"],
                    "created_by": current_user.get("sub")
                }
            )
        
        logger.info(f"Incident created: {db_incident['id']} by {current_user.get('sub')}")
        return db_incident
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.get(
    "/incidents", 
    response_model=List[IncidentResponse],
    summary="Get incidents",
    description="List security incidents with optional filtering",
    tags=["Incidents"]
)
async def get_incidents(
    status: Optional[str] = Query(None, description="Filter by incident status"),
    severity: Optional[str] = Query(None, description="Filter by incident severity"),
    assignee: Optional[str] = Query(None, description="Filter by assigned user"),
    limit: int = Query(20, ge=1, le=100, description="Max number of incidents to return"),
    offset: int = Query(0, ge=0, description="Number of incidents to skip"),
    created_after: Optional[float] = Query(None, description="Filter incidents created after timestamp"),
    created_before: Optional[float] = Query(None, description="Filter incidents created before timestamp"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get security incidents
    
    Returns a list of security incidents matching the specified filters
    """
    return get_incidents_from_db(
        db, 
        status=status, 
        severity=severity, 
        assignee=assignee,
        limit=limit, 
        offset=offset,
        created_after=created_after,
        created_before=created_before
    )

@api_router.get(
    "/incidents/{incident_id}", 
    response_model=IncidentDetailResponse,
    summary="Get incident by ID",
    description="Get detailed information about a specific incident",
    tags=["Incidents"]
)
async def get_incident(
    incident_id: str = Path(..., description="Incident ID to fetch"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get detailed information about a specific incident
    
    Returns complete incident details including timeline, notes, and related playbook executions
    """
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    return incident

@api_router.patch(
    "/incidents/{incident_id}", 
    response_model=IncidentResponse,
    summary="Update incident",
    description="Update an existing security incident",
    tags=["Incidents"]
)
async def update_incident(
    incident_id: str = Path(..., description="Incident ID to update"),
    incident_update: IncidentUpdate = Body(...),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Update an incident
    
    - **status**: New incident status
    - **severity**: New severity level
    - **assigned_to**: Username to assign the incident to
    - **notes**: Additional notes about the incident
    - **resolution**: Resolution details (for closed incidents)
    """
    try:
        updated_incident = update_incident_in_db(
            db, 
            incident_id, 
            incident_update, 
            current_user.get("sub")
        )
        
        if not updated_incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found"
            )
        
        logger.info(f"Incident {incident_id} updated by {current_user.get('sub')}")
        return updated_incident
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.post(
    "/incidents/{incident_id}/close", 
    response_model=IncidentResponse,
    summary="Close incident",
    description="Close a security incident with resolution details",
    tags=["Incidents"]
)
async def close_incident(
    incident_id: str = Path(..., description="Incident ID to close"),
    resolution: str = Body(..., embed=True, description="Resolution details"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Close a security incident
    
    Marks an incident as closed and records the resolution details
    
    - **resolution**: Required explanation of how the incident was resolved
    """
    try:
        closed_incident = close_incident_in_db(
            db, 
            incident_id, 
            resolution, 
            current_user.get("sub")
        )
        
        if not closed_incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found"
            )
        
        logger.info(f"Incident {incident_id} closed by {current_user.get('sub')}")
        return closed_incident
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.post(
    "/incidents/{incident_id}/execute_playbook/{playbook_id}", 
    response_model=PlaybookExecutionResult,
    summary="Execute playbook for incident",
    description="Execute a specific playbook for an incident",
    tags=["Incidents", "Playbooks"]
)
async def execute_playbook_for_incident(
    incident_id: str = Path(..., description="Incident ID"),
    playbook_id: str = Path(..., description="Playbook ID to execute"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Execute a playbook for a specific incident
    
    Launches the specified playbook with the incident context for automated response
    """
    # Get incident data
    incident = get_incident_by_id(db, incident_id)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Check if playbook exists
    playbook = get_playbook_by_id(db, playbook_id)
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    if not playbook.get("enabled", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Playbook is disabled"
        )
    
    # Execute playbook
    try:
        result = playbook_executor.execute_playbook(
            playbook_id, 
            {
                "id": incident["id"],
                "title": incident["title"],
                "description": incident["description"],
                "severity": incident["severity"],
                "detection_id": incident.get("detection_id"),
                "incident_id": incident_id,
                "triggered_by": current_user.get("sub")
            }
        )
        
        # Update incident with execution ID
        if result and "execution_id" in result:
            update_incident_in_db(
                db, 
                incident_id, 
                IncidentUpdate(playbook_execution_id=result["execution_id"]), 
                current_user.get("sub")
            )
        
        logger.info(f"Playbook {playbook_id} executed for incident {incident_id} by {current_user.get('sub')}")
        return result
    except Exception as e:
        logger.error(f"Playbook execution failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Playbook execution failed: {str(e)}"
        )

@api_router.post(
    "/incidents/search", 
    response_model=List[IncidentResponse],
    summary="Search incidents",
    description="Advanced search for incidents based on multiple criteria",
    tags=["Incidents"]
)
async def search_incidents_endpoint(
    query: SearchQuery,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Advanced search for incidents
    
    Search for incidents using multiple criteria with AND/OR logic
    """
    results = search_incidents(db, query)
    return results

# ------------------------------------------------------------------------------
# Playbook routes
# ------------------------------------------------------------------------------

@api_router.post(
    "/playbooks", 
    response_model=PlaybookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create playbook",
    description="Create a new response playbook (admin access required)",
    tags=["Playbooks"]
)
async def create_playbook(
    playbook: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    Create a new response playbook (admin access required)
    
    - **name**: Playbook name
    - **description**: Detailed description
    - **actions**: List of actions to perform
    - **execution_mode**: How to execute actions (sequential or parallel)
    - **enabled**: Whether the playbook is ready for use
    - **tags**: Categorization tags
    - **target_severity**: Severity levels this playbook targets
    """
    try:
        result = create_playbook_in_db(db, playbook, current_user.get("sub"))
        logger.info(f"Playbook created: {result['id']} by {current_user.get('sub')}")
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.get(
    "/playbooks", 
    response_model=List[PlaybookListResponse],
    summary="Get playbooks",
    description="List available response playbooks",
    tags=["Playbooks"]
)
async def get_playbooks(
    enabled_only: bool = Query(False, description="Only return enabled playbooks"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    severity: Optional[str] = Query(None, description="Filter by targeted severity"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get response playbooks
    
    Returns a list of available playbooks, optionally filtered by status, tags, or severity
    """
    return get_playbooks_from_db(
        db, 
        enabled_only=enabled_only, 
        tag=tag, 
        severity=severity
    )

@api_router.get(
    "/playbooks/{playbook_id}", 
    response_model=PlaybookResponse,
    summary="Get playbook",
    description="Get a specific playbook by ID",
    tags=["Playbooks"]
)
async def get_playbook(
    playbook_id: str = Path(..., description="Playbook ID"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get a specific playbook
    
    Returns detailed information about the specified playbook
    """
    playbook = get_playbook_by_id(db, playbook_id)
    
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
        
    return playbook

@api_router.patch(
    "/playbooks/{playbook_id}", 
    response_model=PlaybookResponse,
    summary="Update playbook",
    description="Update an existing response playbook (admin access required)",
    tags=["Playbooks"]
)
async def update_playbook(
    playbook_id: str = Path(..., description="Playbook ID to update"),
    playbook_update: PlaybookUpdate = Body(...),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    Update a playbook (admin access required)
    
    Update an existing playbook's properties or actions
    """
    try:
        updated_playbook = update_playbook_in_db(
            db, 
            playbook_id, 
            playbook_update, 
            current_user.get("sub")
        )
        
        if not updated_playbook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Playbook not found"
            )
        
        logger.info(f"Playbook {playbook_id} updated by {current_user.get('sub')}")
        return updated_playbook
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@api_router.delete(
    "/playbooks/{playbook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete playbook",
    description="Delete an existing playbook (admin access required)",
    tags=["Playbooks"]
)
async def delete_playbook(
    playbook_id: str = Path(..., description="Playbook ID to delete"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin)
):
    """
    Delete a playbook (admin access required)
    
    Completely removes a playbook from the system
    """
    result = delete_playbook_from_db(db, playbook_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    logger.info(f"Playbook {playbook_id} deleted by {current_user.get('sub')}")
    return None

@api_router.post(
    "/playbooks/{playbook_id}/execute", 
    response_model=PlaybookExecutionResult,
    summary="Execute playbook",
    description="Execute a playbook with provided incident data (admin access required)",
    tags=["Playbooks"]
)
async def execute_playbook(
    playbook_id: str = Path(..., description="Playbook ID to execute"),
    incident_data: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user),
    _: bool = Depends(require_admin_or_analyst)
):
    """
    Execute a playbook with provided incident data (admin/analyst access required)
    
    Run a playbook with custom incident context for testing or ad-hoc execution
    """
    # Check if playbook exists
    playbook = get_playbook_by_id(db, playbook_id)
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    # Add triggered_by to incident data
    if incident_data:
        incident_data["triggered_by"] = current_user.get("sub")
    else:
        incident_data = {"triggered_by": current_user.get("sub")}
    
    try:
        result = playbook_executor.execute_playbook(playbook_id, incident_data)
        logger.info(f"Playbook {playbook_id} executed manually by {current_user.get('sub')}")
        return result
    except Exception as e:
        logger.error(f"Playbook execution failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Playbook execution failed: {str(e)}"
        )

@api_router.get(
    "/executions/{execution_id}",
    response_model=PlaybookExecutionDetailResponse,
    summary="Get playbook execution details",
    description="Get detailed results of a playbook execution",
    tags=["Playbooks"]
)
async def get_execution_details(
    execution_id: str = Path(..., description="Execution ID"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get detailed results of a playbook execution
    
    Returns complete information about a playbook execution including all action results
    """
    execution = get_playbook_execution_by_id(db, execution_id)
    
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    return execution

# ------------------------------------------------------------------------------
# Dashboard routes
# ------------------------------------------------------------------------------

@api_router.get(
    "/dashboard/stats", 
    response_model=DashboardStats,
    summary="Get dashboard stats",
    description="Get statistics for the dashboard",
    tags=["Dashboard"]
)
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_active_user)
):
    """
    Get statistics for the dashboard
    
    Returns aggregate statistics about incidents, detections, and system performance
    """
    # Get incidents from database
    incidents = get_incidents_from_db(db)
    
    # Count incidents by status and severity
    incidents_by_status = {}
    incidents_by_severity = {}
    open_incidents = 0
    critical_incidents = 0
    
    for incident in incidents:
        # Count by status
        status = incident["status"]
        incidents_by_status[status] = incidents_by_status.get(status, 0) + 1
        
        # Count by severity
        severity = incident["severity"]
        incidents_by_severity[severity] = incidents_by_severity.get(severity, 0) + 1
        
        # Count open incidents (open, investigating, contained)
        if status in ["open", "investigating", "contained"]:
            open_incidents += 1
            
        # Count critical incidents
        if severity == "critical":
            critical_incidents += 1
    
    # Get recent detections (last 24 hours)
    one_day_ago = time.time() - (24 * 3600)
    detections = get_detections_from_db(
        db, 
        limit=1000, 
        start_time=one_day_ago
    )
    
    # Count detections today
    detections_today = len(detections)
    
    # Calculate average response time (mock value for now - would be calculated from actual data)
    avg_response_time = 12 * 3600  # 12 hours in seconds
    
    # Count playbooks executed today (mock value - would be calculated from execution records)
    playbooks_executed_today = 8
    
    # Get timestamp for last updated
    last_updated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    
    return {
        "total_incidents": len(incidents),
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "incidents_by_severity": incidents_by_severity,
        "incidents_by_status": incidents_by_status,
        "detections_today": detections_today,
        "avg_response_time": avg_response_time,
        "playbooks_executed_today": playbooks_executed_today,
        "last_updated": last_updated,
        "last_updated_by": "Mritunjay-mj"
    }

# ------------------------------------------------------------------------------
# Health check endpoint
# ------------------------------------------------------------------------------

@api_router.get(
    "/health",
    summary="API health check",
    description="Check if the API is running properly",
    tags=["System"]
)
async def api_health_check():
    """API health check endpoint"""
    return {
        "status": "ok", 
        "version": "1.0.0",
        "timestamp": time.time(),
        "server_time": "2025-03-15 16:35:38",
        "last_updated_by": "Rahul"
    }
