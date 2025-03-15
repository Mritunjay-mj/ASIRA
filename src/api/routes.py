"""
API Routes for ASIRA
Defines all REST API endpoints using FastAPI

Version: 1.0.0
Last updated: 2025-03-15
"""
import time
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query, Path
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.common.database import get_db
from src.common.security import (
    create_access_token, 
    hash_password, 
    verify_password,
    get_current_user
)
from src.api.models import (
    UserCreate,
    UserUpdate,
    UserResponse,
    Token,
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookResponse,
    DetectionResultResponse,
    PlaybookExecutionResult,
    DashboardStats
)
from src.api.controllers import (
    get_user_by_username,
    create_user_in_db,
    update_user_in_db,
    update_last_login,
    get_detections_from_db,
    acknowledge_detection,
    create_detection_in_db,
    create_incident_in_db,
    update_incident_in_db,
    get_incidents_from_db,
    create_playbook_in_db,
    update_playbook_in_db,
    get_playbooks_from_db
)
from src.response.executor import PlaybookExecutor
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
    """
    # Get user from database
    user = get_user_by_username(db, form_data.username)
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
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
    
    return {"access_token": access_token, "token_type": "bearer", "expires_at": expires_at}

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
    current_user: Dict = Depends(get_current_user)
):
    """Create a new user"""
    # Verify current user has admin role
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    # Check if user already exists
    db_user = get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Create user in database
    return create_user_in_db(db, user)

@api_router.get(
    "/users/me", 
    response_model=UserResponse,
    summary="Get current user",
    description="Get details about the currently authenticated user",
    tags=["Users"]
)
async def read_users_me(
    current_user: Dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current logged in user"""
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

@api_router.patch(
    "/users/{username}", 
    response_model=UserResponse,
    summary="Update user",
    description="Update user details (admin access required except for own account)",
    tags=["Users"]
)
async def update_user(
    username: str = Path(..., description="Username to update"),
    user_update: UserUpdate = None,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user)
):
    """Update a user"""
    # Check permissions - only admins can update other users
    if current_user.get("sub") != username and current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    # Non-admins cannot change their own role
    if current_user.get("role") != "admin" and user_update.role is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change own role"
        )
    
    # Update user in database
    updated_user = update_user_in_db(db, username, user_update)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return updated_user

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
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user)
):
    """Get anomaly detection results"""
    return get_detections_from_db(db, limit, offset, min_score)

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
    current_user: Dict = Depends(get_current_user)
):
    """Acknowledge a detection"""
    return acknowledge_detection(db, detection_id, current_user.get("sub"))

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
    current_user: Dict = Depends(get_current_user)
):
    """Create a new security incident"""
    # Create incident in database
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
    
    return db_incident

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
    limit: int = Query(20, ge=1, le=100, description="Max number of incidents to return"),
    offset: int = Query(0, ge=0, description="Number of incidents to skip"),
    created_after: Optional[float] = Query(None, description="Filter incidents created after timestamp"),
    created_before: Optional[float] = Query(None, description="Filter incidents created before timestamp"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user)
):
    """Get security incidents"""
    return get_incidents_from_db(
        db, 
        status=status, 
        severity=severity, 
        limit=limit, 
        offset=offset,
        created_after=created_after,
        created_before=created_before
    )

@api_router.patch(
    "/incidents/{incident_id}", 
    response_model=IncidentResponse,
    summary="Update incident",
    description="Update an existing security incident",
    tags=["Incidents"]
)
async def update_incident(
    incident_id: str = Path(..., description="Incident ID to update"),
    incident_update: IncidentUpdate = None,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user)
):
    """Update an incident"""
    return update_incident_in_db(db, incident_id, incident_update, current_user.get("sub"))

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
    current_user: Dict = Depends(get_current_user)
):
    """Execute a playbook for a specific incident"""
    # Get incident data
    incidents = get_incidents_from_db(db)
    incident = next((inc for inc in incidents if inc["id"] == incident_id), None)
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found"
        )
    
    # Execute playbook
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
    
    return result

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
    current_user: Dict = Depends(get_current_user)
):
    """Create a new response playbook"""
    # Verify current user has admin role
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    return create_playbook_in_db(db, playbook, current_user.get("sub"))

@api_router.get(
    "/playbooks", 
    response_model=List[PlaybookResponse],
    summary="Get playbooks",
    description="List available response playbooks",
    tags=["Playbooks"]
)
async def get_playbooks(
    enabled_only: bool = Query(False, description="Only return enabled playbooks"),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user)
):
    """Get response playbooks"""
    return get_playbooks_from_db(db, enabled_only)

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
    current_user: Dict = Depends(get_current_user)
):
    """Get a specific playbook"""
    playbooks = get_playbooks_from_db(db)
    playbook = next((pb for pb in playbooks if pb["id"] == playbook_id), None)
    
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
    playbook_update: PlaybookUpdate = None,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user)
):
    """Update a playbook"""
    # Verify current user has admin role
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
        
    return update_playbook_in_db(db, playbook_id, playbook_update, current_user.get("sub"))

@api_router.post(
    "/playbooks/{playbook_id}/execute", 
    response_model=PlaybookExecutionResult,
    summary="Execute playbook",
    description="Execute a playbook with provided incident data (admin access required)",
    tags=["Playbooks"]
)
async def execute_playbook(
    playbook_id: str = Path(..., description="Playbook ID to execute"),
    incident_data: Dict[str, Any] = None,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user)
):
    """Execute a playbook with provided incident data"""
    # Verify current user has admin role
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    # Add triggered_by to incident data
    if incident_data:
        incident_data["triggered_by"] = current_user.get("sub")
    else:
        incident_data = {"triggered_by": current_user.get("sub")}
    
    result = playbook_executor.execute_playbook(playbook_id, incident_data)
    return result

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
    current_user: Dict = Depends(get_current_user)
):
    """Get statistics for the dashboard"""
    # In a real implementation, this would calculate actual stats
    # For this prototype, we'll return mock data
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
    
    # Calculate average response time (12 hours as mock value)
    avg_response_time = 12 * 3600
    
    return {
        "total_incidents": len(incidents),
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "incidents_by_severity": incidents_by_severity,
        "incidents_by_status": incidents_by_status,
        "detections_today": 15,  # Mock value
        "avg_response_time": avg_response_time,
        "playbooks_executed_today": 8  # Mock value
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
        "server_time": "2025-03-15 11:54:34"  # Current time from prompt
    }
