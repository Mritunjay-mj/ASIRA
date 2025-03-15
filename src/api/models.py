"""
API data models for ASIRA
Defines Pydantic models for request and response validation
"""
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, EmailStr, Field, validator

# Enums for constrained fields
class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"

class ActionType(str, Enum):
    COMMAND = "command"
    API_CALL = "api_call"
    SCRIPT = "script"
    NOTIFICATION = "notification"
    CONTAINMENT = "containment"
    ENRICHMENT = "enrichment"

class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"

# User models
class UserBase(BaseModel):
    """Base user model"""
    username: str
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    """User creation model"""
    password: str
    role: UserRole = UserRole.ANALYST

class UserUpdate(BaseModel):
    """User update model"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

class UserResponse(UserBase):
    """User response model"""
    id: str
    role: UserRole
    is_active: bool
    created_at: float
    last_login: Optional[float] = None
    
    class Config:
        orm_mode = True

# Authentication models
class Token(BaseModel):
    """Token response model"""
    access_token: str
    token_type: str
    expires_at: float

class TokenData(BaseModel):
    """Token data model"""
    sub: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[float] = None

# Detection models
class DetectionBase(BaseModel):
    """Base detection model"""
    event_id: str
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    detection_method: str
    confidence: float = Field(..., ge=0.0, le=1.0)

class DetectionCreate(DetectionBase):
    """Detection creation model"""
    explanation: Dict[str, float]
    related_events: List[str] = []
    raw_data: Optional[Dict[str, Any]] = None

class DetectionResultResponse(DetectionBase):
    """Anomaly detection result response model"""
    id: str
    explanation: Dict[str, float]
    related_events: List[str]
    timestamp: float
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    
    class Config:
        orm_mode = True

# Incident models
class IncidentBase(BaseModel):
    """Base incident model"""
    title: str
    description: str
    severity: IncidentSeverity

class IncidentCreate(IncidentBase):
    """Incident creation model"""
    detection_id: Optional[str] = None
    playbook_id: Optional[str] = None
    assets: Optional[List[str]] = None
    tags: Optional[List[str]] = []

class IncidentUpdate(BaseModel):
    """Incident update model"""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution: Optional[str] = None

class IncidentResponse(IncidentBase):
    """Incident response model"""
    id: str
    status: IncidentStatus
    created_at: float
    updated_at: float
    created_by: str
    assigned_to: Optional[str] = None
    detection_id: Optional[str] = None
    playbook_id: Optional[str] = None
    assets: List[str] = []
    tags: List[str] = []
    notes: Optional[str] = None
    resolution: Optional[str] = None
    playbook_execution_id: Optional[str] = None
    
    class Config:
        orm_mode = True

# Playbook models
class PlaybookAction(BaseModel):
    """Playbook action model"""
    id: str
    type: ActionType
    description: str
    command: Optional[str] = None
    script: Optional[str] = None
    api_endpoint: Optional[str] = None
    api_method: Optional[str] = None
    api_payload: Optional[Dict[str, Any]] = None
    template: Optional[str] = None
    channels: Optional[List[str]] = None
    target: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = {}
    continue_on_failure: bool = False
    timeout: Optional[int] = 60  # seconds
    
    @validator('command', 'script')
    def validate_command_injection(cls, v):
        """Prevent basic command injection attempts"""
        if v is not None and any(char in v for char in [';', '&&', '||', '`', '$(',]):
            raise ValueError('Potentially unsafe characters in command')
        return v

class PlaybookBase(BaseModel):
    """Base playbook model"""
    name: str
    description: str
    actions: List[PlaybookAction]
    enabled: bool = True
    execution_mode: str = Field(..., pattern="^(sequential|parallel)$")
    tags: List[str] = []
    target_severity: Optional[List[IncidentSeverity]] = None

class PlaybookCreate(PlaybookBase):
    """Playbook creation model"""
    pass

class PlaybookUpdate(BaseModel):
    """Playbook update model"""
    name: Optional[str] = None
    description: Optional[str] = None
    actions: Optional[List[PlaybookAction]] = None
    enabled: Optional[bool] = None
    execution_mode: Optional[str] = None
    tags: Optional[List[str]] = None
    target_severity: Optional[List[IncidentSeverity]] = None

class PlaybookResponse(PlaybookBase):
    """Playbook response model"""
    id: str
    created_at: float
    updated_at: float
    created_by: str
    execution_count: int = 0
    last_executed: Optional[float] = None
    
    class Config:
        orm_mode = True

# Playbook execution models
class PlaybookExecutionResult(BaseModel):
    """Playbook execution result model"""
    execution_id: str
    playbook_id: str
    incident_id: Optional[str] = None
    start_time: float
    end_time: Optional[float] = None
    status: str
    actions: List[Dict[str, Any]]
    triggered_by: str
    summary: Optional[str] = None

# Dashboard models
class DashboardStats(BaseModel):
    """Dashboard statistics model"""
    total_incidents: int
    open_incidents: int
    critical_incidents: int
    incidents_by_severity: Dict[str, int]
    incidents_by_status: Dict[str, int]
    detections_today: int
    avg_response_time: Optional[float] = None
    playbooks_executed_today: int
