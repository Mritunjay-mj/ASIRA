"""
API data models for ASIRA
Defines Pydantic models for request and response validation

Version: 1.0.0
Last updated: 2025-03-15 16:44:31
Last updated by: Mritunjay-mj
"""

from typing import List, Dict, Any, Optional, Union, Set, Literal
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, EmailStr, Field, validator, AnyHttpUrl, constr
import re
import ipaddress

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

class ExecutionStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    ABORTED = "aborted"

class LogSourceType(str, Enum):
    FILE = "file"
    SYSLOG = "syslog"
    API = "api"
    CLOUD_TRAIL = "cloud_trail"
    WINDOWS_EVENT = "windows_event"
    DATABASE = "database"

class TimelineEntryType(str, Enum):
    STATUS_CHANGE = "status_change"
    ASSIGNMENT = "assignment"
    COMMENT = "comment"
    PLAYBOOK_EXECUTION = "playbook_execution"
    DETECTION = "detection"
    SEVERITY_CHANGE = "severity_change"
    SYSTEM = "system"

class SearchOperator(str, Enum):
    AND = "and"
    OR = "or"

# User models
class UserBase(BaseModel):
    """Base user model"""
    username: constr(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    """User creation model"""
    password: constr(min_length=8)
    role: UserRole = UserRole.ANALYST
    
    @validator('password')
    def password_strength(cls, v):
        """Validate password strength"""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        return v

class UserUpdate(BaseModel):
    """User update model"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[constr(min_length=8)] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    
    @validator('password')
    def password_strength(cls, v):
        """Validate password strength if provided"""
        if v is not None:
            if not re.search(r'[A-Z]', v):
                raise ValueError('Password must contain at least one uppercase letter')
            if not re.search(r'[a-z]', v):
                raise ValueError('Password must contain at least one lowercase letter')
            if not re.search(r'[0-9]', v):
                raise ValueError('Password must contain at least one digit')
        return v

class UserResponse(UserBase):
    """User response model with detailed information"""
    id: str
    role: UserRole
    is_active: bool
    created_at: float
    last_login: Optional[float] = None
    
    class Config:
        orm_mode = True

class UserListResponse(BaseModel):
    """Simplified user model for list responses"""
    id: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: float
    
    class Config:
        orm_mode = True

# Authentication models
class Token(BaseModel):
    """Token response model"""
    access_token: str
    token_type: str
    expires_at: float
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None

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
    source_ip: Optional[str] = None
    source_type: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    asset_id: Optional[str] = None
    event_type: Optional[str] = None
    
    @validator('source_ip', 'destination_ip', each_item=False)
    def validate_ip(cls, v):
        """Validate IP address format"""
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError('Invalid IP address format')
        return v

class DetectionUpdate(BaseModel):
    """Detection update model"""
    anomaly_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    explanation: Optional[Dict[str, float]] = None
    related_events: Optional[List[str]] = None
    acknowledged: Optional[bool] = None
    false_positive: Optional[bool] = None
    notes: Optional[str] = None

class DetectionResultResponse(DetectionBase):
    """Anomaly detection result response model"""
    id: str
    explanation: Dict[str, float]
    related_events: List[str]
    timestamp: float
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    asset_id: Optional[str] = None
    event_type: Optional[str] = None
    
    class Config:
        orm_mode = True

class DetectionDetailResponse(DetectionResultResponse):
    """Detailed anomaly detection result response model"""
    raw_data: Optional[Dict[str, Any]] = None
    false_positive: bool = False
    incident_id: Optional[str] = None
    notes: Optional[str] = None
    related_detections: Optional[List[str]] = None
    source_type: Optional[str] = None
    detection_rule_id: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    
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
    username: Optional[str] = None
    source_ip: Optional[str] = None
    
    @validator('source_ip')
    def validate_ip(cls, v):
        """Validate IP address format"""
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError('Invalid IP address format')
        return v

class IncidentUpdate(BaseModel):
    """Incident update model"""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution: Optional[str] = None
    tags: Optional[List[str]] = None
    assets: Optional[List[str]] = None
    playbook_execution_id: Optional[str] = None

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

class IncidentDetailResponse(IncidentResponse):
    """Detailed incident response model"""
    timeline: List[Dict[str, Any]] = []
    detections: List[str] = []
    playbook_executions: List[str] = []
    related_incidents: List[str] = []
    last_updated_by: Optional[str] = None
    time_to_response: Optional[int] = None  # seconds
    time_to_containment: Optional[int] = None  # seconds
    time_to_resolution: Optional[int] = None  # seconds
    source_ip: Optional[str] = None
    username: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    
    class Config:
        orm_mode = True

class IncidentTimelineEntry(BaseModel):
    """Incident timeline entry model"""
    entry_id: str
    incident_id: str
    timestamp: float
    entry_type: TimelineEntryType
    user: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None

# Playbook models
class PlaybookAction(BaseModel):
    """Playbook action model"""
    id: str
    type: ActionType
    description: str
    command: Optional[str] = None
    script: Optional[str] = None
    api_endpoint: Optional[AnyHttpUrl] = None
    api_method: Optional[str] = None
    api_payload: Optional[Dict[str, Any]] = None
    template: Optional[str] = None
    channels: Optional[List[str]] = None
    target: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = {}
    continue_on_failure: bool = False
    timeout: Optional[int] = Field(60, ge=1, le=3600)  # seconds
    
    @validator('command', 'script')
    def validate_command_injection(cls, v):
        """Prevent basic command injection attempts"""
        if v is not None:
            dangerous_patterns = [';', '&&', '||', '`', '$(', '>', '>>', '|', 'rm -rf']
            for pattern in dangerous_patterns:
                if pattern in v:
                    raise ValueError(f'Potentially unsafe character/pattern in command: {pattern}')
        return v
    
    @validator('api_method')
    def validate_http_method(cls, v):
        """Validate HTTP methods"""
        if v is not None:
            valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
            if v.upper() not in valid_methods:
                raise ValueError(f'Invalid HTTP method: {v}')
            return v.upper()
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
    version: Optional[str] = "1.0.0"
    author: Optional[str] = None

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
    version: Optional[str] = None

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

class PlaybookListResponse(BaseModel):
    """Simplified playbook model for list responses"""
    id: str
    name: str
    description: str
    enabled: bool
    execution_mode: str
    tags: List[str]
    target_severity: Optional[List[IncidentSeverity]] = None
    execution_count: int
    last_executed: Optional[float] = None
    created_at: float
    
    class Config:
        orm_mode = True

# Playbook execution models
class ActionResult(BaseModel):
    """Action execution result model"""
    action_id: str
    status: str
    output: Optional[str] = None
    error: Optional[str] = None
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    artifacts: Optional[List[Dict[str, Any]]] = None

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

class PlaybookExecutionDetailResponse(PlaybookExecutionResult):
    """Detailed playbook execution result model"""
    duration_seconds: Optional[float] = None
    playbook_name: Optional[str] = None
    playbook_version: Optional[str] = None
    environment: Optional[Dict[str, Any]] = None
    input_parameters: Optional[Dict[str, Any]] = None
    artifacts: Optional[List[Dict[str, Any]]] = None
    logs: Optional[List[Dict[str, Any]]] = None
    success_rate: Optional[float] = None
    
    class Config:
        orm_mode = True

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
    last_updated: Optional[str] = None
    last_updated_by: Optional[str] = None

# Search models
class SearchCriteria(BaseModel):
    """Search criteria model"""
    field: str
    value: Any
    operation: str = "eq"  # eq, neq, gt, lt, contains, startswith

class SearchQuery(BaseModel):
    """Search query model"""
    criteria: List[SearchCriteria]
    operator: SearchOperator = SearchOperator.AND
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)

# Bulk operation models
class BulkActionRequest(BaseModel):
    """Bulk action request model"""
    ids: List[str]
    action: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

# Log source configuration models
class LogSourceConfig(BaseModel):
    """Log source configuration model"""
    name: str
    source_type: LogSourceType
    description: Optional[str] = None
    path: Optional[str] = None  # File path or URL
    credentials_id: Optional[str] = None
    polling_interval: Optional[int] = 300  # seconds
    format: Optional[str] = None  # json, csv, syslog, etc.
    parser_config: Optional[Dict[str, Any]] = None
    enabled: bool = True
    normalizer_config: Optional[Dict[str, Any]] = None
    
    @validator('path')
    def validate_path(cls, v, values):
        """Validate path based on source type"""
        if v is not None and 'source_type' in values:
            source_type = values['source_type']
            if source_type == LogSourceType.FILE:
                # Check for path traversal attempts
                if '..' in v or v.startswith('/etc') or v.startswith('/var/log/secure'):
                    raise ValueError('Path contains potentially unsafe patterns')
            elif source_type == LogSourceType.API:
                # Validate URL format
                if not (v.startswith('http://') or v.startswith('https://')):
                    raise ValueError('API source must have an http/https URL')
        return v

# System configuration models
class SystemConfig(BaseModel):
    """System configuration model"""
    api_port: int = Field(8000, ge=1, le=65535)
    log_level: str = "INFO"
    debug_mode: bool = False
    db_connection_string: Optional[str] = None
    cors_origins: List[str] = ["*"]
    token_expire_minutes: int = Field(1440, ge=1)  # 24 hours
    detection_config: Dict[str, Any] = {}

# Email notification templates
class EmailTemplate(BaseModel):
    """Email notification template model"""
    id: Optional[str] = None
    name: str
    subject: str
    body: str
    variables: List[str] = []
    description: Optional[str] = None
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    created_by: Optional[str] = None

# Detection rule models
class DetectionRule(BaseModel):
    """Detection rule model for custom detection logic"""
    id: Optional[str] = None
    name: str
    description: str
    enabled: bool = True
    rule_type: str  # ml, threshold, signature, correlation
    logic: str  # Rule logic expression or code
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    tags: List[str] = []
    target_log_sources: List[str] = []
    parameters: Dict[str, Any] = {}
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    created_by: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    
    class Config:
        orm_mode = True

# Report models
class ReportTemplate(BaseModel):
    """Report template model"""
    id: Optional[str] = None
    name: str
    description: str
    report_type: str  # incident, detection, playbook, system
    template: Dict[str, Any]
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    created_by: Optional[str] = None
    
    class Config:
        orm_mode = True

class ReportSchedule(BaseModel):
    """Report schedule model"""
    id: Optional[str] = None
    template_id: str
    name: str
    schedule: str  # cron expression
    recipients: List[str]
    parameters: Dict[str, Any] = {}
    enabled: bool = True
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    created_by: Optional[str] = None
    
    class Config:
        orm_mode = True

# Integration models
class IntegrationType(str, Enum):
    SIEM = "siem"
    TICKETING = "ticketing"
    CHAT = "chat"
    EMAIL = "email"
    EDR = "edr"
    SOAR = "soar"
    THREAT_INTEL = "threat_intel"
    CUSTOM = "custom"

class IntegrationConfig(BaseModel):
    """Integration configuration model"""
    id: Optional[str] = None
    name: str
    integration_type: IntegrationType
    description: Optional[str] = None
    config: Dict[str, Any]
    enabled: bool = True
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    created_by: Optional[str] = None
    
    class Config:
        orm_mode = True

# Audit log model
class AuditLogEntry(BaseModel):
    """Audit log entry model"""
    id: Optional[str] = None
    timestamp: float
    user: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    success: bool = True
    
    class Config:
        orm_mode = True

# API key model
class ApiKey(BaseModel):
    """API key model"""
    id: Optional[str] = None
    name: str
    prefix: str
    hashed_key: str
    created_by: str
    created_at: float
    expires_at: Optional[float] = None
    last_used_at: Optional[float] = None
    permissions: List[str] = []
    is_active: bool = True
    
    class Config:
        orm_mode = True

class ApiKeyCreate(BaseModel):
    """API key creation model"""
    name: str
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)
    permissions: List[str] = []

class ApiKeyResponse(BaseModel):
    """API key response model"""
    id: str
    name: str
    key: str  # Full key, only returned once at creation
    prefix: str
    created_at: float
    expires_at: Optional[float] = None
    permissions: List[str] = []
    
    class Config:
        orm_mode = True

# System backup model
class BackupConfig(BaseModel):
    """System backup configuration"""
    id: Optional[str] = None
    location: str
    schedule: str  # cron expression
    retention_days: int = Field(30, ge=1, le=365)
    include_logs: bool = True
    include_incidents: bool = True
    include_detections: bool = True
    include_playbooks: bool = True
    encryption_enabled: bool = True
    last_backup_time: Optional[float] = None
    last_backup_status: Optional[str] = None
    
    class Config:
        orm_mode = True

# Models for bulk operations and analytics
class DateRange(BaseModel):
    """Date range model for analytics queries"""
    start_date: float  # Unix timestamp
    end_date: float  # Unix timestamp
    
    @validator('end_date')
    def end_date_after_start_date(cls, v, values):
        if 'start_date' in values and v < values['start_date']:
            raise ValueError('end_date must be after start_date')
        return v

class AnalyticsQuery(BaseModel):
    """Analytics query model"""
    metric: str  # incidents, detections, response_time, etc.
    date_range: DateRange
    group_by: Optional[str] = None  # severity, status, day, week, month, etc.
    filters: Dict[str, Any] = {}
    limit: int = Field(100, ge=1, le=10000)

class AnalyticsResponse(BaseModel):
    """Analytics response model"""
    metric: str
    date_range: DateRange
    results: List[Dict[str, Any]]
    aggregates: Dict[str, Any] = {}
    generated_at: float = Field(default_factory=lambda: datetime.utcnow().timestamp())
    query_time_ms: float

# Model version information
class ModelVersion(BaseModel):
    """Model version information for the API documentation"""
    version: str = "1.0.0"
    last_updated: str = "2025-03-15 16:46:23"
    last_updated_by: str = "Rahul"
