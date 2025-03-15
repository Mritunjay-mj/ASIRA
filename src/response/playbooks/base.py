"""
ASIRA Response Playbooks Base Module
Defines the base classes and interfaces for security response playbooks

Playbooks define automated response actions that can be executed 
in response to security incidents. This module provides the foundational
structures for defining, validating, and executing playbooks.

Version: 1.0.0
Last updated: 2025-03-15 12:18:25
Last updated by: Mritunjay-mj
"""

import os
import time
import datetime
import logging
import uuid
from enum import Enum, auto
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field, asdict

# Initialize logger
logger = logging.getLogger("asira.response.playbooks")

class ActionType(str, Enum):
    """Types of actions that can be executed in a playbook."""
    COMMAND = "command"         # Execute a system command
    API_CALL = "api_call"       # Make an API call to another system
    SCRIPT = "script"           # Run a script (Python, PowerShell, etc.)
    NOTIFICATION = "notification"  # Send a notification
    CONTAINMENT = "containment"   # Isolate/quarantine a resource
    ENRICHMENT = "enrichment"    # Gather additional information


class ActionStatus(str, Enum):
    """Status of a response action during or after execution."""
    PENDING = "pending"        # Action has not started yet
    IN_PROGRESS = "in_progress"  # Action is currently executing
    COMPLETED = "completed"     # Action completed successfully
    FAILED = "failed"          # Action failed to execute properly
    SKIPPED = "skipped"        # Action was skipped


class TriggerType(str, Enum):
    """Types of triggers that can initiate a playbook."""
    MANUAL = "manual"           # Manually triggered by a user
    DETECTION = "detection"      # Triggered by a detection alert
    SCHEDULED = "scheduled"      # Triggered on a schedule
    EVENT = "event"            # Triggered by a system event
    API = "api"               # Triggered via API call


@dataclass
class ActionDefinition:
    """
    Defines a single action within a playbook.
    Actions are the executable units of a playbook.
    """
    id: str
    type: str
    description: str
    
    # Command-specific fields
    command: Optional[str] = None
    
    # API-specific fields
    api_endpoint: Optional[str] = None
    api_method: Optional[str] = None
    api_payload: Optional[Dict[str, Any]] = None
    
    # Script-specific fields
    script: Optional[str] = None
    
    # Notification-specific fields
    template: Optional[str] = None
    channels: Optional[List[str]] = None
    
    # General fields
    target: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    continue_on_failure: bool = False
    timeout: int = 60  # seconds
    
    def validate(self) -> bool:
        """
        Validate that the action is properly configured
        
        Returns:
            True if valid, False otherwise
        """
        # Check required fields
        if not self.id or not self.type or not self.description:
            logger.error(f"Action missing required fields: {self.id}")
            return False
        
        # Validate based on type
        if self.type == ActionType.COMMAND and not self.command:
            logger.error(f"Command action {self.id} missing command field")
            return False
            
        if self.type == ActionType.API_CALL and (not self.api_endpoint or not self.api_method):
            logger.error(f"API action {self.id} missing endpoint or method")
            return False
            
        if self.type == ActionType.SCRIPT and not self.script:
            logger.error(f"Script action {self.id} missing script field")
            return False
            
        if self.type == ActionType.NOTIFICATION and (not self.template or not self.channels):
            logger.error(f"Notification action {self.id} missing template or channels")
            return False
            
        # Check for command injection vulnerabilities in commands
        if self.command and any(char in self.command for char in [';', '&&', '||', '`', '$(']):
            logger.error(f"Command action {self.id} contains potentially unsafe characters")
            return False
            
        return True


@dataclass
class ActionResult:
    """
    Results of executing an action within a playbook.
    Captures execution details, output, and artifacts.
    """
    action_id: str
    status: ActionStatus
    output: Optional[str] = None
    error: Optional[str] = None
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None
    artifacts: List[Dict] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize default values if not provided"""
        if self.start_time is None:
            self.start_time = datetime.datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation
        
        Returns:
            Dictionary representation of the action result
        """
        result = asdict(self)
        
        # Convert datetime objects to ISO format strings
        if self.start_time:
            result["start_time"] = self.start_time.isoformat()
        if self.end_time:
            result["end_time"] = self.end_time.isoformat()
            
        # Convert enum to string
        result["status"] = self.status.value
        
        return result
    
    def add_artifact(self, name: str, description: str, value: Any, artifact_type: str = "data"):
        """
        Add an artifact to the action result
        
        Args:
            name: Name of the artifact
            description: Description of the artifact
            value: Value of the artifact
            artifact_type: Type of artifact (data, file, url, etc.)
        """
        self.artifacts.append({
            "name": name,
            "description": description,
            "value": value,
            "type": artifact_type,
            "timestamp": datetime.datetime.now().isoformat()
        })


@dataclass
class PlaybookDefinition:
    """
    Defines a complete response playbook.
    A playbook is a sequence of actions to be executed in response to a security incident.
    """
    id: str
    name: str
    description: str
    actions: List[ActionDefinition]
    execution_mode: str = "sequential"  # sequential or parallel
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    target_severity: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    author: str = "ASIRA"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    def validate(self) -> bool:
        """
        Validate that the playbook is properly configured
        
        Returns:
            True if valid, False otherwise
        """
        # Check required fields
        if not self.id or not self.name or not self.description:
            logger.error(f"Playbook missing required fields: {self.id}")
            return False
        
        # Check execution mode
        if self.execution_mode not in ["sequential", "parallel"]:
            logger.error(f"Invalid execution mode for playbook {self.id}: {self.execution_mode}")
            return False
        
        # Validate all actions
        for action in self.actions:
            if not action.validate():
                logger.error(f"Invalid action in playbook {self.id}: {action.id}")
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation
        
        Returns:
            Dictionary representation of the playbook definition
        """
        result = asdict(self)
        return result
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'PlaybookDefinition':
        """
        Create a playbook definition from a dictionary
        
        Args:
            data: Dictionary representation of the playbook
            
        Returns:
            PlaybookDefinition object
        """
        actions = []
        for action_data in data.get("actions", []):
            action = ActionDefinition(
                id=action_data.get("id", ""),
                type=action_data.get("type", "command"),
                description=action_data.get("description", ""),
                command=action_data.get("command"),
                api_endpoint=action_data.get("api_endpoint"),
                api_method=action_data.get("api_method"),
                api_payload=action_data.get("api_payload"),
                script=action_data.get("script"),
                template=action_data.get("template"),
                channels=action_data.get("channels"),
                target=action_data.get("target"),
                parameters=action_data.get("parameters", {}),
                continue_on_failure=action_data.get("continue_on_failure", False),
                timeout=action_data.get("timeout", 60)
            )
            actions.append(action)
        
        return PlaybookDefinition(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            actions=actions,
            execution_mode=data.get("execution_mode", "sequential"),
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
            target_severity=data.get("target_severity", []),
            version=data.get("version", "1.0.0"),
            author=data.get("author", "ASIRA"),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time())
        )


@dataclass
class PlaybookExecution:
    """
    Represents a single execution of a playbook.
    Tracks execution details, results, and metadata.
    """
    execution_id: str
    playbook_id: str
    trigger_type: TriggerType
    trigger_details: Dict[str, Any]
    start_time: datetime.datetime
    status: str = "in_progress"
    action_results: List[ActionResult] = field(default_factory=list)
    end_time: Optional[datetime.datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation
        
        Returns:
            Dictionary representation of the playbook execution
        """
        result = asdict(self)
        
        # Convert datetime objects to ISO format strings
        result["start_time"] = self.start_time.isoformat()
        if self.end_time:
            result["end_time"] = self.end_time.isoformat()
        
        # Convert action results
        result["action_results"] = [ar.to_dict() for ar in self.action_results]
        
        # Convert enum to string
        result["trigger_type"] = self.trigger_type.value
        
        return result


class PlaybookRegistry:
    """
    Registry for managing and retrieving playbooks.
    Provides lookup capabilities by ID, tags, and other attributes.
    """
    
    def __init__(self, playbook_dir: str = None):
        """
        Initialize the playbook registry
        
        Args:
            playbook_dir: Directory containing playbook definition files
        """
        self.playbooks: Dict[str, PlaybookDefinition] = {}
        self.playbook_dir = playbook_dir or os.environ.get("ASIRA_PLAYBOOK_DIR", "/etc/asira/playbooks")
        
        # Create playbook directory if it doesn't exist
        os.makedirs(self.playbook_dir, exist_ok=True)
    
    def load_playbooks(self):
        """
        Load all playbooks from the playbook directory
        """
        import yaml
        
        logger.info(f"Loading playbooks from {self.playbook_dir}")
        
        if not os.path.exists(self.playbook_dir):
            logger.warning(f"Playbook directory not found: {self.playbook_dir}")
            return
        
        # Get all YAML files
        for filename in os.listdir(self.playbook_dir):
            if filename.endswith((".yml", ".yaml")):
                file_path = os.path.join(self.playbook_dir, filename)
                
                try:
                    with open(file_path, "r") as f:
                        playbook_data = yaml.safe_load(f)
                        
                    playbook = PlaybookDefinition.from_dict(playbook_data)
                    
                    if playbook.validate():
                        self.playbooks[playbook.id] = playbook
                        logger.info(f"Loaded playbook: {playbook.id}")
                    else:
                        logger.error(f"Invalid playbook in {filename}")
                        
                except Exception as e:
                    logger.error(f"Error loading playbook from {filename}: {e}")
    
    def get_playbook(self, playbook_id: str) -> Optional[PlaybookDefinition]:
        """
        Get a playbook by ID
        
        Args:
            playbook_id: ID of the playbook
            
        Returns:
            PlaybookDefinition if found, None otherwise
        """
        return self.playbooks.get(playbook_id)
    
    def find_playbooks(
        self,
        tags: Optional[List[str]] = None,
        severity: Optional[str] = None,
        enabled_only: bool = True
    ) -> List[PlaybookDefinition]:
        """
        Find playbooks matching the specified criteria
        
        Args:
            tags: List of tags to match
            severity: Severity level to match
            enabled_only: Only return enabled playbooks
            
        Returns:
            List of matching playbooks
        """
        results = []
        
        for playbook in self.playbooks.values():
            # Filter by enabled status
            if enabled_only and not playbook.enabled:
                continue
                
            # Filter by tags
            if tags and not any(tag in playbook.tags for tag in tags):
                continue
                
            # Filter by severity
            if severity and severity not in playbook.target_severity:
                continue
                
            results.append(playbook)
            
        return results
    
    def add_playbook(self, playbook: PlaybookDefinition) -> bool:
        """
        Add a playbook to the registry
        
        Args:
            playbook: Playbook to add
            
        Returns:
            True if added successfully, False otherwise
        """
        if not playbook.validate():
            logger.error(f"Cannot add invalid playbook: {playbook.id}")
            return False
            
        self.playbooks[playbook.id] = playbook
        
        # Save to file
        self._save_playbook_to_file(playbook)
        
        logger.info(f"Added playbook: {playbook.id}")
        return True
    
    def update_playbook(self, playbook: PlaybookDefinition) -> bool:
        """
        Update an existing playbook
        
        Args:
            playbook: Updated playbook
            
        Returns:
            True if updated successfully, False otherwise
        """
        if not playbook.validate():
            logger.error(f"Cannot update with invalid playbook: {playbook.id}")
            return False
            
        if playbook.id not in self.playbooks:
            logger.error(f"Playbook not found for update: {playbook.id}")
            return False
            
        # Update timestamp
        playbook.updated_at = time.time()
        
        self.playbooks[playbook.id] = playbook
        
        # Save to file
        self._save_playbook_to_file(playbook)
        
        logger.info(f"Updated playbook: {playbook.id}")
        return True
    
    def remove_playbook(self, playbook_id: str) -> bool:
        """
        Remove a playbook from the registry
        
        Args:
            playbook_id: ID of the playbook to remove
            
        Returns:
            True if removed successfully, False otherwise
        """
        if playbook_id not in self.playbooks:
            logger.error(f"Playbook not found for removal: {playbook_id}")
            return False
            
        del self.playbooks[playbook_id]
        
        # Remove file
        file_path = os.path.join(self.playbook_dir, f"{playbook_id}.yml")
        if os.path.exists(file_path):
            os.remove(file_path)
            
        logger.info(f"Removed playbook: {playbook_id}")
        return True
    
    def _save_playbook_to_file(self, playbook: PlaybookDefinition) -> bool:
        """
        Save a playbook to a YAML file
        
        Args:
            playbook: Playbook to save
            
        Returns:
            True if saved successfully, False otherwise
        """
        import yaml
        
        file_path = os.path.join(self.playbook_dir, f"{playbook.id}.yml")
        
        try:
            with open(file_path, "w") as f:
                yaml.dump(playbook.to_dict(), f, default_flow_style=False)
                
            return True
        except Exception as e:
            logger.error(f"Error saving playbook {playbook.id} to file: {e}")
            return False


# Initialize registry as a singleton
registry = PlaybookRegistry()
