"""
ASIRA Response Playbooks Base Module
Defines the base classes and interfaces for security response playbooks

Playbooks define automated response actions that can be executed 
in response to security incidents. This module provides the foundational
structures for defining, validating, and executing playbooks.

Version: 1.0.0
Last updated: 2025-03-15 19:15:22
Last updated by: Rahul
"""

import os
import time
import datetime
import logging
import uuid
from enum import Enum, auto
from typing import List, Dict, Any, Optional, Union, Set, Callable
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


class PlaybookAccessLevel(str, Enum):
    """Access control levels for playbooks."""
    PUBLIC = "public"          # Can be executed by anyone
    ANALYST = "analyst"         # Requires analyst privileges
    ADMIN = "admin"           # Requires admin privileges
    AUTOMATED = "automated"      # Can only be executed by automation


class PlaybookExecutionState(str, Enum):
    """Execution states for a playbook."""
    PENDING = "pending"         # Execution not yet started
    RUNNING = "running"         # Execution in progress
    COMPLETED = "completed"      # Execution completed successfully
    FAILED = "failed"          # Execution failed
    CANCELED = "canceled"       # Execution was manually canceled
    TIMED_OUT = "timed_out"      # Execution timed out


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
    depends_on: List[str] = field(default_factory=list)  # Dependencies on other actions
    condition: Optional[str] = None  # Condition to execute this action
    
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
    details: Dict[str, Any] = field(default_factory=dict)  # Additional execution details
    
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
    
    def get_duration(self) -> float:
        """
        Get the duration of the action execution in seconds
        
        Returns:
            Duration in seconds, or 0 if not completed
        """
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


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
    timeout: int = 3600  # Global timeout in seconds (default 1 hour)
    max_retries: int = 0  # Maximum retries for failed actions
    access_level: PlaybookAccessLevel = PlaybookAccessLevel.ANALYST  # Access control
    documentation: Optional[str] = None  # Extended documentation
    test_scenario: Optional[Dict[str, Any]] = None  # Test scenario
    
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
        
        # Validate dependencies
        action_ids = {action.id for action in self.actions}
        for action in self.actions:
            for dep in action.depends_on:
                if dep not in action_ids:
                    logger.error(f"Action {action.id} depends on non-existent action {dep}")
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
                timeout=action_data.get("timeout", 60),
                depends_on=action_data.get("depends_on", []),
                condition=action_data.get("condition")
            )
            actions.append(action)
        
        # Handle access_level string to enum conversion
        access_level = data.get("access_level", "analyst")
        if isinstance(access_level, str):
            try:
                access_level = PlaybookAccessLevel(access_level)
            except ValueError:
                access_level = PlaybookAccessLevel.ANALYST
        
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
            updated_at=data.get("updated_at", time.time()),
            timeout=data.get("timeout", 3600),
            max_retries=data.get("max_retries", 0),
            access_level=access_level,
            documentation=data.get("documentation"),
            test_scenario=data.get("test_scenario")
        )
    
    def get_action_by_id(self, action_id: str) -> Optional[ActionDefinition]:
        """
        Get an action by ID
        
        Args:
            action_id: ID of the action to retrieve
            
        Returns:
            ActionDefinition if found, None otherwise
        """
        for action in self.actions:
            if action.id == action_id:
                return action
        return None
    
    def get_dependency_graph(self) -> Dict[str, Set[str]]:
        """
        Get a dependency graph for the actions in this playbook
        
        Returns:
            Dictionary mapping action IDs to sets of action IDs they depend on
        """
        graph = {}
        for action in self.actions:
            graph[action.id] = set(action.depends_on)
        return graph
    
    def generate_execution_plan(self) -> List[List[str]]:
        """
        Generate an execution plan that respects dependencies
        
        Returns:
            List of action ID groups, where each group can be executed in parallel
        """
        if self.execution_mode == "parallel":
            # For parallel mode, just check for circular dependencies
            graph = self.get_dependency_graph()
            visited = set()
            temp = set()
            
            def has_cycle(node, graph, visited, temp):
                visited.add(node)
                temp.add(node)
                
                for neighbor in graph.get(node, set()):
                    if neighbor not in visited:
                        if has_cycle(neighbor, graph, visited, temp):
                            return True
                    elif neighbor in temp:
                        return True
                
                temp.remove(node)
                return False
            
            # Check for cycles
            for node in graph:
                if node not in visited:
                    if has_cycle(node, graph, visited, temp):
                        logger.error(f"Circular dependency detected in playbook {self.id}")
                        return []
            
            # If no cycles, we can execute all actions in parallel
            return [list(graph.keys())]
        else:
            # For sequential mode, create a topological sort
            graph = self.get_dependency_graph()
            visited = set()
            temp = set()
            order = []
            
            def topological_sort(node, graph, visited, temp, order):
                visited.add(node)
                temp.add(node)
                
                for neighbor in graph.get(node, set()):
                    if neighbor not in visited:
                        if topological_sort(neighbor, graph, visited, temp, order):
                            return True
                    elif neighbor in temp:
                        return True
                
                temp.remove(node)
                order.append(node)
                return False
            
            # Perform topological sort
            for node in graph:
                if node not in visited:
                    if topological_sort(node, graph, visited, temp, order):
                        logger.error(f"Circular dependency detected in playbook {self.id}")
                        return []
            
            # Reverse to get correct order
            order.reverse()
            
            # Group independent actions together
            plan = []
            while order:
                group = []
                i = 0
                while i < len(order):
                    can_execute = True
                    for dep in graph.get(order[i], set()):
                        if dep in order:
                            can_execute = False
                            break
                    
                    if can_execute:
                        group.append(order.pop(i))
                    else:
                        i += 1
                
                if group:
                    plan.append(group)
                else:
                    # Should never happen if there are no cycles
                    logger.error(f"Could not generate execution plan for playbook {self.id}")
                    return []
            
            return plan


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
    status: PlaybookExecutionState = PlaybookExecutionState.PENDING
    action_results: Dict[str, ActionResult] = field(default_factory=dict)
    end_time: Optional[datetime.datetime] = None
    executed_by: str = "system"
    execution_context: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
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
        result["action_results"] = {
            action_id: ar.to_dict() for action_id, ar in self.action_results.items()
        }
        
        # Convert enums to strings
        result["status"] = self.status.value
        result["trigger_type"] = self.trigger_type.value
        
        return result
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'PlaybookExecution':
        """
        Create a playbook execution from a dictionary
        
        Args:
            data: Dictionary representation of the playbook execution
            
        Returns:
            PlaybookExecution object
        """
        # Parse datetime strings
        start_time = datetime.datetime.fromisoformat(data["start_time"])
        end_time = None
        if data.get("end_time"):
            end_time = datetime.datetime.fromisoformat(data["end_time"])
        
        # Parse action results
        action_results = {}
        for action_id, result_data in data.get("action_results", {}).items():
            status = ActionStatus(result_data["status"])
            
            # Parse timestamps
            ar_start_time = None
            if result_data.get("start_time"):
                ar_start_time = datetime.datetime.fromisoformat(result_data["start_time"])
                
            ar_end_time = None
            if result_data.get("end_time"):
                ar_end_time = datetime.datetime.fromisoformat(result_data["end_time"])
                
            action_result = ActionResult(
                action_id=action_id,
                status=status,
                output=result_data.get("output"),
                error=result_data.get("error"),
                start_time=ar_start_time,
                end_time=ar_end_time,
                artifacts=result_data.get("artifacts", []),
                details=result_data.get("details", {})
            )
            
            action_results[action_id] = action_result
        
        # Parse status
        status = PlaybookExecutionState(data["status"])
        
        # Parse trigger type
        trigger_type = TriggerType(data["trigger_type"])
        
        return PlaybookExecution(
            execution_id=data["execution_id"],
            playbook_id=data["playbook_id"],
            trigger_type=trigger_type,
            trigger_details=data.get("trigger_details", {}),
            start_time=start_time,
            status=status,
            action_results=action_results,
            end_time=end_time,
            executed_by=data.get("executed_by", "system"),
            execution_context=data.get("execution_context", {}),
            metrics=data.get("metrics", {})
        )
    
    def add_action_result(self, result: ActionResult) -> None:
        """
        Add an action result to this execution
        
        Args:
            result: Action result to add
        """
        self.action_results[result.action_id] = result
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the execution
        
        Returns:
            Dictionary with execution summary data
        """
        # Count actions by status
        status_counts = {status.value: 0 for status in ActionStatus}
        for result in self.action_results.values():
            status_counts[result.status.value] += 1
        
        # Calculate total duration
        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        return {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "status": self.status.value,
            "trigger_type": self.trigger_type.value,
            "executed_by": self.executed_by,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration,
            "action_counts": status_counts,
            "total_actions": len(self.action_results)
        }
    
    def calculate_metrics(self) -> Dict[str, Any]:
        """
        Calculate performance metrics for this execution
        
        Returns:
            Dictionary with performance metrics
        """
        metrics = {}
        
        # Total duration
        if self.start_time and self.end_time:
            metrics["total_duration_seconds"] = (self.end_time - self.start_time).total_seconds()
        
        # Action durations
        action_durations = {}
        for action_id, result in self.action_results.items():
            if result.start_time and result.end_time:
                action_durations[action_id] = (result.end_time - result.start_time).total_seconds()
        
        metrics["action_durations"] = action_durations
        
        if action_durations:
            metrics["avg_action_duration"] = sum(action_durations.values()) / len(action_durations)
            metrics["max_action_duration"] = max(action_durations.values())
            metrics["min_action_duration"] = min(action_durations.values())
        
        # Count by status
        status_counts = {status.value: 0 for status in ActionStatus}
        for result in self.action_results.values():
            status_counts[result.status.value] += 1
        
        metrics["action_status_counts"] = status_counts
        
        # Success rate
        total_actions = len(self.action_results)
        if total_actions > 0:
            success_rate = (status_counts["completed"] / total_actions) * 100
            metrics["success_rate_percent"] = success_rate
        
        self.metrics = metrics
        return metrics


class ExecutionContext:
    """
    Context for playbook execution.
    Manages variables, state, and context sharing between actions.
    """
    
    def __init__(self, initial_data: Dict[str, Any] = None):
        """
        Initialize the execution context
        
        Args:
            initial_data: Initial data for the context
        """
        self.data = initial_data or {}
        self.variables = {}
        self.sensitive_keys = set()  # Keys containing sensitive data
        
    def set_variable(self, key: str, value: Any, sensitive: bool = False) -> None:
        """
        Set a variable in the context
        
        Args:
            key: Variable name
            value: Variable value
            sensitive: Whether the variable contains sensitive data
        """
        self.variables[key] = value
        if sensitive:
            self.sensitive_keys.add(key)
            
    def get_variable(self, key: str, default: Any = None) -> Any:
        """
        Get a variable from the context
        
        Args:
            key: Variable name
            default: Default value to return if not found
            
        Returns:
            Variable value or default
        """
        return self.variables.get(key, default)
    
    def update_data(self, data: Dict[str, Any]) -> None:
        """
        Update the context data
        
        Args:
            data: New data to add
        """
        self.data.update(data)
        
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary representation
        
        Args:
            include_sensitive: Whether to include sensitive data
            
        Returns:
            Dictionary representation of the context
        """
        result = {
            "data": self.data,
            "variables": {}
        }
        
        # Include variables, masking sensitive ones if needed
        for key, value in self.variables.items():
            if key in self.sensitive_keys and not include_sensitive:
                result["variables"][key] = "***REDACTED***"
            else:
                result["variables"][key] = value
                
        return result
    
    def evaluate_condition(self, condition: str) -> bool:
        """
        Evaluate a condition in the context of the current variables
        
        Args:
            condition: Condition string to evaluate
            
        Returns:
            Result of evaluation (True or False)
        """
        if not condition:
            return True
            
        try:
            # Create a safe evaluation context
            eval_context = {}
            eval_context.update(self.variables)
            eval_context.update(self.data)
            
            # Sanitsed environment for evaluation
            allowed_names = {
                'True': True, 
                'False': False, 
                'None': None,
                'bool': bool,
                'int': int,
                'str': str,
                'len': len
            }
            eval_context.update(allowed_names)
            
            # Evaluate the condition
            return bool(eval(condition, {"__builtins__": {}}, eval_context))
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {e}")
            return False


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
        
        # Store execution history
        self.execution_history: Dict[str, PlaybookExecution] = {}
        
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
        enabled_only: bool = True,
        access_level: Optional[PlaybookAccessLevel] = None
    ) -> List[PlaybookDefinition]:
        """
        Find playbooks matching the specified criteria
        
        Args:
            tags: List of tags to match
            severity: Severity level to match
            enabled_only: Only return enabled playbooks
            access_level: Minimum access level required
            
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
                
            # Filter by access level
            if access_level and access_level.value < playbook.access_level.value:
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
    
    def record_execution(self, execution: PlaybookExecution) -> None:
        """
        Record a playbook execution in the execution history
        
        Args:
            execution: Playbook execution to record
        """
        self.execution_history[execution.execution_id] = execution
        
        # Save execution record to disk
        self._save_execution_to_file(execution)
    
    def _save_execution_to_file(self, execution: PlaybookExecution) -> bool:
        """
        Save an execution record to a JSON file
        
        Args:
            execution: Execution to save
            
        Returns:
            True if saved successfully, False otherwise
        """
        import json
        
        # Create executions directory if it doesn't exist
        executions_dir = os.path.join(self.playbook_dir, "executions")
        os.makedirs(executions_dir, exist_ok=True)
        
        # Create directory for this playbook's executions
        playbook_executions_dir = os.path.join(executions_dir, execution.playbook_id)
        os.makedirs(playbook_executions_dir, exist_ok=True)
        
        # Save execution record
        file_path = os.path.join(playbook_executions_dir, f"{execution.execution_id}.json")
        
        try:
            with open(file_path, "w") as f:
                json.dump(execution.to_dict(), f, indent=2)
                
            return True
        except Exception as e:
            logger.error(f"Error saving execution {execution.execution_id} to file: {e}")
            return False
    
    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        """
        Get an execution record by ID
        
        Args:
            execution_id: ID of the execution to retrieve
            
        Returns:
            PlaybookExecution if found, None otherwise
        """
        # Check in-memory cache first
        if execution_id in self.execution_history:
            return self.execution_history[execution_id]
            
        # Try to load from disk
        import json
        
        # We don't know which playbook this execution is for, so we need to search all playbook execution dirs
        executions_dir = os.path.join(self.playbook_dir, "executions")
        if not os.path.exists(executions_dir):
            return None
            
        for playbook_id in os.listdir(executions_dir):
            playbook_executions_dir = os.path.join(executions_dir, playbook_id)
            if not os.path.isdir(playbook_executions_dir):
                continue
                
            file_path = os.path.join(playbook_executions_dir, f"{execution_id}.json")
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r") as f:
                        execution_data = json.load(f)
                        
                    execution = PlaybookExecution.from_dict(execution_data)
                    
                    # Cache in memory
                    self.execution_history[execution_id] = execution
                    
                    return execution
                except Exception as e:
                    logger.error(f"Error loading execution {execution_id} from file: {e}")
                    return None
        
        return None
    
    def get_playbook_executions(self, playbook_id: str, limit: int = 10) -> List[PlaybookExecution]:
        """
        Get recent executions of a playbook
        
        Args:
            playbook_id: ID of the playbook
            limit: Maximum number of executions to return
            
        Returns:
            List of recent executions
        """
        import json
        
        # Check if playbook exists
        if playbook_id not in self.playbooks:
            logger.error(f"Playbook not found: {playbook_id}")
            return []
            
        # Get executions from disk
        executions_dir = os.path.join(self.playbook_dir, "executions")
        playbook_executions_dir = os.path.join(executions_dir, playbook_id)
        
        if not os.path.exists(playbook_executions_dir):
            return []
            
        executions = []
        
        # Get all execution files
        execution_files = []
        for filename in os.listdir(playbook_executions_dir):
            if filename.endswith(".json"):
                file_path = os.path.join(playbook_executions_dir, filename)
                file_info = os.stat(file_path)
                execution_files.append((file_path, file_info.st_mtime))
        
        # Sort by modification time (newest first)
        execution_files.sort(key=lambda x: x[1], reverse=True)
        
        # Load executions
        for file_path, _ in execution_files[:limit]:
            try:
                with open(file_path, "r") as f:
                    execution_data = json.load(f)
                    
                execution = PlaybookExecution.from_dict(execution_data)
                
                # Cache in memory
                self.execution_history[execution.execution_id] = execution
                
                executions.append(execution)
            except Exception as e:
                logger.error(f"Error loading execution from {file_path}: {e}")
        
        return executions


# Initialize registry as a singleton
registry = PlaybookRegistry()

# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 19:18:17"
__author__ = "Rahul"
