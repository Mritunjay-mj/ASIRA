"""
ASIRA Response Executor
Handles secure execution of playbooks in response to security incidents

The executor manages the secure execution environment, credentials handling,
action verification, and result documentation for response playbooks.

Version: 1.0.0
Last updated: 2025-03-15 19:08:19
Last updated by: Mritunjay-mj
"""

import os
import uuid
import json
import yaml
import logging
import subprocess
import datetime
import time
import tempfile
import shutil
import threading
import requests
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
from pathlib import Path
import jinja2

from src.common.config import Settings
from src.response.playbooks.base import PlaybookDefinition, ActionResult, ActionStatus, ActionType

# Initialize logger
logger = logging.getLogger("asira.response.executor")

# Initialize settings
settings = Settings()

class ExecutionEnvironment(Enum):
    """Types of execution environments for running actions."""
    DIRECT = "direct"       # Execute directly in the main process
    SUBPROCESS = "subprocess"  # Execute in a subprocess
    CONTAINER = "container"   # Execute in a container
    CHROOT = "chroot"       # Execute in a chroot environment
    VM = "vm"             # Execute in a virtual machine


class SandboxManager:
    """
    Manages secure sandbox environments for executing response actions.
    Creates isolated execution environments based on configuration.
    """
    
    def __init__(self, sandbox_type: str):
        """
        Initialize the sandbox manager
        
        Args:
            sandbox_type: Type of sandbox to use
        """
        self.sandbox_type = sandbox_type
        self.active_sandboxes = {}
        logger.info(f"Initialized SandboxManager with type: {sandbox_type}")
        
    def create_sandbox(self, execution_id: str) -> Dict[str, Any]:
        """
        Create a new sandbox environment
        
        Args:
            execution_id: Unique ID for this execution
            
        Returns:
            Dictionary with sandbox information
        """
        if self.sandbox_type == ExecutionEnvironment.DIRECT.value:
            logger.warning("Using direct execution without sandbox")
            return {"id": execution_id, "type": "direct", "path": os.getcwd()}
        
        elif self.sandbox_type == ExecutionEnvironment.SUBPROCESS.value:
            logger.info(f"Creating subprocess sandbox for execution {execution_id}")
            # Create temporary directory for this execution
            temp_dir = os.path.join(tempfile.gettempdir(), f"asira_{execution_id}")
            os.makedirs(temp_dir, exist_ok=True)
            
            sandbox_info = {
                "id": execution_id,
                "type": "subprocess",
                "path": temp_dir
            }
            
            self.active_sandboxes[execution_id] = sandbox_info
            return sandbox_info
        
        elif self.sandbox_type == ExecutionEnvironment.CONTAINER.value:
            logger.info(f"Creating container sandbox for execution {execution_id}")
            # In a real implementation, this would launch a container
            # For this prototype, we'll simulate it
            
            # Create temporary directory for this execution
            temp_dir = os.path.join(tempfile.gettempdir(), f"asira_{execution_id}")
            os.makedirs(temp_dir, exist_ok=True)
            
            container_id = f"asira-container-{execution_id}"
            
            # In a real implementation, we would:
            # 1. Pull a secure container image
            # 2. Launch the container with limited permissions
            # 3. Map the temp directory into the container
            
            sandbox_info = {
                "id": execution_id,
                "type": "container",
                "path": temp_dir,
                "container_id": container_id
            }
            
            self.active_sandboxes[execution_id] = sandbox_info
            return sandbox_info
        
        elif self.sandbox_type == ExecutionEnvironment.CHROOT.value:
            logger.info(f"Creating chroot sandbox for execution {execution_id}")
            # In a real implementation, this would set up a chroot environment
            # For this prototype, we'll simulate it
            
            # Create temporary directory for this execution
            temp_dir = os.path.join(tempfile.gettempdir(), f"asira_{execution_id}")
            os.makedirs(temp_dir, exist_ok=True)
            
            sandbox_info = {
                "id": execution_id,
                "type": "chroot",
                "path": temp_dir
            }
            
            self.active_sandboxes[execution_id] = sandbox_info
            return sandbox_info
        
        else:
            logger.warning(f"Unsupported sandbox type: {self.sandbox_type}, falling back to direct execution")
            return {"id": execution_id, "type": "direct", "path": os.getcwd()}
    
    def execute_in_sandbox(
        self, 
        sandbox_info: Dict[str, Any], 
        command: str, 
        env: Dict[str, str] = None,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Execute a command in the sandbox environment
        
        Args:
            sandbox_info: Sandbox information dictionary
            command: Command to execute
            env: Environment variables for the command
            timeout: Maximum execution time in seconds
            
        Returns:
            Dictionary with execution results
        """
        start_time = time.time()
        sandbox_type = sandbox_info.get("type", "direct")
        
        # Prepare result structure
        result = {
            "command": command,
            "success": False,
            "output": "",
            "error": "",
            "return_code": -1,
            "execution_time": 0
        }
        
        try:
            if sandbox_type == "direct":
                # Direct execution in current process
                logger.debug(f"Directly executing command: {command}")
                
                # Execute the command
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env or os.environ,
                    text=True
                )
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    result["success"] = process.returncode == 0
                    result["output"] = stdout
                    result["error"] = stderr
                    result["return_code"] = process.returncode
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    result["success"] = False
                    result["output"] = stdout
                    result["error"] = f"Command execution timed out after {timeout} seconds"
                    result["return_code"] = -1
            
            elif sandbox_type == "subprocess":
                # Execute in subprocess with limited permissions
                logger.debug(f"Executing command in subprocess: {command}")
                
                # Set working directory to sandbox path
                working_dir = sandbox_info.get("path", os.getcwd())
                
                # Execute the command
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=working_dir,
                    env=env or os.environ,
                    text=True
                )
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    result["success"] = process.returncode == 0
                    result["output"] = stdout
                    result["error"] = stderr
                    result["return_code"] = process.returncode
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    result["success"] = False
                    result["output"] = stdout
                    result["error"] = f"Command execution timed out after {timeout} seconds"
                    result["return_code"] = -1
            
            elif sandbox_type == "container":
                # Execute in container
                logger.debug(f"Executing command in container: {command}")
                
                # In a real implementation, this would execute the command in the container
                # For this prototype, we'll simulate it
                container_id = sandbox_info.get("container_id", "")
                
                # Simulate docker exec
                docker_command = f"docker exec {container_id} /bin/sh -c '{command}'"
                
                # For prototype, we'll execute locally but log as if in container
                logger.info(f"Would execute in container: {docker_command}")
                
                # Simulate success
                result["success"] = True
                result["output"] = f"Command executed in container {container_id}"
                result["error"] = ""
                result["return_code"] = 0
            
            elif sandbox_type == "chroot":
                # Execute in chroot environment
                logger.debug(f"Executing command in chroot: {command}")
                
                # In a real implementation, this would execute the command in chroot
                # For this prototype, we'll simulate it
                chroot_path = sandbox_info.get("path", "")
                
                # Simulate chroot command
                chroot_command = f"chroot {chroot_path} /bin/sh -c '{command}'"
                
                # For prototype, we'll execute locally but log as if in chroot
                logger.info(f"Would execute in chroot: {chroot_command}")
                
                # Simulate success
                result["success"] = True
                result["output"] = f"Command executed in chroot {chroot_path}"
                result["error"] = ""
                result["return_code"] = 0
            
            else:
                result["success"] = False
                result["error"] = f"Unsupported sandbox type: {sandbox_type}"
        
        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
        
        # Calculate execution time
        result["execution_time"] = time.time() - start_time
        
        return result
    
    def cleanup_sandbox(self, execution_id: str) -> bool:
        """
        Clean up sandbox environment
        
        Args:
            execution_id: ID of the execution to clean up
            
        Returns:
            True if cleanup was successful, False otherwise
        """
        if execution_id not in self.active_sandboxes:
            logger.warning(f"No sandbox found for execution {execution_id}")
            return False
        
        sandbox_info = self.active_sandboxes[execution_id]
        sandbox_type = sandbox_info.get("type", "direct")
        
        try:
            if sandbox_type == "direct":
                # Nothing to clean up
                pass
            
            elif sandbox_type == "subprocess":
                # Remove temporary directory
                temp_dir = sandbox_info.get("path")
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
            
            elif sandbox_type == "container":
                # Stop and remove container
                container_id = sandbox_info.get("container_id")
                if container_id:
                    # In a real implementation, this would stop and remove the container
                    logger.info(f"Would stop and remove container: {container_id}")
                
                # Remove temporary directory
                temp_dir = sandbox_info.get("path")
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
            
            elif sandbox_type == "chroot":
                # Remove chroot directory
                chroot_path = sandbox_info.get("path")
                if chroot_path and os.path.exists(chroot_path):
                    shutil.rmtree(chroot_path, ignore_errors=True)
            
            # Remove from active sandboxes
            del self.active_sandboxes[execution_id]
            
            logger.info(f"Cleaned up sandbox for execution {execution_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error cleaning up sandbox for execution {execution_id}: {e}")
            return False


class CredentialManager:
    """
    Manages secure access to credentials needed for response actions.
    Retrieves secrets and access tokens while maintaining security.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the credential manager
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.cache = {}
        self.vault_enabled = self.config.get("vault_enabled", False)
        self.vault_url = self.config.get("vault_url", "")
        self.vault_token = self.config.get("vault_token", "")
        
        logger.info(f"Initialized CredentialManager (vault_enabled: {self.vault_enabled})")
    
    def get_credential(self, credential_id: str) -> Optional[str]:
        """
        Retrieve a credential by ID
        
        Args:
            credential_id: ID of the credential to retrieve
            
        Returns:
            Credential value or None if not found
        """
        # Check cache first
        if credential_id in self.cache:
            logger.debug(f"Retrieved credential {credential_id} from cache")
            return self.cache[credential_id]
        
        # Try to retrieve from vault if enabled
        if self.vault_enabled and self.vault_url and self.vault_token:
            try:
                # In a real implementation, this would call the vault API
                logger.info(f"Would retrieve credential {credential_id} from vault")
                
                # For this prototype, use environment variable as fallback
                env_var = f"ASIRA_CREDENTIAL_{credential_id.upper()}"
                if env_var in os.environ:
                    credential = os.environ[env_var]
                    self.cache[credential_id] = credential
                    return credential
                
            except Exception as e:
                logger.error(f"Error retrieving credential {credential_id} from vault: {e}")
        
        # Try environment variable
        env_var = f"ASIRA_CREDENTIAL_{credential_id.upper()}"
        if env_var in os.environ:
            credential = os.environ[env_var]
            self.cache[credential_id] = credential
            logger.debug(f"Retrieved credential {credential_id} from environment")
            return credential
        
        # Try config
        if "credentials" in self.config and credential_id in self.config["credentials"]:
            credential = self.config["credentials"][credential_id]
            self.cache[credential_id] = credential
            logger.debug(f"Retrieved credential {credential_id} from config")
            return credential
        
        logger.warning(f"Credential {credential_id} not found")
        return None
    
    def get_token(self, service_id: str) -> Optional[str]:
        """
        Retrieve an access token for a service
        
        Args:
            service_id: ID of the service
            
        Returns:
            Access token or None if not found
        """
        token_id = f"token_{service_id}"
        return self.get_credential(token_id)
    
    def clear_cache(self):
        """Clear credential cache"""
        self.cache = {}
        logger.debug("Cleared credential cache")


class PlaybookExecutor:
    """
    Securely executes response playbooks in an isolated environment.
    Manages execution flow, variable substitution, and result tracking.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the playbook executor with configuration
        
        Args:
            config: Configuration dictionary with execution settings
        """
        self.config = config
        self.execution_dir = config.get("execution_dir", "/tmp/asira/execution")
        self.playbook_dir = config.get("playbook_dir", "/etc/asira/playbooks")
        self.max_execution_time = config.get("max_execution_time", 300)  # seconds
        self.sandbox_type = config.get("sandbox_type", "subprocess")
        
        # Create managers
        self.sandbox_manager = SandboxManager(self.sandbox_type)
        self.credential_manager = CredentialManager(config.get("credentials", {}))
        
        # Template engine for variable substitution
        self.template_env = jinja2.Environment(undefined=jinja2.StrictUndefined)
        
        # Ensure execution directory exists
        os.makedirs(self.execution_dir, exist_ok=True)
        
        logger.info(f"Initialized PlaybookExecutor with sandbox type: {self.sandbox_type}")
    
    def execute_playbook(self, playbook_id: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a response playbook for a given security incident
        
        Args:
            playbook_id: The ID of the playbook to execute
            incident_data: Data about the security incident
            
        Returns:
            Dictionary with execution results
        """
        logger.info(f"Starting execution of playbook {playbook_id}")
        
        # Generate execution ID
        execution_id = f"exec_{uuid.uuid4().hex[:8]}"
        execution_path = os.path.join(self.execution_dir, execution_id)
        os.makedirs(execution_path, exist_ok=True)
        
        # Start time for the execution
        start_time = datetime.datetime.now()
        
        # Load the playbook
        playbook = self._load_playbook(playbook_id)
        if not playbook:
            logger.error(f"Playbook {playbook_id} not found")
            return {
                "execution_id": execution_id,
                "playbook_id": playbook_id,
                "start_time": start_time.timestamp(),
                "end_time": datetime.datetime.now().timestamp(),
                "status": "failed",
                "error": f"Playbook {playbook_id} not found",
                "actions": []
            }
        
        try:
            # Save incident data for reference
            incident_data_path = os.path.join(execution_path, "incident_data.json")
            with open(incident_data_path, "w") as f:
                json.dump(incident_data, f, indent=2)
            
            # Prepare execution context
            context = self._prepare_execution_context(execution_id, incident_data)
            
            # Create sandbox environment
            sandbox_info = self.sandbox_manager.create_sandbox(execution_id)
            
            # Execute actions
            results = []
            
            # Determine execution mode
            is_parallel = playbook.execution_mode == "parallel"
            
            if is_parallel:
                # Execute actions in parallel
                threads = []
                thread_results = [None] * len(playbook.actions)
                
                for i, action in enumerate(playbook.actions):
                    thread = threading.Thread(
                        target=self._execute_action_thread,
                        args=(action, context, sandbox_info, thread_results, i)
                    )
                    threads.append(thread)
                    thread.start()
                
                # Wait for all threads to complete
                for thread in threads:
                    thread.join()
                
                # Collect results
                results = [r for r in thread_results if r is not None]
            else:
                # Execute actions sequentially
                for action in playbook.actions:
                    action_result = self._execute_action(action, context, sandbox_info)
                    results.append(action_result)
                    
                    # Stop execution if action fails and playbook requires it
                    if (action_result.status == ActionStatus.FAILED and 
                        not getattr(action, "continue_on_failure", False)):
                        logger.warning(f"Stopping playbook execution after failed action {action.id}")
                        break
                    
                    # Update context with action results
                    action_dict = action_result.to_dict()
                    context["action_results"][action.id] = action_dict
            
            # Calculate overall status
            if any(r.status == ActionStatus.FAILED for r in results):
                status = "failed"
            elif any(r.status == ActionStatus.SKIPPED for r in results):
                status = "partial"
            else:
                status = "completed"
            
            # End time for the execution
            end_time = datetime.datetime.now()
            
            # Create execution summary
            summary = {
                "execution_id": execution_id,
                "playbook_id": playbook_id,
                "incident_id": incident_data.get("id", "unknown"),
                "start_time": start_time.timestamp(),
                "end_time": end_time.timestamp(),
                "status": status,
                "triggered_by": incident_data.get("triggered_by", "system"),
                "actions": [r.to_dict() for r in results]
            }
            
            # Save execution summary
            summary_path = os.path.join(execution_path, "summary.json")
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
            
            # Create human-readable summary
            self._create_summary_report(execution_path, playbook, summary)
            
            logger.info(f"Playbook {playbook_id} execution completed with status: {status}")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error executing playbook {playbook_id}: {e}", exc_info=True)
            
            return {
                "execution_id": execution_id,
                "playbook_id": playbook_id,
                "start_time": start_time.timestamp(),
                "end_time": datetime.datetime.now().timestamp(),
                "status": "failed",
                "error": str(e),
                "actions": []
            }
            
        finally:
            # Cleanup sandbox environment
            self.sandbox_manager.cleanup_sandbox(execution_id)
    
    def _load_playbook(self, playbook_id: str) -> Optional[PlaybookDefinition]:
        """
        Load a playbook definition from storage
        
        Args:
            playbook_id: ID of the playbook to load
            
        Returns:
            Playbook definition or None if not found
        """
        # Try loading from YAML file
        playbook_path = os.path.join(self.playbook_dir, f"{playbook_id}.yml")
        if not os.path.exists(playbook_path):
            playbook_path = os.path.join(self.playbook_dir, f"{playbook_id}.yaml")
            if not os.path.exists(playbook_path):
                return None
        
        try:
            with open(playbook_path, "r") as f:
                playbook_data = yaml.safe_load(f)
                
            # Create playbook definition
            from src.response.playbooks.base import PlaybookDefinition, ActionDefinition
            
            # Create actions
            actions = []
            for action_data in playbook_data.get("actions", []):
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
            
            # Create playbook
            playbook = PlaybookDefinition(
                id=playbook_data.get("id", playbook_id),
                name=playbook_data.get("name", playbook_id),
                description=playbook_data.get("description", ""),
                actions=actions,
                execution_mode=playbook_data.get("execution_mode", "sequential"),
                enabled=playbook_data.get("enabled", True),
                tags=playbook_data.get("tags", []),
                target_severity=playbook_data.get("target_severity", [])
            )
            
            return playbook
            
        except Exception as e:
            logger.error(f"Error loading playbook {playbook_id}: {e}")
            return None
    
    def _prepare_execution_context(self, execution_id: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare the execution context for variable substitution
        
        Args:
            execution_id: Unique ID for this execution
            incident_data: Data about the security incident
            
        Returns:
            Dictionary with execution context
        """
        context = {
            "execution": {
                "id": execution_id,
                "timestamp": time.time(),
                "date": datetime.datetime.now().strftime("%Y-%m-%d"),
                "time": datetime.datetime.now().strftime("%H:%M:%S")
            },
            "incident": incident_data,
            "action_results": {},
            "env": dict(os.environ)
        }
        
        # Add helper functions
        context["helpers"] = {
            "generate_id": lambda: uuid.uuid4().hex[:8]
        }
        
        return context
    
    def _execute_action_thread(
        self, 
        action, 
        context: Dict[str, Any], 
        sandbox_info: Dict[str, Any], 
        results: List, 
        index: int
    ):
        """
        Execute an action in a separate thread
        
        Args:
            action: Action to execute
            context: Execution context
            sandbox_info: Sandbox information
            results: List to store results
            index: Index in the results list
        """
        try:
            result = self._execute_action(action, context, sandbox_info)
            results[index] = result
        except Exception as e:
            logger.error(f"Error executing action {action.id} in thread: {e}")
            # Create a failed result
            result = ActionResult(
                action_id=action.id,
                status=ActionStatus.FAILED,
                error=str(e),
                start_time=datetime.datetime.now(),
                end_time=datetime.datetime.now()
            )
            results[index] = result
    
    def _execute_action(
        self, 
        action, 
        context: Dict[str, Any], 
        sandbox_info: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute a single action from a playbook
        
        Args:
            action: Action to execute
            context: Execution context
            sandbox_info: Sandbox information
            
        Returns:
            ActionResult with execution details
        """
        # Start time
        start_time = datetime.datetime.now()
        
        # Initialize result
        result = ActionResult(
            action_id=action.id,
            status=ActionStatus.IN_PROGRESS,
            start_time=start_time
        )
        
        logger.info(f"Executing action: {action.id} of type {action.type}")
        
        try:
            # Process template variables
            processed_action = self._process_variables(action, context)
            
            # Execute based on action type
            if processed_action.type == ActionType.COMMAND:
                result = self._execute_command_action(processed_action, context, sandbox_info)
                
            elif processed_action.type == ActionType.API_CALL:
                result = self._execute_api_action(processed_action, context)
                
            elif processed_action.type == ActionType.SCRIPT:
                result = self._execute_script_action(processed_action, context, sandbox_info)
                
            elif processed_action.type == ActionType.NOTIFICATION:
                result = self._execute_notification_action(processed_action, context)
                
            elif processed_action.type == ActionType.CONTAINMENT:
                result = self._execute_containment_action(processed_action, context, sandbox_info)
                
            elif processed_action.type == ActionType.ENRICHMENT:
                result = self._execute_enrichment_action(processed_action, context)
                
            else:
                logger.warning(f"Unknown action type: {processed_action.type}")
                result.status = ActionStatus.FAILED
                result.error = f"Unknown action type: {processed_action.type}"
            
        except Exception as e:
            logger.error(f"Error executing action {action.id}: {e}", exc_info=True)
            result.status = ActionStatus.FAILED
            result.error = str(e)
            
        # Set end time
        result.end_time = datetime.datetime.now()
        
        # Log result
        log_level = logging.INFO if result.status == ActionStatus.COMPLETED else logging.WARNING
        logger.log(log_level, f"Action {action.id} completed with status: {result.status.value}")
        
        return result
    
    def _process_variables(self, action, context: Dict[str, Any]):
        """
        Process template variables in action parameters
        
        Args:
            action: Action to process
            context: Execution context
            
        Returns:
            Action with processed variables
        """
        # Create a deep copy to avoid modifying the original
        from copy import deepcopy
        processed = deepcopy(action)
        
        # Process command
        if processed.command:
            processed.command = self._render_template(processed.command, context)
            
        # Process API endpoint and payload
        if processed.api_endpoint:
            processed.api_endpoint = self._render_template(processed.api_endpoint, context)
            
        if processed.api_payload and isinstance(processed.api_payload, dict):
            for key, value in processed.api_payload.items():
                if isinstance(value, str):
                    processed.api_payload[key] = self._render_template(value, context)
        
        # Process script
        if processed.script:
            processed.script = self._render_template(processed.script, context)
            
        # Process template
        if processed.template:
            processed.template = self._render_template(processed.template, context)
            
        # Process target
        if processed.target:
            processed.target = self._render_template(processed.target, context)
            
        # Process parameters
        if processed.parameters:
            for key, value in processed.parameters.items():
                if isinstance(value, str):
                    processed.parameters[key] = self._render_template(value, context)
                    
        return processed
    
    def _render_template(self, template_str: str, context: Dict[str, Any]) -> str:
        """
        Render a template string using the execution context
        
        Args:
            template_str: Template string with variables
            context: Execution context
            
        Returns:
            Rendered string with variables replaced
        """
        try:
            template = self.template_env.from_string(template_str)
            return template.render(**context)
        except jinja2.exceptions.TemplateError as e:
            logger.error(f"Template rendering error: {e}")
            raise ValueError(f"Error rendering template: {e}")
        except Exception as e:
            logger.error(f"Unexpected error rendering template: {e}")
            raise ValueError(f"Error rendering template: {e}")
    
    def _execute_command_action(
        self, 
        action, 
        context: Dict[str, Any], 
        sandbox_info: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute a command action
        
        Args:
            action: Action to execute
            context: Execution context
            sandbox_info: Sandbox information
            
        Returns:
            ActionResult with execution details
        """
        # Initialize result
        result = ActionResult(
            action_id=action.id,
            status=ActionStatus.IN_PROGRESS,
            start_time=datetime.datetime.now()
        )
        
        # Check if command is provided
        if not action.command:
            result.status = ActionStatus.FAILED
            result.error = "No command provided for command action"
            result.end_time = datetime.datetime.now()
            return result
        
        # Execute command in sandbox
        timeout = action.timeout or 60
        logger.info(f"Executing command: {action.command} with timeout {timeout}s")
        
        # Add any credentials needed for this command
        env = dict(os.environ)
        for param_name, param_value in action.parameters.items():
            if param_name.startswith("credential_"):
                credential_id = param_value
                credential_value = self.credential_manager.get_credential(credential_id)
                if credential_value:
                    env_var_name = param_name.upper()
                    env[env_var_name] = credential_value
        
        # Execute the command in the sandbox
        execution_result = self.sandbox_manager.execute_in_sandbox(
            sandbox_info=sandbox_info,
            command=action.command,
            env=env,
            timeout=timeout
        )
        
        # Process execution result
        if execution_result["success"]:
            result.status = ActionStatus.COMPLETED
            result.output = execution_result["output"]
        else:
            result.status = ActionStatus.FAILED
            result.error = execution_result["error"] or "Unknown error"
            result.output = execution_result["output"]
        
        # Include execution details
        result.details = {
            "command": action.command,
            "return_code": execution_result["return_code"],
            "execution_time": execution_result["execution_time"]
        }
        
        result.end_time = datetime.datetime.now()
        return result
    
    def _execute_api_action(
        self, 
        action, 
        context: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute an API call action
        
        Args:
            action: Action to execute
            context: Execution context
            
        Returns:
            ActionResult with execution details
        """
        # Initialize result
        result = ActionResult(
            action_id=action.id,
            status=ActionStatus.IN_PROGRESS,
            start_time=datetime.datetime.now()
        )
        
        # Check if API endpoint is provided
        if not action.api_endpoint:
            result.status = ActionStatus.FAILED
            result.error = "No API endpoint provided for API action"
            result.end_time = datetime.datetime.now()
            return result
        
        # Check if API method is provided
        method = action.api_method or "GET"
        
        try:
            # Prepare headers
            headers = {}
            
            # Add authentication if needed
            if "auth_type" in action.parameters:
                auth_type = action.parameters["auth_type"]
                
                if auth_type == "basic":
                    if "username" in action.parameters and "password" in action.parameters:
                        # Get credentials
                        username = action.parameters["username"]
                        password_id = action.parameters["password"]
                        password = self.credential_manager.get_credential(password_id)
                        
                        if password:
                            import base64
                            auth_str = f"{username}:{password}"
                            auth_bytes = auth_str.encode("ascii")
                            auth_encoded = base64.b64encode(auth_bytes).decode("ascii")
                            headers["Authorization"] = f"Basic {auth_encoded}"
                        else:
                            raise ValueError(f"Could not retrieve password for credential ID {password_id}")
                            
                elif auth_type == "bearer":
                    if "token_id" in action.parameters:
                        token_id = action.parameters["token_id"]
                        token = self.credential_manager.get_credential(token_id)
                        
                        if token:
                            headers["Authorization"] = f"Bearer {token}"
                        else:
                            raise ValueError(f"Could not retrieve token for credential ID {token_id}")
                            
                elif auth_type == "api_key":
                    if "api_key_id" in action.parameters and "api_key_header" in action.parameters:
                        api_key_id = action.parameters["api_key_id"]
                        api_key_header = action.parameters["api_key_header"]
                        api_key = self.credential_manager.get_credential(api_key_id)
                        
                        if api_key:
                            headers[api_key_header] = api_key
                        else:
                            raise ValueError(f"Could not retrieve API key for credential ID {api_key_id}")
            
            # Add content type header for JSON payload
            if action.api_payload:
                headers["Content-Type"] = "application/json"
            
            # Add additional headers from parameters
            if "headers" in action.parameters and isinstance(action.parameters["headers"], dict):
                headers.update(action.parameters["headers"])
            
            # Prepare request parameters
            timeout = action.timeout or 30
            
            # Log the request (excluding sensitive headers)
            safe_headers = {k: "***" if k.lower() in ("authorization", "api-key") else v 
                           for k, v in headers.items()}
            logger.info(f"Making API request: {method} {action.api_endpoint}")
            logger.debug(f"API headers: {safe_headers}")
            
            # Make the request
            start_time = time.time()
            
            if method.upper() == "GET":
                response = requests.get(
                    action.api_endpoint,
                    headers=headers,
                    timeout=timeout,
                    verify=action.parameters.get("verify_ssl", True)
                )
            elif method.upper() == "POST":
                response = requests.post(
                    action.api_endpoint,
                    json=action.api_payload,
                    headers=headers,
                    timeout=timeout,
                    verify=action.parameters.get("verify_ssl", True)
                )
            elif method.upper() == "PUT":
                response = requests.put(
                    action.api_endpoint,
                    json=action.api_payload,
                    headers=headers,
                    timeout=timeout,
                    verify=action.parameters.get("verify_ssl", True)
                )
            elif method.upper() == "DELETE":
                response = requests.delete(
                    action.api_endpoint,
                    headers=headers,
                    timeout=timeout,
                    verify=action.parameters.get("verify_ssl", True)
                )
            else:
                result.status = ActionStatus.FAILED
                result.error = f"Unsupported HTTP method: {method}"
                result.end_time = datetime.datetime.now()
                return result
                
            # Process response
            execution_time = time.time() - start_time
            response_time_ms = int(execution_time * 1000)
            
            # Determine if request was successful
            is_success = 200 <= response.status_code < 300
            
            if is_success:
                result.status = ActionStatus.COMPLETED
            else:
                result.status = ActionStatus.FAILED
                result.error = f"API request failed with status code {response.status_code}"
            
            # Parse response
            try:
                response_json = response.json()
                result.output = json.dumps(response_json, indent=2)
            except:
                # Not JSON response
                result.output = response.text
            
            # Include execution details
            result.details = {
                "method": method,
                "endpoint": action.api_endpoint,
                "status_code": response.status_code,
                "response_time_ms": response_time_ms,
                "content_type": response.headers.get("Content-Type", "")
            }
            
        except requests.exceptions.Timeout:
            result.status = ActionStatus.FAILED
            result.error = f"API request timed out after {timeout} seconds"
            
        except requests.exceptions.RequestException as e:
            result.status = ActionStatus.FAILED
            result.error = f"API request error: {str(e)}"
            
        except Exception as e:
            result.status = ActionStatus.FAILED
            result.error = f"Error executing API action: {str(e)}"
        
        result.end_time = datetime.datetime.now()
        return result
    
    def _execute_script_action(
        self, 
        action, 
        context: Dict[str, Any], 
        sandbox_info: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute a script action
        
        Args:
            action: Action to execute
            context: Execution context
            sandbox_info: Sandbox information
            
        Returns:
            ActionResult with execution details
        """
        # Initialize result
        result = ActionResult(
            action_id=action.id,
            status=ActionStatus.IN_PROGRESS,
            start_time=datetime.datetime.now()
        )
        
        # Check if script is provided
        if not action.script:
            result.status = ActionStatus.FAILED
            result.error = "No script provided for script action"
            result.end_time = datetime.datetime.now()
            return result
        
        try:
            # Create a temporary script file in the sandbox
            script_path = os.path.join(sandbox_info["path"], f"script_{action.id}.sh")
            with open(script_path, "w") as f:
                f.write(action.script)
            
            # Make script executable
            os.chmod(script_path, 0o755)
            
            # Execute the script
            command = f"{script_path} {action.parameters.get('arguments', '')}"
            
            # Add any environment variables needed for this script
            env = dict(os.environ)
            for param_name, param_value in action.parameters.items():
                if param_name.startswith("env_"):
                    env_var_name = param_name[4:].upper()
                    env[env_var_name] = param_value
                elif param_name.startswith("credential_"):
                    credential_id = param_value
                    credential_value = self.credential_manager.get_credential(credential_id)
                    if credential_value:
                        env_var_name = param_name.upper()
                        env[env_var_name] = credential_value
            
            timeout = action.timeout or 120
            
            # Execute the script command in the sandbox
            execution_result = self.sandbox_manager.execute_in_sandbox(
                sandbox_info=sandbox_info,
                command=command,
                env=env,
                timeout=timeout
            )
            
            # Process execution result
            if execution_result["success"]:
                result.status = ActionStatus.COMPLETED
                result.output = execution_result["output"]
            else:
                result.status = ActionStatus.FAILED
                result.error = execution_result["error"] or "Unknown error"
                result.output = execution_result["output"]
            
            # Include execution details
            result.details = {
                "script_path": script_path,
                "return_code": execution_result["return_code"],
                "execution_time": execution_result["execution_time"]
            }
            
            # Clean up script file
            try:
                os.remove(script_path)
            except:
                pass
            
        except Exception as e:
            result.status = ActionStatus.FAILED
            result.error = f"Error executing script action: {str(e)}"
        
        result.end_time = datetime.datetime.now()
        return result
    
    def _execute_notification_action(
        self, 
        action, 
        context: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute a notification action
        
        Args:
            action: Action to execute
            context: Execution context
            
        Returns:
            ActionResult with execution details
        """
        # Initialize result
        result = ActionResult(
            action_id=action.id,
            status=ActionStatus.IN_PROGRESS,
            start_time=datetime.datetime.now()
        )
        
        # Check if template or message is provided
        if not action.template:
            result.status = ActionStatus.FAILED
            result.error = "No template provided for notification action"
            result.end_time = datetime.datetime.now()
            return result
        
        # Check if channels are provided
        if not action.channels:
            result.status = ActionStatus.FAILED
            result.error = "No channels provided for notification action"
            result.end_time = datetime.datetime.now()
            return result
        
        try:
            # Import notification functions
            from src.response.notifications import (
                send_email_notification,
                send_slack_notification,
                send_sms_notification,
                send_webhook_notification
            )
            
            # Process the template
            notification_content = action.template
            
            # Send notifications to specified channels
            success_channels = []
            failed_channels = {}
            
            for channel in action.channels:
                try:
                    if channel == "email":
                        recipients = action.parameters.get("email_recipients", [])
                        subject = action.parameters.get("email_subject", "Security Incident Notification")
                        
                        if not recipients:
                            failed_channels[channel] = "No recipients specified"
                            continue
                            
                        send_email_notification(recipients, subject, notification_content)
                        success_channels.append(channel)
                        
                    elif channel == "slack":
                        webhook_url = action.parameters.get("slack_webhook_url", "")
                        webhook_id = action.parameters.get("slack_webhook_id", "")
                        
                        # Get webhook URL from credential manager if ID is provided
                        if not webhook_url and webhook_id:
                            webhook_url = self.credential_manager.get_credential(webhook_id)
                        
                        if not webhook_url:
                            failed_channels[channel] = "No webhook URL specified"
                            continue
                            
                        send_slack_notification(webhook_url, notification_content)
                        success_channels.append(channel)
                        
                    elif channel == "sms":
                        phone_numbers = action.parameters.get("phone_numbers", [])
                        
                        if not phone_numbers:
                            failed_channels[channel] = "No phone numbers specified"
                            continue
                            
                        send_sms_notification(phone_numbers, notification_content)
                        success_channels.append(channel)
                        
                    elif channel == "webhook":
                        webhook_url = action.parameters.get("webhook_url", "")
                        webhook_id = action.parameters.get("webhook_id", "")
                        webhook_method = action.parameters.get("webhook_method", "POST")
                        
                        # Get webhook URL from credential manager if ID is provided
                        if not webhook_url and webhook_id:
                            webhook_url = self.credential_manager.get_credential(webhook_id)
                        
                        if not webhook_url:
                            failed_channels[channel] = "No webhook URL specified"
                            continue
                            
                        send_webhook_notification(webhook_url, notification_content, method=webhook_method)
                        success_channels.append(channel)
                        
                    else:
                        failed_channels[channel] = f"Unknown notification channel: {channel}"
                        
                except Exception as e:
                    failed_channels[channel] = str(e)
            
            # Determine overall status
            if success_channels:
                if failed_channels:
                    # Some channels succeeded, some failed
                    result.status = ActionStatus.PARTIAL
                    result.error = f"Failed to send to some channels: {failed_channels}"
                else:
                    # All channels succeeded
                    result.status = ActionStatus.COMPLETED
            else:
                # All channels failed
                result.status = ActionStatus.FAILED
                result.error = f"Failed to send to all channels: {failed_channels}"
            
            # Include details
            result.output = f"Notification sent successfully to: {', '.join(success_channels)}"
            result.details = {
                "success_channels": success_channels,
                "failed_channels": failed_channels,
                "content_length": len(notification_content)
            }
            
        except Exception as e:
            result.status = ActionStatus.FAILED
            result.error = f"Error executing notification action: {str(e)}"
        
        result.end_time = datetime.datetime.now()
        return result
    
    def _execute_containment_action(
        self, 
        action, 
        context: Dict[str, Any], 
        sandbox_info: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute a containment action
        
        Args:
            action: Action to execute
            context: Execution context
            sandbox_info: Sandbox information
            
        Returns:
            ActionResult with execution details
        """
        # Initialize result
        result = ActionResult(
            action_id=action.id,
            status=ActionStatus.IN_PROGRESS,
            start_time=datetime.datetime.now()
        )
        
        # Check if target is provided
        if not action.target:
            result.status = ActionStatus.FAILED
            result.error = "No target provided for containment action"
            result.end_time = datetime.datetime.now()
            return result
        
        try:
            # Import containment functions
            from src.response.containment import (
                isolate_host,
                block_ip,
                block_user,
                disable_account
            )
            
            # Determine containment type
            containment_type = action.parameters.get("containment_type", "")
            target = action.target
            
            if containment_type == "isolate_host":
                success, message = isolate_host(target)
                if success:
                    result.status = ActionStatus.COMPLETED
                    result.output = message
                else:
                    result.status = ActionStatus.FAILED
                    result.error = message
            
            elif containment_type == "block_ip":
                duration = action.parameters.get("duration", 3600)  # Default 1 hour
                success, message = block_ip(target, duration)
                if success:
                    result.status = ActionStatus.COMPLETED
                    result.output = message
                else:
                    result.status = ActionStatus.FAILED
                    result.error = message
            
            elif containment_type == "block_user":
                success, message = block_user(target)
                if success:
                    result.status = ActionStatus.COMPLETED
                    result.output = message
                else:
                    result.status = ActionStatus.FAILED
                    result.error = message
            
            elif containment_type == "disable_account":
                success, message = disable_account(target)
                if success:
                    result.status = ActionStatus.COMPLETED
                    result.output = message
                else:
                    result.status = ActionStatus.FAILED
                    result.error = message
            
            else:
                result.status = ActionStatus.FAILED
                result.error = f"Unknown containment type: {containment_type}"
                
            # Include details
            result.details = {
                "containment_type": containment_type,
                "target": target
            }
            
        except Exception as e:
            result.status = ActionStatus.FAILED
            result.error = f"Error executing containment action: {str(e)}"
        
        result.end_time = datetime.datetime.now()
        return result
    
    def _execute_enrichment_action(
        self, 
        action, 
        context: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute an enrichment action
        
        Args:
            action: Action to execute
            context: Execution context
            
        Returns:
            ActionResult with execution details
        """
        # Initialize result
        result = ActionResult(
            action_id=action.id,
            status=ActionStatus.IN_PROGRESS,
            start_time=datetime.datetime.now()
        )
        
        # Check if target is provided
        if not action.target:
            result.status = ActionStatus.FAILED
            result.error = "No target provided for enrichment action"
            result.end_time = datetime.datetime.now()
            return result
        
        try:
            # Import enrichment functions
            from src.response.enrichment import (
                lookup_ip,
                lookup_domain,
                lookup_file_hash,
                lookup_user
            )
            
            # Determine enrichment type
            enrichment_type = action.parameters.get("enrichment_type", "")
            target = action.target
            
            if enrichment_type == "ip_lookup":
                data = lookup_ip(target)
                result.status = ActionStatus.COMPLETED
                result.output = json.dumps(data, indent=2)
                result.details = {
                    "enrichment_type": enrichment_type,
                    "target": target,
                    "data_fields": list(data.keys())
                }
            
            elif enrichment_type == "domain_lookup":
                data = lookup_domain(target)
                result.status = ActionStatus.COMPLETED
                result.output = json.dumps(data, indent=2)
                result.details = {
                    "enrichment_type": enrichment_type,
                    "target": target,
                    "data_fields": list(data.keys())
                }
            
            elif enrichment_type == "file_hash_lookup":
                data = lookup_file_hash(target)
                result.status = ActionStatus.COMPLETED
                result.output = json.dumps(data, indent=2)
                result.details = {
                    "enrichment_type": enrichment_type,
                    "target": target,
                    "data_fields": list(data.keys())
                }
            
            elif enrichment_type == "user_lookup":
                data = lookup_user(target)
                result.status = ActionStatus.COMPLETED
                result.output = json.dumps(data, indent=2)
                result.details = {
                    "enrichment_type": enrichment_type,
                    "target": target,
                    "data_fields": list(data.keys())
                }
            
            else:
                result.status = ActionStatus.FAILED
                result.error = f"Unknown enrichment type: {enrichment_type}"
            
        except Exception as e:
            result.status = ActionStatus.FAILED
            result.error = f"Error executing enrichment action: {str(e)}"
        
        result.end_time = datetime.datetime.now()
        return result
    
    def _create_summary_report(
        self, 
        execution_path: str, 
        playbook: PlaybookDefinition, 
        summary: Dict[str, Any]
    ) -> None:
        """
        Create a human-readable summary report of the execution
        
        Args:
            execution_path: Path to execution directory
            playbook: Playbook definition
            summary: Execution summary data
        """
        try:
            # Create a markdown report
            report_path = os.path.join(execution_path, "report.md")
            
            with open(report_path, "w") as f:
                f.write(f"# Playbook Execution Report\n\n")
                f.write(f"## Overview\n\n")
                f.write(f"- **Playbook**: {playbook.name}\n")
                f.write(f"- **Description**: {playbook.description}\n")
                f.write(f"- **Execution ID**: {summary['execution_id']}\n")
                f.write(f"- **Status**: {summary['status'].upper()}\n")
                
                # Format timestamps
                start_time = datetime.datetime.fromtimestamp(summary['start_time']).strftime("%Y-%m-%d %H:%M:%S")
                end_time = datetime.datetime.fromtimestamp(summary['end_time']).strftime("%Y-%m-%d %H:%M:%S")
                duration = summary['end_time'] - summary['start_time']
                
                f.write(f"- **Start Time**: {start_time}\n")
                f.write(f"- **End Time**: {end_time}\n")
                f.write(f"- **Duration**: {duration:.2f} seconds\n")
                
                # Actions summary
                f.write(f"\n## Actions Summary\n\n")
                
                for i, action in enumerate(summary['actions']):
                    status = action['status'].upper()
                    status_indicator = "✅" if status == "COMPLETED" else "❌" if status == "FAILED" else "⚠️"
                    
                    f.write(f"### {i+1}. {action['action_id']} {status_indicator}\n\n")
                    
                    # Action details
                    if action.get('error'):
                        f.write(f"**Error**: {action['error']}\n\n")
                    
                    if action.get('output'):
                        f.write(f"**Output**:\n```\n{action['output'][:500]}")
                        if len(action['output']) > 500:
                            f.write("\n... (output truncated)")
                        f.write("\n```\n\n")
                    
                    if action.get('details'):
                        f.write("**Details**:\n\n")
                        for k, v in action['details'].items():
                            f.write(f"- {k}: {v}\n")
                    
                    f.write("\n")
                
                # Final status
                if summary['status'] == "completed":
                    f.write("\n## Result: All actions completed successfully ✅\n")
                elif summary['status'] == "partial":
                    f.write("\n## Result: Some actions completed with issues ⚠️\n")
                else:
                    f.write("\n## Result: Execution failed ❌\n")
            
            logger.info(f"Created summary report at {report_path}")
            
        except Exception as e:
            logger.error(f"Error creating summary report: {e}")


# Create a singleton executor
_playbook_executor = None

def get_playbook_executor(config: Dict[str, Any] = None) -> PlaybookExecutor:
    """
    Get or create the singleton PlaybookExecutor
    
    Args:
        config: Optional configuration
        
    Returns:
        PlaybookExecutor instance
    """
    global _playbook_executor
    
    if _playbook_executor is None:
        if config is None:
            # Use default config
            config = {
                "sandbox_type": ExecutionEnvironment.SUBPROCESS.value,
                "execution_dir": "/tmp/asira/execution",
                "playbook_dir": os.environ.get("ASIRA_PLAYBOOK_DIR", "/etc/asira/playbooks"),
                "max_execution_time": 300
            }
        
        _playbook_executor = PlaybookExecutor(config)
    
    return _playbook_executor


# Module version and info
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 19:10:34"
__author__ = "Rahul"
