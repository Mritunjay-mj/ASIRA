"""
ASIRA Response Executor
Handles secure execution of playbooks in response to security incidents

The executor manages the secure execution environment, credentials handling,
action verification, and result documentation for response playbooks.

Version: 1.0.0
Last updated: 2025-03-15 12:14:58
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
    
    def _render_template(self, template_str: str, context: Dict[str, Any
