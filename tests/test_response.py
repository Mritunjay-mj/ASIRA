"""
Unit tests for ASIRA response module

These tests verify the functionality of the response engine, 
playbook executor, and sandbox environments.

Version: 1.0.0
Last updated: 2025-03-15 12:27:24
Last updated by: Mritunjay-mj
"""

import os
import unittest
import tempfile
import uuid
import json
import yaml
from unittest.mock import patch, MagicMock, mock_open
import datetime

from src.response.executor import PlaybookExecutor, SandboxManager, CredentialManager
from src.response.playbooks.base import (
    PlaybookDefinition, 
    ActionDefinition, 
    ActionStatus, 
    ActionType,
    ActionResult,
    PlaybookRegistry
)


class TestActionDefinition(unittest.TestCase):
    """Test cases for the ActionDefinition class"""
    
    def test_command_action_validation(self):
        """Test validation of a command action"""
        # Valid command action
        action = ActionDefinition(
            id="test_action",
            type=ActionType.COMMAND,
            description="Test command action",
            command="echo 'Hello World'"
        )
        
        self.assertTrue(action.validate())
        
        # Invalid command action (missing command)
        action = ActionDefinition(
            id="test_action",
            type=ActionType.COMMAND,
            description="Test command action"
        )
        
        self.assertFalse(action.validate())
    
    def test_api_action_validation(self):
        """Test validation of an API action"""
        # Valid API action
        action = ActionDefinition(
            id="test_api",
            type=ActionType.API_CALL,
            description="Test API action",
            api_endpoint="https://api.example.com/test",
            api_method="GET"
        )
        
        self.assertTrue(action.validate())
        
        # Invalid API action (missing endpoint)
        action = ActionDefinition(
            id="test_api",
            type=ActionType.API_CALL,
            description="Test API action",
            api_method="GET"
        )
        
        self.assertFalse(action.validate())
    
    def test_command_injection_validation(self):
        """Test validation catches command injection attempts"""
        # Action with command injection attempt
        action = ActionDefinition(
            id="test_action",
            type=ActionType.COMMAND,
            description="Test command action",
            command="echo 'Hello'; rm -rf /tmp"
        )
        
        self.assertFalse(action.validate())


class TestPlaybookDefinition(unittest.TestCase):
    """Test cases for the PlaybookDefinition class"""
    
    def test_playbook_validation(self):
        """Test validation of a playbook definition"""
        # Create a valid action
        action = ActionDefinition(
            id="test_action",
            type=ActionType.COMMAND,
            description="Test command action",
            command="echo 'Hello World'"
        )
        
        # Create a valid playbook
        playbook = PlaybookDefinition(
            id="test_playbook",
            name="Test Playbook",
            description="A test playbook",
            actions=[action],
            execution_mode="sequential"
        )
        
        self.assertTrue(playbook.validate())
        
        # Test invalid execution mode
        playbook.execution_mode = "invalid_mode"
        self.assertFalse(playbook.validate())
    
    def test_playbook_to_dict(self):
        """Test conversion of playbook to dictionary"""
        # Create a sample playbook
        action = ActionDefinition(
            id="test_action",
            type=ActionType.COMMAND,
            description="Test command action",
            command="echo 'Hello World'"
        )
        
        playbook = PlaybookDefinition(
            id="test_playbook",
            name="Test Playbook",
            description="A test playbook",
            actions=[action],
            execution_mode="sequential",
            tags=["test", "demo"]
        )
        
        # Convert to dictionary
        result = playbook.to_dict()
        
        # Verify the result
        self.assertEqual(result["id"], "test_playbook")
        self.assertEqual(result["name"], "Test Playbook")
        self.assertEqual(len(result["actions"]), 1)
        self.assertEqual(result["actions"][0]["id"], "test_action")
        self.assertEqual(result["execution_mode"], "sequential")
        self.assertEqual(result["tags"], ["test", "demo"])
    
    def test_from_dict(self):
        """Test creating a playbook from dictionary"""
        # Sample dictionary representation
        data = {
            "id": "test_playbook",
            "name": "Test Playbook",
            "description": "A test playbook",
            "execution_mode": "sequential",
            "actions": [
                {
                    "id": "test_action",
                    "type": "command",
                    "description": "Test command action",
                    "command": "echo 'Hello World'"
                }
            ],
            "tags": ["test", "demo"]
        }
        
        # Create playbook from dictionary
        playbook = PlaybookDefinition.from_dict(data)
        
        # Verify the result
        self.assertEqual(playbook.id, "test_playbook")
        self.assertEqual(playbook.name, "Test Playbook")
        self.assertEqual(len(playbook.actions), 1)
        self.assertEqual(playbook.actions[0].id, "test_action")
        self.assertEqual(playbook.execution_mode, "sequential")
        self.assertEqual(playbook.tags, ["test", "demo"])


class TestActionResult(unittest.TestCase):
    """Test cases for the ActionResult class"""
    
    def test_action_result_initialization(self):
        """Test initialization of an action result"""
        result = ActionResult(
            action_id="test_action",
            status=ActionStatus.COMPLETED
        )
        
        self.assertEqual(result.action_id, "test_action")
        self.assertEqual(result.status, ActionStatus.COMPLETED)
        self.assertIsNone(result.output)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.start_time)  # Should be auto-populated
    
    def test_to_dict(self):
        """Test conversion to dictionary"""
        start_time = datetime.datetime(2025, 3, 15, 12, 27, 24)
        end_time = datetime.datetime(2025, 3, 15, 12, 27, 30)
        
        result = ActionResult(
            action_id="test_action",
            status=ActionStatus.COMPLETED,
            output="Action output",
            error=None,
            start_time=start_time,
            end_time=end_time
        )
        
        # Convert to dictionary
        result_dict = result.to_dict()
        
        # Verify the result
        self.assertEqual(result_dict["action_id"], "test_action")
        self.assertEqual(result_dict["status"], "completed")
        self.assertEqual(result_dict["output"], "Action output")
        self.assertEqual(result_dict["start_time"], start_time.isoformat())
        self.assertEqual(result_dict["end_time"], end_time.isoformat())
    
    def test_add_artifact(self):
        """Test adding an artifact to the result"""
        result = ActionResult(
            action_id="test_action",
            status=ActionStatus.COMPLETED
        )
        
        # Add an artifact
        result.add_artifact(
            name="test_artifact",
            description="A test artifact",
            value="artifact_data",
            artifact_type="data"
        )
        
        # Verify the artifact was added
        self.assertEqual(len(result.artifacts), 1)
        self.assertEqual(result.artifacts[0]["name"], "test_artifact")
        self.assertEqual(result.artifacts[0]["description"], "A test artifact")
        self.assertEqual(result.artifacts[0]["value"], "artifact_data")
        self.assertEqual(result.artifacts[0]["type"], "data")


class TestSandboxManager(unittest.TestCase):
    """Test cases for the SandboxManager class"""
    
    def setUp(self):
        """Set up test environment"""
        self.sandbox_manager = SandboxManager("subprocess")
    
    def test_create_sandbox(self):
        """Test creation of a sandbox environment"""
        execution_id = str(uuid.uuid4())
        
        sandbox_info = self.sandbox_manager.create_sandbox(execution_id)
        
        self.assertEqual(sandbox_info["id"], execution_id)
        self.assertEqual(sandbox_info["type"], "subprocess")
        self.assertTrue(os.path.exists(sandbox_info["path"]))
        
        # Clean up
        self.sandbox_manager.cleanup_sandbox(execution_id)
    
    @patch("subprocess.Popen")
    def test_execute_in_sandbox(self, mock_popen):
        """Test command execution in a sandbox"""
        # Setup mock
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = ("Command output", "")
        mock_popen.return_value = mock_process
        
        # Create sandbox
        execution_id = str(uuid.uuid4())
        sandbox_info = self.sandbox_manager.create_sandbox(execution_id)
        
        # Execute command
        result = self.sandbox_manager.execute_in_sandbox(
            sandbox_info,
            "echo 'Hello World'",
            timeout=10
        )
        
        # Verify the result
        self.assertTrue(result["success"])
        self.assertEqual(result["output"], "Command output")
        self.assertEqual(result["return_code"], 0)
        
        # Clean up
        self.sandbox_manager.cleanup_sandbox(execution_id)
    
    def test_cleanup_sandbox(self):
        """Test cleanup of a sandbox environment"""
        execution_id = str(uuid.uuid4())
        
        # Create sandbox
        sandbox_info = self.sandbox_manager.create_sandbox(execution_id)
        sandbox_path = sandbox_info["path"]
        
        # Verify sandbox directory exists
        self.assertTrue(os.path.exists(sandbox_path))
        
        # Clean up
        result = self.sandbox_manager.cleanup_sandbox(execution_id)
        
        # Verify cleanup was successful
        self.assertTrue(result)
        
        # Verify sandbox directory was removed
        self.assertFalse(os.path.exists(sandbox_path))


class TestCredentialManager(unittest.TestCase):
    """Test cases for the CredentialManager class"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            "vault_enabled": False,
            "credentials": {
                "test_cred": "test_value",
                "api_key": "secret_api_key"
            }
        }
        self.credential_manager = CredentialManager(self.config)
    
    def test_get_credential_from_config(self):
        """Test retrieving a credential from config"""
        # Get an existing credential
        cred = self.credential_manager.get_credential("test_cred")
        self.assertEqual(cred, "test_value")
        
        # Get a non-existent credential
        cred = self.credential_manager.get_credential("non_existent")
        self.assertIsNone(cred)
    
    @patch.dict(os.environ, {"ASIRA_CREDENTIAL_ENV_CRED": "env_value"})
    def test_get_credential_from_env(self):
        """Test retrieving a credential from environment variable"""
        cred = self.credential_manager.get_credential("env_cred")
        self.assertEqual(cred, "env_value")
    
    def test_get_token(self):
        """Test retrieving a token"""
        # Add a token to the config
        self.credential_manager.config["credentials"]["token_service1"] = "service1_token"
        
        # Get the token
        token = self.credential_manager.get_token("service1")
        self.assertEqual(token, "service1_token")
    
    def test_clear_cache(self):
        """Test clearing the credential cache"""
        # Add a credential to the cache
        self.credential_manager.get_credential("test_cred")  # This will cache the credential
        self.assertIn("test_cred", self.credential_manager.cache)
        
        # Clear the cache
        self.credential_manager.clear_cache()
        self.assertEqual(len(self.credential_manager.cache), 0)


class TestPlaybookExecutor(unittest.TestCase):
    """Test cases for the PlaybookExecutor class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.playbook_dir = os.path.join(self.temp_dir, "playbooks")
        self.execution_dir = os.path.join(self.temp_dir, "execution")
        
        os.makedirs(self.playbook_dir, exist_ok=True)
        os.makedirs(self.execution_dir, exist_ok=True)
        
        # Create executor config
        self.config = {
            "playbook_dir": self.playbook_dir,
            "execution_dir": self.execution_dir,
            "max_execution_time": 30,
            "sandbox_type": "subprocess"
        }
        
        # Create executor
        self.executor = PlaybookExecutor(self.config)
        
        # Create a test playbook file
        self.playbook_id = "test_playbook"
        self.playbook_data = {
            "id": self.playbook_id,
            "name": "Test Playbook",
            "description": "A test playbook",
            "execution_mode": "sequential",
            "actions": [
                {
                    "id": "test_action1",
                    "type": "command",
                    "description": "Test command action",
                    "command": "echo 'Hello {incident.id}'"
                },
                {
                    "id": "test_action2",
                    "type": "command",
                    "description": "Another test action",
                    "command": "ls -la"
                }
            ]
        }
        
        # Write test playbook to file
        playbook_path = os.path.join(self.playbook_dir, f"{self.playbook_id}.yml")
        with open(playbook_path, "w") as f:
            yaml.dump(self.playbook_data, f)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_load_playbook(self):
        """Test loading a playbook from file"""
        playbook = self.executor._load_playbook(self.playbook_id)
        
        self.assertIsNotNone(playbook)
        self.assertEqual(playbook.id, self.playbook_id)
        self.assertEqual(playbook.name, "Test Playbook")
        self.assertEqual(len(playbook.actions), 2)
    
    def test_prepare_execution_context(self):
        """Test preparing execution context"""
        execution_id = "test_execution"
        incident_data = {
            "id": "inc_123",
            "title": "Test Incident",
            "severity": "high"
        }
        
        context = self.executor._prepare_execution_context(execution_id, incident_data)
        
        self.assertIn("execution", context)
        self.assertEqual(context["execution"]["id"], execution_id)
        self.assertIn("incident", context)
        self.assertEqual(context["incident"]["id"], "inc_123")
        self.assertIn("env", context)
        self.assertIn("helpers", context)
    
    @patch("src.response.executor.SandboxManager.execute_in_sandbox")
    def test_execute_command_action(self, mock_execute):
        """Test execution of a command action"""
        # Mock the sandbox execution
        mock_execute.return_value = {
            "success": True,
            "output": "Hello inc_123",
            "error": "",
            "return_code": 0,
            "execution_time": 0.1
        }
        
        # Create action and context
        action = ActionDefinition(
            id="test_action",
            type=ActionType.COMMAND,
            description="Test command action",
            command="echo 'Hello {incident.id}'"
        )
        
        context = {
            "execution": {"id": "test_execution"},
            "incident": {"id": "inc_123"},
            "env": {}
        }
        
        # Create sandbox info
        sandbox_info = {"type": "subprocess", "path": "/tmp"}
        
        # Execute the action
        with patch("src.response.executor.PlaybookExecutor._render_template", return_value="echo 'Hello inc_123'"):
            with patch("src.response.executor.PlaybookExecutor._process_variables", return_value=action):
                result = self.executor._execute_action(action, context, sandbox_info)
        
        # Verify the result
        self.assertEqual(result.action_id, "test_action")
        self.assertEqual(result.status, ActionStatus.IN_PROGRESS)  # Status from mock
    
    @patch("src.response.executor.SandboxManager.execute_in_sandbox")
    def test_execute_playbook(self, mock_execute):
        """Test execution of a complete playbook"""
        # Mock the sandbox execution
        mock_execute.return_value = {
            "success": True,
            "output": "Command output",
            "error": "",
            "return_code": 0,
            "execution_time": 0.1
        }
        
        # Create incident data
        incident_data = {
            "id": "inc_123",
            "title": "Test Incident",
            "severity": "high"
        }
        
        # Override _execute_action to avoid actual execution
        with patch("src.response.executor.PlaybookExecutor._execute_action") as mock_execute_action:
            # Set up mock return value for _execute_action
            mock_execute_action.return_value = ActionResult(
                action_id="test_action",
                status=ActionStatus.COMPLETED,
                output="Action output",
                start_time=datetime.datetime.now(),
                end_time=datetime.datetime.now()
            )
            
            # Execute the playbook
            result = self.executor.execute_playbook(self.playbook_id, incident_data)
        
        # Verify the result
        self.assertIn("execution_id", result)
        self.assertEqual(result["playbook_id"], self.playbook_id)
        self.assertEqual(result["incident_id"], "inc_123")
        self.assertIn("start_time", result)
        self.assertIn("end_time", result)
        self.assertEqual(result["status"], "completed")
        self.assertIn("actions", result)
        self.assertEqual(len(result["actions"]), 2)


class TestPlaybookRegistry(unittest.TestCase):
    """Test cases for the PlaybookRegistry class"""
