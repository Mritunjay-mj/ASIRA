"""
Response Playbooks Module

Provides components for defining, managing, and executing automated response playbooks
for security incident handling. Playbooks define structured sets of actions to be
performed in response to detected security incidents.

Version: 1.0.0
Last updated: 2025-03-15 19:13:35
Last updated by: Rahul
"""

import logging
import os
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

__version__ = "1.0.0"
__author__ = "Mritunjay-mj"

# Set up module-level logger
logger = logging.getLogger("asira.response.playbooks")

# Default playbooks directory
DEFAULT_PLAYBOOKS_DIR = os.environ.get("ASIRA_PLAYBOOKS_DIR", "/etc/asira/playbooks")

# Import key components
try:
    from .base import (
        PlaybookDefinition, 
        ActionDefinition, 
        ActionResult, 
        ActionStatus, 
        ActionType
    )
    from .loader import (
        load_playbook,
        list_available_playbooks,
        validate_playbook
    )
    from .manager import (
        PlaybookManager,
        get_playbook_manager
    )
except ImportError as e:
    logger.warning(f"Error importing playbook components: {e}")


# Convenience function to get a playbook by ID
def get_playbook(playbook_id: str, playbooks_dir: Optional[str] = None) -> Optional[PlaybookDefinition]:
    """
    Get a playbook by ID
    
    Args:
        playbook_id: ID of the playbook to retrieve
        playbooks_dir: Optional directory to search for playbooks
        
    Returns:
        Playbook definition or None if not found
    """
    from .loader import load_playbook
    
    playbooks_dir = playbooks_dir or DEFAULT_PLAYBOOKS_DIR
    return load_playbook(playbook_id, playbooks_dir)


# Convenience function to create a new playbook
def create_playbook(
    id: str, 
    name: str,
    description: str,
    actions: List[ActionDefinition],
    execution_mode: str = "sequential",
    enabled: bool = True,
    tags: List[str] = None,
    target_severity: List[str] = None
) -> PlaybookDefinition:
    """
    Create a new playbook definition
    
    Args:
        id: Unique identifier for the playbook
        name: Human-readable name
        description: Description of the playbook
        actions: List of actions to execute
        execution_mode: Mode of execution (sequential or parallel)
        enabled: Whether the playbook is enabled
        tags: Optional tags for categorization
        target_severity: List of severity levels this playbook targets
        
    Returns:
        New playbook definition
    """
    from .base import PlaybookDefinition
    
    return PlaybookDefinition(
        id=id,
        name=name,
        description=description,
        actions=actions,
        execution_mode=execution_mode,
        enabled=enabled,
        tags=tags or [],
        target_severity=target_severity or []
    )


# Convenience function to create a new action
def create_action(
    id: str,
    type: str,
    description: str = "",
    **kwargs
) -> ActionDefinition:
    """
    Create a new action definition
    
    Args:
        id: Unique identifier for the action
        type: Action type (command, api_call, script, notification, containment, enrichment)
        description: Description of the action
        **kwargs: Additional action parameters
        
    Returns:
        New action definition
    """
    from .base import ActionDefinition, ActionType
    
    # Validate action type
    action_type = None
    for t in ActionType:
        if t.value == type:
            action_type = t
            break
    
    if action_type is None:
        raise ValueError(f"Invalid action type: {type}")
    
    return ActionDefinition(
        id=id,
        type=type,
        description=description,
        **kwargs
    )


# Utility function to find all playbooks matching certain criteria
def find_playbooks(
    tags: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    enabled_only: bool = True,
    playbooks_dir: Optional[str] = None
) -> List[PlaybookDefinition]:
    """
    Find playbooks matching the specified criteria
    
    Args:
        tags: Optional list of tags to match
        severity: Optional list of severity levels to match
        enabled_only: Whether to only include enabled playbooks
        playbooks_dir: Optional directory to search for playbooks
        
    Returns:
        List of matching playbooks
    """
    from .loader import list_available_playbooks, load_playbook
    
    playbooks_dir = playbooks_dir or DEFAULT_PLAYBOOKS_DIR
    playbook_ids = list_available_playbooks(playbooks_dir)
    results = []
    
    for playbook_id in playbook_ids:
        try:
            playbook = load_playbook(playbook_id, playbooks_dir)
            
            # Skip disabled playbooks if enabled_only is True
            if enabled_only and not playbook.enabled:
                continue
                
            # Check tags
            if tags and not any(tag in playbook.tags for tag in tags):
                continue
                
            # Check severity
            if severity and not any(sev in playbook.target_severity for sev in severity):
                continue
                
            results.append(playbook)
        except Exception as e:
            logger.warning(f"Error loading playbook {playbook_id}: {e}")
    
    return results


# Initialize the playbook manager when the module is imported
try:
    from .manager import get_playbook_manager
    playbook_manager = get_playbook_manager()
    logger.debug(f"Initialized playbook manager with {len(playbook_manager.get_available_playbooks())} playbooks")
except Exception as e:
    logger.warning(f"Failed to initialize playbook manager: {e}")
    playbook_manager = None
