"""
Log normalizers for ASIRA
Transform logs into a standard format for analysis

Current version: 1.0.0
Last updated: 2025-03-15 12:03:04
"""
import re
import json
import time
import logging
import asyncio
import datetime
from typing import Dict, Any, List, Optional, Union, Callable, Pattern
from abc import ABC, abstractmethod

# Initialize logger
logger = logging.getLogger("asira.data.normalizers")

class LogNormalizer(ABC):
    """
    Base class for log normalizers
    Defines common interface and helper methods
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the normalizer with configuration
        
        Args:
            config: Normalizer configuration
        """
        self.config = config
        self.name = config.get("name", self.__class__.__name__)
        self.enabled = config.get("enabled", True)
        
        logger.info(f"Initialized {self.name} normalizer")
    
    @abstractmethod
    async def normalize(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a log entry
        
        Args:
            log: Raw log entry
            
        Returns:
            Normalized log entry or None if log should be filtered out
        """
        pass


class GenericLogNormalizer(LogNormalizer):
    """
    Generic log normalizer that can handle various formats
    Uses regex patterns and field mappings
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the generic log normalizer
        
        Args:
            config: Normalizer configuration with these additional fields:
                - patterns: List of regex patterns with named capture groups
                - field_mappings: Mapping of source fields to standardized fields
                - timestamp_formats: List of timestamp formats to try
                - timezone: Timezone for timestamps
        """
        super().__init__(config)
        self.patterns = []
        self.field_mappings = config.get("field_mappings", {})
        self.timestamp_formats = config.get("timestamp_formats", [])
        self.timezone = config.get("timezone", "UTC")
        
        # Compile regex patterns
        for pattern in config.get("patterns", []):
            try:
                self.patterns.append(re.compile(pattern))
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern}': {e}")
        
        logger.info(f"GenericLogNormalizer initialized with {len(self.patterns)} patterns")
    
    async def normalize(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a log entry using regex patterns and field mappings
        
        Args:
            log: Raw log entry
            
        Returns:
            Normalized log entry or None if log doesn't match any pattern
        """
        if not self.enabled:
            return log
            
        # Check if log has a message field
        if "message" not in log:
            logger.debug("Log entry has no message field")
            return log
            
        message = log["message"]
        normalized = {"raw_message": message}
        
        # Copy metadata fields
        for key in log:
            if key.startswith("_"):
                normalized[key] = log[key]
        
        # Try to match message against patterns
        matched = False
        for pattern in self.patterns:
            match = pattern.search(message)
            if match:
                # Extract fields from match
                fields = match.groupdict()
                for field_name, value in fields.items():
                    if value is not None:  # Skip None values
                        # Map field name if a mapping exists
                        dest_name = self.field_mappings.get(field_name, field_name)
                        normalized[dest_name] = value
                        
                matched = True
                break
        
        # If no pattern matched, return original log
        if not matched:
            return log
            
        # Parse timestamp if present
        if "timestamp" in normalized and self.timestamp_formats:
            timestamp_str = normalized["timestamp"]
            parsed = False
