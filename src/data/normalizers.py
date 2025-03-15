"""
Log normalizers for ASIRA
Transform logs into a standard format for analysis

Current version: 1.0.0
Last updated: 2025-03-15 17:45:57
Last updated by: Rahul
"""
import re
import json
import time
import logging
import asyncio
import datetime
import hashlib
import ipaddress
import uuid
from typing import Dict, Any, List, Optional, Union, Callable, Pattern, Tuple, Set
from abc import ABC, abstractmethod
import dateutil.parser
from dateutil import tz

# Initialize logger
from src.common.logging_config import get_logger
logger = get_logger("asira.data.normalizers")

# Import settings if available
try:
    from src.common.config import settings
except ImportError:
    settings = None
    logger.warning("Settings module not available, using default values")

# Standard normalized log fields
STANDARD_FIELDS = {
    'timestamp': 'float',  # Unix timestamp
    'source_ip': 'str',
    'source_port': 'int',
    'dest_ip': 'str',
    'dest_port': 'int',
    'protocol': 'str',
    'action': 'str',     # allow, deny, alert, etc.
    'status': 'str',     # success, failure, error, etc.
    'severity': 'str',   # info, warning, error, critical
    'event_type': 'str', # login, access, network, process, etc.
    'user': 'str',       # username
    'hostname': 'str',
    'process': 'str',
    'command': 'str',
    'duration': 'float',
    'bytes_in': 'int',
    'bytes_out': 'int',
    'url': 'str',
    'domain': 'str',
    'method': 'str',     # HTTP method
    'status_code': 'int',
    'user_agent': 'str',
    'session_id': 'str',
    'source_location': 'str',
    'dest_location': 'str'
}

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
        self.include_raw = config.get("include_raw", True)
        self.drop_fields = set(config.get("drop_fields", []))
        self.enrich_geoip = config.get("enrich_geoip", False)
        self.enrich_hostinfo = config.get("enrich_hostinfo", False)
        self.normalize_count = 0
        self.error_count = 0
        self.start_time = time.time()
        
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
    
    def parse_timestamp(self, timestamp_str: str, formats: List[str] = None) -> Optional[float]:
        """
        Parse a timestamp string into a Unix timestamp
        
        Args:
            timestamp_str: Timestamp string
            formats: List of timestamp formats to try
            
        Returns:
            Unix timestamp or None if parsing failed
        """
        if not timestamp_str:
            return None
            
        # Try dateutil parser first (handles many formats)
        try:
            dt = dateutil.parser.parse(timestamp_str)
            # Convert to UTC if not timezone-aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=tz.tzutc())
            return dt.timestamp()
        except (ValueError, OverflowError):
            pass
        
        # Try specific formats if provided
        if formats:
            for fmt in formats:
                try:
                    dt = datetime.datetime.strptime(timestamp_str, fmt)
                    # Assume UTC if no timezone info
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=tz.tzutc())
                    return dt.timestamp()
                except ValueError:
                    continue
        
        return None
    
    def convert_field_type(self, value: Any, target_type: str) -> Any:
        """
        Convert a value to the specified type
        
        Args:
            value: Value to convert
            target_type: Target type (str, int, float, bool)
            
        Returns:
            Converted value or original if conversion failed
        """
        if value is None:
            return None
            
        try:
            if target_type == 'int':
                # Handle string values that might be floats
                if isinstance(value, str) and '.' in value:
                    return int(float(value))
                return int(value)
            elif target_type == 'float':
                return float(value)
            elif target_type == 'bool':
                if isinstance(value, str):
                    return value.lower() in ('true', 'yes', 'y', '1')
                return bool(value)
            elif target_type == 'str':
                return str(value)
            else:
                return value
        except (ValueError, TypeError):
            return value
    
    def validate_ip(self, ip: str) -> Optional[str]:
        """
        Validate and format an IP address
        
        Args:
            ip: IP address string
            
        Returns:
            Formatted IP address or None if invalid
        """
        if not ip:
            return None
            
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return None
    
    def get_log_id(self, log: Dict[str, Any]) -> str:
        """
        Generate a deterministic ID for a log entry
        
        Args:
            log: Log entry
            
        Returns:
            Log ID
        """
        if "_id" in log:
            return log["_id"]
            
        # Create a deterministic ID from log content
        content = json.dumps(log, sort_keys=True)
        log_hash = hashlib.md5(content.encode()).hexdigest()
        timestamp = int(time.time())
        
        return f"log_{timestamp}_{log_hash}"
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get normalizer statistics
        
        Returns:
            Statistics dictionary
        """
        uptime = time.time() - self.start_time
        return {
            "name": self.name,
            "type": self.__class__.__name__,
            "enabled": self.enabled,
            "normalize_count": self.normalize_count,
            "error_count": self.error_count,
            "uptime": uptime,
            "rate": self.normalize_count / uptime if uptime > 0 else 0
        }


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
        self.type_mappings = config.get("type_mappings", {})
        
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
            
        try:
            message = log["message"]
            normalized = {}
            
            # Preserve raw message if configured
            if self.include_raw:
                normalized["raw_message"] = message
            
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
                            
                            # Convert field type if specified
                            if dest_name in self.type_mappings:
                                value = self.convert_field_type(value, self.type_mappings[dest_name])
                            elif dest_name in STANDARD_FIELDS:
                                value = self.convert_field_type(value, STANDARD_FIELDS[dest_name])
                                
                            normalized[dest_name] = value
                            
                    matched = True
                    break
            
            # If no pattern matched, return original log
            if not matched:
                return log
                
            # Parse timestamp if present
            if "timestamp" in normalized and self.timestamp_formats:
                timestamp_str = normalized["timestamp"]
                parsed_timestamp = self.parse_timestamp(timestamp_str, self.timestamp_formats)
                
                if parsed_timestamp:
                    normalized["timestamp"] = parsed_timestamp
            
            # Validate IP addresses
            for ip_field in ["source_ip", "dest_ip"]:
                if ip_field in normalized:
                    normalized[ip_field] = self.validate_ip(normalized[ip_field]) or normalized[ip_field]
            
            # Generate a log ID if not present
            if "_id" not in normalized:
                normalized["_id"] = self.get_log_id(normalized)
            
            # Add normalized flag
            normalized["_normalized"] = True
            
            # Update stats
            self.normalize_count += 1
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing log: {e}")
            self.error_count += 1
            return log


class SyslogNormalizer(LogNormalizer):
    """
    Normalizer for syslog format logs
    Handles standard syslog formats (RFC3164 and RFC5424)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the syslog normalizer
        
        Args:
            config: Normalizer configuration
        """
        super().__init__(config)
        
        # RFC3164 pattern: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG: MSG
        self.rfc3164_pattern = re.compile(
            r"^<(\d+)>(?:\d+ )?(?:(\w{3}\s+\d{1,2}\s+\d{1,2}:\d{1,2}:\d{1,2})|(\d{4}-\d{2}-\d{2}T\d{1,2}:\d{1,2}:\d{1,2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)) (\S+) (\S+): (.*)",
            re.DOTALL
        )
        
        # RFC5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        self.rfc5424_pattern = re.compile(
            r"^<(\d+)>(\d+) (\d{4}-\d{2}-\d{2}T\d{1,2}:\d{1,2}:\d{1,2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?) (\S+) (\S+) (\S+) (\S+) (\[.*?\]|-)? ?(.*)",
            re.DOTALL
        )
        
        # Timestamp formats
        self.timestamp_formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%b %d %H:%M:%S",
            "%b %d %H:%M:%S %Y"
        ]
        
        # Facility and severity mappings
        self.facilities = {
            0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
            6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv",
            11: "ftp", 12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
            16: "local0", 17: "local1", 18: "local2", 19: "local3",
            20: "local4", 21: "local5", 22: "local6", 23: "local7"
        }
        
        self.severities = {
            0: "emergency", 1: "alert", 2: "critical", 3: "error",
            4: "warning", 5: "notice", 6: "info", 7: "debug"
        }
        
        logger.info(f"SyslogNormalizer initialized")
    
    def _parse_priority(self, pri_str: str) -> Tuple[str, str]:
        """
        Parse syslog priority value
        
        Args:
            pri_str: Priority value as string
            
        Returns:
            Tuple of (facility, severity)
        """
        try:
            pri = int(pri_str)
            facility = pri // 8
            severity = pri % 8
            
            facility_name = self.facilities.get(facility, f"facility{facility}")
            severity_name = self.severities.get(severity, f"severity{severity}")
            
            return facility_name, severity_name
        except (ValueError, TypeError):
            return "unknown", "unknown"
    
    async def normalize(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a syslog message
        
        Args:
            log: Raw log entry
            
        Returns:
            Normalized log entry
        """
        if not self.enabled:
            return log
            
        # Check if log has a message field
        if "message" not in log:
            return log
            
        try:
            message = log["message"]
            normalized = {}
            
            # Preserve raw message if configured
            if self.include_raw:
                normalized["raw_message"] = message
            
            # Copy metadata fields
            for key in log:
                if key.startswith("_"):
                    normalized[key] = log[key]
            
            # Try to match RFC5424 format first (more structured)
            match = self.rfc5424_pattern.search(message)
            if match:
                pri, version, timestamp, hostname, app_name, proc_id, msg_id, structured_data, msg = match.groups()
                
                # Parse priority
                facility, severity = self._parse_priority(pri)
                
                # Build normalized log
                normalized.update({
                    "timestamp": self.parse_timestamp(timestamp, self.timestamp_formats),
                    "hostname": hostname,
                    "application": app_name,
                    "process": proc_id if proc_id != "-" else None,
                    "message": msg,
                    "severity": severity,
                    "facility": facility,
                    "syslog_version": version,
                    "msg_id": msg_id if msg_id != "-" else None
                })
                
                # Parse structured data if present
                if structured_data and structured_data != "-":
                    normalized["structured_data"] = structured_data
                
            else:
                # Try RFC3164 format
                match = self.rfc3164_pattern.search(message)
                if match:
                    pri, timestamp1, timestamp2, hostname, tag, msg = match.groups()
                    timestamp = timestamp1 or timestamp2
                    
                    # Parse priority
                    facility, severity = self._parse_priority(pri)
                    
                    # Extract process and PID from tag (often in format "process[pid]:")
                    process_match = re.match(r"([^\[]+)(?:\[(\d+)\])?", tag)
                    process = tag
                    pid = None
                    
                    if process_match:
                        process = process_match.group(1)
                        pid = process_match.group(2)
                    
                    # Build normalized log
                    normalized.update({
                        "timestamp": self.parse_timestamp(timestamp, self.timestamp_formats),
                        "hostname": hostname,
                        "process": process,
                        "pid": pid,
                        "message": msg,
                        "severity": severity,
                        "facility": facility
                    })
                else:
                    # No match, return original
                    return log
            
            # Extract IP addresses if present in the message
            ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", message)
            if ip_matches:
                # Validate each IP
                valid_ips = [ip for ip in ip_matches if self.validate_ip(ip)]
                if valid_ips:
                    # Assign first IP as source IP if not already set
                    if "source_ip" not in normalized:
                        normalized["source_ip"] = valid_ips[0]
                    
                    # If we have more than one IP, assign second as dest IP
                    if len(valid_ips) > 1 and "dest_ip" not in normalized:
                        normalized["dest_ip"] = valid_ips[1]
            
            # Map event types based on process/facility
            if "process" in normalized:
                process = normalized["process"].lower()
                if "ssh" in process or "sshd" in process:
                    normalized["event_type"] = "auth"
                elif "auth" in process or "login" in process:
                    normalized["event_type"] = "auth"
                elif "firewall" in process or "iptables" in process:
                    normalized["event_type"] = "firewall"
                elif "nginx" in process or "apache" in process:
                    normalized["event_type"] = "webserver"
                elif "kernel" in process:
                    normalized["event_type"] = "system"
            
            # Generate a log ID if not present
            if "_id" not in normalized:
                normalized["_id"] = self.get_log_id(normalized)
            
            # Add normalized flag
            normalized["_normalized"] = True
            
            # Update stats
            self.normalize_count += 1
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing syslog message: {e}")
            self.error_count += 1
            return log


class JSONLogNormalizer(LogNormalizer):
    """
    Normalizer for JSON format logs
    Maps JSON fields to standardized fields
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the JSON normalizer
        
        Args:
            config: Normalizer configuration with these additional fields:
                - field_mappings: Mapping of source fields to standardized fields
                - timestamp_field: Field containing the timestamp
                - timestamp_formats: List of timestamp formats to try
                - nested_separator: Character used to flatten nested objects
        """
        super().__init__(config)
        self.field_mappings = config.get("field_mappings", {})
        self.timestamp_field = config.get("timestamp_field", "timestamp")
        self.timestamp_formats = config.get("timestamp_formats", [])
        self.nested_separator = config.get("nested_separator", ".")
        self.type_mappings = config.get("type_mappings", {})
        self.array_fields = set(config.get("array_fields", []))
        
        logger.info(f"JSONLogNormalizer initialized")
    
    def _flatten_json(self, data: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Flatten nested JSON objects
        
        Args:
            data: Nested JSON object
            prefix: Prefix for keys
            
        Returns:
            Flattened dictionary
        """
        items = {}
        for key, value in data.items():
            new_key = f"{prefix}{key}" if prefix else key
            
            if isinstance(value, dict) and new_key not in self.array_fields:
                # Recursively flatten nested dictionaries
                nested = self._flatten_json(value, f"{new_key}{self.nested_separator}")
                items.update(nested)
            else:
                # Keep the value as is
                items[new_key] = value
                
        return items
    
    async def normalize(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a JSON log entry
        
        Args:
            log: Raw log entry
            
        Returns:
            Normalized log entry
        """
        if not self.enabled:
            return log
            
        try:
            normalized = {}
            
            # Check if log has a message field that might contain JSON
            if "message" in log and isinstance(log["message"], str):
                try:
                    # Try to parse message as JSON
                    json_data = json.loads(log["message"])
                    
                    # If successful, use that as our source data
                    source_data = json_data
                    
                    # Keep original message if configured
                    if self.include_raw:
                        normalized["raw_message"] = log["message"]
                        
                except (json.JSONDecodeError, TypeError):
                    # Not valid JSON, use the log as is
                    source_data = log
            else:
                # No message field or not a string, use the log as is
                source_data = log
            
            # Flatten nested structures
            flattened = self._flatten_json(source_data)
            
            # Copy metadata fields
            for key in log:
                if key.startswith("_"):
                    normalized[key] = log[key]
            
            # Map fields according to the field mappings
            for src_field, value in flattened.items():
                # Skip metadata fields
                if src_field.startswith("_"):
                    continue
                    
                # Map field name if mapping exists
                dest_field = self.field_mappings.get(src_field, src_field)
                
                # Skip fields in drop list
                if dest_field in self.drop_fields:
                    continue
                
                # Convert field type if mapping exists
                if dest_field in self.type_mappings:
                    value = self.convert_field_type(value, self.type_mappings[dest_field])
                elif dest_field in STANDARD_FIELDS:
                    value = self.convert_field_type(value, STANDARD_FIELDS[dest_field])
                
                normalized[dest_field] = value
            
            # Parse timestamp if present
            if self.timestamp_field in normalized:
                timestamp_value = normalized[self.timestamp_field]
                
                # If timestamp is already a number, assume it's a Unix timestamp
                if isinstance(timestamp_value, (int, float)):
                    # Check if it's in milliseconds (common in JSON logs)
                    if timestamp_value > 1000000000000:  # Likely milliseconds
                        normalized["timestamp"] = timestamp_value / 1000
                    else:
                        normalized["timestamp"] = timestamp_value
                else:
                    # Try to parse string timestamp
                    parsed_timestamp = self.parse_timestamp(str(timestamp_value), self.timestamp_formats)
                    if parsed_timestamp:
                        normalized["timestamp"] = parsed_timestamp
            
            # Validate IP addresses
            for ip_field in ["source_ip", "dest_ip"]:
                if ip_field in normalized:
                    normalized[ip_field] = self.validate_ip(normalized[ip_field]) or normalized[ip_field]
            
            # Generate a log ID if not present
            if "_id" not in normalized:
                normalized["_id"] = self.get_log_id(normalized)
            
            # Add normalized flag
            normalized["_normalized"] = True
            
            # Update stats
            self.normalize_count += 1
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing JSON log: {e}")
            self.error_count += 1
            return log


class CEFLogNormalizer(LogNormalizer):
    """
    Normalizer for Common Event Format (CEF) logs
    Used by many security products
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the CEF normalizer
        
        Args:
            config: Normalizer configuration
        """
        super().__init__(config)
        
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        self.cef_pattern = re.compile(r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)")
        
        # Extension field parser
        self.extension_pattern = re.compile(r'([a-zA-Z0-9_]+)=((?:[\\]=|[^=])+)(?:\s|$)')
        
        # Common CEF field mappings
        self.field_mappings = config.get("field_mappings", {
            "src": "source_ip",
            "dst": "dest_ip",
            "spt": "source_port",
            "dpt": "dest_port",
            "proto": "protocol",
            "act": "action",
            "outcome": "status",
            "dhost": "dest_hostname",
            "shost": "source_hostname",
            "duser": "dest_user",
            "suser": "source_user",
            "app": "application",
            "deviceDirection": "direction",
            "cat": "category",
            "reason": "reason",
            "request": "url",
            "requestMethod": "method",
            "cs1": "signature",
            "cs2": "rule_name",
            "cn1": "duration"
        })
        
        logger.info(f"CEFLogNormalizer initialized")
    
    def _parse_cef_extensions(self, extensions: str) -> Dict[str, Any]:
        """
        Parse CEF extension fields
        
        Args:
            extensions: CEF extension string
            
        Returns:
            Dictionary of extension fields
        """
        result = {}
        
        # Find all extension fields
        matches = self.extension_pattern.findall(extensions)
        for key, value in matches:
            # Unescape special characters
            value = value.replace("\\=", "=").replace("\\\\", "\\").replace("\\|", "|")
            
            # Convert numeric values
            if key.startswith(("c", "cf", "cn")):
                # Custom fields might be numeric
                try:
                    if "." in value:
                        value = float(value)
                    else:
                        value = int(value)
                except (ValueError, TypeError):
                    pass
                    
            result[key] = value
            
        return result
    
    async def normalize(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a CEF log entry
        
        Args:
            log: Raw log entry
            
        Returns:
            Normalized log entry
        """
        if not self.enabled:
            return log
            
        # Check if log has a message field
        if "message" not in log:
            return log
            
        try:
            message = log["message"]
            normalized = {}
            
            # Preserve raw message if configured
            if self.include_raw:
                normalized["raw_message"] = message
            
            # Copy metadata fields
            for key in log:
                if key.startswith("_"):
                    normalized[key] = log[key]
            
            # Try to match CEF pattern
            match = self.cef_pattern.search(message)
            if not match:
                return log
                
            # Extract CEF components
            version, vendor, product, device_version, sig_id, name, severity, extensions = match.groups()
            
            # Basic CEF fields
            normalized.update({
                "cef_version": version,
                "vendor": vendor,
                "product": product,
                "device_version": device_version,
                "signature_id": sig_id,
                "event_name": name,
                "severity": severity,
                "event_type": "security"
            })
            
            # Parse extensions
            extension_fields = self._parse_cef_extensions(extensions)
            
            # Map extension fields to standardized names
            for key, value in extension_fields.items():
                dest_key = self.field_mappings.get(key, key)
                normalized[dest_key] = value
            
            # Handle timestamp fields
            if "rt" in extension_fields:  # Receipt time
                normalized["timestamp"] = self.parse_timestamp(extension_fields["rt"])
            elif "end" in extension_fields:  # Event end time
                normalized["timestamp"] = self.parse_timestamp(extension_fields["end"])
            elif "start" in extension_fields:  # Event start time
                normalized["timestamp"] = self.parse_timestamp(extension_fields["start"])
            
            # Convert port numbers to integers
            for port_field in ["source_port", "dest_port"]:
                if port_field in normalized and normalized[port_field]:
                    try:
                        normalized[port_field] = int(normalized[port_field])
                    except (ValueError, TypeError):
                        pass
            
            # Validate IP addresses
            for ip_field in ["source_ip", "dest_ip"]:
                if ip_field in normalized:
                    normalized[ip_field] = self.validate_ip(normalized[ip_field]) or normalized[ip_field]
            
            # Handle user fields - often CEF has "suser" for source user
            if "suser" in extension_fields and "user" not in normalized:
                normalized["user"] = extension_fields["suser"]
                
            # Parse and standardize action field
            if "action" in normalized:
                action = normalized["action"].lower()
                if action in ["allow", "permitted", "accept"]:
                    normalized["action"] = "allow"
                elif action in ["block", "deny", "dropped"]:
                    normalized["action"] = "deny"
                elif action in ["alert", "warned"]:
                    normalized["action"] = "alert"
            
            # Generate a log ID if not present
            if "_id" not in normalized:
                normalized["_id"] = self.get_log_id(normalized)
            
            # Add normalized flag
            normalized["_normalized"] = True
            
            # Update stats
            self.normalize_count += 1
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing CEF log: {e}")
            self.error_count += 1
            return log


class WebServerLogNormalizer(LogNormalizer):
    """
    Normalizer for web server logs (Apache, Nginx)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the web server log normalizer
        
        Args:
            config: Normalizer configuration
        """
        super().__init__(config)
        
        # Common Log Format pattern: %h %l %u %t "%r" %>s %b
        # LogFormat "%h %l %u [%{%d/%b/%Y:%H:%M:%S %z}t] \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
        self.clf_pattern = re.compile(
            r'(\S+) (\S+) (\S+) \[(.*?)\] "([^"]*)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?')
        
        # Nginx JSON log pattern
        self.nginx_json_enabled = config.get("nginx_json_enabled", False)
        
        # Extended fields
        self.parse_user_agent = config.get("parse_user_agent", False)
        self.parse_request = config.get("parse_request", True)
        
        logger.info(f"WebServerLogNormalizer initialized")
    
    def _parse_request(self, request: str) -> Tuple[str, str, str]:
        """
        Parse HTTP request line into method, path, and protocol
        
        Args:
            request: HTTP request line
            
        Returns:
            Tuple of (method, path, protocol)
        """
        parts = request.split()
        method = parts[0] if len(parts) > 0 else ""
        path = parts[1] if len(parts) > 1 else ""
        protocol = parts[2] if len(parts) > 2 else ""
        return method, path, protocol
    
    def _parse_user_agent_string(self, user_agent: str) -> Dict[str, str]:
        """
        Parse user agent string into components
        
        Args:
            user_agent: User agent string
            
        Returns:
            Dictionary with user agent components
        """
        try:
            # Very basic parsing - in production, use a proper UA parsing library
            ua_info = {"user_agent": user_agent}
            
            # Browser detection
            if "Chrome" in user_agent and "Safari" in user_agent:
                ua_info["browser"] = "Chrome"
            elif "Firefox" in user_agent:
                ua_info["browser"] = "Firefox"
            elif "Safari" in user_agent:
                ua_info["browser"] = "Safari"
            elif "Edge" in user_agent:
                ua_info["browser"] = "Edge"
            elif "MSIE" in user_agent or "Trident" in user_agent:
                ua_info["browser"] = "Internet Explorer"
            else:
                ua_info["browser"] = "Other"
                
            # OS detection
            if "Windows" in user_agent:
                ua_info["os"] = "Windows"
            elif "Android" in user_agent:
                ua_info["os"] = "Android"
            elif "iPhone" in user_agent or "iPad" in user_agent:
                ua_info["os"] = "iOS"
            elif "Mac OS" in user_agent:
                ua_info["os"] = "macOS"
            elif "Linux" in user_agent:
                ua_info["os"] = "Linux"
            else:
                ua_info["os"] = "Other"
                
            # Mobile detection
            ua_info["is_mobile"] = any(mobile in user_agent for mobile in ["Mobile", "Android", "iPhone", "iPad"])
            
            return ua_info
        except Exception:
            return {"user_agent": user_agent}
    
    async def normalize(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a web server log entry
        
        Args:
            log: Raw log entry
            
        Returns:
            Normalized log entry
        """
        if not self.enabled:
            return log
            
        # Check if log has a message field
        if "message" not in log:
            return log
            
        try:
            message = log["message"]
            normalized = {}
            
            # Preserve raw message if configured
            if self.include_raw:
                normalized["raw_message"] = message
            
            # Copy metadata fields
            for key in log:
                if key.startswith("_"):
                    normalized[key] = log[key]
            
            # Check for JSON format (Nginx with json log format)
            if self.nginx_json_enabled and message.startswith("{"):
                try:
                    # Parse JSON
                    json_data = json.loads(message)
                    
                    # Map fields
                    field_map = {
                        "remote_addr": "source_ip",
                        "remote_user": "user",
                        "time_local": "timestamp",
                        "request": "request",
                        "status": "status_code",
                        "body_bytes_sent": "bytes_out",
                        "http_referer": "referer",
                        "http_user_agent": "user_agent",
                        "request_time": "duration",
                        "request_method": "method",
                        "host": "host"
                    }
                    
                    for json_field, norm_field in field_map.items():
                        if json_field in json_data:
                            normalized[norm_field] = json_data[json_field]
                    
                    # Parse timestamp if present
                    if "timestamp" in normalized:
                        parsed_time = self.parse_timestamp(normalized["timestamp"])
                        if parsed_time:
                            normalized["timestamp"] = parsed_time
                    
                    # Parse request if present and needed
                    if self.parse_request and "request" in normalized and "method" not in normalized:
                        method, path, protocol = self._parse_request(normalized["request"])
                        normalized["method"] = method
                        normalized["path"] = path
                        normalized["protocol"] = protocol
                    
                    # Parse user agent if enabled
                    if self.parse_user_agent and "user_agent" in normalized:
                        ua_info = self._parse_user_agent_string(normalized["user_agent"])
                        normalized.update(ua_info)
                        
                except json.JSONDecodeError:
                    # Not valid JSON, try common log format
                    pass
            
            # If we don't have fields yet, try Common Log Format
            if not normalized or len(normalized) <= (1 if self.include_raw else 0):
                match = self.clf_pattern.match(message)
                if not match:
                    return log
                
                client_ip, identd, user, timestamp, request, status, size, referer, user_agent = match.groups()
                
                # Convert size to integer if possible
                if size == "-":
                    size = 0
                else:
                    try:
                        size = int(size)
                    except ValueError:
                        size = 0
                
                # Build normalized log
                normalized.update({
                    "source_ip": client_ip,
                    "user": user if user != "-" else None,
                    "status_code": int(status),
                    "bytes_out": size,
                    "request": request,
                    "event_type": "web_access"
                })
                
                # Add referer and user agent if present
                if referer and referer != "-":
                    normalized["referer"] = referer
                    
                if user_agent and user_agent != "-":
                    normalized["user_agent"] = user_agent
                    
                    # Parse user agent if enabled
                    if self.parse_user_agent:
                        ua_info = self._parse_user_agent_string(user_agent)
                        for key, value in ua_info.items():
                            if key != "user_agent":  # Avoid duplicating user_agent
                                normalized[key] = value
                
                # Parse timestamp
                # Convert Apache timestamp format to ISO
                try:
                    dt = datetime.datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
                    normalized["timestamp"] = dt.timestamp()
                except ValueError:
                    # Try other formats
                    parsed_time = self.parse_timestamp(timestamp)
                    if parsed_time:
                        normalized["timestamp"] = parsed_time
                
                # Parse request into method, path, protocol
                if self.parse_request:
                    method, path, protocol = self._parse_request(request)
                    normalized["method"] = method
                    normalized["path"] = path
                    normalized["protocol"] = protocol
            
            # Extract HTTP status type
            if "status_code" in normalized:
                status = int(normalized["status_code"])
                if 100 <= status < 200:
                    normalized["status"] = "informational"
                elif 200 <= status < 300:
                    normalized["status"] = "success"
                elif 300 <= status < 400:
                    normalized["status"] = "redirect"
                elif 400 <= status < 500:
                    normalized["status"] = "client_error"
                elif 500 <= status < 600:
                    normalized["status"] = "server_error"
            
            # Validate IP address
            if "source_ip" in normalized:
                normalized["source_ip"] = self.validate_ip(normalized["source_ip"]) or normalized["source_ip"]
            
            # Generate a log ID if not present
            if "_id" not in normalized:
                normalized["_id"] = self.get_log_id(normalized)
            
            # Add normalized flag
            normalized["_normalized"] = True
            
            # Update stats
            self.normalize_count += 1
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing web server log: {e}")
            self.error_count += 1
            return log


class WindowsEventLogNormalizer(LogNormalizer):
    """
    Normalizer for Windows Event Logs
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Windows Event Log normalizer
        
        Args:
            config: Normalizer configuration
        """
        super().__init__(config)
        
        # Common Windows Event Log fields to standard field mappings
        self.field_mappings = config.get("field_mappings", {
            "EventID": "event_id",
            "Computer": "hostname",
            "Provider_Name": "provider",
            "Channel": "log_channel",
            "Keywords": "keywords",
            "Level": "level",
            "TimeCreated_SystemTime": "timestamp",
            "EventRecordID": "record_id",
            "Security_UserID": "user_sid",
            "Execution_ProcessID": "process_id",
            "Execution_ThreadID": "thread_id",
            "EventData": "event_data"
        })
        
        # Severity mappings for Windows Event Log levels
        self.severity_map = {
            0: "unknown",
            1: "critical",
            2: "error",
            3: "warning",
            4: "info",
            5: "verbose"
        }
        
        # Common security event mappings
        self.security_events = {
            4624: "successful_login",
            4625: "failed_login",
            4634: "account_logoff",
            4648: "explicit_credential_login",
            4720: "account_created",
            4722: "account_enabled",
            4723: "password_change",
            4724: "password_reset",
            4725: "account_disabled",
            4726: "account_deleted",
            4728: "member_added_to_security_group",
            4732: "member_added_to_local_group",
            4740: "account_locked_out",
            4767: "account_unlocked"
        }
        
        logger.info(f"WindowsEventLogNormalizer initialized")
    
    async def normalize(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a Windows Event Log entry
        
        Args:
            log: Raw log entry
            
        Returns:
            Normalized log entry
        """
        if not self.enabled:
            return log
            
        try:
            normalized = {}
            
            # Check if we have a raw message to include
            if "message" in log and self.include_raw:
                normalized["raw_message"] = log["message"]
            
            # Copy metadata fields
            for key in log:
                if key.startswith("_"):
                    normalized[key] = log[key]
            
            # Map fields according to mapping
            for src_field, dest_field in self.field_mappings.items():
                if src_field in log:
                    normalized[dest_field] = log[src_field]
            
            # Copy any fields not specifically mapped
            for field, value in log.items():
                if field not in self.field_mappings and not field.startswith("_") and field != "message":
                    # Skip fields in drop list
                    if field not in self.drop_fields:
                        normalized[field] = value
            
            # Process the level/severity
            if "level" in normalized:
                try:
                    level_num = int(normalized["level"])
                    normalized["severity"] = self.severity_map.get(level_num, "unknown")
                except (ValueError, TypeError):
                    # If level isn't a number, keep it as is
                    pass
            
            # Parse event ID and map to known event types
            if "event_id" in normalized:
                try:
                    event_id = int(normalized["event_id"])
                    if event_id in self.security_events:
                        normalized["event_type"] = self.security_events[event_id]
                        normalized["category"] = "security"
                except (ValueError, TypeError):
                    pass
            
            # Normalize timestamp if present
            if "timestamp" in normalized:
                timestamp_value = normalized["timestamp"]
                # Windows often uses ISO format
                parsed_timestamp = self.parse_timestamp(timestamp_value)
                if parsed_timestamp:
                    normalized["timestamp"] = parsed_timestamp
            
            # Extract username from various places
            if "event_data" in normalized and isinstance(normalized["event_data"], dict):
                event_data = normalized["event_data"]
                
                # Look for common username fields in event data
                username_fields = ["TargetUserName", "SubjectUserName", "UserName", "User"]
                for field in username_fields:
                    if field in event_data and "user" not in normalized:
                        normalized["user"] = event_data[field]
                        break
                
                # Look for IP addresses
                ip_fields = ["IpAddress", "ClientAddress", "ClientIP", "SourceAddress"]
                for field in ip_fields:
                    if field in event_data and "source_ip" not in normalized:
                        ip = event_data[field]
                        # Validate and clean up IP
                        valid_ip = self.validate_ip(ip)
                        if valid_ip:
                            normalized["source_ip"] = valid_ip
                        break
            
            # Generate a log ID if not present
            if "_id" not in normalized:
                normalized["_id"] = self.get_log_id(normalized)
            
            # Add normalized flag
            normalized["_normalized"] = True
            
            # Update stats
            self.normalize_count += 1
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing Windows Event Log: {e}")
            self.error_count += 1
            return log


# Normalizer registry to store available normalizers
NORMALIZER_REGISTRY = {
    "generic": GenericLogNormalizer,
    "syslog": SyslogNormalizer,
    "json": JSONLogNormalizer,
    "cef": CEFLogNormalizer,
    "webserver": WebServerLogNormalizer,
    "windows": WindowsEventLogNormalizer
}


# Factory function to create normalizers
def create_normalizer(config: Dict[str, Any]) -> LogNormalizer:
    """
    Create a log normalizer based on configuration
    
    Args:
        config: Normalizer configuration with type field
        
    Returns:
        Initialized LogNormalizer instance
        
    Raises:
        ValueError: If normalizer type is unknown
    """
    normalizer_type = config.get("type", "").lower()
    
    if normalizer_type in NORMALIZER_REGISTRY:
        return NORMALIZER_REGISTRY[normalizer_type](config)
    else:
        raise ValueError(f"Unknown normalizer type: {normalizer_type}")


# Normalization manager to handle multiple normalizers
class NormalizationManager:
    """
    Manages multiple log normalizers
    Coordinates normalizing logs from multiple sources
    """
    
    def __init__(self, normalizer_configs: List[Dict[str, Any]]):
        """
        Initialize the normalization manager
        
        Args:
            normalizer_configs: List of normalizer configurations
        """
        self.normalizers = []
        self.input_queue = asyncio.Queue()
        self.output_queue = asyncio.Queue()
        self.running = False
        self.tasks = []
        self.stats = {
            "processed": 0,
            "normalized": 0,
            "errors": 0,
            "start_time": time.time()
        }
        
        # Create normalizers
        for config in normalizer_configs:
            try:
                normalizer = create_normalizer(config)
                self.normalizers.append(normalizer)
            except Exception as e:
                logger.error(f"Error creating normalizer: {e}")
        
        logger.info(f"Normalization manager initialized with {len(self.normalizers)} normalizers")
    
    async def start(self):
        """
        Start the normalization process
        """
        self.running = True
        
        # Start processor tasks
        for _ in range(min(3, len(self.normalizers) * 2)):  # Create multiple processor tasks
            task = asyncio.create_task(self._process_logs())
            self.tasks.append(task)
        
        logger.info(f"Started normalization manager with {len(self.tasks)} processor tasks")
    
    async def stop(self):
        """
        Stop the normalization process
        """
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            if not task.done():
                task.cancel()
        
        logger.info("Stopped normalization manager")
    
    async def _process_logs(self):
        """
        Process logs from the input queue
        Apply normalizers and forward to output queue
        """
        try:
            while self.running:
                try:
                    # Get a log entry from the input queue
                    log = await asyncio.wait_for(self.input_queue.get(), timeout=1.0)
                    
                    # Update stats
                    self.stats["processed"] += 1
                    
                    try:
                        # Apply each normalizer in sequence
                        # We could use a different strategy like selecting the best normalizer based on log type
                        normalized_log = log
                        
                        # Skip already normalized logs
                        if "_normalized" in normalized_log and normalized_log["_normalized"]:
                            await self.output_queue.put(normalized_log)
                            self.input_queue.task_done()
                            continue
                        
                        # Try each normalizer until one succeeds
                        for normalizer in self.normalizers:
                            try:
                                result = await normalizer.normalize(normalized_log)
                                if result is not None:
                                    normalized_log = result
                                    # If this normalizer did something useful (added _normalized flag)
                                    if "_normalized" in normalized_log and normalized_log["_normalized"]:
                                        break
                            except Exception as e:
                                logger.error(f"Normalizer {normalizer.name} failed: {e}")
                        
                        # Put normalized log in output queue
                        await self.output_queue.put(normalized_log)
                        
                        # Update stats if normalized
                        if "_normalized" in normalized_log and normalized_log["_normalized"]:
                            self.stats["normalized"] += 1
                        
                    except Exception as e:
                        # On error, forward the original log
                        logger.error(f"Error normalizing log: {e}")
                        self.stats["errors"] += 1
                        await self.output_queue.put(log)
                    
                    # Mark task as done
                    self.input_queue.task_done()
                    
                except asyncio.TimeoutError:
                    # No logs available, continue
                    pass
                    
        except asyncio.CancelledError:
            logger.info("Log normalizer task cancelled")
        except Exception as e:
            logger.error(f"Unexpected error in log normalizer: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics for the normalization process
        
        Returns:
            Dictionary of statistics
        """
        uptime = time.time() - self.stats["start_time"]
        rate = self.stats["processed"] / uptime if uptime > 0 else 0
        
        return {
            "processed": self.stats["processed"],
            "normalized": self.stats["normalized"],
            "errors": self.stats["errors"],
            "uptime": uptime,
            "rate": rate,
            "input_queue_size": self.input_queue.qsize(),
            "output_queue_size": self.output_queue.qsize(),
            "normalizers": [n.get_stats() for n in self.normalizers]
        }


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 17:51:30"
__author__ = "Rahul"
