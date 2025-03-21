"""
Log processor for ASIRA detection engine
Handles ingestion, parsing, and normalization of security logs from various sources

Functionalities:
- Ingest logs from multiple sources (files, syslog, APIs, databases)
- Parse common log formats (JSON, CSV, syslog, Windows Event Log, etc.)
- Normalize logs to a common schema for analysis
- Extract and transform features for anomaly detection models

Version: 1.0.0
Last updated: 2025-03-15 18:04:31
Last updated by: Rahul
"""

import os
import re
import json
import time
import logging
import datetime
from typing import Dict, List, Any, Optional, Union, Tuple, Generator, Callable
import pandas as pd
import numpy as np
from collections import defaultdict
import ipaddress
import hashlib
import gzip
import requests
from pathlib import Path
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

# Import ASIRA modules
from src.common.config import Settings
from src.common.logging_config import get_logger

# Initialize logger
logger = get_logger("asira.detection.processor")

# Import settings
try:
    settings = Settings()
except Exception as e:
    logger.warning(f"Failed to load settings: {e}. Using defaults.")
    settings = None

class LogNormalizer:
    """
    Normalizes logs from different formats into a common schema
    for consistent analysis across data sources
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log normalizer with configuration
        
        Args:
            config: Configuration dictionary for normalization settings
        """
        self.config = config
        self.schema = config.get("schema", {
            "timestamp": "float",
            "source_ip": "string",
            "dest_ip": "string",
            "username": "string",
            "action": "string",
            "status": "string",
            "resource": "string",
            "severity": "string"
        })
        self.timestamp_formats = config.get("timestamp_formats", [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
            "%Y%m%d%H%M%S"
        ])
        self.ip_fields = config.get("ip_fields", ["source_ip", "dest_ip", "ip", "client_ip", "server_ip"])
        self.username_fields = config.get("username_fields", ["username", "user", "account", "user_id", "uid"])
        self.timestamp_fields = config.get("timestamp_fields", ["timestamp", "time", "date", "datetime", "event_time"])
        
        # Custom field mappings from source to normalized schema
        self.field_mappings = config.get("field_mappings", {})
        
    def normalize(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a log entry to the common schema
        
        Args:
            log_entry: Raw log entry dictionary
            
        Returns:
            Normalized log entry following the common schema
        """
        normalized = {}
        
        # Process timestamp
        timestamp = self._extract_timestamp(log_entry)
        if timestamp is not None:
            normalized["timestamp"] = timestamp
            
        # Process IP addresses
        source_ip = self._extract_field_by_candidates(log_entry, self.ip_fields, prefix="source_")
        if source_ip:
            normalized["source_ip"] = self._normalize_ip(source_ip)
            
        dest_ip = self._extract_field_by_candidates(log_entry, self.ip_fields, prefix="dest_")
        if dest_ip:
            normalized["dest_ip"] = self._normalize_ip(dest_ip)
            
        # Process username
        username = self._extract_field_by_candidates(log_entry, self.username_fields)
        if username:
            normalized["username"] = username
            
        # Apply field mappings
        for target_field, source_field in self.field_mappings.items():
            if source_field in log_entry:
                normalized[target_field] = log_entry[source_field]
                
        # For remaining fields in schema that weren't mapped, try to find them directly
        for field in self.schema:
            if field not in normalized and field in log_entry:
                normalized[field] = log_entry[field]
                
        return normalized
    
    def _extract_timestamp(self, log_entry: Dict[str, Any]) -> Optional[float]:
        """
        Extract timestamp from log entry and convert to Unix timestamp
        
        Args:
            log_entry: Raw log entry dictionary
            
        Returns:
            Unix timestamp as float or None if not found
        """
        # First check if we already have a numeric timestamp
        for field in self.timestamp_fields:
            if field in log_entry:
                # If it's already a number, assume it's a timestamp
                if isinstance(log_entry[field], (int, float)):
                    return float(log_entry[field])
                
                # If it's a string, try to parse it
                if isinstance(log_entry[field], str):
                    timestamp_str = log_entry[field]
                    # Try each format
                    for fmt in self.timestamp_formats:
                        try:
                            dt = datetime.datetime.strptime(timestamp_str, fmt)
                            return dt.timestamp()
                        except ValueError:
                            continue
                            
        # If no timestamp found, use current time
        logger.debug("No timestamp found in log entry, using current time")
        return time.time()
    
    def _extract_field_by_candidates(self, log_entry: Dict[str, Any], candidates: List[str], prefix: str = "") -> Optional[str]:
        """
        Extract a field from log entry using a list of candidate field names
        
        Args:
            log_entry: Raw log entry dictionary
            candidates: List of possible field names
            prefix: Optional prefix for field names
            
        Returns:
            Field value or None if not found
        """
        # Try fields with the prefix
        if prefix:
            for field in candidates:
                prefixed_field = prefix + field
                if prefixed_field in log_entry:
                    return log_entry[prefixed_field]
        
        # Try fields without the prefix
        for field in candidates:
            if field in log_entry:
                return log_entry[field]
                
        return None
    
    def _normalize_ip(self, ip_str: str) -> str:
        """
        Normalize IP address format
        
        Args:
            ip_str: IP address string
            
        Returns:
            Normalized IP address string
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return str(ip_obj)
        except ValueError:
            return ip_str


class LogIngester:
    """
    Ingests logs from various sources and formats
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log ingester with configuration
        
        Args:
            config: Configuration dictionary for ingestion settings
        """
        self.config = config
        self.normalizer = LogNormalizer(config.get("normalizer", {}))
        self.batch_size = config.get("batch_size", 1000)
        self.parser_configs = config.get("parsers", {})
        
    def ingest_file(self, file_path: str, format_type: str = None) -> pd.DataFrame:
        """
        Ingest logs from a file and normalize them
        
        Args:
            file_path: Path to the log file
            format_type: Format of the log file (json, csv, syslog, etc.)
                         If None, will try to determine from file extension
                         
        Returns:
            DataFrame containing normalized log entries
        """
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return pd.DataFrame()
            
        # Determine format if not provided
        if not format_type:
            format_type = self._determine_format(file_path)
            
        logger.info(f"Ingesting file {file_path} with format {format_type}")
        
        # Read and parse based on format
        raw_entries = []
        try:
            if format_type == "json":
                raw_entries = self._read_json_file(file_path)
            elif format_type == "csv":
                raw_entries = self._read_csv_file(file_path)
            elif format_type == "syslog":
                raw_entries = self._read_syslog_file(file_path)
            elif format_type == "windows_event":
                raw_entries = self._read_windows_event_file(file_path)
            else:
                logger.error(f"Unsupported format: {format_type}")
                return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return pd.DataFrame()
            
        # Normalize entries
        normalized_entries = [self.normalizer.normalize(entry) for entry in raw_entries]
        
        # Convert to DataFrame
        df = pd.DataFrame(normalized_entries)
        
        # Add event_id as index if not present
        if 'event_id' not in df.columns:
            df['event_id'] = [self._generate_event_id(entry) for entry in normalized_entries]
            
        df.set_index('event_id', inplace=True)
        
        return df
    
    def ingest_api(self, api_config: Dict[str, Any]) -> pd.DataFrame:
        """
        Ingest logs from an API endpoint
        
        Args:
            api_config: API configuration with url, auth, and parameters
            
        Returns:
            DataFrame containing normalized log entries
        """
        url = api_config.get("url")
        if not url:
            logger.error("API URL not provided")
            return pd.DataFrame()
            
        # Set up request parameters
        headers = api_config.get("headers", {})
        params = api_config.get("params", {})
        auth = None
        
        # Handle authentication
        auth_type = api_config.get("auth_type")
        if auth_type == "basic":
            auth = (api_config.get("username", ""), api_config.get("password", ""))
        elif auth_type == "bearer":
            headers["Authorization"] = f"Bearer {api_config.get('token', '')}"
            
        # Make the request
        try:
            response = requests.get(url, headers=headers, params=params, auth=auth)
            response.raise_for_status()
            
            # Parse response based on content type
            content_type = response.headers.get("Content-Type", "")
            
            if "json" in content_type:
                data = response.json()
                # Handle different JSON structures
                if isinstance(data, list):
                    raw_entries = data
                elif isinstance(data, dict) and "data" in data:
                    raw_entries = data["data"]
                elif isinstance(data, dict) and "results" in data:
                    raw_entries = data["results"]
                elif isinstance(data, dict) and "events" in data:
                    raw_entries = data["events"]
                else:
                    raw_entries = [data]
            else:
                # Assume plain text log format
                lines = response.text.splitlines()
                raw_entries = [{"raw": line} for line in lines]
                
            # Normalize entries
            normalized_entries = [self.normalizer.normalize(entry) for entry in raw_entries]
            
            # Convert to DataFrame
            df = pd.DataFrame(normalized_entries)
            
            # Add event_id as index
            if df.empty:
                return df
                
            if 'event_id' not in df.columns:
                df['event_id'] = [self._generate_event_id(entry) for entry in normalized_entries]
                
            df.set_index('event_id', inplace=True)
            
            return df
            
        except Exception as e:
            logger.error(f"Error fetching logs from API {url}: {e}")
            return pd.DataFrame()
    
    def ingest_stream(self, stream_callback: Callable, format_type: str) -> Generator[pd.DataFrame, None, None]:
        """
        Ingest logs from a streaming source (e.g. Kafka, syslog server)
        
        Args:
            stream_callback: Callback function that yields log entries or batches
            format_type: Format of the incoming logs
            
        Yields:
            DataFrame batches containing normalized log entries
        """
        batch = []
        
        for data in stream_callback():
            # Parse data based on format
            if format_type == "json":
                if isinstance(data, str):
                    try:
                        entry = json.loads(data)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON: {data[:100]}...")
                        continue
                else:
                    entry = data
            elif format_type == "syslog":
                entry = self._parse_syslog_line(data)
            elif format_type == "raw":
                entry = {"raw": data}
            else:
                entry = data
                
            # Normalize entry
            normalized = self.normalizer.normalize(entry)
            batch.append(normalized)
            
            # Yield batch when it reaches the batch size
            if len(batch) >= self.batch_size:
                # Convert to DataFrame
                df = pd.DataFrame(batch)
                
                # Add event_id as index
                if 'event_id' not in df.columns:
                    df['event_id'] = [self._generate_event_id(entry) for entry in batch]
                    
                df.set_index('event_id', inplace=True)
                
                yield df
                batch = []
                
        # Yield any remaining entries
        if batch:
            df = pd.DataFrame(batch)
            
            if not df.empty:
                # Add event_id as index
                if 'event_id' not in df.columns:
                    df['event_id'] = [self._generate_event_id(entry) for entry in batch]
                    
                df.set_index('event_id', inplace=True)
                
                yield df
    
    def _determine_format(self, file_path: str) -> str:
        """
        Determine log format from file extension or content
        
        Args:
            file_path: Path to log file
            
        Returns:
            Format type string (json, csv, syslog, etc.)
        """
        # Check extension
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == ".json":
            return "json"
        elif ext == ".csv":
            return "csv"
        elif ext in [".log", ".txt"]:
            # Try to determine from content
            with open(file_path, 'r', errors='ignore') as f:
                # Read first few lines
                lines = [f.readline() for _ in range(5)]
                
                # Check if it looks like JSON
                if any(line.strip().startswith('{') for line in lines):
                    return "json"
                    
                # Check if it looks like CSV
                if any(',' in line for line in lines):
                    return "csv"
                    
                # Default to syslog
                return "syslog"
        elif ext == ".evt" or ext == ".evtx":
            return "windows_event"
        else:
            return "unknown"
    
    def _read_json_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Read and parse a JSON log file
        
        Args:
            file_path: Path to JSON log file
            
        Returns:
            List of parsed log entries
        """
        # Check if gzipped
        if file_path.endswith('.gz'):
            open_func = gzip.open
            mode = 'rt'  # text mode for gzip
        else:
            open_func = open
            mode = 'r'
            
        with open_func(file_path, mode) as f:
            # Check if it's a JSON array or one JSON object per line
            content = f.read(1024)  # Read a small sample to check format
            f.seek(0)  # Reset file pointer
            
            if content.strip().startswith('['):
                # JSON array format
                return json.load(f)
            else:
                # JSON lines format
                entries = []
                for line in f:
                    line = line.strip()
                    if line:  # Skip empty lines
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON line: {line[:100]}...")
                return entries
    
    def _read_csv_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Read and parse a CSV log file
        
        Args:
            file_path: Path to CSV log file
            
        Returns:
            List of parsed log entries
        """
        df = pd.read_csv(file_path)
        return df.to_dict('records')
    
    def _read_syslog_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Read and parse a syslog file
        
        Args:
            file_path: Path to syslog file
            
        Returns:
            List of parsed log entries
        """
        entries = []
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                entry = self._parse_syslog_line(line)
                if entry:
                    entries.append(entry)
        return entries
    
    def _parse_syslog_line(self, line: str) -> Dict[str, Any]:
        """
        Parse a single syslog line
        
        Args:
            line: Syslog line string
            
        Returns:
            Parsed log entry as dictionary
        """
        # Common syslog format: <timestamp> <hostname> <process>[<pid>]: <message>
        # Example: Jan  1 00:00:00 myhost sshd[12345]: Failed password for user from 10.0.0.1
        
        entry = {"raw": line.strip()}
        
        # Extract timestamp
        timestamp_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        timestamp_match = re.match(timestamp_pattern, line)
        if timestamp_match:
            entry["timestamp_raw"] = timestamp_match.group(1)
            
        # Extract hostname and process
        host_process_pattern = r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+([^[:\s]+)(?:\[(\d+)\])?:'
        host_match = re.search(host_process_pattern, line)
        if host_match:
            entry["hostname"] = host_match.group(1)
            entry["process"] = host_match.group(2)
            if host_match.group(3):
                entry["pid"] = host_match.group(3)
                
        # Extract message
        message_pattern = r':\s+(.+)$'
        message_match = re.search(message_pattern, line)
        if message_match:
            entry["message"] = message_match.group(1)
            
        # Extract common security-related patterns
        if "message" in entry:
            msg = entry["message"]
            
            # Failed login attempt
            if "Failed password" in msg:
                entry["event_type"] = "auth_failure"
                user_match = re.search(r'for\s+(\S+)', msg)
                if user_match:
                    entry["username"] = user_match.group(1)
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg)
                if ip_match:
                    entry["source_ip"] = ip_match.group(1)
            
            # Successful login
            elif "Accepted password" in msg or "Accepted publickey" in msg:
                entry["event_type"] = "auth_success"
                user_match = re.search(r'for\s+(\S+)', msg)
                if user_match:
                    entry["username"] = user_match.group(1)
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', msg)
                if ip_match:
                    entry["source_ip"] = ip_match.group(1)
                    
            # Connection closed
            elif "Connection closed" in msg:
                entry["event_type"] = "connection_closed"
                ip_match = re.search(r'by\s+(\d+\.\d+\.\d+\.\d+)', msg)
                if ip_match:
                    entry["source_ip"] = ip_match.group(1)
                    
        return entry
    
    def _read_windows_event_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Read and parse a Windows Event Log file
        
        Args:
            file_path: Path to Windows Event Log file
            
        Returns:
            List of parsed log entries
        """
        # Note: This is a simplified implementation
        # In a real application, you would use a library like python-evtx
        logger.warning("Windows Event Log parsing is simplified in this implementation")
        
        try:
            import xml.etree.ElementTree as ET
            entries = []
            
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Look for XML event data
            xml_start = content.find(b'<Event')
            while xml_start != -1:
                xml_end = content.find(b'</Event>', xml_start)
                if xml_end == -1:
                    break
                    
                xml_chunk = content[xml_start:xml_end + 8]  # '</Event>' is 8 chars
                
                try:
                    root = ET.fromstring(xml_chunk)
                    entry = {"raw": xml_chunk.decode('utf-8', errors='ignore')}
                    
                    # Extract system metadata
                    system = root.find('./System')
                    if system is not None:
                        for child in system:
                            tag = child.tag.split('}')[-1]
                            entry[tag] = child.text
                            
                    # Extract event data
                    event_data = root.find('./EventData')
                    if event_data is not None:
                        for data in event_data.findall('./Data'):
                            name = data.get('Name')
                            if name:
                                entry[name] = data.text
                            
                    entries.append(entry)
                except ET.ParseError:
                    pass
                    
                xml_start = content.find(b'<Event', xml_end)
                
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing Windows Event Log: {e}")
            return []
    
    def _generate_event_id(self, entry: Dict[str, Any]) -> str:
        """
        Generate a unique ID for a log entry
        
        Args:
            entry: Normalized log entry
            
        Returns:
            Unique ID string
        """
        # Use existing ID if present
        if "id" in entry:
            return entry["id"]
            
        # Create a hash of the entry
        timestamp = entry.get("timestamp", time.time())
        source = entry.get("source_ip", "")
        username = entry.get("username", "")
        action = entry.get("action", "")
        message = entry.get("message", "")
        
        # Create a composite string and hash it
        composite = f"{timestamp}|{source}|{username}|{action}|{message}"
        hash_obj = hashlib.md5(composite.encode())
        
        # Add a timestamp prefix for chronological sorting
        return f"evt_{int(timestamp)}_{hash_obj.hexdigest()[:8]}"


class FeatureExtractor:
    """
    Extracts and transforms features from normalized logs for anomaly detection
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the feature extractor with configuration
        
        Args:
            config: Configuration dictionary for feature extraction
        """
        self.config = config
        self.categorical_features = config.get("categorical_features", [
            "source_ip", "dest_ip", "username", "action", "status", "resource"
        ])
        self.numerical_features = config.get("numerical_features", ["duration"])
        self.temporal_features = config.get("temporal_features", True)
        self.window_size = config.get("window_size", 3600)  # 1 hour in seconds
        
    def extract_features(self, logs_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from normalized log entries
        
        Args:
            logs_df: DataFrame containing normalized log entries
            
        Returns:
            DataFrame with extracted features
        """
        if logs_df.empty:
            return pd.DataFrame()
            
        logger.info(f"Extracting features from {len(logs_df)} log entries")
        
        # Copy to avoid modifying original
        features_df = logs_df.copy()
        
        # Ensure timestamp is present
        if "timestamp" not in features_df.columns:
            logger.warning("No timestamp column found in logs")
            features_df["timestamp"] = time.time()
            
        # Process categorical features
        features_df = self._process_categorical_features(features_df)
        
        # Process numerical features
        features_df = self._process_numerical_features(features_df)
        
        # Extract temporal features if enabled
        if self.temporal_features:
            features_df = self._extract_temporal_features(features_df)
            
        # Add behavioral features
        features_df = self._extract_behavioral_features(features_df)
        
        return features_df
    
    def _process_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Process categorical features: one-hot encoding or target encoding
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with processed categorical features
        """
        # Get available categorical features
        available_features = [f for f in self.categorical_features if f in df.columns]
        
        if not available_features:
            return df
            
        # For each categorical feature
        for feature in available_features:
            encoding_type = self.config.get(f"{feature}_encoding", "one_hot")
            
            if encoding_type == "one_hot":
                # One-hot encoding with a limit on categories
                top_n = self.config.get(f"{feature}_top_n", 10)
                
                # Get top N most common values
                value_counts = df[feature].value_counts()
                if len(value_counts) > top_n:
                    top_values = value_counts.nlargest(top_n).index
                    
                    # Replace values not in top N with "other"
                    df[feature] = df[feature].apply(lambda x: x if x in top_values else "other")
                
                # Create one-hot encodings
                dummies = pd.get_dummies(df[feature], prefix=feature)
                
                # Concatenate with original dataframe
                df = pd.concat([df, dummies], axis=1)
                
                # Drop original feature
                df.drop(feature, axis=1, inplace=True)
            
            elif encoding_type == "label":
                # Simple label encoding
                unique_values = df[feature].dropna().unique()
                value_map = {val: idx for idx, val in enumerate(unique_values)}
                
                # Add mapping for missing values
                value_map[np.nan] = -1
                
                # Apply mapping
                df[f"{feature}_encoded"] = df[feature].map(value_map).fillna(-1)
                
                # Drop original feature
                df.drop(feature, axis=1, inplace=True)
                
        return df
    
    def _process_numerical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Process numerical features: scaling, binning, etc.
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with processed numerical features
        """
        # Get available numerical features
        available_features = [f for f in self.numerical_features if f in df.columns]
        
        if not available_features:
            return df
            
        # Replace any infinite values
        for feature in available_features:
            df[feature] = df[feature].replace([np.inf, -np.inf], np.nan)
            
            # Fill missing values with median
            df[feature] = df[feature].fillna(df[feature].median())
            
            # Apply log transformation for skewed distributions if configured
            transform = self.config.get(f"{feature}_transform", None)
            if transform == "log":
                # Add small constant to avoid log(0)
                min_val = df[feature].min()
                offset = 1.0 if min_val >= 0 else (abs(min_val) + 1.0)
                df[f"{feature}_log"] = np.log(df[feature] + offset)
                
            # Bin features if configured
            bins = self.config.get(f"{feature}_bins", 0)
            if bins > 0:
                df[f"{feature}_binned"] = pd.qcut(
                    df[feature], 
                    q=bins, 
                    labels=False, 
                    duplicates='drop'
                ).astype(float)
                
        return df
    
    def _extract_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract time-based features (hour of day, day of week, etc.)
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with added temporal features
        """
        # Convert timestamp to datetime
        if "timestamp" in df.columns:
            # Convert timestamp to datetime
            df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")
            
            # Extract temporal features
            df["hour"] = df["datetime"].dt.hour
            df["day"] = df["datetime"].dt.day
            df["weekday"] = df["datetime"].dt.weekday
            df["month"] = df["datetime"].dt.month
            df["hour_sin"] = np.sin(2 * np.pi * df["hour"] / 24)
            df["hour_cos"] = np.cos(2 * np.pi * df["hour"] / 24)
            df["weekday_sin"] = np.sin(2 * np.pi * df["weekday"] / 7)
            df["weekday_cos"] = np.cos(2 * np.pi * df["weekday"] / 7)
            
            # Drop datetime column as it's not needed for ML
            df.drop("datetime", axis=1, inplace=True)
            
        return df
    
    def _extract_behavioral_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract behavioral features from logs
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with added behavioral features
        """
        # Skip if dataframe is empty or too small
        if df.empty or len(df) < 2:
            return df
            
        # Ensure timestamp is present and sort by it
        if "timestamp" not in df.columns:
            return df
            
        # Sort by timestamp
        df = df.sort_values("timestamp")
        
        # Extract source IP based features if available
        if "source_ip" in df.columns:
            # Count events per IP
            ip_counts = df.groupby("source_ip").size().to_dict()
            df["source_ip_count"] = df["source_ip"].map(ip_counts)
            
            # Calculate time since last activity from this IP
            df["prev_timestamp"] = df.groupby("source_ip")["timestamp"].shift(1)
            df["time_since_last_ip_activity"] = df["timestamp"] - df["prev_timestamp"]
            df["time_since_last_ip_activity"] = df["time_since_last_ip_activity"].fillna(0)
            
            # Calculate event rate (events per hour) for this IP
            first_seen = df.groupby("source_ip")["timestamp"].transform("min")
            last_seen = df.groupby("source_ip")["timestamp"].transform("max")
            time_span = last_seen - first_seen
            # Avoid division by zero
            time_span = np.maximum(time_span, 3600)  # Use at least 1 hour
            df["source_ip_event_rate"] = df["source_ip_count"] / (time_span / 3600)
        
        # Extract username based features if available
        if "username" in df.columns and df["username"].notna().any():
            # Count events per username
            user_counts = df.groupby("username").size().to_dict()
            df["username_count"] = df["username"].map(user_counts)
            
            # Calculate time since last activity from this username
            df["prev_user_timestamp"] = df.groupby("username")["timestamp"].shift(1)
            df["time_since_last_user_activity"] = df["timestamp"] - df["prev_user_timestamp"]
            df["time_since_last_user_activity"] = df["time_since_last_user_activity"].fillna(0)
            
            # Detect username switching on same IP (potential credential stuffing)
            if "source_ip" in df.columns:
                df["prev_ip_username"] = df.groupby("source_ip")["username"].shift(1)
                df["username_switched"] = (df["username"] != df["prev_ip_username"]) & (df["prev_ip_username"].notna())
                df["username_switched"] = df["username_switched"].astype(int)
        
        # Extract action/event type based features if available
        action_field = None
        for field in ["action", "event_type", "category"]:
            if field in df.columns:
                action_field = field
                break
                
        if action_field:
            # Count actions per source
            df["action_count"] = df.groupby([action_field]).cumcount()
            
            # Calculate time since last instance of this action
            df["prev_action_timestamp"] = df.groupby(action_field)["timestamp"].shift(1)
            df["time_since_last_action"] = df["timestamp"] - df["prev_action_timestamp"]
            df["time_since_last_action"] = df["time_since_last_action"].fillna(0)
        
        # Extract status based features if available (success/failure patterns)
        if "status" in df.columns:
            # Count consecutive failures
            is_failure = df["status"].isin(["failure", "failed", "error", "denied"])
            df["is_failure"] = is_failure.astype(int)
            
            # Group by source entities and calculate consecutive failures
            if "source_ip" in df.columns:
                df["failure_group"] = ((is_failure != is_failure.shift(1)) | 
                                      (df["source_ip"] != df["source_ip"].shift(1))).cumsum()
                consecutive_failures = df[is_failure].groupby(["failure_group", "source_ip"]).cumcount() + 1
                df["consecutive_failures"] = 0
                df.loc[is_failure, "consecutive_failures"] = consecutive_failures
                
            # Calculate failure ratio
            if "username" in df.columns:
                failure_counts = df[is_failure].groupby("username").size()
                total_counts = df.groupby("username").size()
                failure_ratios = (failure_counts / total_counts).fillna(0).to_dict()
                df["user_failure_ratio"] = df["username"].map(failure_ratios)
        
        # Add velocity features (rate of events)
        df["event_timestamp_delta"] = df["timestamp"].diff().fillna(0)
        
        # Calculate short-term and long-term event velocities (events per minute)
        # Short-term: based on last N events
        window_sizes = [5, 20]
        for window in window_sizes:
            col_name = f"velocity_{window}"
            df[col_name] = (window / df["timestamp"].rolling(window=window+1).apply(
                lambda x: max(x.iloc[-1] - x.iloc[0], 1), raw=True
            )).fillna(0)
        
        # Clean up intermediate columns
        cols_to_drop = ["prev_timestamp", "prev_action_timestamp", "prev_ip_username",
                        "prev_user_timestamp", "failure_group"]
        for col in cols_to_drop:
            if col in df.columns:
                df.drop(col, axis=1, inplace=True)
                
        return df


class LogProcessor:
    """
    Core log processing class that orchestrates the entire workflow:
    ingestion -> normalization -> feature extraction -> detection
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log processor with configuration
        
        Args:
            config: Configuration dictionary for the processor
        """
        self.config = config
        self.ingester = LogIngester(config.get("ingester", {}))
        self.feature_extractor = FeatureExtractor(config.get("feature_extraction", {}))
        
        # Configure processing settings
        self.batch_size = config.get("batch_size", 1000)
        self.max_threads = config.get("max_threads", 4)
        self.last_processed_timestamp = config.get("start_timestamp", 0)
        
        # Data storage
        self.processed_data = pd.DataFrame()
        self.processed_count = 0
        self.feature_cache = {}
        
        # Create processing queue for async processing
        self.processing_queue = Queue()
        self.queue_size_limit = config.get("queue_size_limit", 10000)
        self.results_queue = Queue()
        
        # Setup thread pool for parallel processing
        self.executor = ThreadPoolExecutor(max_workers=self.max_threads)
        self.processing_active = False
        self.process_thread = None
        
        logger.info(f"LogProcessor initialized with {self.max_threads} worker threads")
        
    def process_file(self, file_path: str, format_type: str = None) -> pd.DataFrame:
        """
        Process a log file: ingest, normalize, and extract features
        
        Args:
            file_path: Path to the log file
            format_type: Format of the log file (optional)
            
        Returns:
            DataFrame with processed logs
        """
        # Ingest the file
        logs_df = self.ingester.ingest_file(file_path, format_type)
        
        if logs_df.empty:
            logger.warning(f"No data ingested from {file_path}")
            return pd.DataFrame()
            
        logger.info(f"Ingested {len(logs_df)} log entries from {file_path}")
        
        # Extract features
        features_df = self.feature_extractor.extract_features(logs_df)
        
        # Update processed count and timestamp
        self.processed_count += len(features_df)
        
        # Update last processed timestamp
        if "timestamp" in features_df.columns and not features_df.empty:
            self.last_processed_timestamp = max(
                self.last_processed_timestamp,
                features_df["timestamp"].max()
            )
            
        # Cache some results for real-time feature extraction
        self._update_feature_cache(features_df)
            
        return features_df
    
    def process_files(self, file_paths: List[str]) -> pd.DataFrame:
        """
        Process multiple log files in parallel
        
        Args:
            file_paths: List of paths to log files
            
        Returns:
            Combined DataFrame with processed logs
        """
        if not file_paths:
            return pd.DataFrame()
            
        logger.info(f"Processing {len(file_paths)} log files")
        
        # Process files in parallel
        all_results = []
        
        # Submit processing tasks to thread pool
        future_to_file = {
            self.executor.submit(self.process_file, file_path): file_path
            for file_path in file_paths
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                df = future.result()
                if not df.empty:
                    all_results.append(df)
                    logger.info(f"Successfully processed {file_path}")
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
        
        # Combine results
        if not all_results:
            return pd.DataFrame()
            
        combined_df = pd.concat(all_results, ignore_index=False)
        
        logger.info(f"Completed processing {len(file_paths)} files, total entries: {len(combined_df)}")
        
        return combined_df
    
    def process_api(self, api_config: Dict[str, Any]) -> pd.DataFrame:
        """
        Process logs from an API endpoint
        
        Args:
            api_config: API configuration
            
        Returns:
            DataFrame with processed logs
        """
        # Ingest from API
        logs_df = self.ingester.ingest_api(api_config)
        
        if logs_df.empty:
            logger.warning(f"No data ingested from API: {api_config.get('url')}")
            return pd.DataFrame()
            
        logger.info(f"Ingested {len(logs_df)} log entries from API")
        
        # Extract features
        features_df = self.feature_extractor.extract_features(logs_df)
        
        # Update processed count and timestamp
        self.processed_count += len(features_df)
        
        # Update last processed timestamp
        if "timestamp" in features_df.columns and not features_df.empty:
            self.last_processed_timestamp = max(
                self.last_processed_timestamp,
                features_df["timestamp"].max()
            )
            
        # Cache some results for real-time feature extraction
        self._update_feature_cache(features_df)
            
        return features_df
    
    def start_stream_processing(self, stream_callback: Callable, format_type: str) -> None:
        """
        Start asynchronous stream processing
        
        Args:
            stream_callback: Function that yields log entries or batches
            format_type: Format of the stream data
        """
        if self.processing_active:
            logger.warning("Stream processing already active")
            return
            
        self.processing_active = True
        
        # Start processing thread
        self.process_thread = threading.Thread(
            target=self._stream_processor,
            args=(stream_callback, format_type),
            daemon=True
        )
        self.process_thread.start()
        
        logger.info("Stream processing started")
    
    def stop_stream_processing(self) -> None:
        """
        Stop asynchronous stream processing
        """
        if not self.processing_active:
            logger.warning("No stream processing active")
            return
            
        self.processing_active = False
        
        # Wait for thread to terminate
        if self.process_thread and self.process_thread.is_alive():
            self.process_thread.join(timeout=5.0)
            
        logger.info("Stream processing stopped")
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """
        Get processing statistics
        
        Returns:
            Dictionary with processing statistics
        """
        return {
            "processed_count": self.processed_count,
            "last_timestamp": self.last_processed_timestamp,
            "last_timestamp_readable": datetime.datetime.fromtimestamp(self.last_processed_timestamp).isoformat() if self.last_processed_timestamp else None,
            "queue_size": self.processing_queue.qsize(),
            "results_queue_size": self.results_queue.qsize(),
            "feature_cache_size": len(self.feature_cache),
            "processing_active": self.processing_active
        }
    
    def get_results(self, block: bool = False, timeout: float = 1.0) -> Optional[pd.DataFrame]:
        """
        Get processed results from the results queue
        
        Args:
            block: Whether to block waiting for results
            timeout: Timeout in seconds if blocking
            
        Returns:
            DataFrame with processed results or None if no results available
        """
        try:
            result = self.results_queue.get(block=block, timeout=timeout)
            self.results_queue.task_done()
            return result
        except Empty:
            return None
    
    def _stream_processor(self, stream_callback: Callable, format_type: str) -> None:
        """
        Internal stream processing worker
        
        Args:
            stream_callback: Function that yields log entries or batches
            format_type: Format of the stream data
        """
        try:
            for batch_df in self.ingester.ingest_stream(stream_callback, format_type):
                if not self.processing_active:
                    break
                    
                if batch_df.empty:
                    continue
                    
                # Extract features
                features_df = self.feature_extractor.extract_features(batch_df)
                
                # Update processed count and timestamp
                self.processed_count += len(features_df)
                
                # Update last processed timestamp
                if "timestamp" in features_df.columns and not features_df.empty:
                    self.last_processed_timestamp = max(
                        self.last_processed_timestamp,
                        features_df["timestamp"].max()
                    )
                    
                # Cache some results for real-time feature extraction
                self._update_feature_cache(features_df)
                
                # Put in results queue
                self.results_queue.put(features_df)
                
                # Avoid memory issues by ensuring queue doesn't grow too large
                while self.results_queue.qsize() > self.queue_size_limit:
                    time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error in stream processor: {e}")
            self.processing_active = False
    
    def _update_feature_cache(self, features_df: pd.DataFrame) -> None:
        """
        Update feature cache with new data
        
        Args:
            features_df: DataFrame with extracted features
        """
        # Cache source IP stats
        if "source_ip" in features_df.columns:
            for ip in features_df["source_ip"].unique():
                if ip is not None and ip != "":
                    ip_df = features_df[features_df["source_ip"] == ip]
                    
                    # Store or update stats
                    if ip not in self.feature_cache:
                        self.feature_cache[ip] = {
                            "first_seen": ip_df["timestamp"].min(),
                            "last_seen": ip_df["timestamp"].max(),
                            "count": len(ip_df),
                            "event_types": {}
                        }
                    else:
                        self.feature_cache[ip]["last_seen"] = max(
                            self.feature_cache[ip]["last_seen"],
                            ip_df["timestamp"].max()
                        )
                        self.feature_cache[ip]["count"] += len(ip_df)
                    
                    # Track event types
                    for event_field in ["event_type", "action"]:
                        if event_field in ip_df.columns:
                            for event_type, count in ip_df[event_field].value_counts().items():
                                if event_type not in self.feature_cache[ip]["event_types"]:
                                    self.feature_cache[ip]["event_types"][event_type] = 0
                                self.feature_cache[ip]["event_types"][event_type] += count
        
        # Limit cache size to avoid memory issues
        max_cache_size = self.config.get("max_cache_size", 10000)
        if len(self.feature_cache) > max_cache_size:
            # Remove oldest entries
            sorted_cache = sorted(
                self.feature_cache.items(),
                key=lambda x: x[1]["last_seen"]
            )
            to_remove = len(self.feature_cache) - max_cache_size
            for i in range(to_remove):
                key = sorted_cache[i][0]
                del self.feature_cache[key]


def create_processor(config_path: str = None) -> LogProcessor:
    """
    Create a LogProcessor with configuration from a file or default settings
    
    Args:
        config_path: Path to configuration file (JSON or YAML)
        
    Returns:
        Configured LogProcessor instance
    """
    config = {}
    
    # Load configuration from file if provided
    if config_path:
        try:
            file_ext = os.path.splitext(config_path)[1].lower()
            
            if file_ext == ".json":
                with open(config_path, 'r') as f:
                    config = json.load(f)
            elif file_ext in [".yml", ".yaml"]:
                try:
                    import yaml
                    with open(config_path, 'r') as f:
                        config = yaml.safe_load(f)
                except ImportError:
                    logger.error("YAML support requires PyYAML package")
            else:
                logger.error(f"Unsupported config file format: {file_ext}")
                
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
    
    # Use default config from settings if available
    if not config and settings:
        config = settings.log_processor_config
    
    # Create processor with config
    return LogProcessor(config)


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 18:06:59"
__author__ = "Rahul"
