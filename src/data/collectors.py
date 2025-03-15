"""
Log collectors for ASIRA
Responsible for collecting logs from various sources

Current version: 1.0.0
Last updated: 2025-03-15 12:03:04
"""
import os
import json
import time
import logging
import socket
import asyncio
import datetime
from typing import List, Dict, Any, Optional, Union, Callable, Tuple
import aiofiles
import aiohttp
from pathlib import Path
from abc import ABC, abstractmethod

# Initialize logger
logger = logging.getLogger("asira.data.collectors")

class LogCollector(ABC):
    """
    Base class for all log collectors
    Defines common interface and helper methods
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the collector with configuration
        
        Args:
            config: Collector configuration
        """
        self.config = config
        self.name = config.get("name", self.__class__.__name__)
        self.enabled = config.get("enabled", True)
        self.collection_interval = config.get("collection_interval", 60)  # seconds
        self.last_collection = 0
        self.batch_size = config.get("batch_size", 1000)
        self.output_queue = None
        self.running = False
        
        logger.info(f"Initialized {self.name} collector")
    
    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from the source
        
        Returns:
            List of log entries as dictionaries
        """
        pass
    
    async def start(self, output_queue: asyncio.Queue):
        """
        Start the collector
        
        Args:
            output_queue: Queue to push collected logs to
        """
        if not self.enabled:
            logger.info(f"{self.name} collector is disabled, not starting")
            return
            
        self.output_queue = output_queue
        self.running = True
        
        logger.info(f"Starting {self.name} collector")
        
        try:
            while self.running:
                if time.time() - self.last_collection >= self.collection_interval:
                    try:
                        logs = await self.collect()
                        if logs:
                            logger.info(f"{self.name} collector retrieved {len(logs)} log entries")
                            for log in logs:
                                # Add metadata
                                log["_collector"] = self.name
                                log["_collected_at"] = time.time()
                                
                                # Put in queue
                                await self.output_queue.put(log)
                                
                            self.last_collection = time.time()
                        else:
                            logger.debug(f"{self.name} collector retrieved no logs")
                    except Exception as e:
                        logger.error(f"Error in {self.name} collector: {e}")
                        
                # Sleep
                await asyncio.sleep(1)
        finally:
            logger.info(f"Stopping {self.name} collector")
            self.running = False
    
    def stop(self):
        """Stop the collector"""
        logger.info(f"Stopping {self.name} collector")
        self.running = False


class FileLogCollector(LogCollector):
    """
    Collector for log files
    Supports both single file and directory monitoring with pattern matching
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the file log collector
        
        Args:
            config: Collector configuration with these additional fields:
                - path: Path to log file or directory
                - pattern: File pattern for directory (e.g., "*.log")
                - read_mode: How to read the file ("full", "tail", or "inotify")
                - position_store: Path to file storing read positions
        """
        super().__init__(config)
        self.path = Path(config["path"])
        self.pattern = config.get("pattern", "*.log")
        self.read_mode = config.get("read_mode", "tail")
        self.position_store_path = config.get("position_store", "/var/lib/asira/file_positions.json")
        self.positions = {}
        
        # Load previous positions if available
        self._load_positions()
        
        logger.info(f"FileLogCollector initialized for {self.path}")
    
    def _load_positions(self):
        """Load stored file positions"""
        if os.path.exists(self.position_store_path):
            try:
                with open(self.position_store_path, 'r') as f:
                    self.positions = json.load(f)
                logger.debug(f"Loaded {len(self.positions)} file positions")
            except Exception as e:
                logger.error(f"Error loading file positions: {e}")
    
    async def _save_positions(self):
        """Save file positions for incremental reading"""
        try:
            os.makedirs(os.path.dirname(self.position_store_path), exist_ok=True)
            async with aiofiles.open(self.position_store_path, 'w') as f:
                await f.write(json.dumps(self.positions))
        except Exception as e:
            logger.error(f"Error saving file positions: {e}")
    
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from files
        
        Returns:
            List of log entries
        """
        logs = []
        
        if self.path.is_dir():
            # Process all matching files in directory
            for file_path in self.path.glob(self.pattern):
                logs.extend(await self._process_file(file_path))
        elif self.path.is_file():
            # Process single file
            logs.extend(await self._process_file(self.path))
        else:
            logger.warning(f"Path does not exist: {self.path}")
        
        # Save positions after processing
        if logs:
            await self._save_positions()
        
        return logs
        
    async def _process_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Process a single log file
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of log entries from the file
        """
        logs = []
        file_key = str(file_path)
        
        try:
            # Check if file exists and has content
            if not file_path.exists() or file_path.stat().st_size == 0:
                return []
                
            # Get the last known position for this file
            last_position = self.positions.get(file_key, 0)
            current_size = file_path.stat().st_size
            
            # Skip if file hasn't changed
            if last_position == current_size and self.read_mode != "full":
                return []
                
            # Reset position if file has been truncated
            if last_position > current_size:
                logger.warning(f"File appears to have been truncated: {file_path}")
                last_position = 0
            
            # Read file
            async with aiofiles.open(file_path, 'r') as file:
                # Seek to last position if not reading full file
                if self.read_mode != "full":
                    await file.seek(last_position)
                
                # Read lines
                line_count = 0
                async for line in file:
                    line = line.strip()
                    if line:
                        logs.append({"message": line, "source_file": str(file_path)})
                        line_count += 1
                        
                        # Limit batch size
                        if line_count >= self.batch_size:
                            break
                
                # Update position
                self.positions[file_key] = await file.tell()
        
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
        
        return logs


class SyslogCollector(LogCollector):
    """
    Collector for syslog messages
    Listens on a UDP socket for syslog messages
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the syslog collector
        
        Args:
            config: Collector configuration with these additional fields:
                - host: Host to bind to
                - port: Port to listen on
                - buffer_size: Maximum UDP packet size
        """
        super().__init__(config)
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 514)
        self.buffer_size = config.get("buffer_size", 8192)
        self.messages = []
        self.lock = asyncio.Lock()
        
        logger.info(f"SyslogCollector initialized on {self.host}:{self.port}")
    
    async def _receive_syslog(self):
        """
        Listen for syslog messages
        This runs as a separate task
        """
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.setblocking(False)
        
        logger.info(f"Syslog listener started on {self.host}:{self.port}")
        
        loop = asyncio.get_event_loop()
        
        try:
            while self.running:
                try:
                    # Wait for data
                    data, addr = await loop.sock_recvfrom(sock, self.buffer_size)
                    message = data.decode('utf-8', errors='ignore').strip()
                    
                    # Store the message
                    async with self.lock:
                        self.messages.append({
                            "message": message,
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "received_at": time.time()
                        })
                        
                        # Limit buffer size
                        if len(self.messages) > self.batch_size * 2:
                            self.messages = self.messages[-self.batch_size:]
                            
                except Exception as e:
                    if self.running:  # Only log if still running
                        logger.error(f"Error receiving syslog message: {e}")
                    await asyncio.sleep(0.1)
                    
        finally:
            sock.close()
            logger.info("Syslog listener stopped")
    
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Collect syslog messages from the buffer
        
        Returns:
            List of syslog message entries
        """
        async with self.lock:
            # Get messages
            messages = self.messages.copy()
            # Clear buffer
            self.messages = []
            
        return messages
    
    async def start(self, output_queue: asyncio.Queue):
        """
        Start the collector and syslog listener
        
        Args:
            output_queue: Queue to push collected logs to
        """
        if not self.enabled:
            logger.info(f"{self.name} collector is disabled, not starting")
            return
            
        self.output_queue = output_queue
        self.running = True
        
        # Start syslog listener task
        listener_task = asyncio.create_task(self._receive_syslog())
        
        # Start collector loop
        try:
            await super().start(output_queue)
        finally:
            self.running = False
            await asyncio.sleep(1)  # Give listener a chance to stop
            if not listener_task.done():
                listener_task.cancel()


class APILogCollector(LogCollector):
    """
    Collector for logs from REST APIs
    Periodically queries APIs and collects log data
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the API log collector
        
        Args:
            config: Collector configuration with these additional fields:
                - url: API endpoint URL
                - method: HTTP method (GET, POST)
                - headers: HTTP headers
                - auth: Authentication (basic, token)
                - username: Username for basic auth
                - password: Password for basic auth
                - token: Token for token auth
                - data: POST data
                - params: Query parameters
                - response_format: Format of response (json, xml, text)
                - timestamp_field: Field containing the timestamp
                - timestamp_format: Format of timestamp
        """
        super().__init__(config)
        self.url = config["url"]
        self.method = config.get("method", "GET")
        self.headers = config.get("headers", {})
        self.auth_type = config.get("auth", None)
        self.username = config.get("username")
        self.password = config.get("password")
        self.token = config.get("token")
        self.data = config.get("data", {})
        self.params = config.get("params", {})
        self.response_format = config.get("response_format", "json")
        self.timestamp_field = config.get("timestamp_field")
        self.timestamp_format = config.get("timestamp_format")
        self.json_path = config.get("json_path", None)  # Path to logs in JSON response
        self.last_timestamp = config.get("start_time", None)
        
        logger.info(f"APILogCollector initialized for {self.url}")
    
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from the API
        
        Returns:
            List of log entries
        """
        logs = []
        
        try:
            # Prepare request parameters
            auth = None
            headers = self.headers.copy()
            
            if self.auth_type == "basic":
                auth = aiohttp.BasicAuth(self.username, self.password)
            elif self.auth_type == "token":
                headers["Authorization"] = f"Bearer {self.token}"
                
            # Add timestamp filter if available
            params = self.params.copy()
            if self.last_timestamp and "timestamp_param" in self.config:
                params[self.config["timestamp_param"]] = self.last_timestamp
                
            # Make request
            async with aiohttp.ClientSession() as session:
                if self.method == "GET":
                    async with session.get(
                        self.url, 
                        headers=headers, 
                        params=params,
                        auth=auth
                    ) as response:
                        if response.status == 200:
                            logs = await self._parse_response(response)
                        else:
                            logger.error(f"API request failed with status {response.status}")
                        
                elif self.method == "POST":
                    async with session.post(
                        self.url, 
                        headers=headers, 
                        params=params,
                        json=self.data,
                        auth=auth
                    ) as response:
                        if response.status == 200:
                            logs = await self._parse_response(response)
                        else:
                            logger.error(f"API request failed with status {response.status}")
                
                else:
                    logger.error(f"Unsupported HTTP method: {self.method}")
                    
        except Exception as e:
            logger.error(f"Error collecting logs from API: {e}")
            
        return logs
    
    async def _parse_response(self, response) -> List[Dict[str, Any]]:
        """
        Parse API response based on format
        
        Args:
            response: aiohttp response object
            
        Returns:
            List of log entries
        """
        logs = []
        
        try:
            if self.response_format == "json":
                data = await response.json()
                
                # Extract logs from json_path if specified
                if self.json_path:
                    current = data
                    for key in self.json_path.split('.'):
                        if key in current:
                            current = current[key]
                        else:
                            logger.error(f"JSON path '{self.json_path}' not found in response")
                            return []
                    
                    if isinstance(current, list):
                        logs = current
                    else:
                        logger.error(f"Expected list at JSON path '{self.json_path}', got {type(current)}")
                        return []
                else:
                    # Assume the response is a list of logs or a single log
                    if isinstance(data, list):
                        logs = data
                    else:
                        logs = [data]
                
            elif self.response_format == "text":
                text = await response.text()
                # Split text into lines
                lines = text.strip().split('\n')
                logs = [{"message": line} for line in lines if line.strip()]
                
            else:
                logger.error(f"Unsupported response format: {self.response_format}")
                
            # Update last timestamp if specified
            if logs and self.timestamp_field:
                try:
                    # Find the most recent timestamp
                    timestamps = []
                    for log in logs:
                        if self.timestamp_field in log:
                            ts_value = log[self.timestamp_field]
                            if self.timestamp_format:
                                # Parse timestamp and convert to string format expected by API
                                dt = datetime.datetime.strptime(ts_value, self.timestamp_format)
                                timestamps.append(dt)
                            else:
                                # Assume it's already in the right format
                                timestamps.append(ts_value)
                    
                    if timestamps:
                        self.last_timestamp = max(timestamps)
                        if isinstance(self.last_timestamp, datetime.datetime):
                            self.last_timestamp = self.last_timestamp.strftime(self.timestamp_format)
                        logger.debug(f"Updated last timestamp to {self.last_timestamp}")
                except Exception as e:
                    logger.error(f"Error updating last timestamp: {e}")
                
        except Exception as e:
            logger.error(f"Error parsing API response: {e}")
            
        return logs


class CloudWatchLogCollector(LogCollector):
    """
    Collector for AWS CloudWatch logs
    Requires boto3
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the CloudWatch log collector
        
        Args:
            config: Collector configuration with these additional fields:
                - log_group: CloudWatch log group name
                - log_stream_prefix: Prefix for log streams
                - aws_region: AWS region
                - aws_access_key: AWS access key
                - aws_secret_key: AWS secret key
                - start_time: Start time in epoch milliseconds
        """
        super().__init__(config)
        self.log_group = config["log_group"]
        self.log_stream_prefix = config.get("log_stream_prefix", "")
        self.aws_region = config.get("aws_region", "us-east-1")
        self.aws_access_key = config.get("aws_access_key")
        self.aws_secret_key = config.get("aws_secret_key")
        self.start_time = config.get("start_time", int(time.time() * 1000) - 3600000)  # Default to 1 hour ago
        self.next_token = None
        
        # Import boto3 here to make it an optional dependency
        try:
            import boto3
            self.boto3_available = True
            
            # Create CloudWatch logs client
            session = boto3.Session(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.aws_region
            )
            self.logs_client = session.client('logs')
            
            logger.info(f"CloudWatchLogCollector initialized for {self.log_group}")
            
        except ImportError:
            logger.error("boto3 is not installed, CloudWatchLogCollector will not work")
            self.boto3_available = False
        except Exception as e:
            logger.error(f"Error initializing CloudWatchLogCollector: {e}")
            self.boto3_available = False
    
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from CloudWatch
        
        Returns:
            List of log entries
        """
        if not self.boto3_available:
            logger.error("boto3 is not available, cannot collect CloudWatch logs")
            return []
            
        logs = []
        
        try:
            # Use asyncio to run boto3 calls in a thread pool
            loop = asyncio.get_event_loop()
            
            # Get log events
            kwargs = {
                'logGroupName': self.log_group,
                'startTime': self.start_time,
                'limit': self.batch_size
            }
            
            if self.log_stream_prefix:
                # Get matching log streams
                stream_response = await loop.run_in_executor(
                    None, 
                    lambda: self.logs_client.describe_log_streams(
                        logGroupName=self.log_group,
                        logStreamNamePrefix=self.log_stream_prefix,
                        limit=50  # Limit the number of streams
                    )
                )
                
                # Process each stream
                for stream in stream_response.get('logStreams', []):
                    stream_name = stream['logStreamName']
                    
                    # Get events from this stream
                    stream_kwargs = kwargs.copy()
                    stream_kwargs['logStreamName'] = stream_name
                    
                    if self.next_token:
                        stream_kwargs['nextToken'] = self.next_token
                    
                    response = await loop.run_in_executor(
                        None, 
                        lambda: self.logs_client.get_log_events(**stream_kwargs)
                    )
                    
                    # Extract events
                    for event in response.get('events', []):
                        logs.append({
                            'message': event.get('message', ''),
                            'timestamp': event.get('timestamp', 0),
                            'log_group': self.log_group,
                            'log_stream': stream_name
                        })
                    
                    # Save next token
                    self.next_token = response.get('nextForwardToken')
                    
                    # Update start time
                    if logs and 'timestamp' in logs[-1]:
                        self.start_time = logs[-1]['timestamp'] + 1
            
            else:
                # Query all streams in the group
                if self.next_token:
                    kwargs['nextToken'] = self.next_token
                    
                response = await loop.run_in_executor(
                    None, 
                    lambda: self.logs_client.filter_log_events(**kwargs)
                )
                
                # Extract events
                for event in response.get('events', []):
                    logs.append({
                        'message': event.get('message', ''),
                        'timestamp': event.get('timestamp', 0),
                        'log_group': self.log_group,
                        'log_stream': event.get('logStreamName', '')
                    })
                
                # Save next token
                self.next_token = response.get('nextToken')
                
                # Update start time
                if logs and 'timestamp' in logs[-1]:
                    self.start_time = logs[-1]['timestamp'] + 1
                    
            logger.info(f"Retrieved {len(logs)} CloudWatch log entries")
                    
        except Exception as e:
            logger.error(f"Error collecting CloudWatch logs: {e}")
            
        return logs


# Factory function to create collectors
def create_collector(config: Dict[str, Any]) -> LogCollector:
    """
    Create a log collector based on configuration
    
    Args:
        config: Collector configuration with type field
        
    Returns:
        Initialized LogCollector instance
        
    Raises:
        ValueError: If collector type is unknown
    """
    collector_type = config.get("type")
    
    if collector_type == "file":
        return FileLogCollector(config)
    elif collector_type == "syslog":
        return SyslogCollector(config)
    elif collector_type == "api":
        return APILogCollector(config)
    elif collector_type == "cloudwatch":
        return CloudWatchLogCollector(config)
    else:
        raise ValueError(f"Unknown collector type: {collector_type}")


# Collection manager to handle multiple collectors
class CollectionManager:
    """
    Manages multiple log collectors
    Coordinates collecting logs from multiple sources
    """
    
    def __init__(self, collector_configs: List[Dict[str, Any]]):
        """
        Initialize the collection manager
        
        Args:
            collector_configs: List of collector configurations
        """
        self.collectors = []
        self.log_queue = asyncio.Queue()
        self.normalizer_queue = asyncio.Queue()
        self.running = False
        self.tasks = []
        
        # Create collectors
        for config in collector_configs:
            try:
                collector = create_collector(config)
                self.collectors.append(collector)
            except Exception as e:
                logger.error(f"Error creating collector: {e}")
        
        logger.info(f"Collection manager initialized with {len(self.collectors)} collectors")
    
    async def start(self):
        """
        Start all collectors
        """
        self.running = True
        
        # Start collectors
        for collector in self.collectors:
            task = asyncio.create_task(collector.start(self.log_queue))
            self.tasks.append(task)
            
        # Start processor task
        processor_task = asyncio.create_task(self._process_logs())
        self.tasks.append(processor_task)
        
        logger.info(f"Started {len(self.collectors)} collectors")
    
    async def stop(self):
        """
        Stop all collectors
        """
        self.running = False
        
        # Stop collectors
        for collector in self.collectors:
            collector.stop()
            
        # Cancel tasks
        for task in self.tasks:
            if not task.done():
                task.cancel()
        
        logger.info("Stopped all collectors")
    
    async def _process_logs(self):
        """
        Process logs from the queue and forward to normalizer queue
        """
        try:
            while self.running:
                try:
                    # Get a log entry
                    log = await asyncio.wait_for(self.log_queue.get(), timeout=1.0)
                    
                    # Forward to normalizer queue
                    await self.normalizer_queue.put(log)
                    
                    # Mark task as done
                    self.log_queue.task_done()
                    
                except asyncio.TimeoutError:
                    # No logs available, continue
                    pass
                except Exception as e:
                    logger.error(f"Error processing logs: {e}")
        except asyncio.CancelledError:
            logger.info("Log processor task cancelled")
        except Exception as e:
            logger.error(f"Unexpected error in log processor: {e}")
