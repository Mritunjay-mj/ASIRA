"""
Log collectors for ASIRA
Responsible for collecting logs from various sources

Current version: 1.0.0
Last updated: 2025-03-15 17:36:08
Last updated by: Rahul
"""
import os
import json
import time
import logging
import socket
import asyncio
import datetime
import re
import ssl
import gzip
import uuid
from typing import List, Dict, Any, Optional, Union, Callable, Tuple, Set
import aiofiles
import aiohttp
from pathlib import Path
from abc import ABC, abstractmethod

# Initialize logger
from src.common.logging_config import get_logger
logger = get_logger("asira.data.collectors")

# Import configuration if available
try:
    from src.common.config import settings
except ImportError:
    settings = None
    logger.warning("Settings module not available, using default values")

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
        
        # Configuration for filtering and transforming logs
        self.include_patterns = self._compile_patterns(config.get("include_patterns", []))
        self.exclude_patterns = self._compile_patterns(config.get("exclude_patterns", []))
        self.transform_function = self._get_transform_function(config.get("transform", None))
        
        # Configuration for error handling
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay", 5)  # seconds
        
        # Add collector-specific tags
        self.tags = config.get("tags", [])
        
        # Stats tracking
        self.stats = {
            "collected": 0,
            "filtered": 0,
            "errors": 0,
            "last_success": None,
            "start_time": time.time()
        }
        
        logger.info(f"Initialized {self.name} collector")
    
    def _compile_patterns(self, patterns: List[str]) -> List[re.Pattern]:
        """
        Compile regex patterns for filtering
        
        Args:
            patterns: List of regex pattern strings
            
        Returns:
            List of compiled regex patterns
        """
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern}': {e}")
        return compiled
        
    def _get_transform_function(self, transform_config: Optional[Dict[str, Any]]) -> Optional[Callable]:
        """
        Create a transform function from config
        
        Args:
            transform_config: Transform configuration
            
        Returns:
            Transform function or None
        """
        if not transform_config:
            return None
            
        transform_type = transform_config.get("type", "")
        
        if transform_type == "javascript":
            # For security reasons, only allow JavaScript transforms in development
            if settings and settings.environment == "development":
                try:
                    import js2py
                    js_code = transform_config.get("code", "")
                    transform_func = js2py.eval_js(
                        f"(function(log) {{ {js_code} }})"
                    )
                    return lambda log: transform_func(log)
                except ImportError:
                    logger.error("js2py module not available for JavaScript transforms")
                except Exception as e:
                    logger.error(f"Error creating JavaScript transform: {e}")
        
        elif transform_type == "python":
            # Parse the Python code into a function
            try:
                code = transform_config.get("code", "")
                if code:
                    local_vars = {}
                    exec(f"def transform_func(log):\n{textwrap.indent(code, '    ')}", {}, local_vars)
                    return local_vars["transform_func"]
            except Exception as e:
                logger.error(f"Error creating Python transform: {e}")
        
        elif transform_type == "jq":
            # Use pyjq for jq-style transforms
            try:
                import pyjq
                query = transform_config.get("query", ".")
                return lambda log: pyjq.first(query, log)
            except ImportError:
                logger.error("pyjq module not available for jq transforms")
            except Exception as e:
                logger.error(f"Error creating jq transform: {e}")
                
        return None
        
    def _should_include_log(self, log: Dict[str, Any]) -> bool:
        """
        Check if a log entry should be included based on filters
        
        Args:
            log: Log entry
            
        Returns:
            True if log should be included, False otherwise
        """
        # Convert log to string for pattern matching
        log_str = json.dumps(log)
        
        # Check exclude patterns first
        for pattern in self.exclude_patterns:
            if pattern.search(log_str):
                return False
        
        # If no include patterns, include all logs
        if not self.include_patterns:
            return True
            
        # Otherwise, at least one include pattern must match
        for pattern in self.include_patterns:
            if pattern.search(log_str):
                return True
                
        return False
        
    def _transform_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply transformation to a log entry
        
        Args:
            log: Log entry
            
        Returns:
            Transformed log entry
        """
        if self.transform_function:
            try:
                transformed = self.transform_function(log)
                if transformed is not None:
                    return transformed
            except Exception as e:
                logger.error(f"Error transforming log: {e}")
                
        return log
    
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
                            processed_count = 0
                            
                            for log in logs:
                                # Add metadata
                                log["_collector"] = self.name
                                log["_collected_at"] = time.time()
                                log["_id"] = str(uuid.uuid4())
                                
                                # Add tags
                                if self.tags:
                                    log["_tags"] = self.tags
                                
                                # Apply filters
                                if not self._should_include_log(log):
                                    self.stats["filtered"] += 1
                                    continue
                                    
                                # Apply transformations
                                log = self._transform_log(log)
                                
                                # Put in queue
                                await self.output_queue.put(log)
                                processed_count += 1
                                
                            # Update stats
                            self.stats["collected"] += processed_count
                            self.stats["last_success"] = time.time()
                            self.last_collection = time.time()
                            
                            logger.info(f"{self.name} collector processed {processed_count} log entries ({len(logs) - processed_count} filtered)")
                        else:
                            logger.debug(f"{self.name} collector retrieved no logs")
                    except Exception as e:
                        self.stats["errors"] += 1
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
        
    def get_status(self) -> Dict[str, Any]:
        """
        Get status information for this collector
        
        Returns:
            Status dictionary
        """
        return {
            "name": self.name,
            "type": self.__class__.__name__,
            "enabled": self.enabled,
            "running": self.running,
            "collection_interval": self.collection_interval,
            "last_collection": self.last_collection,
            "stats": self.stats,
            "uptime": time.time() - self.stats["start_time"]
        }


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
                - recursive: Whether to search subdirectories recursively
                - encoding: File encoding (default: utf-8)
                - max_file_size: Maximum file size to process (default: 100MB)
        """
        super().__init__(config)
        self.path = Path(config["path"])
        self.pattern = config.get("pattern", "*.log")
        self.read_mode = config.get("read_mode", "tail")
        self.position_store_path = config.get("position_store", "/var/lib/asira/file_positions.json")
        self.recursive = config.get("recursive", False)
        self.encoding = config.get("encoding", "utf-8")
        self.max_file_size = config.get("max_file_size", 100 * 1024 * 1024)  # 100MB
        self.positions = {}
        self.file_stats = {}  # Store file stats for change detection
        
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
            pattern = self.pattern
            if self.recursive:
                # Use recursive glob for subdirectories
                for file_path in self.path.rglob(pattern):
                    if len(logs) >= self.batch_size:
                        break
                    logs.extend(await self._process_file(file_path))
            else:
                # Non-recursive glob
                for file_path in self.path.glob(pattern):
                    if len(logs) >= self.batch_size:
                        break
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
            if not file_path.exists():
                return []
                
            # Check file size
            file_stat = file_path.stat()
            if file_stat.st_size == 0:
                return []
                
            if file_stat.st_size > self.max_file_size:
                logger.warning(f"File exceeds maximum size limit ({self.max_file_size} bytes): {file_path}")
                if self.read_mode == "full":
                    return []
            
            # Detect if file is compressed
            is_compressed = file_path.name.endswith('.gz')
            
            # Get the last known position for this file
            last_position = self.positions.get(file_key, 0)
            current_size = file_stat.st_size
            
            # Check file stats for changes
            if file_key in self.file_stats:
                old_stat = self.file_stats[file_key]
                # Check if file was modified
                if old_stat['mtime'] == file_stat.st_mtime and old_stat['size'] == current_size:
                    return []  # No changes
            
            # Update file stats
            self.file_stats[file_key] = {
                'mtime': file_stat.st_mtime,
                'size': current_size,
                'inode': file_stat.st_ino
            }
            
            # Skip if file hasn't changed
            if last_position == current_size and self.read_mode != "full":
                return []
                
            # Reset position if file has been truncated or rotated
            if last_position > current_size:
                logger.warning(f"File appears to have been truncated or rotated: {file_path}")
                last_position = 0
            
            # Choose appropriate file opening method
            if is_compressed:
                # For gzipped files, we need to decompress as we read
                # This requires binary mode
                open_mode = 'rb'
                
                # Handle compressed file differently
                with gzip.open(file_path, 'rt', encoding=self.encoding) as file:
                    if self.read_mode != "full":
                        # For compressed files, we need to read from start 
                        # and skip lines we've already processed
                        line_count = 0
                        lines_to_skip = 0
                        
                        # Count lines up to last position
                        while lines_to_skip < last_position:
                            file.readline()
                            lines_to_skip += 1
                    
                    # Read lines
                    for line in file:
                        line = line.strip()
                        if line:
                            logs.append({
                                "message": line, 
                                "source_file": str(file_path),
                                "compressed": True
                            })
                            line_count += 1
                            
                            # Limit batch size
                            if line_count >= self.batch_size:
                                break
                
                # Update position
                self.positions[file_key] = lines_to_skip + line_count
            else:
                # Regular non-compressed file
                async with aiofiles.open(file_path, 'r', encoding=self.encoding, errors='replace') as file:
                    # Seek to last position if not reading full file
                    if self.read_mode != "full":
                        await file.seek(last_position)
                    
                    # Read lines
                    line_count = 0
                    async for line in file:
                        line = line.strip()
                        if line:
                            logs.append({
                                "message": line, 
                                "source_file": str(file_path),
                                "compressed": False
                            })
                            line_count += 1
                            
                            # Limit batch size
                            if line_count >= self.batch_size:
                                break
                    
                    # Update position
                    self.positions[file_key] = await file.tell()
        
        except UnicodeDecodeError as e:
            logger.error(f"Unicode decode error in file {file_path}: {e}. Try specifying a different encoding.")
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
                - protocol: UDP or TCP (default: UDP)
                - tls: Whether to use TLS for TCP connections
                - tls_cert: Path to TLS certificate
                - tls_key: Path to TLS key
                - tls_ca: Path to TLS CA certificate
        """
        super().__init__(config)
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 514)
        self.buffer_size = config.get("buffer_size", 8192)
        self.protocol = config.get("protocol", "UDP").upper()
        self.tls = config.get("tls", False)
        self.tls_cert = config.get("tls_cert")
        self.tls_key = config.get("tls_key")
        self.tls_ca = config.get("tls_ca")
        self.messages = []
        self.lock = asyncio.Lock()
        
        # Validate protocol
        if self.protocol not in ["UDP", "TCP"]:
            logger.error(f"Invalid protocol: {self.protocol}, defaulting to UDP")
            self.protocol = "UDP"
            
        # Validate TLS settings
        if self.tls and self.protocol != "TCP":
            logger.error("TLS can only be used with TCP, disabling TLS")
            self.tls = False
            
        if self.tls and (not self.tls_cert or not self.tls_key):
            logger.error("TLS requires certificate and key, disabling TLS")
            self.tls = False
        
        logger.info(f"SyslogCollector initialized on {self.host}:{self.port} ({self.protocol})")
    
    async def _receive_syslog_udp(self):
        """
        Listen for syslog messages over UDP
        This runs as a separate task
        """
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.setblocking(False)
        
        logger.info(f"Syslog UDP listener started on {self.host}:{self.port}")
        
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
                            "protocol": "UDP",
                            "received_at": time.time()
                        })
                        
                        # Limit buffer size
                        if len(self.messages) > self.batch_size * 2:
                            self.messages = self.messages[-self.batch_size:]
                            
                except Exception as e:
                    if self.running:  # Only log if still running
                        logger.error(f"Error receiving syslog UDP message: {e}")
                    await asyncio.sleep(0.1)
                    
        finally:
            sock.close()
            logger.info("Syslog UDP listener stopped")
    
    async def _handle_tcp_client(self, reader, writer):
        """
        Handle a TCP client connection
        
        Args:
            reader: StreamReader for the client
            writer: StreamWriter for the client
        """
        peer = writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "unknown"
        client_port = peer[1] if peer else 0
        
        logger.debug(f"New syslog TCP connection from {client_ip}:{client_port}")
        
        try:
            while self.running:
                # Read line (syslog messages are line-delimited)
                data = await reader.readline()
                if not data:  # EOF
                    break
                    
                message = data.decode('utf-8', errors='ignore').strip()
                
                # Store the message
                async with self.lock:
                    self.messages.append({
                        "message": message,
                        "source_ip": client_ip,
                        "source_port": client_port,
                        "protocol": "TCP",
                        "tls": self.tls,
                        "received_at": time.time()
                    })
                    
                    # Limit buffer size
                    if len(self.messages) > self.batch_size * 2:
                        self.messages = self.messages[-self.batch_size:]
                        
        except Exception as e:
            if self.running:
                logger.error(f"Error handling syslog TCP client: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            logger.debug(f"Syslog TCP connection closed from {client_ip}:{client_port}")
    
    async def _receive_syslog_tcp(self):
        """
        Listen for syslog messages over TCP
        This runs as a separate task
        """
        try:
            # Setup TLS if enabled
            ssl_context = None
            if self.tls:
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(self.tls_cert, self.tls_key)
                if self.tls_ca:
                    ssl_context.load_verify_locations(self.tls_ca)
                    ssl_context.verify_mode = ssl.CERT_REQUIRED
                
            # Start server
            server = await asyncio.start_server(
                self._handle_tcp_client,
                self.host,
                self.port,
                ssl=ssl_context
            )
            
            protocol = "TLS" if self.tls else "TCP"
            logger.info(f"Syslog {protocol} listener started on {self.host}:{self.port}")
            
            async with server:
                await server.serve_forever()
                
        except Exception as e:
            if self.running:
                logger.error(f"Error in syslog TCP server: {e}")
    
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
        
        # Start appropriate listener based on protocol
        if self.protocol == "UDP":
            listener_task = asyncio.create_task(self._receive_syslog_udp())
        else:  # TCP
            listener_task = asyncio.create_task(self._receive_syslog_tcp())
        
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
                - verify_ssl: Whether to verify SSL certificates
                - timeout: Request timeout in seconds
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
        self.verify_ssl = config.get("verify_ssl", True)
        self.timeout = config.get("timeout", 30)
        self.pagination = config.get("pagination", {})
        
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
            elif self.auth_type == "api_key":
                # Handle API key in header or query parameter
                api_key = self.config.get("api_key", "")
                api_key_name = self.config.get("api_key_name", "api_key")
                api_key_in = self.config.get("api_key_in", "header")
                
                if api_key_in.lower() == "header":
                    headers[api_key_name] = api_key
                elif api_key_in.lower() == "query":
                    self.params[api_key_name] = api_key
                
            # Add timestamp filter if available
            params = self.params.copy()
            if self.last_timestamp and "timestamp_param" in self.config:
                params[self.config["timestamp_param"]] = self.last_timestamp
                
            # Configure timeout and SSL verification
            ssl_context = None if self.verify_ssl else False
            
            # Setup pagination
            page = 1
            has_more = True
            page_param = self.pagination.get("page_param", "page")
            size_param = self.pagination.get("size_param", "size")
            size_value = self.pagination.get("size", self.batch_size)
            max_pages = self.pagination.get("max_pages", 10)
            
            # Make request with pagination if enabled
            async with aiohttp.ClientSession() as session:
                while has_more and page <= max_pages:
                    # Add pagination parameters if pagination is enabled
                    if self.pagination.get("enabled", False):
                        params[page_param] = page
                        params[size_param] = size_value
                    
                    if self.method == "GET":
                        async with session.get(
                            self.url, 
                            headers=headers, 
                            params=params,
                            auth=auth,
                            ssl=ssl_context,
                            timeout=self.timeout
                        ) as response:
                            if response.status == 200:
                                batch_logs = await self._parse_response(response)
                                logs.extend(batch_logs)
                                
                                # If we didn't get a full batch or pagination is not enabled, no need to fetch more
                                if not self.pagination.get("enabled", False) or len(batch_logs) < size_value:
                                    has_more = False
                                else:
                                    page += 1
                            else:
                                logger.error(f"API request failed with status {response.status}")
                                has_more = False  # Stop pagination on error
                        
                    elif self.method == "POST":
                        async with session.post(
                            self.url, 
                            headers=headers, 
                            params=params,
                            json=self.data,
                            auth=auth,
                            ssl=ssl_context,
                            timeout=self.timeout
                        ) as response:
                            if response.status == 200:
                                batch_logs = await self._parse_response(response)
                                logs.extend(batch_logs)
                                
                                # If we didn't get a full batch or pagination is not enabled, no need to fetch more
                                if not self.pagination.get("enabled", False) or len(batch_logs) < size_value:
                                    has_more = False
                                else:
                                    page += 1
                            else:
                                logger.error(f"API request failed with status {response.status}")
                                has_more = False  # Stop pagination on error
                    
                    else:
                        logger.error(f"Unsupported HTTP method: {self.method}")
                        has_more = False
                    
                    # If we've collected enough logs, stop pagination
                    if len(logs) >= self.batch_size:
                        has_more = False
                        
        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error collecting logs from API: {e}")
        except asyncio.TimeoutError:
            logger.error(f"Timeout error collecting logs from API after {self.timeout}s")
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
                
            elif self.response_format == "xml":
                # Parse XML response
                try:
                    import xml.etree.ElementTree as ET
                    text = await response.text()
                    root = ET.fromstring(text)
                    
                    # Extract logs based on configuration
                    log_path = self.config.get("xml_path", ".//log")
                    for log_elem in root.findall(log_path):
                        log_entry = {}
                        for child in log_elem:
                            log_entry[child.tag] = child.text
                        logs.append(log_entry)
                        
                except ImportError:
                    logger.error("XML parsing requires xml.etree.ElementTree module")
                except Exception as e:
                    logger.error(f"Error parsing XML response: {e}")
                
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
            
            # Add source info to each log
            for log in logs:
                log["source_api"] = self.url
                log["collector_name"] = self.name
                
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
        self.aws_session_token = config.get("aws_session_token")
        self.aws_profile = config.get("aws_profile")
        self.start_time = config.get("start_time", int(time.time() * 1000) - 3600000)  # Default to 1 hour ago
        self.next_token = None
        
        # Import boto3 here to make it an optional dependency
        try:
            import boto3
            self.boto3_available = True
            
            # Set up boto3 session
            session_kwargs = {
                'region_name': self.aws_region
            }
            
            # Add credentials if provided
            if self.aws_access_key and self.aws_secret_key:
                session_kwargs['aws_access_key_id'] = self.aws_access_key
                session_kwargs['aws_secret_access_key'] = self.aws_secret_key
                if self.aws_session_token:
                    session_kwargs['aws_session_token'] = self.aws_session_token
            elif self.aws_profile:
                session_kwargs['profile_name'] = self.aws_profile
            
            # Create boto3 session
            session = boto3.Session(**session_kwargs)
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


class AzureLogCollector(LogCollector):
    """
    Collector for Azure Monitor logs
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Azure Log collector
        
        Args:
            config: Collector configuration with these additional fields:
                - workspace_id: Log Analytics workspace ID
                - client_id: Azure AD client ID
                - client_secret: Azure AD client secret
                - tenant_id: Azure AD tenant ID
                - query: Kusto query to execute
                - timespan: Time span for the query in minutes
        """
        super().__init__(config)
        self.workspace_id = config["workspace_id"]
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.tenant_id = config["tenant_id"]
        self.query = config["query"]
        self.timespan = config.get("timespan", 60)  # Default to last 60 minutes
        self.access_token = None
        self.token_expires = 0
        
        logger.info(f"AzureLogCollector initialized for workspace {self.workspace_id}")
    
    async def _get_access_token(self) -> str:
        """
        Get an Azure AD access token
        
        Returns:
            Access token
        """
        # If we have a valid token, use it
        if self.access_token and time.time() < self.token_expires - 60:
            return self.access_token
            
        # Get a new token
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "resource": "https://api.loganalytics.io"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, data=data) as response:
                if response.status != 200:
                    error = await response.text()
                    raise Exception(f"Failed to get access token: {error}")
                    
                token_data = await response.json()
                self.access_token = token_data["access_token"]
                self.token_expires = time.time() + token_data["expires_in"]
                return self.access_token
    
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from Azure Monitor
        
        Returns:
            List of log entries
        """
        logs = []
        
        try:
            # Get access token
            token = await self._get_access_token()
            
            # Build query URL
            query_url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
            
            # Calculate time range
            end_time = datetime.datetime.utcnow()
            start_time = end_time - datetime.timedelta(minutes=self.timespan)
            
            # Format query with time filter if not already present
            query = self.query
            if "where TimeGenerated" not in query:
                time_filter = f"where TimeGenerated >= datetime('{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}') and TimeGenerated <= datetime('{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}')"
                if "where" in query:
                    # Add to existing where clause
                    query = query.replace("where", f"where TimeGenerated >= datetime('{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}') and TimeGenerated <= datetime('{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}') and")
                else:
                    # Add as new where clause
                    parts = query.split("|")
                    query = f"{parts[0]} | {time_filter} | {' | '.join(parts[1:])}" if len(parts) > 1 else f"{parts[0]} | {time_filter}"
            
            # Set up headers
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            # Make request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    query_url,
                    headers=headers,
                    json={"query": query}
                ) as response:
                    if response.status != 200:
                        error = await response.text()
                        logger.error(f"Azure Log Analytics query failed: {error}")
                        return []
                    
                    result = await response.json()
                    
                    # Extract logs from the result
                    if "tables" in result and len(result["tables"]) > 0:
                        table = result["tables"][0]
                        columns = [col["name"] for col in table["columns"]]
                        
                        for row in table["rows"]:
                            log_entry = {}
                            for i, value in enumerate(row):
                                log_entry[columns[i]] = value
                            
                            # Add metadata
                            log_entry["source"] = "azure_monitor"
                            log_entry["workspace_id"] = self.workspace_id
                            
                            logs.append(log_entry)
                    
            logger.info(f"Retrieved {len(logs)} Azure Monitor log entries")
                    
        except Exception as e:
            logger.error(f"Error collecting Azure Monitor logs: {e}")
            
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
    collector_type = config.get("type", "").lower()
    
    if collector_type == "file":
        return FileLogCollector(config)
    elif collector_type == "syslog":
        return SyslogCollector(config)
    elif collector_type == "api":
        return APILogCollector(config)
    elif collector_type == "cloudwatch":
        return CloudWatchLogCollector(config)
    elif collector_type == "azure":
        return AzureLogCollector(config)
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
        self.collector_stats = {}
        
        # Create collectors
        for config in collector_configs:
            try:
                collector = create_collector(config)
                self.collectors.append(collector)
                # Store initial stats
                self.collector_stats[collector.name] = {
                    "type": config.get("type", ""),
                    "enabled": collector.enabled,
                    "status": "initialized",
                    "last_collection": None,
                    "total_logs": 0,
                    "errors": 0
                }
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
            # Update stats
            if collector.name in self.collector_stats:
                self.collector_stats[collector.name]["status"] = "running"
            
        # Start processor task
        processor_task = asyncio.create_task(self._process_logs())
        self.tasks.append(processor_task)
        
        # Start stats tracking task
        stats_task = asyncio.create_task(self._update_stats())
        self.tasks.append(stats_task)
        
        logger.info(f"Started {len(self.collectors)} collectors")
    
    async def stop(self):
        """
        Stop all collectors
        """
        self.running = False
        
        # Stop collectors
        for collector in self.collectors:
            collector.stop()
            # Update stats
            if collector.name in self.collector_stats:
                self.collector_stats[collector.name]["status"] = "stopped"
            
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
                    
                    # Update stats
                    collector_name = log.get("_collector")
                    if collector_name in self.collector_stats:
                        self.collector_stats[collector_name]["total_logs"] += 1
                    
                except asyncio.TimeoutError:
                    # No logs available, continue
                    pass
                except Exception as e:
                    logger.error(f"Error processing logs: {e}")
        except asyncio.CancelledError:
            logger.info("Log processor task cancelled")
        except Exception as e:
            logger.error(f"Unexpected error in log processor: {e}")
    
    async def _update_stats(self):
        """
        Periodically update collector statistics
        """
        try:
            while self.running:
                # Update stats from collectors
                for collector in self.collectors:
                    if collector.name in self.collector_stats:
                        status = collector.get_status()
                        self.collector_stats[collector.name].update({
                            "last_collection": status.get("last_collection"),
                            "errors": status["stats"].get("errors", 0),
                            "status": "running" if collector.running else "stopped"
                        })
                
                # Sleep for 10 seconds
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            logger.info("Stats tracker task cancelled")
        except Exception as e:
            logger.error(f"Unexpected error in stats tracker: {e}")
    
    def get_collector_stats(self) -> Dict[str, Any]:
        """
        Get statistics for all collectors
        
        Returns:
            Dictionary of collector statistics
        """
        stats = {
            "collectors": self.collector_stats,
            "total_collectors": len(self.collectors),
            "active_collectors": sum(1 for c in self.collectors if c.running),
            "queue_size": self.log_queue.qsize(),
            "normalizer_queue_size": self.normalizer_queue.qsize()
        }
        
        return stats


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 17:40:02"
__author__ = "Rahul"
