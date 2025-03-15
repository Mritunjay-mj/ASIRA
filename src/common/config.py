"""
Configuration management for ASIRA

Handles loading and providing application configuration from environment
variables, files, and default values.

Version: 1.0.0
Last updated: 2025-03-15 17:05:10
Last updated by: Mritunjay-mj
"""
import os
import json
import logging
import secrets
import socket
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any, Union, Set
from pydantic import BaseSettings, validator, Field, AnyHttpUrl, root_validator

# Configure basic logging for the config module itself
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("asira.config")

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables with defaults
    """
    # Basic Settings
    app_name: str = "ASIRA"
    app_version: str = "1.0.0"
    app_description: str = "Automated Security Incident Response Agent"
    debug_mode: bool = False
    environment: str = "production"  # production, development, testing
    
    # API Settings
    api_port: int = 8000
    api_host: str = "0.0.0.0"
    api_workers: int = 4
    log_level: str = "INFO"
    cors_origins: List[str] = ["*"]
    trusted_hosts: Optional[List[str]] = None
    
    # Database Settings
    db_host: str = "localhost"
    db_port: int = 5432
    db_user: str = "asira"
    db_password: str = Field("", env="ASIRA_DB_PASSWORD")
    db_name: str = "asira"
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_echo: bool = False
    db_ssl: bool = True
    db_schema: str = "public"
    db_connection_timeout: int = 30
    
    # Elasticsearch Settings
    es_enabled: bool = True
    es_hosts: List[str] = ["http://localhost:9200"]
    es_username: Optional[str] = None
    es_password: Optional[str] = None
    es_index_prefix: str = "asira_"
    es_shards: int = 1
    es_replicas: int = 0
    es_index_lifecycle_policy: Optional[str] = None
    es_timeout: int = 30
    es_retry_on_timeout: bool = True
    es_max_retries: int = 3
    
    # RabbitMQ Settings
    rabbitmq_enabled: bool = True
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672/"
    rabbitmq_exchange: str = "asira"
    rabbitmq_queue_prefix: str = "asira_"
    rabbitmq_heartbeat: int = 60
    rabbitmq_connection_timeout: int = 30
    rabbitmq_ssl: bool = False
    rabbitmq_ssl_verify: bool = True
    rabbitmq_max_retries: int = 10
    rabbitmq_retry_delay: int = 5
    
    # Redis Settings
    redis_enabled: bool = True
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: Optional[str] = None
    redis_db: int = 0
    redis_ssl: bool = False
    redis_timeout: int = 10
    redis_connection_pool_size: int = 10
    redis_key_prefix: str = "asira:"
    redis_health_check_interval: int = 30
    
    # Security Settings
    secret_key: str = Field("CHANGE_THIS_TO_A_SECURE_VALUE", env="ASIRA_SECRET_KEY")
    token_expire_minutes: int = 60 * 24  # 24 hours
    password_min_length: int = 10
    hash_algorithm: str = "bcrypt"
    bcrypt_rounds: int = 12
    verify_ssl: bool = True
    api_key_expiration_days: int = 180
    session_cookies_secure: bool = True
    session_cookies_http_only: bool = True
    allowed_hosts: List[str] = ["*"]
    rate_limit_enabled: bool = True
    rate_limit_per_second: int = 20
    jwt_algorithm: str = "HS256"
    
    # Playbook Settings
    playbook_dir: str = "/etc/asira/playbooks"
    execution_dir: str = "/tmp/asira/execution"
    max_execution_time: int = 300  # seconds
    sandbox_type: str = "container"  # Options: none, chroot, container, vm
    execution_timeout: int = 300  # seconds
    max_parallel_executions: int = 5
    playbook_validation_level: str = "strict"  # Options: strict, moderate, lenient
    docker_image: str = "asira/execution-sandbox:latest"
    docker_network: Optional[str] = None
    docker_registry: Optional[str] = None
    docker_username: Optional[str] = None
    docker_password: Optional[str] = None
    playbook_cache_enabled: bool = True
    playbook_cache_ttl: int = 300  # seconds
    
    # Detection Settings
    detection_enabled: bool = True
    detection_interval: int = 300  # seconds
    baseline_update_interval: int = 86400  # 24 hours in seconds
    min_anomaly_score: float = 0.7
    max_false_positive_rate: float = 0.01
    detection_models_dir: str = "/var/lib/asira/models"
    detection_backlog_limit: int = 10000
    detection_batch_size: int = 100
    detection_auto_acknowledge_threshold: float = 0.4  # Auto-acknowledge low-score detections
    detection_config: Dict[str, Any] = {
        "algorithms": ["isolation_forest", "local_outlier_factor", "autoencoder"],
        "features": ["source_ip", "destination_ip", "port", "protocol", "bytes", "packets"],
        "preprocessors": ["standard_scaler", "onehot_encoder"],
        "model_update_frequency": 86400  # seconds
    }
    log_normalizer_config: Dict[str, Any] = {
        "timestamp_format": "%Y-%m-%dT%H:%M:%S.%fZ",
        "timestamp_field": "timestamp",
        "ignore_fields": ["raw_message"]
    }
    log_batch_size: int = 1000
    
    # File Storage Settings
    storage_dir: str = "/var/lib/asira"
    max_file_size: int = 10 * 1024 * 1024  # 10 MB
    allowed_extensions: List[str] = ["pdf", "txt", "csv", "json", "yml", "yaml", "log"]
    storage_cleanup_interval: int = 86400  # 24 hours in seconds
    storage_retention_days: int = 90
    enable_file_encryption: bool = False
    file_encryption_key: Optional[str] = None
    upload_chunk_size: int = 1024 * 1024  # 1 MB
    
    # Notification Settings
    notifications_enabled: bool = True
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    email_from: str = "asira@example.com"
    email_templates_dir: str = "/etc/asira/email_templates"
    slack_webhook_url: Optional[str] = None
    slack_channel: Optional[str] = "#security-alerts"
    webhooks: Dict[str, str] = {}
    pagerduty_routing_key: Optional[str] = None
    teams_webhook_url: Optional[str] = None
    
    # Directory Paths 
    log_dir: str = "/var/log/asira"
    tmp_dir: str = "/tmp/asira"
    cache_dir: str = "/var/cache/asira"
    data_dir: str = "/var/lib/asira/data"
    backup_dir: str = "/var/backups/asira"
    
    # Monitoring and Metrics
    enable_metrics: bool = True
    metrics_port: int = 9090
    metrics_path: str = "/metrics"
    prometheus_enabled: bool = False
    statsd_enabled: bool = False
    statsd_host: str = "localhost"
    statsd_port: int = 8125
    statsd_prefix: str = "asira."
    health_check_interval: int = 60  # seconds
    
    # Backup and Maintenance
    backup_enabled: bool = True
    backup_interval: int = 86400  # 24 hours in seconds
    backup_retention_count: int = 7
    backup_compression: bool = True
    backup_encryption: bool = False
    maintenance_window_start: str = "01:00"  # HH:MM in UTC
    maintenance_window_duration: int = 3600  # seconds
    
    # External Integrations
    integration_timeout: int = 30  # seconds
    integration_retry_count: int = 3
    integration_retry_delay: int = 5  # seconds
    siem_integration_enabled: bool = False
    siem_url: Optional[str] = None
    siem_api_key: Optional[str] = None
    threat_intel_enabled: bool = False
    threat_intel_api_url: Optional[str] = None
    threat_intel_api_key: Optional[str] = None
    
    # Validation and transformations
    @validator('cors_origins', pre=True)
    def parse_cors_origins(cls, v):
        """Parse comma-separated string into list"""
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
    
    @validator('es_hosts', pre=True)
    def parse_es_hosts(cls, v):
        """Parse comma-separated string into list"""
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
        
    @validator('allowed_extensions', pre=True)
    def parse_allowed_extensions(cls, v):
        """Parse comma-separated string into list"""
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
    
    @validator('trusted_hosts', pre=True)
    def parse_trusted_hosts(cls, v):
        """Parse comma-separated string into list"""
        if isinstance(v, str) and v:
            return [i.strip() for i in v.split(',')]
        return v
    
    @validator('secret_key')
    def validate_secret_key(cls, v):
        """Validate and warn about insecure secret keys"""
        if v == "CHANGE_THIS_TO_A_SECURE_VALUE":
            logger.warning("Using default secret key. This is insecure! Set ASIRA_SECRET_KEY environment variable.")
            if os.environ.get("ASIRA_ENVIRONMENT", "") == "production":
                logger.error("Default secret key not allowed in production!")
                # Generate a random key for this session
                return secrets.token_hex(32)
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level string"""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in allowed_levels:
            logger.warning(f"Invalid log level: {v}. Using INFO instead.")
            return "INFO"
        return v
    
    @validator('sandbox_type')
    def validate_sandbox_type(cls, v):
        """Validate sandbox type"""
        allowed_types = ["none", "chroot", "container", "vm"]
        v = v.lower()
        if v not in allowed_types:
            logger.warning(f"Invalid sandbox type: {v}. Using none instead.")
            return "none"
        return v
    
    @root_validator
    def validate_elasticsearch_config(cls, values):
        """Validate Elasticsearch configuration"""
        es_enabled = values.get("es_enabled")
        if es_enabled:
            es_hosts = values.get("es_hosts")
            es_username = values.get("es_username")
            es_password = values.get("es_password")
            
            if not es_hosts or not es_hosts[0]:
                logger.warning("Elasticsearch is enabled but no hosts configured")
            
            if (es_username and not es_password) or (not es_username and es_password):
                logger.warning("Elasticsearch username and password should both be set or both be empty")
                
        return values
    
    @root_validator
    def validate_smtp_config(cls, values):
        """Validate SMTP configuration"""
        notifications_enabled = values.get("notifications_enabled")
        if notifications_enabled:
            smtp_server = values.get("smtp_server")
            smtp_username = values.get("smtp_username")
            smtp_password = values.get("smtp_password")
            
            if not smtp_server:
                logger.warning("Notifications are enabled but SMTP server is not configured")
            
            if smtp_server and ((smtp_username and not smtp_password) or (not smtp_username and smtp_password)):
                logger.warning("SMTP username and password should both be set or both be empty")
                
        return values
    
    @property
    def database_url(self) -> str:
        """Construct database URL from components"""
        password = self.db_password.replace("@", "%40") if self.db_password else ""
        url = f"postgresql://{self.db_user}:{password}@{self.db_host}:{self.db_port}/{self.db_name}"
        return url
    
    @property
    def hostname(self) -> str:
        """Get current hostname"""
        return socket.gethostname()
    
    # Additional config loading from file
    def load_from_file(self, config_file: Union[str, Path]) -> "Settings":
        """
        Load additional settings from a JSON or YAML file and return a new Settings instance
        
        Args:
            config_file: Path to the configuration file
            
        Returns:
            Updated Settings instance
        """
        if not isinstance(config_file, Path):
            config_file = Path(config_file)
            
        if not config_file.exists():
            logger.warning(f"Config file {config_file} does not exist, using default settings")
            return self
        
        try:
            if config_file.suffix.lower() == '.json':
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
            elif config_file.suffix.lower() in ('.yaml', '.yml'):
                import yaml
                with open(config_file, 'r') as f:
                    file_config = yaml.safe_load(f)
            else:
                logger.warning(f"Unsupported config file format: {config_file.suffix}")
                return self
                
            # Create a new instance with updated values
            current_dict = self.dict()
            current_dict.update(file_config)
            return Settings(**current_dict)
                
        except Exception as e:
            logger.error(f"Failed to load config from {config_file}: {e}")
            return self
    
    def setup_directories(self):
        """
        Create necessary directories for the application
        """
        directories = [
            self.playbook_dir,
            self.execution_dir,
            self.storage_dir,
            self.log_dir,
            self.tmp_dir,
            self.cache_dir,
            self.data_dir,
            self.backup_dir,
            self.detection_models_dir,
            Path(self.storage_dir) / "logs",
            Path(self.storage_dir) / "uploads",
            Path(self.storage_dir) / "models",
        ]
        
        for directory in directories:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created directory: {directory}")
            except PermissionError:
                logger.error(f"Permission denied while creating directory {directory}")
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {e}")
    
    def get_effective_config(self) -> Dict[str, Any]:
        """
        Get the effective configuration with sensitive fields redacted
        
        Returns:
            Dictionary of configuration values with sensitive information redacted
        """
        config_dict = self.dict()
        
        # Redact sensitive fields
        sensitive_fields = [
            "secret_key", 
            "db_password", 
            "es_password", 
            "smtp_password", 
            "redis_password",
            "file_encryption_key",
            "docker_password",
            "threat_intel_api_key",
            "siem_api_key",
            "pagerduty_routing_key"
        ]
        
        for field in sensitive_fields:
            if field in config_dict and config_dict[field]:
                config_dict[field] = "********"
                
        return config_dict
    
    def log_config_info(self):
        """
        Log configuration information at startup
        """
        logger.info(f"ASIRA {self.app_version} starting in {self.environment} mode")
        logger.info(f"Host: {self.hostname}, API: {self.api_host}:{self.api_port}")
        logger.info(f"Debug mode: {self.debug_mode}, Log level: {self.log_level}")
        
        if self.environment == "development":
            # In development, log more detailed configuration
            for key, value in self.get_effective_config().items():
                if key.startswith("_"):
                    continue
                logger.debug(f"Config: {key}={value}")
    
    def is_production(self) -> bool:
        """Check if running in production mode"""
        return self.environment == "production"
    
    def is_development(self) -> bool:
        """Check if running in development mode"""
        return self.environment == "development"
    
    def is_testing(self) -> bool:
        """Check if running in testing mode"""
        return self.environment == "testing"
    
    class Config:
        env_prefix = "ASIRA_"
        env_file = ".env"
        case_sensitive = False
        validate_assignment = True


# Load config from environment
settings = Settings()

def initialize_config() -> Settings:
    """
    Initialize configuration with file-based overrides
    
    Returns:
        Initialized Settings instance
    """
    global settings
    
    # Try to load from config files in order of precedence
    config_paths = [
        Path("/etc/asira/config.yaml"),  # System-wide
        Path("/etc/asira/config.json"),
        Path.home() / ".config" / "asira" / "config.yaml",  # User-specific
        Path("config.yaml"),  # Current directory
    ]
    
    # Environment variable override for config file
    env_config_file = os.environ.get("ASIRA_CONFIG_FILE")
    if env_config_file:
        config_paths.insert(0, Path(env_config_file))
    
    # Try each config file
    for config_path in config_paths:
        if config_path.exists():
            logger.info(f"Loading configuration from {config_path}")
            settings = settings.load_from_file(config_path)
            break
    
    # Setup required directories
    settings.setup_directories()
    
    # Log configuration details
    settings.log_config_info()
    
    return settings


# Version information for this module
CONFIG_VERSION = "1.0.0"
CONFIG_LAST_UPDATED = "2025-03-15 17:05:10"
CONFIG_LAST_UPDATED_BY = "Rahul"
