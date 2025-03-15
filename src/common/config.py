"""
Configuration management for ASIRA

Handles loading and providing application configuration from environment
variables, files, and default values.

Version: 1.0.0
Last updated: 2025-03-15
"""
import os
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseSettings, validator, Field

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
    
    # API Settings
    api_port: int = 8000
    api_host: str = "0.0.0.0"
    api_workers: int = 4
    log_level: str = "INFO"
    cors_origins: List[str] = ["*"]
    
    # Database Settings
    db_host: str = "localhost"
    db_port: int = 5432
    db_user: str = "asira"
    db_password: str = Field("", env="ASIRA_DB_PASSWORD")
    db_name: str = "asira"
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_echo: bool = False
    
    # Elasticsearch Settings
    es_enabled: bool = True
    es_hosts: List[str] = ["http://localhost:9200"]
    es_username: Optional[str] = None
    es_password: Optional[str] = None
    es_index_prefix: str = "asira_"
    es_shards: int = 1
    es_replicas: int = 0
    
    # RabbitMQ Settings
    rabbitmq_enabled: bool = True
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672/"
    rabbitmq_exchange: str = "asira"
    rabbitmq_queue_prefix: str = "asira_"
    rabbitmq_heartbeat: int = 60
    
    # Redis Settings
    redis_enabled: bool = True
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: Optional[str] = None
    redis_db: int = 0
    
    # Security Settings
    secret_key: str = Field("CHANGE_THIS_TO_A_SECURE_VALUE", env="ASIRA_SECRET_KEY")
    token_expire_minutes: int = 60 * 24  # 24 hours
    password_min_length: int = 10
    hash_algorithm: str = "bcrypt"
    
    # Playbook Settings
    playbook_dir: str = "/etc/asira/playbooks"
    execution_dir: str = "/tmp/asira/execution"
    max_execution_time: int = 300  # seconds
    sandbox_type: str = "container"  # Options: none, chroot, container, vm
    execution_timeout: int = 300  # seconds
    max_parallel_executions: int = 5
    
    # Detection Settings
    detection_enabled: bool = True
    detection_interval: int = 300  # seconds
    baseline_update_interval: int = 86400  # 24 hours in seconds
    min_anomaly_score: float = 0.7
    max_false_positive_rate: float = 0.01
    
    # File Storage Settings
    storage_dir: str = "/var/lib/asira"
    max_file_size: int = 10 * 1024 * 1024  # 10 MB
    allowed_extensions: List[str] = ["pdf", "txt", "csv", "json", "yml", "yaml", "log"]
    
    # Notification Settings
    notifications_enabled: bool = True
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    email_from: str = "asira@example.com"
    slack_webhook_url: Optional[str] = None
    
    # Validation and transformations
    @validator('cors_origins', pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
    
    @validator('es_hosts', pre=True)
    def parse_es_hosts(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
        
    @validator('allowed_extensions', pre=True)
    def parse_allowed_extensions(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(',')]
        return v
    
    @validator('secret_key')
    def validate_secret_key(cls, v):
        if v == "CHANGE_THIS_TO_A_SECURE_VALUE":
            logger.warning("Using default secret key. This is insecure! Set ASIRA_SECRET_KEY environment variable.")
        return v
        
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
            Path(self.storage_dir) / "logs",
            Path(self.storage_dir) / "uploads",
            Path(self.storage_dir) / "models",
        ]
        
        for directory in directories:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created directory: {directory}")
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {e}")
    
    class Config:
        env_prefix = "ASIRA_"
        env_file = ".env"
        case_sensitive = False
