"""
Response Module

Provides components for handling and responding to detected anomalies.
Includes notification mechanisms, response policies, and action handlers.

Version: 1.0.0
Last updated: 2025-03-15 19:04:49
Last updated by: Rahul
"""

from typing import Dict, Any, List, Callable, Optional, Union
import logging

__version__ = "1.0.0"
__author__ = "Mritunjay-mj"

# Set up module-level logger
logger = logging.getLogger("asira.response")

# Registry for response handlers
_response_handlers: Dict[str, Callable] = {}

# Registry for notification channels
_notification_channels: Dict[str, Callable] = {}

# Define severity levels
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Default thresholds for severity levels
DEFAULT_SEVERITY_THRESHOLDS = {
    SEVERITY_LOW: 0.5,
    SEVERITY_MEDIUM: 0.7,
    SEVERITY_HIGH: 0.85,
    SEVERITY_CRITICAL: 0.95
}


def register_response_handler(name: str, handler: Callable) -> None:
    """
    Register a response handler function
    
    Args:
        name: Unique name for the handler
        handler: Handler function
    """
    global _response_handlers
    _response_handlers[name] = handler
    logger.debug(f"Registered response handler: {name}")


def register_notification_channel(name: str, channel: Callable) -> None:
    """
    Register a notification channel
    
    Args:
        name: Unique name for the notification channel
        channel: Channel function for sending notifications
    """
    global _notification_channels
    _notification_channels[name] = channel
    logger.debug(f"Registered notification channel: {name}")


def get_response_handler(name: str) -> Optional[Callable]:
    """
    Get a registered response handler by name
    
    Args:
        name: Handler name
        
    Returns:
        Handler function if registered, None otherwise
    """
    return _response_handlers.get(name)


def get_notification_channel(name: str) -> Optional[Callable]:
    """
    Get a registered notification channel by name
    
    Args:
        name: Channel name
        
    Returns:
        Channel function if registered, None otherwise
    """
    return _notification_channels.get(name)


def get_severity_level(score: float, thresholds: Optional[Dict[str, float]] = None) -> str:
    """
    Determine severity level based on anomaly score
    
    Args:
        score: Anomaly score (0.0 to 1.0)
        thresholds: Optional custom thresholds
        
    Returns:
        Severity level string
    """
    if thresholds is None:
        thresholds = DEFAULT_SEVERITY_THRESHOLDS
    
    if score >= thresholds[SEVERITY_CRITICAL]:
        return SEVERITY_CRITICAL
    elif score >= thresholds[SEVERITY_HIGH]:
        return SEVERITY_HIGH
    elif score >= thresholds[SEVERITY_MEDIUM]:
        return SEVERITY_MEDIUM
    elif score >= thresholds[SEVERITY_LOW]:
        return SEVERITY_LOW
    else:
        return "normal"


def format_anomaly_report(anomaly_data: Dict[str, Any], 
                         include_explanation: bool = True) -> Dict[str, Any]:
    """
    Format anomaly data into a standardized report structure
    
    Args:
        anomaly_data: Raw anomaly data
        include_explanation: Whether to include detailed explanations
        
    Returns:
        Formatted anomaly report
    """
    # Extract basic information
    score = anomaly_data.get("score", 0.0)
    
    report = {
        "timestamp": anomaly_data.get("timestamp", None),
        "score": score,
        "severity": get_severity_level(score),
        "entity_id": anomaly_data.get("entity_id", None),
        "entity_type": anomaly_data.get("entity_type", None),
        "detection_model": anomaly_data.get("model_id", None),
        "is_anomaly": score >= DEFAULT_SEVERITY_THRESHOLDS[SEVERITY_LOW]
    }
    
    # Include explanation if available and requested
    if include_explanation and "explanation" in anomaly_data:
        report["explanation"] = anomaly_data["explanation"]
        
        # Add top contributing factors
        if isinstance(anomaly_data["explanation"], dict):
            factors = sorted(
                anomaly_data["explanation"].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
            report["top_factors"] = dict(factors)
    
    return report


# Import common response components
try:
    from .handlers import basic_response_handler, escalation_handler
    from .notifications import email_notification, webhook_notification
    
    # Register default handlers
    register_response_handler("basic", basic_response_handler)
    register_response_handler("escalation", escalation_handler)
    
    # Register default notification channels
    register_notification_channel("email", email_notification)
    register_notification_channel("webhook", webhook_notification)
    
except ImportError:
    logger.warning("Could not import response handlers or notification channels")
