"""
ASIRA Dashboard Module

Provides visualization, monitoring and interface components for security analytics.
Includes dashboard widgets, metric displays, and interactive visualizations
for security incident monitoring and analysis.

Version: 1.0.0
Last updated: 2025-03-15 19:20:33
Last updated by: Rahul
"""

import logging
from typing import Dict, Any, List, Optional, Union

__version__ = "1.0.0"
__author__ = "Mritunjay-mj"

# Set up module-level logger
logger = logging.getLogger("asira.dashboard")

# Dashboard configuration defaults
DEFAULT_CONFIG = {
    "refresh_interval": 60,  # seconds
    "default_timespan": "24h",
    "theme": "dark",
    "data_retention_days": 30,
    "max_alerts_display": 100,
    "enable_realtime_updates": True,
}

# Dashboard widget types
WIDGET_TYPES = [
    "metric",
    "chart",
    "table",
    "alert_list",
    "status",
    "heatmap",
    "timeline",
    "topology"
]

# List of available chart types
CHART_TYPES = [
    "line",
    "bar",
    "pie",
    "scatter",
    "area",
    "radar",
    "sankey",
    "treemap"
]

# Import key components
try:
    from .widgets import (
        Widget,
        MetricWidget,
        ChartWidget,
        TableWidget,
        AlertListWidget,
        StatusWidget,
        HeatmapWidget,
        TimelineWidget,
        TopologyWidget
    )
    from .layouts import (
        DashboardLayout,
        GridLayout,
        FlexLayout,
        TabLayout
    )
    from .dashboard import Dashboard, DashboardManager
    from .data_sources import DataSource, register_data_source
    from .config import DashboardConfig
    
    # Make key components available at module level
    __all__ = [
        'Widget', 'MetricWidget', 'ChartWidget', 'TableWidget',
        'AlertListWidget', 'StatusWidget', 'HeatmapWidget',
        'TimelineWidget', 'TopologyWidget', 'DashboardLayout',
        'GridLayout', 'FlexLayout', 'TabLayout', 'Dashboard',
        'DashboardManager', 'DataSource', 'register_data_source',
        'DashboardConfig', 'create_dashboard', 'get_dashboard_manager'
    ]
except ImportError as e:
    logger.warning(f"Error importing dashboard components: {e}")
    __all__ = []


# Global dashboard manager instance
_dashboard_manager = None

def get_dashboard_manager() -> 'DashboardManager':
    """
    Get or initialize the global dashboard manager
    
    Returns:
        Global DashboardManager instance
    """
    global _dashboard_manager
    
    if _dashboard_manager is None:
        try:
            from .dashboard import DashboardManager
            _dashboard_manager = DashboardManager()
        except ImportError as e:
            logger.error(f"Could not initialize dashboard manager: {e}")
            raise
            
    return _dashboard_manager


def create_dashboard(
    title: str,
    description: str = "",
    layout: str = "grid",
    widgets: List[Dict[str, Any]] = None,
    config: Dict[str, Any] = None
) -> 'Dashboard':
    """
    Create a new dashboard
    
    Args:
        title: Title of the dashboard
        description: Description of the dashboard
        layout: Layout type (grid, flex, tab)
        widgets: List of widget configurations
        config: Dashboard configuration options
        
    Returns:
        New Dashboard instance
    """
    try:
        from .dashboard import Dashboard
        from .layouts import GridLayout, FlexLayout, TabLayout
        
        # Set default values
        widgets = widgets or []
        config = config or {}
        
        # Create layout
        if layout == "grid":
            layout_instance = GridLayout()
        elif layout == "flex":
            layout_instance = FlexLayout()
        elif layout == "tab":
            layout_instance = TabLayout()
        else:
            raise ValueError(f"Unsupported layout type: {layout}")
            
        # Create dashboard
        dashboard = Dashboard(
            title=title,
            description=description,
            layout=layout_instance,
            config=config
        )
        
        # Add widgets
        for widget_config in widgets:
            dashboard.add_widget_from_config(widget_config)
            
        return dashboard
        
    except ImportError as e:
        logger.error(f"Could not create dashboard: {e}")
        raise


def register_widget_type(name: str, widget_class) -> bool:
    """
    Register a new widget type
    
    Args:
        name: Name of the widget type
        widget_class: Widget class
        
    Returns:
        True if registered successfully, False otherwise
    """
    try:
        from .widgets import register_widget_class
        return register_widget_class(name, widget_class)
    except ImportError as e:
        logger.error(f"Could not register widget type: {e}")
        return False


def get_available_dashboards() -> List[Dict[str, Any]]:
    """
    Get a list of all available dashboards
    
    Returns:
        List of dashboard metadata
    """
    manager = get_dashboard_manager()
    return manager.list_dashboards()


def get_dashboard_by_id(dashboard_id: str) -> Optional['Dashboard']:
    """
    Get a dashboard by ID
    
    Args:
        dashboard_id: Dashboard ID
        
    Returns:
        Dashboard instance or None if not found
    """
    manager = get_dashboard_manager()
    return manager.get_dashboard(dashboard_id)
