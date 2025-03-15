"""
ASIRA Dashboard Application
Web-based interface for monitoring security incidents, detections,
and response actions across the organization's infrastructure.

Features:
- Real-time incident visualization
- Detection result analysis 
- Playbook execution tracking
- System health monitoring
- Advanced filtering and search
- User management and access control

Version: 1.0.0
Last updated: 2025-03-15 19:28:00
Last updated by: Mritunjay-mj
"""

import os
import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import requests
import json
from datetime import datetime, timedelta
import time
from typing import Dict, List, Any, Optional, Union, Tuple

# API connection settings
API_URL = os.environ.get("ASIRA_API_URL", "http://localhost:8000/api")
API_TOKEN = os.environ.get("ASIRA_API_TOKEN", "")

# Initialize logger
import logging
logger = logging.getLogger("asira.dashboard")

# Initialize Dash app
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
    title="ASIRA Security Dashboard"
)
server = app.server  # Expose server for production deployment

# Keep track of authentication status
AUTH_STATUS = {"authenticated": False, "username": None, "role": None, "token": None}

# API helper functions
def api_request(endpoint: str, method: str = "GET", data: Dict = None) -> Tuple[Dict, int]:
    """
    Make a request to the ASIRA API
    
    Args:
        endpoint: API endpoint to call
        method: HTTP method (GET, POST, etc.)
        data: Data to send in the request
        
    Returns:
        Tuple of (response_data, status_code)
    """
    url = f"{API_URL}/{endpoint.lstrip('/')}"
    headers = {
        "Content-Type": "application/json"
    }
    
    if AUTH_STATUS.get("token"):
        headers["Authorization"] = f"Bearer {AUTH_STATUS.get('token')}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data)
        elif method.upper() == "PUT":
            response = requests.put(url, headers=headers, json=data)
        elif method.upper() == "PATCH":
            response = requests.patch(url, headers=headers, json=data)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers)
        else:
            return {"error": "Invalid HTTP method"}, 400
            
        # Check if the response is JSON
        try:
            response_data = response.json()
        except ValueError:
            response_data = {"message": response.text}
            
        return response_data, response.status_code
        
    except Exception as e:
        logger.error(f"API request failed: {str(e)}")
        return {"error": str(e)}, 500

def login(username: str, password: str) -> bool:
    """
    Authenticate with the API
    
    Args:
        username: Username
        password: Password
        
    Returns:
        True if authentication successful, False otherwise
    """
    try:
        # Authentication uses OAuth2 password flow
        response = requests.post(
            f"{API_URL}/auth/token",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if response.status_code == 200:
            data = response.json()
            AUTH_STATUS["authenticated"] = True
            AUTH_STATUS["token"] = data.get("access_token")
            
            # Get user details
            user_data, status_code = api_request("users/me")
            if status_code == 200:
                AUTH_STATUS["username"] = user_data.get("username")
                AUTH_STATUS["role"] = user_data.get("role")
            
            return True
        else:
            return False
            
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return False

def logout():
    """Reset authentication status"""
    AUTH_STATUS["authenticated"] = False
    AUTH_STATUS["username"] = None
    AUTH_STATUS["role"] = None
    AUTH_STATUS["token"] = None

def get_incidents(status: str = None, severity: str = None, limit: int = 100) -> List[Dict]:
    """Get incidents from the API"""
    params = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
        
    # Build query string
    query = "&".join([f"{k}={v}" for k, v in params.items()])
    endpoint = f"incidents?{query}"
    
    data, status_code = api_request(endpoint)
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get incidents: {data.get('detail', '')}")
        return []

def get_detections(limit: int = 100, min_score: float = 0.5) -> List[Dict]:
    """Get detections from the API"""
    params = {"limit": limit, "min_score": min_score}
        
    # Build query string
    query = "&".join([f"{k}={v}" for k, v in params.items()])
    endpoint = f"detections?{query}"
    
    data, status_code = api_request(endpoint)
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get detections: {data.get('detail', '')}")
        return []

def get_dashboard_stats() -> Dict:
    """Get dashboard statistics from the API"""
    data, status_code = api_request("dashboard/stats")
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get dashboard stats: {data.get('detail', '')}")
        return {}

def get_playbook_executions(limit: int = 10) -> List[Dict]:
    """Get recent playbook executions from the API"""
    params = {"limit": limit}
    query = "&".join([f"{k}={v}" for k, v in params.items()])
    endpoint = f"response/executions?{query}"
    
    data, status_code = api_request(endpoint)
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get playbook executions: {data.get('detail', '')}")
        return []

def get_available_playbooks() -> List[Dict]:
    """Get available response playbooks from the API"""
    data, status_code = api_request("response/playbooks")
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get available playbooks: {data.get('detail', '')}")
        return []

def get_system_health() -> Dict:
    """Get system health information from the API"""
    data, status_code = api_request("system/health")
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get system health: {data.get('detail', '')}")
        return {}

def get_incident_details(incident_id: str) -> Dict:
    """Get details for a specific incident"""
    data, status_code = api_request(f"incidents/{incident_id}")
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get incident details: {data.get('detail', '')}")
        return {}

def get_detection_details(detection_id: str) -> Dict:
    """Get details for a specific detection"""
    data, status_code = api_request(f"detections/{detection_id}")
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get detection details: {data.get('detail', '')}")
        return {}

def get_event_timeline(entity_id: str = None, days: int = 7) -> List[Dict]:
    """Get event timeline for a specific entity or the overall system"""
    params = {"days": days}
    if entity_id:
        params["entity_id"] = entity_id
        
    query = "&".join([f"{k}={v}" for k, v in params.items()])
    endpoint = f"events/timeline?{query}"
    
    data, status_code = api_request(endpoint)
    if status_code == 200:
        return data
    else:
        logger.error(f"Failed to get event timeline: {data.get('detail', '')}")
        return []

# UI Components
def create_navbar():
    """Create the navigation bar"""
    return dbc.Navbar(
        dbc.Container(
            [
                html.A(
                    dbc.Row(
                        [
                            dbc.Col(html.Img(src="/assets/logo.png", height="30px"), width="auto"),
                            dbc.Col(dbc.NavbarBrand("ASIRA Security Dashboard", className="ms-2")),
                        ],
                        align="center",
                        className="g-0",
                    ),
                    href="/",
                    style={"textDecoration": "none"},
                ),
                dbc.NavbarToggler(id="navbar-toggler", n_clicks=0),
                dbc.Collapse(
                    dbc.Nav(
                        [
                            dbc.NavItem(dbc.NavLink("Overview", href="/")),
                            dbc.NavItem(dbc.NavLink("Incidents", href="/incidents")),
                            dbc.NavItem(dbc.NavLink("Detections", href="/detections")),
                            dbc.NavItem(dbc.NavLink("Playbooks", href="/playbooks")),
                            dbc.NavItem(dbc.NavLink("System Health", href="/health")),
                            dbc.NavItem(dbc.NavLink("Analytics", href="/analytics")),
                            dbc.DropdownMenu(
                                children=[
                                    dbc.DropdownMenuItem("Profile", id="profile-link"),
                                    dbc.DropdownMenuItem("Settings", id="settings-link"),
                                    dbc.DropdownMenuItem(divider=True),
                                    dbc.DropdownMenuItem("Logout", id="logout-button"),
                                ],
                                nav=True,
                                in_navbar=True,
                                label=html.Span([
                                    html.I(className="fas fa-user me-1"),
                                    html.Span(id="user-display-name", children="User")
                                ]),
                                id="user-menu",
                            ),
                        ],
                        className="ms-auto",
                        navbar=True,
                    ),
                    id="navbar-collapse",
                    navbar=True,
                ),
            ]
        ),
        color="dark",
        dark=True,
        className="mb-4",
        sticky="top",
    )

def create_login_form():
    """Create the login form"""
    return dbc.Container(
        dbc.Card(
            dbc.CardBody(
                [
                    html.H2("ASIRA Login", className="text-center mb-4"),
                    html.Div(
                        html.Img(src="/assets/logo-large.png", className="img-fluid mb-4"),
                        className="text-center"
                    ),
                    dbc.Form(
                        [
                            dbc.Row(
                                [
                                    dbc.Label("Username", width="auto"),
                                    dbc.Col(
                                        dbc.Input(
                                            type="text", id="username-input", placeholder="Enter username"
                                        ),
                                        className="me-3",
                                    ),
                                ],
                                className="mb-3",
                            ),
                            dbc.Row(
                                [
                                    dbc.Label("Password", width="auto"),
                                    dbc.Col(
                                        dbc.Input(
                                            type="password", id="password-input", placeholder="Enter password"
                                        ),
                                        className="me-3",
                                    ),
                                ],
                                className="mb-3",
                            ),
                            dbc.Row(
                                dbc.Col(
                                    [
                                        dbc.Button(
                                            "Login", id="login-button", color="primary", className="me-2"
                                        ),
                                        html.Div(id="login-error", className="text-danger mt-2"),
                                    ]
                                ),
                                className="mb-3",
                            ),
                        ]
                    ),
                ]
            ),
            className="shadow",
            style={"maxWidth": "500px", "margin": "100px auto"},
        )
    )

def create_main_layout():
    """Create the main dashboard layout"""
    return dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H2("Security Overview"),
                            html.Div(id="overview-cards"),
                        ],
                        width=12,
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H4("Incidents by Severity"),
                            dcc.Graph(id="severity-chart"),
                        ],
                        width=6,
                    ),
                    dbc.Col(
                        [
                            html.H4("Incidents by Status"),
                            dcc.Graph(id="status-chart"),
                        ],
                        width=6,
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H4("Detection Trends"),
                            dcc.Graph(id="detection-trend-chart"),
                        ],
                        width=12,
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.Div([
                                html.H4("Recent Incidents", className="d-inline"),
                                dbc.Button("View All", color="link", href="/incidents", className="float-end")
                            ]),
                            html.Div(id="recent-incidents-table"),
                        ],
                        width=12,
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.Div([
                                html.H4("Recent Detections", className="d-inline"),
                                dbc.Button("View All", color="link", href="/detections", className="float-end")
                            ]),
                            html.Div(id="recent-detections-table"),
                        ],
                        width=12,
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.Div([
                                html.H4("Recent Playbook Executions", className="d-inline"),
                                dbc.Button("View All", color="link", href="/playbooks", className="float-end")
                            ]),
                            html.Div(id="recent-playbooks-table"),
                        ],
                        width=12,
                    ),
                ],
                className="mb-4",
            ),
            dcc.Interval(
                id="interval-component",
                interval=30 * 1000,  # 30 seconds
                n_intervals=0,
            ),
        ],
        fluid=True,
        className="p-4",
    )

def create_overview_cards(stats: Dict):
    """Create overview statistic cards"""
    return dbc.Row(
        [
            dbc.Col(
                dbc.Card(
                    dbc.CardBody(
                        [
                            html.H5("Open Incidents", className="card-title"),
                            html.H2(stats.get("open_incidents", 0), className="card-text text-primary"),
                            html.P(
                                [
                                    html.Span(
                                        f"{stats.get('new_incidents_today', 0)} new today", 
                                        className="small text-muted"
                                    )
                                ]
                            )
                        ]
                    ),
                    className="shadow text-center h-100",
                ),
                width=3,
            ),
            dbc.Col(
                dbc.Card(
                    dbc.CardBody(
                        [
                            html.H5("Critical Incidents", className="card-title"),
                            html.H2(
                                stats.get("critical_incidents", 0), 
                                className="card-text text-danger"
                            ),
                            html.P(
                                [
                                    html.I(className="fas fa-exclamation-triangle me-1 text-warning"),
                                    html.Span(
                                        f"Requiring immediate attention", 
                                        className="small text-muted"
                                    )
                                ]
                            )
                        ]
                    ),
                    className="shadow text-center h-100",
                ),
                width=3,
            ),
            dbc.Col(
                dbc.Card(
                    dbc.CardBody(
                        [
                            html.H5("Detections Today", className="card-title"),
                            html.H2(stats.get("detections_today", 0), className="card-text text-info"),
                            html.P(
                                [
                                    html.Span(
                                        f"{stats.get('high_confidence_detections', 0)} high confidence", 
                                        className="small text-muted"
                                    )
                                ]
                            )
                        ]
                    ),
                    className="shadow text-center h-100",
                ),
                width=3,
            ),
            dbc.Col(
                dbc.Card(
                    dbc.CardBody(
                        [
                            html.H5("Avg. Response Time", className="card-title"),
                            html.H2(
                                f"{stats.get('avg_response_time', 0)/3600:.1f}h", 
                                className="card-text text-warning"
                            ),
                            html.P(
                                [
                                    html.I(className=f"fas {'fa-arrow-down text-success' if stats.get('response_time_trend', 0) < 0 else 'fa-arrow-up text-danger'} me-1"),
                                    html.Span(
                                        f"{abs(stats.get('response_time_trend', 0)):.1f}% from last week", 
                                        className="small text-muted"
                                    )
                                ]
                            )
                        ]
                    ),
                    className="shadow text-center h-100",
                ),
                width=3,
            ),
        ],
        className="mb-4 g-2",
    )

def create_incidents_table(incidents: List[Dict]):
    """Create a table of recent incidents"""
    if not incidents:
        return html.Div("No incidents found", className="text-muted text-center py-3")
        
    # Create header row
    header = html.Thead(
        html.Tr(
            [
                html.Th("ID"),
                html.Th("Title"),
                html.Th("Severity"),
                html.Th("Status"),
                html.Th("Created"),
                html.Th("Assigned To"),
                html.Th("Actions"),
            ]
        )
    )
    
    # Create rows for each incident
    rows = []
    for incident in incidents[:10]:  # Limit to 10 incidents
        # Convert timestamp to readable date
        created_at = datetime.fromtimestamp(incident.get("created_at", 0))
        created_str = created_at.strftime("%Y-%m-%d %H:%M")
        
        # Determine severity badge class
        severity = incident.get("severity", "").lower()
        if severity == "critical":
            severity_class = "danger"
        elif severity == "high":
            severity_class = "warning"
        elif severity == "medium":
            severity_class = "info"
        else:
            severity_class = "secondary"
            
        # Determine status badge class
        status = incident.get("status", "").lower()
        if status == "open":
            status_class = "primary"
        elif status == "investigating":
            status_class = "info"
        elif status == "contained":
            status_class = "warning"
        elif status == "closed":
            status_class = "success"
        else:
            status_class = "secondary"
            
        # Create row
        row = html.Tr(
            [
                html.Td(incident.get("id", "")),
                html.Td(incident.get("title", "")),
                html.Td(dbc.Badge(severity, color=severity_class, className="px-2")),
                html.Td(dbc.Badge(status, color=status_class, className="px-2")),
                html.Td(created_str),
                html.Td(incident.get("assigned_to", "-")),
                html.Td(
                    dbc.Button(
                        "View", 
                        color="secondary", 
                        size="sm", 
                        href=f"/incidents/{incident.get('id', '')}"
                    )
                ),
            ]
        )
        rows.append(row)
    
    # Create table body
    body = html.Tbody(rows)
    
    # Create table
    return dbc.Table(
        [header, body],
        bordered=True,
        hover=True,
        responsive=True,
        striped=True,
        className="shadow",
    )

def create_detections_table(detections: List[Dict]):
    """Create a table of recent detections"""
    if not detections:
        return html.Div("No detections found", className="text-muted text-center py-3")
        
    # Create header row
    header = html.Thead(
        html.Tr(
            [
                html.Th("ID"),
                html.Th("Entity"),
                html.Th("Score"),
                html.Th("Method"),
                html.Th("Timestamp"),
                html.Th("Actions"),
            ]
        )
    )
    
    # Create rows for each detection
    rows = []
    for detection in detections[:10]:  # Limit to 10 detections
        # Convert timestamp to readable date
        timestamp = datetime.fromtimestamp(detection.get("timestamp", 0))
        time_str = timestamp.strftime("%Y-%m-%d %H:%M")
        
        # Determine score class based on value
        score = detection.get("anomaly_score", 0)
        if score >= 0.8:
            score_class = "danger"
        elif score >= 0.6:
            score_class = "warning"
        else:
            score_class = "info"
            
        # Create row
        row = html.Tr(
            [
                html.Td(detection.get("id", "")),
                html.Td(detection.get("entity_id", "")),
                html.Td(
                    dbc.Progress(
                        f"{int(score * 100)}%", 
                        value=score * 100, 
                        color=score_class,
                        striped=True,
                        animated=True,
                        style={"height": "20px"}
                    )
                ),
                html.Td(detection.get("detection_method", "")),
                html.Td(time_str),
                html.Td(
                    dbc.ButtonGroup(
                        [
                            dbc.Button(
                                "View", 
                                color="secondary", 
                                size="sm", 
                                href=f"/detections/{detection.get('id', '')}"
                            ),
                            dbc.Button(
                                "Respond", 
                                color="primary", 
                                size="sm", 
                                id={"type": "respond-button", "index": detection.get('id', '')}
                            ),
                        ],
                        size="sm",
                    )
                ),
            ]
        )
        rows.append(row)
    
    # Create table body
    body = html.Tbody(rows)
    
    # Create table
    return dbc.Table(
        [header, body],
        bordered=True,
        hover=True,
        responsive=True,
        striped=True,
        className="shadow",
    )

def create_playbooks_table(executions: List[Dict]):
    """Create a table of recent playbook executions"""
    if not executions:
        return html.Div("No playbook executions found", className="text-muted text-center py-3")
        
    # Create header row
    header = html.Thead(
        html.Tr(
            [
                html.Th("ID"),
                html.Th("Playbook"),
                html.Th("Status"),
                html.Th("Triggered By"),
                html.Th("Started"),
                html.Th("Duration"),
                html.Th("Actions"),
            ]
        )
    )
    
    # Create rows for each execution
    rows = []
    for execution in executions[:10]:  # Limit to 10 executions
        # Convert timestamps to readable format
        start_time = datetime.fromtimestamp(execution.get("start_time", 0))
        start_str = start_time.strftime("%Y-%m-%d %H:%M")
        
        # Calculate duration
        end_time = execution.get("end_time", time.time())
        duration_secs = end_time - execution.get("start_time", 0)
        duration_str = f"{int(duration_secs // 60)}m {int(duration_secs % 60)}s"
        
        # Determine status badge class
        status = execution.get("status", "").lower()
        if status == "completed":
            status_class = "success"
        elif status == "failed":
            status_class = "danger"
        elif status == "in_progress":
            status_class = "primary"
        else:
            status_class = "secondary"
            
        # Create row
        row = html.Tr(
            [
                html.Td(execution.get("execution_id", "")),
                html.Td(execution.get("playbook_id", "")),
                html.Td(dbc.Badge(status, color=status_class, className="px-2")),
                html.Td(execution.get("triggered_by", "system")),
                html.Td(start_str),
                html.Td(duration_str),
                html.Td(
                    dbc.Button(
                        "View", 
                        color="secondary", 
                        size="sm", 
                        href=f"/playbooks/executions/{execution.get('execution_id', '')}"
                    )
                ),
            ]
        )
        rows.append(row)
    
    # Create table body
    body = html.Tbody(rows)
    
    # Create table
    return dbc.Table(
        [header, body],
        bordered=True,
        hover=True,
        responsive=True,
        striped=True,
        className="shadow",
    )

def create_incidents_page():
    """Create the incidents page"""
    return dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H2("Incidents"),
                            html.P("Manage and investigate security incidents", className="lead"),
                        ],
                        width=8,
                    ),
                    dbc.Col(
                        [
                            dbc.Button(
                                [html.I(className="fas fa-plus me-2"), "New Incident"],
                                color="primary",
                                className="float-end",
                                id="new-incident-button"
                            ),
                        ],
                        width=4,
                        className="d-flex align-items-center justify-content-end",
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H4("Filters", className="card-title"),
                                        dbc.Form(
                                            [
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Status"),
                                                                dcc.Dropdown(
                                                                    id="incident-status-filter",
                                                                    options=[
                                                                        {"label": "All", "value": "all"},
                                                                        {"label": "Open", "value": "open"},
                                                                        {"label": "Investigating", "value": "investigating"},
                                                                        {"label": "Contained", "value": "contained"},
                                                                        {"label": "Closed", "value": "closed"},
                                                                    ],
                                                                    value="all",
                                                                    clearable=False,
                                                                ),
                                                            ],
                                                            width=4,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Severity"),
                                                                dcc.Dropdown(
                                                                    id="incident-severity-filter",
                                                                    options=[
                                                                        {"label": "All", "value": "all"},
                                                                        {"label": "Critical", "value": "critical"},
                                                                        {"label": "High", "value": "high"},
                                                                        {"label": "Medium", "value": "medium"},
                                                                        {"label": "Low", "value": "low"},
                                                                    ],
                                                                    value="all",
                                                                    clearable=False,
                                                                ),
                                                            ],
                                                            width=4,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Time Range"),
                                                                dcc.Dropdown(
                                                                    id="incident-time-filter",
                                                                    options=[
                                                                        {"label": "All", "value": "all"},
                                                                        {"label": "Last 24 hours", "value": "24h"},
                                                                        {"label": "Last 7 days", "value": "7d"},
                                                                        {"label": "Last 30 days", "value": "30d"},
                                                                        {"label": "Custom range", "value": "custom"},
                                                                    ],
                                                                    value="7d",
                                                                    clearable=False,
                                                                ),
                                                            ],
                                                            width=4,
                                                        ),
                                                    ],
                                                    className="mb-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Search"),
                                                                dbc.InputGroup(
                                                                    [
                                                                        dbc.Input(
                                                                            id="incident-search-input",
                                                                            placeholder="Search by ID, title, or description",
                                                                        ),
                                                                        dbc.InputGroupText(
                                                                            html.I(className="fas fa-search")
                                                                        ),
                                                                    ]
                                                                ),
                                                            ],
                                                            width=8,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Sort By"),
                                                                dcc.Dropdown(
                                                                    id="incident-sort-dropdown",
                                                                    options=[
                                                                        {"label": "Newest First", "value": "newest"},
                                                                        {"label": "Oldest First", "value": "oldest"},
                                                                        {"label": "Severity (High to Low)", "value": "severity_desc"},
                                                                        {"label": "Severity (Low to High)", "value": "severity_asc"},
                                                                    ],
                                                                    value="newest",
                                                                    clearable=False,
                                                                ),
                                                            ],
                                                            width=4,
                                                        ),
                                                    ],
                                                    className="mb-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            dbc.Button(
                                                                [html.I(className="fas fa-filter me-2"), "Apply Filters"],
                                                                id="apply-incident-filters",
                                                                color="primary",
                                                            ),
                                                            width="auto",
                                                        ),
                                                        dbc.Col(
                                                            dbc.Button(
                                                                [html.I(className="fas fa-times me-2"), "Clear Filters"],
                                                                id="clear-incident-filters",
                                                                color="secondary",
                                                            ),
                                                            width="auto",
                                                        ),
                                                    ],
                                                    className="mt-3",
                                                ),
                                            ]
                                        ),
                                    ]
                                ),
                                className="mb-4 shadow",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.Div(id="incidents-table-container", children=[
                                html.Div(id="incidents-loading", children=[
                                    dbc.Spinner(color="primary", size="lg"),
                                    html.P("Loading incidents...", className="text-center")
                                ])
                            ]),
                            dbc.Pagination(
                                id="incidents-pagination",
                                max_value=5,  # Will be updated dynamically
                                first_last=True,
                                previous_next=True,
                                active_page=1,
                                className="mt-3 justify-content-center",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dcc.Interval(
                id="incidents-refresh-interval",
                interval=60 * 1000,  # 60 seconds
                n_intervals=0,
            ),
            # Hidden components for managing state
            dcc.Store(id="incidents-data-store"),
            dcc.Store(id="incidents-filter-state"),
            dcc.Store(id="incidents-pagination-state", data={"current_page": 1, "page_size": 20, "total_pages": 1}),
            
            # Modal for creating new incidents
            dbc.Modal(
                [
                    dbc.ModalHeader(dbc.ModalTitle("Create New Incident")),
                    dbc.ModalBody(
                        dbc.Form(
                            [
                                dbc.Row(
                                    [
                                        dbc.Col(
                                            [
                                                dbc.Label("Title", html_for="incident-title-input"),
                                                dbc.Input(
                                                    type="text",
                                                    id="incident-title-input",
                                                    placeholder="Enter incident title",
                                                ),
                                            ],
                                            width=12,
                                            className="mb-3",
                                        ),
                                    ]
                                ),
                                dbc.Row(
                                    [
                                        dbc.Col(
                                            [
                                                dbc.Label("Description", html_for="incident-description-input"),
                                                dbc.Textarea(
                                                    id="incident-description-input",
                                                    placeholder="Enter incident description",
                                                    style={"height": "150px"},
                                                ),
                                            ],
                                            width=12,
                                            className="mb-3",
                                        ),
                                    ]
                                ),
                                dbc.Row(
                                    [
                                        dbc.Col(
                                            [
                                                dbc.Label("Severity", html_for="incident-severity-input"),
                                                dcc.Dropdown(
                                                    id="incident-severity-input",
                                                    options=[
                                                        {"label": "Critical", "value": "critical"},
                                                        {"label": "High", "value": "high"},
                                                        {"label": "Medium", "value": "medium"},
                                                        {"label": "Low", "value": "low"},
                                                    ],
                                                    value="medium",
                                                ),
                                            ],
                                            width=6,
                                            className="mb-3",
                                        ),
                                        dbc.Col(
                                            [
                                                dbc.Label("Assign To", html_for="incident-assignee-input"),
                                                dcc.Dropdown(
                                                    id="incident-assignee-input",
                                                    options=[
                                                        {"label": "Unassigned", "value": ""},
                                                        {"label": "Current User", "value": "current_user"},
                                                        # Will be populated with available users
                                                    ],
                                                    value="",
                                                ),
                                            ],
                                            width=6,
                                            className="mb-3",
                                        ),
                                    ]
                                ),
                                html.Div(id="incident-create-error", className="text-danger mb-2"),
                            ]
                        )
                    ),
                    dbc.ModalFooter(
                        [
                            dbc.Button(
                                "Close", id="close-incident-modal", className="ms-auto", color="secondary"
                            ),
                            dbc.Button(
                                "Create Incident", id="submit-new-incident", color="primary"
                            ),
                        ]
                    ),
                ],
                id="new-incident-modal",
                size="lg",
                backdrop="static",
            ),
        ],
        fluid=True,
        className="p-4",
    )

def create_detections_page():
    """Create the detections page"""
    return dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H2("Anomaly Detections"),
                            html.P("View and analyze detected security anomalies", className="lead"),
                        ],
                        width=8,
                    ),
                    dbc.Col(
                        [
                            dbc.ButtonGroup(
                                [
                                    dbc.Button(
                                        [html.I(className="fas fa-file-export me-2"), "Export"],
                                        color="secondary",
                                        id="export-detections-button",
                                        className="me-2"
                                    ),
                                    dbc.Button(
                                        [html.I(className="fas fa-sync-alt me-2"), "Refresh"],
                                        color="primary",
                                        id="refresh-detections-button",
                                    ),
                                ],
                                className="float-end",
                            ),
                        ],
                        width=4,
                        className="d-flex align-items-center justify-content-end",
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H5("Detection Distribution"),
                                        dcc.Graph(id="detection-distribution-chart"),
                                    ]
                                ),
                                className="shadow mb-4",
                            ),
                        ],
                        md=6,
                    ),
                    dbc.Col(
                        [
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H5("Detection Method Performance"),
                                        dcc.Graph(id="detection-method-chart"),
                                    ]
                                ),
                                className="shadow mb-4",
                            ),
                        ],
                        md=6,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H4("Filters", className="card-title"),
                                        dbc.Form(
                                            [
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Minimum Score"),
                                                                dcc.Slider(
                                                                    id="detection-score-slider",
                                                                    min=0,
                                                                    max=1,
                                                                    step=0.05,
                                                                    marks={
                                                                        0: "0",
                                                                        0.25: "0.25",
                                                                        0.5: "0.5",
                                                                        0.75: "0.75",
                                                                        1: "1"
                                                                    },
                                                                    value=0.5,
                                                                ),
                                                            ],
                                                            width=6,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Time Range"),
                                                                dcc.Dropdown(
                                                                    id="detection-time-filter",
                                                                    options=[
                                                                        {"label": "Last 24 hours", "value": "24h"},
                                                                        {"label": "Last 7 days", "value": "7d"},
                                                                        {"label": "Last 30 days", "value": "30d"},
                                                                        {"label": "Custom range", "value": "custom"},
                                                                    ],
                                                                    value="24h",
                                                                    clearable=False,
                                                                ),
                                                            ],
                                                            width=6,
                                                        ),
                                                    ],
                                                    className="mb-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Detection Methods"),
                                                                dcc.Dropdown(
                                                                    id="detection-method-filter",
                                                                    options=[
                                                                        {"label": "All Methods", "value": "all"},
                                                                        {"label": "Statistical", "value": "statistical"},
                                                                        {"label": "Machine Learning", "value": "ml"},
                                                                        {"label": "Rule-based", "value": "rule"},
                                                                        {"label": "Ensemble", "value": "ensemble"},
                                                                    ],
                                                                    value="all",
                                                                    multi=True,
                                                                ),
                                                            ],
                                                            width=6,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                dbc.Label("Entity Type"),
                                                                dcc.Dropdown(
                                                                    id="detection-entity-filter",
                                                                    options=[
                                                                        {"label": "All Entities", "value": "all"},
                                                                        {"label": "Users", "value": "user"},
                                                                        {"label": "Hosts", "value": "host"},
                                                                        {"label": "Applications", "value": "application"},
                                                                        {"label": "Networks", "value": "network"},
                                                                    ],
                                                                    value="all",
                                                                    clearable=False,
                                                                ),
                                                            ],
                                                            width=6,
                                                        ),
                                                    ],
                                                    className="mb-3",
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dbc.Button(
                                                                    [html.I(className="fas fa-filter me-2"), "Apply Filters"],
                                                                    id="apply-detection-filters",
                                                                    color="primary",
                                                                ),
                                                                dbc.Button(
                                                                    [html.I(className="fas fa-times me-2"), "Clear"],
                                                                    id="clear-detection-filters",
                                                                    color="secondary",
                                                                    className="ms-2",
                                                                ),
                                                            ],
                                                            width=12,
                                                            className="d-flex justify-content-end",
                                                        ),
                                                    ],
                                                    className="mt-2",
                                                ),
                                            ]
                                        ),
                                    ]
                                ),
                                className="mb-4 shadow",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.Div(id="detections-table-container"),
                            dbc.Pagination(
                                id="detections-pagination",
                                max_value=5,  # Will be updated dynamically
                                first_last=True,
                                previous_next=True,
                                active_page=1,
                                className="mt-3 justify-content-center",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dcc.Interval(
                id="detections-refresh-interval",
                interval=30 * 1000,  # 30 seconds
                n_intervals=0,
            ),
            # Hidden components for managing state
            dcc.Store(id="detections-data-store"),
            dcc.Store(id="detections-filter-state"),
            dcc.Store(id="detections-pagination-state", data={"current_page": 1, "page_size": 20, "total_pages": 1}),
            
            # Modal for detection details
            dbc.Modal(
                [
                    dbc.ModalHeader(dbc.ModalTitle("Detection Details")),
                    dbc.ModalBody(id="detection-details-content"),
                    dbc.ModalFooter(
                        [
                            dbc.Button(
                                "Create Incident", id="create-incident-from-detection", color="warning"
                            ),
                            dbc.Button(
                                "Close", id="close-detection-modal", className="ms-2", color="secondary"
                            ),
                        ]
                    ),
                ],
                id="detection-details-modal",
                size="lg",
            ),
        ],
        fluid=True,
        className="p-4",
    )

def create_playbooks_page():
    """Create the playbooks page"""
    return dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H2("Response Playbooks"),
                            html.P("Manage and monitor automated response playbooks", className="lead"),
                        ],
                        width=8,
                    ),
                    dbc.Col(
                        [
                            dbc.ButtonGroup(
                                [
                                    dbc.Button(
                                        [html.I(className="fas fa-plus me-2"), "New Playbook"],
                                        color="primary",
                                        id="new-playbook-button",
                                        className="me-2"
                                    ),
                                    dbc.Button(
                                        [html.I(className="fas fa-sync-alt me-2"), "Refresh"],
                                        color="secondary",
                                        id="refresh-playbooks-button",
                                    ),
                                ],
                                className="float-end",
                            ),
                        ],
                        width=4,
                        className="d-flex align-items-center justify-content-end",
                    ),
                ],
                className="mb-4",
            ),
            dbc.Tabs(
                [
                    dbc.Tab(
                        [
                            html.Div(id="available-playbooks-content", className="mt-3"),
                        ],
                        label="Available Playbooks",
                        tab_id="available-tab",
                    ),
                    dbc.Tab(
                        [
                            html.Div(id="executions-content", className="mt-3"),
                        ],
                        label="Execution History",
                        tab_id="executions-tab",
                    ),
                    dbc.Tab(
                        [
                            html.Div(id="playbook-statistics-content", className="mt-3"),
                        ],
                        label="Statistics",
                        tab_id="statistics-tab",
                    ),
                ],
                id="playbooks-tabs",
                active_tab="available-tab",
            ),
            
            # Hidden components for managing state
            dcc.Store(id="playbooks-data-store"),
            dcc.Store(id="executions-data-store"),
            dcc.Interval(
                id="playbooks-refresh-interval",
                interval=60 * 1000,  # 60 seconds
                n_intervals=0,
            ),
            
            # Modal for playbook details
            dbc.Modal(
                [
                    dbc.ModalHeader(dbc.ModalTitle("Playbook Details")),
                    dbc.ModalBody(id="playbook-details-content"),
                    dbc.ModalFooter(
                        [
                            dbc.Button(
                                "Execute", id="execute-playbook-button", color="primary"
                            ),
                            dbc.Button(
                                "Close", id="close-playbook-modal", className="ms-2", color="secondary"
                            ),
                        ]
                    ),
                ],
                id="playbook-details-modal",
                size="xl",
            ),
            
            # Modal for execution details
            dbc.Modal(
                [
                    dbc.ModalHeader(dbc.ModalTitle("Execution Details")),
                    dbc.ModalBody(id="execution-details-content"),
                    dbc.ModalFooter(
                        dbc.Button("Close", id="close-execution-modal", color="secondary")
                    ),
                ],
                id="execution-details-modal",
                size="xl",
            ),
        ],
        fluid=True,
        className="p-4",
    )

def create_health_page():
    """Create the system health monitoring page"""
    return dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H2("System Health"),
                            html.P("Monitor the health and performance of the ASIRA system", className="lead"),
                        ],
                        width=8,
                    ),
                    dbc.Col(
                        [
                            dbc.ButtonGroup(
                                [
                                    dbc.Button(
                                        [html.I(className="fas fa-download me-2"), "Export Report"],
                                        color="secondary",
                                        id="export-health-report-button",
                                        className="me-2"
                                    ),
                                    dbc.Button(
                                        [html.I(className="fas fa-sync-alt me-2"), "Refresh"],
                                        color="primary",
                                        id="refresh-health-button",
                                    ),
                                ],
                                className="float-end",
                            ),
                        ],
                        width=4,
                        className="d-flex align-items-center justify-content-end",
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("System Status", className="bg-transparent"),
                                    dbc.CardBody(id="system-status-content"),
                                ],
                                className="mb-4 shadow",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("CPU Usage", className="bg-transparent"),
                                    dbc.CardBody(
                                        dcc.Graph(id="cpu-usage-graph", config={"displayModeBar": False})
                                    ),
                                ],
                                className="mb-4 shadow",
                            ),
                        ],
                        md=6,
                    ),
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("Memory Usage", className="bg-transparent"),
                                    dbc.CardBody(
                                        dcc.Graph(id="memory-usage-graph", config={"displayModeBar": False})
                                    ),
                                ],
                                className="mb-4 shadow",
                            ),
                        ],
                        md=6,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("Disk Usage", className="bg-transparent"),
                                    dbc.CardBody(
                                        dcc.Graph(id="disk-usage-graph", config={"displayModeBar": False})
                                    ),
                                ],
                                className="mb-4 shadow",
                            ),
                        ],
                        md=6,
                    ),
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("Network Traffic", className="bg-transparent"),
                                    dbc.CardBody(
                                        dcc.Graph(id="network-traffic-graph", config={"displayModeBar": False})
                                    ),
                                ],
                                className="mb-4 shadow",
                            ),
                        ],
                        md=6,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("Component Status", className="bg-transparent"),
                                    dbc.CardBody(id="component-status-table"),
                                ],
                                className="mb-4 shadow",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("Recent Logs", className="bg-transparent"),
                                    dbc.CardBody(
                                        [
                                            dbc.Row(
                                                [
                                                    dbc.Col(
                                                        dbc.Select(
                                                            id="log-level-select",
                                                            options=[
                                                                {"label": "All Levels", "value": "all"},
                                                                {"label": "ERROR", "value": "error"},
                                                                {"label": "WARNING", "value": "warning"},
                                                                {"label": "INFO", "value": "info"},
                                                                {"label": "DEBUG", "value": "debug"},
                                                            ],
                                                            value="all",
                                                        ),
                                                        width=4,
                                                    ),
                                                    dbc.Col(
                                                        dbc.Select(
                                                            id="log-component-select",
                                                            options=[
                                                                {"label": "All Components", "value": "all"},
                                                                {"label": "API", "value": "api"},
                                                                {"label": "Detection", "value": "detection"},
                                                                {"label": "Response", "value": "response"},
                                                                {"label": "Dashboard", "value": "dashboard"},
                                                            ],
                                                            value="all",
                                                        ),
                                                        width=4,
                                                    ),
                                                    dbc.Col(
                                                        dbc.Button(
                                                            "Apply Filters",
                                                            id="apply-log-filters",
                                                            color="primary",
                                                            size="sm",
                                                        ),
                                                        width=4,
                                                        className="d-flex justify-content-end align-items-center",
                                                    ),
                                                ],
                                                className="mb-3",
                                            ),
                                            html.Div(id="recent-logs-content", style={"maxHeight": "400px", "overflow": "auto"}),
                                        ]
                                    ),
                                ],
                                className="shadow",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dcc.Interval(
                id="health-refresh-interval",
                interval=10 * 1000,  # 10 seconds
                n_intervals=0,
            ),
            # Hidden components for managing state
            dcc.Store(id="health-data-store"),
        ],
        fluid=True,
        className="p-4",
    )

def create_analytics_page():
    """Create the analytics page"""
    return dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.H2("Security Analytics"),
                            html.P("Advanced analytics and insights for security data", className="lead"),
                        ],
                        width=8,
                    ),
                    dbc.Col(
                        [
                            dbc.ButtonGroup(
                                [
                                    dbc.Button(
                                        [html.I(className="fas fa-file-export me-2"), "Export"],
                                        color="secondary",
                                        id="export-analytics-button",
                                        className="me-2"
                                    ),
                                    dbc.Button(
                                        [html.I(className="fas fa-cog me-2"), "Settings"],
                                        color="primary",
                                        id="analytics-settings-button",
                                    ),
                                ],
                                className="float-end",
                            ),
                        ],
                        width=4,
                        className="d-flex align-items-center justify-content-end",
                    ),
                ],
                className="mb-4",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            dbc.Card(
                                [
                                    dbc.CardHeader("Analysis Controls", className="bg-transparent"),
                                    dbc.CardBody(
                                        [
                                            dbc.Row(
                                                [
                                                    dbc.Col(
                                                        [
                                                            dbc.Label("Time Range"),
                                                            dcc.Dropdown(
                                                                id="analytics-time-range",
                                                                options=[
                                                                    {"label": "Last 24 hours", "value": "24h"},
                                                                    {"label": "Last 7 days", "value": "7d"},
                                                                    {"label": "Last 30 days", "value": "30d"},
                                                                    {"label": "Last 90 days", "value": "90d"},
                                                                    {"label": "Custom range", "value": "custom"},
                                                                ],
                                                                value="7d",
                                                                clearable=False,
                                                            ),
                                                        ],
                                                        md=4,
                                                    ),
                                                    dbc.Col(
                                                        [
                                                            dbc.Label("Data Source"),
                                                            dcc.Dropdown(
                                                                id="analytics-data-source",
                                                                options=[
                                                                    {"label": "All Data", "value": "all"},
                                                                    {"label": "Incidents", "value": "incidents"},
                                                                    {"label": "Detections", "value": "detections"},
                                                                    {"label": "Events", "value": "events"},
                                                                    {"label": "Audit Logs", "value": "audit"},
                                                                ],
                                                                value="all",
                                                                clearable=False,
                                                            ),
                                                        ],
                                                        md=4,
                                                    ),
                                                    dbc.Col(
                                                        [
                                                            dbc.Label("Analysis Type"),
                                                            dcc.Dropdown(
                                                                id="analytics-type",
                                                                options=[
                                                                    {"label": "Trend Analysis", "value": "trend"},
                                                                    {"label": "Correlation Analysis", "value": "correlation"},
                                                                    {"label": "Entity Risk Analysis", "value": "risk"},
                                                                    {"label": "Pattern Detection", "value": "pattern"},
                                                                ],
                                                                value="trend",
                                                                clearable=False,
                                                            ),
                                                        ],
                                                        md=4,
                                                    ),
                                                ],
                                                className="mb-3",
                                            ),
                                            dbc.Row(
                                                [
                                                    dbc.Col(
                                                        [
                                                            dbc.Button(
                                                                [html.I(className="fas fa-chart-line me-2"), "Run Analysis"],
                                                                id="run-analysis-button",
                                                                color="primary",
                                                            ),
                                                        ],
                                                        width=12,
                                                        className="d-flex justify-content-end",
                                                    ),
                                                ],
                                            ),
                                        ]
                                    ),
                                ],
                                className="mb-4 shadow",
                            ),
                        ],
                        width=12,
                    ),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.Div(id="analytics-content", children=[
                                html.Div(
                                    [
                                        html.H4("Select analysis parameters and click 'Run Analysis'", className="text-center text-muted"),
                                        html.Div(className="text-center py-5", children=[
                                            html.I(className="fas fa-chart-line fa-5x text-muted mb-3"),
                                            html.P("Analytics results will appear here", className="lead text-muted")
                                        ])
                                    ],
                                    className="py-5"
                                )
                            ]),
                        ],
                        width=12,
                    ),
                ]
            ),
            # Hidden components for managing state
            dcc.Store(id="analytics-data-store"),
            dcc.Store(id="analytics-params-store"),
        ],
        fluid=True,
        className="p-4",
    )

# App layout
app.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        html.Div(id="page-content"),
        # Toast for notifications
        dbc.Toast(
            id="notification-toast",
            header="Notification",
            is_open=False,
            dismissable=True,
            icon="primary",
            duration=4000,
            style={"position": "fixed", "top": 20, "right": 20, "width": 350, "z-index": 1999},
        ),
        # Store the authentication state
        dcc.Store(id="auth-state", data=AUTH_STATUS),
        # Version information footer
        html.Footer(
            dbc.Container(
                [
                    html.Hr(),
                    dbc.Row(
                        [
                            dbc.Col(
                                html.P(
                                    [
                                        "ASIRA Dashboard v1.0.0 | ",
                                        html.Span("Last updated: 2025-03-15 19:47:20"),
                                    ],
                                    className="text-muted small"
                                ),
                                width="auto",
                            ),
                            dbc.Col(
                                html.P(
                                    ["Logged in as: ", html.Span(id="footer-username")],
                                    className="text-muted small text-end"
                                ),
                                width="auto",
                                className="ms-auto",
                            ),
                        ]
                    ),
                ],
                fluid=True,
                className="py-2",
            ),
            className="mt-auto bg-light",
        ),
    ],
    className="d-flex flex-column min-vh-100",
)

# Callbacks
@app.callback(
    [
        Output("page-content", "children"),
        Output("footer-username", "children"),
        Output("user-display-name", "children"),
    ],
    [Input("url", "pathname")],
    [State("auth-state", "data")]
)
def display_page(pathname, auth_state):
    """Route to different pages based on URL"""
    # Display username in footer
    username = auth_state.get("username", "Guest") if auth_state else "Guest"
    user_display = username if username else "Guest"
    
    # Check if user is authenticated
    if not auth_state or not auth_state.get("authenticated"):
        return create_login_form(), username, user_display
        
    # Create navbar for all authenticated pages
    navbar = create_navbar()
    
    # Route to the appropriate page
    if pathname == "/incidents" or pathname.startswith("/incidents/"):
        return [navbar, create_incidents_page()], username, user_display
    elif pathname == "/detections" or pathname.startswith("/detections/"):
        return [navbar, create_detections_page()], username, user_display
    elif pathname == "/playbooks" or pathname.startswith("/playbooks/"):
        return [navbar, create_playbooks_page()], username, user_display
    elif pathname == "/health":
        return [navbar, create_health_page()], username, user_display
    elif pathname == "/analytics":
        return [navbar, create_analytics_page()], username, user_display
    else:
        # Default to dashboard
        return [navbar, create_main_layout()], username, user_display

@app.callback(
    [
        Output("login-error", "children"),
        Output("auth-state", "data"),
    ],
    [Input("login-button", "n_clicks")],
    [
        State("username-input", "value"),
        State("password-input", "value"),
    ],
    prevent_initial_call=True
)
def handle_login(n_clicks, username, password):
    """Handle login button click"""
    if not username or not password:
        return "Please enter username and password", dash.no_update
    
    if login(username, password):
        # Update auth state
        auth_state = {
            "authenticated": True,
            "username": AUTH_STATUS["username"],
            "role": AUTH_STATUS["role"],
            "token": AUTH_STATUS["token"]
        }
        return "", auth_state
    else:
        return "Invalid username or password", dash.no_update

@app.callback(
    [
        Output("url", "pathname", allow_duplicate=True),
        Output("auth-state", "data", allow_duplicate=True),
    ],
    [Input("logout-button", "n_clicks")],
    prevent_initial_call=True
)
def handle_logout(n_clicks):
    """Handle logout button click"""
    logout()
    auth_state = {
        "authenticated": False,
        "username": None,
        "role": None,
        "token": None
    }
    return "/", auth_state

@app.callback(
    [
        Output("overview-cards", "children"),
        Output("severity-chart", "figure"),
        Output("status-chart", "figure"),
        Output("detection-trend-chart", "figure"),
        Output("recent-incidents-table", "children"),
        Output("recent-detections-table", "children"),
        Output("recent-playbooks-table", "children"),
    ],
    [Input("interval-component", "n_intervals")]
)
def update_dashboard(n_intervals):
    """Update dashboard with latest data"""
    # Get dashboard stats
    stats = get_dashboard_stats()
    
    # Create overview cards
    cards = create_overview_cards(stats)
    
    # Create severity distribution chart
    severity_data = stats.get("incidents_by_severity", {})
    fig_severity = px.pie(
        names=list(severity_data.keys()),
        values=list(severity_data.values()),
        color_discrete_sequence=px.colors.qualitative.Bold,
        hole=0.4,
    )
    fig_severity.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
    )
    
    # Create status distribution chart
    status_data = stats.get("incidents_by_status", {})
    fig_status = px.bar(
        x=list(status_data.keys()),
        y=list(status_data.values()),
        color=list(status_data.keys()),
        color_discrete_sequence=px.colors.qualitative.Bold,
    )
    fig_status.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        xaxis_title="Status",
        yaxis_title="Count",
        xaxis=dict(title_font=dict(size=12), tickfont=dict(size=10)),
        yaxis=dict(title_font=dict(size=12), tickfont=dict(size=10)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
    )
    
    # Create detection trend chart
    detection_trend = stats.get("detection_trend", {})
    if detection_trend:
        dates = list(detection_trend.keys())
        values = list(detection_trend.values())
        
        fig_detection_trend = go.Figure()
        fig_detection_trend.add_trace(
            go.Scatter(
                x=dates,
                y=values,
                mode='lines+markers',
                name='Detections',
                line=dict(color='rgb(0, 123, 255)', width=3),
                marker=dict(size=8, color='rgb(0, 123, 255)'),
                fill='tozeroy',
                fillcolor='rgba(0, 123, 255, 0.1)'
            )
        )
        fig_detection_trend.update_layout(
            title='Detection Trend',
            xaxis_title='Date',
            yaxis_title='Count',
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
            margin=dict(l=40, r=20, t=40, b=40),
            hovermode="x unified",
        )
    else:
        # Create empty chart if no data
        fig_detection_trend = go.Figure()
        fig_detection_trend.update_layout(
            title='Detection Trend',
            xaxis_title='Date',
            yaxis_title='Count',
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
            margin=dict(l=40, r=20, t=40, b=40),
        )
    
    # Get recent incidents and detections
    incidents = get_incidents(limit=10)
    detections = get_detections(limit=10, min_score=0.6)
    executions = get_playbook_executions(limit=10)
    
    # Create tables
    incidents_table = create_incidents_table(incidents)
    detections_table = create_detections_table(detections)
    playbooks_table = create_playbooks_table(executions)
    
    return cards, fig_severity, fig_status, fig_detection_trend, incidents_table, detections_table, playbooks_table

# Run the app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8050))
    app.run_server(debug=False, host="0.0.0.0", port=port)

# --------------------------------------------------------------------------
# ASIRA Dashboard Application
# --------------------------------------------------------------------------
# Version: 1.0.0
# Last updated: 2025-03-15 19:57:29
# Author: Mritunjay-mj
# 
# This dashboard provides a web-based interface for monitoring security incidents, 
# detections, and response actions across the organization's infrastructure.
# 
# The application is built with Dash and connects to the ASIRA API for data retrieval
# and manipulation. It provides real-time visualization of security events, incident
# management capabilities, and system health monitoring.
#
# Environment variables:
#   - ASIRA_API_URL: URL of the ASIRA API (default: http://localhost:8000/api)
#   - ASIRA_API_TOKEN: Optional API token for authentication
#   - PORT: Port to run the dashboard on (default: 8050)
#
# To run in development mode:
#   python -m src.dashboard.app
#
# For production deployment:
#   gunicorn src.dashboard.app:server
# --------------------------------------------------------------------------
