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
Last updated: 2025-03-15 12:21:15
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
                            dbc.NavItem(dbc.NavLink("Incidents", href="/incidents")),
                            dbc.NavItem(dbc.NavLink("Detections", href="/detections")),
                            dbc.NavItem(dbc.NavLink("Playbooks", href="/playbooks")),
                            dbc.NavItem(dbc.NavLink("System Health", href="/health")),
                            dbc.DropdownMenu(
                                children=[
                                    dbc.DropdownMenuItem("Profile", id="profile-link"),
                                    dbc.DropdownMenuItem("Settings", id="settings-link"),
                                    dbc.DropdownMenuItem(divider=True),
                                    dbc.DropdownMenuItem("Logout", id="logout-button"),
                                ],
                                nav=True,
                                in_navbar=True,
                                label="User",
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
    )

def create_login_form():
    """Create the login form"""
    return dbc.Container(
        dbc.Card(
            dbc.CardBody(
                [
                    html.H2("ASIRA Login", className="text-center mb-4"),
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
                            html.H4("Recent Incidents"),
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
                            html.H4("Recent Detections"),
                            html.Div(id="recent-detections-table"),
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
                        ]
                    ),
                    className="shadow text-center",
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
                        ]
                    ),
                    className="shadow text-center",
                ),
                width=3,
            ),
            dbc.Col(
                dbc.Card(
                    dbc.CardBody(
                        [
                            html.H5("Detections Today", className="card-title"),
                            html.H2(stats.get("detections_today", 0), className="card-text text-info"),
                        ]
                    ),
                    className="shadow text-center",
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
                        ]
                    ),
                    className="shadow text-center",
                ),
                width=3,
            ),
        ],
        className="mb-4",
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
                    dbc.Button("View", color="secondary", size="sm", id=f"view-incident-{incident.get('id', '')}")
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
                html.Th("Event ID"),
                html.Th("Score"),
                html.Th("Method"),
                html.Th("Confidence"),
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
                html.Td(detection.get("event_id", "")),
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
                html.Td(f"{detection.get('confidence', 0):.2f}"),
                html.Td(time_str),
                html.Td(
                    dbc.ButtonGroup(
                        [
                            dbc.Button("View", color="secondary", size="sm", id=f"view-detection-{detection.get('id', '')}"),
                            dbc.Button("Respond", color="primary", size="sm", id=f"respond-detection-{detection.get('id', '')}"),
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

# App layout
app.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        html.Div(id="page-content"),
    ]
)

# Callbacks
@app.callback(
    Output("page-content", "children"),
    [Input("url", "pathname")]
)
def display_page(pathname):
    """Route to different pages based on URL"""
    # Check if user is authenticated
    if not AUTH_STATUS.get("authenticated"):
        return create_login_form()
        
    # Create navbar for all authenticated pages
    navbar = create_navbar()
    
    # Route to the appropriate page
    if pathname == "/incidents":
        return [navbar, html.Div("Incidents Page - Under Construction")]
    elif pathname == "/detections":
        return [navbar, html.Div("Detections Page - Under Construction")]
    elif pathname == "/playbooks":
        return [navbar, html.Div("Playbooks Page - Under Construction")]
    elif pathname == "/health":
        return [navbar, html.Div("System Health Page - Under Construction")]
    else:
        # Default to dashboard
        return [navbar, create_main_layout()]

@app.callback(
    [
        Output("login-error", "children"),
        Output("url", "pathname"),
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
        return "", "/"
    else:
        return "Invalid username or password", dash.no_update

@app.callback(
    Output("url", "pathname", allow_duplicate=True),
    [Input("logout-button", "n_clicks")],
    prevent_initial_call=True
)
def handle_logout(n_clicks):
    """Handle logout button click"""
    logout()
    return "/"

@app.callback(
    [
        Output("overview-cards", "children"),
        Output("severity-chart", "figure"),
        Output("status-chart", "figure"),
        Output("recent-incidents-table", "children"),
        Output("recent-detections-table", "children"),
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
    
    # Get recent incidents and detections
    incidents = get_incidents(limit=10)
    detections = get_detections(limit=10, min_score=0.6)
    
    # Create tables
    incidents_table = create_incidents_table(incidents)
    detections_table = create_detections_table(detections)
    
    return cards, fig_severity, fig_status, incidents_table, detections_table

# Run the app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8050))
    app.run_server(debug=False, host="0.0.0.0", port=port)
