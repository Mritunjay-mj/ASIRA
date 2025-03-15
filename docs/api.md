# ASIRA API Documentation

**Automated Security Incident Response Agent API**

*Version: 1.0.0*  
*Last updated: 2025-03-15 12:30:18*  
*Author: Mritunjay-mj*

## Table of Contents

1. [Introduction](#introduction)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
   - [Authentication](#authentication-endpoints)
   - [Users](#user-endpoints)
   - [Detections](#detection-endpoints)
   - [Incidents](#incident-endpoints)
   - [Playbooks](#playbook-endpoints)
   - [Dashboard](#dashboard-endpoints)
   - [Health](#health-endpoints)
4. [Data Models](#data-models)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Example Usage](#example-usage)

## Introduction

The ASIRA API provides programmatic access to the Automated Security Incident Response Agent platform. It allows you to manage security incidents, view detection results, execute response playbooks, and administer the system.

**Base URL**: `http://your-asira-server/api`

**API Version**: v1

All API endpoints return data in JSON format and accept JSON for request bodies where applicable.

## Authentication

The API uses JWT (JSON Web Token) authentication. To authenticate, you must first obtain a token from the `/auth/token` endpoint.

### Obtaining an Access Token

```
POST /auth/token
```

Request body (form-data):
```
username: your_username
password: your_password
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_at": 1742400618.0
}
```

### Using the Access Token

Include the token in the `Authorization` header for all subsequent requests:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## API Endpoints

### Authentication Endpoints

#### Get Access Token

```
POST /auth/token
```

Authenticates a user and returns an access token.

Request body (form-data):
```
username: your_username
password: your_password
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_at": 1742400618.0
}
```

### User Endpoints

#### Create User

```
POST /users
```

Creates a new user (admin access required).

Request:
```json
{
  "username": "new_user",
  "email": "user@example.com",
  "password": "secure_password",
  "role": "analyst",
  "full_name": "New User"
}
```

Response:
```json
{
  "id": "usr_abcdef12",
  "username": "new_user",
  "email": "user@example.com",
  "full_name": "New User",
  "role": "analyst",
  "is_active": true,
  "created_at": 1741783818.0,
  "last_login": null
}
```

#### Get Current User

```
GET /users/me
```

Returns information about the currently authenticated user.

Response:
```json
{
  "id": "usr_abcdef12",
  "username": "current_user",
  "email": "user@example.com",
  "full_name": "Current User",
  "role": "analyst",
  "is_active": true,
  "created_at": 1741783818.0,
  "last_login": 1741783800.0
}
```

#### Update User

```
PATCH /users/{username}
```

Updates user details (admin access required except for own account).

Request:
```json
{
  "email": "updated@example.com",
  "full_name": "Updated Name",
  "is_active": true
}
```

Response:
```json
{
  "id": "usr_abcdef12",
  "username": "target_user",
  "email": "updated@example.com",
  "full_name": "Updated Name",
  "role": "analyst",
  "is_active": true,
  "created_at": 1741783818.0,
  "last_login": 1741783800.0
}
```

### Detection Endpoints

#### Get Detections

```
GET /detections?limit=20&offset=0&min_score=0.7
```

Lists anomaly detections with optional filtering.

Query parameters:
- `limit`: Maximum number of results to return (default: 20)
- `offset`: Number of results to skip (default: 0)
- `min_score`: Minimum anomaly score (default: 0.0)

Response:
```json
[
  {
    "id": "det_12345678",
    "event_id": "login_event_0001",
    "anomaly_score": 0.85,
    "detection_method": "isolation_forest",
    "explanation": {
      "feature_1": 0.6,
      "feature_2": 0.3,
      "feature_3": 0.1
    },
    "related_events": ["login_event_0002", "login_event_0003"],
    "confidence": 0.82,
    "timestamp": 1741783818.0,
    "acknowledged": false,
    "acknowledged_by": null
  },
  {
    "id": "det_87654321",
    "event_id": "network_event_0001",
    "anomaly_score": 0.79,
    "detection_method": "autoencoder",
    "explanation": {
      "feature_1": 0.2,
      "feature_2": 0.7,
      "feature_3": 0.1
    },
    "related_events": ["network_event_0002"],
    "confidence": 0.75,
    "timestamp": 1741783818.0,
    "acknowledged": true,
    "acknowledged_by": "analyst"
  }
]
```

#### Acknowledge Detection

```
POST /detections/{detection_id}/acknowledge
```

Marks a detection as acknowledged by the current user.

Response:
```json
{
  "id": "det_12345678",
  "acknowledged": true,
  "acknowledged_by": "current_user",
  "acknowledged_at": 1741783818.0
}
```

### Incident Endpoints

#### Create Incident

```
POST /incidents
```

Creates a new security incident.

Request:
```json
{
  "title": "Suspicious Login Activity",
  "description": "Multiple failed login attempts detected from unusual location",
  "severity": "high",
  "detection_id": "det_12345678",
  "playbook_id": "pb_account_lockdown",
  "assets": ["server-web-01"],
  "tags": ["authentication", "brute-force"]
}
```

Response:
```json
{
  "id": "inc_87654321",
  "title": "Suspicious Login Activity",
  "description": "Multiple failed login attempts detected from unusual location",
  "severity": "high",
  "status": "open",
  "created_at": 1741783818.0,
  "updated_at": 1741783818.0,
  "created_by": "current_user",
  "assigned_to": null,
  "detection_id": "det_12345678",
  "playbook_id": "pb_account_lockdown",
  "assets": ["server-web-01"],
  "tags": ["authentication", "brute-force"],
  "notes": null,
  "resolution": null,
  "playbook_execution_id": null
}
```

#### Get Incidents

```
GET /incidents?status=open&severity=high&limit=10
```

Lists security incidents with optional filtering.

Query parameters:
- `status`: Filter by incident status (open, investigating, contained, remediated, closed)
- `severity`: Filter by incident severity (low, medium, high, critical)
- `limit`: Maximum number of results to return (default: 20)
- `offset`: Number of results to skip (default: 0)
- `created_after`: Filter incidents created after timestamp
- `created_before`: Filter incidents created before timestamp

Response:
```json
[
  {
    "id": "inc_87654321",
    "title": "Suspicious Login Activity",
    "description": "Multiple failed login attempts detected from unusual location",
    "severity": "high",
    "status": "open",
    "created_at": 1741783818.0,
    "updated_at": 1741783818.0,
    "created_by": "analyst",
    "assigned_to": null,
    "detection_id": "det_12345678",
    "playbook_id": "pb_account_lockdown",
    "assets": ["server-web-01"],
    "tags": ["authentication", "brute-force"],
    "notes": null,
    "resolution": null,
    "playbook_execution_id": null
  }
]
```

#### Update Incident

```
PATCH /incidents/{incident_id}
```

Updates an existing security incident.

Request:
```json
{
  "status": "investigating",
  "assigned_to": "analyst",
  "notes": "Investigating the source of login attempts"
}
```

Response:
```json
{
  "id": "inc_87654321",
  "title": "Suspicious Login Activity",
  "description": "Multiple failed login attempts detected from unusual location",
  "severity": "high",
  "status": "investigating",
  "created_at": 1741783818.0,
  "updated_at": 1741783828.0,
  "created_by": "analyst",
  "assigned_to": "analyst",
  "detection_id": "det_12345678",
  "playbook_id": "pb_account_lockdown",
  "assets": ["server-web-01"],
  "tags": ["authentication", "brute-force"],
  "notes": "Investigating the source of login attempts",
  "resolution": null,
  "playbook_execution_id": null
}
```

#### Execute Playbook for Incident

```
POST /incidents/{incident_id}/execute_playbook/{playbook_id}
```

Executes a specific playbook for an incident.

Response:
```json
{
  "execution_id": "exec_12345678",
  "playbook_id": "pb_account_lockdown",
  "incident_id": "inc_87654321",
  "start_time": 1741783828.0,
  "end_time": 1741783835.0,
  "status": "completed",
  "triggered_by": "current_user",
  "actions": [
    {
      "action_id": "disable_account",
      "status": "completed",
      "output": "Account disabled successfully",
      "error": null,
      "start_time": "2025-03-15T12:30:28",
      "end_time": "2025-03-15T12:30:30"
    },
    {
      "action_id": "notify_user",
      "status": "completed",
      "output": "Notification sent successfully",
      "error": null,
      "start_time": "2025-03-15T12:30:31",
      "end_time": "2025-03-15T12:30:35"
    }
  ]
}
```

### Playbook Endpoints

#### Create Playbook

```
POST /playbooks
```

Creates a new response playbook (admin access required).

Request:
```json
{
  "name": "Account Lockdown",
  "description": "Locks down a compromised user account",
  "execution_mode": "sequential",
  "enabled": true,
  "actions": [
    {
      "id": "disable_account",
      "type": "command",
      "description": "Disable the compromised account",
      "command": "user_mgmt disable {username}",
      "continue_on_failure": false
    },
    {
      "id": "notify_user",
      "type": "notification",
      "description": "Notify the user about the incident",
      "template": "account_compromise",
      "channels": ["email"],
      "continue_on_failure": true
    }
  ],
  "tags": ["account", "identity"],
  "target_severity": ["medium", "high", "critical"]
}
```

Response:
```json
{
  "id": "pb_account_lockdown",
  "name": "Account Lockdown",
  "description": "Locks down a compromised user account",
  "execution_mode": "sequential",
  "enabled": true,
  "actions": [
    {
      "id": "disable_account",
      "type": "command",
      "description": "Disable the compromised account",
      "command": "user_mgmt disable {username}",
      "continue_on_failure": false
    },
    {
      "id": "notify_user",
      "type": "notification",
      "description": "Notify the user about the incident",
      "template": "account_compromise",
      "channels": ["email"],
      "continue_on_failure": true
    }
  ],
  "tags": ["account", "identity"],
  "target_severity": ["medium", "high", "critical"],
  "created_at": 1741783818.0,
  "updated_at": 1741783818.0,
  "created_by": "admin",
  "execution_count": 0,
  "last_executed": null
}
```

#### Get Playbooks

```
GET /playbooks?enabled_only=true
```

Lists available response playbooks.

Query parameters:
- `enabled_only`: Only return enabled playbooks (default: false)

Response:
```json
[
  {
    "id": "pb_account_lockdown",
    "name": "Account Lockdown",
    "description": "Locks down a compromised user account",
    "execution_mode": "sequential",
    "enabled": true,
    "actions": [
      {
        "id": "disable_account",
        "type": "command",
        "description": "Disable the compromised account",
        "command": "user_mgmt disable {username}",
        "continue_on_failure": false
      },
      {
        "id": "notify_user",
        "type": "notification",
        "description": "Notify the user about the incident",
        "template": "account_compromise",
        "channels": ["email"],
        "continue_on_failure": true
      }
    ],
    "tags": ["account", "identity"],
    "target_severity": ["medium", "high", "critical"],
    "created_at": 1741783818.0,
    "updated_at": 1741783818.0,
    "created_by": "admin",
    "execution_count": 5,
    "last_executed": 1741783818.0
  }
]
```

#### Get Playbook

```
GET /playbooks/{playbook_id}
```

Gets a specific playbook by ID.

Response: Same format as in the list response.

#### Update Playbook

```
PATCH /playbooks/{playbook_id}
```

Updates an existing response playbook (admin access required).

Request:
```json
{
  "name": "Updated Playbook Name",
  "enabled": false,
  "tags": ["account", "identity", "updated"]
}
```

Response: Same format as in the create response, with updated fields.

#### Execute Playbook

```
POST /playbooks/{playbook_id}/execute
```

Executes a playbook with provided incident data (admin access required).

Request:
```json
{
  "id": "inc_87654321",
  "username": "compromised_user",
  "source_ip": "192.168.1.100"
}
```

Response:
```json
{
  "execution_id": "exec_12345678",
  "playbook_id": "pb_account_lockdown",
  "start_time": 1741783818.0,
  "end_time": 1741783828.0,
  "status": "completed",
  "triggered_by": "admin",
  "actions": [
    {
      "action_id": "disable_account",
      "status": "completed",
      "output": "Account disabled successfully",
      "error": null,
      "start_time": "2025-03-15T12:30:18",
      "end_time": "2025-03-15T12:30:20"
    },
    {
      "action_id": "notify_user",
      "status": "completed",
      "output": "Notification sent successfully",
      "error": null,
      "start_time": "2025-03-15T12:30:21",
      "end_time": "2025-03-15T12:30:25"
    }
  ]
}
```

### Dashboard Endpoints

#### Get Dashboard Statistics

```
GET /dashboard/stats
```

Gets statistics for the dashboard.

Response:
```json
{
  "total_incidents": 42,
  "open_incidents": 15,
  "critical_incidents": 3,
  "incidents_by_severity": {
    "low": 10,
    "medium": 18,
    "high": 11,
    "critical": 3
  },
  "incidents_by_status": {
    "open": 8,
    "investigating": 7,
    "contained": 5,
    "remediated": 10,
    "closed": 12
  },
  "detections_today": 15,
  "avg_response_time": 43200,
  "playbooks_executed_today": 8
}
```

### Health Endpoints

#### API Health Check

```
GET /health
```

Checks if the API is running properly.

Response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "timestamp": 1741783818.0,
  "server_time": "2025-03-15 12:30:18"
}
```

## Data Models

### User Models

#### UserCreate

```json
{
  "username": "string",
  "email": "string (email format)",
  "password": "string",
  "full_name": "string (optional)",
  "role": "string (admin, analyst, readonly) - default: analyst"
}
```

#### UserResponse

```json
{
  "id": "string",
  "username": "string",
  "email": "string",
  "full_name": "string (optional)",
  "role": "string",
  "is_active": "boolean",
  "created_at": "float (timestamp)",
  "last_login": "float (timestamp, optional)"
}
```

### Detection Models

#### DetectionResultResponse

```json
{
  "id": "string",
  "event_id": "string",
  "anomaly_score": "float (0.0-1.0)",
  "detection_method": "string",
  "explanation": "object (feature importance)",
  "related_events": ["string"],
  "confidence": "float (0.0-1.0)",
  "timestamp": "float (timestamp)",
  "acknowledged": "boolean",
  "acknowledged_by": "string (optional)"
}
```

### Incident Models

#### IncidentCreate

```json
{
  "title": "string",
  "description": "string",
  "severity": "string (low, medium, high, critical)",
  "detection_id": "string (optional)",
  "playbook_id": "string (optional)",
  "assets": ["string (optional)"],
  "tags": ["string (optional)"]
}
```

#### IncidentResponse

```json
{
  "id": "string",
  "title": "string",
  "description": "string",
  "severity": "string",
  "status": "string (open, investigating, contained, remediated, closed)",
  "created_at": "float (timestamp)",
  "updated_at": "float (timestamp)",
  "created_by": "string",
  "assigned_to": "string (optional)",
  "detection_id": "string (optional)",
  "playbook_id": "string (optional)",
  "assets": ["string"],
  "tags": ["string"],
  "notes": "string (optional)",
  "resolution": "string (optional)",
  "playbook_execution_id": "string (optional)"
}
```

### Playbook Models

#### PlaybookAction

```json
{
  "id": "string",
  "type": "string (command, api_call, script, notification, containment, enrichment)",
  "description": "string",
  "command": "string (optional)",
  "script": "string (optional)",
  "api_endpoint": "string (optional)",
  "api_method": "string (optional)",
  "api_payload": "object (optional)",
  "template": "string (optional)",
  "channels": ["string (optional)"],
  "target": "string (optional)",
  "parameters": "object (optional)",
  "continue_on_failure": "boolean (default: false)",
  "timeout": "integer (seconds, default: 60)"
}
```

#### PlaybookCreate

```json
{
  "name": "string",
  "description": "string",
  "actions": ["PlaybookAction"],
  "enabled": "boolean (default: true)",
  "execution_mode": "string (sequential, parallel)",
  "tags": ["string"],
  "target_severity": ["string (low, medium, high, critical) (optional)"]
}
```

#### PlaybookResponse

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "actions": ["PlaybookAction"],
  "enabled": "boolean",
  "execution_mode": "string",
  "tags": ["string"],
  "target_severity": ["string"],
  "created_at": "float (timestamp)",
  "updated_at": "float (timestamp)",
  "created_by": "string",
  "execution_count": "integer",
  "last_executed": "float (timestamp, optional)"
}
```

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of requests:

- `200 OK`: The request was successful
- `201 Created`: The resource was successfully created
- `400 Bad Request`: The request was invalid or malformed
- `401 Unauthorized`: Authentication failed or token expired
- `403 Forbidden`: The user doesn't have permission to perform the action
