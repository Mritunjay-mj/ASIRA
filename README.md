# ASIRA - Automated Security Incident Response Agent

![ASIRA Logo](docs/images/asira_logo.png)

*Version: 1.0.0*  
*Last updated: 2025-03-15 12:38:13*  
*Author: Mritunjay-mj*

> Intelligent security incident detection and automated response for enterprise environments

## Overview

ASIRA is an advanced security platform that combines anomaly detection and automated incident response to help security teams identify and mitigate threats faster. By leveraging machine learning techniques and predefined response playbooks, ASIRA reduces the time from detection to containment, minimizing the impact of security incidents.

## Features

- **Anomaly Detection**: Multi-model machine learning approach to identify security anomalies
  - Statistical analysis (Z-scores, MAD)
  - Isolation Forest algorithm
  - Deep learning with autoencoders
  - Feature importance explanation

- **Automated Response**: Orchestrate security actions through predefined playbooks
  - Account lockdown and identity protection
  - Malware containment and remediation
  - Network segment isolation
  - Custom playbook creation
  
- **Incident Management**: Complete incident lifecycle tracking
  - Incident creation from detections
  - Status tracking and assignments
  - Integration with existing SOC workflows
  - Evidence collection and documentation

- **Interactive Dashboard**: Real-time security posture visualization
  - Incident overview and metrics
  - Detection results and trends
  - System health monitoring
  - Response action tracking

- **API Integration**: Comprehensive REST API for integration with other security tools
  - Authentication and access control
  - Incident and detection endpoints
  - Playbook execution
  - Dashboard metrics

## System Requirements

### Minimum Requirements
- Python 3.8+
- PostgreSQL 12+
- 4 CPU cores
- 8GB RAM
- 100GB storage

### Recommended Requirements
- Python 3.10+
- PostgreSQL 14+
- 8+ CPU cores
- 16GB+ RAM
- 500GB+ SSD storage
- Redis (for caching)
- Elasticsearch (for log storage and searching)

## Installation

### Production Installation

Use the provided installation script to deploy ASIRA in a production environment:

```bash
# Download the installation script
curl -O https://github.com/mritunjay-cybersec/ASIRA/raw/main/scripts/install.sh

# Make the script executable
chmod +x install.sh

# Run the installation script with root privileges
sudo ./install.sh



The installation script will:

Install system dependencies
Set up the database
Configure the application
Install example playbooks
Set up services for automatic startup
After installation, ASIRA will be available at:

Dashboard: http://your-server-ip/
API: http://your-server-ip/api
Development Setup
For development purposes, use the development setup script:

# Clone the repository
git clone https://github.com/mritunjay-cybersec/ASIRA.git
cd ASIRA

# Make the script executable
chmod +x scripts/setup_dev.sh

# Run the development setup script
./scripts/setup_dev.sh

The development setup includes:

Virtual environment creation
Development dependencies installation
Sample data and playbooks
Pre-commit hooks for code quality
Development helper scripts
Quick Start Guide
1. Accessing the Dashboard
After installation, access the dashboard at http://your-server-ip/ and log in with the default credentials:

Username: admin
Password: asira_admin
Important: Change the default password immediately after first login!

2. Configuring Detection Sources
Navigate to Settings > Detection Sources
Add log sources (files, syslog servers, APIs)
Configure normalization settings
Set up detection schedules
3. Creating Response Playbooks
Navigate to Playbooks > Create New
Choose a playbook template or start from scratch
Define actions and their parameters
Test the playbook in sandbox mode
Enable the playbook when ready
4. Handling Incidents
Navigate to Incidents to view detected issues
Click on an incident to see details
Assign it to a team member
Execute response playbooks
Update incident status as you work through it
5. API Integration
Integrate ASIRA with your existing security tools using the REST API:


# Example: Get an authentication token
curl -X POST http://your-server-ip/api/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=your_username&password=your_password"

# Example: List recent incidents
curl http://your-server-ip/api/incidents \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

Architecture
ASIRA consists of several key modules:

Detection Module: Processes security logs and identifies anomalies
Response Module: Executes playbooks in response to incidents
API Module: Provides REST API endpoints for integration
Dashboard Module: Web interface for security operations
Common Module: Shared utilities and configuration
For more detailed architecture information, see Architecture Documentation.

Configuration
The main configuration file is located at /etc/asira/config.yaml in production or .env in development.

Example configuration:

# API Settings
api_port: 8000
debug_mode: false
log_level: INFO

# Database Settings
db_host: localhost
db_port: 5432
db_user: asira
db_password: your_secure_password
db_name: asira

# Security Settings
secret_key: your_secret_key
token_expire_minutes: 1440  # 24 hours

# Playbook Settings
playbook_dir: /etc/asira/playbooks
execution_dir: /tmp/asira/execution
sandbox_type: subprocess

Development
Directory Structure
├── src/                   # Source code
│   ├── api/               # API module
│   ├── detection/         # Detection engine
│   ├── response/          # Response orchestration
│   ├── dashboard/         # Web dashboard
│   └── common/            # Shared utilities
├── playbooks/             # Playbook definitions
├── tests/                 # Test cases
├── docs/                  # Documentation
├── scripts/               # Installation and utility scripts
└── requirements.txt       # Python dependencies

Running Tests
# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov=src tests/

# Run specific test file
python -m pytest tests/test_detection.py


API Documentation
For comprehensive API documentation, see API Documentation.

Contributing
We welcome contributions to ASIRA! Please follow these guidelines:

Fork the repository
Create a feature branch
Add your changes
Run tests to ensure functionality
Submit a pull request
For more details, see our Contributing Guidelines.

Security
If you discover a security vulnerability in ASIRA, please send an email to security@example.com. All security vulnerabilities will be promptly addressed.


Acknowledgments
Thanks to all contributors who have helped build ASIRA
Special thanks to the open-source projects that made this possible
Inspired by real-world security incident response challenges
For additional support, please open an issue on GitHub or contact support@example.com.

