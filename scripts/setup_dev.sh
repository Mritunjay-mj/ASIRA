#!/bin/bash
#
# ASIRA: Automated Security Incident Response Agent
# Development Environment Setup Script
#
# This script sets up a development environment for ASIRA
#
# Version: 1.0.0
# Last updated: 2025-03-15 12:23:31
# Last updated by: Mritunjay-mj
#

set -e # Exit on error

echo "================================================"
echo "ASIRA Development Environment Setup"
echo "================================================"
echo "Starting setup at $(date)"

# Determine the project root directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "Project directory: $PROJECT_DIR"

# Create necessary directories
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/data"
mkdir -p "${PROJECT_DIR}/playbooks"
mkdir -p "${PROJECT_DIR}/tmp/execution"

# Check if Python is installed
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check for Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Found Python version: $PYTHON_VERSION"

if [[ $(echo "$PYTHON_VERSION < 3.8" | bc) -eq 1 ]]; then
    echo "Error: Python 3.8 or higher is required."
    exit 1
fi

# Create and activate virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "${PROJECT_DIR}/.venv"
source "${PROJECT_DIR}/.venv/bin/activate"

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r "${PROJECT_DIR}/requirements.txt"

# Install development dependencies
echo "Installing development dependencies..."
pip install pytest pytest-cov flake8 black mypy isort pre-commit

# Set up pre-commit hooks
echo "Setting up pre-commit hooks..."
if command -v pre-commit &>/dev/null; then
    cd "${PROJECT_DIR}"
    pre-commit install
else
    echo "Warning: pre-commit not found. Skipping pre-commit hooks setup."
fi

# Set up environment variables for development
echo "Setting up environment variables..."
cat > "${PROJECT_DIR}/.env" << EOF
# ASIRA Development Environment Variables
# Generated on $(date)

# API Settings
ASIRA_API_PORT=8000
ASIRA_DEBUG_MODE=true
ASIRA_LOG_LEVEL=DEBUG

# Database Settings (using SQLite for development)
ASIRA_DB_HOST=localhost
ASIRA_DB_PORT=5432
ASIRA_DB_USER=asira
ASIRA_DB_PASSWORD=dev_password
ASIRA_DB_NAME=asira_dev

# Security Settings
ASIRA_SECRET_KEY=dev_secret_key_$(openssl rand -hex 8)
ASIRA_TOKEN_EXPIRE_MINUTES=1440

# Playbook Settings
ASIRA_PLAYBOOK_DIR=${PROJECT_DIR}/playbooks
ASIRA_EXECUTION_DIR=${PROJECT_DIR}/tmp/execution
ASIRA_SANDBOX_TYPE=subprocess

# Elasticsearch Settings (optional)
# ASIRA_ES_HOSTS=http://localhost:9200

# Redis Settings (optional)
# ASIRA_REDIS_HOST=localhost
# ASIRA_REDIS_PORT=6379
EOF

# Copy sample playbooks to the playbooks directory
echo "Copying sample playbooks..."
cp "${PROJECT_DIR}/playbooks"/*.yml "${PROJECT_DIR}/playbooks/" 2>/dev/null || echo "No sample playbooks found."

# Create test data directory
echo "Creating test data directory..."
mkdir -p "${PROJECT_DIR}/tests/data"

# Generate a simple test playbook
echo "Generating test playbook..."
cat > "${PROJECT_DIR}/playbooks/test_playbook.yml" << EOF
id: pb_test
name: Test Playbook
description: A simple test playbook for development
execution_mode: sequential
enabled: true
actions:
  - id: test_echo
    type: command
    description: Echo a test message
    command: echo "This is a test action"
    continue_on_failure: false
  - id: test_list
    type: command
    description: List directory contents
    command: ls -la
    continue_on_failure: false
tags:
  - test
  - development
target_severity:
  - low
created_at: $(date +%s)
updated_at: $(date +%s)
author: Developer
EOF

# Create a development help script
echo "Creating development helper script..."
cat > "${PROJECT_DIR}/dev.sh" << EOF
#!/bin/bash
# Development helper script
# Last updated: $(date)

source "${PROJECT_DIR}/.venv/bin/activate"

case "\$1" in
    run)
        # Run the application
        cd "${PROJECT_DIR}" && python -m src.main
        ;;
    test)
        # Run tests
        cd "${PROJECT_DIR}" && pytest -xvs "\$2"
        ;;
    lint)
        # Run linters
        cd "${PROJECT_DIR}" && flake8 src tests
        cd "${PROJECT_DIR}" && black --check src tests
        cd "${PROJECT_DIR}" && isort --check-only src tests
        cd "${PROJECT_DIR}" && mypy src
        ;;
    format)
        # Format code
        cd "${PROJECT_DIR}" && black src tests
        cd "${PROJECT_DIR}" && isort src tests
        ;;
    dashboard)
        # Run the dashboard application
        cd "${PROJECT_DIR}" && python -m src.dashboard.app
        ;;
    *)
        echo "Usage: ./dev.sh [run|test|lint|format|dashboard]"
        exit 1
        ;;
esac
EOF
chmod +x "${PROJECT_DIR}/dev.sh"

# Add example detection model
echo "Setting up example detection model..."
mkdir -p "${PROJECT_DIR}/data/models"

# Print setup completion message
echo "================================================"
echo "ASIRA development environment setup complete!"
echo ""
echo "To activate the virtual environment, run:"
echo "  source ${PROJECT_DIR}/.venv/bin/activate"
echo ""
echo "To run the application:"
echo "  ./dev.sh run"
echo ""
echo "To run the dashboard:"
echo "  ./dev.sh dashboard"
echo ""
echo "Environment variables are stored in:"
echo "  ${PROJECT_DIR}/.env"
echo "================================================"
