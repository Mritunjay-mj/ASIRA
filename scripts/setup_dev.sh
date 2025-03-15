#!/bin/bash
#
# ASIRA: Automated Security Incident Response Agent
# Development Environment Setup Script
#
# This script sets up a development environment for ASIRA
#
# Version: 1.0.0
# Last updated: 2025-03-15 20:18:23
# Last updated by: Mritunjay-mj
#

set -e # Exit on error

echo "================================================"
echo "ASIRA Development Environment Setup"
echo "================================================"
echo "Starting setup at $(date)"

# Parse command line arguments
USE_DOCKER=false
SKIP_DEPS=false
SKIP_DB=false
VERBOSE=false

for arg in "$@"; do
    case $arg in
        --docker)
            USE_DOCKER=true
            ;;
        --skip-deps)
            SKIP_DEPS=true
            ;;
        --skip-db)
            SKIP_DB=true
            ;;
        --verbose)
            VERBOSE=true
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --docker     Set up using Docker containers"
            echo "  --skip-deps  Skip installing system dependencies"
            echo "  --skip-db    Skip database setup"
            echo "  --verbose    Show more detailed output"
            echo "  --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to log messages
log() {
    if [ "$VERBOSE" = true ]; then
        echo "[$(date +%H:%M:%S)] $1"
    else
        echo "$1"
    fi
}

# Determine the project root directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log "Project directory: $PROJECT_DIR"

# Detect operating system
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_NAME=Linux;;
    Darwin*)    OS_NAME=Mac;;
    CYGWIN*)    OS_NAME=Cygwin;;
    MINGW*)     OS_NAME=MinGw;;
    *)          OS_NAME="UNKNOWN:${OS}"
esac
log "Detected operating system: $OS_NAME"

# Create necessary directories
log "Creating project directories..."
mkdir -p "${PROJECT_DIR}/logs"
mkdir -p "${PROJECT_DIR}/data"
mkdir -p "${PROJECT_DIR}/data/models"
mkdir -p "${PROJECT_DIR}/data/samples"
mkdir -p "${PROJECT_DIR}/playbooks"
mkdir -p "${PROJECT_DIR}/tmp/execution"
mkdir -p "${PROJECT_DIR}/tmp/cache"
mkdir -p "${PROJECT_DIR}/tests/data"
mkdir -p "${PROJECT_DIR}/tests/fixtures"

# Check if Docker setup is requested
if [ "$USE_DOCKER" = true ]; then
    log "Setting up Docker development environment..."
    
    # Check if Docker is installed
    if ! command -v docker &>/dev/null; then
        echo "Error: Docker is required but not installed."
        echo "Please install Docker and try again."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &>/dev/null; then
        echo "Error: Docker Compose is required but not installed."
        echo "Please install Docker Compose and try again."
        exit 1
    fi
    
    # Create docker-compose.yml for development
    log "Creating Docker Compose configuration..."
    cat > "${PROJECT_DIR}/docker-compose.dev.yml" << EOF
version: '3.8'

services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_USER: asira
      POSTGRES_PASSWORD: dev_password
      POSTGRES_DB: asira_dev
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6
    ports:
      - "6379:6379"

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.14.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5672:5672"
      - "15672:15672"
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest

volumes:
  postgres_data:
  elasticsearch_data:
EOF
    
    # Start Docker containers
    log "Starting development containers..."
    docker-compose -f "${PROJECT_DIR}/docker-compose.dev.yml" up -d
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 10
    
    # Update environment variables for Docker
    log "Configuring environment for Docker services..."
    POSTGRES_HOST="localhost"
    REDIS_HOST="localhost"
    ES_HOST="http://localhost:9200"
    RABBITMQ_URL="amqp://guest:guest@localhost:5672/"
else
    # For local development without Docker
    POSTGRES_HOST="localhost"
    REDIS_HOST="localhost"
    ES_HOST="http://localhost:9200"
    RABBITMQ_URL="amqp://guest:guest@localhost:5672/"
    
    # Install system dependencies if not skipped
    if [ "$SKIP_DEPS" != true ]; then
        log "Installing system dependencies..."
        
        if [ "$OS_NAME" = "Linux" ]; then
            # Check for apt package manager (Debian/Ubuntu)
            if command -v apt-get &>/dev/null; then
                sudo apt-get update
                sudo apt-get install -y \
                    python3-dev \
                    python3-pip \
                    python3-venv \
                    postgresql \
                    postgresql-contrib \
                    libpq-dev \
                    redis-server \
                    git \
                    curl \
                    build-essential
            # Check for yum package manager (RHEL/CentOS/Fedora)
            elif command -v yum &>/dev/null; then
                sudo yum -y install \
                    python3-devel \
                    python3-pip \
                    postgresql \
                    postgresql-server \
                    postgresql-devel \
                    redis \
                    git \
                    curl \
                    make \
                    gcc \
                    gcc-c++
            else
                log "Warning: Unsupported package manager. Please install dependencies manually."
            fi
        elif [ "$OS_NAME" = "Mac" ]; then
            # Check if Homebrew is installed
            if command -v brew &>/dev/null; then
                brew update
                brew install \
                    python@3.9 \
                    postgresql \
                    redis \
                    git
            else
                log "Warning: Homebrew not found. Please install dependencies manually."
            fi
        else
            log "Warning: Unsupported operating system. Please install dependencies manually."
        fi
    fi
fi

# Check if Python is installed
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check for Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log "Found Python version: $PYTHON_VERSION"

if [[ $(echo "$PYTHON_VERSION < 3.8" | bc) -eq 1 ]]; then
    echo "Error: Python 3.8 or higher is required."
    exit 1
fi

# Create and activate virtual environment
log "Creating Python virtual environment..."
python3 -m venv "${PROJECT_DIR}/.venv"
source "${PROJECT_DIR}/.venv/bin/activate"

# Upgrade pip
log "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
log "Installing dependencies..."
pip install -r "${PROJECT_DIR}/requirements.txt"

# Install development dependencies
log "Installing development dependencies..."
pip install pytest pytest-cov pytest-mock flake8 black mypy isort pre-commit bandit safety pytest-xdist jupyterlab

# Set up pre-commit hooks
log "Setting up pre-commit hooks..."
if command -v pre-commit &>/dev/null; then
    cd "${PROJECT_DIR}"
    
    # Create pre-commit configuration if it doesn't exist
    if [ ! -f ".pre-commit-config.yaml" ]; then
        cat > ".pre-commit-config.yaml" << EOF
repos:
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.2.0
    hooks:
    -   id: trailing-whitespace
    -   id: end-of-file-fixer
    -   id: check-yaml
    -   id: check-added-large-files
    -   id: check-json
    -   id: detect-private-key

-   repo: https://github.com/pycqa/isort
    rev: 5.10.1
    hooks:
    -   id: isort
        args: ["--profile", "black"]

-   repo: https://github.com/psf/black
    rev: 22.3.0
    hooks:
    -   id: black
        args: ["--line-length", "88"]

-   repo: https://github.com/pycqa/flake8
    rev: 4.0.1
    hooks:
    -   id: flake8
        additional_dependencies: [flake8-docstrings]

-   repo: https://github.com/pre-commit/mirrors-mypy
    rev: v0.942
    hooks:
    -   id: mypy
        exclude: ^tests/
        args: ["--ignore-missing-imports"]

-   repo: https://github.com/PyCQA/bandit
    rev: 1.7.4
    hooks:
    -   id: bandit
        args: ["-c", "pyproject.toml"]
        additional_dependencies: ["bandit[toml]"]
EOF
    fi
    
    pre-commit install
else
    log "Warning: pre-commit not found. Skipping pre-commit hooks setup."
fi

# Create pyproject.toml if it doesn't exist
if [ ! -f "${PROJECT_DIR}/pyproject.toml" ]; then
    log "Creating pyproject.toml..."
    cat > "${PROJECT_DIR}/pyproject.toml" << EOF
[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"

[tool.black]
line-length = 88
target-version = ['py38', 'py39', 'py310']

[tool.isort]
profile = "black"
multi_line_output = 3

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = "test_*.py"
python_classes = "Test*"
python_functions = "test_*"
addopts = "--cov=src --cov-report=term --cov-report=html"

[tool.mypy]
python_version = "3.8"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
disallow_incomplete_defs = false

[tool.bandit]
exclude_dirs = ["tests", "scripts", ".venv"]
EOF
fi

# Set up environment variables for development
log "Setting up environment variables..."
cat > "${PROJECT_DIR}/.env" << EOF
# ASIRA Development Environment Variables
# Generated on $(date)

# API Settings
ASIRA_API_PORT=8000
ASIRA_DEBUG_MODE=true
ASIRA_LOG_LEVEL=DEBUG
ASIRA_CORS_ORIGINS=http://localhost:3000,http://localhost:8050,http://127.0.0.1:8050

# Database Settings
ASIRA_DB_HOST=$POSTGRES_HOST
ASIRA_DB_PORT=5432
ASIRA_DB_USER=asira
ASIRA_DB_PASSWORD=dev_password
ASIRA_DB_NAME=asira_dev

# Security Settings
ASIRA_SECRET_KEY=dev_secret_key_$(openssl rand -hex 16)
ASIRA_TOKEN_EXPIRE_MINUTES=1440

# Playbook Settings
ASIRA_PLAYBOOK_DIR=${PROJECT_DIR}/playbooks
ASIRA_EXECUTION_DIR=${PROJECT_DIR}/tmp/execution
ASIRA_SANDBOX_TYPE=subprocess

# Elasticsearch Settings
ASIRA_ES_HOSTS=$ES_HOST

# Redis Settings
ASIRA_REDIS_HOST=$REDIS_HOST
ASIRA_REDIS_PORT=6379

# RabbitMQ Settings
ASIRA_RABBITMQ_URL=$RABBITMQ_URL

# Additional Development Settings
ASIRA_ENABLE_PROFILING=true
ASIRA_MOCK_RESPONSES=false
ASIRA_AUTO_RELOAD=true
ASIRA_CACHE_DIR=${PROJECT_DIR}/tmp/cache
EOF

# Set up a small default config.yaml file in addition to env vars
log "Creating default configuration file..."
mkdir -p "${PROJECT_DIR}/config"
cat > "${PROJECT_DIR}/config/config.yaml" << EOF
# ASIRA Development Configuration
# Generated on $(date)

# API Settings
api_port: 8000
debug_mode: true
log_level: "DEBUG"
cors_origins:
  - "http://localhost:3000"
  - "http://localhost:8050"
  - "http://127.0.0.1:8050"

# Playbook Settings
playbook_dir: "${PROJECT_DIR}/playbooks"
execution_dir: "${PROJECT_DIR}/tmp/execution"
sandbox_type: "subprocess"

# Security
secret_key: "dev_secret_key_$(openssl rand -hex 8)"
EOF

# Set up database if not skipped
if [ "$SKIP_DB" != true ] && [ "$USE_DOCKER" != true ]; then
    log "Setting up development database..."
    
    if [ "$OS_NAME" = "Linux" ]; then
        # Start PostgreSQL if not already running
        if ! systemctl is-active --quiet postgresql; then
            log "Starting PostgreSQL service..."
            sudo systemctl start postgresql
        fi
        
        # Create database and user
        if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw asira_dev; then
            log "Database 'asira_dev' already exists."
        else
            log "Creating database 'asira_dev' and user 'asira'..."
            sudo -u postgres psql -c "CREATE USER asira WITH PASSWORD 'dev_password';"
            sudo -u postgres psql -c "CREATE DATABASE asira_dev OWNER asira;"
            sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE asira_dev TO asira;"
        fi
        
        # Start Redis if not already running
        if ! systemctl is-active --quiet redis-server; then
            log "Starting Redis service..."
            sudo systemctl start redis-server
        fi
    elif [ "$OS_NAME" = "Mac" ]; then
        # Start PostgreSQL if using Homebrew
        if command -v brew &>/dev/null && brew list postgresql &>/dev/null; then
            log "Starting PostgreSQL service..."
            brew services start postgresql
            
            # Create database and user
            if psql -lqt postgres | cut -d \| -f 1 | grep -qw asira_dev; then
                log "Database 'asira_dev' already exists."
            else
                log "Creating database 'asira_dev' and user 'asira'..."
                createuser -s asira || true
                psql postgres -c "ALTER USER asira WITH PASSWORD 'dev_password';"
                createdb -O asira asira_dev
            fi
        fi
        
        # Start Redis if using Homebrew
        if command -v brew &>/dev/null && brew list redis &>/dev/null; then
            log "Starting Redis service..."
            brew services start redis
        fi
    fi
fi

# Copy sample playbooks to the playbooks directory
log "Setting up sample playbooks..."

# Generate a simple test playbook
log "Generating test playbook..."
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

# Generate a more comprehensive test playbook
cat > "${PROJECT_DIR}/playbooks/incident_response.yml" << EOF
id: pb_incident_response
name: Basic Incident Response
description: A basic incident response workflow for development testing
execution_mode: sequential
enabled: true
actions:
  - id: collect_system_info
    type: command
    description: Collect basic system information
    command: uname -a && df -h
    continue_on_failure: true
  - id: check_processes
    type: command
    description: Check running processes
    command: ps aux | head -10
    continue_on_failure: true
  - id: send_notification
    type: notification
    description: Send notification about incident
    template: "Incident detected. Basic system checks completed."
    channels:
      - console
    parameters:
      severity: "medium"
tags:
  - incident
  - response
  - system
target_severity:
  - medium
  - high
created_at: $(date +%s)
updated_at: $(date +%s)
author: Developer
EOF

# Create a log enrichment playbook
cat > "${PROJECT_DIR}/playbooks/log_enrichment.yml" << EOF
id: pb_log_enrichment
name: Log Enrichment
description: Enriches log data with additional context
execution_mode: sequential
enabled: true
actions:
  - id: extract_ips
    type: enrichment
    description: Extract and enrich IP addresses
    target: "{{ event.log_data }}"
    parameters:
      enrichment_type: "ip_lookup"
  - id: extract_domains
    type: enrichment
    description: Extract and enrich domains
    target: "{{ event.log_data }}"
    parameters:
      enrichment_type: "domain_lookup"
  - id: generate_report
    type: script
    description: Generate enrichment report
    script: |
      #!/bin/bash
      echo "Log Enrichment Report"
      echo "====================="
      echo "Event ID: {{ event.id }}"
      echo "Timestamp: {{ event.timestamp }}"
      echo "Enriched IPs: {{ extract_ips.output }}"
      echo "Enriched Domains: {{ extract_domains.output }}"
tags:
  - logs
  - enrichment
target_severity:
  - low
  - medium
created_at: $(date +%s)
updated_at: $(date +%s)
author: Developer
EOF

# Create a development help script
log "Creating development helper script..."
cat > "${PROJECT_DIR}/dev.sh" << EOF
#!/bin/bash
# ASIRA Development Helper Script
# Last updated: $(date)

source "${PROJECT_DIR}/.venv/bin/activate"

show_help() {
    echo "ASIRA Development Helper"
    echo "========================"
    echo "Usage: ./dev.sh COMMAND [OPTIONS]"
    echo
    echo "Commands:"
    echo "  run          Run the API application"
    echo "  dashboard    Run the dashboard application"
    echo "  worker       Run the background worker"
    echo "  shell        Start a Python shell with the app context"
    echo "  test         Run the test suite"
    echo "  lint         Run linting checks"
    echo "  format       Format code"
    echo "  clean        Clean temporary files"
    echo "  docker       Manage Docker development environment"
    echo "  version      Show version information"
    echo "  help         Show this help message"
    echo
    echo "Run './dev.sh COMMAND --help' for more information on specific commands."
}

case "\$1" in
    run)
        shift
        ARGS=""
        PORT="8000"
        RELOAD="--reload"
        DEBUG="--debug"
        
        # Parse options
        while [[ \$# -gt 0 ]]; do
            case \$1 in
                --port=*)
                    PORT="\${1#*=}"
                    shift
                    ;;
                --no-reload)
                    RELOAD=""
                    shift
                    ;;
                --no-debug)
                    DEBUG=""
                    shift
                    ;;
                --help)
                    echo "Usage: ./dev.sh run [OPTIONS]"
                    echo
                    echo "Options:"
                    echo "  --port=PORT    Set the port (default: 8000)"
                    echo "  --no-reload    Disable auto-reload"
                    echo "  --no-debug     Disable debug mode"
                    exit 0
                    ;;
                *)
                    ARGS="\$ARGS \$1"
                    shift
                    ;;
            esac
        done
        
        echo "Starting API server on port \$PORT..."
        cd "${PROJECT_DIR}" && uvicorn src.main:app --host 0.0.0.0 --port \$PORT \$RELOAD \$DEBUG \$ARGS
        ;;
        
    dashboard)
        shift
        PORT="8050"
        
        # Parse options
        while [[ \$# -gt 0 ]]; do
            case \$1 in
                --port=*)
                    PORT="\${1#*=}"
                    shift
                    ;;
                --help)
                    echo "Usage: ./dev.sh dashboard [OPTIONS]"
                    echo
                    echo "Options:"
                    echo "  --port=PORT    Set the port (default: 8050)"
                    exit 0
                    ;;
                *)
                    shift
                    ;;
            esac
        done
        
        echo "Starting dashboard server on port \$PORT..."
        cd "${PROJECT_DIR}" && ASIRA_API_URL="http://localhost:8000/api" PORT=\$PORT python -m src.dashboard.app
        ;;
        
    worker)
        echo "Starting background worker..."
        cd "${PROJECT_DIR}" && python -m src.worker
        ;;
        
    shell)
        cd "${PROJECT_DIR}" && python -c "
import sys, os
sys.path.insert(0, os.getcwd())
from src.main import app
from src.config import settings
print('ASIRA development shell - App and settings available')
print(f'API version: {app.version}')
" && python
        ;;
        
    test)
        shift
        TEST_PATH=""
        COVERAGE="--cov"
        VERBOSE="-v"
        
        # Parse options
        while [[ \$# -gt 0 ]]; do
            case \$1 in
                --no-coverage)
                    COVERAGE=""
                    shift
                    ;;
                --quiet)
                    VERBOSE=""
                    shift
                    ;;
                --help)
                    echo "Usage: ./dev.sh test [OPTIONS] [TEST_PATH]"
                    echo
                    echo "Options:"
                    echo "  --no-coverage    Disable coverage reporting"
                    echo "  --quiet          Less verbose output"
                    echo "  TEST_PATH        Path to specific test file or directory"
                    exit 0
                    ;;
                *)
                    TEST_PATH="\$1"
                    shift
                    ;;
            esac
        done
        
        if [ -z "\$TEST_PATH" ]; then
            echo "Running all tests..."
            cd "${PROJECT_DIR}" && pytest \$VERBOSE \$COVERAGE
        else
            echo "Running tests in \$TEST_PATH..."
            cd "${PROJECT_DIR}" && pytest \$VERBOSE \$COVERAGE "\$TEST_PATH"
        fi
        ;;
        
    lint)
        shift
        FIX=false
        
        # Parse options
        while [[ \$# -gt 0 ]]; do
            case \$1 in
                --fix)
                    FIX=true
                    shift
                    ;;
                --help)
                    echo "Usage: ./dev.sh lint [OPTIONS]"
                    echo
                    echo "Options:"
                    echo "  --fix      Fix issues where possible"
                    exit 0
                    ;;
                *)
                    shift
                    ;;
            esac
        done
        
        cd "${PROJECT_DIR}"
        
        if [ "\$FIX" = true ]; then
            echo "Running linters and fixing issues..."
            black src tests
            isort src tests
            flake8 src tests
            mypy src
            bandit -r src
        else
            echo "Running linters..."
            black --check src tests
            isort --check-only src tests
            flake8 src tests
            mypy src
            bandit -r src
        fi
        ;;
        
    format)
        echo "Formatting code..."
        cd "${PROJECT_DIR}" && black src tests
        cd "${PROJECT_DIR}" && isort src tests
        ;;
        
    clean)
        echo "Cleaning temporary files..."
        find "${PROJECT_DIR}" -name "*.pyc" -delete
        find "${PROJECT_DIR}" -name "__pycache__" -delete
        find "${PROJECT_DIR}" -name "*.egg-info" -type d -exec rm -rf {} +
        find "${PROJECT_DIR}" -name "*.egg" -delete
        find "${PROJECT_DIR}" -name ".coverage" -delete
        find "${PROJECT_DIR}" -name "coverage.xml" -delete
        find "${PROJECT_DIR}" -name ".pytest_cache" -type d -exec rm -rf {} +
        find "${PROJECT_DIR}" -name "htmlcov" -type d -exec rm -rf {} +
        find "${PROJECT_DIR}" -name ".mypy_cache" -type d -exec rm -rf {} +
        rm -rf "${PROJECT_DIR}/tmp/cache"/*
        mkdir -p "${PROJECT_DIR}/tmp/cache"
        ;;
        
    docker)
        shift
        
        if [ ! -f "${PROJECT_DIR}/docker-compose.dev.yml" ]; then
            echo "Error: Docker Compose file not found."
            echo "Please run the setup script with --docker option first."
            exit 1
        fi
        
        case "\$1" in
            up)
                echo "Starting Docker development environment..."
                cd "${PROJECT_DIR}" && docker-compose -f docker-compose.dev.yml up -d
                ;;
            down)
                echo "Stopping Docker development environment..."
                cd "${PROJECT_DIR}" && docker-compose -f docker-compose.dev.yml down
                ;;
            restart)
                echo "Restarting Docker development environment..."
                cd "${PROJECT_DIR}" && docker-compose -f docker-compose.dev.yml restart
                ;;
            status)
                echo "Docker development environment status:"
                cd "${PROJECT_DIR}" && docker-compose -f docker-compose.dev.yml ps
                ;;
            logs)
                shift
                if [ -z "\$1" ]; then
                    cd "${PROJECT_DIR}" && docker-compose -f docker-compose.dev.yml logs --tail=100 -f
                else
                    cd "${PROJECT_DIR}" && docker-compose -f docker-compose.dev.yml logs --tail=100 -f \$1
                fi
                ;;
            *)
                echo "Usage: ./dev.sh docker [COMMAND]"
                echo
                echo "Commands:"
                echo "  up          Start the Docker environment"
                echo "  down        Stop the Docker environment"
                echo "  restart     Restart services"
                echo "  status      Show status of services"
                echo "  logs        Show logs (all services or specify service name)"
                exit 1
                ;;
        esac
        ;;
        
    version)
        echo "ASIRA Development Environment"
        echo "Version: 1.0.0"
        echo "Last updated: 2025-03-15 20:18:23"
        echo "Python version: $(python --version)"
        ;;
        
    help)
        show_help
        ;;
        
    *)
        if [ -z "\$1" ]; then
            show_help
        else
            echo "Unknown command: \$1"
            echo "Run './dev.sh help' for usage information"
            exit 1
        fi
        ;;
esac
EOF
chmod +x "${PROJECT_DIR}/dev.sh"

# Create README.dev.md with development instructions
log "Creating development documentation..."
cat > "${PROJECT_DIR}/README.dev.md" << EOF
# ASIRA Development Documentation

This document provides information for setting up and working with the ASIRA development environment.

## Getting Started

1. Set up the environment:
   \`\`\`bash
   ./scripts/setup_dev.sh
   \`\`\`

2. Activate the virtual environment:
   \`\`\`bash
   source .venv/bin/activate
   \`\`\`

3. Run the development server:
   \`\`\`bash
   ./dev.sh run
   \`\`\`

## Development Commands

Use the \`dev.sh\` script for common development tasks:

- \`./dev.sh run\`: Run the API server
- \`./dev.sh dashboard\`: Run the dashboard application
- \`./dev.sh worker\`: Run the background worker
- \`./dev.sh test\`: Run tests
- \`./dev.sh lint\`: Run code linters
- \`./dev.sh format\`: Format code
- \`./dev.sh shell\`: Open a Python shell with app context
- \`./dev.sh clean\`: Clean temporary files
- \`./dev.sh help\`: Show all available commands

## Docker Development Environment

If you set up with Docker (\`--docker\` flag), you can manage containers with:

- \`./dev.sh docker up\`: Start Docker containers
- \`./dev.sh docker down\`: Stop Docker containers
- \`./dev.sh docker logs\`: View container logs

## Project Structure

- \`src/\`: Main source code directory
  - \`api/\`: API endpoints and routers
  - \`dashboard/\`: Dashboard application
  - \`detection/\`: Anomaly detection models
  - \`response/\`: Incident response automation
  - \`database/\`: Database models and operations
  - \`utils/\`: Utility functions and helpers
- \`tests/\`: Test cases
- \`playbooks/\`: Response playbook definitions
- \`data/\`: Data files and models
- \`config/\`: Configuration files
- \`scripts/\`: Utility scripts

## Running Tests

Run all tests with coverage report:
\`\`\`bash
./dev.sh test
\`\`\`

Run a specific test file:
\`\`\`bash
./dev.sh test tests/test_api/test_endpoints.py
./dev.sh format
./dev.sh lint
./dev.sh lint --fix

./dev.sh run

ASIRA_LOG_LEVEL=DEBUG

python -m debugpy --listen 5678 --wait-for-client src/main.py

psql -U asira -d asira_dev

psql -U postgres -c "DROP DATABASE IF EXISTS asira_dev;"
psql -U postgres -c "CREATE DATABASE asira_dev OWNER asira;"

./scripts/install.sh
