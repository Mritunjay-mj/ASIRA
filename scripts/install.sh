#!/bin/bash
#
# ASIRA: Automated Security Incident Response Agent
# Production Installation Script
#
# This script installs ASIRA and its dependencies in production mode
#
# Version: 1.0.0
# Last updated: 2025-03-15 20:07:45
# Last updated by: Mritunjay-mj
#

set -e # Exit on error

# Default configuration
INSTALL_DIR="/opt/asira"
CONFIG_DIR="/etc/asira"
LOG_DIR="/var/log/asira"
TEMP_DIR="/tmp/asira"
REPO_URL="https://github.com/mritunjay-cybersec/ASIRA.git"
DB_USER="asira"
DB_PASSWORD="asira_password"
DB_NAME="asira"
API_PORT=8000
DASHBOARD_PORT=8050
NGINX_PORT=80
INSTALL_MODE="production"
SKIP_DEPS=false
SKIP_DB=false
BRANCH="main"
UPDATE_ONLY=false
FORCE=false

# Function to display help
show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help                 Show this help message"
    echo "  -d, --install-dir DIR      Installation directory (default: /opt/asira)"
    echo "  -c, --config-dir DIR       Configuration directory (default: /etc/asira)"
    echo "  -r, --repo-url URL         Repository URL (default: GitHub URL)"
    echo "  -b, --branch BRANCH        Git branch to use (default: main)"
    echo "  -p, --api-port PORT        API port (default: 8000)"
    echo "  -w, --dashboard-port PORT  Dashboard port (default: 8050)"
    echo "  -n, --nginx-port PORT      Nginx port (default: 80)"
    echo "  --db-user USER             Database user (default: asira)"
    echo "  --db-password PASSWORD     Database password (default: asira_password)"
    echo "  --db-name NAME             Database name (default: asira)"
    echo "  --dev                      Install in development mode"
    echo "  --skip-deps                Skip system dependency installation"
    echo "  --skip-db                  Skip database setup"
    echo "  --update                   Update an existing installation"
    echo "  --force                    Force installation even if directories exist"
    echo
    echo "Example:"
    echo "  $0 --install-dir /usr/local/asira --db-password secure_password"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        -c|--config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        -r|--repo-url)
            REPO_URL="$2"
            shift 2
            ;;
        -b|--branch)
            BRANCH="$2"
            shift 2
            ;;
        -p|--api-port)
            API_PORT="$2"
            shift 2
            ;;
        -w|--dashboard-port)
            DASHBOARD_PORT="$2"
            shift 2
            ;;
        -n|--nginx-port)
            NGINX_PORT="$2"
            shift 2
            ;;
        --db-user)
            DB_USER="$2"
            shift 2
            ;;
        --db-password)
            DB_PASSWORD="$2"
            shift 2
            ;;
        --db-name)
            DB_NAME="$2"
            shift 2
            ;;
        --dev)
            INSTALL_MODE="development"
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --skip-db)
            SKIP_DB=true
            shift
            ;;
        --update)
            UPDATE_ONLY=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

echo "================================================"
echo "ASIRA Production Installation"
echo "================================================"
echo "Starting installation at $(date)"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or using sudo"
  exit 1
fi

# Check for update mode
if [ "$UPDATE_ONLY" = true ]; then
    echo "Updating existing installation..."
    if [ ! -d "$INSTALL_DIR" ] || [ ! -d "$CONFIG_DIR" ]; then
        echo "Error: Cannot update, installation directories not found."
        echo "Please run without --update flag for a fresh installation."
        exit 1
    fi

    # Backup configuration
    echo "Backing up configuration..."
    BACKUP_DIR="${CONFIG_DIR}_backup_$(date +%Y%m%d%H%M%S)"
    cp -r "$CONFIG_DIR" "$BACKUP_DIR"
    echo "Configuration backed up to $BACKUP_DIR"

    # Pull latest code
    echo "Updating code repository..."
    cd "$INSTALL_DIR/repo"
    git fetch --all
    git checkout "$BRANCH"
    git pull

    # Update dependencies
    echo "Updating Python dependencies..."
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install --upgrade gunicorn

    # Restart services
    echo "Restarting services..."
    systemctl restart supervisor
    systemctl restart nginx

    echo "================================================"
    echo "ASIRA update complete!"
    echo "Access the dashboard at http://localhost:$NGINX_PORT"
    echo "API available at http://localhost:$NGINX_PORT/api"
    echo "================================================"
    exit 0
fi

# Check for existing installation
if [ -d "$INSTALL_DIR" ] && [ "$FORCE" != true ]; then
    echo "Error: Installation directory already exists: $INSTALL_DIR"
    echo "Use --force to overwrite or --update to update an existing installation."
    exit 1
fi

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p $INSTALL_DIR
mkdir -p $INSTALL_DIR/logs
mkdir -p $INSTALL_DIR/data
mkdir -p $CONFIG_DIR/playbooks
mkdir -p $LOG_DIR
mkdir -p $TEMP_DIR/execution

# Install system dependencies
if [ "$SKIP_DEPS" != true ]; then
    echo "Installing system dependencies..."
    apt-get update
    apt-get install -y \
      python3 \
      python3-pip \
      python3-venv \
      postgresql \
      redis-server \
      rabbitmq-server \
      nginx \
      supervisor \
      git \
      curl \
      build-essential \
      libpq-dev
fi

# Create asira user if it doesn't exist
if ! id -u asira &>/dev/null; then
  echo "Creating asira user..."
  useradd -r -s /bin/false -m -d /home/asira asira
fi

# Clone the repository
echo "Cloning ASIRA repository..."
if [ -d "$INSTALL_DIR/repo" ]; then
  cd $INSTALL_DIR/repo
  git fetch --all
  git checkout "$BRANCH"
  git pull
else
  git clone -b "$BRANCH" "$REPO_URL" $INSTALL_DIR/repo
  cd $INSTALL_DIR/repo
fi

# Create and activate virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn

# Set up PostgreSQL database
if [ "$SKIP_DB" != true ]; then
    echo "Setting up PostgreSQL database..."
    if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw $DB_NAME; then
      echo "Creating database and user..."
      sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
      sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
      sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    else
      echo "Database already exists, skipping creation..."
    fi
fi

# Create configuration file
echo "Creating configuration file..."
cat > $CONFIG_DIR/config.yaml << EOF
# ASIRA Configuration
# Generated on $(date)

# API Settings
api_port: $API_PORT
debug_mode: false
log_level: INFO
cors_origins:
  - "http://localhost:3000"
  - "http://localhost:$DASHBOARD_PORT"
  - "http://localhost:$NGINX_PORT"

# Database Settings
db_host: localhost
db_port: 5432
db_user: $DB_USER
db_password: $DB_PASSWORD
db_name: $DB_NAME

# Elasticsearch Settings
es_hosts:
  - http://localhost:9200
  
# RabbitMQ Settings
rabbitmq_url: amqp://guest:guest@localhost:5672/

# Redis Settings
redis_host: localhost
redis_port: 6379

# Security Settings
secret_key: $(openssl rand -hex 32)
token_expire_minutes: 1440  # 24 hours

# Playbook Settings
playbook_dir: $CONFIG_DIR/playbooks
execution_dir: $TEMP_DIR/execution
max_execution_time: 300
sandbox_type: subprocess
EOF

# Set up supervisor configuration
echo "Setting up supervisor configuration..."
cat > /etc/supervisor/conf.d/asira.conf << EOF
[program:asira-api]
command=$INSTALL_DIR/venv/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:$API_PORT src.main:app
directory=$INSTALL_DIR/repo
user=asira
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/api-error.log
stdout_logfile=$LOG_DIR/api-output.log
environment=ASIRA_CONFIG_FILE="$CONFIG_DIR/config.yaml"

[program:asira-dashboard]
command=$INSTALL_DIR/venv/bin/python src/dashboard/app.py
directory=$INSTALL_DIR/repo
user=asira
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/dashboard-error.log
stdout_logfile=$LOG_DIR/dashboard-output.log
environment=ASIRA_API_URL="http://localhost:$API_PORT/api",PORT="$DASHBOARD_PORT"

[program:asira-worker]
command=$INSTALL_DIR/venv/bin/python src/worker.py
directory=$INSTALL_DIR/repo
user=asira
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/worker-error.log
stdout_logfile=$LOG_DIR/worker-output.log
environment=ASIRA_CONFIG_FILE="$CONFIG_DIR/config.yaml"

[group:asira]
programs=asira-api,asira-dashboard,asira-worker
EOF

# Set up Nginx configuration
echo "Setting up Nginx configuration..."
cat > /etc/nginx/sites-available/asira << EOF
server {
    listen $NGINX_PORT;
    server_name _;

    location /api {
        proxy_pass http://localhost:$API_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://localhost:$DASHBOARD_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Add SSL configuration if needed
    # ssl_certificate /path/to/cert.pem;
    # ssl_certificate_key /path/to/key.pem;
}
EOF

# Enable Nginx site
if [ -f /etc/nginx/sites-enabled/default ]; then
  rm /etc/nginx/sites-enabled/default
fi
ln -sf /etc/nginx/sites-available/asira /etc/nginx/sites-enabled/

# Set correct permissions
echo "Setting permissions..."
chown -R asira:asira $INSTALL_DIR
chown -R asira:asira $CONFIG_DIR
chown -R asira:asira $LOG_DIR
chown -R asira:asira $TEMP_DIR/execution

# Install example playbooks
echo "Installing example playbooks..."
cp $INSTALL_DIR/repo/playbooks/*.yml $CONFIG_DIR/playbooks/ 2>/dev/null || echo "No example playbooks found"
chown -R asira:asira $CONFIG_DIR/playbooks/

# Set up firewall rules if ufw is installed
if command -v ufw >/dev/null 2>&1; then
    echo "Setting up firewall rules..."
    ufw allow $NGINX_PORT/tcp
    echo "Firewall rules added for port $NGINX_PORT"
fi

# Start services
echo "Starting services..."
systemctl restart postgresql
systemctl restart redis-server
systemctl restart rabbitmq-server
systemctl restart supervisor
systemctl restart nginx

# Run database migrations
echo "Running database migrations..."
source $INSTALL_DIR/venv/bin/activate
cd $INSTALL_DIR/repo
python -m src.database.migrations

# Install initial data if in production mode
if [ "$INSTALL_MODE" = "production" ]; then
    echo "Installing initial data..."
    python -m scripts.load_initial_data
fi

# Run verify installation
echo "Verifying installation..."
ASIRA_UP=false
MAX_RETRIES=10
RETRY_COUNT=0

echo "Waiting for ASIRA API to start (this may take a minute)..."
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    RETRY_COUNT=$((RETRY_COUNT+1))
    if curl -s http://localhost:$API_PORT/api/health | grep -q "status.*ok"; then
        ASIRA_UP=true
        break
    fi
    echo "Waiting for API to come online... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 3
done

if [ "$ASIRA_UP" = true ]; then
    echo "✓ ASIRA API is running properly"
else
    echo "⚠️ Could not verify ASIRA API is running. Check logs at $LOG_DIR/api-error.log"
fi

# Create command completion script
echo "Installing command completion..."
cat > /etc/bash_completion.d/asira << EOF
_asira_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    opts="start stop restart status logs config playbooks help"

    if [[ \${cur} == * ]] ; then
        COMPREPLY=( \$(compgen -W "\${opts}" -- \${cur}) )
        return 0
    fi
}
complete -F _asira_completion asira
EOF

# Create control script
echo "Creating control script..."
cat > /usr/local/bin/asira << EOF
#!/bin/bash
#
# ASIRA Control Script
#

case "\$1" in
    start)
        systemctl start supervisor
        echo "ASIRA services started"
        ;;
    stop)
        systemctl stop supervisor
        echo "ASIRA services stopped"
        ;;
    restart)
        systemctl restart supervisor
        echo "ASIRA services restarted"
        ;;
    status)
        echo "ASIRA Service Status:"
        supervisorctl status all
        ;;
    logs)
        if [ -z "\$2" ]; then
            echo "Usage: asira logs <api|dashboard|worker>"
        else
            case "\$2" in
                api)
                    tail -f $LOG_DIR/api-*.log
                    ;;
                dashboard)
                    tail -f $LOG_DIR/dashboard-*.log
                    ;;
                worker)
                    tail -f $LOG_DIR/worker-*.log
                    ;;
                *)
                    echo "Unknown service: \$2"
                    echo "Available services: api, dashboard, worker"
                    ;;
            esac
        fi
        ;;
    config)
        echo "ASIRA Configuration at $CONFIG_DIR/config.yaml"
        cat $CONFIG_DIR/config.yaml
        ;;
    playbooks)
        echo "Available playbooks in $CONFIG_DIR/playbooks:"
        ls -la $CONFIG_DIR/playbooks/*.yml
        ;;
    help)
        echo "ASIRA Control Script"
        echo "Usage: asira <command> [options]"
        echo
        echo "Commands:"
        echo "  start       Start ASIRA services"
        echo "  stop        Stop ASIRA services"
        echo "  restart     Restart ASIRA services"
        echo "  status      Show status of ASIRA services"
        echo "  logs        Show logs (usage: asira logs <api|dashboard|worker>)"
        echo "  config      Show current configuration"
        echo "  playbooks   List available playbooks"
        echo "  help        Show this help message"
        ;;
    *)
        echo "Unknown command: \$1"
        echo "Run 'asira help' for usage information"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/asira

echo "================================================"
echo "ASIRA installation complete!"
echo "Access the dashboard at http://localhost:$NGINX_PORT"
echo "API available at http://localhost:$NGINX_PORT/api"
echo
echo "To manage ASIRA, use the 'asira' command:"
echo "  asira start    - Start services"
echo "  asira stop     - Stop services"
echo "  asira status   - View service status"
echo "  asira logs api - View API logs"
echo "  asira help     - Show more commands"
echo "================================================"
echo "Installation log saved at $LOG_DIR/installation.log"
echo "Installation completed at $(date)"
echo "================================================"
