#!/bin/bash
#
# ASIRA: Automated Security Incident Response Agent
# Production Installation Script
#
# This script installs ASIRA and its dependencies in production mode
#
# Version: 1.0.0
# Last updated: 2025-03-15 12:23:31
# Last updated by: Mritunjay-mj
#

set -e # Exit on error

echo "================================================"
echo "ASIRA Production Installation"
echo "================================================"
echo "Starting installation at $(date)"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or using sudo"
  exit 1
fi

# Create installation directory
INSTALL_DIR="/opt/asira"
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p $INSTALL_DIR
mkdir -p $INSTALL_DIR/logs
mkdir -p $INSTALL_DIR/data
mkdir -p /etc/asira/playbooks
mkdir -p /var/log/asira
mkdir -p /tmp/asira/execution

# Install system dependencies
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

# Create asira user if it doesn't exist
if ! id -u asira &>/dev/null; then
  echo "Creating asira user..."
  useradd -r -s /bin/false -m -d /home/asira asira
fi

# Clone the repository
echo "Cloning ASIRA repository..."
if [ -d "$INSTALL_DIR/repo" ]; then
  cd $INSTALL_DIR/repo
  git pull
else
  git clone https://github.com/mritunjay-cybersec/ASIRA.git $INSTALL_DIR/repo
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
echo "Setting up PostgreSQL database..."
if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw asira; then
  echo "Creating database and user..."
  sudo -u postgres psql -c "CREATE USER asira WITH PASSWORD 'asira_password';"
  sudo -u postgres psql -c "CREATE DATABASE asira OWNER asira;"
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE asira TO asira;"
fi

# Create configuration file
echo "Creating configuration file..."
cat > /etc/asira/config.yaml << EOF
# ASIRA Configuration
# Generated on $(date)

# API Settings
api_port: 8000
debug_mode: false
log_level: INFO
cors_origins:
  - "http://localhost:3000"
  - "http://localhost:8050"

# Database Settings
db_host: localhost
db_port: 5432
db_user: asira
db_password: asira_password
db_name: asira

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
playbook_dir: /etc/asira/playbooks
execution_dir: /tmp/asira/execution
max_execution_time: 300
sandbox_type: subprocess
EOF

# Set up supervisor configuration
echo "Setting up supervisor configuration..."
cat > /etc/supervisor/conf.d/asira.conf << EOF
[program:asira-api]
command=$INSTALL_DIR/venv/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 src.main:app
directory=$INSTALL_DIR/repo
user=asira
autostart=true
autorestart=true
stderr_logfile=/var/log/asira/api-error.log
stdout_logfile=/var/log/asira/api-output.log
environment=ASIRA_CONFIG_FILE="/etc/asira/config.yaml"

[program:asira-dashboard]
command=$INSTALL_DIR/venv/bin/python src/dashboard/app.py
directory=$INSTALL_DIR/repo
user=asira
autostart=true
autorestart=true
stderr_logfile=/var/log/asira/dashboard-error.log
stdout_logfile=/var/log/asira/dashboard-output.log
environment=ASIRA_API_URL="http://localhost:8000/api",PORT="8050"

[group:asira]
programs=asira-api,asira-dashboard
EOF

# Set up Nginx configuration
echo "Setting up Nginx configuration..."
cat > /etc/nginx/sites-available/asira << EOF
server {
    listen 80;
    server_name _;

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://localhost:8050;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
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
chown -R asira:asira /etc/asira
chown -R asira:asira /var/log/asira
chown -R asira:asira /tmp/asira/execution

# Install example playbooks
echo "Installing example playbooks..."
cp $INSTALL_DIR/repo/playbooks/*.yml /etc/asira/playbooks/
chown -R asira:asira /etc/asira/playbooks/

# Start services
echo "Starting services..."
systemctl restart postgresql
systemctl restart redis-server
systemctl restart rabbitmq-server
systemctl restart supervisor
systemctl restart nginx

echo "================================================"
echo "ASIRA installation complete!"
echo "Access the dashboard at http://localhost:80"
echo "API available at http://localhost:80/api"
echo "================================================"
