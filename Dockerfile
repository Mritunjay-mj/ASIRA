FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /etc/asira/playbooks /var/log/asira /tmp/asira/execution

# Set environment variables
ENV PYTHONPATH=/app
ENV ASIRA_LOG_LEVEL=INFO
ENV ASIRA_PLAYBOOK_DIR=/etc/asira/playbooks
ENV ASIRA_EXECUTION_DIR=/tmp/asira/execution

# Expose application port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
