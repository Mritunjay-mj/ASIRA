"""
ASIRA: Automated Security Incident Response Agent
Main application entry point

Version: 1.0.0
Last updated: 2025-03-15 16:25:01
Last updated by: Rahul
"""

import os
import sys
import logging
import uvicorn
import asyncio
import datetime
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from src.api.routes import api_router
from src.common.config import Settings
from src.common.logging_config import configure_logging
from src.common.database import init_db, close_db, get_db
from src.common.security import verify_api_key
from src.response.playbooks.base import PlaybookRegistry
from src.detection.engine import DetectionEngine
from src.detection.processor import LogIngester

# Load configuration
settings = Settings()

# Configure logging
configure_logging(settings.log_level)
logger = logging.getLogger("asira")

# Global variables
startup_timestamp = datetime.datetime.now().timestamp()
system_info = {
    "version": "1.0.0",
    "name": "ASIRA",
    "description": "Automated Security Incident Response Agent",
    "environment": os.getenv("ENVIRONMENT", "production"),
}

# Define lifecycle events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    logger.info(f"Starting {system_info['name']} v{system_info['version']} in {system_info['environment']} environment")
    
    # Initialize database connections
    logger.info("Initializing database connections")
    await init_db()
    
    # Load playbooks
    logger.info("Loading response playbooks")
    playbook_registry = PlaybookRegistry(settings.playbook_dir)
    playbook_registry.load_playbooks()
    app.state.playbook_registry = playbook_registry
    logger.info(f"Loaded {len(playbook_registry.playbooks)} playbooks")
    
    # Initialize detection engine
    logger.info("Initializing detection engine")
    detection_config = settings.detection_config
    app.state.detection_engine = DetectionEngine(detection_config)
    
    # Check critical directories
    logger.info("Checking required directories")
    directories = [
        settings.playbook_dir,
        settings.execution_dir,
        settings.log_dir,
        settings.data_dir
    ]
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"Directory {directory} does not exist. Creating.")
            dir_path.mkdir(parents=True, exist_ok=True)
    
    # Additional startup info
    logger.info(f"API running on port {settings.api_port}")
    logger.info(f"Debug mode: {settings.debug_mode}")
    
    yield
    
    # Shutdown tasks
    logger.info("Shutting down ASIRA")
    logger.info("Closing database connections")
    await close_db()
    
    # Calculate uptime
    uptime = datetime.datetime.now().timestamp() - startup_timestamp
    logger.info(f"Server uptime: {str(datetime.timedelta(seconds=int(uptime)))}")
    logger.info("Shutdown complete")

# Initialize FastAPI app
app = FastAPI(
    title="ASIRA API",
    description="Automated Security Incident Response Agent API",
    version=system_info["version"],
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add trusted host checking if configured
if settings.trusted_hosts:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.trusted_hosts
    )

# Add global request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", "")
    if not request_id:
        request_id = f"req_{datetime.datetime.now().strftime('%y%m%d%H%M%S%f')}"
    
    logger.debug(f"Request {request_id}: {request.method} {request.url.path}")
    start_time = datetime.datetime.now()
    
    try:
        response = await call_next(request)
        process_time = (datetime.datetime.now() - start_time).total_seconds() * 1000
        logger.debug(f"Request {request_id} completed: {response.status_code} ({process_time:.2f}ms)")
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
        return response
    except Exception as e:
        logger.error(f"Request {request_id} failed: {str(e)}", exc_info=settings.debug_mode)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"}
        )

# Include API routes
app.include_router(api_router, prefix="/api")

# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Check the health status of the ASIRA system
    """
    uptime = datetime.datetime.now().timestamp() - startup_timestamp
    
    # Check database connection
    db_status = "ok"
    try:
        connection = await get_db()
        if not connection:
            db_status = "error"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    # Check playbook registry
    playbooks_status = "ok"
    playbooks_count = 0
    try:
        playbooks_count = len(app.state.playbook_registry.playbooks)
        if playbooks_count == 0:
            playbooks_status = "warning: no playbooks loaded"
    except Exception as e:
        playbooks_status = f"error: {str(e)}"
    
    # Check execution directory
    execution_dir_status = "ok"
    try:
        execution_dir = Path(settings.execution_dir)
        if not execution_dir.exists() or not os.access(execution_dir, os.W_OK):
            execution_dir_status = "error: directory not accessible"
    except Exception as e:
        execution_dir_status = f"error: {str(e)}"
    
    return {
        "status": "ok",
        "version": system_info["version"],
        "environment": system_info["environment"],
        "timestamp": datetime.datetime.now().timestamp(),
        "server_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime_seconds": uptime,
        "uptime_human": str(datetime.timedelta(seconds=int(uptime))),
        "components": {
            "database": db_status,
            "playbooks": playbooks_status,
            "execution_dir": execution_dir_status
        },
        "stats": {
            "playbooks_loaded": playbooks_count
        }
    }

# Version endpoint
@app.get("/version")
async def version():
    """
    Get version information for the ASIRA system
    """
    return {
        "name": system_info["name"],
        "version": system_info["version"],
        "description": system_info["description"],
        "api_version": "v1",
        "build_date": "2025-03-15",
        "environment": system_info["environment"]
    }

# Error handlers
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": "The requested resource was not found"}
    )

@app.exception_handler(500)
async def server_error_exception_handler(request: Request, exc: Exception):
    logger.error(f"Internal server error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    logger.info(f"Starting ASIRA API server on port {settings.api_port}")
    try:
        uvicorn.run(
            "src.main:app", 
            host="0.0.0.0", 
            port=settings.api_port,
            reload=settings.debug_mode,
            log_level=settings.log_level.lower()
        )
    except Exception as e:
        logger.critical(f"Failed to start ASIRA API server: {str(e)}", exc_info=True)
        sys.exit(1)
