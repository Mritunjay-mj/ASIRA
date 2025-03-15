"""
ASIRA: Automated Security Incident Response Agent
Main application entry point
"""
import os
import logging
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.routes import api_router
from src.common.config import Settings
from src.common.logging_config import configure_logging

# Load configuration
settings = Settings()

# Configure logging
configure_logging(settings.log_level)
logger = logging.getLogger("asira")

# Initialize FastAPI app
app = FastAPI(
    title="ASIRA API",
    description="Automated Security Incident Response Agent API",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api")

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    logger.info(f"Starting ASIRA API server on port {settings.api_port}")
    uvicorn.run(
        "src.main:app", 
        host="0.0.0.0", 
        port=settings.api_port,
        reload=settings.debug_mode
    )
