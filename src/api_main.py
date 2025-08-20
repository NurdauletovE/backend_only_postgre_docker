#!/usr/bin/env python3
"""
FastAPI Application Entry Point

This module serves as the entry point for the FastAPI web service only,
without the heavy compliance scanning dependencies.
"""

import asyncio
import os
import sys
from pathlib import Path
import uvicorn

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from security.logging import initialize_logging, get_logger
from api.main import app

def main():
    """Main entry point for the FastAPI application"""
    
    # Configuration from environment
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    log_format = os.getenv('LOG_FORMAT', 'json')
    api_host = os.getenv('API_HOST', '0.0.0.0')
    api_port = int(os.getenv('API_PORT', '8000'))
    
    print("Starting FastAPI Compliance Service...")
    print(f"API Configuration:")
    print(f"  Host: {api_host}")
    print(f"  Port: {api_port}")
    print(f"  Log Level: {log_level}")
    print(f"  JWT Private Key: {os.getenv('JWT_PRIVATE_KEY_PATH')}")
    print(f"  JWT Public Key: {os.getenv('JWT_PUBLIC_KEY_PATH')}")
    
    try:
        # Initialize logging with correct parameter name
        initialize_logging(log_level=log_level, log_format=log_format)
        logger = get_logger(__name__)
        
        # API initialization will happen during FastAPI lifespan
        logger.info(f"Starting FastAPI server on {api_host}:{api_port}")
        
        # Start the server
        uvicorn.run(
            app,
            host=api_host,
            port=api_port,
            log_level=log_level.lower(),
            access_log=True
        )
        
    except Exception as e:
        print(f"Failed to start FastAPI service: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
