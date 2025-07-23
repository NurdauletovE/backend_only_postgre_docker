from fastapi import FastAPI, HTTPException, Depends, Security, Request
from contextlib import asynccontextmanager
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import jwt
import logging
import time
from datetime import datetime, timezone

from db.database import ComplianceDatabase, ComplianceQueries
from security.attestation import ComplianceAttestation
from core.agent import ComplianceAgent
from plugins.base import plugin_manager

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown"""
    # Startup
    logger.info("Starting Compliance Agent API")
    # Services would be initialized here with proper configuration
    yield
    # Shutdown
    logger.info("Shutting down Compliance Agent API")
    
    global compliance_agent, database
    
    if compliance_agent:
        await compliance_agent.stop()
    
    if database:
        await database.close()

# Initialize FastAPI app
app = FastAPI(
    title="Compliance Agent API",
    description="REST API for Security Compliance Automation Agent",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Security
security = HTTPBearer()

# Global instances (would be initialized from configuration)
database: Optional[ComplianceDatabase] = None
attestation_service: Optional[ComplianceAttestation] = None
compliance_agent: Optional[ComplianceAgent] = None


# Pydantic models
class AttestationRequest(BaseModel):
    scan_id: str = Field(..., description="ID of the compliance scan to attest")


class AttestationResponse(BaseModel):
    attestation_token: str = Field(..., description="Signed JWT attestation token")
    expires_at: str = Field(..., description="Token expiration timestamp")
    scan_id: str = Field(..., description="Associated scan ID")


class ScanRequest(BaseModel):
    system_id: Optional[str] = Field(None, description="System ID (auto-detected if not provided)")
    profile: str = Field(..., description="Compliance profile to scan against")
    plugin: str = Field("CIS", description="Plugin to use for scanning")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional scan configuration")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    compliance_score: Optional[float] = None
    message: str


class SystemStatus(BaseModel):
    system_id: str
    hostname: Optional[str] = None
    environment: Optional[str] = None
    latest_scan: Optional[Dict[str, Any]] = None
    compliance_trend: List[Dict[str, Any]] = []


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    components: Dict[str, Any]


# Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID for tracing"""
    import uuid
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://compliance.example.com"],  # Configure as needed
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# Authentication dependency
async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    """
    Verify JWT token for API authentication
    
    Returns:
        Decoded token payload
    """
    try:
        if not attestation_service:
            raise HTTPException(status_code=500, detail="Attestation service not initialized")
        
        # Verify JWT token properly using the attestation service
        if not attestation_service.public_key:
            raise HTTPException(status_code=500, detail="Public key not available for verification")
        
        payload = jwt.decode(
            credentials.credentials,
            key=attestation_service.public_key,
            algorithms=["RS256"],
            options={"verify_signature": True, "verify_exp": True}
        )
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(status_code=401, detail="Token verification failed")


# API Endpoints

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Get API health status"""
    try:
        # Check database
        db_healthy = False
        if database and database.pool:
            try:
                async with database.get_connection() as conn:
                    await conn.fetchval("SELECT 1")
                db_healthy = True
            except Exception:
                pass
        
        # Check plugins
        plugin_health = await plugin_manager.health_check_all()
        
        # Check agent
        agent_healthy = compliance_agent and compliance_agent.running if compliance_agent else False
        
        overall_status = "healthy"
        if not db_healthy or plugin_health.get("overall_status") != "healthy" or not agent_healthy:
            overall_status = "degraded"
        
        return HealthResponse(
            status=overall_status,
            timestamp=datetime.now(timezone.utc).isoformat(),
            version="1.0.0",
            components={
                "database": "healthy" if db_healthy else "unhealthy",
                "plugins": plugin_health,
                "agent": "healthy" if agent_healthy else "unhealthy"
            }
        )
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return HealthResponse(
            status="unhealthy",
            timestamp=datetime.now(timezone.utc).isoformat(),
            version="1.0.0",
            components={"error": str(e)}
        )


@app.post("/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, _user: Dict = Depends(verify_token)):
    """Execute a compliance scan"""
    try:
        if not compliance_agent:
            raise HTTPException(status_code=500, detail="Compliance agent not initialized")
        
        # Use provided system_id or agent's system_id
        system_id = request.system_id or compliance_agent.system_id
        
        # Execute scan
        result = await compliance_agent.execute_scan(request.profile, request.plugin)
        
        if result["success"]:
            return ScanResponse(
                scan_id=result["scan_id"],
                status="completed",
                compliance_score=result["compliance_score"],
                message="Scan completed successfully"
            )
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Scan failed: {result.get('error', 'Unknown error')}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/attestations", response_model=AttestationResponse)
async def create_attestation(request: AttestationRequest, _user: Dict = Depends(verify_token)):
    """Generate compliance attestation with cryptographic signature"""
    try:
        if not database:
            raise HTTPException(status_code=500, detail="Database not initialized")
        if not attestation_service:
            raise HTTPException(status_code=500, detail="Attestation service not initialized")
        
        # Get scan results
        scan_results = await database.get_scan_results(request.scan_id)
        if not scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Create attestation
        token = attestation_service.create_attestation(
            scan_results, 
            scan_results["system_id"]
        )
        
        # Store attestation
        payload = jwt.decode(token, options={"verify_signature": False})
        await database.store_attestation(token, request.scan_id, payload)
        
        return AttestationResponse(
            attestation_token=token,
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat(),
            scan_id=request.scan_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating attestation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/systems/{system_id}/compliance", response_model=SystemStatus)
async def get_compliance_status(system_id: str, _user: Dict = Depends(verify_token)):
    """Get current compliance status with trend analysis"""
    try:
        if not database:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        queries = ComplianceQueries(database)
        
        # Get latest scan
        latest_scan = await database.get_latest_scan(system_id)
        
        # Get compliance trend
        trend = await database.get_compliance_trend(system_id, days=30)
        
        # Get system info
        systems = await database.get_systems_summary()
        system_info = next((s for s in systems if s["system_id"] == system_id), None)
        
        return SystemStatus(
            system_id=system_id,
            hostname=system_info.get("hostname") if system_info else None,
            environment=system_info.get("environment") if system_info else None,
            latest_scan=latest_scan,
            compliance_trend=trend
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting compliance status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans/{scan_id}")
async def get_scan_details(scan_id: str, _user: Dict = Depends(verify_token)):
    """Get detailed scan results"""
    try:
        if not database:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        scan_results = await database.get_scan_results(scan_id)
        if not scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return scan_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/systems")
async def list_systems(_user: Dict = Depends(verify_token)):
    """List all systems and their compliance status"""
    try:
        if not database:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        systems = await database.get_systems_summary()
        return {"systems": systems}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing systems: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard")
async def get_dashboard(_user: Dict = Depends(verify_token)):
    """Get compliance dashboard data"""
    try:
        if not database:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        queries = ComplianceQueries(database)
        dashboard_data = await queries.get_compliance_dashboard()
        
        return dashboard_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/failed-rules")
async def get_failed_rules(
    system_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    _user: Dict = Depends(verify_token)
):
    """Get failed compliance rules"""
    try:
        if not database:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        failed_rules = await database.get_failed_rules(system_id, severity, limit)
        return {"failed_rules": failed_rules}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting failed rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/plugins")
async def list_plugins(_user: Dict = Depends(verify_token)):
    """List available compliance plugins"""
    try:
        plugins = plugin_manager.list_plugins()
        health = await plugin_manager.health_check_all()
        
        return {
            "plugins": plugins,
            "health": health
        }
        
    except Exception as e:
        logger.error(f"Error listing plugins: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/agent/status")
async def get_agent_status(_user: Dict = Depends(verify_token)):
    """Get compliance agent status"""
    try:
        if not compliance_agent:
            raise HTTPException(status_code=500, detail="Compliance agent not initialized")
        
        status = await compliance_agent.get_status()
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(request.state, "request_id", None)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(request.state, "request_id", None)
        }
    )


# Startup and shutdown events are now handled by the lifespan context manager


# Initialize function for external use
async def initialize_api(db: ComplianceDatabase, 
                        attestation: ComplianceAttestation,
                        agent: ComplianceAgent):
    """Initialize API with required services"""
    global database, attestation_service, compliance_agent
    
    database = db
    attestation_service = attestation
    compliance_agent = agent
    
    logger.info("API services initialized")