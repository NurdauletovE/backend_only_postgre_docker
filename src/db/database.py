import asyncpg
from typing import Dict, List, Optional, Any
import json
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import uuid

logger = logging.getLogger(__name__)


class ComplianceDatabase:
    def __init__(self, connection_string: str, pool_min_size: int = 5, pool_max_size: int = 20):
        """
        Initialize the compliance database connection pool
        
        Args:
            connection_string: PostgreSQL connection string
            pool_min_size: Minimum number of connections in pool
            pool_max_size: Maximum number of connections in pool
        """
        self.connection_string = connection_string
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self.pool = None
    
    async def initialize(self):
        """Initialize database connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                self.connection_string,
                min_size=self.pool_min_size,
                max_size=self.pool_max_size,
                command_timeout=60
            )
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise
    
    async def close(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool"""
        if not self.pool:
            raise RuntimeError("Database pool not initialized")
        
        async with self.pool.acquire() as conn:
            yield conn
    
    async def store_scan_results(self, results: Dict, system_id: str) -> str:
        """
        Store compliance scan results with full audit trail
        
        Args:
            results: Scan results dictionary
            system_id: System identifier
            
        Returns:
            Scan ID as string
        """
        async with self.get_connection() as conn:
            async with conn.transaction():
                try:
                    # Insert main scan record
                    scan_id = await conn.fetchval("""
                        INSERT INTO compliance_scans 
                        (system_id, profile, scan_timestamp, compliance_score, status, 
                         scanner, datastream, raw_results, duration_seconds)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        RETURNING id
                    """, 
                        system_id, 
                        results.get("profile", "unknown"),
                        self._parse_timestamp(results.get("timestamp")),
                        results.get("score", 0.0),
                        "completed",
                        results.get("system_info", {}).get("scanner", "OpenSCAP"),
                        results.get("datastream"),
                        json.dumps(results),
                        results.get("duration_seconds")
                    )
                    
                    # Insert individual rule results
                    rules = results.get("rules", [])
                    if rules:
                        rule_data = []
                        for rule in rules:
                            rule_data.append((
                                scan_id,
                                rule.get("id", "unknown"),
                                rule.get("title", ""),
                                rule.get("severity", "unknown"),
                                rule.get("result", "unknown"),
                                rule.get("description", ""),
                                rule.get("remediation", ""),
                                rule.get("check_content", ""),
                                rule.get("fix_text", ""),
                                float(rule.get("weight", 1.0))
                            ))
                        
                        await conn.executemany("""
                            INSERT INTO rule_results 
                            (scan_id, rule_id, title, severity, result, description, 
                             remediation, check_content, fix_text, weight)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        """, rule_data)
                    
                    # Update system information
                    await self._update_system_info(conn, system_id, results.get("system_info", {}))
                    
                    logger.info(f"Stored scan results for system {system_id}, scan_id: {scan_id}")
                    return str(scan_id)
                    
                except Exception as e:
                    logger.error(f"Error storing scan results: {e}")
                    raise
    
    async def store_attestation(self, token: str, scan_id: str, jwt_payload: Dict) -> str:
        """
        Store JWT attestation with metadata
        
        Args:
            token: JWT token string
            scan_id: Associated scan ID
            jwt_payload: Decoded JWT payload
            
        Returns:
            Attestation ID
        """
        async with self.get_connection() as conn:
            try:
                attestation_id = await conn.fetchval("""
                    INSERT INTO attestations 
                    (scan_id, jwt_token, jwt_id, issuer, subject, audience, 
                     algorithm, issued_at, expires_at, verification_status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    RETURNING id
                """,
                    uuid.UUID(scan_id),
                    token,
                    jwt_payload.get("jti"),
                    jwt_payload.get("iss"),
                    jwt_payload.get("sub"),
                    jwt_payload.get("aud"),
                    "RS256",
                    datetime.fromtimestamp(jwt_payload.get("iat", 0), tz=timezone.utc),
                    datetime.fromtimestamp(jwt_payload.get("exp", 0), tz=timezone.utc),
                    "pending"
                )
                
                logger.info(f"Stored attestation for scan {scan_id}")
                return str(attestation_id)
                
            except Exception as e:
                logger.error(f"Error storing attestation: {e}")
                raise
    
    async def get_scan_results(self, scan_id: str) -> Optional[Dict]:
        """
        Retrieve scan results by ID
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Scan results dictionary or None
        """
        async with self.get_connection() as conn:
            try:
                # Get main scan record
                scan_record = await conn.fetchrow("""
                    SELECT cs.*, s.hostname, s.environment 
                    FROM compliance_scans cs
                    LEFT JOIN systems s ON cs.system_id = s.system_id
                    WHERE cs.id = $1
                """, uuid.UUID(scan_id))
                
                if not scan_record:
                    return None
                
                # Get rule results
                rule_records = await conn.fetch("""
                    SELECT * FROM rule_results 
                    WHERE scan_id = $1 
                    ORDER BY severity DESC, result DESC
                """, uuid.UUID(scan_id))
                
                # Convert to dictionary
                scan_data = dict(scan_record)
                scan_data["rules"] = [dict(rule) for rule in rule_records]
                
                return scan_data
                
            except Exception as e:
                logger.error(f"Error retrieving scan results: {e}")
                raise
    
    async def get_latest_scan(self, system_id: str, profile: Optional[str] = None) -> Optional[Dict]:
        """
        Get the latest scan for a system
        
        Args:
            system_id: System identifier
            profile: Optional profile filter
            
        Returns:
            Latest scan results or None
        """
        async with self.get_connection() as conn:
            try:
                query = """
                    SELECT * FROM compliance_scans 
                    WHERE system_id = $1 AND status = 'completed'
                """
                params = [system_id]
                
                if profile:
                    query += " AND profile = $2"
                    params.append(profile)
                
                query += " ORDER BY scan_timestamp DESC LIMIT 1"
                
                record = await conn.fetchrow(query, *params)
                return dict(record) if record else None
                
            except Exception as e:
                logger.error(f"Error retrieving latest scan: {e}")
                raise
    
    async def get_compliance_trend(self, system_id: str, days: int = 30) -> List[Dict]:
        """
        Get compliance score trend for a system
        
        Args:
            system_id: System identifier
            days: Number of days to look back
            
        Returns:
            List of compliance scores over time
        """
        async with self.get_connection() as conn:
            try:
                records = await conn.fetch("""
                    SELECT scan_timestamp, compliance_score, profile
                    FROM compliance_scans 
                    WHERE system_id = $1 AND status = 'completed'
                    AND scan_timestamp >= NOW() - INTERVAL $2 * INTERVAL '1 day'
                    ORDER BY scan_timestamp ASC
                """, system_id, days)
                
                return [dict(record) for record in records]
                
            except Exception as e:
                logger.error(f"Error retrieving compliance trend: {e}")
                raise
    
    async def get_systems_summary(self) -> List[Dict]:
        """Get summary of all systems and their latest compliance status"""
        async with self.get_connection() as conn:
            try:
                records = await conn.fetch("""
                    SELECT 
                        s.system_id,
                        s.hostname,
                        s.environment,
                        s.last_seen,
                        ls.compliance_score,
                        ls.scan_timestamp,
                        ls.profile,
                        ls.status
                    FROM systems s
                    LEFT JOIN latest_scans ls ON s.system_id = ls.system_id
                    WHERE s.is_active = true
                    ORDER BY s.hostname
                """)
                
                return [dict(record) for record in records]
                
            except Exception as e:
                logger.error(f"Error retrieving systems summary: {e}")
                raise
    
    async def get_failed_rules(self, system_id: Optional[str] = None, 
                              severity: Optional[str] = None, 
                              limit: int = 100) -> List[Dict]:
        """
        Get failed compliance rules across systems
        
        Args:
            system_id: Optional system filter
            severity: Optional severity filter
            limit: Maximum number of results
            
        Returns:
            List of failed rules
        """
        async with self.get_connection() as conn:
            try:
                query = """
                    SELECT 
                        rr.rule_id,
                        rr.title,
                        rr.severity,
                        rr.description,
                        rr.remediation,
                        cs.system_id,
                        cs.scan_timestamp,
                        s.hostname
                    FROM rule_results rr
                    JOIN compliance_scans cs ON rr.scan_id = cs.id
                    LEFT JOIN systems s ON cs.system_id = s.system_id
                    WHERE rr.result = 'fail'
                """
                params = []
                
                if system_id:
                    query += " AND cs.system_id = $1"
                    params.append(system_id)
                
                if severity:
                    param_num = len(params) + 1
                    query += f" AND rr.severity = ${param_num}"
                    params.append(severity)
                
                query += " ORDER BY rr.severity DESC, cs.scan_timestamp DESC"
                query += f" LIMIT ${len(params) + 1}"
                params.append(limit)
                
                records = await conn.fetch(query, *params)
                return [dict(record) for record in records]
                
            except Exception as e:
                logger.error(f"Error retrieving failed rules: {e}")
                raise
    
    async def register_system(self, system_info: Dict) -> str:
        """
        Register or update system information
        
        Args:
            system_info: System metadata dictionary
            
        Returns:
            System ID
        """
        async with self.get_connection() as conn:
            try:
                system_id = await conn.fetchval("""
                    INSERT INTO systems 
                    (system_id, hostname, ip_address, operating_system, os_version, 
                     architecture, environment, location, owner_email, tags, last_seen)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    ON CONFLICT (system_id) DO UPDATE SET
                        hostname = EXCLUDED.hostname,
                        ip_address = EXCLUDED.ip_address,
                        operating_system = EXCLUDED.operating_system,
                        os_version = EXCLUDED.os_version,
                        architecture = EXCLUDED.architecture,
                        environment = EXCLUDED.environment,
                        location = EXCLUDED.location,
                        owner_email = EXCLUDED.owner_email,
                        tags = EXCLUDED.tags,
                        last_seen = EXCLUDED.last_seen,
                        updated_at = CURRENT_TIMESTAMP
                    RETURNING system_id
                """,
                    system_info.get("system_id"),
                    system_info.get("hostname"),
                    system_info.get("ip_address"),
                    system_info.get("operating_system"),
                    system_info.get("os_version"),
                    system_info.get("architecture"),
                    system_info.get("environment"),
                    system_info.get("location"),
                    system_info.get("owner_email"),
                    json.dumps(system_info.get("tags", {})),
                    datetime.now(timezone.utc)
                )
                
                return system_id
                
            except Exception as e:
                logger.error(f"Error registering system: {e}")
                raise
    
    async def _update_system_info(self, conn, system_id: str, system_info: Dict):
        """Update system last seen timestamp"""
        try:
            await conn.execute("""
                UPDATE systems 
                SET last_seen = $1, updated_at = CURRENT_TIMESTAMP
                WHERE system_id = $2
            """, datetime.now(timezone.utc), system_id)
        except Exception as e:
            logger.warning(f"Could not update system info: {e}")
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse timestamp string to datetime object"""
        if not timestamp_str:
            return datetime.now(timezone.utc)
        
        try:
            # Try parsing ISO format
            if 'T' in timestamp_str:
                parsed = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                parsed = datetime.fromisoformat(timestamp_str)
            
            # Ensure timezone awareness
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            
            return parsed
        except Exception:
            logger.warning(f"Could not parse timestamp: {timestamp_str}")
            return datetime.now(timezone.utc)
    
    async def log_audit_event(self, actor_type: str, actor_id: str, 
                             event_type: str, description: str,
                             resource_type: Optional[str] = None,
                             resource_id: Optional[str] = None,
                             metadata: Optional[Dict] = None):
        """
        Log audit event
        
        Args:
            actor_type: Type of actor (user, system, api, etc.)
            actor_id: Actor identifier
            event_type: Type of event
            description: Event description
            resource_type: Type of resource affected
            resource_id: Resource identifier
            metadata: Additional metadata
        """
        async with self.get_connection() as conn:
            try:
                await conn.execute("""
                    INSERT INTO audit_logs 
                    (actor_type, actor_id, event_type, event_description,
                     resource_type, resource_id, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                    actor_type,
                    actor_id,
                    event_type,
                    description,
                    resource_type,
                    resource_id,
                    json.dumps(metadata or {})
                )
            except Exception as e:
                logger.error(f"Error logging audit event: {e}")
                # Don't raise exception for audit logging failures


class ComplianceQueries:
    """Helper class for complex compliance queries"""
    
    def __init__(self, db: ComplianceDatabase):
        self.db = db
    
    async def get_compliance_dashboard(self) -> Dict:
        """Get data for compliance dashboard"""
        async with self.db.get_connection() as conn:
            try:
                # Get overall statistics
                stats = await conn.fetchrow("""
                    SELECT 
                        COUNT(DISTINCT s.system_id) as total_systems,
                        COUNT(cs.id) as total_scans,
                        AVG(cs.compliance_score) as avg_compliance_score,
                        COUNT(CASE WHEN cs.compliance_score >= 80 THEN 1 END) as compliant_systems,
                        COUNT(CASE WHEN cs.scan_timestamp >= NOW() - INTERVAL '7 days' THEN 1 END) as recent_scans
                    FROM systems s
                    LEFT JOIN compliance_scans cs ON s.system_id = cs.system_id 
                    WHERE s.is_active = true AND (cs.status IS NULL OR cs.status = 'completed')
                """)
                
                # Get severity breakdown
                severity_stats = await conn.fetch("""
                    SELECT 
                        rr.severity,
                        COUNT(CASE WHEN rr.result = 'fail' THEN 1 END) as failed_count,
                        COUNT(*) as total_count
                    FROM rule_results rr
                    JOIN compliance_scans cs ON rr.scan_id = cs.id
                    WHERE cs.scan_timestamp >= NOW() - INTERVAL '30 days'
                    GROUP BY rr.severity
                    ORDER BY 
                        CASE rr.severity 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                            WHEN 'medium' THEN 3 
                            WHEN 'low' THEN 4 
                            ELSE 5 
                        END
                """)
                
                return {
                    "overview": dict(stats) if stats else {},
                    "severity_breakdown": [dict(row) for row in severity_stats]
                }
                
            except Exception as e:
                logger.error(f"Error getting dashboard data: {e}")
                raise