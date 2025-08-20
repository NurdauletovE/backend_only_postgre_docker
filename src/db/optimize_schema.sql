-- Database Performance Optimization Indexes
-- Run this after initial schema creation

-- Compliance Scans Indexes
CREATE INDEX IF NOT EXISTS idx_compliance_scans_system_timestamp 
  ON compliance_scans(system_id, scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_compliance_scans_status_timestamp 
  ON compliance_scans(status, scan_timestamp DESC) 
  WHERE status = 'completed';

CREATE INDEX IF NOT EXISTS idx_compliance_scans_system_status
  ON compliance_scans(system_id, status)
  WHERE status IN ('completed', 'running');

-- Rule Results Indexes
CREATE INDEX IF NOT EXISTS idx_rule_results_scan_severity 
  ON rule_results(scan_id, severity);

CREATE INDEX IF NOT EXISTS idx_rule_results_scan_result
  ON rule_results(scan_id, result)
  WHERE result IN ('fail', 'error');

CREATE INDEX IF NOT EXISTS idx_rule_results_severity_failed
  ON rule_results(severity, result)
  WHERE result = 'fail';

-- Attestations Indexes
CREATE INDEX IF NOT EXISTS idx_attestations_scan_issued 
  ON attestations(scan_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_attestations_expires
  ON attestations(expires_at)
  WHERE verification_status = 'verified';

CREATE INDEX IF NOT EXISTS idx_attestations_jwt_id
  ON attestations(jwt_id)
  WHERE jwt_id IS NOT NULL;

-- Systems Indexes
CREATE INDEX IF NOT EXISTS idx_systems_active_lastseen
  ON systems(is_active, last_seen DESC)
  WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_systems_environment
  ON systems(environment, is_active)
  WHERE is_active = true;

-- Audit Logs Indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp
  ON audit_logs(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_event
  ON audit_logs(actor_id, event_type, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_resource
  ON audit_logs(resource_type, resource_id, timestamp DESC);

-- Partial indexes for common queries
CREATE INDEX IF NOT EXISTS idx_compliance_scans_recent_completed
  ON compliance_scans(scan_timestamp DESC)
  WHERE status = 'completed' AND scan_timestamp > CURRENT_DATE - INTERVAL '30 days';

-- Statistics update for query planner
ANALYZE compliance_scans;
ANALYZE rule_results;
ANALYZE attestations;
ANALYZE systems;
ANALYZE audit_logs;

-- Function to get index usage statistics
CREATE OR REPLACE FUNCTION get_index_usage_stats()
RETURNS TABLE(
    schemaname text,
    tablename text,
    indexname text,
    index_size text,
    idx_scan bigint,
    idx_tup_read bigint,
    idx_tup_fetch bigint
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.schemaname::text,
        s.tablename::text,
        s.indexname::text,
        pg_size_pretty(pg_relation_size(s.indexrelid))::text as index_size,
        s.idx_scan,
        s.idx_tup_read,
        s.idx_tup_fetch
    FROM pg_stat_user_indexes s
    ORDER BY s.schemaname, s.tablename, s.indexname;
END;
$$ LANGUAGE plpgsql;

-- Function to identify missing indexes
CREATE OR REPLACE FUNCTION suggest_missing_indexes()
RETURNS TABLE(
    tablename text,
    attname text,
    n_distinct real,
    correlation real,
    suggestion text
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        t.tablename::text,
        a.attname::text,
        s.n_distinct,
        s.correlation,
        CASE 
            WHEN s.n_distinct > 100 AND s.correlation < 0.1 
            THEN 'Consider adding index'::text
            WHEN s.n_distinct > 10 AND s.correlation > 0.9 
            THEN 'Consider clustered index'::text
            ELSE 'Index may not be beneficial'::text
        END as suggestion
    FROM pg_stats s
    JOIN pg_tables t ON s.tablename = t.tablename
    JOIN pg_attribute a ON a.attname = s.attname
    JOIN pg_class c ON c.relname = s.tablename
    WHERE 
        s.schemaname = 'public'
        AND a.attrelid = c.oid
        AND NOT EXISTS (
            SELECT 1 FROM pg_index i 
            WHERE i.indrelid = c.oid 
            AND a.attnum = ANY(i.indkey)
        )
        AND s.n_distinct > 10
    ORDER BY s.n_distinct DESC;
END;
$$ LANGUAGE plpgsql;

-- Grant necessary permissions
GRANT EXECUTE ON FUNCTION get_index_usage_stats() TO compliance;
GRANT EXECUTE ON FUNCTION suggest_missing_indexes() TO compliance;