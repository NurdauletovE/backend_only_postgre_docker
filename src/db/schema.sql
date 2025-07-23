-- Security Compliance Automation Agent Database Schema
-- PostgreSQL implementation with comprehensive audit trails and attestation tracking

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Core compliance scan results table
CREATE TABLE compliance_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    system_id VARCHAR(255) NOT NULL,
    profile VARCHAR(255) NOT NULL,
    scan_timestamp TIMESTAMP NOT NULL,
    compliance_score DECIMAL(5,2) CHECK (compliance_score >= 0 AND compliance_score <= 100),
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    scanner VARCHAR(100) NOT NULL DEFAULT 'OpenSCAP',
    datastream VARCHAR(255),
    raw_results JSONB,
    error_message TEXT,
    duration_seconds INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    CONSTRAINT compliance_scans_score_range CHECK (compliance_score IS NULL OR (compliance_score >= 0 AND compliance_score <= 100))
);

-- Individual rule results with detailed information
CREATE TABLE rule_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES compliance_scans(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    title TEXT,
    severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high', 'critical', 'unknown')),
    result VARCHAR(20) NOT NULL CHECK (result IN ('pass', 'fail', 'error', 'unknown', 'notapplicable', 'notchecked', 'informational')),
    description TEXT,
    remediation TEXT,
    check_content TEXT,
    fix_text TEXT,
    weight DECIMAL(3,1) DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- JWT attestation tracking for compliance reporting
CREATE TABLE attestations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES compliance_scans(id) ON DELETE CASCADE,
    jwt_token TEXT NOT NULL,
    jwt_id VARCHAR(255), -- JWT ID claim for tracking
    issuer VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    audience VARCHAR(255) NOT NULL,
    algorithm VARCHAR(50) NOT NULL DEFAULT 'RS256',
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP,
    verification_status VARCHAR(20) CHECK (verification_status IN ('pending', 'verified', 'invalid', 'expired')),
    verification_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure token uniqueness
    UNIQUE(jwt_id)
);

-- System inventory and metadata
CREATE TABLE systems (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    system_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255),
    ip_address INET,
    operating_system VARCHAR(100),
    os_version VARCHAR(50),
    architecture VARCHAR(50),
    environment VARCHAR(50) CHECK (environment IN ('development', 'staging', 'production', 'test')),
    location VARCHAR(255),
    owner_email VARCHAR(255),
    tags JSONB DEFAULT '{}',
    last_seen TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Comprehensive audit trail for all system activities
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_type VARCHAR(50) NOT NULL CHECK (actor_type IN ('system', 'user', 'agent', 'api')),
    actor_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_description TEXT,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'
);

-- Compliance profiles and configurations
CREATE TABLE compliance_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    profile_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    framework VARCHAR(100) NOT NULL, -- CIS, NIST, PCI-DSS, etc.
    version VARCHAR(50),
    datastream VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scheduled scan configurations
CREATE TABLE scan_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    system_id VARCHAR(255) REFERENCES systems(system_id) ON DELETE CASCADE,
    profile_id UUID REFERENCES compliance_profiles(id) ON DELETE CASCADE,
    schedule_expression VARCHAR(100) NOT NULL, -- Cron expression
    is_enabled BOOLEAN DEFAULT true,
    next_run TIMESTAMP,
    last_run TIMESTAMP,
    failure_count INTEGER DEFAULT 0,
    max_failures INTEGER DEFAULT 3,
    notification_emails TEXT[], -- Array of email addresses
    created_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API keys and authentication
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(255) UNIQUE NOT NULL,
    key_hash VARCHAR(255) NOT NULL, -- bcrypt hash
    name VARCHAR(255) NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '{}', -- JSON array of permissions
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    created_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Notification configurations
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type VARCHAR(50) NOT NULL CHECK (type IN ('email', 'webhook', 'slack', 'teams')),
    name VARCHAR(255) NOT NULL,
    configuration JSONB NOT NULL, -- Endpoint URLs, credentials, etc.
    triggers JSONB NOT NULL, -- When to send notifications
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance optimization
CREATE INDEX idx_compliance_scans_system_id ON compliance_scans(system_id);
CREATE INDEX idx_compliance_scans_timestamp ON compliance_scans(scan_timestamp DESC);
CREATE INDEX idx_compliance_scans_status ON compliance_scans(status);
CREATE INDEX idx_compliance_scans_score ON compliance_scans(compliance_score);

CREATE INDEX idx_rule_results_scan_id ON rule_results(scan_id);
CREATE INDEX idx_rule_results_result ON rule_results(result);
CREATE INDEX idx_rule_results_severity ON rule_results(severity);

CREATE INDEX idx_attestations_scan_id ON attestations(scan_id);
CREATE INDEX idx_attestations_expires_at ON attestations(expires_at);
CREATE INDEX idx_attestations_verification_status ON attestations(verification_status);

CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_type, actor_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

CREATE INDEX idx_systems_system_id ON systems(system_id);
CREATE INDEX idx_systems_last_seen ON systems(last_seen DESC);
CREATE INDEX idx_systems_is_active ON systems(is_active);

CREATE INDEX idx_scan_schedules_next_run ON scan_schedules(next_run);
CREATE INDEX idx_scan_schedules_is_enabled ON scan_schedules(is_enabled);

-- Create functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers to relevant tables
CREATE TRIGGER update_compliance_scans_updated_at BEFORE UPDATE ON compliance_scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_systems_updated_at BEFORE UPDATE ON systems
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_compliance_profiles_updated_at BEFORE UPDATE ON compliance_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scan_schedules_updated_at BEFORE UPDATE ON scan_schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notifications_updated_at BEFORE UPDATE ON notifications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create function for automatic audit logging
CREATE OR REPLACE FUNCTION log_audit_event()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (actor_type, actor_id, event_type, resource_type, resource_id, new_values)
        VALUES ('system', 'database', TG_OP, TG_TABLE_NAME, NEW.id::text, row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (actor_type, actor_id, event_type, resource_type, resource_id, old_values, new_values)
        VALUES ('system', 'database', TG_OP, TG_TABLE_NAME, NEW.id::text, row_to_json(OLD), row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (actor_type, actor_id, event_type, resource_type, resource_id, old_values)
        VALUES ('system', 'database', TG_OP, TG_TABLE_NAME, OLD.id::text, row_to_json(OLD));
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ language 'plpgsql';

-- Apply audit triggers to key tables
CREATE TRIGGER audit_compliance_scans AFTER INSERT OR UPDATE OR DELETE ON compliance_scans
    FOR EACH ROW EXECUTE FUNCTION log_audit_event();

CREATE TRIGGER audit_attestations AFTER INSERT OR UPDATE OR DELETE ON attestations
    FOR EACH ROW EXECUTE FUNCTION log_audit_event();

CREATE TRIGGER audit_systems AFTER INSERT OR UPDATE OR DELETE ON systems
    FOR EACH ROW EXECUTE FUNCTION log_audit_event();

-- Create views for common queries
CREATE VIEW compliance_summary AS
SELECT 
    s.system_id,
    s.hostname,
    s.environment,
    cs.profile,
    cs.compliance_score,
    cs.scan_timestamp,
    cs.status,
    COUNT(rr.id) as total_rules,
    COUNT(CASE WHEN rr.result = 'pass' THEN 1 END) as passed_rules,
    COUNT(CASE WHEN rr.result = 'fail' THEN 1 END) as failed_rules,
    COUNT(CASE WHEN rr.severity = 'critical' AND rr.result = 'fail' THEN 1 END) as critical_failures,
    COUNT(CASE WHEN rr.severity = 'high' AND rr.result = 'fail' THEN 1 END) as high_failures
FROM compliance_scans cs
JOIN systems s ON cs.system_id = s.system_id
LEFT JOIN rule_results rr ON cs.id = rr.scan_id
WHERE cs.status = 'completed'
GROUP BY s.system_id, s.hostname, s.environment, cs.id, cs.profile, cs.compliance_score, cs.scan_timestamp, cs.status;

CREATE VIEW latest_scans AS
SELECT DISTINCT ON (cs.system_id, cs.profile)
    cs.id,
    cs.system_id,
    cs.profile,
    cs.compliance_score,
    cs.scan_timestamp,
    cs.status,
    s.hostname,
    s.environment
FROM compliance_scans cs
JOIN systems s ON cs.system_id = s.system_id
WHERE cs.status = 'completed'
ORDER BY cs.system_id, cs.profile, cs.scan_timestamp DESC;

-- Insert default compliance profiles
INSERT INTO compliance_profiles (profile_id, name, description, framework, version, datastream) VALUES
('xccdf_org.ssgproject.content_profile_cis', 'CIS Benchmark Level 1', 'Center for Internet Security Benchmark Level 1 Profile', 'CIS', '1.0', 'ssg-rhel9-ds.xml'),
('xccdf_org.ssgproject.content_profile_cis_server_l1', 'CIS Server Level 1', 'CIS Benchmark for Server Level 1', 'CIS', '1.0', 'ssg-rhel9-ds.xml'),
('xccdf_org.ssgproject.content_profile_pci-dss', 'PCI-DSS', 'Payment Card Industry Data Security Standard', 'PCI-DSS', '3.2', 'ssg-rhel9-ds.xml'),
('xccdf_org.ssgproject.content_profile_stig', 'DISA STIG', 'Defense Information Systems Agency Security Technical Implementation Guide', 'STIG', '1.0', 'ssg-rhel9-ds.xml');

COMMENT ON TABLE compliance_scans IS 'Core table storing compliance scan results and metadata';
COMMENT ON TABLE rule_results IS 'Individual compliance rule results with detailed pass/fail information';
COMMENT ON TABLE attestations IS 'Cryptographically signed compliance attestations for audit trails';
COMMENT ON TABLE systems IS 'System inventory and metadata for tracked systems';
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail for all system activities';
COMMENT ON TABLE compliance_profiles IS 'Available compliance profiles and their configurations';
COMMENT ON TABLE scan_schedules IS 'Automated scan scheduling configurations';
COMMENT ON TABLE api_keys IS 'API authentication keys and permissions';
COMMENT ON TABLE notifications IS 'Notification channel configurations';