# 🌐 API Documentation - Security Compliance Automation Agent

## 📋 Overview

The Compliance Agent API is a RESTful web service that provides comprehensive endpoints for managing security compliance scanning, attestation generation, and compliance reporting. The API implements JWT-based authentication and follows OpenAPI 3.0 specifications.

**Base URL**: `http://localhost:8000`  
**API Version**: `v1.0.0`  
**Authentication**: JWT Bearer Token  
**Content Type**: `application/json`

---

## 🔐 Authentication

### JWT Token Authentication
All API endpoints (except `/health`) require JWT authentication using Bearer tokens.

```http
Authorization: Bearer <jwt_token>
```

### Token Structure
```json
{
  "iss": "compliance-agent",
  "sub": "user-id",
  "iat": 1642781234,
  "exp": 1642867634,
  "roles": ["admin", "operator"],
  "permissions": ["scan:execute", "system:register"]
}
```

### Getting Authentication Token
```bash
# Example token request (implementation-specific)
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure_password"
  }'
```

---

## 📊 API Endpoints

### 🏥 Health & Status

#### `GET /health`
**Description**: Check API and system health status  
**Authentication**: None required  
**Rate Limit**: None

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-21T12:34:56Z",
  "version": "1.0.0",
  "components": {
    "database": "healthy",
    "plugins": {
      "overall_status": "healthy",
      "plugins": {
        "CIS": {
          "status": "healthy",
          "plugin": "CIS",
          "version": "1.0.0",
          "enabled": true,
          "openscap_content_available": true,
          "content_path": "/usr/share/xml/scap/ssg/content",
          "profiles_available": true,
          "supported_profiles_count": 5
        }
      },
      "total_plugins": 1,
      "unhealthy_plugins": 0
    },
    "agent": "healthy"
  }
}
```

**Status Codes**:
- `200` - Service healthy
- `503` - Service degraded or unhealthy

---

### 🖥️ System Management

#### `GET /systems`
**Description**: List all registered systems  
**Authentication**: Required  
**Permissions**: `system:read`

**Query Parameters**:
- `limit` (integer): Number of results (default: 50, max: 200)
- `offset` (integer): Pagination offset (default: 0)
- `environment` (string): Filter by environment (development, staging, production)
- `active_only` (boolean): Show only active systems (default: true)

**Request**:
```bash
curl -X GET "http://localhost:8000/systems?limit=10&environment=production" \
  -H "Authorization: Bearer <jwt_token>"
```

**Response**:
```json
{
  "systems": [
    {
      "id": "uuid-123",
      "system_id": "web-server-01",
      "hostname": "web01.example.com",
      "ip_address": "192.168.1.100",
      "operating_system": "Ubuntu",
      "os_version": "22.04",
      "environment": "production",
      "compliance_status": "compliant",
      "last_scan_time": "2024-01-21T10:30:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 25,
  "limit": 10,
  "offset": 0
}
```

#### `POST /systems`
**Description**: Register a new system for compliance monitoring  
**Authentication**: Required  
**Permissions**: `system:create`

**Request Body**:
```json
{
  "system_id": "db-server-02",
  "hostname": "db02.example.com",
  "ip_address": "192.168.1.200",
  "operating_system": "Ubuntu",
  "os_version": "22.04",
  "architecture": "x86_64",
  "environment": "production",
  "location": "datacenter-east",
  "owner_email": "admin@example.com",
  "tags": {
    "team": "infrastructure",
    "criticality": "high",
    "backup": "daily"
  }
}
```

**Response**:
```json
{
  "id": "uuid-456",
  "system_id": "db-server-02",
  "status": "registered",
  "message": "System successfully registered for compliance monitoring",
  "created_at": "2024-01-21T12:34:56Z"
}
```

#### `GET /systems/{system_id}`
**Description**: Get detailed information about a specific system  
**Authentication**: Required  
**Permissions**: `system:read`

**Response**:
```json
{
  "id": "uuid-123",
  "system_id": "web-server-01",
  "hostname": "web01.example.com",
  "ip_address": "192.168.1.100",
  "operating_system": "Ubuntu",
  "os_version": "22.04",
  "environment": "production",
  "compliance_status": "compliant",
  "compliance_score": 87.5,
  "last_scan": {
    "scan_id": "scan-uuid-789",
    "timestamp": "2024-01-21T10:30:00Z",
    "profile": "cis_ubuntu2204",
    "score": 87.5,
    "status": "completed"
  },
  "compliance_trend": [
    {
      "date": "2024-01-21",
      "score": 87.5
    },
    {
      "date": "2024-01-20",
      "score": 85.2
    }
  ],
  "tags": {
    "team": "web",
    "criticality": "medium"
  }
}
```

#### `PUT /systems/{system_id}`
**Description**: Update system information  
**Authentication**: Required  
**Permissions**: `system:update`

#### `DELETE /systems/{system_id}`
**Description**: Deregister a system  
**Authentication**: Required  
**Permissions**: `system:delete`

---

### 🔍 Compliance Scanning

#### `GET /scans`
**Description**: List compliance scan history  
**Authentication**: Required  
**Permissions**: `scan:read`

**Query Parameters**:
- `system_id` (string): Filter by system ID
- `profile` (string): Filter by compliance profile
- `status` (string): Filter by scan status
- `start_date` (string): Filter scans after date (ISO 8601)
- `end_date` (string): Filter scans before date (ISO 8601)
- `limit` (integer): Number of results (default: 50)
- `offset` (integer): Pagination offset

**Response**:
```json
{
  "scans": [
    {
      "id": "scan-uuid-789",
      "system_id": "web-server-01",
      "profile": "cis_ubuntu2204",
      "status": "completed",
      "compliance_score": 87.5,
      "scan_start_time": "2024-01-21T10:30:00Z",
      "scan_end_time": "2024-01-21T10:35:00Z",
      "duration_seconds": 300,
      "total_rules": 200,
      "passed_rules": 175,
      "failed_rules": 25,
      "attestation_id": "attestation-uuid-101"
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

#### `POST /scans`
**Description**: Trigger a new compliance scan  
**Authentication**: Required  
**Permissions**: `scan:execute`

**Request Body**:
```json
{
  "system_id": "web-server-01",
  "profile": "cis_ubuntu2204",
  "plugin": "CIS",
  "scan_type": "full",
  "config": {
    "remediation": false,
    "severity_filter": "medium",
    "custom_rules": []
  }
}
```

**Response**:
```json
{
  "scan_id": "scan-uuid-890",
  "status": "initiated",
  "message": "Compliance scan successfully initiated",
  "estimated_duration": "5-10 minutes",
  "created_at": "2024-01-21T12:34:56Z"
}
```

#### `GET /scans/{scan_id}`
**Description**: Get detailed scan results  
**Authentication**: Required  
**Permissions**: `scan:read`

**Response**:
```json
{
  "id": "scan-uuid-789",
  "system_id": "web-server-01",
  "profile": "cis_ubuntu2204",
  "status": "completed",
  "compliance_score": 87.5,
  "scan_start_time": "2024-01-21T10:30:00Z",
  "scan_end_time": "2024-01-21T10:35:00Z",
  "summary": {
    "total_rules": 200,
    "passed_rules": 175,
    "failed_rules": 25,
    "error_rules": 0,
    "not_applicable_rules": 0
  },
  "rule_results": [
    {
      "rule_id": "CIS-1.1.1",
      "title": "Ensure mounting of cramfs filesystems is disabled",
      "severity": "medium",
      "result": "pass",
      "description": "The cramfs filesystem type is a compressed read-only Linux filesystem...",
      "remediation": "Edit /etc/modprobe.d/CIS.conf and add: install cramfs /bin/true"
    }
  ],
  "attestation": {
    "id": "attestation-uuid-101",
    "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "issued_at": "2024-01-21T10:35:00Z",
    "expires_at": "2024-01-22T10:35:00Z"
  }
}
```

#### `GET /scans/{scan_id}/results`
**Description**: Download scan results in various formats  
**Authentication**: Required  
**Permissions**: `scan:read`

**Query Parameters**:
- `format` (string): Result format (json, xml, html, pdf)

**Response**: Binary file download

---

### 📜 Attestations

#### `GET /attestations`
**Description**: List compliance attestations  
**Authentication**: Required  
**Permissions**: `attestation:read`

**Response**:
```json
{
  "attestations": [
    {
      "id": "attestation-uuid-101",
      "scan_id": "scan-uuid-789",
      "system_id": "web-server-01",
      "jwt_id": "jwt-123",
      "issuer": "compliance-agent",
      "subject": "web-server-01",
      "issued_at": "2024-01-21T10:35:00Z",
      "expires_at": "2024-01-22T10:35:00Z",
      "verification_status": "verified",
      "compliance_score": 87.5
    }
  ]
}
```

#### `POST /attestations`
**Description**: Generate compliance attestation for a scan  
**Authentication**: Required  
**Permissions**: `attestation:create`

**Request Body**:
```json
{
  "scan_id": "scan-uuid-789",
  "validity_hours": 24,
  "include_remediation": true
}
```

**Response**:
```json
{
  "attestation_id": "attestation-uuid-102",
  "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-01-22T12:34:56Z",
  "scan_id": "scan-uuid-789",
  "compliance_score": 87.5
}
```

#### `POST /attestations/verify`
**Description**: Verify an attestation token  
**Authentication**: Required  
**Permissions**: `attestation:verify`

**Request Body**:
```json
{
  "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response**:
```json
{
  "valid": true,
  "claims": {
    "iss": "compliance-agent",
    "sub": "web-server-01",
    "iat": 1642781234,
    "exp": 1642867634,
    "compliance_data": {
      "scan_id": "scan-uuid-789",
      "profile": "cis_ubuntu2204",
      "score": 87.5,
      "status": "compliant"
    }
  },
  "verification_timestamp": "2024-01-21T12:34:56Z"
}
```

---

### 📊 Reports

#### `GET /reports`
**Description**: List available reports  
**Authentication**: Required  
**Permissions**: `report:read`

**Response**:
```json
{
  "reports": [
    {
      "id": "executive-summary",
      "name": "Executive Compliance Summary",
      "description": "High-level compliance overview for leadership",
      "formats": ["pdf", "html", "json"]
    },
    {
      "id": "technical-details",
      "name": "Technical Compliance Details",
      "description": "Detailed technical findings and remediation",
      "formats": ["html", "xml", "json"]
    }
  ]
}
```

#### `GET /reports/compliance`
**Description**: Generate compliance status report  
**Authentication**: Required  
**Permissions**: `report:read`

**Query Parameters**:
- `system_id` (string): Filter by system
- `environment` (string): Filter by environment
- `format` (string): Report format (json, html, pdf)
- `start_date` (string): Report start date
- `end_date` (string): Report end date

**Response**:
```json
{
  "report_id": "report-uuid-123",
  "generated_at": "2024-01-21T12:34:56Z",
  "period": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-21T23:59:59Z"
  },
  "summary": {
    "total_systems": 25,
    "compliant_systems": 20,
    "non_compliant_systems": 5,
    "average_compliance_score": 85.4
  },
  "systems": [
    {
      "system_id": "web-server-01",
      "compliance_score": 87.5,
      "status": "compliant",
      "last_scan": "2024-01-21T10:30:00Z",
      "critical_issues": 0,
      "high_issues": 2,
      "medium_issues": 5
    }
  ],
  "trends": [
    {
      "date": "2024-01-21",
      "average_score": 85.4
    }
  ]
}
```

#### `GET /reports/trends`
**Description**: Get compliance trend analysis  
**Authentication**: Required  
**Permissions**: `report:read`

---

### 🔌 Plugins

#### `GET /plugins`
**Description**: List available compliance plugins  
**Authentication**: Required  
**Permissions**: `plugin:read`

**Response**:
```json
{
  "plugins": [
    {
      "name": "CIS",
      "version": "1.0.0",
      "description": "Center for Internet Security Benchmarks",
      "status": "active",
      "supported_profiles": [
        {
          "profile": "cis_ubuntu2204",
          "description": "CIS Ubuntu 22.04 LTS Benchmark",
          "version": "1.0.0"
        }
      ]
    }
  ]
}
```

#### `GET /plugins/{plugin_name}/profiles`
**Description**: Get available profiles for a plugin  
**Authentication**: Required  
**Permissions**: `plugin:read`

---

## 🔒 Security Headers

All API responses include security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
X-Request-ID: uuid-request-identifier
```

---

## ⚠️ Error Responses

### Standard Error Format
```json
{
  "error": "Error description",
  "status_code": 400,
  "timestamp": "2024-01-21T12:34:56Z",
  "request_id": "uuid-request-123",
  "details": {
    "field": "Additional error details"
  }
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 409 | Conflict |
| 422 | Validation Error |
| 429 | Rate Limited |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

---

## 🚀 Rate Limiting

API endpoints are rate limited to prevent abuse:

- **Authentication endpoints**: 5 requests per minute
- **Scan triggers**: 10 requests per hour per user
- **General API**: 1000 requests per hour per user
- **Health checks**: Unlimited

Rate limit headers:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642867634
```

---

## 📝 Examples

### Complete Workflow Example

```bash
# 1. Check API health
curl -X GET http://localhost:8000/health

# 2. Register a new system
curl -X POST http://localhost:8000/systems \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "web-server-03",
    "hostname": "web03.example.com",
    "ip_address": "192.168.1.103",
    "operating_system": "Ubuntu",
    "os_version": "22.04"
  }'

# 3. Trigger compliance scan
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "web-server-03",
    "profile": "cis_ubuntu2204"
  }'

# 4. Check scan status
curl -X GET "http://localhost:8000/scans/scan-uuid-890" \
  -H "Authorization: Bearer <jwt_token>"

# 5. Generate attestation
curl -X POST http://localhost:8000/attestations \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-uuid-890"
  }'

# 6. Generate compliance report
curl -X GET "http://localhost:8000/reports/compliance?format=json" \
  -H "Authorization: Bearer <jwt_token>"
```

---

## 🔧 OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

This comprehensive API documentation provides all the information needed to integrate with the Security Compliance Automation Agent, from basic health checks to complex compliance workflows.
