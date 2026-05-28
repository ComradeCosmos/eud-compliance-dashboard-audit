-- ============================================================================
-- EUD Compliance Dashboard - Core Postgres Schema DDL
-- Platform Layer: PostgreSQL 16
-- Multi-Tenant Strategy: Schema-per-Tenant Isolation
-- ============================================================================

CREATE TYPE risk_level_enum AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');
CREATE TYPE device_state_enum AS ENUM ('IN_USE', 'IN_REPAIR', 'BROKEN', 'DECOMMISSIONED');
CREATE TYPE location_group_enum AS ENUM ('Sift', 'Non-Sift');

-- Relational metadata store for reconciled devices
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_name VARCHAR(255) NOT NULL,
    aliases VARCHAR(255)[] DEFAULT '{}',
    serial_number VARCHAR(128) UNIQUE,
    mac_addresses VARCHAR(17)[] DEFAULT '{}',
    fingerprint CHAR(64) UNIQUE, -- SHA256(serial + MAC[0] + manufacturer)
    os_family VARCHAR(64) NOT NULL,
    os_version VARCHAR(64) NOT NULL,
    os_build VARCHAR(64) NOT NULL,
    os_eol BOOLEAN DEFAULT FALSE,
    
    -- Enterprise Corporate Assumed Fields
    user_assigned VARCHAR(255) DEFAULT 'unassigned',
    last_login TIMESTAMPTZ,
    location VARCHAR(255) DEFAULT 'Remote',
    location_group location_group_enum DEFAULT 'Non-Sift',

    -- Source raw records stored per ingestion collector (JSONB)
    source_records JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Real-time compliance scoring dimensions
    risk_score NUMERIC(5, 2) NOT NULL DEFAULT 100.00 CHECK (risk_score >= 0.00 AND risk_score <= 100.00),
    risk_level risk_level_enum NOT NULL DEFAULT 'LOW',
    physical_state device_state_enum NOT NULL DEFAULT 'IN_USE',
    
    -- Vital flags and tracking timestamps
    stale_flags VARCHAR(64)[] DEFAULT '{}',
    last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- PERFORMANCE & SCALE INDEXES
-- ============================================================================
CREATE INDEX idx_devices_risk_level ON devices (risk_level);
CREATE INDEX idx_devices_last_seen ON devices (last_seen DESC);
CREATE INDEX idx_devices_fingerprint ON devices (fingerprint);
CREATE INDEX idx_devices_canonical_name_lower ON devices (LOWER(canonical_name));
CREATE INDEX idx_devices_matching_fields ON devices (serial_number, fingerprint);
CREATE INDEX idx_devices_location_group ON devices (location_group);

-- ============================================================================
-- IDENTITY RECONCILIATION AUDIT LOG
-- ============================================================================
CREATE TABLE IF NOT EXISTS reconciliation_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_device_name VARCHAR(255) NOT NULL,
    target_device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    stage_matched INT NOT NULL, 
    confidence_score NUMERIC(5,2) NOT NULL CHECK (confidence_score >= 0.00 AND confidence_score <= 100.00),
    decision VARCHAR(32) NOT NULL, 
    analyst_user_id UUID, 
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_recon_audit_target ON reconciliation_audit_log (target_device_id);
CREATE INDEX idx_recon_audit_timestamp ON reconciliation_audit_log (event_timestamp DESC);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_update_device_timestamp
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
