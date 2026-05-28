-- ============================================================================
-- EUD Compliance Dashboard - TimescaleDB Time-Series DDL
-- Platform Layer: TimescaleDB 2.x
-- Multi-Tenant Strategy: Schema-per-Tenant hypertable partition
-- ============================================================================

-- Table to store real-time compliance scoring changes and event logs
CREATE TABLE IF NOT EXISTS compliance_events (
    time TIMESTAMPTZ NOT NULL,
    device_id UUID NOT NULL,
    dimension VARCHAR(64) NOT NULL, -- e.g., 'EDR', 'VULNERABILITY', 'PATCH', 'ENCRYPTION', 'ZTA', 'IDENTITY'
    control_id VARCHAR(128) NOT NULL,
    old_status VARCHAR(32),
    new_status VARCHAR(32) NOT NULL,
    old_score NUMERIC(5, 2),
    new_score NUMERIC(5, 2) NOT NULL,
    delta NUMERIC(5,2) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- ============================================================================
-- HYPERTABLE CREATION
-- compliance_events partitioned by 'time' column
-- ============================================================================
SELECT create_hypertable('compliance_events', 'time', if_not_exists => TRUE);

-- Create hypertable indexing for rapid real-time dashboard plotting (Last 30-90 days)
CREATE INDEX IF NOT EXISTS idx_compliance_events_device_dim ON compliance_events (device_id, dimension, time DESC);

-- Configure retention policy: 90-day hot tier
-- Older data is archived to Parquet data lakes in S3/MinIO for low-cost cold queries
SELECT add_retention_policy('compliance_events', INTERVAL '90 days', if_not_exists => TRUE);

-- Configure compression policy for hypertable chunks older than 7 days
-- Reduces historical time-series storage footprint by ~90%
ALTER TABLE compliance_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id, dimension',
    timescaledb.compress_orderby = 'time DESC'
);

SELECT add_compression_policy('compliance_events', INTERVAL '7 days', if_not_exists => TRUE);
