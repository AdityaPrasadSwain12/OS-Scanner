CREATE TABLE IF NOT EXISTS scanner_inventory_states (
    tenant_id text NOT NULL,
    endpoint_id text NOT NULL REFERENCES scanner_endpoints(endpoint_id) ON DELETE CASCADE,
    snapshot_hash char(64) NOT NULL,
    snapshot jsonb NOT NULL,
    source_scan_id text NOT NULL REFERENCES scanner_scans(scan_id),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id),
    CHECK (snapshot_hash ~ '^[0-9a-f]{64}$'),
    CHECK (jsonb_typeof(snapshot) = 'object')
);

CREATE INDEX IF NOT EXISTS scanner_inventory_states_updated_idx
    ON scanner_inventory_states (tenant_id, updated_at DESC);
