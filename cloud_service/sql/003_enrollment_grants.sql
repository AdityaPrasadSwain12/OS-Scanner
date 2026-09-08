CREATE TABLE IF NOT EXISTS scanner_enrollment_grants (
    grant_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    token_hash char(64) UNIQUE NOT NULL,
    issued_by text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    os_family text CHECK (os_family IS NULL OR os_family IN ('WINDOWS','LINUX','MACOS')),
    label text,
    consumed_at timestamptz,
    endpoint_id text REFERENCES scanner_endpoints(endpoint_id),
    CHECK (expires_at > issued_at),
    CHECK (
        (consumed_at IS NULL AND endpoint_id IS NULL)
        OR (consumed_at IS NOT NULL AND endpoint_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS scanner_enrollment_grants_lookup_idx
    ON scanner_enrollment_grants (token_hash, expires_at);

CREATE INDEX IF NOT EXISTS scanner_enrollment_grants_tenant_idx
    ON scanner_enrollment_grants (tenant_id, issued_at DESC);
