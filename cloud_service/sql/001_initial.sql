CREATE TABLE IF NOT EXISTS scanner_endpoints (
    endpoint_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    hostname text NOT NULL,
    os_family text NOT NULL,
    os_version text NOT NULL,
    architecture text NOT NULL,
    scanner_version text NOT NULL,
    credential_generation integer NOT NULL,
    enrolled_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS scanner_endpoints_tenant_idx
    ON scanner_endpoints (tenant_id, enrolled_at DESC);

CREATE TABLE IF NOT EXISTS scanner_credentials (
    token_hash char(64) PRIMARY KEY,
    credential_id text UNIQUE NOT NULL,
    tenant_id text NOT NULL,
    endpoint_id text NOT NULL REFERENCES scanner_endpoints(endpoint_id) ON DELETE CASCADE,
    generation integer NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    superseded_at timestamptz,
    valid_until timestamptz
);
CREATE INDEX IF NOT EXISTS scanner_credentials_endpoint_idx
    ON scanner_credentials (endpoint_id, generation DESC);

CREATE TABLE IF NOT EXISTS scanner_scans (
    scan_id text PRIMARY KEY,
    job_id text UNIQUE NOT NULL,
    tenant_id text NOT NULL,
    endpoint_id text NOT NULL REFERENCES scanner_endpoints(endpoint_id),
    state text NOT NULL,
    job_document jsonb NOT NULL,
    upload jsonb,
    terminal_status jsonb,
    final_report jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS scanner_scans_dispatch_idx
    ON scanner_scans (tenant_id, endpoint_id, state, created_at);

CREATE TABLE IF NOT EXISTS scanner_analysis_tasks (
    task_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    endpoint_id text NOT NULL,
    scan_id text NOT NULL REFERENCES scanner_scans(scan_id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('OSV', 'DEPSCAN')),
    state text NOT NULL CHECK (state IN ('PENDING','RUNNING','SUCCEEDED','RETRY','FAILED')),
    attempts integer NOT NULL DEFAULT 0,
    payload jsonb NOT NULL,
    result jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    available_at timestamptz NOT NULL,
    lease_expires_at timestamptz,
    leased_by text,
    last_error text,
    UNIQUE (scan_id, kind)
);
CREATE INDEX IF NOT EXISTS scanner_tasks_claim_idx
    ON scanner_analysis_tasks (kind, state, available_at, created_at);

CREATE TABLE IF NOT EXISTS scanner_idempotency (
    tenant_id text NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash char(64) NOT NULL,
    response jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS scanner_rejections (
    rejection_id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    endpoint_id text NOT NULL,
    scan_id text,
    reason text NOT NULL,
    document_sha256 char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, endpoint_id, document_sha256)
);

CREATE TABLE IF NOT EXISTS scanner_audit_events (
    event_id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    event_type text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scanner_audit_tenant_idx
    ON scanner_audit_events (tenant_id, occurred_at DESC);
