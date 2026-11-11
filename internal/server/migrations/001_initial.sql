CREATE TABLE IF NOT EXISTS host_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL DEFAULT '',
    distribution TEXT NOT NULL DEFAULT '',
    distribution_version TEXT NOT NULL DEFAULT '',
    kernel_version TEXT NOT NULL DEFAULT '',
    architecture TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL,
    report_collected_at TIMESTAMPTZ NOT NULL,
    last_report_id TEXT NOT NULL DEFAULT '',
    latest_report JSONB NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb
);
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS report_collected_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS last_report_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS hosts_last_seen_idx ON hosts(last_seen DESC);

CREATE TABLE IF NOT EXISTS host_group_members (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES host_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (host_id, group_id)
);

CREATE TABLE IF NOT EXISTS revoked_certificates (
    fingerprint TEXT PRIMARY KEY CHECK (length(fingerprint)=64),
    host_id TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    CHECK (status IN ('open','acknowledged','investigating','recovering','resolved','suppressed'))
);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_active_fingerprint_idx
    ON incidents(host_id, fingerprint) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS incidents_status_last_seen_idx ON incidents(status, last_seen DESC);

CREATE TABLE IF NOT EXISTS recovery_executions (
    id BIGSERIAL PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    policy TEXT NOT NULL,
    service TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    outcome TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    error TEXT NOT NULL DEFAULT '',
    UNIQUE(host_id, policy, started_at)
);
CREATE INDEX IF NOT EXISTS recovery_executions_started_at_idx ON recovery_executions(started_at DESC);

CREATE TABLE IF NOT EXISTS recovery_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    action_type TEXT NOT NULL CHECK (action_type = 'restart_service'),
    service TEXT NOT NULL,
    failure_for TEXT NOT NULL,
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    cooldown TEXT NOT NULL,
    verification_timeout TEXT NOT NULL,
    require_approval BOOLEAN NOT NULL DEFAULT true,
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS recovery_policy_hosts (
    policy_id UUID NOT NULL REFERENCES recovery_policies(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, host_id)
);
CREATE TABLE IF NOT EXISTS policy_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    version BIGINT NOT NULL DEFAULT 1
);
INSERT INTO policy_version(singleton,version) VALUES (true,1) ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS metric_baselines (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    metric TEXT NOT NULL,
    sample_count BIGINT NOT NULL CHECK (sample_count >= 1),
    mean DOUBLE PRECISION NOT NULL,
    squared_deviation_sum DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, metric)
);
