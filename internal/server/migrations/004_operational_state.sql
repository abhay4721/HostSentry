CREATE TABLE IF NOT EXISTS monitored_services (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    load_state TEXT NOT NULL DEFAULT '',
    active_state TEXT NOT NULL DEFAULT '',
    sub_state TEXT NOT NULL DEFAULT '',
    main_pid BIGINT NOT NULL DEFAULT 0 CHECK (main_pid >= 0),
    last_result TEXT NOT NULL DEFAULT '',
    restart_count BIGINT NOT NULL DEFAULT 0 CHECK (restart_count >= 0),
    active_since TIMESTAMPTZ,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (host_id, service_name)
);
CREATE INDEX IF NOT EXISTS monitored_services_active_state_idx ON monitored_services(active_state, observed_at DESC);
INSERT INTO monitored_services(host_id,service_name,load_state,active_state,sub_state,main_pid,last_result,restart_count,active_since,observed_at)
SELECT h.id,s.value->>'name',COALESCE(s.value->>'load_state',''),COALESCE(s.value->>'active_state',''),
       COALESCE(s.value->>'sub_state',''),
       CASE WHEN COALESCE(s.value->>'main_pid','') ~ '^[0-9]+$' THEN (s.value->>'main_pid')::bigint ELSE 0 END,
       COALESCE(s.value->>'last_result',''),
       CASE WHEN COALESCE(s.value->>'restart_count','') ~ '^[0-9]+$' THEN (s.value->>'restart_count')::bigint ELSE 0 END,
       NULLIF(s.value->>'since','')::timestamptz,h.report_collected_at
FROM hosts h
CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(h.latest_report->'services')='array' THEN h.latest_report->'services' ELSE '[]'::jsonb END) AS s(value)
WHERE COALESCE(s.value->>'name','')<>''
ON CONFLICT(host_id,service_name) DO NOTHING;

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    received_at TIMESTAMPTZ NOT NULL,
    report_collected_at TIMESTAMPTZ NOT NULL,
    report_id TEXT NOT NULL,
    agent_version TEXT NOT NULL DEFAULT '',
    warning_count INTEGER NOT NULL DEFAULT 0 CHECK (warning_count >= 0)
);
CREATE INDEX IF NOT EXISTS agent_heartbeats_received_idx ON agent_heartbeats(received_at DESC);
INSERT INTO agent_heartbeats(host_id,received_at,report_collected_at,report_id,agent_version,warning_count)
SELECT id,last_seen,report_collected_at,last_report_id,agent_version,
       CASE WHEN jsonb_typeof(latest_report->'warnings')='array' THEN jsonb_array_length(latest_report->'warnings') ELSE 0 END
FROM hosts
ON CONFLICT(host_id) DO UPDATE SET received_at=GREATEST(agent_heartbeats.received_at,EXCLUDED.received_at),
    report_collected_at=GREATEST(agent_heartbeats.report_collected_at,EXCLUDED.report_collected_at),
    report_id=CASE WHEN EXCLUDED.report_collected_at>=agent_heartbeats.report_collected_at THEN EXCLUDED.report_id ELSE agent_heartbeats.report_id END,
    agent_version=CASE WHEN EXCLUDED.report_collected_at>=agent_heartbeats.report_collected_at THEN EXCLUDED.agent_version ELSE agent_heartbeats.agent_version END,
    warning_count=CASE WHEN EXCLUDED.report_collected_at>=agent_heartbeats.report_collected_at THEN EXCLUDED.warning_count ELSE agent_heartbeats.warning_count END;

CREATE TABLE IF NOT EXISTS host_configuration_versions (
    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    policy_version BIGINT NOT NULL DEFAULT 0 CHECK (policy_version >= 0),
    observed_at TIMESTAMPTZ NOT NULL
);
INSERT INTO host_configuration_versions(host_id,policy_version,observed_at)
SELECT id,CASE WHEN COALESCE(latest_report->>'policy_version','') ~ '^[0-9]+$' THEN (latest_report->>'policy_version')::bigint ELSE 0 END,report_collected_at
FROM hosts
ON CONFLICT(host_id) DO UPDATE SET policy_version=EXCLUDED.policy_version,observed_at=EXCLUDED.observed_at
WHERE host_configuration_versions.observed_at<=EXCLUDED.observed_at;

CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (incident_id, channel)
);
CREATE INDEX IF NOT EXISTS notifications_created_idx ON notifications(created_at DESC, id DESC);
INSERT INTO notifications(incident_id,host_id,channel,severity,message,created_at)
SELECT id,host_id,'dashboard',severity,description,first_seen
FROM incidents
ON CONFLICT (incident_id,channel) DO NOTHING;
