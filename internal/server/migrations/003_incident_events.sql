CREATE TABLE IF NOT EXISTS incident_events (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_events_timeline_idx ON incident_events(incident_id,created_at,id);
INSERT INTO incident_events(incident_id,event_type,actor,details,created_at)
SELECT i.id,'opened','migration',jsonb_build_object('severity',i.severity,'description',i.description),i.first_seen
FROM incidents i
WHERE NOT EXISTS (SELECT 1 FROM incident_events e WHERE e.incident_id=i.id AND e.event_type='opened');
