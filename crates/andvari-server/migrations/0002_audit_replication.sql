-- Tracks the last audit_log row id replicated to each external sink.
-- Single-row-per-sink design — operators rarely have more than one sink.

CREATE TABLE audit_replication_state (
    sink            TEXT PRIMARY KEY,
    last_id         BIGINT NOT NULL DEFAULT 0,
    last_flushed_at TIMESTAMPTZ
);
