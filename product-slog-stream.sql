-- Preparation only. Does not enable split mode or alter existing model data.
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_streams (
 file_id integer PRIMARY KEY REFERENCES bimchat_direct_ownership.model_streams(file_id),
 epoch uuid NOT NULL, ownership_start_sequence bigint NOT NULL CHECK(ownership_start_sequence>=0),
 sequence bigint NOT NULL DEFAULT 0 CHECK(sequence>=0), generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
 baseline jsonb NOT NULL, head jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_participants (
 participant_id uuid PRIMARY KEY REFERENCES bimchat_direct_ownership.model_stream_participants(participant_id),
 file_id integer NOT NULL REFERENCES bimchat_direct_ownership.slog_streams(file_id),
 applied_sequence bigint NOT NULL CHECK(applied_sequence>=0), pin jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_sessions (
 session_id uuid PRIMARY KEY, participant_id uuid NOT NULL REFERENCES bimchat_direct_ownership.slog_participants(participant_id),
 public_key jsonb NOT NULL, key_digest text NOT NULL, expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_admissions (
 request_id uuid PRIMARY KEY, file_id integer NOT NULL REFERENCES bimchat_direct_ownership.slog_streams(file_id),
 participant_id uuid NOT NULL REFERENCES bimchat_direct_ownership.slog_participants(participant_id),
 epoch uuid NOT NULL, arrival bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 state text NOT NULL CHECK(state IN ('waiting','reserved','admitted','completed')),
 generation bigint, base_sequence bigint, changed boolean
);
CREATE UNIQUE INDEX IF NOT EXISTS slog_one_active ON bimchat_direct_ownership.slog_admissions(file_id) WHERE state IN ('reserved','admitted');
CREATE UNIQUE INDEX IF NOT EXISTS slog_one_outstanding ON bimchat_direct_ownership.slog_admissions(file_id,participant_id) WHERE state<>'completed';
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_uploads (
 request_id uuid PRIMARY KEY REFERENCES bimchat_direct_ownership.slog_admissions(request_id), document jsonb NOT NULL, digest text NOT NULL
);
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_upload_chunks (
 request_id uuid NOT NULL REFERENCES bimchat_direct_ownership.slog_uploads(request_id), part bigint NOT NULL CHECK(part>=0),
 bytes bytea NOT NULL CHECK(octet_length(bytes)>0 AND octet_length(bytes)<=262144), PRIMARY KEY(request_id,part)
);
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_operations (
 file_id integer NOT NULL REFERENCES bimchat_direct_ownership.slog_streams(file_id), sequence bigint NOT NULL CHECK(sequence>0),
 request_id uuid NOT NULL UNIQUE REFERENCES bimchat_direct_ownership.slog_admissions(request_id),
 source_participant uuid NOT NULL REFERENCES bimchat_direct_ownership.slog_participants(participant_id),
 before_pin jsonb NOT NULL, after_pin jsonb NOT NULL, append_hash text NOT NULL,
 PRIMARY KEY(file_id,sequence)
);
-- Committed immutable byte extents. Sequence 0 is the explicitly verified base.
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_extents (
 file_id integer NOT NULL REFERENCES bimchat_direct_ownership.slog_streams(file_id), sequence bigint NOT NULL CHECK(sequence>=0),
 byte_offset bigint NOT NULL CHECK(byte_offset>=0), bytes bytea NOT NULL CHECK(octet_length(bytes)>0 AND octet_length(bytes)<=262144),
 PRIMARY KEY(file_id,byte_offset)
);
CREATE TABLE IF NOT EXISTS bimchat_direct_ownership.slog_transitions (
 file_id integer PRIMARY KEY REFERENCES bimchat_direct_ownership.slog_streams(file_id),
 review_digest text NOT NULL CHECK(review_digest ~ '^[A-F0-9]{64}$'),
 review jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
COMMIT;
