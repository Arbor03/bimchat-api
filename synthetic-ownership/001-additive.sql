BEGIN;
CREATE SCHEMA bimchat_synthetic_v1;
SET LOCAL search_path TO bimchat_synthetic_v1,pg_catalog;
CREATE TABLE environment(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), environment_id uuid NOT NULL UNIQUE, synthetic_only boolean NOT NULL CHECK(synthetic_only));
-- STAGED ONLY. Apply exclusively to a separately reviewed disposable test schema.
-- No seed/default enabled experiment; completed existing synthetic rows untouched.
CREATE TABLE observation_experiments (
 id uuid PRIMARY KEY, project_id integer NOT NULL, model text NOT NULL,
 generation uuid NOT NULL, source_session text NOT NULL, receiver_session text NOT NULL,
 source_root_identity text NOT NULL, destination_root_identity text NOT NULL,
 scratch_id uuid NOT NULL, pre_bundle text NOT NULL, sequence bigint NOT NULL,
 source_publication uuid NOT NULL, reviewed_destination jsonb NOT NULL,
 enabled boolean NOT NULL DEFAULT false, state text NOT NULL DEFAULT 'disabled',
 synthetic_only boolean NOT NULL DEFAULT true CHECK(synthetic_only), operator_confirmed_receiver_idle boolean NOT NULL DEFAULT false, idle_expires_at timestamptz,
 admission_id uuid, expires_at timestamptz, pending_operation uuid,
 CHECK(source_session<>receiver_session)
);
CREATE TABLE observation_scratch_attestations (
 experiment_id uuid NOT NULL REFERENCES observation_experiments(id),
 receiver_session text NOT NULL, receipt_id uuid NOT NULL UNIQUE,
 canonical_receipt text NOT NULL, digest text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE observation_transactions (
 operation_id uuid PRIMARY KEY, experiment_id uuid NOT NULL REFERENCES observation_experiments(id),
 admission_id uuid NOT NULL, digest text NOT NULL, wire text NOT NULL,
 state text NOT NULL, ack jsonb, created_at timestamptz NOT NULL DEFAULT now(), acknowledged_at timestamptz
);

CREATE TABLE sessions(session_id text PRIMARY KEY,experiment_id uuid NOT NULL REFERENCES observation_experiments(id),email text NOT NULL,role text NOT NULL CHECK(role IN ('source','receiver')),generation uuid NOT NULL,expires_at timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false,UNIQUE(experiment_id,role),UNIQUE(experiment_id,email));
COMMIT;