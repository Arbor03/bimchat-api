-- PREPARATION ONLY: not applied. Existing models remain disabled.
BEGIN;
ALTER TABLE bimchat_direct_ownership.model_streams
 ADD COLUMN native_gate_enabled boolean NOT NULL DEFAULT false,
 ADD COLUMN native_generation bigint NOT NULL DEFAULT 0 CHECK(native_generation>=0);
CREATE TABLE bimchat_direct_ownership.native_admissions (
 request_id uuid PRIMARY KEY,
 file_id integer NOT NULL REFERENCES bimchat_direct_ownership.model_streams(file_id),
 epoch uuid NOT NULL,
 participant_id uuid NOT NULL REFERENCES bimchat_direct_ownership.model_stream_participants(participant_id),
 arrival bigserial UNIQUE NOT NULL,
 state text NOT NULL CHECK(state IN ('waiting','reserved','admitted','completed')),
 generation bigint,
 base_sequence bigint,
 changed boolean,
 CHECK((state='waiting' AND generation IS NULL AND base_sequence IS NULL) OR
       (state<>'waiting' AND generation IS NOT NULL AND base_sequence IS NOT NULL AND generation>0 AND base_sequence>=0)),
 CHECK((state='completed')=(changed IS NOT NULL)),
 FOREIGN KEY(file_id,epoch) REFERENCES bimchat_direct_ownership.model_streams(file_id,epoch)
);
CREATE UNIQUE INDEX native_admission_one_owner ON bimchat_direct_ownership.native_admissions(file_id)
 WHERE state IN ('reserved','admitted');
CREATE UNIQUE INDEX native_admission_one_request_per_participant ON bimchat_direct_ownership.native_admissions(file_id,participant_id)
 WHERE state<>'completed';
CREATE INDEX native_admission_waiters ON bimchat_direct_ownership.native_admissions(file_id,arrival) WHERE state='waiting';
COMMIT;
