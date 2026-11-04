-- Additive, operator-applied migration. No startup DDL or changes to old receipts.
BEGIN;
CREATE TABLE bimchat_direct_ownership.normal_upload_seal_jobs (
 receipt_id uuid PRIMARY KEY REFERENCES bimchat_direct_ownership.normal_upload_receipts(id),
 owner_id uuid NOT NULL,
 state text NOT NULL CHECK(state IN ('ready','claimed','sealing','verified','completed','uncertain')),
 network_phase text CHECK(network_phase IN ('source-head','source-read','sealed-put','sealed-verify')),
 destination_key text UNIQUE,
 source_etag text,
 expected_sha256 text,
 expected_size bigint,
 verified_pin jsonb,
 result jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK ((state='completed')=(result IS NOT NULL)),
 CHECK (state NOT IN ('verified','completed') OR verified_pin IS NOT NULL)
);
COMMIT;
