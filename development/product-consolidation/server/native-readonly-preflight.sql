-- Execute through an existing authorized DBA connection only. No credentials here.
-- No model writes, locks FOR UPDATE, provisioning or native turn requests.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT current_setting('server_version') AS postgres_version,
       current_setting('transaction_read_only') AS read_only;
SELECT table_name,column_name,data_type,is_nullable,column_default
FROM information_schema.columns
WHERE table_schema='bimchat_direct_ownership'
 AND table_name IN ('model_streams','native_admissions')
ORDER BY table_name,ordinal_position;
SELECT tablename,indexname,indexdef FROM pg_indexes
WHERE schemaname='bimchat_direct_ownership'
 AND tablename='native_admissions' ORDER BY indexname;
SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
WHERE conrelid=to_regclass('bimchat_direct_ownership.native_admissions')
ORDER BY conname;
ROLLBACK;
-- This verifies schema only. Model fileId/epoch/sequence and deployed source hashes
-- require a separately scoped read once the new model's actual fileId is known.
