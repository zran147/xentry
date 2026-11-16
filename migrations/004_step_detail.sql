-- Keep the failure message on the step that failed.
--
-- A step recorded only its reason_code, so the message the failure carried -
-- the readiness script's stderr, the extractor's complaint - existed only in
-- the broker's root-owned exec log, where the app cannot read it and the audit
-- bundle never saw it. Debugging a failure meant guessing. ADD COLUMN needs no
-- table rebuild, so existing rows simply read NULL.

ALTER TABLE job_steps ADD COLUMN detail TEXT;

INSERT INTO schema_version(version) VALUES (4);
