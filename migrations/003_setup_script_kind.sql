-- Admit the provisioning script as evidence.
--
-- The script the broker runs inside the target VM is checked in and hash-pinned
-- in targets/steps.yaml, and the broker re-verifies that hash on the guest
-- before running it. Recording the exact bytes as an artifact puts the script in
-- the audit bundle beside the run it provisioned, so the evidence shows what was
-- executed and its digest can be checked against the manifest. SQLite cannot
-- alter a CHECK constraint, so the table is rebuilt and its rows copied across.

CREATE TABLE artifacts_v3 (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  CHECK (kind IN (
    'image','package','kernel','poc','evidence','bundle','other',
    'held_vms',
    'setup_script',
    'llm_extract_prompt','llm_extract_response',
    'llm_validate_prompt','llm_validate_response'
  )),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

INSERT INTO artifacts_v3 (id, job_id, attempt_id, kind, path, sha256, bytes)
  SELECT id, job_id, attempt_id, kind, path, sha256, bytes FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_v3 RENAME TO artifacts;
CREATE INDEX idx_artifacts_job ON artifacts(job_id, attempt_id);

INSERT INTO schema_version(version) VALUES (3);
