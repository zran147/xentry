-- Widen artifacts.kind for the model transcripts and the held-VM record.
--
-- The audit page shows the prompt and reply of each model call, and a held job
-- records the VMs left running for inspection. Both are stored as artifacts, so
-- the kind CHECK has to admit them. SQLite cannot alter a CHECK constraint, so
-- the table is rebuilt and its rows copied across.

CREATE TABLE artifacts_v2 (
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
    'llm_extract_prompt','llm_extract_response',
    'llm_validate_prompt','llm_validate_response'
  )),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

INSERT INTO artifacts_v2 (id, job_id, attempt_id, kind, path, sha256, bytes)
  SELECT id, job_id, attempt_id, kind, path, sha256, bytes FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_v2 RENAME TO artifacts;
CREATE INDEX idx_artifacts_job ON artifacts(job_id, attempt_id);

INSERT INTO schema_version(version) VALUES (2);
