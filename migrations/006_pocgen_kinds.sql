-- Admit the generated PoC's prompt and reply as evidence.
--
-- The experimental pipeline asks a model to write the exploit, so what it was
-- asked and what it answered is the whole provenance of that run - there is no
-- repository and no commit to point at instead. Without these kinds the
-- recording failed the artifacts CHECK, and transcript.record() swallows a
-- failing sink by design, so the prompt and the reply were written to disk with
-- no row to find them by: silently unauditable. SQLite cannot alter a CHECK
-- constraint, so the table is rebuilt and its rows copied across.

CREATE TABLE artifacts_v6 (
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
    'llm_validate_prompt','llm_validate_response',
    'llm_pocgen_prompt','llm_pocgen_response'
  )),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

INSERT INTO artifacts_v6 (id, job_id, attempt_id, kind, path, sha256, bytes)
  SELECT id, job_id, attempt_id, kind, path, sha256, bytes FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_v6 RENAME TO artifacts;
CREATE INDEX idx_artifacts_job ON artifacts(job_id, attempt_id);

INSERT INTO schema_version(version) VALUES (6);
