-- Reasoning belongs TO a stage, not beside it.
--
-- 008 admitted a standalone 'reasoning' stage, which the audit page rendered
-- as a third block with its own Question and Response - so one model call
-- appeared as two unrelated things, and the validator had no equivalent at
-- all. Both are now recorded against the call they belong to:
--
--   llm_extract.reasoning_response    the extractor's thinking
--   llm_validate.reasoning_response   the verdict's thinking
--
-- and the page shows each as a Reasoning caret after that stage's Question
-- and Response.
--
-- The dot matters. _llm_calls splits llm_<stage>_<part> on "_" and requires
-- exactly three fields, so a stage named extract_reasoning would be skipped
-- in silence while extract.reasoning splits correctly:
--
--   llm_extract.reasoning_response -> ['llm', 'extract.reasoning', 'response']
--
-- The 008 kinds stay admitted. Jobs run between the two migrations have rows
-- naming them, and dropping a kind that already exists in the table would
-- fail the copy.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt and its rows
-- copied across.

CREATE TABLE artifacts_v9 (
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
    'llm_pocgen_prompt','llm_pocgen_response',
    'llm_reasoning_prompt','llm_reasoning_response',
    'llm_extract.reasoning_prompt','llm_extract.reasoning_response',
    'llm_validate.reasoning_prompt','llm_validate.reasoning_response'
  )),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

INSERT INTO artifacts_v9 (id, job_id, attempt_id, kind, path, sha256, bytes)
  SELECT id, job_id, attempt_id, kind, path, sha256, bytes FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_v9 RENAME TO artifacts;
CREATE INDEX idx_artifacts_job ON artifacts(job_id, attempt_id);

INSERT INTO schema_version(version) VALUES (9);
