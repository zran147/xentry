-- Admit the model's reasoning as evidence in its own right.
--
-- ADK turns a provider's reasoning payload into types.Part(thought=True) and
-- puts it BEFORE the answer, and the extractor read parts[0] - so on a
-- reasoning model every extraction parsed the thinking and threw the answer
-- away. deepseek-chat emitted no thought part, which is why this never showed
-- until the account moved to deepseek-flash:
--
--   validator_error: extractor returned invalid JSON [11754 chars of reply]
--
-- where those 11,754 characters were the model reasoning correctly about sudo
-- CVE-2025-32463 and ending "Write JSON." - the JSON it then wrote having gone
-- into a part nobody looked at.
--
-- The reasoning is now recorded under its own stage instead of being dropped.
-- It says what the model understood the task to be, which separates a wrong
-- answer from a misread question, and it is the only account of a decision a
-- verdict rests on. Without these kinds the insert fails the artifacts CHECK,
-- and transcript.record() swallows a failing sink by design, so it would be
-- written to disk with no row to find it by - the exact silent hole that
-- migration 006 was written to close.
--
-- The stage name carries no underscore on purpose: the audit page splits
-- llm_<stage>_<part> on "_" and requires three fields, so "reasoning" is
-- readable there and "extract_reasoning" would be skipped.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt and its rows
-- copied across.

CREATE TABLE artifacts_v8 (
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
    'llm_reasoning_prompt','llm_reasoning_response'
  )),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

INSERT INTO artifacts_v8 (id, job_id, attempt_id, kind, path, sha256, bytes)
  SELECT id, job_id, attempt_id, kind, path, sha256, bytes FROM artifacts;

DROP TABLE artifacts;
ALTER TABLE artifacts_v8 RENAME TO artifacts;
CREATE INDEX idx_artifacts_job ON artifacts(job_id, attempt_id);

INSERT INTO schema_version(version) VALUES (8);
