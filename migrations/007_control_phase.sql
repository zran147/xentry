-- Admit the fixed-version control run's nonce.
--
-- The control run places a nonce of its own and requires the PoC not to print
-- it, the same shape as the null run but against the same stack one package
-- version on. Without this phase the run failed on the CHECK at the moment it
-- placed the nonce, after the target, the attacker and both builds were
-- already up - the most expensive point in the job to discover a constraint.
--
-- UNIQUE(attempt_id, phase) still holds: one control nonce per attempt, and a
-- rewritten experimental PoC replaces its 'real' row as before. SQLite cannot
-- alter a CHECK constraint, so the table is rebuilt and its rows copied.

CREATE TABLE nonces_v7 (
  nonce_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  path TEXT NOT NULL,
  owner TEXT NOT NULL,
  mode INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (phase IN ('null','control','real')),
  UNIQUE(attempt_id, phase),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

INSERT INTO nonces_v7 (
  nonce_id, job_id, attempt_id, phase, sha256, path, owner, mode, created_at
) SELECT
  nonce_id, job_id, attempt_id, phase, sha256, path, owner, mode, created_at
  FROM nonces;

DROP TABLE nonces;
ALTER TABLE nonces_v7 RENAME TO nonces;

INSERT INTO schema_version(version) VALUES (7);
