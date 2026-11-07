PRAGMA foreign_keys = ON;

CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  cve_id TEXT,
  target_id TEXT NOT NULL,
  poc_url TEXT NOT NULL,
  check_id TEXT,
  bundle_sha256 TEXT,
  outcome TEXT,
  cleanup_state TEXT NOT NULL DEFAULT 'pending',
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  reason_code TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  attempt_dir TEXT NOT NULL,
  final_attempt_id TEXT,
  last_outcome_id TEXT,
  verdict TEXT,
  authority TEXT,
  agent_summary TEXT,
  CHECK (outcome IS NULL OR outcome IN ('completed','failed','cancelled','interrupted')),
  CHECK (cleanup_state IN ('pending','running','done','failed')),
  CHECK (cancel_requested IN (0,1)),
  CHECK (verdict IS NULL OR verdict IN ('reproduced','not_reproduced','inconclusive','not_run')),
  CHECK (authority IS NULL OR authority IN ('runner_observed+llm_assessed','guest_attested+llm_assessed','runner_observed'))
);

CREATE TABLE attempts (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_no INTEGER NOT NULL,
  attempt_dir TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  failure_code TEXT,
  previous_attempt_id TEXT,
  UNIQUE(job_id, attempt_no),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(previous_attempt_id) REFERENCES attempts(id)
);

CREATE TABLE job_steps (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  name TEXT NOT NULL,
  step_id TEXT,
  state TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  reason_code TEXT,
  UNIQUE(job_id, attempt_id, seq),
  CHECK (state IN ('pending','running','passed','failed','skipped')),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE vms (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  role TEXT NOT NULL,
  domain_name TEXT NOT NULL,
  state TEXT NOT NULL,
  started_at TEXT,
  destroyed_at TEXT,
  CHECK (role IN ('target','attacker')),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE broker_calls (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  verb TEXT NOT NULL,
  params_sha256 TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  status TEXT,
  result_path TEXT,
  result_sha256 TEXT,
  CHECK (status IS NULL OR status IN ('ok','error')),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE validations (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  authority TEXT NOT NULL,
  validator_model TEXT NOT NULL,
  validator_prompt_hash TEXT NOT NULL,
  verdict TEXT NOT NULL,
  reason_code TEXT,
  nonce_id TEXT NOT NULL,
  runner_nonce_observed INTEGER NOT NULL,
  null_actor_observed_nonce INTEGER NOT NULL,
  evidence_json TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL,
  ts TEXT NOT NULL,
  CHECK (verdict IN ('reproduced','not_reproduced','inconclusive','not_run')),
  CHECK (authority IN ('runner_observed+llm_assessed','guest_attested+llm_assessed')),
  CHECK (runner_nonce_observed IN (0,1)),
  CHECK (null_actor_observed_nonce IN (0,1)),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  CHECK (kind IN ('image','package','kernel','poc','evidence','bundle','other')),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE worker_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  owner TEXT NOT NULL,
  heartbeat TEXT NOT NULL
);

CREATE TABLE schema_version (
  version INTEGER NOT NULL
);

CREATE TABLE job_outcomes (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  outcome TEXT NOT NULL,
  verdict TEXT NOT NULL,
  authority TEXT NOT NULL,
  reason_code TEXT,
  ts TEXT NOT NULL,
  CHECK (outcome IN ('completed','failed','cancelled','interrupted')),
  CHECK (verdict IN ('reproduced','not_reproduced','inconclusive','not_run')),
  CHECK (authority IN ('runner_observed+llm_assessed','guest_attested+llm_assessed','runner_observed')),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE nonces (
  nonce_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  path TEXT NOT NULL,
  owner TEXT NOT NULL,
  mode INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (phase IN ('null','real')),
  UNIQUE(attempt_id, phase),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE link_checks (
  check_id TEXT PRIMARY KEY,
  cve_url TEXT NOT NULL,
  poc_url TEXT NOT NULL,
  cve_id TEXT,
  target_id TEXT,
  bundle_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE INDEX idx_jobs_outcome ON jobs(outcome);
CREATE INDEX idx_jobs_created ON jobs(created_at);
CREATE INDEX idx_job_outcomes_job ON job_outcomes(job_id);
CREATE INDEX idx_nonces_attempt ON nonces(attempt_id);
CREATE INDEX idx_steps_job ON job_steps(job_id, attempt_id, seq);
CREATE INDEX idx_broker_calls_job ON broker_calls(job_id, attempt_id, seq);
CREATE INDEX idx_artifacts_job ON artifacts(job_id, attempt_id);
CREATE INDEX idx_link_checks_expiry ON link_checks(expires_at);

INSERT INTO schema_version(version) VALUES (1);
