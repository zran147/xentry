-- Tell a rebuilt environment apart from a job.
--
-- An environment is the job's own setup sequence stopped after build_poc and
-- left running, so it has no outcome - which is exactly what makes
-- recover_interrupted() destroy it on restart. Without a kind it would also
-- look like an unfinished job: listed on the Jobs page and counted by anything
-- that asks how many jobs are still in flight. ADD COLUMN needs no rebuild and
-- existing rows take the default.

ALTER TABLE jobs ADD COLUMN kind TEXT NOT NULL DEFAULT 'job';

INSERT INTO schema_version(version) VALUES (5);
