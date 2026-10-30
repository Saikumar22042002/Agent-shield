-- AgentShield schema v3 (migrations 1-3), extracted from a copy of a real v3 database. Used by test_migrations.py.
PRAGMA foreign_keys=OFF;
CREATE TABLE audit_log (
	id INTEGER NOT NULL, 
	ts DATETIME NOT NULL, 
	actor VARCHAR(200) NOT NULL, 
	action VARCHAR(64) NOT NULL, 
	run_id VARCHAR(32), 
	target_id INTEGER, 
	payload JSON NOT NULL, 
	prev_hash VARCHAR(64) NOT NULL, 
	hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE events (
	id INTEGER NOT NULL, 
	ts DATETIME NOT NULL, 
	type VARCHAR(32) NOT NULL, 
	run_id VARCHAR(32), 
	data JSON NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE findings (
	id INTEGER NOT NULL, 
	run_id VARCHAR(32) NOT NULL, 
	attempt_id INTEGER NOT NULL, 
	category VARCHAR(16) NOT NULL, 
	test_id VARCHAR(300) NOT NULL, 
	severity VARCHAR(8) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	evidence JSON NOT NULL, 
	remediation_key VARCHAR(64) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	closed_by_run_id VARCHAR(32), 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES runs (id), 
	FOREIGN KEY(attempt_id) REFERENCES test_attempts (id)
);
CREATE TABLE graph_edges (
	id INTEGER NOT NULL, 
	run_id VARCHAR(32) NOT NULL, 
	src VARCHAR(300) NOT NULL, 
	dst VARCHAR(300) NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	meta JSON NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (run_id, src, dst, kind)
);
CREATE TABLE graph_nodes (
	id INTEGER NOT NULL, 
	run_id VARCHAR(32) NOT NULL, 
	"key" VARCHAR(300) NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	label VARCHAR(300) NOT NULL, 
	meta JSON NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (run_id, "key")
);
CREATE TABLE imports (
	id INTEGER NOT NULL, 
	run_id VARCHAR(32) NOT NULL, 
	tool VARCHAR(16) NOT NULL, 
	filename VARCHAR(400) NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	tool_version VARCHAR(64) NOT NULL, 
	imported_by VARCHAR(200) NOT NULL, 
	stats JSON NOT NULL, 
	warnings JSON NOT NULL, 
	imported_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES runs (id)
);
CREATE TABLE runs (
	id VARCHAR(32) NOT NULL, 
	target_id INTEGER NOT NULL, 
	label VARCHAR(200) NOT NULL, 
	status VARCHAR(24) NOT NULL, 
	parent_run_id VARCHAR(32), 
	summary JSON, 
	halt_reason TEXT NOT NULL, 
	started_at DATETIME NOT NULL, 
	finished_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(target_id) REFERENCES targets (id)
);
CREATE TABLE schema_version (version INTEGER NOT NULL);
CREATE TABLE targets (
	id INTEGER NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	harness_arn VARCHAR(400) NOT NULL, 
	qualifier VARCHAR(64) NOT NULL, 
	region VARCHAR(32) NOT NULL, 
	environment VARCHAR(32) NOT NULL, 
	aws_profile VARCHAR(128) NOT NULL, 
	aws_role_arn VARCHAR(400) NOT NULL, 
	owner_attestation TEXT NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	last_check_at DATETIME, 
	last_latency_ms FLOAT, 
	last_wall_ms FLOAT, 
	last_usage JSON, 
	last_error TEXT NOT NULL, 
	created_at DATETIME NOT NULL, provider VARCHAR(32) NOT NULL DEFAULT 'aws_agentcore', config JSON NOT NULL DEFAULT '{}', archived BOOLEAN NOT NULL DEFAULT 0, 
	PRIMARY KEY (id)
);
CREATE TABLE test_attempts (
	id INTEGER NOT NULL, 
	run_id VARCHAR(32) NOT NULL, 
	import_id INTEGER NOT NULL, 
	source VARCHAR(16) NOT NULL, 
	external_id VARCHAR(100) NOT NULL, 
	category VARCHAR(16) NOT NULL, 
	test_id VARCHAR(300) NOT NULL, 
	turns JSON NOT NULL, 
	detector VARCHAR(200) NOT NULL, 
	score FLOAT, 
	verdict VARCHAR(16) NOT NULL, 
	rationale TEXT NOT NULL, 
	trap_hit BOOLEAN NOT NULL, 
	severity VARCHAR(8) NOT NULL, 
	recorded_at DATETIME, model_verdict VARCHAR(16), model_rationale TEXT, model_id VARCHAR(200), model_judged_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (run_id, source, external_id), 
	FOREIGN KEY(run_id) REFERENCES runs (id), 
	FOREIGN KEY(import_id) REFERENCES imports (id)
);
CREATE TABLE trap_hits (
	id INTEGER NOT NULL, 
	run_id VARCHAR(32) NOT NULL, 
	import_id INTEGER NOT NULL, 
	token_id VARCHAR(200) NOT NULL, 
	external_id VARCHAR(100) NOT NULL, 
	received_at DATETIME, 
	source VARCHAR(200) NOT NULL, 
	attempt_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES runs (id), 
	FOREIGN KEY(import_id) REFERENCES imports (id), 
	FOREIGN KEY(attempt_id) REFERENCES test_attempts (id)
);
CREATE INDEX ix_audit_log_run_id ON audit_log (run_id);
CREATE INDEX ix_events_run_id ON events (run_id);
CREATE INDEX ix_findings_run_id ON findings (run_id);
CREATE INDEX ix_graph_edges_run_id ON graph_edges (run_id);
CREATE INDEX ix_graph_nodes_run_id ON graph_nodes (run_id);
CREATE INDEX ix_imports_run_id ON imports (run_id);
CREATE INDEX ix_test_attempts_run_id ON test_attempts (run_id);
CREATE INDEX ix_trap_hits_run_id ON trap_hits (run_id);
INSERT INTO schema_version (version) VALUES (1),(2),(3);
