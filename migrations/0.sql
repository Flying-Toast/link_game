CREATE TABLE user (
	caseid TEXT NOT NULL,
	join_time INTEGER NOT NULL,
	refcode TEXT NOT NULL
);
INSERT INTO user (caseid, join_time, refcode) VALUES ('srs266', 1739061402, '8f7bc7014d00c0d0');

CREATE TABLE session (
	secret INTEGER NOT NULL UNIQUE,
	caseid TEXT NOT NULL UNIQUE
);
