PRAGMA foreign_keys=ON;

CREATE TABLE user (
	rowid INTEGER PRIMARY KEY ASC,
	caseid TEXT NOT NULL,
	join_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
	refcode TEXT NOT NULL,
	inviter INTEGER NOT NULL,
	fullname TEXT,

	FOREIGN KEY (inviter) REFERENCES user (rowid)
) STRICT;
INSERT INTO user (caseid, refcode, inviter, fullname) VALUES ('srs266', '8f7bc7014d00c0d0', 1, 'Simon Schwartz');

CREATE TABLE session (
	secret INTEGER NOT NULL UNIQUE,
	caseid TEXT NOT NULL UNIQUE
) STRICT;
