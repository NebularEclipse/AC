DROP TABLE IF EXISTS version;

CREATE TABLE version (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL
);

INSERT INTO version (id, version) VALUES (1, "1.0.0");