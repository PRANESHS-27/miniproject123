-- VulnWatch PostgreSQL initialization
-- Run as the superuser once, then `app` uses the vulnwatch user.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- The vulnwatch user / database are created by the docker entrypoint;
-- this file only seeds reference data (e.g. severity buckets).

-- Sample reference data — useful for tests
CREATE TABLE IF NOT EXISTS severity_buckets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(16) UNIQUE NOT NULL,
    min_score NUMERIC(3, 1) NOT NULL,
    max_score NUMERIC(3, 1) NOT NULL
);

INSERT INTO severity_buckets (name, min_score, max_score) VALUES
    ('CRITICAL', 9.0, 10.0),
    ('HIGH',     7.0,  8.9),
    ('MEDIUM',   4.0,  6.9),
    ('LOW',      0.1,  3.9),
    ('NONE',     0.0,  0.0)
ON CONFLICT (name) DO NOTHING;
