-- CertLedger database bootstrap
-- Runs automatically on first container start via /docker-entrypoint-initdb.d/

-- Enforce UTC for all sessions
SET timezone = 'UTC';

-- Extensions used by the application
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
