-- This file was automatically created by Diesel to setup helper functions
-- and other internal bookkeeping. This file is safe to edit, any future
-- changes will be added to existing projects as new migrations.




-- Sets up a trigger for the given table to automatically set a column called
-- `updated_at` whenever the row is modified (unless `updated_at` was included
-- in the modified columns)
--
-- # Example
--
-- ```sql
-- CREATE TABLE users (id SERIAL PRIMARY KEY, updated_at TIMESTAMP NOT NULL DEFAULT NOW());
--
-- SELECT diesel_manage_updated_at('users');
-- ```
CREATE OR REPLACE FUNCTION diesel_manage_updated_at(_tbl regclass) RETURNS VOID AS $$
BEGIN
    EXECUTE format('CREATE TRIGGER set_updated_at BEFORE UPDATE ON %s
                    FOR EACH ROW EXECUTE PROCEDURE diesel_set_updated_at()', _tbl);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION diesel_set_updated_at() RETURNS trigger AS $$
BEGIN
    IF (
        NEW IS DISTINCT FROM OLD AND
        NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at
    ) THEN
        NEW.updated_at := current_timestamp;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS "ports" (
    "id" BIGSERIAL PRIMARY KEY,
    "ip" TEXT NOT NULL,
    "port_25_open" BOOLEAN NOT NULL,
    "domain" TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "domains" (
    "id" BIGSERIAL PRIMARY KEY,
    "domain" TEXT NOT NULL,
    "bimi" JSONB NOT NULL,
    "certificate" JSONB NOT NULL,
    "dane" JSONB NOT NULL,
    "dmarc" JSONB NOT NULL,
    "mta" JSONB NOT NULL,
    "tls_rpt" JSONB NOT NULL,
    "spf" JSONB NOT NULL
);
