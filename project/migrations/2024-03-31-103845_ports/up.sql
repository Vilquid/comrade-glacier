CREATE TABLE IF NOT EXISTS "ports" (
    "id" BIGSERIAL PRIMARY KEY,
    "ip" INET NOT NULL,
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
