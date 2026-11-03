CREATE TABLE IF NOT EXISTS identity (
    id          TEXT PRIMARY KEY,
    family_name TEXT NOT NULL,
    given_name  TEXT NOT NULL,
    birth_date  TEXT NOT NULL,          -- date ISO-8601
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_claim (
    id          TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,          -- ClaimType
    value       TEXT NOT NULL,
    scope       TEXT NOT NULL,          -- ClaimScope
    UNIQUE (identity_id, name, scope)
);
