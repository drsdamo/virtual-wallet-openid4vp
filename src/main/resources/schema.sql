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

-- Credentials reçus d'un émetteur par OpenID4VCI : contrairement aux credentials de test, ils ne peuvent pas être
-- réémis et sont donc conservés tels que reçus, avec la clé du porteur qui leur est liée.
CREATE TABLE IF NOT EXISTS received_credential (
    id                TEXT PRIMARY KEY,
    identity_id       TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
    credential_issuer TEXT NOT NULL,
    configuration_id  TEXT NOT NULL,
    format            TEXT NOT NULL,
    credential        TEXT NOT NULL,      -- SD-JWT compact ou IssuerSigned mdoc en base64url
    holder_key        TEXT NOT NULL,      -- JWK privée EC P-256 (données de test : non chiffrée)
    warnings          TEXT NOT NULL,      -- anomalies relevées à la réception, une par ligne
    received_at       TEXT NOT NULL
);
