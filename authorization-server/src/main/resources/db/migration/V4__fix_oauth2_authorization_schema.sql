-- Ensure table exists (no-op if already created)
CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id                             varchar(100) PRIMARY KEY,
    registered_client_id           varchar(100) NOT NULL,
    principal_name                 varchar(200) NOT NULL,
    authorization_grant_type       varchar(100) NOT NULL
);

-- Ensure all expected columns exist with correct types
ALTER TABLE oauth2_authorization
    ADD COLUMN IF NOT EXISTS authorized_scopes         varchar(4000),
    ADD COLUMN IF NOT EXISTS attributes                text,
    ADD COLUMN IF NOT EXISTS state                     varchar(500),

    ADD COLUMN IF NOT EXISTS authorization_code_value       bytea,
    ADD COLUMN IF NOT EXISTS authorization_code_issued_at   timestamp with time zone,
    ADD COLUMN IF NOT EXISTS authorization_code_expires_at  timestamp with time zone,
    ADD COLUMN IF NOT EXISTS authorization_code_metadata    text,

    ADD COLUMN IF NOT EXISTS access_token_value        bytea,
    ADD COLUMN IF NOT EXISTS access_token_issued_at    timestamp with time zone,
    ADD COLUMN IF NOT EXISTS access_token_expires_at   timestamp with time zone,
    ADD COLUMN IF NOT EXISTS access_token_metadata     text,
    ADD COLUMN IF NOT EXISTS access_token_type         varchar(100),
    ADD COLUMN IF NOT EXISTS access_token_scopes       varchar(4000),

    ADD COLUMN IF NOT EXISTS oidc_id_token_value       bytea,
    ADD COLUMN IF NOT EXISTS oidc_id_token_issued_at   timestamp with time zone,
    ADD COLUMN IF NOT EXISTS oidc_id_token_expires_at  timestamp with time zone,
    ADD COLUMN IF NOT EXISTS oidc_id_token_metadata    text,

    ADD COLUMN IF NOT EXISTS refresh_token_value       bytea,
    ADD COLUMN IF NOT EXISTS refresh_token_issued_at   timestamp with time zone,
    ADD COLUMN IF NOT EXISTS refresh_token_expires_at  timestamp with time zone,
    ADD COLUMN IF NOT EXISTS refresh_token_metadata    text,

    ADD COLUMN IF NOT EXISTS user_code_value           bytea,
    ADD COLUMN IF NOT EXISTS user_code_issued_at       timestamp with time zone,
    ADD COLUMN IF NOT EXISTS user_code_expires_at      timestamp with time zone,
    ADD COLUMN IF NOT EXISTS user_code_metadata        text,

    ADD COLUMN IF NOT EXISTS device_code_value         bytea,
    ADD COLUMN IF NOT EXISTS device_code_issued_at     timestamp with time zone,
    ADD COLUMN IF NOT EXISTS device_code_expires_at    timestamp with time zone,
    ADD COLUMN IF NOT EXISTS device_code_metadata      text;

-- Helpful indexes (match SAS sample schema)
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_principal
    ON oauth2_authorization (principal_name);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_registered_client
    ON oauth2_authorization (registered_client_id);
