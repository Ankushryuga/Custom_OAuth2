-- V3__create_clients.sql

-- Create clients table
CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret VARCHAR(200) NOT NULL,
    redirect_uri VARCHAR(200) NOT NULL,
    scopes VARCHAR(200) NOT NULL,
    grant_types VARCHAR(200) NOT NULL
);

-- Insert default client for frontend app (running on port 8081)
INSERT INTO clients (client_id, client_secret, redirect_uri, scopes, grant_types)
VALUES (
    'client-app',
    '{noop}client-secret',
    'http://localhost:8081/login/oauth2/code/client-app',
    'openid,profile,api.read',
    'authorization_code,refresh_token'
)
ON CONFLICT (client_id) DO NOTHING;
