-- Fixed V3__create_clients.sql
-- Create clients table
CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret VARCHAR(200) NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    scopes VARCHAR(200) DEFAULT 'openid,profile,orders.read,api.read',
    grant_types VARCHAR(200) DEFAULT 'authorization_code,refresh_token,client_credentials'
);

-- Clear existing data and insert updated client
DELETE FROM clients WHERE client_id = 'client-app';

INSERT INTO clients (client_id, client_secret, redirect_uri, scopes, grant_types)
VALUES (
    'client-app',
    'client-secret',
    'http://localhost:8091/login/oauth2/code/client-app,http://localhost:3001/login/oauth2/code/client-app',
    'openid,profile,orders.read,api.read',
    'authorization_code,refresh_token,client_credentials'
);

-- Also add a test user if not exists
INSERT INTO users (username, password, enabled) VALUES
('testuser', '{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW', TRUE)
    ON CONFLICT (username) DO NOTHING;

-- Ensure user has proper role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'testuser' AND r.authority = 'ROLE_USER'
ON CONFLICT DO NOTHING;