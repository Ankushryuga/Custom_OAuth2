# Client Registration Guide — Sentinel OAuth2 / OIDC Server

This document lists **all practical ways** to register OAuth2/OIDC clients for your **Custom Authorization Server** (Spring Authorization Server–based), with copy-pasteable examples.

> Replace host/IPs as needed. Examples assume:
>
> ```
> ISSUER     = http://10.201.240.154:8080
> DISCOVERY  = http://10.201.240.154:8080/.well-known/openid-configuration
> DCR        = http://10.201.240.154:8080/connect/register
> ```
>
> If your server requires a bootstrap token for DCR:
> ```
> export AUTH_DCR_INITIAL_TOKEN='<your-initial-token>'
> ```

---

## Contents

- [Prerequisites](#prerequisites)
- [What to Register (quick reference)](#what-to-register-quick-reference)
- [A) Dynamic Client Registration (DCR)](#a-dynamic-client-registration-dcr)
    - [SPA (Public + PKCE)](#spa-public--pkce)
    - [Backend (Confidential, Client Credentials)](#backend-confidential-client-credentials)
    - [Native App (Loopback)](#native-app-loopback)
    - [Multiple Redirect URIs](#multiple-redirect-uris)
    - [Update / Delete (if implemented)](#update--delete-if-implemented)
- [B) Custom Admin API (`/admin/clients`)](#b-custom-admin-api-adminclients)
- [C) Programmatic Seeding (Java @Startup)](#c-programmatic-seeding-java-startup)
- [D) SQL Seeding (Flyway/Liquibase)](#d-sql-seeding-flywayliquibase)
- [E) Postman / GUI](#e-postman--gui)
- [F) Shell Script / Makefile](#f-shell-script--makefile)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Client Metadata Field Reference](#client-metadata-field-reference)

---

## Prerequisites

- Auth server is running and reachable at `$ISSUER`.
- Verify discovery:
  ```bash
  curl -s $ISSUER/.well-known/openid-configuration | jq .
  ```
- If required by your server, obtain a **bootstrap/initial** token and export it:
  ```bash
  export AUTH_DCR_INITIAL_TOKEN='<your-initial-token>'
  ```

---

## What to Register (quick reference)

Pick a client type and grants to match your app:

| App kind         | client_type     | Grants                                 | Token auth method                 | Redirect URIs                                |
|------------------|------------------|----------------------------------------|-----------------------------------|----------------------------------------------|
| SPA (browser)    | `public`         | `authorization_code`, `refresh_token`  | `none` (PKCE)                     | `http://localhost:5174/oidc/callback`        |
| Backend service  | `confidential`   | `client_credentials`                   | `client_secret_basic` or `post`   | *(none)*                                     |
| Native app       | `public`         | `authorization_code`, `refresh_token`  | `none` (PKCE)                     | `http://127.0.0.1:3000/callback`, etc.       |

Scopes: `openid profile email` (+ your APIs, e.g., `api.read`, `api.write`).

---

## A) Dynamic Client Registration (DCR)

**Endpoint**  
`POST $ISSUER/connect/register`

**Headers**
- `Content-Type: application/json`
- If required: `Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN`

### SPA (Public + PKCE)

```bash
curl -sS -i \
  -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN" \
  -H "Content-Type: application/json" \
  --data @- $ISSUER/connect/register <<'JSON'
{
  "client_name": "SPA PKCE (localhost)",
  "client_type": "public",
  "redirect_uris": [
    "http://localhost:5174/oidc/callback"
  ],
  "post_logout_redirect_uris": [
    "http://localhost:5174/"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "none"
}
JSON
```

**Response** (example)
```json
{
  "client_id": "43096f15-bbbc-446d-a51e-81be707f0f31",
  "client_name": "SPA PKCE (localhost)",
  "token_endpoint_auth_method": "none",
  "redirect_uris": ["http://localhost:5174/oidc/callback"],
  "post_logout_redirect_uris": ["http://localhost:5174/"],
  "grant_types": ["authorization_code","refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email"
}
```

> Copy `client_id` for your SPA config.

### Backend (Confidential, Client Credentials)

```bash
curl -sS -i \
  -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN" \
  -H "Content-Type: application/json" \
  --data @- $ISSUER/connect/register <<'JSON'
{
  "client_name": "Go Backend",
  "client_type": "confidential",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "api.read"
}
JSON
```

**Response** includes `client_secret` (store securely).

### Native App (Loopback)

```bash
curl -sS -i \
  -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN" \
  -H "Content-Type: application/json" \
  --data @- $ISSUER/connect/register <<'JSON'
{
  "client_name": "Native App",
  "client_type": "public",
  "redirect_uris": [
    "http://127.0.0.1:3000/callback",
    "http://localhost:3000/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "none"
}
JSON
```

### Multiple Redirect URIs

```json
"redirect_uris": [
  "http://localhost:5174/oidc/callback",
  "http://10.201.240.239:5174/oidc/callback"
],
"post_logout_redirect_uris": [
  "http://localhost:5174/",
  "http://10.201.240.239:5174/"
]
```

### Update / Delete (if implemented)

If your server supports RFC 7592:

- **Read**
  ```
  GET $ISSUER/connect/register/{client_id}
  ```
- **Update**
  ```
  PUT $ISSUER/connect/register/{client_id}
  Content-Type: application/json
  Authorization: Bearer <management token>
  ```
- **Delete**
  ```
  DELETE $ISSUER/connect/register/{client_id}
  ```

---

## B) Custom Admin API (`/admin/clients`)

If your deployment exposes a simpler admin API guarded by a fixed token:

```bash
curl -sS -i -X POST $ISSUER/admin/clients \
  -H "Authorization: Bearer dev-bootstrap-token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "SPA PKCE",
    "client_type": "public",
    "redirect_uris": ["http://localhost:5174/oidc/callback"],
    "post_logout_redirect_uris": ["http://localhost:5174/"],
    "scope": "openid profile email"
  }'
```

Typical verbs (if implemented):
```
GET    /admin/clients
GET    /admin/clients/{client_id}
PUT    /admin/clients/{client_id}
DELETE /admin/clients/{client_id}
```

---

## C) Programmatic Seeding (Java @Startup)

Register clients on app startup (great for dev/test fixtures).

```java
@Bean
CommandLineRunner seedClients(RegisteredClientRepository repo) {
  return args -> {
    // SPA (public + PKCE)
    var spa = RegisteredClient.withId(java.util.UUID.randomUUID().toString())
      .clientId("spa-localhost")
      .clientName("SPA PKCE (seed)")
      .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .redirectUri("http://localhost:5174/oidc/callback")
      .postLogoutRedirectUri("http://localhost:5174/")
      .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE).scope("email")
      .clientSettings(ClientSettings.builder().requireProofKey(true).build())
      .tokenSettings(TokenSettings.builder().build())
      .build();

    // Backend (confidential)
    var backend = RegisteredClient.withId(java.util.UUID.randomUUID().toString())
      .clientId("go-backend")
      .clientSecret("{noop}super-secret") // use a real encoder in prod
      .clientName("Go Backend")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .scope("api.read")
      .tokenSettings(TokenSettings.builder().build())
      .build();

    if (((JdbcRegisteredClientRepository) repo).findByClientId("spa-localhost") == null) repo.save(spa);
    if (((JdbcRegisteredClientRepository) repo).findByClientId("go-backend") == null) repo.save(backend);
  };
}
```

---

## D) SQL Seeding (Flyway/Liquibase)

Insert directly into `oauth2_registered_client`. **Match your SAS version’s schema** (inspect one row created by code to copy the exact formats).

**SPA (public)**
```sql
INSERT INTO oauth2_registered_client (
  id, client_id, client_id_issued_at, client_secret, client_secret_expires_at,
  client_name, client_authentication_methods, authorization_grant_types,
  redirect_uris, post_logout_redirect_uris, scopes, client_settings, token_settings
) VALUES (
  gen_random_uuid(),
  'spa-localhost',
  now(),
  NULL, NULL,
  'SPA PKCE (SQL)',
  'none',
  'authorization_code,refresh_token',
  'http://localhost:5174/oidc/callback',
  'http://localhost:5174/',
  'openid,profile,email',
  '{"requireProofKey":true}',
  '{}'
);
```

**Backend (confidential)**
```sql
INSERT INTO oauth2_registered_client (
  id, client_id, client_id_issued_at, client_secret, client_name,
  client_authentication_methods, authorization_grant_types, scopes, client_settings, token_settings
) VALUES (
  gen_random_uuid(),
  'go-backend',
  now(),
  '{noop}super-secret',
  'Go Backend (SQL)',
  'client_secret_basic',
  'client_credentials',
  'api.read',
  '{}',
  '{}'
);
```

> Column types differ slightly by SAS version (JSON vs delimited text). Use your schema as the source of truth.

---

## E) Postman / GUI

- Request: `POST $ISSUER/connect/register`
- Headers:
    - `Content-Type: application/json`
    - `Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN` (if required)
- Body: JSON from the curl examples above.
- Save the response (`client_id`, and `client_secret` if confidential).

---

## F) Shell Script / Makefile

Keep a repeatable script for teammates/CI:

```bash
#!/usr/bin/env bash
set -euo pipefail

AUTH=${AUTH:-http://10.201.240.154:8080}
TOKEN=${AUTH_DCR_INITIAL_TOKEN:?Set AUTH_DCR_INITIAL_TOKEN}

curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @- "$AUTH/connect/register" <<'JSON' | jq .
{
  "client_name": "SPA PKCE (dev)",
  "client_type": "public",
  "redirect_uris": ["http://localhost:5174/oidc/callback"],
  "post_logout_redirect_uris": ["http://localhost:5174/"],
  "grant_types": ["authorization_code","refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "none"
}
JSON
```

---

## Troubleshooting

- **401 `{"error":"missing bearer"}`**  
  DCR requires the bootstrap token. Add `Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN`, or disable the requirement in dev.

- **400 `invalid_redirect_uri`**  
  Redirect must match exactly (scheme, host, port, path). Register all you actually use.

- **Issuer mismatch at runtime**  
  Your SPA/API must use the exact `issuer` string shown in discovery.

- **CORS during registration (from browser)**  
  Prefer cURL/Postman for DCR. If calling from a browser, ensure `Access-Control-Allow-Origin` includes your origin.

- **Secret handling**  
  For confidential clients, store secrets securely (env/secret manager). Don’t commit them.

---

## Security Notes

- Use **PKCE** for public clients (SPAs, native apps).
- Use **client secrets** only for confidential backends you control.
- Limit scopes to what the app needs.
- Rotate secrets periodically; remove unused clients.
- Prefer **HTTPS** and stable hostnames in non-dev environments.

---

## Client Metadata Field Reference

| Field                          | Type/Example                               | Notes                                  |
|--------------------------------|--------------------------------------------|----------------------------------------|
| `client_name`                  | `"My SPA"`                                 | Display name                            |
| `client_type`                  | `"public"` \\| `"confidential"`             | Present in custom/admin APIs            |
| `redirect_uris`                | `["http://localhost:5174/oidc/callback"]`  | Required for code flow                  |
| `post_logout_redirect_uris`    | `["http://localhost:5174/"]`               | For RP-initiated logout (if supported)  |
| `grant_types`                  | `["authorization_code","refresh_token"]`   | SPA; or `["client_credentials"]` backend|
| `response_types`               | `["code"]`                                 | Code flow                               |
| `scope`                        | `"openid profile email api.read"`          | Space-delimited                         |
| `token_endpoint_auth_method`   | `"none"` \\| `"client_secret_basic"`        | SPA uses `none`; backend uses secret    |
| `client_uri`, `logo_uri`       | URLs                                       | Optional metadata                       |
| `contacts`                     | `["dev@team.test"]`                        | Optional metadata                       |

---

**End of file.**
