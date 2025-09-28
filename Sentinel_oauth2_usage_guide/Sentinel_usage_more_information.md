# Client Registration & Usage Guide — Sentinel OAuth2 / OIDC Server

A practical, copy‑paste friendly guide for registering **and using** clients with your **Sentinel OAuth2 / OIDC Authorization Server** (Spring Authorization Server). It explains:
- How to register clients (SPA, backend, native) in multiple ways.
- **How to use `client_id` and `client_secret`** in your apps.
- How a React SPA obtains tokens and calls your APIs.
- How a Go API validates tokens (issuer, JWKS, scopes).
- Common pitfalls and fixes with clear checklists.

> Replace host/IPs as needed. Examples assume:
>
> ```text
> ISSUER     = http://10.201.240.154:8080
> DISCOVERY  = http://10.201.240.154:8080/.well-known/openid-configuration
> DCR        = http://10.201.240.154:8080/connect/register
> JWKS       = http://10.201.240.154:8080/oauth2/jwks
> ```
>
> If your server requires a DCR bootstrap token:
> ```bash
> export AUTH_DCR_INITIAL_TOKEN='<your-initial-token>'
> ```

---

## Contents

- [Prerequisites](#prerequisites)
- [Core Endpoints & Terms](#core-endpoints--terms)
- [What to Register (Quick Reference)](#what-to-register-quick-reference)
- [Registering Clients](#registering-clients)
    - [A) Dynamic Client Registration (DCR)](#a-dynamic-client-registration-dcr)
    - [B) Custom Admin API](#b-custom-admin-api)
    - [C) Programmatic Seeding (Java @Startup)](#c-programmatic-seeding-java-startup)
    - [D) SQL Seeding (Flyway/Liquibase)](#d-sql-seeding-flywayliquibase)
    - [E) Postman / GUI](#e-postman--gui)
    - [F) Shell Script / Makefile](#f-shell-script--makefile)
- [Using `client_id` / `client_secret` in Your Apps](#using-client_id--client_secret-in-your-apps)
    - [SPA (Browser) — Public Client (PKCE, no secret)](#spa-browser--public-client-pkce-no-secret)
    - [Backend / Server‑to‑Server — Confidential Client (with secret)](#backend--serverto-server--confidential-client-with-secret)
    - [Native App — Public Client (PKCE)](#native-app--public-client-pkce)
- [React SPA — End‑to‑End Flow](#react-spa--endtoend-flow)
- [Go API (Resource Server) — Validation & CORS](#go-api-resource-server--validation--cors)
- [Advanced Topics](#advanced-topics)
    - [Multiple Environments (dev/stage/prod)](#multiple-environments-devstageprod)
    - [Refresh Tokens & Silent Renewal](#refresh-tokens--silent-renewal)
    - [Logout (RP‑initiated)](#logout-rpinitiated)
    - [CORS, Cookies, and SameSite](#cors-cookies-and-samesite)
    - [Scopes & Audience](#scopes--audience)
- [Verify with `curl`](#verify-with-curl)
- [Troubleshooting (Checklist)](#troubleshooting-checklist)
- [Security Notes](#security-notes)
- [Client Metadata Field Reference](#client-metadata-field-reference)

---

## Prerequisites

- Authorization Server is running at `$ISSUER` and advertises the same issuer you will configure in apps:
  ```bash
  curl -s $ISSUER/.well-known/openid-configuration | jq .issuer
  # "http://10.201.240.154:8080"
  ```
- (Optional) DCR bootstrap token exported if required:
  ```bash
  export AUTH_DCR_INITIAL_TOKEN='<your-initial-token>'
  ```

---

## Core Endpoints & Terms

- **Discovery**: `/.well-known/openid-configuration` → where your app learns endpoints.
- **Authorize**: `/oauth2/authorize` → browser redirect to start login.
- **Token**: `/oauth2/token` → exchange code for tokens (and refresh).
- **JWKS**: `/oauth2/jwks` → public keys to validate JWT signatures.
- **UserInfo**: `/userinfo` → OIDC claims for user tokens.
- **Logout**: `/connect/logout` → optional, for RP-initiated logout.

**Public client**: no secret (SPAs, native apps) → **must use PKCE**.  
**Confidential client**: has a secret (backends, CLIs you fully control).

---

## What to Register (Quick Reference)

| App kind         | client_type   | Grants                                 | Token auth at `/token`      | Redirect URIs                                  |
|------------------|---------------|----------------------------------------|-----------------------------|-----------------------------------------------|
| SPA (browser)    | `public`      | `authorization_code`, `refresh_token`  | `none` (PKCE)               | `http://localhost:5174/oidc/callback`         |
| Backend service  | `confidential`| `client_credentials`                   | `client_secret_basic`/post  | *(none)*                                      |
| Native app       | `public`      | `authorization_code`, `refresh_token`  | `none` (PKCE)               | `http://127.0.0.1:3000/callback` (loopback)   |

Scopes: `openid profile email` (+ `api.read`, `api.write`, etc.).

---

## Registering Clients

### A) Dynamic Client Registration (DCR)

**Endpoint**: `POST $ISSUER/connect/register`  
**Headers**: `Content-Type: application/json` (+ `Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN` if required)

**SPA (Public + PKCE)**
```bash
curl -sS -i \
  -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN" \
  -H "Content-Type: application/json" \
  --data @- $ISSUER/connect/register <<'JSON'
{
  "client_name": "SPA PKCE (localhost)",
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
> Copy the **`client_id`** from the response.

**Backend (Confidential)**
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
> Copy both **`client_id`** and **`client_secret`** and store securely.

**Native (Public, PKCE)**
```bash
curl -sS -i \
  -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN" \
  -H "Content-Type: application/json" \
  --data @- $ISSUER/connect/register <<'JSON'
{
  "client_name": "Native App",
  "client_type": "public",
  "redirect_uris": ["http://127.0.0.1:3000/callback","http://localhost:3000/callback"],
  "grant_types": ["authorization_code","refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "none"
}
JSON
```

*Multiple Redirects* — include all you actually use (localhost & IP).  
*Update/Delete* — if you implemented RFC 7592, use `GET/PUT/DELETE $ISSUER/connect/register/{client_id}`.

### B) Custom Admin API

Some deployments expose an admin API (e.g., guarded by `dev-bootstrap-token`):

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
Check if `GET/PUT/DELETE /admin/clients/{client_id}` are available in your build.

### C) Programmatic Seeding (Java @Startup)

```java
@Bean
CommandLineRunner seedClients(RegisteredClientRepository repo) {
  return args -> {
    // SPA
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

    // Backend
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

### D) SQL Seeding (Flyway/Liquibase)

Match your schema/version exactly (inspect an existing row).

```sql
-- SPA (public)
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

-- Backend (confidential)
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

### E) Postman / GUI

- POST `$ISSUER/connect/register`
- Headers: `Content-Type: application/json` (+ `Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN` if required)
- Body: JSON from examples
- Save `client_id` (+ `client_secret` if confidential).

### F) Shell Script / Makefile

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

## Using `client_id` / `client_secret` in Your Apps

### SPA (Browser) — Public Client (PKCE, no secret)

**Never put `client_secret` in a SPA**. Use only `client_id` with **PKCE**.

**SPA `.env`**
```env
VITE_OIDC_ISSUER=http://10.201.240.154:8080
VITE_OIDC_CLIENT_ID=<client_id_from_registration>
VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
VITE_API_BASE=http://localhost:8082/api
```

**How `client_id` is used**
- The SPA calls discovery, builds an `/oauth2/authorize` URL that includes:
    - `client_id`, `redirect_uri`, `scope`, `response_type=code`, `state`
    - PKCE params: `code_challenge` + `code_challenge_method=S256`
- On callback, the SPA posts to `/oauth2/token`:
    - `grant_type=authorization_code`
    - `client_id`, `redirect_uri`, `code`, and **`code_verifier`** (PKCE)
- The Token endpoint returns `access_token` (+ `id_token`, `refresh_token` if enabled).

**Call your API with the access token**
```ts
export async function apiFetch(path: string, init: RequestInit = {}) {
  const tokens = JSON.parse(sessionStorage.getItem("mini_oidc:tokens") || "{}");
  const headers = new Headers(init.headers || {});
  if (tokens?.access_token) headers.set("Authorization", `Bearer ${tokens.access_token}`);
  if (!headers.has("Content-Type") && init.body) headers.set("Content-Type", "application/json");
  return fetch(`${import.meta.env.VITE_API_BASE}${path}`, { ...init, headers });
}
```

### Backend / Server‑to‑Server — Confidential Client (with secret)

**Never expose the secret to browsers.** Keep the **`client_secret`** server‑side (env or secret manager).

**Backend env**
```env
OAUTH_ISSUER=http://10.201.240.154:8080
OAUTH_CLIENT_ID=go-backend
OAUTH_CLIENT_SECRET=super-secret
OAUTH_SCOPES=api.read
```

**Obtain an access token (client credentials)**
```bash
curl -s -X POST "$ISSUER/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u "$OAUTH_CLIENT_ID:$OAUTH_CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=$OAUTH_SCOPES" | jq .
```

Your backend then uses `Authorization: Bearer <access_token>` to call protected APIs.  
If your backend is the API, it validates incoming tokens (see next section).

### Native App — Public Client (PKCE)

Use the registered `client_id` and **PKCE**, with loopback redirect URIs (e.g., `http://127.0.0.1:port/callback`). The flow mirrors the SPA: `authorize` → callback with `code` → `token` with `code_verifier` (no secret).

---

## React SPA — End‑to‑End Flow

1. **Config**: set `VITE_OIDC_ISSUER`, `VITE_OIDC_CLIENT_ID`, `VITE_REDIRECT_URI` in `.env`.
2. **Login button**: generates `state`, `code_verifier`, `code_challenge`, redirects to `authorize`.
3. **Callback route**: reads `code` + `state`, verifies state, POSTs to `token` with `code_verifier`.
4. **Store tokens**: save `access_token` (and `id_token`/`refresh_token` if present).
5. **Call API**: send `Authorization: Bearer <access_token>`.
6. **Logout**: clear tokens locally; optionally hit `end_session_endpoint` with `id_token_hint`.

> HTTP‑only dev: run SPA at `http://localhost` to avoid WebCrypto HTTPS restrictions **or** use a JS SHA‑256 fallback for PKCE (already wired in the sample).

---

## Go API (Resource Server) — Validation & CORS

**Env**
```env
API_PORT=8082
FRONTEND_ORIGIN=http://localhost:5174
OAUTH_ISSUER=http://10.201.240.154:8080
```

**Checklist**
- **CORS**: allow `FRONTEND_ORIGIN` (methods: GET/POST/PATCH/DELETE, headers incl. `Authorization`).
- **JWT validation**:
    - Verify `iss` equals `OAUTH_ISSUER`.
    - Retrieve and cache JWKS from `$OAUTH_ISSUER/oauth2/jwks`.
    - Validate `exp`, `nbf`, `aud` (if used), and required scopes/claims.
- **Scope enforcement**: check `scope` contains `api.read`/`api.write` as required.
- **Clock skew**: allow a small skew (e.g., 60s).

---

## Advanced Topics

### Multiple Environments (dev/stage/prod)

- Create a **separate client** per environment (e.g., `spa-dev`, `spa-stage`, `spa-prod`) with different redirect URIs.
- Parameterize via env vars; never hardcode secrets.
- Distinct issuers (e.g., `https://auth.dev.example.com`, `https://auth.example.com`) are recommended.

### Refresh Tokens & Silent Renewal

- Enable `refresh_token` for SPAs **only** if you accept the trade‑offs. Consider short‑lived access tokens and rotate refresh tokens.
- For silent renewal in SPAs: use hidden iframes + prompt=none (if supported) or background refresh with refresh token; handle failures gracefully.

### Logout (RP‑initiated)

If `end_session_endpoint` is available:
```
GET $ISSUER/connect/logout?id_token_hint=<id_token>&post_logout_redirect_uri=<url>
```
Clear local tokens first to avoid UI confusion.

### CORS, Cookies, and SameSite

- For pure token auth, you usually don’t need cookies between SPA and API.
- If you use cookies, adjust `SameSite` and `Secure` correctly (cross‑site flows need `SameSite=None; Secure`).

### Scopes & Audience

- Use **scopes** to gate capabilities: `api.read`, `api.write`.
- Optionally configure **audience** so APIs verify the token was meant for them (`aud` claim).

---

## Verify with `curl`

**Discovery**
```bash
curl -s $DISCOVERY | jq .
```

**Token (client credentials)**
```bash
curl -s -X POST "$ISSUER/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'go-backend:super-secret' \
  -d 'grant_type=client_credentials&scope=api.read' | jq .
```

**Token (authorization code + PKCE)** — after you have a `code` from the browser redirect:
```bash
curl -s -X POST "$ISSUER/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=<spa-client-id>' \
  -d 'redirect_uri=http://localhost:5174/oidc/callback' \
  -d 'code=<code_from_redirect>' \
  -d 'code_verifier=<the_original_verifier>' | jq .
```

**UserInfo**
```bash
curl -s "$ISSUER/userinfo" -H "Authorization: Bearer <access_token>" | jq .
```

**Introspection / Revocation** (confidential clients)
```bash
curl -s -u 'go-backend:super-secret' -d "token=<access_token>" "$ISSUER/oauth2/introspect" | jq .
curl -s -u 'go-backend:super-secret' -d "token=<access_or_refresh_token>" "$ISSUER/oauth2/revoke"
```

---

## Troubleshooting (Checklist)

- **401 `{"error":"missing bearer"}` on `/connect/register`** → Include `Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN` or disable the requirement in dev.
- **`invalid_redirect_uri`** → Register the exact scheme/host/port/path you actually use.
- **SPA `Crypto.subtle is available only in secure contexts`** → Use `http://localhost` for HTTP, or switch to HTTPS, or use JS SHA‑256 fallback.
- **SPA `No matching state found in storage`** → Start login from SPA (not IdP directly), ensure same origin handled the start & finish; don’t clear storage in between.
- **Issuer mismatch / JWKS errors** → Make app issuer equal discovery `issuer`; fetch JWKS from `$ISSUER/oauth2/jwks`.
- **API 401** → Ensure SPA sends `Authorization: Bearer <token>`; handle expiry/refresh.
- **CORS blocked** → Add SPA origin to API CORS; allow `Authorization` header and required methods.

---

## Security Notes

- Public clients must use **PKCE**; never embed secrets in SPAs/native apps.
- Confidential client **secrets must remain server‑side**; rotate periodically.
- Keep scopes minimal; prefer short‑lived access tokens.
- Always use **HTTPS** outside of local development.

---

## Client Metadata Field Reference

| Field                          | Type/Example                                 | Notes |
|--------------------------------|----------------------------------------------|-------|
| `client_name`                  | `"My SPA"`                                   | Display name |
| `client_type`                  | `"public"` or `"confidential"`               | DCR/custom admin APIs |
| `redirect_uris`                | `["http://localhost:5174/oidc/callback"]`    | Required for code flow |
| `post_logout_redirect_uris`    | `["http://localhost:5174/"]`                 | For RP‑initiated logout |
| `grant_types`                  | `["authorization_code","refresh_token"]`     | SPA; or `["client_credentials"]` backend |
| `response_types`               | `["code"]`                                   | Code flow |
| `scope`                        | `"openid profile email api.read"`            | Space‑delimited |
| `token_endpoint_auth_method`   | `"none"` or `"client_secret_basic"`          | SPA uses none; backend uses secret |
| `client_uri`, `logo_uri`       | URLs                                         | Optional |
| `contacts`                     | `["dev@team.test"]`                          | Optional |

---

**End of file.**


---

## Using `client_id` / `client_secret` with **docker-compose.yml**

This section shows **exact, copy‑pasteable `docker-compose.yml` patterns** for wiring your OAuth2 variables (issuer, `client_id`, `client_secret`) into the **Auth Server**, **React SPA**, and **Go API**.

> You can use **plain environment variables**, an **`.env` file**, or **Docker secrets** (recommended for real secrets). All three patterns are shown below.

### 1) Minimal Compose (dev, HTTP-only)

```yaml
version: "3.9"

services:
  auth-server:
    image: your-org/custom-auth-server:latest
    container_name: auth-server
    ports: ["8080:8080"]
    environment:
      # Make sure the issuer your server advertises matches what clients use
      - SPRING_PROFILES_ACTIVE=dev
      - SERVER_PORT=8080
      - SPRING_SECURITY_OAUTH2_AUTHORIZATIONERVER_ISSUER=http://auth-server:8080
      # Optional: DCR bootstrap (dev only; remove in prod)
      - AUTH_DCR_REQUIRE_INITIAL_TOKEN=false
      - AUTH_DCR_INITIAL_TOKEN=dev-bootstrap-token
    networks: [appnet]

  api:
    image: your-org/go-api:latest
    container_name: go-api
    ports: ["8082:8082"]
    environment:
      - API_PORT=8082
      - FRONTEND_ORIGIN=http://localhost:5174
      - OAUTH_ISSUER=http://auth-server:8080
      # If your API needs to call another API using client_credentials, set these:
      - OAUTH_CLIENT_ID=go-backend
      - OAUTH_CLIENT_SECRET=super-secret    # dev only — use secrets in prod
      - OAUTH_SCOPES=api.read
    depends_on: [auth-server]
    networks: [appnet]

  web:
    image: node:20-alpine
    container_name: web
    working_dir: /app
    command: sh -c "npm ci && npm run dev -- --host"
    volumes:
      - ./web:/app
    environment:
      - VITE_OIDC_ISSUER=http://localhost:8080
      - VITE_OIDC_CLIENT_ID=<spa_client_id_here>
      - VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
      - VITE_API_BASE=http://localhost:8082/api
    ports: ["5174:5174"]
    depends_on: [api, auth-server]
    networks: [appnet]

networks:
  appnet:
    driver: bridge
```

**Notes**
- Inside the Docker network, the Auth Server is reachable as `http://auth-server:8080`. From the **host browser**, it’s `http://localhost:8080`. That’s why the SPA uses `VITE_OIDC_ISSUER=http://localhost:8080` while the API uses `OAUTH_ISSUER=http://auth-server:8080`.
- For local HTTP-only development, run the SPA on **localhost** to avoid WebCrypto HTTPS restrictions for PKCE.
- Replace `<spa_client_id_here>` with the ID returned by your registration.

### 2) Compose with `.env` file

Create a file named **`.env`** next to your `docker-compose.yml`:

```env
# .env
ISSUER_HOST=http://localhost:8080
SPA_ORIGIN=http://localhost:5174
API_ORIGIN=http://localhost:8082

# SPA
VITE_OIDC_CLIENT_ID=43096f15-bbbc-446d-a51e-81be707f0f31
VITE_REDIRECT_URI=http://localhost:5174/oidc/callback

# API (resource server)
OAUTH_ISSUER_INNER=http://auth-server:8080
FRONTEND_ORIGIN=${SPA_ORIGIN}

# Optional: backend confidential client (to call other APIs)
OAUTH_CLIENT_ID=go-backend
OAUTH_CLIENT_SECRET=super-secret
OAUTH_SCOPES=api.read

# Auth-server (dev DCR controls)
AUTH_DCR_REQUIRE_INITIAL_TOKEN=false
AUTH_DCR_INITIAL_TOKEN=dev-bootstrap-token
```

Now reference them in compose:

```yaml
version: "3.9"

services:
  auth-server:
    image: your-org/custom-auth-server:latest
    ports: ["8080:8080"]
    environment:
      - SPRING_SECURITY_OAUTH2_AUTHORIZATIONERVER_ISSUER=${ISSUER_HOST}
      - AUTH_DCR_REQUIRE_INITIAL_TOKEN=${AUTH_DCR_REQUIRE_INITIAL_TOKEN}
      - AUTH_DCR_INITIAL_TOKEN=${AUTH_DCR_INITIAL_TOKEN}
    networks: [appnet]

  api:
    image: your-org/go-api:latest
    ports: ["8082:8082"]
    environment:
      - API_PORT=8082
      - OAUTH_ISSUER=${OAUTH_ISSUER_INNER}
      - FRONTEND_ORIGIN=${FRONTEND_ORIGIN}
      - OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID}
      - OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
      - OAUTH_SCOPES=${OAUTH_SCOPES}
    depends_on: [auth-server]
    networks: [appnet]

  web:
    image: node:20-alpine
    working_dir: /app
    command: sh -c "npm ci && npm run dev -- --host"
    volumes: ["./web:/app"]
    ports: ["5174:5174"]
    environment:
      - VITE_OIDC_ISSUER=${ISSUER_HOST}
      - VITE_OIDC_CLIENT_ID=${VITE_OIDC_CLIENT_ID}
      - VITE_REDIRECT_URI=${VITE_REDIRECT_URI}
      - VITE_API_BASE=${API_ORIGIN}/api
    depends_on: [api, auth-server]
    networks: [appnet]

networks:
  appnet:
    driver: bridge
```

### 3) Compose with **Docker secrets** (recommended for `client_secret`)

1) Create the secret files (not committed to VCS):
```
secrets/
  oauth_client_secret.txt        # contains only the secret string
```

2) Reference them in `docker-compose.yml`:

```yaml
version: "3.9"

secrets:
  oauth_client_secret:
    file: ./secrets/oauth_client_secret.txt

services:
  auth-server:
    image: your-org/custom-auth-server:latest
    ports: ["8080:8080"]
    environment:
      - SPRING_SECURITY_OAUTH2_AUTHORIZATIONERVER_ISSUER=http://auth-server:8080
      - AUTH_DCR_REQUIRE_INITIAL_TOKEN=false
      - AUTH_DCR_INITIAL_TOKEN=dev-bootstrap-token
    networks: [appnet]

  api:
    image: your-org/go-api:latest
    ports: ["8082:8082"]
    environment:
      - API_PORT=8082
      - FRONTEND_ORIGIN=http://localhost:5174
      - OAUTH_ISSUER=http://auth-server:8080
      - OAUTH_CLIENT_ID=go-backend
      # Docker exposes secret at /run/secrets/<name>; read it in your app
      - OAUTH_CLIENT_SECRET_FILE=/run/secrets/oauth_client_secret
      - OAUTH_SCOPES=api.read
    secrets:
      - oauth_client_secret
    depends_on: [auth-server]
    networks: [appnet]

  web:
    image: node:20-alpine
    working_dir: /app
    command: sh -c "npm ci && npm run dev -- --host"
    volumes: ["./web:/app"]
    ports: ["5174:5174"]
    environment:
      - VITE_OIDC_ISSUER=http://localhost:8080
      - VITE_OIDC_CLIENT_ID=<spa_client_id_here>
      - VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
      - VITE_API_BASE=http://localhost:8082/api
    depends_on: [api, auth-server]
    networks: [appnet]

networks:
  appnet:
    driver: bridge
```

3) In your **Go API**, read the secret via `OAUTH_CLIENT_SECRET_FILE`:
```go
func readSecret(path string) (string, error) {
    b, err := os.ReadFile(path)
    if err != nil { return "", err }
    return strings.TrimSpace(string(b)), nil
}

func loadConfig() Config {
    secret := os.Getenv("OAUTH_CLIENT_SECRET")
    if file := os.Getenv("OAUTH_CLIENT_SECRET_FILE"); secret == "" && file != "" {
        if s, err := readSecret(file); err == nil { secret = s }
    }
    // ...build Config{ClientSecret: secret, ...}
}
```

**Why this matters**
- `client_id` is not a secret (safe in env), but **`client_secret` must not be committed** or baked into images.
- Docker secrets mount the secret at runtime (`/run/secrets/...`), avoiding leaks in image layers and `docker inspect`.

### 4) Profiles / Overrides (dev vs prod)

Use `docker-compose.override.yml` for dev tweaks (hot reload, dev tokens), and **don’t** include secrets in the default compose. Example:

```yaml
# docker-compose.override.yml (dev only)
services:
  web:
    command: sh -c "npm ci && npm run dev -- --host"
    volumes: ["./web:/app"]
  auth-server:
    environment:
      - AUTH_DCR_REQUIRE_INITIAL_TOKEN=false
      - AUTH_DCR_INITIAL_TOKEN=dev-bootstrap-token
```

Run:
```bash
docker compose up -d             # uses docker-compose.yml + override automatically
# OR use profiles:
docker compose --profile dev up -d
```

### 5) SPA behind a reverse proxy (optional)

If you serve the SPA via Nginx/Caddy on port 80/443:
- Make sure **the browser-facing URL** (e.g., `https://app.example.com`) appears in OAuth client **redirect URIs** and **post_logout** URIs.
- Point `VITE_OIDC_ISSUER` to the **browser-facing issuer host** (e.g., `https://auth.example.com`).
- Your API stays inside the network (e.g., `http://api:8082`), but CORS must still allow the SPA’s public origin.

---

### Quick sanity checks with Compose

After `docker compose up -d`:

```bash
# 1) Discovery resolves from host:
curl -s http://localhost:8080/.well-known/openid-configuration | jq .issuer

# 2) SPA env was injected (open http://localhost:5174 and inspect network -> discovery call)
# 3) API sees issuer:
docker logs go-api | grep OAUTH_ISSUER

# 4) If using confidential client in API:
#    Confirm API can read OAUTH_CLIENT_SECRET or OAUTH_CLIENT_SECRET_FILE
```

> If you expose Auth Server via a non-local hostname or HTTPS, update the issuer and SPA variables accordingly and re-register clients with matching redirect URIs.
