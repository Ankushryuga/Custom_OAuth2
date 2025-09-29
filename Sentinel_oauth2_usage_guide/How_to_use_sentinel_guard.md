# Sentinel OAuth2 / OIDC — **Complete Client Registration & Usage Guide**

NOTE: ```Here issuer means Sentinel Auth server IP address```

This is a **single, comprehensive** manual for registering clients and wiring your **Sentinel OAuth2 / OIDC Authorization Server** (Spring Authorization Server) into different kinds of web applications. It is written to be **copy‑paste friendly** and to minimize guesswork.

It covers **everything**:
- Exact **IP/host mapping** you asked for
- **Every way** to register a client (DCR, Admin API, Java/SQL seeding, Postman, shell)
- How to **use `client_id` / `client_secret`** safely in: **Go+React**, **Java(Sprint Boot)+React**, **Remix**, **Next.js**
- **docker-compose** patterns (env files, Docker secrets)
- End‑to‑end flows, code snippets, CORS, PKCE (HTTP & HTTPS), logout
- Verification, troubleshooting, FAQs, and security hardening

> **Auth Server IP in this doc (issuer)**: `http://10.201.240.154:8080`  
> **Client machine / SPA & API example IP**: `http://10.201.240.239`  
> For local browser development, prefer **`http://localhost`** for the SPA to avoid WebCrypto HTTPS restrictions.

---

## Table of Contents

1. [Network & Identity at a Glance](#network--identity-at-a-glance)
2. [Core Endpoints & Glossary](#core-endpoints--glossary)
3. [Quick Start (10‑minute checklist)](#quick-start-10minute-checklist)
4. [Registering Clients (All Methods)](#registering-clients-all-methods)
    - [Dynamic Client Registration (DCR)](#dynamic-client-registration-dcr)
    - [Custom Admin API](#custom-admin-api)
    - [Programmatic Seeding (Java @Startup)](#programmatic-seeding-java-startup)
    - [SQL Seeding (Flyway/Liquibase)](#sql-seeding-flywayliquibase)
    - [Postman / GUI](#postman--gui)
    - [Shell Script / Makefile](#shell-script--makefile)
5. [How to Use `client_id` / `client_secret` in Apps](#how-to-use-client_id--client_secret-in-apps)
    - [Go + React (SPA + Go API)](#go--react-spa--go-api)
    - [Java (Spring Boot) + React](#java-spring-boot--react)
    - [Remix (full‑stack)](#remix-fullstack)
    - [Next.js (App Router)](#nextjs-app-router)
6. [docker‑compose: Env, .env, Secrets](#dockercompose-env-env-secrets)
7. [CORS, PKCE, and HTTPS vs HTTP](#cors-pkce-and-https-vs-http)
8. [Logout (RP‑initiated) & Session Notes](#logout-rpinitiated--session-notes)
9. [Verification with curl](#verification-with-curl)
10. [Troubleshooting (Checklist + FAQs)](#troubleshooting-checklist--faqs)
11. [Security Hardening](#security-hardening)
12. [Client Metadata Field Reference](#client-metadata-field-reference)

---

## Network & Identity at a Glance

```text
AUTH SERVER (issuer)   : http://10.201.240.154:8080
CLIENT MACHINE (example): http://10.201.240.239

React SPA (dev)        : http://localhost:5174   (preferred for PKCE on HTTP)
                         or http://10.201.240.239:5174

Go API (resource)      : http://10.201.240.239:8082
Spring Boot API        : http://10.201.240.239:<your-port>
```

**Who owns what?**
- **Auth Server** issues tokens, hosts `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`, etc.
- **SPA** uses **`client_id` only** (no secret) and **PKCE** to obtain tokens in the browser.
- **APIs/backends** validate incoming JWTs using **issuer** + **JWKS** (and may use **client_credentials** flow with **`client_secret`** to call other services).

---

## Core Endpoints & Glossary

- **Issuer**: `http://10.201.240.154:8080`
- **Discovery**: `/.well-known/openid-configuration`
- **Authorize**: `/oauth2/authorize`
- **Token**: `/oauth2/token`
- **JWKS**: `/oauth2/jwks`
- **UserInfo**: `/userinfo`
- **Logout**: `/connect/logout` (if enabled)

**Public client** (SPA/native): **no secret**, must use **PKCE**.  
**Confidential client** (server): has **secret**, keep server‑side only.  
**Scopes**: `openid profile email` (+ `api.read`, `api.write` for your APIs).

---

## Quick Start (10‑minute checklist)

1) **Verify discovery**
```bash
curl -s http://10.201.240.154:8080/.well-known/openid-configuration | jq .issuer
# "http://10.201.240.154:8080"
```

2) **Register SPA (public + PKCE)** → copy `client_id` from the response
```bash
curl -sS -i -H "Content-Type: application/json" --data @- \
  http://10.201.240.154:8080/connect/register <<'JSON'
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

3) **Set SPA env**
```env
VITE_OIDC_ISSUER=http://10.201.240.154:8080
VITE_OIDC_CLIENT_ID=<paste client_id here>
VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
VITE_API_BASE=http://10.201.240.239:8082/api
```

4) **Run SPA and Go API** (or Spring API). Login from SPA → tokens → call API with `Authorization: Bearer`.

5) **API validates JWT** against `issuer` + `jwks_uri` and enforces scopes.

Done. Now drill into details below.

---

## Registering Clients (All Methods)

### Dynamic Client Registration (DCR)

**Endpoint**: `POST http://10.201.240.154:8080/connect/register`  
**Headers**: `Content-Type: application/json` (+ `Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN` if required)

#### SPA (Public + PKCE)
```bash
curl -sS -i \
  -H "Content-Type: application/json" \
  --data @- http://10.201.240.154:8080/connect/register <<'JSON'
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

#### Backend (Confidential, client_credentials)
```bash
curl -sS -i \
  -H "Content-Type: application/json" \
  --data @- http://10.201.240.154:8080/connect/register <<'JSON'
{
  "client_name": "Backend Service",
  "client_type": "confidential",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "api.read"
}
JSON
```

#### Native (Public + PKCE, loopback)
```bash
curl -sS -i \
  -H "Content-Type: application/json" \
  --data @- http://10.201.240.154:8080/connect/register <<'JSON'
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

> **Multiple redirect URIs?** Add both localhost and your IP variant if you use both.

### Custom Admin API

If present, a simplified endpoint (e.g., dev bootstrap token):

```bash
curl -sS -i -X POST http://10.201.240.154:8080/admin/clients \
  -H "Authorization: Bearer dev-bootstrap-token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name":"SPA PKCE",
    "client_type":"public",
    "redirect_uris":["http://localhost:5174/oidc/callback"],
    "post_logout_redirect_uris":["http://localhost:5174/"],
    "scope":"openid profile email"
  }'
```

### Programmatic Seeding (Java @Startup)

See the `CommandLineRunner` example later (Java + React section).

### SQL Seeding (Flyway/Liquibase)

Insert into `oauth2_registered_client` following your SAS schema version. Examples are included later.

### Postman / GUI

Use POST to `/connect/register` with JSON from any example.

### Shell Script / Makefile

Keep a script teammates can run; examples included later.

---

## How to Use `client_id` / `client_secret` in Apps

> Rule of thumb: **SPAs use only `client_id` with PKCE**; **servers use `client_secret`**, never exposing it to browsers.

### Go + React (SPA + Go API)

**Who is who**
- **Issuer (Auth Server)**: `http://10.201.240.154:8080`
- **SPA**: `http://localhost:5174` (prefer localhost in dev for PKCE on HTTP)
- **Go API**: `http://10.201.240.239:8082`

**SPA `.env`**
```env
VITE_OIDC_ISSUER=http://10.201.240.154:8080
VITE_OIDC_CLIENT_ID=<spa_client_id>
VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
VITE_API_BASE=http://10.201.240.239:8082/api
```

**SPA flow (summary)**
1. Read discovery → get `authorization_endpoint`, `token_endpoint`.
2. Create `state`, `code_verifier`, `code_challenge` (PKCE).
3. Redirect to `/oauth2/authorize?...client_id=...&redirect_uri=...&code_challenge=...&scope=openid profile email&response_type=code&state=...`.
4. Callback: POST `/oauth2/token` with `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, `code_verifier`.
5. Save tokens; call API with `Authorization: Bearer <access_token>`.

**Call API from SPA**
```ts
export async function apiFetch(path: string, init: RequestInit = {}) {
  const tokens = JSON.parse(sessionStorage.getItem("mini_oidc:tokens") || "{}");
  const headers = new Headers(init.headers || {});
  if (tokens?.access_token) headers.set("Authorization", `Bearer ${tokens.access_token}`);
  if (!headers.has("Content-Type") && init.body) headers.set("Content-Type", "application/json");
  return fetch(`${import.meta.env.VITE_API_BASE}${path}`, { ...init, headers });
}
```

**Go API `.env`**
```env
API_PORT=8082
FRONTEND_ORIGIN=http://localhost:5174
OAUTH_ISSUER=http://10.201.240.154:8080
```

**Go (Gin) — CORS + JWT validation (sketch)**
```go
r.Use(cors.New(cors.Config{
  AllowOrigins: []string{os.Getenv("FRONTEND_ORIGIN")},
  AllowMethods: []string{"GET","POST","PUT","PATCH","DELETE","OPTIONS"},
  AllowHeaders: []string{"Authorization","Content-Type"},
}))

// JWT middleware: verify iss == OAUTH_ISSUER; get JWKS from OAUTH_ISSUER + "/oauth2/jwks"
```

**Go API → other API via client_credentials (server-to-server)**
```env
OAUTH_CLIENT_ID=backend-service
OAUTH_CLIENT_SECRET=super-secret   # server-only (or use Docker secrets)
OAUTH_SCOPES=api.read
```

Acquire token (server side only):
```bash
curl -s -X POST "http://10.201.240.154:8080/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'backend-service:super-secret' \
  -d 'grant_type=client_credentials&scope=api.read' | jq .
```

---

### Java (Spring Boot) + React

**Who is who**
- **Issuer**: `http://10.201.240.154:8080`
- **SPA**: `http://localhost:5174`
- **Spring Boot API**: `http://10.201.240.239:8085` (example)

**SPA `.env`** (point API base to Spring API):
```env
VITE_OIDC_ISSUER=http://10.201.240.154:8080
VITE_OIDC_CLIENT_ID=<spa_client_id>
VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
VITE_API_BASE=http://10.201.240.239:8085/api
```

**Spring Boot as Resource Server (`application.yml`)**
```yaml
server:
  port: 8085

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://10.201.240.154:8080
          jwk-set-uri: http://10.201.240.154:8080/oauth2/jwks
```

**Security filter chain**
```java
@Bean
SecurityFilterChain rs(HttpSecurity http) throws Exception {
  http.authorizeHttpRequests(a -> a
        .requestMatchers("/public/**").permitAll()
        .anyRequest().authenticated())
      .oauth2ResourceServer(o -> o.jwt());
  return http.build();
}
```

**Scope guard**
```java
@PreAuthorize("hasAuthority('SCOPE_api.read')")
@GetMapping("/api/todos")
public List<Todo> list(){ ... }
```

**Spring → client_credentials to call another API**
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          backend-service:
            provider: custom-issuer
            client-id: backend-service
            client-secret: ${OAUTH_CLIENT_SECRET}
            authorization-grant-type: client_credentials
            scope: api.read
        provider:
          custom-issuer:
            token-uri: http://10.201.240.154:8080/oauth2/token
```

**Programmatic client seeding (optional)**
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
      .clientId("backend-service")
      .clientSecret("{noop}super-secret")
      .clientName("Backend Service")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .scope("api.read").build();

    if (((JdbcRegisteredClientRepository) repo).findByClientId("spa-localhost") == null) repo.save(spa);
    if (((JdbcRegisteredClientRepository) repo).findByClientId("backend-service") == null) repo.save(backend);
  };
}
```

**SQL seeding (check your SAS schema!)**
```sql
INSERT INTO oauth2_registered_client (...)
VALUES (... 'spa-localhost', ..., 'none', 'authorization_code,refresh_token', 'http://localhost:5174/oidc/callback', 'http://localhost:5174/', 'openid,profile,email', '{"requireProofKey":true}', '{}');

INSERT INTO oauth2_registered_client (...)
VALUES (... 'backend-service', ..., '{noop}super-secret', 'client_secret_basic', 'client_credentials', 'api.read', '{}', '{}');
```

---

### Remix (full‑stack)

**Who is who**
- **Issuer**: `http://10.201.240.154:8080`
- **Remix App**: `http://localhost:5173`
- **Your API**: `http://10.201.240.239:8082/api`

**Env**
```env
AUTH_ISSUER=http://10.201.240.154:8080
AUTH_CLIENT_ID=<spa_client_id>          # public client id (no secret)
AUTH_REDIRECT_URI=http://localhost:5173/oidc/callback
SESSION_SECRET=change-me
API_BASE=http://10.201.240.239:8082/api
```

**Flow**
- Route `/login` → generate PKCE (`verifier`, `challenge`) + `state`, store in server session cookie → redirect to `/oauth2/authorize`.
- Route `/oidc/callback` → verify `state`, POST `/oauth2/token` with `code` + `code_verifier`, store tokens in the session (HttpOnly cookie) or session storage (tradeoffs).
- Loaders/actions use the stored `access_token` to call your API with `Authorization: Bearer`.

**Confidential Remix pattern** (server‑only tokens): register a **confidential** client, keep `client_secret` in env, handle the full code exchange on the server and never expose access tokens to the browser. Use SSR to personalize pages.

---

### Next.js (App Router)

**Who is who**
- **Issuer**: `http://10.201.240.154:8080`
- **Next.js**: `http://localhost:3000`

**Env**
```env
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=change-me

OIDC_ISSUER=http://10.201.240.154:8080
OIDC_CLIENT_ID=<client_id>
# Public pattern (PKCE) → do not set a secret; use PKCE client in the browser
# Confidential (server-side) pattern:
OIDC_CLIENT_SECRET=<client_secret>   # server-only
```

**Confidential pattern with NextAuth.js (sketch)**
```ts
import NextAuth from "next-auth"
import { Issuer } from "openid-client"

export const authOptions = async () => {
  const discovered = await Issuer.discover(process.env.OIDC_ISSUER!)
  return {
    providers: [
      {
        id: "custom-oidc",
        name: "Custom OIDC",
        type: "oidc",
        issuer: discovered.issuer,
        clientId: process.env.OIDC_CLIENT_ID,
        clientSecret: process.env.OIDC_CLIENT_SECRET, // omit for public PKCE pattern
      } as any
    ],
    callbacks: {
      async jwt({ token, account }) {
        if (account?.access_token) token.access_token = account.access_token
        return token
      },
      async session({ session, token }) {
        (session as any).access_token = token.access_token
        return session
      }
    }
  }
}
export default NextAuth(await authOptions())
```

Use `getServerSession` inside API routes/server components to obtain `access_token` and call your API server‑side.

---

## docker‑compose: Env, .env, Secrets

**Key rules**
- **SPA**: set `VITE_OIDC_ISSUER`, `VITE_OIDC_CLIENT_ID`, **no secret**.
- **API/Backend**: set `OAUTH_ISSUER` and (if using client_credentials) **provide `client_secret` via Docker secrets**.

**Minimal compose (dev, HTTP)**
```yaml
version: "3.9"
services:
  auth-server:
    image: your-org/custom-auth-server:latest
    ports: ["8080:8080"]
    environment:
      - SPRING_SECURITY_OAUTH2_AUTHORIZATIONERVER_ISSUER=http://auth-server:8080
    networks: [appnet]

  api:
    image: your-org/go-api:latest
    ports: ["8082:8082"]
    environment:
      - API_PORT=8082
      - FRONTEND_ORIGIN=http://localhost:5174
      - OAUTH_ISSUER=http://auth-server:8080
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
      - VITE_OIDC_CLIENT_ID=<spa_client_id>
      - VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
      - VITE_API_BASE=http://localhost:8082/api
    depends_on: [api, auth-server]
    networks: [appnet]

networks:
  appnet: { driver: bridge }
```

**Docker secrets for `client_secret` (recommended)**
```yaml
version: "3.9"
secrets:
  oauth_client_secret:
    file: ./secrets/oauth_client_secret.txt

services:
  api:
    image: your-org/go-api:latest
    ports: ["8082:8082"]
    environment:
      - OAUTH_ISSUER=http://auth-server:8080
      - OAUTH_CLIENT_ID=backend-service
      - OAUTH_CLIENT_SECRET_FILE=/run/secrets/oauth_client_secret
      - OAUTH_SCOPES=api.read
    secrets: [oauth_client_secret]
    networks: [appnet]
```

In Go, read `/run/secrets/oauth_client_secret` at startup and keep it in memory only.

---

## CORS, PKCE, and HTTPS vs HTTP

- **CORS**: Your API must allow the SPA origin and `Authorization` header. Example (Gin): allow `http://localhost:5174` with methods `GET,POST,PUT,PATCH,DELETE,OPTIONS`.
- **PKCE**: Browsers require `Crypto.subtle` (HTTPS or **http://localhost**).
    - Use **`http://localhost`** for SPA dev or run HTTPS locally.
    - A JS SHA‑256 fallback (already wired in your sample) also works on HTTP.
- **HTTPS**: In non‑dev, always use TLS and stable hostnames (`https://auth.example.com`, `https://app.example.com`).

---

## Logout (RP‑initiated) & Session Notes

If `end_session_endpoint` is available:
```
GET http://10.201.240.154:8080/connect/logout?id_token_hint=<id_token>&post_logout_redirect_uri=<url>
```
Clear SPA tokens locally first. If using server sessions (Remix/Next.js confidential), clear server session/cookies too.

---

## Verification with curl

**Discovery**
```bash
curl -s http://10.201.240.154:8080/.well-known/openid-configuration | jq .
```

**Client credentials (confidential)**
```bash
curl -s -X POST "http://10.201.240.154:8080/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'backend-service:super-secret' \
  -d 'grant_type=client_credentials&scope=api.read' | jq .
```

**Authorization code + PKCE** (after you get `code` in browser callback)
```bash
curl -s -X POST "http://10.201.240.154:8080/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=<spa_client_id>' \
  -d 'redirect_uri=http://localhost:5174/oidc/callback' \
  -d 'code=<code_from_redirect>' \
  -d 'code_verifier=<the_original_verifier>' | jq .
```

**UserInfo**
```bash
curl -s "http://10.201.240.154:8080/userinfo" -H "Authorization: Bearer <access_token>" | jq .
```

---

## Troubleshooting (Checklist + FAQs)

- **`invalid_redirect_uri`**: Must match your actual redirect exactly (scheme/host/port/path).
- **SPA `Crypto.subtle ... secure contexts`**: Use `http://localhost` or HTTPS for SPA dev; or use a JS SHA‑256 fallback PKCE.
- **`No matching state found in storage`**: Always initiate login from the SPA; don’t clear storage; callback origin must match the one that stored state.
- **API returns 401**: Ensure SPA includes `Authorization: Bearer` header; verify issuer/JWKS/scopes on the server.
- **Issuer mismatch**: SPA/API issuer must equal discovery `issuer`.
- **CORS**: Add SPA origin and `Authorization` header; verify preflight (`OPTIONS`) succeeds.
- **Where is client_id?**: Returned by registration; record it in your `.env`/compose for SPA.
- **Where is client_secret?**: Returned only for confidential clients; keep server side (env/secrets), never in SPA.

---

## Security Hardening

- **Never** put `client_secret` in browser code or public repos.
- Use **Docker secrets**/vault for secrets; rotate regularly.
- Limit scopes (`api.read` vs `api.write`); keep access tokens short‑lived.
- Enforce HTTPS and stable hostnames outside of development.
- Consider audience (`aud`) for APIs; reject tokens not intended for your API.

---

## Client Metadata Field Reference

| Field                          | Type/Example                                   | Notes |
|--------------------------------|------------------------------------------------|-------|
| `client_name`                  | `"SPA PKCE (localhost)"`                       | Display name |
| `client_type`                  | `"public"` or `"confidential"`                 | SPA/native vs server |
| `redirect_uris`                | `["http://localhost:5174/oidc/callback"]`      | Required for code flow |
| `post_logout_redirect_uris`    | `["http://localhost:5174/"]`                   | Optional logout return |
| `grant_types`                  | `["authorization_code","refresh_token"]`       | SPA/native |
|                                | `["client_credentials"]`                        | Backend |
| `response_types`               | `["code"]`                                     | Code flow |
| `scope`                        | `"openid profile email api.read"`              | Space‑delimited |
| `token_endpoint_auth_method`   | `"none"` (SPA) or `"client_secret_basic"`      | Client auth at `/token` |
| `client_uri`, `logo_uri`       | URLs                                           | Optional |
| `contacts`                     | `["dev@team.test"]`                            | Optional |

---

**End of file.**
