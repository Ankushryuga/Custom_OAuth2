# Custom OAuth 2.1 — Local Complete Setup
Authorization Server you can share with **many apps** using **Dynamic Client Registration (DCR)** — no per-client hardcoding. The stack:

- **Auth Server** (Spring Boot + Spring Authorization Server)
- **Resource Server** (Spring Boot)
- **MVC Client** (Spring Boot)
- **SPA Client (PKCE)** (React + Vite)
- **Custom Login UI** (React + Tailwind) embedded at **`/login`**
- **Auto-generated private JWKS** (no more “Expected private JWK”)
- **Multi-app CORS**

**Demo credentials:** `user` / `password`.

---

## What’s inside

```
auth-server/
  src/main/java/.../config/SecurityConfig.java        # SAS defaults, resume /oauth2/authorize after login
  src/main/java/.../support/FileBackedJwks.java       # generates & persists private RSA JWKS
  src/main/resources/static/login/**                  # built login UI (served at /login)
resource-server/
client-app/                                           # MVC client (confidential)
client-ui/                                            # SPA (PKCE) client (public)
oauth-login-redirect-ui/                              # simple helper (optional)
infra/                                                # optional nginx/certs (not needed locally)
docker-compose.yml
.env
```

---

## Ports

| Service                  | URL / Port                  |
|--------------------------|-----------------------------|
| **Auth Server**          | `http://localhost:8080`     |
| **Resource Server**      | `http://localhost:8082`     |
| **MVC Client**           | `http://localhost:8081`     |
| **SPA (PKCE)**           | `http://localhost:5174`     |
| **Login Redirect UI**    | `http://localhost:5173`     |
| **Postgres (host)**      | `localhost:5433` → container `5432` |
| **Redis**                | `localhost:6379`            |

> Postgres maps to **5433** on the host to avoid conflicts with a local pg.

---

## Prereqs
- Docker Desktop (or Docker + Compose v2)
- (Optional) Node 20+ if you want to run SPA/login UI outside Docker

---

## .env
In case .env is missing then please add .env file with the following .env content in the root directory.
Create/adjust **`.env`** at repo root:

```env
# ---------- Infra ----------
POSTGRES_DB=oauth_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=1234

# ---------- Auth Server ----------
AUTH_DCR_INITIAL_TOKEN=dev-dcr-token-123
AUTH_DCR_REQUIRE_INITIAL_TOKEN=true
SERVER_FORWARD_HEADERS=framework
AUTH_ISSUER_URI=http://localhost:8080

# (Optional) comma-separated origins. Defaults allow localhost & *.localtest.me
# CORS_ALLOWED_ORIGINS=http://localhost:5174,http://localhost:5173,https://*.localtest.me

# ---------- Resource Server ----------
ISSUER_BASE_URI=http://localhost:8080
RS_JWK_SET_URI=http://auth-server:8080/oauth2/jwks

# ---------- MVC Client (fill after DCR) ----------
CLIENT_ID_MVC=
CLIENT_SECRET_MVC=

# ---------- SPA (fill after DCR) ----------
VITE_ISSUER=http://localhost:8080
VITE_CLIENT_ID=
VITE_SCOPE=openid profile email api.read
VITE_REDIRECT_URI=http://localhost:5174/oidc/callback
VITE_RS_BASE=http://localhost:8082

JAVA_TOOL_OPTIONS=-Xms256m -Xmx512m
```

> **Keys**: `FileBackedJwks` persists a private signing key at `./data/jwks/jwks.json`. Treat it like a private key.

---

## Quick start

```bash
# 1) Build all services
docker compose build --no-cache

# 2) Run them
docker compose up -d

# 3) Verify the Auth Server is up
curl -s http://localhost:8080/.well-known/openid-configuration | jq .issuer,.authorization_endpoint,.token_endpoint
# Expect:
# "http://localhost:8080"
# "http://localhost:8080/oauth2/authorize"
# "http://localhost:8080/oauth2/token"
```

**Demo user:** `user` / `password`

---

## Register clients (DCR)

> DCR is protected by `AUTH_DCR_INITIAL_TOKEN`. Change it for real deployments.

### SPA (PKCE, public)

```bash
export AUTH_DCR_INITIAL_TOKEN=dev-dcr-token-123

curl -sS -i -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN"   -H "Content-Type: application/json"   --data @- http://localhost:8080/connect/register <<'JSON'
{
  "client_name": "SPA PKCE",
  "client_type": "public",
  "redirect_uris": ["http://localhost:5174/oidc/callback"],
  "post_logout_redirect_uris": ["http://localhost:5174/"],
  "scope": "openid profile email api.read"
}
JSON
```

Copy the **`client_id`** returned into `.env` → `VITE_CLIENT_ID`, then:

```bash
docker compose build --no-cache client-ui
docker compose up -d client-ui
```

### MVC (confidential)

```bash
curl -sS -i -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN"   -H "Content-Type: application/json"   --data @- http://localhost:8080/connect/register <<'JSON'
{
  "client_name": "Spring MVC Client",
  "client_type": "confidential",
  "redirect_uris": ["http://localhost:8081/login/oauth2/code/generic"],
  "scope": "openid profile email api.read",
  "token_endpoint_auth_method": "client_secret_basic"
}
JSON
```

Copy **`client_id`** and **`client_secret`** into `.env` (`CLIENT_ID_MVC`, `CLIENT_SECRET_MVC`), then:

```bash
docker compose build --no-cache client-app
docker compose up -d client-app
```

---

## Use the apps

### SPA (PKCE)
1. Open **http://localhost:5174**
2. Click **Login** → redirected to **http://localhost:8080/login**
3. Sign in with **user / password**
4. You’ll return to **/oidc/callback**; the SPA exchanges the code for tokens
5. Click **GET /data** to call the Resource Server with the access token

### MVC Client
1. Open **http://localhost:8081**
2. Click **Login with OIDC**
3. Sign in; you’ll return authenticated to the MVC app

---

## Custom login page

- React/Tailwind app served at **`/login`**
- Fetches CSRF from **`/csrf`** and posts with the form
- Best reached by starting from `/oauth2/authorize` (your app).  
  If opened directly, after login you’ll see a message to start from your app.

> Vite is built with `base: '/login/'` so asset URLs work under `/login`.

---

## How the server resumes after login

We resume **the original `/oauth2/authorize`** request using (in this order):

1. **SavedRequest** (session) for `/oauth2/authorize` (we only save this path to avoid noise)
2. Short-lived **`CONTINUE` cookie** (set when redirecting to `/login`)
3. Hidden form field echoing **`?continue=`** from the query string

SAS default security is applied so `/oauth2/token` remains a POST API (not redirected).

---

## CORS for many apps

Default allowed origin **patterns**:

- `http://localhost:*`
- `http://127.0.0.1:*`
- `https://*.localtest.me`

Override via `.env`:

```env
CORS_ALLOWED_ORIGINS=http://myapp.local:3000,https://app.example.com
```

All methods/headers allowed; `allowCredentials=true`.

---

## Sanity checks (curl)

**OIDC discovery:**
```bash
curl -s http://localhost:8080/.well-known/openid-configuration | jq
```

**Token endpoint should return 400 (invalid_grant) for a bad code (not 405):**
```bash
curl -i -X POST http://localhost:8080/oauth2/token   -H 'Content-Type: application/x-www-form-urlencoded'   -H 'Accept: application/json'   -d 'grant_type=authorization_code&code=BAD&redirect_uri=http://localhost:5174/oidc/callback&client_id=YOUR_SPA_CLIENT_ID&code_verifier=foo'
```

---

## DB inspection

List tables:
```bash
docker compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt"'
```

Recent clients:
```bash
docker compose exec -T postgres sh -lc '
psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -x -c "
  SELECT client_id,
         redirect_uris,
         scopes,
         client_authentication_methods,
         authorization_grant_types,
         client_settings
  FROM oauth2_registered_client
  ORDER BY client_id_issued_at DESC
  LIMIT 3;"
'
```

---

## Troubleshooting

**“Token HTTP 405” (browser)**
- If the curl probe above returns **400 JSON**, the server is fine.
- Ensure SPA token exchange uses:
  - `Content-Type: application/x-www-form-urlencoded;charset=UTF-8`
  - `Accept: application/json`
  - `credentials: 'omit'` (don’t send cookies)

**`JwtEncodingException: Expected private JWK but none available`**
- Fixed by `FileBackedJwks`. It **generates** a private RSA signing key in `./data/jwks/jwks.json`.
- If you had an old public-only file, delete it and restart to regenerate.

**Login asks twice or shows `/error?continue`**
- Usually means you visited `/login` directly.
- Start from your app (it must call `/oauth2/authorize?client_id=...&redirect_uri=...`).
- We only cache `/oauth2/authorize` (by design).

**`invalid_grant` at token exchange**
- Mismatched `redirect_uri`, wrong `client_id`, or incorrect `code_verifier`.
- SPA must use the exact `redirect_uri` from DCR and the same `code_verifier` it generated.

**SPA callback “Unexpected end of JSON input”**
- Token endpoint returned HTML (error/redirect) instead of JSON.
- Ensure SPA sets `Accept: application/json`, uses the correct token URL, and doesn’t include cookies.

**Postgres “address already in use”**
- We map host **5433** → container 5432. Free 5433 or pick another host port.

---

## Clean reset

```bash
# Stop & remove containers + volumes (DB, Redis, JWKS)
docker compose down -v

# (Optional) wipe generated JWKS for a fresh key
rm -rf data/jwks

# Rebuild & start
docker compose build --no-cache
docker compose up -d

# Re-run DCR and update .env client IDs as needed
```

---

## Security notes
- Protect **`AUTH_DCR_INITIAL_TOKEN`** in production.
- Treat **`data/jwks/jwks.json`** like a private key (secure storage/backup).
- Use TLS/HTTPS behind a proxy/ingress in real deployments.
- Lock `CORS_ALLOWED_ORIGINS` to real app origins in production.

---

### Default credentials
- **user / password** (demo-only)

---

If anything’s off, grab:
- Browser DevTools → **Network** (`/oauth2/authorize`, `/login`, `/oauth2/token`)
- Auth Server logs around those requests

…and you’ll find the culprit fast.
