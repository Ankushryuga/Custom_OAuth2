# Custom OAuth2 — Localhost (no Nginx) — Java 21, Spring Boot 3.3.x, SAS 1.3.1

Everything runs on **http://localhost** (no TLS, no reverse proxy).

Services
- **auth-server** (http://localhost:8080): Spring Authorization Server (OIDC + DCR)
- **resource-server** (http://localhost:8082): Validates JWTs (scope `api.read`)
- **client-app** (http://localhost:8081): Spring MVC OIDC client (confidential)
- **oauth-login-redirect-ui** (http://localhost:5173): Redirect relay for SPA
- **client-ui** (http://localhost:5174): React SPA (PKCE public client)

## Quick start
```bash
cp .env.example .env
docker compose up --build -d
```

### Register clients (from your host terminal)

#### SPA (public; **no secret**)
```bash
curl -sS -i -H "Authorization: Bearer $AUTH_DCR_INITIAL_TOKEN"   -H "Content-Type: application/json"   --data @- http://localhost:8080/connect/register <<'JSON'
{
  "client_name": "React UI PKCE",
  "client_type": "public",
  "redirect_uris": ["http://localhost:5173"],
  "post_logout_redirect_uris": ["http://localhost:5174/"],
  "scope": "openid profile email api.read"
}
JSON
```
Copy the `client_id`, set it in `.env` → `VITE_CLIENT_ID=...`, then rebuild the SPA:
```bash
docker compose build --no-cache client-ui && docker compose up -d client-ui
```

#### MVC (confidential; **has secret**)
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
Put `client_id` and `client_secret` into `.env` as `CLIENT_ID_MVC` and `CLIENT_SECRET_MVC`, then:
```bash
docker compose up -d --build client-app
```

## Use it
- SPA: http://localhost:5174 → **Login** → username `user` / password `password`
- MVC: http://localhost:8081 → **Login with Generic OIDC`
