# Custom OAuth2.0 — Stable, One-Command Project (Postgres + Redis in Docker)

**Run all services in one command:**
```bash
docker compose up -d --build
```
Open **http://localhost:8082**.

### Features
- Spring Authorization Server (PKCE public client only, multi-tenant claim/issuer)
- Redis session store + token blacklist (revocation)
- Resource Server validates via JWKS and checks blacklist
- Client app (Thymeleaf) for login, calling API, and viewing claims
- Auto-registered client: `client_id=web-pkce`

### Revoke a token
```bash
curl -X POST -u admin:admin123 -d "token=<ACCESS_TOKEN>" http://localhost:9000/oauth2/revoke
```
