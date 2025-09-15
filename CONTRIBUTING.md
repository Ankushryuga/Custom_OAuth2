# Contributing to Custom OAuth 2.1 (Auth Server + Clients)

Welcome! This document describes how to contribute at a **top-tier software engineering** level across all subprojects (Spring Authorization Server, Resource Server, MVC Client, SPA PKCE Client, and the custom Login UI).

> TL;DR: Use **Conventional Commits**, write **tests**, keep **backwards compatibility**, document changes, and open small, focused PRs.

## Code of Conduct
See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Project Structure
```
auth-server/                      # Spring Authorization Server (SAS)
  src/main/java/.../config        # SecurityConfig, CORS, JWKS source
  src/main/java/.../support       # FileBackedJwks (private key management)
  src/main/resources/static/login # Custom React+Tailwind login UI (built assets)
resource-server/                  # Validates tokens, exposes protected API (/data)
client-app/                       # MVC client (confidential) for E2E tests
client-ui/                        # SPA PKCE client (public) with Vite
oauth-login-redirect-ui/          # Minimal helper SPA (optional)
infra/                            # nginx/certs (optional for localhost)
docker-compose.yml
.env                              
README.md
CONTRIBUTING.md
```

**Key flows to preserve:**
- **PKCE Authorization Code Flow** for SPA (`/oauth2/authorize` → `/oauth2/token`).
- **Dynamic Client Registration** under `/connect/register` secured by bootstrap token.
- **Custom /login** UI that properly resumes the original authorize request.
- **JWKS** backed by persisted private key (FileBackedJwks).

## Prerequisites
- Java 21, Maven 3.9+, Node 20+, Docker & Compose v2
- Optional tools: `jq`, `httpie`, `curl`

## Branching, Commits, and PRs
- Branching: `main` (always releasable); `feature/*`, `fix/*`, `chore/*`, `hotfix/*`
- Conventional Commits (examples):
  - `feat(auth-server): add mTLS client auth support`
  - `fix(client-ui): correct token exchange Accept header`
  - `refactor: extract common PKCE helpers`
  - `docs: expand DCR troubleshooting`
  - `chore(build): bump spring boot to 3.3.2`
  - `test(resource): add JWT expiry integration tests`
- Pull Requests:
  - Small, focused (< ~400 LOC delta preferred)
  - Include tests + docs updates
  - PR description: Problem, Solution, Risks, Testing notes, Screenshots/logs where helpful

## Development Workflow
1. Fork & clone.
2. `git switch -c feature/my-change`
3. `docker compose build && docker compose up -d`
4. Register clients via DCR (see README). Update `.env` accordingly.
5. Edit code + run tests locally.
6. Open PR with a Conventional Commit title.

### Running outside Docker (optional)
- Auth Server: `cd auth-server && ./mvnw spring-boot:run`
- SPA: `cd client-ui && npm i && npm run dev` (ensure `VITE_*` environment vars)

## Build, Test, and Lint
- Java: `mvn -q -DskipTests package`; tests via `mvn -q test`
- TypeScript: `npm ci`; `npm run build`; `npm run lint`; `npm run format`
- Recommended: Spotless + Checkstyle (Java), ESLint + Prettier (TS)

### Minimum Test Expectations
- **auth-server**: unit tests for controllers/config; integration tests for `/oauth2/authorize`, `/oauth2/token`, and DCR; Flyway migrations covered.
- **resource-server**: JWT validation + scope authorization tests.
- **clients**: minimal E2E covering happy path and failure modes.

## Database Migrations
- Flyway: new SQL under `src/main/resources/db/migration`
- Backwards compatible first; prefer expand/migrate/contract

## Security Practices
- Never commit secrets; `.env` is local only
- Keep `AUTH_DCR_INITIAL_TOKEN` private in real deployments
- Treat `data/jwks/jwks.json` like a private key
- Validate `redirect_uris` tightly; no wildcards in prod
- Restrict CORS in prod (`CORS_ALLOWED_ORIGINS`)
- Prevent open redirects; validate redirect hosts
- Use PKCE S256 for public clients; strong auth for confidential clients
- Keep dependencies patched; consider Dependabot/Renovate, CodeQL, image scans

## API Compatibility & Versioning
- SemVer across services; avoid breaks without a major bump
- For DB: expand-migrate-contract pattern

## Observability & Logging
- Structured logs; correlation IDs; clear auth error logging
- Consider `/actuator/health` & `/actuator/info`

## Performance
- Avoid blocking token endpoint
- Tune HikariCP
- Load test critical auth flows (k6/Gatling)

## Documentation
- Keep README and `.env` examples current
- Add UPGRADING.md for breaking changes
- JavaDoc complex/public APIs

## Release Process
1. Ensure main is green in CI
2. Draft release notes (features, fixes, DB changes, breaking changes)
3. Tag SemVer (e.g., `v1.2.0`)
4. Build/push images (if publishing)
5. Announce with migration steps

## Issue Reporting
- Use issue templates; provide repro steps, logs, env details

## Code Review Checklist
- [ ] Conventional Commit title
- [ ] Tests + docs updated
- [ ] Backwards compatible (API/DB/config)
- [ ] Security checks (no secrets, redirect safety, CORS, scopes)
- [ ] Perf implications considered
- [ ] Useful logs, not noisy
- [ ] Small/focused PR

## Style Guides
### Java
- Java 21; prefer immutable patterns; null-safety
### TypeScript/React
- Functional components + hooks, strong typings
- Token exchange: `Content-Type: application/x-www-form-urlencoded;charset=UTF-8` and `Accept: application/json`

## Useful Commands
```bash
docker compose build --no-cache
docker compose up -d
docker compose logs -f auth-server

# Hard reset (DB, Redis, JWKS)
docker compose down -v
rm -rf data/jwks
```
