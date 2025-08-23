**This project contains 3 separate spring boot apps**
```
oauth2-custom/
│
├── authorization-server/        # Issues tokens (Access, Refresh, ID Token)
│   ├── src/main/java/com/example/authserver/
│   │   ├── config/              # Security + OAuth2 configuration
│   │   ├── controller/          # Endpoints like /login, /authorize, /token
│   │   ├── model/               # User, Role, Client entity
│   │   ├── repository/          # UserRepository, ClientRepository
│   │   ├── service/             # UserDetailsService, TokenService
│   │   └── AuthServerApplication.java
│   └── src/main/resources/
│       ├── application.yml
│       └── schema.sql           # DB schema for users, clients, roles
│
├── resource-server/             # Protects resources, validates JWT
│   ├── src/main/java/com/example/resourceserver/
│   │   ├── config/              # Security config (JWT validation)
│   │   ├── controller/          # Protected REST APIs
│   │   ├── model/               # Domain models (e.g., Orders, Users)
│   │   ├── repository/          # DB access
│   │   ├── service/             # Business logic
│   │   └── ResourceServerApplication.java
│   └── src/main/resources/
│       ├── application.yml
│
├── client-app/                  # The app requesting tokens
│   ├── src/main/java/com/example/client/
│   │   ├── config/              # OAuth2 client config
│   │   ├── controller/          # Login, callback endpoints
│   │   ├── service/             # Calls resource server with token
│   │   └── ClientApplication.java
│   └── src/main/resources/
│       ├── application.yml
│
├── docker-compose.yml           # If you want DB (Postgres/MySQL) + services
├── README.md
└── pom.xml                      # Parent POM (if multi-module Maven)
```

**Breakdown by Module**
1. Authorization server
    - Endpoints:
        - `/oauth2/authorize`   ->  Handles user login+consent
        - `/oauth2/token`       ->  Issues JWT tokens
        - `/jwks.json`          ->  Publishes public keys for resource servers.
    - Tables
        - `users` (username, password, roles).
        - `oauth_clients` (clientId, clientSecret, scopes, redirectUris).
        - `roles` (ROLE_USER, ROLE_ADMIN, etc).
    - Spring dependencies
        - `spring-boot-starter-security`
        - `spring-boot-starter-oauth2-authorization-server`
        - `spring-boot-starter-data-jpa`
        - Database (Postgres)

2. Resource Server
    - Validates JWT Access Tokens using the Authorization server's JWKS endpoint.
    - Endpoints
      - `/api/user/me` -> returns logged-in user profile
      - `/api/order`   -> samples protected resources
   - Spring dependencies
       - `spring-boot-starter-security`
       - `spring-boot-starter-oauth2-authorization-server`
       - `spring-boot-starter-data-jpa`

3. Client App
    - Acts as OAuth2 client
    - Implements Authorization code flow
        - Redirect user to `auth-server/oauth2/authorize`.
        - Handles redirect via `/callback`.
        - Exchanges code for token at `/token`.
    - Store token in session / cookie and uses it to call **resource server** apis
    - - Spring dependencies
        - `spring-boot-starter-oauth2-client`
        - `spring-boot-starter-web`



🚀 Example Flow
```
1. User opens Client App → redirected to Authorization Server login.
2. User logs in → Auth Server issues code → exchanged for Access Token + ID Token.
3. Client App stores tokens.
4. Client App calls Resource Server API with Authorization: Bearer <token>.
5. Resource Server validates JWT (via Auth Server JWKS).
6. If valid → returns protected data.
```


**Flyway**
```
spring:
  flyway:
    locations: classpath:db/migration
```
- is telling **Flyway** where to look for your database migration scripts

- **What is means**
  - `classpath:` → Look inside your project’s classpath (i.e., src/main/resources/ in a Spring Boot app).
  - `db/migration` → The folder where Flyway expects migration SQL scripts by default.
```
By default, Flyway will scan:
src/main/resources/db/migrations/
```

**Example**
```
src/main/resources/db/migration/
  ├── V1__create_users.sql
  ├── V2__add_roles.sql
  └── V3__insert_initial_data.sql
```
**You can change**
```
spring:
  flyway:
    locations: classpath:db/migration,filesystem:/opt/migrations
```

**Example of migration scripts**
- V1__create_users.sql
```
-- Create users table
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert an admin user (password should be encoded in production)
-- Example: password = "admin123" (later you will hash this with BCrypt)
INSERT INTO users (username, password, email, enabled)
VALUES ('admin', '{bcrypt}$2a$10$Dow1vYtX8hE.7R0S9Y1s5eDtsKk/0cGgGfQIrW1vXj8exk3sp2wPq', 'admin@example.com', TRUE);
```